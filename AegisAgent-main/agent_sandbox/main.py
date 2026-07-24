from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import ValidationError
from starlette.staticfiles import StaticFiles

from .attack import default_attack_plan, validate_attack_plan
from .deployment import image_reserve_status
from .ingest import IngestError, safe_extract_zip
from .llm import audit_with_llms, plan_attacks_with_llm, plan_builds_with_llm
from .plan_discovery import sort_candidate_dicts
from .reporting import build_report, merge_findings, report_to_json, report_to_markdown
from .sandbox import run_dynamic_sandbox
from .schemas import LLMProvider, RunSummary
from .static_scan import scan_project
from .storage import Store

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / ".sandbox_data"
RUNS_DIR = DATA_DIR / "runs"
STORE = Store(DATA_DIR / "runs.sqlite3")

load_dotenv(BASE_DIR / ".env")

app = FastAPI(title="AegisAgent", version="5.0.0")
WEB_DIR = BASE_DIR / "agent_sandbox" / "web"
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/", response_class=FileResponse)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.post("/api/runs", response_model=RunSummary)
async def create_run(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    providers: str | None = Form(default=None),
    runtime_env: str | None = Form(default=None),
    runtime_network: str | None = Form(default=None),
    build_mode: str = Form(default="auto"),
    allow_install_scripts: bool = Form(default=True),
    cache_policy: str = Form(default="use"),
    delete_build_image_after_run: bool = Form(default=False),
) -> RunSummary:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip uploads are supported.")
    run_id = uuid.uuid4().hex
    workspace = RUNS_DIR / run_id
    workspace.mkdir(parents=True, exist_ok=True)
    upload_path = workspace / "upload.zip"
    with upload_path.open("wb") as dst:
        while chunk := await file.read(1024 * 1024):
            dst.write(chunk)
    provider_models = _load_providers(providers)
    runtime_env_values = _load_runtime_env(runtime_env)
    runtime_network_policy = _load_runtime_network(runtime_network, runtime_env_values)
    build_mode_policy = _load_build_mode(build_mode)
    cache_policy_value = _load_cache_policy(cache_policy)
    STORE.create_run(run_id, file.filename, workspace)
    STORE.add_event(run_id, "queued", "info", "Run queued", {"input_name": file.filename, "llm_providers": len(provider_models), "runtime_env_keys": sorted(runtime_env_values), "runtime_network": runtime_network_policy, "build_mode": build_mode_policy, "cache_policy": cache_policy_value, "allow_install_scripts": allow_install_scripts, "delete_build_image_after_run": delete_build_image_after_run})
    background_tasks.add_task(process_run, run_id, upload_path, provider_models, runtime_env_values, runtime_network_policy, build_mode_policy, allow_install_scripts, cache_policy_value, delete_build_image_after_run)
    return _run_summary_or_404(run_id)


@app.get("/api/runs/{run_id}", response_model=RunSummary)
def get_run(run_id: str) -> RunSummary:
    return _run_summary_or_404(run_id)


@app.get("/api/runs/{run_id}/events")
def get_events(run_id: str) -> dict[str, Any]:
    if not STORE.get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    return {"run_id": run_id, "events": STORE.list_events(run_id)}


@app.get("/api/runs/{run_id}/report")
def get_report(run_id: str) -> dict[str, Any]:
    report = STORE.get_report(run_id)
    if report is None:
        if STORE.get_run(run_id):
            raise HTTPException(status_code=409, detail="Report is not ready")
        raise HTTPException(status_code=404, detail="Run not found")
    return report


@app.get("/api/runs/{run_id}/report.md")
def get_markdown_report(run_id: str) -> Response:
    report = STORE.get_report(run_id)
    if report is None:
        if STORE.get_run(run_id):
            raise HTTPException(status_code=409, detail="Report is not ready")
        raise HTTPException(status_code=404, detail="Run not found")
    markdown = report.get("markdown_report") or report_to_markdown(report)
    filename = f"aegisagent-report-{run_id}.md"
    return Response(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/image-reserve")
def get_image_reserve() -> dict[str, Any]:
    return image_reserve_status()


async def process_run(
    run_id: str,
    upload_path: Path,
    providers: list[LLMProvider],
    runtime_env: dict[str, str] | None = None,
    runtime_network: str = "none",
    build_mode: str = "auto",
    allow_install_scripts: bool = True,
    cache_policy: str = "use",
    delete_build_image_after_run: bool = False,
) -> None:
    profile = None
    attack_plan = None
    evidence: dict[str, Any] = {}
    failures: list[dict[str, Any]] = []
    rule_findings = []
    llm_findings = []
    dynamic_status = "static_only"
    llm_status = "llm_disabled" if not providers else "llm_enabled"
    try:
        STORE.update_run(run_id, status="running", stage="ingest", llm_status=llm_status)
        STORE.add_event(run_id, "ingest", "info", "Extracting uploaded zip")
        workspace = upload_path.parent
        ingest = safe_extract_zip(upload_path, workspace)
        for warning in ingest.warnings:
            STORE.add_event(run_id, "ingest", "warning", warning)
        STORE.add_event(run_id, "ingest", "info", "Zip extracted", {"files": ingest.file_count, "bytes": ingest.total_bytes, "root": str(ingest.root_dir)})

        STORE.update_run(run_id, stage="static_scan")
        STORE.add_event(run_id, "static_scan", "info", "Scanning project structure and risky patterns")
        profile, rule_findings, evidence_bundle = scan_project(ingest.root_dir)
        STORE.update_run(run_id, profile_json=profile.model_dump_json())
        STORE.add_event(run_id, "static_scan", "info", "Static scan completed", {"languages": profile.languages, "frameworks": profile.frameworks, "findings": len(rule_findings)})

        audits = []
        if providers:
            STORE.update_run(run_id, stage="llm_audit")
            STORE.add_event(run_id, "llm_audit", "info", "Running optional LLM audit", {"providers": len(providers)})
            llm_findings, audits = await audit_with_llms(evidence_bundle, providers)
            ok_count = sum(1 for item in audits if item.get("ok"))
            llm_status = "llm_enabled" if ok_count or not audits else "llm_failed"
            STORE.update_run(run_id, llm_status=llm_status)
            STORE.add_event(run_id, "llm_audit", "info", "LLM audit completed", {"ok": ok_count, "failed": len(audits) - ok_count, "findings": len(llm_findings)})
            llm_plan_candidates, llm_plan_attempts = await plan_builds_with_llm(evidence_bundle, providers)
            if llm_plan_candidates:
                profile.adapter_matches = sort_candidate_dicts([*llm_plan_candidates, *profile.adapter_matches])
                profile.run_candidates = profile.adapter_matches
                profile.selected_adapter = profile.adapter_matches[0]
                STORE.update_run(run_id, profile_json=profile.model_dump_json())
            evidence["llm_build_plans"] = _sanitize_llm_build_plans(llm_plan_attempts, llm_plan_candidates)
            STORE.add_event(run_id, "llm_build_plan", "info", "Optional LLM BuildPlan planning completed", {"candidates": len(llm_plan_candidates), "attempts": len(llm_plan_attempts)})
        evidence["llm_audits"] = _sanitize_llm_audits(audits)

        all_pre_dynamic_findings = merge_findings(rule_findings, llm_findings, {})
        if providers:
            attack_plan = await plan_attacks_with_llm(evidence_bundle, all_pre_dynamic_findings, providers)
        if attack_plan is None:
            attack_plan = default_attack_plan(all_pre_dynamic_findings)
        attack_plan = validate_attack_plan(attack_plan)
        STORE.add_event(run_id, "attack_plan", "info", "Attack plan prepared", {"source": attack_plan.source, "steps": [step.type for step in attack_plan.steps]})

        STORE.update_run(run_id, stage="dynamic_sandbox")
        STORE.add_event(run_id, "dynamic_sandbox", "info", "Attempting dynamic execution in Docker sandbox", {"runtime_network": runtime_network, "build_mode": build_mode, "cache_policy": cache_policy, "delete_build_image_after_run": delete_build_image_after_run})
        sandbox_result = await asyncio.to_thread(run_dynamic_sandbox, ingest.root_dir, workspace, profile, attack_plan, runtime_env or {}, runtime_network, build_mode, allow_install_scripts, cache_policy, delete_build_image_after_run)
        dynamic_status = sandbox_result.status
        STORE.update_run(run_id, dynamic_status=dynamic_status)
        STORE.add_event(run_id, "dynamic_sandbox", "info" if dynamic_status == "dynamic_completed" else "warning", "Dynamic sandbox finished", {"status": dynamic_status, "runner": sandbox_result.runner, "build_status": (sandbox_result.build_result or {}).get("status"), "cache_hit": (sandbox_result.build_result or {}).get("cache_hit"), "image_cleanup": sandbox_result.image_cleanup})
        failures.extend(sandbox_result.failures)
        evidence.update(
            {
                "adapter": sandbox_result.adapter,
                "install_logs": sandbox_result.install_logs,
                "run_logs": sandbox_result.run_logs,
                "interactions": sandbox_result.interactions,
                "file_diff": sandbox_result.file_diff,
                "canary_hits": sandbox_result.canary_hits,
                "network_events": sandbox_result.network_events,
                "fake_environment": sandbox_result.fake_environment,
                "runtime_env_keys": sorted((runtime_env or {}).keys()),
                "runtime_network": runtime_network,
                "build_plan": sandbox_result.build_plan,
                "build_result": sandbox_result.build_result,
                "launch": sandbox_result.launch,
                "build_status": (sandbox_result.build_result or {}).get("status"),
                "cache_hit": (sandbox_result.build_result or {}).get("cache_hit"),
                "cache_key": (sandbox_result.build_plan or {}).get("cache_key"),
                "delete_build_image_after_run": delete_build_image_after_run,
                "image_cleanup": sandbox_result.image_cleanup,
                "failure_class": next((failure.get("failure_class") for failure in sandbox_result.failures if failure.get("failure_class")), None),
                "suggested_fix": next((failure.get("suggested_fix") for failure in sandbox_result.failures if failure.get("suggested_fix")), None),
                "requires_runtime_api_key": _requires_runtime_api_key(sandbox_result.failures, sandbox_result.run_logs + sandbox_result.interactions),
            }
        )

        findings = merge_findings(rule_findings, llm_findings, evidence)
        report = build_report(
            run_id=run_id,
            status="completed",
            dynamic_status=dynamic_status,
            llm_status=llm_status,
            profile=profile,
            findings=findings,
            attack_plan=attack_plan,
            evidence=evidence,
            failures=failures,
        )
        STORE.update_run(
            run_id,
            status="completed",
            stage="completed",
            dynamic_status=dynamic_status,
            llm_status=llm_status,
            risk_level=report.risk_level,
            report_json=report_to_json(report),
        )
        STORE.add_event(run_id, "completed", "info", "Report generated", {"risk_level": report.risk_level})
    except IngestError as exc:
        await _fail_run(run_id, "ingest", str(exc), profile, dynamic_status, llm_status, evidence, failures)
    except Exception as exc:  # noqa: BLE001 - background task should produce a report
        await _fail_run(run_id, "internal", str(exc), profile, dynamic_status, llm_status, evidence, failures)


async def _fail_run(
    run_id: str,
    stage: str,
    reason: str,
    profile: Any,
    dynamic_status: str,
    llm_status: str,
    evidence: dict[str, Any],
    failures: list[dict[str, Any]],
) -> None:
    failures.append({"stage": stage, "reason": reason[:1000]})
    report = build_report(
        run_id=run_id,
        status="failed",
        dynamic_status=dynamic_status,
        llm_status=llm_status,
        profile=profile,
        findings=[],
        attack_plan=None,
        evidence=evidence,
        failures=failures,
    )
    STORE.update_run(run_id, status="failed", stage=stage, dynamic_status=dynamic_status, llm_status=llm_status, risk_level=report.risk_level, report_json=report_to_json(report))
    STORE.add_event(run_id, stage, "error", "Run failed", {"reason": reason[:500]})


def _parse_providers(raw: str | None) -> list[LLMProvider]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("providers must be a JSON array")
        return [LLMProvider(**item) for item in data]
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid providers: {exc}") from exc


def _load_providers(raw: str | None) -> list[LLMProvider]:
    parsed = _parse_providers(raw)
    if parsed:
        return parsed
    import os

    api_key = os.getenv("SANDBOX_LLM_API_KEY")
    model = os.getenv("SANDBOX_LLM_MODEL")
    if not api_key or not model:
        return []
    return [
        LLMProvider(
            provider=os.getenv("SANDBOX_LLM_PROVIDER", "openai-compatible"),
            base_url=os.getenv("SANDBOX_LLM_BASE_URL"),
            api_key=api_key,
            model=model,
            role=os.getenv("SANDBOX_LLM_ROLE", "audit"),
        )
    ]


def _load_runtime_env(raw: str | None) -> dict[str, str]:
    parsed = _parse_runtime_env(raw)
    if parsed:
        return parsed
    import os

    keys = [
        "OPENAI_API_KEY",
        "OPENAI_API_BASE_URL",
        "OPENAI_API_ENDPOINT",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL_NAME",
        "OPENAI_API_MODEL",
        "MODEL_NAME",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_API_ENDPOINT",
        "DEEPSEEK_MODEL",
        "SILICONFLOW_API_KEY",
        "SILICONFLOW_BASE_URL",
        "SILICONFLOW_API_ENDPOINT",
        "SILICONFLOW_MODEL",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "LLM_API_ENDPOINT",
        "LLM_MODEL",
        "GITHUB_TOKEN",
    ]
    return {key: os.getenv(f"SANDBOX_RUNTIME_{key}") for key in keys if os.getenv(f"SANDBOX_RUNTIME_{key}")}


def _load_runtime_network(raw: str | None, runtime_env: dict[str, str] | None = None) -> str:
    import os

    value = raw or os.getenv("SANDBOX_RUNTIME_NETWORK", "auto")
    value = value.strip().lower()
    if value == "auto":
        return "bridge" if _runtime_env_needs_external_network(runtime_env or {}) else "sandbox"
    if value in {"none", "bridge", "sandbox"}:
        return value
    raise HTTPException(status_code=400, detail="runtime_network must be 'auto', 'sandbox', 'none', or 'bridge'")


def _runtime_env_needs_external_network(runtime_env: dict[str, str]) -> bool:
    keys = {
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "SILICONFLOW_API_KEY",
        "LLM_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE_URL",
        "OPENAI_API_ENDPOINT",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_API_ENDPOINT",
        "SILICONFLOW_BASE_URL",
        "SILICONFLOW_API_ENDPOINT",
        "LLM_BASE_URL",
        "LLM_API_ENDPOINT",
    }
    return any(runtime_env.get(key) for key in keys)


def _load_build_mode(raw: str | None) -> str:
    value = (raw or "auto").strip().lower()
    if value in {"auto", "strict", "sandbox_yaml_only"}:
        return value
    raise HTTPException(status_code=400, detail="build_mode must be 'auto', 'strict', or 'sandbox_yaml_only'")


def _load_cache_policy(raw: str | None) -> str:
    value = (raw or "use").strip().lower()
    if value in {"use", "rebuild", "disabled"}:
        return value
    raise HTTPException(status_code=400, detail="cache_policy must be 'use', 'rebuild', or 'disabled'")


def _parse_runtime_env(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("runtime_env must be a JSON object")
        return {str(key): str(value) for key, value in data.items() if isinstance(key, str)}
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid runtime_env: {exc}") from exc


def _run_summary_or_404(run_id: str) -> RunSummary:
    row = STORE.get_run(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunSummary(
        id=row["id"],
        status=row["status"],
        stage=row["stage"],
        input_name=row["input_name"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        dynamic_status=row["dynamic_status"],
        llm_status=row["llm_status"],
        risk_level=row["risk_level"],
    )


def _sanitize_llm_audits(audits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = []
    for audit in audits:
        cleaned.append(
            {
                "provider": audit.get("provider"),
                "model": audit.get("model"),
                "mode": audit.get("mode"),
                "ok": audit.get("ok"),
                "error": audit.get("error"),
            }
        )
    return cleaned


def _sanitize_llm_build_plans(attempts: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "attempts": _sanitize_llm_audits(attempts),
        "candidate_count": len(candidates),
        "candidates": [
            {
                "name": item.get("name"),
                "kind": item.get("kind"),
                "language": item.get("language"),
                "framework": item.get("framework"),
                "protocol": item.get("protocol"),
                "confidence": item.get("confidence"),
                "reason": item.get("reason"),
            }
            for item in candidates[:6]
        ],
    }


def _requires_runtime_api_key(failures: list[dict[str, Any]], logs: list[dict[str, Any]]) -> bool:
    text = json.dumps({"failures": failures, "logs": logs}, ensure_ascii=False).lower()
    needles = ("api key", "apikey", "openai_api_key", "anthropic_api_key", "authenticationerror", "unauthorized", "missing credentials", "litellm")
    return any(needle in text for needle in needles)
