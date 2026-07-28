from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import tempfile
import traceback
import urllib.request
from urllib.parse import unquote, urljoin, urlparse
import uuid
import zipfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


RESOURCE_SKILL_COPY_DIRS = {
    ".next",
    ".nuxt",
    "assets",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "public",
    "site",
    "static",
    "www",
}


def main() -> int:
    try:
        request_path = Path(sys.argv[1]).resolve()
        request = json.loads(request_path.read_text(encoding="utf-8-sig"))
        provloom_root = Path(request["provloomRoot"]).resolve()
        work_root = Path(request["workRoot"]).resolve()
        tmp_root = work_root / "tmp"
        tmp_root.mkdir(parents=True, exist_ok=True)
        os.environ["TMPDIR"] = str(tmp_root)
        tempfile.tempdir = str(tmp_root)
        sys.path.insert(0, str(provloom_root))
        os.chdir(provloom_root)

        from app.analyzer.rules import analyze_static_skill, analyze_trace
        from app.backend.schemas import LLMConfig
        from app.reporting.risk_mapper import map_risk_profile
        from app.runtime.skill_parser import load_skill_definition
        from app.runner.docker_runner import DockerRunner
        from app.telemetry.collector import build_execution_report

        execution_id = uuid.uuid4().hex
        source_dir = work_root / "uploads" / execution_id
        source_dir.mkdir(parents=True, exist_ok=True)
        skill_specs = prepare_skill_sources(request, source_dir)

        llm_config = LLMConfig.from_dict(request.get("llmConfig") or {})
        runner = DockerRunner(
            dockerfile_dir="docker/sandbox",
            artifacts_root=str(work_root / "runs"),
        )
        results = []
        prepared_root = work_root / "prepared" / execution_id
        for index, skill_spec in enumerate(skill_specs, start=1):
            skill_path = isolate_skill_source(skill_spec, prepared_root, index)
            run_id = execution_id if len(skill_specs) == 1 else f"{execution_id}-{index}"
            try:
                results.append(run_one_skill(
                    runner=runner,
                    execution_id=run_id,
                    skill_path=skill_path,
                    request=request,
                    llm_config=llm_config,
                    analyze_trace=analyze_trace,
                    build_execution_report=build_execution_report,
                    map_risk_profile=map_risk_profile,
                ))
            except Exception as exc:
                results.append(build_failed_skill_result(
                    execution_id=run_id,
                    skill_path=skill_path,
                    request=request,
                    error=exc,
                    analyze_static_skill=analyze_static_skill,
                    load_skill_definition=load_skill_definition,
                    map_risk_profile=map_risk_profile,
                ))

        result = results[0] if len(results) == 1 else aggregate_results(execution_id, results, request)
        print(json.dumps({"ok": True, "result": json_ready(result)}, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "message": str(exc),
            "traceback": traceback.format_exc(limit=12),
        }, ensure_ascii=False))
        return 1


def run_one_skill(
    *,
    runner: Any,
    execution_id: str,
    skill_path: Path,
    request: dict[str, Any],
    llm_config: Any,
    analyze_trace: Any,
    build_execution_report: Any,
    map_risk_profile: Any,
) -> dict[str, Any]:
    restore_skill_entry(skill_path)
    execution = runner.run(
        execution_id=execution_id,
        skill_path=str(skill_path),
        input_payload=request.get("inputPayload") or {},
        timeout_seconds=int(request.get("timeoutSeconds") or 45),
        network_policy=request.get("networkPolicy") or "default",
        llm_config=llm_config,
    )
    report = analyze_trace(execution, analysis_mode=request.get("analysisMode") or "rule_plus_epg")
    telemetry_report = build_execution_report(execution)
    apply_behavior_score_floor(report)
    risk_profile = map_risk_profile(
        risk_score=report["risk_score"],
        detected_behaviors=report["detected_behaviors"],
    )
    runtime_failure = summarize_runtime_failure(execution, report, telemetry_report)
    if runtime_failure:
        report["detected_behaviors"] = sorted(set(report.get("detected_behaviors", [])) | {"runtime_incomplete"})
        risk_profile = {
            "risk_level": "unknown",
            "risk_level_name": "检测未完成",
            "primary_risk": {
                "code": runtime_failure["code"],
                "name": runtime_failure["title"],
                "description": runtime_failure["message"],
                "severity": "unknown",
            },
            "risk_labels": [],
            "risk_summary": runtime_failure["message"],
        }

    result = {
        "executionId": execution_id,
        "status": "completed",
        "executionStatus": "failed" if runtime_failure else "completed",
        "runtimeFailure": runtime_failure,
        "skillName": Path(execution.skill_path).name,
        "skillPath": execution.skill_path,
        "skillFile": execution.skill_file,
        "sandboxImage": execution.sandbox_image,
        "runtimeName": execution.runtime_name,
        "networkPolicy": request.get("networkPolicy") or "default",
        "analysisMode": request.get("analysisMode") or "rule_plus_epg",
        "exitCode": execution.exit_code,
        "timedOut": execution.timed_out,
        "stdout": execution.stdout,
        "stderr": execution.stderr,
        "artifactsDir": getattr(execution, "artifacts_dir", ""),
        "traceSummary": report.get("trace_summary", {}),
        "riskScore": report.get("risk_score", 0),
        "riskLevel": risk_profile.get("risk_level", "unknown"),
        "riskLevelName": risk_profile.get("risk_level_name", "未知"),
        "primaryRisk": risk_profile.get("primary_risk", {}),
        "riskLabels": risk_profile.get("risk_labels", []),
        "riskSummary": risk_profile.get("risk_summary", ""),
        "detectedBehaviors": report.get("detected_behaviors", []),
        "evidenceTimeline": report.get("evidence_timeline", []),
        "fileEvents": telemetry_report.get("file_events", []),
        "networkEvents": telemetry_report.get("network_events", []),
        "processEvents": telemetry_report.get("process_events", []),
        "toolCalls": telemetry_report.get("tool_calls", []),
        "llmEvents": telemetry_report.get("llm_events", []),
        "dataFlows": telemetry_report.get("data_flows", []),
        "resourceUsage": execution.resource_usage.to_dict(),
        "primaryChain": report.get("primary_chain", []),
        "rootCause": report.get("root_cause", "unknown"),
        "rootCauseDetail": report.get("root_cause_detail", "unknown"),
        "graphSummary": report.get("graph_summary", {}),
        "finalDecision": report.get("final_decision", "unknown"),
        "triggeredFactors": report.get("triggered_factors", []),
        "suppressionFactors": report.get("suppression_factors", []),
        "decisionEvidence": report.get("decision_evidence", {}),
        "capabilityProfile": report.get("capability_profile", {}),
        "capabilityTags": report.get("capability_tags", []),
        "triggerPlan": report.get("trigger_plan", {}),
        "triggerUsed": report.get("trigger_used", []),
        "triggerHits": report.get("trigger_hits", []),
        "triggerUnexecuted": report.get("trigger_unexecuted", []),
        "severityLabel": report.get("severity_label", ""),
        "evidenceStrength": report.get("evidence_strength", ""),
        "decisionRationale": report.get("decision_rationale", {}),
    }
    result["markdownReport"] = build_markdown_report(result)
    result["markdown_report"] = result["markdownReport"]
    return result


def aggregate_results(execution_id: str, results: list[dict[str, Any]], request: dict[str, Any]) -> dict[str, Any]:
    max_result = max(results, key=lambda item: int(item.get("riskScore") or 0))
    completed = [item for item in results if item.get("executionStatus") == "completed"]
    failed = [item for item in results if item.get("executionStatus") == "failed"]
    behaviors = sorted({behavior for item in results for behavior in item.get("detectedBehaviors", [])})
    timeline = []
    for item in results:
        for event in item.get("evidenceTimeline", []):
            normalized_event = json_ready(event)
            if isinstance(normalized_event, dict):
                timeline.append({"skill": item.get("skillName") or item.get("skillFile"), **normalized_event})
            else:
                timeline.append({"skill": item.get("skillName") or item.get("skillFile"), "event": normalized_event})

    if failed and not completed:
        risk_level = "unknown"
        risk_level_name = "检测未完成"
        risk_summary = f"本次共检测 {len(results)} 个 Skill，但 {len(failed)} 个未完成运行。请先根据失败原因修复环境或模型配置，再复核安全结论。"
    elif failed:
        risk_level = max_result.get("riskLevel", "unknown")
        risk_level_name = "部分完成"
        risk_summary = f"本次共检测 {len(results)} 个 Skill，其中 {len(completed)} 个完成、{len(failed)} 个未完成。页面展示已完成样本的最高风险和失败原因。"
    else:
        risk_level = max_result.get("riskLevel", "unknown")
        risk_level_name = max_result.get("riskLevelName", "未知")
        risk_summary = f"本次共检测 {len(results)} 个 Skill，页面展示其中最高风险结果与合并行为证据。"

    result = {
        "executionId": execution_id,
        "status": "failed" if failed and not completed else "partial" if failed else "completed",
        "batch": True,
        "skillCount": len(results),
        "completedCount": len(completed),
        "failedCount": len(failed),
        "networkPolicy": request.get("networkPolicy") or "default",
        "analysisMode": request.get("analysisMode") or "rule_plus_epg",
        "riskScore": max_result.get("riskScore", 0),
        "riskLevel": risk_level,
        "riskLevelName": risk_level_name,
        "riskSummary": risk_summary,
        "detectedBehaviors": behaviors,
        "evidenceTimeline": timeline,
        "skillResults": results,
    }
    result["markdownReport"] = build_markdown_report(result)
    result["markdown_report"] = result["markdownReport"]
    return result


def build_failed_skill_result(
    *,
    execution_id: str,
    skill_path: Path,
    request: dict[str, Any],
    error: Exception,
    analyze_static_skill: Any | None = None,
    load_skill_definition: Any | None = None,
    map_risk_profile: Any | None = None,
) -> dict[str, Any]:
    if is_actionless_skill_error(error) and analyze_static_skill and load_skill_definition and map_risk_profile:
        try:
            return build_static_fallback_skill_result(
                execution_id=execution_id,
                skill_path=skill_path,
                request=request,
                analyze_static_skill=analyze_static_skill,
                load_skill_definition=load_skill_definition,
                map_risk_profile=map_risk_profile,
            )
        except Exception:
            pass

    runtime_failure = classify_prepare_or_runtime_error(error)
    result = {
        "executionId": execution_id,
        "status": "completed",
        "executionStatus": "failed",
        "runtimeFailure": runtime_failure,
        "skillName": skill_path.name,
        "skillPath": str(skill_path),
        "skillFile": "SKILL.md",
        "sandboxImage": "",
        "runtimeName": "",
        "networkPolicy": request.get("networkPolicy") or "default",
        "analysisMode": request.get("analysisMode") or "rule_plus_epg",
        "exitCode": None,
        "timedOut": False,
        "stdout": "",
        "stderr": str(error),
        "artifactsDir": "",
        "traceSummary": {},
        "riskScore": 0,
        "riskLevel": "unknown",
        "riskLevelName": "检测未完成",
        "primaryRisk": {
            "code": runtime_failure["code"],
            "name": runtime_failure["title"],
            "description": runtime_failure["message"],
            "severity": "unknown",
        },
        "riskLabels": [],
        "riskSummary": runtime_failure["message"],
        "detectedBehaviors": ["runtime_incomplete"],
        "evidenceTimeline": [],
        "fileEvents": [],
        "networkEvents": [],
        "processEvents": [],
        "toolCalls": [],
        "llmEvents": [],
        "dataFlows": [],
        "resourceUsage": {},
        "primaryChain": [],
        "rootCause": "runtime_incomplete",
        "rootCauseDetail": runtime_failure["message"],
        "graphSummary": {},
        "finalDecision": "incomplete",
        "triggeredFactors": [],
        "suppressionFactors": [],
        "decisionEvidence": {},
        "capabilityProfile": {},
        "capabilityTags": [],
        "triggerPlan": {},
        "triggerUsed": [],
        "triggerHits": [],
        "triggerUnexecuted": [],
        "severityLabel": "",
        "evidenceStrength": "",
        "decisionRationale": {},
    }
    result["markdownReport"] = build_markdown_report(result)
    result["markdown_report"] = result["markdownReport"]
    return result


def is_actionless_skill_error(error: Exception) -> bool:
    lowered = str(error or "").lower()
    return "does not define executable actions" in lowered or "skill-actions" in lowered


def build_static_fallback_skill_result(
    *,
    execution_id: str,
    skill_path: Path,
    request: dict[str, Any],
    analyze_static_skill: Any,
    load_skill_definition: Any,
    map_risk_profile: Any,
) -> dict[str, Any]:
    definition = load_skill_definition(skill_path, "SKILL.md", allow_empty_actions=True)
    report = analyze_static_skill(definition, analysis_mode=request.get("analysisMode") or "rule_plus_epg")
    heuristic = infer_actionless_text_risk(definition.raw_markdown)
    if heuristic["detected_behaviors"]:
        merged_behaviors = sorted(set(report.get("detected_behaviors", [])) | set(heuristic["detected_behaviors"]))
        report["detected_behaviors"] = merged_behaviors
        report["risk_score"] = max(int(report.get("risk_score") or 0), heuristic["risk_score"])
        report["evidence_timeline"] = list(report.get("evidence_timeline") or []) + heuristic["evidence_timeline"]
        trace_summary = dict(report.get("trace_summary") or {})
        trace_summary["text_heuristic_count"] = len(heuristic["detected_behaviors"])
        report["trace_summary"] = trace_summary
    risk_profile = map_risk_profile(
        risk_score=report.get("risk_score", 0),
        detected_behaviors=report.get("detected_behaviors", []),
    )
    summary = risk_profile.get("risk_summary", "") or "该 Skill 没有可执行动作定义，已降级为静态能力画像分析。"
    summary = f"静态降级完成：{summary}"
    result = {
        "executionId": execution_id,
        "status": "completed",
        "executionStatus": "completed",
        "runtimeFailure": None,
        "executionNote": {
            "code": "static_fallback_no_actions",
            "title": "动态动作缺失，已静态降级",
            "message": "SKILL.md 没有定义可执行的 ```skill-actions``` 动作数组；本次使用静态能力画像和规则分析生成评分。",
        },
        "skillName": skill_path.name,
        "skillPath": str(skill_path),
        "skillFile": "SKILL.md",
        "sandboxImage": "",
        "runtimeName": "static-fallback",
        "networkPolicy": request.get("networkPolicy") or "default",
        "analysisMode": request.get("analysisMode") or "rule_plus_epg",
        "exitCode": 0,
        "timedOut": False,
        "stdout": "",
        "stderr": "",
        "artifactsDir": "",
        "traceSummary": report.get("trace_summary", {}),
        "riskScore": report.get("risk_score", 0),
        "riskLevel": risk_profile.get("risk_level", "unknown"),
        "riskLevelName": risk_profile.get("risk_level_name", "未知"),
        "primaryRisk": risk_profile.get("primary_risk", {}),
        "riskLabels": risk_profile.get("risk_labels", []),
        "riskSummary": summary,
        "detectedBehaviors": report.get("detected_behaviors", []),
        "evidenceTimeline": report.get("evidence_timeline", []),
        "fileEvents": [],
        "networkEvents": [],
        "processEvents": [],
        "toolCalls": [],
        "llmEvents": [],
        "dataFlows": [],
        "resourceUsage": {},
        "primaryChain": report.get("primary_chain", []),
        "rootCause": report.get("root_cause", "unknown"),
        "rootCauseDetail": report.get("root_cause_detail", "unknown"),
        "graphSummary": report.get("graph_summary", {}),
        "finalDecision": report.get("final_decision", "static_fallback"),
        "triggeredFactors": report.get("triggered_factors", []),
        "suppressionFactors": report.get("suppression_factors", []),
        "decisionEvidence": report.get("decision_evidence", {}),
        "capabilityProfile": report.get("capability_profile", {}),
        "capabilityTags": report.get("capability_tags", []),
        "triggerPlan": report.get("trigger_plan", {}),
        "triggerUsed": report.get("trigger_used", []),
        "triggerHits": report.get("trigger_hits", []),
        "triggerUnexecuted": report.get("trigger_unexecuted", []),
        "severityLabel": report.get("severity_label", ""),
        "evidenceStrength": report.get("evidence_strength", ""),
        "decisionRationale": report.get("decision_rationale", {}),
    }
    result["markdownReport"] = build_markdown_report(result)
    result["markdown_report"] = result["markdownReport"]
    return result


def apply_behavior_score_floor(report: dict[str, Any]) -> None:
    behaviors = set(report.get("detected_behaviors") or [])
    if not behaviors:
        return

    weights = {
        "file_write": 25,
        "network_access": 35,
        "process_spawn": 35,
        "shell_execution": 60,
        "sensitive_file_read": 65,
        "read_then_exfiltration": 90,
        "execution_timeout": 20,
    }
    floor = max((weights.get(behavior, 10) for behavior in behaviors), default=0)
    if {"sensitive_file_read", "network_access"} <= behaviors:
        floor = max(floor, 80)
    if {"file_write", "process_spawn"} <= behaviors:
        floor = max(floor, 50)

    report["risk_score"] = max(int(report.get("risk_score") or 0), min(100, floor))


def infer_actionless_text_risk(markdown: str) -> dict[str, Any]:
    text = str(markdown or "").lower()
    detected: set[str] = set()
    timeline: list[dict[str, Any]] = []

    def hit(behavior: str, detail: str) -> None:
        detected.add(behavior)
        timeline.append({
            "timestamp": "static",
            "category": "static_text",
            "action": behavior,
            "detail": detail,
            "metadata": {"source": "actionless_skill_text_heuristic"},
        })

    network_markers = ("curl ", "http://", "https://", "api/", "websocket", "sse", "post ", "get ")
    command_markers = ("bash", "powershell", "shell", "subprocess", "terminal", "npm ", "python ", "execute command", "run command")
    mutation_markers = ("write", "create", "delete", "overwrite", "upload", "download", "export ", "-o ")
    sensitive_markers = (
        "~/.codex",
        "~/.claude",
        "~/.ssh",
        ".env",
        "api key",
        "secret",
        "credential",
        "token",
        "cookie",
        "private key",
        "session.jsonl",
        "agent history",
    )
    exfil_markers = ("upload", "webhook", "callback", "post ", "send to", "exfil", "external", "remote server")

    if any(marker in text for marker in network_markers):
        hit("network_access", "SKILL.md describes HTTP/API/network operations.")
    if any(marker in text for marker in command_markers):
        hit("process_spawn", "SKILL.md describes command-line or process execution.")
    if any(marker in text for marker in mutation_markers):
        hit("file_write", "SKILL.md describes write/create/delete/sync/export operations.")
    if any(marker in text for marker in sensitive_markers):
        hit("sensitive_file_read", "SKILL.md describes access to sessions, history, credentials, tokens, or local agent data.")
    if "sensitive_file_read" in detected and any(marker in text for marker in exfil_markers):
        hit("read_then_exfiltration", "Text combines sensitive/local data access with an explicit upload/callback/external send pattern.")

    weights = {
        "network_access": 12,
        "process_spawn": 18,
        "file_write": 16,
        "sensitive_file_read": 35,
        "read_then_exfiltration": 55,
    }
    score = min(75, sum(weights.get(item, 8) for item in detected))
    if "read_then_exfiltration" in detected:
        score = max(score, 70)
    return {
        "risk_score": score,
        "detected_behaviors": sorted(detected),
        "evidence_timeline": timeline,
    }


def classify_prepare_or_runtime_error(error: Exception) -> dict[str, str]:
    message = str(error or "").strip()
    lowered = message.lower()
    if "does not define executable actions" in lowered or "skill-actions" in lowered:
        return {
            "code": "skill_actions_missing",
            "title": "缺少可执行动作定义",
            "message": "SKILL.md 没有定义可执行的 ```skill-actions``` 动作数组，动态沙箱无法启动该样本。请补充动作定义，或将该样本按静态扫描处理。",
        }
    if "docker" in lowered and ("not available" in lowered or "not found" in lowered):
        return {
            "code": "docker_unavailable",
            "title": "Docker 不可用",
            "message": "当前环境无法调用 Docker CLI 或 Docker Engine，动态沙箱无法运行。",
        }
    return {
        "code": "runtime_failed",
        "title": "运行准备失败",
        "message": classify_runtime_blocker(message),
    }


def classify_runtime_blocker(stderr: str) -> str:
    lowered = str(stderr or "").lower()
    heavy_markers = (
        "playwright",
        "browser",
        "chrome",
        "chromium",
        "electron",
        "x server",
        "xvfb",
        "cuda",
        "gpu",
        "kubernetes",
        "kubectl",
        "terraform",
        "aws",
        "gcloud",
        "azure",
    )
    if any(marker in lowered for marker in heavy_markers):
        return "目标 Skill 依赖外部重型平台、浏览器/GPU/云平台或本机服务，当前轻量沙箱无法完整启动。请补充 sandbox.yaml、提供替身服务，或改用具备对应依赖的运行环境。"
    if "module not found" in lowered or "no module named" in lowered or "cannot find module" in lowered:
        return "目标 Skill 的运行依赖未安装或未声明，沙箱没有产生足够证据。请补充 package.json、requirements.txt 或 sandbox.yaml 后重试。"
    if "connection refused" in lowered or "name resolution" in lowered or "network is unreachable" in lowered:
        return "目标 Skill 需要访问外部网络或本地服务，但当前沙箱网络/服务不可达。请检查网络策略或提供可控替身服务。"
    return "目标 Skill 在动态沙箱中没有产生足够的运行证据。请查看执行线索中的错误输出，确认依赖、入口和模型配置是否完整。"


def build_markdown_report(result: dict[str, Any]) -> str:
    is_batch = bool(result.get("batch"))
    items = result.get("skillResults") if is_batch else [result]
    if not isinstance(items, list) or not items:
        items = [result]

    total = int(result.get("skillCount") or len(items) or 1)
    completed = int(result.get("completedCount") if result.get("completedCount") is not None else sum(1 for item in items if item.get("executionStatus") == "completed"))
    failed = int(result.get("failedCount") if result.get("failedCount") is not None else max(0, total - completed))
    score = int(result.get("riskScore") or 0)
    level = str(result.get("riskLevelName") or result.get("riskLevel") or "未知")
    summary = str(result.get("riskSummary") or "检测已完成，请结合证据进行人工复核。")

    lines = [
        "# Skill 动态沙箱检测报告",
        "",
        "## 总览",
        "",
        f"- 检测状态：{completed}/{total} 完成" + (f"，{failed} 个未完成" if failed else "，全部完成"),
        f"- 风险评分：{score}",
        f"- 风险等级：{level}",
        f"- 网络策略：{result.get('networkPolicy') or 'default'}",
        f"- 分析模式：{result.get('analysisMode') or 'rule_plus_epg'}",
        "",
        "## 结论",
        "",
        summary,
        "",
    ]

    behaviors = result.get("detectedBehaviors") or []
    if behaviors:
        lines.extend(["## 命中行为", ""])
        for behavior in behaviors[:12]:
            lines.append(f"- {format_behavior_label(behavior)}")
        lines.append("")

    failures = [item for item in items if item.get("executionStatus") == "failed" or item.get("runtimeFailure")]
    if failures:
        lines.extend(["## 未完成原因", ""])
        for item in failures:
            failure = item.get("runtimeFailure") or {}
            name = item.get("skillName") or item.get("skillFile") or "Skill"
            title = failure.get("title") or "运行未完成"
            message = failure.get("message") or "沙箱没有返回足够证据。"
            lines.append(f"- {name}：{title}。{message}")
        lines.append("")

    lines.extend(["## 样本结果", ""])
    for item in items[:20]:
        name = item.get("skillName") or item.get("skillFile") or "Skill"
        item_status = "完成" if item.get("executionStatus") == "completed" else "未完成"
        item_score = int(item.get("riskScore") or 0)
        item_level = item.get("riskLevelName") or item.get("riskLevel") or "未知"
        item_summary = item.get("riskSummary") or item.get("runtimeFailure", {}).get("message") or ""
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"- 状态：{item_status}")
        lines.append(f"- 分数：{item_score}")
        lines.append(f"- 等级：{item_level}")
        if item_summary:
            lines.append(f"- 摘要：{item_summary}")
        lines.append("")

    timeline = result.get("evidenceTimeline") or []
    if timeline:
        lines.extend(["## 执行线索", ""])
        for event in timeline[:12]:
            if isinstance(event, dict):
                text = event.get("summary") or event.get("message") or event.get("event") or event.get("action") or event.get("type") or json.dumps(event, ensure_ascii=False)[:180]
                prefix = f"{event.get('skill')}：" if event.get("skill") else ""
                lines.append(f"- {prefix}{text}")
            else:
                lines.append(f"- {event}")
        lines.append("")

    lines.extend([
        "## 复核建议",
        "",
        "- 高分或命中文件写入、进程启动、网络访问、敏感读取时，建议人工复核 SKILL.md、动作定义和运行证据。",
        "- 只有在“未完成原因”出现时，才把结果视为环境或外部依赖阻塞；否则以风险评分和命中行为为主要结论。",
    ])
    return "\n".join(lines).strip() + "\n"


def format_behavior_label(value: Any) -> str:
    key = str(value or "")
    labels = {
        "runtime_incomplete": "运行未完成",
        "network_connect": "网络连接行为",
        "file_read": "文件读取行为",
        "file_write": "文件写入行为",
        "process_spawn": "进程启动行为",
        "llm_request": "模型调用行为",
        "sensitive_file_read": "敏感文件读取",
        "read_then_exfiltration": "读取后外传链路",
        "unsafe_or_risky_command_execution": "高风险命令执行",
    }
    return labels.get(key, key.replace("_", " "))


def summarize_runtime_failure(execution: Any, report: dict[str, Any], telemetry_report: dict[str, Any]) -> dict[str, Any] | None:
    has_evidence = has_runtime_evidence(report, telemetry_report)
    if execution.timed_out:
        if has_evidence:
            return None
        return {
            "code": "execution_timeout",
            "title": "运行超时",
            "message": "目标 Skill 未在限定时间内完成，当前结果不能作为低风险结论。请缩短执行入口或提高超时时间后重试。",
        }

    exit_code = int(execution.exit_code or 0)
    if exit_code == 0:
        return None

    stderr = str(execution.stderr or "")
    lowered = stderr.lower()
    if "api key is invalid" in lowered or "http 401" in lowered or "unauthorized" in lowered:
        return {
            "code": "llm_auth_failed",
            "title": "智能分析鉴权失败",
            "message": "LLM 访问密钥无效或服务返回 401。请检查模型服务地址、模型名称和访问密钥。",
        }
    if "skill.md not found" in lowered or "no skill.md" in lowered:
        return {
            "code": "skill_entry_missing_at_runtime",
            "title": "运行时未找到 SKILL.md",
            "message": "沙箱运行目录中没有可识别的 SKILL.md。请上传完整 Skill 目录压缩包、直接上传 SKILL.md，或提供可下载的源码/压缩包 URL。",
        }

    if has_evidence:
        return None

    return {
        "code": "runtime_failed",
        "title": "运行失败",
        "message": "目标 Skill 在动态沙箱中没有产生足够的运行证据。请查看执行线索中的错误输出，确认依赖、入口和模型配置是否完整。",
    }


def has_runtime_evidence(report: dict[str, Any], telemetry_report: dict[str, Any]) -> bool:
    evidence_timeline = report.get("evidence_timeline") or []
    detected_behaviors = [item for item in report.get("detected_behaviors", []) if item != "runtime_incomplete"]
    telemetry_keys = ("file_events", "network_events", "process_events", "tool_calls", "llm_events", "data_flows")
    telemetry_count = sum(len(telemetry_report.get(key) or []) for key in telemetry_keys)
    return bool(evidence_timeline or detected_behaviors or telemetry_count)


def prepare_skill_sources(request: dict[str, Any], source_dir: Path) -> list[dict[str, Any]]:
    files = request.get("files") or []
    for item in files:
        name = str(item.get("name") or "upload.bin")
        raw = base64.b64decode(str(item.get("contentBase64") or ""))
        if name.lower().endswith(".zip"):
            zip_path = source_dir / safe_name(name)
            zip_path.write_bytes(raw)
            extract_zip(zip_path, source_dir)
            zip_path.unlink(missing_ok=True)
        else:
            relative = safe_relative_path(str(item.get("relativePath") or name))
            target = source_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

    source_url = str(request.get("sourceUrl") or "").strip()
    if source_url:
        prepare_source_url(source_url, source_dir)

    skill_files = find_skill_files(source_dir)
    if not skill_files:
        markdown_files = sorted(source_dir.rglob("*.md"))
        if len(markdown_files) == 1:
            skill_files = [normalize_skill_filename(markdown_files[0])]

    if len(skill_files) == 1:
        return build_skill_specs(skill_files)
    if not skill_files:
        if has_skill_metadata_without_entry(source_dir):
            raise ValueError(
                "已找到 Skill 相关元数据，但没有发现 SKILL.md。请上传包含 SKILL.md 的完整 Skill 目录压缩包，或直接上传 SKILL.md 文件。"
            )
        sample_files = list_relative_files(source_dir, limit=12)
        suffix = f" 已发现文件：{', '.join(sample_files)}" if sample_files else ""
        raise ValueError(f"未在上传内容中找到 SKILL.md。请上传包含 SKILL.md 的完整技能目录压缩包，或直接上传 SKILL.md 文件。{suffix}")
    return build_skill_specs(skill_files)


def find_skill_files(source_dir: Path) -> list[Path]:
    candidates = sorted(
        path
        for path in source_dir.rglob("*")
        if path.is_file() and path.name.lower() == "skill.md" and is_probable_skill_entry(path)
    )
    candidates = filter_embedded_skill_copies(candidates)
    return [normalize_skill_filename(path) for path in candidates]


def is_probable_skill_entry(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    lowered = text[:4096].lower()
    return (
        text.startswith("---")
        or "```skill-actions" in lowered
        or ("name:" in lowered and "description:" in lowered)
        or ("# " in text[:512] and "skill" in lowered)
    )


def filter_embedded_skill_copies(candidates: list[Path]) -> list[Path]:
    if len(candidates) <= 1:
        return candidates

    direct_skill_dirs = {path.parent.resolve() for path in candidates}
    selected: list[Path] = []
    for candidate in candidates:
        resolved_parent = candidate.parent.resolve()
        if is_inside_resource_copy_dir(candidate) and has_ancestor_skill_dir(resolved_parent, direct_skill_dirs):
            continue
        selected.append(candidate)

    return selected or candidates


def is_inside_resource_copy_dir(path: Path) -> bool:
    return any(part.lower() in RESOURCE_SKILL_COPY_DIRS for part in path.parts)


def has_ancestor_skill_dir(parent: Path, skill_dirs: set[Path]) -> bool:
    for ancestor in parent.parents:
        if ancestor in skill_dirs:
            return True
    return False


def has_skill_metadata_without_entry(source_dir: Path) -> bool:
    return any(path.is_file() and path.name.lower() in {"_meta.json", "skill.json"} for path in source_dir.rglob("*"))


def build_skill_specs(skill_files: list[Path]) -> list[dict[str, Any]]:
    return [
        {
            "path": skill_file,
            "entry_bytes": skill_file.read_bytes(),
        }
        for skill_file in skill_files
    ]


def isolate_skill_source(spec: dict[str, Any], prepared_root: Path, index: int) -> Path:
    prepared_root.mkdir(parents=True, exist_ok=True)
    skill_file = Path(spec["path"])
    entry_bytes = bytes(spec["entry_bytes"])
    skill_dir = skill_file.parent
    target = prepared_root / f"{index:03d}-{safe_name(skill_dir.name)}"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(skill_dir, target)
    target_skill = target / "SKILL.md"
    target_skill.write_bytes(entry_bytes)
    backup_skill = prepared_root / f"{target.name}.SKILL.md"
    backup_skill.write_bytes(entry_bytes)
    return target


def restore_skill_entry(skill_path: Path) -> None:
    if any(path.is_file() and path.name.lower() == "skill.md" for path in skill_path.iterdir()):
        return
    backup_skill = skill_path.parent / f"{skill_path.name}.SKILL.md"
    if backup_skill.exists():
        (skill_path / "SKILL.md").write_bytes(backup_skill.read_bytes())


def normalize_skill_filename(path: Path) -> Path:
    target = path.parent / "SKILL.md"
    if path == target:
        return path
    if target.exists():
        return target
    path.rename(target)
    return target


def list_relative_files(source_dir: Path, limit: int = 12) -> list[str]:
    result: list[str] = []
    for path in sorted(item for item in source_dir.rglob("*") if item.is_file()):
        try:
            result.append(str(path.relative_to(source_dir)).replace("\\", "/"))
        except ValueError:
            result.append(path.name)
        if len(result) >= limit:
            break
    return result


def prepare_source_url(source_url: str, source_dir: Path) -> None:
    if not source_url.startswith(("http://", "https://")):
        raise ValueError("URL 输入仅支持 http:// 或 https:// 地址。")

    errors: list[str] = []
    for candidate_url in candidate_source_urls(source_url):
        try:
            downloaded = download_source(candidate_url, source_dir)
            if consume_downloaded_source(downloaded, source_dir, source_url):
                return
        except Exception as exc:
            errors.append(f"{candidate_url}: {exc}")

    detail = f" 尝试过：{'; '.join(errors[:3])}" if errors else ""
    raise ValueError(f"无法从 URL 读取 Skill。请提供 GitHub 仓库/blob/raw 链接、可下载 zip，或原始 SKILL.md 地址。{detail}")


def candidate_source_urls(source_url: str) -> list[str]:
    parsed = urlparse(source_url)
    host = (parsed.hostname or "").lower()
    path_parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]

    if host == "github.com" and len(path_parts) >= 2:
        owner, repo = path_parts[0], path_parts[1].removesuffix(".git")
        if len(path_parts) >= 5 and path_parts[2] == "blob":
            branch = path_parts[3]
            raw_path = "/".join(path_parts[4:])
            return [f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{raw_path}", source_url]
        if len(path_parts) >= 5 and path_parts[2] == "tree":
            branch = path_parts[3]
            return [f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}", source_url]
        return [
            f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/main",
            f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/master",
            f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip",
            f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip",
            source_url,
        ]

    return [source_url]


def download_source(url: str, source_dir: Path) -> Path:
    filename = source_filename_from_url(url)
    target = source_dir / filename
    request = urllib.request.Request(url, headers={"User-Agent": "ClawGuard-ProvLoom/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if "zip" in content_type and not target.name.lower().endswith(".zip"):
            target = target.with_suffix(".zip")
        with target.open("wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
    return target


def consume_downloaded_source(downloaded: Path, source_dir: Path, original_url: str) -> bool:
    if is_zip_file(downloaded):
        extract_zip(downloaded, source_dir)
        downloaded.unlink(missing_ok=True)
        return True

    text = read_text_if_possible(downloaded)
    if text and looks_like_html(text):
        links = discover_skill_links(text, original_url)
        downloaded.unlink(missing_ok=True)
        for link in links[:8]:
            try:
                nested = download_source(link, source_dir)
                if consume_downloaded_source(nested, source_dir, link):
                    return True
            except Exception:
                continue
        return False

    if downloaded.suffix.lower() in {".md", ".markdown", ".txt"} or downloaded.name.lower() == "skill.md":
        target = source_dir / "SKILL.md"
        if downloaded.resolve() != target.resolve():
            if target.exists():
                target = source_dir / safe_name(downloaded.name or "SKILL.md")
            downloaded.rename(target)
        return True

    return False


def source_filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    name = unquote(Path(parsed.path).name or "remote-skill")
    if parsed.hostname and parsed.hostname.lower() == "codeload.github.com":
        parts = parsed.path.strip("/").split("/")[:2]
        name = f"{safe_name('-'.join(parts) or 'github-repo')}.zip"
    if "." not in name:
        name = f"{name}.html"
    return safe_name(name)


def is_zip_file(path: Path) -> bool:
    if path.suffix.lower() == ".zip":
        return True
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def read_text_if_possible(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_like_html(text: str) -> bool:
    sample = text[:4096].lstrip().lower()
    return sample.startswith("<!doctype html") or sample.startswith("<html") or ("<body" in sample and "<a " in sample)


def discover_skill_links(html: str, base_url: str) -> list[str]:
    hrefs = re.findall(r"""href=[\"']([^\"']+)[\"']""", html, flags=re.IGNORECASE)
    candidates = []
    for href in hrefs:
        full = urljoin(base_url, href)
        lower = full.lower()
        if "skill.md" in lower or lower.endswith(".zip") or "/archive/refs/heads/" in lower:
            candidates.append(github_blob_to_raw(full))
    return sorted(set(candidates), key=lambda item: (0 if "raw.githubusercontent.com" in item else 1, item))


def github_blob_to_raw(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    if host == "github.com" and len(parts) >= 5 and parts[2] == "blob":
        return f"https://raw.githubusercontent.com/{parts[0]}/{parts[1].removesuffix('.git')}/{parts[3]}/{'/'.join(parts[4:])}"
    return url


def extract_zip(zip_path: Path, target_dir: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            relative = safe_relative_path(member.filename)
            target = target_dir / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
            except OSError:
                if target.name.lower() == "skill.md":
                    raise
                continue


def safe_relative_path(value: str) -> Path:
    clean_parts = []
    for part in Path(value.replace("\\", "/")).parts:
        if part in {"", ".", ".."}:
            continue
        clean_parts.append(safe_name(part))
    if not clean_parts:
        return Path("upload.bin")
    return Path(*clean_parts)


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in value).strip() or "upload"


def json_ready(value: Any) -> Any:
    if is_dataclass(value):
        return json_ready(asdict(value))
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_ready(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


if __name__ == "__main__":
    raise SystemExit(main())
