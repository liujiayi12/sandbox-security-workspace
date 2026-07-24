from __future__ import annotations

import json
import argparse
import shutil
import os
import subprocess
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any

from .attack import default_attack_plan
from .sandbox import docker_available, run_dynamic_sandbox
from .static_scan import scan_project

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE_DIR = Path(__file__).resolve().parents[1]
LOCAL_SAMPLE_DIR = PROJECT_ROOT / "real_samples"
REAL_WORLD_RUNS_DIR = BASE_DIR / ".sandbox_data" / "real_world_runs"

SAMPLES = [
    {
        "name": "modelcontextprotocol-servers",
        "url": "https://github.com/modelcontextprotocol/servers.git",
        "zip_url": "https://github.com/modelcontextprotocol/servers/archive/refs/heads/main.zip",
        "local_zips": ["servers-main.zip", "modelcontextprotocol-servers.zip"],
        "kind": "mcp",
    },
    {
        "name": "crewai-examples",
        "url": "https://github.com/crewAIInc/crewAI-examples.git",
        "zip_url": "https://github.com/crewAIInc/crewAI-examples/archive/refs/heads/main.zip",
        "local_zips": ["crewAI-examples-main.zip", "crewai-examples.zip"],
        "kind": "crewai",
    },
]


def validate_real_world(limit: int = 2, dynamic: bool = True, sample_name: str | None = None) -> list[dict[str, Any]]:
    results = []
    docker_ok, docker_error = docker_available()
    base = REAL_WORLD_RUNS_DIR / uuid.uuid4().hex
    base.mkdir(parents=True, exist_ok=True)
    selected_samples = [sample for sample in SAMPLES if not sample_name or sample["name"] == sample_name or sample["kind"] == sample_name]
    for sample in selected_samples[:limit]:
        sample_dir = base / sample["name"]
        result: dict[str, Any] = {"sample": sample, "ok": False, "workspace": str(base)}
        clone_error = _fetch_sample(sample, sample_dir)
        if clone_error:
            result["failure"] = {"stage": "fetch", "reason": clone_error}
            results.append(result)
            continue
        roots = _candidate_roots(sample_dir, sample["kind"])
        root = roots[0] if roots else sample_dir
        scan_root = _prepare_validation_root(sample_dir, root, sample["kind"])
        profile, findings, _ = scan_project(scan_root)
        result.update(
            {
                "root": str(root.relative_to(sample_dir)),
                "scan_root": str(scan_root.relative_to(sample_dir)) if str(scan_root).startswith(str(sample_dir)) else str(scan_root),
                "languages": profile.languages,
                "frameworks": profile.frameworks,
                "protocols": profile.protocol_candidates,
                "selected_adapter": profile.selected_adapter,
                "adapter_count": len(profile.adapter_matches),
                "static_findings": len(findings),
            }
        )
        if not dynamic:
            result["ok"] = profile.selected_adapter is not None
            result["dynamic_status"] = "skipped"
            results.append(result)
            continue
        if not docker_ok:
            result["failure"] = {"stage": "docker", "reason": docker_error}
            results.append(result)
            continue
        sandbox_result = run_dynamic_sandbox(scan_root, base / f"run-{sample['name']}", profile, default_attack_plan(findings), _runtime_env_from_os(), _runtime_network_from_os())
        result.update(
                {
                    "dynamic_status": sandbox_result.status,
                    "build_status": (sandbox_result.build_result or {}).get("status"),
                    "cache_hit": (sandbox_result.build_result or {}).get("cache_hit"),
                    "failure_class": next((failure.get("failure_class") for failure in sandbox_result.failures if failure.get("failure_class")), None),
                    "adapter": sandbox_result.adapter,
                    "interactions": sandbox_result.interactions[:8],
                    "failures": sandbox_result.failures[:8],
                "ok": sandbox_result.status == "dynamic_completed" or profile.selected_adapter is not None,
            }
        )
        results.append(result)
    return results


def _fetch_sample(sample: dict[str, Any], sample_dir: Path) -> str | None:
    local_error = _fetch_local_zip(sample, sample_dir)
    if local_error is None:
        return None
    clone = subprocess.run(
        ["git", "-c", "http.version=HTTP/1.1", "clone", "--depth=1", sample["url"], str(sample_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if clone.returncode == 0:
        return None
    git_error = (clone.stderr or clone.stdout)[-1000:]
    zip_url = sample.get("zip_url")
    if not zip_url:
        return git_error
    try:
        zip_path = sample_dir.parent / f"{sample['name']}.zip"
        before = {path.resolve() for path in sample_dir.parent.iterdir() if path.is_dir()}
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(sample_dir.parent)
        after = {path.resolve() for path in sample_dir.parent.iterdir() if path.is_dir()}
        created = [Path(path) for path in after - before]
        if not created:
            return f"git failed: {git_error}; zip fallback failed: archive produced no directory"
        extracted = created[0]
        if sample_dir.exists():
            shutil.rmtree(sample_dir)
        shutil.move(str(extracted), sample_dir)
        return None
    except Exception as exc:  # noqa: BLE001
        return f"local failed: {local_error}; git failed: {git_error}; zip fallback failed: {exc}"


def _fetch_local_zip(sample: dict[str, Any], sample_dir: Path) -> str | None:
    for name in sample.get("local_zips", []):
        zip_path = LOCAL_SAMPLE_DIR / name
        if not zip_path.exists():
            continue
        try:
            before = {path.resolve() for path in sample_dir.parent.iterdir() if path.is_dir()}
            with zipfile.ZipFile(zip_path) as archive:
                archive.extractall(sample_dir.parent)
            after = {path.resolve() for path in sample_dir.parent.iterdir() if path.is_dir()}
            created = [Path(path) for path in after - before]
            if not created:
                return f"{zip_path} produced no directory"
            extracted = created[0]
            if sample_dir.exists():
                shutil.rmtree(sample_dir)
            shutil.move(str(extracted), sample_dir)
            return None
        except Exception as exc:  # noqa: BLE001
            return str(exc)
    return f"No local zip found in {LOCAL_SAMPLE_DIR}"


def _runtime_env_from_os() -> dict[str, str]:
    keys = [
        "OPENAI_API_KEY",
        "OPENAI_API_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL_NAME",
        "MODEL_NAME",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_MODEL",
        "SILICONFLOW_API_KEY",
        "SILICONFLOW_BASE_URL",
        "SILICONFLOW_MODEL",
        "LLM_API_KEY",
        "LLM_BASE_URL",
        "LLM_MODEL",
        "GITHUB_TOKEN",
    ]
    return {key: os.getenv(f"SANDBOX_RUNTIME_{key}") for key in keys if os.getenv(f"SANDBOX_RUNTIME_{key}")}


def _runtime_network_from_os() -> str:
    value = os.getenv("SANDBOX_RUNTIME_NETWORK", "auto").strip().lower()
    if value == "auto":
        return "bridge" if _runtime_env_from_os() else "none"
    return value if value in {"none", "bridge"} else "none"


def _candidate_roots(repo: Path, kind: str) -> list[Path]:
    if kind == "mcp":
        preferred = [repo / "src" / "sequentialthinking", repo / "src" / "memory", repo / "src" / "filesystem", repo / "src" / "everything"]
        roots = [path for path in preferred if (path / "package.json").exists()]
        for marker in repo.rglob("package.json"):
            text = marker.read_text(encoding="utf-8", errors="replace")
            if "modelcontextprotocol" in text.lower() or '"mcp"' in text.lower():
                roots.append(marker.parent)
        deduped = []
        seen = set()
        for root in roots:
            resolved = root.resolve()
            if resolved not in seen:
                deduped.append(root)
                seen.add(resolved)
        return deduped[:5]
    if kind == "crewai":
        preferred = [
            repo / "crews" / "markdown_validator",
            repo / "crews" / "marketing_strategy",
            repo / "crews" / "stock_analysis",
        ]
        roots = [path for path in preferred if (path / "pyproject.toml").exists()]
        for marker in repo.rglob("crew.py"):
            roots.append(_project_root_for_python(marker.parent, repo))
        for marker in repo.rglob("agents.yaml"):
            roots.append(_project_root_for_python(marker.parent, repo))
        deduped = []
        seen = set()
        for root in roots:
            resolved = root.resolve()
            if resolved not in seen:
                deduped.append(root)
                seen.add(resolved)
        return deduped[:5]
    return [repo]


def _prepare_validation_root(repo: Path, selected_root: Path, kind: str) -> Path:
    if kind == "mcp" and selected_root != repo:
        rel = selected_root.relative_to(repo).as_posix()
        (repo / "sandbox.yaml").write_text(
            "\n".join(
                [
                    "protocol: mcp",
                    "language: Node.js",
                    "framework: MCP",
                    "image: node:22-bookworm",
                    "install:",
                    f"  - cd {rel} && npm install --ignore-scripts --no-audit --no-fund",
                    f"  - cd {rel} && npm run build",
                    f"start: cd {rel} && node dist/index.js",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return repo
    if kind == "crewai":
        sample = selected_root / "sandbox_sample.md"
        if not sample.exists():
            sample.write_text("# Sandbox Sample\n\nThis markdown file is intentionally simple.\n", encoding="utf-8")
    return selected_root


def _project_root_for_python(path: Path, repo: Path) -> Path:
    current = path
    while current != repo and current.parent != current:
        if (current / "pyproject.toml").exists() or (current / "requirements.txt").exists():
            return current
        current = current.parent
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate sandbox adapters against real GitHub samples.")
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--sample", choices=["mcp", "crewai", "modelcontextprotocol-servers", "crewai-examples"], default=None)
    parser.add_argument("--static-only", action="store_true", help="Only clone and scan samples; skip Docker dynamic execution.")
    args = parser.parse_args()
    print(json.dumps(validate_real_world(limit=args.limit, dynamic=not args.static_only, sample_name=args.sample), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
