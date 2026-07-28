from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .adapters import detect_adapters
from .constants import MAX_TEXT_BYTES
from .fs_utils import safe_walk_files
from .schemas import Finding, ProjectProfile

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".sh",
    ".bash",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
    ".env",
    ".ini",
}

SKIP_SOURCE_DIRS = {".git", ".sandbox_data", ".venv", "venv", "node_modules", "target", "dist", "build", "__pycache__", ".pytest_cache"}
SOURCE_AUDIT_MAX_FILES = 80
SOURCE_AUDIT_MAX_BYTES = 140_000
SOURCE_FILE_MAX_CHARS = 12_000

LANGUAGE_MARKERS = {
    "Python": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "Node.js": ["package.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"],
    "Go": ["go.mod"],
    "Rust": ["Cargo.toml"],
    "Java": ["pom.xml", "build.gradle", "gradlew"],
    "Shell": [".sh"],
    "Docker": ["Dockerfile", "docker-compose.yml", "compose.yml"],
}

DANGEROUS_PATTERNS: list[tuple[str, str, str, str, re.Pattern[str]]] = [
    ("secret_access", "high", "Secret material access", "Code appears to read environment variables or credential files.", re.compile(r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|SLACK_BOT_TOKEN|\.env|\.ssh|credentials|api[_-]?key|token)", re.I)),
    ("shell_execution", "high", "Shell or process execution", "Code can execute shell commands or child processes.", re.compile(r"(subprocess\.|os\.system|exec\(|eval\(|child_process|spawn\(|execSync|Runtime\.getRuntime\(\)\.exec|Command::new)", re.I)),
    ("network_access", "medium", "Network access", "Code can communicate over HTTP, sockets, or webhooks.", re.compile(r"(requests\.|httpx\.|fetch\(|axios\.|urllib|socket\.|webhook|curl |wget |net/http)", re.I)),
    ("persistence", "high", "Persistence or scheduled execution", "Code references memory stores, startup hooks, or scheduled tasks.", re.compile(r"(cron|crontab|schedule|setInterval|systemd|startup|memory|vector|sqlite|chroma|faiss|localStorage)", re.I)),
    ("remote_code", "critical", "Remote code loading", "Code may download and execute remote content.", re.compile(r"(curl.+\|.+sh|wget.+\|.+sh|pip install git\+|npm install.+https?://|importlib|base64\.b64decode|fromCharCode)", re.I)),
    ("mcp_agent", "medium", "Agent/MCP capability", "Project contains agent or MCP-related configuration or code.", re.compile(r"(mcp|langchain|autogen|crewai|openai|anthropic|tool_call|function_call|agent)", re.I)),
    ("external_input", "medium", "External content input", "Code or docs reference browser, email, collaboration, retrieval, or other untrusted external inputs.", re.compile(r"(browser|playwright|selenium|gmail|smtp|email|github|issue|pull request|slack|calendar|google drive|shared document|rag|retrieval|webpage|crawler)", re.I)),
    ("tool_poisoning_surface", "medium", "Tool or plugin metadata surface", "Project references tool manifests, plugins, skills, or MCP descriptors that can carry hidden instructions.", re.compile(r"(tool_manifest|tools/list|plugin|plugins|skill\.md|agents\.md|microagent|description\s*:)", re.I)),
]


def scan_project(root: Path) -> tuple[ProjectProfile, list[Finding], dict[str, Any]]:
    root = root.resolve()
    files, filesystem_warnings = safe_walk_files(root)
    rel_files = [path.relative_to(root).as_posix() for path in files]
    profile = ProjectProfile(root_name=root.name)
    profile.manifests = sorted(_find_manifests(rel_files))
    profile.languages = sorted(_detect_languages(root, rel_files))
    profile.frameworks = sorted(_detect_frameworks(root, files))
    profile.entrypoints = sorted(_detect_entrypoints(root, rel_files))
    profile.protocol_candidates = sorted(_detect_protocols(root, rel_files))
    profile.capabilities = sorted(_detect_capabilities(root, files))
    profile.sandbox_yaml = _read_sandbox_yaml(root)
    adapters = detect_adapters(root, profile)
    profile.adapter_matches = [adapter.to_dict() for adapter in adapters]
    profile.selected_adapter = profile.adapter_matches[0] if profile.adapter_matches else None
    profile.run_candidates = profile.adapter_matches or _build_run_candidates(profile)
    profile.confidence = _confidence(profile)
    findings = _scan_findings(root, files)
    evidence_bundle = _make_evidence_bundle(root, files, profile, findings, filesystem_warnings)
    return profile, findings, evidence_bundle


def _find_manifests(rel_files: list[str]) -> set[str]:
    names = {
        "Dockerfile",
        "docker-compose.yml",
        "compose.yml",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
        "sandbox.yaml",
        "sandbox.yml",
    }
    return {path for path in rel_files if Path(path).name in names or path.lower().endswith(("mcp.json", "agents.md", "skill.md"))}


def _detect_languages(root: Path, rel_files: list[str]) -> set[str]:
    found: set[str] = set()
    rel_names = {Path(path).name for path in rel_files}
    for language, markers in LANGUAGE_MARKERS.items():
        for marker in markers:
            if marker.startswith(".") and any(path.endswith(marker) for path in rel_files):
                found.add(language)
            if marker in rel_names:
                found.add(language)
    suffix_map = {".py": "Python", ".js": "Node.js", ".ts": "Node.js", ".go": "Go", ".rs": "Rust", ".java": "Java", ".sh": "Shell"}
    for path in rel_files:
        language = suffix_map.get(Path(path).suffix)
        if language:
            found.add(language)
        elif _has_shell_shebang(root / path):
            found.add("Shell")
    return found


def _detect_frameworks(root: Path, files: list[Path]) -> set[str]:
    text = "\n".join(_read_text(path)[:4000] for path in files[:300] if _is_text(path))
    frameworks = set()
    markers = {
        "LangChain": r"langchain",
        "CrewAI": r"crewai",
        "AutoGen": r"autogen",
        "OpenAI SDK": r"openai",
        "Anthropic SDK": r"anthropic",
        "MCP": r"\bmcp\b|modelcontextprotocol",
        "FastAPI": r"fastapi",
        "Express": r"express",
        "Playwright": r"playwright",
    }
    for name, pattern in markers.items():
        if re.search(pattern, text, re.I):
            frameworks.add(name)
    return frameworks


def _detect_entrypoints(root: Path, rel_files: list[str]) -> set[str]:
    entries: set[str] = set()
    candidates = ["main.py", "app.py", "server.py", "agent.py", "index.js", "src/index.js", "src/main.ts", "main.go"]
    for candidate in candidates:
        if candidate in rel_files:
            entries.add(candidate)
    for path in rel_files:
        rel = Path(path)
        if rel.name == "main.go" and len(rel.parts) >= 3 and rel.parts[0] == "cmd":
            entries.add(path)
        if _has_shell_shebang(root / path):
            entries.add(path)
    package = root / "package.json"
    if package.exists():
        try:
            data = json.loads(_read_text(package))
            scripts = data.get("scripts", {})
            for key in ("start", "dev", "serve"):
                if key in scripts:
                    entries.add(f"package.json:scripts.{key}")
        except json.JSONDecodeError:
            pass
    return entries


def _detect_protocols(root: Path, rel_files: list[str]) -> set[str]:
    protocols = {"cli"}
    if any(Path(path).name in {"Dockerfile", "docker-compose.yml", "compose.yml"} for path in rel_files):
        protocols.add("docker")
    text_names = " ".join(rel_files).lower()
    if any(name in text_names for name in ["fastapi", "server.py", "app.py", "express", "http", "api"]):
        protocols.add("http")
    content = "\n".join(_read_text(root / path)[:3000] for path in rel_files[:300] if _is_text(root / path))
    if "mcp" in text_names or any(path.lower().endswith("mcp.json") for path in rel_files) or re.search(r"modelcontextprotocol|\bmcp\b|tools/list|resources/list", content, re.I):
        protocols.add("mcp")
    if any(token in text_names for token in ["playwright", "selenium", "browser"]):
        protocols.add("browser")
    sandbox = _read_sandbox_yaml(root)
    if sandbox and sandbox.get("protocol"):
        protocols.add(str(sandbox["protocol"]))
    return protocols


def _detect_capabilities(root: Path, files: list[Path]) -> set[str]:
    capabilities: set[str] = set()
    text = "\n".join(_read_text(path)[:8000] for path in files[:500] if _is_text(path))
    checks = {
        "filesystem": r"(open\(|writeFile|readFile|fs\.|Path\(|File\()",
        "network": r"(requests\.|fetch\(|axios|httpx|socket|webhook)",
        "shell": r"(subprocess|child_process|os\.system|execSync|spawn\()",
        "memory": r"(memory|vector|sqlite|chroma|faiss|redis)",
        "scheduler": r"(cron|schedule|setInterval|systemd)",
        "browser": r"(playwright|selenium|puppeteer)",
        "messaging": r"(slack|discord|telegram|gmail|smtp|email)",
        "mcp": r"(\bmcp\b|tool_call|resources/list|tools/list)",
    }
    for name, pattern in checks.items():
        if re.search(pattern, text, re.I):
            capabilities.add(name)
    return capabilities


def _read_sandbox_yaml(root: Path) -> dict[str, Any] | None:
    for name in ("sandbox.yaml", "sandbox.yml"):
        path = root / name
        if path.exists():
            try:
                data = yaml.safe_load(_read_text(path)) or {}
                return data if isinstance(data, dict) else {"raw": data}
            except yaml.YAMLError as exc:
                return {"error": str(exc)}
    return None


def _build_run_candidates(profile: ProjectProfile) -> list[dict[str, Any]]:
    if profile.sandbox_yaml and not profile.sandbox_yaml.get("error"):
        start = profile.sandbox_yaml.get("start")
        install = profile.sandbox_yaml.get("install", [])
        return [{"kind": "sandbox_yaml", "protocol": profile.sandbox_yaml.get("protocol", "cli"), "install": install, "start": start, "confidence": 0.95}]
    candidates: list[dict[str, Any]] = []
    if "Docker" in profile.languages:
        candidates.append({"kind": "dockerfile", "protocol": "docker", "start": "docker build/run", "confidence": 0.9})
    if "Node.js" in profile.languages:
        candidates.append({"kind": "node", "protocol": "cli", "install": ["npm install"], "start": "npm start", "confidence": 0.65})
    if "Python" in profile.languages:
        start = "python main.py"
        if "app.py" in profile.entrypoints:
            start = "python app.py"
        elif "agent.py" in profile.entrypoints:
            start = "python agent.py"
        candidates.append({"kind": "python", "protocol": "cli", "install": ["pip install -r requirements.txt"], "start": start, "confidence": 0.65})
    for lang, cmd in (("Go", "go run ."), ("Rust", "cargo run"), ("Java", "mvn -q exec:java"), ("Shell", "bash main.sh")):
        if lang in profile.languages:
            candidates.append({"kind": lang.lower(), "protocol": "cli", "install": [], "start": cmd, "confidence": 0.5})
    return candidates


def _confidence(profile: ProjectProfile) -> float:
    score = 0.1
    if profile.languages:
        score += 0.2
    if profile.manifests:
        score += 0.2
    if profile.entrypoints:
        score += 0.2
    if profile.sandbox_yaml:
        score += 0.25
    if profile.run_candidates:
        score += 0.15
    return min(score, 1.0)


def _scan_findings(root: Path, files: list[Path]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for path in files:
        if not _is_text(path):
            continue
        text = _read_text(path)
        rel = path.relative_to(root).as_posix()
        for category, severity, title, description, pattern in DANGEROUS_PATTERNS:
            matches = list(pattern.finditer(text))
            if not matches:
                continue
            finding = findings.get(category)
            if not finding:
                metadata = _finding_metadata(category)
                finding = Finding(
                    id=f"rule_{category}",
                    category=category,
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=description,
                    confidence=0.7,
                    source="rule",
                    risk_type="capability",
                    attack_surface=metadata["attack_surface"],
                    needs_dynamic_validation=True,
                    recommended_dynamic_tests=metadata["recommended_dynamic_tests"],
                )
                findings[category] = finding
            for match in matches[:3]:
                line_no = text[: match.start()].count("\n") + 1
                snippet = _line_at(text, line_no)
                finding.evidence.append({"file": rel, "line": line_no, "snippet": snippet[:240]})
    return list(findings.values())


def _make_evidence_bundle(root: Path, files: list[Path], profile: ProjectProfile, findings: list[Finding], filesystem_warnings: list[dict[str, str]] | None = None) -> dict[str, Any]:
    interesting_files = []
    for path in files:
        if path.relative_to(root).as_posix() in profile.manifests or Path(path).name.lower() in {"readme.md", "agents.md", "skill.md"}:
            interesting_files.append({"path": path.relative_to(root).as_posix(), "content": _read_text(path)[:6000] if _is_text(path) else "[binary]"})
    return {
        "profile": profile.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
        "interesting_files": interesting_files[:25],
        "source_files": _source_files_for_llm(root, files),
        "filesystem_warnings": filesystem_warnings or [],
    }


def _finding_metadata(category: str) -> dict[str, list[str]]:
    mapping = {
        "secret_access": {
            "attack_surface": ["environment", "filesystem", "runtime_secrets"],
            "recommended_dynamic_tests": ["chat", "inject_memory", "assert_sink_clean", "assert_no_canary_exfiltration"],
        },
        "shell_execution": {
            "attack_surface": ["shell", "process"],
            "recommended_dynamic_tests": ["inject_web_page", "inject_email", "inspect_files"],
        },
        "network_access": {
            "attack_surface": ["network", "http", "webhook"],
            "recommended_dynamic_tests": ["monitor_egress", "assert_external_input_control", "assert_sink_clean"],
        },
        "persistence": {
            "attack_surface": ["memory", "scheduler", "filesystem"],
            "recommended_dynamic_tests": ["inject_memory", "inject_scheduler", "restart_and_resume", "inspect_memory"],
        },
        "remote_code": {
            "attack_surface": ["supply_chain", "build_scripts", "network"],
            "recommended_dynamic_tests": ["inspect_files", "monitor_egress"],
        },
        "mcp_agent": {
            "attack_surface": ["mcp", "tools"],
            "recommended_dynamic_tests": ["mcp_initialize", "mcp_list_tools", "inject_mcp_tool_manifest"],
        },
        "external_input": {
            "attack_surface": ["browser", "email", "github", "rag", "slack", "calendar", "drive"],
            "recommended_dynamic_tests": [
                "inject_web_page",
                "inject_email",
                "inject_github_issue",
                "inject_github_pull_request",
                "inject_rag_document",
                "inject_slack_message",
                "inject_calendar_event",
                "inject_drive_document",
                "assert_external_input_control",
            ],
        },
        "tool_poisoning_surface": {
            "attack_surface": ["tools", "plugins", "skills"],
            "recommended_dynamic_tests": ["inject_skill", "inject_tool_manifest", "inject_mcp_tool_manifest", "trigger_skill"],
        },
    }
    return mapping.get(category, {"attack_surface": [], "recommended_dynamic_tests": []})


def _source_files_for_llm(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    scored: list[tuple[int, str, Path]] = []
    for path in files:
        if not _is_text(path) or _skip_source_path(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        scored.append((_source_file_score(rel, _read_text(path)[:8000]), rel, path))
    result: list[dict[str, Any]] = []
    total = 0
    for _score, rel, path in sorted(scored, key=lambda item: (-item[0], len(item[1]), item[1]))[:SOURCE_AUDIT_MAX_FILES]:
        text = _redact_source_text(_read_text(path)[:SOURCE_FILE_MAX_CHARS])
        if not text:
            continue
        if total + len(text) > SOURCE_AUDIT_MAX_BYTES and result:
            break
        total += len(text)
        result.append({"path": rel, "content": text})
    return result


def _skip_source_path(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in SKIP_SOURCE_DIRS or part.startswith(".mypy") or part.startswith(".ruff") for part in rel_parts)


def _source_file_score(rel: str, text: str) -> int:
    lowered = f"{rel}\n{text}".lower()
    score = 0
    name = Path(rel).name.lower()
    if name in {"readme.md", "agents.md", "agent.md", "skill.md", "claude.md", "sandbox.yaml", "sandbox.yml"}:
        score += 80
    if name in {"pyproject.toml", "requirements.txt", "package.json", "go.mod", "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "dockerfile"}:
        score += 70
    if name in {"main.py", "agent.py", "app.py", "server.py", "cli.py", "chat.py", "assistant.py", "index.js", "server.js", "main.go"}:
        score += 60
    for token, weight in (
        ("api_key", 35),
        ("token", 25),
        ("credential", 25),
        ("memory", 25),
        ("schedule", 25),
        ("cron", 25),
        ("skill", 25),
        ("tool", 20),
        ("subprocess", 20),
        ("exec(", 20),
        ("os.system", 20),
        ("child_process", 20),
        ("requests.", 15),
        ("fetch(", 15),
        ("httpx", 15),
        ("openai", 15),
        ("anthropic", 15),
        ("mcp", 15),
        ("langchain", 15),
        ("crewai", 15),
    ):
        if token in lowered:
            score += weight
    return score


def _redact_source_text(text: str) -> str:
    text = re.sub(r"sk-[A-Za-z0-9_-]{10,}", "[redacted-api-key]", text)
    text = re.sub(r"gh[opsu]_[A-Za-z0-9_]{20,}", "[redacted-github-token]", text)
    text = re.sub(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]", r"\1=\"[redacted]\"", text)
    return text


def _is_text(path: Path) -> bool:
    if path.suffix in TEXT_SUFFIXES:
        return True
    if path.name in {"Dockerfile", "Makefile", "README", "AGENTS.md", "SKILL.md"}:
        return True
    if _has_shell_shebang(path):
        return True
    return False


def _has_shell_shebang(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        first = path.read_bytes()[:160].decode("utf-8", errors="replace").splitlines()[0]
    except (IndexError, OSError):
        return False
    return first.startswith("#!") and re.search(r"\b(bash|sh|zsh|ash)\b", first) is not None


def _read_text(path: Path) -> str:
    try:
        data = path.read_bytes()[:MAX_TEXT_BYTES]
        if b"\x00" in data[:1024]:
            return ""
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""
