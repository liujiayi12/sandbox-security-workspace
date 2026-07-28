from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .adapters import AdapterCandidate
from . import image_reserve


MAX_CANDIDATES = 24
LOW_PRIORITY_SAMPLE_CANDIDATE_LIMIT = 4
MANIFEST_ROOT_LIMITS = {
    "Python": 14,
    "Node.js": 14,
    "Java": 8,
}
GO_ENTRYPOINT_LIMIT = 6
DOC_CANDIDATE_LIMIT = 18
CHAT_COMMANDS = ("ask", "chat", "prompt", "query", "generate", "complete", "completion", "send", "message", "say")
ONE_SHOT_COMMANDS = ("run", "ask", "chat", "prompt", "query", "generate", "complete", "completion", "send", "message", "say")
DOC_NAMES = {
    "README",
    "README.md",
    "README.rst",
    "AGENT.md",
    "AGENTS.md",
    "CLAUDE.md",
    "DEVELOPMENT.md",
    "DEV.md",
    "QUICKSTART.md",
    "USAGE.md",
    "RUNNING.md",
    "INSTALL.md",
    "SETUP.md",
    "GETTING_STARTED.md",
}


def discover_plan_candidates(root: Path, profile: Any | None = None) -> list[AdapterCandidate]:
    candidates: list[AdapterCandidate] = []
    candidates.extend(_langgraph_json_candidates(root))
    candidates.extend(_python_project_candidates(root))
    candidates.extend(_node_project_candidates(root))
    candidates.extend(_go_project_candidates(root))
    candidates.extend(_rust_project_candidates(root))
    candidates.extend(_java_project_candidates(root))
    candidates.extend(_shell_script_candidates(root))
    candidates.extend(_documentation_candidates(root))
    candidates.extend(_devcontainer_candidates(root))
    return _dedupe(_expand_candidate_set(candidates))


def llm_plan_to_candidate(plan: dict[str, Any]) -> AdapterCandidate | None:
    if not isinstance(plan, dict):
        return None
    start = _clean_command(plan.get("start_command") or plan.get("start"))
    install = [_clean_command(item) for item in _as_list(plan.get("install_commands") or plan.get("install"))]
    build = [_clean_command(item) for item in _as_list(plan.get("build_commands") or plan.get("build"))]
    if not start:
        return None
    language = str(plan.get("language") or "custom")[:60]
    protocol = str(plan.get("protocol") or "cli").lower()
    if protocol not in {"cli", "http", "mcp", "browser"}:
        protocol = "cli"
    if protocol == "cli" and _is_help_only_command(start):
        return None
    image = str(plan.get("base_image") or plan.get("image") or _default_image(language))[:120]
    confidence = _safe_float(plan.get("confidence"), 0.55)
    confidence = _adjust_confidence_for_start(start, confidence)
    return AdapterCandidate(
        name=str(plan.get("name") or "llm-buildplan")[:80],
        kind="llm_plan",
        language=language,
        framework=str(plan.get("framework"))[:80] if plan.get("framework") else None,
        protocol=protocol,
        image=image,
        install=[item for item in [*install, *build] if item],
        start=start,
        port=_safe_port(plan.get("port")),
        confidence=max(0.1, min(confidence, 0.9)),
        reason=str(plan.get("reason") or "LLM suggested a structured BuildPlan.")[:500],
    )


def expand_candidate_variants(candidate: AdapterCandidate) -> list[AdapterCandidate]:
    # Variants are intentionally not pre-expanded into progressively broader
    # plans. The build layer now starts from the concise inferred plan and only
    # adds packages, tool setup, lockfile relaxation, or reserve-image changes
    # when a concrete failure log asks for them.
    return [candidate]


def sort_candidate_dicts(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str | None, str | None, str | None, str | None, tuple[str, ...]]] = set()
    normal: list[dict[str, Any]] = []
    low_priority: list[dict[str, Any]] = []
    for candidate in sorted(candidates, key=_candidate_dict_score, reverse=True):
        key = (
            str(candidate.get("kind")),
            str(candidate.get("protocol")),
            str(candidate.get("image")),
            str(candidate.get("start")),
            tuple(str(item) for item in candidate.get("install", []) if item),
        )
        if key in seen:
            continue
        seen.add(key)
        if _candidate_dict_is_low_priority_sample(candidate):
            low_priority.append(candidate)
        else:
            normal.append(candidate)
    return [*normal, *low_priority[:LOW_PRIORITY_SAMPLE_CANDIDATE_LIMIT]][:MAX_CANDIDATES]


def _expand_candidate_set(candidates: list[AdapterCandidate]) -> list[AdapterCandidate]:
    expanded: list[AdapterCandidate] = []
    for candidate in candidates:
        expanded.extend(expand_candidate_variants(candidate))
    return expanded


def _langgraph_json_candidates(root: Path) -> list[AdapterCandidate]:
    path = root / "langgraph.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    graphs = data.get("graphs", {})
    if not isinstance(graphs, dict):
        return []
    candidates = []
    root_resolved = root.resolve()
    for name, target in graphs.items():
        if not isinstance(target, str) or ":" not in target:
            continue
        file_part, attr = target.split(":", 1)
        graph_file = (root_resolved / file_part).resolve()
        try:
            graph_file.relative_to(root_resolved)
        except ValueError:
            continue
        if not graph_file.exists():
            continue
        project_root = _nearest_python_project(graph_file.parent, root_resolved)
        rel_project = project_root.relative_to(root_resolved).as_posix() if project_root != root_resolved else "."
        rel_graph = graph_file.relative_to(project_root).as_posix()
        install = _python_install_commands_for(root_resolved, project_root)
        start = _langgraph_probe_command(rel_project, rel_graph, attr, str(name))
        confidence = 0.9 - _install_complexity_penalty(install)
        candidates.append(
            AdapterCandidate(
                name=f"langgraph:{name}",
                kind="plan_python",
                language="Python",
                framework="LangGraph",
                protocol="cli",
                image=_python_image(project_root),
                install=install,
                start=start,
                confidence=confidence,
                reason=f"langgraph.json declares graph '{name}' at {file_part}:{attr}.",
            )
        )
    return candidates


def _install_complexity_penalty(commands: list[str]) -> float:
    text = "\n".join(commands).lower()
    penalty = 0.0
    if "poetry install" in text:
        penalty += 0.05
    if "uv sync" in text:
        penalty += 0.02
    if len(commands) > 4:
        penalty += 0.01
    return min(penalty, 0.08)


def _rank_project_roots(root: Path, project_roots: list[Path], language: str, limit: int = 20) -> list[Path]:
    seen: set[Path] = set()
    paths: list[Path] = []
    for path in project_roots:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(path)

    def key(project_root: Path) -> tuple[float, int, str]:
        try:
            rel = project_root.relative_to(root)
        except ValueError:
            rel = project_root
        return (-_project_root_score(root, project_root, language), len(rel.parts), rel.as_posix())

    return sorted(paths, key=key)[:limit]


def _project_root_score(root: Path, project_root: Path, language: str) -> float:
    try:
        rel_parts = project_root.relative_to(root).parts
    except ValueError:
        rel_parts = project_root.parts
    lowered_path = project_root.as_posix().lower()
    score = 0.0
    if project_root == root:
        score += 0.08
    if any(part.lower() in {"node_modules", "vendor", ".git", "target", "dist", "build", "__pycache__", ".venv", "venv"} for part in rel_parts):
        score -= 1.0
    lowered_parts = [part.lower() for part in rel_parts]
    if any(part in {"tests", "test", "docs", "doc", ".github"} for part in lowered_parts):
        score -= 0.25
    if any(part in {"examples", "example", "samples", "sample", "demo", "demos", "tutorial", "tutorials", "contrib"} for part in lowered_parts):
        score -= 0.28
    if any(part in {"website", "websites", "docs-site", "documentation"} for part in lowered_parts):
        score -= 0.22
    if any(part in {"packages", "libs", "lib", "sdk", "integrations", "plugins"} for part in lowered_parts):
        score -= 0.08
    if any(token in lowered_path for token in ("agent", "assistant", "chat", "bot", "mcp", "langgraph", "crewai", "openai", "deepseek")):
        score += 0.35
    if any(token in lowered_path for token in ("quickstart", "starter", "hello", "simple", "standalone")):
        score += 0.12
    text = "\n".join(
        _read_text(project_root / name)
        for name in ("README.md", "README.rst", "AGENTS.md", "package.json", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml")
    ).lower()
    if re.search(r"\b(agent|assistant|chatbot|chat|mcp|tool|llm|openai|deepseek|langchain|langgraph|crewai)\b", text):
        score += 0.25
    if re.search(r"\b(run|start|serve|chat|ask|prompt|query)\b", text):
        score += 0.12
    if language == "Python" and any((project_root / name).exists() for name in ("main.py", "cli.py", "app.py", "agent.py", "bot.py")):
        score += 0.22
    if language == "Node.js" and any((project_root / name).exists() for name in ("index.js", "index.ts", "src/index.js", "src/index.ts", "src/cli.ts", "src/cli.js")):
        score += 0.22
    if language == "Java" and any((project_root / rel).exists() for rel in ("src/main/java", "src/main/kotlin", "src/main/resources")):
        score += 0.22
    if _looks_like_workspace_root(project_root, language):
        score -= 0.22
    if _project_declares_runnable_surface(project_root, language, text):
        score += 0.18
    return score


def _project_declares_runnable_surface(project_root: Path, language: str, text: str) -> bool:
    if language == "Node.js":
        package = _read_package(project_root / "package.json") or {}
        scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
        return any(name in scripts for name in ("start", "dev", "serve")) or any(_node_script_looks_http(str(value)) for value in scripts.values())
    if language == "Java":
        return _java_is_http_project(project_root, text) or re.search(r"\bpublic\s+static\s+void\s+main\b", text) is not None
    if language == "Python":
        return _python_is_http_project(project_root) or any((project_root / name).exists() for name in ("main.py", "agent.py", "app.py", "server.py", "cli.py"))
    return re.search(r"\b(chat|ask|prompt|serve|start|run)\b", text, re.I) is not None


def _adjust_candidate_confidence_for_project(root: Path, project_root: Path, language: str, confidence: float) -> float:
    try:
        rel_parts = [part.lower() for part in project_root.relative_to(root).parts]
    except ValueError:
        rel_parts = [part.lower() for part in project_root.parts]
    if any(part in {"examples", "example", "samples", "sample", "demo", "demos", "tutorial", "tutorials", "contrib"} for part in rel_parts):
        confidence -= 0.1
    if any(part in {"website", "docs", "doc", "documentation", "packages", "libs", "plugins", "integrations"} for part in rel_parts):
        confidence -= 0.04
    if project_root == root:
        confidence += 0.03
    if _project_declares_runnable_surface(project_root, language, _sample_text(project_root)):
        confidence += 0.03
    return max(0.35, min(confidence, 0.94))


def _looks_like_workspace_root(project_root: Path, language: str) -> bool:
    if language == "Node.js":
        package = _read_package(project_root / "package.json")
        if package and package.get("workspaces") and not any((project_root / rel).exists() for rel in ("src", "index.js", "index.ts")):
            return True
    if language == "Java":
        text = "\n".join(_read_text(project_root / name) for name in ("pom.xml", "settings.gradle", "settings.gradle.kts"))
        return bool(re.search(r"<modules>|include\s*\(", text)) and not any((project_root / rel).exists() for rel in ("src/main/java", "src/main/kotlin"))
    if language == "Python":
        return (project_root / "pyproject.toml").exists() and not any((project_root / rel).exists() for rel in ("src", "main.py", "cli.py", "app.py"))
    return False


def _python_project_candidates(root: Path) -> list[AdapterCandidate]:
    candidates = []
    markers = _rank_project_roots(
        root,
        sorted({path.parent for path in [*root.rglob("pyproject.toml"), *root.rglob("requirements.txt")]}),
        "Python",
        limit=MANIFEST_ROOT_LIMITS["Python"],
    )
    for project_root in markers:
        if _python_is_http_project(project_root):
            continue
        rel = project_root.relative_to(root).as_posix() if project_root != root else "."
        for idx, start in enumerate(_python_one_shot_starts(project_root, root)[:6]):
            candidates.append(
                AdapterCandidate(
                    name=f"python-plan:{rel}:oneshot:{idx + 1}",
                    kind="plan_python",
                    language="Python",
                    framework=_python_framework(project_root),
                    protocol="cli",
                    image=_python_image(project_root),
                    install=_python_install_commands_for(root, project_root),
                    start=start,
                    confidence=_adjust_candidate_confidence_for_project(root, project_root, "Python", 0.84 if rel == "." else 0.8),
                    reason=f"Python one-shot CLI command inferred at {rel}.",
                )
            )
        start = _python_start_for(project_root, root)
        if not start:
            continue
        candidates.append(
            AdapterCandidate(
                name=f"python-plan:{rel}",
                kind="plan_python",
                language="Python",
                framework=_python_runtime_framework(project_root, start),
                protocol="cli",
                image=_python_image(project_root),
                install=_python_install_commands_for(root, project_root),
                start=start,
                confidence=_adjust_candidate_confidence_for_project(root, project_root, "Python", 0.68 if rel != "." else 0.72),
                reason=f"Python project manifest found at {rel}.",
            )
        )
    return candidates


def _node_project_candidates(root: Path) -> list[AdapterCandidate]:
    candidates = []
    package_paths = [
        project_root / "package.json"
        for project_root in _rank_project_roots(root, [path.parent for path in root.rglob("package.json")], "Node.js", limit=MANIFEST_ROOT_LIMITS["Node.js"])
    ]
    for package_path in package_paths:
        project_root = package_path.parent
        try:
            package = json.loads(package_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if _node_is_mcp_project(project_root, package):
            continue
        rel = project_root.relative_to(root).as_posix() if project_root != root else "."
        protocol = "http" if _looks_like_http_node(project_root, package) else "cli"
        if protocol == "http":
            start = _node_start_for(project_root, root, package)
            if start:
                candidates.append(
                    AdapterCandidate(
                        name=f"node-plan:{rel}:http",
                        kind="plan_node",
                        language="Node.js",
                        framework=_node_framework(project_root, package) or "Express",
                        protocol="http",
                        image=_node_image(project_root, package),
                        install=_node_install_commands_for(root, project_root, package),
                        start=start,
                        port=3000,
                        confidence=_adjust_candidate_confidence_for_project(root, project_root, "Node.js", 0.82),
                        reason=f"Node HTTP service manifest found at {rel}.",
                    )
                )
            continue
        framework = _node_framework(project_root, package)
        for idx, start in enumerate(_node_one_shot_starts(project_root, root, package)[:8]):
            candidates.append(
                AdapterCandidate(
                    name=f"node-plan:{rel}:oneshot:{idx + 1}",
                    kind="plan_node",
                    language="Node.js",
                    framework=framework,
                    protocol="cli",
                    image=_node_image(project_root, package),
                    install=_node_install_commands_for(root, project_root, package),
                    start=start,
                    confidence=_adjust_candidate_confidence_for_project(root, project_root, "Node.js", 0.88 if rel == "." else 0.82),
                    reason=f"Node one-shot CLI command inferred at {rel}.",
                )
            )
        start = _node_start_for(project_root, root, package)
        if not start:
            continue
        candidates.append(
            AdapterCandidate(
                name=f"node-plan:{rel}",
                kind="plan_node",
                language="Node.js",
                framework="Express" if protocol == "http" else framework,
                protocol=protocol,
                image=_node_image(project_root, package),
                install=_node_install_commands_for(root, project_root, package),
                start=start,
                port=3000 if protocol == "http" else None,
                confidence=_adjust_candidate_confidence_for_project(root, project_root, "Node.js", _adjust_confidence_for_start(start, 0.6 if rel == "." else 0.7)),
                reason=f"Node package manifest found at {rel}.",
            )
        )
    return candidates


def _go_project_candidates(root: Path) -> list[AdapterCandidate]:
    if not (root / "go.mod").exists():
        return []
    commands = _go_install_commands_for(root)
    candidates: list[AdapterCandidate] = []
    module_text = _read_text(root / "go.mod")
    project_text = _sample_text(root)

    root_main = root / "main.go"
    if _is_go_main(root_main):
        binary = "/tmp/aegisagent-go-root"
        install = _go_entry_commands(root, root, ".", binary)
        if _go_main_looks_mcp(root, project_text):
            candidates.append(_go_mcp_candidate(".", binary, install, module_text, project_text, 0.91, "go.mod and root main.go declare a Go MCP stdio server."))
        candidates.extend(_go_cli_candidates(".", binary, install, module_text, project_text, 0.86, "go.mod and root main.go declare a Go CLI entrypoint."))

    for main_file in _go_main_files(root)[:GO_ENTRYPOINT_LIMIT]:
        rel_dir = main_file.parent.relative_to(root).as_posix()
        if rel_dir == ".":
            continue
        name = _safe_name(main_file.parent.name)
        binary = f"/tmp/aegisagent-{name}"
        module_root = _nearest_go_module(main_file.parent, root)
        package_ref = "." if main_file.parent == module_root else f"./{main_file.parent.relative_to(module_root).as_posix()}"
        install = _go_entry_commands(root, module_root, package_ref, binary)
        confidence = _go_entry_confidence(rel_dir, 0.92 if rel_dir.startswith("cmd/") else 0.78)
        dir_text = f"{project_text}\n{_sample_text(main_file.parent)}"
        if _go_main_looks_mcp(main_file.parent, dir_text):
            candidates.append(_go_mcp_candidate(rel_dir, binary, install, module_text, dir_text, max(0.9, confidence), f"Go MCP stdio server entrypoint found at {rel_dir}/main.go."))
        candidates.extend(_go_cli_candidates(rel_dir, binary, install, module_text, project_text, confidence, f"Go package main entrypoint found at {rel_dir}/main.go."))
    return candidates


def _rust_project_candidates(root: Path) -> list[AdapterCandidate]:
    cargo = root / "Cargo.toml"
    if not cargo.exists():
        return []
    manifest = _read_text(cargo)
    project_text = _sample_text(root)
    docs_text = _docs_text(root)
    package_name = _cargo_package_name(manifest) or root.name
    binary = f"/workspace/target/debug/{_safe_name(package_name)}"
    install = [*_rust_system_package_commands(manifest), "CARGO_HOME=/workspace/.sandbox_deps/cargo cargo fetch", "CARGO_HOME=/workspace/.sandbox_deps/cargo cargo build"]
    starts = _generic_cli_starts(
        binary,
        project_text,
        global_options=_rust_cli_global_options(f"{project_text}\n{docs_text}"),
        extra_verbs=_doc_declared_chat_verbs(root, [package_name, _safe_name(package_name)]),
    )
    framework = _rust_framework(f"{manifest}\n{project_text}\n{docs_text}")
    candidates = []
    for idx, start in enumerate(starts):
        candidates.append(
            AdapterCandidate(
                name=f"rust-plan:.:oneshot:{idx + 1}" if idx else "rust-plan:.",
                kind="plan_rust",
                language="Rust",
                framework=framework,
                protocol="cli",
                image=image_reserve.RUST_1,
                install=install,
                start=start,
                confidence=0.84 if _uses_chat_subcommand(start) else 0.72,
                reason="Cargo.toml and Rust CLI entrypoint inferred.",
            )
        )
    return candidates


def _rust_framework(text: str) -> str | None:
    lowered = text.lower()
    is_cli = re.search(r"\b(clap|structopt)\b", text, re.I) is not None
    is_tui = any(token in lowered for token in ("ratatui", "crossterm", "tui-textarea", "terminal ui", "full-screen terminal"))
    if is_cli and is_tui:
        return "Clap Terminal TUI"
    if is_tui:
        return "Terminal TUI"
    if is_cli:
        return "Clap CLI"
    return None


def _rust_cli_global_options(text: str) -> str:
    options: list[str] = []
    if "--env" in text and re.search(r"\bOPENAI_(?:API_KEY|BASE_URL|API_BASE)\b", text):
        options.append("--env")
    if "--disable-mcp" in text or re.search(r"\bMCP is disabled\b", text, re.I):
        options.append("--disable-mcp")
    return " ".join(options)


def _docs_text(root: Path) -> str:
    return "\n".join(_read_text(doc) for doc in _documentation_files(root)[:12])


def _doc_declared_chat_verbs(root: Path, command_names: list[str]) -> list[str]:
    normalized_names = {_safe_name(name).lower() for name in command_names if name}
    normalized_names.update(name.lower() for name in command_names if name)
    found: list[str] = []
    verb_pattern = "|".join(re.escape(item) for item in CHAT_COMMANDS)
    for doc in _documentation_files(root)[:12]:
        for raw_line in _read_text(doc).splitlines():
            line = raw_line.strip().strip("`")
            line = re.sub(r"^(?:\$|>|PS>|C:\\[^>]+>)\s*", "", line).strip()
            if not line or line.startswith(("-", "*", "#")):
                continue
            match = re.match(rf"(?P<cmd>[\w./-]+)(?:\s+--[\w-]+)*\s+(?P<verb>{verb_pattern})(?:\s|$)", line, re.I)
            if not match:
                continue
            command = match.group("cmd").rsplit("/", 1)[-1].lstrip("./").lower()
            verb = match.group("verb").lower()
            if command in normalized_names and verb not in found:
                found.append(verb)
    return found[:6]


def _rust_system_package_commands(manifest: str) -> list[str]:
    lowered = manifest.lower()
    packages = ["pkg-config", "libssl-dev"]
    if any(token in lowered for token in ("keyring", "secret-service", "dbus", "zbus")):
        packages.append("libdbus-1-dev")
    if any(token in lowered for token in ("rusqlite", "sqlite")):
        packages.append("libsqlite3-dev")
    if any(token in lowered for token in ("clang", "bindgen", "rocksdb", "onnxruntime")):
        packages.extend(["clang", "cmake"])
    if not packages:
        return []
    return [f"apt-get update && apt-get install -y --no-install-recommends {' '.join(dict.fromkeys(packages))}"]


def _java_project_candidates(root: Path) -> list[AdapterCandidate]:
    project_roots = _java_project_roots(root)
    candidates: list[AdapterCandidate] = []
    for project_root in project_roots:
        candidates.extend(_java_single_project_candidates(root, project_root))
    return candidates


def _java_project_roots(root: Path) -> list[Path]:
    roots = {
        path.parent
        for pattern in ("pom.xml", "build.gradle", "build.gradle.kts")
        for path in root.rglob(pattern)
        if path.is_file()
    }
    filtered: list[Path] = []
    for project_root in roots:
        rel_parts = project_root.relative_to(root).parts if project_root != root else ()
        if any(part in {".git", ".sandbox_data", "target", "build", "node_modules", "vendor"} for part in rel_parts):
            continue
        if _java_maven_aggregator_without_sources(project_root):
            continue
        filtered.append(project_root)
    return _rank_project_roots(root, filtered, "Java", limit=MANIFEST_ROOT_LIMITS["Java"])


def _java_single_project_candidates(root: Path, project_root: Path) -> list[AdapterCandidate]:
    if not (project_root / "pom.xml").exists() and not (project_root / "build.gradle").exists() and not (project_root / "build.gradle.kts").exists():
        return []
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    text = _sample_text(project_root)
    manifest_text = "\n".join(_read_text(project_root / name) for name in ("pom.xml", "build.gradle", "build.gradle.kts"))
    java_text = f"{manifest_text}\n{text}"
    candidates: list[AdapterCandidate] = []
    if (project_root / "pom.xml").exists():
        install = _prefix_commands_for_project(root, project_root, _java_install_commands_for(project_root, package_runtime=False))
        exec_install = _prefix_commands_for_project(root, project_root, _java_install_commands_for(project_root, package_runtime=True))
        if _java_is_http_project(project_root, java_text):
            package_install = [
                *install,
                *_prefix_commands_for_project(root, project_root, ["mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q -DskipTests package"]),
            ]
            for idx, start in enumerate(_java_http_starts(project_root, java_text)):
                start = _doc_command_for_project(root, project_root, start)
                candidates.append(
                    AdapterCandidate(
                        name=f"java-maven-http:{idx + 1}" if rel == "." else f"java-maven-http:{rel}:{idx + 1}",
                        kind="plan_java",
                        language="Java",
                        framework=_java_framework(java_text),
                        protocol="http",
                        image=image_reserve.JAVA_21,
                        install=package_install if "target/" in start or "find target" in start else exec_install,
                        start=start,
                        port=_java_port(project_root, text),
                        confidence=_adjust_candidate_confidence_for_project(root, project_root, "Java", 0.9 if idx == 0 else 0.84),
                        reason="Java HTTP service inferred from framework markers, routes, or documentation.",
                    )
                )
        if _java_has_sources_or_entrypoint(project_root, text):
            starts = [
                'mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q exec:java -Dexec.args="$SANDBOX_CLI_INPUT"',
                *[f'mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q exec:java -Dexec.args="{verb} $SANDBOX_CLI_INPUT"' for verb in _chat_verbs_in_text(text)],
            ]
            for idx, start in enumerate(_unique(starts)):
                start = _doc_command_for_project(root, project_root, start)
                candidates.append(
                    AdapterCandidate(
                        name=f"java-maven-plan:.:oneshot:{idx + 1}" if rel == "." else f"java-maven-plan:{rel}:oneshot:{idx + 1}",
                        kind="plan_java",
                        language="Java",
                        framework="Picocli CLI" if "picocli" in text.lower() else None,
                        protocol="cli",
                        image=image_reserve.JAVA_21,
                        install=exec_install,
                        start=start,
                        confidence=_adjust_candidate_confidence_for_project(root, project_root, "Java", 0.74 if idx == 0 else 0.8),
                        reason="Maven Java CLI command inferred.",
                    )
                )
    if (project_root / "build.gradle").exists() or (project_root / "build.gradle.kts").exists():
        gradle = "./gradlew" if (project_root / "gradlew").exists() else "gradle"
        install = _prefix_commands_for_project(root, project_root, _java_gradle_install_commands_for(project_root))
        if _java_is_http_project(project_root, java_text):
            for idx, start in enumerate(_java_gradle_http_starts(project_root, java_text)):
                start = _doc_command_for_project(root, project_root, start)
                candidates.append(
                    AdapterCandidate(
                        name=f"java-gradle-http:{idx + 1}" if rel == "." else f"java-gradle-http:{rel}:{idx + 1}",
                        kind="plan_java",
                        language="Java",
                        framework=_java_framework(java_text),
                        protocol="http",
                        image=image_reserve.JAVA_21,
                        install=install,
                        start=start,
                        port=_java_port(project_root, text),
                        confidence=_adjust_candidate_confidence_for_project(root, project_root, "Java", 0.88 if idx == 0 else 0.82 - idx * 0.03),
                        reason="Gradle Java HTTP service inferred from framework markers.",
                    )
                )
        if _java_has_sources_or_entrypoint(project_root, java_text):
            for idx, start in enumerate(_java_gradle_cli_starts(project_root, java_text)):
                start = _doc_command_for_project(root, project_root, start)
                candidates.append(
                    AdapterCandidate(
                        name=f"java-gradle-plan:.:oneshot:{idx + 1}" if rel == "." else f"java-gradle-plan:{rel}:oneshot:{idx + 1}",
                        kind="plan_java",
                        language="Java",
                        framework=_java_framework(java_text),
                        protocol="cli",
                        image=image_reserve.JAVA_21,
                        install=install,
                        start=start,
                        confidence=_adjust_candidate_confidence_for_project(root, project_root, "Java", 0.78 if idx == 0 else 0.73),
                        reason="Gradle Java CLI command inferred.",
                    )
                )
    return candidates


def _java_is_http_project(root: Path, text: str) -> bool:
    manifest = "\n".join(_read_text(root / name) for name in ("pom.xml", "build.gradle", "build.gradle.kts"))
    return re.search(
        r"spring-boot-starter-web|helidon-webserver|quarkus-resteasy|quarkus-rest|jakarta\.ws\.rs|javax\.ws\.rs|"
        r"@(?:RestController|Controller|GetMapping|PostMapping|RequestMapping|Path)\b|httpRules\.(?:get|post|put|delete)\s*\(|"
        r"server\.port|server:\s*\n\s*port:|localhost:\d+/(?:chat|assistant|api|model)",
        f"{manifest}\n{text}",
        re.I,
    ) is not None


def _java_has_sources_or_entrypoint(project_root: Path, text: str) -> bool:
    if any((project_root / rel).exists() for rel in ("src/main/java", "src/main/kotlin")):
        return True
    return re.search(r"\b(public\s+static\s+void\s+main|picocli|mainClass|mainClassName|exec-maven-plugin|application\s*\{)", text) is not None


def _java_maven_aggregator_without_sources(root: Path) -> bool:
    pom = root / "pom.xml"
    if not pom.exists():
        return False
    text = _read_text(pom)
    if "<modules>" not in text and not re.search(r"<packaging>\s*pom\s*</packaging>", text, re.I):
        return False
    return not any((root / rel).exists() for rel in ("src/main/java", "src/main/kotlin", "src/main/resources/application.properties", "src/main/resources/application.yml"))


def _java_framework(text: str) -> str | None:
    lowered = text.lower()
    if "helidon" in lowered:
        return "Helidon"
    if "spring-boot" in lowered or "@restcontroller" in lowered or "@getmapping" in lowered:
        return "Spring Boot"
    if "quarkus" in lowered:
        return "Quarkus"
    if "jakarta.ws.rs" in lowered or "javax.ws.rs" in lowered:
        return "JAX-RS"
    if "picocli" in lowered:
        return "Picocli CLI"
    return None


def _java_http_starts(root: Path, text: str) -> list[str]:
    starts: list[str] = [
        "JAR=$(find target -maxdepth 1 -type f -name '*.jar' ! -name 'original-*' ! -name '*sources.jar' ! -name '*javadoc.jar' | head -n 1); "
        "test -n \"$JAR\" && exec java -jar \"$JAR\""
    ]
    if "spring-boot-maven-plugin" in text or "spring-boot-starter-web" in text:
        starts.append("mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q spring-boot:run")
    if "quarkus" in text.lower():
        starts.append("mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q quarkus:dev -Dquarkus.http.host=0.0.0.0")
    main_class = _java_main_class(root, text)
    if main_class:
        starts.append(f'mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q exec:java -Dexec.mainClass="{main_class}"')
    return _unique(starts)


def _java_install_commands_for(project_root: Path, package_runtime: bool = False) -> list[str]:
    commands = ["mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q -DskipTests dependency:go-offline"]
    if package_runtime:
        commands.append("mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q org.codehaus.mojo:exec-maven-plugin:3.1.0:help -Ddetail=false >/dev/null")
    return commands


def _java_gradle_install_commands_for(project_root: Path) -> list[str]:
    gradle = "./gradlew" if (project_root / "gradlew").exists() else "gradle"
    commands = [f"{gradle} --no-daemon dependencies >/dev/null || true"]
    if _java_gradle_can_build_artifact(project_root):
        commands.append(f"{gradle} --no-daemon build -x test")
    else:
        commands.append(f"{gradle} --no-daemon assemble -x test")
    return commands


def _java_gradle_http_starts(root: Path, text: str) -> list[str]:
    gradle = "./gradlew" if (root / "gradlew").exists() else "gradle"
    starts: list[str] = [
        "JAR=$(find build/libs -maxdepth 1 -type f -name '*.jar' ! -name '*plain.jar' ! -name '*sources.jar' ! -name '*javadoc.jar' | head -n 1); "
        "test -n \"$JAR\" && exec java -jar \"$JAR\""
    ]
    lowered = text.lower()
    if "spring-boot" in lowered:
        starts.append(f"{gradle} --no-daemon bootRun")
    if "quarkus" in lowered:
        starts.append(f"{gradle} --no-daemon quarkusDev -Dquarkus.http.host=0.0.0.0")
    if re.search(r"\bapplication\b|mainclass|mainclassname|public\s+static\s+void\s+main", text, re.I):
        starts.append(f"{gradle} --no-daemon run")
    return _unique(starts)


def _java_gradle_cli_starts(root: Path, text: str) -> list[str]:
    gradle = "./gradlew" if (root / "gradlew").exists() else "gradle"
    starts = [
        'JAR=$(find build/libs -maxdepth 1 -type f -name \'*.jar\' ! -name \'*plain.jar\' ! -name \'*sources.jar\' ! -name \'*javadoc.jar\' | head -n 1); test -n "$JAR" && exec java -jar "$JAR" "$SANDBOX_CLI_INPUT"',
        f'{gradle} --no-daemon run --args="$SANDBOX_CLI_INPUT"',
        *[f'{gradle} --no-daemon run --args="{verb} $SANDBOX_CLI_INPUT"' for verb in _chat_verbs_in_text(text)],
    ]
    return _unique(starts)


def _java_gradle_can_build_artifact(project_root: Path) -> bool:
    text = "\n".join(_read_text(project_root / name) for name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"))
    return re.search(r"\b(?:application|java|org\.springframework\.boot|io\.quarkus)\b", text, re.I) is not None


def _java_main_class(root: Path, text: str) -> str | None:
    for pattern in (
        r"<mainClass>\s*([^<\s]+)\s*</mainClass>",
        r"mainClass\s*[=:]\s*['\"]([^'\"]+)['\"]",
        r"mainClassName\s*[=:]\s*['\"]([^'\"]+)['\"]",
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip()
    for path in sorted(root.rglob("*.java"))[:300]:
        content = _read_text(path)
        if "public static void main" not in content:
            continue
        package_match = re.search(r"^\s*package\s+([\w.]+)\s*;", content, re.M)
        class_match = re.search(r"public\s+class\s+(\w+)", content)
        if class_match:
            return f"{package_match.group(1)}.{class_match.group(1)}" if package_match else class_match.group(1)
    return None


def _java_port(root: Path, text: str) -> int:
    for path in sorted(root.rglob("*"))[:500]:
        if not path.is_file() or path.suffix.lower() not in {".properties", ".yaml", ".yml", ".java", ".md", ".http"}:
            continue
        content = _read_text(path)
        for pattern in (
            r"\bserver\.port\s*=\s*(\d{2,5})",
            r"\bport\s*:\s*[\"']?(\d{2,5})",
            r"localhost:(\d{2,5})",
            r"127\.0\.0\.1:(\d{2,5})",
        ):
            match = re.search(pattern, content)
            if match:
                port = _safe_port(match.group(1))
                if port:
                    return port
    return 8080


def _shell_script_candidates(root: Path) -> list[AdapterCandidate]:
    candidates: list[AdapterCandidate] = []
    for script in _shell_entrypoint_files(root)[:8]:
        rel = script.relative_to(root).as_posix()
        if _is_auxiliary_shell_script(script, root) and _has_primary_project_manifest(root):
            continue
        text = _read_text(script)
        if _is_maintenance_or_external_agent_command(f"bash {rel}\n{text[:1200]}") and _has_primary_project_manifest(root):
            continue
        openai_like = re.search(r"openai|chat/completions|anthropic|llm|api[_-]?key", text, re.I) is not None
        install = _shell_install_commands(text)
        candidates.append(
            AdapterCandidate(
                name=f"shell-plan:{rel}",
                kind="plan_shell",
                language="Shell",
                framework="OpenAI-compatible CLI" if openai_like else None,
                protocol="cli",
                image=image_reserve.SHELL_BASH,
                install=install,
                start=_shell_start_for(rel, openai_like),
                confidence=0.74 if openai_like else 0.62,
                reason=f"Shell shebang or executable CLI entrypoint found at {rel}.",
            )
        )
    return candidates


def _shell_entrypoint_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in {"vendor", "node_modules", ".git", ".sandbox_data", "__pycache__"} for part in rel_parts):
            continue
        if len(rel_parts) > 3 and rel_parts[0] not in {"bin", "scripts", "cmd"}:
            continue
        if _is_shell_script(path):
            files.append(path)
    files.sort(key=lambda item: (0 if item.parent == root else 1, len(item.parts), item.as_posix()))
    return files


def _is_auxiliary_shell_script(script: Path, root: Path) -> bool:
    rel_parts = script.relative_to(root).parts
    if not rel_parts:
        return False
    first = rel_parts[0].lower()
    if first in {"tapes", "examples", "example", "test", "tests", "docs", ".github", "bench", "benches"}:
        return True
    lowered = script.name.lower()
    if lowered in {"install.sh", "setup.sh", "bootstrap.sh", "configure.sh", "release.sh", "publish.sh", "deploy.sh"}:
        return True
    return any(token in lowered for token in ("test", "demo", "example", "bench", "install", "setup", "bootstrap", "quiet-run", "release", "publish", "deploy"))


def _has_primary_project_manifest(root: Path) -> bool:
    return any((root / name).exists() for name in ("Cargo.toml", "package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts"))


def _is_shell_script(path: Path) -> bool:
    if path.suffix.lower() in {".sh", ".bash"}:
        return True
    try:
        first = path.read_bytes()[:160].decode("utf-8", errors="replace").splitlines()[0]
    except (IndexError, OSError):
        return False
    return first.startswith("#!") and re.search(r"\b(bash|sh|zsh|ash)\b", first) is not None


def _shell_install_commands(text: str) -> list[str]:
    packages = ["ca-certificates"]
    checks = {
        "jq": r"\bjq\b",
        "curl": r"\bcurl\b",
        "git": r"\bgit\b",
    }
    for package, pattern in checks.items():
        if re.search(pattern, text, re.I):
            packages.append(package)
    return [f"apk add --no-cache {' '.join(dict.fromkeys(packages))}"]


def _shell_start_for(rel: str, openai_like: bool) -> str:
    quoted = _shell_quote(rel)
    if openai_like:
        return f"bash {quoted} +stream=false \"$SANDBOX_CLI_INPUT\""
    return (
        f"if [ -n \"${{SANDBOX_CLI_INPUT:-}}\" ]; then bash {quoted} \"$SANDBOX_CLI_INPUT\"; "
        f"else bash {quoted} --help || bash {quoted} -h || bash {quoted}; fi"
    )


def _documentation_candidates(root: Path) -> list[AdapterCandidate]:
    candidates: list[AdapterCandidate] = []
    for doc in _documentation_files(root)[:DOC_CANDIDATE_LIMIT]:
        project_root = _nearest_manifest_project(doc.parent, root)
        rel_project = project_root.relative_to(root).as_posix() if project_root != root else "."
        rel_doc = doc.relative_to(root).as_posix()
        text = _read_text(doc)
        for idx, command in enumerate(_doc_start_commands(text)[:8]):
            language = _doc_language(project_root, command)
            protocol = _doc_protocol_for_project(project_root, command, text)
            confidence = _doc_confidence(command, text, protocol)
            confidence = _adjust_doc_confidence_for_project(root, project_root, language, confidence)
            start = _doc_start_for(root, project_root, command, protocol)
            if not start:
                continue
            install_hints = _doc_install_commands(root, project_root, text, language)
            candidates.append(
                AdapterCandidate(
                    name=f"docs-plan:{rel_project}:{idx + 1}",
                    kind="plan_docs",
                    language=language,
                    framework=_doc_framework(project_root, text, command),
                    protocol=protocol,
                    image=_doc_image(project_root, language, text, command),
                    install=install_hints,
                    start=start,
                    port=_doc_port_for_project(project_root, text, command, protocol),
                    confidence=confidence,
                    reason=f"README-style deployment command inferred from {rel_doc}.",
                )
            )
    return candidates


def _documentation_files(root: Path) -> list[Path]:
    docs = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in DOC_NAMES:
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in {"node_modules", "vendor", ".git", "target", ".sandbox_data", "__pycache__"} for part in rel_parts):
            continue
        if len(rel_parts) > 6:
            continue
        docs.append(path)
    def key(item: Path) -> tuple[float, int, int, str]:
        project_root = _nearest_manifest_project(item.parent, root)
        language = _doc_project_language(project_root)
        root_score = _project_root_score(root, project_root, language)
        doc_priority = 0 if item.name.upper().startswith("README") else 1
        return (-root_score, len(item.relative_to(root).parts), doc_priority, item.as_posix())

    docs.sort(key=key)
    return docs


def _doc_project_language(project_root: Path) -> str:
    if (project_root / "package.json").exists():
        return "Node.js"
    if any((project_root / name).exists() for name in ("pyproject.toml", "requirements.txt")):
        return "Python"
    if (project_root / "go.mod").exists():
        return "Go"
    if (project_root / "Cargo.toml").exists():
        return "Rust"
    if any((project_root / name).exists() for name in ("pom.xml", "build.gradle", "build.gradle.kts")):
        return "Java"
    return "custom"


def _nearest_manifest_project(start: Path, root: Path) -> Path:
    current = start
    while current != root and current.parent != current:
        if _has_project_manifest(current):
            return current
        current = current.parent
    return root


def _has_project_manifest(path: Path) -> bool:
    return any((path / name).exists() for name in ("pyproject.toml", "requirements.txt", "package.json", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "Makefile"))


def _doc_install_commands(root: Path, project_root: Path, text: str, language: str) -> list[str]:
    commands: list[str] = []
    package = _read_package(project_root / "package.json")
    if language == "Python":
        commands.extend(_python_install_commands_for(root, project_root))
    elif language == "Node.js" and package:
        commands.extend(_node_install_commands_for(root, project_root, package))
    elif language == "Go":
        commands.extend(_prefix_commands_for_project(root, project_root, _go_install_commands_for(project_root)))
    elif language == "Rust":
        commands.extend(_prefix_commands_for_project(root, project_root, ["CARGO_HOME=/workspace/.sandbox_deps/cargo cargo fetch"]))
    elif language == "Java":
        if (project_root / "pom.xml").exists():
            commands.extend(_prefix_commands_for_project(root, project_root, _java_install_commands_for(project_root, package_runtime="exec:java" in text.lower())))
        elif (project_root / "build.gradle").exists() or (project_root / "build.gradle.kts").exists():
            commands.extend(_prefix_commands_for_project(root, project_root, _java_gradle_install_commands_for(project_root)))
    for command in _doc_commands(text):
        if _doc_command_role(command) != "install":
            continue
        if not _doc_install_matches_language(project_root, command, language):
            continue
        normalized = _clean_command(_doc_command_for_project(root, project_root, command))
        if normalized:
            commands.append(normalized)
    return _unique(commands)


def _doc_install_matches_language(project_root: Path, command: str, language: str) -> bool:
    lowered = command.lower().strip()
    if language == "Python":
        return re.search(r"^(?:python|python3|uv|poetry|pip|python\s+-m\s+pip)\b", lowered) is not None
    if language == "Node.js":
        return re.search(r"^(?:npm|pnpm|yarn|corepack|bun)\b", lowered) is not None
    if language == "Go":
        return lowered.startswith("go ")
    if language == "Rust":
        return lowered.startswith("cargo ")
    if language == "Java":
        return lowered.startswith(("mvn ", "gradle ", "./gradlew", "./mvnw"))
    if language == "Shell":
        return lowered.startswith(("apt-get ", "apk ", "bash ", "sh "))
    return _doc_language(project_root, command) == language


def _prefix_commands_for_project(root: Path, project_root: Path, commands: list[str]) -> list[str]:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    if rel == ".":
        return commands
    return [f"cd {rel} && {command}" for command in commands]


def _doc_start_commands(text: str) -> list[str]:
    starts = []
    for command in _doc_commands(text):
        role = _doc_command_role(command)
        if role == "start" and not _is_maintenance_or_external_agent_command(command):
            starts.append(command)
    return _unique(starts)


def _doc_commands(text: str) -> list[str]:
    commands: list[str] = []
    for block in re.findall(r"```(?:bash|sh|shell|console|terminal|powershell|ps1|text)?\s*\n(.*?)```", text, re.I | re.S):
        commands.extend(_doc_command_lines(block))
    commands.extend(_doc_command_lines(text))
    return _unique([command for command in commands if _clean_command(command)])


def _doc_command_lines(text: str) -> list[str]:
    commands = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^(?:\$|>|PS>|C:\\[^>]+>)\s*", "", line).strip()
        if not line or line.startswith(("-", "*", "#", "|")):
            continue
        if "&&" in line:
            parts = [part.strip() for part in line.split("&&") if part.strip()]
        else:
            parts = [line]
        for part in parts:
            part = part.rstrip("\\").strip()
            if _doc_command_role(part) in {"install", "start"}:
                commands.append(part)
    return commands


def _doc_command_role(command: str) -> str | None:
    lowered = command.lower().strip()
    if not lowered or _is_help_only_command(lowered):
        return None
    install_patterns = (
        r"^(?:python|python3)\s+-m\s+venv\b",
        r"^(?:python\s+-m\s+)?pip\s+install\b",
        r"^uv\s+sync\b",
        r"^poetry\s+install\b",
        r"^npm\s+(?:install|ci)\b",
        r"^npm\s+run\s+(?:build|compile|prepare)\b",
        r"^pnpm\s+install\b",
        r"^pnpm\s+run\s+(?:build|compile|prepare)\b",
        r"^yarn\s+install\b",
        r"^yarn\s+(?:build|compile|prepare)\b",
        r"^go\s+mod\s+download\b",
        r"^cargo\s+fetch\b",
        r"^mvn\b.*\b(?:dependency:go-offline|package|install)\b",
        r"^(?:\./gradlew|gradle)\b.*\b(?:dependencies|build|assemble)\b",
    )
    if any(re.search(pattern, lowered) for pattern in install_patterns):
        return "install"
    if re.search(r"^(?:npm|pnpm|yarn)\s+run\s+(?:test|lint|format|check)\b", lowered):
        return None
    start_patterns = (
        r"^(?:python|python3)\s+[\w./-]+\.py\b",
        r"^(?:python|python3)\s+-m\s+\w",
        r"^uvicorn\s+",
        r"^flask\s+run\b",
        r"^streamlit\s+run\b",
        r"^chainlit\s+run\b",
        r"^crewai\s+run\b",
        r"^npm\s+(?:start|run\s+[\w:-]+)\b",
        r"^pnpm\s+(?:start|run\s+[\w:-]+)\b",
        r"^yarn\s+(?:start|run\s+[\w:-]+)\b",
        r"^bun\s+(?:start|run\s+[\w:-]+)\b",
        r"^node\s+[\w./-]+\.m?js\b",
        r"^go\s+run\b",
        r"^cargo\s+run\b",
        r"^mvn\b.*\b(?:spring-boot:run|quarkus:dev|exec:java)\b",
        r"^(?:\./gradlew|gradle)\b.*\b(?:bootRun|quarkusDev|run)\b",
        r"^java\s+-jar\b",
        r"^(?:bash|sh)\s+[\w./-]+",
        r"^\./[\w./-]+",
        r"^make\s+(?:run|start|dev|serve)\b",
    )
    if any(re.search(pattern, lowered) for pattern in start_patterns):
        return "start"
    return None


def _is_maintenance_or_external_agent_command(command: str) -> bool:
    lowered = command.lower().strip()
    if not lowered:
        return False
    maintenance_patterns = (
        r"\b(?:release|publish|deploy|ship|changelog|version|tag|prepublish|postpublish)\b",
        r"\b(?:lint|format|test|coverage|benchmark|bench|check|audit)\b",
        r"\b(?:setup|install|bootstrap|configure|migrate|seed|clean|reset)\b",
        r"\bgit\s+(?:commit|stash|push|tag|clean|reset|checkout)\b",
        r"\b(?:docker|docker-compose)\s+",
    )
    if any(re.search(pattern, lowered) for pattern in maintenance_patterns):
        return True
    if re.search(r"\b(?:claude|amp|codex|aider|cursor|opencode|qwen|gemini)\b", lowered) and not re.search(
        r"\b(?:server|serve|mcp|api|http|web|demo)\b", lowered
    ):
        return True
    return False


def _doc_start_for(root: Path, project_root: Path, command: str, protocol: str) -> str:
    command = _doc_command_for_project(root, project_root, command)
    if protocol == "http":
        return command
    command = _replace_prompt_placeholder(command)
    if "$SANDBOX_CLI_INPUT" in command or "${SANDBOX_CLI_INPUT" in command:
        return command
    if re.search(r"\b(?:start|dev|serve|run)\b", command) and _doc_protocol_for_project(project_root, command, "") == "http":
        return command
    if re.search(r"\bnpm\s+run\s+\w+", command):
        return f'{command} -- "$SANDBOX_CLI_INPUT"'
    if re.search(r"\b(?:pnpm|yarn|bun)\s+run\s+\w+", command):
        return f'{command} "$SANDBOX_CLI_INPUT"'
    return f'{command} "$SANDBOX_CLI_INPUT"'


def _doc_command_for_project(root: Path, project_root: Path, command: str) -> str:
    command = _clean_command(command)
    if not command:
        return ""
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    if rel == "." or command.startswith("cd "):
        return command
    return f"cd {rel} && {command}"


def _replace_prompt_placeholder(command: str) -> str:
    command = re.sub(r"(?i)<(?:prompt|question|message|input|query)>", '"$SANDBOX_CLI_INPUT"', command)
    command = re.sub(r"(?i)\{(?:prompt|question|message|input|query)\}", '"$SANDBOX_CLI_INPUT"', command)
    return command


def _doc_language(project_root: Path, command: str) -> str:
    lowered = command.lower()
    if lowered.startswith(("python", "uvicorn", "flask", "streamlit", "chainlit", "crewai", "pip ", "uv ", "poetry ")):
        return "Python"
    if lowered.startswith(("npm ", "pnpm ", "yarn ", "node ", "bun ")):
        return "Node.js"
    if lowered.startswith(("go ",)):
        return "Go"
    if lowered.startswith(("cargo ",)):
        return "Rust"
    if lowered.startswith(("mvn ", "java ", "gradle ", "./gradlew", "./mvnw")):
        return "Java"
    if lowered.startswith(("bash ", "sh ", "./")):
        return "Shell"
    if (project_root / "package.json").exists():
        return "Node.js"
    if (project_root / "go.mod").exists():
        return "Go"
    if (project_root / "Cargo.toml").exists():
        return "Rust"
    if any((project_root / name).exists() for name in ("pom.xml", "build.gradle", "build.gradle.kts")):
        return "Java"
    if any((project_root / name).exists() for name in ("pyproject.toml", "requirements.txt")):
        return "Python"
    return "custom"


def _doc_protocol(command: str, text: str) -> str:
    lowered = command.lower()
    if re.search(r"\b(uvicorn|flask run|streamlit run|chainlit run|fastapi|express|fastify|listen\(|spring-boot:run|quarkus:dev|bootrun|quarkusdev|vite|next\s+dev|nuxt\s+dev|astro\s+dev|svelte-kit\s+dev|webpack\s+serve)\b", lowered):
        return "http"
    if re.search(r"https?://(?:localhost|127\.0\.0\.1):\d+/(?:chat|assistant|api|docs|health|q/health|actuator)", f"{command}\n{text}".lower()):
        return "http"
    return "cli"


def _doc_protocol_for_project(project_root: Path, command: str, text: str) -> str:
    protocol = _doc_protocol(command, text)
    if protocol == "http":
        return protocol
    package = _read_package(project_root / "package.json")
    if not package:
        return protocol
    script = _node_script_for_doc_command(command, package)
    if script and _node_script_looks_http(script):
        return "http"
    return protocol


def _node_script_for_doc_command(command: str, package: dict[str, Any]) -> str:
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    lowered = command.lower().strip()
    script_name = ""
    match = re.search(r"\b(?:npm|pnpm|yarn|bun)\s+run\s+([\w:-]+)\b", lowered)
    if match:
        script_name = match.group(1)
    elif re.search(r"\b(?:npm|pnpm|yarn|bun)\s+start\b", lowered):
        script_name = "start"
    if not script_name:
        return ""
    value = scripts.get(script_name)
    return str(value) if value is not None else ""


def _node_script_looks_http(script: str) -> bool:
    lowered = script.lower()
    return re.search(
        r"\b(vite|next\s+dev|next\s+start|nuxt\s+dev|astro\s+dev|svelte-kit\s+dev|webpack\s+serve|serve|http-server|vite\s+--host)\b|listen\s*\(",
        lowered,
    ) is not None


def _doc_port_for_project(project_root: Path, text: str, command: str, protocol: str) -> int | None:
    if protocol != "http":
        return None
    explicit = _doc_port(f"{command}\n{text}")
    if explicit:
        return explicit
    package = _read_package(project_root / "package.json")
    script = _node_script_for_doc_command(command, package or {})
    lowered = f"{command}\n{script}".lower()
    if "astro" in lowered:
        return 4321
    if "vite" in lowered or "svelte-kit" in lowered:
        return 5173
    if "next" in lowered or "nuxt" in lowered:
        return 3000
    return 8000 if _doc_protocol(command, text) == "http" else 3000


def _doc_port(text: str) -> int | None:
    for pattern in (
        r"https?://(?:localhost|127\.0\.0\.1):(\d{2,5})",
        r"\b--port\s+(\d{2,5})",
        r"\bPORT\s*=\s*(\d{2,5})",
    ):
        match = re.search(pattern, text, re.I)
        if match:
            port = _safe_port(match.group(1))
            if port:
                return port
    return None


def _doc_framework(project_root: Path, text: str, command: str) -> str | None:
    lowered = f"{text}\n{command}".lower()
    package = _read_package(project_root / "package.json")
    if _node_uses_bun(project_root, package or {}) or "bun " in lowered:
        return "Bun"
    if "langgraph" in lowered:
        return "LangGraph"
    if "crewai" in lowered:
        return "CrewAI"
    if "langchain" in lowered:
        return "LangChain/LangGraph"
    if "fastapi" in lowered or "uvicorn" in lowered:
        return "FastAPI"
    if "flask" in lowered:
        return "Flask"
    if "express" in lowered:
        return "Express"
    if "spring-boot" in lowered:
        return "Spring Boot"
    if "quarkus" in lowered:
        return "Quarkus"
    if "helidon" in lowered:
        return "Helidon"
    if (project_root / "Makefile").exists() and command.lower().startswith("make "):
        return "Makefile"
    return None


def _doc_image(project_root: Path, language: str, text: str, command: str) -> str:
    package = _read_package(project_root / "package.json")
    if language == "Node.js" and (_node_uses_bun(project_root, package or {}) or "bun " in f"{text}\n{command}".lower()):
        return image_reserve.BUN_1
    return _default_image(language)


def _doc_confidence(command: str, text: str, protocol: str) -> float:
    confidence = 0.76
    if protocol == "http":
        confidence += 0.08
    if re.search(r"https?://(?:localhost|127\.0\.0\.1):\d+", text):
        confidence += 0.04
    if "$SANDBOX_CLI_INPUT" in _replace_prompt_placeholder(command) or re.search(r"(?i)<(?:prompt|question|message|input|query)>", command):
        confidence += 0.05
    if re.search(r"\bjava\s+-jar\b", command, re.I) and re.search(r"\b(agent|assistant|chat)\b", f"{command}\n{text}", re.I):
        confidence += 0.03
    if re.search(r"(?:^|[/_-])se(?:[/_.-]|$)|standalone", command, re.I):
        confidence += 0.02
    if re.search(r"(?:^|[/_-])mp(?:[/_.-]|$)|microprofile", command, re.I):
        confidence -= 0.02
    if command.lower().startswith("make "):
        confidence -= 0.08
    if re.search(r"\bliberty:dev\b", command, re.I):
        confidence -= 0.06
    if _is_maintenance_or_external_agent_command(command):
        confidence -= 0.3
    return max(0.45, min(confidence, 0.9))


def _adjust_doc_confidence_for_project(root: Path, project_root: Path, language: str, confidence: float) -> float:
    try:
        rel_parts = [part.lower() for part in project_root.relative_to(root).parts]
    except ValueError:
        rel_parts = [part.lower() for part in project_root.parts]
    if any(part in {"examples", "example", "samples", "sample", "demo", "demos", "tutorial", "tutorials", "contrib"} for part in rel_parts):
        confidence -= 0.12
    if any(part in {"website", "docs", "doc", "documentation", "packages", "libs", "plugins", "integrations"} for part in rel_parts):
        confidence -= 0.05
    if _project_declares_runnable_surface(project_root, language, _sample_text(project_root)):
        confidence += 0.04
    return max(0.35, min(confidence, 0.9))


def _read_package(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _devcontainer_candidates(root: Path) -> list[AdapterCandidate]:
    path = root / ".devcontainer" / "devcontainer.json"
    if not path.exists():
        return []
    text = _strip_json_comments(path.read_text(encoding="utf-8", errors="replace"))
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    image = data.get("image")
    if not image:
        return []
    post_create = _as_list(data.get("postCreateCommand"))
    return [
        AdapterCandidate(
            name="devcontainer-plan",
            kind="plan_custom",
            language="custom",
            framework="Devcontainer",
            protocol="cli",
            image=str(image),
            install=[_clean_command(item) for item in post_create if _clean_command(item)],
            start="sh -lc 'echo devcontainer environment ready'",
            confidence=0.62,
            reason=".devcontainer/devcontainer.json declares a reusable runtime image.",
        )
    ]


def _python_install_commands_for(root: Path, project_root: Path) -> list[str]:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    commands = []
    if project_root != root and _python_nested_imports_parent_package(root, project_root):
        commands.append("/opt/agent-venv/bin/python -m pip install .")
    if (project_root / "uv.lock").exists():
        commands.extend([f"{cd}python -m pip install uv", f"{cd}VIRTUAL_ENV=/opt/agent-venv uv sync --frozen --active"])
    elif (project_root / "poetry.lock").exists() or "[tool.poetry]" in _read_text(project_root / "pyproject.toml"):
        commands.extend([f"{cd}/opt/agent-venv/bin/python -m pip install poetry", f"{cd}POETRY_VIRTUALENVS_CREATE=false /opt/agent-venv/bin/poetry install --no-interaction --no-root", f"{cd}/opt/agent-venv/bin/python -m pip install ."])
    elif (project_root / "requirements.txt").exists():
        commands.append(f"{cd}/opt/agent-venv/bin/python -m pip install -r requirements.txt")
        if (project_root / "pyproject.toml").exists():
            commands.append(f"{cd}/opt/agent-venv/bin/python -m pip install .")
    elif (project_root / "pyproject.toml").exists():
        commands.append(f"{cd}/opt/agent-venv/bin/python -m pip install .")
    extras = _python_import_extras(project_root)
    if extras:
        commands.append(f"{cd}/opt/agent-venv/bin/python -m pip install {' '.join(repr(item) for item in extras)}")
    return commands


def _python_nested_imports_parent_package(root: Path, project_root: Path) -> bool:
    if not any((root / name).exists() for name in ("pyproject.toml", "setup.cfg", "setup.py")):
        return False
    packages = _python_root_package_names(root)
    if not packages:
        return False
    text = "\n".join(_read_text(path)[:6000] for path in sorted(project_root.rglob("*.py"))[:60])
    return any(re.search(rf"\b(?:from|import)\s+{re.escape(package)}\b", text) for package in packages)


def _python_root_package_names(root: Path) -> set[str]:
    packages = {
        path.name
        for path in root.iterdir()
        if path.is_dir() and (path / "__init__.py").exists() and not path.name.startswith(".")
    }
    src = root / "src"
    if src.exists():
        packages.update(
            path.name
            for path in src.iterdir()
            if path.is_dir() and (path / "__init__.py").exists() and not path.name.startswith(".")
        )
    pyproject = _read_text(root / "pyproject.toml")
    for pattern in (
        r"\bpackages\s*=\s*\[(?P<items>[^\]]+)\]",
        r"\bmodule\s*=\s*['\"](?P<module>[A-Za-z_][\w.]*)['\"]",
    ):
        for match in re.finditer(pattern, pyproject):
            items = match.groupdict().get("items")
            module = match.groupdict().get("module")
            if module:
                packages.add(module.split(".")[0])
            if items:
                for item in re.findall(r"['\"]([A-Za-z_][\w.]*)['\"]", items):
                    packages.add(item.split(".")[0])
    return packages


def _node_install_commands_for(root: Path, project_root: Path, package: dict[str, Any]) -> list[str]:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    manager = _node_package_manager(project_root, package)
    if manager == "bun":
        commands = [f"{cd}bun install --frozen-lockfile"]
    elif manager == "pnpm":
        commands = [f"{cd}corepack enable", f"{cd}pnpm install --frozen-lockfile"]
    elif manager == "yarn":
        commands = [f"{cd}corepack enable", f"{cd}yarn install --frozen-lockfile"]
    elif manager == "npm-ci":
        commands = [f"{cd}npm ci"]
    else:
        commands = [f"{cd}npm install"]
    if "build" in scripts:
        commands.append(f"{cd}{_node_runner_for_manager(manager)} run build")
    return commands


def _node_package_manager(project_root: Path, package: dict[str, Any]) -> str:
    package_manager = str(package.get("packageManager") or "").lower()
    if _node_uses_bun(project_root, package):
        return "bun"
    if package_manager.startswith("pnpm@") or (project_root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if package_manager.startswith("yarn@") or (project_root / "yarn.lock").exists():
        return "yarn"
    if package_manager.startswith("npm@") or (project_root / "package-lock.json").exists():
        return "npm-ci"
    return "npm"


def _node_runner_for_manager(manager: str) -> str:
    if manager == "bun":
        return "bun"
    if manager == "pnpm":
        return "pnpm"
    if manager == "yarn":
        return "yarn"
    return "npm"


def _python_one_shot_starts(project_root: Path, root: Path) -> list[str]:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    starts: list[str] = []
    scripts = _project_scripts(project_root)
    text = _sample_text(project_root)
    for script_name, module_name in scripts.items():
        if _python_accepts_prompt_argument(project_root, module_name):
            starts.append(f'{cd}{script_name} "$SANDBOX_CLI_INPUT"')
        starts.extend(_python_prompt_subcommand_starts(project_root, module_name, f"{cd}{script_name}"))
        if _python_looks_like_tui_or_repo_orchestrator(project_root, module_name, text):
            continue
        starts.extend(_generic_cli_starts(f"{cd}{script_name}", text))
    for name in ("main.py", "agent.py", "app.py", "server.py", "cli.py", "chat.py", "assistant.py"):
        if (project_root / name).exists():
            if _python_accepts_prompt_argument(project_root, name):
                starts.append(f'{cd}PYTHONPATH=.:/workspace/{rel}:/workspace:$PYTHONPATH python {name} "$SANDBOX_CLI_INPUT"')
            command = f"{cd}PYTHONPATH=.:/workspace/{rel}:/workspace:$PYTHONPATH python {name}"
            starts.extend(_python_prompt_subcommand_starts(project_root, name, command))
            if _python_looks_like_tui_or_repo_orchestrator(project_root, name, text):
                continue
            starts.extend(_generic_cli_starts(f"{cd}PYTHONPATH=.:/workspace/{rel}:/workspace:$PYTHONPATH python {name}", text))
    return _unique(starts)


def _python_accepts_prompt_argument(project_root: Path, module_or_file: str) -> bool:
    source = _python_entry_source(project_root, module_or_file)
    if not source:
        return False
    text = _python_entry_text(project_root, source)
    if "add_subparsers" in text and _python_prompt_subcommands(text):
        return False
    prompt_names = r"(?:prompt|message|question|query|input|text)"
    if re.search(rf"@click\.argument\(\s*['\"]{prompt_names}['\"]", text, re.I):
        return True
    if re.search(r"@click\.argument\([^)]*nargs\s*=\s*-?1", text, re.I | re.S):
        return True
    if re.search(rf"(?:typer\.)?Argument\([^)]*(?:{prompt_names}|help\s*=\s*['\"][^'\"]*{prompt_names})", text, re.I | re.S):
        return True
    if re.search(rf"\.add_argument\(\s*['\"]{prompt_names}['\"]", text, re.I):
        return True
    if re.search(r"\.add_argument\(\s*['\"][^'\"]+['\"][^)]*nargs\s*=\s*['\"]?[+*]", text, re.I | re.S):
        return True
    return False


def _python_prompt_subcommand_starts(project_root: Path, module_or_file: str, base_command: str) -> list[str]:
    source = _python_entry_source(project_root, module_or_file)
    if not source:
        return []
    text = _python_entry_text(project_root, source)
    starts: list[str] = []
    for verb in _python_prompt_subcommands(text):
        starts.append(f'{base_command} {verb} "$SANDBOX_CLI_INPUT"')
    return _unique(starts)


def _python_prompt_subcommands(text: str) -> list[str]:
    found: list[str] = []
    prompt_names = r"(?:prompt|message|question|query|input|text)"
    for match in re.finditer(
        rf"(?P<var>\w+)\s*=\s*\w+\.add_parser\(\s*['\"](?P<verb>{'|'.join(ONE_SHOT_COMMANDS)})['\"][^)]*\)(?P<body>.{{0,1000}}?)"
        rf"(?P=var)\.add_argument\(\s*['\"]{prompt_names}['\"]",
        text,
        re.I | re.S,
    ):
        verb = match.group("verb").lower()
        if verb not in found:
            found.append(verb)
    for match in re.finditer(
        rf"\.add_parser\(\s*['\"](?P<verb>{'|'.join(ONE_SHOT_COMMANDS)})['\"][^)]*\)(?P<body>.{{0,800}}?)"
        rf"\.add_argument\(\s*['\"]{prompt_names}['\"]",
        text,
        re.I | re.S,
    ):
        verb = match.group("verb").lower()
        if verb not in found:
            found.append(verb)
    for match in re.finditer(
        rf"@(?:\w+\.)?command\(\s*['\"](?P<verb>{'|'.join(ONE_SHOT_COMMANDS)})['\"][^)]*\)\s*"
        rf"(?:@\w+\.argument\(\s*['\"]{prompt_names}['\"][^)]*\)\s*)*"
        rf"def\s+\w+\([^)]*{prompt_names}",
        text,
        re.I | re.S,
    ):
        verb = match.group("verb").lower()
        if verb not in found:
            found.append(verb)
    if re.search(r"\btyper\.Typer\(", text) and re.search(rf"\bdef\s+(?P<verb>{'|'.join(ONE_SHOT_COMMANDS)})\([^)]*{prompt_names}", text, re.I | re.S):
        for match in re.finditer(rf"\bdef\s+(?P<verb>{'|'.join(ONE_SHOT_COMMANDS)})\([^)]*{prompt_names}", text, re.I | re.S):
            verb = match.group("verb").lower()
            if verb not in found:
                found.append(verb)
    return found[:6]


def _python_looks_like_tui_or_repo_orchestrator(project_root: Path, module_or_file: str, project_text: str) -> bool:
    source = _python_entry_source(project_root, module_or_file)
    source_text = _python_entry_text(project_root, source) if source else ""
    combined = f"{project_text}\n{source_text}".lower()
    if any(token in combined for token in ("textual.app", "from textual", "rich.prompt", "prompt_toolkit", "curses.")):
        return True
    if "must be launched from inside a git repository" in combined:
        return True
    if all(token in combined for token in ("git repository", "ssh key", "workflow")):
        return True
    return False


def _python_entry_text(project_root: Path, source: Path) -> str:
    texts = [_read_text(source)]
    for related in _python_related_cli_sources(project_root, source):
        if related != source:
            texts.append(_read_text(related))
    return "\n".join(texts)


def _python_related_cli_sources(project_root: Path, source: Path) -> list[Path]:
    candidates: list[Path] = []
    package_root = source.parent
    for path in sorted(package_root.glob("*.py")):
        lowered = path.name.lower()
        if any(token in lowered for token in ("cli", "parser", "command", "arg", "main")):
            candidates.append(path)
    for match in re.finditer(r"from\s+\.(?P<module>[A-Za-z_][\w]*)\s+import|import\s+\.(?P<module2>[A-Za-z_][\w]*)", _read_text(source)):
        module = match.group("module") or match.group("module2")
        candidate = package_root / f"{module}.py"
        if candidate.exists():
            candidates.append(candidate)
    return [path for path in _unique_paths(candidates) if _is_within(path, project_root)]


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    result: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(path)
    return result


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _python_entry_source(project_root: Path, module_or_file: str) -> Path | None:
    file_candidate = project_root / module_or_file
    if file_candidate.exists() and file_candidate.is_file():
        return file_candidate
    module_path = module_or_file.replace(".", "/")
    for suffix in (".py", "/__init__.py"):
        candidate = project_root / f"{module_path}{suffix}"
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _node_one_shot_starts(project_root: Path, root: Path, package: dict[str, Any]) -> list[str]:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    text = _sample_text(project_root)
    starts: list[str] = []
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    for name, command in scripts.items():
        if _is_chat_word(name) or _looks_like_oneshot_command(str(command)):
            starts.append(f"{cd}npm run {name} -- \"$SANDBOX_CLI_INPUT\"")
    for entry in _node_cli_entry_files(project_root, package):
        rel_entry = entry.relative_to(project_root).as_posix()
        entry_text = _read_text(entry)
        verbs = _chat_verbs_in_text(entry_text) or _chat_verbs_in_text(text)
        for verb in verbs:
            starts.append(f"{cd}node {_shell_quote(rel_entry)} {verb} \"$SANDBOX_CLI_INPUT\"")
    starts.extend(_readme_command_starts(project_root, cd))
    return _unique(starts)


def _node_cli_entry_files(project_root: Path, package: dict[str, Any]) -> list[Path]:
    files: list[Path] = []
    bin_field = package.get("bin") if isinstance(package, dict) else None
    if isinstance(bin_field, str):
        files.append(project_root / bin_field)
    elif isinstance(bin_field, dict):
        for value in bin_field.values():
            if isinstance(value, str):
                files.append(project_root / value)
    for name in ("src/cli.js", "cli.js", "bin/cli.js", "src/index.js", "index.js", "dist/cli.js", "build/cli.js"):
        files.append(project_root / name)
    result = []
    for path in files:
        if path.exists() and path.is_file() and path not in result:
            result.append(path)
    return result


def _readme_command_starts(project_root: Path, cd: str) -> list[str]:
    text = "\n".join(_read_text(project_root / name) for name in ("README.md", "QUICKSTART.md", "USAGE.md"))
    starts: list[str] = []
    patterns = [
        r"(?P<cmd>node\s+[\w./-]+\.js\s+(?:ask|chat|prompt|query|generate|complete|send))\s+[\"'<]",
        r"(?P<cmd>npm\s+run\s+(?:ask|chat|prompt|query|generate|complete|send))\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            command = " ".join(match.group("cmd").split())
            if command.startswith("npm run"):
                starts.append(f"{cd}{command} -- \"$SANDBOX_CLI_INPUT\"")
            else:
                starts.append(f"{cd}{command} \"$SANDBOX_CLI_INPUT\"")
    return starts


def _python_start_for(project_root: Path, root: Path) -> str | None:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    scripts = _project_scripts(project_root)
    if scripts:
        text = _sample_text(project_root)
        for script_name, module_name in scripts.items():
            if not _python_looks_like_tui_or_repo_orchestrator(project_root, module_name, text):
                return f"{cd}PYTHONPATH=.:/workspace/{rel}:/workspace:$PYTHONPATH {script_name}"
        return None
    for name in ("main.py", "agent.py", "app.py", "server.py", "crew.py"):
        if (project_root / name).exists():
            return f"{cd}PYTHONPATH=.:/workspace/{rel}:/workspace:$PYTHONPATH python {name}"
    return None


def _python_is_http_project(project_root: Path) -> bool:
    text = _sample_text(project_root)
    declared = "\n".join(_read_text(project_root / name) for name in ("requirements.txt", "pyproject.toml"))
    return re.search(r"\bFastAPI\b|fastapi|uvicorn|Flask\(|from\s+flask\s+import", f"{declared}\n{text}", re.I) is not None


def _node_start_for(project_root: Path, root: Path, package: dict[str, Any]) -> str | None:
    rel = project_root.relative_to(root).as_posix() if project_root != root else "."
    cd = f"cd {rel} && " if rel != "." else ""
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    runner = _node_runner_for_manager(_node_package_manager(project_root, package))
    for key in ("start", "dev", "serve"):
        if key in scripts:
            return f"{cd}{runner} run {key}" if key != "start" else f"{cd}{runner} start"
    for name in ("index.js", "server.js", "main.js", "src/index.js", "build/index.js", "dist/index.js"):
        if (project_root / name).exists():
            return f"{cd}node {name}"
    return None


def _node_framework(project_root: Path, package: dict[str, Any]) -> str | None:
    deps: dict[str, Any] = {}
    deps.update(package.get("dependencies", {}) if isinstance(package.get("dependencies"), dict) else {})
    deps.update(package.get("devDependencies", {}) if isinstance(package.get("devDependencies"), dict) else {})
    text = _sample_text(project_root).lower()
    if _node_uses_bun(project_root, package):
        return "Bun"
    if any(name in deps for name in ("openai", "@langchain/openai", "langchain")) or "chat/completions" in text or "openai" in text:
        return "OpenAI-compatible CLI"
    if "anthropic" in deps or "anthropic" in text:
        return "Anthropic-compatible CLI"
    return None


def _node_image(project_root: Path, package: dict[str, Any]) -> str:
    return image_reserve.BUN_1 if _node_uses_bun(project_root, package) else image_reserve.NODE_22


def _node_uses_bun(project_root: Path, package: dict[str, Any] | None = None) -> bool:
    package = package or {}
    package_manager = str(package.get("packageManager") or "").lower()
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    return (
        (project_root / "bun.lock").exists()
        or (project_root / "bun.lockb").exists()
        or (project_root / ".bun-version").exists()
        or package_manager.startswith("bun@")
        or any("bun " in str(command).lower() for command in scripts.values())
    )


def _node_is_mcp_project(project_root: Path, package: dict[str, Any]) -> bool:
    deps: dict[str, Any] = {}
    deps.update(package.get("dependencies", {}) if isinstance(package.get("dependencies"), dict) else {})
    deps.update(package.get("devDependencies", {}) if isinstance(package.get("devDependencies"), dict) else {})
    text = _sample_text(project_root).lower()
    return "@modelcontextprotocol/sdk" in deps or "modelcontextprotocol" in text or "tools/list" in text or "resources/list" in text


def _go_install_commands_for(root: Path) -> list[str]:
    if (root / "vendor").exists():
        return []
    if (root / "go.mod").exists():
        return ["go mod download"]
    return []


def _go_main_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("main.go")):
        rel_parts = path.relative_to(root).parts
        if any(part in {"vendor", ".git", ".sandbox_data", "testdata"} for part in rel_parts):
            continue
        if any(part.startswith(".") for part in rel_parts):
            continue
        if _is_go_main(path):
            files.append(path)
    files.sort(key=lambda item: (-_go_entrypoint_score(item, root), len(item.relative_to(root).parts), item.as_posix()))
    return files


def _go_entrypoint_score(path: Path, root: Path) -> float:
    rel = path.parent.relative_to(root).as_posix()
    parts = [part.lower() for part in path.parent.relative_to(root).parts]
    score = 0.0
    if rel == ".":
        score += 0.8
    if rel.startswith("cmd/"):
        score += 0.7
    lowered = rel.lower()
    if any(token in lowered for token in ("agent", "assistant", "chat", "bot", "mcp", "server", "api")):
        score += 0.45
    if any(token in lowered for token in ("simple", "hello", "quickstart", "starter")):
        score += 0.18
    if any(part in {"examples", "example", "samples", "sample", "demo", "demos", "tutorials", "tutorial", "contrib"} for part in parts):
        score -= 0.25
    if any(part in {"tests", "test", "docs", "website"} for part in parts):
        score -= 0.35
    text = _sample_text(path.parent).lower()
    if re.search(r"\b(openai|anthropic|deepseek|chat/completions|modelcontextprotocol|mcp)\b", text):
        score += 0.2
    if re.search(r"\b(web-search|browser|computer-use|github|slack|oauth|cloudflare)\b", lowered):
        score -= 0.18
    return score


def _go_entry_confidence(rel_dir: str, confidence: float) -> float:
    lowered = rel_dir.lower()
    if re.search(r"(^|/)(examples?|samples?|demos?|tutorials?|contrib)(/|$)", lowered):
        confidence -= 0.08
    if re.search(r"(^|/)(simple|hello|quickstart|starter|chat|agent|assistant|server|mcp)(/|$)", lowered):
        confidence += 0.04
    if re.search(r"(^|/)(web-search|browser|computer-use|github|slack|cloudflare)(/|$)", lowered):
        confidence -= 0.06
    return max(0.35, min(confidence, 0.94))


def _is_go_main(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    text = _read_text(path)
    return re.search(r"(?m)^\s*package\s+main\s*$", text) is not None and re.search(r"\bfunc\s+main\s*\(", text) is not None


def _go_cli_candidates(rel_dir: str, binary: str, install: list[str], module_text: str, project_text: str, confidence: float, reason: str) -> list[AdapterCandidate]:
    starts = _generic_cli_starts(binary, project_text)
    candidates = []
    for idx, start in enumerate(starts):
        candidates.append(
            AdapterCandidate(
                name=f"go-plan:{rel_dir}:oneshot:{idx + 1}" if idx else f"go-plan:{rel_dir}",
                kind="plan_go",
                language="Go",
                framework=_go_framework(project_text),
                protocol="cli",
                image=_go_image(module_text),
                install=install,
                start=start,
                confidence=_go_start_confidence(confidence, start),
                reason=reason,
            )
        )
    return candidates


def _go_mcp_candidate(rel_dir: str, binary: str, install: list[str], module_text: str, project_text: str, confidence: float, reason: str) -> AdapterCandidate:
    return AdapterCandidate(
        name=f"go-mcp:{rel_dir}",
        kind="plan_go",
        language="Go",
        framework="MCP",
        protocol="mcp",
        image=_go_image(module_text),
        install=install,
        start=binary,
        confidence=confidence,
        reason=reason,
    )


def _go_entry_commands(root: Path, module_root: Path, package_ref: str, binary: str) -> list[str]:
    rel = module_root.relative_to(root).as_posix() if module_root != root else "."
    commands = _go_install_commands_for(module_root)
    commands.append(f"go build -o {binary} {package_ref}")
    if rel == ".":
        return commands
    return [f"cd {rel} && {command}" for command in commands]


def _nearest_go_module(start: Path, root: Path) -> Path:
    current = start
    while current != root and current.parent != current:
        if (current / "go.mod").exists():
            return current
        current = current.parent
    return root


def _go_main_looks_mcp(project_root: Path, text: str) -> bool:
    lowered = text.lower()
    if "modelcontextprotocol" in lowered or "github.com/mark3labs/mcp-go" in lowered or "go-sdk/mcp" in lowered:
        return True
    for path in sorted(project_root.rglob("*.go"))[:30]:
        content = _read_text(path).lower()
        if "mcp.newserver" in content or "server.stdio" in content or "stdio" in content and "mcp" in content:
            return True
    return False


def _go_start_confidence(confidence: float, start: str) -> float:
    if _uses_chat_subcommand(start):
        return min(0.93, confidence + 0.03)
    if 'printf "%s\\n" "$SANDBOX_CLI_INPUT"' in start:
        return max(0.1, confidence - 0.02)
    return confidence


def _go_cli_start(binary: str) -> str:
    return (
        f"if [ -n \"${{SANDBOX_CLI_INPUT:-}}\" ]; then {binary} \"$SANDBOX_CLI_INPUT\"; "
        f"else {binary} --help; fi"
    )


def _go_image(module_text: str) -> str:
    match = re.search(r"(?m)^\s*go\s+(\d+)\.(\d+)(?:\.\d+)?\s*$", module_text)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if (major, minor) >= (1, 25):
            return image_reserve.GO_125
    return image_reserve.GO_124


def _go_framework(text: str) -> str | None:
    lowered = text.lower()
    if "agent" in lowered and any(token in lowered for token in ("openai", "anthropic", "llm", "tool")):
        return "Go CLI Agent"
    if "cobra" in lowered or "spf13/cobra" in lowered:
        return "Cobra CLI"
    return None


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return cleaned[:60] or "go-app"


def _cargo_package_name(manifest: str) -> str | None:
    in_package = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if stripped.startswith("[") and stripped != "[package]":
            in_package = False
        if in_package and stripped.startswith("name") and "=" in stripped:
            return stripped.split("=", 1)[1].strip().strip("\"'")
    return None


def _generic_cli_starts(base_command: str, text: str, global_options: str = "", extra_verbs: list[str] | None = None) -> list[str]:
    verbs = _unique([*(extra_verbs or []), *_chat_verbs_in_text(text)])
    command = " ".join(part for part in (base_command, global_options.strip()) if part).strip()
    starts = [
        f'if [ -n "${{SANDBOX_CLI_INPUT:-}}" ]; then {command} "$SANDBOX_CLI_INPUT"; else {command} --help || {command} -h || {command}; fi',
        f'if [ -n "${{SANDBOX_CLI_INPUT:-}}" ]; then printf "%s\\n" "$SANDBOX_CLI_INPUT" | {command}; else {command} --help || {command} -h || {command}; fi',
    ]
    for verb in verbs:
        starts.append(f'{command} {verb} "$SANDBOX_CLI_INPUT"')
    return _unique(starts)


def _chat_verbs_in_text(text: str) -> list[str]:
    found: list[str] = []
    patterns = [
        r"\.command\(\s*['\"](?P<verb>ask|chat|prompt|query|generate|complete|completion|send|message)(?:\s|<|$)",
        r"\b(?:command|subcommand|Command::new|@app\.command)\s*\(?\s*['\"](?P<verb2>ask|chat|prompt|query|generate|complete|completion|send|message)",
        r"\b(?P<verb3>ask|chat|prompt|query|generate|complete|completion|send|message)\s+<[^>]+>",
        r"\.command\(\s*['\"](?P<verb4>say)(?:\s|<|$)",
        r"\b(?:command|subcommand|Command::new|@app\.command)\s*\(?\s*['\"](?P<verb5>say)",
        r"\b(?P<verb6>say)\s+<[^>]+>",
        r"\b(?:Commands|Subcommand)::(?P<verb8>Ask|Chat|Prompt|Query|Generate|Complete|Completion|Send|Message|Say)\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            verb = next((value for value in match.groupdict().values() if value), "")
            if verb and verb.lower() not in found:
                found.append(verb.lower())
    return found[:6]


def _is_chat_word(value: str) -> bool:
    lowered = value.lower().strip()
    return lowered in CHAT_COMMANDS or any(lowered.endswith(f":{verb}") for verb in CHAT_COMMANDS)


def _looks_like_oneshot_command(command: str) -> bool:
    lowered = command.lower()
    return any(re.search(rf"\b{verb}\b", lowered) for verb in CHAT_COMMANDS) and "interactive" not in lowered


def _uses_chat_subcommand(command: str) -> bool:
    lowered = command.lower()
    return any(re.search(rf"\b{re.escape(verb)}\s+\"\$sandbox_cli_input\"", lowered) for verb in CHAT_COMMANDS)


def _is_interactive_start(command: str) -> bool:
    lowered = command.lower()
    return any(token in lowered for token in (" interactive", " inquirer", "npm start", "pnpm start", "yarn start")) and "sandbox_cli_input" not in lowered


def _adjust_confidence_for_start(command: str, confidence: float) -> float:
    if "$SANDBOX_CLI_INPUT" in command or "${SANDBOX_CLI_INPUT" in command:
        confidence += 0.08
    if _is_interactive_start(command):
        confidence -= 0.25
    return max(0.1, min(confidence, 0.95))


def _candidate_dict_score(candidate: dict[str, Any]) -> tuple[float, float, float, float, float]:
    start = str(candidate.get("start") or "")
    protocol = str(candidate.get("protocol") or "cli").lower()
    confidence = _safe_float(candidate.get("confidence"), 0.0)
    protocol_fit = 1.0 if protocol in {"http", "mcp", "browser"} else 0.0
    oneshot = 1.0 if "$SANDBOX_CLI_INPUT" in start or "${SANDBOX_CLI_INPUT" in start else 0.0
    noninteractive = 0.0 if _is_interactive_start(start) else 1.0
    return (protocol_fit, oneshot, noninteractive, _image_tier_score(str(candidate.get("image") or "")), confidence)


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _langgraph_probe_command(rel_project: str, rel_graph: str, attr: str, graph_name: str) -> str:
    cd = f"cd {rel_project} && " if rel_project != "." else ""
    return (
        f"{cd}PYTHONPATH=.:/workspace/{rel_project}:/workspace:$PYTHONPATH python - <<'PY'\n"
        "import importlib.util\n"
        f"spec = importlib.util.spec_from_file_location('aegisagent_graph', {rel_graph!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "assert spec and spec.loader\n"
        "spec.loader.exec_module(module)\n"
        f"graph = getattr(module, {attr!r})\n"
        f"print('LANGGRAPH_GRAPH_LOADED {graph_name}')\n"
        "print(type(graph).__name__)\n"
        "PY"
    )


def _nearest_python_project(start: Path, root: Path) -> Path:
    current = start
    while current != root and current.parent != current:
        if (current / "pyproject.toml").exists() or (current / "requirements.txt").exists():
            return current
        current = current.parent
    return root


def _python_framework(project_root: Path) -> str | None:
    text = _sample_text(project_root)
    if re.search(r"langgraph", text, re.I):
        return "LangGraph"
    if re.search(r"crewai", text, re.I):
        return "CrewAI"
    if re.search(r"langchain", text, re.I):
        return "LangChain/LangGraph"
    return None


def _python_runtime_framework(project_root: Path, start: str | None) -> str | None:
    framework = _python_framework(project_root)
    text = _sample_text(project_root)
    if start and _python_looks_like_tui_or_repo_orchestrator(project_root, _python_start_module_from_command(start), text):
        return "Repository Terminal UI" if "git repository" in text.lower() or "ssh key" in text.lower() else "Terminal UI"
    return framework


def _python_start_module_from_command(start: str) -> str:
    match = re.search(r"\bpython\s+([A-Za-z0-9_./-]+\.py)\b", start)
    if match:
        return match.group(1)
    parts = start.split()
    return parts[-1] if parts else ""


def _python_image(project_root: Path) -> str:
    return image_reserve.PYTHON_312


def _python_import_extras(project_root: Path) -> list[str]:
    text = _sample_text(project_root)
    declared = "\n".join(_read_text(project_root / name) for name in ("pyproject.toml", "requirements.txt")).lower()
    mapping = {
        "langgraph": "langgraph",
        "langchain": "langchain",
        "langchain_openai": "langchain-openai",
        "langchain_anthropic": "langchain-anthropic",
        "langchain_community": "langchain-community",
        "crewai_tools": "crewai-tools",
        "click": "click",
        "typer": "typer",
        "rich": "rich",
        "yaml": "PyYAML",
        "dotenv": "python-dotenv",
        "requests": "requests",
        "httpx": "httpx",
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "flask": "flask",
        "pydantic_settings": "pydantic-settings",
    }
    extras = []
    for module, package in mapping.items():
        if re.search(rf"\b(import|from)\s+{re.escape(module)}\b", text) and package.lower() not in declared:
            extras.append(package)
    if _uses_legacy_openai_api(text) and not _uses_modern_openai_client(text) and not re.search(r"openai\s*(?:[<~]=?|==)\s*0|openai\s*<\s*1", declared, re.I):
        extras.append("openai<1")
    return extras


def _uses_legacy_openai_api(text: str) -> bool:
    return any(pattern in text for pattern in ("openai.ChatCompletion.create", "openai.Completion.create", "openai.Image.create", "openai.Audio."))


def _uses_modern_openai_client(text: str) -> bool:
    return re.search(r"from\s+openai\s+import\s+(?:AsyncOpenAI|OpenAI)\b|\b(?:AsyncOpenAI|OpenAI)\s*\(", text) is not None


def _project_scripts(project_root: Path) -> dict[str, str]:
    pyproject = _read_text(project_root / "pyproject.toml")
    scripts: dict[str, str] = {}
    in_scripts = False
    for line in pyproject.splitlines():
        stripped = line.strip()
        if stripped == "[project.scripts]":
            in_scripts = True
            continue
        if stripped.startswith("[") and stripped != "[project.scripts]":
            in_scripts = False
        if in_scripts and "=" in stripped:
            key, value = stripped.split("=", 1)
            scripts[key.strip()] = value.strip().strip("\"'").split(":")[0]
    return scripts


def _looks_like_http_node(project_root: Path, package: dict[str, Any]) -> bool:
    deps = {}
    deps.update(package.get("dependencies", {}))
    deps.update(package.get("devDependencies", {}))
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    text = _sample_text(project_root)
    if any(name in deps for name in ("express", "fastify", "vite", "next", "nuxt", "astro", "@sveltejs/kit")):
        return True
    if any(_node_script_looks_http(str(command)) for command in scripts.values()):
        return True
    return re.search(r"express\s*\(|fastify|listen\(", text, re.I) is not None


def _dedupe(candidates: list[AdapterCandidate]) -> list[AdapterCandidate]:
    seen = set()
    normal = []
    low_priority = []
    for candidate in sorted(candidates, key=_candidate_score, reverse=True):
        key = (candidate.kind, candidate.protocol, candidate.image, candidate.start, tuple(candidate.install))
        if not candidate.start or key in seen:
            continue
        seen.add(key)
        if _candidate_is_low_priority_sample(candidate):
            low_priority.append(candidate)
        else:
            normal.append(candidate)
    return [*normal, *low_priority[:LOW_PRIORITY_SAMPLE_CANDIDATE_LIMIT]][:MAX_CANDIDATES]


def _candidate_dict_is_low_priority_sample(candidate: dict[str, Any]) -> bool:
    text = " ".join(
        str(value)
        for value in (
            candidate.get("name"),
            candidate.get("start"),
            " ".join(str(item) for item in candidate.get("install", []) or []),
            candidate.get("reason"),
        )
        if value
    )
    return _candidate_text_is_low_priority_sample(text)


def _candidate_is_low_priority_sample(candidate: AdapterCandidate) -> bool:
    text = " ".join([candidate.name, candidate.start or "", " ".join(candidate.install), candidate.reason or ""])
    return _candidate_text_is_low_priority_sample(text)


def _candidate_text_is_low_priority_sample(text: str) -> bool:
    lowered = text.lower()
    if not re.search(r"(^|[\s:/_-])(examples?|samples?|demos?|tutorials?|contrib)([\s:/_-]|$)", lowered):
        return False
    return not re.search(r"(^|[\s:/_-])(agent|assistant|chat|bot|mcp|server|api|simple|hello|quickstart|starter)([\s:/_-]|$)", lowered)


def _candidate_score(candidate: AdapterCandidate) -> tuple[float, float, float, float, float]:
    start = candidate.start or ""
    protocol_fit = 1.0 if candidate.protocol in {"http", "mcp", "browser"} else 0.0
    oneshot = 1.0 if "$SANDBOX_CLI_INPUT" in start or "${SANDBOX_CLI_INPUT" in start else 0.0
    noninteractive = 0.0 if _is_interactive_start(start) else 1.0
    return (protocol_fit, oneshot, noninteractive, _image_tier_score(candidate.image), candidate.confidence)


def _image_tier_score(image: str) -> float:
    if image.startswith("aegisagent-"):
        return 1.0
    if image in {image_reserve.BUN_1, image_reserve.SHELL_BASH}:
        return 0.95
    if image.startswith("m.daocloud.io/"):
        return 0.65
    if any(image.startswith(prefix + "/") for prefix in image_reserve.DOCKERHUB_MIRROR_PREFIXES):
        return 0.55
    if "/" not in image or image.startswith(("python:", "node:", "golang:", "rust:", "maven:", "bash:")):
        return 0.45
    return 0.35


def _clean_command(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > 2000:
        return ""
    banned = (":(){ :|:& };:", "rm -rf /", "mkfs", "dd if=", "shutdown", "reboot", "docker run", "docker build")
    lowered = value.lower()
    if any(item in lowered for item in banned):
        return ""
    return value


def _is_help_only_command(command: str) -> bool:
    lowered = command.strip().lower()
    if any(token in lowered for token in ("$sandbox_cli_input", "${sandbox_cli_input", "< /dev/stdin")):
        return False
    parts = re.split(r"\s+", lowered)
    return any(part in {"-h", "--help", "help", "usage"} for part in parts[-2:])


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _default_image(language: str) -> str:
    lowered = language.lower()
    if "node" in lowered:
        return image_reserve.NODE_22
    if "go" in lowered:
        return image_reserve.GO_124
    if "rust" in lowered:
        return image_reserve.RUST_1
    if "java" in lowered:
        return image_reserve.JAVA_21
    if "shell" in lowered or "bash" in lowered:
        return image_reserve.SHELL_BASH
    return image_reserve.PYTHON_312


def _language_key(language: str, framework: str | None = None) -> str:
    lowered = f"{language} {framework or ''}".lower()
    if "python" in lowered:
        return "python"
    if "node" in lowered or "javascript" in lowered or "typescript" in lowered:
        return "node"
    if "go" in lowered or "golang" in lowered:
        return "go"
    if "rust" in lowered:
        return "rust"
    if "java" in lowered:
        return "java"
    if "shell" in lowered or "bash" in lowered:
        return "shell"
    return "custom"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _strip_json_comments(text: str) -> str:
    return re.sub(r"//.*", "", text)


def _sample_text(root: Path) -> str:
    parts = []
    for path in list(root.rglob("*"))[:500]:
        if path.is_file() and path.suffix.lower() in {".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".sh", ".bash", ".json", ".yaml", ".yml", ".toml", ".md", ".txt"}:
            parts.append(_read_text(path)[:4000])
    return "\n".join(parts)


def _read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:200000]
    except OSError:
        return ""
