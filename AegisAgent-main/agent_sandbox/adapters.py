from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import image_reserve


@dataclass
class AdapterCandidate:
    name: str
    kind: str
    language: str
    framework: str | None
    protocol: str
    image: str
    install: list[str] = field(default_factory=list)
    start: str | None = None
    port: int | None = None
    fake_llm: bool = False
    confidence: float = 0.5
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_adapters(root: Path, profile: Any) -> list[AdapterCandidate]:
    candidates: list[AdapterCandidate] = []
    sandbox = getattr(profile, "sandbox_yaml", None)
    if sandbox and not sandbox.get("error"):
        install = sandbox.get("install", [])
        if isinstance(install, str):
            install = [install]
        return [
            AdapterCandidate(
                name="sandbox.yaml",
                kind="sandbox_yaml",
                language=str(sandbox.get("language", "custom")),
                framework=sandbox.get("framework"),
                protocol=str(sandbox.get("protocol", "cli")),
                image=str(sandbox.get("image", "python:3.12-slim")),
                install=[str(item) for item in install],
                start=str(sandbox.get("start")) if sandbox.get("start") else None,
                port=int(sandbox.get("port", 8000)) if sandbox.get("port") else None,
                confidence=0.98,
                reason="Project provided sandbox.yaml.",
            )
        ]

    from .plan_discovery import discover_plan_candidates

    candidates.extend(discover_plan_candidates(root, profile))

    if (root / "Dockerfile").exists():
        candidates.append(AdapterCandidate("dockerfile", "dockerfile", "Docker", None, "docker", "local-dockerfile", confidence=0.7, reason="Dockerfile exists."))

    package = _read_package(root)
    pyproject = _read_text(root / "pyproject.toml")
    requirements = _read_text(root / "requirements.txt")
    all_text = _sample_text(root)

    if _looks_like_mcp(root, package, all_text):
        if package:
            node_mcp_start = _node_mcp_start(root, package)
            if node_mcp_start:
                candidates.append(
                    AdapterCandidate(
                        "node-mcp-stdio",
                        "node",
                        "Node.js",
                        "Bun MCP" if _node_uses_bun(root, package) else "MCP",
                        "mcp",
                        _node_image(root, package),
                        install=_node_install(root, package),
                        start=node_mcp_start,
                        confidence=0.93,
                        reason="Node MCP markers found.",
                    )
                )
        elif _looks_like_python_mcp(root, all_text):
            candidates.append(
                AdapterCandidate(
                    "python-mcp-stdio",
                    "python",
                    "Python",
                    "MCP",
                    "mcp",
                    _python_image(root),
                    install=_python_install(root),
                    start=_python_start(root) or "python server.py",
                    confidence=0.9,
                    reason="Python MCP markers found.",
                )
            )

    if _looks_like_crewai(root, pyproject, requirements, all_text):
        candidates.append(
            AdapterCandidate(
                "python-crewai",
                "python",
                "Python",
                "CrewAI",
                "cli",
                _python_image(root),
                install=_python_install(root),
                start=_crewai_start(root),
                fake_llm=True,
                confidence=0.86,
                reason="CrewAI files or dependency markers found.",
            )
        )

    if _looks_like_langchain(pyproject, requirements, all_text):
        candidates.append(
            AdapterCandidate(
                "python-langchain",
                "python",
                "Python",
                "LangChain/LangGraph",
                "cli",
                _python_image(root),
                install=_python_install(root),
                start=_python_start(root),
                confidence=0.78,
                reason="LangChain or LangGraph dependency markers found.",
            )
        )

    if _looks_like_autogen(pyproject, requirements, all_text):
        candidates.append(
            AdapterCandidate(
                "python-autogen",
                "python",
                "Python",
                "AutoGen",
                "cli",
                _python_image(root),
                install=_python_install(root),
                start=_python_start(root),
                confidence=0.76,
                reason="AutoGen dependency markers found.",
            )
        )

    if _looks_like_fastapi(root, requirements, all_text):
        module = _fastapi_module(root)
        candidates.append(
            AdapterCandidate(
                "python-fastapi-http",
                "python",
                "Python",
                "FastAPI",
                "http",
                _python_image(root),
                install=_python_install(root),
                start=f"{_venv_prefix()} PYTHONPATH=/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python -m uvicorn {module}:app --host 0.0.0.0 --port 8000",
                port=8000,
                confidence=0.82,
                reason="FastAPI app object detected.",
            )
        )

    if package:
        framework = "Express" if _looks_like_express(package, all_text) else None
        if _node_uses_bun(root, package):
            framework = f"Bun {framework}".strip() if framework else "Bun"
        protocol = "http" if framework else "cli"
        candidates.append(
            AdapterCandidate(
                "node-express-http" if framework else "node-cli",
                "node",
                "Node.js",
                framework,
                protocol,
                _node_image(root, package),
                install=_node_install(root, package),
                start=_node_start(root, package),
                port=3000 if protocol == "http" else None,
                confidence=0.74 if framework else 0.65,
                reason="package.json start script or Node entrypoint detected.",
            )
        )

    if _has_python(root):
        candidates.append(
            AdapterCandidate(
                "python-cli",
                "python",
                "Python",
                _python_fallback_framework(root),
                "cli",
                _python_image(root),
                install=_python_install(root),
                start=_python_start(root),
                confidence=0.64,
                reason="Python manifest or entrypoint detected.",
            )
        )

    if (root / "go.mod").exists():
        candidates.append(AdapterCandidate("go-cli", "go", "Go", None, "cli", image_reserve.GO_124, install=["GOMODCACHE=/workspace/.sandbox_deps/gomod GOCACHE=/workspace/.sandbox_deps/gocache go mod download"], start="GOMODCACHE=/workspace/.sandbox_deps/gomod GOCACHE=/workspace/.sandbox_deps/gocache go run .", confidence=0.62, reason="go.mod exists."))
    if (root / "Cargo.toml").exists():
        candidates.append(AdapterCandidate("rust-cli", "rust", "Rust", None, "cli", image_reserve.RUST_1, install=[*_rust_system_package_commands(root), "CARGO_HOME=/workspace/.sandbox_deps/cargo cargo fetch"], start="CARGO_HOME=/workspace/.sandbox_deps/cargo cargo run", confidence=0.62, reason="Cargo.toml exists."))
    if (root / "pom.xml").exists():
        candidates.append(AdapterCandidate("java-maven-cli", "java", "Java", None, "cli", image_reserve.JAVA_21, install=["mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q -DskipTests dependency:go-offline"], start="mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q exec:java", confidence=0.6, reason="pom.xml exists."))
    shell = next((path for path in root.glob("*.sh") if not _is_auxiliary_shell_script(path, root)), None)
    if shell:
        candidates.append(AdapterCandidate("shell-cli", "shell", "Shell", None, "cli", "bash:5.2", start=f"bash {shell.name}", confidence=0.55, reason="Shell entrypoint found."))

    return _dedupe_sorted(candidates)


def candidate_from_dict(data: dict[str, Any]) -> AdapterCandidate:
    return AdapterCandidate(**{key: data.get(key) for key in AdapterCandidate.__dataclass_fields__})


def _dedupe_sorted(candidates: list[AdapterCandidate]) -> list[AdapterCandidate]:
    seen: set[tuple[str, str, str | None]] = set()
    unique: list[AdapterCandidate] = []
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        if not candidate.start and candidate.kind not in {"dockerfile"}:
            continue
        key = (candidate.name, candidate.protocol, candidate.image, candidate.start)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique[:20]


def _read_package(root: Path) -> dict[str, Any] | None:
    path = root / "package.json"
    if not path.exists():
        return None
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError:
        return None


def _read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:200000]
    except OSError:
        return ""


def _sample_text(root: Path) -> str:
    parts = []
    for path in list(root.rglob("*"))[:500]:
        if path.is_file() and path.suffix.lower() in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".md"}:
            parts.append(_read_text(path)[:4000])
    return "\n".join(parts)


def _has_python(root: Path) -> bool:
    return any((root / name).exists() for name in ("requirements.txt", "pyproject.toml", "main.py", "app.py", "agent.py", "crew.py"))


def _is_auxiliary_shell_script(script: Path, root: Path) -> bool:
    if not _has_primary_project_manifest(root):
        return False
    lowered = script.name.lower()
    if lowered in {"install.sh", "setup.sh", "bootstrap.sh", "configure.sh"}:
        return True
    return any(token in lowered for token in ("test", "demo", "example", "bench", "install", "setup", "bootstrap", "quiet-run"))


def _has_primary_project_manifest(root: Path) -> bool:
    return any((root / name).exists() for name in ("Cargo.toml", "package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts"))


def _python_install(root: Path) -> list[str]:
    use_venv = (root / "pyproject.toml").exists()
    commands = ["python -m venv /workspace/.sandbox_venv"] if use_venv else []
    python_bin = "/workspace/.sandbox_venv/bin/python" if use_venv else "python"
    target = "" if use_venv else "--target /workspace/.sandbox_deps/python"
    if (root / "requirements.txt").exists():
        commands.append(f"{python_bin} -m pip install --no-cache-dir {target} -r requirements.txt")
    if (root / "pyproject.toml").exists():
        constraint = " crewai==0.193.2" if _looks_like_crewai(root, _read_text(root / "pyproject.toml"), _read_text(root / "requirements.txt"), _sample_text(root)) else ""
        commands.append(f"{python_bin} -m pip install --no-cache-dir .{constraint}")
    extras = _python_import_extras(root)
    if extras:
        commands.append(f"{python_bin} -m pip install --no-cache-dir {target} {' '.join(extras)}")
    return commands


def _python_import_extras(root: Path) -> list[str]:
    text = _sample_text(root)
    declared = f"{_read_text(root / 'pyproject.toml')}\n{_read_text(root / 'requirements.txt')}".lower()
    mapping = {
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


def _python_image(root: Path) -> str:
    return image_reserve.PYTHON_312


def _python_fallback_framework(root: Path) -> str | None:
    text = _sample_text(root).lower()
    if any(token in text for token in ("textual.app", "from textual", "prompt_toolkit", "rich.prompt")):
        return "Repository Terminal UI" if "git repository" in text or "ssh key" in text else "Terminal UI"
    return None


def _python_start(root: Path) -> str | None:
    for name in ("main.py", "agent.py", "crew.py", "app.py", "server.py"):
        if (root / name).exists():
            return f"{_venv_prefix()} PYTHONPATH=/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python {name}"
    scripts = _project_scripts(root)
    if scripts:
        script_name = next(iter(scripts))
        return f"{_venv_prefix()} PYTHONPATH=/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH {script_name}"
    return None


def _crewai_start(root: Path) -> str | None:
    prefix = _fake_llm_prefix()
    if (root / "crew.py").exists():
        return f"{_venv_prefix()} {prefix} PYTHONPATH=/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python crew.py"
    if (root / "src").exists():
        scripts = _project_scripts(root)
        for script_name in ("markdown_validator", "run_crew", "run"):
            if script_name in scripts:
                sample_arg = " sandbox_sample.md" if (root / "sandbox_sample.md").exists() else ""
                return f"{_venv_prefix()} {prefix} PYTHONPATH=/workspace/src:/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python -m {scripts[script_name]}{sample_arg}"
        main = next(root.glob("src/*/main.py"), None)
        if main:
            module = main.relative_to(root / "src").with_suffix("").as_posix().replace("/", ".")
            sample_arg = " sandbox_sample.md" if (root / "sandbox_sample.md").exists() else ""
            return f"{_venv_prefix()} {prefix} PYTHONPATH=/workspace/src:/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python -m {module}{sample_arg}"
    return f"{_venv_prefix()} {prefix} PYTHONPATH=/workspace:/workspace/.sandbox_deps/python:$PYTHONPATH python -m crewai run"


def _venv_prefix() -> str:
    return "if [ -f /workspace/.sandbox_venv/bin/activate ]; then . /workspace/.sandbox_venv/bin/activate; fi;"


def _project_scripts(root: Path) -> dict[str, str]:
    pyproject = _read_text(root / "pyproject.toml")
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


def _fake_llm_prefix() -> str:
    return (
        "export OPENAI_API_KEY=${OPENAI_API_KEY:-sk-sandbox-fake}; "
        "export OPENAI_API_BASE_URL=${OPENAI_API_BASE_URL:-http://127.0.0.1:8765/v1}; "
        "export OPENAI_BASE_URL=${OPENAI_BASE_URL:-http://127.0.0.1:8765/v1}; "
        "export MODEL_NAME=${MODEL_NAME:-gpt-4o-mini}; "
        "python .agent_sandbox_fake_openai.py --host 127.0.0.1 --port 8765 & "
        "FAKE_LLM_PID=$!; sleep 1;"
    )


def _node_start(root: Path, package: dict[str, Any]) -> str:
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    runner = "bun" if _node_uses_bun(root, package) else "npm"
    if "start" in scripts:
        return f"{runner} start"
    if "dev" in scripts:
        return f"{runner} run dev"
    for name in ("index.js", "server.js", "main.js", "src/index.js", "build/index.js", "dist/index.js"):
        if (root / name).exists():
            return f"node {name}"
    bin_field = package.get("bin") if isinstance(package, dict) else None
    if isinstance(bin_field, str):
        return f"{'bun' if _node_uses_bun(root, package) else 'node'} {bin_field}"
    if isinstance(bin_field, dict) and bin_field:
        return f"{'bun' if _node_uses_bun(root, package) else 'node'} {next(iter(bin_field.values()))}"
    return "node -e \"console.log('No Node entrypoint detected')\""


def _node_install(root: Path, package: dict[str, Any]) -> list[str]:
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if _node_uses_bun(root, package):
        commands = ["bun install --frozen-lockfile --ignore-scripts"]
    else:
        commands = ["npm ci --ignore-scripts" if (root / "package-lock.json").exists() else "npm install --ignore-scripts"]
    if "build" in scripts:
        commands.append("bun run build" if _node_uses_bun(root, package) else "npm run build")
    return commands


def _node_image(root: Path, package: dict[str, Any]) -> str:
    return image_reserve.BUN_1 if _node_uses_bun(root, package) else image_reserve.NODE_22


def _node_uses_bun(root: Path, package: dict[str, Any] | None = None) -> bool:
    package = package or {}
    package_manager = str(package.get("packageManager") or "").lower()
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    return (
        (root / "bun.lock").exists()
        or (root / "bun.lockb").exists()
        or (root / ".bun-version").exists()
        or package_manager.startswith("bun@")
        or any("bun " in str(command).lower() for command in scripts.values())
    )


def _rust_system_package_commands(root: Path) -> list[str]:
    manifest = _read_text(root / "Cargo.toml").lower()
    packages = ["pkg-config", "libssl-dev"]
    if any(token in manifest for token in ("keyring", "secret-service", "dbus", "zbus")):
        packages.append("libdbus-1-dev")
    if any(token in manifest for token in ("rusqlite", "sqlite")):
        packages.append("libsqlite3-dev")
    if any(token in manifest for token in ("clang", "bindgen", "rocksdb", "onnxruntime")):
        packages.extend(["clang", "cmake"])
    return [f"apt-get update && apt-get install -y --no-install-recommends {' '.join(dict.fromkeys(packages))}"]


def _node_mcp_start(root: Path, package: dict[str, Any]) -> str | None:
    runtime = "bun" if _node_uses_bun(root, package) else "node"
    bin_field = package.get("bin") if isinstance(package, dict) else None
    if isinstance(bin_field, str):
        return f"{runtime} {bin_field}"
    if isinstance(bin_field, dict) and bin_field:
        return f"{runtime} {next(iter(bin_field.values()))}"
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if "build" in scripts:
        for name in ("dist/index.js", "build/index.js"):
            if (root / name).exists() or (root / "src" / "index.ts").exists() or (root / "index.ts").exists():
                return f"{runtime} {name}"
    for name in ("index.js", "server.js", "main.js", "src/index.js", "build/index.js", "dist/index.js"):
        if (root / name).exists():
            return f"{runtime} {name}"
    if "start" in scripts:
        return "npm start"
    return None


def _looks_like_mcp(root: Path, package: dict[str, Any] | None, text: str) -> bool:
    deps = {}
    if package:
        deps.update(package.get("dependencies", {}))
        deps.update(package.get("devDependencies", {}))
    dep_text = " ".join(deps)
    return "mcp" in dep_text.lower() or "modelcontextprotocol" in dep_text.lower() or re.search(r"\bServer\(|tools/list|resources/list|@modelcontextprotocol", text, re.I) is not None


def _looks_like_python_mcp(root: Path, text: str) -> bool:
    if not any(root.rglob("*.py")):
        return False
    for path in list(root.rglob("*.py"))[:200]:
        rel_parts = path.relative_to(root).parts
        if any(part in {"vendor", ".git", ".sandbox_data", "node_modules"} for part in rel_parts):
            continue
        py_text = _read_text(path)
        if re.search(r"(from|import)\s+mcp\b|FastMCP|stdio_server|Server\(", py_text, re.I):
            return True
    if (root / "mcp.json").exists():
        return True
    return re.search(r"\bpython\b.{0,80}\bmcp\b|\bmcp\b.{0,80}\bpython\b", text, re.I) is not None and not (root / "go.mod").exists()


def _looks_like_crewai(root: Path, pyproject: str, requirements: str, text: str) -> bool:
    return any((root / name).exists() for name in ("agents.yaml", "tasks.yaml", "crew.py")) or re.search(r"\bcrewai\b", f"{pyproject}\n{requirements}\n{text}", re.I) is not None


def _looks_like_langchain(pyproject: str, requirements: str, text: str) -> bool:
    return re.search(r"langchain|langgraph", f"{pyproject}\n{requirements}\n{text}", re.I) is not None


def _looks_like_autogen(pyproject: str, requirements: str, text: str) -> bool:
    return re.search(r"autogen|pyautogen", f"{pyproject}\n{requirements}\n{text}", re.I) is not None


def _looks_like_fastapi(root: Path, requirements: str, text: str) -> bool:
    return re.search(r"FastAPI\s*\(|from fastapi import FastAPI|fastapi", f"{requirements}\n{text}", re.I) is not None


def _fastapi_module(root: Path) -> str:
    for path in root.rglob("*.py"):
        text = _read_text(path)
        if "FastAPI(" in text and re.search(r"\bapp\s*=", text):
            return path.relative_to(root).with_suffix("").as_posix().replace("/", ".")
    return "app"


def _looks_like_express(package: dict[str, Any], text: str) -> bool:
    deps = {}
    deps.update(package.get("dependencies", {}))
    deps.update(package.get("devDependencies", {}))
    return "express" in deps or re.search(r"express\s*\(|require\(['\"]express", text, re.I) is not None
