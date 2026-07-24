from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import image_reserve
from .adapters import AdapterCandidate
from .image_reserve import OFFICIAL_IMAGES

SANDBOX_VERSION = "5.0"
CACHE_PREFIX = "agent-sandbox-build"
CACHE_KEEP = 80
DEFAULT_BUILD_TIMEOUT_SECONDS = 900
SOURCE_HASH_FILE_LIMIT = 256
SOURCE_HASH_BYTES_LIMIT = 5 * 1024 * 1024
DEFAULT_APT_DEBIAN_MIRROR = "https://mirrors.tuna.tsinghua.edu.cn/debian"
DEFAULT_APT_UBUNTU_MIRROR = "https://mirrors.tuna.tsinghua.edu.cn/ubuntu"
DEFAULT_ALPINE_MIRROR = "https://mirrors.tuna.tsinghua.edu.cn/alpine"
DEFAULT_PIP_INDEX_URL = "https://pypi.tuna.tsinghua.edu.cn/simple"
DEFAULT_NPM_REGISTRY = "https://registry.npmmirror.com"
DEFAULT_GOPROXY = "https://goproxy.cn,direct"
DEFAULT_MAVEN_MIRROR_URL = "https://maven.aliyun.com/repository/public"
DEFAULT_MAVEN_DIST_MIRROR = "https://mirrors.tuna.tsinghua.edu.cn/apache/maven/maven-3"
DEFAULT_GRADLE_DIST_MIRROR = "https://mirrors.cloud.tencent.com/gradle"
DEFAULT_CARGO_REGISTRY = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"
IMAGE_EXISTS_TIMEOUT_SECONDS = 12
IMAGE_LIST_TIMEOUT_SECONDS = 12
_IMAGE_EXISTS_CACHE: dict[str, bool] = {}


@dataclass
class BuildOptions:
    build_mode: str = "auto"
    allow_install_scripts: bool = True
    cache_policy: str = "use"


@dataclass
class BuildPlan:
    plan_id: str
    language: str
    framework: str | None
    protocol: str
    base_image: str
    workdir: str
    install_commands: list[str] = field(default_factory=list)
    build_commands: list[str] = field(default_factory=list)
    start_command: str | None = None
    healthcheck: dict[str, Any] = field(default_factory=dict)
    cache_key: str = ""
    cache_image: str = ""
    allow_install_scripts: bool = True
    network_policy: str = "build:bridge,runtime:none"
    source: str = "detector"
    confidence: float = 0.0
    reason: str = ""
    image_resolution: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BuildResult:
    status: str
    cache_hit: bool = False
    image: str | None = None
    logs: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0
    failure_stage: str | None = None
    failure_class: str | None = None
    human_reason: str | None = None
    suggested_fix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_build_options(build_mode: str = "auto", allow_install_scripts: bool = True, cache_policy: str = "use") -> BuildOptions:
    return BuildOptions(
        build_mode=build_mode if build_mode in {"auto", "strict", "sandbox_yaml_only"} else "auto",
        allow_install_scripts=bool(allow_install_scripts),
        cache_policy=cache_policy if cache_policy in {"use", "rebuild", "disabled"} else "use",
    )


def create_build_plan(root: Path, adapter: AdapterCandidate, options: BuildOptions | None = None) -> BuildPlan:
    options = options or BuildOptions()
    source = (
        "sandbox_yaml"
        if adapter.kind == "sandbox_yaml"
        else "dockerfile"
        if adapter.kind == "dockerfile"
        else "llm_suggested"
        if adapter.kind == "llm_plan"
        else "detector"
    )
    if options.build_mode == "sandbox_yaml_only" and source != "sandbox_yaml":
        return _unsupported_plan(root, adapter, options, "sandbox_yaml_only requires a project-provided sandbox.yaml")

    install, build = _commands_for(root, adapter, options)
    image_resolution = _resolve_base_image_details(adapter.image, adapter.language, adapter.framework, source)
    base_image = str(image_resolution["selected_image"])
    image_reason = str(image_resolution["reason"])
    install = _normalize_commands_for_image(install, base_image)
    build = _normalize_commands_for_image(build, base_image)
    plan = BuildPlan(
        plan_id="",
        language=adapter.language,
        framework=adapter.framework,
        protocol=adapter.protocol,
        base_image=base_image,
        workdir="/workspace",
        install_commands=install,
        build_commands=build,
        start_command=adapter.start,
        healthcheck={},
        allow_install_scripts=options.allow_install_scripts,
        source=source,
        confidence=adapter.confidence,
        reason=f"{adapter.reason} {image_reason}".strip(),
        image_resolution=image_resolution,
    )
    if adapter.kind == "dockerfile":
        plan.base_image = "local-dockerfile"
    plan.cache_key = _cache_key(root, plan)
    plan.plan_id = plan.cache_key[:16]
    plan.cache_image = f"{CACHE_PREFIX}:{plan.cache_key[:24]}"
    return plan


def build_environment(root: Path, plan: BuildPlan, options: BuildOptions | None = None) -> BuildResult:
    options = options or BuildOptions()
    started = time.time()
    if plan.base_image == "unsupported":
        return BuildResult(status="skipped", duration_seconds=0.0, failure_stage="build_plan", failure_class="unsupported_project", human_reason=plan.reason, suggested_fix="Add sandbox.yaml with image, install/build, start, and protocol.")
    if plan.source == "dockerfile":
        return _build_project_dockerfile(root, plan, options, started)

    if options.cache_policy == "use" and _image_exists(plan.cache_image):
        return BuildResult(status="cached", cache_hit=True, image=plan.cache_image, duration_seconds=time.time() - started)
    if options.cache_policy == "use":
        legacy_image = _legacy_compatible_cache_image(root, plan)
        if legacy_image:
            subprocess.run(["docker", "tag", legacy_image, plan.cache_image], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            _remember_image_exists(plan.cache_image, True)
            log = {"step": "legacy_cache_lookup", "returncode": 0, "stdout": f"Reused compatible cached image {legacy_image} as {plan.cache_image}.", "stderr": ""}
            return BuildResult(status="cached", cache_hit=True, image=plan.cache_image, logs=[log], duration_seconds=time.time() - started)

    dockerfile = _generated_dockerfile(root, plan)
    command = _docker_build_command(plan.cache_image, options, dockerfile_from_stdin=True, use_buildkit=True)
    proc, timed_out, elapsed = _run_docker_build(command, root, input_text=dockerfile, env={**os.environ, "DOCKER_BUILDKIT": "1"})
    if timed_out:
        log = {"step": "docker_build", "command": command, "returncode": -1, "stdout": _tail(proc.stdout), "stderr": f"Timed out after {elapsed:.0f}s"}
        retry = _retry_classic_builder(root, plan, options, started, [log], f"{proc.stdout}\n{proc.stderr}", dockerfile_from_stdin=True)
        if retry:
            return retry
        return _failed_build_result(started, [log], log["stderr"])
    log = {"step": "docker_build", "command": command, "returncode": proc.returncode, "stdout": proc.stdout[-12000:], "stderr": proc.stderr[-12000:]}
    if proc.returncode != 0:
        retry = _retry_classic_builder(root, plan, options, started, [log], f"{proc.stdout}\n{proc.stderr}", dockerfile_from_stdin=True)
        if retry:
            return retry
        return _failed_build_result(started, [log], f"{proc.stdout}\n{proc.stderr}")
    _remember_image_exists(plan.cache_image, True)
    _prune_cache(keep_image=plan.cache_image)
    return BuildResult(status="built", cache_hit=False, image=plan.cache_image, logs=[log], duration_seconds=time.time() - started)


def classify_build_failure(text: str) -> tuple[str, str, str]:
    lowered = text.lower()
    if (
        "could not resolve" in lowered
        or "temporary failure in name resolution" in lowered
        or "network is unreachable" in lowered
        or "timed out" in lowered
        or "failed to fetch oauth token" in lowered and ("dial tcp" in lowered or "connectex" in lowered)
        or "failed to fetch anonymous token" in lowered
        or "load metadata for docker.io/" in lowered and ("deadlineexceeded" in lowered or "i/o timeout" in lowered or "context deadline exceeded" in lowered)
        or "connection refused" in lowered
        or "connection attempt failed" in lowered
    ):
        return "network_timeout", "Package installation or build command could not reach the network reliably.", "Retry with network available or provide a prebuilt Dockerfile/sandbox.yaml image."
    if "401" in lowered or "403" in lowered or "authentication" in lowered or "authorization" in lowered:
        return "auth_required", "A package registry, git dependency, or model setup step requires authentication.", "Provide a scoped build credential via future build secret support, or vendor/pin the dependency."
    if "no matching distribution" in lowered or "resolution impossible" in lowered or "eresolve" in lowered or "unable to resolve dependency" in lowered:
        return "dependency_resolution_failed", "The declared dependencies could not be resolved in the selected base image.", "Check Python/Node version constraints, lockfiles, or add sandbox.yaml with a compatible image."
    if "lockfile" in lowered or "frozen-lockfile" in lowered or "package-lock.json" in lowered and "out of sync" in lowered:
        return "lockfile_conflict", "The lockfile does not match the manifest.", "Regenerate the lockfile or allow a non-frozen install in sandbox.yaml."
    if "not found" in lowered and "/opt/agent-venv" in lowered:
        return "build_script_failed", "The generated build plan referenced the Python virtualenv before it existed.", "Regenerate the BuildPlan with Python virtualenv initialization before dependency commands."
    if (
        "the system library" in lowered and "was not found" in lowered
        or "pkg-config exited with status code" in lowered
        or "needs to be installed" in lowered
        or "fatal error:" in lowered and (".h:" in lowered or "gcc" in lowered or "g++" in lowered)
        or "unable to find vcvarsall" in lowered
    ):
        return "system_package_missing", "A native dependency needs system packages or compilers not present in the base image.", "Add system_packages or use a custom Dockerfile image with the required OS packages."
    if "postinstall" in lowered or "prepare" in lowered or "build failed" in lowered or "subprocess-exited-with-error" in lowered:
        return "build_script_failed", "A package build or install script failed.", "Inspect build logs and add required system packages or override install/build commands in sandbox.yaml."
    return "unknown_build_failure", "The environment build failed for an unclassified reason.", "Inspect build logs and add sandbox.yaml with explicit image/install/build/start commands."


def runtime_start_command(plan: BuildPlan) -> str:
    command = plan.start_command or ""
    if plan.language == "Python":
        return f"if [ -f /opt/agent-venv/bin/activate ]; then . /opt/agent-venv/bin/activate; fi; {command}"
    return command


def build_failure_dict(plan: BuildPlan, result: BuildResult, adapter: AdapterCandidate) -> dict[str, Any]:
    return {
        "stage": result.failure_stage or "build",
        "adapter": adapter.name,
        "failure_class": result.failure_class,
        "reason": result.human_reason or "Build failed.",
        "suggested_fix": result.suggested_fix,
        "cache_key": plan.cache_key,
    }


def _commands_for(root: Path, adapter: AdapterCandidate, options: BuildOptions) -> tuple[list[str], list[str]]:
    if adapter.kind == "sandbox_yaml":
        sandbox = _read_sandbox_yaml(root)
        install = _as_list(sandbox.get("install"))
        build = _as_list(sandbox.get("build"))
        return install, build
    if adapter.kind == "dockerfile":
        return [], []
    if adapter.kind == "plan_python" or (adapter.kind.startswith("plan_") and adapter.language == "Python") or (adapter.kind == "llm_plan" and adapter.language == "Python"):
        return _python_plan_install_commands(adapter.install), []
    if adapter.kind.startswith("plan_") or adapter.kind == "llm_plan":
        return adapter.install, []
    if adapter.language == "Python":
        return _python_build_commands(root, options), []
    if adapter.language == "Node.js":
        return _node_install_commands(root, options), _node_build_commands(root)
    return adapter.install, []


def _python_plan_install_commands(commands: list[str]) -> list[str]:
    normalized = list(commands)
    lowered = "\n".join(command.lower() for command in normalized)
    prefix: list[str] = []
    if "python -m venv /opt/agent-venv" not in lowered and "/opt/agent-venv" in lowered:
        prefix.append("python -m venv /opt/agent-venv")
    if "pip install --upgrade pip" not in lowered and "/opt/agent-venv" in lowered:
        prefix.append("/opt/agent-venv/bin/python -m pip install --upgrade pip setuptools wheel")
    if not normalized and not prefix:
        return ["python -m venv /opt/agent-venv", "/opt/agent-venv/bin/python -m pip install --upgrade pip setuptools wheel"]
    return [*prefix, *normalized]


def _python_build_commands(root: Path, options: BuildOptions) -> list[str]:
    commands = ["python -m venv /opt/agent-venv", "/opt/agent-venv/bin/python -m pip install --upgrade pip setuptools wheel"]
    if (root / "uv.lock").exists():
        commands.extend(["python -m pip install uv", "VIRTUAL_ENV=/opt/agent-venv uv sync --frozen --active"])
    elif (root / "poetry.lock").exists():
        commands.extend(["/opt/agent-venv/bin/python -m pip install poetry", "POETRY_VIRTUALENVS_CREATE=false /opt/agent-venv/bin/poetry install --no-interaction --no-root", "/opt/agent-venv/bin/python -m pip install ."])
    elif (root / "requirements.txt").exists():
        commands.append("/opt/agent-venv/bin/python -m pip install -r requirements.txt")
        if (root / "pyproject.toml").exists():
            commands.append("/opt/agent-venv/bin/python -m pip install .")
    elif (root / "pyproject.toml").exists():
        commands.append("/opt/agent-venv/bin/python -m pip install .")
    extras = _python_import_extras(root)
    if extras:
        quoted_extras = " ".join(f"'{item}'" for item in extras)
        commands.append(f"/opt/agent-venv/bin/python -m pip install {quoted_extras}")
    return commands


def _python_import_extras(root: Path) -> list[str]:
    text = _sample_text(root)
    declared = "\n".join(_read_text(root / name) for name in ("pyproject.toml", "requirements.txt")).lower()
    mapping = {
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
    if _uses_legacy_openai_api(text) and not _uses_modern_openai_client(text) and not _declares_openai_v0(declared):
        extras.append("openai<1")
    return extras


def _uses_legacy_openai_api(text: str) -> bool:
    return any(pattern in text for pattern in ("openai.ChatCompletion.create", "openai.Completion.create", "openai.Image.create", "openai.Audio."))


def _uses_modern_openai_client(text: str) -> bool:
    return re.search(r"from\s+openai\s+import\s+(?:AsyncOpenAI|OpenAI)\b|\b(?:AsyncOpenAI|OpenAI)\s*\(", text) is not None


def _declares_openai_v0(declared: str) -> bool:
    return re.search(r"openai\s*(?:[<~]=?|==)\s*0|openai\s*<\s*1", declared, re.I) is not None


def _node_install_commands(root: Path, options: BuildOptions) -> list[str]:
    scripts_flag = "" if options.allow_install_scripts else "--ignore-scripts"
    if _node_uses_bun(root, _read_package(root)):
        return [f"bun install --frozen-lockfile {scripts_flag}".strip()]
    if (root / "pnpm-lock.yaml").exists():
        return ["corepack enable", f"pnpm install --frozen-lockfile {scripts_flag}".strip()]
    if (root / "yarn.lock").exists():
        return ["corepack enable", f"yarn install --frozen-lockfile {scripts_flag}".strip()]
    if (root / "package-lock.json").exists():
        return [f"npm ci {scripts_flag}".strip()]
    if (root / "package.json").exists():
        return [f"npm install {scripts_flag}".strip()]
    return []


def _node_build_commands(root: Path) -> list[str]:
    package = _read_package(root)
    scripts = package.get("scripts", {}) if package else {}
    if "build" not in scripts:
        return []
    if _node_uses_bun(root, package):
        return ["bun run build"]
    if (root / "pnpm-lock.yaml").exists():
        return ["pnpm run build"]
    if (root / "yarn.lock").exists():
        return ["yarn build"]
    return ["npm run build"]


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


def _generated_dockerfile(root: Path, plan: BuildPlan, cache_mounts: bool = True) -> str:
    if _can_layer_java_maven_project(root, plan):
        return _generated_java_maven_dockerfile(root, plan, cache_mounts=cache_mounts)
    if _can_layer_java_gradle_project(root, plan):
        return _generated_java_gradle_dockerfile(root, plan, cache_mounts=cache_mounts)
    if plan.language == "Python":
        return _generated_layered_dockerfile(root, plan, "python", cache_mounts=cache_mounts)
    if plan.language == "Node.js":
        return _generated_layered_dockerfile(root, plan, "node", cache_mounts=cache_mounts)
    if plan.language == "Go":
        return _generated_layered_dockerfile(root, plan, "go", cache_mounts=cache_mounts)
    if plan.language == "Rust":
        return _generated_layered_dockerfile(root, plan, "rust", cache_mounts=cache_mounts)
    commands = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in [*plan.install_commands, *plan.build_commands])
    return textwrap.dedent(
        f"""
        FROM {plan.base_image}
        WORKDIR /workspace
        {_build_acceleration_preamble()}
        COPY . /workspace
        {_wrapper_mirror_setup()}
        {commands}
        {_workspace_dependency_backup()}
        """
    ).strip() + "\n"


def _generated_layered_dockerfile(root: Path, plan: BuildPlan, language_key: str, cache_mounts: bool = True) -> str:
    commands = [*plan.install_commands, *plan.build_commands]
    pre_commands, post_commands = _split_dependency_commands(commands, language_key)
    manifest_paths = _manifest_paths(root, language_key)
    mkdirs = _mkdir_for_manifest_paths(manifest_paths)
    manifest_copies = "\n".join(_copy_instruction(path, path) for path in manifest_paths)
    pre = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in pre_commands)
    post = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in post_commands)
    return textwrap.dedent(
        f"""
        FROM {plan.base_image}
        WORKDIR /workspace
        {_build_acceleration_preamble()}
        {mkdirs}
        {manifest_copies}
        {_wrapper_mirror_setup()}
        {pre}
        COPY . /workspace
        {_wrapper_mirror_setup()}
        {post}
        {_workspace_dependency_backup()}
        """
    ).strip() + "\n"


def _generated_java_gradle_dockerfile(root: Path, plan: BuildPlan, cache_mounts: bool = True) -> str:
    manifest_only, after_copy = _split_manifest_only_gradle_commands([*plan.install_commands, *plan.build_commands])
    manifest_commands = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in manifest_only)
    source_commands = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in after_copy)
    manifest_copies = []
    for name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.properties"):
        if (root / name).exists():
            manifest_copies.append(f"COPY {name} ./")
    if (root / "gradle").exists():
        manifest_copies.append("COPY gradle ./gradle")
    if (root / "gradlew").exists():
        manifest_copies.append("COPY gradlew ./")
    if (root / "gradlew.bat").exists():
        manifest_copies.append("COPY gradlew.bat ./")
    copy_lines = "\n".join(manifest_copies)
    return textwrap.dedent(
        f"""
        FROM {plan.base_image}
        WORKDIR /workspace
        {_build_acceleration_preamble()}
        {copy_lines}
        {_wrapper_mirror_setup()}
        {manifest_commands}
        COPY . /workspace
        {_wrapper_mirror_setup()}
        {source_commands}
        {_workspace_dependency_backup()}
        """
    ).strip() + "\n"


def _generated_java_maven_dockerfile(root: Path, plan: BuildPlan, cache_mounts: bool = True) -> str:
    manifest_only, after_copy = _split_manifest_only_java_commands([*plan.install_commands, *plan.build_commands])
    manifest_commands = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in manifest_only)
    source_commands = "\n".join(_run_instruction(command, plan.language, cache_mounts=cache_mounts) for command in after_copy)
    manifest_copies = ["COPY pom.xml ./"]
    if (root / ".mvn").exists():
        manifest_copies.append("COPY .mvn ./.mvn")
    if (root / "mvnw").exists():
        manifest_copies.append("COPY mvnw ./")
    if (root / "mvnw.cmd").exists():
        manifest_copies.append("COPY mvnw.cmd ./")
    copy_lines = "\n".join(manifest_copies)
    return textwrap.dedent(
        f"""
        FROM {plan.base_image}
        WORKDIR /workspace
        {_build_acceleration_preamble()}
        {copy_lines}
        {_wrapper_mirror_setup()}
        {manifest_commands}
        COPY . /workspace
        {_wrapper_mirror_setup()}
        {source_commands}
        {_workspace_dependency_backup()}
        """
    ).strip() + "\n"


def _workspace_dependency_backup() -> str:
    return (
        "RUN set -eux; mkdir -p /opt/aegisagent-workspace-deps; "
        "for p in node_modules .venv venv target build dist; do "
        "if [ -e \"$p\" ]; then rm -rf \"/opt/aegisagent-workspace-deps/$p\"; cp -a \"$p\" \"/opt/aegisagent-workspace-deps/$p\"; fi; "
        "done"
    )


def _can_layer_java_maven_project(root: Path, plan: BuildPlan) -> bool:
    if plan.language != "Java" or not (root / "pom.xml").exists():
        return False
    if (root / ".mvn").exists():
        return True
    return any(_is_maven_command(command) for command in [*plan.install_commands, *plan.build_commands])


def _can_layer_java_gradle_project(root: Path, plan: BuildPlan) -> bool:
    if plan.language != "Java" or not ((root / "build.gradle").exists() or (root / "build.gradle.kts").exists()):
        return False
    if (root / "gradle").exists() or (root / "gradlew").exists():
        return True
    return any(_is_gradle_command(command) for command in [*plan.install_commands, *plan.build_commands])


def _split_manifest_only_java_commands(commands: list[str]) -> tuple[list[str], list[str]]:
    manifest_only: list[str] = []
    after_copy: list[str] = []
    for command in commands:
        if _is_manifest_only_maven_command(command):
            manifest_only.append(command)
        else:
            after_copy.append(command)
    return manifest_only, after_copy


def _split_manifest_only_gradle_commands(commands: list[str]) -> tuple[list[str], list[str]]:
    manifest_only: list[str] = []
    after_copy: list[str] = []
    for command in commands:
        if _is_manifest_only_gradle_command(command):
            manifest_only.append(command)
        else:
            after_copy.append(command)
    return manifest_only, after_copy


def _split_dependency_commands(commands: list[str], language_key: str) -> tuple[list[str], list[str]]:
    pre: list[str] = []
    post: list[str] = []
    for command in commands:
        lowered = command.lower()
        if language_key == "python":
            if "python -m venv" in lowered or "pip install --upgrade pip" in lowered or "pip install uv" in lowered or "pip install poetry" in lowered:
                pre.append(command)
            elif "uv sync" in lowered:
                pre.append(re.sub(r"\buv sync\b", "uv sync --no-install-project", command, count=1))
                post.append(command)
            elif "poetry install" in lowered and "--no-root" in lowered:
                pre.append(command)
            elif "pip install -r" in lowered:
                pre.append(command)
            elif "pip install ." in lowered:
                post.append(command)
            elif "pip install" in lowered:
                pre.append(command)
            else:
                post.append(command)
        elif language_key == "node":
            if any(token in lowered for token in ("corepack enable", "npm ci", "npm install", "pnpm install", "yarn install")):
                pre.append(command)
            else:
                post.append(command)
        elif language_key == "go":
            if "go mod download" in lowered:
                pre.append(command)
            else:
                post.append(command)
        elif language_key == "rust":
            if "cargo fetch" in lowered:
                pre.append(command)
            else:
                post.append(command)
        else:
            post.append(command)
    return pre, post


def _manifest_paths(root: Path, language_key: str) -> list[str]:
    names_by_language = {
        "python": {"pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock", "setup.py", "setup.cfg"},
        "node": {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
        "go": {"go.mod", "go.sum"},
        "rust": {"Cargo.toml", "Cargo.lock"},
    }
    names = names_by_language.get(language_key, set())
    dockerignore = _dockerignore_matcher(root)
    paths = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(root).as_posix()
        if dockerignore(rel_path):
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in {".git", ".sandbox_data", "node_modules", "target", "dist", "build", ".venv", "venv", "__pycache__"} for part in rel_parts):
            continue
        if language_key == "rust" and _is_rust_target_marker(rel_path):
            paths.append(rel_path)
            continue
        if path.name not in names:
            continue
        paths.append(rel_path)
    if language_key == "go":
        paths = _unique_paths([*_go_local_replace_manifest_paths(root), *paths])
    return paths[:240 if language_key == "go" else 80]


def _go_local_replace_manifest_paths(root: Path) -> list[str]:
    paths: list[str] = []
    root_resolved = root.resolve()
    for mod in sorted(root.rglob("go.mod")):
        if not mod.is_file():
            continue
        base = mod.parent
        text = _read_text(mod)
        for match in re.finditer(r"=>\s+(?P<target>\.{1,2}/[^\s]+)", text):
            target = (base / match.group("target")).resolve()
            try:
                target.relative_to(root_resolved)
            except ValueError:
                continue
            for name in ("go.mod", "go.sum"):
                manifest = target / name
                if manifest.exists() and manifest.is_file():
                    paths.append(manifest.resolve().relative_to(root_resolved).as_posix())
    return paths


def _unique_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            result.append(path)
    return result


def _dockerignore_matcher(root: Path):
    rules: list[tuple[str, bool]] = []
    text = _read_text(root / ".dockerignore")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        include = line.startswith("!")
        pattern = line[1:].strip() if include else line
        if pattern:
            rules.append((pattern.replace("\\", "/").strip("/"), include))

    def matches(rel_path: str) -> bool:
        ignored = False
        for pattern, include in rules:
            if _dockerignore_pattern_matches(pattern, rel_path):
                ignored = not include
        return ignored

    return matches


def _dockerignore_pattern_matches(pattern: str, rel_path: str) -> bool:
    rel_path = rel_path.replace("\\", "/").strip("/")
    if not pattern:
        return False
    if any(char in pattern for char in "*?["):
        from fnmatch import fnmatch

        return fnmatch(rel_path, pattern) or fnmatch(Path(rel_path).name, pattern)
    return rel_path == pattern or rel_path.startswith(f"{pattern}/") or Path(rel_path).name == pattern


def _is_rust_target_marker(rel_path: str) -> bool:
    return (
        rel_path in {"src/main.rs", "src/lib.rs", "build.rs"}
        or re.match(r"^src/bin/[^/]+\.rs$", rel_path) is not None
        or re.match(r"^(benches|examples|tests)/[^/]+\.rs$", rel_path) is not None
    )


def _mkdir_for_manifest_paths(paths: list[str]) -> str:
    dirs = sorted({str(Path(path).parent).replace("\\", "/") for path in paths if str(Path(path).parent) != "."})
    if not dirs:
        return ""
    quoted = " ".join(_shell_quote_dir(item) for item in dirs)
    return f"RUN mkdir -p {quoted}"


def _shell_quote_dir(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _docker_path(value: str) -> str:
    return value.replace("\\", "/")


def _copy_instruction(source: str, target: str) -> str:
    return "COPY " + json.dumps([_docker_path(source), _docker_path(target)])


def _build_acceleration_preamble() -> str:
    return textwrap.dedent(
        f"""
        ARG APT_DEBIAN_MIRROR={DEFAULT_APT_DEBIAN_MIRROR}
        ARG APT_UBUNTU_MIRROR={DEFAULT_APT_UBUNTU_MIRROR}
        ARG ALPINE_MIRROR={DEFAULT_ALPINE_MIRROR}
        ARG PIP_INDEX_URL={DEFAULT_PIP_INDEX_URL}
        ARG NPM_REGISTRY={DEFAULT_NPM_REGISTRY}
        ARG GOPROXY={DEFAULT_GOPROXY}
        ARG MAVEN_MIRROR_URL={DEFAULT_MAVEN_MIRROR_URL}
        ARG MAVEN_DIST_MIRROR={DEFAULT_MAVEN_DIST_MIRROR}
        ARG GRADLE_DIST_MIRROR={DEFAULT_GRADLE_DIST_MIRROR}
        ARG CARGO_REGISTRY={DEFAULT_CARGO_REGISTRY}
        ARG GITHUB_PROXY_URL=
        ENV PYTHONUNBUFFERED=1 \\
            DEBIAN_FRONTEND=noninteractive \\
            PIP_DISABLE_PIP_VERSION_CHECK=1 \\
            PIP_DEFAULT_TIMEOUT=90 \\
            PIP_RETRIES=5 \\
            PIP_INDEX_URL=$PIP_INDEX_URL \\
            SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 \\
            HATCH_VCS_PRETEND_VERSION=0.0.0 \\
            UV_HTTP_TIMEOUT=90 \\
            UV_INDEX_URL=$PIP_INDEX_URL \\
            UV_PYTHON=/opt/agent-venv/bin/python \\
            UV_PYTHON_DOWNLOADS=never \\
            UV_NO_MANAGED_PYTHON=1 \\
            npm_config_registry=$NPM_REGISTRY \\
            npm_config_fetch_retries=5 \\
            npm_config_fetch_retry_mintimeout=20000 \\
            npm_config_fetch_retry_maxtimeout=120000 \\
            COREPACK_NPM_REGISTRY=$NPM_REGISTRY \\
            PNPM_HOME=/root/.local/share/pnpm \\
            PNPM_STORE_PATH=/root/.local/share/pnpm/store \\
            YARN_NPM_REGISTRY_SERVER=$NPM_REGISTRY \\
            BUN_CONFIG_REGISTRY=$NPM_REGISTRY \\
            GOPROXY=$GOPROXY \\
            GONOSUMDB= \\
            MAVEN_OPTS="-Dmaven.wagon.http.retryHandler.count=5 -Dmaven.wagon.httpconnectionManager.ttlSeconds=60" \\
            GRADLE_OPTS="-Dorg.gradle.internal.http.connectionTimeout=90000 -Dorg.gradle.internal.http.socketTimeout=90000" \\
            CARGO_NET_RETRY=5 \\
            CARGO_HTTP_TIMEOUT=90 \\
            CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \\
            CARGO_NET_GIT_FETCH_WITH_CLI=true
        RUN set -eux; \\
            if [ -f /etc/apt/sources.list ]; then sed -i -e "s|http://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" -e "s|https://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" -e "s|http://security.debian.org/debian-security|$APT_DEBIAN_MIRROR-security|g" -e "s|https://security.debian.org/debian-security|$APT_DEBIAN_MIRROR-security|g" -e "s|http://archive.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|https://archive.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|http://security.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|https://security.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" /etc/apt/sources.list; fi; \\
            if [ -d /etc/apt/sources.list.d ]; then find /etc/apt/sources.list.d -type f -name '*.sources' -exec sed -i -e "s|http://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" -e "s|https://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" -e "s|http://security.debian.org/debian-security|$APT_DEBIAN_MIRROR-security|g" -e "s|https://security.debian.org/debian-security|$APT_DEBIAN_MIRROR-security|g" -e "s|http://archive.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|https://archive.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|http://security.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" -e "s|https://security.ubuntu.com/ubuntu|$APT_UBUNTU_MIRROR|g" {{}} +; fi; \\
            if [ -d /etc/apt/apt.conf.d ]; then printf '%s\\n' 'Acquire::Retries "5";' 'Acquire::http::Timeout "90";' 'Acquire::https::Timeout "90";' > /etc/apt/apt.conf.d/99aegisagent-retries; fi; \\
            if [ -f /etc/apk/repositories ]; then sed -i "s|https://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g; s|http://dl-cdn.alpinelinux.org/alpine|$ALPINE_MIRROR|g" /etc/apk/repositories; fi
        ENV PATH=$PNPM_HOME:$PATH
        RUN if command -v npm >/dev/null 2>&1; then npm config set registry "$NPM_REGISTRY"; fi
        RUN if command -v corepack >/dev/null 2>&1; then corepack enable || true; fi
        RUN if command -v pnpm >/dev/null 2>&1; then pnpm config set registry "$NPM_REGISTRY"; fi
        RUN if command -v yarn >/dev/null 2>&1; then yarn config set npmRegistryServer "$NPM_REGISTRY" || yarn config set registry "$NPM_REGISTRY" || true; fi
        RUN if command -v bun >/dev/null 2>&1; then mkdir -p /root/.bun && printf '%s\\n' '[install]' 'registry = "'"$NPM_REGISTRY"'"' > /root/.bunfig.toml; fi
        RUN if command -v mvn >/dev/null 2>&1; then mkdir -p /root/.m2 && printf '%s\\n' '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">' '<mirrors><mirror><id>aegisagent-public-mirror</id><mirrorOf>*</mirrorOf><url>'"$MAVEN_MIRROR_URL"'</url></mirror></mirrors>' '</settings>' > /root/.m2/settings.xml; fi
        RUN mkdir -p /usr/local/cargo /root/.cargo && printf '%s\\n' '[source.crates-io]' 'replace-with = "aegisagent-mirror"' '[source.aegisagent-mirror]' 'registry = "'"$CARGO_REGISTRY"'"' '[net]' 'git-fetch-with-cli = true' > /root/.cargo/config.toml && if [ -d /usr/local/cargo ]; then cp /root/.cargo/config.toml /usr/local/cargo/config.toml; fi
        RUN if [ -n "$GITHUB_PROXY_URL" ] && command -v git >/dev/null 2>&1; then git config --global url."$GITHUB_PROXY_URL/https://github.com/".insteadOf "https://github.com/"; fi
        """
    ).strip()


def _wrapper_mirror_setup() -> str:
    return textwrap.dedent(
        """
        RUN set -eux; \\
            if [ -f .mvn/wrapper/maven-wrapper.properties ]; then sed -i -E "s#https?://[^ =]*/apache-maven-([0-9.]+)-bin\\\\.zip#${MAVEN_DIST_MIRROR}/\\\\1/binaries/apache-maven-\\\\1-bin.zip#g" .mvn/wrapper/maven-wrapper.properties; fi; \\
            if [ -f gradle/wrapper/gradle-wrapper.properties ]; then sed -i -E "s#https?://[^ =]*/(gradle-[^/]+-(bin|all)\\\\.zip)#${GRADLE_DIST_MIRROR}/\\\\1#g" gradle/wrapper/gradle-wrapper.properties; fi
        """
    ).strip()


def _run_instruction(command: str, language: str = "", cache_mounts: bool = True) -> str:
    command = _rewrite_package_manager_command(command)
    mounts = _cache_mounts_for_command(command, language) if cache_mounts else ""
    return f"RUN {mounts}{command}"


def _cache_mounts_for_command(command: str, language: str) -> str:
    lowered = f"{language} {command}".lower()
    mounts: list[str] = []
    if any(token in lowered for token in (" pip ", "pip install", " uv ", "uv sync", "poetry ")):
        mounts.extend(["--mount=type=cache,target=/root/.cache/pip ", "--mount=type=cache,target=/root/.cache/uv "])
    if any(token in lowered for token in ("npm ", "pnpm ", "yarn ", "corepack ")):
        mounts.extend(["--mount=type=cache,target=/root/.npm ", "--mount=type=cache,target=/root/.cache/yarn ", "--mount=type=cache,target=/root/.local/share/pnpm/store "])
    if "mvn " in lowered or "./mvnw" in lowered:
        mounts.append("--mount=type=cache,target=/root/.m2 ")
    if "go " in lowered:
        mounts.extend(["--mount=type=cache,target=/go/pkg/mod ", "--mount=type=cache,target=/root/.cache/go-build "])
    if "cargo " in lowered or "rust" in lowered:
        mounts.extend(["--mount=type=cache,target=/usr/local/cargo/registry ", "--mount=type=cache,target=/usr/local/cargo/git "])
    return "".join(mounts)


def _is_maven_command(command: str) -> bool:
    return re.search(r"(^|[;&|]\s*|\bcd\s+[^;&|]+\s+&&\s*)(?:\./mvnw|mvn)\b", command) is not None


def _is_gradle_command(command: str) -> bool:
    return re.search(r"(^|[;&|]\s*|\bcd\s+[^;&|]+\s+&&\s*)(?:\./gradlew|gradle)\b", command) is not None


def _is_manifest_only_maven_command(command: str) -> bool:
    if " cd " in f" {command} " or command.strip().startswith("cd "):
        return False
    lowered = command.lower()
    if not _is_maven_command(command):
        return False
    manifest_goals = (
        "dependency:go-offline",
        "dependency:resolve",
        "dependency:resolve-plugins",
        "org.codehaus.mojo:exec-maven-plugin",
        ":help",
    )
    return any(goal in lowered for goal in manifest_goals)


def _is_manifest_only_gradle_command(command: str) -> bool:
    if " cd " in f" {command} " or command.strip().startswith("cd "):
        return False
    lowered = command.lower()
    if not _is_gradle_command(command):
        return False
    return re.search(r"\bdependencies\b", lowered) is not None


def _resolve_base_image(image: str, language: str = "", framework: str | None = None, source: str = "detector") -> tuple[str, str]:
    details = _resolve_base_image_details(image, language, framework, source)
    return str(details["selected_image"]), str(details["reason"])


def _resolve_base_image_details(image: str, language: str = "", framework: str | None = None, source: str = "detector") -> dict[str, Any]:
    exists_cache: dict[str, bool] = {}

    def exists(candidate: str) -> bool:
        if not candidate:
            return False
        if candidate not in exists_cache:
            exists_cache[candidate] = _image_exists(candidate)
        return exists_cache[candidate]

    language_key = _language_key(language, framework)
    local_candidates = image_reserve.LOCAL_RESERVE_IMAGES.get(language_key, [])
    public_candidates = image_reserve.PUBLIC_FALLBACK_IMAGES.get(language_key, [])
    local_available = [candidate for candidate in local_candidates if exists(candidate)]
    public_available = [candidate for candidate in public_candidates if exists(candidate)]
    base = {
        "requested_image": image,
        "language_key": language_key,
        "source": source,
        "local_reserve_candidates": local_candidates,
        "local_reserve_available": local_available,
        "public_fallback_candidates": public_candidates,
        "public_fallback_available": public_available,
    }

    if source == "sandbox_yaml":
        if image.startswith("aegisagent-"):
            return _resolve_aegisagent_image_details(image, base)
        if exists(image):
            return {**base, "selected_image": image, "selected_layer": "sandbox_yaml_local", "requires_public_pull": False, "reason": "Using image declared by sandbox.yaml because it already exists locally."}
        mirror = _mirror_image_reference(image)
        if mirror:
            return {**base, "selected_image": mirror, "selected_layer": "sandbox_yaml_mirror", "requires_public_pull": not exists(mirror), "mirror_image": mirror, "reason": f"Using registry mirror {mirror} for sandbox.yaml image {image}."}
        return {**base, "selected_image": image, "selected_layer": "sandbox_yaml_declared", "requires_public_pull": not exists(image), "reason": "Using image declared by sandbox.yaml."}
    if source == "dockerfile":
        return {**base, "selected_image": image, "selected_layer": "project_dockerfile", "requires_public_pull": False, "reason": ""}
    if image.startswith("aegisagent-"):
        return _resolve_aegisagent_image_details(image, base)

    local = next(iter(local_available), None)
    if local:
        return {**base, "selected_image": local, "selected_layer": "local_reserve", "requires_public_pull": False, "reason": f"Using local reserve image {local} for {language_key}; requested image was {image}."}
    if exists(image):
        return {**base, "selected_image": image, "selected_layer": "requested_local", "requires_public_pull": False, "reason": "Using requested image because it already exists locally."}
    fallback = next(iter(public_available), None) or next(iter(public_candidates), None)
    if fallback:
        layer = "cached_public_fallback" if fallback in public_available else "public_fallback"
        reason = (
            f"No local reserve image was available for {language_key}; using cached public fallback {fallback} instead of requested image {image}."
            if fallback in public_available
            else f"No local reserve image was available for {language_key}; using public fallback {fallback} instead of requested image {image}."
        )
        return {**base, "selected_image": fallback, "selected_layer": layer, "requires_public_pull": fallback not in public_available, "reason": reason}
    return {**base, "selected_image": image, "selected_layer": "requested_image", "requires_public_pull": not exists(image), "reason": "No language-specific reserve image was available; using requested image."}


def _resolve_aegisagent_image(image: str) -> tuple[str, str]:
    details = _resolve_aegisagent_image_details(image)
    return str(details["selected_image"]), str(details["reason"])


def _resolve_aegisagent_image_details(image: str, base: dict[str, Any] | None = None) -> dict[str, Any]:
    base = dict(base or {})
    if _image_exists(image):
        return {**base, "requested_image": image, "selected_image": image, "selected_layer": "local_reserve", "requires_public_pull": False, "reason": "Using local enhanced AegisAgent image."}
    fallback = _official_fallback(image)
    if fallback:
        return {
            **base,
            "requested_image": image,
            "selected_image": fallback,
            "selected_layer": "cached_public_fallback" if _image_exists(fallback) else "public_fallback",
            "requires_public_pull": not _image_exists(fallback),
            "reason": f"Enhanced image {image} is not built locally; fell back to {'cached ' if _image_exists(fallback) else ''}public image {fallback}.",
        }
    return {**base, "requested_image": image, "selected_image": image, "selected_layer": "requested_image", "requires_public_pull": not _image_exists(image), "reason": "Enhanced image was requested."}


def _language_key(language: str, framework: str | None = None) -> str:
    lowered = f"{language} {framework or ''}".lower()
    if "python" in lowered:
        return "python"
    if "bun" in lowered:
        return "bun"
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


def _first_existing(images: list[str]) -> str | None:
    for image in images:
        if _image_exists(image):
            return image
    return None


def _normalize_commands_for_image(commands: list[str], base_image: str) -> list[str]:
    normalized: list[str] = []
    for command in commands:
        rewritten = _rewrite_apt_install_to_apk(command) if _is_alpine_like_image(base_image) else _rewrite_apk_install_to_apt(command)
        rewritten = _rewrite_package_manager_command(rewritten) if rewritten else rewritten
        if rewritten:
            normalized.append(rewritten)
    return normalized


def _rewrite_package_manager_command(command: str) -> str:
    command = re.sub(r"\s+--no-cache-dir\b", "", command)
    command = _rewrite_uv_sync_command(command)
    command = _rewrite_maven_command(command)
    command = _rewrite_gradle_command(command)
    if re.search(r"\bnpm\s+ci\b", command) and "--prefer-offline" not in command:
        command = re.sub(r"\bnpm\s+ci\b", "npm ci --prefer-offline", command, count=1)
    if re.search(r"\bnpm\s+install\b", command) and "--prefer-offline" not in command:
        command = re.sub(r"\bnpm\s+install\b", "npm install --prefer-offline", command, count=1)
    if re.search(r"\bcd\s+[^&|;]+&&\s+npm\s+(?:ci|install)\b", command) and "--workspaces=false" not in command:
        command = re.sub(r"\bnpm\s+(ci|install)\b", r"npm \1 --workspaces=false", command, count=1)
    if re.search(r"\bpnpm\s+install\b", command) and "--prefer-offline" not in command:
        command = re.sub(r"\bpnpm\s+install\b", "pnpm install --prefer-offline", command, count=1)
    if re.search(r"\byarn\s+install\b", command) and "--prefer-offline" not in command:
        command = re.sub(r"\byarn\s+install\b", "yarn install --prefer-offline", command, count=1)
    return command


def _rewrite_maven_command(command: str) -> str:
    if not re.search(r"(^|[;&|]\s*|\bcd\s+[^;&|]+\s+&&\s*)(?:\./mvnw|mvn)\b", command):
        return command
    if "-Dmaven.repo.local=" not in command:
        command = re.sub(r"(?<![\w./-])(mvn|\./mvnw)\b", r"\1 -Dmaven.repo.local=/workspace/.sandbox_deps/m2", command, count=1)
    if re.search(r"\b(?:clean\s+)?(?:package|install|verify|test)\b", command) and "-DskipTests" not in command and "-DskipITs" not in command:
        command = re.sub(r"(?<![\w./-])(mvn|\./mvnw)\b", r"\1 -DskipTests", command, count=1)
    if " -q" not in command and re.search(r"(?<![\w./-])(?:mvn|\./mvnw)\b", command):
        command = re.sub(r"(?<![\w./-])(mvn|\./mvnw)\b", r"\1 -q", command, count=1)
    return command


def _rewrite_gradle_command(command: str) -> str:
    if not re.search(r"(^|[;&|]\s*|\bcd\s+[^;&|]+\s+&&\s*)(?:\./gradlew|gradle)\b", command):
        return command
    if re.search(r"\b(?:build|assemble|check|test)\b", command) and " -x test" not in command and " -xTest" not in command:
        command = f"{command} -x test"
    if "--no-daemon" not in command:
        command = re.sub(r"(?<![\w./-])(gradle|\./gradlew)\b", r"\1 --no-daemon", command, count=1)
    return command


def _rewrite_uv_sync_command(command: str) -> str:
    if not re.search(r"\buv\s+sync\b", command):
        return command
    if "--python " not in command and "--python=" not in command:
        command = re.sub(r"\buv\s+sync\b", "uv sync --python /opt/agent-venv/bin/python", command, count=1)
    if "--no-managed-python" not in command:
        command = re.sub(r"\buv\s+sync\b", "uv sync --no-managed-python", command, count=1)
    if "--no-python-downloads" not in command and "UV_PYTHON_DOWNLOADS" not in command:
        command = re.sub(r"\buv\s+sync\b", "uv sync --no-python-downloads", command, count=1)
    return command


def _is_alpine_like_image(image: str) -> bool:
    return "alpine" in image or image.startswith("bash:")


def _rewrite_apt_install_to_apk(command: str) -> str | None:
    cleaned = " ".join(command.replace("\\", " ").split())
    if cleaned in {"apt-get update", "apt update"}:
        return None
    match = re.search(r"\bapt(?:-get)?\s+install\b(?P<args>.*)", cleaned)
    if not match:
        return command
    args = [
        item
        for item in match.group("args").split()
        if item
        and not item.startswith("-")
        and item not in {"sudo", "&&", "apt-get", "apt", "update", "install"}
    ]
    if "ca-certificates" not in args:
        args.append("ca-certificates")
    return f"apk add --no-cache {' '.join(args)}"


def _rewrite_apk_install_to_apt(command: str) -> str | None:
    cleaned = " ".join(command.replace("\\", " ").split())
    match = re.search(r"\bapk\s+add\b(?P<args>.*)", cleaned)
    if not match:
        return command
    args = [item for item in match.group("args").split() if item and not item.startswith("-") and item not in {"apk", "add"}]
    if not args:
        return None
    return f"apt-get update && apt-get install -y --no-install-recommends {' '.join(args)}"


def _official_fallback(image: str) -> str | None:
    if image.startswith("aegisagent-python:"):
        return _public_fallback("python")
    if image.startswith("aegisagent-node:"):
        return _public_fallback("node")
    if image.startswith("aegisagent-go:"):
        return _public_fallback("go")
    if image.startswith("aegisagent-rust:"):
        return _public_fallback("rust")
    if image.startswith("aegisagent-java:"):
        return _public_fallback("java")
    if image.startswith("aegisagent-universal:"):
        return _public_fallback("custom")
    return None


def _public_fallback(language_key: str) -> str | None:
    candidates = image_reserve.PUBLIC_FALLBACK_IMAGES.get(language_key, [])
    return _first_existing(candidates) or next(iter(candidates), None)


def image_reserve_status(image_exists: Any | None = None) -> dict[str, Any]:
    exists = image_exists or _image_exists
    language_keys = sorted({*image_reserve.LOCAL_RESERVE_IMAGES.keys(), *image_reserve.PUBLIC_FALLBACK_IMAGES.keys()})
    languages: dict[str, Any] = {}
    summary = {
        "local_reserve_ready": 0,
        "cached_public_fallback_ready": 0,
        "public_pull_required": 0,
        "missing_policy": 0,
    }
    for language_key in language_keys:
        local_candidates = image_reserve.LOCAL_RESERVE_IMAGES.get(language_key, [])
        public_candidates = image_reserve.PUBLIC_FALLBACK_IMAGES.get(language_key, [])
        local_available = [image for image in local_candidates if exists(image)]
        public_available = [image for image in public_candidates if exists(image)]
        if local_available:
            layer = "local_reserve"
            selected = local_available[0]
            summary["local_reserve_ready"] += 1
        elif public_available:
            layer = "cached_public_fallback"
            selected = public_available[0]
            summary["cached_public_fallback_ready"] += 1
        elif public_candidates:
            layer = "public_pull_required"
            selected = public_candidates[0]
            summary["public_pull_required"] += 1
        else:
            layer = "missing_policy"
            selected = None
            summary["missing_policy"] += 1
        languages[language_key] = {
            "selected_layer": layer,
            "selected_image": selected,
            "local_reserve_candidates": local_candidates,
            "local_reserve_available": local_available,
            "public_fallback_candidates": public_candidates,
            "public_fallback_available": public_available,
            "missing_local_reserve": [image for image in local_candidates if image not in local_available],
        }
    return {"version": SANDBOX_VERSION, "summary": summary, "languages": languages}


def _build_project_dockerfile(root: Path, plan: BuildPlan, options: BuildOptions, started: float) -> BuildResult:
    if options.cache_policy == "use" and _image_exists(plan.cache_image):
        return BuildResult(status="cached", cache_hit=True, image=plan.cache_image, duration_seconds=time.time() - started)
    prep_logs = _prepare_dockerfile_base_images(root / "Dockerfile")
    command = _docker_build_command(plan.cache_image, options, dockerfile_from_stdin=False, use_buildkit=True)
    proc, timed_out, elapsed = _run_docker_build(command, root, env={**os.environ, "DOCKER_BUILDKIT": "1"})
    if timed_out:
        log = {"step": "docker_build", "command": command, "returncode": -1, "stdout": _tail(proc.stdout), "stderr": f"Timed out after {elapsed:.0f}s"}
        retry = _retry_classic_builder(root, plan, options, started, [*prep_logs, log], f"{proc.stdout}\n{proc.stderr}", dockerfile_from_stdin=False)
        if retry:
            return retry
        return _failed_build_result(started, [*prep_logs, log], log["stderr"])
    log = {"step": "docker_build", "command": command, "returncode": proc.returncode, "stdout": proc.stdout[-12000:], "stderr": proc.stderr[-12000:]}
    if proc.returncode != 0:
        retry = _retry_classic_builder(root, plan, options, started, [*prep_logs, log], f"{proc.stdout}\n{proc.stderr}", dockerfile_from_stdin=False)
        if retry:
            return retry
        return _failed_build_result(started, [*prep_logs, log], f"{proc.stdout}\n{proc.stderr}")
    _remember_image_exists(plan.cache_image, True)
    _prune_cache(keep_image=plan.cache_image)
    return BuildResult(status="built", image=plan.cache_image, logs=[*prep_logs, log], duration_seconds=time.time() - started)


def _prepare_dockerfile_base_images(dockerfile: Path) -> list[dict[str, Any]]:
    if not dockerfile.exists():
        return []
    logs: list[dict[str, Any]] = []
    for image in _dockerfile_from_images(dockerfile):
        if _image_exists(image):
            continue
        mirrors = _mirror_image_references(image)
        if not mirrors:
            continue
        for mirror in mirrors:
            pull = subprocess.run(["docker", "pull", mirror], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
            logs.append({"step": "docker_pull_mirror", "command": ["docker", "pull", mirror], "returncode": pull.returncode, "stdout": pull.stdout[-12000:], "stderr": pull.stderr[-12000:]})
            if pull.returncode != 0:
                continue
            tag = subprocess.run(["docker", "tag", mirror, image], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            logs.append({"step": "docker_tag_mirror", "command": ["docker", "tag", mirror, image], "returncode": tag.returncode, "stdout": tag.stdout[-12000:], "stderr": tag.stderr[-12000:]})
            if tag.returncode == 0:
                _remember_image_exists(image, True)
            break
    return logs


def _dockerfile_from_images(dockerfile: Path) -> list[str]:
    stages: set[str] = set()
    images: list[str] = []
    for raw in dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = re.match(r"^\s*FROM\s+(?:(?:--platform=\S+)\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>[A-Za-z0-9_.-]+))?", raw, re.IGNORECASE)
        if not match:
            continue
        image = match.group("image")
        stage = match.group("stage")
        if stage:
            stages.add(stage)
        if "$" in image or image.lower() == "scratch" or image in stages:
            continue
        images.append(image)
    return images


def _mirror_image_reference(image: str) -> str | None:
    mirrors = _mirror_image_references(image)
    return mirrors[0] if mirrors else None


def _mirror_image_references(image: str) -> list[str]:
    if image.startswith("m.daocloud.io/"):
        return []
    if image.startswith("docker.io/"):
        repo = image.split("/", 1)[1]
        return [f"{prefix}/{repo}" for prefix in image_reserve.DOCKERHUB_MIRROR_PREFIXES]
    if image.startswith("docker.io/library/"):
        repo = image.split("/", 1)[1]
        return [f"{prefix}/{repo}" for prefix in image_reserve.DOCKERHUB_MIRROR_PREFIXES]
    if image.startswith("mcr.microsoft.com/"):
        return [f"m.daocloud.io/{image}"]
    if image.startswith("ghcr.io/"):
        return [f"m.daocloud.io/{image}"]
    has_slash = "/" in image
    registry = image.split("/", 1)[0]
    has_explicit_registry = has_slash and ("." in registry or ":" in registry or registry == "localhost")
    if not has_explicit_registry:
        repo = image if has_slash else f"library/{image}"
        return [f"{prefix}/{repo}" for prefix in image_reserve.DOCKERHUB_MIRROR_PREFIXES]
    return []


def _docker_build_command(cache_image: str, options: BuildOptions, dockerfile_from_stdin: bool, use_buildkit: bool) -> list[str]:
    command = ["docker", "build", "--pull=false"]
    if use_buildkit:
        command.append("--progress=plain")
    if options.cache_policy == "rebuild":
        command.append("--no-cache")
    if use_buildkit and options.cache_policy == "use":
        command.extend(_cache_from_args(limit=8))
    command.extend(_build_arg_args())
    command.extend(["-t", cache_image])
    if dockerfile_from_stdin:
        command.extend(["-f", "-", "."])
    else:
        command.append(".")
    return command


def _retry_classic_builder(
    root: Path,
    plan: BuildPlan,
    options: BuildOptions,
    started: float,
    logs: list[dict[str, Any]],
    failure_text: str,
    dockerfile_from_stdin: bool,
) -> BuildResult | None:
    if not _should_retry_classic_builder(failure_text, plan.base_image, dockerfile_from_stdin=dockerfile_from_stdin):
        return None
    command = _docker_build_command(plan.cache_image, options, dockerfile_from_stdin=dockerfile_from_stdin, use_buildkit=False)
    input_text = _generated_dockerfile(root, plan, cache_mounts=False) if dockerfile_from_stdin else None
    proc, timed_out, elapsed = _run_docker_build(command, root, input_text=input_text, env={**os.environ, "DOCKER_BUILDKIT": "0"})
    if timed_out:
        retry_log = {"step": "docker_build_classic_retry", "command": command, "returncode": -1, "stdout": _tail(proc.stdout), "stderr": f"Timed out after {elapsed:.0f}s"}
        return _failed_build_result(started, [*logs, retry_log], f"{proc.stdout}\n{proc.stderr}\n{retry_log['stderr']}")
    retry_log = {"step": "docker_build_classic_retry", "command": command, "returncode": proc.returncode, "stdout": proc.stdout[-12000:], "stderr": proc.stderr[-12000:]}
    if proc.returncode != 0:
        return _failed_build_result(started, [*logs, retry_log], f"{proc.stdout}\n{proc.stderr}")
    _remember_image_exists(plan.cache_image, True)
    _prune_cache(keep_image=plan.cache_image)
    return BuildResult(status="built", cache_hit=False, image=plan.cache_image, logs=[*logs, retry_log], duration_seconds=time.time() - started)


def _should_retry_classic_builder(text: str, base_image: str, dockerfile_from_stdin: bool = True) -> bool:
    lowered = text.lower()
    metadata_failure = any(
        token in lowered
        for token in (
            "load metadata for docker.io/",
            "failed to resolve source metadata",
            "failed to fetch anonymous token",
            "failed to fetch oauth token",
            "auth.docker.io/token",
            "docker-image://docker.io/docker/dockerfile",
        )
    )
    if not metadata_failure:
        return False
    if dockerfile_from_stdin:
        return bool(base_image and _image_exists(base_image))
    return True


def _failed_build_result(started: float, logs: list[dict[str, Any]], text: str) -> BuildResult:
    failure_class, reason, fix = classify_build_failure(text)
    return BuildResult(
        status="failed",
        cache_hit=False,
        image=None,
        logs=logs,
        duration_seconds=time.time() - started,
        failure_stage="docker_build",
        failure_class=failure_class,
        human_reason=reason,
        suggested_fix=fix,
    )


def _unsupported_plan(root: Path, adapter: AdapterCandidate, options: BuildOptions, reason: str) -> BuildPlan:
    plan = BuildPlan(plan_id="unsupported", language=adapter.language, framework=adapter.framework, protocol=adapter.protocol, base_image="unsupported", workdir="/workspace", source="detector", confidence=0.0, reason=reason)
    plan.cache_key = _cache_key(root, plan)
    plan.cache_image = ""
    return plan


def _cache_from_args(limit: int = 8) -> list[str]:
    images = _recent_build_cache_images(limit)
    args: list[str] = []
    for image in images:
        args.extend(["--cache-from", image])
    return args


def _build_arg_args() -> list[str]:
    values = {
        "APT_DEBIAN_MIRROR": os.getenv("AGENT_SANDBOX_APT_DEBIAN_MIRROR", DEFAULT_APT_DEBIAN_MIRROR),
        "APT_UBUNTU_MIRROR": os.getenv("AGENT_SANDBOX_APT_UBUNTU_MIRROR", DEFAULT_APT_UBUNTU_MIRROR),
        "ALPINE_MIRROR": os.getenv("AGENT_SANDBOX_ALPINE_MIRROR", DEFAULT_ALPINE_MIRROR),
        "PIP_INDEX_URL": os.getenv("AGENT_SANDBOX_PIP_INDEX_URL", DEFAULT_PIP_INDEX_URL),
        "NPM_REGISTRY": os.getenv("AGENT_SANDBOX_NPM_REGISTRY", DEFAULT_NPM_REGISTRY),
        "GOPROXY": os.getenv("AGENT_SANDBOX_GOPROXY", DEFAULT_GOPROXY),
        "MAVEN_MIRROR_URL": os.getenv("AGENT_SANDBOX_MAVEN_MIRROR_URL", DEFAULT_MAVEN_MIRROR_URL),
        "MAVEN_DIST_MIRROR": os.getenv("AGENT_SANDBOX_MAVEN_DIST_MIRROR", DEFAULT_MAVEN_DIST_MIRROR),
        "GRADLE_DIST_MIRROR": os.getenv("AGENT_SANDBOX_GRADLE_DIST_MIRROR", DEFAULT_GRADLE_DIST_MIRROR),
        "CARGO_REGISTRY": os.getenv("AGENT_SANDBOX_CARGO_REGISTRY", DEFAULT_CARGO_REGISTRY),
        "GITHUB_PROXY_URL": os.getenv("AGENT_SANDBOX_GITHUB_PROXY_URL", ""),
    }
    args: list[str] = []
    for key, value in values.items():
        if value:
            args.extend(["--build-arg", f"{key}={value}"])
    return args


def _recent_build_cache_images(limit: int = 8) -> list[str]:
    try:
        proc = subprocess.run(
            ["docker", "image", "ls", "--filter", f"reference={CACHE_PREFIX}:*", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=IMAGE_LIST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return []
    if proc.returncode != 0:
        return []
    images = [line.strip() for line in proc.stdout.splitlines() if line.strip().startswith(f"{CACHE_PREFIX}:")]
    return images[:limit]


def _legacy_compatible_cache_image(root: Path, plan: BuildPlan) -> str | None:
    db_path = Path(__file__).resolve().parents[1] / ".sandbox_data" / "runs.sqlite3"
    if not db_path.exists():
        return None
    current_manifests = _manifest_hashes(root)
    root_name = root.name
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT workspace, report_json
            FROM runs
            WHERE report_json IS NOT NULL
            ORDER BY updated_at DESC
            LIMIT 200
            """
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        if conn is not None:
            conn.close()
    for row in rows:
        try:
            report = json.loads(row["report_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        build_result = report.get("build_result") or {}
        image = build_result.get("image")
        if build_result.get("status") not in {"built", "cached"} or not image or not _image_exists(str(image)):
            continue
        previous_plan = report.get("build_plan") or {}
        profile = report.get("profile") or {}
        if profile.get("root_name") != root_name:
            continue
        if previous_plan.get("base_image") != plan.base_image:
            continue
        if previous_plan.get("install_commands") != plan.install_commands or previous_plan.get("build_commands") != plan.build_commands:
            continue
        previous_root = _previous_source_root(Path(row["workspace"]), root_name)
        if previous_root and previous_root.exists() and _manifest_hashes(previous_root) != current_manifests:
            continue
        return str(image)
    return None


def _previous_source_root(workspace: Path, root_name: str) -> Path | None:
    source = workspace / "source"
    if source.exists() and source.name == root_name:
        return source
    if (source / root_name).exists():
        return source / root_name
    if source.exists():
        children = [item for item in source.iterdir() if item.is_dir()]
        if len(children) == 1:
            return children[0]
    return None


def _run_docker_build(
    command: list[str],
    root: Path,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> tuple[subprocess.CompletedProcess[str], bool, float]:
    timeout = timeout or _build_timeout_seconds()
    started = time.time()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    proc = subprocess.Popen(
        command,
        cwd=root,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    try:
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        elapsed = time.time() - started
        return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr), False, elapsed
    except subprocess.TimeoutExpired:
        _terminate_process_tree(proc)
        stdout, stderr = proc.communicate(timeout=20)
        elapsed = time.time() - started
        return subprocess.CompletedProcess(command, -1, stdout, stderr), True, elapsed


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        return
    os.killpg(proc.pid, signal.SIGKILL)


def _build_timeout_seconds() -> int:
    raw = os.getenv("AGENT_SANDBOX_BUILD_TIMEOUT_SECONDS")
    if not raw:
        return DEFAULT_BUILD_TIMEOUT_SECONDS
    try:
        return max(60, int(raw))
    except ValueError:
        return DEFAULT_BUILD_TIMEOUT_SECONDS


def _cache_key(root: Path, plan: BuildPlan) -> str:
    hasher = hashlib.sha256()
    payload = {
        "version": SANDBOX_VERSION,
        "base_image": plan.base_image,
        "install": plan.install_commands,
        "build": plan.build_commands,
        "manifest_hashes": _manifest_hashes(root),
        "source_hashes": _source_hashes(root, plan),
    }
    hasher.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    return hasher.hexdigest()


def _manifest_hashes(root: Path) -> dict[str, str]:
    names = [
        "sandbox.yaml",
        "sandbox.yml",
        "Dockerfile",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "gradle.lockfile",
    ]
    result = {}
    for name in names:
        path = root / name
        if path.exists() and path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _source_hashes(root: Path, plan: BuildPlan) -> dict[str, str]:
    candidates = _cache_relevant_source_paths(root, plan)
    result: dict[str, str] = {}
    total = 0
    for path in candidates[:SOURCE_HASH_FILE_LIMIT]:
        try:
            size = path.stat().st_size
            if size > SOURCE_HASH_BYTES_LIMIT or total + size > SOURCE_HASH_BYTES_LIMIT:
                continue
            rel = path.relative_to(root).as_posix()
            result[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
            total += size
        except OSError:
            continue
    return result


def _cache_relevant_source_paths(root: Path, plan: BuildPlan) -> list[Path]:
    selected: dict[str, Path] = {}
    for command in [plan.start_command or "", *plan.install_commands, *plan.build_commands]:
        for rel in _paths_referenced_by_command(command):
            path = (root / rel).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError:
                continue
            if path.is_file() and not _skip_source_hash_path(path, root):
                selected[path.relative_to(root).as_posix()] = path
    if selected:
        return [selected[key] for key in sorted(selected)]
    paths: list[Path] = []
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if name not in {".git", "node_modules", ".venv", "__pycache__", ".sandbox_deps", ".sandbox_venv", "target", "dist", "build", ".agent_sandbox"}]
        for name in files:
            path = current_path / name
            if not _source_hash_extension(path) or _skip_source_hash_path(path, root):
                continue
            paths.append(path)
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def _paths_referenced_by_command(command: str) -> list[Path]:
    paths: list[Path] = []
    for token in re.findall(r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_./-]+\.(?:py|js|mjs|cjs|ts|tsx|java|go|rs|sh|rb|php|jar))", command):
        paths.append(Path(token))
    module = re.search(r"\bpython\s+-m\s+([A-Za-z0-9_.-]+)", command)
    if module:
        paths.append(Path(*module.group(1).split(".")).with_suffix(".py"))
    return paths


def _source_hash_extension(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".rs", ".sh", ".rb", ".php"}


def _skip_source_hash_path(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in {".git", "node_modules", ".venv", "__pycache__", ".sandbox_deps", ".sandbox_venv", "target", "dist", "build", ".agent_sandbox"} for part in rel_parts)


def _image_exists(image: str) -> bool:
    if not image:
        return False
    cached = _IMAGE_EXISTS_CACHE.get(image)
    if cached is not None:
        return cached
    try:
        proc = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=IMAGE_EXISTS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _IMAGE_EXISTS_CACHE[image] = False
        return False
    exists = proc.returncode == 0
    _IMAGE_EXISTS_CACHE[image] = exists
    return exists


def _remember_image_exists(image: str, exists: bool) -> None:
    if image:
        _IMAGE_EXISTS_CACHE[image] = exists


def _prune_cache(keep_image: str | None = None) -> None:
    if os.getenv("AGENT_SANDBOX_PRUNE_CACHE", "").strip().lower() not in {"1", "true", "yes"}:
        return
    try:
        proc = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.CreatedAt}}"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=IMAGE_LIST_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return
    if proc.returncode != 0:
        return
    images = [line.split()[0] for line in proc.stdout.splitlines() if line.startswith(f"{CACHE_PREFIX}:")]
    for image in images[CACHE_KEEP:]:
        if image == keep_image:
            continue
        subprocess.run(["docker", "rmi", image], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)


def _read_sandbox_yaml(root: Path) -> dict[str, Any]:
    for name in ("sandbox.yaml", "sandbox.yml"):
        path = root / name
        if path.exists():
            try:
                import yaml

                return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                return {}
    return {}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _read_package(root: Path) -> dict[str, Any] | None:
    path = root / "package.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _sample_text(root: Path) -> str:
    parts = []
    for path in list(root.rglob("*"))[:500]:
        if path.is_file() and path.suffix.lower() in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".md"}:
            parts.append(_read_text(path)[:4000])
    return "\n".join(parts)


def _read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:200000]
    except OSError:
        return ""


def _tail(value: Any, limit: int = 12000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[-limit:]
