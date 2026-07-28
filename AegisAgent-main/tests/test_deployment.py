from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agent_sandbox import deployment
from agent_sandbox.adapters import AdapterCandidate
from agent_sandbox.deployment import BuildOptions, BuildPatch, BuildPlan, BuildResult, classify_build_failure, create_build_plan
from agent_sandbox.image_reserve import MIRROR_IMAGES, OFFICIAL_IMAGES
from agent_sandbox.static_scan import scan_project


def _selected_plan(root: Path):
    profile, _, _ = scan_project(root)
    adapter = profile.adapter_matches[0]
    from agent_sandbox.adapters import candidate_from_dict

    return create_build_plan(root, candidate_from_dict(adapter), BuildOptions())


def test_python_uv_lock_prefers_uv_sync(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert plan.language == "Python"
    assert any("uv sync" in command and "--frozen" in command for command in plan.install_commands)
    assert plan.cache_image.startswith("agent-sandbox-build:")


def test_docker_build_runner_times_out_and_cleans_child_process(tmp_path: Path) -> None:
    proc, timed_out, elapsed = deployment._run_docker_build(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        tmp_path,
        timeout=1,
    )

    assert timed_out is True
    assert proc.returncode == -1
    assert elapsed < 10


def test_build_patch_from_python_module_failure_installs_missing_package(tmp_path: Path) -> None:
    plan = BuildPlan(
        plan_id="p",
        language="Python",
        framework=None,
        protocol="cli",
        base_image="aegisagent-python:3.12-bookworm",
        workdir="/workspace",
        install_commands=["python -m pip install -r requirements.txt"],
        start_command="python main.py",
    )
    result = BuildResult(
        status="failed",
        failure_class="build_script_failed",
        human_reason="ModuleNotFoundError: No module named 'yaml'",
    )

    patch = deployment.build_patch_from_failure(tmp_path, plan, result, [])

    assert patch is not None
    assert patch.add_python_packages == ["PyYAML"]


def test_apply_build_patches_accumulates_missing_components(tmp_path: Path) -> None:
    plan = BuildPlan(
        plan_id="p",
        language="Python",
        framework=None,
        protocol="cli",
        base_image="aegisagent-python:3.12-bookworm",
        workdir="/workspace",
        install_commands=["python -m pip install -r requirements.txt"],
        start_command="python main.py",
    )

    patched = deployment.apply_build_patches(
        tmp_path,
        plan,
        [
            BuildPatch(add_python_packages=["PyYAML"], reason="missing yaml"),
            BuildPatch(add_system_packages=["libsqlite3-dev"], reason="missing sqlite3.h"),
        ],
    )

    install_text = "\n".join(patched.install_commands)
    assert "libsqlite3-dev" in install_text
    assert "PyYAML" in install_text
    assert len(patched.build_patches) == 2
    assert patched.cache_key != plan.cache_key


def test_base_image_auth_failure_retries_next_public_fallback(tmp_path: Path) -> None:
    plan = BuildPlan(
        plan_id="p",
        language="Node.js",
        framework=None,
        protocol="cli",
        base_image="m.daocloud.io/docker.io/library/node:22-bookworm",
        workdir="/workspace",
        install_commands=["npm ci"],
        start_command="node index.js",
        image_resolution={
            "public_fallback_candidates": [
                "m.daocloud.io/docker.io/library/node:22-bookworm",
                OFFICIAL_IMAGES["node"],
                "docker.1ms.run/library/node:22-bookworm",
            ],
        },
    )
    result = BuildResult(
        status="failed",
        failure_class="auth_required",
        logs=[
            {
                "step": "docker_build",
                "stderr": "failed to resolve source metadata for m.daocloud.io/docker.io/library/node:22-bookworm: 401 Unauthorized",
            }
        ],
    )

    patch = deployment.build_patch_from_failure(tmp_path, plan, result, [])

    assert patch is not None
    assert patch.switch_base_image == OFFICIAL_IMAGES["node"]


def test_progressive_build_retries_with_feedback_patch(monkeypatch, tmp_path: Path) -> None:
    plan = BuildPlan(
        plan_id="p",
        language="Python",
        framework=None,
        protocol="cli",
        base_image="aegisagent-python:3.12-bookworm",
        workdir="/workspace",
        install_commands=["python -m pip install -r requirements.txt"],
        start_command="python main.py",
    )
    calls: list[BuildPlan] = []

    def fake_build_once(root: Path, current: BuildPlan, options: BuildOptions) -> BuildResult:
        calls.append(current)
        if len(calls) == 1:
            return BuildResult(
                status="failed",
                failure_class="build_script_failed",
                human_reason="ModuleNotFoundError: No module named 'yaml'",
            )
        return BuildResult(status="built", image=current.cache_image)

    monkeypatch.setattr(deployment, "_build_environment_once", fake_build_once)

    result = deployment.build_environment(tmp_path, plan, BuildOptions(max_build_attempts=3))

    assert result.status == "built"
    assert len(calls) == 2
    assert "PyYAML" in "\n".join(calls[1].install_commands)
    assert result.applied_patches[0]["add_python_packages"] == ["PyYAML"]
    assert result.attempts[0]["status"] == "failed"
    assert result.attempts[1]["status"] == "built"


def test_rewrite_maven_doc_package_command_uses_cache_and_skips_tests() -> None:
    command = deployment._rewrite_package_manager_command("cd demo && mvn clean package")

    assert "cd demo && mvn" in command
    assert "-Dmaven.repo.local=/workspace/.sandbox_deps/m2" in command
    assert "-DskipTests" in command
    assert " -q" in command


def test_rewrite_gradle_doc_build_command_skips_tests() -> None:
    command = deployment._rewrite_package_manager_command("cd demo && ./gradlew build")

    assert "./gradlew --no-daemon build -x test" in command


def test_recent_build_cache_images_tolerates_docker_timeout(monkeypatch) -> None:
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["docker", "image", "ls"], 12)

    monkeypatch.setattr(deployment.subprocess, "run", fake_run)

    assert deployment._recent_build_cache_images() == []


def test_image_exists_tolerates_docker_timeout(monkeypatch) -> None:
    deployment._IMAGE_EXISTS_CACHE.clear()

    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["docker", "image", "inspect"], 12)

    monkeypatch.setattr(deployment.subprocess, "run", fake_run)

    assert deployment._image_exists("example:latest") is False


def test_python_requirements_uses_opt_venv(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert plan.install_commands[0] == "python -m venv /opt/agent-venv"
    assert any("/opt/agent-venv/bin/python -m pip install -r requirements.txt" in command for command in plan.install_commands)


def test_python_import_extras_are_added_to_build_plan(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\ndependencies=[]\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("from langchain_openai import ChatOpenAI\nfrom langchain.tools import tool\n", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert any("langchain-openai" in command for command in plan.install_commands)
    assert any("langchain" in command for command in plan.install_commands)


def test_python_common_cli_import_extras_are_added_to_build_plan(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\ndependencies=[]\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("import click\nimport yaml\n", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert any("click" in command for command in plan.install_commands)
    assert any("PyYAML" in command for command in plan.install_commands)


def test_node_lockfile_prefers_npm_ci_and_build(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"build":"tsc","start":"node dist/index.js"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "index.js").write_text("console.log('ok')", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert plan.language == "Node.js"
    assert plan.base_image in {"aegisagent-node:22-bookworm", MIRROR_IMAGES["node"], OFFICIAL_IMAGES["node"]}
    assert plan.install_commands == ["npm ci --prefer-offline"]
    assert plan.build_commands == ["npm run build"]


def test_public_fallback_images_prefer_official_before_mirrors() -> None:
    from agent_sandbox import image_reserve

    assert image_reserve.PUBLIC_FALLBACK_IMAGES["node"][0] == image_reserve.OFFICIAL_IMAGES["node"]
    assert image_reserve.PUBLIC_FALLBACK_IMAGES["python"][0] == image_reserve.OFFICIAL_IMAGES["python"]
    assert not image_reserve.PUBLIC_FALLBACK_IMAGES["node"][0].startswith("m.daocloud.io/")


def test_bun_project_uses_bun_image_and_commands(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts":{"build":"bun run scripts/build.ts","start":"bun src/index.ts"}}',
        encoding="utf-8",
    )
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("console.log('ok')", encoding="utf-8")

    plan = _selected_plan(tmp_path)

    assert plan.base_image in {"oven/bun:1", "m.daocloud.io/docker.io/oven/bun:1"}
    assert any(command.startswith("bun install") for command in plan.install_commands)
    assert plan.build_commands == ["bun run build"]


def test_generated_dockerfile_configures_node_package_mirrors(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node index.js"}}', encoding="utf-8")
    (tmp_path / "index.js").write_text("console.log('ok')\n", encoding="utf-8")
    plan = BuildPlan(
        plan_id="node",
        language="Node.js",
        framework=None,
        protocol="cli",
        base_image="aegisagent-node:22-bookworm",
        workdir="/workspace",
        install_commands=["npm install"],
        build_commands=[],
        start_command="node index.js",
        source="test",
        reason="test",
        cache_key="node",
        cache_image="agent-sandbox-build:node",
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert "COREPACK_NPM_REGISTRY=$NPM_REGISTRY" in dockerfile
    assert "PNPM_STORE_PATH=/root/.local/share/pnpm/store" in dockerfile
    assert "YARN_NPM_REGISTRY_SERVER=$NPM_REGISTRY" in dockerfile
    assert "BUN_CONFIG_REGISTRY=$NPM_REGISTRY" in dockerfile
    assert "pnpm config set registry" in dockerfile
    assert "yarn config set npmRegistryServer" in dockerfile


def test_manifest_layer_skips_paths_excluded_by_dockerignore(tmp_path: Path) -> None:
    nested = tmp_path / "vscode-extension" / "openclaude-vscode"
    nested.mkdir(parents=True)
    (tmp_path / ".dockerignore").write_text("vscode-extension\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node index.js"}}', encoding="utf-8")
    (nested / "package.json").write_text("{}", encoding="utf-8")

    candidate = AdapterCandidate(
        name="node",
        kind="node",
        language="Node.js",
        framework=None,
        protocol="cli",
        image="node:22-bookworm",
        install=["npm install"],
        start="node index.js",
    )
    plan = create_build_plan(tmp_path, candidate, BuildOptions())
    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert 'COPY ["package.json", "package.json"]' in dockerfile
    assert "vscode-extension/openclaude-vscode/package.json" not in dockerfile


def test_sandbox_yaml_strong_override_build_plan(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node index.js"}}', encoding="utf-8")
    (tmp_path / "sandbox.yaml").write_text(
        "language: Python\nprotocol: cli\nimage: python:3.12-slim\ninstall:\n  - pip install demo\nbuild:\n  - python -m compileall .\nstart: python custom.py\n",
        encoding="utf-8",
    )

    plan = _selected_plan(tmp_path)

    assert plan.source == "sandbox_yaml"
    assert plan.base_image in {"python:3.12-slim", "m.daocloud.io/docker.io/library/python:3.12-slim"}
    assert "sandbox.yaml" in plan.reason
    assert plan.install_commands == ["pip install demo"]
    assert plan.build_commands == ["python -m compileall ."]
    assert plan.start_command == "python custom.py"


def test_langgraph_json_generates_monorepo_build_plan(tmp_path: Path) -> None:
    project = tmp_path / "all_projects" / "project_one"
    agent = project / "my_agent"
    agent.mkdir(parents=True)
    (tmp_path / "langgraph.json").write_text(
        '{"graphs":{"first":"./all_projects/project_one/my_agent/main.py:graph"}}',
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        "[tool.poetry]\nname='x'\nversion='0.1.0'\n[tool.poetry.dependencies]\npython='>=3.10,<3.13'\nlanggraph='^0.2.0'\n",
        encoding="utf-8",
    )
    (agent / "main.py").write_text("graph = object()\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.selected_adapter is not None
    assert profile.selected_adapter["name"] == "langgraph:first"
    plan = _selected_plan(tmp_path)
    assert plan.framework == "LangGraph"
    assert any("cd all_projects/project_one" in command for command in plan.install_commands)
    assert "LANGGRAPH_GRAPH_LOADED first" in (plan.start_command or "")


def test_langgraph_json_handles_relative_scan_root(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    project = repo / "all_projects" / "my_project" / "project_one"
    agent = project / "agent"
    agent.mkdir(parents=True)
    (repo / "langgraph.json").write_text(
        '{"graphs":{"agent":"./all_projects/my_project/project_one/agent/main.py:graph"}}',
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\n", encoding="utf-8")
    (agent / "main.py").write_text("graph = object()\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    profile, _, _ = scan_project(Path("repo"))

    assert profile.selected_adapter is not None
    assert profile.selected_adapter["name"] == "langgraph:agent"


def test_langgraph_json_prefers_lighter_install_candidate(tmp_path: Path) -> None:
    poetry_project = tmp_path / "poetry_project"
    poetry_agent = poetry_project / "agent"
    poetry_agent.mkdir(parents=True)
    requirements_project = tmp_path / "requirements_project"
    requirements_agent = requirements_project / "agent"
    requirements_agent.mkdir(parents=True)
    (tmp_path / "langgraph.json").write_text(
        '{"graphs":{"poetry":"./poetry_project/agent/main.py:graph","requirements":"./requirements_project/agent/main.py:graph"}}',
        encoding="utf-8",
    )
    (poetry_project / "pyproject.toml").write_text("[tool.poetry]\nname='x'\nversion='0.1.0'\n", encoding="utf-8")
    (requirements_project / "requirements.txt").write_text("langgraph\n", encoding="utf-8")
    (poetry_agent / "main.py").write_text("graph = object()\n", encoding="utf-8")
    (requirements_agent / "main.py").write_text("graph = object()\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.selected_adapter is not None
    assert profile.selected_adapter["name"] == "langgraph:requirements"


def test_go_cmd_main_generates_cli_build_plan(tmp_path: Path) -> None:
    cmd = tmp_path / "cmd" / "chatgpt"
    cmd.mkdir(parents=True)
    (tmp_path / "go.mod").write_text("module example.com/agent\n\ngo 1.24.1\n", encoding="utf-8")
    (cmd / "main.go").write_text(
        "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"agent\") }\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("A Go CLI agent using Cobra and OpenAI tools.\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.selected_adapter is not None
    assert profile.selected_adapter["name"] == "go-plan:cmd/chatgpt"
    plan = _selected_plan(tmp_path)
    assert plan.language == "Go"
    assert plan.base_image in {"aegisagent-go:1.24-bookworm", MIRROR_IMAGES["go"], OFFICIAL_IMAGES["go"]}
    assert any("go build -o /tmp/aegisagent-chatgpt ./cmd/chatgpt" in command for command in plan.install_commands)
    assert 'SANDBOX_CLI_INPUT' in (plan.start_command or "")


def test_go_mod_125_requests_go_125_image(tmp_path: Path) -> None:
    cmd = tmp_path / "cmd" / "agent"
    cmd.mkdir(parents=True)
    (tmp_path / "go.mod").write_text("module example.com/agent\n\ngo 1.25.0\n", encoding="utf-8")
    (cmd / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)
    selected = profile.adapter_matches[0]

    assert selected["image"] == "aegisagent-go:1.25-bookworm"


def test_go_manifest_layer_includes_local_replace_targets(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    model = tmp_path / "model" / "anthropic"
    model.mkdir(parents=True)
    (tmp_path / "go.mod").write_text("module example.com/root\n\ngo 1.24\n", encoding="utf-8")
    (examples / "go.mod").write_text(
        "module example.com/examples\n\ngo 1.24\nreplace example.com/model/anthropic => ../model/anthropic\n",
        encoding="utf-8",
    )
    (model / "go.mod").write_text("module example.com/model/anthropic\n\ngo 1.24\n", encoding="utf-8")

    paths = deployment._manifest_paths(tmp_path, "go")

    assert "model/anthropic/go.mod" in paths


def test_docker_registry_connectivity_failure_is_network_timeout() -> None:
    failure_class, reason, fix = classify_build_failure(
        'failed to fetch oauth token: Post "https://auth.docker.io/token": '
        "dial tcp 157.240.9.36:443: connectex: A connection attempt failed"
    )

    assert failure_class == "network_timeout"
    assert "network" in reason.lower()
    assert "Retry" in fix


def test_native_system_dependency_failure_is_system_package_missing() -> None:
    failure_class, reason, fix = classify_build_failure(
        "The system library `dbus-1` required by crate `libdbus-sys` was not found. "
        "pkg-config exited with status code 1. One possible solution is to install libdbus-1-dev and pkg-config."
    )

    assert failure_class == "system_package_missing"
    assert "native dependency" in reason
    assert "system_packages" in fix


def test_java_maven_dockerfile_layers_manifest_and_persists_local_repo(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project />\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    plan = BuildPlan(
        plan_id="java",
        language="Java",
        framework="Spring",
        protocol="http",
        base_image="maven:3.9-eclipse-temurin-21",
        workdir="/workspace",
        install_commands=[
            "mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q -DskipTests dependency:go-offline",
            "mvn -Dmaven.repo.local=/workspace/.sandbox_deps/m2 -q -DskipTests package",
        ],
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert dockerfile.index("COPY pom.xml ./") < dockerfile.index("COPY . /workspace")
    assert "--mount=type=cache,target=/root/.m2" in dockerfile
    assert dockerfile.index("dependency:go-offline") < dockerfile.index("COPY . /workspace")
    assert dockerfile.index("COPY . /workspace") < dockerfile.index("-DskipTests package")


def test_java_gradle_dockerfile_layers_manifest_before_sources(tmp_path: Path) -> None:
    (tmp_path / "build.gradle.kts").write_text("plugins { java }\n", encoding="utf-8")
    (tmp_path / "settings.gradle.kts").write_text("rootProject.name = \"agent\"\n", encoding="utf-8")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "gradle").mkdir()
    plan = BuildPlan(
        plan_id="java-gradle",
        language="Java",
        framework="Spring",
        protocol="http",
        base_image="maven:3.9-eclipse-temurin-21",
        workdir="/workspace",
        install_commands=[
            "./gradlew --no-daemon dependencies >/dev/null || true",
            "./gradlew --no-daemon build -x test",
        ],
        start_command="java -jar build/libs/agent.jar",
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert dockerfile.index("COPY build.gradle.kts ./") < dockerfile.index("COPY . /workspace")
    assert dockerfile.index("COPY gradle ./gradle") < dockerfile.index("COPY . /workspace")
    assert dockerfile.index("dependencies") < dockerfile.index("COPY . /workspace")
    assert dockerfile.index("COPY . /workspace") < dockerfile.index("build -x test")


def test_build_cache_key_ignores_runtime_start_command(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project />\n", encoding="utf-8")
    first = BuildPlan(
        plan_id="one",
        language="Java",
        framework="Spring",
        protocol="http",
        base_image="maven:3.9-eclipse-temurin-21",
        workdir="/workspace",
        install_commands=["mvn -q dependency:go-offline"],
        start_command="java -jar one.jar",
    )
    second = BuildPlan(
        plan_id="two",
        language="Java",
        framework="Spring",
        protocol="cli",
        base_image="maven:3.9-eclipse-temurin-21",
        workdir="/workspace",
        install_commands=["mvn -q dependency:go-offline"],
        start_command="java -jar two.jar",
    )

    assert deployment._cache_key(tmp_path, first) == deployment._cache_key(tmp_path, second)


def test_python_dockerfile_layers_dependency_manifests_before_source(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    plan = BuildPlan(
        plan_id="python",
        language="Python",
        framework="LangGraph",
        protocol="cli",
        base_image="python:3.12-bookworm",
        workdir="/workspace",
        install_commands=[
            "python -m venv /opt/agent-venv",
            "/opt/agent-venv/bin/python -m pip install --upgrade pip setuptools wheel",
            "python -m pip install uv",
            "VIRTUAL_ENV=/opt/agent-venv uv sync --frozen --active",
        ],
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert "# syntax=docker/dockerfile:1.7" not in dockerfile
    assert dockerfile.index('COPY ["pyproject.toml", "pyproject.toml"]') < dockerfile.index("COPY . /workspace")
    assert "uv sync --no-python-downloads --no-managed-python --python /opt/agent-venv/bin/python --no-install-project --frozen --active" in dockerfile
    assert dockerfile.index("--no-install-project") < dockerfile.index("COPY . /workspace")
    assert dockerfile.rindex("uv sync --no-python-downloads --no-managed-python --python /opt/agent-venv/bin/python --frozen --active") > dockerfile.index("COPY . /workspace")
    assert "--mount=type=cache,target=/root/.cache/uv" in dockerfile


def test_uv_sync_uses_existing_python_and_disables_python_downloads() -> None:
    command = deployment._rewrite_package_manager_command("VIRTUAL_ENV=/opt/agent-venv uv sync --frozen --active")

    assert "--python /opt/agent-venv/bin/python" in command
    assert "--no-managed-python" in command
    assert "--no-python-downloads" in command


def test_subdirectory_npm_install_disables_workspace_lifecycle() -> None:
    command = deployment._rewrite_package_manager_command("cd src/server && npm install --ignore-scripts --no-audit")

    assert "npm install --workspaces=false --prefer-offline" in command


def test_classic_fallback_dockerfile_omits_buildkit_cache_mounts(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    plan = BuildPlan(
        plan_id="python",
        language="Python",
        framework=None,
        protocol="cli",
        base_image="aegisagent-python:3.12-bookworm",
        workdir="/workspace",
        install_commands=["/opt/agent-venv/bin/python -m pip install -r requirements.txt"],
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan, cache_mounts=False)

    assert "--mount=type=cache" not in dockerfile
    assert "PIP_INDEX_URL" in dockerfile


def test_python_docs_plan_initializes_opt_venv_once(tmp_path: Path) -> None:
    candidate = AdapterCandidate(
        name="docs-python",
        kind="plan_docs",
        language="Python",
        framework=None,
        protocol="cli",
        image="aegisagent-python:3.12-bookworm",
        install=["/opt/agent-venv/bin/python -m pip install -r requirements.txt"],
        start="python main.py",
    )

    plan = create_build_plan(tmp_path, candidate, BuildOptions())

    assert plan.install_commands[:2] == [
        "python -m venv /opt/agent-venv",
        "/opt/agent-venv/bin/python -m pip install --upgrade pip setuptools wheel",
    ]
    assert plan.install_commands.count("python -m venv /opt/agent-venv") == 1


def test_rust_dockerfile_copies_target_markers_before_cargo_fetch(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='agent'\nversion='0.1.0'\nedition='2021'\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    benches = tmp_path / "benches"
    benches.mkdir()
    (benches / "render_cache.rs").write_text("fn main() {}\n", encoding="utf-8")
    plan = BuildPlan(
        plan_id="rust",
        language="Rust",
        framework=None,
        protocol="cli",
        base_image="rust:1-bookworm",
        workdir="/workspace",
        install_commands=["CARGO_HOME=/workspace/.sandbox_deps/cargo cargo fetch"],
    )

    dockerfile = deployment._generated_dockerfile(tmp_path, plan)

    assert 'COPY ["src/main.rs", "src/main.rs"]' in dockerfile
    assert 'COPY ["benches/render_cache.rs", "benches/render_cache.rs"]' in dockerfile
    assert dockerfile.index('COPY ["src/main.rs", "src/main.rs"]') < dockerfile.index("cargo fetch")
    assert "--mount=type=cache,target=/workspace/target" not in dockerfile


def test_docker_metadata_failure_retries_classic_when_local_base_exists(monkeypatch) -> None:
    monkeypatch.setattr(deployment, "_image_exists", lambda image: image == "aegisagent-python:3.12-bookworm")

    assert deployment._should_retry_classic_builder(
        "ERROR: failed to solve: aegisagent-python:3.12-bookworm: failed to resolve source metadata for "
        "docker.io/library/aegisagent-python:3.12-bookworm: failed to fetch anonymous token",
        "aegisagent-python:3.12-bookworm",
    )


def test_dockerfile_base_images_are_parsed_without_stage_refs(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM --platform=$BUILDPLATFORM python:3.12-slim AS build\n"
        "FROM build AS copied\n"
        "FROM mcr.microsoft.com/devcontainers/universal:linux\n",
        encoding="utf-8",
    )

    assert deployment._dockerfile_from_images(dockerfile) == [
        "python:3.12-slim",
        "mcr.microsoft.com/devcontainers/universal:linux",
    ]


def test_public_image_references_can_use_registry_mirror() -> None:
    assert deployment._mirror_image_reference("python:3.12-slim") == "m.daocloud.io/docker.io/library/python:3.12-slim"
    assert (
        deployment._mirror_image_reference("mcr.microsoft.com/devcontainers/universal:linux")
        == "m.daocloud.io/mcr.microsoft.com/devcontainers/universal:linux"
    )


def test_public_fallback_prefers_cached_public_image_before_pull(monkeypatch) -> None:
    monkeypatch.setattr(deployment, "_image_exists", lambda image: image == OFFICIAL_IMAGES["python"])

    details = deployment._resolve_base_image_details("python:3.11-slim", "Python")

    assert details["selected_image"] == OFFICIAL_IMAGES["python"]
    assert details["selected_layer"] == "cached_public_fallback"
    assert details["requires_public_pull"] is False
    assert details["public_fallback_available"] == [OFFICIAL_IMAGES["python"]]


def test_aegisagent_fallback_prefers_cached_public_image(monkeypatch) -> None:
    monkeypatch.setattr(deployment, "_image_exists", lambda image: image == OFFICIAL_IMAGES["java"])

    image, reason = deployment._resolve_aegisagent_image("aegisagent-java:21-bookworm")

    assert image == OFFICIAL_IMAGES["java"]
    assert "cached public image" in reason


def test_build_plan_records_image_resolution_layer(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(deployment, "_image_exists", lambda image: image == OFFICIAL_IMAGES["node"])
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node index.js"}}', encoding="utf-8")
    (tmp_path / "index.js").write_text("console.log('ok')\n", encoding="utf-8")
    candidate = AdapterCandidate(
        name="node",
        kind="node",
        language="Node.js",
        framework=None,
        protocol="cli",
        image="node:20-bookworm",
        install=["npm install"],
        start="node index.js",
    )

    plan = create_build_plan(tmp_path, candidate, BuildOptions())

    assert plan.base_image == OFFICIAL_IMAGES["node"]
    assert plan.image_resolution["selected_layer"] == "cached_public_fallback"
    assert plan.image_resolution["requested_image"] == "node:20-bookworm"


def test_image_reserve_status_reports_second_layer_gaps() -> None:
    available = {"aegisagent-python:3.12-bookworm", OFFICIAL_IMAGES["node"]}
    status = deployment.image_reserve_status(lambda image: image in available)

    assert status["languages"]["python"]["selected_layer"] == "local_reserve"
    assert status["languages"]["node"]["selected_layer"] == "cached_public_fallback"
    assert status["languages"]["node"]["selected_image"] == OFFICIAL_IMAGES["node"]
    assert status["languages"]["java"]["selected_layer"] == "public_pull_required"
    assert status["summary"]["local_reserve_ready"] >= 1
    assert status["summary"]["cached_public_fallback_ready"] >= 1
    assert status["summary"]["public_pull_required"] >= 1


def test_build_args_include_dependency_mirrors(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_SANDBOX_PIP_INDEX_URL", "https://pypi.example/simple")

    args = deployment._build_arg_args()

    assert "--build-arg" in args
    assert "PIP_INDEX_URL=https://pypi.example/simple" in args
    assert any(item.startswith("NPM_REGISTRY=") for item in args)
