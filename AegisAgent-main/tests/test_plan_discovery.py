from __future__ import annotations

from pathlib import Path

from agent_sandbox.adapters import AdapterCandidate
from agent_sandbox.deployment import BuildOptions, create_build_plan
from agent_sandbox.plan_discovery import expand_candidate_variants, llm_plan_to_candidate
from agent_sandbox.static_scan import scan_project


def test_llm_build_plan_rejects_dangerous_command() -> None:
    candidate = llm_plan_to_candidate(
        {
            "language": "Python",
            "protocol": "cli",
            "base_image": "python:3.12-slim",
            "install_commands": ["rm -rf /"],
            "start_command": "python main.py",
            "confidence": 0.8,
        }
    )

    assert candidate is not None
    assert candidate.install == []


def test_llm_build_plan_requires_start_command() -> None:
    assert llm_plan_to_candidate({"language": "Python", "install_commands": ["pip install ."]}) is None


def test_llm_build_plan_rejects_help_only_cli_start() -> None:
    assert (
        llm_plan_to_candidate(
            {
                "language": "Bash",
                "protocol": "cli",
                "base_image": "ubuntu:latest",
                "install_commands": ["apt-get install -y jq curl"],
                "start_command": "openai -h",
            }
        )
        is None
    )


def test_shebang_shell_cli_generates_chat_capable_plan(tmp_path: Path) -> None:
    script = tmp_path / "openai"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "check_bin jq\n"
        "curl https://example.invalid/v1/chat/completions\n"
        "echo \"$1\"\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("OpenAI compatible bash CLI.\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert "Shell" in profile.languages
    assert "openai" in profile.entrypoints
    shell_plan = next(item for item in profile.adapter_matches if item["name"].startswith("shell-plan:"))
    assert shell_plan["image"] == "bash:5.2"
    assert "jq" in " ".join(shell_plan["install"])
    assert "curl" in " ".join(shell_plan["install"])
    assert "SANDBOX_CLI_INPUT" in shell_plan["start"]


def test_llm_plan_expands_to_image_reserve_variants() -> None:
    candidate = llm_plan_to_candidate(
        {
            "name": "bash-cli",
            "language": "Bash",
            "framework": "OpenAI-compatible CLI",
            "protocol": "cli",
            "base_image": "ubuntu:latest",
            "install_commands": ["apt-get update", "apt-get install -y jq curl"],
            "start_command": "openai \"$SANDBOX_CLI_INPUT\"",
            "confidence": 0.8,
        }
    )

    assert candidate is not None
    variants = expand_candidate_variants(candidate)

    assert any(item.image == "bash:5.2" for item in variants)


def test_llm_plan_prefers_local_shell_reserve_and_rewrites_apt_for_bash_image(tmp_path: Path) -> None:
    candidate = llm_plan_to_candidate(
        {
            "language": "Bash",
            "protocol": "cli",
            "base_image": "ubuntu:latest",
            "install_commands": ["apt-get update", "apt-get install -y jq curl"],
            "start_command": "openai \"$SANDBOX_CLI_INPUT\"",
            "confidence": 0.8,
        }
    )
    assert candidate is not None

    plan = create_build_plan(tmp_path, candidate, BuildOptions())

    assert plan.base_image != "ubuntu:latest"
    if plan.base_image.startswith("bash:"):
        assert plan.install_commands == ["apk add --no-cache jq curl ca-certificates"]


def test_shell_reserve_variant_rewrites_apk_for_debian_style_image(tmp_path: Path) -> None:
    script = tmp_path / "agent"
    script.write_text("#!/usr/bin/env bash\njq --version\ncurl --version\n", encoding="utf-8")
    profile, _, _ = scan_project(tmp_path)
    variant = next(item for item in profile.adapter_matches if item["image"] == "aegisagent-universal:linux")

    from agent_sandbox.adapters import candidate_from_dict

    plan = create_build_plan(tmp_path, candidate_from_dict(variant), BuildOptions())

    if not plan.base_image.startswith("bash:"):
        assert plan.install_commands == [
            "apt-get update && apt-get install -y --no-install-recommends ca-certificates jq curl"
        ]


def test_node_commander_ask_command_is_ranked_before_interactive_start(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "package.json").write_text(
        '{"scripts":{"start":"node src/cli.js"},"bin":{"ai-client":"./src/cli.js"},"dependencies":{"commander":"^11.0.0","openai":"^4.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (src / "cli.js").write_text(
        "#!/usr/bin/env node\n"
        "const { program } = require('commander');\n"
        "program.command('ask <prompt>').action(() => {});\n"
        "program.command('interactive').action(() => {});\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["name"].startswith("node-plan:.:oneshot")
    assert profile.adapter_matches[0]["start"] == 'node \'src/cli.js\' ask "$SANDBOX_CLI_INPUT"'
    assert "npm start" not in profile.adapter_matches[0]["start"]


def test_python_click_chat_command_generates_one_shot_plan(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='agent'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "cli.py").write_text(
        "import click\n"
        "@click.command('chat')\n"
        "def chat(): pass\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert any(" chat \"$SANDBOX_CLI_INPUT\"" in item["start"] for item in profile.adapter_matches)


def test_python_click_prompt_argument_is_passed_as_cli_argument(tmp_path: Path) -> None:
    pkg = tmp_path / "chat"
    pkg.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='chat-agent'\nversion='0.1.0'\n"
        "[project.scripts]\nchat = 'chat.cli:cli'\n",
        encoding="utf-8",
    )
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cli.py").write_text(
        "import click\n"
        "@click.command()\n"
        "@click.argument('prompt', nargs=-1)\n"
        "def cli(prompt): pass\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["start"] == 'chat "$SANDBOX_CLI_INPUT"'


def test_python_argparse_prompt_subcommand_is_ranked_before_generic_cli(tmp_path: Path) -> None:
    pkg = tmp_path / "freeclaw"
    pkg.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='freeclaw'\nversion='0.1.0'\n"
        "[project.scripts]\nfreeclaw = 'freeclaw.cli:main'\n",
        encoding="utf-8",
    )
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cli.py").write_text(
        "import argparse\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    sub = parser.add_subparsers(dest='cmd', required=True)\n"
        "    p_run = sub.add_parser('run', help='Run a single prompt.')\n"
        "    p_run.add_argument('prompt')\n"
        "    p_chat = sub.add_parser('chat', help='Interactive chat.')\n"
        "    args = parser.parse_args()\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["start"] == 'freeclaw run "$SANDBOX_CLI_INPUT"'
    assert any(item["start"] == 'freeclaw run "$SANDBOX_CLI_INPUT"' for item in profile.adapter_matches)


def test_python_textual_repo_orchestrator_does_not_invent_prompt_argument(tmp_path: Path) -> None:
    pkg = tmp_path / "agentsloop"
    pkg.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='agentsloop-cli'\nversion='0.1.0'\n"
        "[project.scripts]\nagentsloop = 'agentsloop.cli:main'\n",
        encoding="utf-8",
    )
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cli.py").write_text(
        "from textual.app import App\n"
        "def main():\n"
        "    print('AgentsLoop must be launched from inside a Git repository.')\n"
        "    print('Git SSH key path is mandatory.')\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert not any(item["start"] == 'agentsloop "$SANDBOX_CLI_INPUT"' for item in profile.adapter_matches)
    assert profile.adapter_matches[0]["framework"] == "Repository Terminal UI"


def test_install_shell_script_is_auxiliary_when_primary_manifest_exists(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='agent'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('agent')\n", encoding="utf-8")
    (tmp_path / "install.sh").write_text("#!/usr/bin/env bash\npip install git+https://example.invalid/agent.git\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert not any(item["name"] == "shell-plan:install.sh" for item in profile.adapter_matches)
    assert not any(item["name"] == "shell-cli" and item["start"] == "bash install.sh" for item in profile.adapter_matches)


def test_modern_openai_client_is_not_downgraded_by_legacy_docs(tmp_path: Path) -> None:
    pkg = tmp_path / "agent"
    data = tmp_path / "data"
    pkg.mkdir()
    data.mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='agent'\nversion='0.1.0'\n", encoding="utf-8")
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "main.py").write_text("from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8")
    (data / "article.json").write_text('{"text":"old example: openai.Completion.create(prompt=\\"hi\\")"}', encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    installs = "\n".join(command for item in profile.adapter_matches for command in item.get("install", []))
    assert "openai<1" not in installs


def test_nested_python_example_installs_parent_package_when_imported(tmp_path: Path) -> None:
    parent_pkg = tmp_path / "swarm"
    example = tmp_path / "examples" / "support_bot"
    parent_pkg.mkdir()
    example.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='swarm'\nversion='0.1.0'\n", encoding="utf-8")
    (parent_pkg / "__init__.py").write_text("", encoding="utf-8")
    (example / "requirements.txt").write_text("qdrant-client\n", encoding="utf-8")
    (example / "main.py").write_text("from swarm import Agent\nprint(Agent)\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)
    plan = next(item for item in profile.adapter_matches if item["name"].startswith("python-plan:examples/support_bot"))

    assert plan["install"][0] == "/opt/agent-venv/bin/python -m pip install ."


def test_nested_python_src_layout_example_installs_parent_package(tmp_path: Path) -> None:
    parent_pkg = tmp_path / "src" / "agentkit"
    example = tmp_path / "examples" / "server"
    parent_pkg.mkdir(parents=True)
    example.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='agentkit'\nversion='0.1.0'\n", encoding="utf-8")
    (parent_pkg / "__init__.py").write_text("", encoding="utf-8")
    (example / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (example / "app.py").write_text("from agentkit import Agent\nprint(Agent)\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)
    plan = next(item for item in profile.adapter_matches if item["name"].startswith("python-plan:examples/server"))

    assert plan["install"][0] == "/opt/agent-venv/bin/python -m pip install ."


def test_go_cobra_chat_command_generates_subcommand_plan(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/agent\n\ngo 1.24.1\n", encoding="utf-8")
    (tmp_path / "main.go").write_text(
        "package main\n"
        "import \"github.com/spf13/cobra\"\n"
        "func main() { _ = cobra.Command{Use: \"chat <prompt>\"} }\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert any("/tmp/aegisagent-go-root chat \"$SANDBOX_CLI_INPUT\"" in item["start"] for item in profile.adapter_matches)


def test_go_mcp_server_is_ranked_before_plain_cli(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/mcp\n\ngo 1.25.0\nrequire github.com/modelcontextprotocol/go-sdk v1.4.0\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        "package main\n"
        "import \"github.com/modelcontextprotocol/go-sdk/mcp\"\n"
        "func main() { _ = mcp.NewServer }\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["name"] == "go-mcp:."
    assert profile.adapter_matches[0]["protocol"] == "mcp"
    assert profile.adapter_matches[0]["image"] == "aegisagent-go:1.25-bookworm"


def test_go_nested_module_builds_from_nearest_go_mod(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/root\n\ngo 1.24\n", encoding="utf-8")
    nested = tmp_path / "examples" / "server"
    nested.mkdir(parents=True)
    (nested / "go.mod").write_text("module example.com/server\n\ngo 1.24\n", encoding="utf-8")
    (nested / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)
    plan = next(item for item in profile.adapter_matches if item["name"] == "go-plan:examples/server")

    assert "cd examples/server && go build -o /tmp/aegisagent-server ." in plan["install"]
    assert "go build -o /tmp/aegisagent-server ./examples/server" not in plan["install"]


def test_rust_clap_chat_command_generates_subcommand_plan(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text("[package]\nname='agent'\nversion='0.1.0'\nedition='2021'\n", encoding="utf-8")
    (src / "main.rs").write_text('use clap::Command; fn main() { let _ = Command::new("chat <prompt>"); }\n', encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert any("/workspace/target/debug/agent chat \"$SANDBOX_CLI_INPUT\"" in item["start"] for item in profile.adapter_matches)


def test_rust_docs_one_shot_say_command_is_preferred_for_terminal_tui(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname='terminal-agent'\nversion='0.1.0'\nedition='2021'\n"
        "[dependencies]\nclap='4'\nratatui='0.29'\n",
        encoding="utf-8",
    )
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Full-screen terminal chat interface for OpenAI-compatible APIs.\n"
        "OPENAI_API_KEY and OPENAI_BASE_URL configure auth. Use `terminal-agent --env` for environment auth.\n"
        "For one-off questions without the TUI, run:\n"
        "```bash\nterminal-agent say \"What is the capital of France?\"\n```\n"
        "MCP is disabled in terminal-agent say mode.\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["framework"] == "Clap Terminal TUI"
    assert (
        profile.adapter_matches[0]["start"]
        == '/workspace/target/debug/terminal-agent --env --disable-mcp say "$SANDBOX_CLI_INPUT"'
    )


def test_rust_keyring_dependency_adds_native_system_packages(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname='agent'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nkeyring='3'\n",
        encoding="utf-8",
    )
    (src / "main.rs").write_text('fn main() {}\n', encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)
    rust_plan = next(item for item in profile.adapter_matches if item["name"].startswith("rust-plan:"))

    assert "libdbus-1-dev" in " ".join(rust_plan["install"])


def test_generic_chat_words_do_not_create_unverified_rust_subcommands(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (tmp_path / "Cargo.toml").write_text("[package]\nname='agent'\nversion='0.1.0'\nedition='2021'\n", encoding="utf-8")
    (src / "main.rs").write_text('fn main() { println!("terminal chat interface for prompts"); }\n', encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert not any('/workspace/target/debug/agent chat "$SANDBOX_CLI_INPUT"' in item["start"] for item in profile.adapter_matches)
    assert any('printf "%s\\n" "$SANDBOX_CLI_INPUT" | /workspace/target/debug/agent' in item["start"] for item in profile.adapter_matches)


def test_auxiliary_shell_scripts_do_not_displace_primary_manifest(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='agent'\nversion='0.1.0'\nedition='2021'\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    tapes = tmp_path / "tapes"
    tapes.mkdir()
    (tapes / "demo.sh").write_text("#!/usr/bin/env bash\nagent chat \"$1\"\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert not any(item["name"].startswith("shell-plan:tapes/") for item in profile.adapter_matches)
    assert any(item["name"].startswith("rust-plan:") for item in profile.adapter_matches)


def test_docs_python_venv_command_is_not_start_candidate(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/agent\n\ngo 1.24\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "```bash\npython3 -m venv venv\nsource venv/bin/activate\npip install -r requirements.txt\n```\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert not any("python3 -m venv" in item["start"] for item in profile.adapter_matches)


def test_docs_vite_script_is_http_candidate_with_vite_port(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts":{"dev":"vite --host 0.0.0.0"},"dependencies":{"vite":"latest"}}',
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("```bash\nnpm run dev\n```\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert any(item["name"].startswith("docs-plan:") and item["protocol"] == "http" and item["port"] == 5173 for item in profile.adapter_matches)


def test_docs_maintenance_scripts_are_not_start_candidates(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"release":"node release.js","dev":"vite"}}', encoding="utf-8")
    (tmp_path / "README.md").write_text("```bash\nnpm run release\nnpm run dev\n```\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert not any("npm run release" in item["start"] for item in profile.adapter_matches)
    assert any("npm run dev" in item["start"] for item in profile.adapter_matches)


def test_node_lockfile_relaxed_variant_is_preserved() -> None:
    candidate = AdapterCandidate(
        name="node-http",
        kind="plan_node",
        language="Node.js",
        framework="Bun",
        protocol="http",
        image="oven/bun:1",
        install=["bun install --frozen-lockfile --ignore-scripts"],
        start="bun start",
        port=3000,
        confidence=0.8,
    )

    variants = expand_candidate_variants(candidate)

    assert any(item.name.endswith(":relaxed-lockfile") and "bun install --ignore-scripts" in item.install for item in variants)


def test_node_workspace_uses_declared_package_manager_for_build(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"packageManager":"pnpm@9.0.0","scripts":{"build":"tsc","start":"node dist/index.js"}}',
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text("console.log('agent')\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    node_plan = next(item for item in profile.adapter_matches if item["name"].startswith("node-plan:."))
    assert "pnpm install --frozen-lockfile" in node_plan["install"]
    assert "pnpm run build" in node_plan["install"]


def test_monorepo_docs_rank_main_app_before_contrib_samples(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node server.js"},"dependencies":{"express":"latest"}}', encoding="utf-8")
    (tmp_path / "server.js").write_text("require('express')().listen(3000)\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("```bash\nnpm start\n```\n", encoding="utf-8")
    for idx in range(10):
        sample = tmp_path / "contrib" / "samples" / f"demo-{idx}"
        sample.mkdir(parents=True)
        (sample / "package.json").write_text('{"scripts":{"start":"node index.js"}}', encoding="utf-8")
        (sample / "README.md").write_text("```bash\nnpm start\n```\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["name"].startswith("docs-plan:.") or profile.adapter_matches[0]["name"].startswith("node-plan:.:http")
    assert sum(1 for item in profile.adapter_matches if "contrib/samples" in item["name"]) <= 4


def test_go_entrypoints_prefer_cmd_and_simple_over_external_examples(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/agent\n\ngo 1.24\n", encoding="utf-8")
    cmd = tmp_path / "cmd" / "agent"
    cmd.mkdir(parents=True)
    (cmd / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    external = tmp_path / "examples" / "computer-use"
    external.mkdir(parents=True)
    (external / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    simple = tmp_path / "examples" / "simple"
    simple.mkdir(parents=True)
    (simple / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    names = [item["name"] for item in profile.adapter_matches[:6]]
    assert any(name.startswith("go-plan:cmd/agent") for name in names[:2])
    assert all("computer-use" not in name for name in names[:4])


def test_java_picocli_generates_exec_args_plan(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><artifactId>picocli</artifactId></dependency></dependencies></project>", encoding="utf-8")
    src = tmp_path / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "Main.java").write_text('class Main { String cmd = "chat <prompt>"; }\n', encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert any('exec.args="chat $SANDBOX_CLI_INPUT"' in item["start"] for item in profile.adapter_matches)


def test_java_helidon_http_agent_generates_http_plan_before_cli(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>helidon-webserver</artifactId></dependency></dependencies>"
        "<properties><mainClass>dev.example.ApplicationMain</mainClass></properties></project>",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "main" / "java" / "dev" / "example"
    src.mkdir(parents=True)
    (src / "ApplicationMain.java").write_text(
        "package dev.example;\npublic class ApplicationMain { public static void main(String[] args) {} }\n",
        encoding="utf-8",
    )
    (src / "ChatBotService.java").write_text(
        "package dev.example;\nclass ChatBotService { void routing(Object httpRules) { httpRules.get(\"/chat\", this::chat); } }\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("Use http://localhost:8080/chat?question=Hello to talk with the assistant.\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["protocol"] == "http"
    assert profile.adapter_matches[0]["framework"] == "Helidon"
    assert "target" in profile.adapter_matches[0]["start"] or "exec.mainClass" in profile.adapter_matches[0]["start"]


def test_java_spring_boot_http_prefers_packaged_jar(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies>"
        "<build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "main" / "java" / "dev" / "example"
    src.mkdir(parents=True)
    (src / "App.java").write_text(
        "package dev.example;\n"
        "@org.springframework.web.bind.annotation.RestController class App {"
        "@org.springframework.web.bind.annotation.PostMapping(\"/chat\") String chat(){return \"ok\";}"
        "public static void main(String[] args) {}}\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["protocol"] == "http"
    assert "java -jar" in profile.adapter_matches[0]["start"]
    assert any("-DskipTests package" in command for command in profile.adapter_matches[0]["install"])


def test_readme_python_usage_generates_cli_plan(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='agent'\nversion='0.1.0'\n", encoding="utf-8")
    (tmp_path / "ask.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Usage:\n\n```bash\npip install -e .\npython ask.py --question <prompt>\n```\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    docs_plan = next(item for item in profile.adapter_matches if item["name"].startswith("docs-plan:"))
    assert docs_plan["language"] == "Python"
    assert docs_plan["protocol"] == "cli"
    assert 'python ask.py --question "$SANDBOX_CLI_INPUT"' in docs_plan["start"]


def test_readme_node_usage_generates_http_plan_with_port(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"dev":"vite --host 0.0.0.0 --port 5173"}}', encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Run:\n\n```bash\nnpm install\nnpm run dev\n```\nOpen http://localhost:5173/chat?question=hello\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    docs_plan = next(item for item in profile.adapter_matches if item["name"].startswith("docs-plan:"))
    assert docs_plan["language"] == "Node.js"
    assert docs_plan["protocol"] == "http"
    assert docs_plan["port"] == 5173
    assert docs_plan["start"] == "npm run dev"


def test_java_http_prefers_packaged_jar_before_exec_plugin(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>helidon-webserver</artifactId></dependency></dependencies>"
        "<properties><mainClass>dev.example.ApplicationMain</mainClass></properties></project>",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "main" / "java" / "dev" / "example"
    src.mkdir(parents=True)
    (src / "ApplicationMain.java").write_text(
        "package dev.example;\npublic class ApplicationMain { public static void main(String[] args) {} }\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("Use http://localhost:8080/chat?question=Hello\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    java_http = next(item for item in profile.adapter_matches if item["name"] == "java-maven-http:1")
    assert "java -jar" in java_http["start"]
    assert any("package" in command for command in java_http["install"])


def test_java_gradle_http_prefers_packaged_jar(tmp_path: Path) -> None:
    (tmp_path / "build.gradle.kts").write_text(
        "plugins { id(\"org.springframework.boot\") version \"3.4.0\"; java }\n"
        "dependencies { implementation(\"org.springframework.boot:spring-boot-starter-web\") }\n",
        encoding="utf-8",
    )
    src = tmp_path / "src" / "main" / "java" / "dev" / "example"
    src.mkdir(parents=True)
    (src / "App.java").write_text(
        "package dev.example;\n"
        "@org.springframework.web.bind.annotation.RestController class App {"
        "@org.springframework.web.bind.annotation.GetMapping(\"/chat\") String chat(){return \"ok\";}"
        "public static void main(String[] args) {}}\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    java_http = next(item for item in profile.adapter_matches if item["name"] == "java-gradle-http:1")
    assert java_http["protocol"] == "http"
    assert "build/libs" in java_http["start"]
    assert any("build -x test" in command for command in java_http["install"])


def test_agents_md_usage_generates_java_docs_plan(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project />\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text(
        "Run the assistant:\n\n```bash\nmvn -q -DskipTests package\njava -jar target/demo.jar <prompt>\n```\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    docs_plan = next(item for item in profile.adapter_matches if item["name"].startswith("docs-plan:"))
    assert docs_plan["language"] == "Java"
    assert docs_plan["protocol"] == "cli"
    assert 'java -jar target/demo.jar "$SANDBOX_CLI_INPUT"' in docs_plan["start"]


def test_docs_python_command_overrides_root_node_manifest(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"build":"tsc"}}', encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Install and run:\n\n```bash\npip install mcp-server-git\npython -m mcp_server_git\n```\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    docs_plan = next(item for item in profile.adapter_matches if item["name"].startswith("docs-plan:"))
    assert docs_plan["language"] == "Python"
    assert docs_plan["protocol"] == "cli"
    assert docs_plan["image"].startswith("aegisagent-python")
    assert "pip install mcp-server-git" in docs_plan["install"]
    assert all("npm" not in command for command in docs_plan["install"])


def test_java_aggregator_root_does_not_hide_runnable_docs_subproject(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><packaging>pom</packaging><modules><module>demo</module></modules></project>",
        encoding="utf-8",
    )
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "pom.xml").write_text("<project />", encoding="utf-8")
    (demo / "README.md").write_text(
        "Run the assistant:\n\n```bash\nmvn clean package\njava -jar target/demo-assistant.jar\n```\n",
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert all(not item["name"].startswith("java-maven-http") for item in profile.adapter_matches[:3])
    docs_plan = profile.adapter_matches[0]
    assert docs_plan["name"].startswith("docs-plan:demo")
    assert docs_plan["language"] == "Java"
    assert "java -jar target/demo-assistant.jar" in docs_plan["start"]


def test_maven_wrapper_doc_command_is_java_not_shell(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project />", encoding="utf-8")
    (tmp_path / "README.md").write_text("```bash\n./mvnw liberty:dev\n```\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    docs_plan = next(item for item in profile.adapter_matches if item["name"].startswith("docs-plan:"))
    assert docs_plan["language"] == "Java"


def test_docs_prefer_lightweight_se_java_example_over_mp(tmp_path: Path) -> None:
    mp = tmp_path / "coffee-shop-assistant-mp"
    se = tmp_path / "coffee-shop-assistant-se"
    mp.mkdir()
    se.mkdir()
    (tmp_path / "pom.xml").write_text(
        "<project><packaging>pom</packaging><modules><module>coffee-shop-assistant-mp</module><module>coffee-shop-assistant-se</module></modules></project>",
        encoding="utf-8",
    )
    for project in (mp, se):
        (project / "pom.xml").write_text("<project />", encoding="utf-8")
        (project / "README.md").write_text(
            f"```bash\nmvn clean package\njava -jar target/{project.name}.jar\n```\n",
            encoding="utf-8",
        )

    profile, _, _ = scan_project(tmp_path)

    assert profile.adapter_matches[0]["name"].startswith("docs-plan:coffee-shop-assistant-se")
