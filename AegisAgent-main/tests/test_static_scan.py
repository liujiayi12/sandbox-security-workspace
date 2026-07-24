from __future__ import annotations

from pathlib import Path

from agent_sandbox.static_scan import scan_project


def test_static_scan_detects_python_secret_and_shell(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("openai\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "import os, subprocess\nprint(os.getenv('OPENAI_API_KEY'))\nsubprocess.run(['echo','x'])\n",
        encoding="utf-8",
    )

    profile, findings, bundle = scan_project(tmp_path)

    assert "Python" in profile.languages
    assert "main.py" in profile.entrypoints
    categories = {finding.category for finding in findings}
    assert "secret_access" in categories
    assert "shell_execution" in categories
    secret = next(finding for finding in findings if finding.category == "secret_access")
    assert secret.risk_type == "capability"
    assert secret.needs_dynamic_validation is True
    assert "assert_sink_clean" in secret.recommended_dynamic_tests
    assert bundle["profile"]["languages"]
    source = {item["path"]: item["content"] for item in bundle["source_files"]}
    assert "main.py" in source
    assert "OPENAI_API_KEY" in source["main.py"]


def test_static_scan_redacts_source_files_for_llm(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("API_KEY='sk-real-looking-secret-token'\n", encoding="utf-8")

    _, _, bundle = scan_project(tmp_path)

    content = "\n".join(item["content"] for item in bundle["source_files"])
    assert "sk-real-looking-secret-token" not in content
    assert "[redacted" in content


def test_sandbox_yaml_creates_high_confidence_candidate(tmp_path: Path) -> None:
    (tmp_path / "sandbox.yaml").write_text(
        "protocol: cli\nstart: python custom.py\ninstall: []\n",
        encoding="utf-8",
    )
    (tmp_path / "custom.py").write_text("print('ok')", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert profile.sandbox_yaml is not None
    assert profile.run_candidates[0]["kind"] == "sandbox_yaml"
    assert profile.run_candidates[0]["start"] == "python custom.py"
    assert len(profile.adapter_matches) == 1


def test_static_scan_detects_crewai_and_adapter(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=['crewai']\n", encoding="utf-8")
    (tmp_path / "crew.py").write_text("print('crew')", encoding="utf-8")
    (tmp_path / "agents.yaml").write_text("researcher: {}\n", encoding="utf-8")
    (tmp_path / "tasks.yaml").write_text("task: {}\n", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert "CrewAI" in profile.frameworks
    assert profile.selected_adapter is not None
    assert profile.selected_adapter["name"] == "python-crewai"


def test_static_scan_detects_mcp_node_adapter(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"@modelcontextprotocol/sdk":"latest"},"scripts":{"start":"node index.js"}}',
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text("console.log('mcp')", encoding="utf-8")

    profile, _, _ = scan_project(tmp_path)

    assert "MCP" in profile.frameworks
    assert profile.selected_adapter is not None
    assert profile.selected_adapter["protocol"] == "mcp"


def test_static_scan_skips_node_mcp_placeholder_without_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"@modelcontextprotocol/sdk":"latest"},"scripts":{"build":"tsc"}}',
        encoding="utf-8",
    )

    profile, _, _ = scan_project(tmp_path)

    assert all(item["name"] != "node-mcp-stdio" for item in profile.adapter_matches)


def test_static_scan_detects_external_input_and_tool_poisoning_surfaces(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("Use browser email GitHub issues and SKILL.md tool descriptions.\n", encoding="utf-8")

    _, findings, _ = scan_project(tmp_path)
    categories = {finding.category for finding in findings}

    assert "external_input" in categories
    assert "tool_poisoning_surface" in categories
    external = next(finding for finding in findings if finding.category == "external_input")
    assert "assert_external_input_control" in external.recommended_dynamic_tests
