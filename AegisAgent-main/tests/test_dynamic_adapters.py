from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

import agent_sandbox.sandbox as sandbox_module
from agent_sandbox.attack import default_attack_plan
from agent_sandbox.deployment import BuildResult
from agent_sandbox.image_reserve import PYTHON_312
from agent_sandbox.sandbox import _application_failure, _http_probe_urls, docker_available, run_dynamic_sandbox
from agent_sandbox.static_scan import scan_project


pytestmark = pytest.mark.skipif(not docker_available()[0], reason="Docker daemon unavailable")


def test_python_cli_dynamic_adapter_runs(tmp_path: Path) -> None:
    root = tmp_path / "agent"
    root.mkdir()
    (root / "main.py").write_text("print('hello cli')", encoding="utf-8")
    profile, findings, _ = scan_project(root)

    result = run_dynamic_sandbox(root, tmp_path, profile, default_attack_plan(findings))

    assert result.status == "dynamic_completed"
    assert result.adapter is not None
    assert result.adapter["protocol"] == "cli"


def test_fastapi_http_dynamic_adapter_probes(tmp_path: Path) -> None:
    root = tmp_path / "http_agent"
    root.mkdir()
    (root / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from fastapi import FastAPI\napp=FastAPI()\n@app.get('/')\ndef home(): return {'ok': True}\n",
        encoding="utf-8",
    )
    profile, findings, _ = scan_project(root)

    result = run_dynamic_sandbox(root, tmp_path, profile, default_attack_plan(findings))

    assert result.status == "dynamic_completed"
    assert result.adapter is not None
    assert result.adapter["protocol"] == "http"
    assert any(item.get("step") == "http_probe" and item.get("ok") for item in result.interactions)


def test_node_mcp_dynamic_adapter_lists_tools(tmp_path: Path) -> None:
    root = tmp_path / "mcp_agent"
    root.mkdir()
    (root / "package.json").write_text(
        '{"dependencies":{"@modelcontextprotocol/sdk":"latest"},"scripts":{"start":"node index.js"}}',
        encoding="utf-8",
    )
    (root / "index.js").write_text(
        """
process.stdin.setEncoding('utf8');
let buf = require('fs').readFileSync(0, 'utf8');
function handle(msg) {
  if (msg.method === 'initialize') {
    console.log(JSON.stringify({jsonrpc:'2.0', id:msg.id, result:{protocolVersion:'2024-11-05', capabilities:{tools:{}}, serverInfo:{name:'sample', version:'1'}}}));
  }
  if (msg.method === 'tools/list') {
    console.log(JSON.stringify({jsonrpc:'2.0', id:msg.id, result:{tools:[{name:'echo', description:'Echo input'}]}}));
  }
}
while (true) {
  const match = buf.match(/^Content-Length: (\\d+)\\r?\\n\\r?\\n/);
  if (!match) {
    for (const line of buf.split('\\n')) {
      if (line.trim()) handle(JSON.parse(line));
    }
    break;
  }
  const headerLen = match[0].length;
  const len = Number(match[1]);
  if (buf.length < headerLen + len) break;
  handle(JSON.parse(buf.slice(headerLen, headerLen + len)));
  buf = buf.slice(headerLen + len);
}
""",
        encoding="utf-8",
    )
    profile, findings, _ = scan_project(root)
    profile.selected_adapter = profile.adapter_matches[0]
    profile.selected_adapter["install"] = []
    profile.adapter_matches[0]["install"] = []

    result = run_dynamic_sandbox(root, tmp_path, profile, default_attack_plan(findings))

    assert result.status == "dynamic_completed"
    assert result.adapter is not None
    assert result.adapter["protocol"] == "mcp"
    assert any(item.get("step") == "mcp_list_tools" and item.get("ok") for item in result.interactions)


def test_runtime_env_is_only_injected_at_runtime(tmp_path: Path) -> None:
    root = tmp_path / "secret_agent"
    root.mkdir()
    (root / "sandbox.yaml").write_text(
        f"""
language: Python
protocol: cli
image: {PYTHON_312}
install:
  - python -c "import os; print('INSTALL_SECRET=' + os.getenv('TEST_RUNTIME_SECRET', 'missing'))"
start: python -c "import os; print('RUNTIME_SECRET=' + os.getenv('TEST_RUNTIME_SECRET', 'missing'))"
""",
        encoding="utf-8",
    )
    profile, findings, _ = scan_project(root)

    result = run_dynamic_sandbox(root, tmp_path, profile, default_attack_plan(findings), {"TEST_RUNTIME_SECRET": "super-secret-value"}, cache_policy="rebuild")

    assert result.status == "dynamic_completed"
    assert "INSTALL_SECRET=missing" in (result.install_logs[0]["stdout"] + result.install_logs[0]["stderr"])
    assert "super-secret-value" not in str(result.install_logs + result.run_logs + result.interactions)
    assert "[runtime-secret-redacted]" in result.run_logs[0]["stdout"]


def test_dynamic_runner_tries_next_candidate_after_build_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "agent"
    root.mkdir()
    (root / "requirements.txt").write_text("", encoding="utf-8")
    (root / "main.py").write_text("print('second candidate ran')\n", encoding="utf-8")
    profile, findings, _ = scan_project(root)
    bad = {
        **profile.adapter_matches[0],
        "name": "bad-candidate",
        "kind": "plan_python",
        "install": ["python -c \"raise SystemExit(7)\""],
        "confidence": 0.99,
    }
    profile.adapter_matches = [bad, *profile.adapter_matches]

    build_calls = []

    def fake_build_environment(_root: Path, build_plan, _build_options):
        build_calls.append(build_plan)
        if len(build_calls) == 1:
            return BuildResult(
                status="failed",
                logs=[{"step": "docker_build", "returncode": 7}],
                failure_stage="docker_build",
                failure_class="build_script_failed",
                human_reason="simulated first candidate failure",
            )
        return BuildResult(status="built", image="agent-sandbox-build:test", logs=[{"step": "docker_build", "returncode": 0}])

    monkeypatch.setattr(sandbox_module, "docker_available", lambda: (True, None))
    monkeypatch.setattr(sandbox_module, "build_environment", fake_build_environment)
    monkeypatch.setattr(
        sandbox_module,
        "_run_once",
        lambda *_args, **_kwargs: {"step": "start", "returncode": 0, "stdout": "second candidate ran\n", "stderr": ""},
    )

    result = run_dynamic_sandbox(root, tmp_path / "workspace", profile, default_attack_plan(findings), cache_policy="rebuild")

    assert result.status == "dynamic_completed"
    assert len(build_calls) >= 2
    assert any(failure.get("adapter") == "bad-candidate" for failure in result.failures)
    assert result.adapter is not None
    assert result.adapter["name"] != "bad-candidate"


def test_go_cmd_cli_dynamic_adapter_receives_attack_input(tmp_path: Path) -> None:
    if subprocess.run(["docker", "image", "inspect", "aegisagent-go:1.24-bookworm", "golang:1.24-bookworm"], capture_output=True, text=True, timeout=30).returncode != 0:
        pytest.skip("no Go build image is available locally; skipping network-dependent Go image pull")
    root = tmp_path / "go_agent"
    cmd = root / "cmd" / "agent"
    cmd.mkdir(parents=True)
    (root / "go.mod").write_text("module example.com/goagent\n\ngo 1.23\n", encoding="utf-8")
    (cmd / "main.go").write_text(
        """
package main

import (
  "fmt"
  "os"
)

func main() {
  if len(os.Args) > 1 {
    fmt.Println("ARG_INPUT=" + os.Args[1])
    return
  }
  fmt.Println("HELP_OK")
}
""",
        encoding="utf-8",
    )
    profile, findings, _ = scan_project(root)

    result = run_dynamic_sandbox(root, tmp_path / "go_workspace", profile, default_attack_plan(findings), cache_policy="rebuild")

    assert result.status == "dynamic_completed"
    assert result.adapter is not None
    assert result.adapter["name"] == "go-plan:cmd/agent"
    logs = "\n".join(log.get("stdout", "") for log in result.run_logs)
    assert any(log.get("skipped") for log in result.run_logs)
    assert "ARG_INPUT=" in logs


def test_sandbox_network_exposes_fake_services_and_blocks_public_network(tmp_path: Path) -> None:
    root = tmp_path / "fake_env_agent"
    root.mkdir()
    (root / "sandbox.yaml").write_text(
        f"""
language: Python
protocol: cli
image: {PYTHON_312}
install: []
start: python main.py
""",
        encoding="utf-8",
    )
    (root / "main.py").write_text(
        """
import json
import os
import urllib.request

for name in (
    "AGENT_SANDBOX_FAKE_SEARCH_URL",
    "AGENT_SANDBOX_FAKE_GITHUB_API",
    "AGENT_SANDBOX_FAKE_SLACK_API",
    "AGENT_SANDBOX_FAKE_RAG_URL",
):
    with urllib.request.urlopen(os.environ[name], timeout=3) as response:
        print(name + "=" + str(response.status))
try:
    urllib.request.urlopen("https://example.com", timeout=2)
    print("PUBLIC_NETWORK=reachable")
except Exception:
    print("PUBLIC_NETWORK=blocked")
""",
        encoding="utf-8",
    )
    profile, findings, _ = scan_project(root)

    result = run_dynamic_sandbox(root, tmp_path / "fake_env_workspace", profile, default_attack_plan(findings), runtime_network="sandbox")

    logs = "\n".join(log.get("stdout", "") for log in result.run_logs)
    assert result.status == "dynamic_completed"
    assert result.fake_environment["enabled"] is True
    assert {"search", "github", "slack", "rag"}.issubset(result.fake_environment["event_counts"])
    assert "PUBLIC_NETWORK=blocked" in logs


def test_successful_security_advice_about_api_key_is_not_auth_failure() -> None:
    failure = _application_failure(
        "start",
        "node-agent",
        [{"returncode": 0, "stdout": "I will not store your API key. Connection successful.", "stderr": ""}],
    )

    assert failure is None


def test_http_probe_discovers_java_chat_endpoint(tmp_path: Path) -> None:
    root = tmp_path / "java_agent"
    root.mkdir()
    (root / "README.md").write_text("Try http://localhost:8080/chat?question=What can you offer today?\n", encoding="utf-8")
    src = root / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "ChatBotService.java").write_text(
        "class ChatBotService { void routing(Object httpRules) { httpRules.get(\"/assistant\", this::chat); } }\n",
        encoding="utf-8",
    )

    urls = _http_probe_urls(root, 8080)

    assert "http://127.0.0.1:8080/chat?question=What" in urls[0] or any("/chat?question=" in url for url in urls)
    assert any("/assistant?question=Hello" in url for url in urls)
