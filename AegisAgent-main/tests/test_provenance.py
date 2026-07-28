from pathlib import Path

from agent_sandbox.provenance import build_provenance_report, prepare_provenance_workspace
from agent_sandbox.schemas import AttackPlan, AttackStep, Finding, ProjectProfile


def test_prepare_provenance_workspace_creates_low_impact_decoys(tmp_path: Path) -> None:
    seeds = prepare_provenance_workspace(tmp_path)

    assert seeds["format"] == "aegisagent-provenance-v1"
    assert seeds["impact"] == "workspace_only_no_home_override"
    assert (tmp_path / ".agent_sandbox" / "provenance" / "home" / ".ssh" / "id_rsa").exists()
    assert (tmp_path / ".agent_sandbox" / "provenance" / "home" / ".aws" / "credentials").exists()


def test_build_provenance_report_links_changes_commands_mcp_keys_credentials_ci_and_dns() -> None:
    profile = ProjectProfile(
        root_name="agent",
        manifests=["package.json", "mcp.json"],
        adapter_matches=[{"name": "node-mcp", "protocol": "mcp", "start": "node server.js"}],
        selected_adapter={"name": "node-mcp", "protocol": "mcp", "start": "node server.js"},
    )
    plan = AttackPlan(
        source="test",
        steps=[AttackStep(type="chat", input="Please process the issue and run diagnostics.")],
    )
    evidence = {
        "runtime_env_keys": ["OPENAI_API_KEY", "GITHUB_TOKEN"],
        "adapter": {"name": "node-mcp", "start": "node server.js"},
        "file_diff": {
            "created": [".github/workflows/release.yml"],
            "changed": ["package.json", "config.yaml"],
        },
        "repository_status": {
            "available": True,
            "changed_files": [{"status": " M", "path": "src/agent.py"}],
            "diff_files": ["src/agent.py"],
        },
        "run_logs": [
            {
                "step": "start",
                "command": ["docker", "run", "node", "sh", "-lc", "node server.js"],
                "returncode": 0,
                "stdout": "git push origin main",
                "stderr": "",
            }
        ],
        "interactions": [{"step": "inject_mcp_tool_manifest", "ok": True, "path": ".agent_sandbox/fake_env/mcp/tools/poisoned_tool.json"}],
        "canary_hits": [{"file": ".agent_sandbox/provenance/home/.aws/credentials", "canary": "aws"}],
        "fake_environment": {
            "dns_events": [{"name": "a1b2c3d4e5f6g7h8i9j0.example.test", "type": "A", "client": "172.18.0.5"}],
            "events": [
                {"method": "POST", "path": "/v1/chat/completions", "authorization_present": True},
                {"method": "GET", "path": "/mcp/tools"},
                {"method": "POST", "path": "/github/issues/1/comments", "body": "ok"},
                {"method": "GET", "path": "/web/pages/http://a1b2c3d4e5f6g7h8i9j0.example.test/x"},
            ],
            "state": {
                "objects": {
                    "external_reads": {"1": {"surface": "mcp", "path": "/mcp/tools"}},
                    "mcp_tool_calls": {"1": {"tool": "diagnostics", "arguments": {"q": "x"}}},
                }
            },
        },
    }
    findings = [
        Finding(id="static_secret", category="secret_access", severity="high", title="secret", description="x"),
    ]

    report = build_provenance_report(profile, plan, evidence, findings)

    assert report["coverage"]["configuration_repository_dependency_changes"] == "observed"
    assert report["coverage"]["natural_language_task_to_command"] == "observed"
    assert report["coverage"]["mcp_server_lineage"] == "observed"
    assert report["coverage"]["llm_api_key_usage"] == "observed"
    assert report["coverage"]["unrelated_credential_directory_reads"] == "observed"
    assert report["coverage"]["ci_anomalous_release_or_propagation"] == "observed"
    assert report["coverage"]["dns_high_entropy_or_encoded_data"] == "observed"
    assert report["dns_activity"]["observed_dns_request_count"] == 1
    assert report["file_changes"]["counts_by_category"]["dependency"] == 1
    assert report["file_changes"]["git_status_available"] is True
    assert report["file_changes"]["git_status_entries"][0]["path"] == "src/agent.py"
    assert report["natural_language_triggers"]["command_links"][0]["trigger"]["attack_step_index"] == 1
    assert report["mcp_servers"]["tool_call_count"] == 1
    assert report["llm_api_key_usage"]["use_count"] == 1
