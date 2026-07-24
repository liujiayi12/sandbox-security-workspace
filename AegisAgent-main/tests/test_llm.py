from __future__ import annotations

import json
import asyncio

from agent_sandbox.llm import _audit_payloads, _dynamic_test_objectives, audit_with_llms
from agent_sandbox.schemas import Finding, LLMProvider


def test_llm_audit_payloads_include_independent_source_and_scan_review() -> None:
    evidence = {
        "profile": {"languages": ["Python"], "frameworks": ["FastAPI"], "entrypoints": ["app.py"]},
        "findings": [{"category": "secret_access", "severity": "high", "title": "reads key"}],
        "interesting_files": [{"path": "README.md", "content": "Run app"}],
        "source_files": [{"path": "app.py", "content": "import os\nos.getenv('OPENAI_API_KEY')"}],
    }

    payloads = dict(_audit_payloads(evidence))

    independent = json.loads(payloads["independent_source_audit"])
    review = json.loads(payloads["sandbox_scan_review"])
    assert independent["source_files"][0]["path"] == "app.py"
    assert "sandbox_findings" not in independent
    assert review["sandbox_findings"][0]["category"] == "secret_access"
    assert review["source_file_index"][0]["path"] == "app.py"


def test_llm_audit_respects_provider_role() -> None:
    providers = [
        LLMProvider(provider="openai-compatible", base_url="https://example.invalid/v1", api_key="test", model="model", role="build"),
        LLMProvider(provider="openai-compatible", base_url="https://example.invalid/v1", api_key="test", model="model", role="attack"),
    ]

    findings, audits = asyncio.run(audit_with_llms({"profile": {}}, providers))

    assert findings == []
    assert audits == []


def test_dynamic_objectives_target_agent_capability_risks() -> None:
    findings = [
        Finding(
            id="f1",
            category="skill_plugin_injection",
            severity="high",
            title="Skill loads tools",
            description="The agent reads SKILL.md and scheduled cron memory.",
            evidence=[],
        )
    ]

    objectives = _dynamic_test_objectives(findings)
    by_id = {item["id"]: item for item in objectives}

    assert "skill_plugin_injection" in by_id
    assert "inject_skill" in by_id["skill_plugin_injection"]["recommended_steps"]
    assert "scheduler_delayed_action" in by_id
    assert "inject_scheduler" in by_id["scheduler_delayed_action"]["recommended_steps"]


def test_dynamic_objectives_cover_collaboration_and_shared_document_surfaces() -> None:
    findings = [
        Finding(
            id="f1",
            category="external_input",
            severity="medium",
            title="Reads collaboration inputs",
            description="The agent reads Slack, calendar, GitHub pull request, and shared drive documents.",
            evidence=[],
        )
    ]

    objectives = _dynamic_test_objectives(findings)
    steps = {step for item in objectives for step in item["recommended_steps"]}

    assert {"start_scenario", "inject_github_pull_request", "inject_slack_message", "inject_calendar_event", "inject_drive_document"}.issubset(steps)
