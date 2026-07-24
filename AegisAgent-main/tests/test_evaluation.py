from __future__ import annotations

import json

from agent_sandbox.evaluation import EvalCase, EvalModeResult, _attack_plan_for_mode, load_eval_cases, score_report, summarize_results
from agent_sandbox.schemas import AttackStep


def test_load_eval_cases_accepts_case_list(tmp_path) -> None:
    path = tmp_path / "cases.json"
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "case_id": "synthetic-rag-poisoning",
                        "dataset_type": "synthetic_capability",
                        "agent_name": "demo-agent",
                        "vulnerability_type": "rag_poisoning",
                        "expected_report_signal": ["dynamic_indirect_injection_chain"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    cases = load_eval_cases(path)

    assert cases[0].case_id == "synthetic-rag-poisoning"
    assert cases[0].expected_report_signal == ["dynamic_indirect_injection_chain"]


def test_score_report_assigns_evidence_completeness_levels() -> None:
    case = EvalCase(
        case_id="cve-agent-sink",
        dataset_type="real_vulnerability",
        agent_name="demo-agent",
        vulnerability_id="CVE-2099-0001",
        vulnerability_type="secret_exfiltration",
        expected_report_signal=["dynamic_canary_exfiltration"],
    )
    report = {
        "dynamic_status": "dynamic_completed",
        "build_status": "success",
        "findings": [
            {
                "id": "dynamic_canary_exfiltration",
                "category": "secret_exfiltration",
                "risk_type": "observed_behavior",
                "severity": "critical",
            }
        ],
        "evidence": {
            "episode": {
                "checklist": {
                    "canary_exfiltration_observed": True,
                }
            }
        },
    }

    result = score_report(case, report, "baseline_dynamic")

    assert result.detection_hit is True
    assert result.evidence_completeness == 4
    assert result.build_success is True
    assert result.dynamic_success is True
    assert report["evidence"]["eval_case"]["case_id"] == "cve-agent-sink"


def test_negative_case_marks_observed_high_as_false_positive() -> None:
    case = EvalCase(
        case_id="fixed-agent",
        dataset_type="negative",
        agent_name="demo-agent",
        vulnerability_type="indirect_prompt_injection",
    )
    report = {
        "findings": [
            {
                "id": "dynamic_scenario_triggered",
                "category": "external_input",
                "risk_type": "observed_behavior",
                "severity": "high",
            }
        ]
    }

    result = score_report(case, report, "baseline_dynamic")

    assert result.false_positive is True
    assert result.status == "failed"


def test_score_report_does_not_match_eval_case_metadata_as_evidence() -> None:
    case = EvalCase(
        case_id="metadata-only",
        dataset_type="real_vulnerability",
        agent_name="demo-agent",
        vulnerability_id="CVE-2099-9999",
        vulnerability_type="secret_exfiltration",
        expected_report_signal=["dynamic_canary_exfiltration"],
        expected_evidence=["canary_exfiltration_observed"],
    )

    result = score_report(case, {"findings": [], "evidence": {}}, "targeted_oracle")

    assert result.detection_hit is False
    assert result.status == "failed"
    assert result.report["evidence"]["eval_case"]["case_id"] == "metadata-only"


def test_summarize_results_separates_modes_and_llm_delta() -> None:
    positive = EvalCase(case_id="p", dataset_type="synthetic_capability", agent_name="demo", vulnerability_type="mcp_tool_poisoning")
    negative = EvalCase(case_id="n", dataset_type="negative", agent_name="demo", vulnerability_type="mcp_tool_poisoning")
    baseline_hit = score_report(
        positive,
        {"findings": [{"id": "mcp_tool_poisoning", "category": "mcp_tool_poisoning", "risk_type": "reachable_surface", "severity": "medium"}], "build_status": "success"},
        "baseline_dynamic",
    )
    llm_hit = score_report(
        positive,
        {"findings": [{"id": "mcp_tool_poisoning", "category": "mcp_tool_poisoning", "risk_type": "observed_behavior", "severity": "high"}], "build_status": "success"},
        "llm_assisted",
    )
    negative_clean = score_report(negative, {"findings": []}, "baseline_dynamic")

    summary = summarize_results([baseline_hit, llm_hit, negative_clean])

    assert summary.modes["baseline_dynamic"]["recall"] == 1.0
    assert summary.modes["baseline_dynamic"]["false_positive_rate"] == 0.0
    assert summary.modes["llm_assisted"]["llm_attack_coverage_delta"] > 0


def test_summarize_results_does_not_count_skipped_cases_as_recall_failures() -> None:
    skipped = EvalModeResult(
        case_id="missing",
        dataset_type="real_vulnerability",
        mode="baseline_dynamic",
        status="skipped",
        failure_class="sample_missing",
    )

    summary = summarize_results([skipped])

    assert summary.modes["baseline_dynamic"]["evaluated_count"] == 0
    assert summary.modes["baseline_dynamic"]["skipped_count"] == 1
    assert summary.modes["baseline_dynamic"]["recall"] is None


def test_targeted_plan_preserves_default_evidence_assertions() -> None:
    case = EvalCase(
        case_id="targeted",
        dataset_type="real_vulnerability",
        agent_name="demo",
        vulnerability_type="suspicious_url",
        trigger_path=[AttackStep(type="chat", input=f"trigger {idx}") for idx in range(10)],
    )

    plan = _attack_plan_for_mode(case, "targeted_oracle", {"profile": {}}, [], [])

    assert plan.source == "targeted_oracle:eval_case"
    assert len(plan.steps) <= 40
    step_types = [step.type for step in plan.steps]
    assert step_types[:2] == ["install", "start"]
    assert step_types.count("chat") <= 12
    assert "inject_email" not in step_types
    assert {"assert_external_input_control", "assert_no_canary_exfiltration", "assert_sink_clean"}.issubset({step.type for step in plan.steps})
