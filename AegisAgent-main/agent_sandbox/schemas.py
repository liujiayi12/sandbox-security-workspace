from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, SecretStr


class LLMProvider(BaseModel):
    provider: str = Field(..., min_length=1)
    base_url: str | None = None
    api_key: SecretStr
    model: str = Field(..., min_length=1)
    role: str = "audit"


class RunSummary(BaseModel):
    id: str
    status: str
    stage: str
    input_name: str
    created_at: str
    updated_at: str
    dynamic_status: str | None = None
    llm_status: str | None = None
    risk_level: str | None = None


class Event(BaseModel):
    ts: str
    stage: str
    level: Literal["debug", "info", "warning", "error"]
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    category: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: str = "rule"
    votes: list[dict[str, Any]] = Field(default_factory=list)
    risk_type: Literal["capability", "reachable_surface", "observed_behavior"] = "capability"
    attack_surface: list[str] = Field(default_factory=list)
    needs_dynamic_validation: bool = False
    recommended_dynamic_tests: list[str] = Field(default_factory=list)


class ProjectProfile(BaseModel):
    root_name: str
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    protocol_candidates: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    run_candidates: list[dict[str, Any]] = Field(default_factory=list)
    adapter_matches: list[dict[str, Any]] = Field(default_factory=list)
    selected_adapter: dict[str, Any] | None = None
    sandbox_yaml: dict[str, Any] | None = None
    confidence: float = 0.0


class AttackStep(BaseModel):
    type: str
    input: str | None = None
    path: str | None = None
    url: str | None = None
    method: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    observe: list[str] = Field(default_factory=list)


class AttackPlan(BaseModel):
    source: str
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    steps: list[AttackStep] = Field(default_factory=list)


class Report(BaseModel):
    run_id: str
    status: str
    dynamic_status: str
    llm_status: str
    risk_level: str
    recommendation: str
    profile: ProjectProfile | None = None
    findings: list[Finding] = Field(default_factory=list)
    attack_plan: AttackPlan | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    failures: list[dict[str, Any]] = Field(default_factory=list)
    build_status: str | None = None
    build_plan: dict[str, Any] | None = None
    build_result: dict[str, Any] | None = None
    cache_hit: bool | None = None
    cache_key: str | None = None
    failure_class: str | None = None
    suggested_fix: str | None = None
    requires_runtime_api_key: bool = False
    markdown_report: str = ""
