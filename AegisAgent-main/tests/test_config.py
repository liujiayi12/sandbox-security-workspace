from __future__ import annotations

from fastapi import HTTPException

from agent_sandbox.main import _load_build_mode, _load_cache_policy, _load_providers, _load_runtime_env, _load_runtime_network


def test_request_providers_take_precedence_over_env(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOX_LLM_API_KEY", "env-key")
    monkeypatch.setenv("SANDBOX_LLM_MODEL", "env-model")
    raw = '[{"provider":"deepseek","base_url":"https://api.deepseek.com/v1","api_key":"request-key","model":"deepseek-chat","role":"audit"}]'

    providers = _load_providers(raw)

    assert len(providers) == 1
    assert providers[0].provider == "deepseek"
    assert providers[0].api_key.get_secret_value() == "request-key"


def test_env_provider_is_loaded_when_request_missing(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOX_LLM_API_KEY", "env-key")
    monkeypatch.setenv("SANDBOX_LLM_MODEL", "env-model")
    monkeypatch.setenv("SANDBOX_LLM_PROVIDER", "deepseek")

    providers = _load_providers(None)

    assert len(providers) == 1
    assert providers[0].provider == "deepseek"
    assert providers[0].model == "env-model"


def test_runtime_network_policy_defaults_to_sandbox(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_RUNTIME_NETWORK", raising=False)

    assert _load_runtime_network(None, {}) == "sandbox"
    assert _load_runtime_network("sandbox") == "sandbox"
    assert _load_runtime_network("bridge") == "bridge"


def test_runtime_network_auto_enables_bridge_for_runtime_provider_config(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_RUNTIME_NETWORK", raising=False)

    assert _load_runtime_network(None, {"OPENAI_API_KEY": "runtime-key", "OPENAI_BASE_URL": "https://example.test/v1"}) == "bridge"
    assert _load_runtime_network(None, {"OPENAI_API_ENDPOINT": "https://example.test/v1"}) == "bridge"
    assert _load_runtime_network("none", {"OPENAI_API_KEY": "runtime-key"}) == "none"


def test_runtime_env_loads_endpoint_and_model_aliases(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOX_RUNTIME_OPENAI_API_ENDPOINT", "https://example.test/v1")
    monkeypatch.setenv("SANDBOX_RUNTIME_OPENAI_API_MODEL", "provider/model")

    env = _load_runtime_env(None)

    assert env["OPENAI_API_ENDPOINT"] == "https://example.test/v1"
    assert env["OPENAI_API_MODEL"] == "provider/model"


def test_runtime_network_policy_rejects_unknown() -> None:
    try:
        _load_runtime_network("host")
    except HTTPException as exc:
        assert exc.status_code == 400
    else:
        raise AssertionError("expected HTTPException")


def test_build_option_validation() -> None:
    assert _load_build_mode(None) == "auto"
    assert _load_build_mode("sandbox_yaml_only") == "sandbox_yaml_only"
    assert _load_cache_policy(None) == "use"
    assert _load_cache_policy("rebuild") == "rebuild"
