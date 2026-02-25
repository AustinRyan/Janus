"""Tests for configurable policies — TOML-driven thresholds."""
from __future__ import annotations

import pytest

from janus.config import JanusConfig, PolicyConfig, RiskConfig
from janus.risk import thresholds


@pytest.fixture(autouse=True)
def reset_thresholds():
    """Ensure each test starts with defaults and resets after."""
    thresholds.reset()
    yield
    thresholds.reset()


def test_defaults_match_hardcoded():
    assert thresholds.LOCK_THRESHOLD == 80.0
    assert thresholds.SANDBOX_THRESHOLD == 60.0
    assert thresholds.ELEVATED_LOGGING_THRESHOLD == 40.0
    assert thresholds.LLM_RISK_WEIGHT == 0.3
    assert thresholds.VELOCITY_THRESHOLD_CALLS == 12
    assert thresholds.VELOCITY_WINDOW_SECONDS == 60.0
    assert thresholds.KEYWORD_AMPLIFIER_CAP == 60.0
    assert "rm -rf" in thresholds.KEYWORD_AMPLIFIERS
    assert "execute_code" in thresholds.KEYWORD_SENSITIVE_TOOLS


def test_risk_config_overrides():
    risk = RiskConfig(lock_threshold=90.0, sandbox_threshold=70.0)
    thresholds.configure(risk=risk)
    assert thresholds.LOCK_THRESHOLD == 90.0
    assert thresholds.SANDBOX_THRESHOLD == 70.0


def test_policy_llm_weight_override():
    policy = PolicyConfig(llm_risk_weight=0.5)
    thresholds.configure(policy=policy)
    assert thresholds.LLM_RISK_WEIGHT == 0.5


def test_policy_velocity_overrides():
    policy = PolicyConfig(
        velocity_threshold_calls=20,
        velocity_penalty_per_call=5.0,
        velocity_penalty_cap=30.0,
    )
    thresholds.configure(policy=policy)
    assert thresholds.VELOCITY_THRESHOLD_CALLS == 20
    assert thresholds.VELOCITY_PENALTY_PER_CALL == 5.0
    assert thresholds.VELOCITY_PENALTY_CAP == 30.0


def test_custom_keyword_amplifiers_merge():
    policy = PolicyConfig(keyword_amplifiers={"custom_danger": 35.0})
    thresholds.configure(policy=policy)
    # Built-in still present
    assert "rm -rf" in thresholds.KEYWORD_AMPLIFIERS
    # Custom added
    assert thresholds.KEYWORD_AMPLIFIERS["custom_danger"] == 35.0


def test_custom_keyword_amplifiers_override_builtin():
    policy = PolicyConfig(keyword_amplifiers={"rm -rf": 50.0})
    thresholds.configure(policy=policy)
    assert thresholds.KEYWORD_AMPLIFIERS["rm -rf"] == 50.0


def test_custom_keyword_sensitive_tools():
    policy = PolicyConfig(keyword_sensitive_tools=["my_custom_tool", "another_tool"])
    thresholds.configure(policy=policy)
    assert thresholds.KEYWORD_SENSITIVE_TOOLS == frozenset({"my_custom_tool", "another_tool"})


def test_reset_restores_defaults():
    policy = PolicyConfig(llm_risk_weight=0.99, velocity_threshold_calls=100)
    thresholds.configure(policy=policy)
    assert thresholds.LLM_RISK_WEIGHT == 0.99

    thresholds.reset()
    assert thresholds.LLM_RISK_WEIGHT == 0.3
    assert thresholds.VELOCITY_THRESHOLD_CALLS == 12


def test_partial_config_leaves_unset_at_defaults():
    policy = PolicyConfig(llm_risk_weight=0.5)
    thresholds.configure(policy=policy)
    assert thresholds.LLM_RISK_WEIGHT == 0.5
    # Everything else unchanged
    assert thresholds.VELOCITY_THRESHOLD_CALLS == 12
    assert thresholds.KEYWORD_AMPLIFIER_CAP == 60.0
    assert thresholds.LOCK_THRESHOLD == 80.0


def test_from_toml_with_policy(tmp_path):
    toml_path = tmp_path / "janus.toml"
    toml_path.write_text("""\
[risk]
lock_threshold = 70.0
sandbox_threshold = 50.0

[policy]
llm_risk_weight = 0.4

[policy.keyword_amplifiers]
"custom_danger" = 35.0
""")
    config = JanusConfig.from_toml(toml_path)
    assert config.risk.lock_threshold == 70.0
    assert config.policy.llm_risk_weight == 0.4
    assert config.policy.keyword_amplifiers == {"custom_danger": 35.0}

    thresholds.configure(config.risk, config.policy)
    assert thresholds.LOCK_THRESHOLD == 70.0
    assert thresholds.LLM_RISK_WEIGHT == 0.4
    assert thresholds.KEYWORD_AMPLIFIERS["custom_danger"] == 35.0


def test_escalation_overrides():
    policy = PolicyConfig(
        escalation_penalty_per_attempt=10.0,
        escalation_penalty_cap=50.0,
    )
    thresholds.configure(policy=policy)
    assert thresholds.ESCALATION_PENALTY_PER_ATTEMPT == 10.0
    assert thresholds.ESCALATION_PENALTY_CAP == 50.0


def test_keyword_amplifier_cap_override():
    policy = PolicyConfig(keyword_amplifier_cap=80.0)
    thresholds.configure(policy=policy)
    assert thresholds.KEYWORD_AMPLIFIER_CAP == 80.0


def test_configure_with_both_risk_and_policy():
    risk = RiskConfig(lock_threshold=95.0)
    policy = PolicyConfig(llm_risk_weight=0.1)
    thresholds.configure(risk=risk, policy=policy)
    assert thresholds.LOCK_THRESHOLD == 95.0
    assert thresholds.LLM_RISK_WEIGHT == 0.1


def test_default_policy_config_is_empty():
    config = JanusConfig()
    assert config.policy.keyword_amplifiers == {}
    assert config.policy.keyword_sensitive_tools == []
    assert config.policy.llm_risk_weight is None
