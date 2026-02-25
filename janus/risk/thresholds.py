from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from janus.config import PolicyConfig, RiskConfig

# ── Hardcoded defaults ──────────────────────────────────────────────
_DEFAULT_LOCK_THRESHOLD = 80.0
_DEFAULT_SANDBOX_THRESHOLD = 60.0
_DEFAULT_ELEVATED_LOGGING_THRESHOLD = 40.0
_DEFAULT_MAX_RISK_SCORE = 100.0
_DEFAULT_MIN_RISK_SCORE = 0.0

_DEFAULT_TOOL_BASE_RISK: dict[str, float] = {
    "read_file": 0.0,
    "search_web": 0.0,
    "list_files": 0.0,
    "send_message": 0.0,
    "write_file": 0.0,
    "api_call": 0.0,
    "database_query": 0.0,
    "execute_code": 0.0,
    "send_email": 0.0,
    "delete_file": 0.0,
    "database_write": 0.0,
    "financial_transfer": 0.0,
    "modify_permissions": 0.0,
}

_DEFAULT_KEYWORD_AMPLIFIERS: dict[str, float] = {
    "rm -rf": 30.0,
    "chmod 777": 25.0,
    "drop table": 30.0,
    "truncate table": 20.0,
    "os.system": 25.0,
    "subprocess.call": 20.0,
    "subprocess.run": 20.0,
    "subprocess.popen": 20.0,
    "eval(": 25.0,
    "exec(": 25.0,
    "reverse_shell": 35.0,
    "netcat -e": 25.0,
    "nc -e": 25.0,
    "/etc/shadow": 35.0,
    "/etc/passwd": 25.0,
    "exfil": 35.0,
    "password123": 30.0,
    "secret123": 25.0,
    "admin123": 25.0,
    "/auth/login": 20.0,
    "delete_all": 30.0,
    "destroy_all": 30.0,
    "purge_all": 25.0,
    "wipe": 30.0,
}

_DEFAULT_KEYWORD_AMPLIFIER_CAP = 60.0
_DEFAULT_KEYWORD_SENSITIVE_TOOLS = frozenset({
    "execute_code",
    "database_write",
    "database_query",
    "send_email",
    "write_file",
    "api_call",
    "financial_transfer",
    "modify_permissions",
    "delete_file",
})
_DEFAULT_TOOL_BASE_RISK_VALUE = 0.0
_DEFAULT_LLM_RISK_WEIGHT = 0.3

_DEFAULT_VELOCITY_THRESHOLD_CALLS = 12
_DEFAULT_VELOCITY_WINDOW_SECONDS = 60.0
_DEFAULT_VELOCITY_PENALTY_PER_CALL = 2.0
_DEFAULT_VELOCITY_PENALTY_CAP = 15.0

_DEFAULT_ESCALATION_WINDOW_MINUTES = 30
_DEFAULT_ESCALATION_PENALTY_PER_ATTEMPT = 7.0
_DEFAULT_ESCALATION_PENALTY_CAP = 20.0

_DEFAULT_DECAY_RATE_PER_MINUTE = 2.0
_DEFAULT_DECAY_IDLE_THRESHOLD_MINUTES = 5.0


class _ThresholdState:
    """Configurable threshold singleton. Call ``configure()`` once at startup."""

    def __init__(self) -> None:
        self.reset()

    def configure(
        self,
        risk: RiskConfig | None = None,
        policy: PolicyConfig | None = None,
    ) -> None:
        """Apply config overrides. Unset values keep hardcoded defaults."""
        if risk is not None:
            self.LOCK_THRESHOLD = risk.lock_threshold
            self.SANDBOX_THRESHOLD = risk.sandbox_threshold
            self.ELEVATED_LOGGING_THRESHOLD = risk.elevated_logging_threshold
            self.DECAY_RATE_PER_MINUTE = risk.decay_rate_per_minute
            self.DECAY_IDLE_THRESHOLD_MINUTES = risk.decay_idle_threshold_minutes

        if policy is not None:
            if policy.keyword_amplifiers:
                self.KEYWORD_AMPLIFIERS = {**_DEFAULT_KEYWORD_AMPLIFIERS, **policy.keyword_amplifiers}
            if policy.keyword_sensitive_tools:
                self.KEYWORD_SENSITIVE_TOOLS = frozenset(policy.keyword_sensitive_tools)
            if policy.velocity_threshold_calls is not None:
                self.VELOCITY_THRESHOLD_CALLS = policy.velocity_threshold_calls
            if policy.velocity_window_seconds is not None:
                self.VELOCITY_WINDOW_SECONDS = policy.velocity_window_seconds
            if policy.velocity_penalty_per_call is not None:
                self.VELOCITY_PENALTY_PER_CALL = policy.velocity_penalty_per_call
            if policy.velocity_penalty_cap is not None:
                self.VELOCITY_PENALTY_CAP = policy.velocity_penalty_cap
            if policy.escalation_penalty_per_attempt is not None:
                self.ESCALATION_PENALTY_PER_ATTEMPT = policy.escalation_penalty_per_attempt
            if policy.escalation_penalty_cap is not None:
                self.ESCALATION_PENALTY_CAP = policy.escalation_penalty_cap
            if policy.keyword_amplifier_cap is not None:
                self.KEYWORD_AMPLIFIER_CAP = policy.keyword_amplifier_cap
            if policy.llm_risk_weight is not None:
                self.LLM_RISK_WEIGHT = policy.llm_risk_weight

    def reset(self) -> None:
        """Restore all values to hardcoded defaults."""
        self.LOCK_THRESHOLD = _DEFAULT_LOCK_THRESHOLD
        self.SANDBOX_THRESHOLD = _DEFAULT_SANDBOX_THRESHOLD
        self.ELEVATED_LOGGING_THRESHOLD = _DEFAULT_ELEVATED_LOGGING_THRESHOLD
        self.MAX_RISK_SCORE = _DEFAULT_MAX_RISK_SCORE
        self.MIN_RISK_SCORE = _DEFAULT_MIN_RISK_SCORE
        self.TOOL_BASE_RISK = dict(_DEFAULT_TOOL_BASE_RISK)
        self.KEYWORD_AMPLIFIERS = dict(_DEFAULT_KEYWORD_AMPLIFIERS)
        self.KEYWORD_AMPLIFIER_CAP = _DEFAULT_KEYWORD_AMPLIFIER_CAP
        self.KEYWORD_SENSITIVE_TOOLS = _DEFAULT_KEYWORD_SENSITIVE_TOOLS
        self.DEFAULT_TOOL_BASE_RISK = _DEFAULT_TOOL_BASE_RISK_VALUE
        self.LLM_RISK_WEIGHT = _DEFAULT_LLM_RISK_WEIGHT
        self.VELOCITY_THRESHOLD_CALLS = _DEFAULT_VELOCITY_THRESHOLD_CALLS
        self.VELOCITY_WINDOW_SECONDS = _DEFAULT_VELOCITY_WINDOW_SECONDS
        self.VELOCITY_PENALTY_PER_CALL = _DEFAULT_VELOCITY_PENALTY_PER_CALL
        self.VELOCITY_PENALTY_CAP = _DEFAULT_VELOCITY_PENALTY_CAP
        self.ESCALATION_WINDOW_MINUTES = _DEFAULT_ESCALATION_WINDOW_MINUTES
        self.ESCALATION_PENALTY_PER_ATTEMPT = _DEFAULT_ESCALATION_PENALTY_PER_ATTEMPT
        self.ESCALATION_PENALTY_CAP = _DEFAULT_ESCALATION_PENALTY_CAP
        self.DECAY_RATE_PER_MINUTE = _DEFAULT_DECAY_RATE_PER_MINUTE
        self.DECAY_IDLE_THRESHOLD_MINUTES = _DEFAULT_DECAY_IDLE_THRESHOLD_MINUTES


# Module-level singleton — import this to access thresholds
_state = _ThresholdState()

# Public API: access via `thresholds.LOCK_THRESHOLD`, `thresholds.configure(...)`, etc.
configure = _state.configure
reset = _state.reset


def __getattr__(name: str) -> object:
    """Allow `from janus.risk.thresholds import LOCK_THRESHOLD` to work at import-time
    while also reading the configured value at call-time when accessed via module attribute."""
    try:
        return getattr(_state, name)
    except AttributeError:
        raise AttributeError(f"module 'janus.risk.thresholds' has no attribute {name!r}")
