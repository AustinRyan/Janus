from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AgentRow:
    """Row model for the agents table."""

    agent_id: str
    name: str
    role: str
    permissions_json: str = "[]"
    created_at: str = ""
    credential_hash: str = ""
    credential_expires_at: str | None = None
    credential_last_rotated: str | None = None
    is_locked: int = 0
    lock_reason: str = ""
    metadata_json: str = "{}"


@dataclass
class ToolUsageRow:
    """Row model for the tool_usage_log table."""

    agent_id: str
    tool_name: str
    session_id: str
    timestamp: str
    risk_score_at_time: float = 0.0
    id: int | None = None


@dataclass
class SecurityTraceRow:
    """Row model for the security_traces table."""

    trace_id: str
    session_id: str
    agent_id: str
    request_id: str
    tool_name: str
    tool_input_json: str
    verdict: str
    risk_score: float
    risk_delta: float
    timestamp: str
    drift_score: float | None = None
    reasons_json: str = "[]"
    itdr_signals_json: str = "[]"
    explanation: str = ""
    original_goal: str = ""
    conversation_context_json: str = "[]"
    created_at: str = ""


@dataclass
class PatternMatchRow:
    """Row model for the pattern_matches table."""

    session_id: str
    agent_id: str
    pattern_name: str
    matched_steps: int
    total_steps: int
    trace_ids_json: str
    risk_contribution: float
    timestamp: str
    id: int | None = None
    created_at: str = ""


@dataclass
class ITDRSignalRow:
    """Row model for the itdr_signals table."""

    agent_id: str
    signal_type: str
    severity: str
    description: str
    timestamp: str
    metadata_json: str = "{}"
    session_id: str | None = None
    related_agent_id: str | None = None
    id: int | None = None
    created_at: str = ""


@dataclass
class LicenseRow:
    """Row model for the licenses table."""

    license_key: str
    tier: str = "pro"
    customer_email: str = ""
    stripe_customer_id: str | None = None
    stripe_session_id: str | None = None
    status: str = "active"
    created_at: str = ""
    expires_at: str | None = None
    id: int | None = None
