from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Verdict(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    SANDBOX = "sandbox"
    PAUSE = "pause"


@dataclass(frozen=True)
class ToolCallRequest:
    """Immutable representation of a tool call intercepted by Guardian."""

    agent_id: str
    session_id: str
    tool_name: str
    tool_input: dict[str, Any] = field(default_factory=dict)
    original_goal: str = ""
    conversation_history: list[dict[str, Any]] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class CheckResult:
    """Result from a single security check in the pipeline."""

    check_name: str
    passed: bool
    risk_contribution: float = 0.0
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    force_verdict: Verdict | None = None


@dataclass
class SecurityVerdict:
    """Final result of the full security pipeline evaluation."""

    verdict: Verdict
    risk_score: float
    risk_delta: float
    reasons: list[str] = field(default_factory=list)
    drift_score: float = 0.0
    itdr_signals: list[str] = field(default_factory=list)
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    recommended_action: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class PipelineContext:
    """Mutable context passed through all checks in a single evaluation."""

    session_risk_score: float = 0.0
    agent_identity: Any = None
    check_results: list[CheckResult] = field(default_factory=list)
    accumulated_risk_delta: float = 0.0
