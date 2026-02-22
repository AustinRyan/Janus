from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SecurityTrace:
    trace_id: str
    session_id: str
    agent_id: str
    request_id: str
    tool_name: str
    tool_input: dict[str, Any]
    verdict: str
    risk_score: float
    risk_delta: float
    timestamp: datetime
    drift_score: float | None = None
    reasons: list[str] = field(default_factory=list)
    itdr_signals: list[str] = field(default_factory=list)
    explanation: str = ""
    original_goal: str = ""
    conversation_context: list[dict[str, Any]] = field(default_factory=list)
