from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class EscalationAttempt:
    agent_id: str
    tool_attempted: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ITDRSignal:
    agent_id: str
    signal_type: str
    severity: str
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = field(default_factory=dict)
    session_id: str = ""
    related_agent_id: str = ""


@dataclass
class AnomalySignal:
    """Anomaly detection signal — not inheriting to avoid dataclass field ordering issues."""

    agent_id: str
    severity: str
    description: str
    anomaly_types: list[str] = field(default_factory=list)
    signal_type: str = "anomaly"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = field(default_factory=dict)
    session_id: str = ""
    related_agent_id: str = ""


@dataclass
class CollusionSignal:
    """Cross-agent collusion detection signal."""

    agent_id: str
    severity: str
    description: str
    source_agent_id: str = ""
    target_agent_id: str = ""
    data_fingerprint: str = ""
    signal_type: str = "collusion"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = field(default_factory=dict)
    session_id: str = ""
    related_agent_id: str = ""


@dataclass
class EscalationSignal:
    """Privilege escalation tracking signal."""

    agent_id: str
    severity: str
    description: str
    attempts: list[EscalationAttempt] = field(default_factory=list)
    signal_type: str = "escalation"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, str] = field(default_factory=dict)
    session_id: str = ""
    related_agent_id: str = ""
