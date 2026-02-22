from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class RiskEvent:
    """A single risk score change event in a session."""

    risk_delta: float
    new_score: float
    tool_name: str
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class SessionState:
    """In-memory state for an active session."""

    session_id: str
    risk_score: float = 0.0
    original_goal: str = ""
    events: list[RiskEvent] = field(default_factory=list)
    tool_call_history: list[tuple[str, dict[str, object]]] = field(default_factory=list)
    tool_call_count: int = 0
    last_tool_call_time: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class InMemorySessionStore:
    """In-memory store for active session risk scores and events."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def get_or_create_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def get_risk_score(self, session_id: str) -> float:
        session = self._sessions.get(session_id)
        return session.risk_score if session else 0.0

    def set_risk_score(self, session_id: str, score: float) -> None:
        session = self.get_or_create_session(session_id)
        session.risk_score = max(0.0, min(100.0, score))

    def add_event(self, session_id: str, event: RiskEvent) -> None:
        session = self.get_or_create_session(session_id)
        session.events.append(event)
        session.tool_call_count += 1
        session.last_tool_call_time = event.timestamp

    def get_events(self, session_id: str) -> list[RiskEvent]:
        session = self._sessions.get(session_id)
        return session.events if session else []

    def get_recent_events(
        self, session_id: str, window_seconds: float = 60.0
    ) -> list[RiskEvent]:
        events = self.get_events(session_id)
        if not events:
            return []
        now = datetime.now(UTC)
        return [e for e in events if (now - e.timestamp).total_seconds() <= window_seconds]

    def record_tool_call(
        self, session_id: str, tool_name: str, tool_input: dict[str, object],
    ) -> None:
        session = self.get_or_create_session(session_id)
        session.tool_call_history.append((tool_name, tool_input))

    def get_tool_call_history(self, session_id: str) -> list[tuple[str, dict[str, object]]]:
        session = self._sessions.get(session_id)
        return session.tool_call_history if session else []

    def set_goal(self, session_id: str, goal: str) -> None:
        session = self.get_or_create_session(session_id)
        if not session.original_goal:
            session.original_goal = goal

    def get_goal(self, session_id: str) -> str:
        session = self._sessions.get(session_id)
        return session.original_goal if session else ""

    def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def list_sessions(self) -> list[str]:
        return list(self._sessions.keys())
