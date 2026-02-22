from __future__ import annotations

from datetime import UTC, datetime

from sentinel.risk.patterns import PatternDetector, PatternMatchResult
from sentinel.risk.scoring import RiskScorer
from sentinel.risk.thresholds import (
    DECAY_IDLE_THRESHOLD_MINUTES,
    DECAY_RATE_PER_MINUTE,
    LOCK_THRESHOLD,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    VELOCITY_WINDOW_SECONDS,
)
from sentinel.storage.session_store import InMemorySessionStore, RiskEvent


class RiskEngine:
    """Stateful risk engine that manages per-session risk scores."""

    def __init__(
        self,
        session_store: InMemorySessionStore,
        scorer: RiskScorer | None = None,
        pattern_detector: PatternDetector | None = None,
    ) -> None:
        self.session_store = session_store
        self.scorer = scorer or RiskScorer()
        self.pattern_detector = pattern_detector or PatternDetector()

    # ── score access ────────────────────────────────────────────────

    def get_score(self, session_id: str) -> float:
        """Return the current risk score, applying time-based decay if idle."""
        session = self.session_store.get_or_create_session(session_id)
        if session.last_tool_call_time is not None:
            now = datetime.now(UTC)
            idle_minutes = (now - session.last_tool_call_time).total_seconds() / 60.0
            if idle_minutes > DECAY_IDLE_THRESHOLD_MINUTES:
                decay = DECAY_RATE_PER_MINUTE * (idle_minutes - DECAY_IDLE_THRESHOLD_MINUTES)
                decayed_score = max(MIN_RISK_SCORE, session.risk_score - decay)
                session.risk_score = decayed_score
        return session.risk_score

    def update_score(self, session_id: str, delta: float) -> float:
        """Add *delta* to the session's risk score, clamp, and return new value."""
        current = self.session_store.get_risk_score(session_id)
        new_score = max(MIN_RISK_SCORE, min(MAX_RISK_SCORE, current + delta))
        self.session_store.set_risk_score(session_id, new_score)
        return new_score

    def is_locked(self, session_id: str) -> bool:
        """Return True if the session risk score meets or exceeds the lock threshold."""
        return self.get_score(session_id) >= LOCK_THRESHOLD

    # ── event management ────────────────────────────────────────────

    def add_event(self, session_id: str, event: RiskEvent) -> None:
        self.session_store.add_event(session_id, event)

    def get_history(self, session_id: str) -> list[RiskEvent]:
        return self.session_store.get_events(session_id)

    # ── evaluation ──────────────────────────────────────────────────

    async def evaluate_risk(
        self,
        tool_name: str,
        tool_input: dict[str, object],
        session_id: str,
        llm_risk: float,
        escalation_attempts: int,
    ) -> tuple[float, PatternMatchResult | None]:
        """Run both scorer and pattern detector; return (total_risk_delta, pattern_match)."""
        recent_events = self.session_store.get_recent_events(
            session_id, window_seconds=VELOCITY_WINDOW_SECONDS
        )

        # Deterministic scoring
        risk_delta = self.scorer.score(
            tool_name=tool_name,
            tool_input=tool_input,
            llm_risk=llm_risk,
            session_events=recent_events,
            escalation_attempts=escalation_attempts,
        )

        # Pattern matching
        history = self.session_store.get_events(session_id)
        session_history: list[tuple[str, dict[str, object]]] = [
            (e.tool_name, {}) for e in history
        ]
        pattern_result = self.pattern_detector.match(tool_name, tool_input, session_history)

        total_delta = risk_delta
        if pattern_result.matched:
            total_delta += pattern_result.risk_contribution

        total_delta = max(MIN_RISK_SCORE, min(MAX_RISK_SCORE, total_delta))

        return total_delta, pattern_result if pattern_result.matched_steps > 0 else None
