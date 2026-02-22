from __future__ import annotations

from typing import Any

from sentinel.risk.thresholds import (
    DEFAULT_TOOL_BASE_RISK,
    ESCALATION_PENALTY_CAP,
    ESCALATION_PENALTY_PER_ATTEMPT,
    KEYWORD_AMPLIFIER_CAP,
    KEYWORD_AMPLIFIERS,
    LLM_RISK_WEIGHT,
    MAX_RISK_SCORE,
    MIN_RISK_SCORE,
    TOOL_BASE_RISK,
    VELOCITY_PENALTY_CAP,
    VELOCITY_PENALTY_PER_CALL,
    VELOCITY_THRESHOLD_CALLS,
)
from sentinel.storage.session_store import RiskEvent


class RiskScorer:
    """Calculates a risk delta for a single tool call."""

    def score(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        llm_risk: float,
        session_events: list[RiskEvent],
        escalation_attempts: int,
    ) -> float:
        """Return a risk delta clamped to [0, 100].

        Formula:
            base_tool_risk
            + keyword_amplifier
            + (LLM_RISK_WEIGHT * llm_risk)
            + velocity_penalty
            + escalation_penalty
        """
        total = (
            self._get_base_risk(tool_name)
            + self._scan_keywords(tool_input)
            + LLM_RISK_WEIGHT * llm_risk
            + self._velocity_penalty(session_events)
            + self._escalation_penalty(escalation_attempts)
        )
        return max(MIN_RISK_SCORE, min(MAX_RISK_SCORE, total))

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _get_base_risk(tool_name: str) -> float:
        return TOOL_BASE_RISK.get(tool_name, DEFAULT_TOOL_BASE_RISK)

    @staticmethod
    def _scan_keywords(tool_input: dict[str, Any]) -> float:
        """Recursively scan all string values for keyword matches."""
        strings: list[str] = []

        def _collect(value: Any) -> None:
            if isinstance(value, str):
                strings.append(value.lower())
            elif isinstance(value, dict):
                for v in value.values():
                    _collect(v)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _collect(item)

        _collect(tool_input)

        total = 0.0
        for keyword, weight in KEYWORD_AMPLIFIERS.items():
            for s in strings:
                if keyword in s:
                    total += weight
                    break  # count each keyword at most once
        return min(total, KEYWORD_AMPLIFIER_CAP)

    @staticmethod
    def _velocity_penalty(session_events: list[RiskEvent]) -> float:
        """Penalize bursts of calls within the velocity window."""
        count = len(session_events)
        if count <= VELOCITY_THRESHOLD_CALLS:
            return 0.0
        return min(
            VELOCITY_PENALTY_CAP,
            (count - VELOCITY_THRESHOLD_CALLS) * VELOCITY_PENALTY_PER_CALL,
        )

    @staticmethod
    def _escalation_penalty(escalation_attempts: int) -> float:
        return min(
            ESCALATION_PENALTY_CAP,
            escalation_attempts * ESCALATION_PENALTY_PER_ATTEMPT,
        )
