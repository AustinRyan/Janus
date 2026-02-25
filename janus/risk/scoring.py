from __future__ import annotations

import re
from typing import Any

from janus.risk import thresholds
from janus.storage.session_store import RiskEvent

# Patterns that indicate mass-targeting in URLs or resource identifiers
_MASS_TARGET_RE = re.compile(
    r"/all\b|/bulk\b|/everything\b|/\*$|/users/all|/data/all|/records/all",
    re.IGNORECASE,
)
# Destructive HTTP methods
_DESTRUCTIVE_METHODS = frozenset({"delete", "put", "patch"})
# Bonus risk for destructive method + mass target combination
_DESTRUCTIVE_API_BONUS = 40.0


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
            + destructive_api_bonus
            + (LLM_RISK_WEIGHT * llm_risk)
            + velocity_penalty
            + escalation_penalty
        """
        total = (
            self._get_base_risk(tool_name)
            + self._scan_keywords(tool_name, tool_input)
            + self._destructive_api_check(tool_name, tool_input)
            + thresholds.LLM_RISK_WEIGHT * llm_risk
            + self._velocity_penalty(session_events)
            + self._escalation_penalty(escalation_attempts)
        )
        return max(thresholds.MIN_RISK_SCORE, min(thresholds.MAX_RISK_SCORE, total))

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _get_base_risk(tool_name: str) -> float:
        return thresholds.TOOL_BASE_RISK.get(tool_name, thresholds.DEFAULT_TOOL_BASE_RISK)

    @staticmethod
    def _scan_keywords(tool_name: str, tool_input: dict[str, Any]) -> float:
        """Scan tool_input for dangerous payload patterns.

        Only runs on tools that act on their input (execute, write, send).
        Benign tools like read_file and search_web are exempt — searching
        "how to set up login" is not a threat.
        """
        if tool_name not in thresholds.KEYWORD_SENSITIVE_TOOLS:
            return 0.0

        strings: list[str] = []

        def _collect(value: Any) -> None:
            if isinstance(value, str):
                strings.append(value.lower())
            elif isinstance(value, dict):
                for k, v in value.items():
                    if isinstance(k, str):
                        strings.append(k.lower())
                    _collect(v)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _collect(item)

        _collect(tool_input)

        total = 0.0
        for keyword, weight in thresholds.KEYWORD_AMPLIFIERS.items():
            for s in strings:
                if keyword in s:
                    total += weight
                    break  # count each keyword at most once
        return min(total, thresholds.KEYWORD_AMPLIFIER_CAP)

    @staticmethod
    def _destructive_api_check(tool_name: str, tool_input: dict[str, Any]) -> float:
        """Detect destructive HTTP method + mass-targeting URL combinations.

        A DELETE /users/all is dangerous regardless of who runs it.
        This fires independently of keyword amplifiers so it stacks.
        """
        if tool_name != "api_call":
            return 0.0

        method = str(tool_input.get("method", "")).lower()
        url = str(tool_input.get("url", "")).lower()

        if method in _DESTRUCTIVE_METHODS and _MASS_TARGET_RE.search(url):
            return _DESTRUCTIVE_API_BONUS
        return 0.0

    @staticmethod
    def _velocity_penalty(session_events: list[RiskEvent]) -> float:
        """Penalize bursts of calls within the velocity window."""
        count = len(session_events)
        if count <= thresholds.VELOCITY_THRESHOLD_CALLS:
            return 0.0
        return min(
            thresholds.VELOCITY_PENALTY_CAP,
            (count - thresholds.VELOCITY_THRESHOLD_CALLS) * thresholds.VELOCITY_PENALTY_PER_CALL,
        )

    @staticmethod
    def _escalation_penalty(escalation_attempts: int) -> float:
        return min(
            thresholds.ESCALATION_PENALTY_CAP,
            escalation_attempts * thresholds.ESCALATION_PENALTY_PER_ATTEMPT,
        )
