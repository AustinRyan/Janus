"""Collaborative threat intelligence with pattern learning.

Maintains a database of known threat patterns (both built-in and
learned from blocked sessions). Matches current session activity
against these patterns to elevate risk early.
"""
from __future__ import annotations

import fnmatch
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from janus.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
)
from janus.risk import thresholds


@dataclass
class ThreatPattern:
    pattern_id: str
    pattern_type: str
    tool_sequence: list[str]
    risk_contribution: float
    confidence: float
    first_seen: datetime
    times_seen: int
    source: str  # "built_in" | "learned"


def _sequence_matches(
    history: list[str],
    pattern_seq: list[str],
) -> bool:
    """Check if tool history contains the pattern sequence."""
    if not pattern_seq or not history:
        return False
    pi = 0
    for tool in history:
        if fnmatch.fnmatch(tool, pattern_seq[pi]):
            pi += 1
            if pi == len(pattern_seq):
                return True
    return False


# Built-in threat patterns.  Each sequence must be long enough to avoid
# false positives on normal workflows.  Two-step sequences like
# [read_*, send_*] are far too broad — a user reading a file then
# sending a message is completely normal.  Patterns should require at
# least 3 steps with a clearly suspicious final action.
_BUILT_IN_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern_type": "data_exfiltration",
        "tool_sequence": ["database_*", "read_*", "send_*"],
        "risk_contribution": 15.0,
        "confidence": 0.85,
    },
    {
        "pattern_type": "data_exfiltration_via_api",
        "tool_sequence": ["database_*", "read_*", "api_call"],
        "risk_contribution": 18.0,
        "confidence": 0.90,
    },
    {
        "pattern_type": "privilege_escalation",
        "tool_sequence": [
            "read_*",
            "execute_code",
            "write_*",
        ],
        "risk_contribution": 20.0,
        "confidence": 0.80,
    },
    {
        "pattern_type": "credential_theft",
        "tool_sequence": ["search_*", "read_*", "api_call"],
        "risk_contribution": 15.0,
        "confidence": 0.75,
    },
    {
        "pattern_type": "financial_fraud",
        "tool_sequence": ["database_*", "read_*", "financial_*"],
        "risk_contribution": 20.0,
        "confidence": 0.88,
    },
    {
        "pattern_type": "recon_exploit",
        "tool_sequence": ["search_*", "read_*", "execute_code", "api_call"],
        "risk_contribution": 15.0,
        "confidence": 0.70,
    },
]


class ThreatIntelDB:
    """In-memory threat pattern database."""

    def __init__(self) -> None:
        self._patterns: list[ThreatPattern] = []
        self._total_matches: int = 0
        self._seed_built_in()

    def _seed_built_in(self) -> None:
        now = datetime.now(UTC)
        for p in _BUILT_IN_PATTERNS:
            self._patterns.append(
                ThreatPattern(
                    pattern_id=str(uuid.uuid4()),
                    pattern_type=p["pattern_type"],
                    tool_sequence=p["tool_sequence"],
                    risk_contribution=p[
                        "risk_contribution"
                    ],
                    confidence=p["confidence"],
                    first_seen=now,
                    times_seen=0,
                    source="built_in",
                )
            )

    def match(
        self, tool_history: list[str],
    ) -> list[ThreatPattern]:
        """Match session tool history against known patterns."""
        matches: list[ThreatPattern] = []
        for pattern in self._patterns:
            if _sequence_matches(
                tool_history, pattern.tool_sequence
            ):
                pattern.times_seen += 1
                self._total_matches += 1
                matches.append(pattern)
        return matches

    def learn_from_session(
        self,
        tool_history: list[str],
        pattern_type: str,
    ) -> ThreatPattern | None:
        """Extract and store a new learned pattern."""
        if len(tool_history) < 2:
            return None

        for p in self._patterns:
            if p.tool_sequence == tool_history:
                p.times_seen += 1
                return p

        new_pattern = ThreatPattern(
            pattern_id=str(uuid.uuid4()),
            pattern_type=pattern_type,
            tool_sequence=list(tool_history),
            risk_contribution=10.0,
            confidence=0.60,
            first_seen=datetime.now(UTC),
            times_seen=1,
            source="learned",
        )
        self._patterns.append(new_pattern)
        return new_pattern

    def get_all_patterns(self) -> list[ThreatPattern]:
        return list(self._patterns)

    def get_stats(self) -> dict[str, Any]:
        built_in = sum(
            1 for p in self._patterns
            if p.source == "built_in"
        )
        learned = sum(
            1 for p in self._patterns
            if p.source == "learned"
        )
        return {
            "total_patterns": len(self._patterns),
            "built_in_count": built_in,
            "learned_count": learned,
            "total_matches": self._total_matches,
        }


class ThreatIntelCheck:
    """Security check matching against threat intel DB.

    Priority 55: runs after drift detection, before ITDR.
    """

    name: str = "threat_intel"
    priority: int = 55

    def __init__(self, db: ThreatIntelDB) -> None:
        self._db = db
        self._session_tools: dict[str, list[str]] = {}

    def record_tool(
        self, session_id: str, tool_name: str,
    ) -> None:
        if session_id not in self._session_tools:
            self._session_tools[session_id] = []
        self._session_tools[session_id].append(tool_name)

    def get_session_tools(
        self, session_id: str,
    ) -> list[str]:
        return list(
            self._session_tools.get(session_id, [])
        )

    async def evaluate(
        self,
        request: ToolCallRequest,
        context: PipelineContext,
    ) -> CheckResult:
        history = self.get_session_tools(
            request.session_id
        )
        current = [*history, request.tool_name]

        matches = self._db.match(current)

        if not matches:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No threat intel matches.",
            )

        best = max(
            matches, key=lambda m: m.confidence
        )

        # Only materialise threat-intel risk when the CURRENT tool is
        # an action tool.  Read-only tools (read_file, search_web, …)
        # build sequence state but don't accumulate risk themselves.
        if request.tool_name in thresholds.KEYWORD_SENSITIVE_TOOLS:
            risk = best.risk_contribution
        else:
            risk = 0.0

        return CheckResult(
            check_name=self.name,
            passed=True,
            risk_contribution=risk,
            reason=(
                f"Threat pattern"
                f" '{best.pattern_type}' matched"
                f" ({best.confidence:.0%} confidence,"
                f" seen {best.times_seen}x)"
            ),
            metadata={
                "threat_intel_matches": [
                    {
                        "pattern_type": m.pattern_type,
                        "confidence": m.confidence,
                        "times_seen": m.times_seen,
                        "source": m.source,
                    }
                    for m in matches
                ],
            },
        )
