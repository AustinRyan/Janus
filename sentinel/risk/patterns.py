from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any


@dataclass
class PatternStep:
    """A single step in a multi-step attack pattern."""

    tool_match: str  # pipe-separated glob patterns, e.g. "read_*|search_*"
    keyword_match: str  # pipe-separated glob patterns scanned against tool_input values
    risk: float
    description: str


@dataclass
class AttackPattern:
    """A named sequence of steps that together signal malicious intent."""

    name: str
    steps: list[PatternStep]
    description: str


@dataclass
class PatternMatchResult:
    """Result returned by PatternDetector.match."""

    matched: bool = False
    pattern_name: str = ""
    matched_steps: int = 0
    total_steps: int = 0
    risk_contribution: float = 0.0
    description: str = ""


class PatternDetector:
    """Detects multi-step attack patterns across a session's tool call history."""

    ATTACK_PATTERNS: list[AttackPattern] = [
        AttackPattern(
            name="sleeper_reconnaissance",
            description=(
                "Agent gathers documentation, then pivots to auth/credential "
                "discovery, then attempts live exploitation."
            ),
            steps=[
                PatternStep(
                    tool_match="read_*|search_*",
                    keyword_match="*api*|*docs*|*documentation*",
                    risk=5.0,
                    description="Reconnaissance: reading API docs / documentation",
                ),
                PatternStep(
                    tool_match="read_*|search_*",
                    keyword_match="*auth*|*login*|*token*|*key*",
                    risk=15.0,
                    description="Credential discovery: searching for auth tokens / keys",
                ),
                PatternStep(
                    tool_match="*",
                    keyword_match="*test*|*try*|*sample*|*login*|*curl*",
                    risk=70.0,
                    description="Exploitation: attempting live action with discovered credentials",
                ),
            ],
        ),
        AttackPattern(
            name="data_exfiltration",
            description=(
                "Agent reads sensitive data, writes it to an export format, "
                "then sends it externally."
            ),
            steps=[
                PatternStep(
                    tool_match="read_*|database_*",
                    keyword_match="*",
                    risk=5.0,
                    description="Data access: reading files or querying database",
                ),
                PatternStep(
                    tool_match="write_*",
                    keyword_match="*export*|*dump*|*csv*",
                    risk=20.0,
                    description="Staging: writing data to export format",
                ),
                PatternStep(
                    tool_match="send_*|api_call",
                    keyword_match="*upload*|*transfer*|*post*",
                    risk=60.0,
                    description="Exfiltration: sending data externally",
                ),
            ],
        ),
    ]

    # ── public API ──────────────────────────────────────────────────

    def match(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        session_history: list[tuple[str, dict[str, Any]]],
    ) -> PatternMatchResult:
        """Check current request + history against every known pattern.

        Returns the *highest-risk* match found (or a non-matched result).
        """
        full_history = list(session_history) + [(tool_name, tool_input)]

        best = PatternMatchResult()

        for pattern in self.ATTACK_PATTERNS:
            result = self._match_pattern(pattern, full_history)
            if result.risk_contribution > best.risk_contribution:
                best = result

        return best

    # ── internals ───────────────────────────────────────────────────

    def _match_pattern(
        self,
        pattern: AttackPattern,
        history: list[tuple[str, dict[str, Any]]],
    ) -> PatternMatchResult:
        step_idx = 0
        total_risk = 0.0
        total_steps = len(pattern.steps)

        for tool_name, tool_input in history:
            if step_idx >= total_steps:
                break

            step = pattern.steps[step_idx]
            if self._tool_matches(step.tool_match, tool_name) and self._keyword_matches(
                step.keyword_match, tool_input
            ):
                amplifier = 1.0 + 0.5 * (step_idx / total_steps)
                total_risk += step.risk * amplifier
                step_idx += 1

        return PatternMatchResult(
            matched=step_idx == total_steps,
            pattern_name=pattern.name,
            matched_steps=step_idx,
            total_steps=total_steps,
            risk_contribution=total_risk,
            description=pattern.description if step_idx > 0 else "",
        )

    @staticmethod
    def _tool_matches(pattern_str: str, tool_name: str) -> bool:
        """Check tool_name against pipe-separated glob patterns."""
        return any(fnmatch(tool_name, p.strip()) for p in pattern_str.split("|"))

    @staticmethod
    def _keyword_matches(pattern_str: str, tool_input: dict[str, Any]) -> bool:
        """Check if any string value in tool_input matches any of the
        pipe-separated glob patterns."""
        patterns = [p.strip() for p in pattern_str.split("|")]
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

        for s in strings:
            for pat in patterns:
                if fnmatch(s, pat):
                    return True
        return False
