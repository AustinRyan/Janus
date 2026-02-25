"""Causal data-flow taint tracking for sensitive data exfiltration prevention.

Scans tool outputs for sensitive patterns (PII, credentials, etc.) and
blocks export through sink tools (email, API calls, file writes).
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from janus.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
    Verdict,
)


class TaintLabel(Enum):
    """Categories of sensitive data detected in tool outputs."""

    PII = "pii"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    INTERNAL = "internal"
    SOURCE_CODE = "source_code"


@dataclass(frozen=True)
class TaintEntry:
    """A single taint record from scanning a tool output."""

    label: TaintLabel
    source_tool: str
    source_step: int
    patterns_matched: list[str] = field(default_factory=list)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )


# Compiled regex patterns mapping to taint labels.
# Each entry is (compiled_pattern, human_description, TaintLabel).
_TAINT_PATTERNS: list[tuple[re.Pattern[str], str, TaintLabel]] = [
    # PII
    (
        re.compile(r"\d{3}-\d{2}-\d{4}"),
        "ssn",
        TaintLabel.PII,
    ),
    (
        re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ),
        "email",
        TaintLabel.PII,
    ),
    # Financial
    (
        re.compile(
            r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"
        ),
        "credit_card",
        TaintLabel.FINANCIAL,
    ),
    # Credentials
    (
        re.compile(r"sk-[a-zA-Z0-9_-]{4,}"),
        "api_key",
        TaintLabel.CREDENTIALS,
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_access_key",
        TaintLabel.CREDENTIALS,
    ),
    (
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        "github_token",
        TaintLabel.CREDENTIALS,
    ),
    (
        re.compile(r"xox[bsp]-[a-zA-Z0-9-]+"),
        "slack_token",
        TaintLabel.CREDENTIALS,
    ),
    (
        re.compile(
            r"(postgres|mysql|mongodb|redis)://\S+"
        ),
        "db_connection_string",
        TaintLabel.CREDENTIALS,
    ),
    (
        re.compile(
            r"password\s*[:=]\s*\S+", re.IGNORECASE
        ),
        "password",
        TaintLabel.CREDENTIALS,
    ),
    # Internal network
    (
        re.compile(r"10\.\d+\.\d+\.\d+"),
        "internal_ip_10",
        TaintLabel.INTERNAL,
    ),
    (
        re.compile(r"192\.168\.\d+\.\d+"),
        "internal_ip_192",
        TaintLabel.INTERNAL,
    ),
    (
        re.compile(
            r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
        ),
        "internal_ip_172",
        TaintLabel.INTERNAL,
    ),
]

# Tools that can export data outside the session boundary.
SINK_TOOLS: frozenset[str] = frozenset({
    "send_email",
    "send_message",
    "api_call",
    "financial_transfer",
    "write_file",
})


def _flatten_to_text(obj: Any) -> str:
    """Recursively flatten an object into a single text string."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(
            _flatten_to_text(v) for v in obj.values()
        )
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_to_text(v) for v in obj)
    return str(obj)


class TaintTracker:
    """Tracks tainted data flowing through a session.

    Scans every tool output for sensitive patterns and remembers
    which sessions are tainted. When a sink tool is about to be
    called on a tainted session, returns the active taints so the
    pipeline can block the export.
    """

    def __init__(self) -> None:
        self._taints: dict[str, list[TaintEntry]] = (
            defaultdict(list)
        )

    def scan_output(
        self,
        session_id: str,
        tool_name: str,
        tool_output: Any,
        *,
        step: int,
    ) -> list[TaintEntry]:
        """Scan a tool's output for sensitive data patterns.

        Returns newly discovered taint entries and stores them
        for later export checks.
        """
        text = _flatten_to_text(tool_output)
        new_taints: list[TaintEntry] = []
        seen_labels: set[TaintLabel] = set()

        for pattern, description, label in _TAINT_PATTERNS:
            if pattern.search(text) and label not in seen_labels:
                entry = TaintEntry(
                    label=label,
                    source_tool=tool_name,
                    source_step=step,
                    patterns_matched=[description],
                )
                new_taints.append(entry)
                seen_labels.add(label)

        self._taints[session_id].extend(new_taints)
        return new_taints

    def check_export(
        self,
        session_id: str,
        tool_name: str,
    ) -> list[TaintEntry]:
        """Check if a sink tool should be blocked.

        Returns active taints if the tool is a sink and the
        session is tainted. Returns empty list otherwise.
        """
        if tool_name not in SINK_TOOLS:
            return []
        return list(self._taints.get(session_id, []))

    def get_active_taints(
        self, session_id: str
    ) -> list[TaintEntry]:
        """Return all taint entries for a session."""
        return list(self._taints.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        """Remove all taint entries for a session."""
        self._taints.pop(session_id, None)


class TaintAnalysisCheck:
    """SecurityCheck that blocks data exfiltration via sink tools.

    Priority 35: runs after deterministic risk scoring, before
    LLM-based risk classification.
    """

    name: str = "taint_analysis"
    priority: int = 35

    def __init__(self, tracker: TaintTracker) -> None:
        self._tracker = tracker

    async def evaluate(
        self,
        request: ToolCallRequest,
        context: PipelineContext,
    ) -> CheckResult:
        """Evaluate whether a tool call would export tainted data."""
        violations = self._tracker.check_export(
            request.session_id, request.tool_name
        )

        if not violations:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No tainted data at risk of export.",
            )

        labels = sorted(
            {v.label.value for v in violations}
        )
        sources = sorted(
            {v.source_tool for v in violations}
        )

        return CheckResult(
            check_name=self.name,
            passed=False,
            risk_contribution=35.0,
            reason=(
                f"Tainted data ({', '.join(labels)}) "
                f"would be exported via sink tool "
                f"'{request.tool_name}'. "
                f"Sources: {', '.join(sources)}."
            ),
            force_verdict=Verdict.BLOCK,
            metadata={
                "taint_labels": labels,
                "taint_sources": sources,
                "sink_tool": request.tool_name,
            },
        )
