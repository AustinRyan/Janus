# Sentinel V4: Killer Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 4 differentiated security features (taint tracking, predictive risk, cryptographic proof chain, collaborative threat intelligence) with full frontend visualization to make Sentinel a demo-ready product.

**Architecture:** Each feature is a new SecurityCheck (or post-pipeline hook) that slots into the existing Guardian pipeline. Data flows through SecurityVerdict → SecurityEvent → WebSocket → Frontend. The frontend expands from 3 panels to 4 panels with a tabbed right panel.

**Tech Stack:** Python 3.13 / FastAPI / Next.js 16 / TypeScript / Tailwind CSS / SHA-256 / structlog

**Test runner:** `/Users/austinryan/Desktop/sideproject/project-sentinel/.venv/bin/pytest`
**Linter:** `/Users/austinryan/Desktop/sideproject/project-sentinel/.venv/bin/ruff check sentinel/`
**Type checker:** `/Users/austinryan/Desktop/sideproject/project-sentinel/.venv/bin/mypy sentinel/ --ignore-missing-imports`
**Frontend build:** `cd /Users/austinryan/Desktop/sideproject/project-sentinel/frontend && npm run build`

---

## Phase 1: Taint Tracking (Backend)

### Task 1: TaintTracker core data structures and scanner

**Files:**
- Create: `sentinel/core/taint.py`
- Test: `tests/test_taint.py`

**Step 1: Write the failing tests**

Create `tests/test_taint.py`:

```python
"""Tests for the causal data-flow taint tracking system."""
from __future__ import annotations

import pytest

from sentinel.core.taint import TaintLabel, TaintTracker


@pytest.fixture
def tracker() -> TaintTracker:
    return TaintTracker()


def test_no_taints_initially(tracker: TaintTracker) -> None:
    assert tracker.get_active_taints("session-1") == []


def test_scan_detects_ssn(tracker: TaintTracker) -> None:
    output = {"rows": [{"ssn": "123-45-6789", "name": "Alice"}]}
    taints = tracker.scan_output("session-1", "database_query", output, step=1)
    assert len(taints) >= 1
    labels = {t.label for t in taints}
    assert TaintLabel.PII in labels


def test_scan_detects_credit_card(tracker: TaintTracker) -> None:
    output = {"data": "Card: 4111-1111-1111-1111"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.FINANCIAL in labels


def test_scan_detects_api_key(tracker: TaintTracker) -> None:
    output = {"content": "api_key=sk-proj-abc123xyz"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_aws_key(tracker: TaintTracker) -> None:
    output = {"config": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_internal_ip(tracker: TaintTracker) -> None:
    output = {"host": "10.0.1.42"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.INTERNAL in labels


def test_scan_detects_db_connection_string(tracker: TaintTracker) -> None:
    output = {"url": "postgres://admin:secret@db.internal:5432/prod"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_scan_detects_password(tracker: TaintTracker) -> None:
    output = {"content": "password: hunter2"}
    taints = tracker.scan_output("session-1", "read_file", output, step=1)
    labels = {t.label for t in taints}
    assert TaintLabel.CREDENTIALS in labels


def test_clean_output_no_taints(tracker: TaintTracker) -> None:
    output = {"message": "Hello, how can I help?"}
    taints = tracker.scan_output("session-1", "search_web", output, step=1)
    assert taints == []


def test_get_active_taints_returns_accumulated(tracker: TaintTracker) -> None:
    tracker.scan_output("s1", "database_query", {"ssn": "111-22-3333"}, step=1)
    tracker.scan_output("s1", "read_file", {"key": "sk-abc123"}, step=2)
    active = tracker.get_active_taints("s1")
    labels = {t.label for t in active}
    assert TaintLabel.PII in labels
    assert TaintLabel.CREDENTIALS in labels


def test_sessions_are_isolated(tracker: TaintTracker) -> None:
    tracker.scan_output("s1", "db", {"ssn": "111-22-3333"}, step=1)
    assert len(tracker.get_active_taints("s1")) > 0
    assert len(tracker.get_active_taints("s2")) == 0


def test_check_export_flags_tainted_session(tracker: TaintTracker) -> None:
    tracker.scan_output("s1", "database_query", {"ssn": "111-22-3333"}, step=1)
    violations = tracker.check_export("s1", "send_email")
    assert len(violations) > 0
    assert violations[0].label == TaintLabel.PII


def test_check_export_clean_session(tracker: TaintTracker) -> None:
    violations = tracker.check_export("s1", "send_email")
    assert violations == []


def test_non_sink_tool_not_flagged(tracker: TaintTracker) -> None:
    tracker.scan_output("s1", "db", {"ssn": "111-22-3333"}, step=1)
    violations = tracker.check_export("s1", "read_file")
    assert violations == []


def test_clear_session(tracker: TaintTracker) -> None:
    tracker.scan_output("s1", "db", {"ssn": "111-22-3333"}, step=1)
    tracker.clear_session("s1")
    assert tracker.get_active_taints("s1") == []
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_taint.py -v`
Expected: FAIL (module not found)

**Step 3: Implement TaintTracker**

Create `sentinel/core/taint.py`:

```python
"""Causal data-flow taint tracking for the security pipeline.

Tracks sensitive data (PII, credentials, financial) through tool call
chains. Detects when tainted data flows to export/sink tools.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class TaintLabel(Enum):
    PII = "pii"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    INTERNAL = "internal"
    SOURCE_CODE = "source_code"


@dataclass
class TaintEntry:
    label: TaintLabel
    source_tool: str
    source_step: int
    patterns_matched: list[str]
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )


# Patterns that indicate sensitive data
_TAINT_PATTERNS: list[tuple[re.Pattern[str], TaintLabel, str]] = [
    # PII
    (re.compile(r"\d{3}-\d{2}-\d{4}"), TaintLabel.PII, "SSN"),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        TaintLabel.PII,
        "email_address",
    ),
    # Financial
    (
        re.compile(r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"),
        TaintLabel.FINANCIAL,
        "credit_card",
    ),
    # Credentials
    (re.compile(r"sk-[a-zA-Z0-9_-]{10,}"), TaintLabel.CREDENTIALS, "api_key_sk"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), TaintLabel.CREDENTIALS, "aws_key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), TaintLabel.CREDENTIALS, "github_token"),
    (re.compile(r"xox[bsp]-[a-zA-Z0-9-]+"), TaintLabel.CREDENTIALS, "slack_token"),
    (
        re.compile(r"(postgres|mysql|mongodb|redis)://\S+"),
        TaintLabel.CREDENTIALS,
        "db_connection_string",
    ),
    (re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE), TaintLabel.CREDENTIALS, "password"),
    # Internal
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), TaintLabel.INTERNAL, "internal_ip_10"),
    (
        re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        TaintLabel.INTERNAL,
        "internal_ip_192",
    ),
    (
        re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
        TaintLabel.INTERNAL,
        "internal_ip_172",
    ),
]

# Tools that export data outside the system
SINK_TOOLS = frozenset({
    "send_email",
    "send_message",
    "api_call",
    "financial_transfer",
    "write_file",
})


class TaintTracker:
    """Per-session taint state management."""

    def __init__(self) -> None:
        self._taints: dict[str, list[TaintEntry]] = {}

    def scan_output(
        self,
        session_id: str,
        tool_name: str,
        tool_output: dict[str, Any],
        step: int,
    ) -> list[TaintEntry]:
        """Scan tool output for sensitive data patterns.
        Returns new taint entries found."""
        text = json.dumps(tool_output, default=str)
        new_taints: list[TaintEntry] = []
        seen_labels: set[TaintLabel] = set()

        for pattern, label, name in _TAINT_PATTERNS:
            if label in seen_labels:
                continue
            if pattern.search(text):
                entry = TaintEntry(
                    label=label,
                    source_tool=tool_name,
                    source_step=step,
                    patterns_matched=[name],
                )
                new_taints.append(entry)
                seen_labels.add(label)

        if new_taints:
            if session_id not in self._taints:
                self._taints[session_id] = []
            self._taints[session_id].extend(new_taints)

        return new_taints

    def check_export(
        self,
        session_id: str,
        tool_name: str,
    ) -> list[TaintEntry]:
        """Check if a tool call would export tainted data.
        Returns list of active taints if tool is a sink."""
        if tool_name not in SINK_TOOLS:
            return []
        return self.get_active_taints(session_id)

    def get_active_taints(self, session_id: str) -> list[TaintEntry]:
        """Return all active taint entries for a session."""
        return list(self._taints.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        """Remove all taints for a session."""
        self._taints.pop(session_id, None)
```

**Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_taint.py -v`
Expected: All 16 tests PASS

**Step 5: Run ruff + mypy**

Run: `.venv/bin/ruff check sentinel/core/taint.py && .venv/bin/mypy sentinel/core/taint.py --ignore-missing-imports`

**Step 6: Commit**

```
feat: add taint tracking core (data-flow scanner)
```

---

### Task 2: TaintAnalysisCheck pipeline integration

**Files:**
- Create: `tests/test_taint_pipeline.py`
- Modify: `sentinel/core/taint.py` (add TaintAnalysisCheck class)
- Modify: `sentinel/core/guardian.py` (wire into pipeline)
- Modify: `sentinel/web/agent.py` (scan tool outputs after execution)

**Step 1: Write the failing tests**

Create `tests/test_taint_pipeline.py`:

```python
"""Tests for taint analysis pipeline integration."""
from __future__ import annotations

import pytest

from sentinel.core.decision import PipelineContext, ToolCallRequest, Verdict
from sentinel.core.taint import TaintAnalysisCheck, TaintTracker


@pytest.fixture
def tracker() -> TaintTracker:
    return TaintTracker()


@pytest.fixture
def check(tracker: TaintTracker) -> TaintAnalysisCheck:
    return TaintAnalysisCheck(tracker=tracker)


def _make_request(
    tool_name: str,
    session_id: str = "s1",
) -> ToolCallRequest:
    return ToolCallRequest(
        agent_id="test-agent",
        session_id=session_id,
        tool_name=tool_name,
        tool_input={},
    )


async def test_clean_session_allows(
    check: TaintAnalysisCheck,
) -> None:
    request = _make_request("send_email")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.passed is True
    assert result.risk_contribution == 0.0


async def test_tainted_session_blocks_export(
    check: TaintAnalysisCheck,
    tracker: TaintTracker,
) -> None:
    tracker.scan_output("s1", "database_query", {"ssn": "111-22-3333"}, step=1)
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.passed is False
    assert result.force_verdict == Verdict.BLOCK
    assert result.risk_contribution == 35.0
    assert "pii" in result.reason.lower()


async def test_tainted_session_allows_non_sink(
    check: TaintAnalysisCheck,
    tracker: TaintTracker,
) -> None:
    tracker.scan_output("s1", "database_query", {"ssn": "111-22-3333"}, step=1)
    request = _make_request("read_file", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.passed is True


async def test_metadata_includes_taint_labels(
    check: TaintAnalysisCheck,
    tracker: TaintTracker,
) -> None:
    tracker.scan_output("s1", "db", {"ssn": "111-22-3333"}, step=1)
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert "taint_labels" in result.metadata
    assert "pii" in result.metadata["taint_labels"]
```

**Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_taint_pipeline.py -v`

**Step 3: Add TaintAnalysisCheck to taint.py**

Append to `sentinel/core/taint.py`:

```python
from sentinel.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
    Verdict,
)


class TaintAnalysisCheck:
    """Security check that blocks export of tainted data.

    Priority 35: runs after deterministic risk, before predictive risk.
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
        violations = self._tracker.check_export(
            request.session_id, request.tool_name
        )

        if not violations:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No taint violations.",
            )

        labels = sorted({v.label.value for v in violations})
        sources = sorted(
            {f"{v.source_tool} (step {v.source_step})" for v in violations}
        )

        return CheckResult(
            check_name=self.name,
            passed=False,
            risk_contribution=35.0,
            reason=(
                f"Tainted data export blocked: {', '.join(labels)} "
                f"data from {', '.join(sources)} "
                f"would be sent via {request.tool_name}"
            ),
            force_verdict=Verdict.BLOCK,
            metadata={
                "taint_labels": labels,
                "taint_sources": sources,
                "sink_tool": request.tool_name,
            },
        )
```

**Step 4: Wire TaintAnalysisCheck into Guardian pipeline**

Modify `sentinel/core/guardian.py`:

Add import at top:
```python
from sentinel.core.taint import TaintAnalysisCheck, TaintTracker
```

In `Guardian.__init__()`, add `taint_tracker` parameter and insert check:
```python
def __init__(self, ..., taint_tracker: TaintTracker | None = None, ...):
    self._taint_tracker = taint_tracker or TaintTracker()

    # In the checks list, after _DeterministicRiskCheck:
    checks.append(TaintAnalysisCheck(tracker=self._taint_tracker))
```

Expose the tracker as a property:
```python
@property
def taint_tracker(self) -> TaintTracker:
    return self._taint_tracker
```

**Step 5: Wire taint scanning into ChatAgent**

Modify `sentinel/web/agent.py`: after a tool is executed with ALLOW verdict, scan the output:

```python
if verdict.verdict == Verdict.ALLOW:
    result = await self._tool_executor.execute(block_name, block_input)
    # Scan output for sensitive data taints
    if self._guardian.taint_tracker:
        step = len(tool_calls) + 1
        self._guardian.taint_tracker.scan_output(
            self._session_id, block_name, result, step=step
        )
```

**Step 6: Run all tests**

Run: `.venv/bin/pytest tests/ -v`
Expected: All tests PASS (145 existing + 16 taint + 4 taint pipeline)

**Step 7: Commit**

```
feat: wire taint analysis into Guardian pipeline
```

---

## Phase 2: Predictive Risk (Backend)

### Task 3: PredictiveRiskCheck core

**Files:**
- Create: `sentinel/core/predictor.py`
- Create: `tests/test_predictor.py`

**Step 1: Write the failing tests**

Create `tests/test_predictor.py`:

```python
"""Tests for predictive risk lookahead."""
from __future__ import annotations

import pytest

from sentinel.core.decision import PipelineContext, ToolCallRequest
from sentinel.core.predictor import PredictiveRiskCheck, Prediction


@pytest.fixture
def check() -> PredictiveRiskCheck:
    return PredictiveRiskCheck()


def _make_request(
    tool_name: str,
    session_id: str = "s1",
    history: list[tuple[str, dict]] | None = None,
) -> ToolCallRequest:
    return ToolCallRequest(
        agent_id="test-agent",
        session_id=session_id,
        tool_name=tool_name,
        tool_input={},
    )


def _ctx_with_history(
    tool_names: list[str],
) -> PipelineContext:
    """Create context. History is tracked via the check itself."""
    return PipelineContext(session_risk_score=0.0)


async def test_no_prediction_on_first_call(
    check: PredictiveRiskCheck,
) -> None:
    request = _make_request("read_file")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.passed is True
    assert result.risk_contribution == 0.0


async def test_detects_data_exfiltration_trajectory(
    check: PredictiveRiskCheck,
) -> None:
    # Simulate session: read_file → database_query → (now send_email)
    check.record_tool("s1", "read_file")
    check.record_tool("s1", "database_query")
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution > 0
    assert "prediction" in result.metadata
    pred = result.metadata["prediction"]
    assert pred["trajectory_name"] == "data_exfiltration"


async def test_detects_financial_fraud_trajectory(
    check: PredictiveRiskCheck,
) -> None:
    check.record_tool("s1", "database_query")
    check.record_tool("s1", "database_query")
    request = _make_request("financial_transfer", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution > 0
    pred = result.metadata["prediction"]
    assert pred["trajectory_name"] == "financial_fraud"


async def test_benign_sequence_no_prediction(
    check: PredictiveRiskCheck,
) -> None:
    check.record_tool("s1", "read_file")
    request = _make_request("search_web", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution == 0.0


async def test_prediction_includes_advisory(
    check: PredictiveRiskCheck,
) -> None:
    check.record_tool("s1", "read_file")
    check.record_tool("s1", "database_query")
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    pred = result.metadata["prediction"]
    assert "advisory" in pred
    assert len(pred["advisory"]) > 0


async def test_sessions_are_isolated(
    check: PredictiveRiskCheck,
) -> None:
    check.record_tool("s1", "read_file")
    check.record_tool("s1", "database_query")
    request = _make_request("send_email", session_id="s2")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.risk_contribution == 0.0


async def test_does_not_force_verdict(
    check: PredictiveRiskCheck,
) -> None:
    """Predictive risk is advisory — never force-blocks."""
    check.record_tool("s1", "read_file")
    check.record_tool("s1", "database_query")
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.force_verdict is None


async def test_confidence_increases_with_more_matches(
    check: PredictiveRiskCheck,
) -> None:
    # 2 steps matched = higher confidence than 1
    check.record_tool("s1", "read_file")
    request1 = _make_request("database_query", session_id="s1")
    ctx1 = PipelineContext(session_risk_score=0.0)
    result1 = await check.evaluate(request1, ctx1)

    check.record_tool("s2", "read_file")
    check.record_tool("s2", "database_query")
    request2 = _make_request("send_email", session_id="s2")
    ctx2 = PipelineContext(session_risk_score=0.0)
    result2 = await check.evaluate(request2, ctx2)

    # More steps matched = higher risk contribution
    assert result2.risk_contribution >= result1.risk_contribution
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement PredictiveRiskCheck**

Create `sentinel/core/predictor.py`:

```python
"""Predictive risk with lookahead.

Analyzes session trajectory to predict dangerous next actions
and pre-emptively elevate risk scores.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.decision import (
    CheckResult,
    PipelineContext,
    ToolCallRequest,
)


@dataclass
class ThreatTrajectory:
    name: str
    tool_sequence: list[str]  # glob patterns
    risk_at_completion: float
    description: str


@dataclass
class Prediction:
    trajectory_name: str
    confidence: float
    current_step: int
    total_steps: int
    predicted_next: list[str]
    advisory: str


KNOWN_TRAJECTORIES: list[ThreatTrajectory] = [
    ThreatTrajectory(
        "data_exfiltration",
        ["read_*|search_*", "database_*|read_*", "send_*|api_call"],
        35.0,
        "Agent gathering data then attempting to export it",
    ),
    ThreatTrajectory(
        "financial_fraud",
        ["database_*|read_*", "database_*|read_*", "financial_*"],
        40.0,
        "Agent querying financial data then attempting transfer",
    ),
    ThreatTrajectory(
        "code_injection",
        ["read_*", "execute_code", "write_*|api_call"],
        30.0,
        "Agent reading code, executing, then writing/sending results",
    ),
    ThreatTrajectory(
        "credential_theft",
        ["read_*|search_*", "read_*|database_*", "api_call|send_*"],
        35.0,
        "Agent searching for credentials then sending externally",
    ),
    ThreatTrajectory(
        "recon_and_exploit",
        [
            "search_*",
            "read_*|database_*",
            "execute_code",
            "api_call|send_*",
        ],
        35.0,
        "Full attack chain: recon, read, exploit, exfil",
    ),
]


def _tool_matches_pattern(tool_name: str, pattern: str) -> bool:
    """Check if tool matches a pipe-separated glob pattern."""
    return any(
        fnmatch.fnmatch(tool_name, p.strip())
        for p in pattern.split("|")
    )


class PredictiveRiskCheck:
    """Predicts dangerous trajectories based on session history.

    Priority 38: runs after taint analysis, before drift detection.
    Advisory only — never force-blocks.
    """

    name: str = "predictive_risk"
    priority: int = 38

    def __init__(self) -> None:
        self._session_tools: dict[str, list[str]] = {}

    def record_tool(self, session_id: str, tool_name: str) -> None:
        """Record a tool call in session history for prediction."""
        if session_id not in self._session_tools:
            self._session_tools[session_id] = []
        self._session_tools[session_id].append(tool_name)

    def get_session_tools(self, session_id: str) -> list[str]:
        return list(self._session_tools.get(session_id, []))

    async def evaluate(
        self,
        request: ToolCallRequest,
        context: PipelineContext,
    ) -> CheckResult:
        history = self.get_session_tools(request.session_id)
        # Include the current tool in the sequence
        current_sequence = [*history, request.tool_name]

        best_match: Prediction | None = None
        best_confidence = 0.0

        for trajectory in KNOWN_TRAJECTORIES:
            prediction = self._match_trajectory(
                current_sequence, trajectory
            )
            if prediction and prediction.confidence > best_confidence:
                best_match = prediction
                best_confidence = prediction.confidence

        if best_match is None or best_confidence < 0.3:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No threatening trajectory detected.",
            )

        # Risk proportional to confidence and trajectory danger
        trajectory = next(
            t
            for t in KNOWN_TRAJECTORIES
            if t.name == best_match.trajectory_name
        )
        risk = (
            best_match.confidence
            * trajectory.risk_at_completion
            * 0.4
        )

        return CheckResult(
            check_name=self.name,
            passed=True,  # Advisory only
            risk_contribution=risk,
            reason=(
                f"Threat trajectory '{best_match.trajectory_name}'"
                f" detected ({best_match.confidence:.0%} confidence)."
                f" {best_match.advisory}"
            ),
            force_verdict=None,  # Never force-blocks
            metadata={
                "prediction": {
                    "trajectory_name": best_match.trajectory_name,
                    "confidence": best_match.confidence,
                    "current_step": best_match.current_step,
                    "total_steps": best_match.total_steps,
                    "predicted_next": best_match.predicted_next,
                    "advisory": best_match.advisory,
                },
            },
        )

    def _match_trajectory(
        self,
        tool_sequence: list[str],
        trajectory: ThreatTrajectory,
    ) -> Prediction | None:
        """Match tool sequence against a trajectory pattern."""
        pattern = trajectory.tool_sequence
        seq_len = len(tool_sequence)
        pat_len = len(pattern)

        if seq_len == 0:
            return None

        # Find how many consecutive pattern steps match
        # from the end of the sequence
        matched = 0
        seq_idx = seq_len - 1
        pat_idx = min(seq_len, pat_len) - 1

        # Try matching from end of sequence backward
        for pi in range(min(seq_len, pat_len)):
            si = seq_len - 1 - pi
            pat_step = pattern[min(seq_len, pat_len) - 1 - pi]
            if _tool_matches_pattern(tool_sequence[si], pat_step):
                matched += 1
            else:
                break

        if matched < 2:
            return None

        confidence = matched / pat_len
        current_step = matched
        predicted_next: list[str] = []

        if matched < pat_len:
            next_pattern = pattern[matched]
            predicted_next = [
                p.strip() for p in next_pattern.split("|")
            ]

        return Prediction(
            trajectory_name=trajectory.name,
            confidence=confidence,
            current_step=current_step,
            total_steps=pat_len,
            predicted_next=predicted_next,
            advisory=(
                f"Agent may attempt "
                f"{', '.join(predicted_next) if predicted_next else 'completion'}"
                f" next. {trajectory.description}."
            ),
        )
```

**Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_predictor.py -v`
Expected: All PASS

**Step 5: Wire into Guardian**

Modify `sentinel/core/guardian.py`: import `PredictiveRiskCheck` and add to pipeline between TaintAnalysis and DriftDetector. Store on `self._predictor`. After tool call recording, also call `self._predictor.record_tool()`.

**Step 6: Run full test suite + linting**

**Step 7: Commit**

```
feat: add predictive risk lookahead check
```

---

## Phase 3: Cryptographic Proof Chain (Backend)

### Task 4: ProofChain core

**Files:**
- Create: `sentinel/core/proof.py`
- Create: `tests/test_proof.py`

**Step 1: Write the failing tests**

Create `tests/test_proof.py`:

```python
"""Tests for cryptographic proof chain."""
from __future__ import annotations

import json

import pytest

from sentinel.core.proof import ProofChain, ProofNode


@pytest.fixture
def chain() -> ProofChain:
    return ProofChain()


def test_empty_chain(chain: ProofChain) -> None:
    assert chain.get_chain("s1") == []


def test_add_single_node(chain: ProofChain) -> None:
    chain.add(
        session_id="s1",
        agent_id="agent-1",
        tool_name="read_file",
        tool_input={"path": "/etc/config"},
        verdict="allow",
        risk_score=2.0,
        risk_delta=2.0,
    )
    nodes = chain.get_chain("s1")
    assert len(nodes) == 1
    assert nodes[0].step == 1
    assert nodes[0].tool_name == "read_file"
    assert nodes[0].verdict == "allow"
    assert nodes[0].parent_hash == ""


def test_chain_links_parent_hash(chain: ProofChain) -> None:
    chain.add(session_id="s1", agent_id="a", tool_name="read_file",
              tool_input={}, verdict="allow", risk_score=2.0, risk_delta=2.0)
    chain.add(session_id="s1", agent_id="a", tool_name="send_email",
              tool_input={}, verdict="block", risk_score=37.0, risk_delta=35.0)
    nodes = chain.get_chain("s1")
    assert len(nodes) == 2
    assert nodes[1].parent_hash == nodes[0].node_id
    assert nodes[0].parent_hash == ""


def test_verify_valid_chain(chain: ProofChain) -> None:
    chain.add(session_id="s1", agent_id="a", tool_name="t1",
              tool_input={}, verdict="allow", risk_score=5.0, risk_delta=5.0)
    chain.add(session_id="s1", agent_id="a", tool_name="t2",
              tool_input={"x": 1}, verdict="block", risk_score=40.0, risk_delta=35.0)
    chain.add(session_id="s1", agent_id="a", tool_name="t3",
              tool_input={}, verdict="allow", risk_score=42.0, risk_delta=2.0)
    assert chain.verify("s1") is True


def test_verify_empty_chain(chain: ProofChain) -> None:
    assert chain.verify("nonexistent") is True


def test_verify_detects_tampering(chain: ProofChain) -> None:
    chain.add(session_id="s1", agent_id="a", tool_name="t1",
              tool_input={}, verdict="allow", risk_score=5.0, risk_delta=5.0)
    chain.add(session_id="s1", agent_id="a", tool_name="t2",
              tool_input={}, verdict="block", risk_score=40.0, risk_delta=35.0)
    # Tamper with the first node's verdict
    nodes = chain.get_chain("s1")
    nodes[0].verdict = "block"  # TAMPERED
    assert chain.verify("s1") is False


def test_export_returns_json(chain: ProofChain) -> None:
    chain.add(session_id="s1", agent_id="a", tool_name="t1",
              tool_input={}, verdict="allow", risk_score=5.0, risk_delta=5.0)
    exported = chain.export("s1")
    data = json.loads(exported)
    assert isinstance(data, list)
    assert len(data) == 1
    assert "node_id" in data[0]
    assert "parent_hash" in data[0]


def test_sessions_isolated(chain: ProofChain) -> None:
    chain.add(session_id="s1", agent_id="a", tool_name="t1",
              tool_input={}, verdict="allow", risk_score=5.0, risk_delta=5.0)
    chain.add(session_id="s2", agent_id="b", tool_name="t2",
              tool_input={}, verdict="block", risk_score=40.0, risk_delta=40.0)
    assert len(chain.get_chain("s1")) == 1
    assert len(chain.get_chain("s2")) == 1


def test_node_id_is_deterministic(chain: ProofChain) -> None:
    """Same input should produce the same hash."""
    chain.add(session_id="s1", agent_id="a", tool_name="t1",
              tool_input={"k": "v"}, verdict="allow", risk_score=5.0, risk_delta=5.0)
    node = chain.get_chain("s1")[0]
    assert len(node.node_id) == 64  # SHA-256 hex
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement ProofChain**

Create `sentinel/core/proof.py`:

```python
"""Cryptographic proof chain for tamper-evident audit trails.

Each security verdict produces a ProofNode linked to the previous
via SHA-256 hashes, forming a Merkle chain.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ProofNode:
    node_id: str
    parent_hash: str
    step: int
    timestamp: str
    session_id: str
    agent_id: str
    tool_name: str
    tool_input: dict[str, Any]
    verdict: str
    risk_score: float
    risk_delta: float
    content_hash: str


def _compute_content_hash(
    tool_name: str,
    tool_input: dict[str, Any],
    verdict: str,
    risk_score: float,
    risk_delta: float,
) -> str:
    """Hash the core verdict content."""
    payload = json.dumps(
        {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_delta": risk_delta,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_node_id(
    content_hash: str,
    parent_hash: str,
    step: int,
    timestamp: str,
    session_id: str,
    agent_id: str,
) -> str:
    """Hash everything to produce the node ID."""
    payload = json.dumps(
        {
            "content_hash": content_hash,
            "parent_hash": parent_hash,
            "step": step,
            "timestamp": timestamp,
            "session_id": session_id,
            "agent_id": agent_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class ProofChain:
    """Per-session chain of cryptographically linked proof nodes."""

    def __init__(self) -> None:
        self._chains: dict[str, list[ProofNode]] = {}

    def add(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        verdict: str,
        risk_score: float,
        risk_delta: float,
    ) -> ProofNode:
        """Append a new node to the session's proof chain."""
        if session_id not in self._chains:
            self._chains[session_id] = []

        chain = self._chains[session_id]
        parent_hash = chain[-1].node_id if chain else ""
        step = len(chain) + 1
        timestamp = datetime.now(UTC).isoformat()

        content_hash = _compute_content_hash(
            tool_name, tool_input, verdict, risk_score, risk_delta
        )
        node_id = _compute_node_id(
            content_hash, parent_hash, step, timestamp,
            session_id, agent_id,
        )

        node = ProofNode(
            node_id=node_id,
            parent_hash=parent_hash,
            step=step,
            timestamp=timestamp,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_input=tool_input,
            verdict=verdict,
            risk_score=risk_score,
            risk_delta=risk_delta,
            content_hash=content_hash,
        )
        chain.append(node)
        return node

    def get_chain(self, session_id: str) -> list[ProofNode]:
        return self._chains.get(session_id, [])

    def verify(self, session_id: str) -> bool:
        """Walk the chain and verify all hashes are intact."""
        chain = self.get_chain(session_id)
        if not chain:
            return True

        for i, node in enumerate(chain):
            # Verify parent linkage
            expected_parent = chain[i - 1].node_id if i > 0 else ""
            if node.parent_hash != expected_parent:
                return False

            # Recompute content hash
            expected_content = _compute_content_hash(
                node.tool_name, node.tool_input,
                node.verdict, node.risk_score, node.risk_delta,
            )
            if node.content_hash != expected_content:
                return False

            # Recompute node ID
            expected_id = _compute_node_id(
                node.content_hash, node.parent_hash,
                node.step, node.timestamp,
                node.session_id, node.agent_id,
            )
            if node.node_id != expected_id:
                return False

        return True

    def export(self, session_id: str) -> str:
        """Export chain as JSON for auditors."""
        chain = self.get_chain(session_id)
        return json.dumps(
            [
                {
                    "node_id": n.node_id,
                    "parent_hash": n.parent_hash,
                    "step": n.step,
                    "timestamp": n.timestamp,
                    "session_id": n.session_id,
                    "agent_id": n.agent_id,
                    "tool_name": n.tool_name,
                    "tool_input": n.tool_input,
                    "verdict": n.verdict,
                    "risk_score": n.risk_score,
                    "risk_delta": n.risk_delta,
                    "content_hash": n.content_hash,
                }
                for n in chain
            ],
            indent=2,
        )
```

**Step 4: Run tests, linting**

**Step 5: Wire into Guardian as post-pipeline hook + add API endpoints**

Modify `sentinel/core/guardian.py`: after building SecurityVerdict, call `self._proof_chain.add(...)`.

Modify `sentinel/web/app.py`: add `GET /api/sessions/{session_id}/proof` and `POST /api/sessions/{session_id}/proof/verify` endpoints.

**Step 6: Commit**

```
feat: add cryptographic proof chain with tamper detection
```

---

## Phase 4: Collaborative Threat Intelligence (Backend)

### Task 5: ThreatIntelDB + ThreatIntelCheck

**Files:**
- Create: `sentinel/core/threat_intel.py`
- Create: `tests/test_threat_intel.py`

**Step 1: Write the failing tests**

Create `tests/test_threat_intel.py` with tests for:
- Built-in patterns loaded on init
- Matching current session against patterns
- Learning new pattern from blocked session
- Pattern times_seen increments on repeat matches
- Sessions isolated
- get_all_patterns returns all
- get_stats returns counts
- ThreatIntelCheck adds risk when pattern matches
- ThreatIntelCheck returns 0 risk when no match

**Step 2: Implement ThreatIntelDB + ThreatIntelCheck**

Create `sentinel/core/threat_intel.py` with:
- `ThreatPattern` dataclass
- `ThreatIntelDB` with built-in patterns, match(), learn_from_session(), get_all_patterns(), get_stats()
- `ThreatIntelCheck(SecurityCheck, priority=55)`

**Step 3: Wire into Guardian pipeline**

**Step 4: Add API endpoints**: `GET /api/threat-intel`, `GET /api/threat-intel/stats`

**Step 5: Add pattern learning trigger**: after Guardian returns BLOCK with risk >= 80, call `threat_intel_db.learn_from_session()`

**Step 6: Run all tests + linting**

**Step 7: Commit**

```
feat: add collaborative threat intelligence with pattern learning
```

---

## Phase 5: Extend SecurityEvent Data for Frontend

### Task 6: Extend WebSocket event data

**Files:**
- Modify: `sentinel/web/agent.py` (add taint, prediction, proof data to events)
- Modify: `sentinel/web/schemas.py` (add new response fields if needed)

Add to SecurityEvent data dict:
```python
"taint_labels": [...],
"taint_violations": [...],
"prediction": {trajectory_name, confidence, predicted_next, advisory},
"proof_node": {node_id, parent_hash, step},
"threat_intel_matches": [...],
```

**Commit:**
```
feat: extend WebSocket events with taint/prediction/proof data
```

---

## Phase 6: Frontend — Taint Flow Panel

### Task 7: TaintFlowPanel component

**Files:**
- Create: `frontend/src/components/TaintFlowPanel.tsx`

Build a vertical flow diagram that:
- Shows each tool call as a node
- Colors nodes by verdict (green=allow, red=block)
- Shows taint label chips (PII=orange, CREDENTIALS=red, FINANCIAL=amber, INTERNAL=blue)
- Draws connecting lines between source and sink tools
- Animates red pulse when a taint violation blocks a tool
- Header shows active taints count

**Commit:**
```
feat: add TaintFlowPanel frontend component
```

---

## Phase 7: Frontend — Threat Forecast Card

### Task 8: ThreatForecast component

**Files:**
- Modify: `frontend/src/components/SecurityDashboard.tsx` (add forecast card)

Add below the risk gauge:
- Trajectory name
- Confidence progress bar
- Predicted next tool(s)
- Advisory text
- Only shows when a prediction exists

**Commit:**
```
feat: add threat forecast card to SecurityDashboard
```

---

## Phase 8: Frontend — Proof Chain Tab

### Task 9: ProofChainPanel component

**Files:**
- Create: `frontend/src/components/ProofChainPanel.tsx`

Build a vertical chain visualization:
- Each block shows: step#, tool→verdict, truncated hash, parent link
- Blocks connect with vertical lines
- Header: chain length + verified badge
- "Verify Chain" button → calls API, shows animated verification
- "Export JSON" button → downloads proof chain

**Commit:**
```
feat: add ProofChainPanel frontend component
```

---

## Phase 9: Frontend — Threat Intel Tab

### Task 10: ThreatIntelPanel component

**Files:**
- Create: `frontend/src/components/ThreatIntelPanel.tsx`

Build a pattern library view:
- Cards for each known pattern
- Severity color coding
- Tool sequence display
- Confidence + times_seen
- Source badge (built_in vs learned)
- Live match indicator at bottom

**Commit:**
```
feat: add ThreatIntelPanel frontend component
```

---

## Phase 10: Frontend — Layout Restructure

### Task 11: Restructure page.tsx for 4-panel + tabs

**Files:**
- Modify: `frontend/src/app/page.tsx`
- Modify: `frontend/src/components/PipelineDetail.tsx` (wrap in tab)

Change grid from `grid-cols-[35%_35%_30%]` to `grid-cols-[25%_25%_25%_25%]`.

Right panel becomes tabbed: [Pipeline] [Proof Chain] [Threat Intel]

Add taint/prediction/proof/threat data to session state and pass through.

Update header with threat count.

**Commit:**
```
feat: restructure frontend for 4-panel layout with tabs
```

---

## Phase 11: Final Verification

### Task 12: Full verification pass

**Steps:**
1. `.venv/bin/pytest tests/ -v` — all tests pass
2. `.venv/bin/ruff check sentinel/` — clean
3. `.venv/bin/mypy sentinel/ --ignore-missing-imports` — clean
4. `cd frontend && npm run build` — clean
5. Verify all existing 145 tests still pass
6. Count total tests (target: 145 + ~50 new = ~195+)

**Commit:**
```
chore: final verification — all tests and builds pass
```

---

## Summary

| Phase | Task | New Files | Tests |
|-------|------|-----------|-------|
| 1 | Taint core | sentinel/core/taint.py | ~16 |
| 1 | Taint pipeline | (modify guardian) | ~4 |
| 2 | Predictive risk | sentinel/core/predictor.py | ~8 |
| 3 | Proof chain | sentinel/core/proof.py | ~9 |
| 4 | Threat intel | sentinel/core/threat_intel.py | ~10 |
| 5 | Event extension | (modify agent.py) | 0 |
| 6 | TaintFlowPanel | frontend component | 0 |
| 7 | ThreatForecast | frontend component | 0 |
| 8 | ProofChainPanel | frontend component | 0 |
| 9 | ThreatIntelPanel | frontend component | 0 |
| 10 | Layout restructure | (modify page.tsx) | 0 |
| 11 | Verification | — | verify all |

Total estimated new tests: ~47
Total tests after: ~192+
