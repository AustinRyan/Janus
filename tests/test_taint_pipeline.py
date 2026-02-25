"""Tests for taint analysis pipeline integration."""
from __future__ import annotations

import pytest

from janus.core.decision import (
    PipelineContext,
    ToolCallRequest,
    Verdict,
)
from janus.core.taint import TaintAnalysisCheck, TaintTracker


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
    tracker.scan_output(
        "s1", "database_query", {"ssn": "111-22-3333"}, step=1
    )
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
    tracker.scan_output(
        "s1", "database_query", {"ssn": "111-22-3333"}, step=1
    )
    request = _make_request("read_file", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.passed is True


async def test_metadata_includes_taint_labels(
    check: TaintAnalysisCheck,
    tracker: TaintTracker,
) -> None:
    tracker.scan_output(
        "s1", "db", {"ssn": "111-22-3333"}, step=1
    )
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert "taint_labels" in result.metadata
    assert "pii" in result.metadata["taint_labels"]
