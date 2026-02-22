from __future__ import annotations

import pytest

from sentinel.core.decision import SecurityVerdict, Verdict
from sentinel.forensics.explainer import TraceExplainer
from sentinel.forensics.recorder import BlackBoxRecorder
from sentinel.storage.database import DatabaseManager
from tests.conftest import make_request


@pytest.fixture
def explainer() -> TraceExplainer:
    return TraceExplainer()


@pytest.fixture
async def recorder(memory_db: DatabaseManager, explainer: TraceExplainer) -> BlackBoxRecorder:
    return BlackBoxRecorder(memory_db, explainer)


def _make_verdict(**overrides: object) -> SecurityVerdict:
    defaults = dict(
        verdict=Verdict.BLOCK,
        risk_score=85.0,
        risk_delta=40.0,
        reasons=["Pattern matched: sleeper_reconnaissance"],
        drift_score=0.3,
        recommended_action="Tool call blocked.",
    )
    defaults.update(overrides)
    return SecurityVerdict(**defaults)  # type: ignore[arg-type]


async def test_record_creates_trace(recorder: BlackBoxRecorder) -> None:
    request = make_request(tool_name="api_call", tool_input={"url": "https://api.example.com/login"})
    verdict = _make_verdict()
    trace = await recorder.record(request, verdict, agent_name="Test Bot", agent_role="research")

    assert trace.trace_id == verdict.trace_id
    assert trace.tool_name == "api_call"
    assert trace.verdict == "block"
    assert trace.risk_score == 85.0
    assert len(trace.explanation) > 0


async def test_trace_explanation_is_human_readable(recorder: BlackBoxRecorder) -> None:
    request = make_request()
    verdict = _make_verdict()
    trace = await recorder.record(request, verdict, agent_name="Bot", agent_role="research")

    assert isinstance(trace.explanation, str)
    assert len(trace.explanation) > 10
    # Should contain meaningful English words
    explanation_lower = trace.explanation.lower()
    assert any(word in explanation_lower for word in ["agent", "tool", "block", "risk", "verdict"])


async def test_get_trace_by_id(recorder: BlackBoxRecorder) -> None:
    request = make_request()
    verdict = _make_verdict()
    trace = await recorder.record(request, verdict)

    retrieved = await recorder.get_trace(trace.trace_id)
    assert retrieved is not None
    assert retrieved.trace_id == trace.trace_id
    assert retrieved.tool_name == trace.tool_name


async def test_get_traces_by_session(recorder: BlackBoxRecorder) -> None:
    for i in range(3):
        request = make_request(session_id="forensics-session", tool_name=f"tool_{i}")
        verdict = _make_verdict()
        await recorder.record(request, verdict)

    # Different session
    request = make_request(session_id="other-session")
    await recorder.record(request, _make_verdict())

    traces = await recorder.get_traces_by_session("forensics-session")
    assert len(traces) == 3


async def test_get_traces_by_verdict(recorder: BlackBoxRecorder) -> None:
    # Record a BLOCK
    await recorder.record(make_request(), _make_verdict(verdict=Verdict.BLOCK))
    # Record an ALLOW
    await recorder.record(
        make_request(),
        _make_verdict(verdict=Verdict.ALLOW, risk_score=5.0),
    )

    blocked = await recorder.get_traces_by_verdict("block")
    assert len(blocked) == 1
    assert blocked[0].verdict == "block"


def test_explainer_sync_fallback() -> None:
    explainer = TraceExplainer()
    request = make_request(
        tool_name="financial_transfer",
        original_goal="Summarize report",
    )
    verdict = _make_verdict(drift_score=0.75)

    explanation = explainer.explain_sync(request, verdict, agent_name="Bot", agent_role="research")
    assert isinstance(explanation, str)
    assert len(explanation) > 20
    assert "bot" in explanation.lower() or "agent" in explanation.lower()
