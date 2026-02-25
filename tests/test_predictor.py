"""Tests for predictive risk lookahead."""
from __future__ import annotations

import pytest

from janus.core.decision import PipelineContext, ToolCallRequest
from janus.core.predictor import PredictiveRiskCheck


@pytest.fixture
def check() -> PredictiveRiskCheck:
    return PredictiveRiskCheck()


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
    request = _make_request(
        "financial_transfer", session_id="s1"
    )
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
    """Predictive risk is advisory -- never force-blocks."""
    check.record_tool("s1", "read_file")
    check.record_tool("s1", "database_query")
    request = _make_request("send_email", session_id="s1")
    ctx = PipelineContext(session_risk_score=0.0)
    result = await check.evaluate(request, ctx)
    assert result.force_verdict is None


async def test_confidence_increases_with_more_matches(
    check: PredictiveRiskCheck,
) -> None:
    check.record_tool("s1", "read_file")
    request1 = _make_request(
        "database_query", session_id="s1"
    )
    ctx1 = PipelineContext(session_risk_score=0.0)
    result1 = await check.evaluate(request1, ctx1)

    check.record_tool("s2", "read_file")
    check.record_tool("s2", "database_query")
    request2 = _make_request("send_email", session_id="s2")
    ctx2 = PipelineContext(session_risk_score=0.0)
    result2 = await check.evaluate(request2, ctx2)

    assert result2.risk_contribution >= result1.risk_contribution
