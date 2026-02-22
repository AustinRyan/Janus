from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sentinel.core.decision import PipelineContext, Verdict
from sentinel.drift.detector import SemanticDriftDetector
from sentinel.llm.classifier import DriftResult
from tests.conftest import make_request


@pytest.fixture
def mock_classifier() -> AsyncMock:
    classifier = AsyncMock()
    classifier.classify_drift.return_value = DriftResult(
        drift_score=0.1,
        explanation="Action is aligned with goal",
        original_goal_summary="Summarize document",
        current_action_summary="Reading document",
    )
    return classifier


@pytest.fixture
def detector(mock_classifier: AsyncMock) -> SemanticDriftDetector:
    return SemanticDriftDetector(mock_classifier, threshold=0.6)


async def test_no_drift_when_aligned(
    detector: SemanticDriftDetector, mock_classifier: AsyncMock
) -> None:
    request = make_request(original_goal="Summarize the quarterly report")
    context = PipelineContext()

    result = await detector.evaluate(request, context)

    assert result.passed is True
    assert result.force_verdict is None
    assert result.risk_contribution < 10


async def test_drift_detected_when_misaligned(
    detector: SemanticDriftDetector, mock_classifier: AsyncMock
) -> None:
    mock_classifier.classify_drift.return_value = DriftResult(
        drift_score=0.85,
        explanation="Agent was summarizing PDFs but is now requesting API keys",
        original_goal_summary="Summarize quarterly report",
        current_action_summary="Request external API key",
    )
    request = make_request(
        original_goal="Summarize quarterly report",
        tool_name="api_call",
        tool_input={"action": "get_api_key"},
    )
    context = PipelineContext()

    result = await detector.evaluate(request, context)

    assert result.passed is False
    assert result.force_verdict == Verdict.PAUSE
    assert result.risk_contribution == pytest.approx(34.0, abs=0.1)
    assert result.metadata["drift_score"] == 0.85


async def test_drift_skipped_when_no_goal(
    detector: SemanticDriftDetector,
) -> None:
    request = make_request(original_goal="")
    context = PipelineContext()

    result = await detector.evaluate(request, context)

    assert result.passed is True
    assert result.risk_contribution == 0.0
    assert "skipped" in result.reason.lower()


async def test_moderate_drift_does_not_pause(
    detector: SemanticDriftDetector, mock_classifier: AsyncMock
) -> None:
    mock_classifier.classify_drift.return_value = DriftResult(
        drift_score=0.45,
        explanation="Tangentially related action",
        original_goal_summary="Research topic",
        current_action_summary="Looking up related term",
    )
    request = make_request(original_goal="Research AI safety")
    context = PipelineContext()

    result = await detector.evaluate(request, context)

    assert result.passed is True
    assert result.force_verdict is None
    assert result.risk_contribution == pytest.approx(18.0, abs=0.1)
