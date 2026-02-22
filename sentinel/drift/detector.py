from __future__ import annotations

from sentinel.core.decision import CheckResult, PipelineContext, ToolCallRequest, Verdict
from sentinel.llm.classifier import SecurityClassifier


class SemanticDriftDetector:
    """Compares the user's original goal with the agent's current action.

    Uses Claude Haiku for semantic comparison, providing both a drift_score
    and natural-language reasoning.
    """

    name: str = "semantic_drift"
    priority: int = 40

    def __init__(
        self,
        classifier: SecurityClassifier,
        threshold: float = 0.6,
        max_risk_contribution: float = 40.0,
    ) -> None:
        self._classifier = classifier
        self._threshold = threshold
        self._max_risk_contribution = max_risk_contribution

    async def evaluate(
        self, request: ToolCallRequest, context: PipelineContext
    ) -> CheckResult:
        if not request.original_goal:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason="No original goal set; drift detection skipped.",
            )

        drift_result = await self._classifier.classify_drift(
            original_goal=request.original_goal,
            tool_name=request.tool_name,
            tool_input=request.tool_input,
            conversation_history=request.conversation_history,
        )

        risk_contribution = drift_result.drift_score * self._max_risk_contribution
        is_drifting = drift_result.drift_score >= self._threshold

        return CheckResult(
            check_name=self.name,
            passed=not is_drifting,
            risk_contribution=risk_contribution,
            reason=drift_result.explanation,
            force_verdict=Verdict.PAUSE if is_drifting else None,
            metadata={
                "drift_score": drift_result.drift_score,
                "original_goal_summary": drift_result.original_goal_summary,
                "current_action_summary": drift_result.current_action_summary,
            },
        )
