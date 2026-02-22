from __future__ import annotations

from sentinel.core.decision import SecurityVerdict, ToolCallRequest
from sentinel.llm.classifier import SecurityClassifier


class TraceExplainer:
    """Generates human-readable explanations for security events."""

    def __init__(self, classifier: SecurityClassifier | None = None) -> None:
        self._classifier = classifier

    async def explain(
        self,
        request: ToolCallRequest,
        verdict: SecurityVerdict,
        agent_name: str,
        agent_role: str,
    ) -> str:
        """Generate an explanation, using LLM if available, falling back to rules."""
        if self._classifier is not None:
            try:
                return await self._classifier.explain_trace(
                    agent_name=agent_name,
                    agent_role=agent_role,
                    tool_name=request.tool_name,
                    tool_input=request.tool_input,
                    original_goal=request.original_goal,
                    verdict=verdict.verdict.value,
                    risk_score=verdict.risk_score,
                    drift_score=verdict.drift_score,
                    reasons=verdict.reasons,
                    itdr_signals=verdict.itdr_signals,
                )
            except Exception:
                # Fall through to rule-based explanation on any LLM failure
                pass

        return self._rule_based_explanation(request, verdict, agent_name, agent_role)

    def explain_sync(
        self,
        request: ToolCallRequest,
        verdict: SecurityVerdict,
        agent_name: str,
        agent_role: str,
    ) -> str:
        """Synchronous rule-based explanation (no LLM)."""
        return self._rule_based_explanation(request, verdict, agent_name, agent_role)

    def _rule_based_explanation(
        self,
        request: ToolCallRequest,
        verdict: SecurityVerdict,
        agent_name: str,
        agent_role: str,
    ) -> str:
        parts: list[str] = []

        parts.append(
            f"Agent '{agent_name}' ({agent_role}) attempted to call '{request.tool_name}'. "
            f"Verdict: {verdict.verdict.value}. Risk score: {verdict.risk_score}/100."
        )

        if verdict.drift_score is not None and verdict.drift_score > 0.5:
            parts.append(
                f"Significant drift detected from original goal: '{request.original_goal}'."
            )

        if verdict.verdict.value == "block":
            parts.append(
                "Recommended action: Review agent behavior and consider revoking permissions."
            )
        elif verdict.verdict.value == "pause":
            parts.append(
                "Recommended action: Human review required before agent can continue."
            )

        return " ".join(parts)
