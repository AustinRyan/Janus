from __future__ import annotations

from fnmatch import fnmatch

from janus.core.decision import CheckResult, PipelineContext, ToolCallRequest, Verdict
from janus.identity.agent import AgentRole
from janus.llm.classifier import SecurityClassifier
from janus.risk import thresholds


def _has_wildcard_permissions(agent_identity) -> bool:
    """Check if the agent has wildcard (*) permissions."""
    if agent_identity is None:
        return False
    return any(
        fnmatch("anything", p.tool_pattern)
        for p in agent_identity.permissions
    )


class SemanticDriftDetector:
    """Compares the user's original goal with the agent's current action.

    Uses Claude Haiku for semantic comparison, providing both a drift_score
    and natural-language reasoning.

    Read-only tools (read_file, search_web, list_files, send_message) never
    produce risk or PAUSE verdicts from drift alone — an agent reading files
    and searching the web is normal exploratory behaviour.  Drift risk only
    materialises when the agent tries to *act* (execute_code, write_file,
    api_call, etc.) while drifting from the goal.

    Admin agents with wildcard permissions get reduced drift penalties because
    admin work naturally spans many unrelated tasks.
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

        # Extract agent role and permissions for the LLM prompt
        agent = context.agent_identity
        agent_role = agent.role.value if agent else "unknown"
        agent_permissions = (
            ", ".join(p.tool_pattern for p in agent.permissions)
            if agent
            else "unknown"
        )

        drift_result = await self._classifier.classify_drift(
            original_goal=request.original_goal,
            tool_name=request.tool_name,
            tool_input=request.tool_input,
            conversation_history=request.conversation_history,
            agent_role=agent_role,
            agent_permissions=agent_permissions,
        )

        is_drifting = drift_result.drift_score >= self._threshold
        is_action_tool = request.tool_name in thresholds.KEYWORD_SENSITIVE_TOOLS
        is_admin = agent is not None and (
            agent.role == AgentRole.ADMIN or _has_wildcard_permissions(agent)
        )

        # Read-only tools (read_file, search_web, list_files, …) never
        # accumulate drift risk or trigger PAUSE.  Browsing different
        # topics is normal behaviour — risk only matters when the agent
        # tries to *do* something while off-goal.
        if not is_action_tool:
            return CheckResult(
                check_name=self.name,
                passed=True,
                risk_contribution=0.0,
                reason=(
                    f"Drift score {drift_result.drift_score:.2f} "
                    f"(read-only tool '{request.tool_name}'; "
                    "risk deferred to action tools)."
                ),
                metadata={
                    "drift_score": drift_result.drift_score,
                    "original_goal_summary": drift_result.original_goal_summary,
                    "current_action_summary": drift_result.current_action_summary,
                },
            )

        # Agents using tools they are AUTHORIZED for get reduced drift
        # penalties.  Developers running code, researchers reading files,
        # admins doing system checks — these are agents using their tools
        # as intended.  Drift risk should only escalate when the action
        # itself is dangerous, not just off-topic.
        has_permission = agent is not None and any(
            fnmatch(request.tool_name, p.tool_pattern)
            for p in agent.permissions
        )

        if is_admin:
            # Admin: 25% of normal drift risk, PAUSE only at 0.85+
            is_drifting = drift_result.drift_score >= 0.85
            if drift_result.drift_score < 0.5:
                risk_contribution = 0.0
            else:
                risk_contribution = (
                    drift_result.drift_score
                    * self._max_risk_contribution
                    * 0.25
                )
        elif has_permission:
            # Authorized non-admin: 40% of normal drift risk, PAUSE at 0.75+
            # An agent using tools it has permission for is doing its job.
            is_drifting = drift_result.drift_score >= 0.75
            if drift_result.drift_score < 0.4:
                risk_contribution = 0.0
            else:
                risk_contribution = (
                    drift_result.drift_score
                    * self._max_risk_contribution
                    * 0.4
                )
        else:
            # Unauthorized: full drift risk, standard threshold
            if drift_result.drift_score < 0.3:
                risk_contribution = 0.0
            else:
                risk_contribution = (
                    drift_result.drift_score * self._max_risk_contribution
                )

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
