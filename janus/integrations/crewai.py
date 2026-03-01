"""CrewAI integration adapter for Janus.

Usage::

    from janus.integrations.crewai import JanusCrewTool

    tool = JanusCrewTool(
        name="search", description="Search the web",
        fn=my_search_function,
        guardian=guardian, agent_id="agent-1", session_id="s-1",
    )
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from janus.core.approval import ApprovalManager, needs_human_review
from janus.core.decision import Verdict
from janus.core.guardian import Guardian

logger = structlog.get_logger()


class JanusCrewTool:
    """A CrewAI-compatible tool that intercepts calls with Guardian."""

    def __init__(
        self,
        name: str,
        description: str,
        fn: Callable[..., Awaitable[str]],
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
        approval_manager: ApprovalManager | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self._fn = fn
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._original_goal = original_goal
        self._approval_manager = approval_manager

    async def run(self, tool_input: dict[str, Any]) -> str:
        """Execute with Guardian interception."""
        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=self.name,
            tool_input=tool_input,
        )

        if verdict.verdict == Verdict.ALLOW:
            return await self._fn(**tool_input)

        # Check if this needs human review
        approval_id: str | None = None
        if self._approval_manager is not None:
            cr_dicts = [
                {
                    "check_name": cr.check_name,
                    "passed": cr.passed,
                    "risk_contribution": cr.risk_contribution,
                    "reason": cr.reason,
                    "metadata": cr.metadata,
                    "force_verdict": cr.force_verdict.value if cr.force_verdict else None,
                }
                for cr in verdict.check_results
            ]
            if needs_human_review(verdict.verdict.value, cr_dicts):
                try:
                    request = await self._approval_manager.create(
                        session_id=self._session_id,
                        agent_id=self._agent_id,
                        tool_name=self.name,
                        tool_input=tool_input,
                        original_goal=self._original_goal,
                        verdict=verdict.verdict.value,
                        risk_score=verdict.risk_score,
                        risk_delta=verdict.risk_delta,
                        reasons=verdict.reasons,
                        check_results=cr_dicts,
                        trace_id=verdict.trace_id,
                    )
                    approval_id = request.id
                except Exception:
                    logger.exception("crewai_approval_create_error")

        pending_note = ""
        if approval_id:
            pending_note = f" Approval ID: {approval_id}. A human reviewer has been notified."

        return (
            f"BLOCKED by Janus (verdict={verdict.verdict.value}, "
            f"risk={verdict.risk_score:.1f}): {verdict.recommended_action}.{pending_note}"
        )


async def create_crewai_tool(
    name: str,
    description: str,
    fn: Callable[..., Awaitable[str]],
    *,
    agent_id: str = "crewai-agent",
    agent_name: str = "CrewAI Agent",
    agent_role: str = "code",
    permissions: list[str] | None = None,
    session_id: str | None = None,
    original_goal: str = "",
    config: Any | None = None,
    db_path: str | None = None,
    api_key: str | None = None,
) -> JanusCrewTool:
    """One-call factory: create a Janus-protected CrewAI tool.

    Usage::

        from janus.integrations.crewai import create_crewai_tool

        search = await create_crewai_tool(
            "search", "Search the web", my_search_fn,
            agent_id="researcher",
        )
    """
    from janus.integrations import create_janus

    janus = await create_janus(
        agent_id=agent_id,
        agent_name=agent_name,
        agent_role=agent_role,
        permissions=permissions,
        session_id=session_id,
        original_goal=original_goal,
        config=config,
        db_path=db_path,
        api_key=api_key,
    )

    return JanusCrewTool(
        name=name,
        description=description,
        fn=fn,
        guardian=janus.guardian,
        agent_id=agent_id,
        session_id=janus.session_id,
        original_goal=original_goal,
        approval_manager=janus.approval_manager,
    )
