"""OpenAI Assistants/Function Calling integration adapter for Janus.

Sits between OpenAI's function calling response and actual execution.

Usage::

    from janus.integrations.openai import JanusFunctionProxy

    proxy = JanusFunctionProxy(
        guardian=guardian, agent_id="a-1", session_id="s-1",
        functions={"read_file": read_file_fn},
    )
    result = await proxy.execute("read_file", '{"path": "/test.txt"}')
    if result.allowed:
        # feed result.output back to OpenAI
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import structlog

from janus.core.approval import ApprovalManager, needs_human_review
from janus.core.decision import Verdict
from janus.core.guardian import Guardian

logger = structlog.get_logger()


@dataclass
class FunctionResult:
    """Result of a function execution through Janus."""

    allowed: bool
    output: str
    verdict: str
    risk_score: float
    approval_id: str | None = None


class JanusFunctionProxy:
    """Proxy for OpenAI function calling with Guardian interception."""

    def __init__(
        self,
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        functions: dict[str, Callable[..., Awaitable[Any]]],
        original_goal: str = "",
        approval_manager: ApprovalManager | None = None,
    ) -> None:
        self._guardian = guardian
        self._agent_id = agent_id
        self._session_id = session_id
        self._functions = functions
        self._original_goal = original_goal
        self._approval_manager = approval_manager

    async def execute(
        self, function_name: str, arguments: str
    ) -> FunctionResult:
        """Execute a function call with Guardian interception.

        Args:
            function_name: Name of the function to call.
            arguments: JSON string of function arguments (as OpenAI sends them).
        """
        try:
            args = json.loads(arguments)
        except json.JSONDecodeError:
            args = {"raw": arguments}

        verdict = await self._guardian.wrap_tool_call(
            agent_id=self._agent_id,
            session_id=self._session_id,
            original_goal=self._original_goal,
            tool_name=function_name,
            tool_input=args,
        )

        if verdict.verdict == Verdict.ALLOW:
            fn = self._functions.get(function_name)
            if fn is None:
                return FunctionResult(
                    allowed=False,
                    output=f"Unknown function: {function_name}",
                    verdict="error",
                    risk_score=verdict.risk_score,
                )
            result = await fn(**args)
            return FunctionResult(
                allowed=True,
                output=str(result),
                verdict="allow",
                risk_score=verdict.risk_score,
            )

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
                        tool_name=function_name,
                        tool_input=args,
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
                    logger.exception("openai_approval_create_error")

        pending_note = ""
        if approval_id:
            pending_note = f" Approval ID: {approval_id}. A human reviewer has been notified."

        return FunctionResult(
            allowed=False,
            output=(
                f"BLOCKED by Janus (verdict={verdict.verdict.value}, "
                f"risk={verdict.risk_score:.1f}): {verdict.recommended_action}.{pending_note}"
            ),
            verdict=verdict.verdict.value,
            risk_score=verdict.risk_score,
            approval_id=approval_id,
        )


async def create_openai_guard(
    functions: dict[str, Callable[..., Awaitable[Any]]],
    *,
    agent_id: str = "openai-agent",
    agent_name: str = "OpenAI Agent",
    agent_role: str = "code",
    permissions: list[str] | None = None,
    session_id: str | None = None,
    original_goal: str = "",
    config: Any | None = None,
    db_path: str | None = None,
    api_key: str | None = None,
) -> JanusFunctionProxy:
    """One-call factory: create a Janus-protected OpenAI function proxy.

    Usage::

        from janus.integrations.openai import create_openai_guard

        proxy = await create_openai_guard(
            {"search": search_fn, "execute": exec_fn},
            agent_id="my-agent",
        )
        result = await proxy.execute("search", '{"query": "test"}')
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

    return JanusFunctionProxy(
        guardian=janus.guardian,
        agent_id=agent_id,
        session_id=janus.session_id,
        functions=functions,
        original_goal=original_goal,
        approval_manager=janus.approval_manager,
    )
