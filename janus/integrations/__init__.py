"""Janus integration adapters for agent frameworks.

Quickstart — wrap any tool call in 3 lines::

    from janus.integrations import create_janus

    janus = await create_janus(agent_id="my-agent", agent_role="code")

    # Guard a tool call:
    verdict = await janus.guard("execute_code", {"code": "print('hello')"})
    if verdict.allowed:
        result = execute_my_tool("execute_code", {"code": "print('hello')"})
    else:
        print(f"Blocked: {verdict.reason}")
        if verdict.approval_id:
            print(f"Pending human review: {verdict.approval_id}")

Available adapters:
    - ``janus.integrations.langchain`` — LangChain BaseTool wrapper
    - ``janus.integrations.openai`` — OpenAI function calling proxy
    - ``janus.integrations.crewai`` — CrewAI tool wrapper
    - ``janus.integrations.mcp`` — MCP server wrapper
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any

from janus.config import JanusConfig
from janus.core.approval import ApprovalManager, needs_human_review
from janus.core.decision import Verdict
from janus.core.guardian import Guardian
from janus.identity.agent import AgentIdentity, AgentRole, ToolPermission
from janus.identity.registry import AgentRegistry
from janus.storage.database import DatabaseManager
from janus.storage.session_store import InMemorySessionStore
from janus.web.events import EventBroadcaster


@dataclass
class GuardResult:
    """Result of a guarded tool call evaluation."""

    allowed: bool
    verdict: str
    risk_score: float
    risk_delta: float
    reasons: list[str]
    recommended_action: str
    approval_id: str | None = None
    trace_id: str = ""

    @property
    def reason(self) -> str:
        return self.recommended_action


class Janus:
    """High-level SDK client for guarding tool calls.

    Use ``create_janus()`` to construct an instance.
    """

    def __init__(
        self,
        guardian: Guardian,
        agent_id: str,
        session_id: str,
        original_goal: str = "",
        approval_manager: ApprovalManager | None = None,
        broadcaster: EventBroadcaster | None = None,
        db: DatabaseManager | None = None,
    ) -> None:
        self.guardian = guardian
        self.agent_id = agent_id
        self.session_id = session_id
        self.original_goal = original_goal
        self.approval_manager = approval_manager
        self.broadcaster = broadcaster
        self._db = db

    async def guard(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        original_goal: str | None = None,
    ) -> GuardResult:
        """Evaluate a tool call through the Guardian pipeline.

        Returns a ``GuardResult`` with the verdict. If the tool is blocked
        and requires human review, ``approval_id`` will be set.
        """
        goal = original_goal or self.original_goal

        verdict = await self.guardian.wrap_tool_call(
            agent_id=self.agent_id,
            session_id=self.session_id,
            original_goal=goal,
            tool_name=tool_name,
            tool_input=tool_input,
        )

        if verdict.verdict == Verdict.ALLOW:
            return GuardResult(
                allowed=True,
                verdict="allow",
                risk_score=verdict.risk_score,
                risk_delta=verdict.risk_delta,
                reasons=verdict.reasons,
                recommended_action=verdict.recommended_action,
                trace_id=verdict.trace_id,
            )

        # Non-ALLOW — check for human review
        approval_id: str | None = None
        if self.approval_manager is not None:
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
                request = await self.approval_manager.create(
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    original_goal=goal,
                    verdict=verdict.verdict.value,
                    risk_score=verdict.risk_score,
                    risk_delta=verdict.risk_delta,
                    reasons=verdict.reasons,
                    check_results=cr_dicts,
                    trace_id=verdict.trace_id,
                )
                approval_id = request.id

        return GuardResult(
            allowed=False,
            verdict=verdict.verdict.value,
            risk_score=verdict.risk_score,
            risk_delta=verdict.risk_delta,
            reasons=verdict.reasons,
            recommended_action=verdict.recommended_action,
            approval_id=approval_id,
            trace_id=verdict.trace_id,
        )

    async def close(self) -> None:
        """Clean up resources."""
        if self._db:
            await self._db.close()


async def create_janus(
    *,
    agent_id: str = "default-agent",
    agent_name: str = "Agent",
    agent_role: str = "code",
    permissions: list[str] | None = None,
    session_id: str | None = None,
    original_goal: str = "",
    config: JanusConfig | None = None,
    db_path: str | None = None,
    api_key: str | None = None,
) -> Janus:
    """Create a fully-wired Janus SDK client in one call.

    Args:
        agent_id: Unique identifier for the agent.
        agent_name: Human-readable agent name.
        agent_role: Agent role (code, research, financial, admin, etc.).
        permissions: Tool permission patterns (e.g. ["read_*", "search_*"]).
            Defaults to ["*"] (all tools).
        session_id: Session identifier. Auto-generated if not provided.
        original_goal: The agent's stated goal for drift detection.
        config: JanusConfig override. Uses defaults if not provided.
        db_path: SQLite database path. Uses env JANUS_DB_PATH or ":memory:".
        api_key: Anthropic API key for LLM-powered checks. Uses env if not set.

    Returns:
        A ``Janus`` instance ready to call ``.guard()``.
    """
    if config is None:
        config = JanusConfig()

    if db_path is None:
        db_path = os.environ.get("JANUS_DB_PATH", ":memory:")

    if api_key is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")

    if session_id is None:
        session_id = f"sdk-{uuid.uuid4().hex[:8]}"

    # Apply thresholds
    from janus.risk import thresholds
    thresholds.configure(config.risk, config.policy)

    # Database
    db = DatabaseManager(db_path)
    await db.connect()
    await db.apply_migrations()

    # Registry + agent identity
    registry = AgentRegistry(db)
    role = AgentRole(agent_role)
    perms = [ToolPermission(tool_pattern=p) for p in (permissions or ["*"])]
    agent = AgentIdentity(
        agent_id=agent_id,
        name=agent_name,
        role=role,
        permissions=perms,
    )
    await registry.register_agent(agent)

    # Session store
    session_store = InMemorySessionStore()

    # LLM classifier + drift (if API key available)
    classifier = None
    if api_key:
        try:
            from janus.llm.classifier import SecurityClassifier
            from janus.llm.client import AnthropicClientWrapper

            llm_client = AnthropicClientWrapper(api_key=api_key)
            classifier = SecurityClassifier(
                client=llm_client, config=config.guardian_model
            )
        except Exception:
            pass

    # Guardian
    guardian = await Guardian.from_config(
        config=config,
        registry=registry,
        session_store=session_store,
        classifier=classifier,
    )

    # Event broadcaster + approval manager
    broadcaster = EventBroadcaster()
    approval_manager = ApprovalManager(
        db=db,
        broadcaster=broadcaster,
        guardian=guardian,
    )

    return Janus(
        guardian=guardian,
        agent_id=agent_id,
        session_id=session_id,
        original_goal=original_goal,
        approval_manager=approval_manager,
        broadcaster=broadcaster,
        db=db,
    )
