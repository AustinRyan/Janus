"""Sentinel — Autonomous Security Layer for AI Agents.

Usage::

    from sentinel import Guardian, SentinelConfig, AgentIdentity, AgentRole

    config = SentinelConfig()
    guardian = await Guardian.from_config(config, registry, session_store)

    verdict = await guardian.wrap_tool_call(
        agent_id="my-agent",
        session_id="session-123",
        original_goal="Summarize quarterly earnings",
        tool_name="read_file",
        tool_input={"path": "/reports/q4.pdf"},
    )

    if verdict.verdict == Verdict.ALLOW:
        result = execute_tool("read_file", {"path": "/reports/q4.pdf"})
    else:
        print(f"Blocked: {verdict.recommended_action}")
"""

from sentinel.config import SentinelConfig
from sentinel.core.decision import (
    CheckResult,
    PipelineContext,
    SecurityVerdict,
    ToolCallRequest,
    Verdict,
)
from sentinel.core.guardian import Guardian
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.registry import AgentRegistry

__all__ = [
    "AgentIdentity",
    "AgentRegistry",
    "AgentRole",
    "CheckResult",
    "Guardian",
    "PipelineContext",
    "SecurityVerdict",
    "SentinelConfig",
    "ToolCallRequest",
    "ToolPermission",
    "Verdict",
]
