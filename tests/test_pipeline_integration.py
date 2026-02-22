from __future__ import annotations

import pytest

from sentinel.config import SentinelConfig
from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.registry import AgentRegistry
from sentinel.risk.engine import RiskEngine
from sentinel.storage.database import DatabaseManager
from sentinel.storage.session_store import InMemorySessionStore


@pytest.fixture
async def registry(memory_db: DatabaseManager) -> AgentRegistry:
    return AgentRegistry(memory_db)


@pytest.fixture
def session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


@pytest.fixture
def risk_engine(session_store: InMemorySessionStore) -> RiskEngine:
    return RiskEngine(session_store)


@pytest.fixture
async def guardian(
    registry: AgentRegistry, risk_engine: RiskEngine
) -> Guardian:
    config = SentinelConfig()
    g = Guardian(
        config=config,
        registry=registry,
        risk_engine=risk_engine,
    )
    return g


async def test_benign_request_flows_through(
    guardian: Guardian, registry: AgentRegistry
) -> None:
    """A research agent reading a file should be ALLOWED."""
    agent = AgentIdentity(
        agent_id="researcher",
        name="Research Bot",
        role=AgentRole.RESEARCH,
        permissions=[ToolPermission(tool_pattern="read_*")],
    )
    await registry.register_agent(agent)

    verdict = await guardian.wrap_tool_call(
        agent_id="researcher",
        session_id="session-1",
        original_goal="Summarize quarterly report",
        tool_name="read_file",
        tool_input={"path": "/reports/q4.pdf"},
    )
    assert verdict.verdict == Verdict.ALLOW
    assert verdict.risk_score < 20


async def test_out_of_scope_tool_gets_challenged(
    guardian: Guardian, registry: AgentRegistry
) -> None:
    """A research agent trying to use financial tools should be CHALLENGED."""
    agent = AgentIdentity(
        agent_id="researcher",
        name="Research Bot",
        role=AgentRole.RESEARCH,
        permissions=[ToolPermission(tool_pattern="read_*")],
    )
    await registry.register_agent(agent)

    verdict = await guardian.wrap_tool_call(
        agent_id="researcher",
        session_id="session-2",
        original_goal="Summarize quarterly report",
        tool_name="financial_transfer",
        tool_input={"amount": 50000, "destination": "offshore"},
    )
    assert verdict.verdict == Verdict.CHALLENGE


async def test_session_risk_accumulates_to_block(
    guardian: Guardian, registry: AgentRegistry
) -> None:
    """Repeated suspicious calls should accumulate risk and eventually BLOCK."""
    agent = AgentIdentity(
        agent_id="suspicious",
        name="Suspicious Bot",
        role=AgentRole.CODE,
        permissions=[ToolPermission(tool_pattern="*")],
    )
    await registry.register_agent(agent)

    session_id = "session-escalation"

    # First call: execute code with keywords
    v1 = await guardian.wrap_tool_call(
        agent_id="suspicious",
        session_id=session_id,
        original_goal="Help with coding",
        tool_name="execute_code",
        tool_input={"code": "import os; os.system('rm -rf /')"},
    )
    # Should be allowed but with elevated risk
    assert v1.risk_score > 0

    # Second call: database with sensitive keywords
    v2 = await guardian.wrap_tool_call(
        agent_id="suspicious",
        session_id=session_id,
        original_goal="Help with coding",
        tool_name="database_write",
        tool_input={"query": "DROP TABLE credentials; SELECT password FROM admin"},
    )
    # Risk should be climbing
    assert v2.risk_score > v1.risk_score

    # Third call: financial transfer
    v3 = await guardian.wrap_tool_call(
        agent_id="suspicious",
        session_id=session_id,
        original_goal="Help with coding",
        tool_name="financial_transfer",
        tool_input={"amount": 100000, "destination": "untraceable wallet"},
    )
    # Both v2 and v3 should be capped at 100 and BLOCKED
    assert v3.risk_score == 100.0
    assert v3.verdict == Verdict.BLOCK
    assert v2.verdict == Verdict.BLOCK


async def test_multiple_sessions_independent(
    guardian: Guardian, registry: AgentRegistry
) -> None:
    """Risk scores should be independent per session."""
    agent = AgentIdentity(
        agent_id="multi-session",
        name="Multi Session Bot",
        role=AgentRole.RESEARCH,
        permissions=[ToolPermission(tool_pattern="*")],
    )
    await registry.register_agent(agent)

    # Session A: risky call
    va = await guardian.wrap_tool_call(
        agent_id="multi-session",
        session_id="session-a",
        original_goal="Research",
        tool_name="execute_code",
        tool_input={"code": "sudo rm -rf /etc/shadow"},
    )

    # Session B: benign call (separate session)
    vb = await guardian.wrap_tool_call(
        agent_id="multi-session",
        session_id="session-b",
        original_goal="Research",
        tool_name="read_file",
        tool_input={"path": "/docs/readme.md"},
    )

    # Session B should have much lower risk than session A
    assert vb.risk_score < va.risk_score
