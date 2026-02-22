from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from sentinel.circuit.breaker import CircuitBreaker, CircuitState
from sentinel.config import CircuitBreakerConfig, SentinelConfig
from sentinel.core.decision import Verdict
from sentinel.core.guardian import Guardian
from sentinel.identity.agent import AgentIdentity, AgentRole, ToolPermission
from sentinel.identity.registry import AgentRegistry
from sentinel.risk.engine import RiskEngine
from sentinel.storage.database import DatabaseManager
from sentinel.storage.session_store import InMemorySessionStore
from tests.conftest import make_request


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
    registry: AgentRegistry,
    risk_engine: RiskEngine,
) -> Guardian:
    config = SentinelConfig()
    g = Guardian(
        config=config,
        registry=registry,
        risk_engine=risk_engine,
    )
    # Register a test agent
    agent = AgentIdentity(
        agent_id="test-agent",
        name="Test Research Bot",
        role=AgentRole.RESEARCH,
        permissions=[
            ToolPermission(tool_pattern="read_*"),
            ToolPermission(tool_pattern="search_*"),
        ],
    )
    await registry.register_agent(agent)
    return g


async def test_allow_permitted_tool(guardian: Guardian) -> None:
    request = make_request(tool_name="read_file", tool_input={"path": "/docs/readme.md"})
    verdict = await guardian.intercept(request)
    assert verdict.verdict == Verdict.ALLOW


async def test_challenge_unpermitted_tool(guardian: Guardian) -> None:
    request = make_request(tool_name="financial_transfer", tool_input={"amount": 1000})
    verdict = await guardian.intercept(request)
    assert verdict.verdict == Verdict.CHALLENGE


async def test_block_unregistered_agent(guardian: Guardian) -> None:
    request = make_request(agent_id="ghost-agent", tool_name="read_file")
    verdict = await guardian.intercept(request)
    assert verdict.verdict == Verdict.BLOCK
    assert "not registered" in verdict.reasons[0].lower()


async def test_block_locked_agent(guardian: Guardian, registry: AgentRegistry) -> None:
    await registry.lock_agent("test-agent", "Suspicious behavior")
    request = make_request(tool_name="read_file")
    verdict = await guardian.intercept(request)
    assert verdict.verdict == Verdict.BLOCK
    assert "locked" in verdict.reasons[0].lower()


async def test_circuit_breaker_blocks_when_open(
    registry: AgentRegistry, risk_engine: RiskEngine
) -> None:
    config = SentinelConfig()
    breaker = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1))
    breaker.record_failure()  # Force OPEN
    assert breaker.state == CircuitState.OPEN

    g = Guardian(
        config=config,
        registry=registry,
        risk_engine=risk_engine,
        circuit_breaker=breaker,
    )
    agent = AgentIdentity(
        agent_id="test-agent",
        name="Test Bot",
        role=AgentRole.RESEARCH,
        permissions=[ToolPermission(tool_pattern="*")],
    )
    await registry.register_agent(agent)

    request = make_request(tool_name="read_file")
    verdict = await g.intercept(request)
    assert verdict.verdict == Verdict.BLOCK
    assert "circuit breaker" in verdict.reasons[0].lower()


async def test_risk_accumulates_across_calls(guardian: Guardian) -> None:
    # Multiple calls should accumulate risk
    for _ in range(3):
        request = make_request(
            tool_name="search_web",
            tool_input={"query": "public documentation"},
        )
        await guardian.intercept(request)

    # Score should be > 0 after multiple calls
    score = guardian._risk_engine.get_score("test-session")
    assert score > 0


async def test_wrap_tool_call_convenience(guardian: Guardian) -> None:
    verdict = await guardian.wrap_tool_call(
        agent_id="test-agent",
        session_id="test-session",
        original_goal="Read documentation",
        tool_name="read_file",
        tool_input={"path": "/docs/api.md"},
    )
    assert verdict.verdict == Verdict.ALLOW


async def test_guardian_fail_safe_on_error(
    registry: AgentRegistry,
) -> None:
    """If the risk engine raises, Guardian should fail-safe to BLOCK."""
    config = SentinelConfig()
    broken_engine = MagicMock(spec=RiskEngine)
    broken_engine.get_score.side_effect = RuntimeError("Engine exploded")
    broken_engine.session_store = InMemorySessionStore()

    g = Guardian(
        config=config,
        registry=registry,
        risk_engine=broken_engine,
    )
    agent = AgentIdentity(
        agent_id="test-agent",
        name="Test Bot",
        role=AgentRole.RESEARCH,
        permissions=[ToolPermission(tool_pattern="*")],
    )
    await registry.register_agent(agent)

    request = make_request(tool_name="read_file")
    verdict = await g.intercept(request)
    assert verdict.verdict == Verdict.BLOCK
    assert "fail-safe" in verdict.reasons[0].lower()
