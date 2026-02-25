"""Tests for the FastAPI application."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from janus.web.app import _setup, _teardown, create_app, state


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setenv("JANUS_DB_PATH", ":memory:")
    app = create_app()
    await _setup()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        await _teardown()
        # Reset module-level state between tests
        state.guardian = None
        state.registry = None
        state.risk_engine = None
        state.session_store = None
        state.db = None
        state.recorder = None
        state.exporter_coordinator = None
        state.chat_agents.clear()
        state.sessions.clear()


async def test_health_endpoint(client: AsyncClient) -> None:
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


async def test_list_sessions_empty(client: AsyncClient) -> None:
    resp = await client.get("/api/sessions")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_agents(client: AsyncClient) -> None:
    resp = await client.get("/api/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["agent_id"] == "demo-agent"


async def test_list_agents_has_all_personas(client: AsyncClient) -> None:
    resp = await client.get("/api/agents")
    assert resp.status_code == 200
    data = resp.json()
    agent_ids = {a["agent_id"] for a in data}
    assert "demo-agent" in agent_ids
    assert "marketing-bot" in agent_ids
    assert "developer-bot" in agent_ids
    assert "finance-bot" in agent_ids
    assert "research-bot" in agent_ids
    assert "admin-bot" in agent_ids
    assert len(data) == 6


async def test_agent_roles_correct(client: AsyncClient) -> None:
    resp = await client.get("/api/agents")
    data = resp.json()
    role_map = {a["agent_id"]: a["role"] for a in data}
    assert role_map["marketing-bot"] == "communication"
    assert role_map["developer-bot"] == "code"
    assert role_map["finance-bot"] == "financial"
    assert role_map["admin-bot"] == "admin"


async def test_admin_bot_has_wildcard_permission(client: AsyncClient) -> None:
    resp = await client.get("/api/agents")
    data = resp.json()
    admin = next(a for a in data if a["agent_id"] == "admin-bot")
    assert "*" in admin["permissions"]


async def test_create_session(client: AsyncClient) -> None:
    resp = await client.post("/api/sessions", json={
        "agent_id": "demo-agent",
        "original_goal": "Research public API docs",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["agent_id"] == "demo-agent"
    assert data["risk_score"] == 0.0


async def test_create_session_with_finance_bot(client: AsyncClient) -> None:
    resp = await client.post("/api/sessions", json={
        "agent_id": "finance-bot",
        "original_goal": "Review Q4 financial reports",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "finance-bot"
    assert data["risk_score"] == 0.0


async def test_create_session_with_marketing_bot(client: AsyncClient) -> None:
    resp = await client.post("/api/sessions", json={
        "agent_id": "marketing-bot",
        "original_goal": "Draft a campaign email",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "marketing-bot"


async def test_proof_chain_empty(client: AsyncClient) -> None:
    resp = await client.get("/api/sessions/nonexistent/proof")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_proof_verify_empty(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/sessions/nonexistent/proof/verify"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["chain_length"] == 0


async def test_threat_intel_list(
    client: AsyncClient,
) -> None:
    resp = await client.get("/api/threat-intel")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 5


async def test_threat_intel_stats(
    client: AsyncClient,
) -> None:
    resp = await client.get("/api/threat-intel/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_patterns"] >= 5
    assert data["built_in_count"] >= 5


async def test_traces_endpoint_empty(client: AsyncClient) -> None:
    resp = await client.get("/api/traces")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_traces_endpoint_by_session(client: AsyncClient) -> None:
    resp = await client.get("/api/traces", params={"session_id": "nonexistent"})
    assert resp.status_code == 200
    assert resp.json() == []


async def test_traces_endpoint_by_verdict(client: AsyncClient) -> None:
    resp = await client.get("/api/traces", params={"verdict": "allow"})
    assert resp.status_code == 200
    assert resp.json() == []


# ── Auth tests ────────────────────────────────────────────────────────────────


@pytest.fixture
async def auth_client(monkeypatch):
    monkeypatch.setenv("JANUS_DB_PATH", ":memory:")
    monkeypatch.setenv("JANUS_API_KEY", "test-secret-key")
    app = create_app()
    await _setup()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        await _teardown()
        state.guardian = None
        state.registry = None
        state.risk_engine = None
        state.session_store = None
        state.db = None
        state.recorder = None
        state.exporter_coordinator = None
        state.chat_agents.clear()
        state.sessions.clear()


async def test_health_no_auth_required(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/api/health")
    assert resp.status_code == 200


async def test_protected_endpoint_returns_401_without_key(auth_client: AsyncClient) -> None:
    resp = await auth_client.get("/api/agents")
    assert resp.status_code == 401


async def test_protected_endpoint_returns_401_with_wrong_key(auth_client: AsyncClient) -> None:
    resp = await auth_client.get(
        "/api/agents", headers={"Authorization": "Bearer wrong-key"}
    )
    assert resp.status_code == 401


async def test_protected_endpoint_returns_200_with_correct_key(auth_client: AsyncClient) -> None:
    resp = await auth_client.get(
        "/api/agents", headers={"Authorization": "Bearer test-secret-key"}
    )
    assert resp.status_code == 200
