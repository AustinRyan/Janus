"""Tests for licensing API routes."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from janus.licensing import generate_license
from janus.tier import current_tier
from janus.web.app import _setup, _teardown, create_app, state


@pytest.fixture
async def client(monkeypatch):
    monkeypatch.setenv("JANUS_DB_PATH", ":memory:")
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID", raising=False)
    app = create_app()
    await _setup()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        await _teardown()
        current_tier.reset()
        state.guardian = None
        state.registry = None
        state.risk_engine = None
        state.session_store = None
        state.db = None
        state.recorder = None
        state.exporter_coordinator = None
        state.chat_agents.clear()
        state.sessions.clear()


async def test_license_status_default(client: AsyncClient) -> None:
    resp = await client.get("/api/license/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tier"] == "free"
    assert data["is_pro"] is False


async def test_license_activate_valid(client: AsyncClient) -> None:
    key = generate_license(tier="pro", customer_id="test", expiry_days=365)
    resp = await client.post("/api/license/activate", json={"license_key": key})
    assert resp.status_code == 200
    data = resp.json()
    assert data["tier"] == "pro"
    assert data["is_pro"] is True

    # Verify status endpoint reflects activation
    resp2 = await client.get("/api/license/status")
    assert resp2.json()["is_pro"] is True


async def test_license_activate_invalid(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/license/activate", json={"license_key": "invalid-key"}
    )
    assert resp.status_code == 400
    assert "Invalid" in resp.json()["detail"]


async def test_stripe_webhook_returns_501_without_secret(client: AsyncClient) -> None:
    resp = await client.post("/api/webhooks/stripe", content=b"{}")
    assert resp.status_code == 501
    assert "STRIPE_WEBHOOK_SECRET" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Checkout endpoint tests
# ---------------------------------------------------------------------------


async def test_checkout_returns_501_without_stripe_key(client: AsyncClient) -> None:
    """POST /api/billing/checkout returns 501 when STRIPE_SECRET_KEY is not set."""
    resp = await client.post("/api/billing/checkout", json={})
    assert resp.status_code == 501
    assert "STRIPE_SECRET_KEY" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Session lookup tests
# ---------------------------------------------------------------------------


async def test_session_lookup_returns_404_for_nonexistent(client: AsyncClient) -> None:
    """GET /api/billing/session/{id} returns 404 for unknown session ID."""
    resp = await client.get("/api/billing/session/cs_nonexistent_123")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


async def test_session_lookup_returns_license(client: AsyncClient) -> None:
    """GET /api/billing/session/{id} returns stored license data."""
    # Insert a license row directly
    assert state.db is not None
    key = generate_license(tier="pro", customer_id="buyer@example.com")
    await state.db.execute(
        """
        INSERT INTO licenses
            (license_key, tier, customer_email, stripe_customer_id, stripe_session_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (key, "pro", "buyer@example.com", "cus_test123", "cs_test_session_456"),
    )
    await state.db.commit()

    resp = await client.get("/api/billing/session/cs_test_session_456")
    assert resp.status_code == 200
    data = resp.json()
    assert data["license_key"] == key
    assert data["tier"] == "pro"
    assert data["customer_email"] == "buyer@example.com"
    assert "trial_ends_at" in data


# ---------------------------------------------------------------------------
# Webhook: customer.subscription.deleted
# ---------------------------------------------------------------------------


async def test_webhook_subscription_deleted(client: AsyncClient, monkeypatch) -> None:
    """Stripe webhook marks license as expired on subscription cancellation."""
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")

    # Insert an active license
    assert state.db is not None
    key = generate_license(tier="pro", customer_id="cancel@example.com")
    await state.db.execute(
        """
        INSERT INTO licenses
            (license_key, tier, customer_email, stripe_customer_id, stripe_session_id, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key, "pro", "cancel@example.com", "cus_cancel_123", "cs_cancel_456", "active"),
    )
    await state.db.commit()

    # Mock stripe.Webhook.construct_event to return our event
    import types

    mock_stripe = types.ModuleType("stripe")
    mock_stripe.error = types.ModuleType("stripe.error")
    mock_stripe.error.SignatureVerificationError = type("SignatureVerificationError", (Exception,), {})
    mock_stripe.error.StripeError = type("StripeError", (Exception,), {})

    def mock_construct_event(payload, sig_header, secret):
        return {
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "customer": "cus_cancel_123",
                }
            },
        }

    mock_stripe.Webhook = type("Webhook", (), {"construct_event": staticmethod(mock_construct_event)})()

    import sys
    monkeypatch.setitem(sys.modules, "stripe", mock_stripe)

    resp = await client.post(
        "/api/webhooks/stripe",
        content=b"{}",
        headers={"stripe-signature": "t=123,v1=abc"},
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "license_expired"

    # Verify the license is now expired in the DB
    row = await state.db.fetchone(
        "SELECT status FROM licenses WHERE stripe_customer_id = ?",
        ("cus_cancel_123",),
    )
    assert row is not None
    assert row[0] == "expired"
