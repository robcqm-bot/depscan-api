"""Tests for Stripe billing: checkout creation and webhook handlers (Fase 2)."""

import hashlib
import json
import secrets
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_key(
    key_id: int = 1,
    tier: str = "single",
    status: str = "active",
    credits: int = 0,
    customer_id: str | None = None,
    subscription_id: str | None = None,
):
    from app.models.db import APIKey
    k = MagicMock(spec=APIKey)
    k.id = key_id
    k.tier = tier
    k.status = status
    k.credits_remaining = credits
    k.stripe_customer_id = customer_id
    k.stripe_subscription_id = subscription_id
    return k


def _mock_db_factory(scalar_value=None):
    """Return an async generator mock that yields a session returning scalar_value."""
    from app.database import get_db

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = scalar_value
        session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        yield session

    return mock_db, get_db


# ---------------------------------------------------------------------------
# POST /v1/billing/checkout — model validation
# ---------------------------------------------------------------------------

def test_checkout_single_tier_passes_validation():
    """single tier should be accepted by the request model."""
    from app.models.scan import CheckoutRequest
    req = CheckoutRequest(tier="single", quantity=5)
    assert req.tier == "single"
    assert req.quantity == 5


def test_checkout_monitor_tier_passes_validation():
    """monitor tier is now valid in CheckoutRequest."""
    from app.models.scan import CheckoutRequest
    req = CheckoutRequest(tier="monitor")
    assert req.tier == "monitor"


def test_checkout_unlimited_tier_passes_validation():
    """unlimited tier is now valid in CheckoutRequest."""
    from app.models.scan import CheckoutRequest
    req = CheckoutRequest(tier="unlimited")
    assert req.tier == "unlimited"


def test_checkout_invalid_tier_rejected():
    """Unknown tiers must be rejected by Pydantic validation."""
    from pydantic import ValidationError
    from app.models.scan import CheckoutRequest
    with pytest.raises(ValidationError):
        CheckoutRequest(tier="enterprise")


# ---------------------------------------------------------------------------
# POST /v1/billing/checkout — Stripe one-time vs subscription mode
# ---------------------------------------------------------------------------

def _run_checkout(tier: str, quantity: int = 1):
    """Helper: hit POST /v1/billing/checkout with mocked Stripe and DB."""
    from main import app
    from fastapi.testclient import TestClient

    mock_db, get_db = _mock_db_factory()
    app.dependency_overrides[get_db] = mock_db

    mock_session = MagicMock()
    mock_session.id = "cs_test_abc"
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_abc"

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.billing.stripe.checkout.Session.create", return_value=mock_session),
        patch("app.routers.billing.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_fake"
        settings.stripe_price_single = "price_single_abc"
        settings.stripe_price_deep = "price_deep_abc"
        settings.stripe_price_monitor = "price_monitor_abc"
        settings.stripe_price_unlimited = "price_unlimited_abc"
        mock_settings.return_value = settings

        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/billing/checkout",
                json={"tier": tier, "quantity": quantity},
            )

    app.dependency_overrides.clear()
    return response


def test_checkout_single_uses_payment_mode():
    """single tier checkout must call Stripe with mode='payment'."""
    import stripe as stripe_lib
    from main import app
    from fastapi.testclient import TestClient

    mock_db, get_db = _mock_db_factory()
    app.dependency_overrides[get_db] = mock_db

    mock_session = MagicMock()
    mock_session.id = "cs_test_single"
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_single"
    captured_calls = []

    def fake_create(**kwargs):
        captured_calls.append(kwargs)
        return mock_session

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.billing.stripe.checkout.Session.create", side_effect=fake_create),
        patch("app.routers.billing.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_price_single = "price_single_abc"
        mock_settings.return_value = settings

        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/v1/billing/checkout", json={"tier": "single", "quantity": 5})

    app.dependency_overrides.clear()
    assert len(captured_calls) == 1
    assert captured_calls[0]["mode"] == "payment"
    assert captured_calls[0]["line_items"][0]["quantity"] == 5


def test_checkout_monitor_uses_subscription_mode():
    """monitor tier checkout must call Stripe with mode='subscription'."""
    from main import app
    from fastapi.testclient import TestClient

    mock_db, get_db = _mock_db_factory()
    app.dependency_overrides[get_db] = mock_db

    mock_session = MagicMock()
    mock_session.id = "cs_test_monitor"
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_monitor"
    captured_calls = []

    def fake_create(**kwargs):
        captured_calls.append(kwargs)
        return mock_session

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.billing.stripe.checkout.Session.create", side_effect=fake_create),
        patch("app.routers.billing.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_price_monitor = "price_monitor_abc"
        mock_settings.return_value = settings

        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/v1/billing/checkout", json={"tier": "monitor"})

    app.dependency_overrides.clear()
    assert len(captured_calls) == 1
    assert captured_calls[0]["mode"] == "subscription"
    # quantity is always 1 for subscriptions
    assert captured_calls[0]["line_items"][0]["quantity"] == 1
    # credits metadata matches _CREDITS_BY_TIER["monitor"]
    assert captured_calls[0]["metadata"]["credits"] == "500"


def test_checkout_unlimited_uses_subscription_mode():
    """unlimited tier checkout must use mode='subscription' with 999_999 credits."""
    from main import app
    from fastapi.testclient import TestClient

    mock_db, get_db = _mock_db_factory()
    app.dependency_overrides[get_db] = mock_db

    mock_session = MagicMock()
    mock_session.id = "cs_test_unlimited"
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_unlimited"
    captured_calls = []

    def fake_create(**kwargs):
        captured_calls.append(kwargs)
        return mock_session

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.billing.stripe.checkout.Session.create", side_effect=fake_create),
        patch("app.routers.billing.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_price_unlimited = "price_unlimited_abc"
        mock_settings.return_value = settings

        with TestClient(app, raise_server_exceptions=False) as c:
            c.post("/v1/billing/checkout", json={"tier": "unlimited"})

    app.dependency_overrides.clear()
    assert len(captured_calls) == 1
    assert captured_calls[0]["mode"] == "subscription"
    assert captured_calls[0]["metadata"]["credits"] == "999999"


# ---------------------------------------------------------------------------
# Webhook: checkout.session.completed
# ---------------------------------------------------------------------------

def _fake_event(event_type: str, data: dict) -> dict:
    return {"type": event_type, "data": {"object": data}}


def _build_webhook_call(event: dict, api_key_obj=None):
    """Hit POST /v1/webhook/billing with a faked Stripe event (no signature check)."""
    from main import app
    from fastapi.testclient import TestClient

    mock_db, get_db = _mock_db_factory(scalar_value=api_key_obj)
    app.dependency_overrides[get_db] = mock_db

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.billing.stripe.Webhook.construct_event", return_value=event),
        patch("app.routers.billing.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.stripe_secret_key = "sk_test_fake"
        settings.stripe_webhook_secret = "whsec_fake"
        mock_settings.return_value = settings

        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/webhook/billing",
                content=b"{}",
                headers={"stripe-signature": "t=1,v1=fake", "Content-Type": "application/json"},
            )

    app.dependency_overrides.clear()
    return response


def test_webhook_checkout_completed_payment_activates_key():
    """checkout.session.completed (payment) activates key and adds credits."""
    api_key = _make_api_key(key_id=1, tier="single", status="pending", credits=0)

    event = _fake_event("checkout.session.completed", {
        "mode": "payment",
        "customer": "cus_test",
        "subscription": None,
        "metadata": {"api_key_id": "1", "credits": "10", "tier": "single"},
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    assert response.json() == {"received": True}
    assert api_key.status == "active"
    assert api_key.credits_remaining == 10
    assert api_key.stripe_customer_id == "cus_test"


def test_webhook_checkout_completed_subscription_activates_key():
    """checkout.session.completed (subscription) activates key and sets subscription_id."""
    api_key = _make_api_key(key_id=2, tier="monitor", status="pending", credits=0)

    event = _fake_event("checkout.session.completed", {
        "mode": "subscription",
        "customer": "cus_monitor",
        "subscription": "sub_mon_abc",
        "metadata": {"api_key_id": "2", "credits": "500", "tier": "monitor"},
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    assert api_key.status == "active"
    assert api_key.credits_remaining == 500
    assert api_key.stripe_subscription_id == "sub_mon_abc"


def test_webhook_checkout_completed_invalid_metadata_ignored():
    """checkout.session.completed with invalid metadata is logged and ignored (no crash)."""
    event = _fake_event("checkout.session.completed", {
        "mode": "payment",
        "customer": "cus_bad",
        "metadata": {"api_key_id": "not_an_int", "credits": "10"},
    })
    response = _build_webhook_call(event, api_key_obj=None)
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Webhook: invoice.payment_succeeded
# ---------------------------------------------------------------------------

def test_webhook_invoice_subscription_create_skipped():
    """First invoice (billing_reason=subscription_create) must be skipped."""
    api_key = _make_api_key(key_id=3, tier="monitor", credits=100)

    event = _fake_event("invoice.payment_succeeded", {
        "billing_reason": "subscription_create",
        "customer": "cus_abc",
        "subscription": "sub_abc",
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    # Credits must NOT be touched (skip logic)
    assert api_key.credits_remaining == 100


def test_webhook_invoice_renewal_replenishes_monitor_credits():
    """Monthly renewal (billing_reason=subscription_cycle) replenishes monitor credits."""
    api_key = _make_api_key(
        key_id=4, tier="monitor", credits=10,
        subscription_id="sub_renew_abc",
    )

    event = _fake_event("invoice.payment_succeeded", {
        "billing_reason": "subscription_cycle",
        "customer": "cus_renew",
        "subscription": "sub_renew_abc",
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    # Credits should be reset to full allocation for monitor tier
    assert api_key.credits_remaining == 500
    assert api_key.status == "active"


def test_webhook_invoice_renewal_replenishes_unlimited_credits():
    """Monthly renewal for unlimited tier replenishes 999_999 credits."""
    api_key = _make_api_key(
        key_id=5, tier="unlimited", credits=50000,
        subscription_id="sub_unl_abc",
    )

    event = _fake_event("invoice.payment_succeeded", {
        "billing_reason": "subscription_cycle",
        "customer": "cus_unl",
        "subscription": "sub_unl_abc",
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    assert api_key.credits_remaining == 999_999


def test_webhook_invoice_renewal_unknown_key_ignored():
    """invoice.payment_succeeded with no matching key is logged and ignored."""
    event = _fake_event("invoice.payment_succeeded", {
        "billing_reason": "subscription_cycle",
        "customer": "cus_ghost",
        "subscription": "sub_ghost",
    })
    response = _build_webhook_call(event, api_key_obj=None)
    assert response.status_code == 200


def test_webhook_invoice_renewal_non_subscription_tier_ignored():
    """invoice.payment_succeeded for a single-tier key should not replenish credits."""
    api_key = _make_api_key(key_id=6, tier="single", credits=5)

    event = _fake_event("invoice.payment_succeeded", {
        "billing_reason": "subscription_cycle",
        "customer": "cus_single",
        "subscription": "sub_single",
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    # single tier not replenished
    assert api_key.credits_remaining == 5


# ---------------------------------------------------------------------------
# Webhook: customer.subscription.deleted
# ---------------------------------------------------------------------------

def test_webhook_subscription_deleted_deactivates_key():
    """customer.subscription.deleted sets key status to inactive."""
    api_key = _make_api_key(key_id=7, tier="monitor", status="active")

    event = _fake_event("customer.subscription.deleted", {
        "id": "sub_deleted",
        "customer": "cus_deleted",
    })

    response = _build_webhook_call(event, api_key_obj=api_key)

    assert response.status_code == 200
    assert api_key.status == "inactive"


# ---------------------------------------------------------------------------
# dependencies.py: monitor tier skips credits gate
# ---------------------------------------------------------------------------

def test_monitor_tier_skips_credits_gate():
    """A monitor-tier key with 0 credits should still pass get_api_key."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.models.db import APIKey

    monitor_key = MagicMock(spec=APIKey)
    monitor_key.id = 99
    monitor_key.tier = "monitor"
    monitor_key.status = "active"
    monitor_key.credits_remaining = 0  # no credits!

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = monitor_key
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_db

    # Pre-generate a key so sha256 lookup "finds" it
    raw_key = "dsk_live_testmonitorkey123"

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            # POST /v1/monitor/subscribe requires auth; with 0 credits on monitor
            # tier, should NOT get 402 — should get 400 (no URLs) or 200.
            response = c.post(
                "/v1/monitor/subscribe",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": f"Bearer {raw_key}"},
            )

    app.dependency_overrides.clear()
    # Must NOT be 402 CREDITS_EXHAUSTED
    assert response.status_code != 402
    detail = response.json().get("detail", {})
    assert detail.get("code") != "CREDITS_EXHAUSTED"


def test_single_tier_credits_gate_still_enforced():
    """A single-tier key with 0 credits must be blocked (402)."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.models.db import APIKey

    single_key = MagicMock(spec=APIKey)
    single_key.id = 100
    single_key.tier = "single"
    single_key.status = "active"
    single_key.credits_remaining = 0

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = single_key
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_db
    raw_key = "dsk_live_testsinglekey456"

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": f"Bearer {raw_key}"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 402
    assert response.json()["detail"]["code"] == "CREDITS_EXHAUSTED"
