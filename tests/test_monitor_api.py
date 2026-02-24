"""Tests for /v1/monitor endpoints (Fase 2)."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key(tier: str = "monitor", key_id: int = 10):
    from app.models.db import APIKey
    k = MagicMock(spec=APIKey)
    k.id = key_id
    k.tier = tier
    k.credits_remaining = 50
    k.status = "active"
    k.last_used_at = None
    return k


def _make_subscription(subscription_id: str = "mon_abc123", api_key_id: int = 10):
    from app.models.db import Subscription
    s = MagicMock(spec=Subscription)
    s.id = 1
    s.subscription_id = subscription_id
    s.api_key_id = api_key_id
    s.skill_url = None
    s.endpoints_json = '["https://api.github.com"]'
    s.webhook_url = None
    s.alert_threshold = 20
    s.last_score = None
    s.last_scan_id = None
    s.status = "active"
    s.created_at = datetime.now(timezone.utc)
    s.next_check_at = datetime.now(timezone.utc)
    s.alerts = []
    return s


def _app_with_mocked_db(return_value=None):
    """Return (app, mock_db_override) with the DB session returning return_value."""
    from app.database import get_db
    from main import app

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = return_value
        # scalars().all() for list queries
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result.scalars.return_value = scalars_mock
        session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        yield session

    return app, mock_db, get_db


# ---------------------------------------------------------------------------
# POST /v1/monitor/subscribe
# ---------------------------------------------------------------------------

def test_subscribe_single_tier_rejected():
    """A single-tier key cannot subscribe to monitoring."""
    from app.dependencies import get_api_key
    app, mock_db, get_db = _app_with_mocked_db()
    single_key = _make_key(tier="single")

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: single_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/monitor/subscribe",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "TIER_REQUIRED"


def test_subscribe_monitor_tier_succeeds():
    """A monitor-tier key can subscribe."""
    from app.dependencies import get_api_key
    app, mock_db, get_db = _app_with_mocked_db()
    monitor_key = _make_key(tier="monitor")

    # We need a real-enough subscription object after db.refresh
    sub = _make_subscription()

    async def mock_db_with_refresh():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        # refresh sets attributes on the passed object — we just no-op
        session.refresh = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db_with_refresh
    app.dependency_overrides[get_api_key] = lambda: monitor_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch(
            "app.routers.monitor.extract_urls",
            new=AsyncMock(return_value=["https://api.github.com"]),
        ),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/monitor/subscribe",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert "subscription_id" in data
    assert data["subscription_id"].startswith("mon_")
    assert data["endpoints"] == ["https://api.github.com"]


def test_subscribe_unlimited_tier_succeeds():
    """An unlimited-tier key can also subscribe to monitoring."""
    from app.dependencies import get_api_key
    unlimited_key = _make_key(tier="unlimited")
    app, mock_db, get_db = _app_with_mocked_db()

    async def mock_db_fresh():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db_fresh
    app.dependency_overrides[get_api_key] = lambda: unlimited_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch(
            "app.routers.monitor.extract_urls",
            new=AsyncMock(return_value=["https://api.github.com"]),
        ),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/monitor/subscribe",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200


def test_subscribe_no_urls_rejected():
    """If extract_urls returns empty list → 400 NO_URLS."""
    from app.dependencies import get_api_key
    monitor_key = _make_key(tier="monitor")
    app, mock_db, get_db = _app_with_mocked_db()

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: monitor_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.monitor.extract_urls", new=AsyncMock(return_value=[])),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/monitor/subscribe",
                json={"endpoints": ["https://api.github.com"]},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "NO_URLS"


# ---------------------------------------------------------------------------
# DELETE /v1/monitor/{subscription_id}
# ---------------------------------------------------------------------------

def test_unsubscribe_owner_succeeds():
    """Owner of subscription can cancel it → 204."""
    from app.dependencies import get_api_key
    key_id = 10
    monitor_key = _make_key(tier="monitor", key_id=key_id)
    sub = _make_subscription(api_key_id=key_id)

    app, _mock_db, get_db = _app_with_mocked_db(return_value=sub)

    async def mock_db_with_sub():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = sub
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db_with_sub
    app.dependency_overrides[get_api_key] = lambda: monitor_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.delete(
                "/v1/monitor/mon_abc123",
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 204
    assert sub.status == "cancelled"


def test_unsubscribe_non_owner_rejected():
    """A different API key cannot cancel someone else's subscription → 403."""
    from app.dependencies import get_api_key
    other_key = _make_key(tier="monitor", key_id=99)  # different id
    sub = _make_subscription(api_key_id=10)  # belongs to key_id=10

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = sub
        session.execute = AsyncMock(return_value=result)
        session.commit = AsyncMock()
        yield session

    from app.database import get_db
    from main import app

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: other_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.delete(
                "/v1/monitor/mon_abc123",
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "FORBIDDEN"


def test_unsubscribe_not_found():
    """Deleting a nonexistent subscription → 404."""
    from app.dependencies import get_api_key
    from app.database import get_db
    from main import app

    monitor_key = _make_key()

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: monitor_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.delete(
                "/v1/monitor/mon_doesnotexist",
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# GET /v1/monitor/{subscription_id}/history
# ---------------------------------------------------------------------------

def test_history_not_found(client: TestClient):
    """Nonexistent subscription_id → 404."""
    response = client.get("/v1/monitor/mon_doesnotexist/history")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "NOT_FOUND"


def test_history_empty():
    """Found subscription with no history → 200 with empty history list."""
    from app.database import get_db
    from main import app

    sub = _make_subscription()
    sub.last_scan_id = None
    sub.alerts = []

    async def mock_db():
        session = AsyncMock()

        # First execute: subscription query
        sub_result = MagicMock()
        sub_result.scalar_one_or_none.return_value = sub

        # Second execute: scans query (empty)
        scan_result = MagicMock()
        scan_scalars = MagicMock()
        scan_scalars.all.return_value = []
        scan_result.scalars.return_value = scan_scalars

        session.execute = AsyncMock(side_effect=[sub_result, scan_result])
        yield session

    app.dependency_overrides[get_db] = mock_db

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.get("/v1/monitor/mon_abc123/history")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["subscription_id"] == "mon_abc123"
    assert data["history"] == []
    assert data["current_status"] == "active"
    assert data["last_score"] is None


def test_history_with_scan_and_alert():
    """Subscription with one scan + one alert → history list has 1 entry with 1 alert."""
    from app.database import get_db
    from main import app

    now = datetime.now(timezone.utc)

    alert = MagicMock()
    alert.scan_id = "dep_scan001"
    alert.previous_score = 80
    alert.new_score = 45
    alert.webhook_status = "sent"
    alert.created_at = now

    sub = _make_subscription()
    sub.last_scan_id = "dep_scan001"
    sub.last_score = 45
    sub.alerts = [alert]

    mock_scan = MagicMock()
    mock_scan.scan_id = "dep_scan001"
    mock_scan.overall_score = 45
    mock_scan.scan_status = "RISK"
    mock_scan.completed_at = now
    mock_scan.created_at = now

    async def mock_db():
        session = AsyncMock()

        sub_result = MagicMock()
        sub_result.scalar_one_or_none.return_value = sub

        scan_scalars = MagicMock()
        scan_scalars.all.return_value = [mock_scan]
        scan_result = MagicMock()
        scan_result.scalars.return_value = scan_scalars

        session.execute = AsyncMock(side_effect=[sub_result, scan_result])
        yield session

    app.dependency_overrides[get_db] = mock_db

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.get("/v1/monitor/mon_abc123/history")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["last_score"] == 45
    assert len(data["history"]) == 1
    entry = data["history"][0]
    assert entry["scan_id"] == "dep_scan001"
    assert entry["overall_score"] == 45
    assert entry["status"] == "RISK"
    assert len(entry["alerts"]) == 1
    assert entry["alerts"][0]["previous_score"] == 80
    assert entry["alerts"][0]["new_score"] == 45
    assert entry["alerts"][0]["webhook_status"] == "sent"
