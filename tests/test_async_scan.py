"""Tests for async scan flow (Fase 2) — callback_url with > 10 endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_active_key(tier: str = "deep", credits: int = 10):
    from app.models.db import APIKey
    key = MagicMock(spec=APIKey)
    key.id = 1
    key.tier = tier
    key.credits_remaining = credits
    key.status = "active"
    key.last_used_at = None
    return key


def _make_endpoint_result(url: str = "https://example.com"):
    from app.models.scan import EndpointResult
    return EndpointResult(
        url=url,
        status="UP",
        latency_ms=100,
        ssl_expires_days=200,
        ssl_valid=True,
        domain_age_days=3000,
        domain_owner_changed=False,
        abuse_score=0,
        in_blacklist=False,
        flags=[],
        score=100,
    )


def _build_client(active_key, db_execute_side_effect=None):
    """Return (TestClient, app) with mocked dependencies."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.dependencies import get_api_key

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        # By default the atomice credit deduct returns a value (success)
        result.scalar_one_or_none.return_value = active_key.credits_remaining - 1
        if db_execute_side_effect:
            session.execute = AsyncMock(side_effect=db_execute_side_effect)
        else:
            session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: active_key
    return app, get_db, get_api_key


# ---------------------------------------------------------------------------
# Sync path: ≤ 10 endpoints (existing behaviour unchanged)
# ---------------------------------------------------------------------------

def test_sync_scan_ten_endpoints_no_callback():
    """10 endpoints and no callback_url → synchronous (no PENDING)."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.dependencies import get_api_key

    active_key = _make_active_key()
    urls = [f"https://example{i}.com" for i in range(10)]
    endpoint_results = [_make_endpoint_result(u) for u in urls]

    app_, _gdb, _gak = _build_client(active_key)

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.run_scan", new=AsyncMock(return_value=endpoint_results)),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=urls)),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
        patch("app.routers.scan.get_insight_generator") as mock_ig,
    ):
        mock_ig.return_value.analyze = AsyncMock(return_value=None)
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={"endpoints": urls},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    # Sync response should not be PENDING
    assert data["status"] != "PENDING"
    assert len(data["endpoints"]) == 10


def test_sync_scan_more_than_ten_no_callback():
    """More than 10 endpoints but NO callback_url → still synchronous."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.dependencies import get_api_key

    active_key = _make_active_key()
    urls = [f"https://example{i}.com" for i in range(15)]
    endpoint_results = [_make_endpoint_result(u) for u in urls]

    app_, _gdb, _gak = _build_client(active_key)

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.run_scan", new=AsyncMock(return_value=endpoint_results)),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=urls)),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
        patch("app.routers.scan.get_insight_generator") as mock_ig,
    ):
        mock_ig.return_value.analyze = AsyncMock(return_value=None)
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                # No callback_url → must be sync even with 15 endpoints
                json={"endpoints": urls},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["status"] != "PENDING"


# ---------------------------------------------------------------------------
# Async path: > 10 endpoints + callback_url
# ---------------------------------------------------------------------------

def test_async_scan_returns_pending():
    """11+ endpoints + callback_url → immediate PENDING response."""
    from main import app
    from fastapi.testclient import TestClient
    from app.dependencies import get_api_key

    active_key = _make_active_key(credits=5)
    urls = [f"https://example{i}.com" for i in range(11)]

    app_, _gdb, _gak = _build_client(active_key)

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=urls)),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
        # Bypass SSRF check so the test domain doesn't trigger DNS resolution
        patch("app.routers.scan.validate_public_url", return_value=None),
        # Background task: stub out the actual scan so it doesn't run
        patch("app.routers.scan._run_async_scan", new=AsyncMock()),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={
                    "endpoints": urls,
                    "callback_url": "https://myagent.example.com/webhook",
                },
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PENDING"
    assert data["overall_score"] == 0
    assert data["endpoints"] == []
    assert data["scan_id"].startswith("dep_")


def test_async_scan_invalid_callback_url_scheme():
    """callback_url with non-http/https scheme → 400."""
    from main import app
    from fastapi.testclient import TestClient
    from app.dependencies import get_api_key

    active_key = _make_active_key()
    urls = [f"https://example{i}.com" for i in range(11)]

    app_, _gdb, _gak = _build_client(active_key)

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=urls)),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={
                    "endpoints": urls,
                    "callback_url": "ftp://malicious.example.com/hook",
                },
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_CALLBACK_URL"


def test_async_scan_private_callback_url_blocked():
    """callback_url pointing to internal address → 400 (SSRF prevention)."""
    from main import app
    from fastapi.testclient import TestClient
    from app.dependencies import get_api_key

    active_key = _make_active_key()
    urls = [f"https://example{i}.com" for i in range(11)]

    app_, _gdb, _gak = _build_client(active_key)

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=urls)),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
        patch(
            "app.routers.scan.validate_public_url",
            side_effect=ValueError("Blocked: resolves to private address"),
        ),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={
                    "endpoints": urls,
                    "callback_url": "https://192.168.1.1/hook",
                },
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "INVALID_CALLBACK_URL"


# ---------------------------------------------------------------------------
# GET /v1/scan/{scan_id} — PENDING state for in-progress async scans
# ---------------------------------------------------------------------------

def test_get_scan_returns_pending_when_incomplete():
    """GET /v1/scan/{id} returns PENDING when scan_status is None (async in progress)."""
    from main import app
    from fastapi.testclient import TestClient
    from app.database import get_db
    from app.dependencies import get_api_key

    owner_key = _make_active_key()
    owner_key.id = 42

    mock_scan = MagicMock()
    mock_scan.scan_id = "dep_pending001"
    mock_scan.api_key_id = 42
    mock_scan.skill_url = None
    mock_scan.scan_type = "deep"
    mock_scan.scan_status = None   # async scan not yet complete
    mock_scan.overall_score = None
    mock_scan.recommendation = None
    mock_scan.created_at = datetime.now(timezone.utc)
    mock_scan.completed_at = None
    mock_scan.processing_time_ms = None
    mock_scan.endpoint_results = []

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = mock_scan
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: owner_key

    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
        patch("main.AsyncIOScheduler"),
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.get(
                "/v1/scan/dep_pending001",
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PENDING"
    assert data["overall_score"] == 0
    assert data["endpoints"] == []
    assert data["scan_id"] == "dep_pending001"
