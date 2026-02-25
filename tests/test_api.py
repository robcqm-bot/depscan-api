"""Integration smoke tests for the API — uses mocked DB via conftest.py fixture."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    response = client.get("/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_docs_available(client: TestClient):
    response = client.get("/docs")
    assert response.status_code == 200


def test_scan_requires_auth(client: TestClient):
    response = client.post(
        "/v1/scan-deps",
        json={"endpoints": ["https://example.com"]},
    )
    assert response.status_code == 401


def test_scan_missing_auth_header(client: TestClient):
    response = client.post(
        "/v1/scan-deps",
        json={"endpoints": ["https://example.com"]},
    )
    detail = response.json()["detail"]
    assert detail["code"] == "AUTH_MISSING"


def test_scan_invalid_bearer_format(client: TestClient):
    response = client.post(
        "/v1/scan-deps",
        json={"endpoints": ["https://example.com"]},
        headers={"Authorization": "Token something"},
    )
    assert response.status_code == 401


def test_scan_wrong_key_prefix(client: TestClient):
    response = client.post(
        "/v1/scan-deps",
        json={"endpoints": ["https://example.com"]},
        headers={"Authorization": "Bearer sk_not_a_dsk_key"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_INVALID"


def test_scan_unknown_key(client: TestClient):
    """Valid format key that's not in DB → 401 AUTH_NOT_FOUND."""
    response = client.post(
        "/v1/scan-deps",
        json={"endpoints": ["https://example.com"]},
        headers={"Authorization": "Bearer dsk_live_unknownkey123456"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_NOT_FOUND"


def test_scan_missing_endpoints_validation(client: TestClient):
    """Body with no skill_url or endpoints → 422 from Pydantic (or 401 if auth runs first).

    FastAPI resolves header dependencies (auth) before body validation, so without
    a valid Bearer token the response is 401. Either outcome is correct.
    """
    response = client.post(
        "/v1/scan-deps",
        json={},
    )
    assert response.status_code in (401, 422)


def test_checkout_invalid_tier(client: TestClient):
    response = client.post(
        "/v1/billing/checkout",
        json={"tier": "not_a_tier", "quantity": 10},
    )
    assert response.status_code == 422


def test_webhook_without_signature(client: TestClient):
    response = client.post(
        "/v1/webhook/stripe",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_monitor_subscribe_requires_auth(client: TestClient):
    """POST /v1/monitor/subscribe requires Bearer token."""
    response = client.post(
        "/v1/monitor/subscribe",
        json={"endpoints": ["https://api.github.com"]},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Deep scan — Fase 1 (no longer 501)
# ---------------------------------------------------------------------------

def _make_active_key():
    """Return a MagicMock APIKey with enough credits for a deep scan."""
    from app.models.db import APIKey
    key = MagicMock(spec=APIKey)
    key.id = 1
    key.tier = "deep"
    key.credits_remaining = 10
    key.status = "active"
    key.last_used_at = None
    return key


def test_deep_scan_no_longer_returns_501(client: TestClient):
    """POST /v1/scan-deps with scan_type=deep is now accepted (no 501)."""
    from app.database import get_db
    from app.dependencies import get_api_key
    from app.models.scan import EndpointResult
    from main import app

    active_key = _make_active_key()

    endpoint_result = EndpointResult(
        url="https://api.github.com",
        status="UP",
        latency_ms=100,
        ssl_expires_days=120,
        ssl_valid=True,
        domain_age_days=5000,
        domain_owner_changed=False,
        abuse_score=0,
        in_blacklist=False,
        flags=[],
        score=100,
    )

    async def mock_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = active_key
        session.execute = AsyncMock(return_value=result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db
    app.dependency_overrides[get_api_key] = lambda: active_key

    with (
        patch("app.routers.scan.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.routers.scan.extract_urls", new=AsyncMock(return_value=["https://api.github.com"])),
        patch("app.routers.scan.get_insight_generator") as mock_ig,
        patch("app.routers.scan.check_rate_limit", new=AsyncMock()),
    ):
        mock_ig.return_value.analyze = AsyncMock(return_value=None)

        with TestClient(app, raise_server_exceptions=False) as c:
            response = c.post(
                "/v1/scan-deps",
                json={"endpoints": ["https://api.github.com"], "scan_type": "deep"},
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()

    # Should not be 501 — deep scan is now enabled
    assert response.status_code != 501
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "deep"


# ---------------------------------------------------------------------------
# GET /v1/scan/{scan_id}
# ---------------------------------------------------------------------------

def test_get_scan_not_found(client: TestClient):
    """GET /v1/scan/<unknown> without auth → 401 (auth is now required)."""
    response = client.get("/v1/scan/dep_doesnotexist")
    assert response.status_code == 401


def test_get_scan_found():
    """GET /v1/scan/<known_id> with owner's API key → 200 with ScanResponse."""
    from app.database import get_db
    from app.dependencies import get_api_key
    from main import app
    from datetime import datetime, timezone

    owner_key = _make_active_key()
    owner_key.id = 42

    # Build mock DB scan row with endpoint_results
    mock_endpoint = MagicMock()
    mock_endpoint.url = "https://api.github.com"
    mock_endpoint.status = "UP"
    mock_endpoint.latency_ms = 80
    mock_endpoint.ssl_expires_days = 200
    mock_endpoint.ssl_valid = True
    mock_endpoint.domain_age_days = 5000
    mock_endpoint.domain_owner_changed = False
    mock_endpoint.abuse_score = 0
    mock_endpoint.in_blacklist = False
    mock_endpoint.flags = "[]"
    mock_endpoint.score = 100

    mock_scan = MagicMock()
    mock_scan.scan_id = "dep_abc123"
    mock_scan.api_key_id = 42  # matches owner_key.id
    mock_scan.skill_url = None
    mock_scan.overall_score = 100
    mock_scan.scan_status = "SAFE"
    mock_scan.recommendation = "SAFE_TO_INSTALL"
    mock_scan.scan_type = "single"
    mock_scan.created_at = datetime.now(timezone.utc)
    mock_scan.completed_at = datetime.now(timezone.utc)
    mock_scan.processing_time_ms = 500
    mock_scan.endpoint_results = [mock_endpoint]

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
                "/v1/scan/dep_abc123",
                headers={"Authorization": "Bearer dsk_live_testkey"},
            )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "dep_abc123"
    assert data["overall_score"] == 100
    assert data["status"] == "SAFE"
    assert len(data["endpoints"]) == 1
    assert data["endpoints"][0]["url"] == "https://api.github.com"
    assert data["ai_insight"] is None
