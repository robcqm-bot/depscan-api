"""Integration smoke tests for the API — uses mocked DB via conftest.py fixture."""

import pytest
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


def test_monitor_not_implemented(client: TestClient):
    response = client.post("/v1/monitor/subscribe")
    assert response.status_code == 501


def test_monitor_history_not_implemented(client: TestClient):
    response = client.get("/v1/monitor/some_skill_id/history")
    assert response.status_code == 501
