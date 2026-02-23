"""Unit tests for the checker service — mocks network calls."""

import pytest
from unittest.mock import AsyncMock, patch

from app.models.scan import EndpointResult
from app.services.checker import check_endpoint


@pytest.mark.asyncio
async def test_check_endpoint_up():
    uptime_data = {"status": "UP", "latency_ms": 150, "redirect_count": 0}
    ssl_data = {"ssl_valid": True, "ssl_expires_days": 120}
    blacklist_data = {"in_blacklist": False}

    with (
        patch("app.services.checker.uptime_svc.check_uptime", new=AsyncMock(return_value=uptime_data)),
        patch("app.services.checker.ssl_svc.check_ssl", new=AsyncMock(return_value=ssl_data)),
        patch("app.services.checker.blacklist_svc.check_blacklist", new=AsyncMock(return_value=blacklist_data)),
        patch("app.services.checker.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.checker.set_cached", new=AsyncMock()),
    ):
        result = await check_endpoint("https://example.com")

    assert isinstance(result, EndpointResult)
    assert result.status == "UP"
    assert result.latency_ms == 150
    assert result.ssl_valid is True
    assert result.in_blacklist is False
    assert result.score == 100


@pytest.mark.asyncio
async def test_check_endpoint_ssl_error():
    uptime_data = {"status": "UP", "latency_ms": 100, "redirect_count": 0}
    ssl_data = {"ssl_valid": False, "ssl_expires_days": None}
    blacklist_data = {"in_blacklist": False}

    with (
        patch("app.services.checker.uptime_svc.check_uptime", new=AsyncMock(return_value=uptime_data)),
        patch("app.services.checker.ssl_svc.check_ssl", new=AsyncMock(return_value=ssl_data)),
        patch("app.services.checker.blacklist_svc.check_blacklist", new=AsyncMock(return_value=blacklist_data)),
        patch("app.services.checker.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.checker.set_cached", new=AsyncMock()),
    ):
        result = await check_endpoint("https://example.com")

    assert result.status == "SSL_ERROR"
    assert result.ssl_valid is False
    assert result.score <= 55  # significant penalty


@pytest.mark.asyncio
async def test_check_endpoint_no_https_flag():
    uptime_data = {"status": "UP", "latency_ms": 80, "redirect_count": 0}
    ssl_data = {"ssl_valid": None, "ssl_expires_days": None}
    blacklist_data = {"in_blacklist": False}

    with (
        patch("app.services.checker.uptime_svc.check_uptime", new=AsyncMock(return_value=uptime_data)),
        patch("app.services.checker.ssl_svc.check_ssl", new=AsyncMock(return_value=ssl_data)),
        patch("app.services.checker.blacklist_svc.check_blacklist", new=AsyncMock(return_value=blacklist_data)),
        patch("app.services.checker.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.checker.set_cached", new=AsyncMock()),
    ):
        result = await check_endpoint("http://example.com")

    assert "NO_HTTPS" in result.flags
    assert result.score == 85


@pytest.mark.asyncio
async def test_check_endpoint_redirect_chain():
    uptime_data = {"status": "UP", "latency_ms": 300, "redirect_count": 4}
    ssl_data = {"ssl_valid": True, "ssl_expires_days": 60}
    blacklist_data = {"in_blacklist": False}

    with (
        patch("app.services.checker.uptime_svc.check_uptime", new=AsyncMock(return_value=uptime_data)),
        patch("app.services.checker.ssl_svc.check_ssl", new=AsyncMock(return_value=ssl_data)),
        patch("app.services.checker.blacklist_svc.check_blacklist", new=AsyncMock(return_value=blacklist_data)),
        patch("app.services.checker.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.checker.set_cached", new=AsyncMock()),
    ):
        result = await check_endpoint("https://example.com")

    assert "REDIRECT_CHAIN" in result.flags
    assert result.score == 90


@pytest.mark.asyncio
async def test_check_endpoint_uses_cache():
    cached_result = EndpointResult(
        url="https://cached.com",
        status="UP",
        latency_ms=50,
        ssl_valid=True,
        ssl_expires_days=200,
        in_blacklist=False,
        flags=[],
        score=100,
    )

    with patch(
        "app.services.checker.get_cached",
        new=AsyncMock(return_value=cached_result.model_dump_json()),
    ):
        result = await check_endpoint("https://cached.com")

    assert result.score == 100
    assert result.latency_ms == 50
