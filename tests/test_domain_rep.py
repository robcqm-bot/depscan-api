"""Unit tests for domain_rep service — mocks httpx and Redis."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.domain_rep import get_domain_rep, _parse_age_days, _extract_domain


# ---------------------------------------------------------------------------
# Helper / unit tests
# ---------------------------------------------------------------------------

def test_extract_domain_strips_www():
    assert _extract_domain("https://www.example.com/path") == "example.com"


def test_extract_domain_no_www():
    assert _extract_domain("https://api.example.com") == "api.example.com"


def test_extract_domain_invalid():
    assert _extract_domain("not-a-url") is None


def test_parse_age_days_valid_date():
    # Use a fixed date far in the past to guarantee positive days
    days = _parse_age_days("2010-01-01")
    assert days is not None and days > 3000


def test_parse_age_days_iso_datetime():
    days = _parse_age_days("2010-01-01T00:00:00")
    assert days is not None and days > 3000


def test_parse_age_days_none():
    assert _parse_age_days(None) is None


def test_parse_age_days_invalid_string():
    assert _parse_age_days("not-a-date") is None


# ---------------------------------------------------------------------------
# Async integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_domain_rep_no_api_key():
    """No whois_api_key → silent fallback with None values."""
    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.get_settings") as mock_settings,
    ):
        settings = MagicMock()
        settings.whois_api_key = ""
        mock_settings.return_value = settings

        result = await get_domain_rep("https://example.com")

    assert result == {"age_days": None, "owner_changed": None}


@pytest.mark.asyncio
async def test_get_domain_rep_cache_hit():
    """Cached value is returned immediately without hitting the API."""
    cached_data = json.dumps({"age_days": 500, "owner_changed": False})
    with patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=cached_data)):
        result = await get_domain_rep("https://example.com")

    assert result["age_days"] == 500
    assert result["owner_changed"] is False


@pytest.mark.asyncio
async def test_get_domain_rep_valid_response():
    """Successful whoisxmlapi.com response is parsed correctly."""
    api_response = {
        "WhoisRecord": {
            "createdDate": "2010-03-15",
            "registrant": {"organization": "Example Corp"},
        }
    }
    mock_response = MagicMock()
    mock_response.json.return_value = api_response
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.set_cached", new=AsyncMock()),
        patch("app.services.domain_rep.get_settings") as mock_settings,
        patch("app.services.domain_rep.httpx.AsyncClient", return_value=mock_client),
    ):
        settings = MagicMock()
        settings.whois_api_key = "test_key_123"
        mock_settings.return_value = settings

        result = await get_domain_rep("https://example.com")

    assert result["age_days"] is not None and result["age_days"] > 3000
    assert result["owner_changed"] is None  # registrant org only in one place → no change detected


@pytest.mark.asyncio
async def test_get_domain_rep_owner_changed_flag():
    """Differing registrant orgs between registrant and registryData → owner_changed=True."""
    api_response = {
        "WhoisRecord": {
            "createdDate": "2015-06-01",
            "registrant": {"organization": "New Owner Corp"},
            "registryData": {"registrant": {"organization": "Original Owner LLC"}},
        }
    }
    mock_response = MagicMock()
    mock_response.json.return_value = api_response
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.set_cached", new=AsyncMock()),
        patch("app.services.domain_rep.get_settings") as mock_settings,
        patch("app.services.domain_rep.httpx.AsyncClient", return_value=mock_client),
    ):
        settings = MagicMock()
        settings.whois_api_key = "test_key_123"
        mock_settings.return_value = settings

        result = await get_domain_rep("https://example.com")

    assert result["owner_changed"] is True


@pytest.mark.asyncio
async def test_get_domain_rep_api_timeout():
    """Network timeout falls back silently to None values."""
    import httpx as _httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timeout"))

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.set_cached", new=AsyncMock()),
        patch("app.services.domain_rep.get_settings") as mock_settings,
        patch("app.services.domain_rep.httpx.AsyncClient", return_value=mock_client),
    ):
        settings = MagicMock()
        settings.whois_api_key = "test_key_123"
        mock_settings.return_value = settings

        result = await get_domain_rep("https://example.com")

    assert result == {"age_days": None, "owner_changed": None}


@pytest.mark.asyncio
async def test_get_domain_rep_invalid_url():
    """URL without a hostname returns None values immediately."""
    result = await get_domain_rep("not-a-url")
    assert result == {"age_days": None, "owner_changed": None}
