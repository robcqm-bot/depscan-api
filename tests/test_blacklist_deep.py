"""Tests for AbuseIPDB integration in blacklist.py (Fase 1)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.blacklist import check_blacklist, _check_abuseipdb


# ---------------------------------------------------------------------------
# _check_abuseipdb unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_abuseipdb_no_api_key():
    """Returns 0 immediately when abuseipdb_api_key is not configured."""
    with patch("app.services.blacklist.get_settings") as mock_settings:
        settings = MagicMock()
        settings.abuseipdb_api_key = ""
        mock_settings.return_value = settings

        score = await _check_abuseipdb("example.com")

    assert score == 0


@pytest.mark.asyncio
async def test_abuseipdb_returns_score():
    """Successful API response returns the confidence score."""
    api_response = {"data": {"abuseConfidenceScore": 42}}
    mock_response = MagicMock()
    mock_response.json.return_value = api_response
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with (
        patch("app.services.blacklist.get_settings") as mock_settings,
        patch("app.services.blacklist.httpx.AsyncClient", return_value=mock_client),
        # Resolve "example.com" → a real-ish IP in the test
        patch(
            "app.services.blacklist._resolve_ip_sync",
            return_value="93.184.216.34",
        ),
    ):
        settings = MagicMock()
        settings.abuseipdb_api_key = "test_key"
        mock_settings.return_value = settings

        score = await _check_abuseipdb("example.com")

    assert score == 42


@pytest.mark.asyncio
async def test_abuseipdb_network_error_fallback():
    """Network error falls back to 0."""
    import httpx as _httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_httpx.ConnectError("refused"))

    with (
        patch("app.services.blacklist.get_settings") as mock_settings,
        patch("app.services.blacklist.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.blacklist._resolve_ip_sync", return_value="93.184.216.34"),
    ):
        settings = MagicMock()
        settings.abuseipdb_api_key = "test_key"
        mock_settings.return_value = settings

        score = await _check_abuseipdb("example.com")

    assert score == 0


@pytest.mark.asyncio
async def test_abuseipdb_unresolvable_domain():
    """Domain that can't be resolved → score 0 without calling API."""
    with (
        patch("app.services.blacklist.get_settings") as mock_settings,
        patch("app.services.blacklist._resolve_ip_sync", return_value=""),
    ):
        settings = MagicMock()
        settings.abuseipdb_api_key = "test_key"
        mock_settings.return_value = settings

        score = await _check_abuseipdb("unresolvable.invalid")

    assert score == 0


# ---------------------------------------------------------------------------
# check_blacklist integration (returns both fields)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_blacklist_returns_abuse_score():
    """check_blacklist() includes abuse_score in the result dict."""
    with (
        patch(
            "app.services.blacklist._spamhaus_dbl_check_sync",
            return_value=False,
        ),
        patch(
            "app.services.blacklist._check_abuseipdb",
            new=AsyncMock(return_value=75),
        ),
    ):
        result = await check_blacklist("https://example.com")

    assert "in_blacklist" in result
    assert "abuse_score" in result
    assert result["in_blacklist"] is False
    assert result["abuse_score"] == 75


@pytest.mark.asyncio
async def test_check_blacklist_no_domain():
    """URL without a parseable domain returns safe defaults."""
    result = await check_blacklist("not-a-url")
    assert result == {"in_blacklist": False, "abuse_score": 0}


@pytest.mark.asyncio
async def test_check_blacklist_spamhaus_listed():
    """Domain in Spamhaus → in_blacklist=True regardless of abuse_score."""
    with (
        patch(
            "app.services.blacklist._spamhaus_dbl_check_sync",
            return_value=True,
        ),
        patch(
            "app.services.blacklist._check_abuseipdb",
            new=AsyncMock(return_value=0),
        ),
    ):
        result = await check_blacklist("https://malware-domain.com")

    assert result["in_blacklist"] is True
    assert result["abuse_score"] == 0
