"""Unit tests for domain_rep service — uses python-whois (no API key required)."""

import asyncio
import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.domain_rep import get_domain_rep, _extract_domain, _whois_lookup_sync


# ---------------------------------------------------------------------------
# _extract_domain unit tests
# ---------------------------------------------------------------------------

def test_extract_domain_strips_www():
    assert _extract_domain("https://www.example.com/path") == "example.com"


def test_extract_domain_no_www():
    assert _extract_domain("https://api.example.com") == "api.example.com"


def test_extract_domain_invalid():
    assert _extract_domain("not-a-url") is None


# ---------------------------------------------------------------------------
# _whois_lookup_sync unit tests (no I/O — mocks whois.whois)
# ---------------------------------------------------------------------------

def test_whois_lookup_sync_valid_date():
    """Successful whois response with a single creation_date."""
    mock_whois = MagicMock()
    mock_whois.creation_date = datetime(2010, 1, 1, tzinfo=timezone.utc)

    with patch.dict("sys.modules", {"whois": MagicMock(whois=MagicMock(return_value=mock_whois))}):
        result = _whois_lookup_sync("example.com")

    assert result["age_days"] is not None and result["age_days"] > 3000
    assert result["owner_changed"] is None


def test_whois_lookup_sync_list_of_dates():
    """When creation_date is a list, use the earliest."""
    mock_whois = MagicMock()
    mock_whois.creation_date = [
        datetime(2015, 6, 1, tzinfo=timezone.utc),
        datetime(2010, 1, 1, tzinfo=timezone.utc),  # earliest
    ]

    with patch.dict("sys.modules", {"whois": MagicMock(whois=MagicMock(return_value=mock_whois))}):
        result = _whois_lookup_sync("example.com")

    assert result["age_days"] is not None and result["age_days"] > 3000


def test_whois_lookup_sync_none_date():
    """When creation_date is None, returns age_days=None."""
    mock_whois = MagicMock()
    mock_whois.creation_date = None

    with patch.dict("sys.modules", {"whois": MagicMock(whois=MagicMock(return_value=mock_whois))}):
        result = _whois_lookup_sync("example.com")

    assert result == {"age_days": None, "owner_changed": None}


# ---------------------------------------------------------------------------
# get_domain_rep async integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_domain_rep_cache_hit():
    """Cached value is returned without hitting WHOIS servers."""
    cached_data = json.dumps({"age_days": 500, "owner_changed": None})
    with patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=cached_data)):
        result = await get_domain_rep("https://example.com")

    assert result["age_days"] == 500
    assert result["owner_changed"] is None


@pytest.mark.asyncio
async def test_get_domain_rep_valid_response():
    """Successful WHOIS lookup → correct age_days, owner_changed=None."""
    mock_result = {"age_days": 5000, "owner_changed": None}

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.set_cached", new=AsyncMock()),
        patch("app.services.domain_rep.asyncio.wait_for", new=AsyncMock(return_value=mock_result)),
    ):
        result = await get_domain_rep("https://example.com")

    assert result["age_days"] == 5000
    assert result["owner_changed"] is None


@pytest.mark.asyncio
async def test_get_domain_rep_owner_changed_always_none():
    """owner_changed is always None — python-whois has no historical data."""
    mock_result = {"age_days": 1000, "owner_changed": None}

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.set_cached", new=AsyncMock()),
        patch("app.services.domain_rep.asyncio.wait_for", new=AsyncMock(return_value=mock_result)),
    ):
        result = await get_domain_rep("https://example.com")

    assert result["owner_changed"] is None


@pytest.mark.asyncio
async def test_get_domain_rep_timeout():
    """WHOIS timeout falls back silently to None values."""
    async def raise_timeout(*args, **kwargs):
        raise asyncio.TimeoutError()

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.asyncio.wait_for", side_effect=raise_timeout),
    ):
        result = await get_domain_rep("https://example.com")

    assert result == {"age_days": None, "owner_changed": None}


@pytest.mark.asyncio
async def test_get_domain_rep_whois_error():
    """Any WHOIS error falls back silently to None values."""
    async def raise_error(*args, **kwargs):
        raise Exception("connection refused")

    with (
        patch("app.services.domain_rep.get_cached", new=AsyncMock(return_value=None)),
        patch("app.services.domain_rep.asyncio.wait_for", side_effect=raise_error),
    ):
        result = await get_domain_rep("https://example.com")

    assert result == {"age_days": None, "owner_changed": None}


@pytest.mark.asyncio
async def test_get_domain_rep_invalid_url():
    """URL without a valid hostname returns None values immediately."""
    result = await get_domain_rep("not-a-url")
    assert result == {"age_days": None, "owner_changed": None}
