"""Domain reputation lookup via python-whois (free, no API key required).

Queries WHOIS servers directly — no external API, no cost, no artificial
rate limits. The 24h Redis cache prevents hammering WHOIS servers.

owner_changed detection returns None always: python-whois exposes current
registrant data only, not historical. Conservative fallback per design.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from app.cache import get_cached, set_cached

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400   # 24 hours — WHOIS data changes rarely
WHOIS_TIMEOUT_SECONDS = 10.0


def _extract_domain(url: str) -> Optional[str]:
    """Extract apex domain from URL, stripping www."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _whois_lookup_sync(domain: str) -> Dict[str, Any]:
    """Synchronous WHOIS lookup. Designed to run in a thread-pool executor."""
    import whois  # lazy import — avoids slow module-load in every worker

    w = whois.whois(domain)
    creation_date = w.creation_date

    # creation_date can be a single datetime or a list (multiple registrars)
    if isinstance(creation_date, list):
        dates = [d for d in creation_date if isinstance(d, datetime)]
        if not dates:
            return {"age_days": None, "owner_changed": None}
        creation_date = min(dates)

    if not isinstance(creation_date, datetime):
        return {"age_days": None, "owner_changed": None}

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    age_days = max(0, (datetime.now(timezone.utc) - creation_date).days)
    return {"age_days": age_days, "owner_changed": None}


async def get_domain_rep(url: str) -> Dict[str, Any]:
    """Return domain age for the given URL.

    Returns:
        dict with keys:
            age_days (Optional[int])
            owner_changed (Optional[bool])  — always None (no historical data)
    Fallback: {"age_days": None, "owner_changed": None}
    """
    domain = _extract_domain(url)
    if not domain:
        return {"age_days": None, "owner_changed": None}

    cache_key = f"depscan:domain:{domain}"
    cached = await get_cached(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _whois_lookup_sync, domain),
            timeout=WHOIS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("WHOIS lookup timed out for %s", domain)
        return {"age_days": None, "owner_changed": None}
    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, type(exc).__name__)
        return {"age_days": None, "owner_changed": None}

    try:
        await set_cached(cache_key, json.dumps(result), ttl=CACHE_TTL_SECONDS)
    except Exception:
        pass

    return result
