"""Domain reputation lookup via WHOIS (whoapi.com).

Fase 1: provides domain age and owner-change detection.
Silent fallback on any error — never breaks a scan.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from app.cache import get_cached, set_cached
from app.config import get_settings

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400  # 24 hours — WHOIS data changes rarely
WHOISXML_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


def _extract_domain(url: str) -> Optional[str]:
    """Extract apex domain from URL, stripping www."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _parse_age_days(date_str: Optional[str]) -> Optional[int]:
    """Parse an ISO-like date string and return days since that date."""
    if not date_str:
        return None
    # whoapi returns dates in formats like "2008-10-06" or "2008-10-06T00:00:00"
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            created = datetime.strptime(date_str[:19], fmt).replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - created
            return max(0, delta.days)
        except (ValueError, TypeError):
            continue
    return None


async def get_domain_rep(url: str) -> Dict[str, Any]:
    """Return domain age and owner-change flag for the given URL.

    Returns:
        dict with keys:
            age_days (Optional[int])
            owner_changed (Optional[bool])
    Fallback: {"age_days": None, "owner_changed": None}
    """
    domain = _extract_domain(url)
    if not domain:
        return {"age_days": None, "owner_changed": None}

    cache_key = f"depscan:domain:{domain}"
    cached = await get_cached(cache_key)
    if cached:
        import json
        try:
            return json.loads(cached)
        except Exception:
            pass

    settings = get_settings()
    if not settings.whois_api_key:
        return {"age_days": None, "owner_changed": None}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                WHOISXML_URL,
                params={
                    "apiKey": settings.whois_api_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                    "thin": 0,
                },
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning(f"WHOIS lookup failed for {domain}: {exc}")
        return {"age_days": None, "owner_changed": None}

    # whoisxmlapi wraps everything under "WhoisRecord"
    record = data.get("WhoisRecord", {})
    if not record:
        logger.warning(f"WHOIS empty record for {domain}")
        return {"age_days": None, "owner_changed": None}

    # Parse age from createdDate
    date_created = record.get("createdDate") or record.get("registryData", {}).get("createdDate")
    age_days = _parse_age_days(date_created)

    # Detect owner change via updatedDate vs createdDate proximity or registrant org change
    owner_changed: Optional[bool] = None
    registrant = record.get("registrant", {})
    registry_registrant = record.get("registryData", {}).get("registrant", {})
    reg_org = registrant.get("organization") or registrant.get("name")
    reg_org_registry = registry_registrant.get("organization") or registry_registrant.get("name")
    if reg_org and reg_org_registry and reg_org != reg_org_registry:
        owner_changed = True

    result = {"age_days": age_days, "owner_changed": owner_changed}

    import json
    try:
        await set_cached(cache_key, json.dumps(result), ttl=CACHE_TTL_SECONDS)
    except Exception:
        pass

    return result
