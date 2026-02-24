"""Domain blacklist checker.

Fase 0: Spamhaus DBL (DNS-based, free, no API key required).
Fase 1: AbuseIPDB (IP reputation, requires API key).
"""

import asyncio
import logging
import socket
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

SPAMHAUS_DBL_ZONE = "dbl.spamhaus.org"
DNS_TIMEOUT_SECONDS = 5.0
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _spamhaus_dbl_check_sync(domain: str) -> bool:
    """Check domain against Spamhaus DBL via DNS. Blocking."""
    query = f"{domain}.{SPAMHAUS_DBL_ZONE}"
    try:
        socket.getaddrinfo(query, None, socket.AF_INET)
        return True  # resolved → domain is listed
    except socket.gaierror:
        return False  # NXDOMAIN → not listed


def _resolve_ip_sync(domain: str) -> str:
    """Resolve domain to its first IPv4 address. Blocking."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return infos[0][4][0]
    except (socket.gaierror, IndexError):
        return ""


async def _check_abuseipdb(domain: str) -> int:
    """Return AbuseIPDB confidence score (0–100) for the domain's IP.

    Falls back to 0 on any error or if API key is not configured.
    """
    settings = get_settings()
    if not settings.abuseipdb_api_key:
        return 0

    # Resolve domain → IP in thread pool (blocking DNS call)
    loop = asyncio.get_event_loop()
    try:
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, _resolve_ip_sync, domain),
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except (asyncio.TimeoutError, Exception) as exc:
        logger.warning(f"AbuseIPDB DNS resolve failed for {domain}: {exc}")
        return 0

    if not ip:
        return 0

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            return int(data.get("data", {}).get("abuseConfidenceScore", 0))
    except Exception as exc:
        logger.warning(f"AbuseIPDB check failed for {domain} ({ip}): {exc}")
        return 0


async def check_blacklist(url: str) -> Dict[str, Any]:
    """Check if the URL's domain is in Spamhaus DBL and query AbuseIPDB.

    Returns:
        dict with in_blacklist (bool) and abuse_score (int 0–100)
    """
    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        return {"in_blacklist": False, "abuse_score": 0}

    # Strip www. — Spamhaus indexes apex domain
    if domain.startswith("www."):
        domain = domain[4:]

    loop = asyncio.get_event_loop()

    async def _spamhaus() -> bool:
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _spamhaus_dbl_check_sync, domain),
                timeout=DNS_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Spamhaus DBL check timed out for {domain}")
            return False
        except Exception as e:
            logger.warning(f"Spamhaus DBL check error for {domain}: {e}")
            return False

    # Run both checks in parallel
    in_blacklist, abuse_score = await asyncio.gather(
        _spamhaus(),
        _check_abuseipdb(domain),
    )

    return {"in_blacklist": in_blacklist, "abuse_score": abuse_score}
