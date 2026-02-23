"""Domain blacklist checker.

Fase 0: Spamhaus DBL (DNS-based, free, no API key required).
Fase 1: Add AbuseIPDB.
"""

import asyncio
import logging
import socket
from typing import Any, Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

SPAMHAUS_DBL_ZONE = "dbl.spamhaus.org"
DNS_TIMEOUT_SECONDS = 5.0


def _spamhaus_dbl_check_sync(domain: str) -> bool:
    """Check domain against Spamhaus DBL via DNS. Blocking."""
    query = f"{domain}.{SPAMHAUS_DBL_ZONE}"
    try:
        socket.getaddrinfo(query, None, socket.AF_INET)
        return True  # resolved → domain is listed
    except socket.gaierror:
        return False  # NXDOMAIN → not listed


async def check_blacklist(url: str) -> Dict[str, Any]:
    """Check if the URL's domain is in Spamhaus DBL.

    Returns:
        dict with in_blacklist (bool)
    """
    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        return {"in_blacklist": False}

    # Strip www. — Spamhaus indexes apex domain
    if domain.startswith("www."):
        domain = domain[4:]

    loop = asyncio.get_event_loop()
    try:
        in_blacklist = await asyncio.wait_for(
            loop.run_in_executor(None, _spamhaus_dbl_check_sync, domain),
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(f"Spamhaus DBL check timed out for {domain}")
        in_blacklist = False
    except Exception as e:
        logger.warning(f"Spamhaus DBL check error for {domain}: {e}")
        in_blacklist = False

    return {"in_blacklist": in_blacklist}
