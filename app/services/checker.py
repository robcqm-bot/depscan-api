"""Orchestrates all endpoint checks in parallel with Redis caching."""

import asyncio
import logging
from typing import List
from urllib.parse import urlparse

from app.cache import get_cached, set_cached
from app.models.scan import EndpointResult
from app.services import blacklist as blacklist_svc
from app.services import domain_rep as domain_rep_svc
from app.services import scorer
from app.services import ssl_check as ssl_svc
from app.services import uptime as uptime_svc
from app.services.extractor import validate_public_url

logger = logging.getLogger(__name__)

SINGLE_CACHE_TTL = 3600   # 1 hour for single scans
DEEP_CACHE_TTL = 86400    # 24 hours for deep scans (WHOIS data is stable)


async def check_endpoint(url: str, scan_type: str = "single") -> EndpointResult:
    """Run all checks for a single endpoint; uses Redis cache."""
    cache_key = f"depscan:endpoint:{scan_type}:{url}"
    cache_ttl = DEEP_CACHE_TTL if scan_type == "deep" else SINGLE_CACHE_TTL

    # SSRF prevention — block private/internal addresses before any HTTP request
    try:
        await asyncio.get_event_loop().run_in_executor(None, validate_public_url, url)
    except ValueError as e:
        logger.warning(f"SSRF block: {e}")
        return EndpointResult(
            url=url,
            status="UNKNOWN",
            flags=["BLOCKED_PRIVATE_ADDRESS"],
            score=0,
        )

    # Cache lookup
    cached = await get_cached(cache_key)
    if cached:
        try:
            return EndpointResult.model_validate_json(cached)
        except Exception:
            pass  # stale/corrupt cache — recheck

    # Run checks in parallel — deep scan adds domain reputation
    if scan_type == "deep":
        uptime_result, ssl_result, blacklist_result, domain_result = await asyncio.gather(
            uptime_svc.check_uptime(url),
            ssl_svc.check_ssl(url),
            blacklist_svc.check_blacklist(url),   # includes abuse_score
            domain_rep_svc.get_domain_rep(url),   # WHOIS age + owner change
        )
    else:
        uptime_result, ssl_result, blacklist_result = await asyncio.gather(
            uptime_svc.check_uptime(url),
            ssl_svc.check_ssl(url),
            blacklist_svc.check_blacklist(url),
        )
        domain_result = {"age_days": None, "owner_changed": None}

    # Determine effective status
    status = uptime_result["status"]
    if ssl_result.get("ssl_valid") is False and status == "UP":
        status = "SSL_ERROR"

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    result = EndpointResult(
        url=url,
        status=status,
        latency_ms=uptime_result.get("latency_ms"),
        ssl_expires_days=ssl_result.get("ssl_expires_days"),
        ssl_valid=ssl_result.get("ssl_valid"),
        domain_age_days=domain_result.get("age_days"),
        domain_owner_changed=domain_result.get("owner_changed"),
        abuse_score=blacklist_result.get("abuse_score", 0),
        in_blacklist=blacklist_result.get("in_blacklist", False),
        flags=[],
        score=50,
    )

    # Build flags
    flags = scorer.build_flags(result)
    if not is_https:
        flags.append("NO_HTTPS")
    redirect_count = uptime_result.get("redirect_count", 0)
    if redirect_count > 2:
        flags.append("REDIRECT_CHAIN")
    result.flags = flags

    # Calculate score
    result.score = scorer.calculate_endpoint_score(result)

    # Cache result
    await set_cached(cache_key, result.model_dump_json(), ttl=cache_ttl)

    return result


async def run_scan(urls: List[str], scan_type: str = "single") -> List[EndpointResult]:
    """Check all endpoints concurrently."""
    tasks = [check_endpoint(url, scan_type) for url in urls]
    return list(await asyncio.gather(*tasks))
