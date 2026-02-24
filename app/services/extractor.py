"""URL extractor for DepScan scans.

Fase 0: accepts direct endpoint list or treats skill_url as an endpoint.
Fase 1+: parses skill manifests (YAML/JSON) from skill_url.
"""

import ipaddress
import logging
import socket
from typing import List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Private / reserved ranges blocked for SSRF prevention
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # RFC-1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC-1918
    ipaddress.ip_network("192.168.0.0/16"), # RFC-1918
    ipaddress.ip_network("169.254.0.0/16"), # link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"), # carrier-grade NAT
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def _resolves_to_private(hostname: str) -> bool:
    """Return True if hostname resolves to a private/reserved address."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if any(ip in net for net in _BLOCKED_NETWORKS):
                return True
        return False
    except (socket.gaierror, ValueError):
        return True  # can't resolve → block (fail-safe)


def validate_public_url(url: str) -> None:
    """Raise ValueError if URL targets a private/internal host (SSRF prevention)."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid URL — no hostname: {url}")
    if _resolves_to_private(hostname):
        raise ValueError(f"Blocked: {hostname} resolves to a private/reserved address")


# Fields commonly used in skill/API manifests to list endpoint URLs
_MANIFEST_URL_FIELDS = {"url", "endpoint", "base_url", "endpoints", "dependencies"}


def _extract_urls_from_manifest(data: object) -> List[str]:
    """Recursively extract URL strings from parsed YAML/JSON manifest data."""
    urls: List[str] = []

    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in _MANIFEST_URL_FIELDS:
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    urls.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.startswith(("http://", "https://")):
                            urls.append(item)
                        elif isinstance(item, dict):
                            urls.extend(_extract_urls_from_manifest(item))
            else:
                urls.extend(_extract_urls_from_manifest(value))
    elif isinstance(data, list):
        for item in data:
            urls.extend(_extract_urls_from_manifest(item))

    return urls


async def fetch_manifest_urls(skill_url: str) -> List[str]:
    """Fetch a skill manifest from skill_url and extract endpoint URLs.

    Tries YAML first, then JSON. Falls back to [skill_url] on any error
    or if no recognizable URLs are found.
    """
    # SSRF prevention before fetching
    try:
        validate_public_url(skill_url)
    except ValueError as exc:
        logger.warning(f"Manifest fetch blocked (SSRF): {exc}")
        return [skill_url]

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(skill_url)
            response.raise_for_status()
            content = response.text
    except Exception as exc:
        logger.warning(f"Manifest fetch failed for {skill_url}: {exc}")
        return [skill_url]

    # Try YAML first (superset of JSON), then plain JSON
    parsed = None
    try:
        import yaml
        parsed = yaml.safe_load(content)
    except Exception:
        pass

    if parsed is None:
        try:
            import json
            parsed = json.loads(content)
        except Exception:
            pass

    if parsed is None:
        return [skill_url]

    urls = _extract_urls_from_manifest(parsed)
    if not urls:
        return [skill_url]

    return [_normalize_url(u) for u in urls]


async def extract_urls(
    skill_url: Optional[str] = None,
    endpoints: Optional[List[str]] = None,
    scan_type: str = "single",
) -> List[str]:
    """Extract and normalize URLs from scan request.

    For deep scans with a skill_url, attempts to parse the manifest
    and extract all declared endpoints.
    """
    if endpoints:
        return [_normalize_url(url) for url in endpoints if url.strip()]

    if skill_url:
        if scan_type == "deep":
            return await fetch_manifest_urls(_normalize_url(skill_url))
        # single: treat skill_url itself as the endpoint
        return [_normalize_url(skill_url)]

    return []


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def extract_hostname(url: str) -> str:
    """Extract hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or url
