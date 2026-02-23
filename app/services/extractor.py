"""URL extractor for DepScan scans.

Fase 0: accepts direct endpoint list or treats skill_url as an endpoint.
Fase 1+: parses skill manifests (YAML/JSON) from skill_url.
"""

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse

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


def extract_urls(
    skill_url: Optional[str] = None,
    endpoints: Optional[List[str]] = None,
) -> List[str]:
    """Extract and normalize URLs from scan request."""
    if endpoints:
        return [_normalize_url(url) for url in endpoints if url.strip()]

    if skill_url:
        # Fase 0: treat skill_url itself as the endpoint to check
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
