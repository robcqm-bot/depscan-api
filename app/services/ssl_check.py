"""SSL certificate validity and expiration checker."""

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import urlparse

import certifi

logger = logging.getLogger(__name__)


def _get_ssl_info_sync(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Blocking SSL check — run in executor."""
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "ssl_valid": True,
                    "ssl_expires_days": _parse_expiry_days(cert),
                }

    except ssl.SSLCertVerificationError:
        return {"ssl_valid": False, "ssl_expires_days": None}

    except ssl.SSLError as e:
        logger.debug(f"SSL error for {hostname}: {e}")
        return {"ssl_valid": False, "ssl_expires_days": None}

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Connection error during SSL check for {hostname}: {e}")
        return {"ssl_valid": None, "ssl_expires_days": None}


def _parse_expiry_days(cert: Dict) -> int | None:
    not_after = cert.get("notAfter", "")
    if not not_after:
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        return (expiry - datetime.now(timezone.utc)).days
    except ValueError:
        return None


async def check_ssl(url: str) -> Dict[str, Any]:
    """Check SSL certificate validity and expiration.

    Returns None values for non-HTTPS URLs or unreachable hosts.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"ssl_valid": None, "ssl_expires_days": None}

    hostname = parsed.hostname
    port = parsed.port or 443

    if not hostname:
        return {"ssl_valid": None, "ssl_expires_days": None}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_ssl_info_sync, hostname, port)
