"""Uptime and latency checker using httpx async."""

import logging
import time
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 5


async def check_uptime(url: str) -> Dict[str, Any]:
    """Check endpoint uptime and latency.

    Returns:
        dict with keys: status, latency_ms, redirect_count, final_url, http_status
    """
    try:
        start_ms = time.monotonic() * 1000
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            verify=True,
        ) as client:
            resp = await client.get(url)
            latency_ms = int(time.monotonic() * 1000 - start_ms)
            redirect_count = len(resp.history)
            return {
                "status": "UP",
                "latency_ms": latency_ms,
                "redirect_count": redirect_count,
                "final_url": str(resp.url),
                "http_status": resp.status_code,
            }

    except httpx.TimeoutException:
        return {"status": "TIMEOUT", "latency_ms": None, "redirect_count": 0}

    except httpx.ConnectSSLError:
        return {"status": "SSL_ERROR", "latency_ms": None, "redirect_count": 0}

    except httpx.TooManyRedirects:
        return {
            "status": "UP",
            "latency_ms": None,
            "redirect_count": MAX_REDIRECTS + 1,
        }

    except (httpx.ConnectError, httpx.RemoteProtocolError):
        return {"status": "DOWN", "latency_ms": None, "redirect_count": 0}

    except Exception as e:
        logger.warning(f"Uptime check failed for {url}: {e}")
        return {"status": "UNKNOWN", "latency_ms": None, "redirect_count": 0}
