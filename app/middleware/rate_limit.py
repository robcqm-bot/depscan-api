"""Per-API-key rate limiting via Redis sliding window (1 minute).

Falls back to an in-memory counter when Redis is unavailable (fail-closed).
"""

import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# requests per minute by tier (None = unlimited)
RATE_LIMITS: dict[str, int | None] = {
    "single": 60,
    "deep": 60,
    "unlimited": 300,
    "monitor": None,
}

# In-memory fallback: {rate_key: count}. Cleared per-bucket automatically.
_fallback_counts: dict[str, int] = defaultdict(int)
_fallback_lock = Lock()


def _fallback_check(rate_key: str, limit: int) -> None:
    """Thread-safe in-memory rate check used when Redis is unavailable."""
    with _fallback_lock:
        _fallback_counts[rate_key] += 1
        count = _fallback_counts[rate_key]
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": f"Rate limit exceeded: {limit} requests/minute",
                "code": "RATE_LIMITED",
            },
            headers={"Retry-After": "60"},
        )


async def check_rate_limit(api_key_id: int, tier: str) -> None:
    """Raise HTTP 429 if the key has exceeded its per-minute limit."""
    limit = RATE_LIMITS.get(tier)
    if limit is None:
        return

    minute_bucket = int(time.time() / 60)
    rate_key = f"depscan:rate:{api_key_id}:{minute_bucket}"

    try:
        from app.cache import get_redis

        r = await get_redis()
        count = await r.incr(rate_key)
        if count == 1:
            await r.expire(rate_key, 60)

        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": f"Rate limit exceeded: {limit} requests/minute",
                    "code": "RATE_LIMITED",
                },
                headers={"Retry-After": "60"},
            )
    except HTTPException:
        raise
    except Exception as e:
        # Redis unavailable → use in-memory fallback (fail-closed, not open)
        logger.warning(f"Rate limit Redis error — using in-memory fallback: {type(e).__name__}")
        _fallback_check(rate_key, limit)
