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

# In-memory fallback: {rate_key: count}. Keyed with minute bucket embedded in the key
# so that pruning old entries is possible without a separate TTL mechanism.
_fallback_counts: dict[str, int] = defaultdict(int)
_fallback_lock = Lock()


def _prune_old_buckets(current_bucket: int) -> None:
    """Remove entries from previous minute buckets to prevent unbounded growth.

    rate_key format: "depscan:rate:{api_key_id}:{minute_bucket}"
    We only need to keep entries for the *current* bucket — older ones can
    never match the active bucket and are safe to discard.
    """
    suffix = f":{current_bucket}"
    stale = [k for k in _fallback_counts if not k.endswith(suffix)]
    for k in stale:
        del _fallback_counts[k]


def _fallback_check(rate_key: str, limit: int, current_bucket: int) -> None:
    """Thread-safe in-memory rate check used when Redis is unavailable."""
    with _fallback_lock:
        _prune_old_buckets(current_bucket)
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
        logger.warning("Rate limit Redis error — using in-memory fallback: %s", type(e).__name__)
        _fallback_check(rate_key, limit, minute_bucket)
