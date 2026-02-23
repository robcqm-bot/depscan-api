"""Per-API-key rate limiting via Redis sliding window (1 minute)."""

import logging
import time

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# requests per minute by tier (None = unlimited)
RATE_LIMITS: dict[str, int | None] = {
    "single": 60,
    "deep": 60,
    "unlimited": 300,
    "monitor": None,
}


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
        # Redis unavailable → fail open (don't block legitimate requests)
        logger.warning(f"Rate limit check skipped (Redis error): {e}")
