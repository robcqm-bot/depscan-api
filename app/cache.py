import logging
from typing import Optional

import redis.asyncio as aioredis

from app.config import get_settings

logger = logging.getLogger(__name__)

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        settings = get_settings()
        _redis = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


async def get_cached(key: str) -> Optional[str]:
    try:
        r = await get_redis()
        return await r.get(key)
    except Exception as e:
        logger.warning(f"Redis get failed for {key}: {e}")
        return None


async def set_cached(key: str, value: str, ttl: int = 3600) -> None:
    try:
        r = await get_redis()
        await r.setex(key, ttl, value)
    except Exception as e:
        logger.warning(f"Redis set failed for {key}: {e}")
