"""FastAPI dependency injection: API key validation."""

import hashlib
import logging
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.db import APIKey

logger = logging.getLogger(__name__)


async def get_api_key(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Validate Bearer API key and return the APIKey ORM object."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Missing Authorization header", "code": "AUTH_MISSING"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid authorization format", "code": "AUTH_INVALID"},
        )

    raw_key = authorization[7:]
    if not raw_key.startswith("dsk_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid API key format", "code": "AUTH_INVALID"},
        )

    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    result = await db.execute(select(APIKey).where(APIKey.key_hash == key_hash))
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "API key not found", "code": "AUTH_NOT_FOUND"},
        )

    if api_key.status == "pending":
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "Payment not completed — activate your key at checkout",
                "code": "KEY_PENDING",
            },
        )

    if api_key.status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "API key inactive", "code": "KEY_INACTIVE"},
        )

    if api_key.credits_remaining <= 0:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "Insufficient credits", "code": "CREDITS_EXHAUSTED"},
        )

    return api_key
