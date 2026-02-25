"""Scan router: POST /v1/scan-deps, GET /v1/scan/{scan_id}, GET /v1/health, POST /v1/admin/create-key."""

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_api_key
from app.middleware.rate_limit import check_rate_limit
from app.models.db import APIKey, EndpointResultDB, Scan
from app.models.scan import AIInsight, EndpointResult, ScanRequest, ScanResponse
from app.services import scorer
from app.services.ai_insights import get_insight_generator
from app.services.checker import run_scan
from app.services.extractor import extract_urls

logger = logging.getLogger(__name__)
router = APIRouter()

VERSION = "0.1.0"


@router.get("/v1/health")
async def health():
    return {"status": "ok", "version": VERSION}


@router.post("/v1/scan-deps", response_model=ScanResponse)
async def scan_deps(
    request: ScanRequest,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
):
    await check_rate_limit(api_key.id, api_key.tier)

    urls = await extract_urls(
        skill_url=request.skill_url,
        endpoints=request.endpoints,
        scan_type=request.scan_type,
    )
    if not urls:
        raise HTTPException(
            status_code=400,
            detail={"error": "No valid URLs to scan", "code": "NO_URLS"},
        )
    if len(urls) > 50:
        raise HTTPException(
            status_code=400,
            detail={"error": "Maximum 50 endpoints per scan", "code": "TOO_MANY_URLS"},
        )

    scan_id = f"dep_{uuid.uuid4().hex}"
    start_time = time.monotonic()

    # Create scan record
    scan = Scan(
        scan_id=scan_id,
        api_key_id=api_key.id,
        skill_url=request.skill_url,
        scan_type=request.scan_type,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    # Run all checks concurrently
    endpoint_results = await run_scan(urls, request.scan_type)

    # Deduct one credit atomically — prevents double-spend under concurrent requests
    deduct_result = await db.execute(
        update(APIKey)
        .where(APIKey.id == api_key.id, APIKey.credits_remaining > 0)
        .values(
            credits_remaining=APIKey.credits_remaining - 1,
            last_used_at=datetime.now(timezone.utc),
        )
        .returning(APIKey.credits_remaining)
    )
    if deduct_result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=402,
            detail={"error": "Insufficient credits", "code": "CREDITS_EXHAUSTED"},
        )

    # Calculate overall score
    scores = [r.score for r in endpoint_results]
    overall = scorer.calculate_overall_score(scores)
    processing_ms = int((time.monotonic() - start_time) * 1000)

    # Update scan record
    scan.overall_score = overall
    scan.scan_status = scorer.overall_status(overall)
    scan.recommendation = scorer.recommendation(overall)
    scan.completed_at = datetime.now(timezone.utc)
    scan.processing_time_ms = processing_ms

    # Persist endpoint results
    for r in endpoint_results:
        db.add(EndpointResultDB(
            scan_id=scan.id,
            url=r.url,
            status=r.status,
            latency_ms=r.latency_ms,
            ssl_expires_days=r.ssl_expires_days,
            ssl_valid=r.ssl_valid,
            domain_age_days=r.domain_age_days,
            domain_owner_changed=r.domain_owner_changed,
            abuse_score=r.abuse_score,
            in_blacklist=r.in_blacklist,
            flags=json.dumps(r.flags),
            score=r.score,
        ))

    await db.commit()

    # Optional AI insight — uses DeepSeek if key is configured, Claude as fallback
    ai_insight = None
    insight_data = await get_insight_generator().analyze(
        endpoints=endpoint_results,
        overall_score=overall,
        scan_id=scan_id,
    )
    if insight_data:
        try:
            ai_insight = AIInsight(**insight_data)
        except Exception:
            pass  # malformed AI response — don't break scan

    return ScanResponse(
        scan_id=scan_id,
        skill=request.skill_url,
        overall_score=overall,
        status=scorer.overall_status(overall),
        endpoints=endpoint_results,
        recommendation=scorer.recommendation(overall),
        scan_type=request.scan_type,
        timestamp=datetime.now(timezone.utc),
        processing_time_ms=processing_ms,
        ai_insight=ai_insight,
    )


@router.get("/v1/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a previously completed scan by its scan_id. Requires owner's API key."""
    await check_rate_limit(api_key.id, api_key.tier)
    stmt = (
        select(Scan)
        .where(Scan.scan_id == scan_id)
        .options(selectinload(Scan.endpoint_results))
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )

    if scan.api_key_id != api_key.id:
        raise HTTPException(
            status_code=403,
            detail={"error": "Not your scan", "code": "FORBIDDEN"},
        )

    # Reconstruct EndpointResult list from DB rows
    endpoints = [
        EndpointResult(
            url=row.url,
            status=row.status,
            latency_ms=row.latency_ms,
            ssl_expires_days=row.ssl_expires_days,
            ssl_valid=row.ssl_valid,
            domain_age_days=row.domain_age_days,
            domain_owner_changed=row.domain_owner_changed,
            abuse_score=row.abuse_score,
            in_blacklist=row.in_blacklist,
            flags=json.loads(row.flags) if row.flags else [],
            score=row.score,
        )
        for row in scan.endpoint_results
    ]

    return ScanResponse(
        scan_id=scan.scan_id,
        skill=scan.skill_url,
        overall_score=scan.overall_score or 0,
        status=scan.scan_status or "UNKNOWN",
        endpoints=endpoints,
        recommendation=scan.recommendation or "REVIEW_BEFORE_INSTALL",
        scan_type=scan.scan_type,
        timestamp=scan.completed_at or scan.created_at,
        processing_time_ms=scan.processing_time_ms or 0,
        ai_insight=None,  # not persisted in DB
    )


_VALID_TIERS = {"single", "deep", "monitor", "unlimited"}
_MAX_ADMIN_CREDITS = 10_000


@router.post("/v1/admin/create-key", include_in_schema=False)
async def admin_create_key(
    tier: str = "single",
    credits: int = 10,
    x_admin_secret: str = Header(None, alias="X-Admin-Secret"),
    db: AsyncSession = Depends(get_db),
):
    """Create an active API key for testing/admin use. Protected by X-Admin-Secret header."""
    settings = get_settings()
    # Constant-time comparison to prevent timing attacks.
    # Deny immediately if no secret is provided in the request.
    if not x_admin_secret:
        raise HTTPException(status_code=403, detail={"error": "Forbidden", "code": "FORBIDDEN"})
    provided = x_admin_secret.encode()
    expected = settings.secret_key.encode()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail={"error": "Forbidden", "code": "FORBIDDEN"})

    if tier not in _VALID_TIERS:
        raise HTTPException(status_code=400, detail={"error": f"Invalid tier. Valid: {sorted(_VALID_TIERS)}", "code": "INVALID_TIER"})

    if credits < 1 or credits > _MAX_ADMIN_CREDITS:
        raise HTTPException(status_code=400, detail={"error": f"credits must be 1–{_MAX_ADMIN_CREDITS}", "code": "INVALID_CREDITS"})

    raw_key = f"dsk_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = APIKey(
        key_hash=key_hash,
        tier=tier,
        credits_remaining=credits,
        status="active",
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    logger.info(
        "admin_key_created key_id=%s tier=%s credits=%s",
        api_key.id, tier, credits,
    )
    return {"api_key": raw_key, "tier": tier, "credits": credits, "id": api_key.id}
