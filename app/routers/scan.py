"""Scan router: POST /v1/scan-deps, GET /v1/health, POST /v1/admin/create-key."""

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import get_api_key
from app.middleware.rate_limit import check_rate_limit
from app.models.db import APIKey, EndpointResultDB, Scan
from app.models.scan import AIInsight, ScanRequest, ScanResponse
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
    if request.scan_type == "deep":
        raise HTTPException(
            status_code=501,
            detail={
                "error": "Deep scan not yet available (Fase 1)",
                "code": "NOT_IMPLEMENTED",
            },
        )

    await check_rate_limit(api_key.id, api_key.tier)

    urls = extract_urls(skill_url=request.skill_url, endpoints=request.endpoints)
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

    # Deduct one credit
    api_key.credits_remaining -= 1
    api_key.last_used_at = datetime.now(timezone.utc)

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
    # Constant-time comparison to prevent timing attacks
    provided = (x_admin_secret or "").encode()
    expected = settings.secret_key.encode()
    if not settings.secret_key or not hmac.compare_digest(provided, expected):
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

    return {"api_key": raw_key, "tier": tier, "credits": credits, "id": api_key.id}
