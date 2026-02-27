"""Internal router — Fase 3.

POST /internal/scan-deps — endpoint interno para uso desde localhost.
  Sin autenticación, sin deducción de créditos.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import require_localhost
from app.models.db import EndpointResultDB, Scan
from app.models.scan import AIInsight, ScanRequest, ScanResponse
from app.services import scorer
from app.services.ai_insights import get_insight_generator
from app.services.checker import run_scan
from app.services.extractor import extract_urls

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/internal/scan-deps", response_model=ScanResponse, include_in_schema=False)
async def internal_scan_deps(
    request: ScanRequest,
    _: None = Depends(require_localhost),
    db: AsyncSession = Depends(get_db),
):
    """Scan interno. Solo accesible desde localhost.

    Comportamiento idéntico a POST /v1/scan-deps pero:
    - Sin autenticación (no requiere API key)
    - Sin rate limiting
    - Sin deducción de créditos
    """
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

    scan = Scan(
        scan_id=scan_id,
        api_key_id=None,
        skill_url=request.skill_url,
        scan_type=request.scan_type,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()

    endpoint_results = await run_scan(urls, request.scan_type)

    scores = [r.score for r in endpoint_results]
    overall = scorer.calculate_overall_score(scores)
    processing_ms = int((time.monotonic() - start_time) * 1000)

    scan.overall_score = overall
    scan.scan_status = scorer.overall_status(overall)
    scan.recommendation = scorer.recommendation(overall)
    scan.completed_at = datetime.now(timezone.utc)
    scan.processing_time_ms = processing_ms

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
            pass

    logger.info("internal_scan scan_id=%s score=%s urls=%d", scan_id, overall, len(urls))

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
