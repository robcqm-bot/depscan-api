"""Monitor router — Fase 2.

POST   /v1/monitor/subscribe           — create a monitor subscription
DELETE /v1/monitor/{subscription_id}   — cancel a subscription
GET    /v1/monitor/{subscription_id}/history — get scan + alert history
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_api_key
from app.models.db import AlertHistory, APIKey, Scan, Subscription
from app.models.scan import (
    AlertRecord,
    MonitorHistoryEntry,
    MonitorHistoryResponse,
    MonitorSubscribeRequest,
    MonitorSubscribeResponse,
)
from app.services.extractor import extract_urls

logger = logging.getLogger(__name__)
router = APIRouter()

_MONITOR_TIERS = {"monitor", "unlimited"}


@router.post("/v1/monitor/subscribe", response_model=MonitorSubscribeResponse)
async def monitor_subscribe(
    request: MonitorSubscribeRequest,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Subscribe a skill or list of endpoints to periodic monitoring."""
    if api_key.tier not in _MONITOR_TIERS:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Monitor tier required. Upgrade your plan.",
                "code": "TIER_REQUIRED",
            },
        )

    # Resolve URLs from skill_url or raw endpoints
    urls = await extract_urls(
        skill_url=request.skill_url,
        endpoints=request.endpoints,
        scan_type="deep",
    )
    if not urls:
        raise HTTPException(
            status_code=400,
            detail={"error": "No valid URLs to monitor", "code": "NO_URLS"},
        )

    subscription_id = f"mon_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)

    sub = Subscription(
        subscription_id=subscription_id,
        api_key_id=api_key.id,
        skill_url=request.skill_url,
        endpoints_json=json.dumps(urls),
        webhook_url=request.webhook_url,
        alert_threshold=request.alert_threshold,
        status="active",
        created_at=now,
        next_check_at=now + timedelta(hours=6),
    )
    db.add(sub)
    await db.commit()
    await db.refresh(sub)

    return MonitorSubscribeResponse(
        subscription_id=sub.subscription_id,
        status=sub.status,
        skill_url=sub.skill_url,
        endpoints=urls,
        webhook_url=sub.webhook_url,
        alert_threshold=sub.alert_threshold,
        next_check_at=sub.next_check_at,
        created_at=sub.created_at,
    )


@router.delete("/v1/monitor/{subscription_id}", status_code=204)
async def monitor_unsubscribe(
    subscription_id: str,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a monitor subscription. Only the owner can cancel."""
    stmt = select(Subscription).where(Subscription.subscription_id == subscription_id)
    result = await db.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Subscription not found", "code": "NOT_FOUND"},
        )

    if sub.api_key_id != api_key.id:
        raise HTTPException(
            status_code=403,
            detail={"error": "Not your subscription", "code": "FORBIDDEN"},
        )

    sub.status = "cancelled"
    await db.commit()


@router.get("/v1/monitor/{subscription_id}/history", response_model=MonitorHistoryResponse)
async def monitor_history(
    subscription_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get scan history and alerts for a subscription. No auth required — ID is opaque."""
    stmt = (
        select(Subscription)
        .where(Subscription.subscription_id == subscription_id)
        .options(selectinload(Subscription.alerts))
    )
    result = await db.execute(stmt)
    sub = result.scalar_one_or_none()

    if sub is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Subscription not found", "code": "NOT_FOUND"},
        )

    # Load scans linked to this subscription via last_scan_id references in alerts
    # We collect all unique scan_ids from alerts + current last_scan_id
    scan_ids: List[str] = []
    if sub.last_scan_id:
        scan_ids.append(sub.last_scan_id)
    for alert in sub.alerts:
        if alert.scan_id not in scan_ids:
            scan_ids.append(alert.scan_id)

    # Fetch the scan records
    scans_by_id: dict = {}
    if scan_ids:
        scan_stmt = select(Scan).where(Scan.scan_id.in_(scan_ids))
        scan_result = await db.execute(scan_stmt)
        for s in scan_result.scalars().all():
            scans_by_id[s.scan_id] = s

    # Build history entries: one entry per scan
    history: List[MonitorHistoryEntry] = []
    for sid, scan in scans_by_id.items():
        # Find alerts that reference this scan
        alerts_for_scan = [
            AlertRecord(
                previous_score=a.previous_score,
                new_score=a.new_score,
                scan_id=a.scan_id,
                webhook_status=a.webhook_status,
                created_at=a.created_at,
            )
            for a in sub.alerts
            if a.scan_id == sid
        ]
        history.append(MonitorHistoryEntry(
            scan_id=scan.scan_id,
            overall_score=scan.overall_score or 0,
            status=scan.scan_status or "UNKNOWN",
            timestamp=scan.completed_at or scan.created_at,
            alerts=alerts_for_scan,
        ))

    # Sort by timestamp descending (most recent first)
    history.sort(key=lambda e: e.timestamp, reverse=True)

    return MonitorHistoryResponse(
        subscription_id=sub.subscription_id,
        skill_url=sub.skill_url,
        current_status=sub.status,
        last_score=sub.last_score,
        history=history,
    )
