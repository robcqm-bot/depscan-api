"""APScheduler monitor job — Fase 2.

Re-scans all active subscriptions every N hours (default 6).
Uses a Redis distributed lock to prevent double-execution across uvicorn workers.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.cache import get_redis
from app.database import get_session_maker
from app.models.db import AlertHistory, APIKey, EndpointResultDB, Scan, Subscription
from app.services import scorer
from app.services.checker import run_scan
from app.services.webhook import build_alert_payload, send_alert

logger = logging.getLogger(__name__)

_LOCK_KEY = "depscan:monitor:lock"
_LOCK_TTL = 5 * 3600 + 30 * 60  # 5.5 hours in seconds


async def run_monitor_job() -> None:
    """Periodic job: re-scan all active subscriptions, send alerts on score drops."""
    # --- Distributed lock: only one worker executes the job ---
    try:
        r = await get_redis()
        acquired = await r.set(_LOCK_KEY, "1", ex=_LOCK_TTL, nx=True)
        if not acquired:
            logger.info("monitor_job: lock held by another worker — skipping")
            return
    except Exception as exc:
        logger.warning(f"monitor_job: Redis lock error — proceeding anyway: {exc}")

    logger.info("monitor_job: starting")
    session_maker = get_session_maker()

    async with session_maker() as db:
        try:
            # Fetch active subscriptions with their api_key
            stmt = (
                select(Subscription)
                .where(Subscription.status == "active")
                .options(selectinload(Subscription.api_key))
            )
            result = await db.execute(stmt)
            subscriptions = result.scalars().all()

            logger.info(f"monitor_job: found {len(subscriptions)} active subscriptions")

            for sub in subscriptions:
                await _process_subscription(db, sub)

            await db.commit()
        except Exception as exc:
            logger.error(f"monitor_job: unexpected error: {exc}", exc_info=True)
            await db.rollback()

    logger.info("monitor_job: done")


async def _process_subscription(db, sub: Subscription) -> None:
    """Run a deep scan for one subscription and handle alerts/credits."""
    # Parse endpoint URLs
    try:
        urls = json.loads(sub.endpoints_json or "[]")
    except Exception:
        urls = []

    if not urls:
        logger.warning(f"monitor_job: subscription {sub.subscription_id} has no URLs — skipping")
        return

    # Check credits on the linked API key
    api_key: APIKey = sub.api_key
    if api_key.credits_remaining <= 0:
        logger.info(f"monitor_job: key id={api_key.id} no credits — pausing sub {sub.subscription_id}")
        sub.status = "paused"
        return

    scan_id = f"dep_{uuid.uuid4().hex}"
    start = time.monotonic()

    # Run deep scan
    try:
        endpoint_results = await run_scan(urls, scan_type="deep")
    except Exception as exc:
        logger.warning(f"monitor_job: scan failed for {sub.subscription_id}: {exc}")
        return

    processing_ms = int((time.monotonic() - start) * 1000)
    scores = [r.score for r in endpoint_results]
    overall = scorer.calculate_overall_score(scores)
    now = datetime.now(timezone.utc)

    # Persist Scan record
    scan = Scan(
        scan_id=scan_id,
        api_key_id=api_key.id,
        skill_url=sub.skill_url,
        overall_score=overall,
        scan_status=scorer.overall_status(overall),
        recommendation=scorer.recommendation(overall),
        scan_type="deep",
        created_at=now,
        completed_at=now,
        processing_time_ms=processing_ms,
    )
    db.add(scan)
    await db.flush()  # get scan.id

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

    # Score drop detection
    previous_score = sub.last_score
    drop = (previous_score - overall) if previous_score is not None else 0

    if previous_score is not None and drop >= sub.alert_threshold:
        logger.info(
            f"monitor_job: score drop {previous_score}→{overall} (drop={drop}) "
            f"for sub {sub.subscription_id}"
        )
        webhook_status = "no_webhook"

        if sub.webhook_url:
            payload = build_alert_payload(
                subscription_id=sub.subscription_id,
                skill_url=sub.skill_url,
                previous_score=previous_score,
                new_score=overall,
                scan_id=scan_id,
            )
            success = await send_alert(sub.webhook_url, payload)
            webhook_status = "sent" if success else "failed"

        alert = AlertHistory(
            subscription_id=sub.id,
            previous_score=previous_score,
            new_score=overall,
            scan_id=scan_id,
            webhook_url=sub.webhook_url,
            webhook_status=webhook_status,
        )
        db.add(alert)

    # Update subscription state
    sub.last_score = overall
    sub.last_scan_id = scan_id
    sub.next_check_at = now + timedelta(hours=6)

    # Deduct 1 credit
    api_key.credits_remaining -= 1
    api_key.last_used_at = now

    if api_key.credits_remaining <= 0:
        logger.info(f"monitor_job: key id={api_key.id} credits exhausted — pausing sub {sub.subscription_id}")
        sub.status = "paused"
