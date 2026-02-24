"""Webhook alert sender for monitor subscriptions."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)


async def send_alert(webhook_url: str, payload: Dict[str, Any]) -> bool:
    """POST an alert payload to webhook_url.

    Returns True on HTTP 2xx, False on any error.
    Never raises — failures are logged as warnings.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json", "User-Agent": "DepScan-Monitor/1.0"},
            )
            if response.is_success:
                logger.info(f"Webhook sent to {webhook_url}: HTTP {response.status_code}")
                return True
            else:
                logger.warning(f"Webhook non-2xx for {webhook_url}: HTTP {response.status_code}")
                return False
    except Exception as exc:
        logger.warning(f"Webhook delivery failed for {webhook_url}: {exc}")
        return False


def build_alert_payload(
    subscription_id: str,
    skill_url: str | None,
    previous_score: int,
    new_score: int,
    scan_id: str,
) -> Dict[str, Any]:
    return {
        "event": "score_drop",
        "subscription_id": subscription_id,
        "skill_url": skill_url,
        "previous_score": previous_score,
        "new_score": new_score,
        "drop": previous_score - new_score,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
