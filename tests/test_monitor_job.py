"""Tests for the monitor APScheduler job (Fase 2)."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_subscription(
    last_score=None,
    alert_threshold=20,
    webhook_url="https://webhook.site/xxx",
    credits=10,
):
    from app.models.db import APIKey, Subscription

    api_key = MagicMock(spec=APIKey)
    api_key.id = 1
    api_key.credits_remaining = credits
    api_key.last_used_at = None

    sub = MagicMock(spec=Subscription)
    sub.id = 1
    sub.subscription_id = "mon_test001"
    sub.skill_url = "https://example.com/skill.json"
    sub.endpoints_json = '["https://example.com/api"]'
    sub.webhook_url = webhook_url
    sub.alert_threshold = alert_threshold
    sub.last_score = last_score
    sub.last_scan_id = None
    sub.status = "active"
    sub.api_key = api_key

    return sub, api_key


def _build_session_mock(subscriptions, credits_remaining_after_deduct=9):
    """Build an AsyncMock DB session that returns the given subscription list.

    The first execute() call returns the subscription list (scalars().all()).
    Subsequent execute() calls simulate the atomic UPDATE RETURNING, returning
    `credits_remaining_after_deduct` (or None to simulate exhausted credits).
    """
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()

    # First call: SELECT subscriptions
    list_result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = subscriptions
    list_result.scalars.return_value = scalars

    # Subsequent calls: UPDATE RETURNING credits_remaining
    deduct_result = MagicMock()
    deduct_result.scalar_one_or_none.return_value = credits_remaining_after_deduct

    execute_effects = [list_result] + [deduct_result] * max(1, len(subscriptions))
    session.execute = AsyncMock(side_effect=execute_effects)

    # Context manager support (async with session_maker() as db)
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=False)

    session_maker = MagicMock(return_value=cm)
    return session, session_maker


def _make_endpoint_result(score: int = 80):
    from app.models.scan import EndpointResult
    return EndpointResult(
        url="https://example.com/api",
        status="UP",
        score=score,
        flags=[],
    )


@pytest.mark.asyncio
async def test_job_no_alert_when_no_previous_score():
    """First scan (last_score=None) — no alert, but subscription is updated."""
    from app.models.db import AlertHistory
    sub, api_key = _make_subscription(last_score=None, credits=5)
    session, session_maker = _build_session_mock([sub])

    endpoint_result = _make_endpoint_result(score=75)

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock(return_value=True)) as mock_alert,
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    # No webhook sent (no previous score to compare)
    mock_alert.assert_not_called()

    # Subscription last_score should be updated
    assert sub.last_score == 75
    # Credit deduction is atomic via DB UPDATE — api_key object not modified in Python


@pytest.mark.asyncio
async def test_job_sends_alert_on_score_drop():
    """Drop >= threshold → AlertHistory created and webhook sent."""
    from app.models.db import AlertHistory
    sub, api_key = _make_subscription(last_score=80, alert_threshold=20, credits=10)
    session, session_maker = _build_session_mock([sub])

    endpoint_result = _make_endpoint_result(score=50)  # drop=30 >= threshold=20

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock(return_value=True)) as mock_alert,
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    # Webhook should have been called
    mock_alert.assert_called_once()
    call_args = mock_alert.call_args
    assert call_args[0][0] == sub.webhook_url
    payload = call_args[0][1]
    assert payload["event"] == "score_drop"
    assert payload["previous_score"] == 80
    assert payload["new_score"] == 50
    assert payload["drop"] == 30

    # AlertHistory should have been added to the session
    added_items = [call[0][0] for call in session.add.call_args_list]
    alert_items = [item for item in added_items if isinstance(item, AlertHistory)]
    assert len(alert_items) == 1
    assert alert_items[0].webhook_status == "sent"
    assert alert_items[0].previous_score == 80
    assert alert_items[0].new_score == 50

    # Subscription updated
    assert sub.last_score == 50


@pytest.mark.asyncio
async def test_job_no_alert_when_drop_below_threshold():
    """Drop < threshold → no alert, no AlertHistory."""
    from app.models.db import AlertHistory
    sub, api_key = _make_subscription(last_score=80, alert_threshold=20, credits=10)
    session, session_maker = _build_session_mock([sub])

    endpoint_result = _make_endpoint_result(score=65)  # drop=15 < threshold=20

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock(return_value=True)) as mock_alert,
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    mock_alert.assert_not_called()

    added_items = [call[0][0] for call in session.add.call_args_list]
    from app.models.db import AlertHistory
    alert_items = [item for item in added_items if isinstance(item, AlertHistory)]
    assert len(alert_items) == 0

    assert sub.last_score == 65


@pytest.mark.asyncio
async def test_job_webhook_failed_status_recorded():
    """When send_alert returns False, webhook_status = 'failed'."""
    from app.models.db import AlertHistory
    sub, api_key = _make_subscription(last_score=80, alert_threshold=20, credits=10)
    session, session_maker = _build_session_mock([sub])

    endpoint_result = _make_endpoint_result(score=50)

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock(return_value=False)),
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    added_items = [call[0][0] for call in session.add.call_args_list]
    alert_items = [item for item in added_items if isinstance(item, AlertHistory)]
    assert len(alert_items) == 1
    assert alert_items[0].webhook_status == "failed"


@pytest.mark.asyncio
async def test_job_no_webhook_status_when_no_webhook_url():
    """Alert without webhook_url → webhook_status = 'no_webhook', send_alert not called."""
    from app.models.db import AlertHistory
    sub, api_key = _make_subscription(last_score=80, alert_threshold=20, webhook_url=None, credits=10)
    session, session_maker = _build_session_mock([sub])

    endpoint_result = _make_endpoint_result(score=50)

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock(return_value=True)) as mock_alert,
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    mock_alert.assert_not_called()
    added_items = [call[0][0] for call in session.add.call_args_list]
    alert_items = [item for item in added_items if isinstance(item, AlertHistory)]
    assert len(alert_items) == 1
    assert alert_items[0].webhook_status == "no_webhook"


@pytest.mark.asyncio
async def test_job_pauses_subscription_when_credits_exhausted():
    """After deducting the last credit (UPDATE RETURNING returns 0), sub → 'paused'."""
    sub, api_key = _make_subscription(last_score=None, credits=1)
    # Simulate DB returning 0 credits after atomic deduction
    session, session_maker = _build_session_mock([sub], credits_remaining_after_deduct=0)

    endpoint_result = _make_endpoint_result(score=80)

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock(return_value=[endpoint_result])),
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock()),
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    # DB returned 0 remaining → subscription should be paused
    assert sub.status == "paused"


@pytest.mark.asyncio
async def test_job_pauses_subscription_before_scan_when_no_credits():
    """Subscription with zero credits is paused without running a scan."""
    sub, api_key = _make_subscription(credits=0)
    session, session_maker = _build_session_mock([sub])

    with (
        patch("app.tasks.monitor_job.get_session_maker", return_value=session_maker),
        patch("app.tasks.monitor_job.run_scan", new=AsyncMock()) as mock_scan,
        patch("app.tasks.monitor_job.send_alert", new=AsyncMock()),
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    mock_scan.assert_not_called()
    assert sub.status == "paused"


@pytest.mark.asyncio
async def test_job_skips_when_lock_held():
    """If Redis lock is already held (SET NX returns False), job does not run."""
    with (
        patch("app.tasks.monitor_job.get_redis") as mock_get_redis,
        patch("app.tasks.monitor_job.get_session_maker") as mock_sm,
    ):
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=False)  # lock already held
        mock_get_redis.return_value = mock_redis

        from app.tasks.monitor_job import run_monitor_job
        await run_monitor_job()

    mock_sm.assert_not_called()
