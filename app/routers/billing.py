"""Billing router: Stripe checkout creation and webhook handling.

Tiers:
  single_starter / single_pro / single_business  → one-time payment
  deep_starter   / deep_pro   / deep_business    → one-time payment
  monitor        → $9.99/month  (subscription, 500 credits/month)
  unlimited      → $49/month    (subscription, 999_999 credits/month)
"""

import hashlib
import logging
import secrets

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.db import APIKey
from app.models.scan import CheckoutRequest, CheckoutResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# Tiers that use Stripe subscription billing (recurring)
_SUBSCRIPTION_TIERS: set[str] = {"monitor", "unlimited"}

# Credits allocated on checkout / monthly renewal for every tier
_CREDITS_BY_TIER: dict[str, int] = {
    "single_starter":  25,
    "single_pro":      100,
    "single_business": 500,
    "deep_starter":    10,
    "deep_pro":        50,
    "deep_business":   200,
    "monitor":         500,
    "unlimited":       999_999,
}


def _get_price_id(tier: str, settings) -> str:
    attr = f"stripe_price_{tier}"
    return getattr(settings, attr, "")


def _init_stripe() -> None:
    settings = get_settings()
    stripe.api_key = settings.stripe_secret_key


@router.post("/v1/billing/checkout", response_model=CheckoutResponse)
async def create_checkout(
    request: CheckoutRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a Stripe checkout session and return a pending API key."""
    settings = get_settings()
    _init_stripe()

    price_id = _get_price_id(request.tier, settings)
    if not price_id or price_id == "price_xxx":
        raise HTTPException(
            status_code=503,
            detail={"error": "Payment not configured", "code": "PAYMENT_NOT_CONFIGURED"},
        )

    is_subscription = request.tier in _SUBSCRIPTION_TIERS
    credits = _CREDITS_BY_TIER[request.tier]

    # Pre-generate API key (activates after payment completes)
    raw_key = f"dsk_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = APIKey(
        key_hash=key_hash,
        tier=request.tier,
        credits_remaining=0,
        status="pending",
    )
    db.add(api_key)
    await db.flush()

    try:
        if is_subscription:
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{"price": price_id, "quantity": 1}],
                mode="subscription",
                success_url="https://depscan.net/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="https://depscan.net/cancel",
                metadata={
                    "api_key_id": str(api_key.id),
                    "tier": request.tier,
                    "credits": str(credits),
                },
            )
        else:
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{"price": price_id, "quantity": 1}],
                mode="payment",
                success_url="https://depscan.net/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="https://depscan.net/cancel",
                metadata={
                    "api_key_id": str(api_key.id),
                    "tier": request.tier,
                    "credits": str(credits),
                },
            )

        api_key.stripe_session_id = session.id
        await db.commit()

        return CheckoutResponse(
            checkout_url=session.url,
            api_key=raw_key,
        )

    except stripe.StripeError as e:
        await db.rollback()
        logger.error("Stripe error creating checkout for tier=%s: %s", request.tier, e)
        raise HTTPException(
            status_code=503,
            detail={"error": "Payment provider error", "code": "PAYMENT_ERROR"},
        )


@router.post("/v1/webhook/billing", status_code=200, include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """Internal Stripe webhook — not part of the public API.

    Handles:
      checkout.session.completed     → activate key (one-time + subscription first payment)
      invoice.payment_succeeded      → replenish credits on recurring renewal
      invoice.payment_failed         → log warning
      customer.subscription.deleted  → deactivate key
    """
    settings = get_settings()
    _init_stripe()

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret
        )
    except stripe.SignatureVerificationError:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid signature", "code": "INVALID_SIGNATURE"},
        )
    except Exception as e:
        logger.error("Webhook payload error: %s", e)
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid payload", "code": "INVALID_PAYLOAD"},
        )

    event_type = event["type"]
    logger.info("Stripe event received: %s", event_type)

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(event["data"]["object"], db)

    elif event_type == "invoice.payment_succeeded":
        await _handle_invoice_payment_succeeded(event["data"]["object"], db)

    elif event_type == "invoice.payment_failed":
        customer = event["data"]["object"].get("customer", "unknown")
        logger.warning("stripe_payment_failed customer=%s", customer)

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(event["data"]["object"], db)

    return {"received": True}


async def _handle_checkout_completed(session: dict, db: AsyncSession) -> None:
    """Activate API key after successful checkout (one-time or subscription)."""
    metadata = session.get("metadata", {}) or {}
    mode = session.get("mode", "payment")

    try:
        api_key_id = int(metadata.get("api_key_id", 0))
        credits = int(metadata.get("credits", 0))
    except (ValueError, TypeError):
        logger.error("checkout.session.completed: invalid metadata — %s", metadata)
        return

    if api_key_id <= 0 or credits <= 0 or credits > 1_000_000:
        logger.error(
            "checkout.session.completed: out-of-range values api_key_id=%s credits=%s",
            api_key_id, credits,
        )
        return

    result = await db.execute(select(APIKey).where(APIKey.id == api_key_id))
    api_key = result.scalar_one_or_none()
    if not api_key:
        logger.error("checkout.session.completed: api_key_id=%s not found", api_key_id)
        return

    api_key.status = "active"
    api_key.credits_remaining += credits
    api_key.stripe_customer_id = session.get("customer")

    if mode == "subscription":
        # Store subscription ID for future invoice lookups
        api_key.stripe_subscription_id = session.get("subscription")

    await db.commit()
    logger.info(
        "api_key_activated id=%s tier=%s credits=%s mode=%s",
        api_key_id, api_key.tier, credits, mode,
    )


async def _handle_invoice_payment_succeeded(invoice: dict, db: AsyncSession) -> None:
    """Replenish credits on monthly subscription renewal.

    Skips the first invoice (billing_reason=subscription_create) because
    checkout.session.completed already handled it.
    """
    billing_reason = invoice.get("billing_reason", "")
    if billing_reason == "subscription_create":
        # First payment — already handled by checkout.session.completed
        return

    customer_id = invoice.get("customer")
    subscription_id = invoice.get("subscription")

    if not customer_id and not subscription_id:
        logger.warning("invoice.payment_succeeded: no customer or subscription id")
        return

    # Lookup by subscription_id first (more specific), fall back to customer_id
    stmt = select(APIKey).where(
        or_(
            APIKey.stripe_subscription_id == subscription_id,
            APIKey.stripe_customer_id == customer_id,
        )
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        logger.warning(
            "invoice.payment_succeeded: no key found for customer=%s sub=%s",
            customer_id, subscription_id,
        )
        return

    if api_key.tier not in _SUBSCRIPTION_TIERS:
        return  # not a subscription tier — nothing to replenish

    replenish = _CREDITS_BY_TIER[api_key.tier]
    api_key.credits_remaining = replenish   # reset to full allocation (not additive)
    api_key.status = "active"               # reactivate if it was paused on payment failure
    await db.commit()
    logger.info(
        "subscription_renewal key_id=%s tier=%s credits_replenished=%s reason=%s",
        api_key.id, api_key.tier, replenish, billing_reason,
    )


async def _handle_subscription_deleted(subscription: dict, db: AsyncSession) -> None:
    """Deactivate key when Stripe subscription is cancelled."""
    customer_id = subscription.get("customer")
    subscription_id = subscription.get("id")

    stmt = select(APIKey).where(
        or_(
            APIKey.stripe_subscription_id == subscription_id,
            APIKey.stripe_customer_id == customer_id,
        )
    )
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()
    if api_key:
        api_key.status = "inactive"
        await db.commit()
        logger.info(
            "subscription_deleted key_id=%s customer=%s",
            api_key.id, customer_id,
        )
