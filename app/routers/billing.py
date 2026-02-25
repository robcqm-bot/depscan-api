"""Billing router: Stripe checkout creation and webhook handling."""

import hashlib
import logging
import secrets

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.db import APIKey
from app.models.scan import CheckoutRequest, CheckoutResponse

logger = logging.getLogger(__name__)
router = APIRouter()

PRICE_BY_TIER = {
    "single": "stripe_price_single",
    "deep": "stripe_price_deep",
}


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

    price_attr = PRICE_BY_TIER.get(request.tier)
    if not price_attr:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid tier", "code": "INVALID_TIER"},
        )

    price_id = getattr(settings, price_attr, "")
    if not price_id or price_id == "price_xxx":
        raise HTTPException(
            status_code=503,
            detail={"error": "Payment not configured", "code": "PAYMENT_NOT_CONFIGURED"},
        )

    # Pre-generate API key (returned to client immediately; activates after payment)
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
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": request.quantity}],
            mode="payment",
            success_url="https://depscan.net/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url="https://depscan.net/cancel",
            metadata={
                "api_key_id": str(api_key.id),
                "credits": str(request.quantity),
                "tier": request.tier,
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
        logger.error(f"Stripe error creating checkout: {e}")
        raise HTTPException(
            status_code=503,
            detail={"error": "Payment provider error", "code": "STRIPE_ERROR"},
        )


@router.post("/v1/webhook/stripe", status_code=200)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """Receive Stripe events and activate API keys after payment."""
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
        logger.error(f"Webhook payload error: {e}")
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid payload", "code": "INVALID_PAYLOAD"},
        )

    event_type = event["type"]
    logger.info(f"Stripe event received: {event_type}")

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {}) or {}
        try:
            api_key_id = int(metadata.get("api_key_id", 0))
            credits = int(metadata.get("credits", 0))
        except (ValueError, TypeError):
            logger.error(f"Stripe webhook: invalid metadata types — {metadata}")
            return {"received": True}

        if api_key_id <= 0 or credits <= 0 or credits > 10_000:
            logger.error(f"Stripe webhook: out-of-range values api_key_id={api_key_id} credits={credits}")
            return {"received": True}

        result = await db.execute(
            select(APIKey).where(APIKey.id == api_key_id)
        )
        api_key = result.scalar_one_or_none()
        if api_key:
            api_key.status = "active"
            api_key.credits_remaining += credits
            api_key.stripe_customer_id = session.get("customer")
            await db.commit()
            logger.info(f"API key {api_key_id} activated — {credits} credits added")

    elif event_type == "invoice.payment_failed":
        customer = event["data"]["object"].get("customer", "unknown")
        logger.warning("stripe_payment_failed customer=%s", customer)

    elif event_type == "customer.subscription.deleted":
        customer_id = event["data"]["object"].get("customer")
        if customer_id:
            result = await db.execute(
                select(APIKey).where(APIKey.stripe_customer_id == customer_id)
            )
            api_key = result.scalar_one_or_none()
            if api_key:
                api_key.status = "inactive"
                await db.commit()
                logger.info(f"API key deactivated for customer {customer_id}")

    return {"received": True}
