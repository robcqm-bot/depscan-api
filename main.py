import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.cache import close_redis
from app.config import get_settings
from app.database import create_tables
from app.routers import billing as billing_router
from app.routers import internal as internal_router
from app.routers import monitor as monitor_router
from app.routers import scan as scan_router
from app.tasks.monitor_job import run_monitor_job

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DepScan API starting...")
    try:
        await create_tables()
    except Exception as e:
        # With multiple workers, a sibling process may have already created
        # the tables — that's fine, continue normally.
        logger.info(f"Tables already exist or concurrent init: {e}")

    settings = get_settings()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_monitor_job,
        "interval",
        hours=settings.monitor_scan_interval_hours,
        id="monitor_job",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Monitor scheduler started (interval={settings.monitor_scan_interval_hours}h)")

    yield

    scheduler.shutdown(wait=False)
    logger.info("DepScan API shutting down...")
    await close_redis()


def create_app() -> FastAPI:
    app = FastAPI(
        title="DepScan API",
        description=(
            "Dependency health checking for AI agent skills. "
            "Given a list of endpoints, returns uptime, SSL validity, "
            "blacklist status, and a trust score."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://depscan.net",
            "https://www.depscan.net",
        ],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(scan_router.router)
    app.include_router(billing_router.router)
    app.include_router(monitor_router.router)
    app.include_router(internal_router.router)

    @app.get("/v1/quickstart", tags=["quickstart"])
    def quickstart():
        return {
            "service": "DepScan API",
            "description": "Dependency health checking for AI agent skills.",
            "base_url": "https://depscan.net",
            "authentication": {
                "header": "Authorization: Bearer <api_key>",
                "key_format": "dsk_live_...",
                "note": "API key is shown ONCE at checkout — save it before completing payment.",
            },
            "steps": [
                {
                    "step": 1,
                    "action": "Get an API key",
                    "method": "POST",
                    "endpoint": "/v1/billing/checkout",
                    "body": {
                        "tier": "single_starter",
                    },
                    "tiers": {
                        "single_starter": "25 credits — MXN $25 (one-time)",
                        "single_pro": "100 credits — MXN $80 (one-time)",
                        "single_business": "500 credits — MXN $299 (one-time)",
                        "deep_starter": "10 credits — MXN $30 (one-time)",
                        "deep_pro": "50 credits — MXN $120 (one-time)",
                        "deep_business": "200 credits — MXN $449 (one-time)",
                        "monitor": "500 credits/month — MXN $199/month",
                        "unlimited": "999,999 credits/month — MXN $999/month",
                    },
                    "response": {
                        "checkout_url": "Open this URL to complete payment",
                        "api_key": "Save this immediately — not retrievable after checkout",
                    },
                },
                {
                    "step": 2,
                    "action": "Scan endpoints",
                    "method": "POST",
                    "endpoint": "/v1/scan-deps",
                    "headers": {"Authorization": "Bearer dsk_live_..."},
                    "body": {
                        "endpoints": ["https://api.example.com"],
                        "scan_type": "single",
                    },
                    "scan_types": {
                        "single": "Uptime + SSL + blacklist (1 credit per endpoint)",
                        "deep": "Single + WHOIS + AbuseIPDB + redirect chain (1 credit per endpoint)",
                    },
                    "response_fields": {
                        "overall_score": "0-100 trust score",
                        "status": "SAFE | CAUTION | RISK | CRITICAL",
                        "recommendation": "SAFE_TO_INSTALL | REVIEW_BEFORE_INSTALL | DO_NOT_INSTALL",
                        "endpoints[].score": "Individual endpoint score 0-100",
                        "endpoints[].flags": "NEW_DOMAIN | SSL_EXPIRING | ABUSE_REPORTED | IN_BLACKLIST | ...",
                    },
                },
            ],
            "common_errors": {
                "KEY_PENDING": "Payment not completed — finish checkout before using the key",
                "INSUFFICIENT_CREDITS": "Buy more credits at /v1/billing/checkout",
                "402": "Out of credits",
                "401": "Missing or invalid Authorization header",
            },
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run("main:app", host="0.0.0.0", port=settings.app_port, reload=False)
