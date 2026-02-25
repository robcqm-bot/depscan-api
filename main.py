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

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run("main:app", host="0.0.0.0", port=settings.app_port, reload=False)
