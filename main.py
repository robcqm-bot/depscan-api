import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.cache import close_redis
from app.config import get_settings
from app.database import create_tables
from app.routers import billing as billing_router
from app.routers import monitor as monitor_router
from app.routers import scan as scan_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DepScan API starting...")
    await create_tables()
    yield
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
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    app.include_router(scan_router.router)
    app.include_router(billing_router.router)
    app.include_router(monitor_router.router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run("main:app", host="0.0.0.0", port=settings.app_port, reload=False)
