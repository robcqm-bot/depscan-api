"""Alembic environment — configured for asyncpg (SQLAlchemy async)."""

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# Load the Alembic config object (provides access to alembic.ini values)
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Import the ORM Base so Alembic can detect the target schema for autogenerate
# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path when running `alembic` from /opt/depscan-api
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.db import (  # noqa: F401 — side-effects register models on Base.metadata
    AlertHistory,
    APIKey,
    EndpointResultDB,
    Scan,
    Subscription,
)
from app.database import Base

target_metadata = Base.metadata

# ---------------------------------------------------------------------------
# Resolve the database URL from the environment (.env file or env vars)
# Always prefer the runtime DATABASE_URL over alembic.ini so secrets stay
# out of version control.
# ---------------------------------------------------------------------------
def _get_db_url() -> str:
    from dotenv import load_dotenv
    load_dotenv()  # honours .env in the working directory
    url = os.getenv("DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Create a .env file or export DATABASE_URL before running alembic."
        )
    return url


# ---------------------------------------------------------------------------
# Offline migrations (generate SQL without a live DB connection)
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    url = _get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (connect to the real DB and run)
# ---------------------------------------------------------------------------
def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    url = _get_db_url()
    engine = create_async_engine(url, echo=False)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
