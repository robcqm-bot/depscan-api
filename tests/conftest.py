"""Shared pytest fixtures — DB and Redis mocked so tests run without real services."""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Set a valid DATABASE_URL before any app import so the SQLAlchemy engine
# URL parser doesn't fail on an empty string (tests never actually connect).
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost/depscan_test"


@pytest.fixture
def client():
    """TestClient with DB and Redis fully mocked."""
    from fastapi.testclient import TestClient
    from main import app
    from app.database import get_db

    async def mock_db():
        session = AsyncMock()
        # scalar_one_or_none() is synchronous → MagicMock, not AsyncMock
        result = MagicMock()
        result.scalar_one_or_none.return_value = None  # key not found → 401
        session.execute = AsyncMock(return_value=result)
        session.add = AsyncMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        yield session

    app.dependency_overrides[get_db] = mock_db

    # Patch create_tables where it lives in main.py's namespace (not in app.database)
    with (
        patch("main.create_tables", new=AsyncMock()),
        patch("app.cache.get_redis", new=AsyncMock()),
    ):
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    app.dependency_overrides.clear()
