from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

os.environ.setdefault("MONITOR_DATABASE_URL", "sqlite+aiosqlite:////tmp/sub2api-monitor-tests.db")
os.environ.setdefault("MONITOR_MASTER_KEY", "test-master-key-that-is-long-enough")
os.environ.setdefault("MONITOR_ADMIN_PASSWORD", "test-admin-password-long-enough")

from app.database import Base  # noqa: E402


@pytest.fixture
def settings_dict() -> dict[str, object]:
    return {
        "database_url": "sqlite+aiosqlite://",
        "master_key": "test-master-key-that-is-long-enough",
        "admin_password": "test-admin-password-long-enough",
        "allow_private_targets": True,
        "connector_page_size": 2,
        "connector_max_pages": 5,
        "connector_timeout_seconds": 2,
    }


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()
