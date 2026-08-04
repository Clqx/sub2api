from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from sqlalchemy import text

from app import __version__
from app.api.router import router
from app.config import get_settings
from app.database import SessionFactory
from app.security import ensure_admin


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    async with SessionFactory() as session:
        await ensure_admin(session, settings.admin_username, settings.admin_password)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Sub2API Monitor API",
        version=__version__,
        lifespan=lifespan,
    )
    app.include_router(router)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready", tags=["system"])
    async def ready() -> dict[str, str]:
        async with SessionFactory() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ready"}

    return app


app = create_app()


def run() -> None:
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
