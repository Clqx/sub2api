from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import (
    AccountObservation,
    ActiveQuotaAttempt,
    CollectionRun,
    QuotaSample,
    RoutingSessionState,
    RunStatus,
    Session,
)


async def purge_expired_history(
    session: AsyncSession,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> None:
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=settings.history_retention_days)

    await session.execute(delete(Session).where(Session.expires_at <= current))
    await session.execute(delete(QuotaSample).where(QuotaSample.observed_at < cutoff))
    await session.execute(
        delete(AccountObservation).where(AccountObservation.received_at < cutoff)
    )
    await session.execute(
        delete(ActiveQuotaAttempt).where(ActiveQuotaAttempt.created_at < cutoff)
    )
    await session.execute(
        delete(RoutingSessionState).where(RoutingSessionState.updated_at < cutoff)
    )
    await session.execute(
        delete(CollectionRun).where(
            CollectionRun.created_at < cutoff,
            CollectionRun.status.in_([RunStatus.SUCCEEDED.value, RunStatus.FAILED.value]),
        )
    )
    await session.commit()
