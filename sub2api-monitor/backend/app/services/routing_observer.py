"""Independent, leased, resumable route observation with transactional outbox."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import RoutingUsageCursor, Target
from app.security import SecretCipher
from app.services.routing_usage import observe_actual_account_switches
from app.services.targets import connector_for_target, target_with_secret

logger = logging.getLogger(__name__)
OBSERVATION_BUDGET_SECONDS = 15.0
OBSERVATION_LEASE_SECONDS = 45


async def claim_due_route_observations(session: AsyncSession, owner: str, limit: int) -> list[str]:
    now = datetime.now(timezone.utc)
    due = or_(RoutingUsageCursor.next_run_at.is_(None), RoutingUsageCursor.next_run_at <= now)
    unlocked = or_(RoutingUsageCursor.lease_until.is_(None), RoutingUsageCursor.lease_until <= now)
    target_ids = list(
        await session.scalars(
            select(Target.id)
            .outerjoin(RoutingUsageCursor, RoutingUsageCursor.target_id == Target.id)
            .where(Target.enabled.is_(True), Target.monitoring_readiness == "ready", due, unlocked)
            .order_by(RoutingUsageCursor.next_run_at.asc().nullsfirst(), Target.id)
            .limit(limit)
        )
    )
    claimed: list[str] = []
    insert = sqlite_insert if session.get_bind().dialect.name == "sqlite" else pg_insert
    for target_id in target_ids:
        await session.execute(
            insert(RoutingUsageCursor)
            .values(target_id=target_id, updated_at=now)
            .on_conflict_do_nothing(index_elements=["target_id"])
        )
        acquired = await session.scalar(
            update(RoutingUsageCursor)
            .where(RoutingUsageCursor.target_id == target_id, due, unlocked)
            .values(
                lease_owner=owner, lease_until=now + timedelta(seconds=OBSERVATION_LEASE_SECONDS)
            )
            .returning(RoutingUsageCursor.target_id)
        )
        if acquired:
            claimed.append(acquired)
    await session.commit()
    return claimed


async def observe_target_routes(
    session: AsyncSession, target_id: str, settings: Settings, cipher: SecretCipher, owner: str
) -> None:
    deadline = asyncio.get_running_loop().time() + OBSERVATION_BUDGET_SECONDS
    try:
        target = await target_with_secret(session, target_id)
        if target is None or not target.enabled:
            return
        connector = await connector_for_target(session, target, settings, cipher)
        async with connector:
            for _ in range(settings.connector_max_pages):
                cursor = await session.scalar(
                    select(RoutingUsageCursor)
                    .where(
                        RoutingUsageCursor.target_id == target_id,
                        RoutingUsageCursor.lease_owner == owner,
                    )
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if cursor is None:
                    return
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0.1:
                    break
                routes, last_id, more = await asyncio.wait_for(
                    connector.usage_route_page(cursor.last_usage_id), timeout=min(5.0, remaining)
                )
                initializing = cursor.last_usage_id is None
                count = await observe_actual_account_switches(
                    session,
                    target_id=target.id,
                    target_name=target.name,
                    routes=routes,
                    eligible_account_ids=None,
                    actor=f"worker:{owner}",
                    # Also reset legacy session baselines without replaying alerts.
                    initialize_only=initializing,
                )
                cursor.last_usage_id = last_id
                cursor.last_error = None
                cursor.updated_at = datetime.now(timezone.utc)
                # Cursor, session state, audit and notification intents commit together.
                await session.commit()
                logger.info(
                    "routing usage observed target_id=%s cursor=%s "
                    "switches=%s backlog=%s baseline=%s",
                    target.id,
                    last_id,
                    count,
                    more,
                    initializing,
                )
                if initializing or not more:
                    break
    except asyncio.CancelledError:
        # Releasing the lease must not commit a half-observed page on shutdown.
        await session.rollback()
        raise
    except Exception as exc:
        await session.rollback()
        # Error details can contain a target URL/token; retain only safe diagnostics.
        error = f"usage observation failed: {type(exc).__name__} (cursor retained; retry pending)"
        await session.execute(
            update(RoutingUsageCursor)
            .where(
                RoutingUsageCursor.target_id == target_id, RoutingUsageCursor.lease_owner == owner
            )
            .values(last_error=error)
        )
        await session.commit()
        logger.warning("%s target_id=%s", error, target_id)
    finally:
        await session.execute(
            update(RoutingUsageCursor)
            .where(
                RoutingUsageCursor.target_id == target_id, RoutingUsageCursor.lease_owner == owner
            )
            .values(
                lease_owner=None,
                lease_until=None,
                next_run_at=datetime.now(timezone.utc) + timedelta(seconds=5),
            )
        )
        await session.commit()
