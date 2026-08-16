from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.connectors.sub2api import NormalizedUsageRoute
from app.models import (
    AuditEvent,
    NotificationChannel,
    NotificationOutbox,
    RoutingSessionState,
    Target,
)
from app.services.routing_usage import observe_actual_account_switches


async def test_actual_switch_baselines_then_notifies_once(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="switch-target", name="Switch target", base_url="https://example.com")
    channel = NotificationChannel(
        id="switch-channel",
        target_id=target.id,
        name="Switch ntfy",
        server_url="https://ntfy.example.com",
        topic="routing",
    )
    db_session.add_all([target, channel])
    await db_session.commit()

    assert (
        await observe_actual_account_switches(
            db_session,
            target_id=target.id,
            target_name=target.name,
            routes=[route(1, "session-a", "1", "Cheap", now)],
            eligible_account_ids={"1", "2"},
            actor="worker:test",
        )
        == 0
    )
    await db_session.commit()
    state = await db_session.scalar(select(RoutingSessionState))
    assert state is not None
    assert state.external_account_id == "1"
    assert await db_session.scalar(select(NotificationOutbox)) is None

    assert (
        await observe_actual_account_switches(
            db_session,
            target_id=target.id,
            target_name=target.name,
            routes=[
                route(1, "session-a", "1", "Cheap", now),
                route(2, "session-a", "1", "Cheap", now + timedelta(seconds=1)),
                route(3, "session-a", "2", "Fallback", now + timedelta(seconds=2)),
            ],
            eligible_account_ids={"1", "2"},
            actor="worker:test",
        )
        == 1
    )
    await db_session.commit()

    outbox = list(await db_session.scalars(select(NotificationOutbox)))
    assert len(outbox) == 1
    assert outbox[0].incident_id is None
    assert outbox[0].payload["title"] == "[Switch target] Actual routing account switched"
    assert "Cheap (1) to Fallback (2)" in outbox[0].payload["message"]
    audit = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "cost_routing.actual_account.switched")
    )
    assert audit is not None
    assert audit.details["usage_id"] == 3

    assert (
        await observe_actual_account_switches(
            db_session,
            target_id=target.id,
            target_name=target.name,
            routes=[route(3, "session-a", "2", "Fallback", now + timedelta(seconds=2))],
            eligible_account_ids={"1", "2"},
            actor="worker:test",
        )
        == 0
    )
    await db_session.commit()
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) == 1


async def test_actual_switch_respects_event_filter_and_account_scope(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="filtered-target", name="Filtered", base_url="https://example.com")
    channel = NotificationChannel(
        id="filtered-channel",
        target_id=target.id,
        name="Incidents only",
        server_url="https://ntfy.example.com",
        topic="routing",
        event_types=["incident.firing"],
    )
    db_session.add_all([target, channel])
    await db_session.commit()

    await observe_actual_account_switches(
        db_session,
        target_id=target.id,
        target_name=target.name,
        routes=[
            route(1, "eligible", "1", "One", now),
            route(2, "ignored", "9", "Nine", now),
        ],
        eligible_account_ids={"1", "2"},
        actor="worker:test",
    )
    await db_session.commit()
    assert (
        await observe_actual_account_switches(
            db_session,
            target_id=target.id,
            target_name=target.name,
            routes=[route(3, "eligible", "2", "Two", now + timedelta(seconds=1))],
            eligible_account_ids={"1", "2"},
            actor="worker:test",
        )
        == 1
    )
    await db_session.commit()
    assert await db_session.scalar(select(NotificationOutbox)) is None
    states = list(await db_session.scalars(select(RoutingSessionState)))
    assert [(state.session_id, state.external_account_id) for state in states] == [
        ("eligible", "2")
    ]


def route(
    usage_id: int,
    session_id: str,
    account_id: str,
    account_name: str,
    used_at: datetime,
) -> NormalizedUsageRoute:
    return NormalizedUsageRoute(
        usage_id=usage_id,
        session_id=session_id,
        external_account_id=account_id,
        account_name=account_name,
        used_at=used_at,
    )
