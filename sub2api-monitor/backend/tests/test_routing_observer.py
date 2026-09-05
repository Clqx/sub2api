import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import Settings
from app.connectors.sub2api import NormalizedUsageRoute
from app.models import (
    NotificationChannel,
    NotificationOutbox,
    RoutingSessionState,
    RoutingUsageCursor,
    Target,
)
from app.security import SecretCipher
from app.services import routing_observer
from app.services.routing_observer import claim_due_route_observations, observe_target_routes
from app.services.routing_usage import observe_actual_account_switches


@pytest.mark.asyncio
async def test_cursor_catches_up_across_pages_and_retries_atomically(
    db_session, settings_dict, monkeypatch
):
    now = datetime.now(timezone.utc)
    target = Target(
        id="cursor-target",
        name="Cursor",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    cursor = RoutingUsageCursor(target_id=target.id, last_usage_id=1)
    state = RoutingSessionState(
        target_id=target.id,
        session_id="s",
        external_account_id="A",
        account_name="A",
        last_usage_id=1,
        last_used_at=now,
    )
    db_session.add_all(
        [
            target,
            cursor,
            state,
            *[
                NotificationChannel(
                    id=f"cursor-{kind}",
                    target_id=target.id,
                    name=kind,
                    kind=kind,
                    server_url="https://ntfy.example.com",
                    topic="switch",
                )
                for kind in ("ntfy", "telegram")
            ],
        ]
    )
    await db_session.commit()
    assert await claim_due_route_observations(db_session, "one", 10) == [target.id]
    assert await claim_due_route_observations(db_session, "two", 10) == []
    records = [
        NormalizedUsageRoute(
            usage_id=i,
            session_id="s",
            external_account_id="B" if 50 <= i < 150 else "A",
            account_name="B" if 50 <= i < 150 else "A",
            used_at=now + timedelta(seconds=i),
        )
        for i in range(2, 252)
    ]
    fail = True
    cursors = []

    class Connector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def usage_route_page(self, after_id):
            nonlocal fail
            cursors.append(after_id)
            if after_id == 101 and fail:
                fail = False
                raise TimeoutError("do not log secret credentials")
            page = [r for r in records if r.usage_id > after_id][:100]
            return page, max((r.usage_id for r in page), default=after_id), len(page) == 100

    async def target_lookup(*_):
        return target

    async def connector_lookup(*_):
        return Connector()

    monkeypatch.setattr(routing_observer, "target_with_secret", target_lookup)
    monkeypatch.setattr(routing_observer, "connector_for_target", connector_lookup)
    settings = Settings(**settings_dict)
    cipher = SecretCipher(settings.master_key)
    await observe_target_routes(db_session, target.id, settings, cipher, "one")
    await db_session.refresh(cursor)
    assert cursor.last_usage_id == 101
    assert "TimeoutError" in cursor.last_error
    assert "secret" not in cursor.last_error
    await db_session.refresh(target)
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) == 2

    cursor.next_run_at = now - timedelta(seconds=1)
    await db_session.commit()
    assert await claim_due_route_observations(db_session, "two", 10) == [target.id]
    await observe_target_routes(db_session, target.id, settings, cipher, "two")
    await db_session.refresh(cursor)
    assert cursor.last_usage_id == 251
    assert cursor.last_error is None
    assert cursors == [1, 101, 101, 201]
    outbox = list(await db_session.scalars(select(NotificationOutbox)))
    assert len(outbox) == 4  # A -> B -> A, for BOTH ntfy and Telegram.
    assert len({(r.transition_id, r.channel_id) for r in outbox}) == 4


@pytest.mark.asyncio
async def test_first_live_batch_reports_switch_and_older_pages_never_rewind(db_session):
    now = datetime.now(timezone.utc)
    target = Target(id="live-target", name="Live", base_url="https://example.com")
    db_session.add(target)
    await db_session.commit()

    def route(i, account):
        return NormalizedUsageRoute(
            usage_id=i,
            session_id="new",
            external_account_id=account,
            account_name=account,
            used_at=now,
        )

    kwargs = dict(
        target_id=target.id, target_name=target.name, eligible_account_ids=None, actor="test"
    )
    assert (
        await observe_actual_account_switches(
            db_session, routes=[route(10, "A"), route(11, "B"), route(12, "A")], **kwargs
        )
        == 2
    )
    await db_session.commit()
    assert await observe_actual_account_switches(db_session, routes=[route(9, "B")], **kwargs) == 0
    await db_session.commit()
    state = await db_session.scalar(select(RoutingSessionState))
    assert state.last_usage_id == 12
    assert state.external_account_id == "A"
    assert await observe_actual_account_switches(
        db_session, routes=[route(13, "B"), route(14, "A"), route(15, "B")],
        initialize_only=True, **kwargs,
    ) == 0
    assert state.last_usage_id == 15
    assert state.external_account_id == "B"
    assert await observe_actual_account_switches(db_session, routes=[route(16, "A")], **kwargs) == 1


async def test_cancelled_observer_rolls_back_partial_page_before_releasing_lease(
    db_session, settings_dict, monkeypatch
):
    target = Target(
        id="cancel-target", name="Cancel", base_url="https://example.com",
        enabled=True, monitoring_readiness="ready",
    )
    cursor = RoutingUsageCursor(target_id=target.id, last_usage_id=1)
    db_session.add_all([target, cursor])
    await db_session.commit()
    await claim_due_route_observations(db_session, "cancel-worker", 1)

    class Connector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def usage_route_page(self, _):
            return [], 2, False

    async def target_lookup(*_):
        return target

    async def connector_lookup(*_):
        return Connector()

    async def interrupted_page(session, **_):
        cursor.last_usage_id = 999
        await session.flush()
        raise asyncio.CancelledError()

    monkeypatch.setattr(routing_observer, "target_with_secret", target_lookup)
    monkeypatch.setattr(routing_observer, "connector_for_target", connector_lookup)
    monkeypatch.setattr(routing_observer, "observe_actual_account_switches", interrupted_page)
    settings = Settings(**settings_dict)
    with pytest.raises(asyncio.CancelledError):
        await observe_target_routes(
            db_session,
            "cancel-target",
            settings,
            SecretCipher(settings.master_key),
            "cancel-worker",
        )
    await db_session.refresh(cursor)
    assert cursor.last_usage_id == 1
    assert cursor.lease_owner is None
    assert cursor.lease_until is None
