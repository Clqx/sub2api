from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.sub2api import NormalizedUsageRoute
from app.models import (
    AuditEvent,
    NotificationChannel,
    NotificationOutbox,
    RoutingSessionState,
)

ROUTING_SWITCH_EVENT = "routing.account_switched"
ROUTING_RATE_RECOVERED_EVENT = "routing.rate_recovered"


async def queue_rate_recovered(
    session: AsyncSession,
    *,
    target_id: str,
    target_name: str,
    account_id: str,
    account_name: str,
    previous_multiplier: float | None,
    multiplier: float,
    previous_priority: int | None,
    priority: int,
    occurred_at: datetime,
    decision_id: str,
) -> None:
    channels = list(
        await session.scalars(
            select(NotificationChannel).where(
                NotificationChannel.enabled.is_(True),
                or_(
                    NotificationChannel.target_id == target_id,
                    NotificationChannel.target_id.is_(None),
                ),
            )
        )
    )
    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"sub2api-monitor:{target_id}:{ROUTING_RATE_RECOVERED_EVENT}:{decision_id}",
        )
    )
    title = f"[{target_name}] Rate multiplier recovered"
    multiplier_change = (
        f"multiplier dropped from x{previous_multiplier:g} to x{multiplier:g}"
        if previous_multiplier is not None
        else f"multiplier recovered to x{multiplier:g}"
    )
    message = (
        f"Account {account_name} ({account_id}) {multiplier_change}; "
        f"routing priority restored from {previous_priority} to {priority}"
    )
    for channel in channels:
        if (
            ROUTING_RATE_RECOVERED_EVENT not in channel.event_types
            or "warning" not in channel.severities
        ):
            continue
        payload = (
            {
                "event_id": event_id,
                "event_type": ROUTING_RATE_RECOVERED_EVENT,
                "occurred_at": occurred_at.isoformat(),
                "target_id": target_id,
                "severity": "warning",
                "rate_recovery": {
                    "decision_id": decision_id,
                    "account_id": account_id,
                    "account_name": account_name,
                    "previous_multiplier": previous_multiplier,
                    "multiplier": multiplier,
                    "previous_priority": previous_priority,
                    "priority": priority,
                },
            }
            if channel.kind == "webhook"
            else {
                "title": title,
                "message": message[:1000],
                "priority": 3,
                "tags": ["arrow_heading_down", "routing-rate-recovered"],
            }
        )
        session.add(
            NotificationOutbox(
                transition_id=event_id,
                channel_id=channel.id,
                payload=payload,
            )
        )


async def observe_actual_account_switches(
    session: AsyncSession,
    *,
    target_id: str,
    target_name: str,
    routes: list[NormalizedUsageRoute],
    eligible_account_ids: set[str],
    actor: str,
) -> int:
    by_session: dict[str, list[NormalizedUsageRoute]] = defaultdict(list)
    for route in routes:
        if route.external_account_id in eligible_account_ids:
            by_session[route.session_id].append(route)
    if not by_session:
        return 0

    states = list(
        await session.scalars(
            select(RoutingSessionState).where(
                RoutingSessionState.target_id == target_id,
                RoutingSessionState.session_id.in_(by_session),
            )
        )
    )
    state_by_session = {state.session_id: state for state in states}
    switch_count = 0
    now = datetime.now(timezone.utc)

    for session_id, session_routes in by_session.items():
        session_routes.sort(key=lambda item: item.usage_id)
        state = state_by_session.get(session_id)
        if state is None:
            latest = session_routes[-1]
            session.add(
                RoutingSessionState(
                    target_id=target_id,
                    session_id=session_id,
                    external_account_id=latest.external_account_id,
                    account_name=latest.account_name,
                    last_usage_id=latest.usage_id,
                    last_used_at=latest.used_at,
                )
            )
            continue

        newest = session_routes[-1]
        if newest.usage_id < state.last_usage_id:
            _update_state(state, newest, now)
            continue

        for route in session_routes:
            if route.usage_id <= state.last_usage_id:
                continue
            if route.external_account_id != state.external_account_id:
                await _queue_switch(
                    session,
                    target_id=target_id,
                    target_name=target_name,
                    route=route,
                    previous_account_id=state.external_account_id,
                    previous_account_name=state.account_name,
                )
                session.add(
                    AuditEvent(
                        actor=actor,
                        action="cost_routing.actual_account.switched",
                        target_id=target_id,
                        details={
                            "session_id": route.session_id,
                            "usage_id": route.usage_id,
                            "previous_account_id": state.external_account_id,
                            "previous_account_name": state.account_name,
                            "account_id": route.external_account_id,
                            "account_name": route.account_name,
                        },
                    )
                )
                switch_count += 1
            _update_state(state, route, now)
    return switch_count


def _update_state(
    state: RoutingSessionState,
    route: NormalizedUsageRoute,
    updated_at: datetime,
) -> None:
    state.external_account_id = route.external_account_id
    state.account_name = route.account_name
    state.last_usage_id = route.usage_id
    state.last_used_at = route.used_at
    state.updated_at = updated_at


async def _queue_switch(
    session: AsyncSession,
    *,
    target_id: str,
    target_name: str,
    route: NormalizedUsageRoute,
    previous_account_id: str,
    previous_account_name: str,
) -> None:
    channels = list(
        await session.scalars(
            select(NotificationChannel).where(
                NotificationChannel.enabled.is_(True),
                or_(
                    NotificationChannel.target_id == target_id,
                    NotificationChannel.target_id.is_(None),
                ),
            )
        )
    )
    title = f"[{target_name}] Actual routing account switched"
    message = (
        f"Session {route.session_id} switched from {previous_account_name} "
        f"({previous_account_id}) to {route.account_name} "
        f"({route.external_account_id}); usage_id={route.usage_id}"
    )
    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"sub2api-monitor:{target_id}:{ROUTING_SWITCH_EVENT}:{route.usage_id}",
        )
    )
    for channel in channels:
        if ROUTING_SWITCH_EVENT not in channel.event_types or "warning" not in channel.severities:
            continue
        payload = (
            {
                "event_id": event_id,
                "event_type": ROUTING_SWITCH_EVENT,
                "occurred_at": route.used_at.isoformat(),
                "target_id": target_id,
                "severity": "warning",
                "routing_switch": {
                    "session_id": route.session_id,
                    "usage_id": route.usage_id,
                    "previous_account_id": previous_account_id,
                    "previous_account_name": previous_account_name,
                    "account_id": route.external_account_id,
                    "account_name": route.account_name,
                },
            }
            if channel.kind == "webhook"
            else {
                "title": title,
                "message": message[:1000],
                "priority": 3,
                "tags": ["twisted_rightwards_arrows", "routing-account-switched"],
            }
        )
        session.add(
            NotificationOutbox(
                transition_id=event_id,
                channel_id=channel.id,
                payload=payload,
            )
        )
