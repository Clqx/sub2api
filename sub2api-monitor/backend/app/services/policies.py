from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AccountCurrent,
    ChannelMonitorCurrent,
    Incident,
    IncidentStatus,
    IncidentTransition,
    NotificationChannel,
    NotificationOutbox,
    Policy,
    QuotaSample,
)


def incident_fingerprint(
    target_id: str,
    policy_id: str,
    subject_type: str,
    subject_id: str,
    rule_key: str,
    window_key: str,
) -> str:
    raw = "\x1f".join([target_id, policy_id, subject_type, subject_id, rule_key, window_key])
    return hashlib.sha256(raw.encode()).hexdigest()


async def policy_for_target(session: AsyncSession, target_id: str) -> Policy:
    policy = await session.scalar(
        select(Policy)
        .where(
            Policy.enabled.is_(True), or_(Policy.target_id == target_id, Policy.target_id.is_(None))
        )
        .order_by(Policy.target_id.is_(None), Policy.id)
    )
    if policy is None:
        policy = Policy(name="Default", target_id=None)
        session.add(policy)
        await session.flush()
    return policy


async def _queue_transition(
    session: AsyncSession, incident: Incident, transition: IncidentTransition, event: str
) -> None:
    channels = list(
        await session.scalars(
            select(NotificationChannel).where(
                NotificationChannel.enabled.is_(True),
                or_(
                    NotificationChannel.target_id == incident.target_id,
                    NotificationChannel.target_id.is_(None),
                ),
            )
        )
    )
    for channel in channels:
        session.add(
            NotificationOutbox(
                incident_id=incident.id,
                transition_id=transition.id,
                channel_id=channel.id,
                payload={
                    "title": incident.title,
                    "message": incident.message,
                    "priority": 5 if incident.severity == "critical" else 3,
                    "tags": [event, incident.rule_key.replace(".", "-")],
                },
            )
        )


async def _set_incident(
    session: AsyncSession,
    *,
    target_id: str,
    policy: Policy,
    subject_id: str,
    rule_key: str,
    window_key: str,
    firing: bool,
    severity: str,
    title: str,
    message: str,
    subject_type: str = "account",
) -> None:
    fingerprint = incident_fingerprint(
        target_id, policy.id, subject_type, subject_id, rule_key, window_key
    )
    incident = await session.scalar(select(Incident).where(Incident.fingerprint == fingerprint))
    now = datetime.now(timezone.utc)
    if firing:
        if incident is None:
            incident = Incident(
                target_id=target_id,
                policy_id=policy.id,
                subject_type=subject_type,
                subject_id=subject_id,
                rule_key=rule_key,
                window_key=window_key,
                fingerprint=fingerprint,
                status=IncidentStatus.FIRING.value,
                severity=severity,
                title=title,
                message=message,
            )
            session.add(incident)
            await session.flush()
            transition = IncidentTransition(
                incident_id=incident.id,
                from_status=None,
                to_status=IncidentStatus.FIRING.value,
                reason="threshold crossed",
            )
            session.add(transition)
            await session.flush()
            await _queue_transition(session, incident, transition, "warning")
        elif incident.status == IncidentStatus.RESOLVED.value:
            old = incident.status
            incident.status = IncidentStatus.FIRING.value
            incident.severity = severity
            incident.title = title
            incident.message = message
            incident.fired_at = now
            incident.resolved_at = None
            transition = IncidentTransition(
                incident_id=incident.id,
                from_status=old,
                to_status=IncidentStatus.FIRING.value,
                reason="condition recurred",
            )
            session.add(transition)
            await session.flush()
            await _queue_transition(session, incident, transition, "warning")
        elif severity == "critical" and incident.severity != "critical":
            incident.severity = severity
            incident.title = title
            incident.message = message
            transition = IncidentTransition(
                incident_id=incident.id,
                from_status=incident.status,
                to_status=incident.status,
                reason="severity escalated",
            )
            session.add(transition)
            await session.flush()
            await _queue_transition(session, incident, transition, "warning")
    elif incident is not None and incident.status != IncidentStatus.RESOLVED.value:
        old = incident.status
        incident.status = IncidentStatus.RESOLVED.value
        incident.resolved_at = now
        transition = IncidentTransition(
            incident_id=incident.id,
            from_status=old,
            to_status=IncidentStatus.RESOLVED.value,
            reason="condition recovered",
        )
        session.add(transition)
        await session.flush()
        await _queue_transition(session, incident, transition, "white_check_mark")


async def evaluate_account(
    session: AsyncSession,
    target_name: str,
    account: AccountCurrent,
    quotas: list[QuotaSample],
) -> None:
    policy = await policy_for_target(session, account.target_id)
    if policy.unavailable_enabled:
        await _set_incident(
            session,
            target_id=account.target_id,
            policy=policy,
            subject_id=account.external_account_id,
            rule_key="account.unavailable",
            window_key="",
            firing=not account.available,
            severity="critical",
            title=f"[{target_name}] Account unavailable",
            message=(
                f"Account {account.name} is unavailable: " + ", ".join(account.availability_reasons)
            )[:1000],
        )
    for quota in quotas:
        if quota.freshness != "fresh" or quota.remaining_percent is None:
            continue
        severity = (
            "critical" if quota.remaining_percent <= policy.quota_critical_remaining else "warning"
        )
        firing = quota.remaining_percent <= policy.quota_warning_remaining
        if not firing and quota.remaining_percent < policy.quota_recovery_remaining:
            # Hysteresis band: retain the current incident state without a transition.
            continue
        await _set_incident(
            session,
            target_id=account.target_id,
            policy=policy,
            subject_id=account.external_account_id,
            rule_key="quota.low",
            window_key=quota.quota_key,
            firing=firing,
            severity=severity,
            title=f"[{target_name}] Account quota low",
            message=(
                f"Account {account.name}, {quota.label}: {quota.remaining_percent:.1f}% remaining"
            ),
        )


def upstream_rate_multiplier(snapshot: dict[str, Any] | None) -> float | None:
    if not isinstance(snapshot, dict):
        return None
    data = snapshot.get("data")
    if not isinstance(data, dict):
        data = {}
    for value in (
        data.get("resolved_rate_multiplier"),
        data.get("effective_rate_multiplier"),
        snapshot.get("synced_rate_multiplier"),
    ):
        if value is None or isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        try:
            multiplier = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(multiplier) and multiplier >= 0:
            return multiplier
    return None


async def evaluate_upstream_rate_change(
    session: AsyncSession,
    target_name: str,
    account: AccountCurrent,
    previous_multiplier: float | None,
) -> None:
    if (
        account.platform.casefold() != "openai"
        or account.account_type.casefold() != "apikey"
        or not account.upstream_billing_probe_enabled
    ):
        return
    current_multiplier = upstream_rate_multiplier(account.upstream_billing_probe)
    if previous_multiplier is None or current_multiplier is None:
        return
    changed = not math.isclose(
        previous_multiplier,
        current_multiplier,
        rel_tol=1e-9,
        abs_tol=1e-9,
    )
    policy = await policy_for_target(session, account.target_id)
    await _set_incident(
        session,
        target_id=account.target_id,
        policy=policy,
        subject_id=account.external_account_id,
        rule_key="upstream.rate_multiplier.changed",
        window_key="resolved_rate_multiplier",
        firing=changed,
        severity="warning",
        title=f"[{target_name}] Upstream rate multiplier changed",
        message=(
            f"Account {account.name} upstream resolved rate multiplier changed "
            f"from x{previous_multiplier:g} to x{current_multiplier:g}"
        ),
    )


async def evaluate_channel(
    session: AsyncSession, target_name: str, channel: ChannelMonitorCurrent
) -> None:
    policy = await policy_for_target(session, channel.target_id)
    if not policy.channel_failure_enabled:
        return
    unhealthy = channel.enabled and channel.primary_status in {"failed", "error"}
    degraded = channel.enabled and channel.primary_status == "degraded"
    await _set_incident(
        session,
        target_id=channel.target_id,
        policy=policy,
        subject_id=channel.external_monitor_id,
        subject_type="channel_monitor",
        rule_key="channel.unhealthy",
        window_key=channel.primary_model,
        firing=unhealthy or degraded,
        severity="critical" if unhealthy else "warning",
        title=f"[{target_name}] Channel monitor unhealthy",
        message=(
            f"Channel {channel.name} ({channel.primary_model or 'primary model'}) is "
            f"{channel.primary_status or 'unknown'}; latency={channel.primary_latency_ms}ms"
        )[:1000],
    )
