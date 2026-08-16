from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.sub2api import NativeAlertEvent
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
    session: AsyncSession,
    incident: Incident,
    transition: IncidentTransition,
    event_type: str,
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
        if event_type not in channel.event_types or incident.severity not in channel.severities:
            continue
        payload: dict[str, Any]
        if channel.kind == "webhook":
            payload = {
                "event_id": transition.id,
                "event_type": event_type,
                "occurred_at": transition.created_at.isoformat(),
                "target_id": incident.target_id,
                "incident": {
                    "id": incident.id,
                    "status": incident.status,
                    "severity": incident.severity,
                    "rule_key": incident.rule_key,
                    "subject_type": incident.subject_type,
                    "subject_id": incident.subject_id,
                    "title": incident.title,
                    "message": incident.message,
                },
            }
        else:
            tag = "white_check_mark" if event_type == "incident.resolved" else "warning"
            payload = {
                "title": incident.title,
                "message": incident.message,
                "priority": 5 if incident.severity == "critical" else 3,
                "tags": [tag, incident.rule_key.replace(".", "-")],
            }
        session.add(
            NotificationOutbox(
                incident_id=incident.id,
                transition_id=transition.id,
                channel_id=channel.id,
                payload=payload,
            )
        )


async def _queue_automation_transition(
    session: AsyncSession, incident: Incident, transition: IncidentTransition
) -> None:
    from app.services.automation import schedule_automations

    await schedule_automations(session, incident, transition)


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
    notify_on_change: bool = False,
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
            await _queue_transition(session, incident, transition, "incident.firing")
            await _queue_automation_transition(session, incident, transition)
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
            await _queue_transition(session, incident, transition, "incident.firing")
            await _queue_automation_transition(session, incident, transition)
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
            await _queue_transition(session, incident, transition, "incident.escalated")
        elif notify_on_change and (incident.title != title or incident.message != message):
            incident.severity = severity
            incident.title = title
            incident.message = message
            transition = IncidentTransition(
                incident_id=incident.id,
                from_status=incident.status,
                to_status=incident.status,
                reason="condition changed",
            )
            session.add(transition)
            await session.flush()
            await _queue_transition(session, incident, transition, "incident.firing")
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
        await _queue_transition(session, incident, transition, "incident.resolved")


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
        data.get("effective_rate_multiplier"),
        data.get("resolved_rate_multiplier"),
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
    if account.platform.casefold() != "openai" or account.account_type.casefold() != "apikey":
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
            f"Account {account.name} upstream effective rate multiplier changed "
            f"from x{previous_multiplier:g} to x{current_multiplier:g}"
        ),
        notify_on_change=True,
    )


async def evaluate_upstream_probe_health(
    session: AsyncSession,
    target_name: str,
    account: AccountCurrent,
) -> None:
    if account.platform.casefold() != "openai" or account.account_type.casefold() != "apikey":
        return
    snapshot = account.upstream_billing_probe
    status = snapshot.get("status") if isinstance(snapshot, dict) else None
    error = snapshot.get("last_error") if isinstance(snapshot, dict) else None
    policy = await policy_for_target(session, account.target_id)
    await _set_incident(
        session,
        target_id=account.target_id,
        policy=policy,
        subject_id=account.external_account_id,
        rule_key="upstream.billing_probe.failed",
        window_key="",
        firing=status not in {"ok", "unsupported"},
        severity="critical",
        title=f"[{target_name}] Upstream billing probe failed",
        message=(
            f"Account {account.name} upstream billing probe failed: "
            f"{error or status or 'missing result'}"
        )[:1000],
        notify_on_change=True,
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


async def evaluate_collection_health(
    session: AsyncSession, target_id: str, target_name: str, error: str | None
) -> None:
    policy = await policy_for_target(session, target_id)
    if not policy.collection_failure_enabled:
        return
    await _set_incident(
        session,
        target_id=target_id,
        policy=policy,
        subject_id=target_id,
        subject_type="target",
        rule_key="target.collection_failed",
        window_key="",
        firing=error is not None,
        severity="critical",
        title=f"[{target_name}] Scheduled collection failed",
        message=(error or "Scheduled collection recovered")[:1000],
    )


async def evaluate_cost_routing_run(
    session: AsyncSession,
    target_id: str,
    target_name: str,
    error: str | None,
) -> None:
    policy = await policy_for_target(session, target_id)
    await _set_incident(
        session,
        target_id=target_id,
        policy=policy,
        subject_id=target_id,
        subject_type="target",
        rule_key="cost_routing.run_failed",
        window_key="",
        firing=error is not None,
        severity="critical",
        title=f"[{target_name}] Cost routing control failed",
        message=(error or "Cost routing control recovered")[:1000],
        notify_on_change=True,
    )


async def evaluate_routing_action(
    session: AsyncSession,
    *,
    target_id: str,
    target_name: str,
    account_id: str,
    account_name: str,
    mode: str,
    firing: bool,
    reason: str,
    previous_priority: int | None,
    desired_priority: int,
    error: str | None = None,
    detail: str | None = None,
) -> None:
    policy = await policy_for_target(session, target_id)
    if error is not None:
        rule_key = "cost_routing.priority_update_failed"
        title = f"[{target_name}] Routing priority update failed"
        message = (
            f"Account {account_name} priority {previous_priority} -> {desired_priority} failed: "
            f"{error}"
        )
        severity = "critical"
    else:
        rule_key = (
            "cost_routing.priority_recommended"
            if mode == "recommend"
            else "cost_routing.priority_changed"
        )
        title = (
            f"[{target_name}] Routing priority recommendation"
            if mode == "recommend"
            else f"[{target_name}] Routing priority changed"
        )
        verb = "recommended" if mode == "recommend" else "changed"
        message = (
            f"Account {account_name} priority {verb} from {previous_priority} "
            f"to {desired_priority}; reason={reason}"
        )
        severity = (
            "critical"
            if reason in {"unavailable", "probe_failed", "quality_failed"}
            else "warning"
        )
    if detail:
        message = f"{message}; detail={detail}"
    await _set_incident(
        session,
        target_id=target_id,
        policy=policy,
        subject_id=account_id,
        rule_key=rule_key,
        window_key="priority",
        firing=firing,
        severity=severity,
        title=title,
        message=message[:1000],
        notify_on_change=True,
    )


async def evaluate_native_alerts(
    session: AsyncSession,
    target_id: str,
    target_name: str,
    events: list[NativeAlertEvent],
    *,
    complete: bool,
) -> None:
    policy = await policy_for_target(session, target_id)
    if not policy.native_alerts_enabled:
        return
    seen: set[str] = set()
    for event in events:
        seen.add(event.external_event_id)
        await _set_incident(
            session,
            target_id=target_id,
            policy=policy,
            subject_id=event.external_event_id,
            subject_type="native_alert",
            rule_key="target.native_alert",
            window_key=event.rule_id,
            firing=event.status == "firing",
            severity=event.severity,
            title=f"[{target_name}] {event.title}"[:300],
            message=event.description or "Sub2API reported a native operational alert",
        )
    if not complete:
        return
    active = list(
        await session.scalars(
            select(Incident).where(
                Incident.target_id == target_id,
                Incident.policy_id == policy.id,
                Incident.subject_type == "native_alert",
                Incident.rule_key == "target.native_alert",
                Incident.status != IncidentStatus.RESOLVED.value,
            )
        )
    )
    for incident in active:
        if incident.subject_id in seen:
            continue
        await _set_incident(
            session,
            target_id=target_id,
            policy=policy,
            subject_id=incident.subject_id,
            subject_type=incident.subject_type,
            rule_key=incident.rule_key,
            window_key=incident.window_key,
            firing=False,
            severity=incident.severity,
            title=incident.title,
            message="Native Sub2API alert resolved",
        )
