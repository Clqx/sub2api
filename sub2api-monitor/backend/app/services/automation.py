from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import (
    AccountCurrent,
    AuditEvent,
    AutomationExecution,
    AutomationRule,
    CollectionRun,
    Incident,
    IncidentStatus,
    IncidentTransition,
    RunStatus,
    Target,
)
from app.security import SecretCipher
from app.services.monitoring import target_connector

ACTION_REASON_ALLOWLIST = {
    "recover_state": {
        "status:error",
        "rate_limited",
        "overloaded",
        "temporarily_unschedulable",
    },
    "clear_error": {"status:error"},
    "clear_rate_limit": {"rate_limited"},
    "clear_temp_unschedulable": {"temporarily_unschedulable"},
    "set_schedulable": {"manually_unschedulable"},
}


async def schedule_automations(
    session: AsyncSession, incident: Incident, transition: IncidentTransition
) -> None:
    if (
        transition.to_status != IncidentStatus.FIRING.value
        or incident.subject_type != "account"
        or incident.rule_key != "account.unavailable"
    ):
        return
    account = await session.scalar(
        select(AccountCurrent).where(
            AccountCurrent.target_id == incident.target_id,
            AccountCurrent.external_account_id == incident.subject_id,
        )
    )
    if account is None:
        return
    rules = list(
        await session.scalars(
            select(AutomationRule).where(
                AutomationRule.enabled.is_(True),
                AutomationRule.trigger_rule_key == incident.rule_key,
                or_(
                    AutomationRule.target_id == incident.target_id,
                    AutomationRule.target_id.is_(None),
                ),
            )
        )
    )
    now = datetime.now(timezone.utc)
    reasons = set(account.availability_reasons)
    for rule in rules:
        if reasons.isdisjoint(ACTION_REASON_ALLOWLIST.get(rule.action, set())):
            continue
        if rule.reason_filters and reasons.isdisjoint(rule.reason_filters):
            continue
        recent = await session.scalar(
            select(func.count())
            .select_from(AutomationExecution)
            .where(
                AutomationExecution.rule_id == rule.id,
                AutomationExecution.external_account_id == account.external_account_id,
                AutomationExecution.created_at >= now - timedelta(seconds=rule.cooldown_seconds),
                AutomationExecution.status.in_(["queued", "running", "recommended", "succeeded"]),
            )
        )
        if recent:
            continue
        status = "recommended" if rule.mode == "recommend" else "queued"
        execution = AutomationExecution(
            rule_id=rule.id,
            incident_id=incident.id,
            transition_id=transition.id,
            target_id=incident.target_id,
            external_account_id=account.external_account_id,
            action=rule.action,
            mode=rule.mode,
            status=status,
            idempotency_key=f"monitor-auto-{rule.id}-{transition.id}",
            result={
                "account_name": account.name,
                "availability_reasons": account.availability_reasons,
            },
            finished_at=now if status == "recommended" else None,
        )
        session.add(execution)
        session.add(
            AuditEvent(
                actor="worker",
                action=f"automation.{status}",
                target_id=incident.target_id,
                details={
                    "rule_id": rule.id,
                    "incident_id": incident.id,
                    "account_id": account.external_account_id,
                    "action": rule.action,
                },
            )
        )


async def dispatch_automations(
    session: AsyncSession,
    settings: Settings,
    cipher: SecretCipher,
    *,
    limit: int = 10,
) -> int:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(seconds=settings.worker_stale_seconds)
    stale = list(
        await session.scalars(
            select(AutomationExecution).where(
                AutomationExecution.status == "running",
                AutomationExecution.started_at < stale_cutoff,
            )
        )
    )
    for execution in stale:
        execution.status = "queued"
        execution.last_error = "worker stopped before automation completed"
    if stale:
        await session.commit()

    rows = list(
        await session.scalars(
            select(AutomationExecution)
            .where(AutomationExecution.status == "queued")
            .order_by(AutomationExecution.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    claimed: list[tuple[AutomationExecution, Target]] = []
    for execution in rows:
        rule = (
            await session.get(AutomationRule, execution.rule_id)
            if execution.rule_id is not None
            else None
        )
        target = (
            await session.get(Target, execution.target_id)
            if execution.target_id is not None
            else None
        )
        if rule is None or target is None or not rule.enabled or execution.mode != "execute":
            execution.status = "skipped"
            execution.last_error = "automation rule or target is no longer executable"
            execution.finished_at = datetime.now(timezone.utc)
            session.add(
                AuditEvent(
                    actor="worker",
                    action="automation.skipped",
                    target_id=execution.target_id,
                    details={
                        "execution_id": execution.id,
                        "rule_id": execution.rule_id,
                        "account_id": execution.external_account_id,
                        "action": execution.action,
                        "error": execution.last_error,
                    },
                )
            )
            continue
        execution.status = "running"
        execution.started_at = datetime.now(timezone.utc)
        execution.attempts += 1
        claimed.append((execution, target))
    if rows:
        await session.commit()

    completed = 0
    for execution, target in claimed:
        try:
            _target, connector = await target_connector(session, target.id, settings, cipher)
            async with connector:
                result = await connector.execute_account_action(
                    execution.external_account_id,
                    execution.action,
                    idempotency_key=execution.idempotency_key,
                )
            execution.status = "succeeded"
            execution.result = {**execution.result, **result}
            execution.last_error = None
            completed += 1
            locked_target = await session.scalar(
                select(Target).where(Target.id == target.id).with_for_update()
            )
            if locked_target is not None:
                active = await session.scalar(
                    select(func.count())
                    .select_from(CollectionRun)
                    .where(
                        CollectionRun.target_id == target.id,
                        CollectionRun.status.in_(
                            [RunStatus.QUEUED.value, RunStatus.RUNNING.value]
                        ),
                    )
                )
                if not active:
                    session.add(
                        CollectionRun(target_id=locked_target.id, trigger="automation_verify")
                    )
        except Exception as exc:
            execution.status = "failed"
            execution.last_error = _safe_error(exc)
        execution.finished_at = datetime.now(timezone.utc)
        session.add(
            AuditEvent(
                actor="worker",
                action=f"automation.{execution.status}",
                target_id=execution.target_id,
                details={
                    "execution_id": execution.id,
                    "rule_id": execution.rule_id,
                    "account_id": execution.external_account_id,
                    "action": execution.action,
                    "attempts": execution.attempts,
                    "error": execution.last_error,
                },
            )
        )
        await session.commit()
    return completed


def _safe_error(exc: Exception) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return (text or exc.__class__.__name__)[:500]
