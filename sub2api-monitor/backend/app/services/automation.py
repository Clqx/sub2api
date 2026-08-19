from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import ConnectorError
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


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def account_state_snapshot(account: AccountCurrent) -> dict[str, Any]:
    state = {
        "target_id": account.target_id,
        "external_account_id": account.external_account_id,
        "status": account.status,
        "schedulable": account.schedulable,
        "available": account.available,
        "availability_reasons": sorted(set(account.availability_reasons)),
        "observed_at": _iso(account.observed_at),
        "source_updated_at": _iso(account.source_updated_at),
        "rate_limit_reset_at": _iso(account.rate_limit_reset_at),
        "overload_until": _iso(account.overload_until),
        "temp_unschedulable_until": _iso(account.temp_unschedulable_until),
    }
    fingerprint_state = {key: value for key, value in state.items() if key != "observed_at"}
    encoded = json.dumps(fingerprint_state, sort_keys=True, separators=(",", ":")).encode()
    return {**state, "fingerprint": hashlib.sha256(encoded).hexdigest()}


def _rule_snapshot(rule: AutomationRule) -> dict[str, Any]:
    return {
        "rule_id": rule.id,
        "target_id": rule.target_id,
        "trigger_rule_key": rule.trigger_rule_key,
        "action": rule.action,
        "reason_filters": sorted(set(rule.reason_filters)),
        "reason_match_mode": rule.reason_match_mode,
    }


def _reasons_match(rule: AutomationRule, reasons: set[str]) -> bool:
    action_reasons = ACTION_REASON_ALLOWLIST.get(rule.action)
    if not action_reasons or reasons.isdisjoint(action_reasons):
        return False
    filters = set(rule.reason_filters)
    if not filters:
        return True
    if not filters.issubset(action_reasons):
        return False
    if rule.reason_match_mode == "all":
        return filters.issubset(reasons)
    return rule.reason_match_mode == "any" and not reasons.isdisjoint(filters)


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
    rules.sort(key=lambda item: (item.target_id is None, item.id))
    matched_actions: set[str] = set()
    for rule in rules:
        if rule.action in matched_actions or not _reasons_match(rule, reasons):
            continue
        # A target-scoped rule takes precedence over a global rule for the same
        # action, preventing duplicate recommendations with competing policy.
        matched_actions.add(rule.action)
        recent = await session.scalar(
            select(func.count())
            .select_from(AutomationExecution)
            .where(
                AutomationExecution.rule_id == rule.id,
                AutomationExecution.external_account_id == account.external_account_id,
                AutomationExecution.created_at >= now - timedelta(seconds=rule.cooldown_seconds),
                AutomationExecution.status.in_(
                    ["queued", "running", "recommended", "applied", "verified"]
                ),
            )
        )
        if recent:
            continue
        # A fault transition is evidence of failure, never evidence of recovery.
        # Even execute-mode rules must be explicitly approved from this recommendation.
        execution = AutomationExecution(
            rule_id=rule.id,
            incident_id=incident.id,
            transition_id=transition.id,
            target_id=incident.target_id,
            external_account_id=account.external_account_id,
            action=rule.action,
            mode="recommend",
            status="recommended",
            idempotency_key=f"monitor-auto-{rule.id}-{transition.id}",
            result={
                "account_name": account.name,
                "availability_reasons": account.availability_reasons,
                "reason_match_mode": rule.reason_match_mode,
                "requested_mode": rule.mode,
                "rule_snapshot": _rule_snapshot(rule),
                "state_snapshot": account_state_snapshot(account),
            },
            finished_at=now,
        )
        session.add(execution)
        session.add(
            AuditEvent(
                actor="worker",
                action="automation.recommended",
                target_id=incident.target_id,
                details={
                    "rule_id": rule.id,
                    "incident_id": incident.id,
                    "account_id": account.external_account_id,
                    "action": rule.action,
                },
            )
        )


async def approve_recommendation(
    session: AsyncSession, execution: AutomationExecution, *, actor: str
) -> tuple[bool, str | None]:
    reason, terminal_status = await _execution_guard(session, execution, require_approval=False)
    if reason is not None:
        _mark_terminal(session, execution, terminal_status, reason, actor=actor)
        return False, reason
    now = datetime.now(timezone.utc)
    execution.mode = "execute"
    execution.status = "queued"
    execution.last_error = None
    execution.finished_at = None
    execution.result = {
        **execution.result,
        "approved_at": _iso(now),
        "approved_by": actor,
    }
    session.add(
        AuditEvent(
            actor=actor,
            action="automation.execution.approve",
            target_id=execution.target_id,
            details={"execution_id": execution.id, "action": execution.action},
        )
    )
    return True, None


async def _execution_guard(
    session: AsyncSession,
    execution: AutomationExecution,
    *,
    require_approval: bool,
) -> tuple[str | None, str]:
    rule = await session.get(AutomationRule, execution.rule_id) if execution.rule_id else None
    target = await session.get(Target, execution.target_id) if execution.target_id else None
    if rule is None or target is None or not rule.enabled:
        return "automation rule or target is no longer executable", "cancelled"
    if (
        rule.trigger_rule_key != "account.unavailable"
        or rule.action != execution.action
        or rule.reason_match_mode not in {"any", "all"}
        or (rule.target_id is not None and rule.target_id != execution.target_id)
    ):
        return "automation rule changed after recommendation", "cancelled"
    if execution.result.get("rule_snapshot") != _rule_snapshot(rule):
        return "automation rule changed after recommendation", "cancelled"
    if require_approval and (
        execution.mode != "execute" or not execution.result.get("approved_at")
    ):
        return "automation execution has not been manually approved", "cancelled"
    incident = await session.get(Incident, execution.incident_id) if execution.incident_id else None
    if (
        incident is None
        or incident.status
        not in {IncidentStatus.FIRING.value, IncidentStatus.ACKNOWLEDGED.value}
        or incident.rule_key != "account.unavailable"
        or incident.subject_type != "account"
        or incident.target_id != execution.target_id
        or incident.subject_id != execution.external_account_id
    ):
        return "incident is no longer the firing account fault", "skipped_stale"
    account = await session.scalar(
        select(AccountCurrent).where(
            AccountCurrent.target_id == execution.target_id,
            AccountCurrent.external_account_id == execution.external_account_id,
        )
    )
    snapshot = execution.result.get("state_snapshot")
    if account is None or not isinstance(snapshot, dict):
        return "account state snapshot is missing", "skipped_stale"
    if not snapshot.get("source_updated_at"):
        return "upstream account version is unavailable", "skipped_unverifiable"
    if account_state_snapshot(account).get("fingerprint") != snapshot.get("fingerprint"):
        return "account state changed after recommendation", "skipped_stale"
    if account.available or not _reasons_match(rule, set(account.availability_reasons)):
        return "account fault no longer matches the automation rule", "skipped_stale"
    return None, ""


def _mark_terminal(
    session: AsyncSession,
    execution: AutomationExecution,
    status: str,
    reason: str,
    *,
    actor: str = "worker",
) -> None:
    execution.status = status
    execution.last_error = reason
    execution.finished_at = datetime.now(timezone.utc)
    session.add(
        AuditEvent(
            actor=actor,
            action=f"automation.{status}",
            target_id=execution.target_id,
            details={
                "execution_id": execution.id,
                "rule_id": execution.rule_id,
                "account_id": execution.external_account_id,
                "action": execution.action,
                "error": reason,
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
    finalized = await verify_applied_automations(
        session,
        timeout_seconds=settings.automation_verification_timeout_seconds,
    )
    if finalized:
        await session.commit()
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
        reason, terminal_status = await _execution_guard(
            session, execution, require_approval=True
        )
        if reason is not None:
            _mark_terminal(session, execution, terminal_status, reason)
            continue
        target = await session.get(Target, execution.target_id)
        if target is None:  # Guarded above; keeps the type checker honest.
            _mark_terminal(session, execution, "cancelled", "target no longer exists")
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
                    expected_state=execution.result["state_snapshot"],
                )
            applied_at = datetime.now(timezone.utc)
            execution.status = "applied"
            execution.result = {**execution.result, **result, "applied_at": _iso(applied_at)}
            execution.last_error = None
            completed += 1
            active = await session.scalar(
                select(func.count())
                .select_from(CollectionRun)
                .where(
                    CollectionRun.target_id == target.id,
                    CollectionRun.status.in_([RunStatus.QUEUED.value, RunStatus.RUNNING.value]),
                )
            )
            if not active:
                session.add(CollectionRun(target_id=target.id, trigger="automation_verify"))
        except ConnectorError as exc:
            execution.status = (
                "skipped_stale"
                if exc.status_code == 409 and exc.reason == "ACCOUNT_STATE_CHANGED"
                else "failed"
            )
            execution.last_error = _safe_error(exc)
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


async def verify_applied_automations(
    session: AsyncSession,
    target_id: str | None = None,
    *,
    timeout_seconds: int = 300,
) -> int:
    query = select(AutomationExecution).where(AutomationExecution.status == "applied")
    if target_id is not None:
        query = query.where(AutomationExecution.target_id == target_id)
    executions = list(await session.scalars(query.with_for_update(skip_locked=True)))
    finalized = 0
    now = datetime.now(timezone.utc)
    for execution in executions:
        account = await session.scalar(
            select(AccountCurrent).where(
                AccountCurrent.target_id == execution.target_id,
                AccountCurrent.external_account_id == execution.external_account_id,
            )
        )
        applied_at = execution.result.get("applied_at")
        if not isinstance(applied_at, str):
            _mark_terminal(
                session,
                execution,
                "verification_failed",
                "automation result has no valid applied_at timestamp",
            )
            finalized += 1
            continue
        try:
            applied_time = datetime.fromisoformat(applied_at)
        except (TypeError, ValueError):
            _mark_terminal(
                session,
                execution,
                "verification_failed",
                "automation result has no valid applied_at timestamp",
            )
            finalized += 1
            continue
        if applied_time.tzinfo is None:
            applied_time = applied_time.replace(tzinfo=timezone.utc)
        else:
            applied_time = applied_time.astimezone(timezone.utc)
        verification_expired = now >= applied_time + timedelta(seconds=timeout_seconds)
        if account is None:
            if verification_expired:
                _mark_terminal(
                    session,
                    execution,
                    "verification_failed",
                    "account was absent throughout the recovery verification window",
                )
                finalized += 1
            continue
        observed_at = account.observed_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        if observed_at <= applied_time:
            if verification_expired:
                _mark_terminal(
                    session,
                    execution,
                    "verification_failed",
                    "no fresh account observation arrived within the recovery verification window",
                )
                finalized += 1
            continue
        status = "verified" if account.available else "verification_failed"
        execution.status = status
        execution.finished_at = datetime.now(timezone.utc)
        execution.last_error = (
            None
            if status == "verified"
            else "account remained unavailable after recovery verification"
        )
        session.add(
            AuditEvent(
                actor="worker",
                action=f"automation.{status}",
                target_id=execution.target_id,
                details={
                    "execution_id": execution.id,
                    "account_id": execution.external_account_id,
                    "action": execution.action,
                    "availability_reasons": account.availability_reasons,
                },
            )
        )
        finalized += 1
    return finalized


def _safe_error(exc: Exception) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ").strip()
    return (text or exc.__class__.__name__)[:500]
