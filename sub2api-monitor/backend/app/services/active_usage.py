from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import (
    NormalizedAccount,
    ProbeFact,
    QuotaWindow,
    active_usage_supported,
)
from app.models import ActiveQuotaAttempt, Capability, CollectionRun, QuotaSample, Target

TARGET_RATE_LIMIT_OUTCOMES = frozenset(
    {"running", "succeeded", "failed", "unsupported", "persistence_failed"}
)
ACCOUNT_RATE_LIMIT_OUTCOMES = frozenset({"running", "succeeded", "failed", "unsupported"})


class ActiveUsageConnector(Protocol):
    async def active_usage(
        self, account: NormalizedAccount
    ) -> tuple[ProbeFact, list[QuotaWindow]]: ...


async def collect_active_usage(
    session: AsyncSession,
    target: Target,
    run: CollectionRun,
    connector: ActiveUsageConnector,
    accounts: list[NormalizedAccount],
    settings: Settings,
    worker_id: str,
) -> dict[str, list[QuotaWindow]]:
    capability = await session.scalar(
        select(Capability).where(
            Capability.target_id == target.id,
            Capability.key == "quota.active_refresh",
            Capability.scope_type == "target",
            Capability.scope_id == "",
        )
    )
    if capability is None or not capability.enabled or run.trigger != "scheduled":
        return {}
    if not settings.active_quota_refresh_enabled:
        capability.runtime_state = "disabled"
        capability.reason = "global active quota refresh switch is disabled"
        capability.freshness = "missing"
        await session.commit()
        return {}

    now = datetime.now(timezone.utc)
    target_cutoff = now - timedelta(seconds=settings.active_quota_target_interval_seconds)
    recent_target_attempt = await session.scalar(
        select(func.max(ActiveQuotaAttempt.created_at)).where(
            ActiveQuotaAttempt.target_id == target.id,
            ActiveQuotaAttempt.outcome.in_(TARGET_RATE_LIMIT_OUTCOMES),
            ActiveQuotaAttempt.created_at >= target_cutoff,
        )
    )
    if recent_target_attempt is not None:
        capability.reason = "active quota refresh target rate limit is in effect"
        await session.commit()
        return {}

    supported_accounts = [account for account in accounts if active_usage_supported(account)]
    if not supported_accounts:
        capability.support_state = "unsupported"
        capability.runtime_state = "unavailable"
        capability.freshness = "missing"
        capability.reason = "no account supports active usage"
        await session.commit()
        return {}
    results: dict[str, list[QuotaWindow]] = {}
    facts: list[ProbeFact] = []
    attempted_at: list[datetime] = []
    success_at: list[datetime] = []
    error_at: list[datetime] = []

    attempt_rows = await session.execute(
        select(
            ActiveQuotaAttempt.external_account_id,
            func.max(ActiveQuotaAttempt.created_at),
        )
        .where(
            ActiveQuotaAttempt.target_id == target.id,
            ActiveQuotaAttempt.outcome.in_(ACCOUNT_RATE_LIMIT_OUTCOMES),
        )
        .group_by(ActiveQuotaAttempt.external_account_id)
    )
    last_attempts = {account_id: attempted_at for account_id, attempted_at in attempt_rows.all()}
    eligible_candidates: list[tuple[datetime | None, int, NormalizedAccount]] = []
    for index, account in enumerate(supported_accounts):
        account_cutoff = now - timedelta(seconds=settings.active_quota_account_interval_seconds)
        last_account_attempt = last_attempts.get(account.external_account_id)
        if last_account_attempt is not None and last_account_attempt.tzinfo is None:
            last_account_attempt = last_account_attempt.replace(tzinfo=timezone.utc)
        if last_account_attempt is not None and last_account_attempt >= account_cutoff:
            continue
        eligible_candidates.append((last_account_attempt, index, account))

    oldest = datetime.min.replace(tzinfo=timezone.utc)
    eligible_candidates.sort(key=lambda item: (item[0] or oldest, item[1]))
    eligible = [
        item[2] for item in eligible_candidates[: settings.active_quota_max_accounts_per_run]
    ]

    for account in eligible:
        before_observed_at = await session.scalar(
            select(func.max(QuotaSample.observed_at)).where(
                QuotaSample.target_id == target.id,
                QuotaSample.external_account_id == account.external_account_id,
            )
        )
        attempt = ActiveQuotaAttempt(
            correlation_id=str(uuid.uuid4()),
            target_id=target.id,
            run_id=run.id,
            external_account_id=account.external_account_id,
            actor=f"scheduler:{worker_id}"[:160],
            outcome="running",
            before_observed_at=before_observed_at,
        )
        session.add(attempt)
        await session.commit()
        attempt_time = datetime.now(timezone.utc)
        attempted_at.append(attempt_time)

        try:
            fact, windows = await connector.active_usage(account)
        except Exception as exc:
            finished_at = datetime.now(timezone.utc)
            attempt.outcome = "failed"
            attempt.error = _safe_error(exc)
            attempt.finished_at = finished_at
            error_at.append(finished_at)
            facts.append(ProbeFact("unknown", "unavailable", "missing", attempt.error))
            _apply_capability_summary(capability, facts, attempted_at, success_at, error_at)
            await session.commit()
            continue

        finished_at = datetime.now(timezone.utc)
        facts.append(fact)
        attempt.finished_at = finished_at
        attempt.quota_count = len(windows)
        attempt.after_observed_at = max((window.observed_at for window in windows), default=None)
        if fact.runtime_state == "healthy" and windows:
            attempt.outcome = "succeeded"
            success_at.append(finished_at)
            results[account.external_account_id] = windows
            for window in windows:
                session.add(_quota_sample(target.id, account.external_account_id, window))
        elif fact.runtime_state == "healthy":
            fact = ProbeFact(
                fact.support_state,
                "unavailable",
                "missing",
                "active usage returned no quota windows",
            )
            facts[-1] = fact
            attempt.outcome = "failed"
            attempt.error = fact.reason
            error_at.append(finished_at)
        elif fact.support_state == "unsupported":
            attempt.outcome = "unsupported"
            attempt.error = fact.reason
            error_at.append(finished_at)
        else:
            attempt.outcome = "failed"
            attempt.error = fact.reason
            error_at.append(finished_at)
        _apply_capability_summary(capability, facts, attempted_at, success_at, error_at)
        try:
            await session.commit()
        except Exception as exc:
            await session.rollback()
            persisted_attempt = await session.get(ActiveQuotaAttempt, attempt.id)
            persisted_capability = await session.get(Capability, capability.id)
            if persisted_attempt is not None:
                persisted_attempt.outcome = "persistence_failed"
                persisted_attempt.error = _safe_error(exc)
                persisted_attempt.finished_at = datetime.now(timezone.utc)
            if persisted_capability is not None:
                persisted_capability.runtime_state = "unavailable"
                persisted_capability.freshness = "stale"
                persisted_capability.reason = "active quota result persistence failed"
                persisted_capability.last_error_at = datetime.now(timezone.utc)
            await session.commit()
            results.pop(account.external_account_id, None)
            success_at.remove(finished_at)
            failure_time = datetime.now(timezone.utc)
            error_at.append(failure_time)
            facts[-1] = ProbeFact(
                "supported",
                "unavailable",
                "missing",
                "active quota result persistence failed",
            )

    if not facts:
        if capability.last_success_at is not None:
            fresh_sample = await session.scalar(
                select(QuotaSample.id).where(
                    QuotaSample.target_id == target.id,
                    QuotaSample.source.in_({"sub2api_api_active", "sub2api_api_usage_cache"}),
                    QuotaSample.freshness == "fresh",
                    QuotaSample.observed_at
                    >= now - timedelta(seconds=settings.target_quota_stale_seconds),
                )
            )
            capability.support_state = "supported"
            capability.runtime_state = "healthy"
            capability.freshness = "fresh" if fresh_sample is not None else "stale"
        capability.reason = "active quota refresh account rate limit is in effect"
        await session.commit()
        return results
    _apply_capability_summary(capability, facts, attempted_at, success_at, error_at)
    await session.commit()
    return results


def _apply_capability_summary(
    capability: Capability,
    facts: list[ProbeFact],
    attempted_at: list[datetime],
    success_at: list[datetime],
    error_at: list[datetime],
) -> None:
    capability.last_attempt_at = max(attempted_at)
    if success_at:
        capability.support_state = "supported"
        capability.runtime_state = "healthy"
        capability.freshness = (
            "fresh" if any(fact.freshness == "fresh" for fact in facts) else "stale"
        )
        capability.last_success_at = max(success_at)
        failures = len(facts) - len(success_at)
        capability.reason = (
            f"{failures} of {len(facts)} active usage calls failed" if failures else None
        )
    elif all(fact.support_state == "unsupported" for fact in facts):
        capability.support_state = "unsupported"
        capability.runtime_state = "unavailable"
        capability.freshness = "missing"
        capability.reason = "active usage is unsupported for all attempted accounts"
    else:
        capability.runtime_state = "unavailable"
        capability.freshness = "missing"
        capability.reason = "all active usage calls failed"
    if error_at:
        capability.last_error_at = max(error_at)


def _safe_error(exc: Exception) -> str:
    return (str(exc) or exc.__class__.__name__)[:500]


def _quota_sample(target_id: str, account_id: str, window: QuotaWindow) -> QuotaSample:
    return QuotaSample(
        target_id=target_id,
        external_account_id=account_id,
        provider=window.provider,
        quota_key=window.quota_key,
        label=window.label,
        utilization_percent=window.utilization_percent,
        remaining_percent=window.remaining_percent,
        used_value=window.used_value,
        limit_value=window.limit_value,
        remaining_value=window.remaining_value,
        unit=window.unit,
        reset_at=window.reset_at,
        observed_at=window.observed_at,
        source=window.source,
        freshness=window.freshness,
    )
