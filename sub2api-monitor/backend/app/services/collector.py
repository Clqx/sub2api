from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.postgres import (
    DatabaseAccountSnapshot,
    account_identity_fingerprint,
    account_identity_record,
)
from app.connectors.sub2api import NormalizedAccount, ProbeFact, QuotaWindow, normalize_account
from app.models import (
    AccountCurrent,
    AccountObservation,
    CollectionRun,
    QuotaSample,
    RunStatus,
    Target,
)
from app.security import SecretCipher
from app.services.active_usage import collect_active_usage
from app.services.monitoring import sync_channel_monitors
from app.services.policies import (
    evaluate_account,
    evaluate_channel,
    evaluate_upstream_rate_change,
    upstream_rate_multiplier,
)
from app.services.targets import (
    apply_probe_fact,
    connector_for_target,
    database_connector_for_target,
    target_with_secret,
)


async def collect_run(
    session: AsyncSession,
    run: CollectionRun,
    settings: Settings,
    cipher: SecretCipher,
    worker_id: str,
) -> None:
    run_id = run.id
    run.status = RunStatus.RUNNING.value
    run.worker_id = worker_id
    run.started_at = datetime.now(timezone.utc)
    await session.commit()
    target = await target_with_secret(session, run.target_id)
    if target is None:
        await _fail_run(session, run, "target no longer exists")
        return
    if target.monitoring_readiness != "ready":
        await _fail_run(session, run, "target is not ready; probe it first")
        return
    try:
        connector = await connector_for_target(session, target, settings, cipher)
        async with connector:
            accounts_fact, accounts = await connector.accounts()
            now = datetime.now(timezone.utc)
            await apply_probe_fact(session, target.id, "accounts.inventory", accounts_fact, now)
            await apply_probe_fact(session, target.id, "accounts.availability", accounts_fact, now)
            passive_results: dict[str, list[QuotaWindow]] = {}
            passive_attempted = 0
            passive_succeeded = 0
            active_results: dict[str, list[QuotaWindow]] = {}
            try:
                billing_fact, _ = await connector.upstream_billing_probe_settings()
            except Exception as exc:
                billing_fact = ProbeFact("unknown", "unavailable", "missing", _safe_error(exc))
            try:
                channel_fact, channel_monitors = await connector.channel_monitors()
            except Exception as exc:
                channel_fact = ProbeFact("unknown", "unavailable", "missing", _safe_error(exc))
                channel_monitors = []
            if accounts_fact.runtime_state == "healthy":
                (
                    passive_results,
                    passive_attempted,
                    passive_succeeded,
                ) = await _collect_passive_usage(connector, accounts)
            if target.mode == "full":
                accounts, database_quotas = await _collect_full_accounts(
                    session,
                    target,
                    accounts_fact,
                    accounts,
                    settings,
                    cipher,
                    now,
                )
                for account_id, windows in database_quotas.items():
                    passive_results.setdefault(account_id, []).extend(windows)
                if database_quotas:
                    passive_attempted += len(accounts)
                    passive_succeeded += len(database_quotas)
            elif accounts_fact.runtime_state != "healthy":
                raise RuntimeError(accounts_fact.reason or "account inventory unavailable")
            if accounts_fact.runtime_state == "healthy":
                await collect_active_usage(
                    session,
                    target,
                    run,
                    connector,
                    accounts,
                    settings,
                    worker_id,
                )
                active_results = await _latest_persisted_active_usage(
                    session, target.id, accounts, settings, now
                )
        await apply_probe_fact(
            session, target.id, "accounts.upstream_billing_probe", billing_fact, now
        )
        await apply_probe_fact(session, target.id, "channels.monitor", channel_fact, now)
        if channel_fact.runtime_state == "healthy":
            stored_channels, removed_channels = await sync_channel_monitors(
                session, target, channel_monitors, observed_at=now
            )
            for channel in stored_channels:
                await evaluate_channel(session, target.name, channel)
            for channel in removed_channels:
                channel.enabled = False
                await evaluate_channel(session, target.name, channel)
                await session.delete(channel)
        passive_fact = _passive_capability_fact(
            passive_results, passive_attempted, passive_succeeded
        )
        passive_capability = await apply_probe_fact(
            session, target.id, "quota.passive", passive_fact, now
        )
        session.add(passive_capability)
        await session.flush()
        batch_id = str(uuid.uuid4())
        seen_ids: set[str] = set()
        quota_count = 0
        for sequence, account in enumerate(accounts):
            seen_ids.add(account.external_account_id)
            account.quotas = _newest_quotas(
                [
                    *account.quotas,
                    *passive_results.get(account.external_account_id, []),
                    *active_results.get(account.external_account_id, []),
                ]
            )
            current, quotas, previous_upstream_multiplier = await _store_account(
                session,
                target,
                run,
                account,
                batch_id,
                sequence,
                settings.producer_id,
                {
                    (window.quota_key, window.observed_at, window.source)
                    for window in active_results.get(account.external_account_id, [])
                },
            )
            quota_count += len(quotas)
            await evaluate_account(session, target.name, current, quotas)
            await evaluate_upstream_rate_change(
                session,
                target.name,
                current,
                previous_upstream_multiplier,
            )
        previous = list(
            await session.scalars(
                select(AccountCurrent).where(AccountCurrent.target_id == target.id)
            )
        )
        for item in previous:
            if item.external_account_id not in seen_ids:
                item.available = False
                item.availability_reasons = ["missing_from_inventory"]
                await evaluate_account(session, target.name, item, [])
        target.last_collected_at = now
        target.next_collection_at = now + timedelta(seconds=target.collection_interval_seconds)
        target.last_error = None
        run.status = RunStatus.SUCCEEDED.value
        run.account_count = len(accounts)
        run.quota_count = quota_count
        run.finished_at = datetime.now(timezone.utc)
        await session.commit()
    except Exception as exc:
        await session.rollback()
        failed_run = await session.get(CollectionRun, run_id)
        target = await session.get(Target, failed_run.target_id) if failed_run else None
        if target:
            safe_error = _safe_error(exc)
            target.last_error = safe_error
            if "identity" in safe_error:
                target.binding_state = (
                    "mismatch" if "mismatch" in safe_error or "changed" in safe_error else "pending"
                )
                target.monitoring_readiness = "not_ready"
            target.next_collection_at = datetime.now(timezone.utc) + timedelta(
                seconds=max(target.collection_interval_seconds, 60)
            )
        if failed_run:
            failed_run.status = RunStatus.FAILED.value
            failed_run.error = _safe_error(exc)
            failed_run.finished_at = datetime.now(timezone.utc)
        await session.commit()


async def _collect_full_accounts(
    session: AsyncSession,
    target: Target,
    api_fact: ProbeFact,
    api_accounts: list[NormalizedAccount],
    settings: Settings,
    cipher: SecretCipher,
    now: datetime,
) -> tuple[list[NormalizedAccount], dict[str, list[QuotaWindow]]]:
    if target.binding_state != "verified":
        target.monitoring_readiness = "not_ready"
        raise RuntimeError("API/database identity binding is not verified")
    database_connector = database_connector_for_target(target, settings, cipher)
    database_fact, snapshots, schema_fingerprint = await database_connector.accounts()
    await apply_probe_fact(
        session,
        target.id,
        "database.inventory",
        database_fact,
        now,
        source="database",
    )
    target.db_connection_state = (
        "connected" if database_fact.runtime_state == "healthy" else database_fact.runtime_state
    )
    if database_fact.runtime_state != "healthy":
        raise RuntimeError(database_fact.reason or "target database inventory unavailable")

    db_fingerprint = account_identity_fingerprint(
        [
            account_identity_record(
                snapshot.external_account_id,
                snapshot.name,
                snapshot.platform,
                snapshot.account_type,
            )
            for snapshot in snapshots
        ]
    )
    if (
        schema_fingerprint is None
        or target.binding_db_schema_fingerprint is None
        or schema_fingerprint != target.binding_db_schema_fingerprint
    ):
        target.binding_state = "mismatch"
        target.monitoring_readiness = "not_ready"
        raise RuntimeError("target database schema identity changed; reprobe required")

    if api_fact.runtime_state == "healthy":
        api_fingerprint = account_identity_fingerprint(
            [
                account_identity_record(
                    account.external_account_id,
                    account.name,
                    account.platform,
                    account.account_type,
                )
                for account in api_accounts
            ]
        )
        if api_fingerprint is None or db_fingerprint is None or api_fingerprint != db_fingerprint:
            target.binding_state = "mismatch"
            target.monitoring_readiness = "not_ready"
            raise RuntimeError("API/database account identity mismatch; collection stopped")
        target.binding_api_fingerprint = api_fingerprint
        target.binding_db_fingerprint = db_fingerprint
        target.binding_checked_at = now
        target.binding_expires_at = now + timedelta(hours=settings.target_binding_ttl_hours)
        merged = merge_database_snapshots(api_accounts, snapshots, now)
    else:
        fallback_deadline = now - timedelta(minutes=settings.target_db_fallback_minutes)
        if (
            settings.target_db_fallback_minutes == 0
            or target.binding_expires_at is None
            or _aware(target.binding_expires_at) <= now
            or target.binding_checked_at is None
            or _aware(target.binding_checked_at) < fallback_deadline
            or db_fingerprint is None
            or db_fingerprint != target.binding_db_fingerprint
        ):
            raise RuntimeError(api_fact.reason or "account inventory unavailable")
        merged = [_snapshot_fallback(snapshot, now) for snapshot in snapshots]
        target.api_connection_state = "unavailable"

    return merged, {
        snapshot.external_account_id: snapshot.quotas for snapshot in snapshots if snapshot.quotas
    }


async def _latest_persisted_active_usage(
    session: AsyncSession,
    target_id: str,
    accounts: list[NormalizedAccount],
    settings: Settings,
    now: datetime,
) -> dict[str, list[QuotaWindow]]:
    account_ids = [account.external_account_id for account in accounts]
    if not account_ids:
        return {}
    samples = list(
        await session.scalars(
            select(QuotaSample)
            .where(
                QuotaSample.target_id == target_id,
                QuotaSample.external_account_id.in_(account_ids),
                QuotaSample.source.in_({"sub2api_api_active", "sub2api_api_usage_cache"}),
                QuotaSample.freshness == "fresh",
                QuotaSample.observed_at
                >= now - timedelta(seconds=settings.target_quota_stale_seconds),
            )
            .order_by(QuotaSample.observed_at.desc())
        )
    )
    results: dict[str, list[QuotaWindow]] = {}
    seen: set[tuple[str, str]] = set()
    for sample in samples:
        key = (sample.external_account_id, sample.quota_key)
        if key in seen:
            continue
        reset_at = sample.reset_at
        if reset_at is not None and reset_at.tzinfo is None:
            reset_at = reset_at.replace(tzinfo=timezone.utc)
        if reset_at is not None and reset_at <= now:
            continue
        seen.add(key)
        results.setdefault(sample.external_account_id, []).append(
            QuotaWindow(
                provider=sample.provider,
                quota_key=sample.quota_key,
                label=sample.label,
                utilization_percent=sample.utilization_percent,
                remaining_percent=sample.remaining_percent,
                used_value=sample.used_value,
                limit_value=sample.limit_value,
                remaining_value=sample.remaining_value,
                unit=sample.unit,
                reset_at=reset_at,
                observed_at=sample.observed_at,
                source=sample.source,
                freshness=sample.freshness,
            )
        )
    return results


def merge_database_snapshots(
    api_accounts: list[NormalizedAccount],
    snapshots: list[DatabaseAccountSnapshot],
    now: datetime,
) -> list[NormalizedAccount]:
    by_id = {snapshot.external_account_id: snapshot for snapshot in snapshots}
    merged: list[NormalizedAccount] = []
    for api_account in api_accounts:
        snapshot = by_id.get(api_account.external_account_id)
        if snapshot is None:
            continue
        raw = {
            "id": api_account.external_account_id,
            "name": api_account.name,
            "platform": api_account.platform,
            "type": api_account.account_type,
            "status": snapshot.status if snapshot.status is not None else api_account.status,
            "schedulable": (
                snapshot.schedulable
                if snapshot.schedulable is not None
                else api_account.schedulable
            ),
            "expires_at": snapshot.expires_at or api_account.expires_at,
            "auto_pause_on_expired": (
                snapshot.auto_pause_on_expired
                if snapshot.auto_pause_on_expired is not None
                else True
            ),
            "rate_limit_reset_at": (
                snapshot.rate_limit_reset_at or api_account.rate_limit_reset_at
            ),
            "overload_until": snapshot.overload_until or api_account.overload_until,
            "temp_unschedulable_until": (
                snapshot.temp_unschedulable_until or api_account.temp_unschedulable_until
            ),
            "group_ids": api_account.group_ids,
            "rate_multiplier": api_account.rate_multiplier,
            "extra": {
                "upstream_billing_probe_enabled": api_account.upstream_billing_probe_enabled,
                "upstream_billing_rate_sync_enabled": (
                    api_account.upstream_billing_rate_sync_enabled
                ),
                "upstream_billing_probe": api_account.upstream_billing_probe,
            },
        }
        item = normalize_account(raw, now=now)
        item.quotas = _newest_quotas([*api_account.quotas, *snapshot.quotas])
        merged.append(item)
    return merged


def _snapshot_fallback(snapshot: DatabaseAccountSnapshot, now: datetime) -> NormalizedAccount:
    item = normalize_account(
        {
            "id": snapshot.external_account_id,
            "name": snapshot.name,
            "platform": snapshot.platform,
            "type": snapshot.account_type,
            "status": snapshot.status,
            "schedulable": snapshot.schedulable,
            "expires_at": snapshot.expires_at,
            "auto_pause_on_expired": snapshot.auto_pause_on_expired,
            "rate_limit_reset_at": snapshot.rate_limit_reset_at,
            "overload_until": snapshot.overload_until,
            "temp_unschedulable_until": snapshot.temp_unschedulable_until,
        },
        now=now,
    )
    item.quotas = snapshot.quotas
    return item


def _newest_quotas(windows: list[QuotaWindow]) -> list[QuotaWindow]:
    newest: dict[str, QuotaWindow] = {}
    for window in windows:
        previous = newest.get(window.quota_key)
        fresher_state = previous is not None and (
            (window.freshness == "fresh") != (previous.freshness == "fresh")
        )
        if (
            previous is None
            or (fresher_state and window.freshness == "fresh")
            or (not fresher_state and _aware(window.observed_at) >= _aware(previous.observed_at))
        ):
            newest[window.quota_key] = window
    return list(newest.values())


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def _collect_passive_usage(
    connector: object, accounts: list[NormalizedAccount]
) -> tuple[dict[str, list[QuotaWindow]], int, int]:
    # The connector type is structural here to make fixture connectors easy to inject in tests.
    semaphore = asyncio.Semaphore(10)
    results: dict[str, list[QuotaWindow]] = {}
    attempted = 0
    succeeded = 0

    async def collect(account: NormalizedAccount) -> None:
        nonlocal attempted, succeeded
        if account.platform.lower() != "anthropic" or account.account_type not in {
            "oauth",
            "setup-token",
        }:
            return
        attempted += 1
        async with semaphore:
            try:
                windows = await connector.passive_usage(account)  # type: ignore[attr-defined]
            except Exception:
                return
            succeeded += 1
            results[account.external_account_id] = windows

    await asyncio.gather(*(collect(account) for account in accounts))
    return results, attempted, succeeded


def _passive_capability_fact(
    results: dict[str, list[QuotaWindow]], attempted: int, succeeded: int
) -> ProbeFact:
    if attempted == 0:
        return ProbeFact(
            "unknown", "unavailable", "missing", "no eligible Anthropic OAuth/SetupToken accounts"
        )
    if succeeded == 0:
        return ProbeFact("unknown", "unavailable", "missing", "all passive quota reads failed")
    if any(results.values()):
        windows = [window for account_windows in results.values() for window in account_windows]
        if any(window.freshness == "fresh" for window in windows):
            return ProbeFact("supported", "healthy", "fresh")
        return ProbeFact("supported", "healthy", "stale", "all passive quota snapshots are stale")
    return ProbeFact("unknown", "unavailable", "missing", "passive quota data is unavailable")


async def _store_account(
    session: AsyncSession,
    target: Target,
    run: CollectionRun,
    account: NormalizedAccount,
    batch_id: str,
    sequence: int,
    producer_id: str,
    persisted_quota_keys: set[tuple[str, datetime, str]] | None = None,
) -> tuple[AccountCurrent, list[QuotaSample], float | None]:
    observation = AccountObservation(
        producer_id=producer_id,
        target_id=target.id,
        run_id=run.id,
        batch_id=batch_id,
        sequence=sequence,
        external_account_id=account.external_account_id,
        observed_at=account.observed_at,
        payload=account.observation_payload(),
    )
    session.add(observation)
    await session.flush()
    current = await session.scalar(
        select(AccountCurrent).where(
            AccountCurrent.target_id == target.id,
            AccountCurrent.external_account_id == account.external_account_id,
        )
    )
    previous_upstream_multiplier = (
        upstream_rate_multiplier(current.upstream_billing_probe) if current is not None else None
    )
    if current is None:
        current = AccountCurrent(
            target_id=target.id,
            external_account_id=account.external_account_id,
            name=account.name,
            platform=account.platform,
            account_type=account.account_type,
            status=account.status,
            schedulable=account.schedulable,
            available=account.available,
            availability_reasons=account.availability_reasons,
            group_ids=account.group_ids,
            observed_at=account.observed_at,
            last_seen_at=account.observed_at,
        )
        session.add(current)
    current.name = account.name
    current.platform = account.platform
    current.account_type = account.account_type
    current.status = account.status
    current.schedulable = account.schedulable
    current.available = account.available
    current.availability_reasons = account.availability_reasons
    current.group_ids = account.group_ids
    current.expires_at = account.expires_at
    current.rate_limit_reset_at = account.rate_limit_reset_at
    current.overload_until = account.overload_until
    current.temp_unschedulable_until = account.temp_unschedulable_until
    current.rate_multiplier = account.rate_multiplier
    current.upstream_billing_probe_enabled = account.upstream_billing_probe_enabled
    current.upstream_billing_rate_sync_enabled = account.upstream_billing_rate_sync_enabled
    current.upstream_billing_probe = account.upstream_billing_probe
    current.source_observation_id = observation.id
    current.observed_at = account.observed_at
    current.last_seen_at = datetime.now(timezone.utc)
    samples: list[QuotaSample] = []
    for window in account.quotas:
        sample = QuotaSample(
            target_id=target.id,
            external_account_id=account.external_account_id,
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
            source_observation_id=observation.id,
        )
        persistence_key = (window.quota_key, window.observed_at, window.source)
        if persistence_key not in (persisted_quota_keys or set()):
            session.add(sample)
        samples.append(sample)
    await session.flush()
    return current, samples, previous_upstream_multiplier


async def _fail_run(session: AsyncSession, run: CollectionRun, error: str) -> None:
    run.status = RunStatus.FAILED.value
    run.error = error
    run.finished_at = datetime.now(timezone.utc)
    await session.commit()


def _safe_error(exc: Exception) -> str:
    # Connector exceptions intentionally contain no response bodies or credentials.
    return str(exc)[:500] or exc.__class__.__name__
