from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.config import Settings
from app.connectors.postgres import (
    DatabaseAccountSnapshot,
    account_identity_fingerprint,
    account_identity_record,
)
from app.connectors.sub2api import NormalizedAccount, ProbeFact, QuotaWindow
from app.models import (
    AccountCurrent,
    AccountObservation,
    ActiveQuotaAttempt,
    Capability,
    CollectionRun,
    Incident,
    QuotaSample,
    Target,
)
from app.security import SecretCipher
from app.services import collector


class FixtureConnector:
    def __init__(self, target_id: str):
        self.target_id = target_id
        self.passive_calls = 0

    async def __aenter__(self) -> FixtureConnector:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def accounts(self) -> tuple[ProbeFact, list[NormalizedAccount]]:
        now = datetime.now(timezone.utc)
        return ProbeFact("supported", "healthy", "fresh"), [
            NormalizedAccount(
                external_account_id="shared-account-id",
                name=f"account-{self.target_id}",
                platform="anthropic",
                account_type="oauth",
                status="active",
                schedulable=True,
                available=True,
                availability_reasons=[],
                group_ids=["group-1"],
                expires_at=None,
                rate_limit_reset_at=None,
                overload_until=None,
                temp_unschedulable_until=None,
                observed_at=now,
            )
        ]

    async def passive_usage(self, _: NormalizedAccount) -> list[QuotaWindow]:
        self.passive_calls += 1
        return [
            QuotaWindow(
                provider="anthropic",
                quota_key="five_hour",
                label="5 hour quota",
                utilization_percent=90,
                remaining_percent=10,
                source="fixture_passive",
            )
        ]

    async def active_usage(self, _: NormalizedAccount) -> tuple[ProbeFact, list[QuotaWindow]]:
        raise RuntimeError("fixture active usage failure")


class SuccessfulActiveConnector(FixtureConnector):
    def __init__(self, target_id: str):
        super().__init__(target_id)
        self.active_calls = 0

    async def passive_usage(self, _: NormalizedAccount) -> list[QuotaWindow]:
        return []

    async def active_usage(self, _: NormalizedAccount) -> tuple[ProbeFact, list[QuotaWindow]]:
        self.active_calls += 1
        now = datetime.now(timezone.utc)
        return ProbeFact("supported", "healthy", "fresh"), [
            QuotaWindow(
                provider="anthropic",
                quota_key="five_hour",
                label="5 hour quota",
                utilization_percent=99,
                remaining_percent=1,
                reset_at=now + timedelta(hours=1),
                observed_at=now,
                source="sub2api_api_active",
            )
        ]


async def test_collection_isolates_targets_and_uses_only_passive_usage(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict)
    cipher = SecretCipher(settings.master_key)
    connectors: dict[str, FixtureConnector] = {}

    async def connector_for_target(_session, target, _settings, _cipher):
        connector = FixtureConnector(target.id)
        connectors[target.id] = connector
        return connector

    monkeypatch.setattr(collector, "connector_for_target", connector_for_target)
    targets = [
        Target(
            id="target-a",
            name="First",
            base_url="https://first.example.com",
            monitoring_readiness="ready",
        ),
        Target(
            id="target-b",
            name="Second",
            base_url="https://second.example.com",
            monitoring_readiness="ready",
        ),
    ]
    runs = [CollectionRun(target_id=target.id) for target in targets]
    db_session.add_all([*targets, *runs])
    await db_session.commit()

    for run in runs:
        await collector.collect_run(db_session, run, settings, cipher, "worker-test")

    accounts = list(
        await db_session.scalars(select(AccountCurrent).order_by(AccountCurrent.target_id))
    )
    observations = list(await db_session.scalars(select(AccountObservation)))
    quotas = list(await db_session.scalars(select(QuotaSample)))
    capabilities = list(await db_session.scalars(select(Capability)))
    passive_capabilities = [item for item in capabilities if item.key == "quota.passive"]
    assert [(item.target_id, item.external_account_id) for item in accounts] == [
        ("target-a", "shared-account-id"),
        ("target-b", "shared-account-id"),
    ]
    assert all(run.status == "succeeded" for run in runs)
    assert all(connector.passive_calls == 1 for connector in connectors.values())
    assert len(observations) == 2
    assert len(quotas) == 2
    assert len(passive_capabilities) == 2, [(item.target_id, item.key) for item in capabilities]
    assert all(item.support_state == "supported" for item in passive_capabilities)
    assert all(item.runtime_state == "healthy" for item in passive_capabilities)
    assert all("credentials" not in observation.payload for observation in observations)
    assert all(item.freshness == "fresh" for item in quotas)


async def test_active_failure_does_not_fail_passive_collection(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict, active_quota_refresh_enabled=True)
    cipher = SecretCipher(settings.master_key)
    target = Target(
        id="active-failure-target",
        name="Active failure",
        base_url="https://example.com",
        monitoring_readiness="ready",
    )
    run = CollectionRun(target_id=target.id, trigger="scheduled")
    active_capability = Capability(
        target_id=target.id,
        key="quota.active_refresh",
        enabled=True,
        runtime_state="unavailable",
        side_effect="upstream_call_and_possible_target_write",
    )
    db_session.add_all([target, run, active_capability])
    await db_session.commit()

    async def connector_for_target(_session, current_target, _settings, _cipher):
        return FixtureConnector(current_target.id)

    monkeypatch.setattr(collector, "connector_for_target", connector_for_target)
    await collector.collect_run(db_session, run, settings, cipher, "worker-test")

    quotas = list(await db_session.scalars(select(QuotaSample)))
    attempts = list(await db_session.scalars(select(ActiveQuotaAttempt)))
    assert run.status == "succeeded"
    assert len(quotas) == 1
    assert quotas[0].source == "fixture_passive"
    assert len(attempts) == 1
    assert attempts[0].outcome == "failed"


def test_passive_capability_reports_all_stale_windows() -> None:
    fact = collector._passive_capability_fact(
        {
            "1": [
                QuotaWindow(
                    provider="openai",
                    quota_key="codex.five_hour",
                    label="5 hour quota",
                    freshness="stale",
                )
            ]
        },
        attempted=1,
        succeeded=1,
    )
    assert fact.runtime_state == "healthy"
    assert fact.freshness == "stale"


def test_full_merge_prefers_db_state_and_newest_quota() -> None:
    now = datetime.now(timezone.utc)
    api = NormalizedAccount(
        external_account_id="42",
        name="api-name",
        platform="openai",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=["group-a"],
        expires_at=None,
        rate_limit_reset_at=None,
        overload_until=None,
        temp_unschedulable_until=None,
        observed_at=now,
        quotas=[
            QuotaWindow(
                provider="openai",
                quota_key="codex.five_hour",
                label="old",
                utilization_percent=10,
                remaining_percent=90,
                observed_at=now.replace(hour=0),
                source="api",
            )
        ],
    )
    db_quota = QuotaWindow(
        provider="openai",
        quota_key="codex.five_hour",
        label="db",
        utilization_percent=80,
        remaining_percent=20,
        observed_at=now,
        source="sub2api_db_passive",
    )
    snapshot = DatabaseAccountSnapshot(
        external_account_id="42",
        name="db-name",
        platform="openai",
        account_type="oauth",
        status="disabled",
        schedulable=False,
        expires_at=None,
        auto_pause_on_expired=True,
        rate_limit_reset_at=None,
        overload_until=None,
        temp_unschedulable_until=None,
        observed_at=now,
        quotas=[db_quota],
    )

    merged = collector.merge_database_snapshots([api], [snapshot], now)[0]

    assert merged.name == "api-name"
    assert merged.group_ids == ["group-a"]
    assert merged.status == "disabled"
    assert merged.schedulable is False
    assert merged.available is False
    assert merged.quotas[0].source == "sub2api_db_passive"


def _identity_account(account_id: str, name: str) -> NormalizedAccount:
    now = datetime.now(timezone.utc)
    return NormalizedAccount(
        external_account_id=account_id,
        name=name,
        platform="openai",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        expires_at=None,
        rate_limit_reset_at=None,
        overload_until=None,
        temp_unschedulable_until=None,
        observed_at=now,
    )


def _identity_snapshot(account_id: str, name: str) -> DatabaseAccountSnapshot:
    return DatabaseAccountSnapshot(
        external_account_id=account_id,
        name=name,
        platform="openai",
        account_type="oauth",
        status="active",
        schedulable=True,
        expires_at=None,
        auto_pause_on_expired=True,
        rate_limit_reset_at=None,
        overload_until=None,
        temp_unschedulable_until=None,
        observed_at=datetime.now(timezone.utc),
    )


class FullDatabaseConnector:
    def __init__(self, snapshots: list[DatabaseAccountSnapshot]):
        self.snapshots = snapshots

    async def accounts(self):
        return ProbeFact("supported", "healthy", "fresh"), self.snapshots, "schema-v1"


async def test_full_collection_renews_binding_after_matching_inventory_change(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict)
    now = datetime.now(timezone.utc)
    old_fingerprint = account_identity_fingerprint(
        [account_identity_record("1", "first", "openai", "oauth")]
    )
    target = Target(
        id="full-changing",
        name="FULL changing",
        base_url="https://full.example.com",
        mode="full",
        monitoring_readiness="ready",
        binding_state="verified",
        binding_api_fingerprint=old_fingerprint,
        binding_db_fingerprint=old_fingerprint,
        binding_db_schema_fingerprint="schema-v1",
        binding_checked_at=now - timedelta(hours=1),
        binding_expires_at=now - timedelta(seconds=1),
    )
    db_session.add(target)
    await db_session.commit()
    api_accounts = [_identity_account("1", "first"), _identity_account("2", "second")]
    snapshots = [_identity_snapshot("1", "first"), _identity_snapshot("2", "second")]
    monkeypatch.setattr(
        collector,
        "database_connector_for_target",
        lambda *_: FullDatabaseConnector(snapshots),
    )

    merged, _ = await collector._collect_full_accounts(
        db_session,
        target,
        ProbeFact("supported", "healthy", "fresh"),
        api_accounts,
        settings,
        SecretCipher(settings.master_key),
        now,
    )

    expected = account_identity_fingerprint(
        [
            account_identity_record("1", "first", "openai", "oauth"),
            account_identity_record("2", "second", "openai", "oauth"),
        ]
    )
    assert len(merged) == 2
    assert target.binding_api_fingerprint == expected
    assert target.binding_db_fingerprint == expected
    assert target.binding_expires_at is not None and target.binding_expires_at > now


async def test_full_collection_rejects_same_ids_from_different_instance(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict)
    now = datetime.now(timezone.utc)
    target = Target(
        id="full-mismatch",
        name="FULL mismatch",
        base_url="https://full.example.com",
        mode="full",
        monitoring_readiness="ready",
        binding_state="verified",
        binding_db_schema_fingerprint="schema-v1",
        binding_checked_at=now,
        binding_expires_at=now + timedelta(hours=1),
    )
    db_session.add(target)
    await db_session.commit()
    api_accounts = [_identity_account("1", "expected-name")]
    snapshots = [_identity_snapshot("1", "wrong-instance-name")]
    monkeypatch.setattr(
        collector,
        "database_connector_for_target",
        lambda *_: FullDatabaseConnector(snapshots),
    )

    with pytest.raises(RuntimeError, match="identity mismatch"):
        await collector._collect_full_accounts(
            db_session,
            target,
            ProbeFact("supported", "healthy", "fresh"),
            api_accounts,
            settings,
            SecretCipher(settings.master_key),
            now,
        )

    assert target.binding_state == "mismatch"
    assert target.monitoring_readiness == "not_ready"


async def test_full_binding_mismatch_blocks_active_usage(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict, active_quota_refresh_enabled=True)
    now = datetime.now(timezone.utc)
    target = Target(
        id="full-active-mismatch",
        name="FULL active mismatch",
        base_url="https://full.example.com",
        mode="full",
        monitoring_readiness="ready",
        binding_state="verified",
        binding_db_schema_fingerprint="schema-v1",
        binding_checked_at=now,
        binding_expires_at=now + timedelta(hours=1),
    )
    run = CollectionRun(target_id=target.id, trigger="scheduled")
    capability = Capability(
        target_id=target.id,
        key="quota.active_refresh",
        enabled=True,
        side_effect="upstream_call_and_possible_target_write",
    )
    db_session.add_all([target, run, capability])
    await db_session.commit()

    connector = FixtureConnector(target.id)

    async def connector_for_target(*_):
        return connector

    active_called = False

    async def active_usage(*_):
        nonlocal active_called
        active_called = True
        return {}

    monkeypatch.setattr(collector, "connector_for_target", connector_for_target)
    monkeypatch.setattr(collector, "collect_active_usage", active_usage)
    monkeypatch.setattr(
        collector,
        "database_connector_for_target",
        lambda *_: FullDatabaseConnector([_identity_snapshot("shared-account-id", "wrong")]),
    )

    await collector.collect_run(
        db_session, run, settings, SecretCipher(settings.master_key), "worker"
    )

    await db_session.refresh(run)
    assert run.status == "failed"
    assert active_called is False


async def test_active_attempt_success_always_has_a_persisted_sample(
    db_session, settings_dict, monkeypatch
) -> None:
    settings = Settings(**settings_dict, active_quota_refresh_enabled=True)
    target = Target(
        id="active-persistence",
        name="Active persistence",
        base_url="https://active.example.com",
        monitoring_readiness="ready",
    )
    run = CollectionRun(target_id=target.id, trigger="scheduled")
    capability = Capability(
        target_id=target.id,
        key="quota.active_refresh",
        enabled=True,
        side_effect="upstream_call_and_possible_target_write",
    )
    db_session.add_all([target, run, capability])
    await db_session.commit()
    connector = SuccessfulActiveConnector(target.id)

    async def connector_for_target(*_):
        return connector

    async def fail_policy_evaluation(*_):
        raise RuntimeError("forced downstream persistence failure")

    evaluate_account = collector.evaluate_account
    monkeypatch.setattr(collector, "connector_for_target", connector_for_target)
    monkeypatch.setattr(collector, "evaluate_account", fail_policy_evaluation)

    await collector.collect_run(
        db_session, run, settings, SecretCipher(settings.master_key), "worker"
    )

    await db_session.refresh(run)
    await db_session.refresh(capability)
    attempt = await db_session.scalar(
        select(ActiveQuotaAttempt).where(ActiveQuotaAttempt.run_id == run.id)
    )
    samples = list(
        await db_session.scalars(
            select(QuotaSample).where(
                QuotaSample.target_id == target.id,
                QuotaSample.source == "sub2api_api_active",
            )
        )
    )
    assert run.status == "failed"
    assert attempt is not None
    assert attempt.outcome == "succeeded"
    assert attempt.quota_count == 1
    assert len(samples) == 1
    assert capability.runtime_state == "healthy"
    assert capability.freshness == "fresh"

    attempt.created_at = datetime.now(timezone.utc) - timedelta(minutes=6)
    retry_run = CollectionRun(target_id=target.id, trigger="scheduled")
    db_session.add(retry_run)
    await db_session.commit()
    monkeypatch.setattr(collector, "evaluate_account", evaluate_account)

    await collector.collect_run(
        db_session, retry_run, settings, SecretCipher(settings.master_key), "worker"
    )

    await db_session.refresh(retry_run)
    incidents = list(
        await db_session.scalars(
            select(Incident).where(
                Incident.target_id == target.id,
                Incident.rule_key == "quota.low",
            )
        )
    )
    assert retry_run.status == "succeeded"
    assert connector.active_calls == 1
    assert len(incidents) == 1
