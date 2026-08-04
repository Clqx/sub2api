from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select

from app.config import Settings
from app.connectors.sub2api import NormalizedAccount, ProbeFact, QuotaWindow
from app.models import (
    ActiveQuotaAttempt,
    AuditEvent,
    Capability,
    CollectionRun,
    QuotaSample,
    Target,
)
from app.schemas import ActiveRefreshCapabilityUpdate
from app.services.active_usage import collect_active_usage
from app.services.targets import set_active_refresh_enabled


class FixtureActiveConnector:
    def __init__(
        self, *, fail_ids: set[str] | None = None, empty_ids: set[str] | None = None
    ) -> None:
        self.fail_ids = fail_ids or set()
        self.empty_ids = empty_ids or set()
        self.calls: list[str] = []

    async def active_usage(self, account: NormalizedAccount) -> tuple[ProbeFact, list[QuotaWindow]]:
        self.calls.append(account.external_account_id)
        if account.external_account_id in self.fail_ids:
            raise RuntimeError("upstream active usage failed")
        if account.external_account_id in self.empty_ids:
            return ProbeFact("supported", "healthy", "fresh"), []
        now = datetime.now(timezone.utc)
        return ProbeFact("supported", "healthy", "fresh"), [
            QuotaWindow(
                provider=account.platform,
                quota_key="five_hour",
                label="5 hour quota",
                utilization_percent=75,
                remaining_percent=25,
                reset_at=now + timedelta(hours=1),
                observed_at=now,
                source="sub2api_api_active",
            )
        ]


def account(account_id: str, *, account_type: str = "oauth") -> NormalizedAccount:
    now = datetime.now(timezone.utc)
    return NormalizedAccount(
        external_account_id=account_id,
        name=f"account-{account_id}",
        platform="openai",
        account_type=account_type,
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


async def active_fixture(db_session, *, capability_enabled: bool = True):
    target = Target(id="active-target", name="Active", base_url="https://example.com")
    run = CollectionRun(id="active-run", target_id=target.id, trigger="scheduled")
    capability = Capability(
        target_id=target.id,
        key="quota.active_refresh",
        enabled=capability_enabled,
        side_effect="upstream_call_and_possible_target_write",
        runtime_state="unavailable" if capability_enabled else "disabled",
    )
    db_session.add_all([target, run, capability])
    await db_session.commit()
    return target, run, capability


async def test_active_collection_requires_global_and_target_opt_in(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, capability = await active_fixture(db_session, capability_enabled=False)
    connector = FixtureActiveConnector()
    enabled_settings = Settings(**settings_dict, active_quota_refresh_enabled=True)

    assert (
        await collect_active_usage(
            db_session, target, run, connector, [account("1")], enabled_settings, "worker"
        )
        == {}
    )
    capability.enabled = True
    await db_session.commit()
    disabled_settings = Settings(**settings_dict, active_quota_refresh_enabled=False)
    assert (
        await collect_active_usage(
            db_session, target, run, connector, [account("1")], disabled_settings, "worker"
        )
        == {}
    )
    assert connector.calls == []
    assert capability.runtime_state == "disabled"
    assert list(await db_session.scalars(select(ActiveQuotaAttempt))) == []


async def test_active_collection_never_runs_for_manual_collection(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, _ = await active_fixture(db_session)
    run.trigger = "manual"
    await db_session.commit()
    connector = FixtureActiveConnector()

    results = await collect_active_usage(
        db_session,
        target,
        run,
        connector,
        [account("1")],
        Settings(**settings_dict, active_quota_refresh_enabled=True),
        "worker",
    )

    assert results == {}
    assert connector.calls == []
    assert list(await db_session.scalars(select(ActiveQuotaAttempt))) == []


async def test_active_collection_is_persistently_rate_limited(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, capability = await active_fixture(db_session)
    connector = FixtureActiveConnector()
    settings = Settings(**settings_dict, active_quota_refresh_enabled=True)

    first = await collect_active_usage(
        db_session, target, run, connector, [account("1")], settings, "worker"
    )
    second = await collect_active_usage(
        db_session, target, run, connector, [account("1")], settings, "worker"
    )

    attempts = list(await db_session.scalars(select(ActiveQuotaAttempt)))
    assert list(first) == ["1"]
    assert second == {}
    assert connector.calls == ["1"]
    assert len(attempts) == 1
    assert attempts[0].outcome == "succeeded"
    assert attempts[0].correlation_id
    assert attempts[0].actor == "scheduler:worker"
    assert capability.last_success_at is not None

    attempts[0].created_at = datetime.now(timezone.utc) - timedelta(minutes=6)
    capability.runtime_state = "unavailable"
    capability.freshness = "missing"
    db_session.add(
        QuotaSample(
            target_id=target.id,
            external_account_id="1",
            provider="openai",
            quota_key="codex.five_hour",
            label="Codex 5 hour quota",
            remaining_percent=25,
            unit="percent",
            observed_at=datetime.now(timezone.utc),
            source="sub2api_api_active",
            freshness="fresh",
        )
    )
    await db_session.commit()
    third = await collect_active_usage(
        db_session, target, run, connector, [account("1")], settings, "worker"
    )
    assert third == {}
    assert connector.calls == ["1"]
    assert capability.support_state == "supported"
    assert capability.runtime_state == "healthy"
    assert capability.freshness == "fresh"
    assert capability.reason == "active quota refresh account rate limit is in effect"


async def test_active_collection_rotates_past_accounts_in_cooldown(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, _ = await active_fixture(db_session)
    connector = FixtureActiveConnector()
    settings = Settings(
        **settings_dict,
        active_quota_refresh_enabled=True,
        active_quota_max_accounts_per_run=2,
    )
    accounts = [account("1"), account("2"), account("3")]

    await collect_active_usage(db_session, target, run, connector, accounts, settings, "worker")
    attempts = list(await db_session.scalars(select(ActiveQuotaAttempt)))
    for attempt in attempts:
        attempt.created_at = datetime.now(timezone.utc) - timedelta(minutes=16)
    await db_session.commit()

    await collect_active_usage(db_session, target, run, connector, accounts, settings, "worker")

    assert connector.calls == ["1", "2", "3", "1"]
    third_attempt = await db_session.scalar(
        select(ActiveQuotaAttempt).where(ActiveQuotaAttempt.external_account_id == "3")
    )
    assert third_attempt is not None
    assert third_attempt.outcome == "succeeded"


async def test_active_collection_uses_bounded_attempt_queries_for_large_pool(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, _ = await active_fixture(db_session)
    connector = FixtureActiveConnector()
    statements: list[str] = []

    def record_statement(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.lstrip().lower().startswith("select") and "active_quota_attempts" in statement:
            statements.append(statement)

    sync_engine = db_session.bind.sync_engine
    event.listen(sync_engine, "before_cursor_execute", record_statement)
    try:
        await collect_active_usage(
            db_session,
            target,
            run,
            connector,
            [account(str(index)) for index in range(1, 1001)],
            Settings(
                **settings_dict,
                active_quota_refresh_enabled=True,
                active_quota_max_accounts_per_run=1,
            ),
            "worker",
        )
    finally:
        event.remove(sync_engine, "before_cursor_execute", record_statement)

    assert connector.calls == ["1"]
    assert len(statements) == 2


async def test_active_collection_isolates_partial_failure(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, capability = await active_fixture(db_session)
    connector = FixtureActiveConnector(fail_ids={"1"})
    settings = Settings(**settings_dict, active_quota_refresh_enabled=True)

    results = await collect_active_usage(
        db_session,
        target,
        run,
        connector,
        [account("1"), account("2"), account("3", account_type="apikey")],
        settings,
        "worker",
    )

    attempts = list(
        await db_session.scalars(select(ActiveQuotaAttempt).order_by(ActiveQuotaAttempt.created_at))
    )
    assert connector.calls == ["1", "2"]
    assert list(results) == ["2"]
    assert [attempt.outcome for attempt in attempts] == ["failed", "succeeded"]
    assert capability.runtime_state == "healthy"
    assert capability.reason == "1 of 2 active usage calls failed"


async def test_active_collection_does_not_mark_empty_response_successful(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, run, capability = await active_fixture(db_session)
    connector = FixtureActiveConnector(empty_ids={"1"})

    results = await collect_active_usage(
        db_session,
        target,
        run,
        connector,
        [account("1")],
        Settings(**settings_dict, active_quota_refresh_enabled=True),
        "worker",
    )

    attempt = await db_session.scalar(select(ActiveQuotaAttempt))
    samples = list(await db_session.scalars(select(QuotaSample)))
    assert results == {}
    assert attempt is not None
    assert attempt.outcome == "failed"
    assert attempt.quota_count == 0
    assert samples == []
    assert capability.runtime_state == "unavailable"
    assert capability.freshness == "missing"


async def test_active_refresh_enablement_requires_confirmation_and_audits(
    db_session, settings_dict: dict[str, object]
) -> None:
    target, _, capability = await active_fixture(db_session, capability_enabled=False)
    with pytest.raises(ValueError, match="confirm_side_effects"):
        ActiveRefreshCapabilityUpdate(enabled=True)
    with pytest.raises(ValueError, match="explicitly confirmed"):
        await set_active_refresh_enabled(
            db_session,
            target,
            enabled=True,
            confirm_side_effects=False,
            settings=Settings(**settings_dict),
            actor="admin",
        )

    updated = await set_active_refresh_enabled(
        db_session,
        target,
        enabled=True,
        confirm_side_effects=True,
        settings=Settings(**settings_dict, active_quota_refresh_enabled=True),
        actor="admin",
    )

    audit = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "capability.quota_active_refresh.update")
    )
    assert updated.id == capability.id
    assert updated.enabled is True
    assert updated.runtime_state == "unavailable"
    assert audit is not None
    assert audit.details == {
        "enabled": True,
        "side_effect": "upstream_call_and_possible_target_write",
        "global_switch_enabled": True,
    }
