from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.api import router as router_module
from app.api.router import create_policy, delete_target_route, update_policy_route
from app.models import (
    AccountCurrent,
    AuditEvent,
    ChannelMonitorCurrent,
    Incident,
    IncidentTransition,
    NotificationChannel,
    NotificationOutbox,
    Policy,
    QuotaSample,
    Target,
    User,
)
from app.schemas import PolicyCreate
from app.services import policies as policies_module
from app.services.policies import (
    evaluate_account,
    evaluate_channel,
    evaluate_ttft,
    evaluate_upstream_rate_change,
    incident_fingerprint,
    policy_for_target,
    resolve_channel_monitor_incidents,
)


class _LockOrderSession:
    def __init__(self, session) -> None:
        self._session = session
        self.events: list[str] = []
        self.lock_statements: list[object] = []

    def _record_lock(self, statement) -> None:
        lock_options = getattr(statement, "_for_update_arg", None)
        if lock_options is None:
            return
        descriptions = getattr(statement, "column_descriptions", [])
        entity = descriptions[0].get("entity") if descriptions else None
        if entity in {Target, Policy}:
            self.lock_statements.append(statement)
            mode = (
                ":no_key_update"
                if entity is Target and lock_options.key_share and not lock_options.read
                else ""
            )
            self.events.append(f"lock:{entity.__name__}{mode}")

    async def scalar(self, statement, *args, **kwargs):
        self._record_lock(statement)
        return await self._session.scalar(statement, *args, **kwargs)

    async def scalars(self, statement, *args, **kwargs):
        self._record_lock(statement)
        return await self._session.scalars(statement, *args, **kwargs)

    async def delete(self, instance) -> None:
        self.events.append(f"delete:{type(instance).__name__}")
        await self._session.delete(instance)

    def __getattr__(self, name: str):
        return getattr(self._session, name)


async def test_incident_fingerprint_is_target_isolated() -> None:
    first = incident_fingerprint("target-a", "policy", "account", "1", "quota.low", "5h")
    second = incident_fingerprint("target-b", "policy", "account", "1", "quota.low", "5h")
    assert first != second


async def test_policy_update_locks_target_before_policy(db_session) -> None:
    target = Target(
        id="target-policy-lock-order",
        name="Prod",
        base_url="https://example.com",
    )
    policy = Policy(
        id="policy-lock-order",
        target_id=target.id,
        name="TTFT",
    )
    user = User(username="admin", password_hash="unused")
    db_session.add_all([target, policy])
    await db_session.commit()
    recording_session = _LockOrderSession(db_session)

    await update_policy_route(
        policy.id,
        PolicyCreate(name="TTFT updated", target_id=target.id),
        user,
        recording_session,  # type: ignore[arg-type]
    )

    assert recording_session.events[:2] == [
        "lock:Target:no_key_update",
        "lock:Policy",
    ]


async def test_policy_lookup_takes_no_key_update_target_lifecycle_lock(db_session) -> None:
    target = Target(
        id="target-policy-lookup-lock",
        name="Prod",
        base_url="https://example.com",
    )
    policy = Policy(
        id="policy-lookup-lock",
        target_id=target.id,
        name="TTFT",
    )
    db_session.add_all([target, policy])
    await db_session.commit()
    recording_session = _LockOrderSession(db_session)

    selected = await policy_for_target(
        recording_session,  # type: ignore[arg-type]
        target.id,
    )

    assert selected is not None
    assert selected.id == policy.id
    assert recording_session.events == ["lock:Target:no_key_update"]
    compiled = str(
        recording_session.lock_statements[0].compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert compiled.endswith("ORDER BY targets.id FOR NO KEY UPDATE")


async def test_policy_update_recomputes_target_locks_after_concurrent_rebind(
    db_session, monkeypatch
) -> None:
    targets = [
        Target(
            id=f"target-policy-rebind-{suffix}",
            name=suffix,
            base_url=f"https://{suffix}.test",
        )
        for suffix in ("a", "b", "c")
    ]
    policy = Policy(
        id="policy-concurrent-rebind",
        target_id=targets[0].id,
        name="TTFT",
    )
    user = User(
        id="user-policy-concurrent-rebind",
        username="admin",
        password_hash="unused",
    )
    db_session.add_all([*targets, policy, user])
    await db_session.commit()
    target_ids = [target.id for target in targets]
    policy_id = policy.id
    lock_sets: list[set[str]] = []

    async def rebind_during_first_lock(session, requested_ids) -> set[str]:
        requested = set(requested_ids)
        lock_sets.append(requested)
        if len(lock_sets) == 1:
            await session.execute(
                update(Policy)
                .where(Policy.id == policy_id)
                .values(target_id=target_ids[2])
                .execution_options(synchronize_session=False)
            )
            await session.commit()
        return requested

    monkeypatch.setattr(
        router_module,
        "lock_ttft_target_rows",
        rebind_during_first_lock,
    )

    updated = await update_policy_route(
        policy_id,
        PolicyCreate(name="TTFT updated", target_id=target_ids[1]),
        user,
        db_session,
    )

    assert updated.target_id == target_ids[1]
    assert lock_sets == [
        {target_ids[0], target_ids[1]},
        {target_ids[1], target_ids[2]},
    ]
    audits = list(
        await db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == "policy.update")
        )
    )
    assert len(audits) == 1
    assert audits[0].actor == "admin"


async def test_policy_evaluation_is_noop_after_target_is_deleted(db_session) -> None:
    target = Target(
        id="target-policy-deleted-noop",
        name="Deleted",
        base_url="https://deleted.test",
    )
    policy = Policy(
        id="policy-deleted-noop",
        target_id=target.id,
        name="TTFT",
    )
    db_session.add_all([target, policy])
    await db_session.commit()
    target_id = target.id
    await db_session.delete(target)
    await db_session.commit()

    assert await policy_for_target(db_session, target_id) is None
    await policies_module.evaluate_collection_health(
        db_session,
        target_id,
        "Deleted",
        "late worker failure",
    )
    await db_session.commit()

    assert await db_session.scalar(select(Incident)) is None


async def test_target_delete_locks_target_then_policy_before_delete(db_session) -> None:
    target = Target(
        id="target-delete-lock-order",
        name="Prod",
        base_url="https://example.com",
    )
    policy = Policy(
        id="policy-delete-lock-order",
        target_id=target.id,
        name="TTFT",
    )
    user = User(username="admin", password_hash="unused")
    db_session.add_all([target, policy])
    await db_session.commit()
    recording_session = _LockOrderSession(db_session)

    await delete_target_route(
        target.id,
        user,
        recording_session,  # type: ignore[arg-type]
    )

    assert recording_session.events[:3] == [
        "lock:Target",
        "lock:Policy",
        "delete:Target",
    ]


async def test_policy_creates_deduplicated_incident_and_durable_outbox(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-a", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-a", name="Default")
    channel = NotificationChannel(
        id="channel-a", name="ntfy", server_url="https://ntfy.example.com", topic="alerts"
    )
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="1",
        name="account-1",
        platform="openai",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        observed_at=now,
        last_seen_at=now,
    )
    quota = QuotaSample(
        target_id=target.id,
        external_account_id="1",
        provider="openai",
        quota_key="five_hour",
        label="5 hour quota",
        remaining_percent=4,
        utilization_percent=96,
        unit="percent",
        observed_at=now,
        source="fixture",
    )
    db_session.add_all([target, policy, channel, account, quota])
    await db_session.flush()

    await evaluate_account(db_session, target.name, account, [quota])
    await evaluate_account(db_session, target.name, account, [quota])
    await db_session.commit()

    incidents = list(await db_session.scalars(select(Incident)))
    outbox = list(await db_session.scalars(select(NotificationOutbox)))
    assert len(incidents) == 1
    assert incidents[0].severity == "critical"
    assert len(outbox) == 1
    assert outbox[0].status == "pending"


async def test_quota_incident_hysteresis_requires_recovery_threshold(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-a", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-a", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="1",
        name="account-1",
        platform="anthropic",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        observed_at=now,
        last_seen_at=now,
    )
    quota = QuotaSample(
        target_id=target.id,
        external_account_id="1",
        provider="anthropic",
        quota_key="five_hour",
        label="5 hour quota",
        remaining_percent=10,
        utilization_percent=90,
        unit="percent",
        observed_at=now,
        source="fixture",
    )
    db_session.add_all([target, policy, account, quota])
    await db_session.flush()

    await evaluate_account(db_session, target.name, account, [quota])
    quota.remaining_percent = 25
    await evaluate_account(db_session, target.name, account, [quota])
    incident = await db_session.scalar(select(Incident).where(Incident.rule_key == "quota.low"))
    assert incident is not None
    assert incident.status == "firing"

    quota.remaining_percent = 31
    await evaluate_account(db_session, target.name, account, [quota])
    assert incident.status == "resolved"


async def test_stale_quota_neither_fires_nor_resolves_incident(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-stale", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-stale", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="1",
        name="account-1",
        platform="openai",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        observed_at=now,
        last_seen_at=now,
    )
    quota = QuotaSample(
        target_id=target.id,
        external_account_id="1",
        provider="openai",
        quota_key="codex.five_hour",
        label="5 hour quota",
        remaining_percent=4,
        utilization_percent=96,
        unit="percent",
        observed_at=now,
        source="sub2api_db_passive",
        freshness="stale",
    )
    db_session.add_all([target, policy, account, quota])
    await db_session.flush()

    await evaluate_account(db_session, target.name, account, [quota])
    assert await db_session.scalar(select(Incident)) is None

    quota.freshness = "fresh"
    await evaluate_account(db_session, target.name, account, [quota])
    incident = await db_session.scalar(select(Incident).where(Incident.rule_key == "quota.low"))
    assert incident is not None and incident.status == "firing"

    quota.freshness = "stale"
    quota.remaining_percent = 100
    await evaluate_account(db_session, target.name, account, [quota])
    assert incident.status == "firing"


async def test_channel_failure_fires_once_and_recovers(db_session) -> None:
    target = Target(id="target-channel", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-channel", name="Default")
    channel = ChannelMonitorCurrent(
        target_id=target.id,
        external_monitor_id="7",
        name="Primary Codex",
        provider="openai",
        endpoint="https://upstream.example.com",
        primary_model="gpt-5.3-codex",
        primary_status="failed",
        primary_latency_ms=1200,
    )
    db_session.add_all([target, policy, channel])
    await db_session.flush()

    await evaluate_channel(db_session, target.name, channel)
    await evaluate_channel(db_session, target.name, channel)
    incidents = list(await db_session.scalars(select(Incident)))
    assert len(incidents) == 1
    assert incidents[0].subject_type == "channel_monitor"
    assert incidents[0].status == "firing"

    channel.primary_status = "operational"
    await evaluate_channel(db_session, target.name, channel)
    assert incidents[0].status == "resolved"


async def test_paused_model_detection_resolves_channel_incidents(db_session) -> None:
    target = Target(id="target-channel-paused", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-channel-paused", name="Default")
    channel = ChannelMonitorCurrent(
        target_id=target.id,
        external_monitor_id="7",
        name="Primary Codex",
        provider="openai",
        endpoint="https://upstream.example.com",
        primary_model="gpt-5.3-codex",
        primary_status="failed",
    )
    db_session.add_all([target, policy, channel])
    await db_session.flush()

    await evaluate_channel(db_session, target.name, channel)
    incident = await db_session.scalar(select(Incident))
    assert incident is not None and incident.status == "firing"

    await resolve_channel_monitor_incidents(db_session, target.id)

    assert incident.status == "resolved"
    assert "does not indicate service recovery" in incident.message


async def test_upstream_rate_change_alerts_only_for_enabled_openai_apikey(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-rate", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-rate", name="Default")
    channel = NotificationChannel(
        id="channel-rate", name="ntfy", server_url="https://ntfy.example.com", topic="alerts"
    )
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="9",
        name="relay",
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        upstream_billing_probe_enabled=True,
        upstream_billing_probe={
            "status": "ok",
            "data": {"resolved_rate_multiplier": 0.08},
        },
        observed_at=now,
        last_seen_at=now,
    )
    db_session.add_all([target, policy, channel, account])
    await db_session.flush()

    await evaluate_upstream_rate_change(db_session, target.name, account, 0.06)
    await evaluate_upstream_rate_change(db_session, target.name, account, 0.06)
    await db_session.flush()

    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "upstream.rate_multiplier.changed")
    )
    outbox = list(await db_session.scalars(select(NotificationOutbox)))
    assert incident is not None
    assert incident.status == "firing"
    assert "x0.06 to x0.08" in incident.message
    assert len(outbox) == 1

    await evaluate_upstream_rate_change(db_session, target.name, account, 0.08)
    assert incident.status == "resolved"

    account.account_type = "oauth"
    account.upstream_billing_probe = {
        "status": "ok",
        "data": {"resolved_rate_multiplier": 0.2},
    }
    await evaluate_upstream_rate_change(db_session, target.name, account, 0.08)
    incidents = list(await db_session.scalars(select(Incident)))
    assert len(incidents) == 1


async def test_ttft_alert_uses_streaming_sample_gate_and_recovery_hysteresis(
    db_session,
) -> None:
    target = Target(id="target-ttft", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft",
        target_id=target.id,
        name="TTFT",
        ttft_min_samples=5,
        ttft_warning_ms=3000,
        ttft_critical_ms=6000,
        ttft_recovery_ms=2500,
    )
    channel = NotificationChannel(
        id="channel-ttft",
        target_id=target.id,
        name="TTFT alerts",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    db_session.add_all([target, policy, channel])
    await db_session.flush()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 4, "ttft": {"p95_ms": 7000}},
    )
    assert await db_session.scalar(select(Incident)) is None

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 3500}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None
    assert incident.severity == "warning"

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 7000}},
    )
    assert incident.severity == "critical"
    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 2700}},
    )
    assert incident.status == "firing"
    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 2000}},
    )
    assert incident.status == "resolved"
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) == 3


async def test_ttft_disabled_resolves_firing_incident_without_claiming_metric_recovery(
    db_session,
) -> None:
    target = Target(id="target-ttft-disabled", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft-disabled",
        target_id=target.id,
        name="TTFT",
        ttft_enabled=True,
    )
    db_session.add_all([target, policy])
    await db_session.flush()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None and incident.status == "firing"

    policy.ttft_enabled = False
    await evaluate_ttft(db_session, target.id, target.name, None)

    assert incident.status == "resolved"
    assert "does not indicate metric recovery" in incident.message
    transitions = list(
        await db_session.scalars(
            select(IncidentTransition)
            .where(IncidentTransition.incident_id == incident.id)
            .order_by(IncidentTransition.created_at, IncidentTransition.id)
        )
    )
    assert transitions[-1].reason == "TTFT monitoring is disabled"


async def test_policy_update_closes_ttft_incident_immediately_when_disabled(
    db_session,
) -> None:
    target = Target(id="target-ttft-api", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft-api",
        target_id=target.id,
        name="TTFT",
        ttft_enabled=True,
    )
    user = User(id="user-ttft-api", username="admin", password_hash="unused")
    db_session.add_all([target, policy, user])
    await db_session.flush()
    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None and incident.status == "firing"

    await update_policy_route(
        policy.id,
        PolicyCreate(name="TTFT", target_id=target.id, ttft_enabled=False),
        user,
        db_session,
    )

    assert incident.status == "resolved"
    transition = await db_session.scalar(
        select(IncidentTransition)
        .where(
            IncidentTransition.incident_id == incident.id,
            IncidentTransition.to_status == "resolved",
        )
        .order_by(IncidentTransition.created_at.desc(), IncidentTransition.id.desc())
    )
    assert transition is not None
    assert transition.reason == "TTFT monitoring is disabled"


async def test_stale_ttft_evaluator_does_not_reopen_after_policy_is_disabled(
    db_session,
) -> None:
    target = Target(
        id="target-ttft-stale-evaluator",
        name="Prod",
        base_url="https://example.com",
    )
    policy = Policy(
        id="policy-ttft-stale-evaluator",
        target_id=target.id,
        name="TTFT",
    )
    user = User(
        id="user-ttft-stale-evaluator",
        username="admin",
        password_hash="unused",
    )
    db_session.add_all([target, policy, user])
    await db_session.commit()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    await db_session.commit()

    stale_factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    async with stale_factory() as stale_session:
        stale_policy = await policy_for_target(stale_session, target.id)
        await stale_session.commit()
        assert stale_policy.ttft_enabled is True

        await update_policy_route(
            policy.id,
            PolicyCreate(
                name=policy.name,
                target_id=target.id,
                ttft_enabled=False,
            ),
            user,
            db_session,
        )
        assert stale_policy.ttft_enabled is True

        await evaluate_ttft(
            stale_session,
            target.id,
            target.name,
            {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
        )
        await stale_session.commit()
        assert stale_policy.ttft_enabled is False

    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None
    await db_session.refresh(incident)
    assert incident.status == "resolved"
    transitions = list(
        await db_session.scalars(
            select(IncidentTransition)
            .where(IncidentTransition.incident_id == incident.id)
            .order_by(IncidentTransition.created_at, IncidentTransition.id)
        )
    )
    assert [item.to_status for item in transitions] == ["firing", "resolved"]


async def test_policy_create_closes_only_old_effective_target_ttft_incident(
    db_session,
) -> None:
    target_a = Target(
        id="target-ttft-create-a", name="A", base_url="https://a.example.com"
    )
    target_b = Target(
        id="target-ttft-create-b", name="B", base_url="https://b.example.com"
    )
    global_policy = Policy(id="policy-ttft-create-global", name="Global")
    old_target_policy = Policy(
        id="zzzz-policy-ttft-create-a",
        target_id=target_a.id,
        name="Old A override",
    )
    user = User(id="user-ttft-create", username="admin", password_hash="unused")
    db_session.add_all(
        [target_a, target_b, global_policy, old_target_policy, user]
    )
    await db_session.flush()
    for target in (target_a, target_b):
        await evaluate_ttft(
            db_session,
            target.id,
            target.name,
            {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
        )

    new_policy = await create_policy(
        PolicyCreate(name="A override", target_id=target_a.id, ttft_enabled=False),
        user,
        db_session,
    )

    incidents = {
        incident.target_id: incident
        for incident in await db_session.scalars(
            select(Incident).where(Incident.rule_key == "response.ttft.high")
        )
    }
    assert (await policy_for_target(db_session, target_a.id)).id == new_policy.id
    assert (await policy_for_target(db_session, target_b.id)).id == global_policy.id
    assert incidents[target_a.id].policy_id == old_target_policy.id
    assert incidents[target_a.id].status == "resolved"
    assert incidents[target_b.id].status == "firing"
    transition = await db_session.scalar(
        select(IncidentTransition).where(
            IncidentTransition.incident_id == incidents[target_a.id].id,
            IncidentTransition.to_status == "resolved",
        )
    )
    assert transition is not None
    assert transition.reason == "TTFT policy superseded"


async def test_policy_enable_closes_old_effective_ttft_without_collection(
    db_session,
) -> None:
    target = Target(
        id="target-ttft-enable", name="Prod", base_url="https://example.com"
    )
    old_policy = Policy(id="policy-ttft-enable-global", name="Global")
    new_policy = Policy(
        id="policy-ttft-enable-specific",
        target_id=target.id,
        name="Override",
        enabled=False,
        ttft_enabled=False,
    )
    user = User(id="user-ttft-enable", username="admin", password_hash="unused")
    db_session.add_all([target, old_policy, new_policy, user])
    await db_session.flush()
    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None and incident.policy_id == old_policy.id

    await update_policy_route(
        new_policy.id,
        PolicyCreate(
            name="Override",
            target_id=target.id,
            enabled=True,
            ttft_enabled=False,
        ),
        user,
        db_session,
    )

    assert (await policy_for_target(db_session, target.id)).id == new_policy.id
    assert incident.status == "resolved"
    transition = await db_session.scalar(
        select(IncidentTransition).where(
            IncidentTransition.incident_id == incident.id,
            IncidentTransition.to_status == "resolved",
        )
    )
    assert transition is not None
    assert transition.reason == "TTFT policy superseded"


async def test_policy_retarget_closes_new_targets_old_effective_ttft_incident(
    db_session,
) -> None:
    target_a = Target(
        id="target-ttft-retarget-a", name="A", base_url="https://a.example.com"
    )
    target_b = Target(
        id="target-ttft-retarget-b", name="B", base_url="https://b.example.com"
    )
    global_policy = Policy(id="policy-ttft-retarget-global", name="Global")
    moving_policy = Policy(
        id="policy-ttft-retarget-moving",
        target_id=target_a.id,
        name="Moving override",
        ttft_enabled=False,
    )
    user = User(id="user-ttft-retarget", username="admin", password_hash="unused")
    db_session.add_all([target_a, target_b, global_policy, moving_policy, user])
    await db_session.flush()
    await evaluate_ttft(
        db_session,
        target_b.id,
        target_b.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None and incident.policy_id == global_policy.id

    await update_policy_route(
        moving_policy.id,
        PolicyCreate(
            name="Moving override",
            target_id=target_b.id,
            ttft_enabled=False,
        ),
        user,
        db_session,
    )

    assert (await policy_for_target(db_session, target_b.id)).id == moving_policy.id
    assert incident.status == "resolved"
    transition = await db_session.scalar(
        select(IncidentTransition).where(
            IncidentTransition.incident_id == incident.id,
            IncidentTransition.to_status == "resolved",
        )
    )
    assert transition is not None
    assert transition.reason == "TTFT policy superseded"


async def test_ttft_percentile_change_reuses_stable_incident_identity(db_session) -> None:
    target = Target(id="target-ttft-percentile", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft-percentile",
        target_id=target.id,
        name="TTFT",
        ttft_percentile="p95",
    )
    db_session.add_all([target, policy])
    await db_session.flush()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None
    original_id = incident.id
    original_fingerprint = incident.fingerprint
    assert incident.window_key == "streaming"

    policy.ttft_percentile = "p99"
    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p99_ms": 4500}},
    )

    incidents = list(
        await db_session.scalars(
            select(Incident).where(Incident.rule_key == "response.ttft.high")
        )
    )
    assert len(incidents) == 1
    assert incidents[0].id == original_id
    assert incidents[0].fingerprint == original_fingerprint
    assert incidents[0].status == "firing"
    assert "P99 time to first token" in incidents[0].message

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p99_ms": 2000}},
    )
    assert incidents[0].status == "resolved"


async def test_ttft_low_samples_and_missing_metrics_keep_existing_incident_unknown(
    db_session,
) -> None:
    target = Target(id="target-ttft-unknown", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft-unknown",
        target_id=target.id,
        name="TTFT",
        ttft_min_samples=5,
    )
    db_session.add_all([target, policy])
    await db_session.flush()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 10, "ttft": {"p95_ms": 4000}},
    )
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "response.ttft.high")
    )
    assert incident is not None and incident.status == "firing"

    for overview in (
        {"ttft_sample_count": 4, "ttft": {"p95_ms": 1000}},
        {"ttft_sample_count": 10, "ttft": {}},
        {"ttft_sample_count": 10},
        None,
    ):
        await evaluate_ttft(db_session, target.id, target.name, overview)
        assert incident.status == "firing"

    transitions = list(
        await db_session.scalars(
            select(IncidentTransition).where(IncidentTransition.incident_id == incident.id)
        )
    )
    assert [transition.to_status for transition in transitions] == ["firing"]


async def test_ttft_legacy_percentile_fingerprint_is_adopted_during_unknown_data(
    db_session,
) -> None:
    target = Target(id="target-ttft-legacy", name="Prod", base_url="https://example.com")
    policy = Policy(
        id="policy-ttft-legacy",
        target_id=target.id,
        name="TTFT",
        ttft_percentile="p99",
    )
    legacy = Incident(
        id="incident-ttft-legacy",
        target_id=target.id,
        policy_id=policy.id,
        subject_type="target",
        subject_id=target.id,
        rule_key="response.ttft.high",
        window_key="p95",
        fingerprint=incident_fingerprint(
            target.id,
            policy.id,
            "target",
            target.id,
            "response.ttft.high",
            "p95",
        ),
        status="firing",
        severity="warning",
        title="Legacy TTFT alert",
        message="Legacy P95 TTFT alert",
    )
    db_session.add_all([target, policy, legacy])
    await db_session.flush()

    await evaluate_ttft(
        db_session,
        target.id,
        target.name,
        {"ttft_sample_count": 0, "ttft": {}},
    )

    assert legacy.status == "firing"
    assert legacy.window_key == "streaming"
    assert legacy.fingerprint == incident_fingerprint(
        target.id,
        policy.id,
        "target",
        target.id,
        "response.ttft.high",
        "streaming",
    )
    assert await db_session.scalar(select(IncidentTransition)) is None
