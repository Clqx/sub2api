from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.models import (
    AccountCurrent,
    ChannelMonitorCurrent,
    Incident,
    NotificationChannel,
    NotificationOutbox,
    Policy,
    QuotaSample,
    Target,
)
from app.services.policies import (
    evaluate_account,
    evaluate_channel,
    evaluate_upstream_rate_change,
    incident_fingerprint,
)


async def test_incident_fingerprint_is_target_isolated() -> None:
    first = incident_fingerprint("target-a", "policy", "account", "1", "quota.low", "5h")
    second = incident_fingerprint("target-b", "policy", "account", "1", "quota.low", "5h")
    assert first != second


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
