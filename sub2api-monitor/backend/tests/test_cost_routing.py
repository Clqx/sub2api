from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from app.api.router import update_cost_routing_policy
from app.config import Settings
from app.connectors.sub2api import ProbeFact, normalize_account
from app.models import (
    AccountCurrent,
    AuditEvent,
    ChannelMonitorCurrent,
    CostRoutingPolicy,
    Incident,
    IncidentTransition,
    NotificationChannel,
    NotificationOutbox,
    Policy,
    RoutingDecision,
    Target,
    TargetSecret,
    User,
)
from app.schemas import CostRoutingPolicyUpdate
from app.security import SecretCipher
from app.services import cost_routing
from app.services.cost_routing import (
    claim_due_cost_routing_policies,
    desired_priority,
    reconcile_unknown_routing_decisions,
    renew_cost_routing_claim,
    routing_rate_multiplier,
    run_cost_routing_policy,
)
from app.services.policies import evaluate_upstream_rate_change, upstream_rate_multiplier


def test_cost_priority_uses_absolute_multiplier_bands() -> None:
    assert (
        upstream_rate_multiplier(
            {
                "status": "ok",
                "data": {
                    "resolved_rate_multiplier": 0.2,
                    "effective_rate_multiplier": 0.8,
                },
            }
        )
        == 0.8
    )
    assert (
        desired_priority(
            0.16,
            healthy=True,
            priority_scale=1000,
            minimum_priority=1,
            unhealthy_priority=100000,
        )
        == 160
    )
    assert (
        desired_priority(
            0.8,
            healthy=True,
            priority_scale=1000,
            minimum_priority=1,
            unhealthy_priority=100000,
        )
        == 800
    )
    assert (
        desired_priority(
            0.16,
            healthy=False,
            priority_scale=1000,
            minimum_priority=1,
            unhealthy_priority=100000,
        )
        == 100000
    )


@pytest.mark.parametrize(
    ("snapshot", "configured", "expected"),
    [
        (
            {"status": "ok", "data": {"effective_rate_multiplier": 0.8}},
            0.3,
            (0.8, "upstream_probe"),
        ),
        ({"status": "unsupported"}, 0.3, (0.3, "account_config")),
        (
            {"status": "failed", "data": {"effective_rate_multiplier": 0.2}},
            0.3,
            (None, None),
        ),
        ({"status": "ok", "data": {}}, 0.3, (None, None)),
    ],
)
def test_routing_rate_multiplier_falls_back_only_for_unsupported_probe(
    snapshot: dict[str, object],
    configured: float,
    expected: tuple[float | None, str | None],
) -> None:
    assert routing_rate_multiplier(snapshot, configured) == expected


def test_enabling_cost_routing_requires_explicit_side_effect_confirmation() -> None:
    with pytest.raises(ValidationError, match="confirm_side_effects"):
        CostRoutingPolicyUpdate(enabled=True, mode="recommend")
    policy = CostRoutingPolicyUpdate(
        enabled=True,
        mode="execute",
        confirm_side_effects=True,
    )
    assert policy.probe_interval_seconds == 30


@pytest.mark.asyncio
async def test_cost_routing_claim_prevents_overlapping_workers(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(
        id="target-claim",
        name="Claim",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="claim-policy",
        target_id=target.id,
        enabled=True,
        next_run_at=now - timedelta(seconds=1),
    )
    db_session.add_all([target, policy])
    await db_session.commit()

    assert await claim_due_cost_routing_policies(db_session, owner_id="worker-a") == [policy.id]
    assert await claim_due_cost_routing_policies(db_session, owner_id="worker-b") == []
    assert not await renew_cost_routing_claim(db_session, policy.id, "worker-b")
    assert await renew_cost_routing_claim(db_session, policy.id, "worker-a")


@pytest.mark.asyncio
async def test_execute_mode_demotes_fault_and_applies_cost_increase(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-routing",
        name="Prod",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    incident_policy = Policy(id="incident-policy-routing", target_id=target.id, name="Routing")
    routing_policy = CostRoutingPolicy(
        id="routing-policy",
        target_id=target.id,
        enabled=True,
        mode="execute",
        priority_scale=1000,
        unhealthy_priority=100000,
        minimum_priority=1,
    )
    channel = NotificationChannel(
        id="routing-channel",
        target_id=target.id,
        name="routing alerts",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    cheap = _account(
        target.id,
        "1",
        "Cheap",
        priority=200,
        multiplier=0.2,
        now=now,
    )
    expensive = _account(
        target.id,
        "2",
        "Expensive",
        priority=200,
        multiplier=0.2,
        now=now,
    )
    db_session.add_all([target, secret, incident_policy, routing_policy, channel, cheap, expensive])
    await db_session.commit()

    inventory = [
        normalize_account(
            {
                "id": "1",
                "name": "Cheap",
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": False,
                "priority": 200,
            },
            now,
        ),
        normalize_account(
            {
                "id": "2",
                "name": "Expensive",
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 200,
            },
            now,
        ),
    ]
    writes: list[tuple[str, int]] = []
    expensive_multiplier = {"value": 0.8}

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def probe_upstream_billing_batch(self, account_ids: list[str]):
            assert account_ids == ["1", "2"]
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.2},
                    },
                },
                {
                    "account_id": "2",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": expensive_multiplier["value"]},
                    },
                },
            ]

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"http_status": 200, "priority": priority}

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    succeeded = await run_cost_routing_policy(
        db_session,
        routing_policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )

    assert succeeded
    assert set(writes) == {("1", 100000), ("2", 800)}
    await db_session.refresh(cheap)
    await db_session.refresh(expensive)
    await db_session.refresh(routing_policy)
    assert cheap.priority == 100000
    assert expensive.priority == 800
    assert routing_policy.last_change_count == 2
    decisions = list(
        await db_session.scalars(select(RoutingDecision).order_by(RoutingDecision.account_name))
    )
    assert [(item.reason, item.status) for item in decisions] == [
        ("unavailable", "succeeded"),
        ("cost_increase", "succeeded"),
    ]
    incident_keys = set(await db_session.scalars(select(Incident.rule_key)))
    assert "account.unavailable" in incident_keys
    assert "upstream.rate_multiplier.changed" in incident_keys
    assert "cost_routing.priority_changed" in incident_keys
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) >= 3

    expensive_multiplier["value"] = 0.1
    writes.clear()

    async def fail_after_priority_write(*_args: object) -> None:
        raise RuntimeError("post-write policy evaluation failed")

    monkeypatch.setattr(cost_routing, "evaluate_account", fail_after_priority_write)
    assert not await run_cost_routing_policy(
        db_session,
        routing_policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    assert ("2", 100) in writes
    recovery_decision = await db_session.scalar(
        select(RoutingDecision).where(RoutingDecision.reason == "cost_decrease")
    )
    assert recovery_decision is not None
    assert recovery_decision.status == "succeeded"
    recovery_outbox = list(
        await db_session.scalars(
            select(NotificationOutbox).where(
                NotificationOutbox.payload["title"].as_string()
                == "[Prod] Rate multiplier recovered"
            )
        )
    )
    assert len(recovery_outbox) == 1


@pytest.mark.asyncio
async def test_recommend_mode_chunks_probes_without_priority_writes(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-recommend",
        name="Recommend",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="recommend-policy",
        target_id=target.id,
        enabled=True,
        mode="recommend",
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    accounts = [
        _account(target.id, str(index), f"Account {index}", priority=100, multiplier=0.1, now=now)
        for index in range(1, 22)
    ]
    oauth_account = _account(
        target.id,
        "oauth-22",
        "OAuth excluded",
        priority=50,
        multiplier=0.05,
        now=now,
    )
    oauth_account.account_type = "oauth"
    old_decision = RoutingDecision(
        policy_id=policy.id,
        target_id=target.id,
        external_account_id="expired",
        account_name="Expired",
        observed_multiplier=0.1,
        previous_priority=100,
        desired_priority=100,
        reason="in_sync",
        mode="recommend",
        status="recommended",
        created_at=now - timedelta(days=31),
    )
    db_session.add_all([target, secret, policy, *accounts, oauth_account, old_decision])
    await db_session.commit()

    inventory = [
        normalize_account(
            {
                "id": account.external_account_id,
                "name": account.name,
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 100,
            },
            now,
        )
        for account in accounts
    ]
    inventory.append(
        normalize_account(
            {
                "id": "new-23",
                "name": "New account",
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 100,
            },
            now,
        )
    )
    inventory.append(
        normalize_account(
            {
                "id": oauth_account.external_account_id,
                "name": oauth_account.name,
                "platform": "openai",
                "type": "oauth",
                "status": "active",
                "schedulable": True,
                "priority": 50,
            },
            now,
        )
    )
    batches: list[list[str]] = []
    active_batches = 0
    max_active_batches = 0

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def probe_upstream_billing_batch(self, account_ids: list[str]):
            nonlocal active_batches, max_active_batches
            batches.append(account_ids)
            active_batches += 1
            max_active_batches = max(max_active_batches, active_batches)
            try:
                await asyncio.sleep(0.01)
                return [
                    {
                        "account_id": account_id,
                        "snapshot": {
                            "status": "ok",
                            "data": {"effective_rate_multiplier": 0.3},
                        },
                    }
                    for account_id in account_ids
                ]
            finally:
                active_batches -= 1

        async def set_account_priority(self, _account_id: str, _priority: int, *, control):
            raise AssertionError("recommend mode must not write account priority")

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    assert sorted(len(batch) for batch in batches) == [2, 2, 20, 20]
    assert max_active_batches == 2
    decisions = list(await db_session.scalars(select(RoutingDecision)))
    assert len(decisions) == 22
    assert {decision.status for decision in decisions} == {"recommended"}
    assert {decision.desired_priority for decision in decisions} == {300}
    new_account = await db_session.scalar(
        select(AccountCurrent).where(AccountCurrent.external_account_id == "new-23")
    )
    assert new_account is not None
    assert new_account.routing_desired_priority == 300
    await db_session.refresh(accounts[0])
    assert accounts[0].priority == 100
    assert accounts[0].routing_desired_priority == 300
    await db_session.refresh(oauth_account)
    assert oauth_account.routing_desired_priority is None
    assert await db_session.get(RoutingDecision, old_decision.id) is None


@pytest.mark.asyncio
async def test_recommend_mode_adapts_to_configured_account_multipliers(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-account-rates",
        name="Account rates",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-account-rates",
        target_id=target.id,
        enabled=True,
        mode="recommend",
        priority_scale=100,
        unhealthy_priority=10000,
        minimum_priority=1,
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    db_session.add_all([target, secret, policy])
    await db_session.commit()

    configured_rates = {"12": 0.3, "16": 0.5, "17": 0.8}

    def inventory():
        return [
            normalize_account(
                {
                    "id": account_id,
                    "name": name,
                    "platform": "openai",
                    "type": "apikey",
                    "status": "active",
                    "schedulable": True,
                    "priority": 1,
                    "rate_multiplier": configured_rates[account_id],
                },
                now,
            )
            for account_id, name in (
                ("12", "GLM"),
                ("16", "GLM (Copy)"),
                ("17", "GLM (Copy) (Copy)"),
            )
        ]

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory()

        async def probe_upstream_billing_batch(self, account_ids: list[str]):
            return [
                {
                    "account_id": account_id,
                    "snapshot": {"status": "unsupported", "last_error": "HTTP 404"},
                }
                for account_id in account_ids
            ]

        async def set_account_priority(self, _account_id: str, _priority: int, *, control):
            raise AssertionError("recommend mode must not write account priority")

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    settings = Settings(**settings_dict)
    with caplog.at_level("INFO", logger="app.services.cost_routing"):
        assert await run_cost_routing_policy(
            db_session,
            policy.id,
            settings,
            cipher,
            actor="worker:test",
        )

    first_decisions = list(
        await db_session.scalars(select(RoutingDecision).order_by(RoutingDecision.account_name))
    )
    assert [decision.observed_multiplier for decision in first_decisions] == [0.3, 0.5, 0.8]
    assert [decision.desired_priority for decision in first_decisions] == [30, 50, 80]
    assert {decision.result["cost_source"] for decision in first_decisions} == {"account_config"}
    assert "account_id=12 multiplier=0.3 cost_source=account_config" in caplog.text
    assert "account_count=3 change_count=0" in caplog.text

    configured_rates["12"] = 1.2
    with caplog.at_level("INFO", logger="app.services.cost_routing"):
        assert await run_cost_routing_policy(
            db_session,
            policy.id,
            settings,
            cipher,
            actor="worker:test",
        )

    changed = list(
        await db_session.scalars(
            select(RoutingDecision)
            .where(RoutingDecision.external_account_id == "12")
            .order_by(RoutingDecision.created_at)
        )
    )
    assert [decision.desired_priority for decision in changed] == [30, 10000]
    assert changed[-1].reason == "cost_increase"
    assert "account_id=12 multiplier=1.2 cost_source=account_config" in caplog.text


@pytest.mark.asyncio
async def test_fallback_accounts_ignore_high_multiplier_and_probe_failure(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-fallback",
        name="Fallback",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-fallback",
        target_id=target.id,
        enabled=True,
        mode="recommend",
        priority_scale=1000,
        unhealthy_priority=100000,
        minimum_priority=1,
        fallback_account_ids=["high", "probe-failed"],
        fallback_priorities={"high": 7, "probe-failed": 8},
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    db_session.add_all([target, secret, policy])
    await db_session.commit()

    inventory = [
        normalize_account(
            {
                "id": account_id,
                "name": account_id,
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 500,
                "rate_multiplier": 2,
            },
            now,
        )
        for account_id in ("high", "probe-failed")
    ]

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def probe_upstream_billing_batch(self, account_ids: list[str]):
            return [
                {
                    "account_id": account_id,
                    "snapshot": (
                        {"status": "ok", "data": {"effective_rate_multiplier": 2}}
                        if account_id == "high"
                        else {"status": "failed", "last_error": "timeout"}
                    ),
                }
                for account_id in account_ids
            ]

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )

    decisions = list(
        await db_session.scalars(select(RoutingDecision).order_by(RoutingDecision.account_name))
    )
    assert [decision.desired_priority for decision in decisions] == [7, 8]
    assert {decision.reason for decision in decisions} == {"fallback_protected"}
    assert [decision.observed_multiplier for decision in decisions] == [2, None]


@pytest.mark.asyncio
@pytest.mark.parametrize("pending_mode", [None, "recommend"])
async def test_execute_mode_guard_cancels_pending_priority_write(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    pending_mode: str | None,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id=f"target-guard-{pending_mode}",
        name="Guard",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id=f"policy-guard-{pending_mode}",
        target_id=target.id,
        enabled=True,
        mode="execute",
        lease_owner="worker-a",
    )
    account = _account(target.id, "1", "Guarded", priority=100, multiplier=0.1, now=now)
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    db_session.add_all([target, secret, policy, account])
    await db_session.commit()
    inventory = [
        normalize_account(
            {
                "id": "1",
                "name": "Guarded",
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 100,
            },
            now,
        )
    ]
    writes: list[tuple[str, int]] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.8},
                    },
                }
            ]

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"priority": priority}

    guard_calls = 0

    async def execution_guard(_policy_id: str, _owner: str | None) -> str | None:
        nonlocal guard_calls
        guard_calls += 1
        return "execute" if guard_calls == 1 else pending_mode

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
        claim_owner="worker-a",
        execution_mode_guard=execution_guard,
    )
    assert writes == []
    await db_session.refresh(account)
    assert account.priority == 100
    assert account.routing_status == "cancelled"
    decision = await db_session.scalar(select(RoutingDecision))
    assert decision is not None
    assert decision.status == "cancelled"


@pytest.mark.asyncio
async def test_retired_model_quality_binding_does_not_demote_account(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-quality",
        name="Quality",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-quality",
        target_id=target.id,
        enabled=True,
        mode="execute",
        quality_bindings={"1": ["monitor-1"]},
    )
    account = _account(target.id, "1", "Bound", priority=100, multiplier=0.1, now=now)
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    db_session.add_all([target, secret, policy, account])
    await db_session.commit()
    inventory = [
        normalize_account(
            {
                "id": "1",
                "name": "Bound",
                "extra": {
                    "monitor_cost_routing": {
                        "version": 1,
                        "unhealthy_priority": 100000,
                        "fallback": False,
                        "suppressed": False,
                    }
                },
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 100,
            },
            now,
        )
    ]
    writes: list[tuple[str, int]] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def channel_monitors(self):
            raise AssertionError("retired model quality must not be loaded")

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.1},
                    },
                }
            ]

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"priority": priority}

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    assert writes == []
    decision = await db_session.scalar(select(RoutingDecision))
    assert decision is None
    await db_session.refresh(account)
    assert account.priority == 100
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "cost_routing.priority_changed")
    )
    assert incident is None


@pytest.mark.asyncio
async def test_inventory_timeout_fails_closed_without_priority_write(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-timeout",
        name="Timeout",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-timeout",
        target_id=target.id,
        enabled=True,
        mode="execute",
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    db_session.add_all([target, secret, policy])
    await db_session.commit()
    writes: list[tuple[str, int]] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            await asyncio.sleep(0.05)
            return ProbeFact("supported", "healthy", "fresh"), []

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"priority": priority}

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    monkeypatch.setattr(cost_routing, "COST_ROUTING_INVENTORY_TIMEOUT_SECONDS", 0.01)
    assert not await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    assert writes == []
    await db_session.refresh(policy)
    assert policy.last_error == "TimeoutError"
    assert await db_session.scalar(select(RoutingDecision)) is None


@pytest.mark.asyncio
async def test_consecutive_multiplier_changes_emit_repeated_notifications(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(
        id="target-rate-notify",
        name="Notify",
        base_url="https://example.com",
    )
    policy = Policy(id="policy-rate-notify", target_id=target.id, name="Notify")
    channel = NotificationChannel(
        id="channel-rate-notify",
        target_id=target.id,
        name="Rate alerts",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    account = _account(target.id, "1", "Rate account", priority=100, multiplier=0.2, now=now)
    db_session.add_all([target, policy, channel, account])
    await db_session.commit()

    await evaluate_upstream_rate_change(db_session, target.name, account, 0.1)
    account.upstream_billing_probe = {
        "status": "ok",
        "data": {"effective_rate_multiplier": 0.3},
    }
    await evaluate_upstream_rate_change(db_session, target.name, account, 0.2)
    await db_session.commit()

    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "upstream.rate_multiplier.changed")
    )
    assert incident is not None
    transitions = list(
        await db_session.scalars(
            select(IncidentTransition).where(IncidentTransition.incident_id == incident.id)
        )
    )
    assert [transition.reason for transition in transitions] == [
        "threshold crossed",
        "condition changed",
    ]
    outbox = list(
        await db_session.scalars(
            select(NotificationOutbox).where(NotificationOutbox.incident_id == incident.id)
        )
    )
    assert len(outbox) == 2


@pytest.mark.asyncio
async def test_quality_bindings_reject_foreign_or_ineligible_references(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="binding-target", name="Binding", base_url="https://example.com")
    other = Target(id="binding-other", name="Other", base_url="https://other.example.com")
    valid = _account(target.id, "valid", "Valid", priority=100, multiplier=0.1, now=now)
    oauth = _account(target.id, "oauth", "OAuth", priority=100, multiplier=0.1, now=now)
    oauth.account_type = "oauth"
    foreign = _account(other.id, "foreign", "Foreign", priority=100, multiplier=0.1, now=now)
    valid_monitor = ChannelMonitorCurrent(
        target_id=target.id,
        external_monitor_id="valid-monitor",
        name="Valid monitor",
        provider="openai",
        endpoint="https://api.openai.com",
        observed_at=now,
    )
    wrong_provider = ChannelMonitorCurrent(
        target_id=target.id,
        external_monitor_id="wrong-provider",
        name="Wrong provider",
        provider="anthropic",
        endpoint="https://api.anthropic.com",
        observed_at=now,
    )
    foreign_monitor = ChannelMonitorCurrent(
        target_id=other.id,
        external_monitor_id="foreign-monitor",
        name="Foreign monitor",
        provider="openai",
        endpoint="https://api.openai.com",
        observed_at=now,
    )
    db_session.add_all(
        [
            target,
            other,
            valid,
            oauth,
            foreign,
            valid_monitor,
            wrong_provider,
            foreign_monitor,
        ]
    )
    await db_session.commit()
    payload = CostRoutingPolicyUpdate(
        quality_bindings={
            "valid": ["valid-monitor", "wrong-provider", "foreign-monitor"],
            "oauth": ["valid-monitor"],
            "foreign": ["valid-monitor"],
        }
    )

    with pytest.raises(HTTPException) as error:
        await update_cost_routing_policy(
            target.id,
            payload,
            User(username="admin", password_hash="unused"),
            db_session,
        )

    assert error.value.status_code == 409
    assert error.value.detail["code"] == "model_detection_paused"
    assert await db_session.scalar(select(CostRoutingPolicy)) is None

    saved = await update_cost_routing_policy(
        target.id,
        CostRoutingPolicyUpdate(fallback_account_ids=["valid"]),
        User(username="admin", password_hash="unused"),
        db_session,
    )
    assert saved.fallback_account_ids == ["valid"]
    assert saved.fallback_priorities == {"valid": 100}

    valid.priority = 900
    await db_session.commit()
    saved = await update_cost_routing_policy(
        target.id,
        CostRoutingPolicyUpdate(fallback_account_ids=["valid"]),
        User(username="admin", password_hash="unused"),
        db_session,
    )
    assert saved.fallback_priorities == {"valid": 100}


@pytest.mark.asyncio
async def test_execute_intent_survives_worker_crash_before_outcome(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-crash",
        name="Crash",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-crash",
        target_id=target.id,
        enabled=True,
        mode="execute",
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    account = _account(target.id, "1", "Crash account", priority=100, multiplier=0.1, now=now)
    db_session.add_all([target, policy, secret, account])
    await db_session.commit()
    inventory = [
        normalize_account(
            {
                "id": "1",
                "name": "Crash account",
                "platform": "openai",
                "type": "apikey",
                "status": "active",
                "schedulable": True,
                "priority": 100,
            },
            now,
        )
    ]

    class WorkerCrash(BaseException):
        pass

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), inventory

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.2},
                    },
                }
            ]

        async def set_account_priority(self, _account_id: str, _priority: int, *, control):
            raise WorkerCrash()

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    with pytest.raises(WorkerCrash):
        await run_cost_routing_policy(
            db_session,
            policy.id,
            Settings(**settings_dict),
            cipher,
            actor="worker:test",
        )

    decision = await db_session.scalar(select(RoutingDecision))
    assert decision is not None
    assert decision.status == "running"
    started = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "cost_routing.priority.started")
    )
    assert started is not None

    await cost_routing._recover_interrupted_routing_decisions(
        db_session,
        policy,
        "worker:recovery",
        target_name=target.name,
        actual_priorities={"1": 100},
    )
    await db_session.refresh(decision)
    assert decision.status == "interrupted"
    assert decision.last_error == "worker stopped before routing outcome was persisted"


@pytest.mark.asyncio
async def test_interrupted_rate_recovery_reconciles_actual_priority_and_queues_notice(
    db_session,
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-reconcile", name="Reconcile", base_url="https://example.com")
    policy = CostRoutingPolicy(
        id="policy-reconcile",
        target_id=target.id,
        enabled=True,
        mode="execute",
    )
    channel = NotificationChannel(
        id="channel-reconcile",
        target_id=target.id,
        name="Recovery alerts",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    decision = RoutingDecision(
        id="decision-reconcile",
        policy_id=policy.id,
        target_id=target.id,
        external_account_id="1",
        account_name="Recovered account",
        observed_multiplier=0.1,
        previous_priority=800,
        desired_priority=100,
        reason="cost_decrease",
        mode="execute",
        status="running",
        result={"previous_multiplier": 0.8},
        created_at=now,
    )
    db_session.add_all([target, policy, channel, decision])
    await db_session.commit()

    await cost_routing._recover_interrupted_routing_decisions(
        db_session,
        policy,
        "worker:recovery",
        target_name=target.name,
        actual_priorities={"1": 100},
    )

    await db_session.refresh(decision)
    assert decision.status == "succeeded"
    assert decision.last_error is None
    assert decision.result["reconciled_after_interruption"] is True
    outbox = await db_session.scalar(
        select(NotificationOutbox).where(
            NotificationOutbox.transition_id.is_not(None),
            NotificationOutbox.channel_id == channel.id,
        )
    )
    assert outbox is not None
    assert outbox.payload["title"] == "[Reconcile] Rate multiplier recovered"
    audit = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "cost_routing.priority.reconciled")
    )
    assert audit is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocked_state",
    ["policy_disabled", "target_disabled", "target_not_ready"],
)
async def test_applied_priority_with_lost_response_is_reconciled_and_notified(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    blocked_state: str,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-lost-response",
        name="Lost response",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-lost-response",
        target_id=target.id,
        enabled=True,
        mode="execute",
        priority_scale=1000,
        unhealthy_priority=100000,
        minimum_priority=1,
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    channel = NotificationChannel(
        id="channel-lost-response",
        target_id=target.id,
        name="Recovery alerts",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    existing_account = _account(
        target.id,
        "1",
        "Recovered account",
        priority=800,
        multiplier=0.8,
        now=now,
    )
    db_session.add_all([target, secret, policy, channel, existing_account])
    await db_session.commit()

    applied_priority = {"value": 800}
    applied_control = {"value": None}
    multiplier = {"value": 0.1}
    calls = {"accounts": 0, "probes": 0, "writes": 0}

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def accounts(self):
            calls["accounts"] += 1
            account = normalize_account(
                {
                    "id": "1",
                    "name": "Recovered account",
                    "platform": "openai",
                    "type": "apikey",
                    "status": "active",
                    "schedulable": True,
                    "priority": applied_priority["value"],
                    "extra": {"monitor_cost_routing": applied_control["value"]},
                    "rate_multiplier": multiplier["value"],
                },
                now,
            )
            return ProbeFact("supported", "healthy", "fresh"), [account]

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            calls["probes"] += 1
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": multiplier["value"]},
                    },
                }
            ]

        async def set_account_priority(self, _account_id: str, priority: int, *, control):
            calls["writes"] += 1
            applied_priority["value"] = priority
            applied_control["value"] = control
            raise TimeoutError("response lost after apply")

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )
    uncertain = await db_session.scalar(
        select(RoutingDecision).where(RoutingDecision.policy_id == policy.id)
    )
    assert uncertain is not None
    assert uncertain.status == "running"
    assert uncertain.finished_at is None
    assert uncertain.result["outcome_unknown"] is True

    if blocked_state == "policy_disabled":
        policy.enabled = False
    elif blocked_state == "target_disabled":
        target.enabled = False
    else:
        target.monitoring_readiness = "not_ready"
    await db_session.commit()
    calls.update(accounts=0, probes=0, writes=0)

    # A fresh read that has not observed the desired priority keeps the outcome
    # reconcilable instead of prematurely declaring the mutation failed.
    applied_priority["value"] = 800
    assert (
        await reconcile_unknown_routing_decisions(
            db_session,
            Settings(**settings_dict),
            cipher,
            actor="worker:reconcile",
        )
        == 0
    )
    await db_session.refresh(uncertain)
    assert uncertain.status == "running"
    assert uncertain.finished_at is None
    assert uncertain.result["reconcile_actual_priority"] == 800
    assert uncertain.result["reconcile_mismatch_attempts"] == 1
    pending_outbox = list(await db_session.scalars(select(NotificationOutbox)))
    assert all(
        item.payload.get("title") != "[Lost response] Rate multiplier recovered"
        for item in pending_outbox
    )

    assert (
        await reconcile_unknown_routing_decisions(
            db_session,
            Settings(**settings_dict),
            cipher,
            actor="worker:reconcile",
        )
        == 0
    )
    await db_session.refresh(uncertain)
    assert uncertain.status == "running"
    assert uncertain.result["reconcile_mismatch_attempts"] == 2

    applied_priority["value"] = 100
    assert (
        await reconcile_unknown_routing_decisions(
            db_session,
            Settings(**settings_dict),
            cipher,
            actor="worker:reconcile",
        )
        == 1
    )
    assert (
        await reconcile_unknown_routing_decisions(
            db_session,
            Settings(**settings_dict),
            cipher,
            actor="worker:reconcile",
        )
        == 0
    )
    await db_session.refresh(uncertain)
    assert uncertain.status == "succeeded"
    assert uncertain.result["reconciled_after_interruption"] is True
    assert calls == {"accounts": 3, "probes": 0, "writes": 0}
    recovery_outbox = [
        item
        for item in await db_session.scalars(
            select(NotificationOutbox).where(NotificationOutbox.channel_id == channel.id)
        )
        if item.payload.get("title") == "[Lost response] Rate multiplier recovered"
    ]
    assert len(recovery_outbox) == 1
    audits = list(
        await db_session.scalars(
            select(AuditEvent).where(AuditEvent.action == "cost_routing.priority.reconciled")
        )
    )
    assert len(audits) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_enabled", [True, False])
async def test_unknown_mismatch_threshold_allows_only_active_policy_to_retry(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    policy_enabled: bool,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-mismatch-limit",
        name="Mismatch limit",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-mismatch-limit",
        target_id=target.id,
        enabled=policy_enabled,
        mode="execute",
        priority_scale=1000,
        unhealthy_priority=100000,
        minimum_priority=1,
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    account = _account(
        target.id,
        "1",
        "Pending account",
        priority=800,
        multiplier=0.8,
        now=now,
    )
    decision = RoutingDecision(
        id="decision-mismatch-limit",
        policy_id=policy.id,
        target_id=target.id,
        external_account_id="1",
        account_name="Pending account",
        observed_multiplier=0.1,
        previous_priority=800,
        desired_priority=100,
        reason="cost_decrease",
        mode="execute",
        status="running",
        result={"outcome_unknown": True, "previous_multiplier": 0.8},
    )
    db_session.add_all([target, secret, policy, account, decision])
    await db_session.commit()

    inventory_mode = {"value": "error"}
    writes: list[tuple[str, int]] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def accounts(self):
            if inventory_mode["value"] == "error":
                return ProbeFact("supported", "unavailable", "missing", "temporary error"), []
            if inventory_mode["value"] == "missing":
                return ProbeFact("supported", "healthy", "fresh"), []
            return ProbeFact("supported", "healthy", "fresh"), [
                normalize_account(
                    {
                        "id": "1",
                        "name": "Pending account",
                        "platform": "openai",
                        "type": "apikey",
                        "status": "active",
                        "schedulable": True,
                        "priority": 800,
                        "rate_multiplier": 0.1,
                    },
                    now,
                )
            ]

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.1},
                    },
                }
            ]

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"priority": priority}

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    settings = Settings(**settings_dict)

    for mode in ("error", "missing"):
        inventory_mode["value"] = mode
        assert (
            await reconcile_unknown_routing_decisions(
                db_session,
                settings,
                cipher,
                actor="worker:reconcile",
            )
            == 0
        )
        await db_session.refresh(decision)
        assert "reconcile_mismatch_attempts" not in decision.result

    inventory_mode["value"] = "mismatch"
    for attempt in range(1, 4):
        assert (
            await reconcile_unknown_routing_decisions(
                db_session,
                settings,
                cipher,
                actor="worker:reconcile",
            )
            == 0
        )
        await db_session.refresh(decision)
        assert decision.result["reconcile_mismatch_attempts"] == attempt
        assert decision.status == ("failed" if attempt == 3 else "running")

    assert decision.finished_at is not None
    failure_audits = list(
        await db_session.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "cost_routing.priority.reconciliation_failed"
            )
        )
    )
    assert len(failure_audits) == 1

    ran = await run_cost_routing_policy(
        db_session,
        policy.id,
        settings,
        cipher,
        actor="worker:test",
    )
    assert ran is policy_enabled
    assert writes == ([("1", 100)] if policy_enabled else [])
    decisions = list(
        await db_session.scalars(
            select(RoutingDecision).order_by(RoutingDecision.created_at, RoutingDecision.id)
        )
    )
    assert len(decisions) == (2 if policy_enabled else 1)
    if policy_enabled:
        assert decisions[-1].status == "succeeded"


@pytest.mark.asyncio
async def test_worker_reconciles_unknown_outcomes_without_due_policies(
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import worker as worker_module
    from app.worker import Worker

    calls = {"reconcile": 0, "claim": 0, "dispatch": 0}

    class FakeSessionContext:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, *_args: object) -> None:
            return None

    def fake_session_factory() -> FakeSessionContext:
        return FakeSessionContext()

    async def fake_reconcile(*_args: object, **_kwargs: object) -> int:
        calls["reconcile"] += 1
        return 1

    async def fake_claim(*_args: object, **_kwargs: object) -> list[str]:
        calls["claim"] += 1
        return []

    async def fake_dispatch(*_args: object, **_kwargs: object) -> int:
        calls["dispatch"] += 1
        return 1

    monkeypatch.setattr(worker_module, "SessionFactory", fake_session_factory)
    monkeypatch.setattr(worker_module, "reconcile_unknown_routing_decisions", fake_reconcile)
    monkeypatch.setattr(worker_module, "claim_due_cost_routing_policies", fake_claim)
    monkeypatch.setattr(worker_module, "dispatch_due", fake_dispatch)

    await Worker(Settings(**settings_dict))._cost_routing_tick()

    assert calls == {"reconcile": 1, "claim": 1, "dispatch": 1}


@pytest.mark.asyncio
async def test_policy_run_keeps_unknown_mismatch_reconcilable(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(timezone.utc)
    cipher = SecretCipher(str(settings_dict["master_key"]))
    target = Target(
        id="target-unknown-mismatch",
        name="Unknown",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="policy-unknown-mismatch",
        target_id=target.id,
        enabled=True,
        mode="execute",
    )
    secret = TargetSecret(
        target_id=target.id,
        auth_type="x_api_key",
        ciphertext=cipher.encrypt_json({"api_key": "test-admin-key"}),
    )
    account = _account(
        target.id,
        "1",
        "Pending account",
        priority=800,
        multiplier=0.8,
        now=now,
    )
    decision = RoutingDecision(
        id="decision-unknown-mismatch",
        policy_id=policy.id,
        target_id=target.id,
        external_account_id="1",
        account_name="Pending account",
        observed_multiplier=0.1,
        previous_priority=800,
        desired_priority=100,
        reason="cost_decrease",
        mode="execute",
        status="running",
        result={"outcome_unknown": True, "previous_multiplier": 0.8},
    )
    db_session.add_all([target, secret, policy, account, decision])
    await db_session.commit()

    writes: list[tuple[str, int]] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), [
                normalize_account(
                    {
                        "id": "1",
                        "name": "Pending account",
                        "platform": "openai",
                        "type": "apikey",
                        "status": "active",
                        "schedulable": True,
                        "priority": 800,
                        "rate_multiplier": 0.1,
                    },
                    now,
                )
            ]

        async def probe_upstream_billing_batch(self, _account_ids: list[str]):
            return [
                {
                    "account_id": "1",
                    "snapshot": {
                        "status": "ok",
                        "data": {"effective_rate_multiplier": 0.1},
                    },
                }
            ]

        async def set_account_priority(self, account_id: str, priority: int, *, control):
            writes.append((account_id, priority))
            return {"priority": priority}

    async def fake_connector(*_args: object):
        return FakeConnector()

    monkeypatch.setattr(cost_routing, "connector_for_target", fake_connector)
    assert await run_cost_routing_policy(
        db_session,
        policy.id,
        Settings(**settings_dict),
        cipher,
        actor="worker:test",
    )

    await db_session.refresh(decision)
    assert decision.status == "running"
    assert decision.finished_at is None
    assert decision.result["reconcile_actual_priority"] == 800
    assert writes == []
    decisions = list(await db_session.scalars(select(RoutingDecision)))
    assert [item.id for item in decisions] == [decision.id]


def _account(
    target_id: str,
    external_id: str,
    name: str,
    *,
    priority: int,
    multiplier: float,
    now: datetime,
) -> AccountCurrent:
    return AccountCurrent(
        target_id=target_id,
        external_account_id=external_id,
        name=name,
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        priority=priority,
        rate_multiplier=multiplier,
        upstream_billing_probe={
            "status": "ok",
            "data": {"effective_rate_multiplier": multiplier},
        },
        observed_at=now,
        last_seen_at=now,
    )
