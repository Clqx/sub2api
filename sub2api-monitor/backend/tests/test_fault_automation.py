from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.config import Settings
from app.connectors.sub2api import ConnectorError, NativeAlertEvent, Sub2APIConnector
from app.models import (
    AccountCurrent,
    AuditEvent,
    AutomationExecution,
    AutomationRule,
    CollectionRun,
    Incident,
    NotificationChannel,
    NotificationOutbox,
    Policy,
    Target,
)
from app.schemas import AutomationRuleCreate
from app.security import SecretCipher
from app.services import automation, notifier
from app.services.policies import (
    evaluate_account,
    evaluate_collection_health,
    evaluate_native_alerts,
)


async def test_native_alerts_are_mirrored_resolved_and_subscription_filtered(
    db_session,
) -> None:
    target = Target(id="target-native", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-native", name="Default")
    webhook = NotificationChannel(
        id="webhook-native",
        name="critical webhook",
        kind="webhook",
        server_url="https://hooks.example.com/events",
        topic="",
        event_types=["incident.firing"],
        severities=["critical"],
    )
    db_session.add_all([target, policy, webhook])
    await db_session.flush()

    await evaluate_native_alerts(
        db_session,
        target.id,
        target.name,
        [
            NativeAlertEvent(
                external_event_id="42",
                rule_id="7",
                severity="critical",
                status="firing",
                title="Error rate high",
                description="Upstream 5xx exceeded threshold",
                fired_at=datetime.now(timezone.utc),
            )
        ],
        complete=True,
    )
    await db_session.flush()
    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "target.native_alert")
    )
    rows = list(await db_session.scalars(select(NotificationOutbox)))
    assert incident is not None and incident.status == "firing"
    assert len(rows) == 1
    assert rows[0].payload["event_type"] == "incident.firing"
    assert rows[0].payload["event_id"] == rows[0].transition_id

    await evaluate_native_alerts(db_session, target.id, target.name, [], complete=True)
    await db_session.flush()
    assert incident.status == "resolved"
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) == 1


async def test_collection_failure_fires_and_recovers(db_session) -> None:
    target = Target(id="target-collection", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-collection", name="Default")
    channel = NotificationChannel(
        id="channel-collection",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    db_session.add_all([target, policy, channel])
    await db_session.flush()

    await evaluate_collection_health(db_session, target.id, target.name, "target timed out")
    await evaluate_collection_health(db_session, target.id, target.name, None)
    await db_session.flush()

    incident = await db_session.scalar(
        select(Incident).where(Incident.rule_key == "target.collection_failed")
    )
    assert incident is not None and incident.status == "resolved"
    assert len(list(await db_session.scalars(select(NotificationOutbox)))) == 2


async def test_automation_skips_action_unrelated_to_observed_fault(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-unrelated", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-unrelated", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="11",
        name="temporary fault",
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=False,
        availability_reasons=["temporarily_unschedulable"],
        group_ids=[],
        observed_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-unrelated",
        name="Clear rate limits",
        enabled=True,
        action="clear_rate_limit",
        mode="execute",
        reason_filters=[],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()

    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()

    assert await db_session.scalar(select(AutomationExecution)) is None


async def test_fault_transition_only_recommends_then_manual_approval_applies(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-auto", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-auto", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="9",
        name="relay",
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=False,
        availability_reasons=["temporarily_unschedulable"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-auto",
        name="Recover temporary failures",
        enabled=True,
        trigger_rule_key="account.unavailable",
        action="recover_state",
        mode="execute",
        reason_filters=["temporarily_unschedulable"],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()

    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    execution = await db_session.scalar(select(AutomationExecution))
    assert execution is not None
    assert execution.status == "recommended"
    assert execution.mode == "recommend"

    settings = Settings(**settings_dict)
    cipher = SecretCipher(settings.master_key)
    assert await automation.dispatch_automations(db_session, settings, cipher) == 0
    approved, error = await automation.approve_recommendation(
        db_session, execution, actor="operator"
    )
    assert approved and error is None
    await db_session.commit()

    seen_accounts: list[str] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute_account_action(
            self,
            account_id: str,
            action: str,
            *,
            idempotency_key: str,
            expected_state: dict[str, object],
        ) -> dict[str, object]:
            seen_accounts.append(account_id)
            assert account_id == "9"
            assert action == "recover_state"
            assert idempotency_key == execution.idempotency_key
            assert expected_state["source_updated_at"] == now.isoformat()
            assert expected_state["status"] == "active"
            assert expected_state["schedulable"] is True
            return {"http_status": 200, "idempotency_replayed": False}

    async def fake_target_connector(*_args: object):
        return target, FakeConnector()

    monkeypatch.setattr(automation, "target_connector", fake_target_connector)
    assert await automation.dispatch_automations(db_session, settings, cipher) == 1
    await db_session.refresh(execution)
    assert execution.status == "applied"
    assert seen_accounts == ["9"]
    run = await db_session.scalar(select(CollectionRun))
    assert run is not None and run.trigger == "automation_verify"

    account.available = True
    account.availability_reasons = []
    account.observed_at = datetime.fromisoformat(execution.result["applied_at"]) + timedelta(
        seconds=1
    )
    assert await automation.verify_applied_automations(db_session, target.id) == 1
    assert execution.status == "verified"


async def test_delayed_approval_marks_changed_account_stale(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-stale", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-stale", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="12",
        name="stale",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-stale",
        name="Clear error",
        enabled=True,
        action="clear_error",
        mode="recommend",
        reason_filters=["status:error"],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()
    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    execution = await db_session.scalar(select(AutomationExecution))
    assert execution is not None

    account.source_updated_at = now + timedelta(microseconds=1)
    approved, reason = await automation.approve_recommendation(
        db_session, execution, actor="operator"
    )
    assert not approved
    assert reason == "account state changed after recommendation"
    assert execution.status == "skipped_stale"


async def test_new_collection_with_same_source_state_and_ack_can_be_approved(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-ack", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-ack", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="15",
        name="acknowledged",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-ack",
        name="Clear acknowledged error",
        enabled=True,
        action="clear_error",
        mode="recommend",
        reason_filters=["status:error"],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()
    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    execution = await db_session.scalar(select(AutomationExecution))
    incident = await db_session.get(Incident, execution.incident_id if execution else "")
    assert execution is not None and incident is not None

    account.observed_at = now + timedelta(minutes=1)
    incident.status = "acknowledged"
    approved, reason = await automation.approve_recommendation(
        db_session, execution, actor="operator"
    )
    assert approved and reason is None
    assert execution.status == "queued"


async def test_post_action_collection_marks_persistent_fault_verification_failed(
    db_session,
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-verify-fail", name="Prod", base_url="https://example.com")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="16",
        name="still broken",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    execution = AutomationExecution(
        id="execution-verify-fail",
        transition_id="transition-verify-fail",
        target_id=target.id,
        external_account_id=account.external_account_id,
        action="clear_error",
        mode="execute",
        status="applied",
        idempotency_key="verify-fail",
        result={"applied_at": (now - timedelta(seconds=1)).isoformat()},
    )
    db_session.add_all([target, account, execution])
    await db_session.flush()

    assert await automation.verify_applied_automations(db_session, target.id) == 1
    assert execution.status == "verification_failed"
    assert execution.last_error == "account remained unavailable after recovery verification"


async def test_applied_verification_terminates_missing_invalid_and_stale_evidence(
    db_session,
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-verify-terminal", name="Prod", base_url="https://example.com")
    stale_account = AccountCurrent(
        target_id=target.id,
        external_account_id="stale-observation",
        name="not observed again",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=now - timedelta(minutes=2),
        last_seen_at=now - timedelta(minutes=2),
    )
    missing_inventory = AccountCurrent(
        target_id=target.id,
        external_account_id="missing-inventory",
        name="missing from inventory",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["missing_from_inventory"],
        group_ids=[],
        observed_at=now,
        last_seen_at=now - timedelta(minutes=2),
    )
    old_applied_at = (now - timedelta(minutes=1)).isoformat()
    executions = [
            AutomationExecution(
                id="execution-account-absent",
                transition_id="transition-account-absent",
            target_id=target.id,
            external_account_id="deleted-account",
            action="clear_error",
            mode="execute",
            status="applied",
            idempotency_key="verify-account-absent",
            result={"applied_at": old_applied_at},
        ),
            AutomationExecution(
                id="execution-observation-stale",
                transition_id="transition-observation-stale",
            target_id=target.id,
            external_account_id=stale_account.external_account_id,
            action="clear_error",
            mode="execute",
            status="applied",
            idempotency_key="verify-observation-stale",
            result={"applied_at": old_applied_at},
        ),
            AutomationExecution(
                id="execution-invalid-applied-at",
                transition_id="transition-invalid-applied-at",
            target_id=target.id,
            external_account_id=stale_account.external_account_id,
            action="clear_error",
            mode="execute",
            status="applied",
            idempotency_key="verify-invalid-applied-at",
            result={"applied_at": "not-a-timestamp"},
        ),
            AutomationExecution(
                id="execution-missing-inventory",
                transition_id="transition-missing-inventory",
            target_id=target.id,
            external_account_id=missing_inventory.external_account_id,
            action="clear_error",
            mode="execute",
            status="applied",
            idempotency_key="verify-missing-inventory",
            result={"applied_at": (now - timedelta(seconds=1)).isoformat()},
        ),
    ]
    db_session.add_all([target, stale_account, missing_inventory, *executions])
    await db_session.flush()

    assert (
        await automation.verify_applied_automations(
            db_session, target.id, timeout_seconds=30
        )
        == 4
    )
    assert all(item.status == "verification_failed" for item in executions)
    assert "absent throughout" in (executions[0].last_error or "")
    assert "no fresh account observation" in (executions[1].last_error or "")
    assert "no valid applied_at" in (executions[2].last_error or "")
    assert executions[3].last_error == (
        "account remained unavailable after recovery verification"
    )


async def test_dispatch_deadline_sweep_terminates_applied_without_collection(
    db_session, settings_dict: dict[str, object]
) -> None:
    settings_dict["automation_verification_timeout_seconds"] = 30
    target = Target(
        id="target-verify-no-collection",
        name="Disabled target",
        base_url="https://example.com",
        enabled=False,
    )
    fresh_available = AccountCurrent(
        target_id=target.id,
        external_account_id="fresh-available",
        name="recovered",
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        group_ids=[],
        observed_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    fresh_unavailable = AccountCurrent(
        target_id=target.id,
        external_account_id="fresh-unavailable",
        name="still unavailable",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    absent_execution = AutomationExecution(
        id="execution-verify-no-collection",
        transition_id="transition-verify-no-collection",
        target_id=target.id,
        external_account_id="absent",
        action="clear_error",
        mode="execute",
        status="applied",
        idempotency_key="verify-no-collection",
        result={
            "applied_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        },
    )
    recent_applied_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    available_execution = AutomationExecution(
        id="execution-verify-global-available",
        transition_id="transition-verify-global-available",
        target_id=target.id,
        external_account_id=fresh_available.external_account_id,
        action="clear_error",
        mode="execute",
        status="applied",
        idempotency_key="verify-global-available",
        result={"applied_at": recent_applied_at},
    )
    unavailable_execution = AutomationExecution(
        id="execution-verify-global-unavailable",
        transition_id="transition-verify-global-unavailable",
        target_id=target.id,
        external_account_id=fresh_unavailable.external_account_id,
        action="clear_error",
        mode="execute",
        status="applied",
        idempotency_key="verify-global-unavailable",
        result={"applied_at": recent_applied_at},
    )
    db_session.add_all(
        [
            target,
            fresh_available,
            fresh_unavailable,
            absent_execution,
            available_execution,
            unavailable_execution,
        ]
    )
    await db_session.commit()

    delivered = await automation.dispatch_automations(
        db_session,
        Settings(**settings_dict),
        SecretCipher("test-master-key-that-is-long-enough"),
    )
    for execution in (absent_execution, available_execution, unavailable_execution):
        await db_session.refresh(execution)

    assert delivered == 0
    assert absent_execution.status == "verification_failed"
    assert "absent throughout" in (absent_execution.last_error or "")
    assert available_execution.status == "verified"
    assert available_execution.last_error is None
    assert unavailable_execution.status == "verification_failed"
    assert unavailable_execution.last_error == (
        "account remained unavailable after recovery verification"
    )


async def test_overload_firing_never_dispatches_without_approval(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-overload", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-overload", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="13",
        name="overloaded",
        platform="openai",
        account_type="apikey",
        status="active",
        schedulable=True,
        available=False,
        availability_reasons=["overloaded"],
        group_ids=[],
        overload_until=now.replace(year=now.year + 1),
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-overload",
        name="Legacy execute overload",
        enabled=True,
        action="recover_state",
        mode="execute",
        reason_filters=["overloaded"],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()
    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    execution = await db_session.scalar(select(AutomationExecution))
    assert execution is not None and execution.status == "recommended"

    async def must_not_connect(*_args: object):
        pytest.fail("fault firing must not invoke an account recovery endpoint")

    monkeypatch.setattr(automation, "target_connector", must_not_connect)
    delivered = await automation.dispatch_automations(
        db_session,
        Settings(**settings_dict),
        SecretCipher("test-master-key-that-is-long-enough"),
    )
    assert delivered == 0
    assert account.overload_until is not None


@pytest.mark.parametrize(
    ("upstream_reason", "expected_status"),
    [
        ("ACCOUNT_STATE_CHANGED", "skipped_stale"),
        ("IDEMPOTENCY_IN_PROGRESS", "failed"),
        ("IDEMPOTENCY_RETRY_BACKOFF", "failed"),
    ],
)
async def test_upstream_conflict_classification_uses_envelope_reason(
    db_session,
    settings_dict: dict[str, object],
    monkeypatch,
    upstream_reason: str,
    expected_status: str,
) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-cas", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-cas", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="18",
        name="cas conflict",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    rule = AutomationRule(
        id="rule-cas",
        name="Clear error",
        enabled=True,
        action="clear_error",
        mode="recommend",
        reason_filters=["status:error"],
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, rule])
    await db_session.flush()
    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    execution = await db_session.scalar(select(AutomationExecution))
    assert execution is not None
    approved, _ = await automation.approve_recommendation(
        db_session, execution, actor="operator"
    )
    assert approved
    await db_session.commit()

    class ConflictingConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute_account_action(self, *_args: object, **_kwargs: object):
            raise ConnectorError(
                upstream_reason,
                status_code=409,
                reason=upstream_reason,
            )

    async def fake_target_connector(*_args: object):
        return target, ConflictingConnector()

    monkeypatch.setattr(automation, "target_connector", fake_target_connector)
    delivered = await automation.dispatch_automations(
        db_session,
        Settings(**settings_dict),
        SecretCipher("test-master-key-that-is-long-enough"),
    )
    assert delivered == 0
    assert execution.status == expected_status
    assert execution.last_error == upstream_reason


async def test_reason_match_all_and_invalid_combinations(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(id="target-multi", name="Prod", base_url="https://example.com")
    policy = Policy(id="policy-multi", name="Default")
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="14",
        name="multi",
        platform="openai",
        account_type="apikey",
        status="error",
        schedulable=True,
        available=False,
        availability_reasons=["status:error", "overloaded"],
        group_ids=[],
        observed_at=now,
        source_updated_at=now,
        last_seen_at=now,
    )
    matching = AutomationRule(
        id="rule-all-match",
        name="Both reasons",
        target_id=target.id,
        enabled=True,
        action="recover_state",
        mode="recommend",
        reason_filters=["status:error", "overloaded"],
        reason_match_mode="all",
        cooldown_seconds=900,
    )
    not_matching = AutomationRule(
        id="rule-all-miss",
        name="Three reasons",
        enabled=True,
        action="recover_state",
        mode="recommend",
        reason_filters=["status:error", "overloaded", "rate_limited"],
        reason_match_mode="all",
        cooldown_seconds=900,
    )
    global_matching = AutomationRule(
        id="rule-global-match",
        name="Global duplicate",
        enabled=True,
        action="recover_state",
        mode="recommend",
        reason_filters=["status:error", "overloaded"],
        reason_match_mode="all",
        cooldown_seconds=900,
    )
    db_session.add_all([target, policy, account, matching, not_matching, global_matching])
    await db_session.flush()
    await evaluate_account(db_session, target.name, account, [])
    await db_session.flush()
    rows = list(await db_session.scalars(select(AutomationExecution)))
    assert [row.rule_id for row in rows] == [matching.id]
    matching.reason_filters = ["status:error"]
    approved, reason = await automation.approve_recommendation(
        db_session, rows[0], actor="operator"
    )
    assert not approved and reason == "automation rule changed after recommendation"
    assert rows[0].status == "cancelled"

    with pytest.raises(ValidationError, match="incompatible"):
        AutomationRuleCreate(
            name="invalid",
            action="clear_error",
            reason_filters=["overloaded"],
        )
    with pytest.raises(ValidationError, match="at least 1"):
        AutomationRuleCreate(name="too broad", action="recover_state", reason_filters=[])
    with pytest.raises(ValidationError, match="manual approval"):
        AutomationRuleCreate(
            name="unsafe execute",
            action="clear_error",
            mode="execute",
            enabled=True,
            reason_filters=["status:error"],
            confirm_side_effects=True,
        )
    with pytest.raises(ValidationError, match="cannot be enabled"):
        AutomationRuleCreate(
            name="broad recovery",
            action="recover_state",
            enabled=True,
            reason_filters=["overloaded"],
        )


async def test_connector_uses_native_alert_filter_and_idempotent_action(
    settings_dict: dict[str, object],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/alert-events"):
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": [
                        {
                            "id": 3,
                            "rule_id": 5,
                            "severity": "critical",
                            "status": "firing",
                            "title": "High failures",
                            "description": "5xx",
                            "fired_at": "2026-08-09T00:00:00Z",
                        }
                    ],
                },
            )
        return httpx.Response(200, json={"code": 0, "data": {"updated": True}})

    connector = Sub2APIConnector(
        base_url="https://sub.example.com",
        auth_type="x_api_key",
        secret={"api_key": "admin-test"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        fact, events, complete = await connector.native_alert_events()
        result = await connector.execute_account_action(
            "17",
            "recover_state",
            idempotency_key="stable-operation",
            expected_state={
                "source_updated_at": "2026-08-09T00:00:00+00:00",
                "status": "error",
                "schedulable": True,
                "temp_unschedulable_until": None,
            },
        )
    assert fact.runtime_state == "healthy" and complete
    assert events[0].external_event_id == "3"
    assert requests[0].url.params["status"] == "firing"
    assert requests[1].url.path.endswith("/accounts/17/recover-state")
    assert requests[1].headers["Idempotency-Key"] == "stable-operation"
    assert json.loads(requests[1].content) == {
        "expected_updated_at": "2026-08-09T00:00:00+00:00",
        "expected_status": "error",
        "expected_schedulable": True,
        "expected_temp_unschedulable_until": None,
    }
    assert result["http_status"] == 200


async def test_webhook_delivery_is_hmac_signed(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    channel = NotificationChannel(
        id="webhook-signed",
        name="signed",
        kind="webhook",
        server_url="https://hooks.example.com/events",
        topic="",
        signing_secret_ciphertext=cipher.encrypt_text("signing-secret-long-enough"),
    )
    row = NotificationOutbox(
        id="delivery-signed",
        transition_id="event-signed",
        channel_id=channel.id,
        payload={"event_type": "incident.firing", "value": 7},
    )
    db_session.add_all([channel, row])
    await db_session.commit()

    class FakeClient:
        def __init__(self, **_: object):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, _url: httpx.URL, *, content: bytes, headers, extensions):
            assert str(_url) == "https://203.0.113.9/events"
            assert headers["Host"] == "hooks.example.com"
            assert extensions == {"sni_hostname": "hooks.example.com"}
            assert json.loads(content) == row.payload
            assert headers["X-Sub2API-Monitor-Event"] == "incident.firing"
            assert headers["X-Sub2API-Monitor-Delivery"] == row.id
            expected = hmac.new(b"signing-secret-long-enough", content, hashlib.sha256).hexdigest()
            assert headers["X-Sub2API-Monitor-Signature"] == f"sha256={expected}"
            return httpx.Response(204)

    async def resolve(*_args: object, **_kwargs: object) -> str:
        return "203.0.113.9"

    monkeypatch.setattr(notifier.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(notifier, "resolve_target_address", resolve)
    assert await notifier.dispatch_due(db_session, Settings(**settings_dict), cipher) == 1


async def test_orphaned_automation_execution_is_retained_and_audited(
    db_session, settings_dict: dict[str, object]
) -> None:
    execution = AutomationExecution(
        id="execution-orphaned",
        rule_id=None,
        incident_id=None,
        transition_id="transition-deleted",
        target_id=None,
        external_account_id="17",
        action="recover_state",
        mode="execute",
        status="queued",
        idempotency_key="monitor-auto-deleted-parent",
    )
    db_session.add(execution)
    await db_session.commit()

    delivered = await automation.dispatch_automations(
        db_session,
        Settings(**settings_dict),
        SecretCipher("test-master-key-that-is-long-enough"),
    )
    await db_session.refresh(execution)
    audit = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "automation.cancelled")
    )

    assert delivered == 0
    assert execution.status == "cancelled"
    assert execution.last_error == "automation rule or target is no longer executable"
    assert audit is not None
    assert audit.details["execution_id"] == execution.id


def test_automation_execution_foreign_keys_preserve_audit_history() -> None:
    for name in ("rule_id", "incident_id", "target_id"):
        column = AutomationExecution.__table__.c[name]
        foreign_key = next(iter(column.foreign_keys))
        assert column.nullable is True
        assert foreign_key.ondelete == "SET NULL"
