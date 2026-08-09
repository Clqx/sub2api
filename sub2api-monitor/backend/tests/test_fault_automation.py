from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.config import Settings
from app.connectors.sub2api import NativeAlertEvent, Sub2APIConnector
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


async def test_automation_executes_once_and_queues_verification(
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
    assert execution is not None and execution.status == "queued"
    second = AutomationExecution(
        id="execution-auto-second",
        rule_id=rule.id,
        incident_id=execution.incident_id,
        transition_id="transition-auto-second",
        target_id=target.id,
        external_account_id="10",
        action="recover_state",
        mode="execute",
        status="queued",
        idempotency_key="monitor-auto-second",
    )
    db_session.add(second)
    await db_session.flush()

    seen_accounts: list[str] = []

    class FakeConnector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def execute_account_action(
            self, account_id: str, action: str, *, idempotency_key: str
        ) -> dict[str, object]:
            if not seen_accounts:
                statuses = list(
                    await db_session.scalars(
                        select(AutomationExecution.status).order_by(AutomationExecution.id)
                    )
                )
                assert len(statuses) == 2 and set(statuses) == {"running"}
            seen_accounts.append(account_id)
            assert account_id in {"9", "10"}
            assert action == "recover_state"
            expected_key = (
                execution.idempotency_key if account_id == "9" else second.idempotency_key
            )
            assert idempotency_key == expected_key
            return {"http_status": 200, "idempotency_replayed": False}

    async def fake_target_connector(*_args: object):
        return target, FakeConnector()

    monkeypatch.setattr(automation, "target_connector", fake_target_connector)
    settings = Settings(**settings_dict)
    cipher = SecretCipher(settings.master_key)
    assert await automation.dispatch_automations(db_session, settings, cipher) == 2
    await db_session.refresh(execution)
    await db_session.refresh(second)
    assert execution.status == second.status == "succeeded"
    assert set(seen_accounts) == {"9", "10"}
    run = await db_session.scalar(select(CollectionRun))
    assert run is not None and run.trigger == "automation_verify"


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
            "17", "recover_state", idempotency_key="stable-operation"
        )
    assert fact.runtime_state == "healthy" and complete
    assert events[0].external_event_id == "3"
    assert requests[0].url.params["status"] == "firing"
    assert requests[1].url.path.endswith("/accounts/17/recover-state")
    assert requests[1].headers["Idempotency-Key"] == "stable-operation"
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
        select(AuditEvent).where(AuditEvent.action == "automation.skipped")
    )

    assert delivered == 0
    assert execution.status == "skipped"
    assert execution.last_error == "automation rule or target is no longer executable"
    assert audit is not None
    assert audit.details["execution_id"] == execution.id


def test_automation_execution_foreign_keys_preserve_audit_history() -> None:
    for name in ("rule_id", "incident_id", "target_id"):
        column = AutomationExecution.__table__.c[name]
        foreign_key = next(iter(column.foreign_keys))
        assert column.nullable is True
        assert foreign_key.ondelete == "SET NULL"
