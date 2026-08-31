from collections.abc import Awaitable
from typing import Any

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.router import (
    create_channel_monitor,
    dashboard,
    delete_channel_monitor,
    run_channel_monitor,
    update_channel_monitor,
)
from app.config import Settings
from app.models import AccountCurrent, ChannelMonitorCurrent, Target, User
from app.schemas import (
    AutomationRuleCreate,
    ChannelCreate,
    ChannelMonitorCreate,
    ChannelMonitorUpdate,
    UpstreamBillingSettings,
)
from app.security import SecretCipher
from app.services.monitoring import supports_upstream_billing_probe


def account(*, platform: str, account_type: str) -> AccountCurrent:
    return AccountCurrent(
        target_id="target",
        external_account_id="1",
        name="account",
        platform=platform,
        account_type=account_type,
        status="active",
        schedulable=True,
        available=True,
    )


def test_upstream_billing_probe_is_limited_to_openai_api_keys() -> None:
    assert supports_upstream_billing_probe(account(platform="OpenAI", account_type="APIKEY"))
    assert not supports_upstream_billing_probe(account(platform="openai", account_type="oauth"))
    assert not supports_upstream_billing_probe(account(platform="anthropic", account_type="apikey"))


def test_upstream_billing_interval_matches_target_contract() -> None:
    assert UpstreamBillingSettings(enabled=True, interval_minutes=5).interval_minutes == 5
    with pytest.raises(ValidationError):
        UpstreamBillingSettings(enabled=True, interval_minutes=4)


def test_fault_automation_cannot_enable_unattended_execution() -> None:
    with pytest.raises(ValidationError):
        AutomationRuleCreate(
            name="recover",
            enabled=True,
            action="clear_error",
            mode="execute",
            reason_filters=["status:error"],
        )
    with pytest.raises(ValidationError, match="manual approval"):
        AutomationRuleCreate(
            name="recover",
            enabled=True,
            action="clear_error",
            mode="execute",
            reason_filters=["status:error"],
            confirm_side_effects=True,
        )
    legacy_disabled_rule = AutomationRuleCreate(
        name="recover",
        enabled=False,
        action="recover_state",
        mode="execute",
        reason_filters=["status:error"],
    )
    assert not legacy_disabled_rule.enabled


def test_notification_contract_distinguishes_ntfy_and_webhook() -> None:
    with pytest.raises(ValidationError):
        ChannelCreate(name="ntfy", server_url="https://ntfy.example.com")
    webhook = ChannelCreate(
        name="events",
        kind="webhook",
        server_url="https://hooks.example.com/events",
        signing_secret="signing-secret-long-enough",
    )
    assert webhook.topic == ""


def test_telegram_channel_requires_valid_bot_token_and_chat_id() -> None:
    with pytest.raises(ValidationError):
        ChannelCreate(
            name="telegram",
            kind="telegram",
            server_url="https://api.telegram.org",
            topic="-1001234567890",
        )
    channel = ChannelCreate(
        name="telegram",
        kind="telegram",
        server_url="https://api.telegram.org",
        topic="-1001234567890",
        token="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi",
    )
    assert channel.topic == "-1001234567890"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_model_detection_mutations_are_paused_before_upstream_access(
    db_session: AsyncSession, settings_dict: dict[str, object]
) -> None:
    user = User(username="admin", password_hash="unused")
    settings = Settings.model_validate(settings_dict)
    cipher = SecretCipher(settings.master_key)
    create_payload = ChannelMonitorCreate(
        target_id="missing-target",
        name="paused",
        provider="openai",
        endpoint="https://api.openai.com",
        api_key="secret",
        primary_model="gpt-5",
    )

    async def assert_paused(operation: Awaitable[Any]) -> None:
        with pytest.raises(HTTPException) as error:
            await operation
        assert error.value.status_code == 409
        assert error.value.detail["code"] == "model_detection_paused"

    await assert_paused(
        create_channel_monitor(create_payload, user, db_session, settings, cipher)
    )
    await assert_paused(
        update_channel_monitor(
            "missing-monitor",
            ChannelMonitorUpdate(name="paused"),
            user,
            db_session,
            settings,
            cipher,
        )
    )
    await assert_paused(
        delete_channel_monitor("missing-monitor", user, db_session, settings, cipher)
    )
    await assert_paused(
        run_channel_monitor("missing-monitor", user, db_session, settings, cipher)
    )


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_dashboard_does_not_report_frozen_model_detection_snapshots(
    db_session: AsyncSession,
) -> None:
    target = Target(id="target", name="Target", base_url="https://example.com")
    db_session.add_all(
        [
            target,
            ChannelMonitorCurrent(
                target_id=target.id,
                external_monitor_id="legacy-monitor",
                name="Legacy monitor",
                provider="openai",
                endpoint="https://api.openai.com",
                enabled=True,
                primary_status="failed",
            ),
        ]
    )
    await db_session.commit()

    response = await dashboard(User(username="admin", password_hash="unused"), db_session)

    assert response.channels_total == 0
    assert response.channels_unhealthy == 0
