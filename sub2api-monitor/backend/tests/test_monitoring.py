import pytest
from pydantic import ValidationError

from app.models import AccountCurrent
from app.schemas import AutomationRuleCreate, ChannelCreate, UpstreamBillingSettings
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
