import pytest
from pydantic import ValidationError

from app.models import AccountCurrent
from app.schemas import UpstreamBillingSettings
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
