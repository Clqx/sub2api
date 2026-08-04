from datetime import datetime, timedelta, timezone

from app.api.router import account_responses
from app.models import AccountCurrent, QuotaSample, Target


async def test_account_response_includes_latest_lowest_quota_and_target(db_session) -> None:
    now = datetime.now(timezone.utc)
    target = Target(name="prod", base_url="https://sub.example.com")
    db_session.add(target)
    await db_session.flush()
    account = AccountCurrent(
        target_id=target.id,
        external_account_id="42",
        name="anthropic-low",
        platform="anthropic",
        account_type="oauth",
        status="active",
        schedulable=True,
        available=True,
        availability_reasons=[],
        observed_at=now,
        last_seen_at=now,
    )
    db_session.add(account)
    db_session.add_all(
        [
            QuotaSample(
                target_id=target.id,
                external_account_id="42",
                provider="anthropic",
                quota_key="five_hour",
                label="5 hour",
                remaining_percent=8,
                utilization_percent=92,
                unit="percent",
                observed_at=now,
                source="fixture",
                freshness="fresh",
            ),
            QuotaSample(
                target_id=target.id,
                external_account_id="42",
                provider="anthropic",
                quota_key="seven_day",
                label="7 day",
                remaining_percent=40,
                utilization_percent=60,
                unit="percent",
                observed_at=now + timedelta(seconds=5),
                source="fixture",
                freshness="fresh",
            ),
        ]
    )
    await db_session.flush()

    response = (await account_responses(db_session, [account]))[0]

    assert response.target_name == "prod"
    assert response.remaining_percent == 8
    assert response.quota_freshness == "fresh"
