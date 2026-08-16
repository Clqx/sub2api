from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import Settings
from app.models import (
    AccountObservation,
    ActiveQuotaAttempt,
    AuditEvent,
    CollectionRun,
    QuotaSample,
    RoutingSessionState,
    RunStatus,
    Session,
    Target,
    User,
)
from app.services.maintenance import purge_expired_history


async def test_history_cleanup_removes_only_expired_operational_data(
    db_session,
    settings_dict: dict[str, object],
) -> None:
    now = datetime(2026, 8, 15, tzinfo=timezone.utc)
    old = now - timedelta(days=31)
    recent = now - timedelta(days=1)
    target = Target(id="target-maintenance", name="Maintenance", base_url="https://example.com")
    user = User(id="user-maintenance", username="admin", password_hash="unused")
    old_run = CollectionRun(
        id="run-old",
        target_id=target.id,
        status=RunStatus.SUCCEEDED.value,
        created_at=old,
        finished_at=old,
    )
    recent_run = CollectionRun(
        id="run-recent",
        target_id=target.id,
        status=RunStatus.SUCCEEDED.value,
        created_at=recent,
        finished_at=recent,
    )
    running_run = CollectionRun(
        id="run-running",
        target_id=target.id,
        status=RunStatus.RUNNING.value,
        created_at=old,
    )
    db_session.add_all(
        [
            target,
            user,
            old_run,
            recent_run,
            running_run,
            Session(
                id="session-old", user_id=user.id, token_hash="a" * 64, expires_at=old
            ),
            Session(
                id="session-recent",
                user_id=user.id,
                token_hash="b" * 64,
                expires_at=now + timedelta(days=1),
            ),
            AccountObservation(
                id="observation-old",
                producer_id="worker",
                target_id=target.id,
                run_id=old_run.id,
                batch_id="batch-old",
                sequence=0,
                external_account_id="1",
                observed_at=old,
                received_at=old,
                payload={},
            ),
            AccountObservation(
                id="observation-recent",
                producer_id="worker",
                target_id=target.id,
                run_id=recent_run.id,
                batch_id="batch-recent",
                sequence=0,
                external_account_id="1",
                observed_at=recent,
                received_at=recent,
                payload={},
            ),
            QuotaSample(
                id="quota-old",
                target_id=target.id,
                external_account_id="1",
                provider="openai",
                quota_key="five_hour",
                label="5 hour",
                unit="percent",
                observed_at=old,
                source="test",
            ),
            QuotaSample(
                id="quota-recent",
                target_id=target.id,
                external_account_id="1",
                provider="openai",
                quota_key="five_hour",
                label="5 hour",
                unit="percent",
                observed_at=recent,
                source="test",
            ),
            ActiveQuotaAttempt(
                id="attempt-old",
                correlation_id="correlation-old",
                target_id=target.id,
                run_id=old_run.id,
                external_account_id="1",
                actor="worker",
                created_at=old,
            ),
            ActiveQuotaAttempt(
                id="attempt-recent",
                correlation_id="correlation-recent",
                target_id=target.id,
                run_id=recent_run.id,
                external_account_id="1",
                actor="worker",
                created_at=recent,
            ),
            RoutingSessionState(
                id="routing-session-old",
                target_id=target.id,
                session_id="session-old",
                external_account_id="1",
                account_name="Old account",
                last_usage_id=1,
                last_used_at=old,
                created_at=old,
                updated_at=old,
            ),
            RoutingSessionState(
                id="routing-session-recent",
                target_id=target.id,
                session_id="session-recent",
                external_account_id="2",
                account_name="Recent account",
                last_usage_id=2,
                last_used_at=recent,
                created_at=recent,
                updated_at=recent,
            ),
            AuditEvent(
                id="audit-old",
                actor="worker",
                action="retained",
                target_id=target.id,
                created_at=old,
            ),
        ]
    )
    await db_session.commit()

    await purge_expired_history(
        db_session,
        Settings(**{**settings_dict, "history_retention_days": 30}),
        now=now,
    )

    assert await db_session.get(CollectionRun, old_run.id) is None
    assert await db_session.get(AccountObservation, "observation-old") is None
    assert await db_session.get(QuotaSample, "quota-old") is None
    assert await db_session.get(ActiveQuotaAttempt, "attempt-old") is None
    assert await db_session.get(RoutingSessionState, "routing-session-old") is None
    assert await db_session.get(Session, "session-old") is None
    assert await db_session.get(CollectionRun, recent_run.id) is not None
    assert await db_session.get(CollectionRun, running_run.id) is not None
    assert await db_session.get(AccountObservation, "observation-recent") is not None
    assert await db_session.get(QuotaSample, "quota-recent") is not None
    assert await db_session.get(ActiveQuotaAttempt, "attempt-recent") is not None
    assert await db_session.get(RoutingSessionState, "routing-session-recent") is not None
    assert await db_session.get(Session, "session-recent") is not None
    assert await db_session.get(AuditEvent, "audit-old") is not None
