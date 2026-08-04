from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import CollectionRun, RunStatus, Target
from app.worker import Worker


@pytest.mark.asyncio
async def test_worker_restart_recovers_same_container_run(
    db_session: AsyncSession,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    monkeypatch.setattr("app.worker.SessionFactory", factory)
    worker = Worker(Settings(**settings_dict))
    run = CollectionRun(
        target_id="target-1",
        status=RunStatus.RUNNING.value,
        worker_id=f"{worker.hostname}-99-deadbeef",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(run)
    await db_session.commit()

    await worker._recover_stale_runs(recover_same_host=True)
    await db_session.refresh(run)

    assert run.status == RunStatus.FAILED.value
    assert run.finished_at is not None
    assert run.error == "worker stopped before collection completed"


@pytest.mark.asyncio
async def test_worker_schedules_ready_api_only_and_full_targets(
    db_session: AsyncSession,
    settings_dict: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    monkeypatch.setattr("app.worker.SessionFactory", factory)
    due = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.add_all(
        [
            Target(
                id="api-target",
                name="API",
                base_url="https://api.example.com",
                mode="api_only",
                enabled=True,
                monitoring_readiness="ready",
                next_collection_at=due,
            ),
            Target(
                id="full-target",
                name="FULL",
                base_url="https://full.example.com",
                mode="full",
                enabled=True,
                monitoring_readiness="ready",
                next_collection_at=due,
            ),
        ]
    )
    await db_session.commit()

    await Worker(Settings(**settings_dict))._schedule_due_targets()

    runs = list(await db_session.scalars(select(CollectionRun).order_by(CollectionRun.target_id)))
    assert [(run.target_id, run.trigger) for run in runs] == [
        ("api-target", "scheduled"),
        ("full-target", "scheduled"),
    ]
