from __future__ import annotations

import asyncio
import logging
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.sql.elements import ColumnElement

from app.config import Settings, get_settings
from app.database import SessionFactory
from app.models import CollectionRun, RunStatus, Target, WorkerHeartbeat
from app.security import SecretCipher, ensure_admin
from app.services.collector import collect_run
from app.services.notifier import dispatch_due

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.hostname = socket.gethostname()
        self.worker_id = f"{self.hostname}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.cipher = SecretCipher(settings.master_key)
        self._semaphore = asyncio.Semaphore(settings.worker_concurrency)
        self._health_file = Path("/tmp/sub2api-monitor-worker-health")

    async def run_forever(self) -> None:
        async with SessionFactory() as session:
            await ensure_admin(session, self.settings.admin_username, self.settings.admin_password)
        await self._recover_stale_runs(recover_same_host=True)
        logger.info("worker started", extra={"worker_id": self.worker_id})
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            while True:
                try:
                    await self.tick()
                except Exception:
                    logger.exception("worker tick failed")
                await asyncio.sleep(self.settings.worker_poll_seconds)
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

    async def tick(self) -> None:
        await self._recover_stale_runs()
        await self._schedule_due_targets()
        run_ids = await self._claim_queued_runs(self.settings.worker_concurrency)
        if run_ids:
            await asyncio.gather(*(self._execute(run_id) for run_id in run_ids))
        async with SessionFactory() as session:
            await dispatch_due(session, self.cipher)

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await self._heartbeat()
            except Exception:
                logger.exception("worker heartbeat failed")
            await asyncio.sleep(min(self.settings.worker_poll_seconds, 5.0))

    async def _heartbeat(self) -> None:
        async with SessionFactory() as session:
            heartbeat = await session.get(WorkerHeartbeat, self.worker_id)
            if heartbeat is None:
                heartbeat = WorkerHeartbeat(worker_id=self.worker_id)
                session.add(heartbeat)
            heartbeat.last_seen_at = datetime.now(timezone.utc)
            heartbeat.details = {"pid": os.getpid(), "version": "0.1.0"}
            await session.commit()
        self._health_file.touch()

    async def _recover_stale_runs(self, *, recover_same_host: bool = False) -> None:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.settings.worker_stale_seconds)
        async with SessionFactory() as session:
            stale_workers = select(WorkerHeartbeat.worker_id).where(
                WorkerHeartbeat.last_seen_at < cutoff
            )
            conditions: list[ColumnElement[bool]] = [
                CollectionRun.worker_id.in_(stale_workers),
            ]
            if recover_same_host:
                conditions.append(CollectionRun.worker_id.startswith(f"{self.hostname}-"))
            runs = list(
                await session.scalars(
                    select(CollectionRun)
                    .where(
                        CollectionRun.status == RunStatus.RUNNING.value,
                        or_(*conditions),
                    )
                    .with_for_update(skip_locked=True)
                )
            )
            for run in runs:
                run.status = RunStatus.FAILED.value
                run.error = "worker stopped before collection completed"
                run.finished_at = now
            if runs:
                await session.commit()

    async def _schedule_due_targets(self) -> None:
        now = datetime.now(timezone.utc)
        async with SessionFactory() as session:
            targets = list(
                await session.scalars(
                    select(Target)
                    .where(
                        Target.enabled.is_(True),
                        Target.monitoring_readiness == "ready",
                        Target.next_collection_at <= now,
                    )
                    .with_for_update(skip_locked=True)
                )
            )
            for target in targets:
                active = await session.scalar(
                    select(func.count())
                    .select_from(CollectionRun)
                    .where(
                        CollectionRun.target_id == target.id,
                        CollectionRun.status.in_([RunStatus.QUEUED.value, RunStatus.RUNNING.value]),
                    )
                )
                if not active:
                    session.add(CollectionRun(target_id=target.id, trigger="scheduled"))
                target.next_collection_at = now + timedelta(
                    seconds=target.collection_interval_seconds
                )
            await session.commit()

    async def _claim_queued_runs(self, limit: int) -> list[str]:
        async with SessionFactory() as session:
            stmt = (
                select(CollectionRun)
                .where(CollectionRun.status == RunStatus.QUEUED.value)
                .order_by(CollectionRun.created_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            runs = list(await session.scalars(stmt))
            for run in runs:
                run.status = RunStatus.RUNNING.value
                run.worker_id = self.worker_id
                run.started_at = datetime.now(timezone.utc)
            await session.commit()
            return [run.id for run in runs]

    async def _execute(self, run_id: str) -> None:
        async with self._semaphore:
            async with SessionFactory() as session:
                run = await session.get(CollectionRun, run_id)
                if run is None:
                    return
                await collect_run(session, run, self.settings, self.cipher, self.worker_id)


async def async_main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    await Worker(settings).run_forever()


def run() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    run()
