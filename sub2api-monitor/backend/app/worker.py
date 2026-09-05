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
from app.models import CollectionRun, CostRoutingPolicy, RunStatus, Target, WorkerHeartbeat
from app.security import SecretCipher, ensure_admin
from app.services.automation import dispatch_automations
from app.services.collector import collect_run
from app.services.cost_routing import (
    COST_ROUTING_LEASE_SECONDS,
    claim_due_cost_routing_policies,
    reconcile_unknown_routing_decisions,
    renew_cost_routing_claim,
    run_cost_routing_policy,
)
from app.services.maintenance import purge_expired_history
from app.services.notifier import dispatch_due
from app.services.routing_observer import claim_due_route_observations, observe_target_routes

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.hostname = socket.gethostname()
        self.worker_id = f"{self.hostname}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.cipher = SecretCipher(settings.master_key)
        self._semaphore = asyncio.Semaphore(settings.worker_concurrency)
        self._routing_semaphore = asyncio.Semaphore(max(1, min(4, settings.worker_concurrency)))
        self._health_file = Path("/tmp/sub2api-monitor-worker-health")
        self._next_maintenance_at = 0.0
        initialized_at = datetime.now(timezone.utc)
        self._critical_loop_started_at: dict[str, datetime] = {}
        self._critical_loop_completed_at: dict[str, datetime] = {
            "main": initialized_at,
            "cost_routing": initialized_at,
        }

    async def run_forever(self) -> None:
        async with SessionFactory() as session:
            await ensure_admin(session, self.settings.admin_username, self.settings.admin_password)
        await self._recover_stale_runs(recover_same_host=True)
        logger.info("worker started", extra={"worker_id": self.worker_id})
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        cost_routing_task = asyncio.create_task(self._cost_routing_loop())
        routing_observation_task = asyncio.create_task(self._routing_observation_loop())
        try:
            while True:
                self._critical_loop_started_at["main"] = datetime.now(timezone.utc)
                try:
                    await self.tick()
                except Exception:
                    logger.exception("worker tick failed")
                finally:
                    self._critical_loop_started_at.pop("main", None)
                    self._critical_loop_completed_at["main"] = datetime.now(timezone.utc)
                await asyncio.sleep(self.settings.worker_poll_seconds)
        finally:
            heartbeat_task.cancel()
            cost_routing_task.cancel()
            routing_observation_task.cancel()
            await asyncio.gather(
                heartbeat_task, cost_routing_task, routing_observation_task, return_exceptions=True
            )

    async def tick(self) -> None:
        await self._recover_stale_runs()
        await self._schedule_due_targets()
        run_ids = await self._claim_queued_runs(self.settings.worker_concurrency)
        if run_ids:
            await asyncio.gather(*(self._execute(run_id) for run_id in run_ids))
        async with SessionFactory() as session:
            await dispatch_automations(session, self.settings, self.cipher)
            await dispatch_due(
                session,
                self.settings,
                self.cipher,
                claim_owner=self.worker_id,
            )
        await self._run_maintenance_if_due()

    async def _run_maintenance_if_due(self) -> None:
        loop = asyncio.get_running_loop()
        if loop.time() < self._next_maintenance_at:
            return
        async with SessionFactory() as session:
            await purge_expired_history(session, self.settings)
        self._next_maintenance_at = loop.time() + self.settings.maintenance_interval_seconds

    async def _cost_routing_loop(self) -> None:
        while True:
            self._critical_loop_started_at["cost_routing"] = datetime.now(timezone.utc)
            try:
                await self._cost_routing_tick()
            except Exception:
                logger.exception("cost routing tick failed")
            finally:
                self._critical_loop_started_at.pop("cost_routing", None)
                self._critical_loop_completed_at["cost_routing"] = datetime.now(timezone.utc)
            await asyncio.sleep(min(self.settings.worker_poll_seconds, 2.0))

    async def _cost_routing_tick(self) -> None:
        async with SessionFactory() as session:
            reconciled_count = await reconcile_unknown_routing_decisions(
                session,
                self.settings,
                self.cipher,
                actor=f"worker:{self.worker_id}",
                limit=self.settings.worker_concurrency,
            )
            policy_ids = await claim_due_cost_routing_policies(
                session,
                owner_id=self.worker_id,
                limit=self.settings.worker_concurrency,
            )
        if policy_ids:
            await asyncio.gather(
                *(self._execute_cost_routing(policy_id) for policy_id in policy_ids)
            )
        if reconciled_count or policy_ids:
            async with SessionFactory() as session:
                await dispatch_due(
                    session,
                    self.settings,
                    self.cipher,
                    claim_owner=self.worker_id,
                )

    async def _routing_observation_loop(self) -> None:
        while True:
            self._critical_loop_started_at["routing_observation"] = datetime.now(timezone.utc)
            try:
                async with SessionFactory() as session:
                    targets = await claim_due_route_observations(
                        session, self.worker_id, self.settings.worker_concurrency
                    )

                async def observe(target_id: str) -> None:
                    async with SessionFactory() as session:
                        await observe_target_routes(
                            session, target_id, self.settings, self.cipher, self.worker_id
                        )

                await asyncio.gather(*(observe(target_id) for target_id in targets))
                async with SessionFactory() as session:
                    await dispatch_due(
                        session, self.settings, self.cipher, claim_owner=self.worker_id
                    )
            except Exception:
                logger.exception("routing observation tick failed")
            finally:
                self._critical_loop_started_at.pop("routing_observation", None)
                self._critical_loop_completed_at["routing_observation"] = datetime.now(timezone.utc)
            await asyncio.sleep(min(self.settings.worker_poll_seconds, 2.0))

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await self._heartbeat()
            except Exception:
                logger.exception("worker heartbeat failed")
            await asyncio.sleep(min(self.settings.worker_poll_seconds, 5.0))

    async def _heartbeat(self) -> None:
        now = datetime.now(timezone.utc)
        stalled_cutoff = now - timedelta(seconds=self.settings.worker_stale_seconds)
        stalled_loops = sorted(
            name
            for name, started_at in self._critical_loop_started_at.items()
            if started_at < stalled_cutoff
        )
        async with SessionFactory() as session:
            heartbeat = await session.get(WorkerHeartbeat, self.worker_id)
            if heartbeat is None:
                heartbeat = WorkerHeartbeat(worker_id=self.worker_id)
                session.add(heartbeat)
            heartbeat.last_seen_at = now
            heartbeat.details = {
                "pid": os.getpid(),
                "version": "0.1.0",
                "critical_loop_stalled": stalled_loops,
                "critical_loop_started_at": {
                    name: value.isoformat()
                    for name, value in self._critical_loop_started_at.items()
                },
                "critical_loop_completed_at": {
                    name: value.isoformat()
                    for name, value in self._critical_loop_completed_at.items()
                },
            }
            await session.commit()
        if not stalled_loops:
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

    async def _execute_cost_routing(self, policy_id: str) -> None:
        async with self._routing_semaphore:
            renew_task = asyncio.create_task(self._renew_cost_routing_claim(policy_id))
            try:
                async with SessionFactory() as session:
                    await run_cost_routing_policy(
                        session,
                        policy_id,
                        self.settings,
                        self.cipher,
                        actor=f"worker:{self.worker_id}",
                        claim_owner=self.worker_id,
                        execution_mode_guard=self._cost_routing_execution_mode,
                    )
            finally:
                renew_task.cancel()
                await asyncio.gather(renew_task, return_exceptions=True)

    async def _renew_cost_routing_claim(self, policy_id: str) -> None:
        interval = COST_ROUTING_LEASE_SECONDS / 3
        while True:
            await asyncio.sleep(interval)
            async with SessionFactory() as session:
                renewed = await renew_cost_routing_claim(session, policy_id, self.worker_id)
            if not renewed:
                return

    async def _cost_routing_execution_mode(
        self,
        policy_id: str,
        claim_owner: str | None,
    ) -> str | None:
        async with SessionFactory() as session:
            policy = await session.get(CostRoutingPolicy, policy_id)
            if policy is None or not policy.enabled:
                return None
            if claim_owner is not None and policy.lease_owner != claim_owner:
                return None
            return policy.mode


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
