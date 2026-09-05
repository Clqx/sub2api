from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import (
    ConnectorError,
    NormalizedAccount,
    Sub2APIConnector,
    sanitize_monitoring_error,
    sanitize_upstream_billing_snapshot,
)
from app.models import (
    AccountCurrent,
    AuditEvent,
    CostRoutingPolicy,
    RoutingDecision,
    Target,
    uuid_str,
)
from app.security import SecretCipher
from app.services.monitoring import supports_upstream_billing_probe
from app.services.policies import (
    evaluate_account,
    evaluate_cost_routing_run,
    evaluate_routing_action,
    evaluate_upstream_probe_health,
    evaluate_upstream_rate_change,
    upstream_rate_multiplier,
)
from app.services.routing_usage import queue_rate_recovered
from app.services.targets import connector_for_target, target_with_secret

logger = logging.getLogger(__name__)

BATCH_PROBE_LIMIT = 20
PROBE_BATCH_CONCURRENCY = 10
PRIORITY_WRITE_CONCURRENCY = 20
COST_ROUTING_LEASE_SECONDS = 90
COST_ROUTING_RUN_BUDGET_SECONDS = 25.0
COST_ROUTING_INVENTORY_TIMEOUT_SECONDS = 8.0
COST_ROUTING_WRITE_TIMEOUT_SECONDS = 5.0
COST_ROUTING_WRITE_RESERVE_SECONDS = 6.0
COST_ROUTING_RECONCILIATION_LEASE_SECONDS = 30
COST_ROUTING_RECONCILIATION_MISMATCH_LIMIT = 3

ExecutionModeGuard = Callable[[str, str | None], Awaitable[str | None]]


class CostRoutingCancelled(RuntimeError):
    pass


@dataclass(slots=True)
class AccountRoutingPlan:
    account: AccountCurrent
    previous_multiplier: float | None
    multiplier: float | None
    previous_priority: int | None
    desired_priority: int
    reason: str
    cost_signal_ok: bool
    cost_source: str | None
    quality_failures: list[str]
    fallback_protected: bool
    control: dict[str, Any]
    decision: RoutingDecision | None = None


def desired_priority(
    multiplier: float | None,
    *,
    healthy: bool,
    priority_scale: int,
    minimum_priority: int,
    unhealthy_priority: int,
    maximum_multiplier: float = 1.0,
) -> int:
    if not healthy or multiplier is None or not math.isfinite(multiplier) or multiplier < 0:
        return unhealthy_priority
    if multiplier >= maximum_multiplier:
        return unhealthy_priority
    calculated = max(minimum_priority, round(multiplier * priority_scale))
    return min(calculated, unhealthy_priority - 1)


def routing_rate_multiplier(
    snapshot: dict[str, Any] | None,
    configured_multiplier: float | None,
) -> tuple[float | None, str | None]:
    """Resolve a trusted cost signal and identify its source."""
    status = snapshot.get("status") if isinstance(snapshot, dict) else None
    probed_multiplier = upstream_rate_multiplier(snapshot)
    if status == "ok" and probed_multiplier is not None:
        return probed_multiplier, "upstream_probe"

    # Unsupported is an expected capability gap. Other failures stay closed.
    if status != "unsupported":
        return None, None
    if (
        configured_multiplier is None
        or isinstance(configured_multiplier, bool)
        or not isinstance(configured_multiplier, (int, float))
    ):
        return None, None
    value = float(configured_multiplier)
    if not math.isfinite(value) or value < 0:
        return None, None
    return value, "account_config"


async def claim_due_cost_routing_policies(
    session: AsyncSession,
    *,
    owner_id: str,
    limit: int = 20,
) -> list[str]:
    now = datetime.now(timezone.utc)
    policies = list(
        await session.scalars(
            select(CostRoutingPolicy)
            .join(Target, Target.id == CostRoutingPolicy.target_id)
            .where(
                CostRoutingPolicy.enabled.is_(True),
                Target.enabled.is_(True),
                or_(
                    CostRoutingPolicy.lease_until.is_(None),
                    CostRoutingPolicy.lease_until <= now,
                ),
                or_(
                    CostRoutingPolicy.next_run_at.is_(None),
                    CostRoutingPolicy.next_run_at <= now,
                ),
            )
            .order_by(CostRoutingPolicy.next_run_at, CostRoutingPolicy.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for policy in policies:
        policy.lease_owner = owner_id
        policy.lease_until = now + timedelta(seconds=COST_ROUTING_LEASE_SECONDS)
        policy.next_run_at = now + timedelta(seconds=policy.probe_interval_seconds)
    if policies:
        await session.commit()
    return [policy.id for policy in policies]


async def renew_cost_routing_claim(
    session: AsyncSession,
    policy_id: str,
    owner_id: str,
) -> bool:
    now = datetime.now(timezone.utc)
    renewed_policy_id = await session.scalar(
        update(CostRoutingPolicy)
        .where(
            CostRoutingPolicy.id == policy_id,
            CostRoutingPolicy.lease_owner == owner_id,
            CostRoutingPolicy.enabled.is_(True),
        )
        .values(lease_until=now + timedelta(seconds=COST_ROUTING_LEASE_SECONDS))
        .returning(CostRoutingPolicy.id)
    )
    await session.commit()
    return renewed_policy_id is not None


async def reconcile_unknown_routing_decisions(
    session: AsyncSession,
    settings: Settings,
    cipher: SecretCipher,
    *,
    actor: str,
    limit: int = 20,
) -> int:
    """Reconcile uncertain writes without running the cost-routing policy."""
    if limit <= 0:
        return 0

    now = datetime.now(timezone.utc)
    claim_id = uuid_str()
    candidates = list(
        await session.scalars(
            select(RoutingDecision)
            .where(RoutingDecision.status == "running", RoutingDecision.target_id.is_not(None))
            .order_by(RoutingDecision.created_at, RoutingDecision.id)
            .with_for_update(skip_locked=True)
        )
    )
    claimed: list[tuple[str, str]] = []
    for decision in candidates:
        result = decision.result if isinstance(decision.result, dict) else {}
        if result.get("outcome_unknown") is not True:
            continue
        if not _reconciliation_claim_expired(result.get("reconcile_lease_until"), now):
            continue
        target_id = decision.target_id
        if target_id is None:
            continue
        decision.result = {
            **result,
            "reconcile_claim_id": claim_id,
            "reconcile_lease_until": (
                now + timedelta(seconds=COST_ROUTING_RECONCILIATION_LEASE_SECONDS)
            ).isoformat(),
        }
        claimed.append((decision.id, target_id))
        if len(claimed) >= limit:
            break
    if not claimed:
        await session.commit()
        return 0
    await session.commit()

    target_ids = sorted({target_id for _, target_id in claimed})
    targets: dict[str, Target] = {}
    target_errors: dict[str, str] = {}
    for target_id in target_ids:
        target = await target_with_secret(session, target_id)
        if target is None:
            target_errors[target_id] = "target no longer exists"
        else:
            targets[target_id] = target

    async def read_priorities(
        target: Target,
    ) -> tuple[str, dict[str, NormalizedAccount] | None, str | None]:
        try:
            connector = await connector_for_target(session, target, settings, cipher)
            async with connector:
                fact, inventory = await asyncio.wait_for(
                    connector.accounts(), timeout=COST_ROUTING_INVENTORY_TIMEOUT_SECONDS
                )
            if fact.runtime_state != "healthy":
                reason = sanitize_monitoring_error(
                    fact.reason or "account inventory unavailable",
                    limit=500,
                )
                return target.id, None, reason
            return (
                target.id,
                {item.external_account_id: item for item in inventory},
                None,
            )
        except Exception as exc:
            return target.id, None, _safe_error(exc)

    inventory_results = await asyncio.gather(
        *(read_priorities(target) for target in targets.values())
    )
    priorities_by_target: dict[str, dict[str, NormalizedAccount]] = {}
    for target_id, priorities, error in inventory_results:
        if priorities is None:
            target_errors[target_id] = error or "account inventory unavailable"
        else:
            priorities_by_target[target_id] = priorities

    reconciled = 0
    completed_at = datetime.now(timezone.utc)
    claimed_ids = [decision_id for decision_id, _ in claimed]
    claimed_decisions = list(
        await session.scalars(
            select(RoutingDecision)
            .where(RoutingDecision.id.in_(claimed_ids))
            .order_by(RoutingDecision.created_at, RoutingDecision.id)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    for decision in claimed_decisions:
        result = decision.result if isinstance(decision.result, dict) else {}
        if decision.status != "running" or result.get("reconcile_claim_id") != claim_id:
            continue
        target_id = decision.target_id
        target = targets.get(target_id or "")
        priorities = priorities_by_target.get(target_id or "")
        error = target_errors.get(target_id or "")
        actual_account = priorities.get(decision.external_account_id) if priorities else None
        actual_priority = actual_account.priority if actual_account else None
        control_matches = "required_control" not in result or (
            actual_account is not None
            and actual_account.routing_control == result["required_control"]
        )
        next_result = {
            key: value
            for key, value in result.items()
            if key not in {"reconcile_claim_id", "reconcile_lease_until"}
        }
        next_result["reconcile_last_attempt_at"] = completed_at.isoformat()
        if error is not None:
            next_result["reconcile_last_error"] = error
            logger.warning(
                "cost routing reconciliation unavailable target_id=%s account_id=%s "
                "decision_id=%s error=%s",
                target_id,
                decision.external_account_id,
                decision.id,
                error,
            )
        elif decision.external_account_id not in (priorities or {}):
            next_result["reconcile_last_error"] = "account missing from fresh inventory"
            logger.warning(
                "cost routing reconciliation account missing target_id=%s account_id=%s "
                "decision_id=%s",
                target_id,
                decision.external_account_id,
                decision.id,
            )
        elif actual_priority != decision.desired_priority or not control_matches:
            next_result, mismatch_attempts, terminal = _record_reconciliation_mismatch(
                next_result,
                actual_priority=actual_priority,
                attempted_at=completed_at,
            )
            if terminal:
                decision.status = "failed"
                decision.last_error = next_result["reconcile_last_error"]
                decision.finished_at = completed_at
                session.add(
                    AuditEvent(
                        actor=actor,
                        action="cost_routing.priority.reconciliation_failed",
                        target_id=target_id,
                        details={
                            "decision_id": decision.id,
                            "account_id": decision.external_account_id,
                            "desired_priority": decision.desired_priority,
                            "actual_priority": actual_priority,
                            "mismatch_attempts": mismatch_attempts,
                        },
                    )
                )
                logger.warning(
                    "cost routing reconciliation failed target_id=%s account_id=%s "
                    "actual_priority=%s desired_priority=%s attempts=%s decision_id=%s",
                    target_id,
                    decision.external_account_id,
                    actual_priority,
                    decision.desired_priority,
                    mismatch_attempts,
                    decision.id,
                )
            else:
                logger.info(
                    "cost routing reconciliation pending target_id=%s account_id=%s "
                    "actual_priority=%s desired_priority=%s attempts=%s decision_id=%s",
                    target_id,
                    decision.external_account_id,
                    actual_priority,
                    decision.desired_priority,
                    mismatch_attempts,
                    decision.id,
                )
        else:
            next_result.pop("reconcile_last_error", None)
            next_result.pop("reconcile_actual_priority", None)
            next_result["actual_priority"] = actual_priority
            next_result["reconciled_after_interruption"] = True
            decision.status = "succeeded"
            decision.last_error = None
            decision.finished_at = completed_at
            if (
                target is not None
                and decision.reason == "cost_decrease"
                and decision.observed_multiplier is not None
            ):
                await _queue_reconciled_rate_recovery(
                    session,
                    decision,
                    target_name=target.name,
                    occurred_at=completed_at,
                )
            session.add(
                AuditEvent(
                    actor=actor,
                    action="cost_routing.priority.reconciled",
                    target_id=target_id,
                    details={
                        "decision_id": decision.id,
                        "account_id": decision.external_account_id,
                        "desired_priority": decision.desired_priority,
                        "actual_priority": actual_priority,
                    },
                )
            )
            reconciled += 1
            logger.info(
                "cost routing reconciliation succeeded target_id=%s account_id=%s "
                "priority=%s decision_id=%s",
                target_id,
                decision.external_account_id,
                actual_priority,
                decision.id,
            )
        decision.result = next_result
    await session.commit()
    return reconciled


async def run_cost_routing_policy(
    session: AsyncSession,
    policy_id: str,
    settings: Settings,
    cipher: SecretCipher,
    *,
    actor: str,
    claim_owner: str | None = None,
    execution_mode_guard: ExecutionModeGuard | None = None,
) -> bool:
    loop = asyncio.get_running_loop()
    run_deadline = loop.time() + COST_ROUTING_RUN_BUDGET_SECONDS
    policy = await session.get(CostRoutingPolicy, policy_id)
    if policy is None:
        return False
    if claim_owner is not None and policy.lease_owner != claim_owner:
        return False
    if not policy.enabled:
        _release_claim(policy, claim_owner)
        await session.commit()
        return False
    target_id = policy.target_id
    target = await target_with_secret(session, target_id)
    if target is None:
        return False
    try:
        if not target.enabled or target.monitoring_readiness != "ready":
            raise RuntimeError("target is not ready for cost routing")
        connector = await connector_for_target(session, target, settings, cipher)
        async with connector:
            inventory_fact, inventory = await _load_routing_inventory(connector)
            if inventory_fact.runtime_state != "healthy":
                raise RuntimeError(inventory_fact.reason or "account inventory unavailable")
            await _recover_interrupted_routing_decisions(
                session,
                policy,
                actor,
                target_name=target.name,
                actual_priorities={item.external_account_id: item.priority for item in inventory},
                actual_controls={
                    item.external_account_id: item.routing_control for item in inventory
                },
            )
            unresolved_account_ids = {
                decision.external_account_id
                for decision in await session.scalars(
                    select(RoutingDecision).where(
                        RoutingDecision.policy_id == policy.id,
                        RoutingDecision.status == "running",
                    )
                )
                if decision.result.get("outcome_unknown") is True
            }
            previous_accounts = list(
                await session.scalars(
                    select(AccountCurrent)
                    .where(AccountCurrent.target_id == target.id)
                    .order_by(AccountCurrent.external_account_id)
                )
            )
            previous_available = {
                account.external_account_id: account.available for account in previous_accounts
            }
            previous_multipliers = {
                account.external_account_id: routing_rate_multiplier(
                    account.upstream_billing_probe,
                    account.rate_multiplier,
                )[0]
                for account in previous_accounts
            }
            accounts = await _sync_inventory_accounts(session, target.id, inventory)
            eligible = [account for account in accounts if supports_upstream_billing_probe(account)]
            inventory_by_id = {
                item.external_account_id: item
                for item in inventory
                if item.platform.casefold() == "openai" and item.account_type.casefold() == "apikey"
            }
            probe_ids = [
                account.external_account_id
                for account in eligible
                if account.external_account_id in inventory_by_id
            ]
            probe_budget = run_deadline - loop.time() - COST_ROUTING_WRITE_RESERVE_SECONDS
            if probe_budget <= 0:
                raise TimeoutError("cost routing inventory exceeded the observation budget")
            result_by_id = await asyncio.wait_for(
                _probe_billing_batches(connector, probe_ids),
                timeout=probe_budget,
            )

            current_mode = await _current_execution_mode(
                session,
                policy,
                claim_owner,
                execution_mode_guard,
            )
            if current_mode is None:
                raise CostRoutingCancelled("cost routing was disabled while probing")
            policy.mode = current_mode

            now = datetime.now(timezone.utc)
            # V1 model probes are retired. Keep stored bindings for a future
            # passive-quality design, but never let stale probe state suppress traffic.
            quality_by_account: dict[str, list[str]] = {}
            plans: list[AccountRoutingPlan] = []
            for account in eligible:
                external_account_id = account.external_account_id
                prior_multiplier = previous_multipliers.get(external_account_id)
                was_available = previous_available.get(external_account_id, account.available)
                probe_result = result_by_id.get(account.external_account_id)
                raw_snapshot = (
                    probe_result.get("snapshot")
                    if isinstance(probe_result, dict)
                    and isinstance(probe_result.get("snapshot"), dict)
                    else None
                )
                snapshot = sanitize_upstream_billing_snapshot(raw_snapshot)
                if snapshot is None:
                    snapshot = {
                        "status": "failed",
                        "last_attempt_at": now.isoformat(),
                        "last_error": _result_error(probe_result),
                    }
                account.upstream_billing_probe = snapshot
                synced = snapshot.get("synced_rate_multiplier")
                if isinstance(synced, (int, float)) and not isinstance(synced, bool):
                    account.rate_multiplier = float(synced)
                multiplier, cost_source = routing_rate_multiplier(
                    snapshot,
                    account.rate_multiplier,
                )
                cost_signal_ok = cost_source is not None
                quality_failures = quality_by_account.get(external_account_id, [])
                fallback_protected = (
                    external_account_id in policy.fallback_account_ids
                    and account.available
                    and not quality_failures
                )
                if fallback_protected:
                    baseline = policy.fallback_priorities.get(
                        external_account_id, policy.minimum_priority
                    )
                    wanted = max(
                        policy.minimum_priority,
                        min(int(baseline), policy.unhealthy_priority - 1),
                    )
                else:
                    healthy = account.available and cost_signal_ok and not quality_failures
                    wanted = desired_priority(
                        multiplier,
                        healthy=healthy,
                        priority_scale=policy.priority_scale,
                        minimum_priority=policy.minimum_priority,
                        unhealthy_priority=policy.unhealthy_priority,
                        maximum_multiplier=policy.maximum_multiplier,
                    )
                control = {
                    "version": 1,
                    "unhealthy_priority": policy.unhealthy_priority,
                    "fallback": external_account_id in policy.fallback_account_ids,
                    "suppressed": wanted >= policy.unhealthy_priority,
                }
                source_account = inventory_by_id.get(external_account_id)
                control_matches = (
                    source_account is not None and source_account.routing_control == control
                )
                reason = _routing_reason(
                    account=account,
                    was_available=was_available,
                    previous_multiplier=prior_multiplier,
                    multiplier=multiplier,
                    cost_signal_ok=cost_signal_ok,
                    quality_failures=quality_failures,
                    fallback_protected=fallback_protected,
                    desired=wanted,
                )
                previous_desired_priority = account.routing_desired_priority
                previous_routing_status = account.routing_status
                account.routing_desired_priority = wanted
                account.routing_updated_at = now
                if external_account_id in unresolved_account_ids:
                    account.routing_status = "outcome_unknown"
                else:
                    account.routing_status = (
                        "in_sync" if account.priority == wanted and control_matches else policy.mode
                    )
                plan = AccountRoutingPlan(
                    account=account,
                    previous_multiplier=prior_multiplier,
                    multiplier=multiplier,
                    previous_priority=account.priority,
                    desired_priority=wanted,
                    reason=reason,
                    cost_signal_ok=cost_signal_ok,
                    cost_source=cost_source,
                    quality_failures=quality_failures,
                    fallback_protected=fallback_protected,
                    control=control,
                )
                logger.info(
                    "cost routing account evaluated policy_id=%s target_id=%s "
                    "account_id=%s multiplier=%s cost_source=%s available=%s "
                    "fallback_protected=%s previous_priority=%s desired_priority=%s "
                    "reason=%s desired_suppressed=%s",
                    policy.id,
                    target.id,
                    external_account_id,
                    multiplier,
                    cost_source or "none",
                    account.available,
                    fallback_protected,
                    account.priority,
                    wanted,
                    reason,
                    control["suppressed"],
                )
                should_record_decision = (
                    external_account_id not in unresolved_account_ids
                    and (account.priority != wanted or not control_matches)
                    and (
                        policy.mode == "execute"
                        or previous_desired_priority != wanted
                        or previous_routing_status not in {"recommend", "recommended"}
                    )
                )
                if should_record_decision:
                    decision = RoutingDecision(
                        id=uuid_str(),
                        policy_id=policy.id,
                        target_id=target.id,
                        external_account_id=account.external_account_id,
                        account_name=account.name,
                        observed_multiplier=multiplier,
                        previous_priority=account.priority,
                        desired_priority=wanted,
                        reason=reason,
                        mode=policy.mode,
                        status="recommended" if policy.mode == "recommend" else "running",
                        result={
                            "cost_source": cost_source,
                            "required_control": control,
                            **(
                                {"previous_multiplier": prior_multiplier}
                                if prior_multiplier is not None
                                else {}
                            ),
                            **({"fallback_protected": True} if fallback_protected else {}),
                            **({"quality_failures": quality_failures} if quality_failures else {}),
                        },
                        finished_at=now if policy.mode == "recommend" else None,
                    )
                    session.add(decision)
                    plan.decision = decision
                plans.append(plan)

            execute_plans = [
                plan for plan in plans if plan.decision is not None and policy.mode == "execute"
            ]
            if execute_plans:
                for plan in execute_plans:
                    routing_decision = plan.decision
                    if routing_decision is None:
                        continue
                    session.add(
                        AuditEvent(
                            actor=actor,
                            action="cost_routing.priority.started",
                            target_id=target.id,
                            details={
                                "decision_id": routing_decision.id,
                                "account_id": plan.account.external_account_id,
                                "previous_priority": plan.previous_priority,
                                "desired_priority": plan.desired_priority,
                                "reason": plan.reason,
                                "cost_source": plan.cost_source,
                            },
                        )
                    )
                # Persist intent before the first external write. A crash can leave
                # an interrupted decision, but never an untracked target mutation.
                await session.commit()
                semaphore = asyncio.Semaphore(PRIORITY_WRITE_CONCURRENCY)

                async def apply_priority(
                    plan: AccountRoutingPlan,
                ) -> tuple[
                    AccountRoutingPlan,
                    dict[str, Any] | None,
                    str | None,
                    bool,
                    bool,
                ]:
                    async with semaphore:
                        latest_mode = await _current_execution_mode(
                            session,
                            policy,
                            claim_owner,
                            execution_mode_guard,
                            refresh_session=False,
                        )
                        if latest_mode != "execute":
                            return plan, None, None, True, False
                        remaining = run_deadline - loop.time()
                        if remaining <= 0:
                            return (
                                plan,
                                None,
                                "cost routing write deadline exceeded",
                                False,
                                False,
                            )
                        try:
                            result = await asyncio.wait_for(
                                connector.set_account_priority(
                                    plan.account.external_account_id,
                                    plan.desired_priority,
                                    control=plan.control,
                                ),
                                timeout=min(COST_ROUTING_WRITE_TIMEOUT_SECONDS, remaining),
                            )
                            return plan, result, None, False, False
                        except ConnectorError as exc:
                            # Explicit client-side rejection (e.g. old target without
                            # enforcement) is not an uncertain applied mutation.
                            unknown = (
                                exc.status_code is None
                                or exc.status_code >= 500
                                or exc.status_code in {408, 429}
                            )
                            return plan, None, _safe_error(exc), False, unknown
                        except Exception as exc:
                            # Once the connector call starts, an exception cannot prove
                            # that the upstream rejected the mutation. Reconcile it
                            # against fresh inventory before retrying or notifying.
                            return plan, None, _safe_error(exc), False, True

                outcomes = await asyncio.gather(*(apply_priority(plan) for plan in execute_plans))
                for plan, priority_result, error, cancelled, outcome_unknown in outcomes:
                    routing_decision = plan.decision
                    if routing_decision is None:
                        continue
                    outcome_at = datetime.now(timezone.utc)
                    routing_decision.finished_at = None if outcome_unknown else outcome_at
                    audit_status = routing_decision.status
                    if cancelled:
                        routing_decision.status = "cancelled"
                        plan.account.routing_status = "cancelled"
                    elif error is None:
                        routing_decision.status = "succeeded"
                        routing_decision.result = {
                            **routing_decision.result,
                            **(priority_result or {}),
                        }
                        plan.account.priority = plan.desired_priority
                        plan.account.routing_status = "succeeded"
                        plan.account.routing_applied_at = outcome_at
                        if (
                            plan.reason == "cost_decrease"
                            and plan.previous_multiplier is not None
                            and plan.multiplier is not None
                        ):
                            await queue_rate_recovered(
                                session,
                                target_id=target.id,
                                target_name=target.name,
                                account_id=plan.account.external_account_id,
                                account_name=plan.account.name,
                                previous_multiplier=plan.previous_multiplier,
                                multiplier=plan.multiplier,
                                previous_priority=plan.previous_priority,
                                priority=plan.desired_priority,
                                occurred_at=outcome_at,
                                decision_id=routing_decision.id,
                            )
                            logger.info(
                                "cost routing rate recovered target_id=%s account_id=%s "
                                "multiplier=%s->%s priority=%s->%s decision_id=%s",
                                target.id,
                                plan.account.external_account_id,
                                plan.previous_multiplier,
                                plan.multiplier,
                                plan.previous_priority,
                                plan.desired_priority,
                                routing_decision.id,
                            )
                    elif outcome_unknown:
                        routing_decision.result = {
                            **routing_decision.result,
                            "outcome_unknown": True,
                        }
                        routing_decision.last_error = error
                        plan.account.routing_status = "running"
                        audit_status = "outcome_unknown"
                    else:
                        routing_decision.status = "failed"
                        routing_decision.last_error = error
                        plan.account.routing_status = "failed"
                    if audit_status == "running":
                        audit_status = routing_decision.status
                    logger.info(
                        "cost routing priority write policy_id=%s target_id=%s "
                        "account_id=%s previous_priority=%s desired_priority=%s "
                        "cost_source=%s status=%s applied_suppressed=%s error=%s",
                        policy.id,
                        target.id,
                        plan.account.external_account_id,
                        plan.previous_priority,
                        plan.desired_priority,
                        plan.cost_source or "none",
                        routing_decision.status,
                        (
                            plan.control["suppressed"]
                            if routing_decision.status == "succeeded"
                            else None
                        ),
                        error or "none",
                    )
                    session.add(
                        AuditEvent(
                            actor=actor,
                            action=f"cost_routing.priority.{audit_status}",
                            target_id=target.id,
                            details={
                                "decision_id": routing_decision.id,
                                "account_id": plan.account.external_account_id,
                                "previous_priority": plan.previous_priority,
                                "desired_priority": plan.desired_priority,
                                "reason": plan.reason,
                                "cost_source": plan.cost_source,
                                "quality_failures": plan.quality_failures,
                                "error": error,
                            },
                        )
                    )
                # External writes cannot be rolled back. Persist their outcomes and
                # notification outbox before later incident/usage evaluation.
                await session.commit()

            for plan in plans:
                await evaluate_account(session, target.name, plan.account, [])
                await evaluate_upstream_rate_change(
                    session,
                    target.name,
                    plan.account,
                    plan.previous_multiplier,
                )
                await evaluate_upstream_probe_health(session, target.name, plan.account)
                await _evaluate_routing_incidents(session, target, policy, plan)

        policy.last_run_at = datetime.now(timezone.utc)
        policy.last_error = None
        policy.last_account_count = len(plans)
        policy.last_change_count = sum(
            plan.decision is not None and plan.decision.status == "succeeded" for plan in plans
        )
        retention_cutoff = datetime.now(timezone.utc) - timedelta(
            days=settings.cost_routing_decision_retention_days
        )
        await session.execute(
            delete(RoutingDecision)
            .where(RoutingDecision.created_at < retention_cutoff)
            .execution_options(synchronize_session="fetch")
        )
        await evaluate_cost_routing_run(session, target.id, target.name, None)
        _release_claim(policy, claim_owner)
        session.add(
            AuditEvent(
                actor=actor,
                action="cost_routing.run.succeeded",
                target_id=target.id,
                details={
                    "policy_id": policy.id,
                    "mode": policy.mode,
                    "account_count": policy.last_account_count,
                    "change_count": policy.last_change_count,
                },
            )
        )
        await session.commit()
        logger.info(
            "cost routing run succeeded policy_id=%s target_id=%s mode=%s "
            "account_count=%s change_count=%s",
            policy.id,
            target.id,
            policy.mode,
            policy.last_account_count,
            policy.last_change_count,
        )
        return True
    except CostRoutingCancelled as exc:
        reason = _safe_error(exc)
        logger.info(
            "cost routing run cancelled policy_id=%s target_id=%s reason=%s",
            policy_id,
            target_id,
            reason,
        )
        await session.rollback()
        cancelled_policy = await session.get(CostRoutingPolicy, policy_id)
        if cancelled_policy is not None:
            cancelled_policy.last_run_at = datetime.now(timezone.utc)
            cancelled_policy.last_error = None
            cancelled_policy.last_account_count = 0
            cancelled_policy.last_change_count = 0
            _release_claim(cancelled_policy, claim_owner)
        session.add(
            AuditEvent(
                actor=actor,
                action="cost_routing.run.cancelled",
                target_id=target_id,
                details={"policy_id": policy_id, "reason": reason},
            )
        )
        await session.commit()
        return False
    except Exception as exc:
        error = _safe_error(exc)
        logger.exception(
            "cost routing run failed policy_id=%s target_id=%s error_type=%s",
            policy_id,
            target_id,
            exc.__class__.__name__,
        )
        await session.rollback()
        failed_policy = await session.get(CostRoutingPolicy, policy_id)
        failed_target = await session.get(Target, target_id)
        if failed_policy is not None:
            failed_policy.last_run_at = datetime.now(timezone.utc)
            failed_policy.last_error = error
            failed_policy.last_account_count = 0
            failed_policy.last_change_count = 0
            _release_claim(failed_policy, claim_owner)
        if failed_target is not None:
            await evaluate_cost_routing_run(
                session,
                failed_target.id,
                failed_target.name,
                error,
            )
        session.add(
            AuditEvent(
                actor=actor,
                action="cost_routing.run.failed",
                target_id=target_id,
                details={"policy_id": policy_id, "error": error},
            )
        )
        await session.commit()
        return False


async def _load_routing_inventory(
    connector: Sub2APIConnector,
) -> tuple[Any, list[NormalizedAccount]]:
    account_result = await asyncio.wait_for(
        connector.accounts(), timeout=COST_ROUTING_INVENTORY_TIMEOUT_SECONDS
    )
    account_fact, accounts = account_result
    return account_fact, accounts


async def _sync_inventory_accounts(
    session: AsyncSession,
    target_id: str,
    inventory: list[NormalizedAccount],
) -> list[AccountCurrent]:
    inventory_by_id = {item.external_account_id: item for item in inventory}
    current_ids = set(
        await session.scalars(
            select(AccountCurrent.external_account_id).where(AccountCurrent.target_id == target_id)
        )
    )
    missing = [
        item
        for item in inventory
        if item.external_account_id not in current_ids
        and item.platform.casefold() == "openai"
        and item.account_type.casefold() == "apikey"
    ]
    if missing:
        values = [_new_account_values(target_id, item) for item in missing]
        dialect = session.get_bind().dialect.name
        if dialect == "sqlite":
            await session.execute(
                sqlite_insert(AccountCurrent)
                .values(values)
                .on_conflict_do_nothing(index_elements=["target_id", "external_account_id"])
            )
        elif dialect == "postgresql":
            await session.execute(
                postgresql_insert(AccountCurrent)
                .values(values)
                .on_conflict_do_nothing(index_elements=["target_id", "external_account_id"])
            )
        else:
            raise RuntimeError(
                f"unsupported monitor database dialect for inventory sync: {dialect}"
            )
        await session.commit()

    accounts = list(
        await session.scalars(
            select(AccountCurrent)
            .where(AccountCurrent.target_id == target_id)
            .order_by(AccountCurrent.external_account_id)
        )
    )
    for account in accounts:
        source = inventory_by_id.get(account.external_account_id)
        if source is not None:
            _apply_inventory(account, source)
        elif supports_upstream_billing_probe(account):
            account.available = False
            account.availability_reasons = ["missing_from_inventory"]
    await session.commit()
    return accounts


def _new_account_values(target_id: str, source: NormalizedAccount) -> dict[str, Any]:
    return {
        "id": uuid_str(),
        "target_id": target_id,
        "external_account_id": source.external_account_id,
        "name": source.name,
        "platform": source.platform,
        "account_type": source.account_type,
        "status": source.status,
        "schedulable": source.schedulable,
        "available": source.available,
        "availability_reasons": source.availability_reasons,
        "group_ids": source.group_ids,
        "priority": source.priority,
        "rate_multiplier": source.rate_multiplier,
        "upstream_billing_probe_enabled": source.upstream_billing_probe_enabled,
        "upstream_billing_rate_sync_enabled": source.upstream_billing_rate_sync_enabled,
        "upstream_billing_probe": source.upstream_billing_probe,
        "expires_at": source.expires_at,
        "rate_limit_reset_at": source.rate_limit_reset_at,
        "overload_until": source.overload_until,
        "temp_unschedulable_until": source.temp_unschedulable_until,
        "observed_at": source.observed_at,
        "last_seen_at": datetime.now(timezone.utc),
    }


async def _probe_billing_batches(
    connector: Sub2APIConnector,
    account_ids: list[str],
) -> dict[str, dict[str, Any]]:
    semaphore = asyncio.Semaphore(PROBE_BATCH_CONCURRENCY)

    async def probe_chunk(chunk: list[str]) -> list[dict[str, Any]]:
        async with semaphore:
            return await connector.probe_upstream_billing_batch(chunk)

    chunks = [
        account_ids[offset : offset + BATCH_PROBE_LIMIT]
        for offset in range(0, len(account_ids), BATCH_PROBE_LIMIT)
    ]
    batches = await asyncio.gather(*(probe_chunk(chunk) for chunk in chunks))
    result_by_id: dict[str, dict[str, Any]] = {}
    for results in batches:
        for result in results:
            account_id = result.get("account_id")
            if isinstance(account_id, (str, int)):
                result_by_id[str(account_id)] = result
    return result_by_id


async def _current_execution_mode(
    session: AsyncSession,
    policy: CostRoutingPolicy,
    claim_owner: str | None,
    execution_mode_guard: ExecutionModeGuard | None,
    *,
    refresh_session: bool = True,
) -> str | None:
    if execution_mode_guard is not None:
        return await execution_mode_guard(policy.id, claim_owner)
    if refresh_session:
        await session.refresh(policy, attribute_names=["enabled", "mode", "lease_owner"])
    if not policy.enabled:
        return None
    if claim_owner is not None and policy.lease_owner != claim_owner:
        return None
    return policy.mode


def _apply_inventory(account: AccountCurrent, source: NormalizedAccount) -> None:
    account.name = source.name
    account.platform = source.platform
    account.account_type = source.account_type
    account.status = source.status
    account.schedulable = source.schedulable
    account.available = source.available
    account.availability_reasons = source.availability_reasons
    account.group_ids = source.group_ids
    if source.priority is not None:
        account.priority = source.priority
    account.rate_multiplier = source.rate_multiplier
    account.upstream_billing_probe_enabled = source.upstream_billing_probe_enabled
    account.upstream_billing_rate_sync_enabled = source.upstream_billing_rate_sync_enabled
    account.expires_at = source.expires_at
    account.rate_limit_reset_at = source.rate_limit_reset_at
    account.overload_until = source.overload_until
    account.temp_unschedulable_until = source.temp_unschedulable_until
    account.observed_at = source.observed_at
    account.last_seen_at = datetime.now(timezone.utc)


def _routing_reason(
    *,
    account: AccountCurrent,
    was_available: bool,
    previous_multiplier: float | None,
    multiplier: float | None,
    cost_signal_ok: bool,
    quality_failures: list[str],
    fallback_protected: bool,
    desired: int,
) -> str:
    if not account.available:
        return "unavailable"
    if quality_failures:
        return "quality_failed"
    if fallback_protected:
        return "fallback_protected"
    if not cost_signal_ok:
        return "probe_failed"
    if not was_available:
        return "recovery"
    if previous_multiplier is None:
        return "cost_discovered"
    if multiplier is not None and not math.isclose(
        previous_multiplier, multiplier, rel_tol=1e-9, abs_tol=1e-9
    ):
        return "cost_increase" if multiplier > previous_multiplier else "cost_decrease"
    if account.priority != desired:
        return "priority_reconcile"
    return "in_sync"


async def _evaluate_routing_incidents(
    session: AsyncSession,
    target: Target,
    policy: CostRoutingPolicy,
    plan: AccountRoutingPlan,
) -> None:
    decision = plan.decision
    recommended = policy.mode == "recommend" and plan.previous_priority != plan.desired_priority
    changed = decision is not None and decision.status == "succeeded"
    failed = decision is not None and decision.status == "failed"
    detail = ", ".join(plan.quality_failures) if plan.quality_failures else None
    await evaluate_routing_action(
        session,
        target_id=target.id,
        target_name=target.name,
        account_id=plan.account.external_account_id,
        account_name=plan.account.name,
        mode="recommend",
        firing=recommended,
        reason=plan.reason,
        previous_priority=plan.previous_priority,
        desired_priority=plan.desired_priority,
        detail=detail,
    )
    await evaluate_routing_action(
        session,
        target_id=target.id,
        target_name=target.name,
        account_id=plan.account.external_account_id,
        account_name=plan.account.name,
        mode="execute",
        firing=changed,
        reason=plan.reason,
        previous_priority=plan.previous_priority,
        desired_priority=plan.desired_priority,
        detail=detail,
    )
    await evaluate_routing_action(
        session,
        target_id=target.id,
        target_name=target.name,
        account_id=plan.account.external_account_id,
        account_name=plan.account.name,
        mode=policy.mode,
        firing=failed,
        reason=plan.reason,
        previous_priority=plan.previous_priority,
        desired_priority=plan.desired_priority,
        error=decision.last_error if failed and decision is not None else "recovered",
        detail=detail,
    )


def _result_error(result: dict[str, Any] | None) -> str:
    if isinstance(result, dict):
        for key in ("error", "message"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                return sanitize_monitoring_error(value, limit=500)
    return "upstream billing probe returned no account result"


def _safe_error(exc: Exception) -> str:
    text = sanitize_monitoring_error(str(exc), limit=500)
    return text or exc.__class__.__name__


def _release_claim(policy: CostRoutingPolicy, owner_id: str | None) -> None:
    if owner_id is None or policy.lease_owner == owner_id:
        policy.lease_owner = None
        policy.lease_until = None


def _reconciliation_claim_expired(value: object, now: datetime) -> bool:
    if not isinstance(value, str):
        return True
    try:
        expires_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= now


def _record_reconciliation_mismatch(
    result: dict[str, Any],
    *,
    actual_priority: int | None,
    attempted_at: datetime,
) -> tuple[dict[str, Any], int, bool]:
    raw_attempts = result.get("reconcile_mismatch_attempts", 0)
    previous_attempts = (
        int(raw_attempts)
        if isinstance(raw_attempts, int) and not isinstance(raw_attempts, bool)
        else 0
    )
    mismatch_attempts = max(0, previous_attempts) + 1
    terminal = mismatch_attempts >= COST_ROUTING_RECONCILIATION_MISMATCH_LIMIT
    error = (
        f"desired priority not observed after {mismatch_attempts} healthy inventory checks"
        if terminal
        else "desired priority not observed yet"
    )
    return (
        {
            **result,
            "reconcile_actual_priority": actual_priority,
            "reconcile_last_attempt_at": attempted_at.isoformat(),
            "reconcile_last_error": error,
            "reconcile_mismatch_attempts": mismatch_attempts,
            **({"reconciliation_terminal": True} if terminal else {}),
        },
        mismatch_attempts,
        terminal,
    )


def _decision_previous_multiplier(decision: RoutingDecision) -> float | None:
    raw_previous_multiplier = decision.result.get("previous_multiplier")
    if (
        isinstance(raw_previous_multiplier, (int, float))
        and not isinstance(raw_previous_multiplier, bool)
        and math.isfinite(float(raw_previous_multiplier))
    ):
        return float(raw_previous_multiplier)
    return None


async def _queue_reconciled_rate_recovery(
    session: AsyncSession,
    decision: RoutingDecision,
    *,
    target_name: str,
    occurred_at: datetime,
) -> None:
    if decision.target_id is None or decision.observed_multiplier is None:
        return
    await queue_rate_recovered(
        session,
        target_id=decision.target_id,
        target_name=target_name,
        account_id=decision.external_account_id,
        account_name=decision.account_name,
        previous_multiplier=_decision_previous_multiplier(decision),
        multiplier=decision.observed_multiplier,
        previous_priority=decision.previous_priority,
        priority=decision.desired_priority,
        occurred_at=occurred_at,
        decision_id=decision.id,
    )


async def _recover_interrupted_routing_decisions(
    session: AsyncSession,
    policy: CostRoutingPolicy,
    actor: str,
    *,
    target_name: str,
    actual_priorities: dict[str, int | None],
    actual_controls: dict[str, dict[str, Any] | None] | None = None,
) -> None:
    interrupted = list(
        await session.scalars(
            select(RoutingDecision).where(
                RoutingDecision.policy_id == policy.id,
                RoutingDecision.status == "running",
            )
        )
    )
    if not interrupted:
        return
    now = datetime.now(timezone.utc)
    for decision in interrupted:
        account_present = decision.external_account_id in actual_priorities
        actual_priority = actual_priorities.get(decision.external_account_id)
        reconciled = actual_priority == decision.desired_priority and (
            "required_control" not in decision.result
            or (actual_controls or {}).get(decision.external_account_id)
            == decision.result["required_control"]
        )
        audit_action: str
        if reconciled:
            decision.status = "succeeded"
            decision.last_error = None
            decision.result = {
                **decision.result,
                "actual_priority": actual_priority,
                "reconciled_after_interruption": True,
            }
            if decision.reason == "cost_decrease" and decision.observed_multiplier is not None:
                await _queue_reconciled_rate_recovery(
                    session,
                    decision,
                    target_name=target_name,
                    occurred_at=now,
                )
            audit_action = "cost_routing.priority.reconciled"
        elif decision.result.get("outcome_unknown") is True:
            if not account_present:
                decision.result = {
                    **decision.result,
                    "reconcile_last_attempt_at": now.isoformat(),
                    "reconcile_last_error": "account missing from fresh inventory",
                }
                continue
            decision.result, _, terminal = _record_reconciliation_mismatch(
                decision.result,
                actual_priority=actual_priority,
                attempted_at=now,
            )
            if not terminal:
                continue
            decision.status = "failed"
            decision.last_error = decision.result["reconcile_last_error"]
            audit_action = "cost_routing.priority.reconciliation_failed"
        else:
            decision.status = "interrupted"
            decision.last_error = "worker stopped before routing outcome was persisted"
            audit_action = "cost_routing.priority.interrupted"
        decision.finished_at = now
        session.add(
            AuditEvent(
                actor=actor,
                action=audit_action,
                target_id=decision.target_id,
                details={
                    "decision_id": decision.id,
                    "account_id": decision.external_account_id,
                    "desired_priority": decision.desired_priority,
                    "actual_priority": actual_priority,
                },
            )
        )
    await session.commit()
