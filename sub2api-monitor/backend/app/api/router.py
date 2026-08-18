from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import bearer, current_user, get_cipher
from app.config import Settings, get_settings
from app.connectors.postgres import validate_database_url
from app.connectors.sub2api import ConnectorError, Sub2APIConnector, validate_target_url
from app.database import get_session
from app.models import (
    AccountCurrent,
    AuditEvent,
    AutomationExecution,
    AutomationRule,
    Capability,
    ChannelMonitorCurrent,
    CollectionRun,
    CostRoutingPolicy,
    Incident,
    IncidentStatus,
    NotificationChannel,
    NotificationOutbox,
    OutboxStatus,
    Policy,
    QuotaSample,
    RoutingDecision,
    RunStatus,
    Target,
    User,
    WorkerHeartbeat,
)
from app.schemas import (
    TELEGRAM_TOKEN_PATTERN,
    AccountActionRequest,
    AccountCursorPage,
    AccountResponse,
    AccountUsageStatsResponse,
    ActiveRefreshCapabilityUpdate,
    AutomationExecutionResponse,
    AutomationRuleCreate,
    AutomationRuleResponse,
    CapabilityResponse,
    ChannelCheckResponse,
    ChannelCreate,
    ChannelMonitorCreate,
    ChannelMonitorResponse,
    ChannelMonitorUpdate,
    ChannelResponse,
    ChannelUpdate,
    CostRoutingPolicyResponse,
    CostRoutingPolicyUpdate,
    CostRoutingRunRequest,
    DashboardResponse,
    IncidentResponse,
    LoginRequest,
    LoginResponse,
    OutboxResponse,
    PolicyCreate,
    PolicyResponse,
    ProbeResponse,
    QuotaResponse,
    RoutingDecisionResponse,
    RunResponse,
    SystemStatus,
    TargetCreate,
    TargetResponse,
    TargetUpdate,
    UpstreamBillingBatchRequest,
    UpstreamBillingProbeResponse,
    UpstreamBillingProbeToggle,
    UpstreamBillingSettings,
    UserResponse,
)
from app.security import (
    SecretCipher,
    authenticate,
    create_session_token,
    login_throttle,
    revoke_session_token,
)
from app.services.monitoring import (
    account_connector,
    channel_payload,
    supports_upstream_billing_probe,
    target_connector,
    upsert_channel_monitor,
)
from app.services.notifier import validate_telegram_server_url
from app.services.policies import (
    effective_policy_ids_for_targets,
    evaluate_channel,
    evaluate_upstream_rate_change,
    lock_ttft_target_rows,
    resolve_replaced_effective_ttft_policies,
    resolve_ttft_incidents_for_policy,
    upstream_rate_multiplier,
)
from app.services.targets import (
    create_target,
    probe_target,
    set_active_refresh_enabled,
    target_with_secret,
    update_target,
)

router = APIRouter(prefix="/api/v1")


def target_response(target: Target) -> TargetResponse:
    result = TargetResponse.model_validate(target)
    result.secret_configured = target.secret is not None
    result.database_configured = target.database_secret is not None
    return result


def channel_response(channel: NotificationChannel) -> ChannelResponse:
    result = ChannelResponse.model_validate(channel)
    result.token_configured = bool(channel.token_ciphertext)
    result.signing_secret_configured = bool(channel.signing_secret_ciphertext)
    return result


def outbox_response(
    outbox: NotificationOutbox, channel: NotificationChannel | None = None
) -> OutboxResponse:
    result = OutboxResponse.model_validate(outbox)
    if channel is not None:
        result.channel_name = channel.name
        result.channel_kind = channel.kind
    return result


@router.post("/auth/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    client_ip = request.client.host if request.client else "unknown"
    retry_after = await login_throttle.check(client_ip, payload.username.casefold())
    if retry_after is not None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many login attempts",
            headers={"Retry-After": str(retry_after)},
        )
    user = await authenticate(session, payload.username, payload.password)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    await login_throttle.reset_account(client_ip, payload.username.casefold())
    token, expires_at = await create_session_token(session, user, settings.session_ttl_hours)
    return LoginResponse(access_token=token, expires_at=expires_at)


@router.get("/auth/me", response_model=UserResponse)
async def me(user: User = Depends(current_user)) -> User:
    return user


@router.delete("/auth/session", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    if credentials:
        await revoke_session_token(session, credentials.credentials)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target_route(
    payload: TargetCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    cipher: SecretCipher = Depends(get_cipher),
    settings: Settings = Depends(get_settings),
) -> TargetResponse:
    await validate_remote_url(str(payload.base_url), settings, verify_tls=payload.verify_tls)
    if payload.database is not None:
        await validate_remote_database_url(
            payload.database.database_url,
            settings,
            ca_certificate=payload.database.ca_certificate,
        )
    target = await create_target(session, payload, cipher, user.username)
    return target_response(target)


@router.get("/targets", response_model=list[TargetResponse])
async def list_targets(
    _: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[TargetResponse]:
    targets = list(
        await session.scalars(
            select(Target)
            .options(selectinload(Target.secret), selectinload(Target.database_secret))
            .order_by(Target.name, Target.id)
        )
    )
    return [target_response(item) for item in targets]


async def required_target(session: AsyncSession, target_id: str) -> Target:
    target = await target_with_secret(session, target_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    return target


@router.get("/targets/{target_id}", response_model=TargetResponse)
async def get_target_route(
    target_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> TargetResponse:
    return target_response(await required_target(session, target_id))


@router.patch("/targets/{target_id}", response_model=TargetResponse)
async def update_target_route(
    target_id: str,
    payload: TargetUpdate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    cipher: SecretCipher = Depends(get_cipher),
    settings: Settings = Depends(get_settings),
) -> TargetResponse:
    target = await required_target(session, target_id)
    if payload.base_url is not None or payload.verify_tls is not None:
        await validate_remote_url(
            str(payload.base_url or target.base_url),
            settings,
            verify_tls=payload.verify_tls if payload.verify_tls is not None else target.verify_tls,
        )
    if payload.database is not None:
        await validate_remote_database_url(
            payload.database.database_url,
            settings,
            ca_certificate=payload.database.ca_certificate,
        )
    try:
        updated = await update_target(session, target, payload, cipher, user.username)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return target_response(updated)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target_route(
    target_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    target = await session.scalar(
        select(Target).where(Target.id == target_id).with_for_update()
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    # Keep the lifecycle lock order consistent with policy updates. PostgreSQL
    # applies the same Policy locks later for the target's ON DELETE cascade.
    await session.scalars(
        select(Policy.id)
        .where(Policy.target_id == target_id)
        .order_by(Policy.id)
        .with_for_update()
    )
    session.add(AuditEvent(actor=user.username, action="target.delete", target_id=target.id))
    await session.flush()
    await session.delete(target)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/targets/{target_id}/probe", response_model=ProbeResponse)
async def probe_target_route(
    target_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> ProbeResponse:
    target = await required_target(session, target_id)
    try:
        result = await probe_target(session, target, settings, cipher, user.username)
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    capabilities = list(
        await session.scalars(
            select(Capability).where(Capability.target_id == target.id).order_by(Capability.key)
        )
    )
    target = await required_target(session, target.id)
    return ProbeResponse(
        target=target_response(target),
        capabilities=[CapabilityResponse.model_validate(item) for item in capabilities],
        account_count=len(result.normalized_accounts),
    )


@router.get("/targets/{target_id}/capabilities", response_model=list[CapabilityResponse])
async def target_capabilities(
    target_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[Capability]:
    await required_target(session, target_id)
    return list(
        await session.scalars(
            select(Capability).where(Capability.target_id == target_id).order_by(Capability.key)
        )
    )


@router.put(
    "/targets/{target_id}/capabilities/quota.active_refresh",
    response_model=CapabilityResponse,
)
async def update_active_refresh_capability(
    target_id: str,
    payload: ActiveRefreshCapabilityUpdate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Capability:
    target = await required_target(session, target_id)
    return await set_active_refresh_enabled(
        session,
        target,
        enabled=payload.enabled,
        confirm_side_effects=payload.confirm_side_effects,
        settings=settings,
        actor=user.username,
    )


@router.post(
    "/targets/{target_id}/collect", response_model=RunResponse, status_code=status.HTTP_202_ACCEPTED
)
async def queue_collection(
    target_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> CollectionRun:
    target = await session.scalar(
        select(Target).where(Target.id == target_id).with_for_update()
    )
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    if target.monitoring_readiness != "ready":
        raise HTTPException(status.HTTP_409_CONFLICT, "target must pass probe before collection")
    existing = await session.scalar(
        select(CollectionRun).where(
            CollectionRun.target_id == target_id,
            CollectionRun.status.in_([RunStatus.QUEUED.value, RunStatus.RUNNING.value]),
        )
    )
    if existing:
        return existing
    run = CollectionRun(target_id=target_id, trigger="manual")
    session.add(run)
    session.add(AuditEvent(actor=user.username, action="collection.queue", target_id=target_id))
    await session.commit()
    await session.refresh(run)
    return run


@router.get("/accounts", response_model=AccountCursorPage)
async def list_accounts(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    platform: str | None = None,
    account_type: str | None = None,
    available: bool | None = None,
    search: str | None = None,
    cursor: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> AccountCursorPage:
    conditions: list[Any] = []
    if target_id:
        conditions.append(AccountCurrent.target_id == target_id)
    if platform:
        conditions.append(AccountCurrent.platform == platform)
    if account_type:
        conditions.append(AccountCurrent.account_type == account_type)
    if available is not None:
        conditions.append(AccountCurrent.available.is_(available))
    if search:
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                AccountCurrent.name.ilike(pattern),
                AccountCurrent.external_account_id.ilike(pattern),
                AccountCurrent.platform.ilike(pattern),
            )
        )
    if cursor:
        conditions.append(AccountCurrent.id > cursor)
    stmt = select(AccountCurrent).order_by(AccountCurrent.id).limit(limit + 1)
    if conditions:
        stmt = stmt.where(and_(*conditions))
    items = list(await session.scalars(stmt))
    next_cursor = items[limit - 1].id if len(items) > limit else None
    page_items = items[:limit]
    return AccountCursorPage(
        items=await account_responses(session, page_items), next_cursor=next_cursor
    )


@router.get("/accounts/{account_id}", response_model=AccountResponse)
async def get_account(
    account_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AccountResponse:
    account = await session.get(AccountCurrent, account_id)
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    return (await account_responses(session, [account]))[0]


async def account_responses(
    session: AsyncSession, accounts: list[AccountCurrent]
) -> list[AccountResponse]:
    if not accounts:
        return []
    target_ids = {item.target_id for item in accounts}
    target_rows = await session.execute(
        select(Target.id, Target.name).where(Target.id.in_(target_ids))
    )
    target_names: dict[str, str] = {
        target_id: target_name for target_id, target_name in target_rows.all()
    }
    pair_conditions = [
        and_(
            QuotaSample.target_id == item.target_id,
            QuotaSample.external_account_id == item.external_account_id,
        )
        for item in accounts
    ]
    latest_times = (
        select(
            QuotaSample.target_id.label("target_id"),
            QuotaSample.external_account_id.label("external_account_id"),
            QuotaSample.quota_key.label("quota_key"),
            func.max(QuotaSample.observed_at).label("observed_at"),
        )
        .where(or_(*pair_conditions))
        .group_by(
            QuotaSample.target_id,
            QuotaSample.external_account_id,
            QuotaSample.quota_key,
        )
        .subquery()
    )
    latest_samples = list(
        await session.scalars(
            select(QuotaSample).join(
                latest_times,
                and_(
                    QuotaSample.target_id == latest_times.c.target_id,
                    QuotaSample.external_account_id == latest_times.c.external_account_id,
                    QuotaSample.quota_key == latest_times.c.quota_key,
                    QuotaSample.observed_at == latest_times.c.observed_at,
                ),
            )
        )
    )
    quota_by_account: dict[tuple[str, str], list[QuotaSample]] = {}
    for sample in latest_samples:
        quota_by_account.setdefault((sample.target_id, sample.external_account_id), []).append(
            sample
        )
    results: list[AccountResponse] = []
    for account in accounts:
        result = AccountResponse.model_validate(account)
        result.target_name = target_names.get(account.target_id)
        samples = quota_by_account.get((account.target_id, account.external_account_id), [])
        percentages = [
            sample.remaining_percent for sample in samples if sample.remaining_percent is not None
        ]
        result.remaining_percent = min(percentages) if percentages else None
        if samples:
            result.quota_freshness = (
                "stale" if any(sample.freshness == "stale" for sample in samples) else "fresh"
            )
        results.append(result)
    return results


@router.get("/accounts/{account_id}/quota", response_model=list[QuotaResponse])
async def account_quota(
    account_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[QuotaSample]:
    account = await session.get(AccountCurrent, account_id)
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    samples = list(
        await session.scalars(
            select(QuotaSample)
            .where(
                QuotaSample.target_id == account.target_id,
                QuotaSample.external_account_id == account.external_account_id,
            )
            .order_by(QuotaSample.observed_at.desc())
            .limit(1000)
        )
    )
    latest: dict[str, QuotaSample] = {}
    for item in samples:
        latest.setdefault(item.quota_key, item)
    return list(latest.values())


@router.get(
    "/accounts/{account_id}/stats",
    response_model=AccountUsageStatsResponse,
)
async def account_usage_stats(
    account_id: str,
    days: int = Query(default=30, ge=1, le=90),
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> dict[str, Any]:
    account, _target, connector = await _account_connector_or_404(
        session, account_id, settings, cipher
    )
    try:
        async with connector:
            return await connector.account_usage_stats(account.external_account_id, days=days)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc


@router.get(
    "/targets/{target_id}/upstream-billing-probe/settings",
    response_model=UpstreamBillingSettings,
)
async def get_upstream_billing_settings(
    target_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> UpstreamBillingSettings:
    _target, connector = await _target_connector_or_404(session, target_id, settings, cipher)
    try:
        async with connector:
            fact, data = await connector.upstream_billing_probe_settings()
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    if fact.runtime_state != "healthy" or data is None:
        raise HTTPException(status.HTTP_409_CONFLICT, fact.reason or "feature unavailable")
    return UpstreamBillingSettings.model_validate(data)


@router.put(
    "/targets/{target_id}/upstream-billing-probe/settings",
    response_model=UpstreamBillingSettings,
)
async def update_upstream_billing_settings(
    target_id: str,
    payload: UpstreamBillingSettings,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> UpstreamBillingSettings:
    _, connector = await _target_connector_or_404(session, target_id, settings, cipher)
    try:
        async with connector:
            result = await connector.update_upstream_billing_probe_settings(**payload.model_dump())
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    session.add(
        AuditEvent(
            actor=user.username,
            action="upstream_billing.settings.update",
            target_id=target_id,
            details=payload.model_dump(),
        )
    )
    await session.commit()
    return UpstreamBillingSettings.model_validate(result)


@router.get(
    "/targets/{target_id}/cost-routing-policy",
    response_model=CostRoutingPolicyResponse,
)
async def get_cost_routing_policy(
    target_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> CostRoutingPolicyResponse:
    await required_target(session, target_id)
    policy = await session.scalar(
        select(CostRoutingPolicy).where(CostRoutingPolicy.target_id == target_id)
    )
    if policy is None:
        return CostRoutingPolicyResponse(target_id=target_id)
    return CostRoutingPolicyResponse.model_validate(policy)


@router.put(
    "/targets/{target_id}/cost-routing-policy",
    response_model=CostRoutingPolicyResponse,
)
async def update_cost_routing_policy(
    target_id: str,
    payload: CostRoutingPolicyUpdate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> CostRoutingPolicy:
    await required_target(session, target_id)
    referenced_account_ids = set(payload.quality_bindings) | set(payload.fallback_account_ids)
    accounts: list[AccountCurrent] = []
    unknown_quality_accounts: list[str] = []
    unknown_fallback_accounts: list[str] = []
    unknown_monitors: list[str] = []
    if referenced_account_ids:
        accounts = list(
            await session.scalars(
                select(AccountCurrent).where(
                    AccountCurrent.target_id == target_id,
                    AccountCurrent.external_account_id.in_(referenced_account_ids),
                )
            )
        )
        eligible_account_ids = {
            account.external_account_id
            for account in accounts
            if account.platform.casefold() == "openai"
            and account.account_type.casefold() == "apikey"
        }
        unknown_quality_accounts = sorted(set(payload.quality_bindings) - eligible_account_ids)
        unknown_fallback_accounts = sorted(
            set(payload.fallback_account_ids) - eligible_account_ids
        )
    if payload.quality_bindings:
        bound_monitor_ids = {
            monitor_id
            for monitor_ids in payload.quality_bindings.values()
            for monitor_id in monitor_ids
        }
        monitors = list(
            await session.scalars(
                select(ChannelMonitorCurrent).where(
                    ChannelMonitorCurrent.target_id == target_id,
                    ChannelMonitorCurrent.external_monitor_id.in_(bound_monitor_ids),
                )
            )
        )
        eligible_monitor_ids = {
            monitor.external_monitor_id
            for monitor in monitors
            if monitor.provider.casefold() == "openai"
        }
        unknown_monitors = sorted(bound_monitor_ids - eligible_monitor_ids)
    if unknown_quality_accounts or unknown_fallback_accounts or unknown_monitors:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "message": (
                    "routing controls must reference this target's OpenAI API-key "
                    "accounts and OpenAI channel monitors"
                ),
                "account_ids": unknown_quality_accounts,
                "fallback_account_ids": unknown_fallback_accounts,
                "monitor_ids": unknown_monitors,
            },
        )
    policy = await session.scalar(
        select(CostRoutingPolicy).where(CostRoutingPolicy.target_id == target_id)
    )
    if policy is None:
        policy = CostRoutingPolicy(target_id=target_id)
        session.add(policy)
    existing_fallback_priorities = policy.fallback_priorities or {}
    account_by_id = {account.external_account_id: account for account in accounts}
    fallback_priorities: dict[str, int] = {}
    for account_id in payload.fallback_account_ids:
        existing_priority = existing_fallback_priorities.get(account_id)
        baseline: int | None
        if isinstance(existing_priority, int) and not isinstance(existing_priority, bool):
            baseline = existing_priority
        else:
            baseline = account_by_id[account_id].priority
            if baseline is None:
                baseline = payload.minimum_priority
        fallback_priorities[account_id] = max(
            payload.minimum_priority,
            min(int(baseline), payload.unhealthy_priority - 1),
        )
    for key, value in payload.model_dump(exclude={"confirm_side_effects"}).items():
        setattr(policy, key, value)
    policy.fallback_priorities = fallback_priorities
    policy.next_run_at = datetime.now(timezone.utc) if policy.enabled else None
    session.add(
        AuditEvent(
            actor=user.username,
            action="cost_routing.policy.update",
            target_id=target_id,
            details={
                "enabled": policy.enabled,
                "mode": policy.mode,
                "probe_interval_seconds": policy.probe_interval_seconds,
                "priority_scale": policy.priority_scale,
                "unhealthy_priority": policy.unhealthy_priority,
                "minimum_priority": policy.minimum_priority,
                "fallback_account_ids": policy.fallback_account_ids,
                "fallback_priorities": policy.fallback_priorities,
            },
        )
    )
    await session.commit()
    await session.refresh(policy)
    return policy


@router.post(
    "/targets/{target_id}/cost-routing-policy/run",
    response_model=CostRoutingPolicyResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def queue_cost_routing_run(
    target_id: str,
    payload: CostRoutingRunRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> CostRoutingPolicy:
    await required_target(session, target_id)
    policy = await session.scalar(
        select(CostRoutingPolicy).where(CostRoutingPolicy.target_id == target_id)
    )
    if policy is None or not policy.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "cost routing policy is not enabled")
    if not payload.confirm_side_effects:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "confirm_side_effects is required to queue a cost routing run",
        )
    policy.next_run_at = datetime.now(timezone.utc)
    session.add(
        AuditEvent(
            actor=user.username,
            action="cost_routing.run.queue",
            target_id=target_id,
            details={"policy_id": policy.id, "mode": policy.mode},
        )
    )
    await session.commit()
    await session.refresh(policy)
    return policy


@router.get("/routing-decisions", response_model=list[RoutingDecisionResponse])
async def list_routing_decisions(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    decision_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[RoutingDecision]:
    stmt = select(RoutingDecision).order_by(RoutingDecision.created_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(RoutingDecision.target_id == target_id)
    if decision_status:
        stmt = stmt.where(RoutingDecision.status == decision_status)
    return list(await session.scalars(stmt))


@router.get("/targets/{target_id}/operations")
async def target_operations(
    target_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
    time_range: Literal["5m", "30m", "1h", "6h", "24h"] = "1h",
) -> dict[str, Any]:
    target, connector = await _target_connector_or_404(session, target_id, settings, cipher)
    try:
        async with connector:
            facts, snapshot = await connector.monitoring_snapshot(time_range)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    snapshot["target_id"] = target.id
    snapshot["target_name"] = target.name
    snapshot["capabilities"] = {
        key: {
            "support_state": fact.support_state,
            "runtime_state": fact.runtime_state,
            "freshness": fact.freshness,
            "reason": fact.reason,
        }
        for key, fact in facts.items()
    }
    return snapshot


@router.put(
    "/accounts/{account_id}/upstream-billing-probe",
    response_model=UpstreamBillingProbeResponse,
)
async def toggle_upstream_billing_probe(
    account_id: str,
    payload: UpstreamBillingProbeToggle,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> UpstreamBillingProbeResponse:
    account, target, connector = await _account_connector_or_404(
        session, account_id, settings, cipher
    )
    _require_upstream_billing_account(account)
    try:
        async with connector:
            await connector.set_upstream_billing_probe_enabled(
                account.external_account_id, payload.enabled
            )
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    account.upstream_billing_probe_enabled = payload.enabled
    session.add(
        AuditEvent(
            actor=user.username,
            action="upstream_billing.account.toggle",
            target_id=target.id,
            details={"account_id": account.external_account_id, "enabled": payload.enabled},
        )
    )
    await session.commit()
    return UpstreamBillingProbeResponse(
        account_id=account.id,
        target_id=target.id,
        external_account_id=account.external_account_id,
        snapshot=account.upstream_billing_probe,
    )


@router.post(
    "/accounts/{account_id}/upstream-billing-probe",
    response_model=UpstreamBillingProbeResponse,
)
async def probe_upstream_billing(
    account_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> UpstreamBillingProbeResponse:
    account, target, connector = await _account_connector_or_404(
        session, account_id, settings, cipher
    )
    _require_upstream_billing_account(account)
    previous_multiplier = upstream_rate_multiplier(account.upstream_billing_probe)
    try:
        async with connector:
            result = await connector.probe_upstream_billing(account.external_account_id)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    snapshot = result.get("snapshot") if isinstance(result.get("snapshot"), dict) else None
    account.upstream_billing_probe = snapshot
    if snapshot is not None and isinstance(snapshot.get("synced_rate_multiplier"), (int, float)):
        account.rate_multiplier = float(snapshot["synced_rate_multiplier"])
    await evaluate_upstream_rate_change(
        session,
        target.name,
        account,
        previous_multiplier,
    )
    session.add(
        AuditEvent(
            actor=user.username,
            action="upstream_billing.account.probe",
            target_id=target.id,
            details={
                "account_id": account.external_account_id,
                "status": snapshot.get("status") if snapshot else "missing",
            },
        )
    )
    await session.commit()
    return UpstreamBillingProbeResponse(
        account_id=account.id,
        target_id=target.id,
        external_account_id=account.external_account_id,
        snapshot=snapshot,
    )


@router.post(
    "/accounts/upstream-billing-probe/batch",
    response_model=list[UpstreamBillingProbeResponse],
)
async def probe_upstream_billing_batch(
    payload: UpstreamBillingBatchRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> list[UpstreamBillingProbeResponse]:
    accounts = list(
        await session.scalars(
            select(AccountCurrent).where(AccountCurrent.id.in_(payload.account_ids))
        )
    )
    if len(accounts) != len(set(payload.account_ids)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "one or more accounts were not found")
    for account in accounts:
        _require_upstream_billing_account(account)
    by_target: dict[str, list[AccountCurrent]] = {}
    for account in accounts:
        by_target.setdefault(account.target_id, []).append(account)
    output: list[UpstreamBillingProbeResponse] = []
    for target_id, target_accounts in by_target.items():
        target, connector = await _target_connector_or_404(session, target_id, settings, cipher)
        try:
            async with connector:
                results = await connector.probe_upstream_billing_batch(
                    [account.external_account_id for account in target_accounts]
                )
        except ConnectorError as exc:
            raise _remote_http_error(exc) from exc
        result_by_id = {str(result.get("account_id")): result for result in results}
        for account in target_accounts:
            previous_multiplier = upstream_rate_multiplier(account.upstream_billing_probe)
            result = result_by_id.get(account.external_account_id, {})
            snapshot = result.get("snapshot") if isinstance(result.get("snapshot"), dict) else None
            if snapshot is not None:
                account.upstream_billing_probe = snapshot
                synced = snapshot.get("synced_rate_multiplier")
                if isinstance(synced, (int, float)):
                    account.rate_multiplier = float(synced)
                await evaluate_upstream_rate_change(
                    session,
                    target.name,
                    account,
                    previous_multiplier,
                )
            output.append(
                UpstreamBillingProbeResponse(
                    account_id=account.id,
                    target_id=target.id,
                    external_account_id=account.external_account_id,
                    snapshot=snapshot,
                )
            )
        session.add(
            AuditEvent(
                actor=user.username,
                action="upstream_billing.account.batch_probe",
                target_id=target.id,
                details={"account_ids": [item.external_account_id for item in target_accounts]},
            )
        )
    await session.commit()
    return output


@router.get("/channel-monitors", response_model=list[ChannelMonitorResponse])
async def list_channel_monitors(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    provider: str | None = None,
    enabled: bool | None = None,
) -> list[ChannelMonitorResponse]:
    stmt = select(ChannelMonitorCurrent, Target.name).join(
        Target, Target.id == ChannelMonitorCurrent.target_id
    )
    if target_id:
        stmt = stmt.where(ChannelMonitorCurrent.target_id == target_id)
    if provider:
        stmt = stmt.where(ChannelMonitorCurrent.provider == provider)
    if enabled is not None:
        stmt = stmt.where(ChannelMonitorCurrent.enabled.is_(enabled))
    rows = (await session.execute(stmt.order_by(Target.name, ChannelMonitorCurrent.name))).all()
    output: list[ChannelMonitorResponse] = []
    for item, target_name in rows:
        response = ChannelMonitorResponse.model_validate(item)
        response.target_name = target_name
        output.append(response)
    return output


@router.post(
    "/channel-monitors", response_model=ChannelMonitorResponse, status_code=status.HTTP_201_CREATED
)
async def create_channel_monitor(
    payload: ChannelMonitorCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> ChannelMonitorResponse:
    target, connector = await _target_connector_or_404(session, payload.target_id, settings, cipher)
    remote_payload = channel_payload(payload.model_dump(), include_target=True)
    try:
        async with connector:
            remote = await connector.create_channel_monitor(remote_payload)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    item = await upsert_channel_monitor(session, target.id, remote)
    session.add(
        AuditEvent(
            actor=user.username,
            action="channel_monitor.create",
            target_id=target.id,
            details={"external_monitor_id": remote.external_monitor_id},
        )
    )
    await session.commit()
    response = ChannelMonitorResponse.model_validate(item)
    response.target_name = target.name
    return response


@router.patch("/channel-monitors/{monitor_id}", response_model=ChannelMonitorResponse)
async def update_channel_monitor(
    monitor_id: str,
    payload: ChannelMonitorUpdate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> ChannelMonitorResponse:
    item = await _required_channel(session, monitor_id)
    target, connector = await _target_connector_or_404(session, item.target_id, settings, cipher)
    remote_payload = channel_payload(payload.model_dump(exclude_unset=True))
    try:
        async with connector:
            remote = await connector.update_channel_monitor(
                item.external_monitor_id, remote_payload
            )
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    item = await upsert_channel_monitor(session, target.id, remote)
    session.add(
        AuditEvent(
            actor=user.username,
            action="channel_monitor.update",
            target_id=target.id,
            details={"external_monitor_id": item.external_monitor_id},
        )
    )
    await session.commit()
    response = ChannelMonitorResponse.model_validate(item)
    response.target_name = target.name
    return response


@router.delete("/channel-monitors/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel_monitor(
    monitor_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> Response:
    item = await _required_channel(session, monitor_id)
    target, connector = await _target_connector_or_404(session, item.target_id, settings, cipher)
    try:
        async with connector:
            await connector.delete_channel_monitor(item.external_monitor_id)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    session.add(
        AuditEvent(
            actor=user.username,
            action="channel_monitor.delete",
            target_id=target.id,
            details={"external_monitor_id": item.external_monitor_id},
        )
    )
    item.enabled = False
    await evaluate_channel(session, target.name, item)
    await session.delete(item)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/channel-monitors/{monitor_id}/run", response_model=list[ChannelCheckResponse])
async def run_channel_monitor(
    monitor_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
) -> list[ChannelCheckResponse]:
    item = await _required_channel(session, monitor_id)
    target, connector = await _target_connector_or_404(session, item.target_id, settings, cipher)
    try:
        async with connector:
            results = await connector.run_channel_monitor(item.external_monitor_id)
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    primary = next((result for result in results if result.model == item.primary_model), None)
    if primary is None and results:
        primary = results[0]
    if primary is not None:
        item.primary_status = primary.status
        item.primary_latency_ms = primary.latency_ms
        item.last_checked_at = primary.checked_at
        item.observed_at = datetime.now(timezone.utc)
    await evaluate_channel(session, target.name, item)
    session.add(
        AuditEvent(
            actor=user.username,
            action="channel_monitor.run",
            target_id=target.id,
            details={"external_monitor_id": item.external_monitor_id},
        )
    )
    await session.commit()
    return [_channel_check_response(result) for result in results]


@router.get("/channel-monitors/{monitor_id}/history", response_model=list[ChannelCheckResponse])
async def channel_monitor_history(
    monitor_id: str,
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    cipher: SecretCipher = Depends(get_cipher),
    model: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[ChannelCheckResponse]:
    item = await _required_channel(session, monitor_id)
    _target, connector = await _target_connector_or_404(session, item.target_id, settings, cipher)
    try:
        async with connector:
            results = await connector.channel_monitor_history(
                item.external_monitor_id, model=model, limit=limit
            )
    except ConnectorError as exc:
        raise _remote_http_error(exc) from exc
    return [_channel_check_response(result) for result in results]


@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Policy:
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    affected_target_ids = (
        {payload.target_id}
        if payload.target_id is not None
        else set(await session.scalars(select(Target.id)))
    )
    locked_target_ids = await lock_ttft_target_rows(session, affected_target_ids)
    if payload.target_id is not None and payload.target_id not in locked_target_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    previous_policy_ids = await effective_policy_ids_for_targets(
        session, affected_target_ids
    )
    policy = Policy(**payload.model_dump())
    session.add(policy)
    await session.flush()
    await resolve_replaced_effective_ttft_policies(session, previous_policy_ids)
    session.add(
        AuditEvent(actor=user.username, action="policy.create", target_id=payload.target_id)
    )
    await session.commit()
    await session.refresh(policy)
    return policy


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(
    _: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[Policy]:
    return list(await session.scalars(select(Policy).order_by(Policy.name, Policy.id)))


@router.put("/policies/{policy_id}", response_model=PolicyResponse)
async def update_policy_route(
    policy_id: str,
    payload: PolicyCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Policy:
    actor = user.username
    while True:
        policy_snapshot = await session.scalar(
            select(Policy)
            .where(Policy.id == policy_id)
            .execution_options(populate_existing=True)
        )
        if policy_snapshot is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
        snapshot_target_id = policy_snapshot.target_id
        if snapshot_target_id is None or payload.target_id is None:
            affected_target_ids = set(await session.scalars(select(Target.id)))
        else:
            affected_target_ids = {snapshot_target_id, payload.target_id}
        locked_target_ids = await lock_ttft_target_rows(session, affected_target_ids)
        if payload.target_id is not None and payload.target_id not in locked_target_ids:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
        policy = await session.scalar(
            select(Policy)
            .where(Policy.id == policy_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if policy is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
        if policy.target_id == snapshot_target_id:
            break
        # The binding changed while target locks were being acquired. Release
        # them and recompute the complete target-first lock set.
        await session.rollback()

    previous_target_id = policy.target_id
    previous_enabled = policy.enabled
    previous_ttft_enabled = policy.ttft_enabled
    previous_policy_ids = await effective_policy_ids_for_targets(
        session, affected_target_ids
    )
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    await session.flush()
    if (
        (previous_enabled and not policy.enabled)
        or (previous_ttft_enabled and not policy.ttft_enabled)
        or previous_target_id != policy.target_id
    ):
        reason = (
            "TTFT policy target changed"
            if previous_target_id != policy.target_id
            else "TTFT monitoring is disabled"
        )
        await resolve_ttft_incidents_for_policy(session, policy.id, reason=reason)
    await resolve_replaced_effective_ttft_policies(session, previous_policy_ids)
    session.add(AuditEvent(actor=actor, action="policy.update", target_id=policy.target_id))
    await session.commit()
    await session.refresh(policy)
    return policy


@router.get("/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    incident_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[Incident]:
    stmt = select(Incident).order_by(Incident.updated_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(Incident.target_id == target_id)
    if incident_status:
        stmt = stmt.where(Incident.status == incident_status)
    return list(await session.scalars(stmt))


@router.post("/incidents/{incident_id}/ack", response_model=IncidentResponse)
async def acknowledge_incident(
    incident_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    if incident.status == IncidentStatus.FIRING.value:
        incident.status = IncidentStatus.ACKNOWLEDGED.value
        incident.acknowledged_at = datetime.now(timezone.utc)
    session.add(
        AuditEvent(actor=user.username, action="incident.ack", target_id=incident.target_id)
    )
    await session.commit()
    await session.refresh(incident)
    return incident


@router.post(
    "/automation-rules",
    response_model=AutomationRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_automation_rule(
    payload: AutomationRuleCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AutomationRule:
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    rule = AutomationRule(**payload.model_dump(exclude={"confirm_side_effects"}))
    session.add(rule)
    session.add(
        AuditEvent(
            actor=user.username,
            action="automation.rule.create",
            target_id=payload.target_id,
            details={"action": payload.action, "mode": payload.mode, "enabled": payload.enabled},
        )
    )
    await session.commit()
    await session.refresh(rule)
    return rule


@router.get("/automation-rules", response_model=list[AutomationRuleResponse])
async def list_automation_rules(
    _: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[AutomationRule]:
    return list(await session.scalars(select(AutomationRule).order_by(AutomationRule.name)))


@router.put("/automation-rules/{rule_id}", response_model=AutomationRuleResponse)
async def update_automation_rule(
    rule_id: str,
    payload: AutomationRuleCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AutomationRule:
    rule = await session.get(AutomationRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "automation rule not found")
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    for key, value in payload.model_dump(exclude={"confirm_side_effects"}).items():
        setattr(rule, key, value)
    session.add(
        AuditEvent(
            actor=user.username,
            action="automation.rule.update",
            target_id=rule.target_id,
            details={"rule_id": rule.id, "mode": rule.mode, "enabled": rule.enabled},
        )
    )
    await session.commit()
    await session.refresh(rule)
    return rule


@router.delete("/automation-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_automation_rule(
    rule_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    rule = await session.get(AutomationRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "automation rule not found")
    session.add(
        AuditEvent(
            actor=user.username,
            action="automation.rule.delete",
            target_id=rule.target_id,
            details={"rule_id": rule.id},
        )
    )
    await session.delete(rule)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/automation-executions", response_model=list[AutomationExecutionResponse])
async def list_automation_executions(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    execution_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[AutomationExecution]:
    stmt = select(AutomationExecution).order_by(AutomationExecution.created_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(AutomationExecution.target_id == target_id)
    if execution_status:
        stmt = stmt.where(AutomationExecution.status == execution_status)
    return list(await session.scalars(stmt))


@router.post(
    "/automation-executions/{execution_id}/approve",
    response_model=AutomationExecutionResponse,
)
async def approve_automation_execution(
    execution_id: str,
    _: AccountActionRequest,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AutomationExecution:
    execution = await session.get(AutomationExecution, execution_id)
    if execution is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "automation execution not found")
    if execution.status not in {"recommended", "failed"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "execution cannot be queued from its state")
    execution.mode = "execute"
    execution.status = "queued"
    execution.last_error = None
    execution.finished_at = None
    session.add(
        AuditEvent(
            actor=user.username,
            action="automation.execution.approve",
            target_id=execution.target_id,
            details={"execution_id": execution.id, "action": execution.action},
        )
    )
    await session.commit()
    await session.refresh(execution)
    return execution


@router.post("/notification-channels", response_model=ChannelResponse, status_code=201)
async def create_channel(
    payload: ChannelCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    cipher: SecretCipher = Depends(get_cipher),
    settings: Settings = Depends(get_settings),
) -> ChannelResponse:
    await validate_notification_url(str(payload.server_url), settings)
    validate_telegram_channel(
        payload.kind,
        str(payload.server_url),
        bool(payload.token),
        settings,
    )
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    channel = NotificationChannel(
        target_id=payload.target_id,
        name=payload.name,
        kind=payload.kind,
        server_url=str(payload.server_url),
        topic=payload.topic,
        enabled=payload.enabled,
        event_types=list(dict.fromkeys(payload.event_types)),
        severities=list(dict.fromkeys(payload.severities)),
        token_ciphertext=cipher.encrypt_text(payload.token) if payload.token else None,
        signing_secret_ciphertext=(
            cipher.encrypt_text(payload.signing_secret) if payload.signing_secret else None
        ),
    )
    session.add(channel)
    session.add(
        AuditEvent(actor=user.username, action="notification.create", target_id=payload.target_id)
    )
    await session.commit()
    await session.refresh(channel)
    return channel_response(channel)


@router.get("/notification-channels", response_model=list[ChannelResponse])
async def list_channels(
    _: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> list[ChannelResponse]:
    channels = list(
        await session.scalars(select(NotificationChannel).order_by(NotificationChannel.name))
    )
    return [channel_response(item) for item in channels]


@router.patch("/notification-channels/{channel_id}", response_model=ChannelResponse)
async def update_channel(
    channel_id: str,
    payload: ChannelUpdate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    cipher: SecretCipher = Depends(get_cipher),
    settings: Settings = Depends(get_settings),
) -> ChannelResponse:
    actor = user.username
    requested_server_url = (
        str(payload.server_url) if payload.server_url is not None else None
    )
    notification_url_validated = False
    while True:
        channel_snapshot = await session.scalar(
            select(NotificationChannel)
            .where(NotificationChannel.id == channel_id)
            .execution_options(populate_existing=True)
        )
        if channel_snapshot is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
        if requested_server_url is not None and not notification_url_validated:
            await validate_notification_url(requested_server_url, settings)
            notification_url_validated = True
        snapshot_target_id = channel_snapshot.target_id
        affected_target_ids = {
            target_id
            for target_id in (snapshot_target_id, payload.target_id)
            if target_id is not None
        }
        locked_target_ids = await lock_ttft_target_rows(session, affected_target_ids)
        if payload.target_id is not None and payload.target_id not in locked_target_ids:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
        channel = await session.scalar(
            select(NotificationChannel)
            .where(NotificationChannel.id == channel_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if channel is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
        if channel.target_id == snapshot_target_id:
            break
        await session.rollback()

    new_kind = payload.kind if payload.kind is not None else channel.kind
    new_server_url = (
        requested_server_url if requested_server_url is not None else channel.server_url
    )
    credential_boundary_changed = (
        new_kind != channel.kind
        or notification_authority(new_server_url) != notification_authority(channel.server_url)
    )
    token_was_submitted = "token" in payload.model_fields_set
    effective_token_configured = (
        bool(payload.token)
        if token_was_submitted
        else bool(channel.token_ciphertext) and not credential_boundary_changed
    )
    validate_telegram_channel(
        new_kind,
        new_server_url,
        effective_token_configured,
        settings,
    )
    values = payload.model_dump(
        exclude_unset=True,
        exclude={"kind", "server_url", "token", "signing_secret"},
    )
    if values.get("event_types") is not None:
        values["event_types"] = list(dict.fromkeys(values["event_types"]))
    if values.get("severities") is not None:
        values["severities"] = list(dict.fromkeys(values["severities"]))
    for key, value in values.items():
        setattr(channel, key, value)
    channel.kind = new_kind
    if channel.kind in {"ntfy", "telegram"} and not channel.topic:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "topic is required for ntfy and Telegram channels",
        )
    channel.server_url = new_server_url
    if credential_boundary_changed and not token_was_submitted:
        channel.token_ciphertext = None
    if token_was_submitted:
        if (
            channel.kind == "telegram"
            and payload.token
            and not TELEGRAM_TOKEN_PATTERN.fullmatch(payload.token)
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "invalid Telegram bot token",
            )
        channel.token_ciphertext = cipher.encrypt_text(payload.token) if payload.token else None
    signing_secret_was_submitted = "signing_secret" in payload.model_fields_set
    if channel.kind != "webhook":
        channel.signing_secret_ciphertext = None
    elif credential_boundary_changed and not signing_secret_was_submitted:
        channel.signing_secret_ciphertext = None
    if signing_secret_was_submitted:
        if channel.kind != "webhook" and payload.signing_secret:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "signing_secret is only accepted for webhook channels",
            )
        channel.signing_secret_ciphertext = (
            cipher.encrypt_text(payload.signing_secret) if payload.signing_secret else None
        )
    session.add(
        AuditEvent(actor=actor, action="notification.update", target_id=channel.target_id)
    )
    await session.commit()
    await session.refresh(channel)
    return channel_response(channel)


@router.delete("/notification-channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    session.add(
        AuditEvent(actor=user.username, action="notification.delete", target_id=channel.target_id)
    )
    await session.delete(channel)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/notification-channels/{channel_id}/test", response_model=OutboxResponse, status_code=202
)
async def test_channel(
    channel_id: str,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> OutboxResponse:
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    payload = (
        {
            "event_id": str(uuid.uuid4()),
            "event_type": "test",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "target_id": channel.target_id,
            "message": "Webhook subscription is configured.",
        }
        if channel.kind == "webhook"
        else {
            "title": "Sub2API Monitor test",
            "message": "Notification channel is configured.",
            "priority": 3,
            "tags": ["test_tube"],
        }
    )
    outbox = NotificationOutbox(
        transition_id=str(uuid.uuid4()),
        channel_id=channel.id,
        payload=payload,
    )
    session.add(outbox)
    session.add(
        AuditEvent(actor=user.username, action="notification.test", target_id=channel.target_id)
    )
    await session.commit()
    await session.refresh(outbox)
    return outbox_response(outbox, channel)


@router.get("/runs", response_model=list[RunResponse])
async def list_runs(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    target_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CollectionRun]:
    stmt = select(CollectionRun).order_by(CollectionRun.created_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(CollectionRun.target_id == target_id)
    return list(await session.scalars(stmt))


@router.get("/outbox", response_model=list[OutboxResponse])
async def list_outbox(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[OutboxResponse]:
    rows = (
        await session.execute(
            select(NotificationOutbox, NotificationChannel)
            .join(NotificationChannel, NotificationChannel.id == NotificationOutbox.channel_id)
            .order_by(NotificationOutbox.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [outbox_response(outbox, channel) for outbox, channel in rows]


@router.get("/system/status", response_model=SystemStatus)
async def system_status(
    _: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> SystemStatus:
    heartbeat = await session.scalar(
        select(WorkerHeartbeat).order_by(WorkerHeartbeat.last_seen_at.desc()).limit(1)
    )
    now = datetime.now(timezone.utc)
    heartbeat_at = _aware(heartbeat.last_seen_at) if heartbeat else None
    stalled_loops = (
        list(heartbeat.details.get("critical_loop_stalled") or []) if heartbeat else []
    )
    stale = bool(stalled_loops) or heartbeat_at is None or heartbeat_at < now - timedelta(
        seconds=settings.worker_stale_seconds
    )
    pending = await session.scalar(
        select(func.count())
        .select_from(NotificationOutbox)
        .where(
            NotificationOutbox.status.in_(
                [OutboxStatus.PENDING.value, OutboxStatus.DELIVERING.value]
            )
        )
    )
    failed_since = now - timedelta(hours=24)
    failed = await session.scalar(
        select(func.count())
        .select_from(CollectionRun)
        .where(
            CollectionRun.status == RunStatus.FAILED.value,
            CollectionRun.created_at >= failed_since,
        )
    )
    return SystemStatus(
        database="ok",
        ready=not stale,
        worker_last_seen_at=heartbeat_at,
        worker_stale=stale,
        worker_stalled_loops=stalled_loops,
        pending_outbox=int(pending or 0),
        failed_runs_24h=int(failed or 0),
    )


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    _: User = Depends(current_user), session: AsyncSession = Depends(get_session)
) -> DashboardResponse:
    targets_total = await session.scalar(select(func.count()).select_from(Target))
    targets_ready = await session.scalar(
        select(func.count())
        .select_from(Target)
        .where(Target.enabled.is_(True), Target.monitoring_readiness == "ready")
    )
    accounts_total = await session.scalar(select(func.count()).select_from(AccountCurrent))
    accounts_available = await session.scalar(
        select(func.count()).select_from(AccountCurrent).where(AccountCurrent.available.is_(True))
    )
    latest_quota = (
        select(
            QuotaSample.target_id.label("target_id"),
            QuotaSample.external_account_id.label("external_account_id"),
            QuotaSample.quota_key.label("quota_key"),
            func.max(QuotaSample.observed_at).label("observed_at"),
        )
        .group_by(
            QuotaSample.target_id,
            QuotaSample.external_account_id,
            QuotaSample.quota_key,
        )
        .subquery()
    )
    low_accounts = (
        select(QuotaSample.target_id, QuotaSample.external_account_id)
        .join(
            latest_quota,
            and_(
                QuotaSample.target_id == latest_quota.c.target_id,
                QuotaSample.external_account_id == latest_quota.c.external_account_id,
                QuotaSample.quota_key == latest_quota.c.quota_key,
                QuotaSample.observed_at == latest_quota.c.observed_at,
            ),
        )
        .where(QuotaSample.remaining_percent <= 20)
        .group_by(QuotaSample.target_id, QuotaSample.external_account_id)
        .subquery()
    )
    low_quota_accounts = await session.scalar(select(func.count()).select_from(low_accounts))
    active_incidents = await session.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.status != IncidentStatus.RESOLVED.value)
    )
    failed_since = datetime.now(timezone.utc) - timedelta(hours=24)
    failed_collections = await session.scalar(
        select(func.count())
        .select_from(CollectionRun)
        .where(
            CollectionRun.status == RunStatus.FAILED.value,
            CollectionRun.created_at >= failed_since,
        )
    )
    channels_total = await session.scalar(select(func.count()).select_from(ChannelMonitorCurrent))
    channels_unhealthy = await session.scalar(
        select(func.count())
        .select_from(ChannelMonitorCurrent)
        .where(
            ChannelMonitorCurrent.enabled.is_(True),
            ChannelMonitorCurrent.primary_status.in_(["degraded", "failed", "error"]),
        )
    )
    return DashboardResponse(
        targets_total=int(targets_total or 0),
        targets_ready=int(targets_ready or 0),
        accounts_total=int(accounts_total or 0),
        accounts_available=int(accounts_available or 0),
        low_quota_accounts=int(low_quota_accounts or 0),
        active_incidents=int(active_incidents or 0),
        failed_collections_24h=int(failed_collections or 0),
        channels_total=int(channels_total or 0),
        channels_unhealthy=int(channels_unhealthy or 0),
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def validate_remote_url(url: str, settings: Settings, *, verify_tls: bool = True) -> None:
    try:
        if not settings.allow_private_targets and not verify_tls:
            raise ConnectorError("TLS verification cannot be disabled for public targets")
        await validate_target_url(url, allow_private=settings.allow_private_targets)
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


async def validate_remote_database_url(
    url: str,
    settings: Settings,
    *,
    ca_certificate: str | None = None,
) -> None:
    try:
        await validate_database_url(
            url,
            allow_private=settings.allow_private_targets,
            ca_certificate=ca_certificate,
        )
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


async def validate_notification_url(url: str, settings: Settings) -> None:
    try:
        await validate_target_url(url, allow_private=settings.allow_private_notification_targets)
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def validate_telegram_channel(
    kind: str,
    server_url: str,
    token_configured: bool,
    settings: Settings,
) -> None:
    if kind != "telegram":
        return
    if not token_configured:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "token is required for Telegram channels",
        )
    try:
        validate_telegram_server_url(server_url, settings.telegram_api_allowed_hosts)
    except ConnectorError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Telegram server_url must be an HTTPS base URL on the trusted host allowlist",
        ) from exc


def notification_authority(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    scheme = parsed.scheme.casefold()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (parsed.hostname or "").rstrip(".").casefold(), parsed.port or default_port


async def _target_connector_or_404(
    session: AsyncSession, target_id: str, settings: Settings, cipher: SecretCipher
) -> tuple[Target, Sub2APIConnector]:
    try:
        return await target_connector(session, target_id, settings, cipher)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


async def _account_connector_or_404(
    session: AsyncSession, account_id: str, settings: Settings, cipher: SecretCipher
) -> tuple[AccountCurrent, Target, Sub2APIConnector]:
    try:
        return await account_connector(session, account_id, settings, cipher)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


async def _required_channel(session: AsyncSession, monitor_id: str) -> ChannelMonitorCurrent:
    item = await session.get(ChannelMonitorCurrent, monitor_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel monitor not found")
    return item


def _require_upstream_billing_account(account: AccountCurrent) -> None:
    if not supports_upstream_billing_probe(account):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "upstream billing probes are limited to OpenAI API-key accounts",
        )


def _remote_http_error(exc: ConnectorError) -> HTTPException:
    remote_status = exc.status_code
    if remote_status in {400, 401, 403, 404, 409, 422, 429}:
        return HTTPException(remote_status, str(exc))
    return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))


def _channel_check_response(result: Any) -> ChannelCheckResponse:
    return ChannelCheckResponse(
        model=result.model,
        status=result.status,
        latency_ms=result.latency_ms,
        ping_latency_ms=result.ping_latency_ms,
        message=result.message,
        checked_at=result.checked_at,
    )
