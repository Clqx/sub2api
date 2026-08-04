from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import bearer, current_user, get_cipher
from app.config import Settings, get_settings
from app.connectors.postgres import validate_database_url
from app.connectors.sub2api import ConnectorError, validate_target_url
from app.database import get_session
from app.models import (
    AccountCurrent,
    AuditEvent,
    Capability,
    CollectionRun,
    Incident,
    IncidentStatus,
    NotificationChannel,
    NotificationOutbox,
    OutboxStatus,
    Policy,
    QuotaSample,
    RunStatus,
    Target,
    User,
    WorkerHeartbeat,
)
from app.schemas import (
    AccountCursorPage,
    AccountResponse,
    ActiveRefreshCapabilityUpdate,
    CapabilityResponse,
    ChannelCreate,
    ChannelResponse,
    ChannelUpdate,
    DashboardResponse,
    IncidentResponse,
    LoginRequest,
    LoginResponse,
    OutboxResponse,
    PolicyCreate,
    PolicyResponse,
    ProbeResponse,
    QuotaResponse,
    RunResponse,
    SystemStatus,
    TargetCreate,
    TargetResponse,
    TargetUpdate,
    UserResponse,
)
from app.security import (
    SecretCipher,
    authenticate,
    create_session_token,
    login_throttle,
    revoke_session_token,
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
    await validate_remote_url(str(payload.base_url), settings)
    if payload.database is not None:
        await validate_remote_database_url(payload.database.database_url, settings)
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
    if payload.base_url is not None:
        await validate_remote_url(str(payload.base_url), settings)
    if payload.database is not None:
        await validate_remote_database_url(payload.database.database_url, settings)
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
    target = await required_target(session, target_id)
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
    target = await required_target(session, target_id)
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


@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> Policy:
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    policy = Policy(**payload.model_dump())
    session.add(policy)
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
    policy = await session.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    for key, value in payload.model_dump().items():
        setattr(policy, key, value)
    session.add(AuditEvent(actor=user.username, action="policy.update", target_id=policy.target_id))
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


@router.post("/notification-channels", response_model=ChannelResponse, status_code=201)
async def create_channel(
    payload: ChannelCreate,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
    cipher: SecretCipher = Depends(get_cipher),
    settings: Settings = Depends(get_settings),
) -> ChannelResponse:
    await validate_remote_url(str(payload.server_url), settings)
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    channel = NotificationChannel(
        target_id=payload.target_id,
        name=payload.name,
        server_url=str(payload.server_url),
        topic=payload.topic,
        enabled=payload.enabled,
        token_ciphertext=cipher.encrypt_text(payload.token) if payload.token else None,
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
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    if payload.target_id and await session.get(Target, payload.target_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "target not found")
    values = payload.model_dump(exclude_unset=True, exclude={"server_url", "token"})
    for key, value in values.items():
        setattr(channel, key, value)
    if payload.server_url is not None:
        await validate_remote_url(str(payload.server_url), settings)
        channel.server_url = str(payload.server_url)
    if "token" in payload.model_fields_set:
        channel.token_ciphertext = cipher.encrypt_text(payload.token) if payload.token else None
    session.add(
        AuditEvent(actor=user.username, action="notification.update", target_id=channel.target_id)
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
) -> NotificationOutbox:
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    outbox = NotificationOutbox(
        transition_id=str(uuid.uuid4()),
        channel_id=channel.id,
        payload={
            "title": "Sub2API Monitor test",
            "message": "Notification channel is configured.",
            "priority": 3,
            "tags": ["test_tube"],
        },
    )
    session.add(outbox)
    session.add(
        AuditEvent(actor=user.username, action="notification.test", target_id=channel.target_id)
    )
    await session.commit()
    await session.refresh(outbox)
    return outbox


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
) -> list[NotificationOutbox]:
    return list(
        await session.scalars(
            select(NotificationOutbox).order_by(NotificationOutbox.created_at.desc()).limit(limit)
        )
    )


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
    stale = heartbeat_at is None or heartbeat_at < now - timedelta(
        seconds=settings.worker_stale_seconds
    )
    pending = await session.scalar(
        select(func.count())
        .select_from(NotificationOutbox)
        .where(NotificationOutbox.status == OutboxStatus.PENDING.value)
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
    return DashboardResponse(
        targets_total=int(targets_total or 0),
        targets_ready=int(targets_ready or 0),
        accounts_total=int(accounts_total or 0),
        accounts_available=int(accounts_available or 0),
        low_quota_accounts=int(low_quota_accounts or 0),
        active_incidents=int(active_incidents or 0),
        failed_collections_24h=int(failed_collections or 0),
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def validate_remote_url(url: str, settings: Settings) -> None:
    try:
        await validate_target_url(url, allow_private=settings.allow_private_targets)
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


async def validate_remote_database_url(url: str, settings: Settings) -> None:
    try:
        await validate_database_url(url, allow_private=settings.allow_private_targets)
    except ConnectorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
