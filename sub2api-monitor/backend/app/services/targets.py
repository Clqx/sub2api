from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.config import Settings
from app.connectors.postgres import (
    Sub2APIPostgresConnector,
    account_identity_fingerprint,
    account_identity_record,
)
from app.connectors.sub2api import ProbeFact, ProbeResult, Sub2APIConnector
from app.models import AuditEvent, Capability, Target, TargetDatabaseSecret, TargetSecret
from app.schemas import TargetCreate, TargetUpdate
from app.security import SecretCipher

CAPABILITY_DEFAULTS: dict[str, tuple[bool, str]] = {
    "instance.health": (True, "none"),
    "instance.version": (True, "none"),
    "accounts.inventory": (True, "none"),
    "accounts.availability": (True, "none"),
    "accounts.upstream_billing_probe": (True, "upstream_call_on_manual_probe"),
    "channels.monitor": (True, "upstream_call_on_channel_check"),
    "groups.inventory": (True, "none"),
    "groups.usage": (True, "none"),
    "groups.capacity": (True, "none"),
    "ops.dashboard": (True, "none"),
    "ops.latency": (True, "none"),
    "ops.errors": (True, "none"),
    "ops.openai_token_stats": (True, "none"),
    "ops.concurrency": (True, "none"),
    "ops.user_concurrency": (True, "none"),
    "ops.account_availability": (True, "none"),
    "ops.realtime_traffic": (True, "none"),
    "ops.request_errors": (True, "none"),
    "ops.upstream_errors": (True, "none"),
    "ops.request_details": (True, "none"),
    "ops.alert_events": (True, "none"),
    "ops.system_logs": (True, "none"),
    "ops.system_log_health": (True, "none"),
    "ops.auth_cache_health": (True, "none"),
    "ops.ingress_health": (True, "none"),
    "quota.passive": (True, "none"),
    "quota.active_refresh": (False, "upstream_call_and_possible_target_write"),
    "quota.balance": (True, "none"),
    "quota.credits": (True, "none"),
    "database.inventory": (True, "none"),
    "database.identity_binding": (True, "none"),
}


async def target_with_secret(session: AsyncSession, target_id: str) -> Target | None:
    target: Target | None = await session.scalar(
        select(Target)
        .options(selectinload(Target.secret), selectinload(Target.database_secret))
        .where(Target.id == target_id)
    )
    return target


async def create_target(
    session: AsyncSession, payload: TargetCreate, cipher: SecretCipher, actor: str
) -> Target:
    target = Target(
        name=payload.name,
        base_url=str(payload.base_url).rstrip("/"),
        mode=payload.mode,
        enabled=payload.enabled,
        verify_tls=payload.verify_tls,
        collection_interval_seconds=payload.collection_interval_seconds,
        labels=payload.labels,
    )
    target.secret = TargetSecret(
        auth_type=payload.credential.auth_type,
        ciphertext=cipher.encrypt_json(payload.credential.secret_dict()),
    )
    if payload.database is not None:
        target.database_secret = TargetDatabaseSecret(
            ciphertext=cipher.encrypt_json(payload.database.secret_dict())
        )
        target.db_connection_state = "unknown"
        target.binding_state = "pending"
    session.add(target)
    await session.flush()
    for key, (enabled, side_effect) in CAPABILITY_DEFAULTS.items():
        if key.startswith("database.") and payload.mode != "full":
            enabled = False
        session.add(
            Capability(
                target_id=target.id,
                key=key,
                enabled=enabled,
                side_effect=side_effect,
                runtime_state="disabled" if not enabled else "unavailable",
            )
        )
    session.add(AuditEvent(actor=actor, action="target.create", target_id=target.id))
    await session.commit()
    return (await target_with_secret(session, target.id)) or target


async def update_target(
    session: AsyncSession,
    target: Target,
    payload: TargetUpdate,
    cipher: SecretCipher,
    actor: str,
) -> Target:
    changed_connector = False
    values = payload.model_dump(
        exclude_unset=True, exclude={"credential", "database", "base_url", "mode"}
    )
    for key, value in values.items():
        setattr(target, key, value)
    if payload.base_url is not None:
        base_url = str(payload.base_url).rstrip("/")
        changed_connector = base_url != target.base_url
        target.base_url = base_url
    if payload.credential is not None:
        changed_connector = True
        if target.secret is None:
            target.secret = TargetSecret(
                target_id=target.id, auth_type=payload.credential.auth_type, ciphertext=""
            )
        target.secret.auth_type = payload.credential.auth_type
        target.secret.ciphertext = cipher.encrypt_json(payload.credential.secret_dict())
    next_mode = payload.mode or target.mode
    if payload.database is not None:
        changed_connector = True
        if target.database_secret is None:
            target.database_secret = TargetDatabaseSecret(target_id=target.id, ciphertext="")
        target.database_secret.ciphertext = cipher.encrypt_json(payload.database.secret_dict())
    if next_mode == "full" and target.database_secret is None:
        raise ValueError("database is required for full mode")
    if payload.mode is not None and payload.mode != target.mode:
        changed_connector = True
        target.mode = payload.mode
        capabilities = list(
            await session.scalars(select(Capability).where(Capability.target_id == target.id))
        )
        for capability in capabilities:
            if capability.key.startswith("database."):
                capability.enabled = payload.mode == "full"
    if next_mode == "api_only" and target.database_secret is not None:
        await session.delete(target.database_secret)
        target.database_secret = None
        target.db_connection_state = "not_configured"
        target.binding_state = "not_required"
    if changed_connector:
        target.monitoring_readiness = "not_ready"
        target.api_connection_state = "unknown"
        target.version = None
        target.last_error = None
        target.binding_method = None
        target.binding_confidence = None
        target.binding_api_fingerprint = None
        target.binding_db_fingerprint = None
        target.binding_db_schema_fingerprint = None
        target.binding_checked_at = None
        target.binding_expires_at = None
        if target.mode == "full":
            target.db_connection_state = "unknown"
            target.binding_state = "pending"
        capabilities = list(
            await session.scalars(select(Capability).where(Capability.target_id == target.id))
        )
        for capability in capabilities:
            capability.support_state = "unknown"
            capability.runtime_state = "disabled" if not capability.enabled else "unavailable"
            capability.freshness = "missing"
            capability.reason = "connector configuration changed; reprobe required"
    session.add(AuditEvent(actor=actor, action="target.update", target_id=target.id))
    await session.commit()
    return (await target_with_secret(session, target.id)) or target


async def _capability(session: AsyncSession, target_id: str, key: str) -> Capability:
    item = await session.scalar(
        select(Capability).where(
            Capability.target_id == target_id,
            Capability.key == key,
            Capability.scope_type == "target",
            Capability.scope_id == "",
        )
    )
    if item is None:
        enabled, side_effect = CAPABILITY_DEFAULTS[key]
        item = Capability(target_id=target_id, key=key, enabled=enabled, side_effect=side_effect)
        session.add(item)
    return item


async def apply_probe_fact(
    session: AsyncSession,
    target_id: str,
    key: str,
    fact: ProbeFact,
    now: datetime,
    *,
    source: str = "api",
) -> Capability:
    item = await _capability(session, target_id, key)
    item.support_state = fact.support_state
    item.runtime_state = fact.runtime_state
    item.freshness = fact.freshness
    item.reason = fact.reason
    item.source = source
    item.last_attempt_at = now
    if fact.runtime_state == "healthy":
        item.last_success_at = now
    else:
        item.last_error_at = now
    return item


async def set_active_refresh_enabled(
    session: AsyncSession,
    target: Target,
    *,
    enabled: bool,
    confirm_side_effects: bool,
    settings: Settings,
    actor: str,
) -> Capability:
    if enabled and not confirm_side_effects:
        raise ValueError("active refresh side effects must be explicitly confirmed")
    capability = await _capability(session, target.id, "quota.active_refresh")
    capability.enabled = enabled
    capability.freshness = "missing"
    if enabled:
        capability.runtime_state = (
            "unavailable" if settings.active_quota_refresh_enabled else "disabled"
        )
        capability.reason = (
            "awaiting scheduled active usage collection"
            if settings.active_quota_refresh_enabled
            else "global active quota refresh switch is disabled"
        )
    else:
        capability.runtime_state = "disabled"
        capability.reason = "disabled by operator"
    session.add(
        AuditEvent(
            actor=actor,
            action="capability.quota_active_refresh.update",
            target_id=target.id,
            details={
                "enabled": enabled,
                "side_effect": capability.side_effect,
                "global_switch_enabled": settings.active_quota_refresh_enabled,
            },
        )
    )
    await session.commit()
    await session.refresh(capability)
    return capability


async def connector_for_target(
    session: AsyncSession, target: Target, settings: Settings, cipher: SecretCipher
) -> Sub2APIConnector:
    if target.secret is None:
        raise ValueError("target has no API credential")
    secret = cipher.decrypt_json(target.secret.ciphertext)
    secret_id = target.secret.id

    async def rotate(updated: dict[str, str]) -> None:
        # Token rotation is an upstream side effect. Persist it independently so a
        # later observation failure cannot roll back the only valid refresh token.
        factory = async_sessionmaker(session.bind, expire_on_commit=False)
        async with factory() as rotation_session:
            await rotation_session.execute(
                update(TargetSecret)
                .where(TargetSecret.id == secret_id)
                .values(
                    ciphertext=cipher.encrypt_json(updated), updated_at=datetime.now(timezone.utc)
                )
            )
            await rotation_session.commit()

    return Sub2APIConnector(
        base_url=target.base_url,
        auth_type=target.secret.auth_type,
        secret={str(k): str(v) for k, v in secret.items()},
        settings=settings,
        verify_tls=target.verify_tls,
        on_secret_rotated=rotate,
    )


def database_connector_for_target(
    target: Target, settings: Settings, cipher: SecretCipher
) -> Sub2APIPostgresConnector:
    if target.database_secret is None:
        raise ValueError("target has no database credential")
    secret = cipher.decrypt_json(target.database_secret.ciphertext)
    database_url = secret.get("database_url")
    if not isinstance(database_url, str) or not database_url:
        raise ValueError("target database credential is invalid")
    ca_certificate = secret.get("ca_certificate")
    return Sub2APIPostgresConnector(
        database_url=database_url,
        ca_certificate=ca_certificate if isinstance(ca_certificate, str) else None,
        settings=settings,
    )


async def probe_target(
    session: AsyncSession,
    target: Target,
    settings: Settings,
    cipher: SecretCipher,
    actor: str,
) -> ProbeResult:
    now = datetime.now(timezone.utc)
    database_error_reason: str | None = None
    connector = await connector_for_target(session, target, settings, cipher)
    monitoring_facts: dict[str, ProbeFact] = {}
    async with connector:
        result = await connector.probe()
        try:
            billing_fact, _ = await connector.upstream_billing_probe_settings()
        except Exception as exc:
            billing_fact = ProbeFact("unknown", "unavailable", "missing", str(exc)[:500])
        try:
            channel_fact, _ = await connector.channel_monitors()
        except Exception as exc:
            channel_fact = ProbeFact("unknown", "unavailable", "missing", str(exc)[:500])
        try:
            monitoring_facts, _ = await connector.monitoring_snapshot("5m", page_size=1)
        except Exception as exc:
            reason = str(exc)[:500]
            monitoring_facts = {
                key: ProbeFact("unknown", "unavailable", "missing", reason)
                for key in CAPABILITY_DEFAULTS
                if key.startswith("ops.") or key.startswith("groups.")
            }
    await apply_probe_fact(session, target.id, "instance.health", result.health, now)
    await apply_probe_fact(session, target.id, "instance.version", result.version, now)
    await apply_probe_fact(session, target.id, "accounts.inventory", result.accounts, now)
    await apply_probe_fact(session, target.id, "accounts.availability", result.accounts, now)
    await apply_probe_fact(
        session, target.id, "accounts.upstream_billing_probe", billing_fact, now
    )
    await apply_probe_fact(session, target.id, "channels.monitor", channel_fact, now)
    for key, fact in monitoring_facts.items():
        await apply_probe_fact(session, target.id, key, fact, now)
    local_quota_found = any(
        quota.quota_key.startswith("local.")
        for account in result.normalized_accounts
        for quota in account.quotas
    )
    local_quota_fact = (
        ProbeFact("supported", "healthy", "fresh")
        if local_quota_found
        else ProbeFact(
            "unsupported", "unavailable", "missing", "account inventory has no local quota fields"
        )
    )
    await apply_probe_fact(session, target.id, "quota.balance", local_quota_fact, now)
    await apply_probe_fact(session, target.id, "quota.credits", local_quota_fact, now)
    target.version = result.version_text
    target.last_probe_at = now
    target.api_connection_state = (
        "connected" if result.accounts.runtime_state == "healthy" else result.accounts.runtime_state
    )
    api_ready = (
        result.accounts.support_state == "supported" and result.accounts.runtime_state == "healthy"
    )
    ready = api_ready
    if target.mode == "full":
        database_connector = database_connector_for_target(target, settings, cipher)
        database_probe_error: str | None = None
        try:
            database_result = await database_connector.probe()
        except Exception as exc:
            database_result = None
            database_probe_error = str(exc)[:500]
        if database_result is None:
            database_fact = ProbeFact(
                "unknown",
                "unavailable",
                "missing",
                database_probe_error or "target database probe failed",
            )
            target.db_connection_state = "unavailable"
            target.binding_state = "inconclusive"
            target.binding_api_fingerprint = account_identity_fingerprint(
                [
                    account_identity_record(
                        account.external_account_id,
                        account.name,
                        account.platform,
                        account.account_type,
                    )
                    for account in result.normalized_accounts
                ]
            )
            target.binding_db_fingerprint = None
            target.binding_db_schema_fingerprint = None
            database_error_reason = database_fact.reason
        else:
            database_fact = database_result.fact
            target.db_connection_state = (
                "connected"
                if database_fact.runtime_state == "healthy"
                else database_fact.runtime_state
            )
            api_fingerprint = account_identity_fingerprint(
                [
                    account_identity_record(
                        account.external_account_id,
                        account.name,
                        account.platform,
                        account.account_type,
                    )
                    for account in result.normalized_accounts
                ]
            )
            db_fingerprint = database_result.identity_fingerprint
            target.binding_api_fingerprint = api_fingerprint
            target.binding_db_fingerprint = db_fingerprint
            target.binding_db_schema_fingerprint = database_result.schema_fingerprint
            if (
                api_fingerprint is None
                or db_fingerprint is None
                or database_result.schema_fingerprint is None
                or result.version_text is None
            ):
                target.binding_state = "inconclusive"
            elif api_fingerprint == db_fingerprint:
                target.binding_state = "verified"
            else:
                target.binding_state = "mismatch"
            if database_fact.runtime_state != "healthy":
                database_error_reason = database_fact.reason
        target.binding_method = "account_identity_set+api_version+public_accounts_schema_v1"
        target.binding_confidence = "medium" if target.binding_state == "verified" else "none"
        target.binding_checked_at = now
        target.binding_expires_at = now + timedelta(hours=settings.target_binding_ttl_hours)
        await apply_probe_fact(
            session,
            target.id,
            "database.inventory",
            database_fact,
            now,
            source="database",
        )
        binding_ready = target.binding_state == "verified"
        binding_fact = ProbeFact(
            "supported" if binding_ready else "unknown",
            "healthy" if binding_ready else "unavailable",
            "fresh" if binding_ready else "missing",
            None if binding_ready else f"API/database identity binding is {target.binding_state}",
        )
        await apply_probe_fact(
            session,
            target.id,
            "database.identity_binding",
            binding_fact,
            now,
            source="api+database",
        )
        ready = api_ready and database_fact.runtime_state == "healthy" and binding_ready
    else:
        target.db_connection_state = "not_configured"
        target.binding_state = "not_required"
    target.monitoring_readiness = "ready" if ready else "not_ready"
    target.last_error = (
        None
        if ready
        else result.accounts.reason
        or database_error_reason
        or (
            f"API/database identity binding is {target.binding_state}"
            if target.mode == "full"
            else None
        )
    )
    if ready and target.next_collection_at is None:
        target.next_collection_at = now
    session.add(
        AuditEvent(
            actor=actor,
            action="target.probe",
            target_id=target.id,
            details={
                "ready": ready,
                "account_count": len(result.normalized_accounts),
                "binding_state": target.binding_state,
            },
        )
    )
    await session.commit()
    return result
