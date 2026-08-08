from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import NormalizedChannelMonitor, Sub2APIConnector
from app.models import AccountCurrent, ChannelMonitorCurrent, Target
from app.security import SecretCipher
from app.services.targets import connector_for_target, target_with_secret


async def target_connector(
    session: AsyncSession, target_id: str, settings: Settings, cipher: SecretCipher
) -> tuple[Target, Sub2APIConnector]:
    target = await target_with_secret(session, target_id)
    if target is None:
        raise LookupError("target not found")
    return target, await connector_for_target(session, target, settings, cipher)


async def account_connector(
    session: AsyncSession, account_id: str, settings: Settings, cipher: SecretCipher
) -> tuple[AccountCurrent, Target, Sub2APIConnector]:
    account = await session.get(AccountCurrent, account_id)
    if account is None:
        raise LookupError("account not found")
    target, connector = await target_connector(session, account.target_id, settings, cipher)
    return account, target, connector


def supports_upstream_billing_probe(account: AccountCurrent) -> bool:
    return (
        account.platform.casefold() == "openai"
        and account.account_type.casefold() == "apikey"
    )


async def upsert_channel_monitor(
    session: AsyncSession,
    target_id: str,
    monitor: NormalizedChannelMonitor,
    *,
    observed_at: datetime | None = None,
) -> ChannelMonitorCurrent:
    item = await session.scalar(
        select(ChannelMonitorCurrent).where(
            ChannelMonitorCurrent.target_id == target_id,
            ChannelMonitorCurrent.external_monitor_id == monitor.external_monitor_id,
        )
    )
    if item is None:
        item = ChannelMonitorCurrent(
            target_id=target_id, external_monitor_id=monitor.external_monitor_id
        )
        session.add(item)
    item.name = monitor.name
    item.provider = monitor.provider
    item.api_mode = monitor.api_mode
    item.endpoint = monitor.endpoint
    item.api_key_masked = monitor.api_key_masked
    item.api_key_decrypt_failed = monitor.api_key_decrypt_failed
    item.primary_model = monitor.primary_model
    item.extra_models = monitor.extra_models
    item.group_name = monitor.group_name
    item.enabled = monitor.enabled
    item.interval_seconds = monitor.interval_seconds
    item.jitter_seconds = monitor.jitter_seconds
    item.last_checked_at = monitor.last_checked_at
    item.primary_status = monitor.primary_status
    item.primary_latency_ms = monitor.primary_latency_ms
    item.availability_7d = monitor.availability_7d
    item.extra_models_status = monitor.extra_models_status
    item.template_id = monitor.template_id
    item.extra_headers = monitor.extra_headers
    item.body_override_mode = monitor.body_override_mode
    item.body_override = monitor.body_override
    item.source_created_at = monitor.created_at
    item.source_updated_at = monitor.updated_at
    item.observed_at = observed_at or datetime.now(timezone.utc)
    await session.flush()
    return item


async def sync_channel_monitors(
    session: AsyncSession,
    target: Target,
    monitors: list[NormalizedChannelMonitor],
    *,
    observed_at: datetime,
) -> tuple[list[ChannelMonitorCurrent], list[ChannelMonitorCurrent]]:
    current = list(
        await session.scalars(
            select(ChannelMonitorCurrent).where(ChannelMonitorCurrent.target_id == target.id)
        )
    )
    output: list[ChannelMonitorCurrent] = []
    seen: set[str] = set()
    for monitor in monitors:
        seen.add(monitor.external_monitor_id)
        item = await upsert_channel_monitor(
            session, target.id, monitor, observed_at=observed_at
        )
        output.append(item)
    removed = [item for item in current if item.external_monitor_id not in seen]
    return output, removed


def channel_payload(payload: dict[str, Any], *, include_target: bool = False) -> dict[str, Any]:
    excluded = {"target_id"} if include_target else set()
    result = {key: value for key, value in payload.items() if key not in excluded}
    if result.get("endpoint") is not None:
        result["endpoint"] = str(result["endpoint"])
    return result
