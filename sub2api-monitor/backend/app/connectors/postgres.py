from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import parse_qs, urlparse

import asyncpg  # type: ignore[import-untyped]

from app.config import Settings
from app.connectors.sub2api import ConnectorError, ProbeFact, QuotaWindow

ACCOUNT_COLUMNS = frozenset(
    {
        "id",
        "name",
        "platform",
        "type",
        "status",
        "schedulable",
        "expires_at",
        "auto_pause_on_expired",
        "rate_limit_reset_at",
        "overload_until",
        "temp_unschedulable_until",
        "updated_at",
        "deleted_at",
        "extra",
    }
)

EXTRA_KEYS = (
    "quota_limit",
    "quota_used",
    "quota_daily_limit",
    "quota_daily_used",
    "quota_daily_reset_at",
    "quota_weekly_limit",
    "quota_weekly_used",
    "quota_weekly_reset_at",
    "codex_5h_used_percent",
    "codex_5h_reset_at",
    "codex_7d_used_percent",
    "codex_7d_reset_at",
    "codex_usage_updated_at",
    "passive_usage_7d_utilization",
    "passive_usage_7d_reset",
    "passive_usage_7d_oi_utilization",
    "passive_usage_7d_oi_reset",
    "passive_usage_sampled_at",
)

IDENTITY_COLUMNS = frozenset({"id", "name", "platform", "type"})

SCHEMA_QUERY = """
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'accounts'
ORDER BY ordinal_position
"""

PERMISSION_QUERY = """
SELECT
    has_column_privilege(current_user, 'public.accounts', 'id', 'SELECT') AS can_select,
    has_table_privilege(current_user, 'public.accounts', 'INSERT')
        OR has_table_privilege(current_user, 'public.accounts', 'UPDATE')
        OR has_table_privilege(current_user, 'public.accounts', 'DELETE')
        OR has_table_privilege(current_user, 'public.accounts', 'TRUNCATE') AS can_write
"""

ConnectCallback = Callable[..., Awaitable[Any]]
ResultT = TypeVar("ResultT")


@dataclass(slots=True)
class DatabaseAccountSnapshot:
    external_account_id: str
    name: str | None
    platform: str | None
    account_type: str | None
    status: str | None
    schedulable: bool | None
    expires_at: datetime | None
    auto_pause_on_expired: bool | None
    rate_limit_reset_at: datetime | None
    overload_until: datetime | None
    temp_unschedulable_until: datetime | None
    observed_at: datetime
    quotas: list[QuotaWindow] = field(default_factory=list)


@dataclass(slots=True)
class DatabaseProbeResult:
    fact: ProbeFact
    account_ids: list[str]
    identity_fingerprint: str | None
    schema_fingerprint: str | None
    columns: frozenset[str]


def account_identity_record(
    external_account_id: object,
    name: object,
    platform: object,
    account_type: object,
) -> tuple[str, str, str, str]:
    return (
        str(external_account_id),
        str(name or ""),
        str(platform or "").casefold(),
        str(account_type or "").casefold(),
    )


def account_identity_fingerprint(
    account_records: list[tuple[str, str, str, str]],
) -> str | None:
    normalized = sorted({record for record in account_records if record[0]})
    if not normalized:
        return None
    digest = hashlib.sha256()
    digest.update(b"sub2api-account-identity-set-v2\0")
    for record in normalized:
        digest.update("\x1f".join(record).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


async def resolve_database_address(database_url: str, *, allow_private: bool) -> str | None:
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise ConnectorError("target database URL must use PostgreSQL")
    if not parsed.hostname or not parsed.path.strip("/"):
        raise ConnectorError("target database URL must include a host and database name")
    if allow_private:
        return None
    ssl_modes = {value.casefold() for value in parse_qs(parsed.query).get("sslmode", [])}
    if "verify-full" in ssl_modes:
        raise ConnectorError(
            "public target database URLs with sslmode=verify-full are not supported "
            "because DNS pinning cannot preserve hostname verification"
        )
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo, parsed.hostname, parsed.port or 5432
        )
    except socket.gaierror as exc:
        raise ConnectorError("target database hostname cannot be resolved") from exc
    for item in addresses:
        if not ipaddress.ip_address(item[4][0]).is_global:
            raise ConnectorError(
                "target database resolves to a non-public address blocked by policy"
            )
    return str(ipaddress.ip_address(addresses[0][4][0]))


async def validate_database_url(database_url: str, *, allow_private: bool) -> None:
    await resolve_database_address(database_url, allow_private=allow_private)


class Sub2APIPostgresConnector:
    def __init__(
        self,
        *,
        database_url: str,
        settings: Settings,
        connect: ConnectCallback | None = None,
    ):
        self.database_url = _asyncpg_url(database_url)
        self.settings = settings
        self._connect = connect or asyncpg.connect

    async def probe(self) -> DatabaseProbeResult:
        async def operation(connection: Any) -> DatabaseProbeResult:
            rows = await connection.fetch(SCHEMA_QUERY)
            columns = frozenset(
                str(row["column_name"])
                for row in rows
                if str(row["column_name"]) in ACCOUNT_COLUMNS
            )
            if not IDENTITY_COLUMNS.issubset(columns):
                return DatabaseProbeResult(
                    ProbeFact(
                        "unsupported",
                        "unavailable",
                        "missing",
                        "public.accounts identity columns were not found",
                    ),
                    [],
                    None,
                    None,
                    columns,
                )
            await _validate_account_permissions(connection)
            where = " WHERE deleted_at IS NULL" if "deleted_at" in columns else ""
            identity_query = (
                f"SELECT id, name, platform, type FROM public.accounts{where} ORDER BY id LIMIT $1"
            )
            identity_rows = await connection.fetch(
                identity_query, self.settings.target_db_max_accounts + 1
            )
            if len(identity_rows) > self.settings.target_db_max_accounts:
                raise ConnectorError("target database account limit exceeded")
            account_ids = [str(row["id"]) for row in identity_rows]
            identity_fingerprint = account_identity_fingerprint(
                [
                    account_identity_record(row["id"], row["name"], row["platform"], row["type"])
                    for row in identity_rows
                ]
            )
            schema_text = "\0".join(sorted(columns))
            schema_fingerprint = hashlib.sha256(schema_text.encode("utf-8")).hexdigest()
            return DatabaseProbeResult(
                ProbeFact("supported", "healthy", "fresh"),
                account_ids,
                identity_fingerprint,
                schema_fingerprint,
                columns,
            )

        try:
            return await self._read_transaction(operation)
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorError("target database probe failed") from exc

    async def accounts(
        self,
    ) -> tuple[ProbeFact, list[DatabaseAccountSnapshot], str | None]:
        async def operation(connection: Any) -> tuple[list[DatabaseAccountSnapshot], str]:
            schema_rows = await connection.fetch(SCHEMA_QUERY)
            columns = frozenset(
                str(row["column_name"])
                for row in schema_rows
                if str(row["column_name"]) in ACCOUNT_COLUMNS
            )
            if not IDENTITY_COLUMNS.issubset(columns):
                raise ConnectorError("public.accounts identity columns were not found")
            await _validate_account_permissions(connection)
            query = _snapshot_query(columns)
            rows = await connection.fetch(query, self.settings.target_db_max_accounts + 1)
            if len(rows) > self.settings.target_db_max_accounts:
                raise ConnectorError("target database account limit exceeded")
            schema_fingerprint = hashlib.sha256(
                "\0".join(sorted(columns)).encode("utf-8")
            ).hexdigest()
            return (
                [
                    _normalize_snapshot(row, self.settings.target_quota_stale_seconds)
                    for row in rows
                ],
                schema_fingerprint,
            )

        try:
            snapshots, schema_fingerprint = await self._read_transaction(operation)
        except ConnectorError as exc:
            return ProbeFact("unknown", "unavailable", "missing", str(exc)), [], None
        except Exception:
            return (
                ProbeFact(
                    "unknown", "unavailable", "missing", "target database account read failed"
                ),
                [],
                None,
            )
        return ProbeFact("supported", "healthy", "fresh"), snapshots, schema_fingerprint

    async def _read_transaction(self, operation: Callable[[Any], Awaitable[ResultT]]) -> ResultT:
        pinned_ip = await resolve_database_address(
            self.database_url, allow_private=self.settings.allow_private_targets
        )
        connect_kwargs: dict[str, Any] = {
            "timeout": self.settings.target_db_connect_timeout_seconds
        }
        if pinned_ip is not None:
            connect_kwargs["host"] = pinned_ip
        connection = await self._connect(self.database_url, **connect_kwargs)
        transaction = connection.transaction(readonly=True)
        transaction_started = False
        try:
            await transaction.start()
            transaction_started = True
            await connection.execute(
                "SELECT set_config('statement_timeout', $1, true)",
                f"{self.settings.target_db_statement_timeout_ms}ms",
            )
            await connection.execute(
                "SELECT set_config('lock_timeout', $1, true)",
                f"{self.settings.target_db_lock_timeout_ms}ms",
            )
            transaction_read_only = await connection.fetchval(
                "SELECT current_setting('transaction_read_only')"
            )
            if transaction_read_only != "on":
                raise ConnectorError("target database transaction is not read-only")
            return await operation(connection)
        finally:
            try:
                if transaction_started:
                    await transaction.rollback()
            finally:
                await connection.close()


async def _validate_account_permissions(connection: Any) -> None:
    permissions = await connection.fetchrow(PERMISSION_QUERY)
    if permissions is None or not permissions["can_select"]:
        raise ConnectorError("target database role cannot read public.accounts")
    if permissions["can_write"]:
        raise ConnectorError("target database role has write access to public.accounts")


def _snapshot_query(columns: frozenset[str]) -> str:
    projections = [
        _column_projection(column, columns)
        for column in (
            "id",
            "name",
            "platform",
            "type",
            "status",
            "schedulable",
            "expires_at",
            "auto_pause_on_expired",
            "rate_limit_reset_at",
            "overload_until",
            "temp_unschedulable_until",
            "updated_at",
        )
    ]
    if "extra" in columns:
        projections.extend(f"extra ->> '{key}' AS {key}" for key in EXTRA_KEYS)
    else:
        projections.extend(f"NULL AS {key}" for key in EXTRA_KEYS)
    where = " WHERE deleted_at IS NULL" if "deleted_at" in columns else ""
    return "SELECT " + ", ".join(projections) + f" FROM public.accounts{where} ORDER BY id LIMIT $1"


def _column_projection(column: str, columns: frozenset[str]) -> str:
    return column if column in columns else f"NULL AS {column}"


def _normalize_snapshot(
    row: Mapping[str, Any], quota_stale_seconds: int
) -> DatabaseAccountSnapshot:
    now = datetime.now(timezone.utc)
    observed_at = _as_datetime(row.get("updated_at")) or now
    platform = _as_text(row.get("platform"))
    return DatabaseAccountSnapshot(
        external_account_id=str(row["id"]),
        name=_as_text(row.get("name")),
        platform=platform,
        account_type=_as_text(row.get("type")),
        status=_as_text(row.get("status")),
        schedulable=_as_bool(row.get("schedulable")),
        expires_at=_as_datetime(row.get("expires_at")),
        auto_pause_on_expired=_as_bool(row.get("auto_pause_on_expired")),
        rate_limit_reset_at=_as_datetime(row.get("rate_limit_reset_at")),
        overload_until=_as_datetime(row.get("overload_until")),
        temp_unschedulable_until=_as_datetime(row.get("temp_unschedulable_until")),
        observed_at=observed_at,
        quotas=_quota_windows(row, platform or "unknown", observed_at, quota_stale_seconds, now),
    )


def _quota_windows(
    row: Mapping[str, Any],
    provider: str,
    account_observed_at: datetime,
    stale_seconds: int,
    now: datetime,
) -> list[QuotaWindow]:
    windows: list[QuotaWindow] = []
    for key, label, used_key, limit_key, reset_key in (
        ("total", "Total local quota", "quota_used", "quota_limit", None),
        (
            "daily",
            "Daily local quota",
            "quota_daily_used",
            "quota_daily_limit",
            "quota_daily_reset_at",
        ),
        (
            "weekly",
            "Weekly local quota",
            "quota_weekly_used",
            "quota_weekly_limit",
            "quota_weekly_reset_at",
        ),
    ):
        used = _as_float(row.get(used_key))
        limit = _as_float(row.get(limit_key))
        if used is None or limit is None or limit <= 0:
            continue
        utilization = max(0.0, used / limit * 100.0)
        reset_at = _as_datetime(row.get(reset_key)) if reset_key else None
        windows.append(
            QuotaWindow(
                provider=provider,
                quota_key=f"local.{key}",
                label=label,
                utilization_percent=utilization,
                remaining_percent=max(0.0, 100.0 - utilization),
                used_value=used,
                limit_value=limit,
                remaining_value=max(0.0, limit - used),
                unit="currency",
                reset_at=reset_at,
                observed_at=account_observed_at,
                source="sub2api_db_passive",
                freshness=_quota_freshness(account_observed_at, reset_at, now, stale_seconds),
            )
        )

    codex_observed_at = _as_datetime(row.get("codex_usage_updated_at")) or account_observed_at
    for key, label, used_key, reset_key in (
        ("codex.five_hour", "Codex 5 hour quota", "codex_5h_used_percent", "codex_5h_reset_at"),
        ("codex.seven_day", "Codex 7 day quota", "codex_7d_used_percent", "codex_7d_reset_at"),
    ):
        codex_utilization = _as_float(row.get(used_key))
        if codex_utilization is None:
            continue
        reset_at = _as_datetime(row.get(reset_key))
        windows.append(
            QuotaWindow(
                provider=provider,
                quota_key=key,
                label=label,
                utilization_percent=codex_utilization,
                remaining_percent=max(0.0, 100.0 - codex_utilization),
                reset_at=reset_at,
                observed_at=codex_observed_at,
                source="sub2api_db_passive",
                freshness=_quota_freshness(codex_observed_at, reset_at, now, stale_seconds),
            )
        )

    passive_observed_at = _as_datetime(row.get("passive_usage_sampled_at")) or account_observed_at
    for key, label, used_key, reset_key in (
        (
            "seven_day",
            "7 day quota",
            "passive_usage_7d_utilization",
            "passive_usage_7d_reset",
        ),
        (
            "seven_day_fable",
            "7 day Fable quota",
            "passive_usage_7d_oi_utilization",
            "passive_usage_7d_oi_reset",
        ),
    ):
        utilization_fraction = _as_float(row.get(used_key))
        if utilization_fraction is None:
            continue
        utilization = utilization_fraction * 100.0
        reset_at = _as_datetime(row.get(reset_key))
        windows.append(
            QuotaWindow(
                provider=provider,
                quota_key=key,
                label=label,
                utilization_percent=utilization,
                remaining_percent=max(0.0, 100.0 - utilization),
                reset_at=reset_at,
                observed_at=passive_observed_at,
                source="sub2api_db_passive",
                freshness=_quota_freshness(passive_observed_at, reset_at, now, stale_seconds),
            )
        )
    return windows


def _asyncpg_url(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _quota_freshness(
    observed_at: datetime,
    reset_at: datetime | None,
    now: datetime,
    stale_seconds: int,
) -> str:
    observed = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=timezone.utc)
    reset = (
        reset_at if reset_at is None or reset_at.tzinfo else reset_at.replace(tzinfo=timezone.utc)
    )
    if (now - observed).total_seconds() > stale_seconds or (reset is not None and reset <= now):
        return "stale"
    return "fresh"


def _as_text(value: Any) -> str | None:
    return str(value) if value is not None else None


def _as_bool(value: Any) -> bool | None:
    return bool(value) if isinstance(value, bool) else None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.isdigit():
            return datetime.fromtimestamp(int(text), timezone.utc)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None
