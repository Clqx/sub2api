from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.config import Settings
from app.connectors.postgres import (
    ACCOUNT_COLUMNS,
    EXTRA_KEYS,
    Sub2APIPostgresConnector,
    account_identity_fingerprint,
    account_identity_record,
    resolve_database_address,
)
from app.connectors.sub2api import ConnectorError


class FakeTransaction:
    def __init__(self) -> None:
        self.started = False
        self.rolled_back = False

    async def start(self) -> None:
        self.started = True

    async def rollback(self) -> None:
        self.rolled_back = True


class FakeConnection:
    def __init__(
        self,
        snapshot: dict[str, Any],
        *,
        can_select: bool = True,
        can_write: bool = False,
        transaction_read_only: str = "on",
    ) -> None:
        self.snapshot = snapshot
        self.can_select = can_select
        self.can_write = can_write
        self.transaction_read_only = transaction_read_only
        self.transaction_value = FakeTransaction()
        self.readonly: bool | None = None
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.queries: list[str] = []
        self.closed = False

    def transaction(self, *, readonly: bool) -> FakeTransaction:
        self.readonly = readonly
        return self.transaction_value

    async def execute(self, query: str, *args: Any) -> None:
        self.executed.append((query, args))

    async def fetch(self, query: str, *_: Any) -> list[dict[str, Any]]:
        self.queries.append(query)
        if "information_schema.columns" in query:
            return [{"column_name": name, "data_type": "text"} for name in ACCOUNT_COLUMNS]
        if query.startswith("SELECT id, name, platform, type FROM"):
            return [{"id": 7, "name": "codex", "platform": "openai", "type": "oauth"}]
        return [self.snapshot]

    async def fetchval(self, query: str, *_: Any) -> str:
        assert "transaction_read_only" in query
        return self.transaction_read_only

    async def fetchrow(self, query: str, *_: Any) -> dict[str, bool]:
        assert "has_table_privilege" in query
        return {"can_select": self.can_select, "can_write": self.can_write}

    async def close(self) -> None:
        self.closed = True


async def test_database_connector_uses_readonly_bounded_allowlisted_queries(
    settings_dict: dict[str, object],
) -> None:
    snapshot = {
        "id": 7,
        "name": "codex",
        "platform": "openai",
        "type": "oauth",
        "status": "active",
        "schedulable": True,
        "expires_at": None,
        "auto_pause_on_expired": True,
        "rate_limit_reset_at": None,
        "overload_until": None,
        "temp_unschedulable_until": None,
        "updated_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
        "quota_limit": "100",
        "quota_used": "25",
        "quota_daily_limit": None,
        "quota_daily_used": None,
        "quota_daily_reset_at": None,
        "quota_weekly_limit": None,
        "quota_weekly_used": None,
        "quota_weekly_reset_at": None,
        "codex_5h_used_percent": "82.5",
        "codex_5h_reset_at": "2026-08-03T10:00:00Z",
        "codex_7d_used_percent": "40",
        "codex_7d_reset_at": "2026-08-10T00:00:00Z",
        "codex_usage_updated_at": "2026-08-03T09:00:00Z",
        "passive_usage_7d_utilization": None,
        "passive_usage_7d_reset": None,
        "passive_usage_7d_oi_utilization": None,
        "passive_usage_7d_oi_reset": None,
        "passive_usage_sampled_at": None,
    }
    connection = FakeConnection(snapshot)

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api",
        settings=Settings(**settings_dict),
        connect=connect,
    )
    fact, accounts, schema_fingerprint = await connector.accounts()

    assert fact.runtime_state == "healthy"
    assert connection.readonly is True
    assert connection.transaction_value.started is True
    assert connection.transaction_value.rolled_back is True
    assert connection.closed is True
    assert [args[0] for _, args in connection.executed] == ["5000ms", "1000ms"]
    account_query = connection.queries[-1]
    assert "credentials" not in account_query
    assert "SELECT extra" not in account_query
    assert "extra ->>" in account_query
    assert all(key in account_query for key in EXTRA_KEYS)
    assert len(accounts) == 1
    assert schema_fingerprint is not None
    quotas = {window.quota_key: window for window in accounts[0].quotas}
    assert quotas["local.total"].remaining_value == 75
    assert quotas["codex.five_hour"].remaining_percent == 17.5
    assert quotas["codex.five_hour"].source == "sub2api_db_passive"
    assert quotas["codex.five_hour"].observed_at == datetime(2026, 8, 3, 9, tzinfo=timezone.utc)


async def test_probe_returns_only_hashed_binding_input(
    settings_dict: dict[str, object],
) -> None:
    connection = FakeConnection({})

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api",
        settings=Settings(**settings_dict),
        connect=connect,
    )
    result = await connector.probe()

    assert result.account_ids == ["7"]
    identity = account_identity_record("7", "codex", "openai", "oauth")
    fingerprint = account_identity_fingerprint([identity])
    assert fingerprint == result.identity_fingerprint
    assert fingerprint == account_identity_fingerprint([identity, identity])
    assert fingerprint != account_identity_fingerprint(
        [account_identity_record("7", "different", "openai", "oauth")]
    )
    assert fingerprint is not None and len(fingerprint) == 64 and fingerprint != "7"


async def test_probe_rejects_role_with_write_privileges(
    settings_dict: dict[str, object],
) -> None:
    connection = FakeConnection({}, can_write=True)

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://owner:secret@db:5432/sub2api",
        settings=Settings(**settings_dict),
        connect=connect,
    )

    try:
        await connector.probe()
    except RuntimeError as exc:
        assert str(exc) == "target database role has write access to public.accounts"
    else:
        raise AssertionError("write-capable database role was accepted")
    assert connection.transaction_value.rolled_back is True
    assert connection.closed is True


async def test_probe_rejects_role_without_select_privilege(
    settings_dict: dict[str, object],
) -> None:
    connection = FakeConnection({}, can_select=False)

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://noaccess:secret@db:5432/sub2api",
        settings=Settings(**settings_dict),
        connect=connect,
    )

    try:
        await connector.probe()
    except RuntimeError as exc:
        assert str(exc) == "target database role cannot read public.accounts"
    else:
        raise AssertionError("database role without SELECT was accepted")


async def test_probe_rejects_non_readonly_transaction(
    settings_dict: dict[str, object],
) -> None:
    connection = FakeConnection({}, transaction_read_only="off")

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api",
        settings=Settings(**settings_dict),
        connect=connect,
    )

    try:
        await connector.probe()
    except RuntimeError as exc:
        assert str(exc) == "target database transaction is not read-only"
    else:
        raise AssertionError("non-readonly transaction was accepted")


async def test_public_database_connection_uses_resolved_ip(
    settings_dict: dict[str, object], monkeypatch
) -> None:
    connection = FakeConnection({})
    connect_kwargs: dict[str, Any] = {}

    async def resolve(*_: Any, **__: Any) -> str:
        return "203.0.113.9"

    async def connect(*_: Any, **kwargs: Any) -> FakeConnection:
        connect_kwargs.update(kwargs)
        return connection

    monkeypatch.setattr("app.connectors.postgres.resolve_database_address", resolve)
    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db.example.com:5432/sub2api",
        settings=Settings(**{**settings_dict, "allow_private_targets": False}),
        connect=connect,
    )

    await connector.probe()

    assert connect_kwargs["host"] == "203.0.113.9"


async def test_database_connection_uses_supplied_ca_certificate(
    settings_dict: dict[str, object], monkeypatch
) -> None:
    connection = FakeConnection({})
    connect_kwargs: dict[str, Any] = {}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    captured: dict[str, str] = {}

    def create_default_context(*, cadata: str) -> ssl.SSLContext:
        captured["cadata"] = cadata
        return context

    async def connect(*_: Any, **kwargs: Any) -> FakeConnection:
        connect_kwargs.update(kwargs)
        return connection

    monkeypatch.setattr(
        "app.connectors.postgres.ssl.create_default_context", create_default_context
    )
    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api?sslmode=require",
        ca_certificate="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        settings=Settings(**settings_dict),
        connect=connect,
    )

    await connector.probe()

    assert captured["cadata"].startswith("-----BEGIN CERTIFICATE-----")
    assert connect_kwargs["ssl"] is context
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is False


async def test_database_connection_rejects_invalid_ca_certificate(
    settings_dict: dict[str, object],
) -> None:
    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api?sslmode=require",
        ca_certificate="not-a-certificate",
        settings=Settings(**settings_dict),
    )

    with pytest.raises(ConnectorError, match="CA certificate is invalid"):
        await connector.probe()


async def test_database_connection_reports_gateway_reset(
    settings_dict: dict[str, object],
) -> None:
    async def connect(*_: Any, **__: Any) -> FakeConnection:
        raise ConnectionResetError("gateway reset")

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api?sslmode=require",
        settings=Settings(**settings_dict),
        connect=connect,
    )

    with pytest.raises(ConnectorError, match="TCP gateway allowlist"):
        await connector.probe()


async def test_public_database_rejects_verify_full_before_connection() -> None:
    with pytest.raises(ConnectorError, match="cannot preserve hostname verification"):
        await resolve_database_address(
            "postgresql://readonly:secret@db.example.com:5432/sub2api?sslmode=verify-full",
            allow_private=False,
        )


async def test_private_database_allows_verify_full_without_dns_pinning() -> None:
    assert (
        await resolve_database_address(
            "postgresql://readonly:secret@db:5432/sub2api?sslmode=verify-full",
            allow_private=True,
        )
        is None
    )


async def test_expired_or_old_database_quota_is_stale(
    settings_dict: dict[str, object],
) -> None:
    old = datetime.now(timezone.utc) - timedelta(days=5)
    snapshot: dict[str, Any] = {key: None for key in EXTRA_KEYS}
    snapshot.update(
        {
            "id": 9,
            "name": "old-codex",
            "platform": "openai",
            "type": "oauth",
            "status": "active",
            "schedulable": True,
            "expires_at": None,
            "auto_pause_on_expired": True,
            "rate_limit_reset_at": None,
            "overload_until": None,
            "temp_unschedulable_until": None,
            "updated_at": old,
            "codex_5h_used_percent": "99",
            "codex_5h_reset_at": old.isoformat(),
            "codex_usage_updated_at": old.isoformat(),
        }
    )
    connection = FakeConnection(snapshot)

    async def connect(*_: Any, **__: Any) -> FakeConnection:
        return connection

    connector = Sub2APIPostgresConnector(
        database_url="postgresql://readonly:secret@db:5432/sub2api",
        settings=Settings(**settings_dict, target_quota_stale_seconds=3600),
        connect=connect,
    )
    _, accounts, _ = await connector.accounts()

    assert accounts[0].quotas[0].freshness == "stale"
    assert connection.transaction_value.rolled_back is True
