from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import Settings
from app.connectors.sub2api import (
    ConnectorError,
    ContractError,
    Sub2APIConnector,
    normalize_account,
)


@pytest.mark.asyncio
async def test_probe_uses_bounded_read_only_endpoints(settings_dict: dict[str, object]) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/admin/system/version":
            return httpx.Response(200, json={"code": 0, "data": {"version": "1.2.3"}})
        if request.url.path == "/api/v1/admin/accounts":
            page = int(request.url.params["page"])
            items = (
                [
                    {
                        "id": 1,
                        "name": "one",
                        "platform": "openai",
                        "type": "oauth",
                        "status": "active",
                        "schedulable": True,
                        "credentials": {"access_token": "must-not-survive"},
                        "extra": {"session": "must-not-survive"},
                    },
                    {
                        "id": 2,
                        "name": "two",
                        "platform": "anthropic",
                        "type": "oauth",
                        "status": "active",
                        "schedulable": True,
                    },
                ]
                if page == 1
                else [
                    {
                        "id": 3,
                        "name": "three",
                        "platform": "gemini",
                        "type": "oauth",
                        "status": "error",
                        "schedulable": False,
                    }
                ]
            )
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {"items": items, "total": 3, "page": page, "page_size": 2, "pages": 2},
                },
            )
        raise AssertionError(f"unexpected endpoint: {request.url}")

    settings = Settings(**settings_dict)
    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=settings,
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        result = await connector.probe()

    assert result.version_text == "1.2.3"
    assert result.accounts.support_state == "supported"
    assert [item.external_account_id for item in result.normalized_accounts] == ["1", "2", "3"]
    assert result.normalized_accounts[0].observation_payload().get("credentials") is None
    assert result.normalized_accounts[0].observation_payload().get("extra") is None
    assert all("/usage" not in request.url.path for request in requests)
    assert [
        request.url.params.get("page")
        for request in requests
        if request.url.path.endswith("accounts")
    ] == ["1", "2"]
    assert all(
        request.headers.get("x-api-key") == "secret"
        for request in requests
        if request.url.path != "/health"
    )


@pytest.mark.asyncio
async def test_passive_usage_never_requests_active_source(settings_dict: dict[str, object]) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "source": "passive",
                    "updated_at": "2026-08-03T01:00:00Z",
                    "five_hour": {"utilization": 82, "resets_at": "2026-08-03T05:00:00Z"},
                },
            },
        )

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="bearer",
        secret={"access_token": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    account = normalize_account(
        {
            "id": 7,
            "name": "anthropic",
            "platform": "anthropic",
            "type": "oauth",
            "status": "active",
            "schedulable": True,
        }
    )
    async with connector:
        windows = await connector.passive_usage(account)
    assert windows[0].remaining_percent == 18
    assert seen[0].url.params.get("source") == "passive"
    assert "force" not in seen[0].url.params


@pytest.mark.asyncio
async def test_active_usage_parses_openai_usage_without_force(
    settings_dict: dict[str, object],
) -> None:
    seen: list[httpx.Request] = []
    now = datetime.now(timezone.utc)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "source": "active",
                    "updated_at": now.isoformat(),
                    "five_hour": {
                        "utilization": 81.5,
                        "resets_at": (now + timedelta(hours=2)).isoformat(),
                        "window_stats": {"raw": "ignored"},
                    },
                    "seven_day": {
                        "utilization": 40,
                        "resets_at": (now + timedelta(days=5)).isoformat(),
                    },
                    "antigravity_quota": {"raw": "ignored"},
                },
            },
        )

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    account = normalize_account(
        {
            "id": 11,
            "name": "openai-oauth",
            "platform": "openai",
            "type": "oauth",
            "status": "active",
            "schedulable": True,
        }
    )
    async with connector:
        fact, windows = await connector.active_usage(account)

    assert fact.support_state == "supported"
    assert fact.runtime_state == "healthy"
    assert [window.quota_key for window in windows] == [
        "codex.five_hour",
        "codex.seven_day",
    ]
    assert [window.label for window in windows] == ["Codex 5 hour quota", "Codex 7 day quota"]
    assert windows[0].remaining_percent == pytest.approx(18.5)
    assert windows[0].source == "sub2api_api_active"
    assert dict(seen[0].url.params) == {"source": "active"}
    assert "force" not in seen[0].url.params


@pytest.mark.asyncio
async def test_active_usage_rejects_apikey_without_request(
    settings_dict: dict[str, object],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        raise AssertionError("unsupported account must not be called")

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    account = normalize_account(
        {
            "id": 12,
            "name": "local-key",
            "platform": "openai",
            "type": "apikey",
            "status": "active",
            "schedulable": True,
        }
    )
    async with connector:
        fact, windows = await connector.active_usage(account)

    assert fact.support_state == "unsupported"
    assert windows == []
    assert seen == []


def test_effective_availability_and_local_quota() -> None:
    now = datetime.now(timezone.utc)
    account = normalize_account(
        {
            "id": 10,
            "name": "limited",
            "platform": "openai",
            "type": "apikey",
            "status": "active",
            "schedulable": True,
            "rate_limit_reset_at": (now + timedelta(minutes=5)).isoformat(),
            "quota_limit": 100,
            "quota_used": 95,
        },
        now,
    )
    assert not account.available
    assert account.availability_reasons == ["rate_limited"]
    assert account.quotas[0].remaining_percent == pytest.approx(5)
    assert account.quotas[0].remaining_value == pytest.approx(5)


@pytest.mark.asyncio
async def test_connector_rejects_oversized_decompressed_response(
    settings_dict: dict[str, object],
) -> None:
    settings_dict["connector_max_response_bytes"] = 65_536

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 65_537)

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        with pytest.raises(ContractError, match="size limit"):
            await connector.request("GET", "/api/v1/admin/accounts")


@pytest.mark.asyncio
async def test_connector_does_not_decode_compressed_response_twice(
    settings_dict: dict[str, object],
) -> None:
    compressed = gzip.compress(b'{"code":0,"data":{"version":"1.2.3"}}')

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
            content=compressed,
        )

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        fact, version = await connector.version()

    assert fact.runtime_state == "healthy"
    assert version == "1.2.3"


@pytest.mark.asyncio
async def test_monitoring_snapshot_covers_ops_groups_and_redacts_secrets(
    settings_dict: dict[str, object],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/alert-events") or request.url.path.endswith("/groups/all"):
            data: object = []
        else:
            data = {
                "token_consumed": 42,
                "credentials": {"access_token": "must-not-survive"},
                "nested": {"api_key": "must-not-survive", "healthy": True},
            }
        return httpx.Response(200, json={"code": 0, "data": data})

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        facts, snapshot = await connector.monitoring_snapshot("1h", page_size=5)

    assert facts["ops.dashboard"].runtime_state == "healthy"
    assert facts["groups.inventory"].support_state == "supported"
    assert snapshot["resources"]["ops_snapshot"]["token_consumed"] == 42
    assert "credentials" not in snapshot["resources"]["ops_snapshot"]
    assert "api_key" not in snapshot["resources"]["ops_snapshot"]["nested"]
    realtime = next(
        request for request in seen if request.url.path.endswith("/ops/realtime-traffic")
    )
    token_stats = next(
        request for request in seen if request.url.path.endswith("/openai-token-stats")
    )
    request_errors = next(
        request for request in seen if request.url.path.endswith("/ops/request-errors")
    )
    assert realtime.url.params["window"] == "5m"
    assert token_stats.url.params["time_range"] == "1h"
    assert request_errors.url.params["page_size"] == "5"


@pytest.mark.asyncio
async def test_account_usage_stats_is_bounded_sanitized_and_encoded(
    settings_dict: dict[str, object],
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "code": 0,
                "data": {
                    "history": [{"date": "2026-08-08", "requests": 12}],
                    "summary": {
                        "total_requests": 12,
                        "credentials": {"access_token": "must-not-survive"},
                    },
                    "models": [
                        {"model": "gpt-5", "requests": 12, "api_key": "must-not-survive"}
                    ],
                    "endpoints": [],
                    "upstream_endpoints": [],
                    "request_body": {"secret": "must-not-survive"},
                },
            },
        )

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        result = await connector.account_usage_stats("account/with space", days=7)

    assert seen[0].url.path == "/api/v1/admin/accounts/account/with space/stats"
    assert seen[0].url.raw_path.startswith(b"/api/v1/admin/accounts/account%2Fwith%20space/stats")
    assert seen[0].url.params["days"] == "7"
    assert result["summary"]["total_requests"] == 12
    assert "credentials" not in result["summary"]
    assert "api_key" not in result["models"][0]
    assert "request_body" not in result


@pytest.mark.asyncio
async def test_account_usage_stats_rejects_invalid_contract_and_http_errors(
    settings_dict: dict[str, object],
) -> None:
    responses = iter(
        [
            httpx.Response(200, json={"code": 0, "data": {"summary": {}}}),
            httpx.Response(403, json={"code": 403, "message": "forbidden"}),
        ]
    )

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(lambda _: next(responses)),
    )
    async with connector:
        with pytest.raises(ContractError, match="invalid account usage stats"):
            await connector.account_usage_stats("1")
        with pytest.raises(ConnectorError, match="HTTP 403") as error:
            await connector.account_usage_stats("1")
    assert getattr(error.value, "status_code", None) == 403


@pytest.mark.asyncio
async def test_connector_pins_validated_dns_address(
    settings_dict: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings_dict["allow_private_targets"] = False

    async def resolved(_: str, *, allow_private: bool) -> str:
        assert not allow_private
        return "203.0.113.10"

    monkeypatch.setattr("app.connectors.sub2api.resolve_target_address", resolved)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "203.0.113.10"
        assert request.headers["host"] == "target.example"
        return httpx.Response(200, json={"code": 0, "data": {"version": "1.0"}})

    connector = Sub2APIConnector(
        base_url="https://target.example",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        fact, version = await connector.version()
    assert fact.runtime_state == "healthy"
    assert version == "1.0"


@pytest.mark.asyncio
async def test_upstream_billing_and_channel_monitor_contracts(
    settings_dict: dict[str, object],
) -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path.endswith("upstream-billing-probe/batch"):
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "results": [
                            {"account_id": 11, "snapshot": {"status": "ok"}}
                        ]
                    },
                },
            )
        if request.url.path.endswith("upstream-billing-probe/settings"):
            return httpx.Response(
                200, json={"code": 0, "data": {"enabled": True, "interval_minutes": 15}}
            )
        if request.url.path == "/api/v1/admin/channel-monitors":
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "items": [
                            {
                                "id": 9,
                                "name": "Codex",
                                "provider": "openai",
                                "endpoint": "https://upstream.example.com",
                                "primary_model": "gpt-5.3-codex",
                                "enabled": True,
                                "interval_seconds": 60,
                                "primary_status": "operational",
                                "primary_latency_ms": 321,
                                "availability_7d": 99.5,
                            }
                        ],
                        "pages": 1,
                    },
                },
            )
        if request.url.path.endswith("/run"):
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "results": [
                            {
                                "model": "gpt-5.3-codex",
                                "status": "operational",
                                "latency_ms": 300,
                                "ping_latency_ms": 20,
                                "message": "ok",
                                "checked_at": "2026-08-08T00:00:00Z",
                            }
                        ]
                    },
                },
            )
        if request.url.path.endswith("/history"):
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "items": [
                            {
                                "model": "gpt-5.3-codex",
                                "status": "degraded",
                                "latency_ms": 900,
                                "ping_latency_ms": 25,
                                "message": "slow",
                                "checked_at": "2026-08-07T00:00:00Z",
                            }
                        ]
                    },
                },
            )
        raise AssertionError(f"unexpected endpoint: {request.method} {request.url}")

    connector = Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "secret"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    )
    async with connector:
        billing_fact, settings = await connector.upstream_billing_probe_settings()
        billing_batch = await connector.probe_upstream_billing_batch(["11"])
        channel_fact, channels = await connector.channel_monitors()
        run = await connector.run_channel_monitor("9")
        history = await connector.channel_monitor_history("9", model="gpt-5.3-codex")

    assert billing_fact.support_state == "supported"
    assert settings == {"enabled": True, "interval_minutes": 15}
    assert billing_batch[0]["snapshot"] == {"status": "ok"}
    assert channel_fact.runtime_state == "healthy"
    assert channels[0].primary_status == "operational"
    assert channels[0].availability_7d == pytest.approx(99.5)
    assert run[0].latency_ms == 300
    assert history[0].status == "degraded"
    assert ("POST", "/api/v1/admin/channel-monitors/9/run") in seen


def test_account_normalizes_upstream_billing_snapshot() -> None:
    account = normalize_account(
        {
            "id": 3,
            "name": "relay",
            "platform": "openai",
            "type": "apikey",
            "status": "active",
            "schedulable": True,
            "rate_multiplier": 0.2,
            "extra": {
                "upstream_billing_probe_enabled": True,
                "upstream_billing_rate_sync_enabled": True,
                "upstream_billing_probe": {
                    "status": "ok",
                    "last_attempt_at": "2026-08-08T00:00:00Z",
                    "data": {"resolved_rate_multiplier": 0.18},
                    "credential": "must-not-survive",
                },
            },
        }
    )

    assert account.rate_multiplier == pytest.approx(0.2)
    assert account.upstream_billing_probe_enabled
    assert account.upstream_billing_rate_sync_enabled
    assert account.upstream_billing_probe is not None
    assert account.upstream_billing_probe["data"] == {"resolved_rate_multiplier": 0.18}
    assert "credential" not in account.upstream_billing_probe
