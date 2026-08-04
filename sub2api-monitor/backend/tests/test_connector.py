from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import Settings
from app.connectors.sub2api import ContractError, Sub2APIConnector, normalize_account


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
