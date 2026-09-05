from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select
from test_connector import _channel_quality_matrix_data

from app.api import router as api_router
from app.api.router import update_cost_routing_policy
from app.config import Settings
from app.connectors.sub2api import ContractError, ProbeFact, Sub2APIConnector, normalize_account
from app.models import (
    AccountCurrent,
    CostRoutingPolicy,
    NotificationChannel,
    NotificationOutbox,
    Target,
    User,
)
from app.schemas import CostRoutingPolicyUpdate
from app.security import SecretCipher
from app.services import cost_routing


async def test_dormant_binding_cannot_block_normal_save_or_disable(db_session):
    target = Target(id="dormant-target", name="Dormant", base_url="https://example.com")
    policy = CostRoutingPolicy(
        target_id=target.id, enabled=True, quality_bindings={"deleted-account": ["deleted-monitor"]}
    )
    db_session.add_all([target, policy])
    await db_session.commit()
    for payload in (
        CostRoutingPolicyUpdate(quality_bindings=policy.quality_bindings, priority_scale=1200),
        CostRoutingPolicyUpdate(priority_scale=1300),
    ):
        saved = await update_cost_routing_policy(
            target.id, payload, User(username="admin", password_hash="unused"), db_session
        )
        assert not saved.enabled
        assert saved.priority_scale == payload.priority_scale
        assert saved.quality_bindings == {"deleted-account": ["deleted-monitor"]}


async def test_three_accounts_ceiling_fallback_and_sudden_recovery(
    db_session, settings_dict, monkeypatch
):
    now = datetime.now(timezone.utc)
    target = Target(
        id="cost-gate",
        name="Gate",
        base_url="https://example.com",
        enabled=True,
        monitoring_readiness="ready",
    )
    policy = CostRoutingPolicy(
        id="cost-policy",
        target_id=target.id,
        enabled=True,
        mode="execute",
        fallback_account_ids=["3"],
        fallback_priorities={"3": 300},
    )
    db_session.add_all(
        [
            target,
            policy,
            NotificationChannel(
                id="gate-ntfy",
                target_id=target.id,
                name="ntfy",
                server_url="https://ntfy.example.com",
                topic="gate",
            ),
        ]
    )
    await db_session.commit()
    rates = {"1": 0.3, "2": 0.5, "3": 0.8}
    raw = {
        id: dict(
            id=id,
            name=id,
            platform="openai",
            type="apikey",
            status="active",
            schedulable=True,
            priority=100,
            extra={},
        )
        for id in rates
    }
    writes = []

    class Connector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def accounts(self):
            return ProbeFact("supported", "healthy", "fresh"), [
                normalize_account(item, now) for item in raw.values()
            ]

        async def probe_upstream_billing_batch(self, ids):
            return [
                {
                    "account_id": id,
                    "snapshot": {"status": "ok", "data": {"effective_rate_multiplier": rates[id]}},
                }
                for id in ids
            ]

        async def set_account_priority(self, id, priority, *, control):
            raw[id]["priority"] = priority
            raw[id]["extra"]["monitor_cost_routing"] = dict(control)
            writes.append(id)
            return {"priority": priority, "control": control}

    async def target_lookup(*_):
        return target

    async def connector_lookup(*_):
        return Connector()

    monkeypatch.setattr(cost_routing, "target_with_secret", target_lookup)
    monkeypatch.setattr(cost_routing, "connector_for_target", connector_lookup)
    settings = Settings(**settings_dict)

    async def run():
        assert await cost_routing.run_cost_routing_policy(
            db_session, policy.id, settings, SecretCipher(settings.master_key), actor="test"
        )

    await run()
    assert all(not a["extra"]["monitor_cost_routing"]["suppressed"] for a in raw.values())
    rates.update({"1": 1, "2": 3, "3": 5})
    await run()
    assert raw["1"]["extra"]["monitor_cost_routing"]["suppressed"]
    assert raw["2"]["extra"]["monitor_cost_routing"]["suppressed"]
    assert not raw["3"]["extra"]["monitor_cost_routing"]["suppressed"]
    assert all(a["schedulable"] for a in raw.values())
    rates["1"] = 0.1
    await run()
    assert raw["1"]["priority"] == 100
    assert not raw["1"]["extra"]["monitor_cost_routing"]["suppressed"]
    assert any(
        "recovered" in n.payload.get("title", "")
        for n in await db_session.scalars(select(NotificationOutbox))
    )
    writes.clear()
    await run()
    assert writes == []  # State-confirmed steady state does not rewrite the gate.


@pytest.mark.parametrize(
    "reported_lag,age,expected", [(0, 7200, "stale"), (7200, 0, "stale"), (0, 30, "fresh")]
)
async def test_quality_freshness_uses_both_watermark_and_clock(
    settings_dict, reported_lag, age, expected
):
    now = datetime.now(timezone.utc)

    def handler(request):
        if request.url.path.endswith("/matrix"):
            matrix = _channel_quality_matrix_data()
            matrix["coverage"].update(
                data_through=(now - timedelta(seconds=age)).isoformat(),
                computed_at=(now - timedelta(seconds=age)).isoformat(),
                aggregation_lag_seconds=reported_lag,
            )
            return httpx.Response(200, json={"code": 0, "data": matrix})
        return httpx.Response(200, json={"code": 0, "data": []})

    async with Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "test"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    ) as connector:
        snapshot = await connector.channel_quality_snapshot()
    assert snapshot["coverage"]["freshness"] == expected
    assert snapshot["coverage"]["coverage_complete"] is True
    assert snapshot["items"][0]["health"]["overall"] == (
        "unknown" if expected == "stale" else "healthy"
    )


async def test_quality_separates_account_costs_and_target_scope(
    db_session, settings_dict, monkeypatch
):
    now = datetime.now(timezone.utc)
    target = Target(id="quality-cost", name="Quality", base_url="https://example.com")
    other = Target(id="other-quality-cost", name="Other", base_url="https://other.example.com")

    def account(id, tid, groups, multiplier):
        return AccountCurrent(
            id=id,
            target_id=tid,
            external_account_id=id,
            name=id,
            platform="openai",
            account_type="apikey",
            status="active",
            schedulable=True,
            available=True,
            last_seen_at=now,
            group_ids=groups,
            observed_at=now,
            rate_multiplier=0.3,
            upstream_billing_probe={
                "status": "ok",
                "data": {"effective_rate_multiplier": multiplier},
            },
        )

    db_session.add_all(
        [
            target,
            other,
            account("first", target.id, ["7"], 0.3),
            account("raised", target.id, ["7"], 3),
            account("different-group", target.id, ["8"], 8),
            account("foreign", other.id, ["7"], 9),
        ]
    )
    await db_session.commit()

    class Connector:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def channel_quality_snapshot(self, _):
            return {"items": [{"platform": "openai", "group_id": 7, "rate_multiplier": 0.3}]}

    async def lookup(*_):
        return target, Connector()

    monkeypatch.setattr(api_router, "_target_connector_or_404", lookup)
    settings = Settings(**settings_dict)
    result = await api_router.target_channel_quality(
        target.id,
        User(username="admin", password_hash="unused"),
        db_session,
        settings,
        SecretCipher(settings.master_key),
        "6h",
    )
    row = result["items"][0]
    assert row["rate_multiplier"] == 0.3
    assert {a["name"]: a["upstream_multiplier"] for a in row["accounts"]} == {
        "first": 0.3,
        "raised": 3,
    }


@pytest.mark.parametrize("header", [None, "1"])
async def test_usage_cursor_requires_explicit_contract_and_advances_non_session_rows(
    settings_dict, header
):
    def handler(request):
        assert request.url.params["after_id"] == "100"
        assert request.url.params["sort_order"] == "asc"
        return httpx.Response(
            200,
            headers={"X-Usage-Cursor-Version": header} if header else {},
            json={"code": 0, "data": {"items": [{"id": 101}]}},
        )

    async with Sub2APIConnector(
        base_url="http://target.test",
        auth_type="x_api_key",
        secret={"api_key": "test"},
        settings=Settings(**settings_dict),
        transport=httpx.MockTransport(handler),
    ) as connector:
        if header:
            assert await connector.usage_route_page(100) == ([], 101, False)
        else:
            with pytest.raises(ContractError, match="upgrade Sub2API"):
                await connector.usage_route_page(100)
