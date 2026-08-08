from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from app.config import Settings


class ConnectorError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ContractError(ConnectorError):
    pass


@dataclass(slots=True)
class ProbeFact:
    support_state: str
    runtime_state: str
    freshness: str
    reason: str | None = None


@dataclass(slots=True)
class QuotaWindow:
    provider: str
    quota_key: str
    label: str
    utilization_percent: float | None = None
    remaining_percent: float | None = None
    used_value: float | None = None
    limit_value: float | None = None
    remaining_value: float | None = None
    unit: str = "percent"
    reset_at: datetime | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "sub2api_api"
    freshness: str = "fresh"


@dataclass(slots=True)
class NormalizedAccount:
    external_account_id: str
    name: str
    platform: str
    account_type: str
    status: str
    schedulable: bool
    available: bool
    availability_reasons: list[str]
    group_ids: list[str]
    expires_at: datetime | None
    rate_limit_reset_at: datetime | None
    overload_until: datetime | None
    temp_unschedulable_until: datetime | None
    observed_at: datetime
    rate_multiplier: float | None = None
    upstream_billing_probe_enabled: bool = False
    upstream_billing_rate_sync_enabled: bool = False
    upstream_billing_probe: dict[str, Any] | None = None
    quotas: list[QuotaWindow] = field(default_factory=list)

    def observation_payload(self) -> dict[str, Any]:
        return {
            "external_account_id": self.external_account_id,
            "name": self.name,
            "platform": self.platform,
            "account_type": self.account_type,
            "status": self.status,
            "schedulable": self.schedulable,
            "available": self.available,
            "availability_reasons": self.availability_reasons,
            "group_ids": self.group_ids,
            "expires_at": _iso(self.expires_at),
            "rate_limit_reset_at": _iso(self.rate_limit_reset_at),
            "overload_until": _iso(self.overload_until),
            "temp_unschedulable_until": _iso(self.temp_unschedulable_until),
            "rate_multiplier": self.rate_multiplier,
            "upstream_billing_probe_enabled": self.upstream_billing_probe_enabled,
            "upstream_billing_rate_sync_enabled": self.upstream_billing_rate_sync_enabled,
            "upstream_billing_probe": self.upstream_billing_probe,
        }


@dataclass(slots=True)
class ProbeResult:
    health: ProbeFact
    version: ProbeFact
    accounts: ProbeFact
    version_text: str | None
    normalized_accounts: list[NormalizedAccount]


@dataclass(slots=True)
class NormalizedChannelMonitor:
    external_monitor_id: str
    name: str
    provider: str
    api_mode: str
    endpoint: str
    api_key_masked: str
    api_key_decrypt_failed: bool
    primary_model: str
    extra_models: list[str]
    group_name: str
    enabled: bool
    interval_seconds: int
    jitter_seconds: int
    last_checked_at: datetime | None
    primary_status: str
    primary_latency_ms: int | None
    availability_7d: float
    extra_models_status: list[dict[str, Any]]
    template_id: str | None
    extra_headers: dict[str, str]
    body_override_mode: str
    body_override: dict[str, Any] | None
    created_at: datetime | None
    updated_at: datetime | None


@dataclass(slots=True)
class ChannelCheckResult:
    model: str
    status: str
    latency_ms: int | None
    ping_latency_ms: int | None
    message: str
    checked_at: datetime


SecretRotatedCallback = Callable[[dict[str, str]], Awaitable[None]]

ACTIVE_USAGE_PLATFORMS = frozenset({"anthropic", "openai"})
ACTIVE_USAGE_ACCOUNT_TYPES = frozenset({"oauth", "setup-token"})
MONITORING_TIME_RANGES = frozenset({"5m", "30m", "1h", "6h", "24h"})
MONITORING_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "headers",
        "password",
        "refresh_token",
        "request_body",
        "response_body",
        "secret",
    }
)


async def resolve_target_address(url: str, *, allow_private: bool) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ConnectorError("target URL must be an HTTP(S) URL without user info")
    if allow_private:
        return None
    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except socket.gaierror as exc:
        raise ConnectorError("target hostname cannot be resolved") from exc
    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ConnectorError("target URL resolves to a non-public address blocked by policy")
    return str(ipaddress.ip_address(addresses[0][4][0]))


async def validate_target_url(url: str, *, allow_private: bool) -> None:
    await resolve_target_address(url, allow_private=allow_private)


class Sub2APIConnector:
    def __init__(
        self,
        *,
        base_url: str,
        auth_type: str,
        secret: dict[str, str],
        settings: Settings,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        on_secret_rotated: SecretRotatedCallback | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_type = auth_type
        self.secret = secret.copy()
        self.settings = settings
        self.on_secret_rotated = on_secret_rotated
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=settings.connector_timeout_seconds,
            verify=verify_tls,
            follow_redirects=False,
            transport=transport,
        )

    async def __aenter__(self) -> Sub2APIConnector:
        await validate_target_url(self.base_url, allow_private=self.settings.allow_private_targets)
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.client.aclose()

    def _headers(self) -> dict[str, str]:
        if self.auth_type == "x_api_key":
            return {"x-api-key": self.secret["api_key"]}
        return {"Authorization": f"Bearer {self.secret['access_token']}"}

    async def _refresh_token_pair(self) -> bool:
        if self.auth_type != "token_pair" or not self.secret.get("refresh_token"):
            return False
        try:
            response = await self._send_bounded(
                "POST",
                "/api/v1/auth/refresh",
                json={"refresh_token": self.secret["refresh_token"]},
                authenticated=False,
            )
        except (httpx.HTTPError, ConnectorError):
            return False
        if response.status_code != 200:
            return False
        data = _envelope_data(response)
        if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            return False
        self.secret["access_token"] = data["access_token"]
        if isinstance(data.get("refresh_token"), str) and data["refresh_token"]:
            self.secret["refresh_token"] = data["refresh_token"]
        if self.on_secret_rotated:
            await self.on_secret_rotated(self.secret.copy())
        return True

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {**self._headers(), **kwargs.pop("headers", {})}
        try:
            response = await self._send_bounded(method, path, headers=headers, **kwargs)
        except httpx.TimeoutException as exc:
            raise ConnectorError("target request timed out") from exc
        except httpx.HTTPError as exc:
            raise ConnectorError("target request failed") from exc
        if response.status_code == 401 and await self._refresh_token_pair():
            response = await self._send_bounded(method, path, headers=self._headers(), **kwargs)
        return response

    async def _send_bounded(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if authenticated:
            headers = {**self._headers(), **headers}
        request = self.client.build_request(method, path, headers=headers, **kwargs)
        pinned_ip = await resolve_target_address(
            self.base_url, allow_private=self.settings.allow_private_targets
        )
        if pinned_ip is not None:
            parsed = urlparse(self.base_url)
            request.url = request.url.copy_with(host=pinned_ip)
            request.headers["Host"] = parsed.netloc
            request.extensions["sni_hostname"] = parsed.hostname
        response: httpx.Response | None = None
        try:
            response = await self.client.send(request, stream=True)
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > self.settings.connector_max_response_bytes:
                    raise ContractError(
                        "target response exceeded configured size limit",
                        status_code=response.status_code,
                    )
            decoded_headers = response.headers.copy()
            for header in ("content-encoding", "content-length", "transfer-encoding"):
                decoded_headers.pop(header, None)
            return httpx.Response(
                response.status_code,
                headers=decoded_headers,
                content=bytes(content),
                request=request,
                extensions=response.extensions,
            )
        finally:
            if response is not None:
                await response.aclose()

    async def health(self) -> ProbeFact:
        try:
            response = await self._send_bounded("GET", "/health", authenticated=False)
        except (httpx.HTTPError, ConnectorError):
            return ProbeFact("unknown", "unavailable", "missing", "health request failed")
        if response.status_code == 200:
            return ProbeFact("supported", "healthy", "fresh")
        if response.status_code == 404:
            return ProbeFact("unsupported", "unavailable", "missing", "health endpoint missing")
        return ProbeFact("unknown", "unavailable", "missing", f"health HTTP {response.status_code}")

    async def version(self) -> tuple[ProbeFact, str | None]:
        response = await self.request("GET", "/api/v1/admin/system/version")
        fact = _fact_from_response(response, "version")
        if response.status_code != 200:
            return fact, None
        data = _envelope_data(response)
        if isinstance(data, str):
            return fact, data[:100]
        if isinstance(data, dict):
            for key in ("version", "current_version"):
                if isinstance(data.get(key), str):
                    return fact, data[key][:100]
        return ProbeFact("unknown", "unavailable", "missing", "invalid version response"), None

    async def accounts(self) -> tuple[ProbeFact, list[NormalizedAccount]]:
        output: list[NormalizedAccount] = []
        page = 1
        while page <= self.settings.connector_max_pages:
            response = await self.request(
                "GET",
                "/api/v1/admin/accounts",
                params={
                    "page": page,
                    "page_size": self.settings.connector_page_size,
                    "sort_by": "id",
                    "sort_order": "asc",
                },
            )
            fact = _fact_from_response(response, "account inventory")
            if response.status_code != 200:
                return fact, []
            data = _envelope_data(response)
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                return ProbeFact(
                    "unknown", "unavailable", "missing", "invalid account list response"
                ), []
            for raw in data["items"]:
                if isinstance(raw, dict):
                    output.append(normalize_account(raw))
            pages = _as_int(data.get("pages"))
            total = _as_int(data.get("total"))
            if (pages and page >= pages) or len(data["items"]) < self.settings.connector_page_size:
                break
            if total is not None and len(output) >= total:
                break
            page += 1
        else:
            raise ContractError("account pagination exceeded configured page limit")
        return ProbeFact("supported", "healthy", "fresh"), output

    async def account_usage_stats(
        self, external_account_id: str, *, days: int = 30
    ) -> dict[str, Any]:
        encoded_account_id = quote(str(external_account_id), safe="")
        response = await self.request(
            "GET",
            f"/api/v1/admin/accounts/{encoded_account_id}/stats",
            params={"days": days},
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"account usage stats returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        data = _envelope_data(response)
        if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
            raise ContractError(
                "invalid account usage stats response", status_code=response.status_code
            )
        for key in ("history", "models", "endpoints", "upstream_endpoints"):
            if not isinstance(data.get(key), list):
                raise ContractError(
                    "invalid account usage stats response", status_code=response.status_code
                )
        sanitized = _sanitize_monitoring_payload(data)
        if not isinstance(sanitized, dict):
            raise ContractError(
                "invalid account usage stats response", status_code=response.status_code
            )
        return sanitized

    async def upstream_billing_probe_settings(self) -> tuple[ProbeFact, dict[str, Any] | None]:
        response = await self.request(
            "GET", "/api/v1/admin/accounts/upstream-billing-probe/settings"
        )
        fact = _fact_from_response(response, "upstream billing probe")
        if response.status_code != 200:
            return fact, None
        data = _envelope_data(response)
        if not isinstance(data, dict) or not isinstance(data.get("enabled"), bool):
            return ProbeFact(
                "unknown", "unavailable", "missing", "invalid upstream billing settings response"
            ), None
        return fact, {
            "enabled": data["enabled"],
            "interval_minutes": _as_int(data.get("interval_minutes")) or 30,
        }

    async def update_upstream_billing_probe_settings(
        self, *, enabled: bool, interval_minutes: int
    ) -> dict[str, Any]:
        response = await self.request(
            "PUT",
            "/api/v1/admin/accounts/upstream-billing-probe/settings",
            json={"enabled": enabled, "interval_minutes": interval_minutes},
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"upstream billing settings returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return _require_dict_data(response, "upstream billing settings")

    async def set_upstream_billing_probe_enabled(
        self, external_account_id: str, enabled: bool
    ) -> dict[str, Any]:
        response = await self.request(
            "PUT",
            f"/api/v1/admin/accounts/{external_account_id}/upstream-billing-probe",
            json={"enabled": enabled},
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"upstream billing probe toggle returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return _require_dict_data(response, "upstream billing probe toggle")

    async def probe_upstream_billing(self, external_account_id: str) -> dict[str, Any]:
        response = await self.request(
            "POST", f"/api/v1/admin/accounts/{external_account_id}/upstream-billing-probe"
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"upstream billing probe returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return _require_dict_data(response, "upstream billing probe")

    async def probe_upstream_billing_batch(
        self, external_account_ids: list[str]
    ) -> list[dict[str, Any]]:
        account_ids: list[int | str] = [
            int(account_id) if account_id.isdigit() else account_id
            for account_id in external_account_ids
        ]
        response = await self.request(
            "POST",
            "/api/v1/admin/accounts/upstream-billing-probe/batch",
            json={"account_ids": account_ids},
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"upstream billing batch probe returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        raw = _require_dict_data(response, "upstream billing batch probe").get("results")
        if not isinstance(raw, list):
            raise ContractError("invalid upstream billing batch probe response")
        return [item for item in raw if isinstance(item, dict)]

    async def channel_monitors(self) -> tuple[ProbeFact, list[NormalizedChannelMonitor]]:
        output: list[NormalizedChannelMonitor] = []
        page = 1
        page_size = min(self.settings.connector_page_size, 100)
        while page <= self.settings.connector_max_pages:
            response = await self.request(
                "GET",
                "/api/v1/admin/channel-monitors",
                params={"page": page, "page_size": page_size},
            )
            fact = _fact_from_response(response, "channel monitor inventory")
            if response.status_code != 200:
                return fact, []
            data = _envelope_data(response)
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                return ProbeFact(
                    "unknown", "unavailable", "missing", "invalid channel monitor response"
                ), []
            output.extend(
                normalize_channel_monitor(raw)
                for raw in data["items"]
                if isinstance(raw, dict)
            )
            pages = _as_int(data.get("pages"))
            if (pages and page >= pages) or len(data["items"]) < page_size:
                break
            page += 1
        else:
            raise ContractError("channel monitor pagination exceeded configured page limit")
        return ProbeFact("supported", "healthy", "fresh"), output

    async def monitoring_snapshot(
        self, time_range: str = "1h", *, page_size: int = 20
    ) -> tuple[dict[str, ProbeFact], dict[str, Any]]:
        if time_range not in MONITORING_TIME_RANGES:
            raise ValueError("unsupported monitoring time range")
        bounded_page_size = min(max(page_size, 1), 100)
        token_time_range = {
            "5m": "30m",
            "30m": "30m",
            "1h": "1h",
            "6h": "1d",
            "24h": "1d",
        }[time_range]
        specs: dict[str, tuple[str, dict[str, Any], str]] = {
            "ops_snapshot": (
                "/api/v1/admin/ops/dashboard/snapshot-v2",
                {"time_range": time_range},
                "ops.dashboard",
            ),
            "latency_histogram": (
                "/api/v1/admin/ops/dashboard/latency-histogram",
                {"time_range": time_range},
                "ops.latency",
            ),
            "error_distribution": (
                "/api/v1/admin/ops/dashboard/error-distribution",
                {"time_range": time_range},
                "ops.errors",
            ),
            "openai_token_stats": (
                "/api/v1/admin/ops/dashboard/openai-token-stats",
                {"time_range": token_time_range, "page": 1, "page_size": bounded_page_size},
                "ops.openai_token_stats",
            ),
            "concurrency": (
                "/api/v1/admin/ops/concurrency",
                {},
                "ops.concurrency",
            ),
            "user_concurrency": (
                "/api/v1/admin/ops/user-concurrency",
                {},
                "ops.user_concurrency",
            ),
            "account_availability": (
                "/api/v1/admin/ops/account-availability",
                {},
                "ops.account_availability",
            ),
            "realtime_traffic": (
                "/api/v1/admin/ops/realtime-traffic",
                {"window": "5m"},
                "ops.realtime_traffic",
            ),
            "request_errors": (
                "/api/v1/admin/ops/request-errors",
                {"time_range": time_range, "page": 1, "page_size": bounded_page_size},
                "ops.request_errors",
            ),
            "upstream_errors": (
                "/api/v1/admin/ops/upstream-errors",
                {"time_range": time_range, "page": 1, "page_size": bounded_page_size},
                "ops.upstream_errors",
            ),
            "requests": (
                "/api/v1/admin/ops/requests",
                {"time_range": time_range, "page": 1, "page_size": bounded_page_size},
                "ops.request_details",
            ),
            "alert_events": (
                "/api/v1/admin/ops/alert-events",
                {"page": 1, "page_size": bounded_page_size},
                "ops.alert_events",
            ),
            "system_logs": (
                "/api/v1/admin/ops/system-logs",
                {"time_range": time_range, "page": 1, "page_size": bounded_page_size},
                "ops.system_logs",
            ),
            "system_log_health": (
                "/api/v1/admin/ops/system-logs/health",
                {},
                "ops.system_log_health",
            ),
            "auth_cache_health": (
                "/api/v1/admin/ops/auth-cache-invalidation/health",
                {},
                "ops.auth_cache_health",
            ),
            "ingress_health": (
                "/api/v1/admin/ops/ingress-rejections/health",
                {},
                "ops.ingress_health",
            ),
            "groups": (
                "/api/v1/admin/groups/all",
                {},
                "groups.inventory",
            ),
            "group_usage": (
                "/api/v1/admin/groups/usage-summary",
                {"time_range": time_range},
                "groups.usage",
            ),
            "group_capacity": (
                "/api/v1/admin/groups/capacity-summary",
                {},
                "groups.capacity",
            ),
        }

        async def fetch(
            resource: str, path: str, params: dict[str, Any], capability: str
        ) -> tuple[str, str, ProbeFact, Any | None]:
            try:
                response = await self.request("GET", path, params=params)
                fact = _fact_from_response(response, resource.replace("_", " "))
                if response.status_code != 200:
                    return resource, capability, fact, None
                data = _envelope_data(response)
                if not isinstance(data, (dict, list)):
                    return (
                        resource,
                        capability,
                        ProbeFact(
                            "unknown",
                            "unavailable",
                            "missing",
                            f"invalid {resource.replace('_', ' ')} response",
                        ),
                        None,
                    )
                return resource, capability, fact, _sanitize_monitoring_payload(data)
            except (ConnectorError, ContractError) as exc:
                return (
                    resource,
                    capability,
                    ProbeFact("unknown", "unavailable", "missing", str(exc)[:500]),
                    None,
                )

        results = await asyncio.gather(
            *(
                fetch(resource, path, params, capability)
                for resource, (path, params, capability) in specs.items()
            )
        )
        facts: dict[str, ProbeFact] = {}
        resources: dict[str, Any] = {}
        failures: dict[str, str] = {}
        for resource, capability, fact, data in results:
            facts[capability] = fact
            if data is not None:
                resources[resource] = data
            elif fact.reason:
                failures[resource] = fact.reason
        return facts, {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": time_range,
            "resources": resources,
            "failures": failures,
        }

    async def channel_monitor_history(
        self, external_monitor_id: str, *, model: str | None = None, limit: int = 100
    ) -> list[ChannelCheckResult]:
        params: dict[str, Any] = {"limit": limit}
        if model:
            params["model"] = model
        response = await self.request(
            "GET",
            f"/api/v1/admin/channel-monitors/{external_monitor_id}/history",
            params=params,
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"channel monitor history returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return _normalize_channel_results(
            _require_dict_data(response, "channel monitor history").get("items")
        )

    async def run_channel_monitor(self, external_monitor_id: str) -> list[ChannelCheckResult]:
        response = await self.request(
            "POST", f"/api/v1/admin/channel-monitors/{external_monitor_id}/run"
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"channel monitor run returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return _normalize_channel_results(
            _require_dict_data(response, "channel monitor run").get("results")
        )

    async def create_channel_monitor(self, payload: dict[str, Any]) -> NormalizedChannelMonitor:
        response = await self.request("POST", "/api/v1/admin/channel-monitors", json=payload)
        if response.status_code not in {200, 201}:
            raise ConnectorError(
                f"channel monitor create returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return normalize_channel_monitor(_require_dict_data(response, "channel monitor create"))

    async def update_channel_monitor(
        self, external_monitor_id: str, payload: dict[str, Any]
    ) -> NormalizedChannelMonitor:
        response = await self.request(
            "PUT", f"/api/v1/admin/channel-monitors/{external_monitor_id}", json=payload
        )
        if response.status_code != 200:
            raise ConnectorError(
                f"channel monitor update returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return normalize_channel_monitor(_require_dict_data(response, "channel monitor update"))

    async def delete_channel_monitor(self, external_monitor_id: str) -> None:
        response = await self.request(
            "DELETE", f"/api/v1/admin/channel-monitors/{external_monitor_id}"
        )
        if response.status_code not in {200, 204}:
            raise ConnectorError(
                f"channel monitor delete returned HTTP {response.status_code}",
                status_code=response.status_code,
            )

    async def passive_usage(self, account: NormalizedAccount) -> list[QuotaWindow]:
        if account.platform.lower() != "anthropic" or account.account_type not in {
            "oauth",
            "setup-token",
        }:
            return []
        response = await self.request(
            "GET",
            f"/api/v1/admin/accounts/{account.external_account_id}/usage",
            params={"source": "passive"},
        )
        if response.status_code in {400, 404, 422}:
            return []
        if response.status_code != 200:
            raise ConnectorError(
                f"passive usage returned HTTP {response.status_code}",
                status_code=response.status_code,
            )
        data = _envelope_data(response)
        if not isinstance(data, dict):
            return []
        observed_at = _parse_datetime(data.get("updated_at")) or datetime.now(timezone.utc)
        windows: list[QuotaWindow] = []
        for key, label in {
            "five_hour": "5 hour quota",
            "seven_day": "7 day quota",
            "seven_day_sonnet": "7 day Sonnet quota",
            "seven_day_fable": "7 day Fable quota",
        }.items():
            raw = data.get(key)
            if not isinstance(raw, dict):
                continue
            utilization = _as_float(raw.get("utilization"))
            if utilization is None:
                continue
            windows.append(
                QuotaWindow(
                    provider=account.platform,
                    quota_key=key,
                    label=label,
                    utilization_percent=utilization,
                    remaining_percent=max(0.0, 100.0 - utilization),
                    reset_at=_parse_datetime(raw.get("resets_at")),
                    observed_at=observed_at,
                    source="sub2api_api_passive",
                )
            )
        return windows

    async def active_usage(self, account: NormalizedAccount) -> tuple[ProbeFact, list[QuotaWindow]]:
        if not active_usage_supported(account):
            return (
                ProbeFact(
                    "unsupported",
                    "disabled",
                    "missing",
                    "account platform or credential type is not allowlisted for active usage",
                ),
                [],
            )
        response = await self.request(
            "GET",
            f"/api/v1/admin/accounts/{account.external_account_id}/usage",
            params={"source": "active"},
        )
        if response.status_code in {400, 404, 422}:
            return (
                ProbeFact(
                    "unsupported",
                    "unavailable",
                    "missing",
                    f"active usage returned HTTP {response.status_code}",
                ),
                [],
            )
        fact = _fact_from_response(response, "active usage")
        if response.status_code != 200:
            return fact, []
        data = _envelope_data(response)
        if not isinstance(data, dict):
            return ProbeFact("unknown", "unavailable", "missing", "invalid usage response"), []
        observed_at = _parse_datetime(data.get("updated_at")) or datetime.now(timezone.utc)
        response_source = str(data.get("source") or "active").lower()
        source = "sub2api_api_active" if response_source == "active" else "sub2api_api_usage_cache"
        windows: list[QuotaWindow] = []
        definitions = {
            "five_hour": "5 hour quota",
            "seven_day": "7 day quota",
            "seven_day_sonnet": "7 day Sonnet quota",
            "seven_day_fable": "7 day Fable quota",
        }
        if account.platform.lower() == "openai":
            definitions["five_hour"] = "Codex 5 hour quota"
            definitions["seven_day"] = "Codex 7 day quota"
        for response_key, label in definitions.items():
            raw = data.get(response_key)
            if not isinstance(raw, dict):
                continue
            utilization = _as_float(raw.get("utilization"))
            if utilization is None:
                continue
            reset_at = _parse_datetime(raw.get("resets_at"))
            windows.append(
                QuotaWindow(
                    provider=account.platform,
                    quota_key=(
                        f"codex.{response_key}"
                        if account.platform.lower() == "openai"
                        and response_key in {"five_hour", "seven_day"}
                        else response_key
                    ),
                    label=label,
                    utilization_percent=utilization,
                    remaining_percent=max(0.0, 100.0 - utilization),
                    reset_at=reset_at,
                    observed_at=observed_at,
                    source=source,
                    freshness=_usage_freshness(
                        observed_at,
                        reset_at,
                        self.settings.target_quota_stale_seconds,
                    ),
                )
            )
        freshness = (
            "fresh"
            if any(window.freshness == "fresh" for window in windows)
            else "stale"
            if windows
            else "missing"
        )
        return ProbeFact("supported", "healthy", freshness), windows

    async def probe(self) -> ProbeResult:
        health = await self.health()
        try:
            version_fact, version_text = await self.version()
        except ConnectorError as exc:
            version_fact, version_text = (
                ProbeFact("unknown", "unavailable", "missing", str(exc)),
                None,
            )
        try:
            accounts_fact, accounts = await self.accounts()
        except ConnectorError as exc:
            accounts_fact, accounts = ProbeFact("unknown", "unavailable", "missing", str(exc)), []
        return ProbeResult(health, version_fact, accounts_fact, version_text, accounts)


def normalize_account(raw: dict[str, Any], now: datetime | None = None) -> NormalizedAccount:
    observed_at = now or datetime.now(timezone.utc)
    external_id = raw.get("id")
    if not isinstance(external_id, (str, int)):
        raise ContractError("account is missing a stable id")
    status = str(raw.get("status") or "unknown")
    schedulable = bool(raw.get("schedulable", False))
    expires_at = _parse_datetime(raw.get("expires_at"))
    rate_reset = _parse_datetime(raw.get("rate_limit_reset_at"))
    overload_until = _parse_datetime(raw.get("overload_until"))
    temp_until = _parse_datetime(raw.get("temp_unschedulable_until"))
    reasons: list[str] = []
    if status != "active":
        reasons.append(f"status:{status}")
    if not schedulable:
        reasons.append("manually_unschedulable")
    if bool(raw.get("auto_pause_on_expired", True)) and expires_at and observed_at >= expires_at:
        reasons.append("expired")
    if rate_reset and observed_at < rate_reset:
        reasons.append("rate_limited")
    if overload_until and observed_at < overload_until:
        reasons.append("overloaded")
    if temp_until and observed_at < temp_until:
        reasons.append("temporarily_unschedulable")
    quotas = _local_quota_windows(raw, observed_at, str(raw.get("platform") or "unknown"))
    if any(q.remaining_value is not None and q.remaining_value <= 0 for q in quotas):
        reasons.append("local_quota_exhausted")
    group_ids: list[str] = []
    if isinstance(raw.get("group_ids"), list):
        group_ids = [str(item) for item in raw["group_ids"] if isinstance(item, (str, int))]
    raw_extra = raw.get("extra")
    extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
    probe = extra.get("upstream_billing_probe")
    if not isinstance(probe, dict):
        probe = None
    return NormalizedAccount(
        external_account_id=str(external_id),
        name=str(raw.get("name") or f"account-{external_id}")[:160],
        platform=str(raw.get("platform") or "unknown")[:50],
        account_type=str(raw.get("type") or "unknown")[:30],
        status=status[:30],
        schedulable=schedulable,
        available=not reasons,
        availability_reasons=reasons,
        group_ids=group_ids,
        expires_at=expires_at,
        rate_limit_reset_at=rate_reset,
        overload_until=overload_until,
        temp_unschedulable_until=temp_until,
        rate_multiplier=_as_float(raw.get("rate_multiplier")),
        upstream_billing_probe_enabled=bool(extra.get("upstream_billing_probe_enabled", False)),
        upstream_billing_rate_sync_enabled=bool(
            extra.get("upstream_billing_rate_sync_enabled", False)
        ),
        upstream_billing_probe=_sanitize_probe_snapshot(probe),
        observed_at=observed_at,
        quotas=quotas,
    )


def normalize_channel_monitor(raw: dict[str, Any]) -> NormalizedChannelMonitor:
    external_id = raw.get("id")
    if not isinstance(external_id, (str, int)):
        raise ContractError("channel monitor is missing a stable id")
    raw_extra_models = raw.get("extra_models")
    extra_models: list[Any] = raw_extra_models if isinstance(raw_extra_models, list) else []
    raw_extra_status = raw.get("extra_models_status")
    extra_status: list[Any] = raw_extra_status if isinstance(raw_extra_status, list) else []
    raw_headers = raw.get("extra_headers")
    headers: dict[str, Any] = raw_headers if isinstance(raw_headers, dict) else {}
    body = raw.get("body_override") if isinstance(raw.get("body_override"), dict) else None
    return NormalizedChannelMonitor(
        external_monitor_id=str(external_id),
        name=str(raw.get("name") or f"channel-{external_id}")[:160],
        provider=str(raw.get("provider") or "unknown")[:50],
        api_mode=str(raw.get("api_mode") or "chat_completions")[:30],
        endpoint=str(raw.get("endpoint") or "")[:2048],
        api_key_masked=str(raw.get("api_key_masked") or "")[:100],
        api_key_decrypt_failed=bool(raw.get("api_key_decrypt_failed", False)),
        primary_model=str(raw.get("primary_model") or "")[:200],
        extra_models=[str(item)[:200] for item in extra_models if isinstance(item, str)],
        group_name=str(raw.get("group_name") or "")[:160],
        enabled=bool(raw.get("enabled", False)),
        interval_seconds=_as_int(raw.get("interval_seconds")) or 60,
        jitter_seconds=_as_int(raw.get("jitter_seconds")) or 0,
        last_checked_at=_parse_datetime(raw.get("last_checked_at")),
        primary_status=str(raw.get("primary_status") or "")[:30],
        primary_latency_ms=_as_int(raw.get("primary_latency_ms")),
        availability_7d=_as_float(raw.get("availability_7d")) or 0.0,
        extra_models_status=[
            {
                "model": str(item.get("model") or "")[:200],
                "status": str(item.get("status") or "")[:30],
                "latency_ms": _as_int(item.get("latency_ms")),
            }
            for item in extra_status
            if isinstance(item, dict)
        ],
        template_id=str(raw["template_id"]) if raw.get("template_id") is not None else None,
        extra_headers={str(key)[:200]: str(value)[:2000] for key, value in headers.items()},
        body_override_mode=str(raw.get("body_override_mode") or "off")[:20],
        body_override=body,
        created_at=_parse_datetime(raw.get("created_at")),
        updated_at=_parse_datetime(raw.get("updated_at")),
    )


def active_usage_supported(account: NormalizedAccount) -> bool:
    return (
        account.platform.lower() in ACTIVE_USAGE_PLATFORMS
        and account.account_type.lower() in ACTIVE_USAGE_ACCOUNT_TYPES
    )


def _local_quota_windows(
    raw: dict[str, Any], observed_at: datetime, provider: str
) -> list[QuotaWindow]:
    windows: list[QuotaWindow] = []
    definitions = (
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
    )
    for key, label, used_key, limit_key, reset_key in definitions:
        used = _as_float(raw.get(used_key))
        limit = _as_float(raw.get(limit_key))
        if used is None or limit is None or limit <= 0:
            continue
        remaining = max(0.0, limit - used)
        utilization = max(0.0, used / limit * 100.0)
        windows.append(
            QuotaWindow(
                provider=provider,
                quota_key=f"local.{key}",
                label=label,
                utilization_percent=utilization,
                remaining_percent=max(0.0, 100.0 - utilization),
                used_value=used,
                limit_value=limit,
                remaining_value=remaining,
                unit="currency",
                reset_at=_parse_datetime(raw.get(reset_key)) if reset_key else None,
                observed_at=observed_at,
                source="sub2api_api_inventory",
            )
        )
    return windows


def _fact_from_response(response: httpx.Response, name: str) -> ProbeFact:
    if response.status_code == 200:
        return ProbeFact("supported", "healthy", "fresh")
    if response.status_code in {401, 403}:
        return ProbeFact(
            "permission_denied", "misconfigured", "missing", f"{name} permission denied"
        )
    if response.status_code == 404:
        return ProbeFact("unsupported", "unavailable", "missing", f"{name} endpoint missing")
    return ProbeFact(
        "unknown", "unavailable", "missing", f"{name} returned HTTP {response.status_code}"
    )


def _envelope_data(response: httpx.Response) -> Any:
    try:
        body = response.json()
    except ValueError as exc:
        raise ContractError(
            "target returned invalid JSON", status_code=response.status_code
        ) from exc
    if not isinstance(body, dict):
        raise ContractError("target response is not an object", status_code=response.status_code)
    if "code" in body and body.get("code") not in {0, 200}:
        raise ConnectorError(
            "target returned an application error", status_code=response.status_code
        )
    return body.get("data", body)


def _require_dict_data(response: httpx.Response, name: str) -> dict[str, Any]:
    data = _envelope_data(response)
    if not isinstance(data, dict):
        raise ContractError(f"invalid {name} response", status_code=response.status_code)
    return data


def _sanitize_probe_snapshot(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    allowed = {
        "status",
        "data",
        "received_at",
        "fresh_until",
        "last_attempt_at",
        "next_probe_at",
        "failure_count",
        "http_status",
        "last_error",
        "synced_rate_multiplier",
    }
    return {key: value for key, value in snapshot.items() if key in allowed}


def _sanitize_monitoring_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize_monitoring_payload(item)
            for key, item in value.items()
            if str(key).lower() not in MONITORING_SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_monitoring_payload(item) for item in value]
    if isinstance(value, str):
        return value[:4000]
    return value


def _normalize_channel_results(raw: Any) -> list[ChannelCheckResult]:
    if not isinstance(raw, list):
        raise ContractError("invalid channel monitor result response")
    results: list[ChannelCheckResult] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        checked_at = _parse_datetime(item.get("checked_at"))
        if checked_at is None:
            continue
        results.append(
            ChannelCheckResult(
                model=str(item.get("model") or "")[:200],
                status=str(item.get("status") or "error")[:30],
                latency_ms=_as_int(item.get("latency_ms")),
                ping_latency_ms=_as_int(item.get("ping_latency_ms")),
                message=str(item.get("message") or "")[:1000],
                checked_at=checked_at,
            )
        )
    return results


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        # Sub2API account DTO uses Unix seconds for expires_at.
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return datetime.fromtimestamp(int(text), timezone.utc)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _usage_freshness(
    observed_at: datetime,
    reset_at: datetime | None,
    stale_seconds: int,
) -> str:
    now = datetime.now(timezone.utc)
    if (now - observed_at).total_seconds() > stale_seconds:
        return "stale"
    if reset_at is not None and reset_at <= now:
        return "stale"
    return "fresh"


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
