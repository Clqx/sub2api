from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

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
        }


@dataclass(slots=True)
class ProbeResult:
    health: ProbeFact
    version: ProbeFact
    accounts: ProbeFact
    version_text: str | None
    normalized_accounts: list[NormalizedAccount]


SecretRotatedCallback = Callable[[dict[str, str]], Awaitable[None]]

ACTIVE_USAGE_PLATFORMS = frozenset({"anthropic", "openai"})
ACTIVE_USAGE_ACCOUNT_TYPES = frozenset({"oauth", "setup-token"})


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
            return httpx.Response(
                response.status_code,
                headers=response.headers,
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
        observed_at=observed_at,
        quotas=quotas,
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
