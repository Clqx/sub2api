from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import ConnectorError, resolve_target_address
from app.models import NotificationChannel, NotificationOutbox, OutboxStatus
from app.security import SecretCipher

TELEGRAM_TOKEN_PATTERN = re.compile(r"^\d{6,20}:[A-Za-z0-9_-]{20,}$")


@dataclass(frozen=True)
class _ClaimedDelivery:
    id: str
    channel_id: str
    channel_kind: str | None
    server_url: str | None
    topic: str
    token_ciphertext: str | None
    signing_secret_ciphertext: str | None
    payload: dict[str, object]
    attempts: int
    channel_enabled: bool


@dataclass(frozen=True)
class _DeliveryResult:
    id: str
    attempts: int
    delivered: bool
    retryable: bool
    error: str | None = None


class _TelegramTokenTransport(httpx.AsyncBaseTransport):
    """Insert the bot token below httpx's request logging layer."""

    def __init__(
        self,
        token: str,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token = token
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.rstrip("/")
        if not path.endswith("/sendMessage"):
            raise httpx.UnsupportedProtocol("unexpected Telegram Bot API path")
        prefix = path[: -len("/sendMessage")]
        actual_request = httpx.Request(
            request.method,
            request.url.copy_with(path=f"{prefix}/bot{self._token}/sendMessage"),
            headers=request.headers,
            content=request.content,
            extensions=request.extensions,
        )
        return await self._inner.handle_async_request(actual_request)

    async def aclose(self) -> None:
        await self._inner.aclose()


async def dispatch_due(
    session: AsyncSession,
    settings: Settings,
    cipher: SecretCipher,
    *,
    limit: int = 50,
    claim_owner: str | None = None,
) -> int:
    now = datetime.now(timezone.utc)
    owner = f"{claim_owner or 'dispatcher'}:{uuid.uuid4()}"
    claim_limit = min(limit, settings.notification_dispatch_concurrency)
    rows = list(
        await session.scalars(
            select(NotificationOutbox)
            .where(
                or_(
                    and_(
                        NotificationOutbox.status == OutboxStatus.PENDING.value,
                        NotificationOutbox.next_attempt_at <= now,
                    ),
                    and_(
                        NotificationOutbox.status == OutboxStatus.DELIVERING.value,
                        NotificationOutbox.lease_expires_at <= now,
                    ),
                )
            )
            .order_by(NotificationOutbox.created_at)
            .limit(claim_limit)
            .with_for_update(skip_locked=True)
        )
    )
    if not rows:
        await session.rollback()
        return 0
    channel_ids = {row.channel_id for row in rows}
    channels = {
        channel.id: channel
        for channel in await session.scalars(
            select(NotificationChannel).where(NotificationChannel.id.in_(channel_ids))
        )
    }
    claimed: list[_ClaimedDelivery] = []
    lease_expires_at = now + timedelta(seconds=settings.notification_claim_seconds)
    for row in rows:
        channel = channels.get(row.channel_id)
        row.status = OutboxStatus.DELIVERING.value
        row.lease_owner = owner
        row.lease_expires_at = lease_expires_at
        claimed.append(
            _ClaimedDelivery(
                id=row.id,
                channel_id=row.channel_id,
                channel_kind=channel.kind if channel is not None else None,
                server_url=channel.server_url if channel is not None else None,
                topic=channel.topic if channel is not None else "",
                token_ciphertext=channel.token_ciphertext if channel is not None else None,
                signing_secret_ciphertext=(
                    channel.signing_secret_ciphertext if channel is not None else None
                ),
                payload=dict(row.payload),
                attempts=row.attempts,
                channel_enabled=bool(channel and channel.enabled),
            )
        )
    # The row locks and transaction end before any destination is contacted.
    await session.commit()

    semaphore = asyncio.Semaphore(settings.notification_dispatch_concurrency)
    delivery_timeout = min(15.0, settings.notification_claim_seconds / 2)
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        async def send(item: _ClaimedDelivery) -> _DeliveryResult:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        _deliver(item, client, settings, cipher),
                        timeout=delivery_timeout,
                    )
                except asyncio.TimeoutError:
                    return _DeliveryResult(
                        item.id,
                        item.attempts + 1,
                        False,
                        True,
                        "notification delivery timed out",
                    )
                except Exception:
                    return _DeliveryResult(
                        item.id,
                        item.attempts + 1,
                        False,
                        True,
                        "notification delivery failed unexpectedly",
                    )

        results = await asyncio.gather(*(send(item) for item in claimed))

    delivered = 0
    for result in results:
        finished_at = datetime.now(timezone.utc)
        values: dict[str, object | None] = {
            "lease_owner": None,
            "lease_expires_at": None,
        }
        if result.delivered:
            values.update(
                status=OutboxStatus.SENT.value,
                sent_at=finished_at,
                last_error=None,
            )
        else:
            values.update(attempts=result.attempts, last_error=result.error)
            if result.retryable and result.attempts < 10:
                delay = min(3600, 2 ** min(result.attempts, 10))
                values.update(
                    status=OutboxStatus.PENDING.value,
                    next_attempt_at=finished_at + timedelta(seconds=delay),
                )
            else:
                values["status"] = OutboxStatus.DEAD.value
        outcome = await session.execute(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.id == result.id,
                NotificationOutbox.status == OutboxStatus.DELIVERING.value,
                NotificationOutbox.lease_owner == owner,
            )
            .values(**values)
            .returning(NotificationOutbox.id)
        )
        persisted = outcome.scalar_one_or_none() is not None
        # A result is durable independently of later deliveries in the batch.
        await session.commit()
        if result.delivered and persisted:
            delivered += 1
    return delivered


async def _deliver(
    item: _ClaimedDelivery,
    client: httpx.AsyncClient,
    settings: Settings,
    cipher: SecretCipher,
) -> _DeliveryResult:
    if not item.channel_enabled or item.channel_kind is None or item.server_url is None:
        return _DeliveryResult(
            item.id,
            item.attempts + 1,
            False,
            False,
            "notification channel is missing or disabled",
        )
    kind = item.channel_kind
    try:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        token = cipher.decrypt_text(item.token_ciphertext) if item.token_ciphertext else None
        if kind == "webhook":
            if token:
                headers["Authorization"] = f"Bearer {token}"
            body = json.dumps(
                item.payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode()
            headers["X-Sub2API-Monitor-Event"] = str(
                item.payload.get("event_type") or "test"
            )
            headers["X-Sub2API-Monitor-Delivery"] = item.id
            if item.signing_secret_ciphertext:
                signing_secret = cipher.decrypt_text(item.signing_secret_ciphertext).encode()
                signature = hmac.new(signing_secret, body, hashlib.sha256).hexdigest()
                headers["X-Sub2API-Monitor-Signature"] = f"sha256={signature}"
            response = await _post_json(client, item.server_url, body, headers, settings)
        elif kind == "telegram":
            if token is None or not TELEGRAM_TOKEN_PATTERN.fullmatch(token):
                raise ValueError("invalid Telegram bot token")
            title = str(item.payload.get("title") or "Sub2API Monitor")
            message = str(item.payload.get("message") or "Notification event")
            response = await _post_telegram(
                item.server_url,
                token,
                {
                    "chat_id": item.topic,
                    "text": f"{title}\n{message}"[:4096],
                    "disable_web_page_preview": True,
                },
                settings,
            )
        else:
            if token:
                headers["Authorization"] = f"Bearer {token}"
            body = json.dumps(
                {"topic": item.topic, **item.payload},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            response = await _post_json(client, item.server_url, body, headers, settings)
        if 200 <= response.status_code < 300:
            return _DeliveryResult(item.id, item.attempts, True, False)
        return _DeliveryResult(
            item.id,
            item.attempts + 1,
            False,
            response.status_code == 429 or response.status_code >= 500,
            f"{kind} returned HTTP {response.status_code}",
        )
    except httpx.HTTPError:
        return _DeliveryResult(
            item.id, item.attempts + 1, False, True, f"{kind} request failed"
        )
    except ConnectorError as exc:
        return _DeliveryResult(
            item.id,
            item.attempts + 1,
            False,
            "cannot be resolved" in str(exc),
            "notification destination failed network policy validation",
        )
    except ValueError:
        return _DeliveryResult(
            item.id,
            item.attempts + 1,
            False,
            False,
            "notification token cannot be decrypted or is invalid",
        )


async def _post_json(
    client: httpx.AsyncClient,
    url: str,
    body: bytes,
    headers: dict[str, str],
    settings: Settings,
) -> httpx.Response:
    pinned_ip = await resolve_target_address(
        url, allow_private=settings.allow_private_notification_targets
    )
    request_url = httpx.URL(url)
    extensions: dict[str, str] = {}
    if pinned_ip is not None:
        parsed = urlparse(url)
        request_url = request_url.copy_with(host=pinned_ip)
        headers = {**headers, "Host": parsed.netloc}
        extensions["sni_hostname"] = parsed.hostname or ""
    return await client.post(
        request_url,
        content=body,
        headers=headers,
        extensions=extensions,
    )


async def _post_telegram(
    server_url: str,
    token: str,
    payload: dict[str, object],
    settings: Settings,
) -> httpx.Response:
    validate_telegram_server_url(server_url, settings.telegram_api_allowed_hosts)
    safe_url = f"{server_url.rstrip('/')}/sendMessage"
    pinned_ip = await resolve_target_address(
        safe_url, allow_private=settings.allow_private_notification_targets
    )
    request_url = httpx.URL(safe_url)
    headers = {"Content-Type": "application/json"}
    extensions: dict[str, str] = {}
    if pinned_ip is not None:
        parsed = urlparse(safe_url)
        request_url = request_url.copy_with(host=pinned_ip)
        headers["Host"] = parsed.netloc
        extensions["sni_hostname"] = parsed.hostname or ""
    transport = _TelegramTokenTransport(token)
    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=False,
        transport=transport,
    ) as client:
        return await client.post(
            request_url,
            content=json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            headers=headers,
            extensions=extensions,
        )


def validate_telegram_server_url(server_url: str, allowed_hosts: list[str]) -> None:
    parsed = urlparse(server_url)
    host = (parsed.hostname or "").rstrip(".").casefold()
    if (
        parsed.scheme.casefold() != "https"
        or host not in allowed_hosts
        or "/bot" in parsed.path.casefold()
        or ":" in parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ConnectorError("Telegram Bot API destination is not trusted")
