from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.connectors.sub2api import ConnectorError, resolve_target_address
from app.models import NotificationChannel, NotificationOutbox, OutboxStatus
from app.security import SecretCipher


async def dispatch_due(
    session: AsyncSession, settings: Settings, cipher: SecretCipher, *, limit: int = 50
) -> int:
    now = datetime.now(timezone.utc)
    rows = list(
        await session.scalars(
            select(NotificationOutbox)
            .where(
                NotificationOutbox.status == OutboxStatus.PENDING.value,
                NotificationOutbox.next_attempt_at <= now,
            )
            .order_by(NotificationOutbox.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    delivered = 0
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        for row in rows:
            channel = await session.get(NotificationChannel, row.channel_id)
            if channel is None or not channel.enabled:
                row.status = OutboxStatus.DEAD.value
                row.last_error = "notification channel is missing or disabled"
                continue
            try:
                headers: dict[str, str] = {"Content-Type": "application/json"}
                if channel.token_ciphertext:
                    token = cipher.decrypt_text(channel.token_ciphertext)
                    headers["Authorization"] = f"Bearer {token}"
                if channel.kind == "webhook":
                    webhook_body = json.dumps(
                        row.payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                    ).encode()
                    headers["X-Sub2API-Monitor-Event"] = str(
                        row.payload.get("event_type") or "test"
                    )
                    headers["X-Sub2API-Monitor-Delivery"] = row.id
                    if channel.signing_secret_ciphertext:
                        signing_secret = cipher.decrypt_text(
                            channel.signing_secret_ciphertext
                        ).encode()
                        signature = hmac.new(
                            signing_secret, webhook_body, hashlib.sha256
                        ).hexdigest()
                        headers["X-Sub2API-Monitor-Signature"] = f"sha256={signature}"
                    response = await _post_json(
                        client,
                        channel.server_url,
                        webhook_body,
                        headers,
                        settings,
                    )
                else:
                    ntfy_body = {"topic": channel.topic, **row.payload}
                    response = await _post_json(
                        client,
                        channel.server_url,
                        json.dumps(
                            ntfy_body,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode(),
                        headers,
                        settings,
                    )
                if 200 <= response.status_code < 300:
                    row.status = OutboxStatus.SENT.value
                    row.sent_at = now
                    row.last_error = None
                    delivered += 1
                    continue
                error = f"{channel.kind} returned HTTP {response.status_code}"
                retryable = response.status_code == 429 or response.status_code >= 500
            except httpx.HTTPError:
                error = f"{channel.kind} request failed"
                retryable = True
            except ConnectorError as exc:
                error = "notification destination failed network policy validation"
                retryable = "cannot be resolved" in str(exc)
            except ValueError:
                error = "notification token cannot be decrypted"
                retryable = False
            row.attempts += 1
            row.last_error = error
            if retryable and row.attempts < 10:
                delay = min(3600, 2 ** min(row.attempts, 10))
                row.next_attempt_at = now + timedelta(seconds=delay)
            else:
                row.status = OutboxStatus.DEAD.value
    await session.commit()
    return delivered


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
