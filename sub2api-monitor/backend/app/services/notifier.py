from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NotificationChannel, NotificationOutbox, OutboxStatus
from app.security import SecretCipher


async def dispatch_due(session: AsyncSession, cipher: SecretCipher, *, limit: int = 50) -> int:
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
                body = {"topic": channel.topic, **row.payload}
                response = await client.post(channel.server_url, json=body, headers=headers)
                if 200 <= response.status_code < 300:
                    row.status = OutboxStatus.SENT.value
                    row.sent_at = now
                    row.last_error = None
                    delivered += 1
                    continue
                error = f"ntfy returned HTTP {response.status_code}"
                retryable = response.status_code == 429 or response.status_code >= 500
            except httpx.HTTPError:
                error = "ntfy request failed"
                retryable = True
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
