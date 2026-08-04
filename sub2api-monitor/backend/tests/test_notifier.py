from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from app.models import NotificationChannel, NotificationOutbox
from app.security import SecretCipher
from app.services import notifier


async def test_ntfy_outbox_retries_without_persisting_response_body(
    db_session, monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    channel = NotificationChannel(
        id="channel-a",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
        token_ciphertext=cipher.encrypt_text("ntfy-secret"),
    )
    row = NotificationOutbox(
        id="outbox-a",
        transition_id="transition-a",
        channel_id=channel.id,
        payload={"title": "Quota low", "message": "10% remaining"},
    )
    db_session.add_all([channel, row])
    await db_session.commit()

    class FakeClient:
        calls = 0
        authorizations: list[str | None] = []

        def __init__(self, **_: object):
            pass

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, _url: str, *, json, headers) -> httpx.Response:
            FakeClient.calls += 1
            FakeClient.authorizations.append(headers.get("Authorization"))
            status = 503 if FakeClient.calls == 1 else 200
            return httpx.Response(status, json={"sensitive": "must-not-be-stored"})

    monkeypatch.setattr(notifier.httpx, "AsyncClient", FakeClient)

    assert await notifier.dispatch_due(db_session, cipher) == 0
    assert row.status == "pending"
    assert row.attempts == 1
    assert row.last_error == "ntfy returned HTTP 503"
    assert "sensitive" not in row.last_error

    row.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.commit()
    assert await notifier.dispatch_due(db_session, cipher) == 1
    await db_session.refresh(row)
    assert row.status == "sent"
    assert row.attempts == 1
    assert FakeClient.authorizations == ["Bearer ntfy-secret", "Bearer ntfy-secret"]
