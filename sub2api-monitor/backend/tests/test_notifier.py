from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api import router as router_module
from app.config import Settings
from app.models import NotificationChannel, NotificationOutbox, OutboxStatus, User
from app.schemas import ChannelUpdate
from app.security import SecretCipher
from app.services import notifier


class _SerializedChannelSession:
    """Make SQLite exercise the row-lock ordering used by PostgreSQL."""

    def __init__(
        self,
        session: AsyncSession,
        row_lock: asyncio.Lock,
        *,
        acquired: asyncio.Event | None = None,
        release: asyncio.Event | None = None,
        attempting: asyncio.Event | None = None,
    ) -> None:
        self._session = session
        self._row_lock = row_lock
        self._acquired = acquired
        self._release = release
        self._attempting = attempting
        self._owns_lock = False

    async def scalar(self, statement, *args, **kwargs):
        descriptions = getattr(statement, "column_descriptions", [])
        entity = descriptions[0].get("entity") if descriptions else None
        is_channel_lock = (
            entity is NotificationChannel
            and getattr(statement, "_for_update_arg", None) is not None
        )
        if is_channel_lock:
            if self._attempting is not None:
                self._attempting.set()
            await self._row_lock.acquire()
            self._owns_lock = True
        result = await self._session.scalar(statement, *args, **kwargs)
        if is_channel_lock and self._acquired is not None:
            self._acquired.set()
            if self._release is not None:
                await self._release.wait()
        return result

    async def commit(self) -> None:
        try:
            await self._session.commit()
        finally:
            self._release_lock()

    async def rollback(self) -> None:
        try:
            await self._session.rollback()
        finally:
            self._release_lock()

    def _release_lock(self) -> None:
        if self._owns_lock:
            self._owns_lock = False
            self._row_lock.release()

    def __getattr__(self, name: str):
        return getattr(self._session, name)


async def _run_concurrent_channel_updates(
    db_session: AsyncSession,
    channel_id: str,
    first_payload: ChannelUpdate,
    second_payload: ChannelUpdate,
    cipher: SecretCipher,
    settings: Settings,
) -> None:
    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    row_lock = asyncio.Lock()
    first_acquired = asyncio.Event()
    release_first = asyncio.Event()
    second_attempting = asyncio.Event()
    user = User(username="admin", password_hash="unused")
    async with factory() as first, factory() as second:
        first_session = _SerializedChannelSession(
            first,
            row_lock,
            acquired=first_acquired,
            release=release_first,
        )
        second_session = _SerializedChannelSession(
            second,
            row_lock,
            attempting=second_attempting,
        )
        first_task = asyncio.create_task(
            router_module.update_channel(
                channel_id,
                first_payload,
                user,
                first_session,  # type: ignore[arg-type]
                cipher,
                settings,
            )
        )
        await asyncio.wait_for(first_acquired.wait(), timeout=1)
        second_task = asyncio.create_task(
            router_module.update_channel(
                channel_id,
                second_payload,
                user,
                second_session,  # type: ignore[arg-type]
                cipher,
                settings,
            )
        )
        await asyncio.wait_for(second_attempting.wait(), timeout=1)
        assert not second_task.done()
        release_first.set()
        await asyncio.gather(first_task, second_task)


async def test_telegram_transport_keeps_bot_token_out_of_httpx_request_log(caplog) -> None:
    token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    observed_paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed_paths.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    transport = notifier._TelegramTokenTransport(token, httpx.MockTransport(handler))
    caplog.set_level(logging.INFO, logger="httpx")
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post(
            "https://api.telegram.org/sendMessage",
            json={"chat_id": "-1001234567890", "text": "test"},
        )

    assert response.status_code == 200
    assert observed_paths == [f"/bot{token}/sendMessage"]
    assert token not in caplog.text


async def test_telegram_post_uses_chat_id_and_plain_text(
    settings_dict: dict[str, object], monkeypatch
) -> None:
    token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    observed: list[dict[str, object]] = []

    async def resolve(*_args: object, **_kwargs: object) -> None:
        return None

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(json.loads(request.content))
        assert request.url.path == f"/bot{token}/sendMessage"
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(notifier, "resolve_target_address", resolve)
    monkeypatch.setattr(
        notifier.httpx,
        "AsyncHTTPTransport",
        lambda: httpx.MockTransport(handler),
    )
    response = await notifier._post_telegram(
        "https://api.telegram.org/",
        token,
        {"chat_id": "-1001234567890", "text": "Alert\nRecovered"},
        Settings(**settings_dict),
    )

    assert response.status_code == 200
    assert observed == [{"chat_id": "-1001234567890", "text": "Alert\nRecovered"}]


def test_telegram_destination_fails_closed_outside_exact_allowlist(
    settings_dict: dict[str, object],
) -> None:
    settings = Settings(**settings_dict)

    with pytest.raises(notifier.ConnectorError, match="not trusted"):
        notifier.validate_telegram_server_url(
            "https://api.telegram.org.attacker.example",
            settings.telegram_api_allowed_hosts,
        )
    with pytest.raises(notifier.ConnectorError, match="not trusted"):
        notifier.validate_telegram_server_url(
            "http://api.telegram.org",
            settings.telegram_api_allowed_hosts,
        )


async def test_channel_kind_change_clears_hidden_telegram_token(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    old_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    channel = NotificationChannel(
        id="channel-kind-change",
        name="telegram",
        kind="telegram",
        server_url="https://api.telegram.org",
        topic="-1001234567890",
        token_ciphertext=cipher.encrypt_text(old_token),
    )
    db_session.add(channel)
    await db_session.commit()

    async def validate_url(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(router_module, "validate_notification_url", validate_url)
    await router_module.update_channel(
        channel.id,
        ChannelUpdate(kind="webhook", server_url="https://hooks.example.com/events"),
        User(username="admin", password_hash="unused"),
        db_session,
        cipher,
        Settings(**settings_dict),
    )

    await db_session.refresh(channel)
    assert channel.kind == "webhook"
    assert channel.token_ciphertext is None


async def test_telegram_authority_change_requires_fresh_token(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    old_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    channel = NotificationChannel(
        id="channel-authority-change",
        name="telegram",
        kind="telegram",
        server_url="https://api.telegram.org",
        topic="-1001234567890",
        token_ciphertext=cipher.encrypt_text(old_token),
    )
    db_session.add(channel)
    await db_session.commit()

    async def validate_url(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(router_module, "validate_notification_url", validate_url)
    settings = Settings(
        **settings_dict,
        telegram_api_allowed_hosts=["api.telegram.org", "telegram-proxy.example.com"],
    )
    with pytest.raises(HTTPException, match="token is required"):
        await router_module.update_channel(
            channel.id,
            ChannelUpdate(server_url="https://telegram-proxy.example.com"),
            User(username="admin", password_hash="unused"),
            db_session,
            cipher,
            settings,
        )
    await db_session.rollback()

    await db_session.refresh(channel)
    assert cipher.decrypt_text(channel.token_ciphertext or "") == old_token


async def test_telegram_path_change_keeps_token_on_same_authority(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    channel = NotificationChannel(
        id="channel-path-change",
        name="telegram",
        kind="telegram",
        server_url="https://api.telegram.org",
        topic="-1001234567890",
        token_ciphertext=cipher.encrypt_text(token),
    )
    db_session.add(channel)
    await db_session.commit()

    async def validate_url(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(router_module, "validate_notification_url", validate_url)
    await router_module.update_channel(
        channel.id,
        ChannelUpdate(server_url="https://api.telegram.org/proxy"),
        User(username="admin", password_hash="unused"),
        db_session,
        cipher,
        Settings(**settings_dict),
    )

    await db_session.refresh(channel)
    assert cipher.decrypt_text(channel.token_ciphertext or "") == token


async def test_concurrent_channel_boundary_change_cannot_reuse_rotated_token(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    old_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    rotated_token = "234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghi"
    channel = NotificationChannel(
        id="channel-concurrent-token-boundary",
        name="telegram",
        kind="telegram",
        server_url="https://api.telegram.org",
        topic="-1001234567890",
        token_ciphertext=cipher.encrypt_text(old_token),
    )
    db_session.add(channel)
    await db_session.commit()

    async def validate_url(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(router_module, "validate_notification_url", validate_url)
    await _run_concurrent_channel_updates(
        db_session,
        channel.id,
        ChannelUpdate(token=rotated_token),
        ChannelUpdate(
            kind="webhook",
            server_url="https://hooks.example.com/events",
        ),
        cipher,
        Settings(**settings_dict),
    )

    await db_session.refresh(channel)
    assert channel.kind == "webhook"
    assert channel.server_url == "https://hooks.example.com/events"
    assert channel.token_ciphertext is None


async def test_concurrent_webhook_boundary_change_cannot_reuse_rotated_signing_secret(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    channel = NotificationChannel(
        id="channel-concurrent-signing-boundary",
        name="webhook",
        kind="webhook",
        server_url="https://hooks-a.example.com/events",
        topic="",
        signing_secret_ciphertext=cipher.encrypt_text("old-signing-secret"),
    )
    db_session.add(channel)
    await db_session.commit()

    async def validate_url(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(router_module, "validate_notification_url", validate_url)
    await _run_concurrent_channel_updates(
        db_session,
        channel.id,
        ChannelUpdate(signing_secret="rotated-signing-secret"),
        ChannelUpdate(
            server_url="https://hooks-b.example.com/events",
        ),
        cipher,
        Settings(**settings_dict),
    )

    await db_session.refresh(channel)
    assert channel.server_url == "https://hooks-b.example.com/events"
    assert channel.signing_secret_ciphertext is None


async def test_ntfy_outbox_retries_without_persisting_response_body(
    db_session, settings_dict: dict[str, object], monkeypatch
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

        async def post(self, _url: httpx.URL, *, content, headers, extensions) -> httpx.Response:
            FakeClient.calls += 1
            FakeClient.authorizations.append(headers.get("Authorization"))
            assert json.loads(content)["topic"] == "alerts"
            assert extensions == {}
            status = 503 if FakeClient.calls == 1 else 200
            return httpx.Response(status, json={"sensitive": "must-not-be-stored"})

    monkeypatch.setattr(notifier.httpx, "AsyncClient", FakeClient)

    settings = Settings(**settings_dict, allow_private_notification_targets=True)
    assert await notifier.dispatch_due(db_session, settings, cipher) == 0
    assert row.status == "pending"
    assert row.attempts == 1
    assert row.last_error == "ntfy returned HTTP 503"
    assert "sensitive" not in row.last_error

    row.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.commit()
    assert await notifier.dispatch_due(db_session, settings, cipher) == 1
    await db_session.refresh(row)
    assert row.status == "sent"
    assert row.attempts == 1
    assert FakeClient.authorizations == ["Bearer ntfy-secret", "Bearer ntfy-secret"]


async def test_dispatch_releases_claim_transaction_and_limits_concurrency(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    channel = NotificationChannel(
        id="channel-concurrency",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    rows = [
        NotificationOutbox(
            id=f"outbox-{index}",
            transition_id=f"transition-{index}",
            channel_id=channel.id,
            payload={"title": f"Alert {index}"},
        )
        for index in range(5)
    ]
    db_session.add_all([channel, *rows])
    await db_session.commit()
    active = 0
    maximum_active = 0

    async def deliver(item, *_args):
        nonlocal active, maximum_active
        assert not db_session.in_transaction()
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return notifier._DeliveryResult(item.id, item.attempts, True, False)

    monkeypatch.setattr(notifier, "_deliver", deliver)
    settings = Settings(**settings_dict, notification_dispatch_concurrency=2)

    cipher = SecretCipher(settings.master_key)
    assert await notifier.dispatch_due(db_session, settings, cipher) == 2
    assert await notifier.dispatch_due(db_session, settings, cipher) == 2
    assert await notifier.dispatch_due(db_session, settings, cipher) == 1
    assert maximum_active == 2
    for row in rows:
        await db_session.refresh(row)
        assert row.status == OutboxStatus.SENT.value
        assert row.lease_owner is None
        assert row.lease_expires_at is None


async def test_dispatch_reclaims_expired_delivery_lease(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    channel = NotificationChannel(
        id="channel-expired-lease",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    row = NotificationOutbox(
        id="outbox-expired-lease",
        transition_id="transition-expired-lease",
        channel_id=channel.id,
        payload={"title": "Recover me"},
        status=OutboxStatus.DELIVERING.value,
        lease_owner="dead-worker",
        lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    db_session.add_all([channel, row])
    await db_session.commit()

    async def deliver(item, *_args):
        return notifier._DeliveryResult(item.id, item.attempts, True, False)

    monkeypatch.setattr(notifier, "_deliver", deliver)
    settings = Settings(**settings_dict)

    assert await notifier.dispatch_due(
        db_session,
        settings,
        SecretCipher(settings.master_key),
        claim_owner="new-worker",
    ) == 1
    await db_session.refresh(row)
    assert row.status == OutboxStatus.SENT.value
    assert row.lease_owner is None


async def test_stale_claim_owner_cannot_overwrite_reclaimed_delivery(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    channel = NotificationChannel(
        id="channel-owner-race",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    row = NotificationOutbox(
        id="outbox-owner-race",
        transition_id="transition-owner-race",
        channel_id=channel.id,
        payload={"title": "Race"},
    )
    db_session.add_all([channel, row])
    await db_session.commit()

    async def deliver(item, *_args):
        claimed_row = await db_session.get(NotificationOutbox, item.id)
        assert claimed_row is not None
        claimed_row.lease_owner = "worker:new-claim-token"
        claimed_row.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=120)
        await db_session.commit()
        return notifier._DeliveryResult(item.id, item.attempts, True, False)

    monkeypatch.setattr(notifier, "_deliver", deliver)
    settings = Settings(**settings_dict, notification_dispatch_concurrency=1)

    assert await notifier.dispatch_due(
        db_session,
        settings,
        SecretCipher(settings.master_key),
        claim_owner="worker",
    ) == 0
    await db_session.refresh(row)
    assert row.status == OutboxStatus.DELIVERING.value
    assert row.lease_owner == "worker:new-claim-token"


async def test_minimum_lease_claims_only_one_bounded_wave(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    channel = NotificationChannel(
        id="channel-short-lease",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    rows = [
        NotificationOutbox(
            id=f"outbox-short-{index}",
            transition_id=f"transition-short-{index}",
            channel_id=channel.id,
            payload={"title": str(index)},
        )
        for index in range(3)
    ]
    db_session.add_all([channel, *rows])
    await db_session.commit()

    async def deliver(item, *_args):
        return notifier._DeliveryResult(item.id, item.attempts, True, False)

    monkeypatch.setattr(notifier, "_deliver", deliver)
    settings = Settings(
        **settings_dict,
        notification_dispatch_concurrency=1,
        notification_claim_seconds=30,
    )

    assert await notifier.dispatch_due(
        db_session, settings, SecretCipher(settings.master_key), limit=50
    ) == 1
    statuses = [row.status for row in rows]
    assert statuses.count(OutboxStatus.SENT.value) == 1
    assert statuses.count(OutboxStatus.PENDING.value) == 2


async def test_unexpected_delivery_error_does_not_discard_other_results(
    db_session, settings_dict: dict[str, object], monkeypatch
) -> None:
    channel = NotificationChannel(
        id="channel-isolated-errors",
        name="ntfy",
        server_url="https://ntfy.example.com",
        topic="alerts",
    )
    failed = NotificationOutbox(
        id="outbox-isolated-failed",
        transition_id="transition-isolated-failed",
        channel_id=channel.id,
        payload={"title": "Fail"},
    )
    sent = NotificationOutbox(
        id="outbox-isolated-sent",
        transition_id="transition-isolated-sent",
        channel_id=channel.id,
        payload={"title": "Send"},
    )
    db_session.add_all([channel, failed, sent])
    await db_session.commit()

    async def deliver(item, *_args):
        if item.id == failed.id:
            raise RuntimeError("unexpected sensitive details")
        return notifier._DeliveryResult(item.id, item.attempts, True, False)

    monkeypatch.setattr(notifier, "_deliver", deliver)
    settings = Settings(**settings_dict, notification_dispatch_concurrency=2)

    assert await notifier.dispatch_due(
        db_session, settings, SecretCipher(settings.master_key)
    ) == 1
    await db_session.refresh(failed)
    await db_session.refresh(sent)
    assert failed.status == OutboxStatus.PENDING.value
    assert failed.attempts == 1
    assert failed.last_error == "notification delivery failed unexpectedly"
    assert "sensitive" not in failed.last_error
    assert sent.status == OutboxStatus.SENT.value
