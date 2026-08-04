from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Session, User

PBKDF2_ITERATIONS = 600_000


class LoginThrottle:
    def __init__(self, *, window_seconds: int = 60, ip_limit: int = 20, account_limit: int = 5):
        self.window_seconds = window_seconds
        self.ip_limit = ip_limit
        self.account_limit = account_limit
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, client_ip: str, username: str) -> int | None:
        now = time.monotonic()
        keys = (
            (f"ip:{client_ip}", self.ip_limit),
            (f"account:{client_ip}:{username}", self.account_limit),
        )
        async with self._lock:
            for key, _ in keys:
                attempts = self._attempts[key]
                while attempts and attempts[0] <= now - self.window_seconds:
                    attempts.popleft()
            retry_after = 0
            for key, limit in keys:
                attempts = self._attempts[key]
                if len(attempts) >= limit:
                    retry_after = max(
                        retry_after,
                        max(1, int(self.window_seconds - (now - attempts[0])) + 1),
                    )
            if retry_after:
                return retry_after
            for key, _ in keys:
                self._attempts[key].append(now)
        return None

    async def reset_account(self, client_ip: str, username: str) -> None:
        async with self._lock:
            self._attempts.pop(f"account:{client_ip}:{username}", None)


login_throttle = LoginThrottle()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    salt_text = base64.urlsafe_b64encode(salt).decode()
    digest_text = base64.urlsafe_b64encode(digest).decode()
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_text}${digest_text}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SecretCipher:
    def __init__(self, master_key: str):
        key = base64.urlsafe_b64encode(hashlib.sha256(master_key.encode()).digest())
        self._fernet = Fernet(key)

    def encrypt_json(self, value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return self._fernet.encrypt(raw).decode()

    def decrypt_json(self, ciphertext: str) -> dict[str, Any]:
        try:
            value = json.loads(self._fernet.decrypt(ciphertext.encode()))
        except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("secret cannot be decrypted") from exc
        if not isinstance(value, dict):
            raise ValueError("secret payload is not an object")
        return value

    def encrypt_text(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt_text(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("secret cannot be decrypted") from exc


async def ensure_admin(session: AsyncSession, username: str, password: str) -> User:
    user = await session.scalar(select(User).where(User.username == username))
    if user is None:
        user = User(username=username, password_hash=hash_password(password), is_admin=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    user = await session.scalar(select(User).where(User.username == username))
    if user is None or not user.is_admin:
        return None
    password_valid = await asyncio.to_thread(verify_password, password, user.password_hash)
    if not password_valid:
        return None
    return user


async def create_session_token(
    session: AsyncSession, user: User, ttl_hours: int
) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    session.add(Session(user_id=user.id, token_hash=hash_token(token), expires_at=expires_at))
    await session.commit()
    return token, expires_at


async def revoke_session_token(session: AsyncSession, token: str) -> None:
    await session.execute(delete(Session).where(Session.token_hash == hash_token(token)))
    await session.commit()


async def user_for_session_token(session: AsyncSession, token: str) -> User | None:
    now = datetime.now(timezone.utc)
    stmt = (
        select(User)
        .join(Session, Session.user_id == User.id)
        .where(
            Session.token_hash == hash_token(token),
            Session.expires_at > now,
            User.is_admin.is_(True),
        )
    )
    user: User | None = await session.scalar(stmt)
    return user
