from __future__ import annotations

import pytest

from app.security import LoginThrottle


@pytest.mark.asyncio
async def test_login_throttle_limits_repeated_account_failures() -> None:
    throttle = LoginThrottle(window_seconds=60, ip_limit=20, account_limit=2)

    assert await throttle.check("192.0.2.1", "admin") is None
    assert await throttle.check("192.0.2.1", "admin") is None
    assert await throttle.check("192.0.2.1", "admin") is not None

    await throttle.reset_account("192.0.2.1", "admin")
    assert await throttle.check("192.0.2.1", "admin") is None
