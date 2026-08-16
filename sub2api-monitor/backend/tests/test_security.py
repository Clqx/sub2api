from __future__ import annotations

from app.security import (
    SecretCipher,
    create_session_token,
    ensure_admin,
    hash_password,
    user_for_session_token,
    verify_password,
)


def test_password_hash_round_trip() -> None:
    encoded = hash_password("a sufficiently long password")
    assert "a sufficiently long password" not in encoded
    assert verify_password("a sufficiently long password", encoded)
    assert not verify_password("wrong", encoded)


def test_secret_cipher_round_trip_and_wrong_key() -> None:
    cipher = SecretCipher("first sufficiently long master key")
    encrypted = cipher.encrypt_json({"api_key": "admin-secret"})
    assert "admin-secret" not in encrypted
    assert cipher.decrypt_json(encrypted) == {"api_key": "admin-secret"}

    other = SecretCipher("second sufficiently long master key")
    try:
        other.decrypt_json(encrypted)
    except ValueError as exc:
        assert str(exc) == "secret cannot be decrypted"
    else:
        raise AssertionError("ciphertext unexpectedly decrypted with another key")


async def test_admin_password_rotation_invalidates_existing_sessions(db_session) -> None:
    user = await ensure_admin(db_session, "admin", "first-password-long-enough")
    token, _ = await create_session_token(db_session, user, 12)

    unchanged = await ensure_admin(db_session, "admin", "first-password-long-enough")
    assert unchanged.id == user.id
    assert await user_for_session_token(db_session, token) is not None

    rotated = await ensure_admin(db_session, "admin", "second-password-long-enough")
    assert verify_password("second-password-long-enough", rotated.password_hash)
    assert not verify_password("first-password-long-enough", rotated.password_hash)
    assert await user_for_session_token(db_session, token) is None
