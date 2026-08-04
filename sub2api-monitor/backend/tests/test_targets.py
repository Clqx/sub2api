from __future__ import annotations

from sqlalchemy import select

from app.config import Settings
from app.models import Capability, TargetDatabaseSecret, TargetSecret
from app.schemas import TargetCreate
from app.security import SecretCipher
from app.services.targets import connector_for_target, create_target


async def test_target_secret_is_encrypted_and_capabilities_are_independent(
    db_session,
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    target = await create_target(
        db_session,
        TargetCreate.model_validate(
            {
                "name": "prod",
                "base_url": "https://sub.example.com",
                "credential": {"auth_type": "x_api_key", "api_key": "admin-secret"},
            }
        ),
        cipher,
        "admin",
    )
    secret = await db_session.scalar(
        select(TargetSecret).where(TargetSecret.target_id == target.id)
    )
    assert secret is not None
    assert "admin-secret" not in secret.ciphertext
    assert cipher.decrypt_json(secret.ciphertext) == {"api_key": "admin-secret"}

    capabilities = list(
        await db_session.scalars(select(Capability).where(Capability.target_id == target.id))
    )
    active = next(item for item in capabilities if item.key == "quota.active_refresh")
    inventory = next(item for item in capabilities if item.key == "accounts.inventory")
    assert active.support_state == "unknown"
    assert active.enabled is False
    assert active.side_effect == "upstream_call_and_possible_target_write"
    assert inventory.enabled is True


async def test_full_target_database_secret_is_separately_encrypted(db_session) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    database_url = "postgresql://readonly:db-secret@database:5432/sub2api"
    target = await create_target(
        db_session,
        TargetCreate.model_validate(
            {
                "name": "full",
                "base_url": "https://sub.example.com",
                "mode": "full",
                "credential": {"auth_type": "x_api_key", "api_key": "admin-secret"},
                "database": {"database_url": database_url},
            }
        ),
        cipher,
        "admin",
    )
    database_secret = await db_session.scalar(
        select(TargetDatabaseSecret).where(TargetDatabaseSecret.target_id == target.id)
    )
    assert database_secret is not None
    assert database_url not in database_secret.ciphertext
    assert cipher.decrypt_json(database_secret.ciphertext) == {"database_url": database_url}
    capabilities = list(
        await db_session.scalars(select(Capability).where(Capability.target_id == target.id))
    )
    assert next(item for item in capabilities if item.key == "database.inventory").enabled


async def test_rotated_token_survives_observation_transaction_rollback(
    db_session, settings_dict: dict[str, object]
) -> None:
    cipher = SecretCipher("test-master-key-that-is-long-enough")
    target = await create_target(
        db_session,
        TargetCreate.model_validate(
            {
                "name": "rotating",
                "base_url": "https://sub.example.com",
                "credential": {
                    "auth_type": "token_pair",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                },
            }
        ),
        cipher,
        "admin",
    )
    connector = await connector_for_target(db_session, target, Settings(**settings_dict), cipher)
    target_id = target.id
    assert connector.on_secret_rotated is not None

    await connector.on_secret_rotated(
        {"access_token": "new-access", "refresh_token": "new-refresh"}
    )
    target.name = "rolled-back-name"
    await db_session.rollback()

    secret = await db_session.scalar(
        select(TargetSecret).where(TargetSecret.target_id == target_id)
    )
    assert secret is not None
    assert cipher.decrypt_json(secret.ciphertext) == {
        "access_token": "new-access",
        "refresh_token": "new-refresh",
    }
