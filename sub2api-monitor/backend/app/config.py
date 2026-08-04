from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MONITOR_", env_file=".env", extra="ignore", case_sensitive=False
    )

    environment: str = "development"
    database_url: str = "postgresql+asyncpg://monitor:monitor@localhost:5432/monitor"
    database_url_file: str | None = None
    master_key: str = Field(min_length=16)
    master_key_file: str | None = None
    admin_username: str = "admin"
    admin_password: str = Field(min_length=12)
    admin_password_file: str | None = None
    session_ttl_hours: int = Field(default=12, ge=1, le=720)
    connector_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    connector_max_pages: int = Field(default=100, ge=1, le=1000)
    connector_page_size: int = Field(default=100, ge=1, le=500)
    connector_max_response_bytes: int = Field(default=2_097_152, ge=65_536, le=16_777_216)
    target_db_connect_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    target_db_statement_timeout_ms: int = Field(default=5_000, ge=100, le=60_000)
    target_db_lock_timeout_ms: int = Field(default=1_000, ge=100, le=10_000)
    target_db_max_accounts: int = Field(default=20_000, ge=1, le=100_000)
    target_quota_stale_seconds: int = Field(default=3_600, ge=60, le=604_800)
    active_quota_refresh_enabled: bool = False
    active_quota_target_interval_seconds: int = Field(default=300, ge=60, le=86_400)
    active_quota_account_interval_seconds: int = Field(default=900, ge=60, le=604_800)
    active_quota_max_accounts_per_run: int = Field(default=20, ge=1, le=500)
    target_binding_ttl_hours: int = Field(default=24, ge=1, le=168)
    target_db_fallback_minutes: int = Field(default=60, ge=0, le=240)
    allow_private_targets: bool = False
    worker_poll_seconds: float = Field(default=2.0, ge=0.2, le=60.0)
    worker_concurrency: int = Field(default=8, ge=1, le=100)
    worker_stale_seconds: int = Field(default=60, ge=10, le=3600)
    producer_id: str = "hub-worker"
    log_level: str = "INFO"

    @model_validator(mode="before")
    @classmethod
    def load_secret_files(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        for field_name, file_field in (
            ("database_url", "database_url_file"),
            ("master_key", "master_key_file"),
            ("admin_password", "admin_password_file"),
        ):
            file_name = data.get(file_field)
            if file_name:
                try:
                    data[field_name] = Path(str(file_name)).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise ValueError(f"cannot read {file_field}") from exc
        return data


@lru_cache
def get_settings() -> Settings:
    return Settings()
