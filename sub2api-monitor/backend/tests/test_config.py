from __future__ import annotations

from pathlib import Path

from app.config import Settings


def test_runtime_secrets_can_be_loaded_from_files(tmp_path: Path) -> None:
    master = tmp_path / "master"
    admin = tmp_path / "admin"
    database = tmp_path / "database-url"
    master.write_text("file-master-key-that-is-long-enough\n", encoding="utf-8")
    admin.write_text("file-admin-password\n", encoding="utf-8")
    database.write_text("sqlite+aiosqlite://\n", encoding="utf-8")

    settings = Settings(
        master_key_file=str(master),
        admin_password_file=str(admin),
        database_url_file=str(database),
    )

    assert settings.master_key == "file-master-key-that-is-long-enough"
    assert settings.admin_password == "file-admin-password"
    assert settings.database_url == "sqlite+aiosqlite://"
