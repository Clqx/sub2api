from __future__ import annotations

from app.main import create_app


def test_openapi_never_exposes_ciphertext_or_raw_target_secret() -> None:
    schema_text = str(create_app().openapi())
    assert "ciphertext" not in schema_text
    assert "TargetSecret" not in schema_text
    assert "/api/v1/targets/{target_id}/collect" in schema_text
    assert "/api/v1/targets/{target_id}/probe" in schema_text
    assert "/api/v1/targets/{target_id}/capabilities/quota.active_refresh" in schema_text
    assert "force" not in schema_text
