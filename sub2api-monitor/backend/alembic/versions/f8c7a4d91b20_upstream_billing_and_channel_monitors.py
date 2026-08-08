"""add upstream billing and channel monitoring

Revision ID: f8c7a4d91b20
Revises: e6b8f01c2d33
Create Date: 2026-08-08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "f8c7a4d91b20"
down_revision: Union[str, None] = "e6b8f01c2d33"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("accounts", sa.Column("rate_multiplier", sa.Float(), nullable=True))
    op.add_column(
        "accounts",
        sa.Column(
            "upstream_billing_probe_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "accounts",
        sa.Column(
            "upstream_billing_rate_sync_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("accounts", sa.Column("upstream_billing_probe", sa.JSON(), nullable=True))
    op.add_column(
        "policies",
        sa.Column(
            "channel_failure_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    op.create_table(
        "channel_monitors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("external_monitor_id", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("api_mode", sa.String(length=30), nullable=False),
        sa.Column("endpoint", sa.String(length=2048), nullable=False),
        sa.Column("api_key_masked", sa.String(length=100), nullable=False),
        sa.Column("api_key_decrypt_failed", sa.Boolean(), nullable=False),
        sa.Column("primary_model", sa.String(length=200), nullable=False),
        sa.Column("extra_models", sa.JSON(), nullable=False),
        sa.Column("group_name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("jitter_seconds", sa.Integer(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("primary_status", sa.String(length=30), nullable=False),
        sa.Column("primary_latency_ms", sa.Integer(), nullable=True),
        sa.Column("availability_7d", sa.Float(), nullable=False),
        sa.Column("extra_models_status", sa.JSON(), nullable=False),
        sa.Column("template_id", sa.String(length=160), nullable=True),
        sa.Column("extra_headers", sa.JSON(), nullable=False),
        sa.Column("body_override_mode", sa.String(length=20), nullable=False),
        sa.Column("body_override", sa.JSON(), nullable=True),
        sa.Column("source_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "target_id", "external_monitor_id", name="uq_channel_target_external"
        ),
    )
    op.create_index("ix_channel_monitors_target_id", "channel_monitors", ["target_id"])
    op.create_index(
        "ix_channel_target_status", "channel_monitors", ["target_id", "primary_status"]
    )


def downgrade() -> None:
    op.drop_index("ix_channel_target_status", table_name="channel_monitors")
    op.drop_index("ix_channel_monitors_target_id", table_name="channel_monitors")
    op.drop_table("channel_monitors")
    op.drop_column("policies", "channel_failure_enabled")
    op.drop_column("accounts", "upstream_billing_probe")
    op.drop_column("accounts", "upstream_billing_rate_sync_enabled")
    op.drop_column("accounts", "upstream_billing_probe_enabled")
    op.drop_column("accounts", "rate_multiplier")
