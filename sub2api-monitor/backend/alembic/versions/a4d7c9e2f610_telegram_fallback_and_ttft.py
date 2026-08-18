"""add Telegram, fallback routing, and TTFT policy controls

Revision ID: a4d7c9e2f610
Revises: f2a9c6d4e810
Create Date: 2026-08-16
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "a4d7c9e2f610"
down_revision: Union[str, None] = "f2a9c6d4e810"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("policies") as batch_op:
        batch_op.add_column(
            sa.Column("ttft_enabled", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch_op.add_column(
            sa.Column("ttft_percentile", sa.String(length=10), nullable=False, server_default="p95")
        )
        batch_op.add_column(
            sa.Column("ttft_min_samples", sa.Integer(), nullable=False, server_default="5")
        )
        batch_op.add_column(
            sa.Column("ttft_warning_ms", sa.Integer(), nullable=False, server_default="3000")
        )
        batch_op.add_column(
            sa.Column("ttft_critical_ms", sa.Integer(), nullable=False, server_default="6000")
        )
        batch_op.add_column(
            sa.Column("ttft_recovery_ms", sa.Integer(), nullable=False, server_default="2500")
        )
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.add_column(
            sa.Column("fallback_account_ids", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("fallback_priorities", sa.JSON(), nullable=False, server_default="{}")
        )
    channels = sa.table(
        "notification_channels",
        sa.column("id", sa.String()),
        sa.column("event_types", sa.JSON()),
    )
    connection = op.get_bind()
    for channel_id, event_types in connection.execute(
        sa.select(channels.c.id, channels.c.event_types)
    ):
        values = list(event_types or [])
        if "routing.rate_recovered" not in values:
            values.append("routing.rate_recovered")
            connection.execute(
                channels.update()
                .where(channels.c.id == channel_id)
                .values(event_types=values)
            )


def downgrade() -> None:
    channels = sa.table(
        "notification_channels",
        sa.column("id", sa.String()),
        sa.column("event_types", sa.JSON()),
    )
    connection = op.get_bind()
    for channel_id, event_types in connection.execute(
        sa.select(channels.c.id, channels.c.event_types)
    ):
        values = [item for item in (event_types or []) if item != "routing.rate_recovered"]
        connection.execute(
            channels.update()
            .where(channels.c.id == channel_id)
            .values(event_types=values)
        )
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.drop_column("fallback_priorities")
        batch_op.drop_column("fallback_account_ids")
    with op.batch_alter_table("policies") as batch_op:
        batch_op.drop_column("ttft_recovery_ms")
        batch_op.drop_column("ttft_critical_ms")
        batch_op.drop_column("ttft_warning_ms")
        batch_op.drop_column("ttft_min_samples")
        batch_op.drop_column("ttft_percentile")
        batch_op.drop_column("ttft_enabled")
