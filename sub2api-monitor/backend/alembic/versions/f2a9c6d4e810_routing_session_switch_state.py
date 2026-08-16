"""add actual routing session switch state

Revision ID: f2a9c6d4e810
Revises: e95c3d1a6b20
Create Date: 2026-08-16
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "f2a9c6d4e810"
down_revision: Union[str, None] = "e95c3d1a6b20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "routing_session_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=160), nullable=False),
        sa.Column("external_account_id", sa.String(length=160), nullable=False),
        sa.Column("account_name", sa.String(length=160), nullable=False),
        sa.Column("last_usage_id", sa.BigInteger(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "target_id", "session_id", name="uq_routing_session_target_session"
        ),
    )
    op.create_index(
        "ix_routing_session_states_target_id",
        "routing_session_states",
        ["target_id"],
    )
    op.create_index(
        "ix_routing_session_state_updated",
        "routing_session_states",
        ["updated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_routing_session_state_updated", table_name="routing_session_states")
    op.drop_index("ix_routing_session_states_target_id", table_name="routing_session_states")
    op.drop_table("routing_session_states")
