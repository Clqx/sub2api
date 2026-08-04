"""active quota attempt audit

Revision ID: d3a4e8c1f920
Revises: b7f31d9a2c44
Create Date: 2026-08-03
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "d3a4e8c1f920"
down_revision: Union[str, None] = "b7f31d9a2c44"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "active_quota_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("correlation_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("external_account_id", sa.String(length=160), nullable=False),
        sa.Column("actor", sa.String(length=160), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("before_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("after_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quota_count", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["collection_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_id"),
    )
    op.create_index(
        op.f("ix_active_quota_attempts_created_at"),
        "active_quota_attempts",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_active_quota_attempts_outcome"),
        "active_quota_attempts",
        ["outcome"],
        unique=False,
    )
    op.create_index(
        op.f("ix_active_quota_attempts_run_id"),
        "active_quota_attempts",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_active_quota_attempts_target_id"),
        "active_quota_attempts",
        ["target_id"],
        unique=False,
    )
    op.create_index(
        "ix_active_quota_attempt_target_account_time",
        "active_quota_attempts",
        ["target_id", "external_account_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_active_quota_attempt_target_account_time", table_name="active_quota_attempts")
    op.drop_index(op.f("ix_active_quota_attempts_target_id"), table_name="active_quota_attempts")
    op.drop_index(op.f("ix_active_quota_attempts_run_id"), table_name="active_quota_attempts")
    op.drop_index(op.f("ix_active_quota_attempts_outcome"), table_name="active_quota_attempts")
    op.drop_index(op.f("ix_active_quota_attempts_created_at"), table_name="active_quota_attempts")
    op.drop_table("active_quota_attempts")
