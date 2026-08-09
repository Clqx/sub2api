"""add one-minute cost routing control

Revision ID: c72f8e91a4b3
Revises: a91d2c4e5f60
Create Date: 2026-08-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c72f8e91a4b3"
down_revision: Union[str, None] = "a91d2c4e5f60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.add_column(sa.Column("priority", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("routing_desired_priority", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("routing_status", sa.String(length=30), nullable=True))
        batch_op.add_column(
            sa.Column("routing_updated_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("routing_applied_at", sa.DateTime(timezone=True), nullable=True)
        )

    op.create_table(
        "cost_routing_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("mode", sa.String(length=20), nullable=False, server_default="recommend"),
        sa.Column("probe_interval_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("priority_scale", sa.Integer(), nullable=False, server_default="1000"),
        sa.Column("unhealthy_priority", sa.Integer(), nullable=False, server_default="100000"),
        sa.Column("minimum_priority", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("last_account_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_change_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", name="uq_cost_routing_policy_target"),
    )
    op.create_index(
        "ix_cost_routing_policies_target_id",
        "cost_routing_policies",
        ["target_id"],
    )
    op.create_index(
        "ix_cost_routing_due",
        "cost_routing_policies",
        ["enabled", "next_run_at"],
    )

    op.create_table(
        "routing_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("policy_id", sa.String(length=36), nullable=True),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("external_account_id", sa.String(length=160), nullable=False),
        sa.Column("account_name", sa.String(length=160), nullable=False),
        sa.Column("observed_multiplier", sa.Float(), nullable=True),
        sa.Column("previous_priority", sa.Integer(), nullable=True),
        sa.Column("desired_priority", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=40), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["policy_id"], ["cost_routing_policies.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_routing_decisions_policy_id", "routing_decisions", ["policy_id"])
    op.create_index("ix_routing_decisions_target_id", "routing_decisions", ["target_id"])
    op.create_index("ix_routing_decisions_created_at", "routing_decisions", ["created_at"])
    op.create_index(
        "ix_routing_decision_target_time",
        "routing_decisions",
        ["target_id", "created_at"],
    )
    op.create_index(
        "ix_routing_decision_account_time",
        "routing_decisions",
        ["target_id", "external_account_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_routing_decision_account_time", table_name="routing_decisions")
    op.drop_index("ix_routing_decision_target_time", table_name="routing_decisions")
    op.drop_index("ix_routing_decisions_created_at", table_name="routing_decisions")
    op.drop_index("ix_routing_decisions_target_id", table_name="routing_decisions")
    op.drop_index("ix_routing_decisions_policy_id", table_name="routing_decisions")
    op.drop_table("routing_decisions")
    op.drop_index("ix_cost_routing_due", table_name="cost_routing_policies")
    op.drop_index("ix_cost_routing_policies_target_id", table_name="cost_routing_policies")
    op.drop_table("cost_routing_policies")
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.drop_column("routing_applied_at")
        batch_op.drop_column("routing_updated_at")
        batch_op.drop_column("routing_status")
        batch_op.drop_column("routing_desired_priority")
        batch_op.drop_column("priority")
