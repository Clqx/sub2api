"""add event subscriptions and incident automation

Revision ID: a91d2c4e5f60
Revises: f8c7a4d91b20
Create Date: 2026-08-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "a91d2c4e5f60"
down_revision: Union[str, None] = "f8c7a4d91b20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("policies") as batch_op:
        batch_op.add_column(
            sa.Column(
                "native_alerts_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "collection_failure_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
            )
        )
    with op.batch_alter_table("notification_channels") as batch_op:
        batch_op.add_column(
            sa.Column("kind", sa.String(length=20), nullable=False, server_default="ntfy")
        )
        batch_op.add_column(sa.Column("event_types", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("severities", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("signing_secret_ciphertext", sa.Text(), nullable=True))
    op.execute(
        "UPDATE notification_channels "
        'SET event_types = \'["incident.firing","incident.escalated","incident.resolved"]\', '
        'severities = \'["warning","critical"]\''
    )
    with op.batch_alter_table("notification_channels") as batch_op:
        batch_op.alter_column("event_types", nullable=False)
        batch_op.alter_column("severities", nullable=False)

    op.create_table(
        "automation_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("trigger_rule_key", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("reason_filters", sa.JSON(), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_automation_rules_target_id", "automation_rules", ["target_id"])

    op.create_table(
        "automation_executions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=True),
        sa.Column("incident_id", sa.String(length=36), nullable=True),
        sa.Column("transition_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("external_account_id", sa.String(length=160), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["rule_id"], ["automation_rules.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
        sa.UniqueConstraint("rule_id", "transition_id", name="uq_automation_rule_transition"),
    )
    op.create_index("ix_automation_executions_rule_id", "automation_executions", ["rule_id"])
    op.create_index(
        "ix_automation_executions_incident_id", "automation_executions", ["incident_id"]
    )
    op.create_index("ix_automation_executions_target_id", "automation_executions", ["target_id"])
    op.create_index("ix_automation_due", "automation_executions", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_automation_due", table_name="automation_executions")
    op.drop_index("ix_automation_executions_target_id", table_name="automation_executions")
    op.drop_index("ix_automation_executions_incident_id", table_name="automation_executions")
    op.drop_index("ix_automation_executions_rule_id", table_name="automation_executions")
    op.drop_table("automation_executions")
    op.drop_index("ix_automation_rules_target_id", table_name="automation_rules")
    op.drop_table("automation_rules")
    with op.batch_alter_table("notification_channels") as batch_op:
        batch_op.drop_column("signing_secret_ciphertext")
        batch_op.drop_column("severities")
        batch_op.drop_column("event_types")
        batch_op.drop_column("kind")
    with op.batch_alter_table("policies") as batch_op:
        batch_op.drop_column("collection_failure_enabled")
        batch_op.drop_column("native_alerts_enabled")
