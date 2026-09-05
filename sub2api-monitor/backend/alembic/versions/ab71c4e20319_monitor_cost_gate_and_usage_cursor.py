"""monitor cost ceiling and independent usage cursor

Revision ID: ab71c4e20319
Revises: 7b3e1d9f2a40
"""

from alembic import op
import sqlalchemy as sa

revision = "ab71c4e20319"
down_revision = "7b3e1d9f2a40"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cost_routing_policies",
        sa.Column("maximum_multiplier", sa.Float(), nullable=False, server_default="1"),
    )
    op.create_table(
        "routing_usage_cursors",
        sa.Column(
            "target_id",
            sa.String(36),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("last_usage_id", sa.BigInteger()),
        sa.Column("lease_owner", sa.String(100)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(500)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("routing_usage_cursors")
    op.drop_column("cost_routing_policies", "maximum_multiplier")
