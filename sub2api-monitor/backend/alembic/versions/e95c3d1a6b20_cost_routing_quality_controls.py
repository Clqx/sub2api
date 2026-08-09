"""add cost routing quality controls

Revision ID: e95c3d1a6b20
Revises: d84a7f2b9c10
Create Date: 2026-08-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "e95c3d1a6b20"
down_revision: Union[str, None] = "d84a7f2b9c10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.add_column(
            sa.Column(
                "quality_bindings",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.alter_column("probe_interval_seconds", server_default="30")
    op.execute(
        sa.text("UPDATE cost_routing_policies SET probe_interval_seconds = 30")
    )


def downgrade() -> None:
    op.execute(
        sa.text("UPDATE cost_routing_policies SET probe_interval_seconds = 60")
    )
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.alter_column("probe_interval_seconds", server_default="60")
        batch_op.drop_column("quality_bindings")
