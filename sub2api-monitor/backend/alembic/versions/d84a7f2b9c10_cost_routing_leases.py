"""add cost routing execution leases

Revision ID: d84a7f2b9c10
Revises: c72f8e91a4b3
Create Date: 2026-08-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "d84a7f2b9c10"
down_revision: Union[str, None] = "c72f8e91a4b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.add_column(sa.Column("lease_owner", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index("ix_cost_routing_policies_lease_until", ["lease_until"])


def downgrade() -> None:
    with op.batch_alter_table("cost_routing_policies") as batch_op:
        batch_op.drop_index("ix_cost_routing_policies_lease_until")
        batch_op.drop_column("lease_until")
        batch_op.drop_column("lease_owner")
