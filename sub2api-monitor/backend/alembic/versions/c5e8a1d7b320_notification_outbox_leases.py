"""add notification outbox delivery leases

Revision ID: c5e8a1d7b320
Revises: a4d7c9e2f610
Create Date: 2026-08-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c5e8a1d7b320"
down_revision: Union[str, None] = "a4d7c9e2f610"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("notification_outbox") as batch_op:
        batch_op.add_column(sa.Column("lease_owner", sa.String(length=160), nullable=True))
        batch_op.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(
            "ix_outbox_claim",
            ["status", "lease_expires_at", "next_attempt_at"],
            unique=False,
        )


def downgrade() -> None:
    outbox = sa.table(
        "notification_outbox",
        sa.column("status", sa.String()),
    )
    op.get_bind().execute(
        outbox.update().where(outbox.c.status == "delivering").values(status="pending")
    )
    with op.batch_alter_table("notification_outbox") as batch_op:
        batch_op.drop_index("ix_outbox_claim")
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("lease_owner")
