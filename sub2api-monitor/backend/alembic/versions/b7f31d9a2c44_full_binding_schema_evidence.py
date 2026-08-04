"""store full binding schema evidence

Revision ID: b7f31d9a2c44
Revises: 9c2b1e7d4a10
Create Date: 2026-08-03
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b7f31d9a2c44"
down_revision: Union[str, None] = "9c2b1e7d4a10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("binding_db_schema_fingerprint", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("targets", "binding_db_schema_fingerprint")
