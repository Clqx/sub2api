"""merge safe automation and notification outbox heads

Revision ID: 7b3e1d9f2a40
Revises: 1f4c8a2d7b90, c5e8a1d7b320
"""

from typing import Sequence, Union


revision: str = "7b3e1d9f2a40"
down_revision: Union[str, Sequence[str], None] = (
    "1f4c8a2d7b90",
    "c5e8a1d7b320",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
