"""full mode database connector

Revision ID: 9c2b1e7d4a10
Revises: 588940ec7204
Create Date: 2026-08-03
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9c2b1e7d4a10"
down_revision: Union[str, None] = "588940ec7204"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column(
            "db_connection_state",
            sa.String(length=30),
            nullable=False,
            server_default="not_configured",
        ),
    )
    op.add_column(
        "targets",
        sa.Column(
            "binding_state", sa.String(length=30), nullable=False, server_default="not_required"
        ),
    )
    op.add_column("targets", sa.Column("binding_method", sa.String(length=60), nullable=True))
    op.add_column("targets", sa.Column("binding_confidence", sa.String(length=20), nullable=True))
    op.add_column(
        "targets", sa.Column("binding_api_fingerprint", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "targets", sa.Column("binding_db_fingerprint", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "targets", sa.Column("binding_checked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "targets", sa.Column("binding_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_table(
        "target_database_secrets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_target_database_secrets_target_id"),
        "target_database_secrets",
        ["target_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_target_database_secrets_target_id"), table_name="target_database_secrets"
    )
    op.drop_table("target_database_secrets")
    op.drop_column("targets", "binding_expires_at")
    op.drop_column("targets", "binding_checked_at")
    op.drop_column("targets", "binding_db_fingerprint")
    op.drop_column("targets", "binding_api_fingerprint")
    op.drop_column("targets", "binding_confidence")
    op.drop_column("targets", "binding_method")
    op.drop_column("targets", "binding_state")
    op.drop_column("targets", "db_connection_state")
