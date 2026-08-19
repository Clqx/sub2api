"""make fault automation recommendation-only and snapshot guarded

Revision ID: 1f4c8a2d7b90
Revises: e95c3d1a6b20
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "1f4c8a2d7b90"
down_revision: Union[str, None] = "e95c3d1a6b20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.add_column(sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("automation_rules") as batch_op:
        batch_op.add_column(
            sa.Column("reason_match_mode", sa.String(length=10), nullable=False, server_default="any")
        )
    # Tasks created before state snapshots existed are unsafe to execute. Existing
    # execute rules are disabled so an operator has to review the new semantics.
    op.execute(
        "UPDATE automation_executions SET status = 'cancelled', "
        "last_error = 'cancelled during safe automation upgrade', finished_at = CURRENT_TIMESTAMP "
        "WHERE status IN ('queued', 'running')"
    )
    op.execute("UPDATE automation_rules SET enabled = FALSE WHERE mode = 'execute'")
    op.execute(
        "UPDATE automation_rules SET enabled = FALSE "
        "WHERE action IN ('recover_state', 'set_schedulable')"
    )


def downgrade() -> None:
    with op.batch_alter_table("automation_rules") as batch_op:
        batch_op.drop_column("reason_match_mode")
    with op.batch_alter_table("accounts") as batch_op:
        batch_op.drop_column("source_updated_at")
