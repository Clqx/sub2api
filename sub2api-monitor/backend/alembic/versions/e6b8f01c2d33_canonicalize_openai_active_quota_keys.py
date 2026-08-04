"""canonicalize OpenAI active quota keys

Revision ID: e6b8f01c2d33
Revises: d3a4e8c1f920
Create Date: 2026-08-03
"""

from typing import Sequence, Union

from alembic import op


revision: str = "e6b8f01c2d33"
down_revision: Union[str, None] = "d3a4e8c1f920"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE quota_samples
        SET quota_key = 'codex.five_hour', label = 'Codex 5 hour quota'
        WHERE provider = 'openai'
          AND quota_key = 'five_hour'
          AND source IN ('sub2api_api_active', 'sub2api_api_usage_cache')
        """
    )
    op.execute(
        """
        UPDATE quota_samples
        SET quota_key = 'codex.seven_day', label = 'Codex 7 day quota'
        WHERE provider = 'openai'
          AND quota_key = 'seven_day'
          AND source IN ('sub2api_api_active', 'sub2api_api_usage_cache')
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE quota_samples
        SET quota_key = 'five_hour', label = '5 hour quota'
        WHERE provider = 'openai'
          AND quota_key = 'codex.five_hour'
          AND source IN ('sub2api_api_active', 'sub2api_api_usage_cache')
        """
    )
    op.execute(
        """
        UPDATE quota_samples
        SET quota_key = 'seven_day', label = '7 day quota'
        WHERE provider = 'openai'
          AND quota_key = 'codex.seven_day'
          AND source IN ('sub2api_api_active', 'sub2api_api_usage_cache')
        """
    )
