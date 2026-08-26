"""add roles table

Revision ID: 55b630e9782c
Revises: 860ef4619f15
Create Date: 2026-08-26 14:01:19.144753

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '55b630e9782c'
down_revision: Union[str, Sequence[str], None] = '860ef4619f15'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
