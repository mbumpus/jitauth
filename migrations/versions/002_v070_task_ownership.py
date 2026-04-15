"""v0.7.0: add tasks.created_by for task ownership enforcement.

For upgraded deployments:
  - Adds ``tasks.created_by`` column (nullable, VARCHAR(255))
  - Existing tasks will have NULL created_by (operators can still access them)

For fresh deployments:
  - Use migration 000 (baseline) which already includes the column.
    Then stamp: ``alembic stamp 002``

Revision ID: 002
Revises: 001
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa


revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Check if column already exists (fresh DB from updated 000)
    from sqlalchemy import inspect
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("tasks")]

    if "created_by" not in columns:
        op.add_column("tasks", sa.Column("created_by", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("tasks", "created_by")
