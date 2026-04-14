"""v0.5.0 schema hardening: widen runtime_secret_hash, add audit chain_seq.

Revision ID: 001
Revises:
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Widen tasks.runtime_secret_hash from VARCHAR(64) to VARCHAR(130)
    #    to accommodate scrypt salt$hash format (was SHA-256 only).
    #    - SQLite does not enforce column widths, so this is a no-op there.
    #    - Postgres / MySQL will ALTER COLUMN.
    with op.batch_alter_table("tasks") as batch_op:
        batch_op.alter_column(
            "runtime_secret_hash",
            existing_type=sa.String(64),
            type_=sa.String(130),
            existing_nullable=True,
        )

    # 2. Add audit_events.chain_seq for monotonic DB-serialized ordering.
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.add_column(
            sa.Column("chain_seq", sa.Integer(), nullable=True, unique=True),
        )
        batch_op.create_index("ix_audit_events_chain_seq", ["chain_seq"])


def downgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_index("ix_audit_events_chain_seq")
        batch_op.drop_column("chain_seq")

    with op.batch_alter_table("tasks") as batch_op:
        batch_op.alter_column(
            "runtime_secret_hash",
            existing_type=sa.String(130),
            type_=sa.String(64),
            existing_nullable=True,
        )
