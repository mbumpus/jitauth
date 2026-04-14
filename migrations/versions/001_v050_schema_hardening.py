"""v0.5.0 schema hardening: widen runtime_secret_hash, add audit chain_seq.

For upgraded deployments (tables already exist from ``create_all()``):
  - Widens ``tasks.runtime_secret_hash`` from VARCHAR(64) to VARCHAR(130)
  - Adds ``audit_events.chain_seq`` column
  - Backfills ``chain_seq`` for all existing audit rows in timestamp order

For fresh deployments:
  - Use migration 000 (baseline) first, which already includes these columns.
    Then stamp this revision: ``alembic stamp 001``

Revision ID: 001
Revises: 000
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa


revision = "001"
down_revision = "000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # 1. Widen tasks.runtime_secret_hash from VARCHAR(64) to VARCHAR(130)
    with op.batch_alter_table("tasks") as batch_op:
        batch_op.alter_column(
            "runtime_secret_hash",
            existing_type=sa.String(64),
            type_=sa.String(130),
            existing_nullable=True,
        )

    # 2. Add audit_events.chain_seq for monotonic DB-serialized ordering.
    #    Skip if column already exists (fresh installs via 000 baseline).
    inspector = sa.inspect(conn)
    existing_cols = {c["name"] for c in inspector.get_columns("audit_events")}
    if "chain_seq" not in existing_cols:
        with op.batch_alter_table("audit_events") as batch_op:
            batch_op.add_column(
                sa.Column("chain_seq", sa.Integer(), nullable=True),
            )
        # Create unique index outside batch mode (avoids SQLite unnamed constraint error)
        op.create_index("ix_audit_events_chain_seq", "audit_events", ["chain_seq"], unique=True)

    # 3. Backfill chain_seq for legacy rows that don't have one yet.
    #    Assigns sequence numbers in original timestamp order so the
    #    existing hash chain remains valid.
    audit_events = sa.table(
        "audit_events",
        sa.column("id", sa.String),
        sa.column("chain_seq", sa.Integer),
        sa.column("timestamp", sa.DateTime),
    )
    legacy_rows = conn.execute(
        sa.select(audit_events.c.id)
        .where(audit_events.c.chain_seq.is_(None))
        .order_by(audit_events.c.timestamp.asc())
    ).fetchall()

    if legacy_rows:
        # Find the current max chain_seq to continue from
        max_seq = conn.execute(
            sa.select(sa.func.coalesce(sa.func.max(audit_events.c.chain_seq), 0))
        ).scalar()
        for i, row in enumerate(legacy_rows, start=max_seq + 1):
            conn.execute(
                audit_events.update()
                .where(audit_events.c.id == row[0])
                .values(chain_seq=i)
            )


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
