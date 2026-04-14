"""Baseline schema: creates all JITAuth tables from scratch.

This migration represents the full v0.5.0 schema. It is safe to run
on an empty database.  For pre-existing deployments that already have
tables (created via ``create_all()``), stamp this revision without
running it::

    alembic stamp 000

Then run subsequent migrations normally.

Revision ID: 000
Revises:
Create Date: 2026-04-14
"""

from alembic import op
import sqlalchemy as sa


revision = "000"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- tasks ---
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("requester_type", sa.String(50), nullable=False),
        sa.Column("requester_id", sa.String(255), nullable=False),
        sa.Column("requester_auth_context", sa.String(255), nullable=True),
        sa.Column("runtime_id", sa.String(255), nullable=False),
        sa.Column("runtime_type", sa.String(100), nullable=False),
        sa.Column("runtime_trust_tier", sa.String(20), nullable=False, server_default="low"),
        sa.Column("runtime_secret_hash", sa.String(130), nullable=True),
        sa.Column("objective", sa.Text, nullable=False),
        sa.Column("risk_tier", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="created"),
        sa.Column("max_actions", sa.Integer, nullable=False, server_default="10"),
        sa.Column("time_limit_seconds", sa.Integer, nullable=False, server_default="300"),
        sa.Column("allow_destructive", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tasks_status", "tasks", ["status"])
    op.create_index("ix_tasks_requester", "tasks", ["requester_id"])
    op.create_index("ix_tasks_runtime", "tasks", ["runtime_id"])
    op.create_index("ix_tasks_created", "tasks", ["created_at"])

    # --- task_actions ---
    op.create_table(
        "task_actions",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("task_id", sa.String(26), sa.ForeignKey("tasks.id"), nullable=False, index=True),
        sa.Column("system", sa.String(100), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("action_class", sa.String(20), nullable=False),
        sa.Column("resource_scope", sa.Text, nullable=True),
        sa.Column("data_scope", sa.Text, nullable=True),
    )

    # --- policy_decisions ---
    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("task_id", sa.String(26), sa.ForeignKey("tasks.id"), nullable=False, index=True),
        sa.Column("rule_name", sa.String(255), nullable=False),
        sa.Column("effect", sa.String(30), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("computed_scope", sa.Text, nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # --- capabilities ---
    op.create_table(
        "capabilities",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("task_id", sa.String(26), sa.ForeignKey("tasks.id"), nullable=False, index=True),
        sa.Column("runtime_id", sa.String(255), nullable=False, index=True),
        sa.Column("target_system", sa.String(100), nullable=False),
        sa.Column("allowed_actions", sa.Text, nullable=False),
        sa.Column("resource_scope", sa.Text, nullable=True),
        sa.Column("max_calls", sa.Integer, nullable=False, server_default="10"),
        sa.Column("calls_used", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_capabilities_status", "capabilities", ["status"])
    op.create_index("ix_capabilities_expires", "capabilities", ["expires_at"])

    # --- credential_leases ---
    op.create_table(
        "credential_leases",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("capability_id", sa.String(26), sa.ForeignKey("capabilities.id"), nullable=False, index=True),
        sa.Column("credential_type", sa.String(50), nullable=False),
        sa.Column("target_system", sa.String(100), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default="0"),
    )

    # --- tool_invocations ---
    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("task_id", sa.String(26), sa.ForeignKey("tasks.id"), nullable=False, index=True),
        sa.Column("capability_id", sa.String(26), sa.ForeignKey("capabilities.id"), nullable=False, index=True),
        sa.Column("tool", sa.String(255), nullable=False),
        sa.Column("arguments", sa.Text, nullable=True),
        sa.Column("expected_effect", sa.Text, nullable=True),
        sa.Column("idempotency_key", sa.String(255), nullable=True),
        sa.Column("result_summary", sa.Text, nullable=True),
        sa.Column("success", sa.Boolean, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("invoked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_invocation_idempotency", "tool_invocations", ["task_id", "capability_id", "idempotency_key"])

    # --- approval_records ---
    op.create_table(
        "approval_records",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("task_id", sa.String(26), sa.ForeignKey("tasks.id"), nullable=False, index=True),
        sa.Column("approver_id", sa.String(255), nullable=False),
        sa.Column("approved", sa.Boolean, nullable=False),
        sa.Column("reduced_scope", sa.Text, nullable=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )

    # --- audit_events ---
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("chain_seq", sa.Integer, nullable=True, unique=True),
        sa.Column("task_id", sa.String(26), nullable=True, index=True),
        sa.Column("event_type", sa.String(100), nullable=False, index=True),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("details", sa.Text, nullable=True),
        sa.Column("prev_event_hash", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index("ix_audit_events_chain_seq", "audit_events", ["chain_seq"])
    op.create_index("ix_audit_task_time", "audit_events", ["task_id", "timestamp"])

    # --- revocation_events ---
    op.create_table(
        "revocation_events",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("capability_id", sa.String(26), sa.ForeignKey("capabilities.id"), nullable=False, index=True),
        sa.Column("task_id", sa.String(26), nullable=True, index=True),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("revoked_by", sa.String(255), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("revocation_events")
    op.drop_table("audit_events")
    op.drop_table("approval_records")
    op.drop_table("tool_invocations")
    op.drop_table("credential_leases")
    op.drop_table("capabilities")
    op.drop_table("policy_decisions")
    op.drop_table("task_actions")
    op.drop_table("tasks")
