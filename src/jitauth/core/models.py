"""SQLAlchemy models for JITAuth core entities."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ---------- Enums ----------


class TaskStatus(str, enum.Enum):
    created = "created"
    classifying = "classifying"
    pending_policy = "pending_policy"
    approved = "approved"
    pending_approval = "pending_approval"
    denied = "denied"
    executing = "executing"
    completed = "completed"
    failed = "failed"


class RiskTier(str, enum.Enum):
    tier_0 = "tier_0"  # harmless read
    tier_1 = "tier_1"  # internal read
    tier_2 = "tier_2"  # bounded write
    tier_3 = "tier_3"  # material change
    tier_4 = "tier_4"  # destructive / privileged


class PolicyEffect(str, enum.Enum):
    allow = "allow"
    allow_reduced = "allow_reduced"
    require_approval = "require_approval"
    require_simulation = "require_simulation"
    deny = "deny"
    quarantine = "quarantine"


class CapabilityStatus(str, enum.Enum):
    active = "active"
    expired = "expired"
    revoked = "revoked"


class ActionClass(str, enum.Enum):
    read = "read"
    write = "write"
    delete = "delete"
    execute = "execute"
    send = "send"
    publish = "publish"


# ---------- Models ----------


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)  # ULID
    requester_type: Mapped[str] = mapped_column(String(50))
    requester_id: Mapped[str] = mapped_column(String(255))
    requester_auth_context: Mapped[str | None] = mapped_column(String(255))
    runtime_id: Mapped[str] = mapped_column(String(255))
    runtime_type: Mapped[str] = mapped_column(String(100))
    runtime_trust_tier: Mapped[str] = mapped_column(String(20), default="low")
    runtime_secret_hash: Mapped[str | None] = mapped_column(String(130))  # scrypt salt$hash
    created_by: Mapped[str | None] = mapped_column(String(255))  # authenticated caller identity
    objective: Mapped[str] = mapped_column(Text)
    risk_tier: Mapped[RiskTier | None] = mapped_column(Enum(RiskTier))
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus), default=TaskStatus.created
    )
    max_actions: Mapped[int] = mapped_column(Integer, default=10)
    time_limit_seconds: Mapped[int] = mapped_column(Integer, default=300)
    allow_destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Relationships
    actions: Mapped[list[TaskAction]] = relationship(back_populates="task", cascade="all, delete")
    capabilities: Mapped[list[Capability]] = relationship(back_populates="task")
    policy_decisions: Mapped[list[PolicyDecision]] = relationship(back_populates="task")
    approval_records: Mapped[list[ApprovalRecord]] = relationship(back_populates="task")

    __table_args__ = (
        Index("ix_tasks_status", "status"),
        Index("ix_tasks_requester", "requester_id"),
        Index("ix_tasks_runtime", "runtime_id"),
        Index("ix_tasks_created", "created_at"),
    )


class TaskAction(Base):
    __tablename__ = "task_actions"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    system: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    action_class: Mapped[ActionClass] = mapped_column(Enum(ActionClass))
    resource_scope: Mapped[str | None] = mapped_column(Text)
    data_scope: Mapped[str | None] = mapped_column(Text)

    task: Mapped[Task] = relationship(back_populates="actions")


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    effect: Mapped[PolicyEffect] = mapped_column(Enum(PolicyEffect))
    reason: Mapped[str | None] = mapped_column(Text)
    computed_scope: Mapped[str | None] = mapped_column(Text)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    task: Mapped[Task] = relationship(back_populates="policy_decisions")


class Capability(Base):
    __tablename__ = "capabilities"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    runtime_id: Mapped[str] = mapped_column(String(255), index=True)
    target_system: Mapped[str] = mapped_column(String(100))
    allowed_actions: Mapped[str] = mapped_column(Text)  # JSON array
    resource_scope: Mapped[str | None] = mapped_column(Text)  # JSON
    max_calls: Mapped[int] = mapped_column(Integer, default=10)
    calls_used: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[CapabilityStatus] = mapped_column(
        Enum(CapabilityStatus), default=CapabilityStatus.active
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    task: Mapped[Task] = relationship(back_populates="capabilities")
    invocations: Mapped[list[ToolInvocation]] = relationship(back_populates="capability")

    # --- Typed accessors for JSON fields ---

    @property
    def allowed_actions_list(self) -> list[str]:
        from jitauth.core.json_fields import parse_json_list
        return parse_json_list(self.allowed_actions)

    @allowed_actions_list.setter
    def allowed_actions_list(self, value: list[str]) -> None:
        from jitauth.core.json_fields import dump_json
        self.allowed_actions = dump_json(value)

    @property
    def resource_scope_parsed(self) -> dict | list | None:
        from jitauth.core.json_fields import parse_json
        return parse_json(self.resource_scope)

    __table_args__ = (
        Index("ix_capabilities_status", "status"),
        Index("ix_capabilities_expires", "expires_at"),
    )


class CredentialLease(Base):
    __tablename__ = "credential_leases"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    capability_id: Mapped[str] = mapped_column(ForeignKey("capabilities.id"), index=True)
    credential_type: Mapped[str] = mapped_column(String(50))  # jwt, vault_token, sts_session
    target_system: Mapped[str] = mapped_column(String(100))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class ToolInvocation(Base):
    __tablename__ = "tool_invocations"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    capability_id: Mapped[str] = mapped_column(ForeignKey("capabilities.id"), index=True)
    tool: Mapped[str] = mapped_column(String(255))
    arguments: Mapped[str | None] = mapped_column(Text)  # JSON, sanitized
    expected_effect: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str | None] = mapped_column(String(255))
    result_summary: Mapped[str | None] = mapped_column(Text)
    success: Mapped[bool | None] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(Text)
    invoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    capability: Mapped[Capability] = relationship(back_populates="invocations")

    __table_args__ = (
        Index("ix_invocation_idempotency", "task_id", "capability_id", "idempotency_key"),
    )


class ApprovalRecord(Base):
    __tablename__ = "approval_records"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    approver_id: Mapped[str] = mapped_column(String(255))
    approved: Mapped[bool] = mapped_column(Boolean)
    reduced_scope: Mapped[str | None] = mapped_column(Text)  # JSON if scope was reduced
    reason: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    task: Mapped[Task] = relationship(back_populates="approval_records")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    chain_seq: Mapped[int | None] = mapped_column(Integer, unique=True, index=True)  # monotonic DB sequence for chain ordering
    task_id: Mapped[str | None] = mapped_column(String(26), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    details: Mapped[str | None] = mapped_column(Text)  # JSON
    prev_event_hash: Mapped[str | None] = mapped_column(String(64))  # SHA-256 of previous event
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    __table_args__ = (Index("ix_audit_task_time", "task_id", "timestamp"),)


class RevocationEvent(Base):
    __tablename__ = "revocation_events"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    capability_id: Mapped[str] = mapped_column(ForeignKey("capabilities.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(26), index=True)
    reason: Mapped[str] = mapped_column(Text)
    revoked_by: Mapped[str] = mapped_column(String(255))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
