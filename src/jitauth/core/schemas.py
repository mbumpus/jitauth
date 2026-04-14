"""Pydantic schemas for JITAuth API request/response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from jitauth.core.models import (
    ActionClass,
    CapabilityStatus,
    PolicyEffect,
    RiskTier,
    TaskStatus,
)

# ---------- Task ----------


class TaskActionCreate(BaseModel):
    system: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    action_class: ActionClass
    resource_scope: str | None = Field(default=None, max_length=1000)
    data_scope: str | None = Field(default=None, max_length=1000)


class TaskCreate(BaseModel):
    requester_type: str = Field(default="human_user", max_length=50)
    requester_id: str = Field(min_length=1, max_length=255)
    requester_auth_context: str | None = Field(default=None, max_length=255)
    runtime_id: str = Field(min_length=1, max_length=255)
    runtime_type: str = Field(default="llm_orchestrator", max_length=100)
    runtime_trust_tier: str = Field(default="low", max_length=20)
    runtime_secret: str | None = Field(
        default=None, min_length=32, max_length=255,
        description="Session secret for runtime authentication. "
        "When provided, the broker stores a SHA-256 hash and requires "
        "the same secret on /execute calls to bind execution to the "
        "originally authenticated runtime.",
    )
    objective: str = Field(min_length=1, max_length=100_000)
    actions: list[TaskActionCreate] = Field(min_length=1, max_length=100)
    max_actions: int = Field(default=10, ge=1, le=100)
    time_limit_seconds: int = Field(default=300, ge=10, le=3600)
    allow_destructive: bool = False


class TaskActionResponse(BaseModel):
    id: str
    system: str
    action: str
    action_class: ActionClass
    resource_scope: str | None
    data_scope: str | None

    model_config = {"from_attributes": True}


class TaskResponse(BaseModel):
    id: str
    requester_id: str
    runtime_id: str
    runtime_type: str
    objective: str
    risk_tier: RiskTier | None
    status: TaskStatus
    actions: list[TaskActionResponse]
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}


# ---------- Policy ----------


class ActionDecisionResponse(BaseModel):
    system: str
    action: str
    action_class: str
    rule_name: str
    effect: PolicyEffect
    reason: str | None


class PolicyDecisionResponse(BaseModel):
    id: str
    task_id: str
    rule_name: str
    effect: PolicyEffect
    reason: str | None
    evaluated_at: datetime
    action_decisions: list[ActionDecisionResponse] | None = None

    model_config = {"from_attributes": True}


class ClassifyResponse(BaseModel):
    task_id: str
    risk_tier: RiskTier
    action_classes: list[str]


# ---------- Capability ----------


class CapabilityResponse(BaseModel):
    id: str
    task_id: str
    runtime_id: str
    target_system: str
    allowed_actions: str  # JSON
    resource_scope: str | None
    max_calls: int
    calls_used: int
    status: CapabilityStatus
    issued_at: datetime
    expires_at: datetime
    token: str | None = None  # Signed JWT capability token

    model_config = {"from_attributes": True}


# ---------- Execution ----------


class ExecuteRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=26)
    capability_id: str = Field(min_length=1, max_length=26)
    capability_token: str = Field(min_length=1, max_length=4096)
    runtime_secret: str | None = Field(
        default=None, min_length=32, max_length=255,
        description="Runtime session secret.  Required if the task was "
        "created with a runtime_secret.",
    )
    tool: str = Field(min_length=3, max_length=255, pattern=r"^[\w.-]+$")
    arguments: dict = Field(default_factory=dict)
    expected_effect: str | None = Field(default=None, max_length=1000)
    idempotency_key: str | None = Field(default=None, max_length=255)


class ExecuteResponse(BaseModel):
    invocation_id: str
    tool: str
    success: bool
    result: dict | str | None = None
    error: str | None = None


# ---------- Approval ----------


class ApprovalRequest(BaseModel):
    approver_id: str = Field(min_length=1, max_length=255)
    approved: bool
    reduced_scope: dict | None = None
    reason: str | None = Field(default=None, max_length=1000)


class ApprovalResponse(BaseModel):
    id: str
    task_id: str
    approver_id: str
    approved: bool
    decided_at: datetime

    model_config = {"from_attributes": True}


# ---------- Task Completion ----------


class CompleteTaskRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=1000)
    completed_by: str = Field(min_length=1, max_length=255)


class CompleteTaskResponse(BaseModel):
    task_id: str
    status: TaskStatus
    capabilities_expired: int


# ---------- Revocation ----------


class RevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)
    revoked_by: str = Field(min_length=1, max_length=255)


class RevokeResponse(BaseModel):
    capability_id: str
    status: CapabilityStatus
    revoked_at: datetime


# ---------- Audit ----------


class AuditEventResponse(BaseModel):
    id: str
    task_id: str | None
    event_type: str
    actor: str
    details: str | None
    timestamp: datetime

    model_config = {"from_attributes": True}
