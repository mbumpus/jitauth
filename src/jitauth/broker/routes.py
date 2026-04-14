"""JITAuth API routes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from jitauth import __version__
from jitauth.config.settings import get_settings
from jitauth.core.id import new_id
from jitauth.core.models import (
    ApprovalRecord,
    AuditEvent,
    Capability,
    CapabilityStatus,
    PolicyDecision,
    RevocationEvent,
    Task,
    TaskAction,
    TaskStatus,
)
from jitauth.core.schemas import (
    ApprovalRequest,
    ApprovalResponse,
    AuditEventResponse,
    CapabilityResponse,
    ClassifyResponse,
    ExecuteRequest,
    ExecuteResponse,
    PolicyDecisionResponse,
    RevokeRequest,
    RevokeResponse,
    TaskCreate,
    TaskResponse,
)
from jitauth.db.session import get_db
from jitauth.proxy.gateway import GatewayError

router = APIRouter()


# ---------- Health ----------


@router.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "service": "jitauth-broker",
    }


# ---------- Tasks ----------


@router.post("/tasks", response_model=TaskResponse, status_code=201)
def create_task(req: TaskCreate, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)

    task = Task(
        id=new_id(),
        requester_type=req.requester_type,
        requester_id=req.requester_id,
        requester_auth_context=req.requester_auth_context,
        runtime_id=req.runtime_id,
        runtime_type=req.runtime_type,
        runtime_trust_tier=req.runtime_trust_tier,
        objective=req.objective,
        status=TaskStatus.created,
        max_actions=req.max_actions,
        time_limit_seconds=req.time_limit_seconds,
        allow_destructive=req.allow_destructive,
        created_at=now,
        expires_at=now + timedelta(seconds=req.time_limit_seconds),
    )

    for a in req.actions:
        task.actions.append(
            TaskAction(
                id=new_id(),
                system=a.system,
                action=a.action,
                action_class=a.action_class,
                resource_scope=a.resource_scope,
                data_scope=a.data_scope,
            )
        )

    db.add(task)
    _audit(db, task.id, "task_created", req.requester_id, {"objective": req.objective})
    db.commit()
    db.refresh(task)
    return task


@router.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(task_id: str, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    return task


# ---------- Classification ----------


@router.post("/tasks/{task_id}/classify", response_model=ClassifyResponse)
def classify_task(task_id: str, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.created:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'created'")

    from jitauth.policy.risk import classify_risk

    risk_tier, action_classes = classify_risk(task)
    task.risk_tier = risk_tier
    task.status = TaskStatus.pending_policy

    _audit(db, task_id, "task_classified", "system", {
        "risk_tier": risk_tier.value,
        "action_classes": action_classes,
    })
    db.commit()
    return ClassifyResponse(
        task_id=task_id,
        risk_tier=risk_tier,
        action_classes=action_classes,
    )


# ---------- Policy Evaluation ----------


@router.post("/tasks/{task_id}/policy-evaluate", response_model=PolicyDecisionResponse)
def evaluate_policy(task_id: str, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.pending_policy:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'pending_policy'")

    from jitauth.policy.engine import evaluate

    decision = evaluate(task)

    pd = PolicyDecision(
        id=new_id(),
        task_id=task_id,
        rule_name=decision["rule_name"],
        effect=decision["effect"],
        reason=decision.get("reason"),
        computed_scope=json.dumps(decision.get("scope")) if decision.get("scope") else None,
    )
    db.add(pd)

    # Update task status based on decision
    effect = decision["effect"]
    if effect == "allow" or effect == "allow_reduced":
        task.status = TaskStatus.approved
    elif effect == "require_approval":
        task.status = TaskStatus.pending_approval
    else:
        task.status = TaskStatus.denied

    _audit(db, task_id, "policy_evaluated", "policy_engine", {
        "rule": decision["rule_name"],
        "effect": effect,
        "reason": decision.get("reason"),
    })
    db.commit()
    db.refresh(pd)
    return pd


# ---------- Approval ----------


@router.post("/tasks/{task_id}/approve", response_model=ApprovalResponse)
def approve_task(task_id: str, req: ApprovalRequest, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.pending_approval:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'pending_approval'")

    record = ApprovalRecord(
        id=new_id(),
        task_id=task_id,
        approver_id=req.approver_id,
        approved=req.approved,
        reduced_scope=json.dumps(req.reduced_scope) if req.reduced_scope else None,
        reason=req.reason,
    )
    db.add(record)

    task.status = TaskStatus.approved if req.approved else TaskStatus.denied

    _audit(db, task_id, "task_approval", req.approver_id, {
        "approved": req.approved,
        "reason": req.reason,
    })
    db.commit()
    db.refresh(record)
    return record


# ---------- Capabilities ----------


@router.post("/tasks/{task_id}/capabilities", response_model=list[CapabilityResponse])
def request_capabilities(task_id: str, db: Session = Depends(get_db)):
    settings = get_settings()
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.approved:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'approved'")

    now = datetime.now(timezone.utc)
    ttl = min(task.time_limit_seconds, settings.default_capability_ttl_seconds)
    caps = []

    # Group actions by target system
    systems: dict[str, list[TaskAction]] = {}
    for action in task.actions:
        systems.setdefault(action.system, []).append(action)

    for system, actions in systems.items():
        cap = Capability(
            id=new_id(),
            task_id=task_id,
            runtime_id=task.runtime_id,
            target_system=system,
            allowed_actions=json.dumps([a.action for a in actions]),
            resource_scope=actions[0].resource_scope,  # Use first action's scope
            max_calls=task.max_actions,
            status=CapabilityStatus.active,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        db.add(cap)
        caps.append(cap)

    task.status = TaskStatus.executing

    _audit(db, task_id, "capabilities_minted", "broker", {
        "count": len(caps),
        "ttl_seconds": ttl,
    })
    db.commit()

    # Mint JWT tokens for each capability
    from jitauth.core.tokens import mint_capability_token

    results = []
    for c in caps:
        db.refresh(c)
        token = mint_capability_token(
            capability_id=c.id,
            task_id=c.task_id,
            runtime_id=c.runtime_id,
            target_system=c.target_system,
            allowed_actions=json.loads(c.allowed_actions),
            issued_at=c.issued_at,
            expires_at=c.expires_at,
            resource_scope=c.resource_scope,
            max_calls=c.max_calls,
        )
        results.append(CapabilityResponse(
            id=c.id,
            task_id=c.task_id,
            runtime_id=c.runtime_id,
            target_system=c.target_system,
            allowed_actions=c.allowed_actions,
            resource_scope=c.resource_scope,
            max_calls=c.max_calls,
            calls_used=c.calls_used,
            status=c.status,
            issued_at=c.issued_at,
            expires_at=c.expires_at,
            token=token,
        ))
    return results


# ---------- Execution ----------


@router.post("/execute", response_model=ExecuteResponse)
async def execute_tool(req: ExecuteRequest, db: Session = Depends(get_db)):
    from jitauth.proxy.gateway import execute_tool_call

    try:
        result = await execute_tool_call(
            db=db,
            capability_id=req.capability_id,
            tool=req.tool,
            arguments=req.arguments,
            expected_effect=req.expected_effect,
            idempotency_key=req.idempotency_key,
        )
        return ExecuteResponse(**result)
    except GatewayError as e:
        raise HTTPException(
            status_code=403 if "not_allowed" in e.code or "revoked" in e.code else 400,
            detail={"error": e.code, "message": str(e)},
        ) from None


# ---------- Revocation ----------


@router.post("/capabilities/{capability_id}/revoke", response_model=RevokeResponse)
def revoke_capability(capability_id: str, req: RevokeRequest, db: Session = Depends(get_db)):
    cap = db.get(Capability, capability_id)
    if not cap:
        raise HTTPException(404, "Capability not found")
    if cap.status != CapabilityStatus.active:
        raise HTTPException(409, f"Capability is already '{cap.status}'")

    now = datetime.now(timezone.utc)
    cap.status = CapabilityStatus.revoked
    cap.revoked_at = now

    event = RevocationEvent(
        id=new_id(),
        capability_id=capability_id,
        task_id=cap.task_id,
        reason=req.reason,
        revoked_by=req.revoked_by,
    )
    db.add(event)

    _audit(db, cap.task_id, "capability_revoked", req.revoked_by, {
        "capability_id": capability_id,
        "reason": req.reason,
    })
    db.commit()
    return RevokeResponse(
        capability_id=capability_id,
        status=cap.status,
        revoked_at=now,
    )


# ---------- Audit ----------


@router.get("/audit", response_model=list[AuditEventResponse])
def query_audit(
    task_id: str | None = None,
    runtime_id: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(AuditEvent)
    if task_id:
        q = q.filter(AuditEvent.task_id == task_id)
    if event_type:
        q = q.filter(AuditEvent.event_type == event_type)
    q = q.order_by(AuditEvent.timestamp.desc()).limit(min(limit, 200))
    return q.all()


# ---------- Helpers ----------


def _audit(db: Session, task_id: str | None, event_type: str, actor: str, details: dict):
    """Write an audit event."""
    event = AuditEvent(
        id=new_id(),
        task_id=task_id,
        event_type=event_type,
        actor=actor,
        details=json.dumps(details),
    )
    db.add(event)
