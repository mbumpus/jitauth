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
    ActionDecisionResponse,
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
from jitauth.broker.auth import AuthenticatedCaller, get_caller, require_operator
from jitauth.db.session import get_db
from jitauth.proxy.gateway import GatewayError

router = APIRouter()


# ---------- Ownership ----------


def _enforce_task_ownership(task: Task, caller: AuthenticatedCaller) -> None:
    """Ensure non-operator callers can only access tasks they created.

    Operators bypass ownership checks.  Runtime-role callers must have
    created the task (``task.created_by == caller.caller_id``).

    This prevents one runtime from manipulating another runtime's tasks.
    """
    if caller.is_operator:
        return
    if task.created_by and task.created_by != caller.caller_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "task_ownership_denied",
                "message": f"Caller '{caller.caller_id}' is not the creator of task '{task.id}'",
            },
        )


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
def create_task(req: TaskCreate, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    now = datetime.now(timezone.utc)

    # Hash the runtime session secret if provided (Finding-2 #1, scrypt KDF)
    secret_hash = None
    if req.runtime_secret:
        from jitauth.core.crypto import hash_secret
        secret_hash = hash_secret(req.runtime_secret)

    task = Task(
        id=new_id(),
        requester_type=req.requester_type,
        requester_id=req.requester_id,
        requester_auth_context=req.requester_auth_context,
        runtime_id=req.runtime_id,
        runtime_type=req.runtime_type,
        runtime_trust_tier=req.runtime_trust_tier,
        runtime_secret_hash=secret_hash,
        created_by=caller.caller_id,
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
    _audit(db, task.id, "task_created", caller.caller_id, {
        "objective": req.objective,
        "requester_id": req.requester_id,
        "runtime_id": req.runtime_id,
    })
    db.commit()
    db.refresh(task)
    return task


@router.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    _enforce_task_ownership(task, caller)
    return task


# ---------- Classification ----------


@router.post("/tasks/{task_id}/classify", response_model=ClassifyResponse)
def classify_task(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    _enforce_task_ownership(task, caller)
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
def evaluate_policy(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    _enforce_task_ownership(task, caller)
    if task.status != TaskStatus.pending_policy:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'pending_policy'")

    from jitauth.policy.engine import evaluate

    decision = evaluate(task)
    action_decisions = decision.get("action_decisions", [])

    pd = PolicyDecision(
        id=new_id(),
        task_id=task_id,
        rule_name=decision["rule_name"],
        effect=decision["effect"],
        reason=decision.get("reason"),
        computed_scope=json.dumps({
            "scope": decision.get("scope"),
            "action_decisions": action_decisions,
        }),
    )
    db.add(pd)

    # Update task status based on composite decision (most restrictive wins)
    effect = decision["effect"]
    if effect == "allow" or effect == "allow_reduced":
        task.status = TaskStatus.approved
    elif effect == "require_approval":
        task.status = TaskStatus.pending_approval
    elif effect in ("require_simulation", "quarantine"):
        # These effects are defined in the policy vocabulary but not yet
        # implemented as broker workflows.  Treat as denied with a clear
        # reason rather than silently accepting an unenforceable state.
        task.status = TaskStatus.denied
        _audit(db, task_id, "policy_effect_unsupported", "policy_engine", {
            "effect": effect,
            "message": f"Policy effect '{effect}' is not yet implemented; task denied.",
        })
    else:
        task.status = TaskStatus.denied

    _audit(db, task_id, "policy_evaluated", "policy_engine", {
        "rule": decision["rule_name"],
        "effect": effect,
        "reason": decision.get("reason"),
        "action_decisions": [
            {"system": ad["system"], "action": ad["action"], "effect": ad["effect"]}
            for ad in action_decisions
        ],
    })
    db.commit()
    db.refresh(pd)

    # Build response with per-action decisions
    resp = PolicyDecisionResponse(
        id=pd.id,
        task_id=pd.task_id,
        rule_name=pd.rule_name,
        effect=pd.effect,
        reason=pd.reason,
        evaluated_at=pd.evaluated_at,
        action_decisions=[
            ActionDecisionResponse(
                system=ad["system"],
                action=ad["action"],
                action_class=ad["action_class"],
                rule_name=ad["rule_name"],
                effect=ad["effect"],
                reason=ad.get("reason"),
            )
            for ad in action_decisions
        ],
    )
    return resp


# ---------- Approval ----------


@router.post("/tasks/{task_id}/approve", response_model=ApprovalResponse)
def approve_task(task_id: str, req: ApprovalRequest, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(require_operator)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.pending_approval:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'pending_approval'")

    # Derive approver identity from authenticated caller, not request body
    approver_id = caller.caller_id

    record = ApprovalRecord(
        id=new_id(),
        task_id=task_id,
        approver_id=approver_id,
        approved=req.approved,
        reduced_scope=json.dumps(req.reduced_scope) if req.reduced_scope else None,
        reason=req.reason,
    )
    db.add(record)

    task.status = TaskStatus.approved if req.approved else TaskStatus.denied

    _audit(db, task_id, "task_approval", approver_id, {
        "approved": req.approved,
        "reason": req.reason,
    })
    db.commit()
    db.refresh(record)
    return record


# ---------- Capabilities ----------


@router.post("/tasks/{task_id}/capabilities", response_model=list[CapabilityResponse])
def request_capabilities(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    settings = get_settings()
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    _enforce_task_ownership(task, caller)
    if task.status != TaskStatus.approved:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'approved'")

    now = datetime.now(timezone.utc)
    ttl = min(task.time_limit_seconds, settings.default_capability_ttl_seconds)
    caps = []

    # Check for approval reductions
    reduced_scope = None
    approval = (
        db.query(ApprovalRecord)
        .filter(ApprovalRecord.task_id == task_id, ApprovalRecord.approved.is_(True))
        .order_by(ApprovalRecord.decided_at.desc())
        .first()
    )
    if approval and approval.reduced_scope:
        reduced_scope = json.loads(approval.reduced_scope)

    # Retrieve policy-derived scopes from the most recent PolicyDecision
    # for this task.  Policy scope is the ceiling — requester-supplied
    # scope can only narrow it further, not widen it (Finding-2 #2).
    policy_scopes: dict[str, dict | list | None] = {}
    latest_pd = (
        db.query(PolicyDecision)
        .filter(PolicyDecision.task_id == task_id)
        .order_by(PolicyDecision.evaluated_at.desc())
        .first()
    )
    if latest_pd and latest_pd.computed_scope:
        pd_data = json.loads(latest_pd.computed_scope)
        for ad in pd_data.get("action_decisions", []):
            scope_val = ad.get("scope")
            # Only use structured scopes (dict/list) for intersection.
            # String sentinels like "minimal" mean "defer to requester scope".
            if isinstance(scope_val, (dict, list)):
                policy_scopes.setdefault(ad["system"], scope_val)

    # Group actions by target system
    systems: dict[str, list[TaskAction]] = {}
    for action in task.actions:
        systems.setdefault(action.system, []).append(action)

    for system, actions in systems.items():
        # Start with policy-derived scope as the ceiling
        policy_scope = policy_scopes.get(system)

        # Merge resource scopes from all actions in this system
        # resource_scope on TaskAction is already a JSON string — parse before merging
        parsed_scopes = []
        for a in actions:
            if a.resource_scope:
                try:
                    parsed_scopes.append(json.loads(a.resource_scope))
                except (json.JSONDecodeError, TypeError):
                    parsed_scopes.append(a.resource_scope)

        if len(parsed_scopes) == 1:
            requester_scope = parsed_scopes[0]
        elif parsed_scopes:
            requester_scope = parsed_scopes
        else:
            requester_scope = None

        # Intersect: policy scope is the ceiling, requester scope narrows
        effective_scope = _intersect_scopes(policy_scope, requester_scope)

        # Apply approval reductions — must only narrow, never widen.
        # Intersect the reduction with the already-computed effective scope
        # so a broad reduced_scope payload cannot exceed the policy ceiling
        # (Finding-3 #1).
        if reduced_scope:
            system_reduction = reduced_scope.get(system)
            if system_reduction:
                effective_scope = _intersect_scopes(effective_scope, system_reduction)

        merged_scope = json.dumps(effective_scope) if effective_scope is not None else None

        cap = Capability(
            id=new_id(),
            task_id=task_id,
            runtime_id=task.runtime_id,
            target_system=system,
            allowed_actions=json.dumps([a.action for a in actions]),
            resource_scope=merged_scope,
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
            allowed_actions=c.allowed_actions_list,
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
async def execute_tool(req: ExecuteRequest, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(get_caller)):
    from jitauth.proxy.gateway import execute_tool_call

    try:
        result = await execute_tool_call(
            db=db,
            task_id=req.task_id,
            capability_id=req.capability_id,
            capability_token=req.capability_token,
            tool=req.tool,
            arguments=req.arguments,
            expected_effect=req.expected_effect,
            idempotency_key=req.idempotency_key,
            runtime_secret=req.runtime_secret,
        )
        return ExecuteResponse(**result)
    except GatewayError as e:
        raise HTTPException(
            status_code=403 if any(
                k in e.code
                for k in ("not_allowed", "revoked", "mismatch", "token_", "runtime_auth")
            ) else 400,
            detail={"error": e.code, "message": str(e)},
        ) from None


# ---------- Task Completion ----------


@router.post("/tasks/{task_id}/complete")
def complete_task(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(require_operator)):
    """Mark a task as completed and expire all active capabilities."""
    from jitauth.core.schemas import CompleteTaskResponse

    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status != TaskStatus.executing:
        raise HTTPException(409, f"Task is in state '{task.status}', expected 'executing'")

    now = datetime.now(timezone.utc)
    task.status = TaskStatus.completed

    # Expire all active capabilities for this task
    caps = (
        db.query(Capability)
        .filter(Capability.task_id == task_id, Capability.status == CapabilityStatus.active)
        .all()
    )
    for cap in caps:
        cap.status = CapabilityStatus.expired
        cap.expires_at = now

    _audit(db, task_id, "task_completed", caller.caller_id, {
        "capabilities_expired": len(caps),
    })
    db.commit()
    return CompleteTaskResponse(
        task_id=task_id,
        status=TaskStatus.completed,
        capabilities_expired=len(caps),
    )


@router.post("/tasks/{task_id}/fail")
def fail_task(task_id: str, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(require_operator)):
    """Mark a task as failed and revoke all active capabilities."""
    from jitauth.core.schemas import CompleteTaskResponse

    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    if task.status not in (TaskStatus.executing, TaskStatus.approved, TaskStatus.pending_approval):
        raise HTTPException(409, f"Task is in state '{task.status}', cannot fail")

    now = datetime.now(timezone.utc)
    task.status = TaskStatus.failed

    # Revoke all active capabilities for this task
    caps = (
        db.query(Capability)
        .filter(Capability.task_id == task_id, Capability.status == CapabilityStatus.active)
        .all()
    )
    for cap in caps:
        cap.status = CapabilityStatus.revoked
        cap.revoked_at = now

    _audit(db, task_id, "task_failed", caller.caller_id, {
        "capabilities_revoked": len(caps),
    })
    db.commit()
    return CompleteTaskResponse(
        task_id=task_id,
        status=TaskStatus.failed,
        capabilities_expired=len(caps),
    )


# ---------- Revocation ----------


@router.post("/capabilities/{capability_id}/revoke", response_model=RevokeResponse)
def revoke_capability(capability_id: str, req: RevokeRequest, db: Session = Depends(get_db), caller: AuthenticatedCaller = Depends(require_operator)):
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
        revoked_by=caller.caller_id,
    )
    db.add(event)

    _audit(db, cap.task_id, "capability_revoked", caller.caller_id, {
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
    caller: AuthenticatedCaller = Depends(require_operator),
):
    q = db.query(AuditEvent)
    if task_id:
        q = q.filter(AuditEvent.task_id == task_id)
    if runtime_id:
        q = q.filter(AuditEvent.actor.contains(runtime_id))
    if event_type:
        q = q.filter(AuditEvent.event_type == event_type)
    q = q.order_by(AuditEvent.timestamp.desc()).limit(min(limit, 200))
    return q.all()


@router.get("/audit/verify")
def verify_audit(
    task_id: str | None = None,
    db: Session = Depends(get_db),
    caller: AuthenticatedCaller = Depends(require_operator),
):
    """Verify the integrity of the audit hash chain."""
    from jitauth.audit.logger import verify_audit_chain

    return verify_audit_chain(db, task_id=task_id)


# ---------- Helpers ----------


def _intersect_scopes(
    policy_scope: dict | list | str | None,
    requester_scope: dict | list | str | None,
) -> dict | list | str | None:
    """Intersect two scopes monotonically: the result is always ≤ both inputs.

    Rules:
      - If either is None → use the other (None = "no constraint")
      - If both are dicts → per-field intersection
        - Both have a field as lists → keep only common values (may be empty)
        - Only one side has a field → use that side's constraint
        - Both non-list → policy wins (ceiling)
      - If both are lists → keep only common entries
      - Otherwise → policy ceiling wins (narrower by assumption)

    An empty list for a field means "no values allowed" — the gateway's
    _enforce_scope will reject any argument for that field.

    This function is monotonic: the output can never contain a value that
    was absent from both inputs (Finding-3 #2).
    """
    if policy_scope is None:
        return requester_scope
    if requester_scope is None:
        return policy_scope

    # Both are dicts: intersect per field
    if isinstance(policy_scope, dict) and isinstance(requester_scope, dict):
        result = {}
        for field in set(policy_scope) | set(requester_scope):
            p_vals = policy_scope.get(field)
            r_vals = requester_scope.get(field)
            if p_vals is None:
                # Policy has no constraint on this field — requester narrows
                result[field] = r_vals
            elif r_vals is None:
                # Requester has no constraint — policy narrows
                result[field] = p_vals
            elif isinstance(p_vals, list) and isinstance(r_vals, list):
                # True intersection — may be empty, which means "nothing allowed"
                result[field] = [v for v in r_vals if v in p_vals]
            else:
                # Non-list: policy ceiling wins
                result[field] = p_vals
        return result

    # Both are lists: true set intersection
    if isinstance(policy_scope, list) and isinstance(requester_scope, list):
        return [v for v in requester_scope if v in policy_scope]

    # Incompatible types: policy ceiling wins
    return policy_scope


def _audit(db: Session, task_id: str | None, event_type: str, actor: str, details: dict):
    """Write an audit event with hash chaining."""
    from jitauth.audit.logger import write_audit_event

    write_audit_event(db, event_type, actor, task_id=task_id, details=details)
