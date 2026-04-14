"""Execution proxy gateway.

This is the core of the broker's enforcement: it validates capabilities,
dispatches to adapters, enforces call limits and TTLs, and logs everything.

The runtime calls POST /execute with a capability_id and tool call.
The gateway:
1. Validates the capability (exists, active, not expired, not revoked)
2. Checks the action is allowed by the capability
3. Checks call count limits
4. Dispatches to the correct adapter
5. Injects credentials server-side (runtime never sees them)
6. Records the invocation in the audit trail
7. Returns sanitized results
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from jitauth.core.id import new_id
from jitauth.core.json_fields import parse_json
from jitauth.core.models import (
    Capability,
    CapabilityStatus,
    ToolInvocation,
)
from jitauth.proxy.base import AdapterConfig, BaseAdapter

logger = logging.getLogger(__name__)


class GatewayError(Exception):
    """Raised when the gateway rejects a request."""

    def __init__(self, message: str, code: str = "gateway_error"):
        super().__init__(message)
        self.code = code


# ---------- Adapter Registry ----------

_adapters: dict[str, BaseAdapter] = {}
_adapter_configs: dict[str, AdapterConfig] = {}


def register_adapter(adapter: BaseAdapter) -> None:
    """Register a tool adapter with the gateway."""
    _adapters[adapter.system_name] = adapter
    logger.info("Registered adapter: %s (%s)", adapter.system_name, type(adapter).__name__)


def register_adapter_config(config: AdapterConfig) -> None:
    """Register an adapter config for lazy instantiation."""
    _adapter_configs[config.system_name] = config


def get_adapter(system_name: str) -> BaseAdapter | None:
    """Get or lazily instantiate an adapter for a system."""
    if system_name in _adapters:
        return _adapters[system_name]

    if system_name in _adapter_configs:
        config = _adapter_configs[system_name]
        adapter = _create_adapter(config)
        if adapter:
            _adapters[system_name] = adapter
            return adapter

    return None


def _create_adapter(config: AdapterConfig) -> BaseAdapter | None:
    """Create an adapter instance from config."""
    from jitauth.proxy.adapters.http import HTTPAdapter
    from jitauth.proxy.adapters.shell import ShellAdapter

    adapter_types = {
        "http": HTTPAdapter,
        "shell": ShellAdapter,
    }

    cls = adapter_types.get(config.adapter_type)
    if cls is None:
        logger.error("Unknown adapter type: %s", config.adapter_type)
        return None

    return cls(config)


def clear_adapters() -> None:
    """Clear all registered adapters. For testing."""
    _adapters.clear()
    _adapter_configs.clear()


# ---------- Gateway Execution ----------


async def execute_tool_call(
    db: Session,
    task_id: str,
    capability_id: str,
    capability_token: str,
    tool: str,
    arguments: dict[str, Any],
    expected_effect: str | None = None,
    idempotency_key: str | None = None,
    runtime_secret: str | None = None,
) -> dict:
    """Execute a tool call through the gateway.

    This is the main entry point for the execution proxy.

    Args:
        db: Database session
        task_id: The task this execution belongs to
        capability_id: The capability authorizing this call
        capability_token: Signed JWT capability token for verification
        tool: Tool identifier (e.g., "crm.read_account")
        arguments: Tool call arguments
        expected_effect: Human-readable description of expected effect
        idempotency_key: Optional dedup key
        runtime_secret: Runtime session secret for caller authentication

    Returns:
        dict with invocation_id, tool, success, result, error

    Raises:
        GatewayError: If the capability is invalid or the call is rejected
    """
    # 0. Verify the capability token (cryptographic proof of issuance)
    from jitauth.core.tokens import TokenError, verify_capability_token

    try:
        token_claims = verify_capability_token(capability_token)
    except TokenError as e:
        raise GatewayError(
            f"Capability token verification failed: {e}",
            f"token_{e.code}",
        ) from e

    # Verify token claims match the request
    if token_claims["sub"] != capability_id:
        raise GatewayError(
            "Token subject does not match capability_id",
            "token_binding_mismatch",
        )
    if token_claims["jitauth:task_id"] != task_id:
        raise GatewayError(
            "Token task_id claim does not match request task_id",
            "token_binding_mismatch",
        )

    # 1. Validate capability in DB (for revocation and call counting)
    cap = db.get(Capability, capability_id)
    if cap is None:
        raise GatewayError("Capability not found", "capability_not_found")

    _validate_capability(cap)

    # 1b. Verify task binding — caller's task_id must match DB
    if cap.task_id != task_id:
        raise GatewayError(
            f"Task '{task_id}' does not own capability '{capability_id}'",
            "task_mismatch",
        )

    # 1b2. Verify runtime authentication (Finding-2 #1)
    # If the task was created with a runtime_secret, the caller must prove
    # possession of the same secret.  This binds execution to the originally
    # authenticated runtime, not just to possession of the capability token.
    from jitauth.core.models import Task
    task_obj = db.get(Task, task_id)
    if task_obj and task_obj.runtime_secret_hash:
        import hashlib
        if not runtime_secret:
            raise GatewayError(
                "This task requires runtime authentication (runtime_secret)",
                "runtime_auth_required",
            )
        caller_hash = hashlib.sha256(runtime_secret.encode()).hexdigest()
        if caller_hash != task_obj.runtime_secret_hash:
            raise GatewayError(
                "Runtime secret does not match the task's registered runtime",
                "runtime_auth_failed",
            )

    # 1c. Verify token runtime claim matches DB capability
    if token_claims["jitauth:runtime_id"] != cap.runtime_id:
        raise GatewayError(
            "Token runtime_id does not match capability runtime",
            "token_binding_mismatch",
        )
    if token_claims["jitauth:target_system"] != cap.target_system:
        raise GatewayError(
            "Token target_system does not match capability",
            "token_binding_mismatch",
        )

    # 2. Parse tool identifier → system + action
    system, action = _parse_tool(tool)

    # 3. Check action is allowed by capability
    allowed_actions = cap.allowed_actions_list
    if action not in allowed_actions:
        raise GatewayError(
            f"Action '{action}' not allowed by capability. Allowed: {allowed_actions}",
            "action_not_allowed",
        )

    # 4. Check target system matches
    if system != cap.target_system:
        raise GatewayError(
            f"System '{system}' does not match capability target '{cap.target_system}'",
            "system_mismatch",
        )

    # 4b. Enforce resource scope
    _enforce_scope(cap, arguments)

    # 5. Get adapter
    adapter = get_adapter(system)
    if adapter is None:
        raise GatewayError(
            f"No adapter registered for system '{system}'",
            "no_adapter",
        )

    # 6. Check idempotency (scoped to task + capability)
    if idempotency_key:
        existing = (
            db.query(ToolInvocation)
            .filter(
                ToolInvocation.task_id == task_id,
                ToolInvocation.capability_id == capability_id,
                ToolInvocation.idempotency_key == idempotency_key,
            )
            .first()
        )
        if existing:
            return {
                "invocation_id": existing.id,
                "tool": tool,
                "success": existing.success,
                "result": parse_json(existing.result_summary),
                "error": existing.error,
            }

    # 7. Increment call count (before execution — fail fast)
    cap.calls_used += 1
    if cap.calls_used > cap.max_calls:
        raise GatewayError(
            f"Call limit exceeded ({cap.max_calls} max)",
            "call_limit_exceeded",
        )

    # 8. Execute via adapter (credentials injected server-side)
    credential = _get_credential_for_system(system)
    adapter_result = await adapter.execute(action, arguments, credential)

    # Collect per-adapter redaction config
    adapter_config = _adapter_configs.get(system)
    extra_redact = adapter_config.redact_keys if adapter_config else set()
    redact_full_result = adapter_config.redact_result if adapter_config else False

    # 9. Record invocation (sanitize both arguments and stored result)
    sanitized_args = _sanitize_for_log(arguments, extra_keys=extra_redact)
    if redact_full_result:
        stored_result = '{"_redacted": true}'
    elif isinstance(adapter_result.result, dict):
        stored_result = json.dumps(_sanitize_for_log(adapter_result.result, extra_keys=extra_redact))
    elif isinstance(adapter_result.result, str):
        stored_result = json.dumps(_sanitize_string(adapter_result.result))
    elif adapter_result.result is not None:
        stored_result = json.dumps(adapter_result.result)
    else:
        stored_result = None

    invocation = ToolInvocation(
        id=new_id(),
        task_id=cap.task_id,
        capability_id=capability_id,
        tool=tool,
        arguments=json.dumps(sanitized_args),
        expected_effect=expected_effect,
        idempotency_key=idempotency_key,
        result_summary=stored_result,
        success=adapter_result.success,
        error=adapter_result.error,
    )
    db.add(invocation)

    # 10. Audit event (hash-chained)
    from jitauth.audit.logger import write_audit_event

    write_audit_event(db, "tool_invoked", f"runtime:{cap.runtime_id}",
                      task_id=cap.task_id, details={
                          "tool": tool,
                          "success": adapter_result.success,
                          "capability_id": capability_id,
                          "calls_used": cap.calls_used,
                          "calls_max": cap.max_calls,
                      })
    db.commit()

    # Sanitize result before returning to runtime (prevent credential leakage)
    if isinstance(adapter_result.result, dict):
        sanitized_result = _sanitize_for_log(adapter_result.result, extra_keys=extra_redact)
    elif isinstance(adapter_result.result, str):
        sanitized_result = _sanitize_string(adapter_result.result)
    else:
        sanitized_result = adapter_result.result

    return {
        "invocation_id": invocation.id,
        "tool": tool,
        "success": adapter_result.success,
        "result": sanitized_result,
        "error": adapter_result.error,
    }


def _validate_capability(cap: Capability) -> None:
    """Validate that a capability is usable right now."""
    if cap.status == CapabilityStatus.revoked:
        raise GatewayError("Capability has been revoked", "capability_revoked")

    if cap.status == CapabilityStatus.expired:
        raise GatewayError("Capability has expired", "capability_expired")

    # Check time-based expiry even if status hasn't been updated yet
    now = datetime.now(timezone.utc)
    if cap.expires_at.tzinfo is None:
        # Handle naive datetimes from SQLite
        from datetime import timezone as tz
        expires = cap.expires_at.replace(tzinfo=tz.utc)
    else:
        expires = cap.expires_at

    if now > expires:
        cap.status = CapabilityStatus.expired
        raise GatewayError("Capability has expired", "capability_expired")

    if cap.status != CapabilityStatus.active:
        raise GatewayError(
            f"Capability is in state '{cap.status}', expected 'active'",
            "capability_inactive",
        )


def _parse_tool(tool: str) -> tuple[str, str]:
    """Parse 'system.action' into (system, action)."""
    parts = tool.split(".", 1)
    if len(parts) != 2:
        raise GatewayError(
            f"Invalid tool format '{tool}'. Expected 'system.action'",
            "invalid_tool_format",
        )
    return parts[0], parts[1]


def _get_credential_for_system(system: str) -> dict | None:
    """Retrieve credentials for a target system.

    In MVP, credentials are stored in the adapter config.
    Future: vault integration, STS federation, etc.
    """
    config = _adapter_configs.get(system)
    if config and config.credentials:
        return config.credentials
    return None


def _enforce_scope(cap: Capability, arguments: dict[str, Any]) -> None:
    """Enforce resource scope constraints on tool call arguments.

    If the capability has a resource_scope, arguments that reference
    resources (by common identifier patterns) must fall within the
    allowed scope. This is the mechanism by which least privilege is
    enforced at execution time — not just at policy evaluation.

    Scope format:
        - JSON list of allowed resource patterns (e.g. ["account:acme_*"])
        - JSON dict with per-field constraints (e.g. {"account_id": ["acme_123"]})
        - None means no scope constraint (all arguments allowed)
    """
    scope = cap.resource_scope_parsed
    if scope is None:
        return

    if isinstance(scope, dict):
        # Dict scope: keys map to lists of allowed values
        for field_name, allowed_values in scope.items():
            if field_name in arguments:
                arg_val = str(arguments[field_name])
                if isinstance(allowed_values, list):
                    if arg_val not in [str(v) for v in allowed_values]:
                        raise GatewayError(
                            f"Argument '{field_name}' value '{arg_val}' "
                            f"not in allowed scope: {allowed_values}",
                            "scope_violation",
                        )
                elif isinstance(allowed_values, str):
                    if arg_val != allowed_values:
                        raise GatewayError(
                            f"Argument '{field_name}' value '{arg_val}' "
                            f"does not match scope: {allowed_values}",
                            "scope_violation",
                        )

    elif isinstance(scope, list):
        # List scope: check common resource-identifying argument keys
        resource_keys = {
            "account_id", "contact_id", "calendar_id", "resource_id",
            "user_id", "org_id", "project_id", "id",
        }
        for key in resource_keys:
            if key in arguments:
                arg_val = str(arguments[key])
                matched = any(
                    arg_val == str(s) or (
                        isinstance(s, str) and s.endswith("*")
                        and arg_val.startswith(s[:-1])
                    )
                    for s in scope
                )
                if not matched:
                    raise GatewayError(
                        f"Resource '{key}={arg_val}' not in "
                        f"allowed scope: {scope}",
                        "scope_violation",
                    )


_DEFAULT_SENSITIVE_KEYS = frozenset({
    "password", "secret", "token", "api_key", "credential", "key",
    "access_token", "refresh_token", "authorization", "bearer",
})

# Patterns that indicate a value itself contains a secret, regardless of
# the key name.  These are compiled once at module load.  Each pattern is
# tested against string values; a match triggers redaction of the entire
# value (Finding-2 #6).
import re as _re

_SECRET_VALUE_PATTERNS: list[_re.Pattern] = [
    # Bearer / Basic / Token auth headers embedded in values
    _re.compile(r"(?i)\b(?:bearer|basic|token)\s+[A-Za-z0-9_\-\.]{8,}"),
    # AWS-style keys (AKIA...)
    _re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Generic long hex secrets (≥32 hex chars, e.g. API keys)
    _re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    # Generic long base64-ish tokens (≥40 chars, alphanumeric + common token chars)
    _re.compile(r"[A-Za-z0-9_\-]{40,}"),
    # Private key material
    _re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    # Connection strings with passwords
    _re.compile(r"(?i)(?:password|pwd)\s*[:=]\s*\S+"),
]


def _value_looks_secret(value: str) -> bool:
    """Heuristic: return True if a string value appears to contain a secret."""
    return any(pat.search(value) for pat in _SECRET_VALUE_PATTERNS)


def _sanitize_string(value: str) -> str:
    """Sanitize a plain string value (e.g. stdout, HTTP body).

    If the string looks like it contains secret material, redact the
    entire value rather than trying to surgically remove the secret.
    """
    if _value_looks_secret(value):
        return "[REDACTED — potential secret in output]"
    return value


def _sanitize_for_log(data: dict, extra_keys: set[str] | None = None) -> dict:
    """Remove sensitive fields from data before logging or returning to runtime.

    Applies both key-name redaction and value-pattern scanning so that
    secrets echoed in ordinary fields or shell output are caught.

    Args:
        data: Dict to sanitize.
        extra_keys: Additional field names to redact (from per-adapter config).
    """
    sensitive = _DEFAULT_SENSITIVE_KEYS | {k.lower() for k in (extra_keys or set())}
    sanitized = {}
    for k, v in data.items():
        if k.lower() in sensitive:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_for_log(v, extra_keys=extra_keys)
        elif isinstance(v, list):
            sanitized[k] = [
                _sanitize_for_log(item, extra_keys=extra_keys)
                if isinstance(item, dict)
                else (_sanitize_string(item) if isinstance(item, str) else item)
                for item in v
            ]
        elif isinstance(v, str):
            sanitized[k] = _sanitize_string(v)
        else:
            sanitized[k] = v
    return sanitized
