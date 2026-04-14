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
from jitauth.core.models import (
    AuditEvent,
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
    capability_id: str,
    tool: str,
    arguments: dict[str, Any],
    expected_effect: str | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """Execute a tool call through the gateway.

    This is the main entry point for the execution proxy.

    Args:
        db: Database session
        capability_id: The capability authorizing this call
        tool: Tool identifier (e.g., "crm.read_account")
        arguments: Tool call arguments
        expected_effect: Human-readable description of expected effect
        idempotency_key: Optional dedup key

    Returns:
        dict with invocation_id, tool, success, result, error

    Raises:
        GatewayError: If the capability is invalid or the call is rejected
    """
    # 1. Validate capability
    cap = db.get(Capability, capability_id)
    if cap is None:
        raise GatewayError("Capability not found", "capability_not_found")

    _validate_capability(cap)

    # 2. Parse tool identifier → system + action
    system, action = _parse_tool(tool)

    # 3. Check action is allowed by capability
    allowed_actions = json.loads(cap.allowed_actions)
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

    # 5. Get adapter
    adapter = get_adapter(system)
    if adapter is None:
        raise GatewayError(
            f"No adapter registered for system '{system}'",
            "no_adapter",
        )

    # 6. Check idempotency
    if idempotency_key:
        existing = (
            db.query(ToolInvocation)
            .filter(ToolInvocation.idempotency_key == idempotency_key)
            .first()
        )
        if existing:
            return {
                "invocation_id": existing.id,
                "tool": tool,
                "success": existing.success,
                "result": json.loads(existing.result_summary) if existing.result_summary else None,
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

    # 9. Record invocation
    invocation = ToolInvocation(
        id=new_id(),
        task_id=cap.task_id,
        capability_id=capability_id,
        tool=tool,
        arguments=json.dumps(_sanitize_for_log(arguments)),
        expected_effect=expected_effect,
        idempotency_key=idempotency_key,
        result_summary=json.dumps(adapter_result.result) if adapter_result.result else None,
        success=adapter_result.success,
        error=adapter_result.error,
    )
    db.add(invocation)

    # 10. Audit event
    audit = AuditEvent(
        id=new_id(),
        task_id=cap.task_id,
        event_type="tool_invoked",
        actor=f"runtime:{cap.runtime_id}",
        details=json.dumps({
            "tool": tool,
            "success": adapter_result.success,
            "capability_id": capability_id,
            "calls_used": cap.calls_used,
            "calls_max": cap.max_calls,
        }),
    )
    db.add(audit)
    db.commit()

    return {
        "invocation_id": invocation.id,
        "tool": tool,
        "success": adapter_result.success,
        "result": adapter_result.result,
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


def _sanitize_for_log(data: dict) -> dict:
    """Remove sensitive fields from arguments before logging."""
    sensitive_keys = {"password", "secret", "token", "api_key", "credential", "key"}
    sanitized = {}
    for k, v in data.items():
        if k.lower() in sensitive_keys:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_for_log(v)
        else:
            sanitized[k] = v
    return sanitized
