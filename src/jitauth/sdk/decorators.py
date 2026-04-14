"""Decorators for wrapping tool functions with JITAuth governance.

Usage:
    from jitauth.sdk import JITAuthClient
    from jitauth.sdk.decorators import jitauth_tool

    client = JITAuthClient("http://localhost:8700")

    @jitauth_tool(client, system="crm", action="read_account", action_class="read")
    async def read_account(account_id: str) -> dict:
        # Your existing tool implementation
        return await crm_api.get_account(account_id)

    # When called, this will:
    # 1. Create a task
    # 2. Evaluate policy
    # 3. Mint capability
    # 4. Execute through broker (if adapter registered) or locally (if passthrough)
    # 5. Log to audit trail
    result = await read_account("user_123", account_id="456")
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from jitauth.sdk.client import JITAuthClient

logger = logging.getLogger(__name__)


def jitauth_tool(
    client: JITAuthClient,
    system: str,
    action: str,
    action_class: str = "read",
    resource_scope: str | None = None,
    max_actions: int = 1,
    time_limit_seconds: int = 120,
    auto_approve: bool = False,
    approver_id: str | None = None,
    runtime_secret: str | None = None,
):
    """Decorator that wraps a tool function with JITAuth governance.

    The decorated function gains a required first argument `requester`
    (the user ID requesting this action). All other arguments are
    passed through to the original function.

    Args:
        client: JITAuthClient instance
        system: Target system name
        action: Action name
        action_class: One of read, write, delete, execute, send, publish
        resource_scope: Optional resource scope string
        max_actions: Max calls allowed (default 1 for single-action tools)
        time_limit_seconds: Task TTL
        auto_approve: Auto-approve if policy requires it
        approver_id: Approver ID for auto-approval
        runtime_secret: Session secret for runtime authentication
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(requester: str, **kwargs: Any) -> Any:
            action_def: dict[str, Any] = {
                "system": system,
                "action": action,
                "action_class": action_class,
            }
            if resource_scope:
                action_def["resource_scope"] = resource_scope

            async with client.task(
                requester=requester,
                objective=f"{action} on {system} via {func.__name__}",
                actions=[action_def],
                max_actions=max_actions,
                time_limit_seconds=time_limit_seconds,
                auto_approve=auto_approve,
                approver_id=approver_id,
                runtime_secret=runtime_secret,
            ) as task:
                # Execute through the broker — capability enforcement,
                # credential injection, and audit all happen server-side
                result = await task.execute(
                    f"{system}.{action}",
                    arguments=kwargs,
                    expected_effect=f"{func.__name__}({', '.join(f'{k}={v!r}' for k, v in kwargs.items())})",
                )
                logger.info(
                    "Governed call %s.%s completed for task %s",
                    system,
                    action,
                    task.task_id,
                )
                return result

        # Attach metadata for introspection
        wrapper._jitauth_system = system
        wrapper._jitauth_action = action
        wrapper._jitauth_action_class = action_class
        return wrapper

    return decorator
