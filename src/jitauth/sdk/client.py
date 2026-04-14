"""JITAuth Python SDK.

This is the primary integration surface for agent framework authors.
It wraps the broker's REST API in a clean async context manager interface.

Usage:
    from jitauth.sdk import JITAuthClient

    client = JITAuthClient(broker_url="http://localhost:8700")

    async with client.task(
        requester="user_123",
        objective="Look up client and draft follow-up",
        actions=[
            {"system": "crm", "action": "read_account", "action_class": "read"},
            {"system": "email", "action": "create_draft", "action_class": "write"},
        ],
    ) as task:
        account = await task.execute("crm.read_account", {"account_id": "456"})
        await task.execute("email.create_draft", {"body": "...", "to": "client@co.com"})
        # Capabilities auto-expire on exit
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class JITAuthError(Exception):
    """Base exception for JITAuth SDK errors."""

    def __init__(self, message: str, code: str = "sdk_error", details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details


class TaskDeniedError(JITAuthError):
    """Raised when policy denies the task."""
    pass


class ApprovalRequiredError(JITAuthError):
    """Raised when task requires human approval."""

    def __init__(self, message: str, task_id: str):
        super().__init__(message, code="approval_required")
        self.task_id = task_id


class CapabilityError(JITAuthError):
    """Raised for capability-related failures (revoked, expired, limit exceeded)."""
    pass


class ExecutionError(JITAuthError):
    """Raised when a tool call fails at the adapter level."""
    pass


@dataclass
class TaskHandle:
    """A governed task with minted capabilities.

    Use this to execute tool calls through the broker.
    Created by JITAuthClient.task() context manager.
    """

    task_id: str
    capabilities: list[dict]
    _client: JITAuthClient
    _cap_map: dict[str, str] = field(default_factory=dict, init=False)
    _cap_token_map: dict[str, str] = field(default_factory=dict, init=False)

    def __post_init__(self):
        # Build system → capability_id and system → token lookups
        for cap in self.capabilities:
            system = cap["target_system"]
            self._cap_map[system] = cap["id"]
            self._cap_token_map[system] = cap.get("token", "")

    async def execute(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        expected_effect: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict | str | None:
        """Execute a tool call through the broker.

        Args:
            tool: Tool identifier as "system.action" (e.g., "crm.read_account")
            arguments: Tool call arguments (passed to the adapter)
            expected_effect: Human-readable description of expected effect
            idempotency_key: Optional dedup key for retries

        Returns:
            The result from the adapter (varies by tool)

        Raises:
            CapabilityError: If capability is revoked, expired, or limit exceeded
            ExecutionError: If the tool call itself fails
        """
        system = tool.split(".", 1)[0] if "." in tool else tool
        cap_id = self._cap_map.get(system)
        cap_token = self._cap_token_map.get(system)
        if not cap_id:
            available = list(self._cap_map.keys())
            raise CapabilityError(
                f"No capability for system '{system}'. Available: {available}",
                code="no_capability_for_system",
            )

        payload: dict[str, Any] = {
            "task_id": self.task_id,
            "capability_id": cap_id,
            "capability_token": cap_token,
            "tool": tool,
            "arguments": arguments or {},
        }
        if expected_effect:
            payload["expected_effect"] = expected_effect
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key

        resp = await self._client._post("/execute", payload)

        if resp.status_code != 200:
            detail = resp.json().get("detail", {})
            error_code = detail.get("error", "unknown")
            message = detail.get("message", resp.text)

            if "revoked" in error_code or "expired" in error_code or "limit" in error_code:
                raise CapabilityError(message, code=error_code)
            raise ExecutionError(message, code=error_code)

        data = resp.json()
        if not data.get("success"):
            raise ExecutionError(
                data.get("error", "Tool call failed"),
                code="adapter_error",
                details=data,
            )

        return data.get("result")

    @property
    def systems(self) -> list[str]:
        """List of systems this task has capabilities for."""
        return list(self._cap_map.keys())


class JITAuthClient:
    """Client for interacting with a JITAuth broker.

    Usage:
        client = JITAuthClient("http://localhost:8700")

        async with client.task(
            requester="user_123",
            objective="Read CRM data",
            actions=[{"system": "crm", "action": "read", "action_class": "read"}],
        ) as task:
            result = await task.execute("crm.read", {"account_id": "123"})
    """

    def __init__(
        self,
        broker_url: str = "http://localhost:8700",
        runtime_id: str = "sdk_runtime",
        runtime_type: str = "llm_orchestrator",
        runtime_trust_tier: str = "low",
        timeout: float = 30.0,
    ):
        self.broker_url = broker_url.rstrip("/")
        self.runtime_id = runtime_id
        self.runtime_type = runtime_type
        self.runtime_trust_tier = runtime_trust_tier
        self.timeout = timeout
        self._http: httpx.AsyncClient | None = None

    async def _get_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.broker_url,
                timeout=self.timeout,
            )
        return self._http

    async def _post(self, path: str, json: dict) -> httpx.Response:
        http = await self._get_http()
        return await http.post(path, json=json)

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        http = await self._get_http()
        return await http.get(path, params=params)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    @asynccontextmanager
    async def task(
        self,
        requester: str,
        objective: str,
        actions: list[dict[str, str]],
        requester_type: str = "human_user",
        max_actions: int = 10,
        time_limit_seconds: int = 300,
        allow_destructive: bool = False,
        auto_approve: bool = False,
        approver_id: str | None = None,
    ):
        """Create and manage a governed task.

        This context manager handles the full lifecycle:
        1. Create the task
        2. Classify risk
        3. Evaluate policy
        4. Handle approval if needed
        5. Mint capabilities
        6. Yield a TaskHandle for executing tool calls
        7. Capabilities auto-expire on exit

        Args:
            requester: The user ID requesting this task
            objective: Human-readable description of what the task does
            actions: List of dicts with system, action, action_class (and optional scopes)
            requester_type: Type of requester (default "human_user")
            max_actions: Max tool calls allowed (default 10)
            time_limit_seconds: Task TTL in seconds (default 300)
            allow_destructive: Whether to allow destructive actions (default False)
            auto_approve: If True and task requires approval, auto-approve with approver_id
            approver_id: ID to use for auto-approval

        Yields:
            TaskHandle with minted capabilities

        Raises:
            TaskDeniedError: If policy denies the task
            ApprovalRequiredError: If task needs approval and auto_approve is False
            JITAuthError: For other failures
        """
        task_id = None
        try:
            # 1. Create task
            resp = await self._post("/tasks", {
                "requester_type": requester_type,
                "requester_id": requester,
                "runtime_id": self.runtime_id,
                "runtime_type": self.runtime_type,
                "runtime_trust_tier": self.runtime_trust_tier,
                "objective": objective,
                "actions": actions,
                "max_actions": max_actions,
                "time_limit_seconds": time_limit_seconds,
                "allow_destructive": allow_destructive,
            })
            if resp.status_code != 201:
                raise JITAuthError(f"Failed to create task: {resp.text}", code="create_failed")

            task_data = resp.json()
            task_id = task_data["id"]
            logger.info("Created task %s: %s", task_id, objective)

            # 2. Classify
            resp = await self._post(f"/tasks/{task_id}/classify", {})
            if resp.status_code != 200:
                raise JITAuthError(f"Classification failed: {resp.text}", code="classify_failed")

            classify_data = resp.json()
            logger.info("Task %s classified as %s", task_id, classify_data["risk_tier"])

            # 3. Evaluate policy
            resp = await self._post(f"/tasks/{task_id}/policy-evaluate", {})
            if resp.status_code != 200:
                raise JITAuthError(f"Policy evaluation failed: {resp.text}", code="policy_failed")

            policy_data = resp.json()
            effect = policy_data["effect"]
            logger.info("Task %s policy: %s (%s)", task_id, effect, policy_data.get("reason"))

            # 4. Handle policy decision
            if effect == "deny":
                raise TaskDeniedError(
                    f"Task denied by policy rule '{policy_data['rule_name']}': "
                    f"{policy_data.get('reason', 'no reason given')}",
                    code="policy_denied",
                )

            if effect == "require_approval":
                if auto_approve and approver_id:
                    resp = await self._post(f"/tasks/{task_id}/approve", {
                        "approver_id": approver_id,
                        "approved": True,
                        "reason": "Auto-approved by SDK",
                    })
                    if resp.status_code != 200:
                        raise JITAuthError(
                            f"Auto-approval failed: {resp.text}", code="approval_failed"
                        )
                    logger.info("Task %s auto-approved by %s", task_id, approver_id)
                else:
                    raise ApprovalRequiredError(
                        f"Task requires approval (rule: {policy_data['rule_name']}). "
                        f"Approve via POST /tasks/{task_id}/approve",
                        task_id=task_id,
                    )

            # 5. Mint capabilities
            resp = await self._post(f"/tasks/{task_id}/capabilities", {})
            if resp.status_code != 200:
                raise JITAuthError(
                    f"Capability minting failed: {resp.text}", code="capability_failed"
                )

            capabilities = resp.json()
            logger.info(
                "Task %s: minted %d capabilities", task_id, len(capabilities)
            )

            # 6. Yield task handle
            handle = TaskHandle(
                task_id=task_id,
                capabilities=capabilities,
                _client=self,
            )
            yield handle

        except (TaskDeniedError, ApprovalRequiredError):
            raise
        except JITAuthError:
            raise
        except Exception as e:
            raise JITAuthError(f"Unexpected error: {e}", code="unexpected") from e

    async def health(self) -> dict:
        """Check broker health."""
        resp = await self._get("/health")
        return resp.json()

    async def get_task(self, task_id: str) -> dict:
        """Get task details."""
        resp = await self._get(f"/tasks/{task_id}")
        if resp.status_code != 200:
            raise JITAuthError(f"Task not found: {task_id}", code="not_found")
        return resp.json()

    async def approve_task(
        self,
        task_id: str,
        approver_id: str,
        approved: bool = True,
        reason: str | None = None,
    ) -> dict:
        """Approve or deny a task that's pending approval."""
        resp = await self._post(f"/tasks/{task_id}/approve", {
            "approver_id": approver_id,
            "approved": approved,
            "reason": reason,
        })
        if resp.status_code != 200:
            raise JITAuthError(f"Approval failed: {resp.text}", code="approval_failed")
        return resp.json()

    async def revoke_capability(
        self,
        capability_id: str,
        reason: str,
        revoked_by: str,
    ) -> dict:
        """Revoke an active capability."""
        resp = await self._post(f"/capabilities/{capability_id}/revoke", {
            "reason": reason,
            "revoked_by": revoked_by,
        })
        if resp.status_code != 200:
            raise JITAuthError(f"Revocation failed: {resp.text}", code="revoke_failed")
        return resp.json()

    async def get_audit_trail(
        self,
        task_id: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Query the audit trail."""
        params: dict[str, Any] = {"limit": limit}
        if task_id:
            params["task_id"] = task_id
        if event_type:
            params["event_type"] = event_type
        resp = await self._get("/audit", params=params)
        return resp.json()
