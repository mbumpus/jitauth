"""Tests for the JITAuth Python SDK.

These test the SDK client against a real broker via httpx's ASGITransport,
so we get genuine end-to-end coverage without needing a running server.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from jitauth.broker.server import create_app
from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter
from jitauth.sdk.client import (
    ApprovalRequiredError,
    CapabilityError,
    ExecutionError,
    JITAuthClient,
    TaskDeniedError,
)


class EchoAdapter(BaseAdapter):
    """Test adapter that echoes back arguments."""
    supported_actions = ["read_account", "create_draft", "send_email"]

    async def execute(self, action, arguments, credential=None):
        return AdapterResult(success=True, result={"echoed": arguments, "action": action})


class FailingAdapter(BaseAdapter):
    """Test adapter that always fails."""
    supported_actions = ["fail_action"]

    async def execute(self, action, arguments, credential=None):
        return AdapterResult(success=False, error="Simulated adapter failure")


@pytest.fixture(autouse=True)
def _clean():
    clear_adapters()
    yield
    clear_adapters()


@pytest.fixture
def echo_adapter():
    config = AdapterConfig(system_name="crm", adapter_type="mock", config={})
    adapter = EchoAdapter(config)
    register_adapter(adapter)
    return adapter


@pytest.fixture
def email_adapter():
    config = AdapterConfig(system_name="email", adapter_type="mock", config={})
    adapter = EchoAdapter(config)
    register_adapter(adapter)
    return adapter


@pytest.fixture
async def sdk_client():
    """SDK client wired to the test app via ASGI transport."""
    from jitauth.db.session import init_db

    app = create_app()
    init_db()  # ASGI transport doesn't trigger lifespan
    transport = httpx.ASGITransport(app=app)
    async_client = httpx.AsyncClient(transport=transport, base_url="http://test")

    client = JITAuthClient(broker_url="http://test")
    client._http = async_client

    yield client

    await async_client.aclose()


# ---------- Happy path ----------


@pytest.mark.asyncio
async def test_sdk_happy_path(sdk_client, echo_adapter):
    """Full SDK lifecycle: create task → execute → get result."""
    async with sdk_client.task(
        requester="user_123",
        objective="Read CRM account",
        actions=[{"system": "crm", "action": "read_account", "action_class": "read"}],
    ) as task:
        assert task.task_id is not None
        assert "crm" in task.systems

        result = await task.execute("crm.read_account", {"account_id": "456"})
        assert result["echoed"]["account_id"] == "456"
        assert result["action"] == "read_account"


@pytest.mark.asyncio
async def test_sdk_multi_system(sdk_client, echo_adapter, email_adapter):
    """Task spanning multiple systems gets capabilities for each."""
    async with sdk_client.task(
        requester="user_123",
        objective="Read CRM and draft email",
        actions=[
            {"system": "crm", "action": "read_account", "action_class": "read"},
            {"system": "email", "action": "create_draft", "action_class": "write"},
        ],
    ) as task:
        assert "crm" in task.systems
        assert "email" in task.systems

        crm_result = await task.execute("crm.read_account", {"account_id": "123"})
        assert crm_result["action"] == "read_account"

        email_result = await task.execute("email.create_draft", {"body": "Hello"})
        assert email_result["action"] == "create_draft"


# ---------- Policy enforcement ----------


@pytest.mark.asyncio
async def test_sdk_denied_task(sdk_client):
    """Destructive task should be denied by policy."""
    with pytest.raises(TaskDeniedError) as exc_info:
        async with sdk_client.task(
            requester="user_123",
            objective="Delete everything",
            actions=[{"system": "db", "action": "drop_table", "action_class": "delete"}],
        ) as task:
            pass  # Should never get here

    assert "denied" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_sdk_approval_required(sdk_client, email_adapter):
    """Send action should raise ApprovalRequiredError."""
    with pytest.raises(ApprovalRequiredError) as exc_info:
        async with sdk_client.task(
            requester="user_123",
            objective="Send external email",
            actions=[{"system": "email", "action": "send_email", "action_class": "send"}],
        ) as task:
            pass

    assert exc_info.value.task_id is not None


@pytest.mark.asyncio
async def test_sdk_auto_approve(sdk_client, email_adapter):
    """Auto-approve should work for tasks requiring approval."""
    async with sdk_client.task(
        requester="user_123",
        objective="Send email with auto-approve",
        actions=[{"system": "email", "action": "send_email", "action_class": "send"}],
        auto_approve=True,
        approver_id="admin_bot",
    ) as task:
        result = await task.execute("email.send_email", {"to": "test@example.com"})
        assert result["action"] == "send_email"


# ---------- Capability enforcement via SDK ----------


@pytest.mark.asyncio
async def test_sdk_wrong_system(sdk_client, echo_adapter):
    """Executing against a system not in the task should fail."""
    async with sdk_client.task(
        requester="user_123",
        objective="CRM only",
        actions=[{"system": "crm", "action": "read_account", "action_class": "read"}],
    ) as task:
        with pytest.raises(CapabilityError) as exc_info:
            await task.execute("email.send_email", {})

        assert "no capability" in str(exc_info.value).lower()


# ---------- Health and utility ----------


@pytest.mark.asyncio
async def test_sdk_health(sdk_client):
    """Health check via SDK."""
    health = await sdk_client.health()
    assert health["status"] == "ok"
    assert health["service"] == "jitauth-broker"


@pytest.mark.asyncio
async def test_sdk_audit_trail(sdk_client, echo_adapter):
    """SDK should be able to query audit trail."""
    async with sdk_client.task(
        requester="user_123",
        objective="Auditable task",
        actions=[{"system": "crm", "action": "read_account", "action_class": "read"}],
    ) as task:
        await task.execute("crm.read_account", {"account_id": "999"})

        trail = await sdk_client.get_audit_trail(task_id=task.task_id)
        event_types = [e["event_type"] for e in trail]
        assert "task_created" in event_types
        assert "tool_invoked" in event_types
