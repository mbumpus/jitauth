"""Tests for the execution proxy: gateway, adapters, capability enforcement."""

from __future__ import annotations

from typing import Any

import pytest

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter, register_adapter_config


# ---------- Mock adapter for testing ----------


class MockAdapter(BaseAdapter):
    """A simple adapter that echoes back arguments."""

    supported_actions = ["read_account", "update_contact", "send_email"]

    def __init__(self, config: AdapterConfig):
        super().__init__(config)
        self.call_log: list[dict] = []

    async def execute(
        self,
        action: str,
        arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
        self.call_log.append({"action": action, "arguments": arguments})
        return AdapterResult(
            success=True,
            result={"echo": arguments, "action": action},
        )


@pytest.fixture(autouse=True)
def _clean_adapters():
    clear_adapters()
    yield
    clear_adapters()


@pytest.fixture
def mock_adapter():
    config = AdapterConfig(system_name="crm", adapter_type="mock", config={})
    adapter = MockAdapter(config)
    register_adapter(adapter)
    return adapter


def _create_and_approve_task(client, system="crm", action="read_account", action_class="read"):
    """Helper: create task, classify, evaluate policy, mint capabilities."""
    resp = client.post("/tasks", json={
        "requester_id": "user_123",
        "runtime_id": "agent_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "Test proxy execution",
        "actions": [{"system": system, "action": action, "action_class": action_class}],
        "time_limit_seconds": 300,
    })
    task_id = resp.json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    policy_resp = client.post(f"/tasks/{task_id}/policy-evaluate")

    # If requires approval, approve it
    if policy_resp.json()["effect"] == "require_approval":
        client.post(f"/tasks/{task_id}/approve", json={
            "approver_id": "admin",
            "approved": True,
        })

    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    return task_id, caps


# ---------- Happy path ----------


def test_execute_happy_path(client, mock_adapter):
    """Full lifecycle: create task → policy → capability → execute tool call."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {"account_id": "456"},
        "capability_token": cap_token,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["result"]["echo"]["account_id"] == "456"
    assert data["result"]["action"] == "read_account"

    # Adapter should have been called
    assert len(mock_adapter.call_log) == 1


def test_execute_with_expected_effect(client, mock_adapter):
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {"account_id": "456"},
        "expected_effect": "Read account details for client 456",
        "capability_token": cap_token,
    })
    assert resp.status_code == 200


# ---------- Capability enforcement ----------


def test_execute_wrong_action(client, mock_adapter):
    """Action not in capability's allowed list should be rejected."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.delete_account",  # Not in allowed actions
        "arguments": {},
        "capability_token": cap_token,
    })
    assert resp.status_code in (400, 403)
    assert "not allowed" in resp.json()["detail"]["message"].lower()


def test_execute_wrong_system(client, mock_adapter):
    """Targeting wrong system should be rejected."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "email.send_email",  # Wrong system
        "arguments": {},
        "capability_token": cap_token,
    })
    assert resp.status_code in (400, 403)


def test_execute_task_id_mismatch(client, mock_adapter):
    """Capability used with wrong task_id should be rejected."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": "wrong_task_id",
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {},
        "capability_token": cap_token,
    })
    # Task ownership check (404 for non-existent task) or token mismatch (403)
    assert resp.status_code in (403, 404)


def test_execute_invalid_capability(client, mock_adapter):
    """Non-existent capability should fail."""
    resp = client.post("/execute", json={
        "task_id": "fake",
        "capability_id": "nonexistent",
        "tool": "crm.read_account",
        "arguments": {},
        "capability_token": "fake.token.value",
    })
    # Task lookup (404), fake token (400/403) — any rejection is correct
    assert resp.status_code in (400, 403, 404)


def test_execute_revoked_capability(client, mock_adapter):
    """Revoked capability should be rejected."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    # Revoke it
    client.post(f"/capabilities/{cap_id}/revoke", json={
        "reason": "Testing revocation enforcement",
        "revoked_by": "admin",
    })

    # Try to execute
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {},
        "capability_token": cap_token,
    })
    assert resp.status_code == 403
    assert "revoked" in resp.json()["detail"]["message"].lower()


def test_execute_call_limit(client, mock_adapter):
    """Exceeding call limit should be rejected."""
    resp = client.post("/tasks", json={
        "requester_id": "user_123",
        "runtime_id": "agent_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "Limited task",
        "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        "max_actions": 2,  # Only 2 calls allowed
        "time_limit_seconds": 300,
    })
    task_id = resp.json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    client.post(f"/tasks/{task_id}/policy-evaluate")
    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    # First two calls should succeed
    for i in range(2):
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "crm.read_account",
            "arguments": {"call": i},
            "capability_token": cap_token,
        })
        assert resp.status_code == 200

    # Third call should be rejected
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {"call": 3},
        "capability_token": cap_token,
    })
    assert resp.status_code == 400
    assert "limit" in resp.json()["detail"]["message"].lower()


def test_execute_no_adapter(client):
    """System with no registered adapter should fail gracefully."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    # No adapter registered for "crm" (mock_adapter fixture not used)
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {},
        "capability_token": cap_token,
    })
    assert resp.status_code == 400
    assert "no adapter" in resp.json()["detail"]["message"].lower()


def test_execute_invalid_tool_format(client, mock_adapter):
    """Bad tool format should be rejected."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "no_dot_separator",  # Invalid
        "arguments": {},
        "capability_token": cap_token,
    })
    assert resp.status_code == 400


# ---------- Idempotency ----------


def test_idempotency_key(client, mock_adapter):
    """Same idempotency key should return cached result."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    payload = {
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {"account_id": "789"},
        "idempotency_key": "idem_test_001",
        "capability_token": cap_token,
    }

    resp1 = client.post("/execute", json=payload)
    resp2 = client.post("/execute", json=payload)

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json()["invocation_id"] == resp2.json()["invocation_id"]
    # Adapter should only have been called once
    assert len(mock_adapter.call_log) == 1


# ---------- Audit trail for executions ----------


def test_execute_creates_audit_events(client, mock_adapter):
    """Tool execution should produce audit events."""
    task_id, caps = _create_and_approve_task(client)
    cap_id = caps[0]["id"]
    cap_token = caps[0]["token"]

    client.post("/execute", json={
        "task_id": task_id,
        "capability_id": cap_id,
        "tool": "crm.read_account",
        "arguments": {},
        "capability_token": cap_token,
    })

    resp = client.get(f"/audit?task_id={task_id}")
    events = resp.json()
    event_types = [e["event_type"] for e in events]
    assert "tool_invoked" in event_types


# ---------- Scope enforcement ----------


def _create_scoped_task(client, resource_scope):
    """Create a task with a specific resource scope on the action."""
    resp = client.post("/tasks", json={
        "requester_id": "scope_user",
        "runtime_id": "scope_agent",
        "objective": "Scoped test",
        "actions": [{
            "system": "crm",
            "action": "read_account",
            "action_class": "read",
            "resource_scope": resource_scope,
        }],
    })
    task_id = resp.json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    client.post(f"/tasks/{task_id}/policy-evaluate")
    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    return task_id, caps


def test_scope_dict_allows_matching_arg(client, mock_adapter):
    """Dict scope: matching argument value should pass."""
    task_id, caps = _create_scoped_task(
        client, '{"account_id": ["acme_123", "acme_456"]}'
    )
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": caps[0]["id"],
        "capability_token": caps[0]["token"],
        "tool": "crm.read_account",
        "arguments": {"account_id": "acme_123"},
    })
    assert resp.status_code == 200


def test_scope_dict_rejects_non_matching_arg(client, mock_adapter):
    """Dict scope: non-matching argument value should be rejected."""
    task_id, caps = _create_scoped_task(
        client, '{"account_id": ["acme_123"]}'
    )
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": caps[0]["id"],
        "capability_token": caps[0]["token"],
        "tool": "crm.read_account",
        "arguments": {"account_id": "evil_corp_999"},
    })
    assert resp.status_code in (400, 403)
    assert "scope_violation" in resp.json()["detail"]["error"]


def test_scope_list_allows_matching_resource(client, mock_adapter):
    """List scope with wildcard: matching resource should pass."""
    task_id, caps = _create_scoped_task(client, '["acme_*"]')
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": caps[0]["id"],
        "capability_token": caps[0]["token"],
        "tool": "crm.read_account",
        "arguments": {"account_id": "acme_123"},
    })
    assert resp.status_code == 200


def test_scope_list_rejects_non_matching_resource(client, mock_adapter):
    """List scope: non-matching resource should be rejected."""
    task_id, caps = _create_scoped_task(client, '["acme_123"]')
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": caps[0]["id"],
        "capability_token": caps[0]["token"],
        "tool": "crm.read_account",
        "arguments": {"account_id": "evil_corp_999"},
    })
    assert resp.status_code in (400, 403)
    assert "scope_violation" in resp.json()["detail"]["error"]


def test_no_scope_allows_anything(client, mock_adapter):
    """No scope constraint should allow any arguments."""
    task_id, caps = _create_and_approve_task(client)
    resp = client.post("/execute", json={
        "task_id": task_id,
        "capability_id": caps[0]["id"],
        "capability_token": caps[0]["token"],
        "tool": "crm.read_account",
        "arguments": {"account_id": "anything_goes"},
    })
    assert resp.status_code == 200
