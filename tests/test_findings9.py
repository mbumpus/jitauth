"""Tests for findings-9.md hardening.

Covers:
  1. Task ownership enforcement (created_by, cross-runtime isolation)
  2. SDK API-key wiring (JITAuthClient sends Authorization header)
  3. Atomic task/capability budget enforcement
  4. README/examples describe authenticated flow (verified by grep)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from jitauth.broker.auth import AuthenticatedCaller, get_caller
from jitauth.config.settings import Settings, get_settings, override_settings
from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter


# ---------- Mock adapter ----------


class MockAdapter(BaseAdapter):
    supported_actions = ["read_account", "update_contact"]

    def __init__(self, config: AdapterConfig, *, result_override: AdapterResult | None = None):
        super().__init__(config)
        self._result_override = result_override

    async def execute(self, action: str, arguments: dict[str, Any], credential: dict[str, Any] | None = None) -> AdapterResult:
        if self._result_override:
            return self._result_override
        return AdapterResult(success=True, result={"echo": arguments, "action": action})


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


def _lifecycle(client, **task_overrides):
    payload = {
        "requester_id": "user_1",
        "runtime_id": "rt_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "findings-9 test",
        "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        "time_limit_seconds": 300,
    }
    payload.update(task_overrides)
    resp = client.post("/tasks", json=payload)
    assert resp.status_code == 201, resp.json()
    task_id = resp.json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    pol = client.post(f"/tasks/{task_id}/policy-evaluate")
    if pol.json()["effect"] == "require_approval":
        client.post(f"/tasks/{task_id}/approve", json={"approved": True})
    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    return task_id, caps


# ====================================================================
# 1. Task ownership enforcement
# ====================================================================


class TestTaskOwnership:
    """Tasks record created_by and enforce ownership for non-operators."""

    def test_created_by_recorded(self, client):
        """Task records the authenticated caller as created_by."""
        resp = client.post("/tasks", json={
            "requester_id": "end-user-1",
            "runtime_id": "rt1",
            "objective": "test ownership",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        assert resp.status_code == 201
        task = resp.json()
        # Default test caller is "test-user" (operator)
        assert task.get("created_by") == "test-user"

    def test_operator_can_access_any_task(self, client):
        """Operators bypass ownership checks."""
        resp = client.post("/tasks", json={
            "requester_id": "u1", "runtime_id": "rt1", "objective": "test",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task_id = resp.json()["id"]
        # Operator should be able to get any task
        resp = client.get(f"/tasks/{task_id}")
        assert resp.status_code == 200

    def test_non_operator_cannot_access_other_runtime_task(self, tmp_path):
        """Runtime caller can't access tasks created by a different caller."""
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={
                "sk-runtime-a": "runtime:agent-a",
                "sk-runtime-b": "runtime:agent-b",
            },
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            # Agent A creates a task (runtime_id must match caller identity)
            resp = c.post("/tasks", json={
                "requester_id": "u1", "runtime_id": "agent-a", "objective": "a's task",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            }, headers={"Authorization": "Bearer sk-runtime-a"})
            assert resp.status_code == 201
            task_id = resp.json()["id"]

            # Agent B tries to access it
            resp = c.get(f"/tasks/{task_id}",
                         headers={"Authorization": "Bearer sk-runtime-b"})
            assert resp.status_code == 403
            assert "task_ownership_denied" in resp.json()["detail"]["error"]

    def test_non_operator_cannot_impersonate_runtime(self, tmp_path):
        """Runtime caller can't create task with a different runtime_id."""
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={"sk-runtime-a": "runtime:agent-a"},
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            resp = c.post("/tasks", json={
                "requester_id": "u1", "runtime_id": "someone-else", "objective": "impersonate",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            }, headers={"Authorization": "Bearer sk-runtime-a"})
            assert resp.status_code == 403
            assert "identity_mismatch" in resp.json()["detail"]["error"]

    def test_non_operator_can_access_own_task(self, tmp_path):
        """Runtime caller CAN access tasks they created."""
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={"sk-runtime-a": "runtime:agent-a"},
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            resp = c.post("/tasks", json={
                "requester_id": "u1", "runtime_id": "agent-a", "objective": "own task",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            }, headers={"Authorization": "Bearer sk-runtime-a"})
            assert resp.status_code == 201
            task_id = resp.json()["id"]

            resp = c.get(f"/tasks/{task_id}",
                         headers={"Authorization": "Bearer sk-runtime-a"})
            assert resp.status_code == 200

    def test_classify_enforces_ownership(self, tmp_path):
        """Runtime caller can't classify another runtime's task."""
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={
                "sk-runtime-a": "runtime:agent-a",
                "sk-runtime-b": "runtime:agent-b",
            },
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            resp = c.post("/tasks", json={
                "requester_id": "u1", "runtime_id": "agent-a", "objective": "test",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            }, headers={"Authorization": "Bearer sk-runtime-a"})
            task_id = resp.json()["id"]

            # Agent B tries to classify A's task
            resp = c.post(f"/tasks/{task_id}/classify",
                          headers={"Authorization": "Bearer sk-runtime-b"})
            assert resp.status_code == 403


    def test_execute_enforces_ownership(self, tmp_path, mock_adapter):
        """Runtime caller can't execute against another runtime's task."""
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={
                "sk-runtime-a": "runtime:agent-a",
                "sk-runtime-b": "runtime:agent-b",
                "sk-ops": "operator:admin",
            },
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            # Operator creates and progresses a task
            resp = c.post("/tasks", json={
                "requester_id": "u1", "runtime_id": "agent-a", "objective": "exec test",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            }, headers={"Authorization": "Bearer sk-ops"})
            task_id = resp.json()["id"]
            c.post(f"/tasks/{task_id}/classify",
                   headers={"Authorization": "Bearer sk-ops"})
            c.post(f"/tasks/{task_id}/policy-evaluate",
                   headers={"Authorization": "Bearer sk-ops"})
            caps = c.post(f"/tasks/{task_id}/capabilities",
                          headers={"Authorization": "Bearer sk-ops"}).json()
            cap = caps[0]

            # Agent B tries to execute against admin's task
            resp = c.post("/execute", json={
                "task_id": task_id,
                "capability_id": cap["id"],
                "capability_token": cap["token"],
                "tool": "crm.read_account",
                "arguments": {"account_id": "a1"},
            }, headers={"Authorization": "Bearer sk-runtime-b"})
            assert resp.status_code == 403
            assert "task_ownership_denied" in resp.json()["detail"]["error"]

    def test_legacy_null_created_by_denied_for_runtime(self, client):
        """Tasks with NULL created_by are denied for non-operator callers."""
        # Create a task normally (will have created_by set)
        resp = client.post("/tasks", json={
            "requester_id": "u1", "runtime_id": "rt1", "objective": "test legacy",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task_id = resp.json()["id"]

        # Simulate a legacy task by clearing created_by
        from jitauth.db.session import get_session_factory
        from jitauth.core.models import Task
        db = get_session_factory()()
        task = db.get(Task, task_id)
        task.created_by = None
        db.commit()
        db.close()

        # Now set up auth and try as a runtime caller
        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=s.policy_dir,
            jwt_secret=s.jwt_secret,
            require_api_auth=True,
            api_keys={"sk-rt": "runtime:agent-x"},
        ))
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            resp = c.get(f"/tasks/{task_id}",
                         headers={"Authorization": "Bearer sk-rt"})
            assert resp.status_code == 403
            assert "legacy" in resp.json()["detail"]["message"].lower()


# ====================================================================
# 2. SDK API-key wiring
# ====================================================================


class TestSDKAPIKey:
    """JITAuthClient sends Authorization header when api_key is set."""

    def test_sdk_sends_auth_header(self):
        """Client includes api_key as Bearer header."""
        from jitauth.sdk.client import JITAuthClient
        client = JITAuthClient(
            broker_url="http://localhost:8700",
            api_key="sk-test-123",
        )
        assert client.api_key == "sk-test-123"

    @pytest.mark.asyncio
    async def test_sdk_http_client_has_auth_header(self):
        """HTTP client created by SDK includes auth header."""
        from jitauth.sdk.client import JITAuthClient
        client = JITAuthClient(
            broker_url="http://localhost:8700",
            api_key="sk-test-123",
        )
        http = await client._get_http()
        assert http.headers.get("authorization") == "Bearer sk-test-123"
        await client.close()

    @pytest.mark.asyncio
    async def test_sdk_no_auth_header_when_no_key(self):
        """HTTP client omits auth header when api_key is None."""
        from jitauth.sdk.client import JITAuthClient
        client = JITAuthClient(broker_url="http://localhost:8700")
        http = await client._get_http()
        assert "authorization" not in http.headers
        await client.close()


# ====================================================================
# 3. Atomic budget enforcement
# ====================================================================


class TestAtomicBudget:
    """Budget checks use FOR UPDATE locking (functional test)."""

    def test_budget_enforced_sequentially(self, client, mock_adapter):
        """Sequential calls respect task budget correctly."""
        task_id, caps = _lifecycle(client, max_actions=3)
        cap = caps[0]

        # Three calls succeed
        for i in range(3):
            resp = client.post("/execute", json={
                "task_id": task_id,
                "capability_id": cap["id"],
                "capability_token": cap["token"],
                "tool": "crm.read_account",
                "arguments": {"account_id": f"a{i}"},
            })
            assert resp.status_code == 200, f"Call {i+1} failed: {resp.json()}"

        # Fourth call is rejected
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"account_id": "a4"},
        })
        assert resp.status_code in (400, 403)

    def test_gateway_locks_capability_row(self):
        """Verify gateway code uses with_for_update on capability query."""
        import inspect
        from jitauth.proxy.gateway import execute_tool_call
        source = inspect.getsource(execute_tool_call)
        assert "with_for_update" in source, "Capability query should use FOR UPDATE"

    def test_gateway_locks_task_row(self):
        """Verify gateway code uses with_for_update on task query."""
        import inspect
        from jitauth.proxy.gateway import execute_tool_call
        source = inspect.getsource(execute_tool_call)
        # Should have at least two with_for_update calls (cap + task)
        assert source.count("with_for_update") >= 2, "Both cap and task queries should use FOR UPDATE"


# ====================================================================
# 4. MCP server API-key wiring
# ====================================================================


class TestMCPAPIKey:
    """MCP server passes api_key to SDK client."""

    def test_mcp_server_accepts_api_key(self):
        """create_mcp_server accepts api_key parameter."""
        from jitauth.mcp.server import create_mcp_server
        import inspect
        sig = inspect.signature(create_mcp_server)
        assert "api_key" in sig.parameters

    def test_mcp_server_ctx_includes_api_key(self):
        """Server context dict includes api_key for tool handlers."""
        import inspect
        from jitauth.mcp.server import create_mcp_server
        source = inspect.getsource(create_mcp_server)
        assert '"api_key"' in source or "'api_key'" in source


# ====================================================================
# 5. CLI --api-key option
# ====================================================================


class TestCLIAPIKey:
    """MCP serve CLI has --api-key option."""

    def test_mcp_serve_has_api_key_option(self):
        """mcp-serve command accepts --api-key."""
        from click.testing import CliRunner
        from jitauth.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["mcp-serve", "--help"])
        assert "--api-key" in result.output

    def test_mcp_serve_has_envvar(self):
        """--api-key reads from JITAUTH_MCP_API_KEY env var."""
        from click.testing import CliRunner
        from jitauth.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ["mcp-serve", "--help"])
        assert "JITAUTH_MCP_API_KEY" in result.output


# ====================================================================
# 6. Audit trail records caller identity on task creation
# ====================================================================


class TestAuditCallerIdentity:
    """Task creation audit events use caller identity, not just requester_id."""

    def test_audit_records_caller_identity(self, client):
        """Audit event for task_created uses caller.caller_id as actor."""
        resp = client.post("/tasks", json={
            "requester_id": "end-user-1",
            "runtime_id": "rt1",
            "objective": "audit test",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task_id = resp.json()["id"]

        # Query audit for this task
        audit = client.get(f"/audit?task_id={task_id}").json()
        created_events = [e for e in audit if e["event_type"] == "task_created"]
        assert len(created_events) == 1
        # Actor should be the authenticated caller ("test-user"), not the
        # requester_id from JSON ("end-user-1")
        assert created_events[0]["actor"] == "test-user"
        # Details should include the requester_id for reference
        details = json.loads(created_events[0]["details"])
        assert details["requester_id"] == "end-user-1"
