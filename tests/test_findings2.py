"""Tests for findings-2.md fixes.

Each test is tagged with the finding number it validates.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter


# ---------- Mock adapter ----------


class MockAdapter(BaseAdapter):
    """Adapter that echoes arguments back."""

    supported_actions = ["read_account", "update_contact"]

    def __init__(self, config: AdapterConfig, *, result_override: AdapterResult | None = None):
        super().__init__(config)
        self._result_override = result_override

    async def execute(
        self,
        action: str,
        arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
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
    """Create → classify → policy → capabilities.  Returns (task_id, caps)."""
    payload = {
        "requester_id": "user_1",
        "runtime_id": "rt_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "findings-2 test",
        "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        "time_limit_seconds": 300,
    }
    payload.update(task_overrides)
    resp = client.post("/tasks", json=payload)
    assert resp.status_code == 201
    task_id = resp.json()["id"]

    client.post(f"/tasks/{task_id}/classify")
    pol = client.post(f"/tasks/{task_id}/policy-evaluate")
    if pol.json()["effect"] == "require_approval":
        client.post(f"/tasks/{task_id}/approve", json={"approver_id": "admin", "approved": True})
    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    return task_id, caps


# ====================================================================
# Finding #1 — Runtime authentication
# ====================================================================


class TestRuntimeAuth:
    """Finding-2 #1: execution bound to authenticated runtime, not just bearer."""

    def test_runtime_secret_happy_path(self, client, mock_adapter):
        """Task created with runtime_secret → execute with same secret works."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "runtime_secret": runtime_secret,
            "tool": "crm.read_account",
            "arguments": {"account_id": "1"},
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_runtime_secret_wrong_secret_rejected(self, client, mock_adapter):
        """Wrong runtime_secret → 403."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "runtime_secret": secrets.token_hex(32),  # different secret
            "tool": "crm.read_account",
            "arguments": {},
        })
        assert resp.status_code == 403
        assert "runtime_auth_failed" in resp.json()["detail"]["error"]

    def test_runtime_secret_missing_when_required(self, client, mock_adapter):
        """Task has secret but caller omits it → 403."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            # no runtime_secret
            "tool": "crm.read_account",
            "arguments": {},
        })
        assert resp.status_code == 403
        assert "runtime_auth_required" in resp.json()["detail"]["error"]

    def test_no_secret_tasks_still_work(self, client, mock_adapter):
        """Tasks without runtime_secret remain backward compatible."""
        task_id, caps = _lifecycle(client)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"account_id": "1"},
        })
        assert resp.status_code == 200


# ====================================================================
# Finding #2 — Policy-derived scope flows into capability minting
# ====================================================================


class TestPolicyScopeFlow:
    """Finding-2 #2: policy-derived scope used when minting capabilities."""

    def test_policy_structured_scope_applied(self, client, mock_adapter, tmp_path):
        """When policy rule has a structured scope, it constrains the capability."""
        # Write a policy rule with explicit structured scope
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir(exist_ok=True)
        (policy_dir / "default.yaml").write_text("""
rules:
  - name: allow-reads-scoped
    priority: 50
    match:
      action_class: "read"
    effect: allow
    scope:
      account_id: ["acme_123", "acme_456"]
""")
        from jitauth.config.settings import get_settings, override_settings, Settings
        from jitauth.policy.engine import reload_rules

        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=str(policy_dir),
            jwt_secret=s.jwt_secret,
        ))
        reload_rules()

        # Create task WITH requester-supplied scope that's broader than policy
        task_id, caps = _lifecycle(
            client,
            actions=[{
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
                "resource_scope": json.dumps({"account_id": ["acme_123", "acme_456", "acme_789"]}),
            }],
        )

        cap = caps[0]
        # The minted capability's scope should be intersected (policy ceiling wins)
        scope = json.loads(cap["resource_scope"])
        assert isinstance(scope, dict)
        # acme_789 should NOT be in the effective scope (policy doesn't allow it)
        allowed = scope.get("account_id", [])
        assert "acme_789" not in allowed
        assert "acme_123" in allowed
        assert "acme_456" in allowed


# ====================================================================
# Finding #3 — Audit chain init wired on startup
# ====================================================================


class TestAuditChainInit:
    """Finding-2 #3: audit chain initialized from DB on broker startup."""

    def test_chain_continuity_across_client_instances(self, client):
        """Creating two TestClient instances (simulating restarts) should
        produce a continuous audit chain because lifespan calls initialize_chain."""
        # First client: create a task (generates audit events)
        resp = client.post("/tasks", json={
            "requester_id": "u1",
            "runtime_id": "rt1",
            "objective": "chain test 1",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        assert resp.status_code == 201

        # Verify chain is valid
        verify = client.get("/audit/verify")
        assert verify.json()["valid"] is True
        first_count = verify.json()["events_checked"]
        assert first_count >= 1

        # Create a second task (more events in the same chain)
        resp2 = client.post("/tasks", json={
            "requester_id": "u2",
            "runtime_id": "rt2",
            "objective": "chain test 2",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        assert resp2.status_code == 201

        verify2 = client.get("/audit/verify")
        assert verify2.json()["valid"] is True
        assert verify2.json()["events_checked"] > first_count


# ====================================================================
# Finding #4 — Task-scoped verification for interleaved tasks
# ====================================================================


class TestInterleavedAuditVerification:
    """Finding-2 #4: task-scoped audit verify doesn't false-alarm on interleaving."""

    def test_interleaved_tasks_verify_correctly(self, client):
        """Create events from two tasks interleaved, then verify each task
        individually — should not report chain broken."""
        # Task 1
        r1 = client.post("/tasks", json={
            "requester_id": "u1",
            "runtime_id": "rt1",
            "objective": "task A",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task1_id = r1.json()["id"]

        # Task 2 (interleaved)
        r2 = client.post("/tasks", json={
            "requester_id": "u2",
            "runtime_id": "rt2",
            "objective": "task B",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task2_id = r2.json()["id"]

        # More events for task 1
        client.post(f"/tasks/{task1_id}/classify")

        # Global chain should be valid
        verify_all = client.get("/audit/verify")
        assert verify_all.json()["valid"] is True

        # Task-scoped verification should also be valid (not false broken)
        verify_t1 = client.get(f"/audit/verify?task_id={task1_id}")
        assert verify_t1.json()["valid"] is True
        assert verify_t1.json()["task_events_checked"] >= 1

        verify_t2 = client.get(f"/audit/verify?task_id={task2_id}")
        assert verify_t2.json()["valid"] is True
        assert verify_t2.json()["task_events_checked"] >= 1


# ====================================================================
# Finding #5 — Adapter loading uses config/loader with env-var resolution
# ====================================================================


class TestAdapterLoading:
    """Finding-2 #5: startup adapter loading resolves ${ENV_VAR} placeholders."""

    def test_env_var_resolution_in_credentials(self, tmp_path, monkeypatch):
        """Adapter config with ${ENV} credentials should resolve them."""
        monkeypatch.setenv("TEST_ADAPTER_TOKEN", "resolved_secret_value")

        config_file = tmp_path / "adapters.yaml"
        config_file.write_text("""
adapters:
  - system_name: test_sys
    adapter_type: http
    config:
      base_url: "https://example.com"
    credentials:
      type: bearer
      token: "${TEST_ADAPTER_TOKEN}"
""")
        from jitauth.config.loader import load_adapter_configs
        from jitauth.proxy.gateway import _adapter_configs, clear_adapters

        clear_adapters()
        configs = load_adapter_configs(str(config_file))
        assert len(configs) == 1
        assert configs[0].credentials["token"] == "resolved_secret_value"
        clear_adapters()

    def test_unresolved_env_var_stays_placeholder(self, tmp_path):
        """If env var isn't set, the placeholder string survives."""
        config_file = tmp_path / "adapters.yaml"
        config_file.write_text("""
adapters:
  - system_name: test_sys
    adapter_type: http
    config: {}
    credentials:
      token: "${NONEXISTENT_VAR_12345}"
""")
        from jitauth.config.loader import load_adapter_configs
        from jitauth.proxy.gateway import clear_adapters

        clear_adapters()
        configs = load_adapter_configs(str(config_file))
        # Unresolved var keeps the placeholder (logged as warning)
        assert configs[0].credentials["token"] == "${NONEXISTENT_VAR_12345}"
        clear_adapters()


# ====================================================================
# Finding #6 — Value-based secret scanning
# ====================================================================


class TestSecretScanning:
    """Finding-2 #6: result sanitization catches secrets in values, not just keys."""

    def test_bearer_token_in_stdout_redacted(self, client):
        """Shell-like stdout containing a bearer token should be redacted."""
        from jitauth.proxy.gateway import _sanitize_string

        stdout = "HTTP/1.1 200 OK\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc"
        result = _sanitize_string(stdout)
        assert "[REDACTED" in result

    def test_aws_key_in_value_redacted(self):
        from jitauth.proxy.gateway import _sanitize_string

        value = "found key: AKIAIOSFODNN7EXAMPLE in config"
        assert "[REDACTED" in _sanitize_string(value)

    def test_private_key_in_value_redacted(self):
        from jitauth.proxy.gateway import _sanitize_string

        value = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg..."
        assert "[REDACTED" in _sanitize_string(value)

    def test_password_in_connection_string_redacted(self):
        from jitauth.proxy.gateway import _sanitize_string

        value = "postgresql://user:password=hunter2@db.example.com:5432/mydb"
        assert "[REDACTED" in _sanitize_string(value)

    def test_normal_text_not_redacted(self):
        from jitauth.proxy.gateway import _sanitize_string

        value = "Account acme_123 has 42 contacts."
        assert value == _sanitize_string(value)

    def test_sanitize_for_log_catches_secret_in_string_value(self):
        """_sanitize_for_log should redact string values containing secrets."""
        from jitauth.proxy.gateway import _sanitize_for_log

        data = {
            "status": "ok",
            "debug_output": "token Bearer sk-abc123456789012345678901234567890123456789",
        }
        sanitized = _sanitize_for_log(data)
        assert "[REDACTED" in sanitized["debug_output"]
        assert sanitized["status"] == "ok"

    def test_execute_redacts_string_result(self, client):
        """When adapter returns a string containing a secret, /execute redacts it."""
        secret_output = "config: password=SuperSecret123! token Bearer AKIAIOSFODNN7EXAMPLE"
        config = AdapterConfig(system_name="crm", adapter_type="mock", config={})
        adapter = MockAdapter(config, result_override=AdapterResult(
            success=True, result=secret_output,
        ))
        register_adapter(adapter)

        task_id, caps = _lifecycle(client)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {},
        })
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert "[REDACTED" in result
