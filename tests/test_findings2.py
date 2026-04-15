"""Tests for findings-2.md and findings-3.md fixes.

Each test class is tagged with the finding number it validates.
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
    """Create -> classify -> policy -> capabilities. Returns (task_id, caps)."""
    payload = {
        "requester_id": "user_1",
        "runtime_id": "rt_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "findings test",
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
# Findings-2 #1 / Findings-3 #3 -- Runtime authentication (broker + SDK)
# ====================================================================


class TestRuntimeAuth:
    """Runtime session secret authentication."""

    def test_runtime_secret_happy_path(self, client, mock_adapter):
        """Execute with correct runtime_secret works."""
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

    def test_wrong_secret_rejected(self, client, mock_adapter):
        """Wrong runtime_secret -> 403."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "runtime_secret": secrets.token_hex(32),
            "tool": "crm.read_account",
            "arguments": {},
        })
        assert resp.status_code == 403
        assert "runtime_auth_failed" in resp.json()["detail"]["error"]

    def test_missing_secret_when_required(self, client, mock_adapter):
        """Task has secret but caller omits it -> 403."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {},
        })
        assert resp.status_code == 403
        assert "runtime_auth_required" in resp.json()["detail"]["error"]

    def test_no_secret_backward_compatible(self, client, mock_adapter):
        """Tasks without runtime_secret still work."""
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
# Findings-2 #2 / Findings-3 #1+#2 -- Scope math (monotonic, intersection)
# ====================================================================


class TestScopeMath:
    """Policy scope, requester scope, and approval reduction intersection."""

    def test_intersect_scopes_basic(self):
        from jitauth.broker.routes import _intersect_scopes

        # Both dicts with overlapping lists
        result = _intersect_scopes(
            {"account_id": ["a1", "a2", "a3"]},
            {"account_id": ["a2", "a3", "a4"]},
        )
        assert result == {"account_id": ["a2", "a3"]}

    def test_intersect_scopes_no_overlap_produces_empty(self):
        """No-overlap must produce empty list, not fall back to policy (Finding-3 #2)."""
        from jitauth.broker.routes import _intersect_scopes

        result = _intersect_scopes(
            {"account_id": ["a1"]},
            {"account_id": ["a2"]},
        )
        assert result == {"account_id": []}

    def test_intersect_scopes_none_policy_passes_requester(self):
        from jitauth.broker.routes import _intersect_scopes

        assert _intersect_scopes(None, {"x": [1]}) == {"x": [1]}

    def test_intersect_scopes_none_requester_passes_policy(self):
        from jitauth.broker.routes import _intersect_scopes

        assert _intersect_scopes({"x": [1]}, None) == {"x": [1]}

    def test_intersect_scopes_both_none(self):
        from jitauth.broker.routes import _intersect_scopes

        assert _intersect_scopes(None, None) is None

    def test_intersect_scopes_list_intersection(self):
        from jitauth.broker.routes import _intersect_scopes

        result = _intersect_scopes(["a", "b", "c"], ["b", "c", "d"])
        assert result == ["b", "c"]

    def test_approval_reduction_cannot_widen(self, client, mock_adapter, tmp_path):
        """Approval reduced_scope intersects with effective scope, never widens (Finding-3 #1)."""
        # Policy allowing reads on account_id: a1, a2 only
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
      account_id: ["a1", "a2"]
  - name: require-approval-write
    priority: 40
    match:
      action_class: "write"
    effect: require_approval
    scope:
      account_id: ["a1", "a2"]
""")
        from jitauth.config.settings import Settings, get_settings, override_settings
        from jitauth.policy.engine import reload_rules

        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=str(policy_dir),
            jwt_secret=s.jwt_secret,
            require_api_auth=s.require_api_auth,
        ))
        reload_rules()

        # Create task requiring approval (write)
        resp = client.post("/tasks", json={
            "requester_id": "u1",
            "runtime_id": "rt_01",
            "objective": "write test",
            "actions": [{"system": "crm", "action": "update_contact", "action_class": "write"}],
            "time_limit_seconds": 300,
        })
        task_id = resp.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")

        # Approve with a reduced_scope that tries to WIDEN to a3
        client.post(f"/tasks/{task_id}/approve", json={
            "approver_id": "admin",
            "approved": True,
            "reduced_scope": {"crm": {"account_id": ["a1", "a3"]}},
        })

        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_scope = json.loads(caps[0]["resource_scope"])

        # a3 must NOT appear — approval reduction intersects, doesn't override
        allowed = cap_scope.get("account_id", [])
        assert "a3" not in allowed
        assert "a1" in allowed

    def test_policy_structured_scope_narrows_requester(self, client, mock_adapter, tmp_path):
        """Policy scope ceiling prevents requester from widening (Finding-2 #2)."""
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
      account_id: ["a1", "a2"]
""")
        from jitauth.config.settings import Settings, get_settings, override_settings
        from jitauth.policy.engine import reload_rules

        s = get_settings()
        override_settings(Settings(
            database_url=s.database_url,
            policy_dir=str(policy_dir),
            jwt_secret=s.jwt_secret,
            require_api_auth=s.require_api_auth,
        ))
        reload_rules()

        task_id, caps = _lifecycle(
            client,
            actions=[{
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
                "resource_scope": json.dumps({"account_id": ["a1", "a2", "a9"]}),
            }],
        )
        scope = json.loads(caps[0]["resource_scope"])
        allowed = scope.get("account_id", [])
        assert "a9" not in allowed
        assert "a1" in allowed
        assert "a2" in allowed


# ====================================================================
# Findings-2 #3 -- Audit chain init wired on startup
# ====================================================================


class TestAuditChainInit:
    """Audit chain initialized from DB on broker startup."""

    def test_chain_continuity(self, client):
        """Events across multiple tasks form a valid chain."""
        client.post("/tasks", json={
            "requester_id": "u1", "runtime_id": "rt1", "objective": "chain 1",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        verify = client.get("/audit/verify")
        assert verify.json()["valid"] is True
        first_count = verify.json()["events_checked"]

        client.post("/tasks", json={
            "requester_id": "u2", "runtime_id": "rt2", "objective": "chain 2",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        verify2 = client.get("/audit/verify")
        assert verify2.json()["valid"] is True
        assert verify2.json()["events_checked"] > first_count


# ====================================================================
# Findings-2 #4 -- Task-scoped audit verification (interleaving)
# ====================================================================


class TestInterleavedAudit:
    """Task-scoped audit verify handles interleaved events correctly."""

    def test_interleaved_tasks_both_valid(self, client):
        r1 = client.post("/tasks", json={
            "requester_id": "u1", "runtime_id": "rt1", "objective": "A",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task1_id = r1.json()["id"]

        r2 = client.post("/tasks", json={
            "requester_id": "u2", "runtime_id": "rt2", "objective": "B",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task2_id = r2.json()["id"]

        client.post(f"/tasks/{task1_id}/classify")

        assert client.get("/audit/verify").json()["valid"] is True
        v1 = client.get(f"/audit/verify?task_id={task1_id}").json()
        assert v1["valid"] is True
        assert v1["task_events_checked"] >= 1

        v2 = client.get(f"/audit/verify?task_id={task2_id}").json()
        assert v2["valid"] is True
        assert v2["task_events_checked"] >= 1


# ====================================================================
# Findings-2 #5 -- Adapter loading env-var resolution
# ====================================================================


class TestAdapterLoading:
    """Startup adapter loading resolves ${ENV_VAR} placeholders."""

    def test_env_var_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_TOKEN_F2", "resolved_value")
        config_file = tmp_path / "adapters.yaml"
        config_file.write_text("""
adapters:
  - system_name: test_sys
    adapter_type: http
    config:
      base_url: "https://example.com"
    credentials:
      type: bearer
      token: "${TEST_TOKEN_F2}"
""")
        from jitauth.config.loader import load_adapter_configs
        clear_adapters()
        configs = load_adapter_configs(str(config_file))
        assert configs[0].credentials["token"] == "resolved_value"
        clear_adapters()

    def test_unresolved_env_var_keeps_placeholder(self, tmp_path):
        config_file = tmp_path / "adapters.yaml"
        config_file.write_text("""
adapters:
  - system_name: test_sys
    adapter_type: http
    config: {}
    credentials:
      token: "${NONEXISTENT_12345}"
""")
        from jitauth.config.loader import load_adapter_configs
        clear_adapters()
        configs = load_adapter_configs(str(config_file))
        assert configs[0].credentials["token"] == "${NONEXISTENT_12345}"
        clear_adapters()


# ====================================================================
# Findings-2 #6 -- Value-based secret scanning
# ====================================================================


class TestSecretScanning:
    """Result sanitization catches secrets in values, not just key names."""

    def test_bearer_token_in_stdout(self):
        from jitauth.proxy.gateway import _sanitize_string
        assert "[REDACTED" in _sanitize_string(
            "HTTP/1.1 200 OK\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc"
        )

    def test_aws_key_in_value(self):
        from jitauth.proxy.gateway import _sanitize_string
        assert "[REDACTED" in _sanitize_string("key: AKIAIOSFODNN7EXAMPLE in config")

    def test_private_key(self):
        from jitauth.proxy.gateway import _sanitize_string
        assert "[REDACTED" in _sanitize_string("-----BEGIN PRIVATE KEY-----\nMII...")

    def test_password_in_connection_string(self):
        from jitauth.proxy.gateway import _sanitize_string
        assert "[REDACTED" in _sanitize_string("postgresql://user:password=hunter2@db:5432/x")

    def test_normal_text_untouched(self):
        from jitauth.proxy.gateway import _sanitize_string
        v = "Account acme_123 has 42 contacts."
        assert v == _sanitize_string(v)

    def test_sanitize_for_log_string_values(self):
        from jitauth.proxy.gateway import _sanitize_for_log
        data = {
            "status": "ok",
            "debug_output": "token Bearer sk-abc123456789012345678901234567890123456789",
        }
        sanitized = _sanitize_for_log(data)
        assert "[REDACTED" in sanitized["debug_output"]
        assert sanitized["status"] == "ok"

    def test_execute_redacts_string_result(self, client):
        """Adapter returning a string with secrets -> redacted in response."""
        secret_output = "config: password=X token Bearer AKIAIOSFODNN7EXAMPLE"
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
        assert "[REDACTED" in resp.json()["result"]
