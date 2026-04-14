"""Tests for findings-4.md residual hardening items.

Covers:
  1. DB-level audit hash chaining (no process-local state)
  2. scrypt KDF for runtime_secret (replaces plain SHA-256)
  3. Configurable per-adapter resource_keys for list-scope enforcement
"""

from __future__ import annotations

import json
import secrets
from typing import Any

import pytest

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import (
    clear_adapters,
    register_adapter,
    _DEFAULT_RESOURCE_KEYS,
    register_adapter_config,
)


# ---------- Mock adapter ----------


class MockAdapter(BaseAdapter):
    """Adapter that echoes arguments back."""

    supported_actions = ["read_account", "update_contact", "read_ticket"]

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
        "objective": "findings-4 test",
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
# 1. DB-level audit hash chaining
# ====================================================================


class TestDBAuditChain:
    """Audit chain uses DB-level sequencing, not process-local state."""

    def test_get_previous_hash_queries_db(self, client):
        """_get_previous_hash returns the hash of the latest event from DB."""
        from jitauth.audit.logger import _get_previous_hash, _hash_event
        from jitauth.db.session import get_session_factory
        from jitauth.core.models import AuditEvent

        # Create a task to generate audit events
        client.post("/tasks", json={
            "requester_id": "u1", "runtime_id": "rt1", "objective": "chain test",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })

        db = get_session_factory()()
        try:
            last_event = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).first()
            assert last_event is not None
            expected_hash = _hash_event(last_event)
            assert _get_previous_hash(db) == expected_hash
        finally:
            db.close()

    def test_chain_valid_across_multiple_tasks(self, client):
        """Multiple tasks produce a valid global chain."""
        for i in range(5):
            client.post("/tasks", json={
                "requester_id": f"u{i}", "runtime_id": f"rt{i}", "objective": f"task {i}",
                "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
            })
        verify = client.get("/audit/verify")
        result = verify.json()
        assert result["valid"] is True
        assert result["events_checked"] >= 5

    def test_initialize_chain_is_noop(self, client):
        """initialize_chain is a no-op (backward compat); doesn't crash."""
        from jitauth.audit.logger import initialize_chain
        from jitauth.db.session import get_session_factory
        db = get_session_factory()()
        try:
            initialize_chain(db)  # should not raise
        finally:
            db.close()

    def test_reset_chain_is_noop(self):
        """reset_chain is a no-op (backward compat); doesn't crash."""
        from jitauth.audit.logger import reset_chain
        reset_chain()  # should not raise


# ====================================================================
# 2. scrypt KDF for runtime_secret
# ====================================================================


class TestScryptKDF:
    """Runtime secret hashing uses scrypt, not plain SHA-256."""

    def test_hash_secret_format(self):
        """hash_secret returns salt_hex$scrypt_hex format."""
        from jitauth.core.crypto import hash_secret
        h = hash_secret("test-secret-at-least-32-bytes-long-for-validation")
        assert "$" in h
        salt_part, hash_part = h.split("$", 1)
        # salt is 16 bytes = 32 hex chars
        assert len(salt_part) == 32
        # scrypt output is 32 bytes = 64 hex chars
        assert len(hash_part) == 64

    def test_hash_secret_unique_salts(self):
        """Same secret produces different hashes (random salt)."""
        from jitauth.core.crypto import hash_secret
        secret = "test-secret-at-least-32-bytes-long-for-validation"
        h1 = hash_secret(secret)
        h2 = hash_secret(secret)
        assert h1 != h2

    def test_verify_secret_roundtrip(self):
        """verify_secret returns True for a correct secret."""
        from jitauth.core.crypto import hash_secret, verify_secret
        secret = "test-secret-at-least-32-bytes-long-for-validation"
        h = hash_secret(secret)
        assert verify_secret(secret, h) is True
        assert verify_secret("wrong-secret-at-least-32-bytes-long-xxxxx", h) is False

    def test_verify_secret_legacy_sha256(self):
        """verify_secret accepts legacy SHA-256 hashes (no $ separator)."""
        import hashlib
        from jitauth.core.crypto import verify_secret
        secret = "test-secret-at-least-32-bytes-long-for-validation"
        legacy_hash = hashlib.sha256(secret.encode()).hexdigest()
        assert verify_secret(secret, legacy_hash) is True
        assert verify_secret("wrong-secret-at-least-32-bytes-long-xxxxx", legacy_hash) is False

    def test_verify_secret_bad_format(self):
        """verify_secret returns False for malformed stored hashes."""
        from jitauth.core.crypto import verify_secret
        assert verify_secret("anything", "not-valid-hex$also-bad") is False
        assert verify_secret("anything", "") is False

    def test_runtime_auth_uses_scrypt_e2e(self, client, mock_adapter):
        """End-to-end: task creation hashes with scrypt, execute verifies."""
        runtime_secret = secrets.token_hex(32)
        task_id, caps = _lifecycle(client, runtime_secret=runtime_secret)
        cap = caps[0]

        # Correct secret works
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "runtime_secret": runtime_secret,
            "tool": "crm.read_account",
            "arguments": {"account_id": "1"},
        })
        assert resp.status_code == 200

        # Verify the stored hash is scrypt format (has $)
        from jitauth.db.session import get_session_factory
        from jitauth.core.models import Task
        db = get_session_factory()()
        try:
            task_obj = db.get(Task, task_id)
            assert "$" in task_obj.runtime_secret_hash
            assert len(task_obj.runtime_secret_hash) == 97  # 32 + 1 + 64
        finally:
            db.close()

    def test_wrong_secret_still_rejected(self, client, mock_adapter):
        """Wrong runtime_secret is rejected with scrypt verification."""
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


# ====================================================================
# 3. Configurable per-adapter resource_keys for list-scope enforcement
# ====================================================================


class TestConfigurableResourceKeys:
    """List-scope enforcement uses per-adapter resource_keys when configured."""

    def test_default_resource_keys_exist(self):
        """Default resource keys are defined and non-empty."""
        assert len(_DEFAULT_RESOURCE_KEYS) > 0
        assert "account_id" in _DEFAULT_RESOURCE_KEYS
        assert "id" in _DEFAULT_RESOURCE_KEYS

    def test_adapter_config_resource_keys_field(self):
        """AdapterConfig accepts resource_keys."""
        config = AdapterConfig(
            system_name="ticketing",
            adapter_type="http",
            config={},
            resource_keys={"ticket_id", "incident_id"},
        )
        assert config.resource_keys == {"ticket_id", "incident_id"}

    def test_adapter_resource_keys_used_in_scope_enforcement(self, client, tmp_path):
        """When adapter has resource_keys, those are used for list-scope checking."""
        # Set up adapter with custom resource_keys
        config = AdapterConfig(
            system_name="crm",
            adapter_type="mock",
            config={},
            resource_keys={"ticket_id"},  # custom key
        )
        adapter = MockAdapter(config)
        register_adapter(adapter)

        # Create task with list-scope
        task_id, caps = _lifecycle(
            client,
            actions=[{
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
                "resource_scope": json.dumps(["ticket:123"]),
            }],
        )
        cap = caps[0]

        # Execute with ticket_id matching scope — should work
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"ticket_id": "ticket:123"},
        })
        assert resp.status_code == 200

    def test_adapter_resource_keys_rejects_non_matching(self, client):
        """Custom resource_keys rejects arguments that don't match scope."""
        config = AdapterConfig(
            system_name="crm",
            adapter_type="mock",
            config={},
            resource_keys={"ticket_id"},
        )
        adapter = MockAdapter(config)
        register_adapter(adapter)

        task_id, caps = _lifecycle(
            client,
            actions=[{
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
                "resource_scope": json.dumps(["ticket:123"]),
            }],
        )
        cap = caps[0]

        # ticket_id doesn't match scope value
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"ticket_id": "ticket:999"},
        })
        assert resp.status_code == 400
        assert "scope_violation" in resp.json()["detail"]["error"]

    def test_default_keys_used_when_no_adapter_config(self, client):
        """When no adapter resource_keys configured, defaults are used."""
        config = AdapterConfig(system_name="crm", adapter_type="mock", config={})
        adapter = MockAdapter(config)
        register_adapter(adapter)

        task_id, caps = _lifecycle(
            client,
            actions=[{
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
                "resource_scope": json.dumps(["acme_123"]),
            }],
        )
        cap = caps[0]

        # account_id is in default keys — should be checked
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"account_id": "acme_123"},
        })
        assert resp.status_code == 200

    def test_loader_reads_resource_keys(self, tmp_path, monkeypatch):
        """Adapter YAML loader picks up resource_keys."""
        config_file = tmp_path / "adapters.yaml"
        config_file.write_text("""
adapters:
  - system_name: ticketing
    adapter_type: http
    config:
      base_url: "https://example.com"
    resource_keys:
      - ticket_id
      - incident_id
""")
        from jitauth.config.loader import load_adapter_configs
        clear_adapters()
        configs = load_adapter_configs(str(config_file))
        assert configs[0].resource_keys == {"ticket_id", "incident_id"}
        clear_adapters()
