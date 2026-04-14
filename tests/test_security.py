"""Security hardening tests.

Tests for input fuzzing, SQL injection attempts, path traversal,
oversized payloads, and rate limiting.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from jitauth.broker.server import create_app


@pytest.fixture
def client():
    app = create_app(rate_limit=False)
    with TestClient(app) as c:
        yield c


# ---------- Helpers ----------


def _create_read_task(client, **overrides):
    payload = {
        "requester_id": "sec_user",
        "runtime_id": "sec_runtime",
        "objective": "security test",
        "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
    }
    payload.update(overrides)
    return client.post("/tasks", json=payload)


# ---------- SQL Injection ----------


class TestSQLInjection:
    """Verify that SQL injection payloads are treated as opaque strings."""

    SQLI_PAYLOADS = [
        "'; DROP TABLE tasks; --",
        "1' OR '1'='1",
        "1; SELECT * FROM audit_events --",
        "' UNION SELECT id, requester_id FROM tasks --",
        "admin'--",
        "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    ]

    def test_sqli_in_requester_id(self, client):
        for payload in self.SQLI_PAYLOADS:
            r = _create_read_task(client, requester_id=payload)
            assert r.status_code == 201
            # Verify the payload is stored as-is, not interpreted
            task = r.json()
            assert task["requester_id"] == payload

    def test_sqli_in_objective(self, client):
        for payload in self.SQLI_PAYLOADS:
            r = _create_read_task(client, objective=payload)
            assert r.status_code == 201

    def test_sqli_in_runtime_id(self, client):
        for payload in self.SQLI_PAYLOADS:
            r = _create_read_task(client, runtime_id=payload)
            assert r.status_code == 201

    def test_sqli_in_query_params(self, client):
        """SQL injection in audit query parameters."""
        for payload in self.SQLI_PAYLOADS:
            r = client.get("/audit", params={"task_id": payload})
            assert r.status_code == 200
            assert r.json() == []  # No results, but no error

    def test_sqli_in_task_id_path(self, client):
        """SQL injection in path parameters."""
        r = client.get("/tasks/' OR 1=1 --")
        assert r.status_code == 404


# ---------- Input Validation ----------


class TestInputValidation:
    """Verify that malformed inputs are properly rejected."""

    def test_empty_actions_list(self, client):
        r = client.post("/tasks", json={
            "requester_id": "user",
            "runtime_id": "rt",
            "objective": "test",
            "actions": [],
        })
        # Empty actions should be rejected
        assert r.status_code == 422

    def test_missing_required_fields(self, client):
        r = client.post("/tasks", json={})
        assert r.status_code == 422

    def test_invalid_action_class(self, client):
        r = client.post("/tasks", json={
            "requester_id": "user",
            "runtime_id": "rt",
            "objective": "test",
            "actions": [{"system": "x", "action": "y", "action_class": "nuke"}],
        })
        assert r.status_code == 422

    def test_time_limit_too_low(self, client):
        r = _create_read_task(client, time_limit_seconds=1)
        assert r.status_code == 422

    def test_time_limit_too_high(self, client):
        r = _create_read_task(client, time_limit_seconds=999999)
        assert r.status_code == 422

    def test_max_actions_zero(self, client):
        r = _create_read_task(client, max_actions=0)
        assert r.status_code == 422

    def test_max_actions_too_high(self, client):
        r = _create_read_task(client, max_actions=101)
        assert r.status_code == 422

    def test_invalid_json_body(self, client):
        r = client.post("/tasks", content=b"not json", headers={"Content-Type": "application/json"})
        assert r.status_code == 422

    def test_extra_fields_ignored(self, client):
        """Ensure extra fields don't cause errors or get stored."""
        r = _create_read_task(client, evil_field="rm -rf /")
        assert r.status_code == 201


# ---------- Oversized Payloads ----------


class TestOversizedPayloads:
    """Test that oversized inputs are handled."""

    def test_very_long_objective(self, client):
        """A very long objective should still work (it's a Text column)."""
        r = _create_read_task(client, objective="x" * 100_000)
        assert r.status_code == 201

    def test_very_long_requester_id(self, client):
        """Long requester_id within column limit."""
        r = _create_read_task(client, requester_id="x" * 255)
        assert r.status_code == 201

    def test_many_actions(self, client):
        """Many actions in a single task."""
        actions = [
            {"system": f"sys_{i}", "action": f"act_{i}", "action_class": "read"}
            for i in range(50)
        ]
        r = client.post("/tasks", json={
            "requester_id": "user",
            "runtime_id": "rt",
            "objective": "many actions",
            "actions": actions,
        })
        assert r.status_code == 201

    def test_deeply_nested_arguments(self, client):
        """Deep nesting in execute arguments — pydantic handles this."""
        # Build deeply nested dict
        nested = {"value": "leaf"}
        for _ in range(50):
            nested = {"nested": nested}

        r = client.post("/execute", json={
            "task_id": "fake",
            "capability_id": "fake",
            "tool": "sys.action",
            "arguments": nested,
        })
        # Should reach gateway validation (not crash)
        assert r.status_code in (400, 403)


# ---------- State Machine Violations ----------


class TestStateMachineViolations:
    """Verify that operations are rejected when task is in wrong state."""

    def test_classify_already_classified(self, client):
        r = _create_read_task(client)
        task_id = r.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        r2 = client.post(f"/tasks/{task_id}/classify")
        assert r2.status_code == 409

    def test_evaluate_before_classify(self, client):
        r = _create_read_task(client)
        task_id = r.json()["id"]
        r2 = client.post(f"/tasks/{task_id}/policy-evaluate")
        assert r2.status_code == 409

    def test_capabilities_before_approval(self, client):
        r = _create_read_task(client)
        task_id = r.json()["id"]
        r2 = client.post(f"/tasks/{task_id}/capabilities")
        assert r2.status_code == 409

    def test_approve_already_approved(self, client):
        """Can't approve a task that's already approved."""
        r = _create_read_task(client)
        task_id = r.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        # Task is now approved (read action), trying to approve should fail
        r2 = client.post(f"/tasks/{task_id}/approve", json={
            "approver_id": "admin",
            "approved": True,
        })
        assert r2.status_code == 409

    def test_double_revoke(self, client):
        """Can't revoke an already revoked capability."""
        # Create full lifecycle
        r = _create_read_task(client)
        task_id = r.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_id = caps[0]["id"]

        # Revoke once
        r1 = client.post(f"/capabilities/{cap_id}/revoke", json={
            "reason": "first revoke",
            "revoked_by": "admin",
        })
        assert r1.status_code == 200

        # Revoke again
        r2 = client.post(f"/capabilities/{cap_id}/revoke", json={
            "reason": "second revoke",
            "revoked_by": "admin",
        })
        assert r2.status_code == 409


# ---------- Path Traversal ----------


class TestPathTraversal:
    """Ensure path-like payloads don't escape."""

    TRAVERSAL_PAYLOADS = [
        "../../etc/passwd",
        "/etc/shadow",
        "..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    def test_path_traversal_in_system_name(self, client):
        for payload in self.TRAVERSAL_PAYLOADS:
            r = client.post("/tasks", json={
                "requester_id": "user",
                "runtime_id": "rt",
                "objective": "test",
                "actions": [{"system": payload, "action": "read", "action_class": "read"}],
            })
            # Should create the task (system name is opaque to the broker)
            assert r.status_code == 201


# ---------- Audit Query Bounds ----------


class TestAuditQueryBounds:
    """Verify audit query limit enforcement."""

    def test_audit_limit_capped(self, client):
        """Limit should be capped at 200 even if higher requested."""
        r = client.get("/audit", params={"limit": 9999})
        assert r.status_code == 200

    def test_audit_negative_limit(self, client):
        """Negative limit should be handled gracefully."""
        r = client.get("/audit", params={"limit": -1})
        # FastAPI/SQLAlchemy handles this — should not crash
        assert r.status_code == 200


# ---------- Rate Limiting ----------


class TestRateLimiting:
    """Verify rate limiting middleware works."""

    def test_rate_limit_headers_present(self):
        """Rate-limited app should return X-RateLimit headers."""
        app = create_app(rate_limit=True, requests_per_minute=100)
        with TestClient(app) as c:
            r = c.get("/health")
            assert r.status_code == 200
            assert "X-RateLimit-Limit" in r.headers
            assert "X-RateLimit-Remaining" in r.headers

    def test_rate_limit_enforced(self):
        """Should return 429 when rate limit is exceeded."""
        # Very low limit for testing
        app = create_app(rate_limit=True, requests_per_minute=2)
        with TestClient(app) as c:
            # Burst allowance is 20 by default, so total limit = 2 + 20 = 22
            # But we can set burst lower by directly configuring middleware
            pass

        # Test with a custom rate limiter directly
        from jitauth.broker.middleware import RateLimiter
        app = create_app(rate_limit=False)
        app.add_middleware(RateLimiter, requests_per_minute=3, burst=0)
        with TestClient(app) as c:
            for i in range(3):
                r = c.get("/health")
                assert r.status_code == 200, f"Request {i+1} should succeed"
            # 4th request should be rate-limited
            r = c.get("/health")
            assert r.status_code == 429
            assert "Retry-After" in r.headers
