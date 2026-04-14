"""End-to-end integration tests.

These test complete scenarios from the spec (section 22)
through the full system: API → policy → capability → proxy → audit.
"""

from __future__ import annotations

from typing import Any

import pytest

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter


# ---------- Mock adapters simulating real systems ----------


class MockCalendarAdapter(BaseAdapter):
    supported_actions = ["read_availability", "create_event"]

    async def execute(self, action, arguments, credential=None):
        if action == "read_availability":
            return AdapterResult(success=True, result={
                "available_slots": ["2026-04-15T10:00", "2026-04-15T14:00"],
            })
        if action == "create_event":
            return AdapterResult(success=True, result={
                "event_id": "evt_001",
                "title": arguments.get("title", "Meeting"),
                "time": arguments.get("time"),
            })
        return AdapterResult(success=False, error=f"Unknown action: {action}")


class MockCRMAdapter(BaseAdapter):
    supported_actions = ["read_account", "read_notes", "update_stage"]

    async def execute(self, action, arguments, credential=None):
        if action == "read_account":
            return AdapterResult(success=True, result={
                "account_id": arguments.get("account_id"),
                "name": "Acme Corp",
                "status": "active",
            })
        if action == "read_notes":
            return AdapterResult(success=True, result={
                "notes": ["Last call: discussed pricing", "Follow-up scheduled"],
            })
        if action == "update_stage":
            return AdapterResult(success=True, result={
                "updated": True,
                "new_stage": arguments.get("stage"),
            })
        return AdapterResult(success=False, error=f"Unknown action: {action}")


class MockEmailAdapter(BaseAdapter):
    supported_actions = ["create_draft", "send_email"]

    async def execute(self, action, arguments, credential=None):
        if action == "create_draft":
            return AdapterResult(success=True, result={
                "draft_id": "draft_001",
                "to": arguments.get("to"),
                "body_preview": arguments.get("body", "")[:50],
            })
        if action == "send_email":
            return AdapterResult(success=True, result={"sent": True})
        return AdapterResult(success=False, error=f"Unknown action: {action}")


class MockDatabaseAdapter(BaseAdapter):
    supported_actions = ["read_query", "write_query", "drop_table"]

    async def execute(self, action, arguments, credential=None):
        return AdapterResult(success=True, result={"rows_affected": 0})


@pytest.fixture(autouse=True)
def _setup_adapters():
    clear_adapters()
    register_adapter(MockCalendarAdapter(AdapterConfig("calendar", "mock", {})))
    register_adapter(MockCRMAdapter(AdapterConfig("crm", "mock", {})))
    register_adapter(MockEmailAdapter(AdapterConfig("email", "mock", {})))
    register_adapter(MockDatabaseAdapter(AdapterConfig("database", "mock", {})))
    yield
    clear_adapters()


# ---------- Scenario A: Calendar Scheduling (spec section 22) ----------


class TestCalendarScenario:
    """User asks agent to schedule a meeting."""

    def test_calendar_read_and_create(self, client):
        """Should allow reading availability and creating an event."""
        # Create task with both actions
        resp = client.post("/tasks", json={
            "requester_id": "user_alice",
            "runtime_id": "agent_01",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Schedule a meeting with the client next week",
            "actions": [
                {"system": "calendar", "action": "read_availability", "action_class": "read"},
                {"system": "calendar", "action": "create_event", "action_class": "write"},
            ],
            "time_limit_seconds": 300,
        })
        assert resp.status_code == 201
        task_id = resp.json()["id"]

        # Classify → should be tier_2 (bounded write)
        resp = client.post(f"/tasks/{task_id}/classify")
        assert resp.json()["risk_tier"] == "tier_2"

        # Policy → should allow bounded writes
        resp = client.post(f"/tasks/{task_id}/policy-evaluate")
        assert resp.json()["effect"] == "allow"

        # Mint capabilities
        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_id = caps[0]["id"]
        cap_token = caps[0]["token"]

        # Read availability
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "calendar.read_availability",
            "arguments": {},
            "capability_token": cap_token,
        })
        assert resp.status_code == 200
        assert "available_slots" in resp.json()["result"]

        # Create event
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "calendar.create_event",
            "arguments": {"title": "Client Meeting", "time": "2026-04-15T10:00"},
            "capability_token": cap_token,
        })
        assert resp.status_code == 200
        assert resp.json()["result"]["event_id"] == "evt_001"

        # Verify audit trail
        audit = client.get(f"/audit?task_id={task_id}").json()
        types = [e["event_type"] for e in audit]
        assert "task_created" in types
        assert "tool_invoked" in types


# ---------- Scenario B: CRM Lookup + Draft Follow-Up ----------


class TestCRMLookupScenario:
    """User asks agent to summarize client activity and draft a response."""

    def test_crm_read_and_draft(self, client):
        """Read CRM + create draft email should be allowed."""
        resp = client.post("/tasks", json={
            "requester_id": "user_bob",
            "runtime_id": "agent_02",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Summarize client activity and draft follow-up",
            "actions": [
                {"system": "crm", "action": "read_account", "action_class": "read"},
                {"system": "crm", "action": "read_notes", "action_class": "read"},
                {"system": "email", "action": "create_draft", "action_class": "write"},
            ],
        })
        task_id = resp.json()["id"]

        client.post(f"/tasks/{task_id}/classify")
        resp = client.post(f"/tasks/{task_id}/policy-evaluate")
        # Has write action → tier_2 → should allow bounded write
        assert resp.json()["effect"] == "allow"

        caps = client.post(f"/tasks/{task_id}/capabilities").json()

        # Find CRM capability
        crm_cap = next(c for c in caps if c["target_system"] == "crm")
        email_cap = next(c for c in caps if c["target_system"] == "email")
        crm_token = crm_cap["token"]
        email_token = email_cap["token"]

        # Read CRM
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": crm_cap["id"],
            "tool": "crm.read_account",
            "arguments": {"account_id": "acme_123"},
            "capability_token": crm_token,
        })
        assert resp.json()["success"]
        assert resp.json()["result"]["name"] == "Acme Corp"

        # Create draft
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": email_cap["id"],
            "tool": "email.create_draft",
            "arguments": {"to": "client@acme.com", "body": "Following up on our discussion..."},
            "capability_token": email_token,
        })
        assert resp.json()["success"]

    def test_send_email_requires_approval(self, client):
        """Sending email (not drafting) should require approval."""
        resp = client.post("/tasks", json={
            "requester_id": "user_bob",
            "runtime_id": "agent_02",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Send follow-up email",
            "actions": [
                {"system": "email", "action": "send_email", "action_class": "send"},
            ],
        })
        task_id = resp.json()["id"]

        client.post(f"/tasks/{task_id}/classify")
        resp = client.post(f"/tasks/{task_id}/policy-evaluate")
        assert resp.json()["effect"] == "require_approval"

        # Verify task is stuck until approval
        task = client.get(f"/tasks/{task_id}").json()
        assert task["status"] == "pending_approval"

        # Can't mint capabilities yet
        resp = client.post(f"/tasks/{task_id}/capabilities")
        assert resp.status_code == 409


# ---------- Scenario C: Destructive Action ----------


class TestDestructiveScenario:
    """User asks agent to do something dangerous."""

    def test_delete_denied(self, client):
        """Delete operations should be denied by default."""
        resp = client.post("/tasks", json={
            "requester_id": "user_carol",
            "runtime_id": "agent_03",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Clean up old database tables",
            "actions": [
                {"system": "database", "action": "drop_table", "action_class": "delete"},
            ],
        })
        task_id = resp.json()["id"]

        client.post(f"/tasks/{task_id}/classify")
        resp = client.post(f"/tasks/{task_id}/policy-evaluate")
        assert resp.json()["effect"] == "deny"

        # Task should be denied
        task = client.get(f"/tasks/{task_id}").json()
        assert task["status"] == "denied"

        # Definitely can't mint capabilities
        resp = client.post(f"/tasks/{task_id}/capabilities")
        assert resp.status_code == 409


# ---------- Scenario D: Privilege escalation attempt ----------


class TestPrivilegeEscalation:
    """Agent tries to exceed its authorized scope."""

    def test_cant_use_capability_for_wrong_action(self, client):
        """Capability for read_account should not allow drop_table."""
        resp = client.post("/tasks", json={
            "requester_id": "user_dave",
            "runtime_id": "agent_04",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Read CRM data",
            "actions": [
                {"system": "crm", "action": "read_account", "action_class": "read"},
            ],
        })
        task_id = resp.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_id = caps[0]["id"]
        cap_token = caps[0]["token"]

        # Try to use CRM capability for a different action
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "crm.update_stage",
            "arguments": {"stage": "closed_won"},
            "capability_token": cap_token,
        })
        assert resp.status_code in (400, 403)

    def test_cant_use_capability_for_wrong_system(self, client):
        """CRM capability should not work for database operations."""
        resp = client.post("/tasks", json={
            "requester_id": "user_dave",
            "runtime_id": "agent_04",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Read CRM data",
            "actions": [
                {"system": "crm", "action": "read_account", "action_class": "read"},
            ],
        })
        task_id = resp.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_id = caps[0]["id"]
        cap_token = caps[0]["token"]

        # Try to use CRM capability against database
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "database.drop_table",
            "arguments": {"table": "users"},
            "capability_token": cap_token,
        })
        assert resp.status_code in (400, 403)


# ---------- Scenario E: Mid-task revocation ----------


class TestRevocationScenario:
    """Admin revokes capability while task is executing."""

    def test_revoke_stops_execution(self, client):
        """Revoking a capability should immediately block further calls."""
        resp = client.post("/tasks", json={
            "requester_id": "user_eve",
            "runtime_id": "agent_05",
            "runtime_type": "llm_orchestrator",
            "runtime_trust_tier": "low",
            "objective": "Read CRM data",
            "actions": [
                {"system": "crm", "action": "read_account", "action_class": "read"},
            ],
            "max_actions": 10,
        })
        task_id = resp.json()["id"]
        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        caps = client.post(f"/tasks/{task_id}/capabilities").json()
        cap_id = caps[0]["id"]
        cap_token = caps[0]["token"]

        # First call works
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "crm.read_account",
            "arguments": {"account_id": "123"},
            "capability_token": cap_token,
        })
        assert resp.status_code == 200

        # Admin revokes
        client.post(f"/capabilities/{cap_id}/revoke", json={
            "reason": "Anomalous behavior detected",
            "revoked_by": "admin_security",
        })

        # Next call is blocked
        resp = client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap_id,
            "tool": "crm.read_account",
            "arguments": {"account_id": "456"},
            "capability_token": cap_token,
        })
        assert resp.status_code == 403

        # Audit trail shows revocation
        audit = client.get(f"/audit?task_id={task_id}").json()
        types = [e["event_type"] for e in audit]
        assert "capability_revoked" in types
