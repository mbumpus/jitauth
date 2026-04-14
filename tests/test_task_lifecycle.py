"""Test the core task lifecycle: create → classify → policy → capabilities."""


def _create_task(client, **overrides):
    """Helper to create a task."""
    payload = {
        "requester_id": "user_123",
        "runtime_id": "agent_runtime_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "Test task",
        "actions": [
            {
                "system": "crm",
                "action": "read_account",
                "action_class": "read",
            }
        ],
        "time_limit_seconds": 300,
    }
    payload.update(overrides)
    return client.post("/tasks", json=payload)


def test_create_task(client):
    resp = _create_task(client)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "created"
    assert data["requester_id"] == "user_123"
    assert len(data["actions"]) == 1


def test_get_task(client):
    resp = _create_task(client)
    task_id = resp.json()["id"]

    resp = client.get(f"/tasks/{task_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == task_id


def test_get_nonexistent_task(client):
    resp = client.get("/tasks/nonexistent")
    assert resp.status_code == 404


def test_classify_task(client):
    task_id = _create_task(client).json()["id"]

    resp = client.post(f"/tasks/{task_id}/classify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_tier"] == "tier_1"  # read action = tier_1
    assert "read" in data["action_classes"]


def test_classify_write_task(client):
    task_id = _create_task(
        client,
        actions=[{"system": "crm", "action": "update_contact", "action_class": "write"}],
    ).json()["id"]

    resp = client.post(f"/tasks/{task_id}/classify")
    assert resp.status_code == 200
    assert resp.json()["risk_tier"] == "tier_2"


def test_classify_delete_task(client):
    task_id = _create_task(
        client,
        actions=[{"system": "database", "action": "drop_table", "action_class": "delete"}],
    ).json()["id"]

    resp = client.post(f"/tasks/{task_id}/classify")
    assert resp.status_code == 200
    assert resp.json()["risk_tier"] == "tier_4"


def test_policy_allow_read(client):
    """Read action on CRM should be allowed."""
    task_id = _create_task(client).json()["id"]
    client.post(f"/tasks/{task_id}/classify")

    resp = client.post(f"/tasks/{task_id}/policy-evaluate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["effect"] == "allow"
    assert data["rule_name"] == "allow-reads"


def test_policy_deny_destructive(client):
    """Delete action should be denied."""
    task_id = _create_task(
        client,
        actions=[{"system": "database", "action": "drop_table", "action_class": "delete"}],
    ).json()["id"]
    client.post(f"/tasks/{task_id}/classify")

    resp = client.post(f"/tasks/{task_id}/policy-evaluate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["effect"] == "deny"


def test_policy_require_approval_send(client):
    """Send action should require approval."""
    task_id = _create_task(
        client,
        actions=[{"system": "email", "action": "send_external", "action_class": "send"}],
    ).json()["id"]
    client.post(f"/tasks/{task_id}/classify")

    resp = client.post(f"/tasks/{task_id}/policy-evaluate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["effect"] == "require_approval"


def test_full_happy_path(client):
    """Complete lifecycle: create → classify → policy → capabilities."""
    # Create
    task_id = _create_task(client).json()["id"]

    # Classify
    client.post(f"/tasks/{task_id}/classify")

    # Policy
    resp = client.post(f"/tasks/{task_id}/policy-evaluate")
    assert resp.json()["effect"] == "allow"

    # Capabilities
    resp = client.post(f"/tasks/{task_id}/capabilities")
    assert resp.status_code == 200
    caps = resp.json()
    assert len(caps) == 1
    assert caps[0]["target_system"] == "crm"
    assert caps[0]["status"] == "active"

    # Task should now be executing
    task = client.get(f"/tasks/{task_id}").json()
    assert task["status"] == "executing"


def test_approval_flow(client):
    """Task requiring approval → approve → capabilities."""
    task_id = _create_task(
        client,
        actions=[{"system": "email", "action": "send_external", "action_class": "send"}],
    ).json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    client.post(f"/tasks/{task_id}/policy-evaluate")

    # Task should be pending approval
    task = client.get(f"/tasks/{task_id}").json()
    assert task["status"] == "pending_approval"

    # Approve
    resp = client.post(f"/tasks/{task_id}/approve", json={
        "approver_id": "admin_1",
        "approved": True,
        "reason": "Looks good",
    })
    assert resp.status_code == 200

    # Now can mint capabilities
    resp = client.post(f"/tasks/{task_id}/capabilities")
    assert resp.status_code == 200


def test_revocation(client):
    """Mint capability then revoke it."""
    task_id = _create_task(client).json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    client.post(f"/tasks/{task_id}/policy-evaluate")
    caps = client.post(f"/tasks/{task_id}/capabilities").json()
    cap_id = caps[0]["id"]

    # Revoke
    resp = client.post(f"/capabilities/{cap_id}/revoke", json={
        "reason": "Suspicious activity",
        "revoked_by": "admin_1",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"

    # Can't revoke again
    resp = client.post(f"/capabilities/{cap_id}/revoke", json={
        "reason": "Again",
        "revoked_by": "admin_1",
    })
    assert resp.status_code == 409


def test_audit_trail(client):
    """Audit log should capture the full lifecycle."""
    task_id = _create_task(client).json()["id"]
    client.post(f"/tasks/{task_id}/classify")
    client.post(f"/tasks/{task_id}/policy-evaluate")
    client.post(f"/tasks/{task_id}/capabilities")

    resp = client.get(f"/audit?task_id={task_id}")
    assert resp.status_code == 200
    events = resp.json()
    event_types = [e["event_type"] for e in events]
    assert "task_created" in event_types
    assert "task_classified" in event_types
    assert "policy_evaluated" in event_types
    assert "capabilities_minted" in event_types
