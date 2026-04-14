"""JITAuth Quickstart Example.

Demonstrates the full governance pipeline:
1. Register a mock CRM adapter
2. Create a task via the SDK
3. Execute governed tool calls
4. Query the audit trail

Run:
    # Terminal 1: Start the broker
    jitauth serve

    # Terminal 2: Run this example
    python examples/quickstart.py
"""

import asyncio
import json
import sys

from jitauth.sdk import JITAuthClient, TaskDeniedError, ApprovalRequiredError


async def main():
    # Connect to the broker
    client = JITAuthClient(
        broker_url="http://localhost:8700",
        runtime_id="quickstart_agent",
        runtime_type="llm_orchestrator",
        runtime_trust_tier="low",
    )

    print("=" * 60)
    print("JITAuth Quickstart")
    print("=" * 60)

    # Check broker health
    health = await client.health()
    print(f"\nBroker: {health['service']} v{health['version']} — {health['status']}")

    # --- Scenario 1: Allowed read ---
    print("\n--- Scenario 1: CRM Read (should be allowed) ---")
    try:
        async with client.task(
            requester="demo_user",
            objective="Read CRM account data",
            actions=[{"system": "crm", "action": "read_account", "action_class": "read"}],
        ) as task:
            print(f"Task {task.task_id} — approved")
            print(f"Systems: {task.systems}")
            result = await task.execute("crm.read_account", {"account_id": "acme_123"})
            print(f"Result: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"Error: {e}")

    # --- Scenario 2: Denied destructive action ---
    print("\n--- Scenario 2: Database Delete (should be denied) ---")
    try:
        async with client.task(
            requester="demo_user",
            objective="Drop old tables",
            actions=[{"system": "db", "action": "drop_table", "action_class": "delete"}],
        ) as task:
            print("This shouldn't print — task should be denied")
    except TaskDeniedError as e:
        print(f"Denied (as expected): {e}")

    # --- Scenario 3: Requires approval ---
    print("\n--- Scenario 3: Email Send (requires approval) ---")
    try:
        async with client.task(
            requester="demo_user",
            objective="Send email to client",
            actions=[{"system": "email", "action": "send_email", "action_class": "send"}],
        ) as task:
            print("This shouldn't print — approval required")
    except ApprovalRequiredError as e:
        print(f"Approval required (as expected): {e}")
        print(f"Task ID for approval: {e.task_id}")

    # --- Scenario 4: Auto-approved send ---
    print("\n--- Scenario 4: Email Send with Auto-Approve ---")
    try:
        async with client.task(
            requester="demo_user",
            objective="Send email with auto-approval",
            actions=[{"system": "email", "action": "send_email", "action_class": "send"}],
            auto_approve=True,
            approver_id="admin_bot",
        ) as task:
            print(f"Task {task.task_id} — auto-approved")
            result = await task.execute("email.send_email", {"to": "client@example.com"})
            print(f"Result: {json.dumps(result, indent=2)}")

            # Query audit trail
            print(f"\nAudit trail for task {task.task_id}:")
            trail = await client.get_audit_trail(task_id=task.task_id)
            for event in reversed(trail):  # Chronological order
                print(f"  [{event['event_type']}] {event['actor']}")
    except Exception as e:
        print(f"Error: {e}")

    await client.close()
    print("\n" + "=" * 60)
    print("Done. Every action was governed, scoped, and audited.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
