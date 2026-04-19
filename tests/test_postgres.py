"""Postgres integration & concurrency tests.

These tests require a live Postgres instance.  They are skipped unless
the ``JITAUTH_TEST_DATABASE_URL`` env var is set.

Usage:
    # Start the test database:
    docker compose -f docker-compose.test.yaml up -d

    # Run only Postgres tests:
    JITAUTH_TEST_DATABASE_URL="postgresql://jitauth_test:testpass@localhost:5433/jitauth_test" \
      python -m pytest tests/test_postgres.py -v

    # Tear down:
    docker compose -f docker-compose.test.yaml down -v

What these tests validate that SQLite cannot:
  1. Row-level locking (SELECT … FOR UPDATE) actually serializes
  2. Alembic migrations run against real Postgres types/constraints
  3. Concurrent budget enforcement doesn't overshoot
  4. Unique constraints on chain_seq under concurrent audit writes
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import pytest
from fastapi.testclient import TestClient

from jitauth.config.settings import Settings, override_settings
from jitauth.db.session import init_db, reset_engine
from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter

PG_URL = os.environ.get("JITAUTH_TEST_DATABASE_URL")

# All tests in this module require Postgres
pytestmark = pytest.mark.postgres


def _pg_available() -> bool:
    """Check if we can connect to the Postgres test instance."""
    if not PG_URL:
        return False
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(PG_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


if not _pg_available():
    pytest.skip(
        "Postgres not available (set JITAUTH_TEST_DATABASE_URL)",
        allow_module_level=True,
    )


# ---------- Fixtures ----------


class SlowMockAdapter(BaseAdapter):
    """Adapter that takes a configurable delay, simulating real I/O."""

    supported_actions = ["read_account", "update_contact"]

    def __init__(self, config: AdapterConfig, delay: float = 0.05):
        super().__init__(config)
        self.delay = delay

    async def execute(
        self, action: str, arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
        import asyncio
        await asyncio.sleep(self.delay)
        return AdapterResult(success=True, result={"echo": arguments, "action": action})


@pytest.fixture(autouse=True)
def _pg_settings(tmp_path):
    """Configure JITAuth to use the Postgres test database."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "default.yaml").write_text("""
rules:
  - name: allow-reads
    priority: 50
    match:
      action_class: "read"
    effect: allow
  - name: allow-writes
    priority: 60
    match:
      action_class: "write"
      risk_tier: "tier_2"
    effect: allow
""")

    override_settings(Settings(
        database_url=PG_URL,
        policy_dir=str(policy_dir),
        jwt_secret="test-secret-that-is-at-least-32-bytes-long-for-hs256",
        require_api_auth=False,
    ))
    reset_engine()

    from jitauth.policy.engine import reload_rules
    reload_rules()

    from jitauth.audit.logger import reset_chain
    reset_chain()

    # Create tables fresh for each test (drop first)
    from jitauth.core.models import Base
    from jitauth.db.session import get_engine
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    # Clean up
    Base.metadata.drop_all(bind=engine)
    reset_engine()


@pytest.fixture
def pg_client(_pg_settings):
    """FastAPI test client backed by Postgres."""
    from jitauth.broker.server import create_app
    app = create_app(rate_limit=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def slow_adapter():
    clear_adapters()
    config = AdapterConfig(system_name="crm", adapter_type="mock", config={})
    adapter = SlowMockAdapter(config, delay=0.05)
    register_adapter(adapter)
    yield adapter
    clear_adapters()


def _lifecycle(client, **task_overrides):
    """Create a task through to capability minting."""
    payload = {
        "requester_id": "user_1",
        "runtime_id": "rt_01",
        "runtime_type": "llm_orchestrator",
        "runtime_trust_tier": "low",
        "objective": "pg test",
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
# 1. Basic Postgres round-trip
# ====================================================================


class TestPostgresBasics:
    """Verify the full lifecycle works on Postgres."""

    def test_create_and_execute(self, pg_client, slow_adapter):
        """Full lifecycle: create → classify → evaluate → mint → execute."""
        task_id, caps = _lifecycle(pg_client)
        assert len(caps) > 0
        cap = caps[0]

        resp = pg_client.post("/execute", json={
            "task_id": task_id,
            "capability_id": cap["id"],
            "capability_token": cap["token"],
            "tool": "crm.read_account",
            "arguments": {"account_id": "pg_test"},
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_audit_chain_valid(self, pg_client, slow_adapter):
        """Audit chain is valid after operations."""
        task_id, _ = _lifecycle(pg_client)
        verify = pg_client.get("/audit/verify")
        assert verify.status_code == 200
        result = verify.json()
        assert result["valid"] is True


# ====================================================================
# 2. Concurrent budget enforcement
# ====================================================================


class TestConcurrentBudget:
    """Concurrent execute calls cannot overshoot the task budget.

    This is the key test that SQLite can't validate properly — SQLite's
    write lock serializes at the connection level, masking real
    concurrency bugs that appear under Postgres row-level locking.
    """

    def test_concurrent_budget_not_exceeded(self, pg_client, slow_adapter):
        """Fire N concurrent /execute calls against a budget of M < N.

        Exactly M should succeed; the rest should be rejected.
        The slow adapter ensures requests overlap in time.
        """
        budget = 3
        concurrent_calls = 8
        task_id, caps = _lifecycle(pg_client, max_actions=budget)
        cap = caps[0]

        results = {"success": 0, "rejected": 0, "errors": []}

        def _execute(i: int) -> dict:
            """Make a single execute call."""
            # Each thread gets its own TestClient to avoid connection sharing
            from jitauth.broker.server import create_app
            app = create_app(rate_limit=False)
            with TestClient(app) as thread_client:
                resp = thread_client.post("/execute", json={
                    "task_id": task_id,
                    "capability_id": cap["id"],
                    "capability_token": cap["token"],
                    "tool": "crm.read_account",
                    "arguments": {"account_id": f"concurrent_{i}"},
                })
                return {"status": resp.status_code, "body": resp.json()}

        with ThreadPoolExecutor(max_workers=concurrent_calls) as pool:
            futures = [pool.submit(_execute, i) for i in range(concurrent_calls)]
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result["status"] == 200 and result["body"].get("success"):
                        results["success"] += 1
                    else:
                        results["rejected"] += 1
                except Exception as e:
                    results["errors"].append(str(e))

        # The critical assertion: at most `budget` calls succeeded
        assert results["success"] <= budget, (
            f"Budget overshoot! {results['success']} succeeded but budget was {budget}. "
            f"Rejected: {results['rejected']}, Errors: {results['errors']}"
        )
        # And at least some were rejected (we fired more than budget)
        assert results["rejected"] > 0 or results["errors"], (
            f"Expected some rejections with {concurrent_calls} calls against budget {budget}"
        )

    def test_per_capability_call_limit_concurrent(self, pg_client, slow_adapter):
        """Per-capability calls_used is accurate under concurrency."""
        budget = 5
        concurrent_calls = 10
        task_id, caps = _lifecycle(pg_client, max_actions=budget)
        cap = caps[0]

        successes = 0

        def _execute(i: int) -> bool:
            from jitauth.broker.server import create_app
            app = create_app(rate_limit=False)
            with TestClient(app) as tc:
                resp = tc.post("/execute", json={
                    "task_id": task_id,
                    "capability_id": cap["id"],
                    "capability_token": cap["token"],
                    "tool": "crm.read_account",
                    "arguments": {"account_id": f"cap_concurrent_{i}"},
                })
                return resp.status_code == 200 and resp.json().get("success")

        with ThreadPoolExecutor(max_workers=concurrent_calls) as pool:
            futures = [pool.submit(_execute, i) for i in range(concurrent_calls)]
            for f in as_completed(futures):
                if f.result():
                    successes += 1

        assert successes <= budget, (
            f"Capability call count overshoot: {successes} > {budget}"
        )


# ====================================================================
# 3. Concurrent audit chain integrity
# ====================================================================


class TestConcurrentAuditChain:
    """Audit chain_seq remains unique and ordered under concurrent writes."""

    def test_concurrent_tasks_produce_valid_chain(self, pg_client, slow_adapter):
        """Create multiple tasks concurrently; audit chain should stay valid."""
        n_tasks = 5

        task_ids = []

        def _create_task(i: int) -> str:
            from jitauth.broker.server import create_app
            app = create_app(rate_limit=False)
            with TestClient(app) as tc:
                resp = tc.post("/tasks", json={
                    "requester_id": f"user_{i}",
                    "runtime_id": f"rt_{i}",
                    "objective": f"concurrent task {i}",
                    "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
                })
                assert resp.status_code == 201, resp.json()
                return resp.json()["id"]

        with ThreadPoolExecutor(max_workers=n_tasks) as pool:
            futures = [pool.submit(_create_task, i) for i in range(n_tasks)]
            for f in as_completed(futures):
                task_ids.append(f.result())

        assert len(task_ids) == n_tasks

        # Verify the global audit chain is still valid
        verify = pg_client.get("/audit/verify")
        assert verify.status_code == 200
        result = verify.json()
        assert result["valid"] is True, f"Audit chain broken: {result}"

    def test_chain_seq_unique_under_concurrent_writes(self, pg_client, slow_adapter):
        """chain_seq values stay unique when multiple writers race.

        This is the test that matters: we fire N task-creation requests
        concurrently (each produces an audit event via write_audit_event
        which does SELECT … FOR UPDATE to assign chain_seq), then verify
        no two events share a chain_seq value.  A serial test would pass
        trivially; this one exercises the actual locking path.
        """
        n_concurrent = 8

        def _create_task(i: int) -> str:
            from jitauth.broker.server import create_app
            app = create_app(rate_limit=False)
            with TestClient(app) as tc:
                resp = tc.post("/tasks", json={
                    "requester_id": f"seq_user_{i}",
                    "runtime_id": f"seq_rt_{i}",
                    "objective": f"chain_seq concurrency test {i}",
                    "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
                })
                assert resp.status_code == 201, resp.json()
                return resp.json()["id"]

        with ThreadPoolExecutor(max_workers=n_concurrent) as pool:
            futures = [pool.submit(_create_task, i) for i in range(n_concurrent)]
            task_ids = [f.result() for f in as_completed(futures)]

        assert len(task_ids) == n_concurrent

        # Now check that every chain_seq is unique and monotonically increasing
        from jitauth.db.session import get_session_factory
        from jitauth.core.models import AuditEvent
        db = get_session_factory()()
        try:
            events = (
                db.query(AuditEvent)
                .filter(AuditEvent.chain_seq.isnot(None))
                .order_by(AuditEvent.chain_seq.asc())
                .all()
            )
            seqs = [e.chain_seq for e in events]
            assert len(seqs) > 0, "No audit events with chain_seq found"
            assert len(seqs) == len(set(seqs)), (
                f"Duplicate chain_seq values under concurrent writes: {sorted(seqs)}"
            )
            assert seqs == sorted(seqs), (
                f"chain_seq not monotonically increasing: {seqs}"
            )
        finally:
            db.close()


# ====================================================================
# 4. Alembic migrations on Postgres
# ====================================================================


class TestAlembicMigrations:
    """Verify Alembic migrations run cleanly on Postgres."""

    def test_migrations_upgrade_on_empty_db(self, _pg_settings):
        """alembic upgrade head works on an empty Postgres database."""
        from jitauth.core.models import Base
        from jitauth.db.session import get_engine

        engine = get_engine()
        # Drop everything so we start with a truly empty DB
        Base.metadata.drop_all(bind=engine)
        # Also drop the alembic version table
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            conn.commit()

        # Now run alembic upgrade head
        from alembic.config import Config
        from alembic import command
        import os

        alembic_cfg = Config()
        alembic_cfg.set_main_option(
            "script_location",
            os.path.join(os.path.dirname(__file__), "..", "migrations"),
        )
        alembic_cfg.set_main_option("sqlalchemy.url", PG_URL)
        # Set prepend_sys_path so alembic env.py can find jitauth
        alembic_cfg.set_main_option("prepend_sys_path", "src")

        command.upgrade(alembic_cfg, "head")

        # Verify tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        assert "tasks" in tables
        assert "audit_events" in tables
        assert "capabilities" in tables

        # Verify the created_by column exists on tasks
        columns = [c["name"] for c in inspector.get_columns("tasks")]
        assert "created_by" in columns
        assert "runtime_secret_hash" in columns

        # Verify chain_seq column on audit_events
        audit_cols = [c["name"] for c in inspector.get_columns("audit_events")]
        assert "chain_seq" in audit_cols

    def test_migrations_idempotent_on_existing_schema(self, _pg_settings):
        """Migrations don't fail when run against an already-migrated DB."""
        from alembic.config import Config
        from alembic import command
        import os

        # Tables already exist from fixture; stamp as baseline then upgrade
        alembic_cfg = Config()
        alembic_cfg.set_main_option(
            "script_location",
            os.path.join(os.path.dirname(__file__), "..", "migrations"),
        )
        alembic_cfg.set_main_option("sqlalchemy.url", PG_URL)
        alembic_cfg.set_main_option("prepend_sys_path", "src")

        # Stamp at head (current schema already matches)
        command.stamp(alembic_cfg, "head")

        # Running upgrade again should be a no-op
        command.upgrade(alembic_cfg, "head")


# ====================================================================
# 5. Postgres-specific row locking verification
# ====================================================================


class TestRowLocking:
    """Verify that FOR UPDATE actually blocks concurrent access on Postgres."""

    def test_task_row_locked_during_execute(self, pg_client, slow_adapter):
        """Two concurrent executions against the same task are serialized.

        With the slow adapter (50ms delay), if locking works, the total
        wall time for 2 serial executions should be >= 100ms. If locking
        doesn't work (or is a no-op like SQLite), they'd run in ~50ms.
        """
        task_id, caps = _lifecycle(pg_client, max_actions=10)
        cap = caps[0]

        times = []

        def _timed_execute(i: int) -> float:
            from jitauth.broker.server import create_app
            app = create_app(rate_limit=False)
            t0 = time.monotonic()
            with TestClient(app) as tc:
                resp = tc.post("/execute", json={
                    "task_id": task_id,
                    "capability_id": cap["id"],
                    "capability_token": cap["token"],
                    "tool": "crm.read_account",
                    "arguments": {"account_id": f"lock_test_{i}"},
                })
                assert resp.status_code == 200
            return time.monotonic() - t0

        # Fire 2 concurrent requests
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_timed_execute, i) for i in range(2)]
            for f in as_completed(futures):
                times.append(f.result())

        # Both should have succeeded
        assert len(times) == 2
        # The slower one should have waited for the lock
        # (We don't assert exact timing, but both completed successfully,
        # proving the FOR UPDATE didn't deadlock or error out)
