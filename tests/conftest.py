"""Shared test fixtures."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from jitauth.config.settings import Settings, override_settings
from jitauth.db.session import init_db, reset_engine
from jitauth.broker.server import create_app


@pytest.fixture(autouse=True)
def _test_settings(tmp_path):
    """Use a file-based temp SQLite DB and temp policy dir for each test."""
    db_path = tmp_path / "test.db"
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()

    # Write default test policy
    (policy_dir / "default.yaml").write_text("""
rules:
  - name: deny-destructive
    priority: 10
    match:
      risk_tier: "tier_4"
    effect: deny
    reason: "Destructive actions denied"

  - name: require-approval-send
    priority: 30
    match:
      action_class: "send"
    effect: require_approval
    reason: "Send requires approval"

  - name: allow-reads
    priority: 50
    match:
      action_class: "read"
      risk_tier: ["tier_0", "tier_1"]
    effect: allow
    scope: minimal

  - name: allow-bounded-writes
    priority: 60
    match:
      action_class: "write"
      risk_tier: "tier_2"
    effect: allow
    scope: minimal
""")

    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        policy_dir=str(policy_dir),
        jwt_secret="test-secret-that-is-at-least-32-bytes-long-for-hs256",
        debug=False,
    )
    override_settings(settings)
    reset_engine()

    # Reload policy rules for each test
    from jitauth.policy.engine import reload_rules
    reload_rules()

    yield

    reset_engine()


@pytest.fixture
def client(_test_settings):
    """FastAPI test client with rate limiting disabled."""
    app = create_app(rate_limit=False)
    # init_db is called in lifespan, but TestClient triggers lifespan for us
    with TestClient(app) as c:
        yield c
