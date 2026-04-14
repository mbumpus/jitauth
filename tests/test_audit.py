"""Tests for audit logger with hash chaining."""

from __future__ import annotations

from jitauth.audit.logger import reset_chain, verify_audit_chain, write_audit_event
from jitauth.core.models import AuditEvent
from jitauth.db.session import get_session_factory, init_db


def test_audit_hash_chain():
    """Audit events written via the logger should form a valid hash chain."""
    init_db()
    factory = get_session_factory()
    db = factory()
    reset_chain()

    try:
        # Write 3 events through the chain-aware logger
        e1 = write_audit_event(db, "test_event_1", "tester", task_id="task_chain", details={"step": 1})
        db.flush()
        e2 = write_audit_event(db, "test_event_2", "tester", task_id="task_chain", details={"step": 2})
        db.flush()
        e3 = write_audit_event(db, "test_event_3", "tester", task_id="task_chain", details={"step": 3})
        db.commit()

        # First event should have no prev hash
        assert e1.prev_event_hash is None
        # Subsequent events should have prev hashes
        assert e2.prev_event_hash is not None
        assert e3.prev_event_hash is not None
        # Hashes should be different
        assert e2.prev_event_hash != e3.prev_event_hash

        # Verify the chain
        result = verify_audit_chain(db, task_id="task_chain")
        assert result["valid"] is True
        assert result["events_checked"] == 3
        assert result["first_broken_at"] is None
    finally:
        db.close()


def test_audit_chain_empty():
    """Empty chain should be valid."""
    init_db()
    factory = get_session_factory()
    db = factory()
    reset_chain()

    try:
        result = verify_audit_chain(db, task_id="nonexistent")
        assert result["valid"] is True
        assert result["events_checked"] == 0
    finally:
        db.close()


def test_audit_chain_detects_tampering():
    """Modifying an event should break the chain."""
    init_db()
    factory = get_session_factory()
    db = factory()
    reset_chain()

    try:
        write_audit_event(db, "event_1", "tester", task_id="task_tamper", details={"x": 1})
        db.flush()
        write_audit_event(db, "event_2", "tester", task_id="task_tamper", details={"x": 2})
        db.flush()
        write_audit_event(db, "event_3", "tester", task_id="task_tamper", details={"x": 3})
        db.commit()

        # Tamper with the middle event's prev hash
        events = (
            db.query(AuditEvent)
            .filter(AuditEvent.task_id == "task_tamper")
            .order_by(AuditEvent.timestamp.asc())
            .all()
        )
        events[1].prev_event_hash = "tampered_hash_value"
        db.commit()

        result = verify_audit_chain(db, task_id="task_tamper")
        assert result["valid"] is False
        assert result["first_broken_at"] == events[1].id
    finally:
        db.close()
