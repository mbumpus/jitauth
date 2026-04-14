"""Audit event logger with optional hash chaining.

Each audit event can include a SHA-256 hash of the previous event,
creating a lightweight tamper-evident chain. This isn't a blockchain —
it's a simple integrity check that makes silent log modification detectable.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from jitauth.config.settings import get_settings
from jitauth.core.id import new_id
from jitauth.core.models import AuditEvent

logger = logging.getLogger(__name__)

_last_event_hash: str | None = None


def write_audit_event(
    db: Session,
    event_type: str,
    actor: str,
    task_id: str | None = None,
    details: dict | None = None,
) -> AuditEvent:
    """Write an audit event with optional hash chaining.

    Args:
        db: Database session
        event_type: Event type string (e.g., "task_created", "tool_invoked")
        actor: Who/what caused this event
        task_id: Associated task ID (if any)
        details: Event details as a dict

    Returns:
        The created AuditEvent
    """
    global _last_event_hash
    settings = get_settings()

    prev_hash = None
    if settings.audit_hash_chain:
        prev_hash = _last_event_hash

    event = AuditEvent(
        id=new_id(),
        task_id=task_id,
        event_type=event_type,
        actor=actor,
        details=json.dumps(details) if details else None,
        prev_event_hash=prev_hash,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(event)

    # Compute hash of this event for the chain
    if settings.audit_hash_chain:
        _last_event_hash = _hash_event(event)

    return event


def verify_audit_chain(db: Session, task_id: str | None = None) -> dict:
    """Verify the integrity of the audit chain.

    Returns:
        {
            "valid": bool,
            "events_checked": int,
            "first_broken_at": str | None,  # event ID where chain breaks
        }
    """
    q = db.query(AuditEvent).order_by(AuditEvent.timestamp.asc())
    if task_id:
        q = q.filter(AuditEvent.task_id == task_id)

    events = q.all()
    if not events:
        return {"valid": True, "events_checked": 0, "first_broken_at": None}

    prev_hash = None
    for event in events:
        if event.prev_event_hash is not None and event.prev_event_hash != prev_hash:
            return {
                "valid": False,
                "events_checked": events.index(event) + 1,
                "first_broken_at": event.id,
            }
        prev_hash = _hash_event(event)

    return {"valid": True, "events_checked": len(events), "first_broken_at": None}


def _hash_event(event: AuditEvent) -> str:
    """Compute SHA-256 hash of an audit event's content."""
    # Normalize timestamp to naive UTC string for consistent hashing
    # (SQLite strips timezone info on round-trip)
    ts = event.timestamp
    if ts.tzinfo is not None:
        ts = ts.replace(tzinfo=None)
    parts = [event.id, event.task_id, event.event_type, event.actor, event.details, ts.isoformat()]
    content = "|".join(str(p) for p in parts)
    return hashlib.sha256(content.encode()).hexdigest()


def reset_chain() -> None:
    """Reset the hash chain. For testing."""
    global _last_event_hash
    _last_event_hash = None
