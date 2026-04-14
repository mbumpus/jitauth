"""Typed accessors for JSON text-blob columns.

Policy-critical fields like allowed_actions, resource_scope, and
reduced_scope are stored as JSON text in the database. Rather than
scattering json.loads/json.dumps across the codebase, these helpers
provide a single, type-safe access layer.

Usage on a model:

    class Capability(Base):
        allowed_actions: Mapped[str] = mapped_column(Text)

        @property
        def allowed_actions_list(self) -> list[str]:
            return parse_json_list(self.allowed_actions)

        @allowed_actions_list.setter
        def allowed_actions_list(self, value: list[str]) -> None:
            self.allowed_actions = dump_json(value)
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_json(raw: str | None, fallback: Any = None) -> Any:
    """Parse a JSON text blob, returning fallback on failure."""
    if raw is None:
        return fallback
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse JSON field: %r", raw[:100] if raw else raw)
        return fallback


def parse_json_list(raw: str | None) -> list[str]:
    """Parse a JSON text blob expected to be a list of strings."""
    result = parse_json(raw, fallback=[])
    if not isinstance(result, list):
        return []
    return [str(item) for item in result]


def parse_json_dict(raw: str | None) -> dict[str, Any]:
    """Parse a JSON text blob expected to be a dict."""
    result = parse_json(raw, fallback={})
    if not isinstance(result, dict):
        return {}
    return result


def dump_json(value: Any) -> str:
    """Serialize a value to a JSON string for storage."""
    return json.dumps(value, separators=(",", ":"))


def dump_json_or_none(value: Any) -> str | None:
    """Serialize a value to JSON, returning None if the value is None/empty."""
    if value is None:
        return None
    if isinstance(value, (list, dict)) and not value:
        return None
    return dump_json(value)
