"""Base adapter interface for execution proxy."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterResult:
    """Result from a tool adapter execution."""

    success: bool
    result: dict | str | None = None
    error: str | None = None


@dataclass
class AdapterConfig:
    """Configuration for a tool adapter instance."""

    system_name: str
    adapter_type: str  # "http", "shell", "custom"
    config: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)
    redact_keys: set[str] = field(default_factory=set)  # Extra keys to redact for this system
    redact_result: bool = False  # If True, store "[REDACTED]" instead of full result
    resource_keys: set[str] = field(default_factory=set)  # Argument keys treated as resource identifiers for list-scope enforcement


class BaseAdapter(ABC):
    """Base class for all tool adapters.

    Adapters mediate between the TRSAA broker and downstream target systems.
    The adapter receives sanitized arguments and server-side credentials —
    the agent runtime never sees the credentials.
    """

    system_name: str = ""
    supported_actions: list[str] = []

    def __init__(self, config: AdapterConfig):
        self.config = config
        self.system_name = config.system_name

    @abstractmethod
    async def execute(
        self,
        action: str,
        arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Execute an action against the target system.

        Args:
            action: The action to perform (must be in supported_actions).
            arguments: Sanitized arguments from the runtime's tool call.
            credential: Server-side credentials injected by the broker.
                       Never exposed to the agent runtime.

        Returns:
            AdapterResult with success/failure and result data.
        """
        ...

    def validates_action(self, action: str) -> bool:
        """Check if this adapter supports the given action."""
        if not self.supported_actions:
            return True  # No restriction = supports all
        return action in self.supported_actions

    async def health_check(self) -> bool:
        """Check if the target system is reachable. Override in subclasses."""
        return True
