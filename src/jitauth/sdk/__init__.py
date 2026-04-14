"""JITAuth SDK — client library for agent framework integration."""

from jitauth.sdk.client import (
    ApprovalRequiredError,
    CapabilityError,
    ExecutionError,
    JITAuthClient,
    JITAuthError,
    TaskDeniedError,
    TaskHandle,
)

__all__ = [
    "JITAuthClient",
    "JITAuthError",
    "TaskDeniedError",
    "ApprovalRequiredError",
    "CapabilityError",
    "ExecutionError",
    "TaskHandle",
]
