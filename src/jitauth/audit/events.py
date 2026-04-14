"""Audit event type constants."""

# Task lifecycle
TASK_CREATED = "task_created"
TASK_CLASSIFIED = "task_classified"
TASK_COMPLETED = "task_completed"
TASK_FAILED = "task_failed"

# Policy
POLICY_EVALUATED = "policy_evaluated"

# Approval
TASK_APPROVAL = "task_approval"

# Capabilities
CAPABILITIES_MINTED = "capabilities_minted"
CAPABILITY_EXPIRED = "capability_expired"
CAPABILITY_REVOKED = "capability_revoked"

# Execution
TOOL_INVOKED = "tool_invoked"
TOOL_RESULT = "tool_result"

# System
BROKER_STARTED = "broker_started"
ADAPTER_REGISTERED = "adapter_registered"
POLICY_RELOADED = "policy_reloaded"
