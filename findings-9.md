# Follow-Up Review Against `v0.6.0` "Bulletproof" Claims

Date: 2026-04-14

Verification:

- Reviewed the `0.6.0` changelog claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `171 passed, 1 warning` via `.venv/bin/pytest -q`

## Findings

### High: control-plane auth authenticates callers, but still does not bind broker actions to the authenticated identity

Relevant code:

- `create_task()` still trusts `requester_id`, `requester_auth_context`, and `runtime_id` from request JSON: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:62)
- execution requires an authenticated caller, but does not verify the caller’s role or identity against `task.runtime_id`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:409)
- generic task-management routes (`get_task`, `classify`, `policy-evaluate`, `capabilities`) allow any authenticated caller, with no task ownership check: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:109), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:120), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:149), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:266)
- auth only yields `role` and `caller_id`; there is no enforcement that a runtime caller can only create or execute tasks for itself: [auth.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/auth.py:31)

Why this is still a trust-boundary gap:

- any valid API key can still create a task on behalf of any arbitrary `requester_id`
- any valid API key can still choose any arbitrary `runtime_id` in task creation
- any authenticated caller can still read or advance any known task through large parts of the lifecycle
- the broker now authenticates “someone called”, but it still does not strongly enforce “this caller is the requester/runtime/operator authorized for this task”

Impact:

- the changelog statement “identity derived from auth not JSON” is only fully true for approval and revocation
- the main task/requester/runtime provenance still depends on caller-supplied JSON

What would close it:

- derive `requester_id` from authenticated context for human/operator flows, or explicitly separate “delegated requester” from authenticated caller
- enforce that runtime callers can only create/execute tasks for their own runtime identity
- require ownership or operator role for task lookup/classification/policy/capability routes

### High: the primary SDK and MCP client paths do not support the new default API-auth requirement

Relevant code:

- `Settings.require_api_auth` now defaults to `True`: [settings.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/config/settings.py:25)
- `JITAuthClient` has no API-key parameter and sends no `Authorization` header in `_get()` / `_post()`: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:177), [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:200)
- MCP integration instantiates that same SDK client without auth credentials: [mcp/server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/mcp/server.py:229)
- tests pass because the shared test fixture disables API auth (`require_api_auth=False`): [tests/conftest.py](/Users/mikebumpus/Documents/GitHub/jitauth/tests/conftest.py:59)

Why this matters:

- in the repo’s own default secure configuration, the public SDK path is not actually usable without out-of-band patching
- the MCP server path is likewise not wired for the new auth requirement
- this is not just a docs issue; it means the main integration surfaces lag the broker’s new default policy

Impact:

- `require_api_auth=True` breaks the advertised SDK/MCP flows
- the test suite does not currently exercise those paths under auth-enabled settings

What would close it:

- add API-key support to `JITAuthClient` and attach `Authorization: Bearer <api_key>` on every request
- plumb that through the MCP server constructor and CLI
- add auth-enabled SDK and MCP integration tests

### Medium: task-level total action-budget enforcement is not concurrency-safe

Relevant code:

- task budget is enforced by counting committed `ToolInvocation` rows before the new invocation is written: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:263)
- capability call counters are also incremented in-process without a locking read/compare/write boundary: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:255)

Why this matters:

- two concurrent executions on the same task can both observe `total_invocations < max_actions` and both proceed
- the same race exists for per-capability `calls_used`
- for “bulletproof” guarantees, these counters need the same concurrency discipline that audit chaining now has

What would close it:

- serialize budget checks at the DB boundary, or
- use atomic update conditions / row locks on task and capability counters

### Low: the public docs and examples still describe an unauthenticated broker flow

Relevant code:

- README quick start still says `jitauth serve` with no API-auth setup: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:17)
- README SDK example does not show how to configure bearer auth: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:27)

Why this matters:

- the repo now defaults to auth-enabled control-plane access
- the top-level docs still describe the pre-`0.6.0` operational model

## Closed From `findings-8.md`

These `findings-8.md` items are substantively addressed:

- broker endpoints now require auth dependencies, with operator gating on approval/revocation/audit: [auth.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/auth.py:47), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:232), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:513), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:548)
- startup now rejects weak/default JWT secrets: [server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/server.py:47)
- request-size limiting now enforces while streaming the body: [middleware.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/middleware.py:79)
- unsupported policy effects now deny with explicit audit: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:181)
- SDK now auto-generates `runtime_secret` by default: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:276)
- the suite result matches the changelog claim: `171 passed, 1 warning`

## Re-Score

**A-**

This is still a strong system, and `v0.6.0` materially improves the public-deployment posture. But I would not call it “bulletproof” yet, because the new auth layer is not fully identity-binding and the repo’s own SDK/MCP integration paths are not wired for the new default security requirement.

## Bottom Line

`v0.6.0` closes most of the `findings-8.md` hardening list, but it leaves a last mile:

1. bind task/request/runtime identity to the authenticated caller, not just to request JSON
2. add API-key support to the SDK and MCP paths
3. make task and capability budgets concurrency-safe

Those are the remaining gaps between “strong public release” and “bulletproof broker.”
