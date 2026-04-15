# Follow-Up Review Against `v0.7.0`

Date: 2026-04-15

Verification:

- Reviewed the `0.7.0` changelog claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `185 passed, 1 warning` via `.venv/bin/pytest -q`

## Findings

### High: task/request/runtime identity is still not fully bound to the authenticated caller

Relevant code:

- task creation still trusts `requester_id`, `requester_auth_context`, and `runtime_id` from request JSON: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:85)
- the new ownership model records `created_by=caller.caller_id`, but that is separate from `runtime_id`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:104)
- `/execute` requires an authenticated caller but does not use that caller to enforce runtime identity or task ownership: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:441)

Why this is still open:

- a runtime caller can still create a task claiming any arbitrary `runtime_id`
- a caller can still assert any `requester_id` string they want in the task object
- the new ownership control protects “who created this task in JITAuth”, but it still does not make `runtime_id` or `requester_id` trustworthy broker-derived identities

Impact:

- the changelog claim is accurate for task ownership, but not for full identity binding
- audit and policy can now trust `created_by`; they still cannot fully trust `requester_id` or `runtime_id` as authenticated facts

What would close it:

- derive `runtime_id` from authenticated runtime identity, or validate it matches the authenticated caller
- explicitly separate authenticated caller from delegated requester if delegation is intended
- use caller identity in `/execute` to enforce runtime ownership, not just bearer presence

### Medium: legacy tasks from upgraded deployments still bypass ownership enforcement

Relevant code:

- migration `002` only adds `tasks.created_by` and leaves existing rows `NULL`: [002_v070_task_ownership.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/versions/002_v070_task_ownership.py:26)
- ownership enforcement only denies when `task.created_by` is non-null and mismatched: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:50)

Observed behavior:

- with `task.created_by = NULL`, `_enforce_task_ownership()` allows a runtime caller through
- I verified this directly in this workspace by calling `_enforce_task_ownership()` with a runtime caller and a mock task whose `created_by` was `None`; it returned without error

Impact:

- existing tasks in upgraded deployments remain accessible to any runtime caller until they are recreated or otherwise backfilled
- that weakens the new ownership guarantee exactly where operators are most likely to rely on migration safety

What would close it:

- backfill `created_by` during migration where possible, or
- fail closed for runtime callers on `NULL created_by` tasks and reserve legacy-task access to operators only

### Medium: the documented MCP CLI flow is still broken under auth-enabled defaults

Relevant code:

- README now documents `jitauth mcp-serve --api-key sk-mcp-key`: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:70)
- `create_mcp_server()` does accept `api_key`: [mcp/server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/mcp/server.py:36)
- but the CLI `mcp-serve` command still has no `--api-key` option and never passes one through: [cli.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/cli.py:41)

Why this matters:

- the programmatic MCP path is wired correctly
- the advertised CLI path is not
- under the default `require_api_auth=True`, the README command line cannot work as documented

What would close it:

- add `--api-key` to `jitauth mcp-serve`, or
- document the env-based alternative explicitly if CLI injection is not desired

## Closed From `findings-9.md`

These items are substantively addressed:

- SDK now sends bearer auth when `api_key` is configured: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:177)
- programmatic MCP integration now passes `api_key` through to the SDK client: [mcp/server.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/mcp/server.py:231)
- task ownership checks now protect `get`, `classify`, `policy-evaluate`, and `capabilities` for non-operators: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:137), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:149), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:179), [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:297)
- capability and task rows are now locked with `FOR UPDATE` before budget checks: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:162), [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:181)
- README has been updated substantially for the auth-enabled model

## Re-Score

**A-**

`v0.7.0` is another strong increment. The SDK path is materially improved, ownership checks exist, and the budget logic is more defensible under concurrency. But I would not move this to a clean `A` yet because the identity-binding story is still incomplete, upgraded deployments still have a legacy-task ownership hole, and the documented MCP CLI flow does not match the actual CLI.

## Bottom Line

The repo is close. The remaining work is narrow and concrete:

1. bind `runtime_id` and delegated requester semantics to authenticated identity
2. close the `NULL created_by` legacy-task hole for upgraded deployments
3. make `mcp-serve --api-key` real, or fix the docs
