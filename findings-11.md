# Follow-Up Review Against `v0.7.1`

Date: 2026-04-15

Verification:

- Reviewed the `0.7.1` changelog claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `190 passed, 1 warning` via `.venv/bin/pytest -q`

## Findings

### Medium: requester identity is still caller-supplied data, not broker-authenticated identity

Relevant code:

- task creation still stores `requester_id` and `requester_auth_context` directly from request JSON: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:100)
- the new runtime binding only enforces `req.runtime_id == caller.caller_id` for non-operators: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:104)

Why this still matters:

- `created_by` is now trustworthy for “which authenticated caller created this task”
- `runtime_id` is now trustworthy for non-operator callers
- but `requester_id` remains an asserted field provided by the caller, not an authenticated identity derived by the broker

Impact:

- the system can now reliably answer “which runtime/API caller created this task”
- it still cannot independently authenticate “which end user requested this task” unless callers are separately trusted to assert that field correctly

What would close it:

- either explicitly document `requester_id` as delegated metadata supplied by a trusted runtime, or
- add a first-class caller/delegator model where authenticated caller identity and delegated requester identity are separately represented and policy-evaluable

### Medium: the updated README examples still conflict with the new runtime-identity enforcement

Relevant code and docs:

- runtime callers must use their own identity as `runtime_id`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:104)
- README auth example defines `sk-agent-key` as `runtime:agent-1`: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:29)
- README SDK example uses `api_key="sk-agent-key"` but `runtime_id="my-agent"`: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:45)
- README MCP example defines `sk-mcp-key` as `runtime:mcp-agent`, but the command does not pass `--runtime-id mcp-agent` and the CLI default is `mcp_runtime`: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:70), [cli.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/cli.py:46)

Why this matters:

- the code is enforcing the right thing
- the published examples now instruct users into an identity mismatch that will 403 under the default secure configuration
- the current tests verify option presence and wiring, but not the auth-enabled README flows end to end

What would close it:

- make the README examples use matching API-key identity and `runtime_id`, or
- have the SDK / MCP default `runtime_id` to the authenticated runtime identity when practical

### Low: README status line is stale after the `0.7.1` release

Relevant docs:

- README still says `v0.7.0` in the status section: [README.md](/Users/mikebumpus/Documents/GitHub/jitauth/README.md:242)

## Closed From `findings-10.md`

These items are substantively addressed:

- non-operator callers can no longer create tasks for arbitrary `runtime_id` values: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:107)
- `/execute` now enforces task ownership before gateway dispatch: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:473)
- legacy tasks with `created_by = NULL` now fail closed for runtime callers: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:63)
- the MCP CLI now really has `--api-key` and `JITAUTH_MCP_API_KEY` support: [cli.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/cli.py:48)

## Re-Score

**A**

`v0.7.1` closes the concrete security/control-plane gaps from `findings-10.md`. The remaining items are narrower:

- one trust-model clarification gap around delegated requester identity
- one documentation/example mismatch under the new runtime-binding rule

At this point the implementation itself is strong enough to land in the `A` range.

## Bottom Line

The `findings-10.md` backlog is closed. What remains is mostly polish and model clarity, not a blocker to public use:

1. clarify or harden the semantics of `requester_id` versus authenticated caller identity
2. fix the README examples so auth identity and `runtime_id` match
3. update the README status line to `v0.7.1`
