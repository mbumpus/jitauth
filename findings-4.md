# Follow-Up Review Against `findings-3.md`

Date: 2026-04-14

Verification:

- Reviewed the latest `CHANGELOG.md` claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `140 passed, 1 warning` via `.venv/bin/pytest -q`

## Re-Score

**B+**

This round closes the remaining items from `findings-3.md`. The code now has:

- monotonic scope intersection
- approval reductions that only narrow
- runtime-secret support in the broker and the primary SDK path
- a verified matching test count

The project is no longer carrying any open findings from `findings-3.md`.

## Findings-3 Status

### 1. Approval reductions widening scope

Status: **closed**

Verified in code:

- approval reduction now intersects with the already-computed effective scope rather than replacing it: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:325)
- narrowing is applied via `_intersect_scopes(effective_scope, system_reduction)`: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:332)

Verified in tests:

- widening attempt via approval payload is explicitly tested and rejected: [tests/test_findings2.py](/Users/mikebumpus/Documents/GitHub/jitauth/tests/test_findings2.py:202)

### 2. `_intersect_scopes()` not monotonic

Status: **closed**

Verified in code:

- no-overlap dict/list cases now produce empty intersections rather than falling back to policy scope: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:606)
- list-vs-list intersection is implemented: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:614)

Verified in tests:

- overlapping, no-overlap, `None`, and list/list cases are covered: [tests/test_findings2.py](/Users/mikebumpus/Documents/GitHub/jitauth/tests/test_findings2.py:158)

### 3. SDK does not expose `runtime_secret`

Status: **closed**

Verified in code:

- `JITAuthClient.task()` accepts `runtime_secret`: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:214)
- task creation sends it to `/tasks`: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:264)
- `TaskHandle` stores it and automatically includes it on `/execute`: [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:76), [client.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/client.py:129)
- `jitauth_tool` exposes and forwards it: [decorators.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/decorators.py:35), [decorators.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/sdk/decorators.py:77)

### 4. Test count mismatch

Status: **closed**

Verified result:

- current local run: `140 passed, 1 warning`

The changelog count now matches the executed suite.

## Residual Risks

These are not open items from `findings-3.md`, but they still keep me from scoring the project in the `A` range.

### 1. Audit hash chaining still depends on process-local state during live writes

Relevant code:

- chain continuity is restored on startup, but ongoing writes still use process-global `_last_event_hash`: [audit/logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:23), [audit/logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:64)

Why it matters:

- single-process correctness is much better now
- multi-process or horizontally scaled broker writes can still diverge unless chaining is made DB-serialized rather than memory-serialized

### 2. Runtime secret storage uses raw SHA-256 rather than a password KDF

Relevant code:

- task creation hashes the runtime secret with plain SHA-256: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:68)

Why it matters:

- if runtime secrets are always high-entropy random values, this is probably acceptable
- if operators ever choose lower-entropy values, this is weaker than a salted KDF-based design

### 3. List-scope enforcement still depends on a fixed set of resource-like argument names

Relevant code:

- list-scope enforcement only checks a hard-coded set of argument keys such as `account_id`, `contact_id`, `id`, etc.: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:417)

Why it matters:

- dict-shaped scopes are strong when policies specify exact fields
- list-shaped scopes remain somewhat convention-based and can miss nonstandard parameter names unless the adapter/policy author uses dict scopes

## Bottom Line

The `findings-3.md` issues are closed, and the current implementation is substantially more defensible than the earlier revisions. The broker now enforces a coherent combination of task binding, token verification, optional runtime authentication, monotonic scope narrowing, and audited lifecycle control. I would hand this back to the coding agent as a strong `B+` implementation with a short residual-risk list rather than an open-finding backlog.
