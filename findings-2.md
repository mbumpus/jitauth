# Follow-Up Review Against `findings.md`

Date: 2026-04-14

Verification:

- Reviewed `CHANGELOG.md` against the current codebase
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `117 passed, 1 warning` via `.venv/bin/pytest -q`

## Re-Score

**C**

The repository is materially improved from the original `D`. Several important correctness and enforcement gaps were actually fixed: token timestamps, task-capability binding, JWT verification on execute, idempotency scoping, decorator broker enforcement, audit writes on the live path, lifecycle endpoints, and the missing `runtime_id` audit filter.

It still falls short of a trusted TRSAA enforcement boundary because a few core guarantees remain incomplete: runtime binding is still effectively bearer-token based, policy-derived minimum scope is still not enforced, and the audit-chain story is still weaker than the changelog claims.

## Remaining Open Findings

### 1. High: execution is still not bound to an authenticated runtime, only to possession of a valid bearer token

Relevant code:

- `ExecuteRequest` includes `task_id`, `capability_id`, and `capability_token`, but no authenticated runtime identity or caller attestation: `src/jitauth/core/schemas.py:121-129`
- The gateway verifies token claims only against the request and DB record: `src/jitauth/proxy/gateway.py:135-182`

Impact:

- Any caller that obtains a valid `capability_token` plus `capability_id` can replay the capability until expiry or revocation.
- The `runtime_id` claim is checked for consistency with the database record, but there is still no verified caller identity to compare it against.

Why this remains open from the original review:

- The code is better than before, but authority still attaches to possession of the signed artifact, not to a provably authenticated runtime session.

### 2. High: policy-derived scope is still not used when minting or enforcing capabilities

Relevant code:

- The policy engine now returns per-action `scope` data: `src/jitauth/policy/engine.py:91-99`, `src/jitauth/policy/engine.py:142-148`
- `request_capabilities()` ignores policy scope and instead builds capability scope from caller-supplied `TaskAction.resource_scope`, then optionally overrides it with approval reduction: `src/jitauth/broker/routes.py:275-299`
- Gateway scope enforcement only validates against `cap.resource_scope_parsed`: `src/jitauth/proxy/gateway.py:355-414`

Impact:

- Minimum-necessary scope is still not broker-derived from policy.
- Least privilege is still heavily shaped by what the requester put into the task object, not what policy computed should be allowed.

Changelog check:

- The changelog’s “Resource scope enforcement” entry is directionally true, but incomplete relative to the original finding. Scope is enforced only after minting, and the minted scope still does not come from policy output.

### 3. Medium: audit chain initialization on startup is claimed, but not wired

Relevant code:

- `initialize_chain()` exists: `src/jitauth/audit/logger.py:26-42`
- Broker startup does not call it: `src/jitauth/broker/server.py:60-65`

Impact:

- After a restart, `_last_event_hash` is not restored from the database.
- Audit continuity still depends on in-process state rather than startup reconstruction.

Changelog check:

- `CHANGELOG.md` claims “Audit hash chain initialization from DB on startup,” but that is not implemented in the broker lifespan path.

### 4. Medium: task-scoped audit verification is logically incorrect for interleaved tasks

Relevant code:

- `write_audit_event()` creates a single global chain using `_last_event_hash`: `src/jitauth/audit/logger.py:64-85`
- `verify_audit_chain(task_id=...)` filters events by task before verifying that chain: `src/jitauth/audit/logger.py:89-117`

Impact:

- If events from different tasks are interleaved, `/audit/verify?task_id=...` can report a broken chain even when the global chain is valid.
- The endpoint therefore over-promises per-task integrity verification.

Observed repro:

- With alternating events for `task1`, `task2`, `task1`, the global chain verifies as valid, while `verify_audit_chain(task_id="task1")` reports invalid because the second `task1` event correctly points to the previous global event from `task2`.

### 5. Medium: broker startup adapter loading bypasses env-var resolution and duplicates loader logic

Relevant code:

- Startup path reads raw adapter credentials directly from YAML: `src/jitauth/broker/server.py:47-55`
- The dedicated loader resolves `${ENV_VAR}` placeholders before registering configs: `src/jitauth/config/loader.py:78-86`

Impact:

- `jitauth serve` can load literal placeholder strings like `${JITAUTH_CRM_TOKEN}` into adapter credentials.
- The project now has two different adapter-loading code paths with different behavior.

Changelog check:

- The changelog’s startup-loading claim is only partially complete. Startup loading exists, but it does not use the more correct loader already present in the codebase.

### 6. Medium: result sanitization is still key-name based and does not stop secret values in normal fields or raw text outputs

Relevant code:

- Returned results are sanitized only by recursively redacting sensitive key names: `src/jitauth/proxy/gateway.py:288-293`, `src/jitauth/proxy/gateway.py:422-443`
- Shell adapter returns raw `stdout` and `stderr` strings: `src/jitauth/proxy/adapters/shell.py:145-160`
- HTTP adapter can return raw string response bodies when JSON parsing fails: `src/jitauth/proxy/adapters/http.py:136-165`

Impact:

- Secret values echoed under ordinary field names, or emitted in shell/stdout/plain-text HTTP bodies, still pass through to the runtime and to stored invocation summaries.

Changelog check:

- The “Gateway sanitizes both stored audit results and runtime-returned results” claim is only partially true. The implementation redacts by field name, not by detected secret content.

## Resolved Since `findings.md`

These original issues appear meaningfully addressed in code:

- JWT timestamp bug fixed via UTC normalization before token minting
- `/execute` now enforces `task_id == capability.task_id`
- `/execute` now requires and verifies `capability_token`
- idempotency is scoped to `task_id + capability_id + idempotency_key`
- SDK decorator now executes through the broker
- runtime-based audit filtering is implemented
- lifecycle now supports explicit `complete` and `fail`
- route and gateway audit writes now go through the chain-aware audit writer
- `verify_audit_chain()` no longer uses the O(n²) `events.index(event)` pattern

## Changelog Accuracy Summary

Mostly accurate:

- per-action policy evaluation
- capability token verification
- task-capability binding
- idempotency scoping
- decorator broker routing
- lifecycle endpoints
- audit write-path migration

Overstated or incomplete:

- audit chain initialization from DB on startup
- resource scope enforcement as a full closure of the original least-privilege finding
- result sanitization as a full closure of the original secret-echo concern
- startup adapter loading, because the new path skips env-var resolution

## Bottom Line

The current codebase is a stronger and more coherent prototype than the version reviewed in `findings.md`, and the full suite is green. The biggest remaining gap is that the system still does not authenticate the executing runtime itself; it authenticates possession of a signed capability token. The second major gap is that policy still does not derive and enforce the effective minimum scope. Until those two are fixed, plus the audit-chain continuity issues, I would not score this higher than `C`.
