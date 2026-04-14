# Follow-Up Review Against `findings-4.md` and `v0.4.0`

Date: 2026-04-14

Verification:

- Reviewed `CHANGELOG.md` `0.4.0` claims against the current implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `157 passed, 1 warning` via `.venv/bin/pytest -q`

## Findings

### Medium: Audit chaining is still not transaction-safe under concurrent writers

Relevant code:

- previous hash is read with a plain latest-row query: [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:47)
- the new event is then created with that value and only later committed by the caller: [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:63)

Why this is still open:

- this removes the old process-local `_last_event_hash`, which is an improvement
- but it does not make the chain correct under concurrent multi-worker writes
- two sessions can still read the same latest event, both derive the same `prev_event_hash`, and then commit sibling events that fork the chain
- ordering is also based on `timestamp` rather than a DB-serialized sequence, so equal-time writes can remain ambiguous

Impact:

- the changelog statement that the chain is now "correct under multi-worker deployments" is overstated
- the implementation is restart-safe, but not yet concurrency-safe

What would close it:

- serialize chain writes in the database boundary, or
- derive chain order from a DB-owned monotonic sequence and lock/retry the read-then-insert path

### Medium: `v0.4.0` changes the persisted hash width but does not ship a migration path

Relevant code:

- `Task.runtime_secret_hash` is now widened to `String(130)`: [models.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/models.py:89)
- task creation now stores scrypt output in that field: [routes.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/broker/routes.py:65)
- the only built-in DB initialization path is `create_all()` and is explicitly marked dev/test only: [session.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/db/session.py:36)

Why this is still open:

- fresh databases are fine
- upgraded deployments need a real schema migration for the column-width change
- I did not find Alembic config or migration files in the repo, so an existing production database would not pick this up automatically

Impact:

- on a pre-`0.4.0` database, scrypt hashes can exceed the old `String(64)` width
- depending on the backing database, that can fail writes or truncate values and break runtime authentication

What would close it:

- ship an explicit migration widening `tasks.runtime_secret_hash`, and
- mention upgrade sequencing in the release notes

### Low: `verify_secret()` claims constant-time comparison but uses normal equality

Relevant code:

- the function comment says "Constant-time comparison", but the implementation is `dk == expected`: [crypto.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/crypto.py:77)

Why it matters:

- this is an authentication check on a secret-derived value
- Python byte equality is not the right primitive to claim constant-time behavior

What would close it:

- switch to `hmac.compare_digest(dk, expected)`

## Closed From `findings-4.md`

These hardening items are substantively addressed:

- process-local audit state is gone; writes now look to the database instead: [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:47)
- `runtime_secret` hashing now uses salted scrypt with legacy SHA-256 fallback: [crypto.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/crypto.py:22)
- per-adapter `resource_keys` now exist in config, load from YAML, and are used by scope enforcement: [base.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/base.py:20), [loader.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/config/loader.py:82), [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:423)
- `register_adapter()` now populates `_adapter_configs`, so enforcement sees the adapter config in the direct-registration path: [gateway.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/proxy/gateway.py:52)
- the changelog’s test-count claim is now accurate: `.venv/bin/pytest -q` => `157 passed, 1 warning`

## Re-Score

**A-**

This is now a strong prototype with a credible hardening trajectory, not a backlog-heavy security sketch. The v0.4.0 work materially improves runtime secret handling, scope enforcement ergonomics, and audit durability across restarts, and the test suite has expanded meaningfully.

I am not at `A` yet because two release-quality gaps remain: the audit chain is still not safe against concurrent writer races, and the persisted schema change does not appear to ship with a migration path for upgraded deployments.

## Bottom Line

The repo no longer has open items from `findings-4.md` as originally written, but `v0.4.0` still has a short residual list before I would call it fully production-hardened. If this goes back to the coding agent, the next fixes should be:

1. make audit-chain writes DB-serialized rather than "query latest then insert"
2. add a real migration for `tasks.runtime_secret_hash`
3. switch secret verification to `compare_digest`
