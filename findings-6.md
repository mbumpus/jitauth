# Follow-Up Review Against `findings-5.md` and `v0.5.0`

Date: 2026-04-14

Verification:

- Reviewed the `0.5.0` changelog claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `157 passed, 1 warning` via `.venv/bin/pytest -q`
- Sanity-checked the new Alembic path and mixed pre/post-migration audit-chain behavior locally

## Findings

### High: `v0.5.0` breaks audit-chain verification on upgraded deployments with existing audit rows

Relevant code:

- the migration adds `audit_events.chain_seq` as nullable, but does not backfill existing rows: [001_v050_schema_hardening.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/versions/001_v050_schema_hardening.py:32)
- new writes derive ordering only from `chain_seq`: [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:62)
- verification now prefers non-null `chain_seq` rows before legacy `NULL` rows: [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:141)

Why this is a real break:

- on a pre-`0.5.0` deployment, all existing audit rows will have `chain_seq = NULL`
- after upgrade, newly written events get `chain_seq` values such as `1`, `2`, ...
- `verify_audit_chain()` now sorts those new rows ahead of the legacy `NULL` rows, even though the hash chain was originally built in chronological order
- the next-write path also chooses the "latest" row by `chain_seq` only, so immediately after migration it can anchor the new chain to an arbitrary legacy row rather than the actual latest audit event

Local repro:

- with two legacy rows (`chain_seq = NULL`) followed by one post-upgrade row (`chain_seq = 1`), `verify_audit_chain()` returned `{'valid': False, 'events_checked': 1, ...}` in this workspace

Impact:

- the new migration path is not safe for existing deployments that already have audit history
- audit verification can false-fail after upgrade, and new chain continuation can be based on the wrong predecessor

What would close it:

- backfill `chain_seq` for existing audit rows during migration in original chain order, or
- keep legacy rows ordered ahead of new rows until backfill is complete, and
- make `_get_previous_hash_locked()` fall back to the real latest legacy event when no `chain_seq` has been assigned yet

### Medium: the shipped Alembic baseline does not bootstrap a fresh database

Relevant code:

- the only migration revision is an alter-only migration over existing tables: [001_v050_schema_hardening.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/versions/001_v050_schema_hardening.py:19)
- there is no initial schema-creation revision before it: [migrations](/Users/mikebumpus/Documents/GitHub/jitauth/migrations)

Observed behavior:

- running `alembic upgrade head` against a fresh SQLite database in this repo failed with `sqlalchemy.exc.NoSuchTableError: tasks`

Impact:

- the new Alembic infrastructure works as an upgrade patch over an existing schema, but not as a standalone schema bootstrap path
- operators who reasonably expect Alembic to initialize a fresh deployment will hit a hard failure

What would close it:

- add an initial baseline migration that creates the schema, or
- document and enforce a separate bootstrap/stamp flow explicitly

## Closed From `findings-5.md`

These items are genuinely fixed:

- `verify_secret()` now uses constant-time comparison in both the legacy SHA-256 and scrypt paths: [crypto.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/core/crypto.py:55)
- Alembic infrastructure now exists in the repo: [alembic.ini](/Users/mikebumpus/Documents/GitHub/jitauth/alembic.ini:1), [env.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/env.py:1)
- the suite result is accurately reported as `157 passed, 1 warning`

## Re-Score

**A-**

The repo remains strong overall. The v0.5.0 work closes the cryptographic comparison issue and adds real migration infrastructure, and the implementation is substantially closer to production shape than the earlier revisions.

I am not moving it higher because the new upgrade path has a correctness bug around legacy audit history, and the Alembic path is not yet a complete bootstrap story.

## Bottom Line

The `findings-5.md` items are not simply still open in their old form; most are addressed. The problem is that `v0.5.0` introduces a new migration/ordering bug for pre-existing audit data. If this goes back to the coding agent, the next fixes should be:

1. backfill `audit_events.chain_seq` during migration and preserve legacy chain order
2. make the post-migration "find latest event" logic safe when legacy `NULL chain_seq` rows still exist
3. add a real baseline Alembic revision, or clearly separate bootstrap from upgrade
