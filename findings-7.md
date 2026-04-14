# Follow-Up Review Against `findings-6.md` and `v0.5.1`

Date: 2026-04-14

Verification:

- Reviewed the `0.5.1` changelog claims against the implementation
- Re-ran the full suite in the local Python 3.11 virtualenv
- Result: `157 passed, 1 warning` via `.venv/bin/pytest -q`
- Verified fresh-database Alembic bootstrap locally with `alembic upgrade head`
- Verified legacy upgrade path locally with `alembic stamp 000 && alembic upgrade head` against a DB containing pre-existing audit rows

## Findings

No new blocking findings from the `findings-6.md` backlog.

The two open items from the previous round are substantively closed:

- migration `001` now backfills `audit_events.chain_seq` for legacy rows in timestamp order, and the logger ordering is safe for mixed `NULL` / non-`NULL` `chain_seq` states: [001_v050_schema_hardening.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/versions/001_v050_schema_hardening.py:51), [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:67), [logger.py](/Users/mikebumpus/Documents/GitHub/jitauth/src/jitauth/audit/logger.py:153)
- Alembic now has a real baseline migration, and `alembic upgrade head` works on an empty database: [000_baseline_schema.py](/Users/mikebumpus/Documents/GitHub/jitauth/migrations/versions/000_baseline_schema.py:27)

Local upgrade-path verification matched the changelog:

- fresh DB: `alembic upgrade head` completed successfully
- legacy DB: after `stamp 000` then `upgrade head`, the legacy audit rows were assigned `chain_seq = 1, 2` in timestamp order and `verify_audit_chain()` returned valid

## Residual Note

The suite still emits one warning:

- `tests/test_tokens.py::TestVerifyToken::test_verify_wrong_secret` triggers `InsecureKeyLengthWarning` from the JWT library because the test uses a short HMAC key

I do not consider that an open product finding. It is test-only noise unless the same short key pattern appears in real deployment config.

## Re-Score

**A**

This round closes the migration correctness gap and the fresh-bootstrap gap. The repo now has:

- task/runtime binding with broker-enforced execution
- policy-constrained capability minting and scope enforcement
- approval narrowing that is monotonic
- value-based output redaction
- runtime-secret hashing with scrypt and constant-time verification
- audit chaining with DB-backed sequencing and an upgrade story that preserves legacy history
- working Alembic bootstrap and upgrade paths

## Bottom Line

The `findings-6.md` items are closed. At this point I would return this to the coding agent as an `A` implementation rather than an open-finding handoff. The remaining caution is operational, not architectural: keep production config disciplined, especially JWT secret length and database/backend behavior under real concurrency.
