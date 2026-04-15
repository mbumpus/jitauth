# Findings-13

## Verified Baseline

- `.venv/bin/pytest -q` => `190 passed, 1 skipped, 1 warning`
- Verified in-repo additions:
  - [tests/test_postgres.py](/Users/mikebumpus/Documents/GitHub/jitauth/tests/test_postgres.py)
  - [docker-compose.test.yaml](/Users/mikebumpus/Documents/GitHub/jitauth/docker-compose.test.yaml)
  - [Makefile](/Users/mikebumpus/Documents/GitHub/jitauth/Makefile)
  - Postgres pytest marker in [pyproject.toml](/Users/mikebumpus/Documents/GitHub/jitauth/pyproject.toml)

I could not execute the live Postgres suite in this environment because `docker` is not installed here, so the review below combines executed SQLite-suite verification with static review of the new Postgres matrix.

## Findings

### Medium

1. **The new Postgres matrix overstates concurrent `chain_seq` coverage.**
   [tests/test_postgres.py](/Users/mikebumpus/Documents/GitHub/jitauth/tests/test_postgres.py) says `test_chain_seq_is_unique` covers "concurrent writes", but the test body creates tasks serially with `for i in range(3): _lifecycle(pg_client)` at lines 350-352. The concurrent task test above it verifies global hash-chain validity, but not `chain_seq` uniqueness under concurrent writers. That leaves the exact race this matrix is meant to harden only partially tested.

### Low

2. **`make test-postgres` does not guarantee cleanup after a failing run.**
   [Makefile](/Users/mikebumpus/Documents/GitHub/jitauth/Makefile) defines `test-postgres` as `test-postgres-up test-postgres-run test-postgres-down` at line 34. In `make`, if `test-postgres-run` fails, `test-postgres-down` will not execute, leaving the test Postgres container and volume running. This is an operational footgun for local iteration and CI debugging rather than a product issue.

## Updated Score

`A-`

The core solution still looks strong. `v0.8.0` improves confidence by adding a real Postgres path, but this round does not fully prove every concurrency property it claims, and I could not independently execute the live Postgres suite from this machine.

## Suggested Follow-Ups

1. Make `test_chain_seq_is_unique` actually concurrent, or rename it to match what it currently proves.
2. Change `make test-postgres` to always tear down, even on failure.
   One pragmatic pattern is a single shell recipe with a trap, or a small script that does `up -> run -> down` in `finally`-style cleanup.
