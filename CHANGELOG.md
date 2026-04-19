# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-04-15

### Fixed
- **Concurrent chain_seq test** (Finding-13 #1): replaced serial `test_chain_seq_is_unique` with `test_chain_seq_unique_under_concurrent_writes` — fires 8 concurrent task-creation requests via `ThreadPoolExecutor` with per-thread `TestClient` instances, then verifies all `chain_seq` values are unique and monotonically increasing. This validates the `FOR UPDATE` serialization actually holds under real concurrency.
- **Makefile cleanup on failure** (Finding-13 #2): `make test-postgres` now always tears down the Docker Postgres container even if the test run fails, using a trap-style `rc` capture pattern instead of a simple prerequisite chain.

## [0.8.0] - 2026-04-15

### Added
- **Postgres integration & concurrency test suite** (`tests/test_postgres.py`): 9 tests covering concurrent budget enforcement, audit chain integrity under concurrency, Alembic migration validation, and row-locking verification — all against a real Postgres instance. Skipped automatically when `JITAUTH_TEST_DATABASE_URL` is unset.
- `docker-compose.test.yaml`: RAM-backed Postgres 16 for fast test runs (port 5433)
- `Makefile` with `test`, `test-postgres`, `test-all`, and `lint` targets
- `postgres` pytest marker registered in `pyproject.toml`
- `psycopg2-binary` in `[project.optional-dependencies.postgres]` for Postgres driver support

### Test coverage
- **Concurrent budget enforcement**: fires N concurrent `/execute` calls against budget M < N; verifies at most M succeed (validates `SELECT … FOR UPDATE` serialization)
- **Concurrent audit chain**: creates tasks concurrently; verifies `chain_seq` uniqueness and hash chain integrity
- **Alembic on Postgres**: `upgrade head` on empty DB, idempotent re-run on migrated DB
- **Row locking**: verifies `FOR UPDATE` doesn't deadlock under concurrent access

## [0.7.2] - 2026-04-15

### Changed
- **requester_id trust model documented** (Finding-11 #1): `requester_id` is explicitly documented as caller-supplied metadata that the broker records but does not authenticate. Upstream identity verification is the caller's responsibility. Field description added to `TaskCreate` schema and README Authentication section.
- **README examples match runtime-binding rule** (Finding-11 #2): API key example uses `runtime:my-agent` matching the SDK's `runtime_id="my-agent"`. MCP example includes `--runtime-id mcp-agent` to match the key's caller_id. Auth section explains why runtime_id must match caller_id.
- `runtime_id` field description in `TaskCreate` schema documents the non-operator binding enforcement
- README status line updated to v0.7.2

## [0.7.1] - 2026-04-15

### Security
- **Runtime identity binding on task creation** (Finding-10 #1): Non-operator callers must use their own `caller_id` as the `runtime_id` when creating tasks. This prevents a runtime from impersonating another runtime. Operators can still specify any identity.
- **Execute enforces task ownership** (Finding-10 #1): The `/execute` endpoint now verifies the authenticated caller owns the task before dispatching to the gateway. A runtime cannot execute against another runtime's task.
- **Legacy tasks fail closed** (Finding-10 #2): Tasks with `NULL` `created_by` (pre-v0.7.0 legacy) are denied for non-operator callers. Only operators can manage legacy tasks.

### Added
- `--api-key` CLI option for `mcp-serve` command (Finding-10 #3): Also reads from `JITAUTH_MCP_API_KEY` environment variable. The advertised CLI interface now matches the implementation.
- Runtime identity mismatch check in `create_task()` — returns 403 with `identity_mismatch` error
- Task existence check in `/execute` route before gateway dispatch — returns 404 for missing tasks
- 5 new tests (runtime impersonation, execute ownership, legacy task denial, CLI option) — 190 total

### Changed
- `_enforce_task_ownership()` now denies non-operator access to tasks with `NULL` `created_by` (fail closed)
- `/execute` performs task lookup + ownership check before calling gateway
- Tests updated to accept 404 for bogus task_id in execute (task lookup now precedes token verification)

## [0.7.0] - 2026-04-14

### Security
- **Task ownership enforcement** (Finding-9 #1): Tasks now record `created_by` (the authenticated caller identity). Non-operator (runtime) callers can only access, classify, evaluate, and mint capabilities for tasks they created. Operators bypass ownership checks. This prevents cross-runtime task manipulation.
- **Atomic budget enforcement** (Finding-9 #3): Both the per-capability `calls_used` increment and per-task action budget check now use `SELECT … FOR UPDATE` row locking. Concurrent execution requests are serialized at the database level, preventing budget overshoot.

### Added
- `created_by` column on `Task` model — records authenticated caller identity at creation time
- `_enforce_task_ownership()` helper in routes — checks caller against `task.created_by`
- `api_key` parameter on `JITAuthClient` (Finding-9 #2): SDK sends `Authorization: Bearer <api_key>` on all HTTP requests when configured. Works with both the default `require_api_auth=True` config and disabled auth.
- `api_key` parameter on `create_mcp_server()`: MCP server passes the key to the SDK client for authenticated broker communication.
- Migration `002_v070_task_ownership`: adds `created_by` column for existing deployments
- 14 new tests covering all findings-9 items (185 total, was 171)

### Changed
- Task creation audit events now use `caller.caller_id` as actor (not `requester_id` from JSON) and include `requester_id` + `runtime_id` in the event details
- `GET /tasks/{id}`, `POST /tasks/{id}/classify`, `POST /tasks/{id}/policy-evaluate`, and `POST /tasks/{id}/capabilities` all enforce task ownership for non-operator callers
- Gateway `execute_tool_call` locks both the Capability and Task rows with `FOR UPDATE` before budget checks
- README updated with authenticated SDK examples, API key configuration, and current security features

## [0.6.0] - 2026-04-14

### Security
- **Control-plane API authentication** (Finding-8 #1): All broker endpoints now require Bearer-token authentication when `require_api_auth=True` (default). API keys map to `role:name` identities. Approval and revocation derive the operator identity from the authenticated caller, not from request JSON — prevents identity spoofing. `/health` remains public.
- **JWT startup secret validation** (Finding-8 #2): Broker startup now rejects known-weak JWT secrets (e.g. `CHANGE-ME-IN-PRODUCTION`, `changeme`, `secret`) and secrets shorter than 32 characters, failing fast with a clear error message.
- **SDK auto-generates runtime_secret by default** (Finding-8 #6): `JITAuthClient.task()` now auto-generates a 64-hex-char `runtime_secret` when the caller doesn't supply one. Pass `runtime_secret=""` to explicitly opt out. Runtime-bound execution is now the secure-by-default path.

### Added
- `jitauth.broker.auth` module: `AuthenticatedCaller` dataclass, `get_caller` and `require_operator` FastAPI dependencies
- `require_api_auth` and `api_keys` settings in `Settings`
- `_validate_startup_config()` in `server.py` with known-weak-secret detection
- Task-level total action budget enforcement in gateway (Finding-8 #3): `max_actions` is now enforced across all capabilities for a task, not just per-capability. Third call beyond budget returns 400/403.
- Streaming request body size enforcement in middleware (Finding-8 #4): `RequestSizeLimiter` now reads the body stream with a byte cap for POST/PUT/PATCH, catching chunked or missing `Content-Length` requests.
- `require_simulation` and `quarantine` policy effects now explicitly deny with audit (Finding-8 #5): Instead of silently proceeding, these unimplemented effects set the task to `denied` and log a `policy_effect_unsupported` audit event.
- 14 new tests covering all 6 findings-8 items (171 total, was 157)

### Changed
- `ApprovalRequest.approver_id` and `RevokeRequest.revoked_by` are now optional in schemas (identity derived from auth)
- All task lifecycle routes (`approve`, `revoke`, `complete`, `fail`) use authenticated caller identity

## [0.5.1] - 2026-04-14

### Fixed
- **Audit chain backfill on upgrade** (Finding-6 #1): Migration `001` now backfills `chain_seq` for all pre-existing audit rows in timestamp order, preserving the original hash chain. Logger ordering uses `NULLS FIRST` / `NULLS LAST` correctly so legacy rows always sort before new rows even if backfill hasn't run yet.
- **Fresh-database bootstrap via Alembic** (Finding-6 #2): Added baseline migration `000` that creates the complete schema from scratch. `alembic upgrade head` now works against an empty database without requiring a prior `create_all()` call.

### Added
- Migration `000_baseline_schema`: creates all 9 tables with indexes and constraints
- Upgrade documentation in migration docstrings (stamp flow for existing deployments)

### Changed
- Migration `001` now depends on `000` (was previously `down_revision = None`)
- Logger `_get_previous_hash_locked` and `verify_audit_chain` use secondary timestamp sort for deterministic ordering when `chain_seq` values are mixed

## [0.5.0] - 2026-04-14

### Security
- **Audit chain writes are now DB-serialized** (Finding-5 #1): `write_audit_event` uses `SELECT … FOR UPDATE` to hold a row lock on the latest event while computing the next hash and inserting. Concurrent writers are serialized at the database level, preventing chain forks. A new `chain_seq` monotonic integer column provides deterministic ordering independent of timestamp granularity.
- **Constant-time secret comparison** (Finding-5 #3): `verify_secret()` now uses `hmac.compare_digest()` for both scrypt and legacy SHA-256 paths, preventing timing side-channel attacks.

### Added
- Alembic migration infrastructure (`alembic.ini`, `migrations/env.py`, `migrations/versions/`)
- Migration `001_v050_schema_hardening`: widens `tasks.runtime_secret_hash` from `VARCHAR(64)` to `VARCHAR(130)` and adds `audit_events.chain_seq` column
- `chain_seq` column on `AuditEvent` model for monotonic DB-serialized chain ordering
- Upgrade notes: run `alembic upgrade head` after updating to v0.5.0 on existing deployments

### Changed
- `verify_audit_chain` now orders by `chain_seq` (with `timestamp` fallback for pre-v0.5.0 rows)
- `_get_previous_hash` renamed to `_get_previous_hash_locked`; returns `(prev_hash, next_seq)` tuple

## [0.4.0] - 2026-04-14

### Security
- **scrypt KDF replaces SHA-256 for runtime_secret** (Finding-4 #2): `runtime_secret_hash` now uses `hashlib.scrypt` with random salt (OWASP-recommended parameters: N=16384, r=8, p=1). Stored format is `salt_hex$scrypt_hex`. Legacy SHA-256 hashes are still accepted during verification for zero-downtime migration. Column widened from `String(64)` to `String(130)`.
- **Audit hash chain is now DB-level** (Finding-4 #1): `write_audit_event` queries the most recent event hash from the database on each write instead of relying on process-local state. This makes the chain correct under multi-worker deployments and eliminates the startup initialization requirement. `initialize_chain()` and `reset_chain()` are now no-ops for backward compatibility.
- **Configurable per-adapter resource keys for list-scope enforcement** (Finding-4 #3): `AdapterConfig` now accepts a `resource_keys` field specifying which argument keys are treated as resource identifiers during list-scope enforcement. Adapters without explicit keys fall back to built-in defaults. Loader reads `resource_keys` from adapter YAML config.

### Added
- `jitauth.core.crypto` module with `hash_secret()` and `verify_secret()` (scrypt + legacy SHA-256 fallback)
- `_DEFAULT_RESOURCE_KEYS` frozenset in gateway for fallback list-scope enforcement
- `resource_keys` field on `AdapterConfig` dataclass
- `register_adapter()` now also populates `_adapter_configs` for consistent scope enforcement
- 17 new tests covering findings-4 hardening (157 total, was 140)

## [0.3.0] - 2026-04-14

### Fixed
- **Runtime authentication on execute** (Finding-2 #1, Finding-3 #3): Tasks can now be created with a `runtime_secret`. The broker stores a SHA-256 hash and requires the caller to prove possession of the same secret on `/execute`. Authority no longer attaches solely to possession of a capability token. SDK `task()` and `jitauth_tool` decorator now expose `runtime_secret` so the main client path can use it.
- **Policy-derived scope flows into capability minting** (Finding-2 #2): When a policy rule specifies a structured `scope` (dict/list), it becomes the ceiling during capability minting. Requester-supplied scope can only narrow it, not widen it.
- **Approval reductions intersect, never widen** (Finding-3 #1): `reduced_scope` from approval now intersects with the already-computed effective scope instead of overriding it. A broad `reduced_scope` payload cannot exceed the policy ceiling.
- **`_intersect_scopes` is truly monotonic** (Finding-3 #2): No-overlap cases now produce empty lists (denying access to that field) instead of falling back to policy scope. List-vs-list intersection is also handled. The result can never contain values absent from both inputs.
- **Audit chain initialization wired on startup** (Finding-2 #3): Broker lifespan now calls `initialize_chain(db)` to restore `_last_event_hash` from the most recent DB event, ensuring hash-chain continuity across restarts.
- **Task-scoped audit verification no longer false-alarms** (Finding-2 #4): `verify_audit_chain(task_id=...)` now verifies the full global chain (which interleaves all tasks) and reports per-task event counts. Previously, filtering by `task_id` before verification broke the chain at interleaving boundaries.
- **Startup adapter loading uses config/loader.py** (Finding-2 #5): `_load_adapters_from_config()` now delegates to `load_adapter_configs()` which resolves `${ENV_VAR}` placeholders in credentials. No more duplicate loading paths.
- **Value-based secret scanning in result sanitization** (Finding-2 #6): `_sanitize_for_log` and `_sanitize_string` now scan string values for secret patterns (bearer tokens, AWS keys, private keys, connection string passwords, long hex/base64 tokens). Shell stdout, HTTP body strings, and non-key-named secrets are now caught.

### Added
- `runtime_secret` field on `TaskCreate`, `ExecuteRequest`, SDK `task()`, and `jitauth_tool` decorator
- `runtime_secret_hash` column on `Task` model
- `_runtime_secret` on `TaskHandle` — automatically included in every `/execute` call
- `_sanitize_string()` function for pattern-based secret detection in plain text
- `_intersect_scopes()` helper for monotonic policy×requester×approval scope intersection
- `_value_looks_secret()` with compiled regex patterns for common secret formats
- `redact_keys` and `redact_result` support in `config/loader.py` (previously only in `server.py`)
- 23 new tests covering findings-2 and findings-3 (140 total, was 117)

## [0.2.0] - 2026-04-14

### Fixed
- **Per-action policy evaluation**: Policy engine now evaluates each TaskAction independently with its own risk tier, using most-restrictive-wins composite. Mixed read+write tasks no longer over-restrict reads. (Finding #1)
- **Capability token verification**: Gateway now cryptographically verifies JWT capability tokens and checks claims (sub, task_id, runtime_id, target_system) match the request before allowing execution. (Finding #2)
- **Task-capability binding**: Gateway enforces that the caller's task_id matches the capability's task_id in the database, preventing cross-task capability reuse. (Finding #3)
- **Idempotency scoping**: Idempotency deduplication now scoped to task_id + capability_id + idempotency_key (was global). Added composite index for efficient lookups. (Finding #4)
- **Decorator bypass**: SDK `@jitauth_tool` decorator now routes through `task.execute()` instead of calling the function directly, ensuring broker enforcement. (Finding #5)
- **Resource scope enforcement**: New `_enforce_scope()` in gateway validates tool call arguments against capability resource_scope (dict-scope per-field and list-scope with wildcard matching). (Finding #6)
- **Double JSON encoding**: Capability minting no longer double-encodes resource_scope — parses TaskAction JSON strings before merging. (Finding #7)
- **O(n²) audit chain verification**: Replaced `events.index(event)` with `enumerate`-based loop in `verify_audit_chain()`. (Finding #15)

### Added
- `POST /tasks/{task_id}/complete` endpoint — marks task completed, expires all active capabilities
- `POST /tasks/{task_id}/fail` endpoint — marks task failed, revokes all active capabilities
- `GET /audit/verify` endpoint — verifies audit hash chain integrity
- `jitauth.core.json_fields` module — typed wrappers (`parse_json`, `parse_json_list`, `parse_json_dict`, `dump_json`) replacing scattered `json.loads`/`json.dumps` on policy-critical fields
- Typed property accessors on `Capability` model (`allowed_actions_list`, `resource_scope_parsed`)
- Per-action risk tier classification (`classify_action_risk()`)
- Per-adapter configurable redaction (`redact_keys`, `redact_result` on `AdapterConfig`)
- YAML adapter config loading on startup with redaction settings
- `adapters_config` setting for pointing to adapter YAML file
- Audit hash chain initialization from DB on startup (`initialize_chain()`)
- 15 new tests (token verification, scope enforcement, lifecycle, hash chain, per-action policy)

### Security
- Gateway sanitizes both stored audit results and runtime-returned results using `_sanitize_for_log` with configurable per-adapter redaction keys
- Sensitive key detection expanded: `_DEFAULT_SENSITIVE_KEYS` frozenset covers password, secret, token, api_key, credential, key, access_token, refresh_token, authorization, bearer
- Recursive sanitization now handles nested dicts and lists of dicts
- Approval-reduced scopes applied during capability minting

## [0.1.0] - 2026-04-14

### Added
- Core task-scoped authentication and authorization broker
- Task lifecycle with state machine (created → classifying → pending_policy → approved/denied → executing → completed)
- YAML-based deny-by-default policy engine with match/effect/priority rules
- Risk tier classification (tier_0 through tier_4) driving policy decisions
- Scoped capability minting with time-limited, call-limited tokens
- JWT-signed capability tokens for cryptographic proof of issuance
- Execution proxy gateway with adapter pattern
- HTTP adapter for REST APIs with server-side credential injection
- Shell adapter with allowlisted command templates and parameter validation
- Hash-chained audit trail with SHA-256 tamper detection
- Python SDK with async context manager interface
- Decorator interface for wrapping existing tool functions
- MCP (Model Context Protocol) server for agent framework integration
- Rate limiting and request size limiting middleware
- CLI with `serve`, `init-db`, `mcp-serve`, and `openapi` commands
- Docker Compose production configuration with Postgres
- OpenAPI 3.1 spec export
- 102 tests covering security, tokens, lifecycle, adapters, SDK, MCP, and integration scenarios

### Security
- Deny-by-default policy: no action proceeds without an explicit allow rule
- Credentials never exposed to agent runtimes — broker proxies all execution
- Input validation with Pydantic field constraints on all API schemas
- SQL injection resistance verified by test suite
- Rate limiting (configurable per-IP sliding window)
- Request body size limiting (1MB default)
- Shell adapter rejects dangerous characters and unexpected parameters
- Audit hash chain detects post-hoc tampering

[0.8.0]: https://github.com/digitalego/jitauth/releases/tag/v0.8.0
[0.7.2]: https://github.com/digitalego/jitauth/releases/tag/v0.7.2
[0.7.1]: https://github.com/digitalego/jitauth/releases/tag/v0.7.1
[0.7.0]: https://github.com/digitalego/jitauth/releases/tag/v0.7.0
[0.6.0]: https://github.com/digitalego/jitauth/releases/tag/v0.6.0
[0.5.1]: https://github.com/digitalego/jitauth/releases/tag/v0.5.1
[0.5.0]: https://github.com/digitalego/jitauth/releases/tag/v0.5.0
[0.4.0]: https://github.com/digitalego/jitauth/releases/tag/v0.4.0
[0.3.0]: https://github.com/digitalego/jitauth/releases/tag/v0.3.0
[0.2.0]: https://github.com/digitalego/jitauth/releases/tag/v0.2.0
[0.1.0]: https://github.com/digitalego/jitauth/releases/tag/v0.1.0
