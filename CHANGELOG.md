# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.5.0]: https://github.com/digitalego/jitauth/releases/tag/v0.5.0
[0.4.0]: https://github.com/digitalego/jitauth/releases/tag/v0.4.0
[0.3.0]: https://github.com/digitalego/jitauth/releases/tag/v0.3.0
[0.2.0]: https://github.com/digitalego/jitauth/releases/tag/v0.2.0
[0.1.0]: https://github.com/digitalego/jitauth/releases/tag/v0.1.0
