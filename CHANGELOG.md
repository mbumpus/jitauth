# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/digitalego/jitauth/releases/tag/v0.1.0
