# Contributing to JITAuth

Thanks for your interest in contributing to JITAuth. This document covers the development workflow, coding conventions, and how to get changes merged.

## Development setup

```bash
git clone https://github.com/digitalego/jitauth.git
cd jitauth
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
```

## Running tests

```bash
pytest
```

Tests use a temporary SQLite database per test, so they're fully isolated and require no external services. The full suite runs in under 5 seconds.

## Code style

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting. Check before committing:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

Key conventions: 100-character line length, Python 3.10+ type hints, `from __future__ import annotations` in every module.

## Project structure

```
src/jitauth/
├── broker/        # FastAPI app, routes, middleware
├── core/          # SQLAlchemy models, Pydantic schemas, ULID generation, JWT tokens
├── config/        # Settings (env vars) and adapter config loader
├── policy/        # YAML rule engine and risk classification
├── proxy/         # Execution gateway and adapters (HTTP, shell)
├── audit/         # Hash-chained audit logger
├── sdk/           # Python client library and decorators
├── mcp/           # MCP server integration
├── db/            # SQLAlchemy engine and session management
└── cli.py         # Click CLI entry point
```

## Writing tests

Put tests in `tests/` with the naming convention `test_<module>.py`. The shared fixtures in `conftest.py` give you a fresh database and policy configuration for each test.

For API endpoint tests, use the `client` fixture (a FastAPI `TestClient`). For SDK tests, use `httpx.ASGITransport` to wire the SDK client directly to the app.

## Adding an adapter

1. Create a new file in `src/jitauth/proxy/adapters/`.
2. Subclass `BaseAdapter` from `src/jitauth/proxy/base.py`.
3. Implement the `execute(action, arguments, credential)` method.
4. Register the adapter type string in `proxy/gateway.py:_create_adapter()`.
5. Add tests in `tests/test_<adapter_name>_adapter.py`.

## Adding a policy effect

Policy effects are defined in `src/jitauth/core/models.py` as the `PolicyEffect` enum. To add a new effect:

1. Add the value to `PolicyEffect`.
2. Handle it in `broker/routes.py:evaluate_policy()` (the status transition).
3. Document it in the README.

## Pull requests

1. Fork the repo and create a feature branch from `main`.
2. Write tests for your changes.
3. Make sure `pytest` and `ruff check` both pass.
4. Open a PR with a clear description of what changed and why.

We review PRs for correctness, security implications, and test coverage. The core security invariant — that agent runtimes never see credentials and all actions go through policy — must be preserved by every change.

## Reporting security issues

If you find a security vulnerability, please email admin@digitalego.ai rather than opening a public issue. We'll acknowledge within 48 hours and work with you on a fix before any public disclosure.
