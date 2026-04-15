"""Control-plane authentication for JITAuth broker.

Provides API key-based authentication for all broker endpoints.
API keys map to roles ("operator" or "runtime") and a caller identity.

Configuration (settings.py / env vars):
    api_keys: dict mapping key → "role:name", e.g. {"sk-abc": "operator:admin"}
    require_api_auth: bool (default True; set False for tests / local dev)

Usage in routes:
    from jitauth.broker.auth import get_caller, require_operator

    @router.post("/tasks/{task_id}/approve")
    def approve(caller: AuthenticatedCaller = Depends(get_caller)):
        ...

    @router.get("/audit")
    def audit(caller: AuthenticatedCaller = Depends(require_operator)):
        ...
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from jitauth.config.settings import get_settings


@dataclass(frozen=True)
class AuthenticatedCaller:
    """Represents an authenticated API caller."""

    caller_id: str  # e.g. "admin", "agent-1"
    role: str  # "operator" or "runtime"

    @property
    def is_operator(self) -> bool:
        return self.role == "operator"


# Default identity used when auth is disabled (tests / local dev)
_TEST_CALLER = AuthenticatedCaller(caller_id="test-user", role="operator")


def get_caller(request: Request) -> AuthenticatedCaller:
    """FastAPI dependency: extract and validate authenticated caller.

    Reads ``Authorization: Bearer <api_key>`` header, looks up the key
    in settings.api_keys, and returns an AuthenticatedCaller.

    When ``require_api_auth`` is False (tests), returns a default
    operator identity so existing tests pass unchanged.
    """
    settings = get_settings()

    if not settings.require_api_auth:
        return _TEST_CALLER

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_auth", "message": "Authorization: Bearer <api_key> required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    api_key = auth_header[7:]  # strip "Bearer "
    role_spec = settings.api_keys.get(api_key)
    if role_spec is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_api_key", "message": "Unknown API key"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Parse "role:name" format
    if ":" not in role_spec:
        raise HTTPException(
            status_code=500,
            detail={"error": "config_error", "message": f"Malformed api_keys entry: {role_spec!r}"},
        )

    role, caller_id = role_spec.split(":", 1)
    if role not in ("operator", "runtime"):
        raise HTTPException(
            status_code=500,
            detail={"error": "config_error", "message": f"Unknown role: {role!r}"},
        )

    return AuthenticatedCaller(caller_id=caller_id, role=role)


def require_operator(caller: AuthenticatedCaller = Depends(get_caller)) -> AuthenticatedCaller:
    """FastAPI dependency: require operator role."""
    if not caller.is_operator:
        raise HTTPException(
            status_code=403,
            detail={"error": "insufficient_role", "message": "Operator role required"},
        )
    return caller
