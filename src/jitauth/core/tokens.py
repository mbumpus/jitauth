"""JWT capability token minting and verification.

Capabilities are minted as signed JWTs so they can be verified without
a database round-trip. The JWT contains the capability's scope, TTL,
and binding to a specific task and runtime.

The token is NOT a replacement for the database record — the broker
still validates against the DB for revocation checks and call counting.
The JWT provides a cryptographic proof that the capability was legitimately
issued and has not been tampered with.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import jwt

from jitauth.config.settings import get_settings


def _ensure_utc_timestamp(dt: datetime) -> int:
    """Convert a datetime to a UTC Unix timestamp.

    Handles naive datetimes (e.g. from SQLite round-trip) by assuming
    they are already UTC. This is critical: datetime.timestamp() treats
    naive datetimes as local time, which shifts iat/exp claims on
    non-UTC machines.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


class TokenError(Exception):
    """Raised when a capability token is invalid."""

    def __init__(self, message: str, code: str = "token_error"):
        super().__init__(message)
        self.code = code


def mint_capability_token(
    capability_id: str,
    task_id: str,
    runtime_id: str,
    target_system: str,
    allowed_actions: list[str],
    issued_at: datetime,
    expires_at: datetime,
    resource_scope: str | None = None,
    max_calls: int = 10,
) -> str:
    """Mint a signed JWT capability token.

    Args:
        capability_id: The capability's ULID.
        task_id: The task this capability is bound to.
        runtime_id: The runtime this capability is issued to.
        target_system: The downstream system this capability authorizes.
        allowed_actions: List of action names allowed.
        issued_at: When the capability was issued.
        expires_at: When the capability expires.
        resource_scope: Optional resource scope constraint.
        max_calls: Maximum number of tool calls allowed.

    Returns:
        A signed JWT string.
    """
    settings = get_settings()

    payload: dict[str, Any] = {
        # Standard JWT claims
        "iss": "jitauth-broker",
        "sub": capability_id,
        "iat": _ensure_utc_timestamp(issued_at),
        "exp": _ensure_utc_timestamp(expires_at),
        # JITAuth-specific claims
        "jitauth:task_id": task_id,
        "jitauth:runtime_id": runtime_id,
        "jitauth:target_system": target_system,
        "jitauth:allowed_actions": allowed_actions,
        "jitauth:max_calls": max_calls,
    }

    if resource_scope:
        payload["jitauth:resource_scope"] = resource_scope

    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def verify_capability_token(token: str) -> dict[str, Any]:
    """Verify and decode a capability token.

    Args:
        token: The JWT string.

    Returns:
        The decoded payload dict.

    Raises:
        TokenError: If the token is invalid, expired, or tampered with.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer="jitauth-broker",
            options={
                "require": ["exp", "iat", "iss", "sub"],
            },
        )
    except jwt.ExpiredSignatureError as e:
        raise TokenError("Capability token has expired", "token_expired") from e
    except jwt.InvalidIssuerError as e:
        raise TokenError("Token was not issued by this broker", "token_invalid_issuer") from e
    except jwt.InvalidTokenError as e:
        raise TokenError(f"Invalid capability token: {e}", "token_invalid") from e

    # Validate required JITAuth claims
    required_claims = [
        "jitauth:task_id",
        "jitauth:runtime_id",
        "jitauth:target_system",
        "jitauth:allowed_actions",
    ]
    for claim in required_claims:
        if claim not in payload:
            raise TokenError(f"Missing required claim: {claim}", "token_missing_claim")

    return payload
