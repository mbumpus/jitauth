"""Tests for JWT capability token minting and verification."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from jitauth.config.settings import get_settings
from jitauth.core.tokens import TokenError, mint_capability_token, verify_capability_token


def _mint_test_token(**overrides) -> str:
    """Helper to mint a token with sensible defaults."""
    now = datetime.now(timezone.utc)
    kwargs = {
        "capability_id": "cap_test_123",
        "task_id": "task_test_456",
        "runtime_id": "rt_test_789",
        "target_system": "crm",
        "allowed_actions": ["read_account", "read_contacts"],
        "issued_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    kwargs.update(overrides)
    return mint_capability_token(**kwargs)


class TestMintToken:
    def test_mint_returns_string(self):
        token = _mint_test_token()
        assert isinstance(token, str)
        assert len(token) > 50  # JWTs are at least this long

    def test_mint_produces_valid_jwt(self):
        token = _mint_test_token()
        settings = get_settings()
        # Should decode without error
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        assert payload["sub"] == "cap_test_123"
        assert payload["iss"] == "jitauth-broker"
        assert payload["jitauth:task_id"] == "task_test_456"
        assert payload["jitauth:runtime_id"] == "rt_test_789"
        assert payload["jitauth:target_system"] == "crm"
        assert payload["jitauth:allowed_actions"] == ["read_account", "read_contacts"]

    def test_mint_includes_resource_scope(self):
        token = _mint_test_token(resource_scope="account:acme_123")
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        assert payload["jitauth:resource_scope"] == "account:acme_123"

    def test_mint_with_naive_datetimes(self):
        """Naive datetimes (SQLite round-trip) should be treated as UTC."""
        now_utc = datetime.now(timezone.utc)
        # Simulate SQLite round-trip: strip timezone info
        naive_issued = now_utc.replace(tzinfo=None)
        naive_expires = (now_utc + timedelta(minutes=5)).replace(tzinfo=None)

        token = _mint_test_token(issued_at=naive_issued, expires_at=naive_expires)
        # Should verify without error — naive treated as UTC
        payload = verify_capability_token(token)
        assert payload["sub"] == "cap_test_123"

        # iat should be within 2 seconds of the expected UTC timestamp
        expected_iat = int(now_utc.timestamp())
        assert abs(payload["iat"] - expected_iat) <= 2

    def test_mint_excludes_resource_scope_when_none(self):
        token = _mint_test_token(resource_scope=None)
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        assert "jitauth:resource_scope" not in payload


class TestVerifyToken:
    def test_verify_valid_token(self):
        token = _mint_test_token()
        payload = verify_capability_token(token)
        assert payload["sub"] == "cap_test_123"
        assert payload["jitauth:target_system"] == "crm"

    def test_verify_expired_token(self):
        now = datetime.now(timezone.utc)
        token = _mint_test_token(
            issued_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        with pytest.raises(TokenError, match="expired"):
            verify_capability_token(token)

    def test_verify_tampered_token(self):
        token = _mint_test_token()
        # Flip a character in the signature
        parts = token.split(".")
        sig = list(parts[2])
        sig[0] = "X" if sig[0] != "X" else "Y"
        parts[2] = "".join(sig)
        tampered = ".".join(parts)

        with pytest.raises(TokenError, match="Invalid"):
            verify_capability_token(tampered)

    def test_verify_wrong_secret(self):
        """Token signed with a different secret should fail."""
        settings = get_settings()
        now = datetime.now(timezone.utc)
        payload = {
            "iss": "jitauth-broker",
            "sub": "cap_fake",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jitauth:task_id": "task_fake",
            "jitauth:runtime_id": "rt_fake",
            "jitauth:target_system": "crm",
            "jitauth:allowed_actions": ["read"],
        }
        token = jwt.encode(payload, "wrong-secret", algorithm=settings.jwt_algorithm)
        with pytest.raises(TokenError, match="Invalid"):
            verify_capability_token(token)

    def test_verify_wrong_issuer(self):
        settings = get_settings()
        now = datetime.now(timezone.utc)
        payload = {
            "iss": "not-jitauth",
            "sub": "cap_fake",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "jitauth:task_id": "task_fake",
            "jitauth:runtime_id": "rt_fake",
            "jitauth:target_system": "crm",
            "jitauth:allowed_actions": ["read"],
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(TokenError, match="issued by this broker"):
            verify_capability_token(token)

    def test_verify_missing_jitauth_claims(self):
        settings = get_settings()
        now = datetime.now(timezone.utc)
        payload = {
            "iss": "jitauth-broker",
            "sub": "cap_fake",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            # Missing jitauth: claims
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        with pytest.raises(TokenError, match="Missing required claim"):
            verify_capability_token(token)


class TestCapabilityEndpointJWT:
    """Test that the /capabilities endpoint returns signed JWTs."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from jitauth.broker.server import create_app
        app = create_app(rate_limit=False)
        with TestClient(app) as c:
            yield c

    def test_capabilities_include_token(self, client):
        # Full lifecycle to get capabilities
        r = client.post("/tasks", json={
            "requester_id": "jwt_user",
            "runtime_id": "jwt_runtime",
            "objective": "test JWT tokens",
            "actions": [{"system": "crm", "action": "read_account", "action_class": "read"}],
        })
        task_id = r.json()["id"]

        client.post(f"/tasks/{task_id}/classify")
        client.post(f"/tasks/{task_id}/policy-evaluate")
        r = client.post(f"/tasks/{task_id}/capabilities")
        assert r.status_code == 200

        caps = r.json()
        assert len(caps) == 1
        assert caps[0]["token"] is not None

        # Verify the token is valid
        payload = verify_capability_token(caps[0]["token"])
        assert payload["sub"] == caps[0]["id"]
        assert payload["jitauth:task_id"] == task_id
        assert payload["jitauth:target_system"] == "crm"
        assert "read_account" in payload["jitauth:allowed_actions"]
