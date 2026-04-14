"""Cryptographic helpers for JITAuth.

Provides KDF-based secret hashing (scrypt) instead of plain SHA-256,
making stored hashes resistant to brute-force even if the DB leaks.
Uses only stdlib hashlib — no external dependencies required.
"""

from __future__ import annotations

import hashlib
import hmac
import os


# scrypt parameters — OWASP recommended minimums for interactive use.
_SCRYPT_N = 16384  # CPU/memory cost
_SCRYPT_R = 8      # block size
_SCRYPT_P = 1      # parallelization
_SCRYPT_DKLEN = 32 # output length in bytes
_SALT_BYTES = 16


def hash_secret(secret: str) -> str:
    """Hash a runtime secret using scrypt with a random salt.

    Returns:
        A string in the format ``salt_hex$scrypt_hex`` suitable for
        storage in a VARCHAR(130) column.
    """
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.scrypt(
        secret.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"{salt.hex()}${dk.hex()}"


def verify_secret(secret: str, stored_hash: str) -> bool:
    """Verify a runtime secret against a stored scrypt hash.

    Also accepts legacy plain SHA-256 hex hashes (64-char, no ``$``)
    for backward compatibility with existing DB rows.

    Args:
        secret: The plaintext secret to check.
        stored_hash: The value from ``Task.runtime_secret_hash``.

    Returns:
        True if the secret matches.
    """
    if "$" not in stored_hash:
        # Legacy SHA-256 hash — verify and caller should consider re-hashing
        legacy_hash = hashlib.sha256(secret.encode()).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)

    parts = stored_hash.split("$", 1)
    if len(parts) != 2:
        return False

    try:
        salt = bytes.fromhex(parts[0])
        expected = bytes.fromhex(parts[1])
    except ValueError:
        return False

    dk = hashlib.scrypt(
        secret.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    # Constant-time comparison to prevent timing side-channels
    return hmac.compare_digest(dk, expected)
