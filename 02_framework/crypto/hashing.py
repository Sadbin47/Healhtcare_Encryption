"""Hashing and canonical serialization helpers for framework metadata."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_digest(data: bytes) -> bytes:
    """Return the SHA-256 digest of bytes."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest."""

    return sha256_digest(data).hex()


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    """Constant-time comparison of data's SHA-256 digest with ``expected_hex``."""

    import hmac

    if not isinstance(expected_hex, str):
        raise TypeError("expected_hex must be a string")
    return hmac.compare_digest(sha256_hex(data), expected_hex.lower())


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON metadata deterministically for hashing or AAD."""

    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
