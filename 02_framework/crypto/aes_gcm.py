"""Small AES-256-GCM primitives used by the framework.

The module deliberately keeps the binary format explicit: callers receive the
nonce, ciphertext, and authentication tag as separate values.  Higher-level
code can then serialize them in the encrypted-record envelope.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


def generate_key() -> bytes:
    """Generate a random 256-bit AES key."""

    return AESGCM.generate_key(bit_length=256)


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise TypeError("AES key must be bytes")
    if len(key) != AES_KEY_SIZE:
        raise ValueError("AES-256 requires a 32-byte key")


def _validate_plaintext(plaintext: bytes) -> None:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")


def _validate_nonce(nonce: bytes) -> None:
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("AES-GCM requires a 12-byte nonce")


def _validate_aad(aad: Optional[bytes]) -> None:
    if aad is not None and not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes or None")


def encrypt_record(
    plaintext: bytes,
    aes_key: bytes,
    aad: Optional[bytes] = None,
) -> tuple[bytes, bytes, bytes]:
    """Encrypt ``plaintext`` and return ``(nonce, ciphertext, tag)``."""

    _validate_plaintext(plaintext)
    _validate_key(aes_key)
    _validate_aad(aad)

    nonce = os.urandom(GCM_NONCE_SIZE)
    encrypted = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    return nonce, encrypted[:-GCM_TAG_SIZE], encrypted[-GCM_TAG_SIZE:]


def decrypt_record(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aes_key: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Authenticate and decrypt a separated AES-GCM record."""

    _validate_nonce(nonce)
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(tag, bytes):
        raise TypeError("tag must be bytes")
    if len(tag) != GCM_TAG_SIZE:
        raise ValueError("AES-GCM requires a 16-byte authentication tag")
    _validate_key(aes_key)
    _validate_aad(aad)

    return AESGCM(aes_key).decrypt(nonce, ciphertext + tag, aad)
