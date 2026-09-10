"""ML-KEM-768 protection for an AES data-encryption key."""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aes_gcm import AES_KEY_SIZE, GCM_NONCE_SIZE
from .hashing import canonical_json_bytes


ALGORITHM = "ML-KEM-768-AES-GCM"
_HKDF_INFO_PREFIX = b"NS-PaperWork ML-KEM-768 AES-256 key protection v1"


def generate_key_pair() -> tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey]:
    """Generate an ML-KEM-768 recipient key pair."""

    private_key = mlkem.MLKEM768PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_public_key(public_key: mlkem.MLKEM768PublicKey) -> str:
    """Serialize a raw ML-KEM-768 public key as base64."""

    return base64.b64encode(public_key.public_bytes_raw()).decode("ascii")


def deserialize_public_key(value: str) -> mlkem.MLKEM768PublicKey:
    """Load a raw ML-KEM-768 public key from base64."""

    raw = base64.b64decode(value, validate=True)
    return mlkem.MLKEM768PublicKey.from_public_bytes(raw)


def _public_key(value: Any) -> mlkem.MLKEM768PublicKey:
    if isinstance(value, mlkem.MLKEM768PublicKey):
        return value
    if isinstance(value, bytes):
        return mlkem.MLKEM768PublicKey.from_public_bytes(value)
    raise TypeError("recipient public key must be an ML-KEM-768 key or raw bytes")


def _private_key(value: Any) -> mlkem.MLKEM768PrivateKey:
    if isinstance(value, mlkem.MLKEM768PrivateKey):
        return value
    if isinstance(value, bytes):
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(value)
    raise TypeError("recipient private key must be an ML-KEM-768 key or seed bytes")


def _aad(doctor_key_id: str, ciphertext: str) -> bytes:
    return canonical_json_bytes(
        {
            "algorithm": ALGORITHM,
            "doctor_key_id": doctor_key_id,
            "kem_ciphertext": ciphertext,
        }
    )


def _hkdf(shared_secret: bytes, doctor_key_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=_HKDF_INFO_PREFIX + b":" + doctor_key_id.encode("utf-8"),
    ).derive(shared_secret)


def protect_aes_key(
    aes_key: bytes,
    recipient_public_key: Any,
    doctor_key_id: str,
) -> dict[str, str]:
    """Wrap an AES key using ML-KEM-768 and AES-GCM."""

    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes")
    if not isinstance(doctor_key_id, str) or not doctor_key_id:
        raise ValueError("doctor_key_id must be a non-empty string")

    recipient = _public_key(recipient_public_key)
    shared_secret, ciphertext = recipient.encapsulate()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    wrapping_key = _hkdf(shared_secret, doctor_key_id)
    nonce = os.urandom(GCM_NONCE_SIZE)
    wrapped = AESGCM(wrapping_key).encrypt(
        nonce,
        aes_key,
        _aad(doctor_key_id, ciphertext_b64),
    )
    return {
        "algorithm": ALGORITHM,
        "doctor_key_id": doctor_key_id,
        "kem_ciphertext": ciphertext_b64,
        "wrapper_nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_aes_key": base64.b64encode(wrapped).decode("ascii"),
    }


def recover_aes_key(protected_key: dict[str, str], recipient_private_key: Any) -> bytes:
    """Recover an AES key from an ML-KEM-768 protected-key package."""

    required = {
        "algorithm",
        "doctor_key_id",
        "kem_ciphertext",
        "wrapper_nonce",
        "wrapped_aes_key",
    }
    if not isinstance(protected_key, dict) or not required.issubset(protected_key):
        raise ValueError("invalid ML-KEM protected-key package")
    if protected_key["algorithm"] != ALGORITHM:
        raise ValueError("protected-key algorithm does not match ML-KEM branch")

    private_key = _private_key(recipient_private_key)
    ciphertext = base64.b64decode(protected_key["kem_ciphertext"], validate=True)
    shared_secret = private_key.decapsulate(ciphertext)
    wrapping_key = _hkdf(shared_secret, protected_key["doctor_key_id"])
    nonce = base64.b64decode(protected_key["wrapper_nonce"], validate=True)
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("invalid ML-KEM wrapper nonce")
    wrapped = base64.b64decode(protected_key["wrapped_aes_key"], validate=True)
    return AESGCM(wrapping_key).decrypt(
        nonce,
        wrapped,
        _aad(protected_key["doctor_key_id"], protected_key["kem_ciphertext"]),
    )
