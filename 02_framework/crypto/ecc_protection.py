"""Recipient-based ECC/ECDH protection for an AES data-encryption key."""

from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aes_gcm import AES_KEY_SIZE, GCM_NONCE_SIZE
from .hashing import canonical_json_bytes


ALGORITHM = "ECC-ECDH-P256-AES-GCM"
_HKDF_INFO_PREFIX = b"NS-PaperWork ECC AES-256 key protection v1"


def generate_key_pair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a P-256 recipient key pair."""

    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Serialize a public key as base64-encoded DER SubjectPublicKeyInfo."""

    return base64.b64encode(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")


def deserialize_public_key(value: str) -> ec.EllipticCurvePublicKey:
    """Load a base64-encoded DER SubjectPublicKeyInfo public key."""

    key = serialization.load_der_public_key(base64.b64decode(value, validate=True))
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("serialized key is not an ECC public key")
    if key.curve.name != "secp256r1":
        raise ValueError("ECC framework keys must use secp256r1")
    return key


def _public_key(value: Any) -> ec.EllipticCurvePublicKey:
    if isinstance(value, ec.EllipticCurvePublicKey):
        key = value
    elif isinstance(value, bytes):
        key = serialization.load_pem_public_key(value)
    else:
        raise TypeError("recipient public key must be an ECC key or PEM bytes")
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("recipient public key is not an ECC public key")
    if key.curve.name != "secp256r1":
        raise ValueError("ECC framework keys must use secp256r1")
    return key


def _private_key(value: Any) -> ec.EllipticCurvePrivateKey:
    if isinstance(value, ec.EllipticCurvePrivateKey):
        key = value
    elif isinstance(value, bytes):
        key = serialization.load_pem_private_key(value, password=None)
    else:
        raise TypeError("recipient private key must be an ECC key or PEM bytes")
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("recipient private key is not an ECC private key")
    if key.curve.name != "secp256r1":
        raise ValueError("ECC framework keys must use secp256r1")
    return key


def _aad(doctor_key_id: str, ephemeral_public_key: str) -> bytes:
    return canonical_json_bytes(
        {
            "algorithm": ALGORITHM,
            "doctor_key_id": doctor_key_id,
            "ephemeral_public_key": ephemeral_public_key,
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
    """Wrap an AES key for a recipient using ephemeral ECDH and AES-GCM."""

    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes")
    if not isinstance(doctor_key_id, str) or not doctor_key_id:
        raise ValueError("doctor_key_id must be a non-empty string")

    recipient = _public_key(recipient_public_key)
    ephemeral_private, ephemeral_public = generate_key_pair()
    ephemeral_public_b64 = serialize_public_key(ephemeral_public)
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient)
    wrapping_key = _hkdf(shared_secret, doctor_key_id)

    nonce = os.urandom(GCM_NONCE_SIZE)
    wrapped = AESGCM(wrapping_key).encrypt(
        nonce,
        aes_key,
        _aad(doctor_key_id, ephemeral_public_b64),
    )
    return {
        "algorithm": ALGORITHM,
        "doctor_key_id": doctor_key_id,
        "ephemeral_public_key": ephemeral_public_b64,
        "wrapper_nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_aes_key": base64.b64encode(wrapped).decode("ascii"),
    }


def recover_aes_key(protected_key: dict[str, str], recipient_private_key: Any) -> bytes:
    """Recover an AES key from an ECC protected-key package."""

    required = {
        "algorithm",
        "doctor_key_id",
        "ephemeral_public_key",
        "wrapper_nonce",
        "wrapped_aes_key",
    }
    if not isinstance(protected_key, dict) or not required.issubset(protected_key):
        raise ValueError("invalid ECC protected-key package")
    if protected_key["algorithm"] != ALGORITHM:
        raise ValueError("protected-key algorithm does not match ECC branch")

    private_key = _private_key(recipient_private_key)
    ephemeral_public = deserialize_public_key(protected_key["ephemeral_public_key"])
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
    wrapping_key = _hkdf(shared_secret, protected_key["doctor_key_id"])
    nonce = base64.b64decode(protected_key["wrapper_nonce"], validate=True)
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("invalid ECC wrapper nonce")
    wrapped = base64.b64decode(protected_key["wrapped_aes_key"], validate=True)
    return AESGCM(wrapping_key).decrypt(
        nonce,
        wrapped,
        _aad(protected_key["doctor_key_id"], protected_key["ephemeral_public_key"]),
    )
