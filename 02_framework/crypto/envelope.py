"""Canonical JSON-safe encrypted-record envelope."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from .aes_gcm import GCM_TAG_SIZE
from .hashing import canonical_json_bytes, sha256_hex, verify_sha256


ENVELOPE_VERSION = 1


def record_aad(record_id: str, key_protection: str, key_reference: str) -> bytes:
    """Build deterministic AAD binding ciphertext to record metadata."""

    if not all(isinstance(value, str) and value for value in (record_id, key_protection, key_reference)):
        raise ValueError("record metadata must be non-empty strings")
    return canonical_json_bytes(
        {
            "record_id": record_id,
            "key_protection": key_protection,
            "key_reference": key_reference,
        }
    )


@dataclass(frozen=True)
class EncryptedEnvelope:
    """Serialized metadata and ciphertext required for authorized recovery."""

    record_id: str
    key_protection: str
    key_reference: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    wrapped_key: dict[str, str]
    ciphertext_hash: str
    version: int = ENVELOPE_VERSION
    algorithm: str = "AES-256-GCM"

    def __post_init__(self) -> None:
        if self.version != ENVELOPE_VERSION:
            raise ValueError("unsupported envelope version")
        if not self.record_id or not self.key_protection or not self.key_reference:
            raise ValueError("record_id, key_protection, and key_reference are required")
        if len(self.nonce) != 12:
            raise ValueError("envelope nonce must be 12 bytes")
        if len(self.tag) != GCM_TAG_SIZE:
            raise ValueError("envelope tag must be 16 bytes")
        if not isinstance(self.ciphertext, bytes):
            raise TypeError("envelope ciphertext must be bytes")
        payload_hash = sha256_hex(self.nonce + self.ciphertext + self.tag)
        if payload_hash != self.ciphertext_hash:
            raise ValueError("ciphertext_hash does not match envelope payload")

    @classmethod
    def create(
        cls,
        record_id: str,
        key_protection: str,
        key_reference: str,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        wrapped_key: dict[str, str],
    ) -> "EncryptedEnvelope":
        return cls(
            record_id=record_id,
            key_protection=key_protection,
            key_reference=key_reference,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            wrapped_key=dict(wrapped_key),
            ciphertext_hash=sha256_hex(nonce + ciphertext + tag),
        )

    def payload_bytes(self) -> bytes:
        return self.nonce + self.ciphertext + self.tag

    def verify_payload(self) -> bool:
        return verify_sha256(self.payload_bytes(), self.ciphertext_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "record_id": self.record_id,
            "algorithm": self.algorithm,
            "key_protection": self.key_protection,
            "key_reference": self.key_reference,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "tag": base64.b64encode(self.tag).decode("ascii"),
            "wrapped_key": self.wrapped_key,
            "ciphertext_hash": self.ciphertext_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EncryptedEnvelope":
        required = {
            "version", "record_id", "algorithm", "key_protection", "key_reference",
            "nonce", "ciphertext", "tag", "wrapped_key", "ciphertext_hash",
        }
        if not isinstance(value, dict) or not required.issubset(value):
            raise ValueError("invalid encrypted envelope")
        if value["algorithm"] != "AES-256-GCM":
            raise ValueError("unsupported envelope data-encryption algorithm")
        return cls(
            version=int(value["version"]),
            record_id=str(value["record_id"]),
            key_protection=str(value["key_protection"]),
            key_reference=str(value["key_reference"]),
            nonce=base64.b64decode(value["nonce"], validate=True),
            ciphertext=base64.b64decode(value["ciphertext"], validate=True),
            tag=base64.b64decode(value["tag"], validate=True),
            wrapped_key=dict(value["wrapped_key"]),
            ciphertext_hash=str(value["ciphertext_hash"]),
            algorithm=str(value["algorithm"]),
        )

    @classmethod
    def from_json(cls, value: str) -> "EncryptedEnvelope":
        if not isinstance(value, str):
            raise TypeError("envelope JSON must be a string")
        return cls.from_dict(json.loads(value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())
