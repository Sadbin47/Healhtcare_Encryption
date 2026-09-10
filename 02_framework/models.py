"""Domain models stored by the Phase 2 metadata database.

These models intentionally contain identifiers, public-key material, and
encrypted-record metadata only. Plaintext EHR data and private key material do
not belong in this database.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> str:
    """Return a stable, timezone-aware UTC timestamp for SQLite text fields."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class Patient:
    patient_id: str
    display_name_or_alias: str
    created_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "patient_id", require_text(self.patient_id, "patient_id"))
        object.__setattr__(
            self,
            "display_name_or_alias",
            require_text(self.display_name_or_alias, "display_name_or_alias"),
        )
        if not self.created_at:
            object.__setattr__(self, "created_at", utc_now())
        else:
            object.__setattr__(self, "created_at", require_text(self.created_at, "created_at"))


@dataclass(frozen=True)
class Doctor:
    doctor_id: str
    name: str
    public_key: str
    key_algorithm: str
    created_at: str = ""

    def __post_init__(self) -> None:
        for field_name in ("doctor_id", "name", "public_key", "key_algorithm"):
            object.__setattr__(self, field_name, require_text(getattr(self, field_name), field_name))
        if not self.created_at:
            object.__setattr__(self, "created_at", utc_now())
        else:
            object.__setattr__(self, "created_at", require_text(self.created_at, "created_at"))


@dataclass(frozen=True)
class MedicalRecord:
    record_id: str
    patient_id: str
    encrypted_file_hash: str
    ipfs_cid: Optional[str]
    key_protection_algorithm: str
    created_at: str = ""

    def __post_init__(self) -> None:
        for field_name in (
            "record_id",
            "patient_id",
            "encrypted_file_hash",
            "key_protection_algorithm",
        ):
            object.__setattr__(self, field_name, require_text(getattr(self, field_name), field_name))
        if self.ipfs_cid is not None:
            object.__setattr__(self, "ipfs_cid", require_text(self.ipfs_cid, "ipfs_cid"))
        if not self.created_at:
            object.__setattr__(self, "created_at", utc_now())
        else:
            object.__setattr__(self, "created_at", require_text(self.created_at, "created_at"))


@dataclass(frozen=True)
class AccessGrant:
    patient_id: str
    doctor_id: str
    record_id: str
    permission: str = "read"
    granted_at: str = ""
    revoked_at: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in ("patient_id", "doctor_id", "record_id", "permission"):
            object.__setattr__(self, field_name, require_text(getattr(self, field_name), field_name))
        if not self.granted_at:
            object.__setattr__(self, "granted_at", utc_now())
        else:
            object.__setattr__(self, "granted_at", require_text(self.granted_at, "granted_at"))
        if self.revoked_at is not None:
            object.__setattr__(self, "revoked_at", require_text(self.revoked_at, "revoked_at"))

