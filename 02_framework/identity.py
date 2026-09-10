"""Registration helpers for patient and doctor identities.

The database stores doctor public-key material only. Private keys remain with
the doctor/key-management layer and are never accepted by these helpers.
"""

from __future__ import annotations

try:
    from .database import Database
    from .models import Doctor, Patient
except ImportError:  # pragma: no cover - direct module use.
    from database import Database
    from models import Doctor, Patient


SUPPORTED_KEY_ALGORITHMS = frozenset({
    "ECC-ECDH-P256-AES-GCM",
    "ML-KEM-768-AES-GCM",
})


def register_patient(
    database: Database,
    patient_id: str,
    display_name_or_alias: str,
) -> Patient:
    """Create and persist a patient metadata record."""

    patient = Patient(patient_id=patient_id, display_name_or_alias=display_name_or_alias)
    return database.add_patient(patient)


def register_doctor(
    database: Database,
    doctor_id: str,
    name: str,
    public_key: str,
    key_algorithm: str,
) -> Doctor:
    """Create and persist a doctor with public-key metadata only."""

    if key_algorithm not in SUPPORTED_KEY_ALGORITHMS:
        raise ValueError(
            f"unsupported doctor key algorithm: {key_algorithm}; "
            f"expected one of {sorted(SUPPORTED_KEY_ALGORITHMS)}"
        )
    doctor = Doctor(
        doctor_id=doctor_id,
        name=name,
        public_key=public_key,
        key_algorithm=key_algorithm,
    )
    return database.add_doctor(doctor)

