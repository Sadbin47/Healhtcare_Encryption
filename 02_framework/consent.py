"""Patient-consent operations over the Phase 2 metadata database.

This module expresses the current prototype policy: a patient may grant or
revoke read access to one registered doctor for one of that patient's records.
Authentication of the caller is intentionally outside this service and will be
added by a later application/API phase.
"""

from __future__ import annotations

try:
    from .database import Database
    from .models import AccessGrant, require_text, utc_now
except ImportError:  # pragma: no cover - direct module use.
    from database import Database
    from models import AccessGrant, require_text, utc_now


READ_PERMISSION = "read"


def _validate_ids(patient_id: str, doctor_id: str, record_id: str) -> tuple[str, str, str]:
    return (
        require_text(patient_id, "patient_id"),
        require_text(doctor_id, "doctor_id"),
        require_text(record_id, "record_id"),
    )


def _validate_scope(database: Database, patient_id: str, doctor_id: str, record_id: str) -> None:
    if database.get_patient(patient_id) is None:
        raise ValueError("patient does not exist")
    if database.get_doctor(doctor_id) is None:
        raise ValueError("doctor does not exist")
    record = database.get_record(record_id)
    if record is None:
        raise ValueError("medical record does not exist")
    if record.patient_id != patient_id:
        raise ValueError("medical record does not belong to patient")


def grant_access(
    database: Database,
    patient_id: str,
    doctor_id: str,
    record_id: str,
    permission: str = READ_PERMISSION,
) -> AccessGrant:
    """Grant a doctor read access to a patient's record.

    Granting an already-active permission is idempotent. A previously revoked
    grant is reactivated with a fresh ``granted_at`` timestamp.
    """

    patient_id, doctor_id, record_id = _validate_ids(patient_id, doctor_id, record_id)
    permission = require_text(permission, "permission")
    if permission != READ_PERMISSION:
        raise ValueError(f"unsupported permission: {permission}; only 'read' is supported")
    _validate_scope(database, patient_id, doctor_id, record_id)
    return database.upsert_access_grant(
        AccessGrant(
            patient_id=patient_id,
            doctor_id=doctor_id,
            record_id=record_id,
            permission=permission,
            granted_at=utc_now(),
            revoked_at=None,
        )
    )


def revoke_access(
    database: Database,
    patient_id: str,
    doctor_id: str,
    record_id: str,
) -> AccessGrant | None:
    """Revoke a doctor's access; return the revoked grant or ``None``.

    Revocation is idempotent for a missing grant. Existing revoked grants are
    returned unchanged except for their latest revocation timestamp.
    """

    patient_id, doctor_id, record_id = _validate_ids(patient_id, doctor_id, record_id)
    _validate_scope(database, patient_id, doctor_id, record_id)
    return database.revoke_access_grant(patient_id, doctor_id, record_id, utc_now())


def check_access(
    database: Database,
    patient_id: str,
    doctor_id: str,
    record_id: str,
) -> bool:
    """Return whether the doctor currently has active read access.

    A scope mismatch or missing entity is a denial rather than an exception,
    keeping this function safe to use as an authorization decision point.
    """

    patient_id, doctor_id, record_id = _validate_ids(patient_id, doctor_id, record_id)
    patient = database.get_patient(patient_id)
    doctor = database.get_doctor(doctor_id)
    record = database.get_record(record_id)
    if patient is None or doctor is None or record is None or record.patient_id != patient_id:
        return False
    grant = database.get_access_grant(patient_id, doctor_id, record_id)
    return grant is not None and grant.permission == READ_PERMISSION and grant.revoked_at is None


def list_active_grants_for_record(database: Database, record_id: str) -> list[AccessGrant]:
    """Return only active read grants for a record."""

    record_id = require_text(record_id, "record_id")
    return [
        grant
        for grant in database.list_access_grants_for_record(record_id)
        if grant.permission == READ_PERMISSION and grant.revoked_at is None
    ]
