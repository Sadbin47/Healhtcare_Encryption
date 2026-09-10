"""Healthcare encryption framework package."""

from .database import Database
from .consent import check_access, grant_access, list_active_grants_for_record, revoke_access
from .identity import register_doctor, register_patient
from .models import AccessGrant, Doctor, MedicalRecord, Patient

__all__ = [
    "AccessGrant",
    "Database",
    "Doctor",
    "MedicalRecord",
    "Patient",
    "check_access",
    "grant_access",
    "list_active_grants_for_record",
    "revoke_access",
    "register_doctor",
    "register_patient",
]
