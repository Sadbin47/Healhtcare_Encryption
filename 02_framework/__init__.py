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
"""Reusable healthcare-encryption framework components."""

from .record_storage import retrieve_encrypted_record, store_encrypted_record
from .blockchain_client import BlockchainClient
from .service import HealthcareWorkflowService
from .audit import AuditEntry, AuditEvent, JsonlAuditSink, MemoryAuditSink

__all__ = [
    "BlockchainClient",
    "HealthcareWorkflowService",
    "AuditEntry",
    "AuditEvent",
    "JsonlAuditSink",
    "MemoryAuditSink",
    "retrieve_encrypted_record",
    "store_encrypted_record",
]
