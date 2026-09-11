"""Application-level encrypted-record storage and authorized retrieval."""

from __future__ import annotations

try:
    from .consent import check_access
    from .crypto.envelope import EncryptedEnvelope
    from .database import Database
    from .storage.base import EncryptedRecordStore, StorageError, validate_envelope
except ImportError:  # pragma: no cover - direct framework imports.
    from consent import check_access
    from crypto.envelope import EncryptedEnvelope
    from database import Database
    from storage.base import EncryptedRecordStore, StorageError, validate_envelope


def store_encrypted_record(
    database: Database,
    store: EncryptedRecordStore,
    envelope: EncryptedEnvelope,
    patient_id: str,
):
    """Upload an envelope and persist its backend reference in metadata.

    The record must already be registered. Storage receives only the encrypted
    envelope; key recovery remains a separate operation on the authorized side.
    """

    validate_envelope(envelope)
    existing = database.get_record(envelope.record_id)
    if existing is None:
        raise ValueError("medical record must be registered before storage")
    if existing.patient_id != patient_id:
        raise ValueError("medical record does not belong to patient")
    reference = store.upload_encrypted_record(envelope)
    updated = database.update_record_storage(envelope.record_id, store.backend_name, reference)
    if updated is None:  # pragma: no cover - protected by the preflight lookup.
        raise StorageError("record metadata disappeared during storage update")
    return updated


def retrieve_encrypted_record(
    database: Database,
    store: EncryptedRecordStore,
    patient_id: str,
    doctor_id: str,
    record_id: str,
) -> EncryptedEnvelope:
    """Check patient consent, then retrieve and verify the encrypted envelope."""

    if not check_access(database, patient_id, doctor_id, record_id):
        raise PermissionError("doctor is not authorized to access this record")
    record = database.get_record(record_id)
    if record is None or record.patient_id != patient_id:
        raise PermissionError("record is not available to this patient")
    if record.storage_backend and record.storage_backend != store.backend_name:
        raise StorageError(
            f"record is stored in {record.storage_backend}, not {store.backend_name}"
        )
    reference = record.storage_reference
    if not reference:
        raise StorageError("record has no storage reference")
    envelope = store.download_encrypted_record(reference)
    if envelope.record_id != record_id or envelope.ciphertext_hash != record.encrypted_file_hash:
        raise StorageError("retrieved envelope does not match record metadata")
    return envelope
