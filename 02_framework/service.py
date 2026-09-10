"""End-to-end encrypted EHR upload and authorized doctor retrieval service."""

from __future__ import annotations

import base64
import os
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

try:
    from .audit import AuditEvent, AuditSink, MemoryAuditSink
    from .blockchain_client import BlockchainClient
    from .consent import check_access
    from .crypto.aes_gcm import decrypt_record, encrypt_record, generate_key
    from .crypto.ecc_protection import (
        ALGORITHM as ECC_ALGORITHM,
        deserialize_public_key as deserialize_ecc_public_key,
        protect_aes_key as protect_aes_key_ecc,
        recover_aes_key as recover_aes_key_ecc,
    )
    from .crypto.envelope import EncryptedEnvelope, record_aad
    from .crypto.mlkem_protection import (
        ALGORITHM as MLKEM_ALGORITHM,
        deserialize_public_key as deserialize_mlkem_public_key,
        protect_aes_key as protect_aes_key_mlkem,
        recover_aes_key as recover_aes_key_mlkem,
    )
    from .database import Database
    from .models import MedicalRecord
    from .storage.base import EncryptedRecordStore, StorageError, validate_envelope
except ImportError:  # pragma: no cover - direct framework imports.
    from audit import AuditEvent, AuditSink, MemoryAuditSink
    from blockchain_client import BlockchainClient
    from consent import check_access
    from crypto.aes_gcm import decrypt_record, encrypt_record, generate_key
    from crypto.ecc_protection import (
        ALGORITHM as ECC_ALGORITHM,
        deserialize_public_key as deserialize_ecc_public_key,
        protect_aes_key as protect_aes_key_ecc,
        recover_aes_key as recover_aes_key_ecc,
    )
    from crypto.envelope import EncryptedEnvelope, record_aad
    from crypto.mlkem_protection import (
        ALGORITHM as MLKEM_ALGORITHM,
        deserialize_public_key as deserialize_mlkem_public_key,
        protect_aes_key as protect_aes_key_mlkem,
        recover_aes_key as recover_aes_key_mlkem,
    )
    from database import Database
    from models import MedicalRecord
    from storage.base import EncryptedRecordStore, StorageError, validate_envelope


SUPPORTED_ALGORITHMS = frozenset({ECC_ALGORITHM, MLKEM_ALGORITHM})


def _read_ehr_bytes(ehr_file: bytes | bytearray | memoryview | str | os.PathLike[str] | Any) -> bytes:
    if isinstance(ehr_file, bytes):
        return ehr_file
    if isinstance(ehr_file, (bytearray, memoryview)):
        return bytes(ehr_file)
    if isinstance(ehr_file, (str, os.PathLike)):
        return Path(ehr_file).read_bytes()
    if hasattr(ehr_file, "read"):
        value = ehr_file.read()
        if not isinstance(value, bytes):
            raise TypeError("ehr_file.read() must return bytes")
        return value
    raise TypeError("ehr_file must be bytes, a path, or a binary file object")


class HealthcareWorkflowService:
    """Compose encryption, storage, consent, blockchain, and audit layers.

    ``private_key_resolver`` is called only during doctor retrieval and must
    return key material held by the authorized application/doctor. It is never
    persisted by this service.
    """

    def __init__(
        self,
        database: Database,
        storage: EncryptedRecordStore,
        blockchain: BlockchainClient,
        *,
        doctor_addresses: Mapping[str, str] | None = None,
        private_key_resolver: Callable[[str], Any] | None = None,
        registrar_address: str | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.database = database
        self.storage = storage
        self.blockchain = blockchain
        self.doctor_addresses = dict(doctor_addresses or {})
        self.private_key_resolver = private_key_resolver
        self.registrar_address = registrar_address
        self.audit_sink = audit_sink or MemoryAuditSink()

    @property
    def audit_events(self) -> list[AuditEvent]:
        return list(getattr(self.audit_sink, "events", []))

    def _doctor_address(self, doctor_id: str) -> str:
        address = self.doctor_addresses.get(doctor_id)
        if not address and isinstance(doctor_id, str) and doctor_id.startswith("0x"):
            address = doctor_id
        if not address:
            raise ValueError("no blockchain address is registered for doctor")
        return address

    def _audit(self, **kwargs: Any) -> None:
        self.audit_sink.record(AuditEvent(**kwargs))

    def upload_record(
        self,
        patient_id: str,
        ehr_file: bytes | bytearray | memoryview | str | os.PathLike[str] | Any,
        doctor_id: str,
        algorithm: str,
        *,
        record_id: Optional[str] = None,
    ) -> MedicalRecord:
        """Encrypt, store, register, and persist one EHR record."""

        patient = self.database.get_patient(patient_id)
        doctor = self.database.get_doctor(doctor_id)
        if patient is None:
            raise ValueError("patient does not exist")
        if doctor is None:
            raise ValueError("doctor does not exist")
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"unsupported key-protection algorithm: {algorithm}")
        if doctor.key_algorithm != algorithm:
            raise ValueError("requested algorithm does not match doctor's registered key algorithm")
        record_id = record_id or f"record-{uuid.uuid4().hex}"
        if self.database.get_record(record_id) is not None:
            raise ValueError("medical record already exists")
        plaintext = _read_ehr_bytes(ehr_file)
        aes_key = generate_key()
        aad = record_aad(record_id, algorithm, doctor_id)
        nonce, ciphertext, tag = encrypt_record(plaintext, aes_key, aad)
        if algorithm == ECC_ALGORITHM:
            public_key = deserialize_ecc_public_key(doctor.public_key)
            wrapped_key = protect_aes_key_ecc(aes_key, public_key, doctor_id)
        else:
            public_key = deserialize_mlkem_public_key(doctor.public_key)
            wrapped_key = protect_aes_key_mlkem(aes_key, public_key, doctor_id)
        envelope = EncryptedEnvelope.create(
            record_id=record_id,
            key_protection=algorithm,
            key_reference=doctor_id,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            wrapped_key=wrapped_key,
        )
        validate_envelope(envelope)
        reference = self.storage.upload_encrypted_record(envelope)
        try:
            register_kwargs = {"sender": self.registrar_address} if self.registrar_address else {}
            self.blockchain.register_record(record_id, reference, envelope.ciphertext_hash, **register_kwargs)
            stored = MedicalRecord(
                record_id=record_id,
                patient_id=patient_id,
                encrypted_file_hash=envelope.ciphertext_hash,
                ipfs_cid=reference if self.storage.backend_name == "ipfs" else None,
                key_protection_algorithm=algorithm,
                storage_backend=self.storage.backend_name,
                storage_reference=reference,
            )
            self.database.add_record(stored)
        except Exception:
            self._audit(
                action="upload_record",
                outcome="failure",
                record_id=record_id,
                patient_id=patient_id,
                doctor_id=doctor_id,
                backend=self.storage.backend_name,
                detail="blockchain registration or metadata persistence failed",
            )
            raise
        self._audit(
            action="upload_record",
            outcome="success",
            record_id=record_id,
            patient_id=patient_id,
            doctor_id=doctor_id,
            backend=self.storage.backend_name,
        )
        return stored

    def request_record(self, doctor_id: str, record_id: str) -> bytes:
        """Authorize, retrieve, recover the AES key, and decrypt an EHR."""

        doctor = self.database.get_doctor(doctor_id)
        record = self.database.get_record(record_id)
        if doctor is None:
            raise ValueError("doctor does not exist")
        if record is None:
            raise ValueError("medical record does not exist")
        doctor_address = self._doctor_address(doctor_id)
        if not self.blockchain.check_access(record_id, doctor_address):
            self._audit(action="request_record", outcome="denied", record_id=record_id, doctor_id=doctor_id)
            raise PermissionError("blockchain access is not granted")
        if not check_access(self.database, record.patient_id, doctor_id, record_id):
            self._audit(
                action="request_record",
                outcome="denied",
                record_id=record_id,
                patient_id=record.patient_id,
                doctor_id=doctor_id,
                detail="local patient consent is not active",
            )
            raise PermissionError("patient consent is not active")
        if self.private_key_resolver is None:
            raise ValueError("private_key_resolver is required for doctor retrieval")
        cid, chain_hash, _ = self.blockchain.get_record_metadata(record_id)
        if chain_hash.hex() != record.encrypted_file_hash.lower().removeprefix("0x"):
            raise StorageError("blockchain hash does not match local record metadata")
        envelope = self.storage.download_encrypted_record(cid)
        if envelope.record_id != record_id or envelope.ciphertext_hash != record.encrypted_file_hash:
            raise StorageError("retrieved envelope does not match record metadata")
        private_key = self.private_key_resolver(doctor_id)
        aad = record_aad(record_id, envelope.key_protection, envelope.key_reference)
        if envelope.key_protection == ECC_ALGORITHM:
            aes_key = recover_aes_key_ecc(envelope.wrapped_key, private_key)
        elif envelope.key_protection == MLKEM_ALGORITHM:
            aes_key = recover_aes_key_mlkem(envelope.wrapped_key, private_key)
        else:
            raise StorageError("unsupported envelope key-protection algorithm")
        plaintext = decrypt_record(envelope.nonce, envelope.ciphertext, envelope.tag, aes_key, aad)
        register_kwargs = {"sender": doctor_address}
        self.blockchain.record_access(record_id, **register_kwargs)
        self._audit(
            action="request_record",
            outcome="success",
            record_id=record_id,
            patient_id=record.patient_id,
            doctor_id=doctor_id,
            backend=self.storage.backend_name,
        )
        return plaintext
