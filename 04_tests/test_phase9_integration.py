"""Phase 9 integration tests for the complete local workflow.

These tests intentionally use local storage and a deterministic blockchain
double. They verify the application composition without claiming that a live
IPFS node, EVM chain, or VPN tunnel was deployed.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from audit import (  # noqa: E402
    ACCESS_DENIED,
    ACCESS_GRANTED,
    ACCESS_REVOKED,
    DECRYPTION_FAILED,
    DECRYPTION_SUCCESS,
    RECORD_CREATED,
    RECORD_RETRIEVED,
    MemoryAuditSink,
)
from consent import grant_access, revoke_access  # noqa: E402
from crypto.aes_gcm import decrypt_record, encrypt_record, generate_key  # noqa: E402
from crypto.ecc_protection import (  # noqa: E402
    ALGORITHM as ECC_ALGORITHM,
    generate_key_pair as generate_ecc_key_pair,
    serialize_public_key as serialize_ecc_public_key,
)
from crypto.envelope import EncryptedEnvelope, record_aad  # noqa: E402
from crypto.mlkem_protection import (  # noqa: E402
    ALGORITHM as MLKEM_ALGORITHM,
    generate_key_pair as generate_mlkem_key_pair,
    serialize_public_key as serialize_mlkem_public_key,
)
from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from service import HealthcareWorkflowService  # noqa: E402
from storage import LocalStorage, RecordNotFound, StorageError  # noqa: E402


PATIENT_ID = "patient-001"
OTHER_PATIENT_ID = "patient-002"
DOCTOR_ID = "doctor-001"
OTHER_DOCTOR_ID = "doctor-002"
DOCTOR_ADDRESS = "0x2222222222222222222222222222222222222222"
OTHER_DOCTOR_ADDRESS = "0x3333333333333333333333333333333333333333"
REGISTRAR_ADDRESS = "0x1111111111111111111111111111111111111111"
EHR_BYTES = b"patient_id,diagnosis\npatient-001,example\n"


class FakeBlockchain:
    """Small deterministic double for the Phase 5 client contract."""

    def __init__(self) -> None:
        self.records: dict[str, tuple[str, bytes, str | None]] = {}
        self.permissions: set[tuple[str, str]] = set()
        self.access_events: list[tuple[str, str | None]] = []

    def register_record(self, record_id, cid, file_hash, **kwargs):
        if record_id in self.records:
            raise ValueError("record already registered")
        digest = bytes.fromhex(file_hash) if isinstance(file_hash, str) else bytes(file_hash)
        self.records[record_id] = (cid, digest, kwargs.get("sender"))
        return "tx-register"

    def grant_access(self, record_id, doctor_address, **kwargs):
        self.permissions.add((record_id, doctor_address))
        return "tx-grant"

    def revoke_access(self, record_id, doctor_address, **kwargs):
        self.permissions.discard((record_id, doctor_address))
        return "tx-revoke"

    def check_access(self, record_id, doctor_address):
        return (record_id, doctor_address) in self.permissions

    def get_record_metadata(self, record_id):
        return self.records[record_id]

    def record_access(self, record_id, **kwargs):
        self.access_events.append((record_id, kwargs.get("sender")))
        return "tx-access"


class Phase9IntegrationTests(unittest.TestCase):
    def _build_service(self, algorithm: str):
        database = Database()
        register_patient(database, PATIENT_ID, "Patient Alias")
        register_patient(database, OTHER_PATIENT_ID, "Other Alias")
        if algorithm == ECC_ALGORITHM:
            private_key, public_key = generate_ecc_key_pair()
            public_key_text = serialize_ecc_public_key(public_key)
        else:
            private_key, public_key = generate_mlkem_key_pair()
            public_key_text = serialize_mlkem_public_key(public_key)
        register_doctor(database, DOCTOR_ID, "Doctor A", public_key_text, algorithm)
        register_doctor(database, OTHER_DOCTOR_ID, "Doctor B", public_key_text, algorithm)
        storage_root = tempfile.TemporaryDirectory()
        blockchain = FakeBlockchain()
        audit = MemoryAuditSink()
        service = HealthcareWorkflowService(
            database,
            LocalStorage(storage_root.name),
            blockchain,
            doctor_addresses={DOCTOR_ID: DOCTOR_ADDRESS, OTHER_DOCTOR_ID: OTHER_DOCTOR_ADDRESS},
            private_key_resolver=lambda doctor_id: private_key if doctor_id == DOCTOR_ID else None,
            registrar_address=REGISTRAR_ADDRESS,
            audit_sink=audit,
        )
        return database, storage_root, blockchain, audit, service, private_key

    def _upload_and_authorize(self, algorithm: str, record_id: str = "record-001"):
        database, storage_root, blockchain, audit, service, private_key = self._build_service(algorithm)
        record = service.upload_record(PATIENT_ID, EHR_BYTES, DOCTOR_ID, algorithm, record_id=record_id)
        service.grant_doctor_access(PATIENT_ID, DOCTOR_ID, record_id)
        return database, storage_root, blockchain, audit, service, private_key, record

    def test_complete_ecc_lifecycle_and_revocation(self) -> None:
        self._complete_lifecycle(ECC_ALGORITHM)

    def test_complete_mlkem_lifecycle_and_revocation(self) -> None:
        self._complete_lifecycle(MLKEM_ALGORITHM)

    def _complete_lifecycle(self, algorithm: str) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(algorithm)
        try:
            self.assertEqual(service.request_record(DOCTOR_ID, record.record_id), EHR_BYTES)
            self.assertEqual(blockchain.access_events, [(record.record_id, DOCTOR_ADDRESS)])
            self.assertEqual(
                [event.operation for event in audit.events],
                [RECORD_CREATED, ACCESS_GRANTED, DECRYPTION_SUCCESS, RECORD_RETRIEVED],
            )
            service.revoke_doctor_access(PATIENT_ID, DOCTOR_ID, record.record_id)
            with self.assertRaises(PermissionError):
                service.request_record(DOCTOR_ID, record.record_id)
            self.assertEqual(audit.events[-2].operation, ACCESS_REVOKED)
            self.assertEqual(audit.events[-1].operation, ACCESS_DENIED)
        finally:
            database.close()
            storage_root.cleanup()

    def test_aes_round_trip_is_independent_of_key_protection(self) -> None:
        key = generate_key()
        nonce, ciphertext, tag = encrypt_record(EHR_BYTES, key, b"integration-aad")
        self.assertEqual(decrypt_record(nonce, ciphertext, tag, key, b"integration-aad"), EHR_BYTES)

    def test_modified_ciphertext_is_rejected(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(ECC_ALGORITHM)
        try:
            reference = record.storage_reference
            self.assertIsNotNone(reference)
            path = Path(storage_root.name) / reference
            value = json.loads(path.read_text(encoding="utf-8"))
            value["ciphertext"] = base64.b64encode(b"modified").decode("ascii")
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(StorageError):
                service.request_record(DOCTOR_ID, record.record_id)
            self.assertEqual(audit.events[-1].operation, DECRYPTION_FAILED)
        finally:
            database.close()
            storage_root.cleanup()

    def test_wrong_doctor_key_is_rejected(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(MLKEM_ALGORITHM)
        try:
            grant_access(database, PATIENT_ID, OTHER_DOCTOR_ID, record.record_id)
            blockchain.grant_access(record.record_id, OTHER_DOCTOR_ADDRESS)
            wrong_private_key, _ = generate_mlkem_key_pair()
            service.private_key_resolver = lambda _doctor_id: wrong_private_key
            with self.assertRaises(Exception) as failure:
                service.request_record(OTHER_DOCTOR_ID, record.record_id)
            self.assertNotIsInstance(failure.exception, PermissionError)
            self.assertEqual(audit.events[-1].operation, DECRYPTION_FAILED)
        finally:
            database.close()
            storage_root.cleanup()

    def test_wrong_patient_is_denied(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(ECC_ALGORITHM)
        try:
            with self.assertRaisesRegex(ValueError, "does not belong"):
                grant_access(database, OTHER_PATIENT_ID, DOCTOR_ID, record.record_id)
            revoke_access(database, PATIENT_ID, DOCTOR_ID, record.record_id)
            with self.assertRaises(PermissionError):
                service.request_record(DOCTOR_ID, record.record_id)
            self.assertFalse(
                service.blockchain.check_access(record.record_id, OTHER_DOCTOR_ADDRESS)
            )
            self.assertEqual(database.get_record(record.record_id).patient_id, PATIENT_ID)
        finally:
            database.close()
            storage_root.cleanup()

    def test_invalid_blockchain_permission_is_denied(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key = self._build_service(ECC_ALGORITHM)
        try:
            service.upload_record(PATIENT_ID, EHR_BYTES, DOCTOR_ID, ECC_ALGORITHM, record_id="record-chain-denied")
            grant_access(database, PATIENT_ID, DOCTOR_ID, "record-chain-denied")
            with self.assertRaises(PermissionError):
                service.request_record(DOCTOR_ID, "record-chain-denied")
            self.assertEqual(audit.events[-1].operation, ACCESS_DENIED)
        finally:
            database.close()
            storage_root.cleanup()

    def test_invalid_cid_and_missing_file_are_rejected(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(ECC_ALGORITHM)
        try:
            blockchain.records[record.record_id] = (
                "invalid-cid",
                bytes.fromhex(record.encrypted_file_hash),
                REGISTRAR_ADDRESS,
            )
            with self.assertRaises(RecordNotFound):
                service.request_record(DOCTOR_ID, record.record_id)
            blockchain.records[record.record_id] = (
                record.storage_reference,
                bytes.fromhex(record.encrypted_file_hash),
                REGISTRAR_ADDRESS,
            )
            Path(storage_root.name, record.storage_reference).unlink()
            with self.assertRaises(RecordNotFound):
                service.request_record(DOCTOR_ID, record.record_id)
        finally:
            database.close()
            storage_root.cleanup()

    def test_wrong_wrapper_and_repeated_access(self) -> None:
        database, storage_root, blockchain, audit, service, _private_key, record = self._upload_and_authorize(ECC_ALGORITHM)
        try:
            reference = record.storage_reference
            path = Path(storage_root.name) / reference
            original = path.read_text(encoding="utf-8")
            value = json.loads(original)
            value["wrapped_key"]["wrapped_aes_key"] = base64.b64encode(b"wrong-wrapper").decode("ascii")
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(Exception):
                service.request_record(DOCTOR_ID, record.record_id)
            path.write_text(original, encoding="utf-8")
            self.assertEqual(service.request_record(DOCTOR_ID, record.record_id), EHR_BYTES)
            self.assertEqual(service.request_record(DOCTOR_ID, record.record_id), EHR_BYTES)
            self.assertEqual(len(blockchain.access_events), 2)
            self.assertEqual(
                sum(event.operation == RECORD_RETRIEVED for event in audit.events), 2
            )
        finally:
            database.close()
            storage_root.cleanup()


if __name__ == "__main__":
    unittest.main()
