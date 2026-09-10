"""Phase 6 end-to-end workflow tests using local storage and a fake chain."""

from __future__ import annotations

import base64
import sys
import tempfile
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from api import HealthcareAPI  # noqa: E402
from audit import (  # noqa: E402
    ACCESS_DENIED,
    ACCESS_GRANTED,
    ACCESS_REVOKED,
    DECRYPTION_SUCCESS,
    RECORD_CREATED,
    RECORD_RETRIEVED,
    MemoryAuditSink,
)
from consent import grant_access  # noqa: E402
from crypto.ecc_protection import (  # noqa: E402
    ALGORITHM as ECC_ALGORITHM,
    generate_key_pair as generate_ecc_key_pair,
    serialize_public_key as serialize_ecc_public_key,
)
from crypto.mlkem_protection import (  # noqa: E402
    ALGORITHM as MLKEM_ALGORITHM,
    generate_key_pair as generate_mlkem_key_pair,
    serialize_public_key as serialize_mlkem_public_key,
)
from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from service import HealthcareWorkflowService  # noqa: E402
from storage import LocalStorage  # noqa: E402


PATIENT_ID = "patient-001"
DOCTOR_ID = "doctor-001"
DOCTOR_ADDRESS = "0x2222222222222222222222222222222222222222"


class FakeBlockchain:
    def __init__(self):
        self.records = {}
        self.permissions = set()
        self.access_events = []

    def register_record(self, record_id, cid, file_hash, **kwargs):
        if record_id in self.records:
            raise ValueError("duplicate record")
        self.records[record_id] = (cid, bytes.fromhex(file_hash) if isinstance(file_hash, str) else file_hash, kwargs.get("sender"))
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


class Phase6ServiceTests(unittest.TestCase):
    def _service(self, algorithm):
        database = Database()
        patient = register_patient(database, PATIENT_ID, "Patient Alias")
        if algorithm == ECC_ALGORITHM:
            private_key, public_key = generate_ecc_key_pair()
            serialized_public = serialize_ecc_public_key(public_key)
        else:
            private_key, public_key = generate_mlkem_key_pair()
            serialized_public = serialize_mlkem_public_key(public_key)
        register_doctor(database, DOCTOR_ID, "Doctor", serialized_public, algorithm)
        storage_root = tempfile.TemporaryDirectory()
        storage = LocalStorage(storage_root.name)
        blockchain = FakeBlockchain()
        audit = MemoryAuditSink()
        service = HealthcareWorkflowService(
            database,
            storage,
            blockchain,
            doctor_addresses={DOCTOR_ID: DOCTOR_ADDRESS},
            private_key_resolver=lambda _doctor_id: private_key,
            registrar_address="0x1111111111111111111111111111111111111111",
            audit_sink=audit,
        )
        return database, storage_root, blockchain, audit, service

    def test_upload_and_request_round_trip_for_ecc(self) -> None:
        self._round_trip(ECC_ALGORITHM)

    def test_upload_and_request_round_trip_for_mlkem(self) -> None:
        self._round_trip(MLKEM_ALGORITHM)

    def _round_trip(self, algorithm):
        database, storage_root, blockchain, audit, service = self._service(algorithm)
        try:
            source = b"patient,diagnosis\n001,example\n"
            record = service.upload_record(PATIENT_ID, source, DOCTOR_ID, algorithm, record_id="record-001")
            self.assertEqual(record.storage_backend, "local")
            self.assertNotEqual(record.encrypted_file_hash, "")
            with self.assertRaises(PermissionError):
                service.request_record(DOCTOR_ID, record.record_id)
            blockchain.grant_access(record.record_id, DOCTOR_ADDRESS)
            grant_access(database, PATIENT_ID, DOCTOR_ID, record.record_id)
            self.assertEqual(service.request_record(DOCTOR_ID, record.record_id), source)
            self.assertEqual(
                [event.outcome for event in audit.events],
                ["success", "denied", "success", "success"],
            )
            self.assertEqual(
                [event.operation for event in audit.events],
                [RECORD_CREATED, ACCESS_DENIED, DECRYPTION_SUCCESS, RECORD_RETRIEVED],
            )
            self.assertEqual(blockchain.access_events, [("record-001", DOCTOR_ADDRESS)])
        finally:
            database.close()
            storage_root.cleanup()

    def test_api_authentication_and_base64_transport(self) -> None:
        database, storage_root, blockchain, _audit, service = self._service(ECC_ALGORITHM)
        try:
            api = HealthcareAPI(service, authenticate=lambda payload: payload.get("token") == "ok")
            response = api.upload(
                {
                    "token": "ok",
                    "patient_id": PATIENT_ID,
                    "doctor_id": DOCTOR_ID,
                    "algorithm": ECC_ALGORITHM,
                    "record_id": "record-api",
                    "ehr_base64": base64.b64encode(b"api ehr").decode("ascii"),
                }
            )
            self.assertEqual(response["record_id"], "record-api")
            with self.assertRaises(PermissionError):
                api.request({"token": "bad", "doctor_id": DOCTOR_ID, "record_id": "record-api"})
            blockchain.grant_access("record-api", DOCTOR_ADDRESS)
            grant_access(database, PATIENT_ID, DOCTOR_ID, "record-api")
            result = api.request({"token": "ok", "doctor_id": DOCTOR_ID, "record_id": "record-api"})
            self.assertEqual(base64.b64decode(result["ehr_base64"]), b"api ehr")
        finally:
            database.close()
            storage_root.cleanup()

    def test_service_grant_and_revoke_are_audited(self) -> None:
        database, storage_root, blockchain, audit, service = self._service(ECC_ALGORITHM)
        try:
            service.upload_record(
                PATIENT_ID, b"consent test", DOCTOR_ID, ECC_ALGORITHM, record_id="record-consent"
            )
            grant = service.grant_doctor_access(PATIENT_ID, DOCTOR_ID, "record-consent")
            self.assertIsNone(grant.revoked_at)
            self.assertTrue(blockchain.check_access("record-consent", DOCTOR_ADDRESS))
            revoked = service.revoke_doctor_access(PATIENT_ID, DOCTOR_ID, "record-consent")
            self.assertIsNotNone(revoked.revoked_at)
            self.assertFalse(blockchain.check_access("record-consent", DOCTOR_ADDRESS))
            self.assertEqual(
                [item.operation for item in audit.events],
                [RECORD_CREATED, ACCESS_GRANTED, ACCESS_REVOKED],
            )
        finally:
            database.close()
            storage_root.cleanup()


if __name__ == "__main__":
    unittest.main()
