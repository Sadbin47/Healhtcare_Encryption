"""Phase 4 storage and consent-gated retrieval tests."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from consent import grant_access  # noqa: E402
from crypto.aes_gcm import encrypt_record, generate_key  # noqa: E402
from crypto.envelope import EncryptedEnvelope  # noqa: E402
from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from models import MedicalRecord  # noqa: E402
from record_storage import retrieve_encrypted_record, store_encrypted_record  # noqa: E402
from storage import (  # noqa: E402
    LocalStorage,
    RecordNotFound,
    StorageError,
    StorageIntegrityError,
    VPSStorage,
    create_vps_server,
)


def make_envelope(record_id: str = "record-001") -> EncryptedEnvelope:
    nonce, ciphertext, tag = encrypt_record(b"encrypted EHR test bytes", generate_key())
    return EncryptedEnvelope.create(
        record_id=record_id,
        key_protection="ML-KEM-768",
        key_reference="doctor-key-001",
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        wrapped_key={"algorithm": "ML-KEM-768"},
    )


class Phase4StorageTests(unittest.TestCase):
    def test_local_round_trip_and_missing_reference(self) -> None:
        envelope = make_envelope()
        with tempfile.TemporaryDirectory() as directory:
            store = LocalStorage(directory)
            reference = store.upload_encrypted_record(envelope)
            self.assertEqual(store.download_encrypted_record(reference), envelope)
            with self.assertRaises(RecordNotFound):
                store.download_encrypted_record("missing")

    def test_local_storage_rejects_tampering(self) -> None:
        envelope = make_envelope()
        with tempfile.TemporaryDirectory() as directory:
            store = LocalStorage(directory)
            reference = store.upload_encrypted_record(envelope)
            path = Path(directory) / reference
            value = json.loads(path.read_text(encoding="utf-8"))
            value["ciphertext"] = "AA=="
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(StorageIntegrityError):
                store.download_encrypted_record(reference)

    def test_vps_client_uses_authentication_and_round_trips(self) -> None:
        envelope = make_envelope()
        captured: list[tuple[str, str, dict[str, str], bytes | None]] = []

        def requester(method, url, headers, body, timeout):
            captured.append((method, url, dict(headers), body))
            if method == "POST":
                return 201, b'{"reference":"object-001"}'
            return 200, envelope.to_json().encode("utf-8")

        store = VPSStorage("https://storage.example.test", "secret-token", requester=requester)
        self.assertEqual(store.upload_encrypted_record(envelope), "object-001")
        self.assertEqual(store.download_encrypted_record("object-001"), envelope)
        self.assertEqual(captured[0][2]["Authorization"], "Bearer secret-token")
        self.assertIn("/records/object-001", captured[1][1])
        with self.assertRaises(ValueError):
            VPSStorage("http://storage.example.test", "secret-token")

    def test_vps_api_and_client_round_trip(self) -> None:
        envelope = make_envelope()
        with tempfile.TemporaryDirectory() as directory:
            server = create_vps_server("127.0.0.1", 0, "api-token", directory)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                store = VPSStorage(url, "api-token", allow_insecure_http=True)
                reference = store.upload_encrypted_record(envelope)
                self.assertEqual(store.download_encrypted_record(reference), envelope)
                unauthorized = VPSStorage(url, "wrong-token", allow_insecure_http=True)
                with self.assertRaises(StorageError):
                    unauthorized.download_encrypted_record(reference)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_storage_reference_and_consent_gate(self) -> None:
        envelope = make_envelope()
        with tempfile.TemporaryDirectory() as directory, Database() as database:
            patient = register_patient(database, "patient-001", "Alias")
            doctor = register_doctor(database, "doctor-001", "Doctor", "public", "ML-KEM-768-AES-GCM")
            database.add_record(
                MedicalRecord(
                    "record-001",
                    patient.patient_id,
                    envelope.ciphertext_hash,
                    envelope.key_protection,
                )
            )
            store = LocalStorage(directory)
            stored = store_encrypted_record(database, store, envelope, patient.patient_id)
            self.assertEqual(stored.storage_backend, "local")
            self.assertIsNotNone(stored.storage_reference)
            with self.assertRaises(PermissionError):
                retrieve_encrypted_record(database, store, patient.patient_id, doctor.doctor_id, "record-001")
            grant_access(database, patient.patient_id, doctor.doctor_id, "record-001")
            self.assertEqual(
                retrieve_encrypted_record(database, store, patient.patient_id, doctor.doctor_id, "record-001"),
                envelope,
            )
            other_backend = VPSStorage(
                "https://storage.example.test", "token", requester=lambda *args: (500, b"")
            )
            with self.assertRaisesRegex(StorageError, "stored in local"):
                retrieve_encrypted_record(
                    database, other_backend, patient.patient_id, doctor.doctor_id, "record-001"
                )

    def test_fresh_schema_has_storage_reference_only(self) -> None:
        with Database() as database:
            columns = {
                row["name"] for row in database.connection.execute("PRAGMA table_info(medical_records)")
            }
            self.assertIn("storage_backend", columns)
            self.assertIn("storage_reference", columns)


if __name__ == "__main__":
    unittest.main()
