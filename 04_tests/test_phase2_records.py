"""Focused Phase 2 tests; run from the V2 root with unittest discovery."""

from __future__ import annotations

import sqlite3
import unittest

from pathlib import Path
import sys

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from models import AccessGrant, MedicalRecord  # noqa: E402


class Phase2RecordTests(unittest.TestCase):
    def test_register_and_retrieve_metadata(self) -> None:
        with Database() as database:
            patient = register_patient(database, "patient-001", "Patient Alias 001")
            doctor = register_doctor(
                database,
                "doctor-001",
                "Doctor A",
                "public-key-material",
                "ML-KEM-768-AES-GCM",
            )
            record = database.add_record(
                MedicalRecord(
                    record_id="record-001",
                    patient_id=patient.patient_id,
                    encrypted_file_hash="a" * 64,
                    key_protection_algorithm=doctor.key_algorithm,
                )
            )
            grant = database.add_access_grant(
                AccessGrant(patient.patient_id, doctor.doctor_id, record.record_id)
            )

            self.assertEqual(database.get_patient(patient.patient_id), patient)
            self.assertEqual(database.get_doctor(doctor.doctor_id), doctor)
            self.assertEqual(database.get_record(record.record_id), record)
            self.assertEqual(
                database.get_access_grant(patient.patient_id, doctor.doctor_id, record.record_id),
                grant,
            )

    def test_foreign_keys_and_duplicate_ids(self) -> None:
        with Database() as database:
            patient = register_patient(database, "patient-001", "Alias")
            with self.assertRaises(ValueError):
                register_patient(database, "patient-001", "Duplicate")
            with self.assertRaises(ValueError):
                database.add_record(
                    MedicalRecord(
                        "record-001",
                        "missing-patient",
                        "b" * 64,
                        "ML-KEM-768-AES-GCM",
                    )
                )
            self.assertEqual(database.get_patient(patient.patient_id), patient)

    def test_database_contains_no_plaintext_or_private_key_columns(self) -> None:
        with Database() as database:
            tables = {
                row["name"]: row["sql"]
                for row in database.connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'table'"
                )
            }
            schema = "\n".join(tables.values()).lower()
            for forbidden in ("plaintext", "aes_key", "private_key", "ehr_data"):
                self.assertNotIn(forbidden, schema)
            self.assertTrue("public_key" in tables["doctors"])
            self.assertTrue("encrypted_file_hash" in tables["medical_records"])


if __name__ == "__main__":
    unittest.main()
