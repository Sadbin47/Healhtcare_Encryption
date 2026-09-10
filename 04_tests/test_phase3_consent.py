"""Focused Phase 3 patient-consent tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from consent import check_access, grant_access, list_active_grants_for_record, revoke_access  # noqa: E402
from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from models import MedicalRecord  # noqa: E402


class Phase3ConsentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = Database()
        self.patient = register_patient(self.database, "patient-001", "Patient Alias")
        self.other_patient = register_patient(self.database, "patient-002", "Other Alias")
        self.doctor = register_doctor(
            self.database,
            "doctor-001",
            "Doctor A",
            "public-key-material",
            "ML-KEM-768-AES-GCM",
        )
        self.other_doctor = register_doctor(
            self.database,
            "doctor-002",
            "Doctor B",
            "other-public-key-material",
            "ECC-ECDH-P256-AES-GCM",
        )
        self.record = self.database.add_record(
            MedicalRecord(
                "record-001",
                self.patient.patient_id,
                "a" * 64,
                None,
                "ML-KEM-768-AES-GCM",
            )
        )

    def tearDown(self) -> None:
        self.database.close()

    def test_grant_allows_access_and_is_idempotent(self) -> None:
        self.assertFalse(check_access(self.database, "patient-001", "doctor-001", "record-001"))
        first = grant_access(self.database, "patient-001", "doctor-001", "record-001")
        second = grant_access(self.database, "patient-001", "doctor-001", "record-001")
        self.assertTrue(check_access(self.database, "patient-001", "doctor-001", "record-001"))
        self.assertEqual(first.patient_id, second.patient_id)
        self.assertEqual(first.granted_at, second.granted_at)
        self.assertEqual(len(list_active_grants_for_record(self.database, "record-001")), 1)

    def test_revoke_denies_future_access_and_regrant_reactivates(self) -> None:
        grant_access(self.database, "patient-001", "doctor-001", "record-001")
        revoked = revoke_access(self.database, "patient-001", "doctor-001", "record-001")
        self.assertIsNotNone(revoked)
        self.assertIsNotNone(revoked.revoked_at)
        self.assertFalse(check_access(self.database, "patient-001", "doctor-001", "record-001"))
        reactivated = grant_access(self.database, "patient-001", "doctor-001", "record-001")
        self.assertIsNone(reactivated.revoked_at)
        self.assertTrue(check_access(self.database, "patient-001", "doctor-001", "record-001"))

    def test_grant_requires_record_ownership_and_registered_entities(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not belong"):
            grant_access(self.database, "patient-002", "doctor-001", "record-001")
        with self.assertRaisesRegex(ValueError, "doctor does not exist"):
            grant_access(self.database, "patient-001", "missing-doctor", "record-001")
        with self.assertRaisesRegex(ValueError, "unsupported permission"):
            grant_access(self.database, "patient-001", "doctor-001", "record-001", "write")

    def test_denial_is_scoped_to_the_exact_patient_doctor_record(self) -> None:
        grant_access(self.database, "patient-001", "doctor-001", "record-001")
        self.assertFalse(check_access(self.database, "patient-002", "doctor-001", "record-001"))
        self.assertFalse(check_access(self.database, "patient-001", "doctor-002", "record-001"))
        self.assertFalse(check_access(self.database, "patient-001", "doctor-001", "missing-record"))

    def test_revoke_without_existing_grant_is_safe(self) -> None:
        self.assertIsNone(revoke_access(self.database, "patient-001", "doctor-001", "record-001"))


if __name__ == "__main__":
    unittest.main()
