"""Phase 10 dataset validation, grouping, and workflow-connection tests."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

SCRIPTS = Path(__file__).parents[1] / "05_scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from import_ehr import (  # noqa: E402
    DatasetImportError,
    connect_dataset,
    load_dataset,
    write_manifest,
)
from crypto.ecc_protection import (  # noqa: E402
    ALGORITHM as ECC_ALGORITHM,
    generate_key_pair,
    serialize_public_key,
)
from database import Database  # noqa: E402
from identity import register_doctor, register_patient  # noqa: E402
from service import HealthcareWorkflowService  # noqa: E402
from storage import LocalStorage  # noqa: E402


ROOT = Path(__file__).parents[3]
SOURCE = ROOT / "06_Datasets_and_Data" / "EHR.csv"


class _Record:
    def __init__(self, record_id: str) -> None:
        self.record_id = record_id
        self.storage_backend = "local"
        self.storage_reference = f"{record_id}.json"
        self.encrypted_file_hash = "a" * 64


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, str, str, str]] = []

    def upload_record(self, patient_id, payload, doctor_id, algorithm, *, record_id):
        self.calls.append((patient_id, payload, doctor_id, algorithm, record_id))
        return _Record(record_id)


class _Blockchain:
    def __init__(self) -> None:
        self.records = {}
        self.permissions = set()

    def register_record(self, record_id, reference, file_hash, **_kwargs):
        self.records[record_id] = (reference, bytes.fromhex(file_hash), None)

    def grant_access(self, record_id, doctor_address, **_kwargs):
        self.permissions.add((record_id, doctor_address))

    def check_access(self, record_id, doctor_address):
        return (record_id, doctor_address) in self.permissions

    def get_record_metadata(self, record_id):
        return self.records[record_id]

    def record_access(self, _record_id, **_kwargs):
        return "tx-access"


class Phase10DatasetTests(unittest.TestCase):
    def test_real_dataset_is_valid_and_dataset_mode_preserves_source_bytes(self) -> None:
        before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        imported = load_dataset(SOURCE, mode="dataset")
        self.assertEqual(imported.summary.row_count, 1447)
        self.assertEqual(imported.summary.column_count, 29)
        self.assertEqual(imported.summary.patient_unit_count, 1447)
        self.assertEqual(len(imported.units), 1)
        self.assertEqual(imported.units[0].payload, SOURCE.read_bytes())
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), before)

    def test_patient_mode_is_deterministic_and_preserves_group_row_order(self) -> None:
        source = (
            "patientunitstayid,diagnosis,value\n"
            "b,\"Hypertension, uncontrolled\",2\n"
            "a,Flu,1\n"
            "b,\"Hypertension, uncontrolled\",3\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ehr.csv"
            path.write_text(source, encoding="utf-8", newline="")
            first = load_dataset(path, mode="patient")
            second = load_dataset(path, mode="patient")
        self.assertEqual([unit.unit_id for unit in first.units], ["patientunitstay-a", "patientunitstay-b"])
        self.assertEqual(first, second)
        self.assertEqual(first.units[1].row_count, 2)
        self.assertIn(b"Hypertension, uncontrolled", first.units[1].payload)
        self.assertEqual(first.units[1].source_row_numbers, (2, 4))

    def test_validation_rejects_missing_column_and_malformed_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.csv"
            missing.write_text("id,value\n1,ok\n", encoding="utf-8")
            malformed = Path(directory) / "malformed.csv"
            malformed.write_text('patientunitstayid,value\n1,"unterminated\n', encoding="utf-8")
            with self.assertRaisesRegex(DatasetImportError, "missing required column"):
                load_dataset(missing)
            with self.assertRaises(DatasetImportError):
                load_dataset(malformed)

    def test_validation_rejects_short_rows_and_empty_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            short = Path(directory) / "short.csv"
            short.write_text("patientunitstayid,value\n1\n", encoding="utf-8")
            empty = Path(directory) / "empty-id.csv"
            empty.write_text("patientunitstayid,value\n,ok\n", encoding="utf-8")
            with self.assertRaises(DatasetImportError):
                load_dataset(short)
            with self.assertRaises(DatasetImportError):
                load_dataset(empty)

    def test_connector_requires_explicit_patient_mapping_and_uploads_units(self) -> None:
        source = "patientunitstayid,value\na,one\nb,two\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ehr.csv"
            path.write_text(source, encoding="utf-8")
            imported = load_dataset(path, mode="patient")
            service = _Service()
            with self.assertRaisesRegex(ValueError, "patient_id_for_unit"):
                connect_dataset(service, imported, doctor_id="doctor", algorithm="ECC")
            records = connect_dataset(
                service,
                imported,
                doctor_id="doctor",
                algorithm="ECC",
                patient_id_for_unit=lambda unit: f"app-{unit.patientunitstayid}",
            )
        self.assertEqual([record.record_id for record in records], ["ehr-patientunitstay-a", "ehr-patientunitstay-b"])
        self.assertEqual([call[0] for call in service.calls], ["app-a", "app-b"])
        self.assertTrue(all(b"private_key" not in payload for _, payload, *_ in service.calls))

    def test_manifest_contains_metadata_only(self) -> None:
        source = "patientunitstayid,diagnosis\na,private diagnosis\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ehr.csv"
            path.write_text(source, encoding="utf-8")
            imported = load_dataset(path)
            manifest_path = write_manifest(imported, Path(directory) / "out")
            manifest_text = manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
        self.assertNotIn("private diagnosis", manifest_text)
        self.assertNotIn("aes_key", manifest_text)
        self.assertNotIn("private_key", manifest_text)
        self.assertEqual(manifest["units"][0]["row_count"], 1)
        self.assertNotIn("payload", manifest["units"][0])

    def test_dataset_mode_connects_to_real_local_workflow(self) -> None:
        source = "patientunitstayid,diagnosis\na,Hypertension\n"
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "ehr.csv"
            source_path.write_text(source, encoding="utf-8")
            imported = load_dataset(source_path, mode="dataset")
            database = Database()
            storage = LocalStorage(Path(directory) / "storage")
            private_key, public_key = generate_key_pair()
            register_patient(database, "patient-app-001", "Patient alias")
            register_doctor(
                database,
                "doctor-001",
                "Doctor",
                serialize_public_key(public_key),
                ECC_ALGORITHM,
            )
            blockchain = _Blockchain()
            address = "0x" + "11" * 20
            service = HealthcareWorkflowService(
                database,
                storage,
                blockchain,
                doctor_addresses={"doctor-001": address},
                private_key_resolver=lambda _doctor_id: private_key,
            )
            records = connect_dataset(
                service,
                imported,
                patient_id="patient-app-001",
                doctor_id="doctor-001",
                algorithm=ECC_ALGORITHM,
                record_id_prefix="dataset",
            )
            record = records[0]
            blockchain.grant_access(record.record_id, address)
            service.grant_doctor_access("patient-app-001", "doctor-001", record.record_id)
            recovered = service.request_record("doctor-001", record.record_id)
            database.close()
        self.assertEqual(recovered, source.encode("utf-8"))
        self.assertEqual(record.storage_backend, "local")


if __name__ == "__main__":
    unittest.main()
