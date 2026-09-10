"""SQLite persistence for patient, doctor, record, and grant metadata."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Union

try:  # Supports both ``from framework.database`` and direct module imports.
    from .models import AccessGrant, Doctor, MedicalRecord, Patient
except ImportError:  # pragma: no cover - exercised by direct script-style use.
    from models import AccessGrant, Doctor, MedicalRecord, Patient


DatabasePath = Union[str, Path]


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS patients (
    patient_id TEXT PRIMARY KEY,
    display_name_or_alias TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS doctors (
    doctor_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    key_algorithm TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS medical_records (
    record_id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL,
    encrypted_file_hash TEXT NOT NULL,
    ipfs_cid TEXT,
    key_protection_algorithm TEXT NOT NULL,
    created_at TEXT NOT NULL,
    storage_backend TEXT NOT NULL DEFAULT '',
    storage_reference TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_grants (
    patient_id TEXT NOT NULL,
    doctor_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (patient_id, doctor_id, record_id),
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id) ON DELETE CASCADE,
    FOREIGN KEY (record_id) REFERENCES medical_records(record_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_records_patient ON medical_records(patient_id);
CREATE INDEX IF NOT EXISTS idx_grants_doctor ON access_grants(doctor_id);
CREATE INDEX IF NOT EXISTS idx_grants_record ON access_grants(record_id);
"""


class Database:
    """Small transaction-safe SQLite repository for framework metadata."""

    def __init__(self, path: DatabasePath = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(SCHEMA)
        self._migrate_storage_columns()
        self.connection.commit()

    def _migrate_storage_columns(self) -> None:
        """Add Phase 4 columns when opening an older Phase 2/3 database."""

        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(medical_records)")}
        if "storage_backend" not in columns:
            self.connection.execute(
                "ALTER TABLE medical_records ADD COLUMN storage_backend TEXT NOT NULL DEFAULT ''"
            )
        if "storage_reference" not in columns:
            self.connection.execute("ALTER TABLE medical_records ADD COLUMN storage_reference TEXT")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    @staticmethod
    def _integrity_error(error: sqlite3.IntegrityError) -> ValueError:
        message = str(error)
        if "UNIQUE" in message or "PRIMARY KEY" in message:
            return ValueError("metadata entity already exists")
        if "FOREIGN KEY" in message:
            return ValueError("referenced patient, doctor, or record does not exist")
        return ValueError(message)

    def add_patient(self, patient: Patient) -> Patient:
        if not isinstance(patient, Patient):
            raise TypeError("patient must be a Patient")
        try:
            with self.transaction() as db:
                db.execute(
                    "INSERT INTO patients(patient_id, display_name_or_alias, created_at) VALUES (?, ?, ?)",
                    (patient.patient_id, patient.display_name_or_alias, patient.created_at),
                )
        except sqlite3.IntegrityError as error:
            raise self._integrity_error(error) from error
        return patient

    def get_patient(self, patient_id: str) -> Optional[Patient]:
        row = self.connection.execute(
            "SELECT patient_id, display_name_or_alias, created_at FROM patients WHERE patient_id = ?",
            (patient_id,),
        ).fetchone()
        return None if row is None else Patient(**dict(row))

    def list_patients(self) -> list[Patient]:
        rows = self.connection.execute(
            "SELECT patient_id, display_name_or_alias, created_at FROM patients ORDER BY patient_id"
        ).fetchall()
        return [Patient(**dict(row)) for row in rows]

    def add_doctor(self, doctor: Doctor) -> Doctor:
        if not isinstance(doctor, Doctor):
            raise TypeError("doctor must be a Doctor")
        try:
            with self.transaction() as db:
                db.execute(
                    """
                    INSERT INTO doctors(
                        doctor_id, name, public_key, key_algorithm, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        doctor.doctor_id,
                        doctor.name,
                        doctor.public_key,
                        doctor.key_algorithm,
                        doctor.created_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise self._integrity_error(error) from error
        return doctor

    def get_doctor(self, doctor_id: str) -> Optional[Doctor]:
        row = self.connection.execute(
            "SELECT doctor_id, name, public_key, key_algorithm, created_at FROM doctors WHERE doctor_id = ?",
            (doctor_id,),
        ).fetchone()
        return None if row is None else Doctor(**dict(row))

    def list_doctors(self) -> list[Doctor]:
        rows = self.connection.execute(
            "SELECT doctor_id, name, public_key, key_algorithm, created_at FROM doctors ORDER BY doctor_id"
        ).fetchall()
        return [Doctor(**dict(row)) for row in rows]

    def add_record(self, record: MedicalRecord) -> MedicalRecord:
        if not isinstance(record, MedicalRecord):
            raise TypeError("record must be a MedicalRecord")
        try:
            with self.transaction() as db:
                db.execute(
                    """
                    INSERT INTO medical_records(
                        record_id, patient_id, encrypted_file_hash, ipfs_cid,
                        key_protection_algorithm, created_at, storage_backend, storage_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.record_id,
                        record.patient_id,
                        record.encrypted_file_hash,
                        record.ipfs_cid,
                        record.key_protection_algorithm,
                        record.created_at,
                        record.storage_backend,
                        record.storage_reference,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise self._integrity_error(error) from error
        return record

    def get_record(self, record_id: str) -> Optional[MedicalRecord]:
        row = self.connection.execute(
            """
            SELECT record_id, patient_id, encrypted_file_hash, ipfs_cid,
                   key_protection_algorithm, created_at, storage_backend, storage_reference
            FROM medical_records WHERE record_id = ?
            """,
            (record_id,),
        ).fetchone()
        return None if row is None else MedicalRecord(**dict(row))

    def list_records_for_patient(self, patient_id: str) -> list[MedicalRecord]:
        rows = self.connection.execute(
            """
            SELECT record_id, patient_id, encrypted_file_hash, ipfs_cid,
                   key_protection_algorithm, created_at, storage_backend, storage_reference
            FROM medical_records WHERE patient_id = ? ORDER BY created_at, record_id
            """,
            (patient_id,),
        ).fetchall()
        return [MedicalRecord(**dict(row)) for row in rows]

    def update_record_storage(
        self,
        record_id: str,
        storage_backend: str,
        storage_reference: str,
    ) -> Optional[MedicalRecord]:
        """Persist a backend reference after an encrypted upload succeeds."""

        if not isinstance(storage_backend, str) or not storage_backend.strip():
            raise ValueError("storage_backend must be a non-empty string")
        if not isinstance(storage_reference, str) or not storage_reference.strip():
            raise ValueError("storage_reference must be a non-empty string")
        backend = storage_backend.strip()
        reference = storage_reference.strip()
        with self.transaction() as db:
            cursor = db.execute(
                """
                UPDATE medical_records
                SET storage_backend = ?, storage_reference = ?,
                    ipfs_cid = CASE WHEN ? = 'ipfs' THEN ? ELSE NULL END
                WHERE record_id = ?
                """,
                (backend, reference, backend, reference, record_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get_record(record_id)

    def add_access_grant(self, grant: AccessGrant) -> AccessGrant:
        if not isinstance(grant, AccessGrant):
            raise TypeError("grant must be an AccessGrant")
        try:
            with self.transaction() as db:
                db.execute(
                    """
                    INSERT INTO access_grants(
                        patient_id, doctor_id, record_id, permission, granted_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        grant.patient_id,
                        grant.doctor_id,
                        grant.record_id,
                        grant.permission,
                        grant.granted_at,
                        grant.revoked_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise self._integrity_error(error) from error
        return grant

    def upsert_access_grant(self, grant: AccessGrant) -> AccessGrant:
        """Create or reactivate a grant for the same patient/doctor/record."""

        if not isinstance(grant, AccessGrant):
            raise TypeError("grant must be an AccessGrant")
        try:
            with self.transaction() as db:
                db.execute(
                    """
                    INSERT INTO access_grants(
                        patient_id, doctor_id, record_id, permission, granted_at, revoked_at
                    ) VALUES (?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(patient_id, doctor_id, record_id) DO UPDATE SET
                        permission = excluded.permission,
                        granted_at = excluded.granted_at,
                        revoked_at = NULL
                    """,
                    (
                        grant.patient_id,
                        grant.doctor_id,
                        grant.record_id,
                        grant.permission,
                        grant.granted_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise self._integrity_error(error) from error
        return self.get_access_grant(grant.patient_id, grant.doctor_id, grant.record_id)  # type: ignore[return-value]

    def revoke_access_grant(
        self,
        patient_id: str,
        doctor_id: str,
        record_id: str,
        revoked_at: str,
    ) -> Optional[AccessGrant]:
        """Mark an existing grant revoked and return its new state."""

        with self.transaction() as db:
            cursor = db.execute(
                """
                UPDATE access_grants
                SET revoked_at = ?
                WHERE patient_id = ? AND doctor_id = ? AND record_id = ?
                """,
                (revoked_at, patient_id, doctor_id, record_id),
            )
            if cursor.rowcount == 0:
                return None
        return self.get_access_grant(patient_id, doctor_id, record_id)

    def get_access_grant(
        self,
        patient_id: str,
        doctor_id: str,
        record_id: str,
    ) -> Optional[AccessGrant]:
        row = self.connection.execute(
            """
            SELECT patient_id, doctor_id, record_id, permission, granted_at, revoked_at
            FROM access_grants
            WHERE patient_id = ? AND doctor_id = ? AND record_id = ?
            """,
            (patient_id, doctor_id, record_id),
        ).fetchone()
        return None if row is None else AccessGrant(**dict(row))

    def list_access_grants_for_record(self, record_id: str) -> list[AccessGrant]:
        rows = self.connection.execute(
            """
            SELECT patient_id, doctor_id, record_id, permission, granted_at, revoked_at
            FROM access_grants WHERE record_id = ? ORDER BY granted_at, doctor_id
            """,
            (record_id,),
        ).fetchall()
        return [AccessGrant(**dict(row)) for row in rows]

    def list_access_grants_for_doctor(self, doctor_id: str) -> list[AccessGrant]:
        """Return all grants associated with a doctor, including revoked grants."""

        rows = self.connection.execute(
            """
            SELECT patient_id, doctor_id, record_id, permission, granted_at, revoked_at
            FROM access_grants WHERE doctor_id = ? ORDER BY granted_at, record_id
            """,
            (doctor_id,),
        ).fetchall()
        return [AccessGrant(**dict(row)) for row in rows]
