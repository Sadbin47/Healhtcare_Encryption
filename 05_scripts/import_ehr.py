"""Validate and connect the project's EHR CSV to the framework workflow.

The importer deliberately treats the source CSV as immutable.  In ``dataset``
mode the exact source bytes become one workflow payload.  In ``patient`` mode
the rows are grouped by ``patientunitstayid`` and each group is serialized as
an independent, deterministic CSV payload containing the original header.
No plaintext payload is written by this module; callers either pass payloads to
``HealthcareWorkflowService`` or request a metadata-only manifest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


REQUIRED_COLUMN = "patientunitstayid"
SERIALIZATION = "UTF-8 CSV, repeated header, LF line endings"


class DatasetImportError(ValueError):
    """Raised when the source CSV cannot be imported safely."""


@dataclass(frozen=True)
class DatasetSummary:
    source_path: str
    source_sha256: str
    source_size_bytes: int
    row_count: int
    column_count: int
    columns: tuple[str, ...]
    patient_unit_count: int
    missing_cell_count: int


@dataclass(frozen=True)
class DatasetUnit:
    """One encryption unit, either the full dataset or one patient/unit stay."""

    unit_id: str
    patientunitstayid: str | None
    row_count: int
    payload: bytes
    payload_sha256: str
    source_row_numbers: tuple[int, ...]


@dataclass(frozen=True)
class ImportedDataset:
    summary: DatasetSummary
    columns: tuple[str, ...]
    rows: tuple[Mapping[str, str], ...]
    mode: str
    units: tuple[DatasetUnit, ...]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_source(path: str | Path) -> tuple[Path, bytes, str]:
    source = Path(path).expanduser()
    if not source.is_file():
        raise DatasetImportError(f"dataset file does not exist: {source}")
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise DatasetImportError(f"unable to read dataset: {source}") from error
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DatasetImportError("dataset must be valid UTF-8") from error
    if not raw:
        raise DatasetImportError("dataset is empty")
    return source.resolve(), raw, text


def _parse_rows(text: str) -> tuple[tuple[str, ...], tuple[Mapping[str, str], ...]]:
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    try:
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise DatasetImportError("dataset has no CSV header")
        columns = tuple(fieldnames)
        if any(not isinstance(column, str) or not column for column in columns):
            raise DatasetImportError("dataset contains an empty column name")
        if len(set(columns)) != len(columns):
            raise DatasetImportError("dataset contains duplicate column names")
        rows: list[Mapping[str, str]] = []
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise DatasetImportError(f"row {row_number} has more fields than the header")
            if any(value is None for value in row.values()):
                raise DatasetImportError(f"row {row_number} has fewer fields than the header")
            rows.append(dict(row))
    except csv.Error as error:
        raise DatasetImportError(f"malformed CSV near row {reader.line_num}") from error
    if not rows:
        raise DatasetImportError("dataset contains no data rows")
    return columns, tuple(rows)


def _serialize_rows(columns: Sequence[str], rows: Iterable[Mapping[str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=list(columns),
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def inspect_dataset(path: str | Path, *, required_column: str = REQUIRED_COLUMN) -> tuple[DatasetSummary, tuple[str, ...], tuple[Mapping[str, str], ...]]:
    """Validate a CSV and return its summary, columns, and parsed rows.

    Values are retained as strings exactly as parsed by Python's strict CSV
    reader.  No type conversion, sorting, imputation, or normalization occurs.
    """

    source, raw, text = _read_source(path)
    columns, rows = _parse_rows(text)
    if required_column not in columns:
        raise DatasetImportError(f"dataset is missing required column: {required_column}")
    identifiers = [row[required_column] for row in rows]
    if any(not value.strip() for value in identifiers):
        raise DatasetImportError(f"dataset contains an empty {required_column} value")
    missing_cells = sum(value == "" for row in rows for value in row.values())
    summary = DatasetSummary(
        source_path=str(source),
        source_sha256=_sha256(raw),
        source_size_bytes=len(raw),
        row_count=len(rows),
        column_count=len(columns),
        columns=columns,
        patient_unit_count=len(set(identifiers)),
        missing_cell_count=missing_cells,
    )
    return summary, columns, rows


def load_dataset(path: str | Path, *, mode: str = "dataset", required_column: str = REQUIRED_COLUMN) -> ImportedDataset:
    """Build deterministic encryption units from the immutable source CSV.

    ``dataset`` mode creates exactly one unit whose payload is byte-identical
    to the source file.  ``patient`` mode creates one unit per distinct
    ``patientunitstayid``; groups are ordered by identifier and rows retain
    their source order.  Each grouped payload contains the header and only the
    group's rows, serialized using :data:`SERIALIZATION`.
    """

    if mode not in {"dataset", "patient"}:
        raise DatasetImportError("mode must be 'dataset' or 'patient'")
    summary, columns, rows = inspect_dataset(path, required_column=required_column)
    if mode == "dataset":
        raw = Path(path).expanduser().read_bytes()
        unit = DatasetUnit(
            unit_id="dataset",
            patientunitstayid=None,
            row_count=len(rows),
            payload=raw,
            payload_sha256=_sha256(raw),
            source_row_numbers=tuple(range(2, len(rows) + 2)),
        )
        units = (unit,)
    else:
        groups: dict[str, list[tuple[int, Mapping[str, str]]]] = {}
        for row_number, row in enumerate(rows, start=2):
            identifier = row[required_column]
            groups.setdefault(identifier, []).append((row_number, row))
        units_list: list[DatasetUnit] = []
        for identifier in sorted(groups):
            entries = groups[identifier]
            grouped_rows = [row for _, row in entries]
            payload = _serialize_rows(columns, grouped_rows)
            units_list.append(
                DatasetUnit(
                    unit_id=f"patientunitstay-{identifier}",
                    patientunitstayid=identifier,
                    row_count=len(grouped_rows),
                    payload=payload,
                    payload_sha256=_sha256(payload),
                    source_row_numbers=tuple(number for number, _ in entries),
                )
            )
        units = tuple(units_list)
    return ImportedDataset(summary=summary, columns=columns, rows=rows, mode=mode, units=units)


def import_ehr(path: str | Path, *, mode: str = "dataset", required_column: str = REQUIRED_COLUMN) -> ImportedDataset:
    """Public Phase 10 entry point; equivalent to :func:`load_dataset`."""

    return load_dataset(path, mode=mode, required_column=required_column)


def connect_dataset(
    service: Any,
    imported: ImportedDataset,
    *,
    doctor_id: str,
    algorithm: str,
    patient_id: str | None = None,
    patient_id_for_unit: Callable[[DatasetUnit], str] | None = None,
    record_id_prefix: str = "ehr",
) -> list[Any]:
    """Encrypt and upload imported units through ``HealthcareWorkflowService``.

    The connector never auto-registers patients or doctors.  Dataset mode
    requires ``patient_id``.  Patient mode requires ``patient_id_for_unit`` so
    the caller explicitly maps each source unit to an already registered
    application identity.
    """

    if not doctor_id:
        raise ValueError("doctor_id is required")
    if not algorithm:
        raise ValueError("algorithm is required")
    if imported.mode == "dataset":
        if not patient_id:
            raise ValueError("patient_id is required in dataset mode")
        resolver = lambda _unit: patient_id
    else:
        if patient_id_for_unit is None:
            raise ValueError("patient_id_for_unit is required in patient mode")
        resolver = patient_id_for_unit

    records: list[Any] = []
    for unit in imported.units:
        mapped_patient = resolver(unit)
        if not isinstance(mapped_patient, str) or not mapped_patient.strip():
            raise ValueError(f"patient mapping is empty for {unit.unit_id}")
        record_id = f"{record_id_prefix}-{unit.unit_id}"
        records.append(
            service.upload_record(
                mapped_patient,
                unit.payload,
                doctor_id,
                algorithm,
                record_id=record_id,
            )
        )
    return records


def write_manifest(
    imported: ImportedDataset,
    output_dir: str | Path,
    *,
    records: Sequence[Any] | None = None,
) -> Path:
    """Write a metadata-only manifest; plaintext and private keys are excluded."""

    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    records = list(records or [])
    if records and len(records) != len(imported.units):
        raise ValueError("records must correspond one-to-one with imported units")
    unit_entries = []
    for index, unit in enumerate(imported.units):
        record = records[index] if records else None
        unit_entries.append(
            {
                "unit_id": unit.unit_id,
                "patientunitstayid": unit.patientunitstayid,
                "row_count": unit.row_count,
                "source_row_numbers": list(unit.source_row_numbers),
                "payload_sha256": unit.payload_sha256,
                "serialization": "source bytes" if imported.mode == "dataset" else SERIALIZATION,
                "record_id": getattr(record, "record_id", None),
                "storage_backend": getattr(record, "storage_backend", None),
                "storage_reference": getattr(record, "storage_reference", None),
                "encrypted_file_hash": getattr(record, "encrypted_file_hash", None),
            }
        )
    manifest = {
        "manifest_version": 1,
        "mode": imported.mode,
        "source": {
            "path": imported.summary.source_path,
            "sha256": imported.summary.source_sha256,
            "size_bytes": imported.summary.source_size_bytes,
            "row_count": imported.summary.row_count,
            "column_count": imported.summary.column_count,
            "columns": list(imported.summary.columns),
            "patient_unit_count": imported.summary.patient_unit_count,
            "missing_cell_count": imported.summary.missing_cell_count,
        },
        "units": unit_entries,
    }
    output = destination / "import_manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="path to the source EHR CSV")
    parser.add_argument("--mode", choices=("dataset", "patient"), default="dataset")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for metadata-only manifest")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        imported = load_dataset(args.source, mode=args.mode)
        manifest = write_manifest(imported, args.output_dir)
    except (DatasetImportError, OSError, ValueError) as error:
        print(f"import failed: {error}", file=sys.stderr)
        return 2
    print(
        f"validated {imported.summary.row_count} rows into "
        f"{len(imported.units)} {imported.mode} unit(s); manifest={manifest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
