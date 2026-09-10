"""Benchmark the complete local workflow for ECC and ML-KEM branches.

The benchmark uses LocalStorage and a deterministic blockchain double. It does
not pretend to measure a real blockchain, IPFS, VPS, TLS, or WireGuard path.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Sequence

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

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


PATIENT_ID = "benchmark-patient"
DOCTOR_ID = "benchmark-doctor"
DOCTOR_ADDRESS = "0x" + "22" * 20


class LocalBlockchainDouble:
    """Deterministic local substitute; its timings are not network timings."""

    def __init__(self) -> None:
        self.records: dict[str, tuple[str, bytes, str | None]] = {}
        self.permissions: set[tuple[str, str]] = set()
        self.access_events: list[tuple[str, str | None]] = []

    def register_record(self, record_id, cid, file_hash, **kwargs):
        self.records[record_id] = (cid, bytes.fromhex(file_hash), kwargs.get("sender"))
        return "local-register"

    def grant_access(self, record_id, doctor_address, **_kwargs):
        self.permissions.add((record_id, doctor_address))
        return "local-grant"

    def revoke_access(self, record_id, doctor_address, **_kwargs):
        self.permissions.discard((record_id, doctor_address))
        return "local-revoke"

    def check_access(self, record_id, doctor_address):
        return (record_id, doctor_address) in self.permissions

    def get_record_metadata(self, record_id):
        return self.records[record_id]

    def record_access(self, record_id, **kwargs):
        self.access_events.append((record_id, kwargs.get("sender")))
        return "local-access"


def _samples(function: Callable[[], Any], repeats: int, warmups: int) -> list[int]:
    for _ in range(warmups):
        function()
    values: list[int] = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        function()
        values.append(time.perf_counter_ns() - start)
    return values


def _summary(samples: list[int]) -> dict[str, float | int]:
    values = [sample / 1_000_000 for sample in samples]
    return {
        "count": len(values),
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "stdev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min_ms": min(values),
        "max_ms": max(values),
    }


def _metric(name: str, algorithm: str, samples: list[int]) -> dict[str, Any]:
    return {"name": name, "algorithm": algorithm, "samples_ns": samples, "summary": _summary(samples)}


def _build_service(
    algorithm: str,
    root: str,
    private_key: Any,
    public_key_text: str,
) -> tuple[HealthcareWorkflowService, Database, LocalBlockchainDouble]:
    database = Database()
    register_patient(database, PATIENT_ID, "Benchmark alias")
    register_doctor(database, DOCTOR_ID, "Benchmark doctor", public_key_text, algorithm)
    blockchain = LocalBlockchainDouble()
    service = HealthcareWorkflowService(
        database,
        LocalStorage(root),
        blockchain,
        doctor_addresses={DOCTOR_ID: DOCTOR_ADDRESS},
        private_key_resolver=lambda _doctor_id: private_key,
    )
    return service, database, blockchain


def _benchmark_algorithm(algorithm: str, plaintext: bytes, repeats: int, warmups: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    metrics: list[dict[str, Any]] = []
    upload_sizes: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="ns-phase11-") as root:
        if algorithm == ECC_ALGORITHM:
            private_key, public_key = generate_ecc_key_pair()
            public_key_text = serialize_ecc_public_key(public_key)
        else:
            private_key, public_key = generate_mlkem_key_pair()
            public_key_text = serialize_mlkem_public_key(public_key)

        service, database, blockchain = _build_service(
            algorithm, root, private_key, public_key_text
        )
        try:
            upload_counter = 0

            def upload_once() -> None:
                nonlocal upload_counter
                upload_counter += 1
                service.upload_record(
                    PATIENT_ID,
                    plaintext,
                    DOCTOR_ID,
                    algorithm,
                    record_id=f"upload-timed-{upload_counter}",
                )

            upload_samples = _samples(upload_once, repeats, warmups)
            metrics.append(_metric("workflow_upload_local_storage", algorithm, upload_samples))

            record = service.upload_record(PATIENT_ID, plaintext, DOCTOR_ID, algorithm, record_id="access-timed")
            service.grant_doctor_access(PATIENT_ID, DOCTOR_ID, record.record_id)
            upload_sizes = {
                "storage_reference_length": len(record.storage_reference or ""),
                "encrypted_file_hash_bytes": len(record.encrypted_file_hash) // 2,
            }
            access_samples = _samples(lambda: blockchain.check_access(record.record_id, DOCTOR_ADDRESS), repeats, warmups)
            metrics.append(_metric("blockchain_access_check_local_double", algorithm, access_samples))
            request_samples = _samples(lambda: service.request_record(DOCTOR_ID, record.record_id), repeats, warmups)
            metrics.append(_metric("authorized_access_end_to_end_local", algorithm, request_samples))
            download_samples = _samples(
                lambda: service.storage.download_encrypted_record(record.storage_reference), repeats, warmups
            )
            metrics.append(_metric("encrypted_envelope_download_local_storage", algorithm, download_samples))
        finally:
            database.close()
    return metrics, upload_sizes


def run_benchmark(source: str | Path, *, repeats: int = 10, warmups: int = 2) -> dict[str, Any]:
    if repeats < 1 or warmups < 0:
        raise ValueError("repeats must be positive and warmups cannot be negative")
    source_path = Path(source).expanduser().resolve()
    plaintext = source_path.read_bytes()
    metrics: list[dict[str, Any]] = []
    sizes: dict[str, dict[str, int]] = {}
    for algorithm in (ECC_ALGORITHM, MLKEM_ALGORITHM):
        branch_metrics, branch_sizes = _benchmark_algorithm(algorithm, plaintext, repeats, warmups)
        metrics.extend(branch_metrics)
        sizes[algorithm] = branch_sizes
    return {
        "benchmark": "phase11-workflow-local",
        "status": "VERIFIED_LOCAL_ONLY",
        "source": {
            "path": str(source_path),
            "size_bytes": len(plaintext),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
        },
        "protocol": {
            "repeats": repeats,
            "warmups": warmups,
            "timer": "time.perf_counter_ns",
            "statistics": ["mean", "median", "stdev", "min", "max"],
            "storage": "LocalStorage",
            "blockchain": "LocalBlockchainDouble; not a network benchmark",
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "cryptography": __import__("cryptography").__version__,
        },
        "metrics": metrics,
        "sizes": sizes,
        "unavailable_live_metrics": {
            "ipfs_upload": "NOT_RUN: no live IPFS node configured",
            "ipfs_download": "NOT_RUN: no live IPFS node configured",
            "vps_upload": "NOT_RUN: no live VPS configured",
            "vps_download": "NOT_RUN: no live VPS configured",
            "blockchain_registration": "NOT_RUN: no live Anvil/Hardhat/provider configured",
            "tls_latency": "NOT_RUN: no deployed HTTPS endpoint configured",
            "wireguard_latency": "NOT_RUN: no live WireGuard tunnel configured",
        },
    }


def write_results(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "benchmark_workflow.json"
    csv_path = destination / "benchmark_workflow_samples.csv"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("metric", "algorithm", "sample_index", "elapsed_ns"))
        writer.writeheader()
        for metric in result["metrics"]:
            for index, sample in enumerate(metric["samples_ns"], start=1):
                writer.writerow({"metric": metric["name"], "algorithm": metric["algorithm"], "sample_index": index, "elapsed_ns": sample})
    return json_path, csv_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args(argv)
    result = run_benchmark(args.source, repeats=args.repeats, warmups=args.warmups)
    paths = write_results(result, args.output_dir)
    print(json.dumps({"status": result["status"], "results": [str(path) for path in paths]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
