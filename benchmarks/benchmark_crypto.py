"""Benchmark the reusable cryptography layer with local, repeatable timings.

This benchmark intentionally excludes live IPFS, VPS, blockchain, TLS, and
WireGuard operations. It measures the cryptographic work that is available in
the local framework and writes raw samples plus summary statistics. No
plaintext or secret key material is written to the result files.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from crypto.aes_gcm import decrypt_record, encrypt_record, generate_key  # noqa: E402
from crypto.ecc_protection import (  # noqa: E402
    ALGORITHM as ECC_ALGORITHM,
    generate_key_pair as generate_ecc_key_pair,
    protect_aes_key as protect_ecc,
    recover_aes_key as recover_ecc,
    serialize_public_key as serialize_ecc_public_key,
)
from crypto.envelope import EncryptedEnvelope, record_aad  # noqa: E402
from crypto.mlkem_protection import (  # noqa: E402
    ALGORITHM as MLKEM_ALGORITHM,
    generate_key_pair as generate_mlkem_key_pair,
    protect_aes_key as protect_mlkem,
    recover_aes_key as recover_mlkem,
    serialize_public_key as serialize_mlkem_public_key,
)


def _timed(function: Callable[[], Any], repeats: int, warmups: int) -> list[int]:
    for _ in range(warmups):
        function()
    samples: list[int] = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        function()
        samples.append(time.perf_counter_ns() - start)
    return samples


def _stats(samples: list[int]) -> dict[str, float | int]:
    if not samples:
        raise ValueError("at least one timing sample is required")
    values_ms = [sample / 1_000_000 for sample in samples]
    return {
        "count": len(values_ms),
        "mean_ms": statistics.mean(values_ms),
        "median_ms": statistics.median(values_ms),
        "stdev_ms": statistics.stdev(values_ms) if len(values_ms) > 1 else 0.0,
        "min_ms": min(values_ms),
        "max_ms": max(values_ms),
    }


def _metric(name: str, algorithm: str, samples: list[int]) -> dict[str, Any]:
    return {
        "name": name,
        "algorithm": algorithm,
        "samples_ns": samples,
        "summary": _stats(samples),
    }


def run_benchmark(source: str | Path, *, repeats: int = 10, warmups: int = 2) -> dict[str, Any]:
    if repeats < 1 or warmups < 0:
        raise ValueError("repeats must be positive and warmups cannot be negative")
    source_path = Path(source).expanduser().resolve()
    plaintext = source_path.read_bytes()
    aes_key = generate_key()
    aad = record_aad("benchmark-record", ECC_ALGORITHM, "benchmark-doctor")
    nonce, ciphertext, tag = encrypt_record(plaintext, aes_key, aad)

    ecc_private, ecc_public = generate_ecc_key_pair()
    ecc_protected = protect_ecc(aes_key, ecc_public, "benchmark-doctor")
    mlkem_private, mlkem_public = generate_mlkem_key_pair()
    mlkem_protected = protect_mlkem(aes_key, mlkem_public, "benchmark-doctor")

    metrics = [
        _metric("aes_key_generation", "AES-256-GCM", _timed(generate_key, repeats, warmups)),
        _metric(
            "aes_encryption",
            "AES-256-GCM",
            _timed(lambda: encrypt_record(plaintext, aes_key, aad), repeats, warmups),
        ),
        _metric(
            "aes_decryption",
            "AES-256-GCM",
            _timed(lambda: decrypt_record(nonce, ciphertext, tag, aes_key, aad), repeats, warmups),
        ),
        _metric(
            "ecc_key_generation",
            ECC_ALGORITHM,
            _timed(generate_ecc_key_pair, repeats, warmups),
        ),
        _metric(
            "ecc_key_protection",
            ECC_ALGORITHM,
            _timed(lambda: protect_ecc(aes_key, ecc_public, "benchmark-doctor"), repeats, warmups),
        ),
        _metric(
            "ecc_key_recovery",
            ECC_ALGORITHM,
            _timed(lambda: recover_ecc(ecc_protected, ecc_private), repeats, warmups),
        ),
        _metric(
            "mlkem_key_generation",
            MLKEM_ALGORITHM,
            _timed(generate_mlkem_key_pair, repeats, warmups),
        ),
        _metric(
            "mlkem_key_protection",
            MLKEM_ALGORITHM,
            _timed(lambda: protect_mlkem(aes_key, mlkem_public, "benchmark-doctor"), repeats, warmups),
        ),
        _metric(
            "mlkem_key_recovery",
            MLKEM_ALGORITHM,
            _timed(lambda: recover_mlkem(mlkem_protected, mlkem_private), repeats, warmups),
        ),
    ]

    ecc_envelope = EncryptedEnvelope.create(
        record_id="benchmark-record",
        key_protection=ECC_ALGORITHM,
        key_reference="benchmark-doctor",
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        wrapped_key=ecc_protected,
    )
    mlkem_envelope = EncryptedEnvelope.create(
        record_id="benchmark-record",
        key_protection=MLKEM_ALGORITHM,
        key_reference="benchmark-doctor",
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        wrapped_key=mlkem_protected,
    )
    sizes = {
        "plaintext_bytes": len(plaintext),
        "aes_ciphertext_bytes": len(ciphertext),
        "aes_payload_bytes": len(ecc_envelope.payload_bytes()),
        "ecc_public_key_serialized_bytes": len(serialize_ecc_public_key(ecc_public)),
        "ecc_protected_key_json_bytes": len(json.dumps(ecc_protected, sort_keys=True).encode()),
        "ecc_envelope_json_bytes": len(ecc_envelope.to_json().encode()),
        "mlkem_public_key_serialized_bytes": len(serialize_mlkem_public_key(mlkem_public)),
        "mlkem_protected_key_json_bytes": len(json.dumps(mlkem_protected, sort_keys=True).encode()),
        "mlkem_envelope_json_bytes": len(mlkem_envelope.to_json().encode()),
    }
    return {
        "benchmark": "phase11-crypto-local",
        "status": "VERIFIED_LOCAL_ONLY",
        "source": {
            "path": str(source_path),
            "size_bytes": len(plaintext),
            "sha256": __import__("hashlib").sha256(plaintext).hexdigest(),
        },
        "protocol": {
            "repeats": repeats,
            "warmups": warmups,
            "timer": "time.perf_counter_ns",
            "statistics": ["mean", "median", "stdev", "min", "max"],
            "aad": "record-bound metadata; value excluded from output",
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
            "wireguard_latency": "NOT_RUN: no live WireGuard tunnel configured",
        },
    }


def write_results(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "benchmark_crypto.json"
    csv_path = destination / "benchmark_crypto_samples.csv"
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
