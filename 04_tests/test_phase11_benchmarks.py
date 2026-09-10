"""Phase 11 benchmark runner smoke tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

BENCHMARKS = Path(__file__).parents[1] / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

from benchmark_crypto import run_benchmark as run_crypto  # noqa: E402
from benchmark_workflow import run_benchmark as run_workflow  # noqa: E402


class Phase11BenchmarkTests(unittest.TestCase):
    def _source(self, directory: str) -> Path:
        path = Path(directory) / "ehr.csv"
        path.write_bytes(b"patientunitstayid,diagnosis\n001,example\n")
        return path

    def test_crypto_benchmark_has_repeated_local_metrics_without_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_crypto(self._source(directory), repeats=2, warmups=0)
        self.assertEqual(result["status"], "VERIFIED_LOCAL_ONLY")
        self.assertEqual(result["protocol"]["repeats"], 2)
        self.assertTrue(any(metric["name"] == "mlkem_key_recovery" for metric in result["metrics"]))
        serialized = json.dumps(result)
        self.assertNotIn("private_key", serialized)
        self.assertNotIn("shared_secret", serialized)
        self.assertIn("NOT_RUN", serialized)

    def test_workflow_benchmark_compares_both_branches_locally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_workflow(self._source(directory), repeats=2, warmups=0)
        algorithms = {metric["algorithm"] for metric in result["metrics"]}
        self.assertEqual(algorithms, {"ECC-ECDH-P256-AES-GCM", "ML-KEM-768-AES-GCM"})
        names = {metric["name"] for metric in result["metrics"]}
        self.assertIn("workflow_upload_local_storage", names)
        self.assertIn("authorized_access_end_to_end_local", names)
        self.assertEqual(result["protocol"]["blockchain"], "LocalBlockchainDouble; not a network benchmark")


if __name__ == "__main__":
    unittest.main()
