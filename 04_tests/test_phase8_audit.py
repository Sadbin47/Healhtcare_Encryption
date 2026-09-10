"""Phase 8 structured and tamper-evident audit tests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from audit import (  # noqa: E402
    ACCESS_DENIED,
    DECRYPTION_SUCCESS,
    GENESIS_HASH,
    RECORD_CREATED,
    AuditEvent,
    AuditIntegrityError,
    JsonlAuditSink,
    MemoryAuditSink,
)


def event(operation=RECORD_CREATED, success=True, reason=None):
    return AuditEvent(
        operation=operation,
        success=success,
        actor="patient-001" if operation == RECORD_CREATED else "doctor-001",
        patient_id="patient-001",
        record_id="record-001",
        algorithm="ML-KEM-768-AES-GCM",
        backend="local",
        reason=reason,
        timestamp="2026-09-10T12:00:00+00:00",
    )


class Phase8AuditTests(unittest.TestCase):
    def test_memory_sink_chains_events(self) -> None:
        sink = MemoryAuditSink()
        first = sink.record(event())
        second = sink.record(event(DECRYPTION_SUCCESS))
        self.assertEqual(first.previous_hash, GENESIS_HASH)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertTrue(sink.verify())
        self.assertEqual([entry.sequence for entry in sink.entries], [1, 2])

    def test_failed_event_requires_reason(self) -> None:
        with self.assertRaises(ValueError):
            event(ACCESS_DENIED, success=False)

    def test_jsonl_persists_reopens_and_detects_content_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink.record(event())
            sink.record(event(ACCESS_DENIED, success=False, reason="permission revoked"))
            head_hash = sink.head_hash
            reopened = JsonlAuditSink(path)
            self.assertTrue(reopened.verify())
            self.assertEqual(reopened.head_hash, head_hash)
            lines = path.read_text(encoding="utf-8").splitlines()
            value = json.loads(lines[0])
            value["event"]["actor"] = "attacker"
            lines[0] = json.dumps(value)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(AuditIntegrityError):
                JsonlAuditSink(path)

    def test_live_sink_detects_tail_truncation_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            sink.record(event())
            sink.record(event(DECRYPTION_SUCCESS))
            first_line = path.read_text(encoding="utf-8").splitlines()[0]
            path.write_text(first_line + "\n", encoding="utf-8")
            with self.assertRaises(AuditIntegrityError):
                sink.record(event())

    def test_serialized_log_contains_no_medical_payload_or_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            JsonlAuditSink(path).record(event())
            text = path.read_text(encoding="utf-8").lower()
            for forbidden in ("ehr_base64", "plaintext", "aes_key", "private_key", "ciphertext"):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
