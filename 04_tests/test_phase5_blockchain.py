"""Phase 5 contract/client tests without requiring a live chain."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
ROOT = Path(__file__).parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from blockchain_client import (  # noqa: E402
    BlockchainClient,
    BlockchainValidationError,
    normalize_file_hash,
)


PATIENT = "0x1111111111111111111111111111111111111111"
DOCTOR = "0x2222222222222222222222222222222222222222"
FILE_HASH = "ab" * 32


class FakeCall:
    def __init__(self, value):
        self.value = value

    def call(self):
        return self.value


class FakeTransaction:
    def __init__(self, name, args, calls):
        self.name = name
        self.args = args
        self.calls = calls

    def transact(self, tx):
        self.calls.append((self.name, self.args, tx))
        return f"tx-{self.name}"


class FakeFunctions:
    def __init__(self):
        self.calls = []
        self.allowed = False

    def registerRecord(self, *args):
        return FakeTransaction("registerRecord", args, self.calls)

    def grantAccess(self, *args):
        return FakeTransaction("grantAccess", args, self.calls)

    def revokeAccess(self, *args):
        return FakeTransaction("revokeAccess", args, self.calls)

    def recordAccess(self, *args):
        return FakeTransaction("recordAccess", args, self.calls)

    def canAccess(self, *args):
        return FakeCall(self.allowed)

    def getRecordMetadata(self, *args):
        return FakeCall(("bafy-test-cid", bytes.fromhex(FILE_HASH), PATIENT))


class FakeContract:
    def __init__(self):
        self.functions = FakeFunctions()


class Phase5BlockchainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = FakeContract()
        self.client = BlockchainClient(contract=self.contract)

    def test_required_operations_use_expected_contract_methods(self) -> None:
        self.assertEqual(
            self.client.register_record("record-001", "bafy-test-cid", FILE_HASH, sender=PATIENT),
            "tx-registerRecord",
        )
        self.assertEqual(self.client.grant_access("record-001", DOCTOR, sender=PATIENT), "tx-grantAccess")
        self.assertEqual(self.client.revoke_access("record-001", DOCTOR, sender=PATIENT), "tx-revokeAccess")
        self.contract.functions.allowed = True
        self.assertTrue(self.client.check_access("record-001", DOCTOR))
        self.assertEqual(self.client.record_access("record-001", sender=DOCTOR), "tx-recordAccess")
        cid, digest, owner = self.client.get_record_metadata("record-001")
        self.assertEqual(cid, "bafy-test-cid")
        self.assertEqual(digest, bytes.fromhex(FILE_HASH))
        self.assertEqual(owner, PATIENT)
        self.assertEqual(len(self.contract.functions.calls), 4)
        self.assertEqual(self.contract.functions.calls[0][1][2], bytes.fromhex(FILE_HASH))

    def test_validation_rejects_bad_hash_and_address(self) -> None:
        with self.assertRaises(BlockchainValidationError):
            normalize_file_hash("not-a-sha256-digest")
        with self.assertRaises(BlockchainValidationError):
            self.client.grant_access("record-001", "0x0", sender=PATIENT)
        with self.assertRaises(BlockchainValidationError):
            self.client.register_record("", "cid", FILE_HASH, sender=PATIENT)

    def test_contract_does_not_contain_sensitive_data_fields(self) -> None:
        source = (ROOT / "03_contracts" / "AccessControl.sol").read_text(encoding="utf-8").lower()
        self.assertIn("mapping(bytes32 => recordmetadata)", source)
        self.assertIn("string cid", source)
        self.assertIn("bytes32 filehash", source)
        for forbidden in ("ehrplaintext", "aeskey", "privatekey", "encryptedfile"):
            self.assertNotIn(forbidden, source)
        for function_name in ("registerrecord", "grantaccess", "revokeaccess", "canaccess", "recordaccess"):
            self.assertIn(f"function {function_name}", source)
        for event_name in ("recordregistered", "accessgranted", "accessrevoked", "recordaccessed"):
            self.assertIn(f"event {event_name}", source)


if __name__ == "__main__":
    unittest.main()
