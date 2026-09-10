"""Phase 7 WireGuard policy tests; no live tunnel is required."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1] / "02_framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from api import HealthcareAPI, create_server  # noqa: E402
from vpn import VPNAccessPolicy, VPNPolicyError  # noqa: E402


class Phase7VPNTests(unittest.TestCase):
    def test_policy_allows_only_vpn_peers(self) -> None:
        policy = VPNAccessPolicy.create("10.77.0.0/24", "10.77.0.1")
        self.assertTrue(policy.allows_peer("10.77.0.2"))
        self.assertFalse(policy.allows_peer("192.168.1.10"))
        with self.assertRaises(PermissionError):
            policy.require_peer("8.8.8.8")

    def test_policy_rejects_invalid_interface_configuration(self) -> None:
        with self.assertRaises(VPNPolicyError):
            VPNAccessPolicy.create("10.77.0.0/24", "192.168.1.2")
        with self.assertRaises(VPNPolicyError):
            VPNAccessPolicy.create("10.77.0.0/24", "10.77.0.0")

    def test_server_requires_complete_vpn_configuration(self) -> None:
        api = HealthcareAPI(object())  # construction only; no request is made.
        with self.assertRaises(ValueError):
            create_server("127.0.0.1", 0, api, vpn_network="10.77.0.0/24")
        with self.assertRaises(ValueError):
            create_server(
                "127.0.0.1",
                0,
                api,
                vpn_network="10.77.0.0/24",
                vpn_interface_address="10.77.0.1",
            )


if __name__ == "__main__":
    unittest.main()
