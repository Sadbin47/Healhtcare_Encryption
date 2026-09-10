"""WireGuard-network admission policy for the healthcare API."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class VPNPolicyError(ValueError):
    """Raised when a VPN bind or peer address is outside the configured network."""


@dataclass(frozen=True)
class VPNAccessPolicy:
    """Validate that the API binds and accepts clients only on WireGuard CIDR."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    interface_address: ipaddress.IPv4Address | ipaddress.IPv6Address

    @classmethod
    def create(cls, network: str, interface_address: str) -> "VPNAccessPolicy":
        try:
            parsed_network = ipaddress.ip_network(network, strict=True)
            parsed_address = ipaddress.ip_address(interface_address)
        except ValueError as error:
            raise VPNPolicyError("invalid VPN network or interface address") from error
        if parsed_address not in parsed_network:
            raise VPNPolicyError("API interface address is outside the VPN network")
        if parsed_address == parsed_network.network_address:
            raise VPNPolicyError("API interface address cannot be the network address")
        return cls(parsed_network, parsed_address)

    def allows_peer(self, peer_address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(peer_address)
        except ValueError:
            return False
        return parsed.version == self.network.version and parsed in self.network

    def require_peer(self, peer_address: str) -> None:
        if not self.allows_peer(peer_address):
            raise PermissionError("request source is outside the WireGuard network")
