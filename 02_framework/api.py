"""Dependency-free JSON API boundary for the workflow service.

This module does not authenticate users itself. The caller supplies an
``authenticate`` callback; deployment should place the API behind HTTPS/VPN
and bind doctor private keys through a server-side resolver, never request
payloads.
"""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

try:
    from .vpn import VPNAccessPolicy
except ImportError:  # pragma: no cover - direct framework imports.
    from vpn import VPNAccessPolicy

try:
    from .service import HealthcareWorkflowService
except ImportError:  # pragma: no cover - direct framework imports.
    from service import HealthcareWorkflowService


class HealthcareAPI:
    def __init__(
        self,
        service: HealthcareWorkflowService,
        *,
        authenticate: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        self.service = service
        self.authenticate = authenticate or (lambda _payload: False)

    def upload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.authenticate(payload):
            raise PermissionError("request authentication failed")
        try:
            ehr = base64.b64decode(payload["ehr_base64"], validate=True)
            record = self.service.upload_record(
                payload["patient_id"],
                ehr,
                payload["doctor_id"],
                payload["algorithm"],
                record_id=payload.get("record_id"),
            )
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("invalid upload request") from error
        return {
            "record_id": record.record_id,
            "storage_backend": record.storage_backend,
            "storage_reference": record.storage_reference,
            "encrypted_file_hash": record.encrypted_file_hash,
        }

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.authenticate(payload):
            raise PermissionError("request authentication failed")
        try:
            plaintext = self.service.request_record(payload["doctor_id"], payload["record_id"])
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("invalid record request") from error
        return {"record_id": payload["record_id"], "ehr_base64": base64.b64encode(plaintext).decode("ascii")}

    def grant_access(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.authenticate(payload):
            raise PermissionError("request authentication failed")
        try:
            grant = self.service.grant_doctor_access(
                payload["patient_id"], payload["doctor_id"], payload["record_id"]
            )
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("invalid access-grant request") from error
        return {
            "patient_id": grant.patient_id,
            "doctor_id": grant.doctor_id,
            "record_id": grant.record_id,
            "permission": grant.permission,
            "active": grant.revoked_at is None,
        }

    def revoke_access(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.authenticate(payload):
            raise PermissionError("request authentication failed")
        try:
            grant = self.service.revoke_doctor_access(
                payload["patient_id"], payload["doctor_id"], payload["record_id"]
            )
        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("invalid access-revocation request") from error
        return {
            "patient_id": payload["patient_id"],
            "doctor_id": payload["doctor_id"],
            "record_id": payload["record_id"],
            "active": False,
            "grant_existed": grant is not None,
        }


class HealthcareRequestHandler(BaseHTTPRequestHandler):
    api: HealthcareAPI
    server_version = "HealthcareWorkflowAPI/1"
    sys_version = ""

    def _vpn_allowed(self) -> bool:
        policy = getattr(self.server, "vpn_policy", None)
        if policy is None:
            return True
        try:
            policy.require_peer(self.client_address[0])
        except PermissionError:
            self._response(403, {"error": "vpn_network_required"})
            return False
        return True

    def _response(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if not self._vpn_allowed():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/records":
                result = self.api.upload(payload)
            elif self.path == "/records/request":
                result = self.api.request(payload)
            elif self.path == "/access/grant":
                result = self.api.grant_access(payload)
            elif self.path == "/access/revoke":
                result = self.api.revoke_access(payload)
            else:
                self._response(404, {"error": "not_found"})
                return
            self._response(200, result)
        except PermissionError as error:
            self._response(403, {"error": str(error)})
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            self._response(400, {"error": str(error)})
        except Exception:
            self._response(500, {"error": "internal_error"})

    def log_message(self, format: str, *args: object) -> None:
        return


class HealthcareHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        api: HealthcareAPI,
        vpn_policy: VPNAccessPolicy | None = None,
    ) -> None:
        self.api = api
        self.vpn_policy = vpn_policy
        super().__init__(address, HealthcareRequestHandler)


def create_server(
    host: str,
    port: int,
    api: HealthcareAPI,
    *,
    vpn_network: str | None = None,
    vpn_interface_address: str | None = None,
) -> HealthcareHTTPServer:
    """Create an API server, optionally enforcing WireGuard-only access.

    Production deployment must provide both VPN arguments. Omitting them is
    retained for local unit tests and non-network service composition only.
    """

    if (vpn_network is None) != (vpn_interface_address is None):
        raise ValueError("vpn_network and vpn_interface_address must be supplied together")
    policy = (
        VPNAccessPolicy.create(vpn_network, vpn_interface_address)
        if vpn_network is not None and vpn_interface_address is not None
        else None
    )
    if policy is not None and host != vpn_interface_address:
        raise ValueError("VPN-enforced API must bind to the configured WireGuard interface address")
    return HealthcareHTTPServer((host, port), api, policy)
