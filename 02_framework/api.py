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


class HealthcareRequestHandler(BaseHTTPRequestHandler):
    api: HealthcareAPI
    server_version = "HealthcareWorkflowAPI/1"
    sys_version = ""

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
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/records":
                result = self.api.upload(payload)
            elif self.path == "/records/request":
                result = self.api.request(payload)
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

    def __init__(self, address: tuple[str, int], api: HealthcareAPI) -> None:
        self.api = api
        super().__init__(address, HealthcareRequestHandler)


def create_server(host: str, port: int, api: HealthcareAPI) -> HealthcareHTTPServer:
    return HealthcareHTTPServer((host, port), api)
