"""Minimal VPS API that stores encrypted envelopes and nothing else.

For deployment, bind this service to loopback and place it behind an HTTPS
reverse proxy such as Caddy or nginx. The API token must be supplied by the
deployment environment, never committed to source control.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .base import RecordNotFound, StorageError, StorageIntegrityError, parse_envelope_json
from .local_storage import LocalStorage


DEFAULT_MAX_ENVELOPE_BYTES = 100 * 1024 * 1024


class VPSStorageHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        token: str,
        storage_root: str | os.PathLike[str],
        max_envelope_bytes: int,
    ) -> None:
        if not token:
            raise ValueError("VPS API token must not be empty")
        if max_envelope_bytes <= 0:
            raise ValueError("max_envelope_bytes must be positive")
        self.api_token = token
        self.record_store = LocalStorage(storage_root)
        self.max_envelope_bytes = max_envelope_bytes
        super().__init__(server_address, VPSStorageRequestHandler)


class VPSStorageRequestHandler(BaseHTTPRequestHandler):
    """Bearer-authenticated POST/GET API for ciphertext envelopes."""

    server: VPSStorageHTTPServer
    server_version = "EncryptedRecordStore/1"
    sys_version = ""

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.api_token}"
        return hmac.compare_digest(supplied, expected)

    def _send_json(self, status: int, value: dict[str, str]) -> None:
        body = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _require_authorization(self) -> bool:
        if self._authorized():
            return True
        self._send_json(401, {"error": "unauthorized"})
        return False

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if not self._require_authorization():
            return
        if urlsplit(self.path).path != "/records":
            self._send_json(404, {"error": "not_found"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(400, {"error": "invalid_content_length"})
            return
        if content_length <= 0 or content_length > self.server.max_envelope_bytes:
            self._send_json(413, {"error": "invalid_envelope_size"})
            return
        raw = self.rfile.read(content_length)
        try:
            envelope = parse_envelope_json(raw.decode("utf-8"))
            reference = self.server.record_store.upload_encrypted_record(envelope)
        except UnicodeDecodeError:
            self._send_json(400, {"error": "invalid_encoding"})
            return
        except StorageIntegrityError:
            self._send_json(422, {"error": "invalid_envelope"})
            return
        except StorageError:
            self._send_json(500, {"error": "storage_failure"})
            return
        self._send_json(201, {"reference": reference})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if not self._require_authorization():
            return
        path = urlsplit(self.path).path
        prefix = "/records/"
        if not path.startswith(prefix) or len(path) == len(prefix):
            self._send_json(404, {"error": "not_found"})
            return
        reference = unquote(path[len(prefix):])
        try:
            envelope = self.server.record_store.download_encrypted_record(reference)
        except RecordNotFound:
            self._send_json(404, {"error": "not_found"})
            return
        except StorageError:
            self._send_json(500, {"error": "storage_failure"})
            return
        body = envelope.to_json().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Deployment logging belongs at the authenticated reverse proxy layer;
        # this avoids accidentally mixing identifiers into console output.
        return


def create_vps_server(
    host: str,
    port: int,
    token: str,
    storage_root: str | os.PathLike[str],
    *,
    max_envelope_bytes: int = DEFAULT_MAX_ENVELOPE_BYTES,
) -> VPSStorageHTTPServer:
    """Create the HTTP service used behind the VPS HTTPS reverse proxy."""

    return VPSStorageHTTPServer(
        (host, port),
        token=token,
        storage_root=storage_root,
        max_envelope_bytes=max_envelope_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve encrypted EHR envelopes on a VPS")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--storage-root", type=Path, required=True)
    parser.add_argument("--token-env", default="EHR_STORAGE_API_TOKEN")
    args = parser.parse_args()
    token = os.environ.get(args.token_env, "")
    if not token:
        parser.error(f"environment variable {args.token_env} must contain the API token")
    server = create_vps_server(args.host, args.port, token, args.storage_root)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
