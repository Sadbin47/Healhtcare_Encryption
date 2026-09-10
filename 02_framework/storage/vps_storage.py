"""Authenticated HTTPS client for a VPS encrypted-object service.

The VPS API is intentionally small: POST /records returns ``reference`` and
GET /records/{reference} returns the serialized encrypted envelope. The VPS
stores ciphertext envelopes only; authorization remains in the application.
"""

from __future__ import annotations

import json
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

try:
    from ..crypto.envelope import EncryptedEnvelope
except ImportError:  # pragma: no cover - direct framework imports.
    from crypto.envelope import EncryptedEnvelope

from .base import EncryptedRecordStore, RecordNotFound, StorageError, parse_envelope_json, validate_envelope


HttpRequester = Callable[[str, str, Mapping[str, str], bytes | None, float], tuple[int, bytes]]


def _default_requester(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, bytes]:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310 - URL is configured by operator.
            return int(response.status), response.read()
    except HTTPError as error:
        try:
            payload = error.read()
            if error.code == 404:
                raise RecordNotFound("encrypted record was not found on VPS") from error
            raise StorageError(f"VPS request failed with HTTP {error.code}: {payload[:200]!r}") from error
        finally:
            error.close()
    except URLError as error:
        raise StorageError(f"VPS connection failed: {error.reason}") from error
    except OSError as error:
        raise StorageError("VPS request failed") from error


class VPSStorage(EncryptedRecordStore):
    """Store envelopes through an authenticated HTTPS API."""

    backend_name = "vps"

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 10.0,
        requester: HttpRequester | None = None,
        allow_insecure_http: bool = False,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL")
        normalized = base_url.rstrip("/")
        if not normalized.startswith("https://") and not (allow_insecure_http and normalized.startswith("http://")):
            raise ValueError("VPS storage requires an https:// URL")
        if not isinstance(token, str) or not token.strip():
            raise ValueError("token must be a non-empty bearer token")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = normalized
        self.token = token
        self.timeout = float(timeout)
        self._request = requester or _default_requester

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def upload_encrypted_record(self, envelope: EncryptedEnvelope) -> str:
        validate_envelope(envelope)
        status, body = self._request(
            "POST",
            f"{self.base_url}/records",
            self._headers(),
            envelope.to_json().encode("utf-8"),
            self.timeout,
        )
        if status < 200 or status >= 300:
            raise StorageError(f"VPS upload failed with HTTP {status}")
        try:
            response = json.loads(body.decode("utf-8"))
            reference = response["reference"]
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
            raise StorageError("VPS upload returned an invalid reference") from error
        if not isinstance(reference, str) or not reference.strip() or "/" in reference or "\\" in reference:
            raise StorageError("VPS returned an unsafe storage reference")
        return reference

    def download_encrypted_record(self, reference: str) -> EncryptedEnvelope:
        if not isinstance(reference, str) or not reference.strip():
            raise ValueError("reference must be a non-empty string")
        status, body = self._request(
            "GET",
            f"{self.base_url}/records/{quote(reference, safe='')}",
            self._headers(),
            None,
            self.timeout,
        )
        if status == 404:
            raise RecordNotFound(f"encrypted record not found: {reference}")
        if status < 200 or status >= 300:
            raise StorageError(f"VPS download failed with HTTP {status}")
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StorageError("VPS returned non-UTF-8 data") from error
        return parse_envelope_json(raw)
