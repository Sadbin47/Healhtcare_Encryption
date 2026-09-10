"""IPFS HTTP API client for encrypted-envelope storage.

This client targets a Kubo-compatible API (``/api/v0/add``) and an IPFS
gateway (``/ipfs/{cid}``). IPFS provides content addressing, not consent or
authorization; those checks remain in the framework service.
"""

from __future__ import annotations

import json
import uuid
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
                raise RecordNotFound("IPFS object was not found") from error
            raise StorageError(f"IPFS request failed with HTTP {error.code}: {payload[:200]!r}") from error
        finally:
            error.close()
    except URLError as error:
        raise StorageError(f"IPFS connection failed: {error.reason}") from error
    except OSError as error:
        raise StorageError("IPFS request failed") from error


def _multipart_envelope(payload: bytes) -> tuple[bytes, str]:
    boundary = f"----NSPaperWork{uuid.uuid4().hex}"
    marker = boundary.encode("ascii")
    body = (
        b"--" + marker + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="envelope.json"\r\n'
        b"Content-Type: application/json\r\n\r\n"
        + payload
        + b"\r\n--"
        + marker
        + b"--\r\n"
    )
    return body, f"multipart/form-data; boundary={boundary}"


class IPFSStorage(EncryptedRecordStore):
    """Store serialized envelopes through a Kubo API and gateway."""

    backend_name = "ipfs"

    def __init__(
        self,
        api_url: str = "http://127.0.0.1:5001",
        gateway_url: str = "http://127.0.0.1:8080",
        *,
        timeout: float = 10.0,
        requester: HttpRequester | None = None,
    ) -> None:
        if not api_url or not gateway_url:
            raise ValueError("api_url and gateway_url are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.api_url = api_url.rstrip("/")
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = float(timeout)
        self._request = requester or _default_requester

    def upload_encrypted_record(self, envelope: EncryptedEnvelope) -> str:
        validate_envelope(envelope)
        body, content_type = _multipart_envelope(envelope.to_json().encode("utf-8"))
        status, response_body = self._request(
            "POST",
            f"{self.api_url}/api/v0/add?pin=true",
            {"Accept": "application/json", "Content-Type": content_type},
            body,
            self.timeout,
        )
        if status < 200 or status >= 300:
            raise StorageError(f"IPFS upload failed with HTTP {status}")
        try:
            # Kubo returns one JSON object per line; the final object is the file.
            records = [json.loads(line) for line in response_body.decode("utf-8").splitlines() if line.strip()]
            response = records[-1]
            cid = response["Hash"]
        except (IndexError, KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
            raise StorageError("IPFS upload returned an invalid CID") from error
        if not isinstance(cid, str) or not cid.strip():
            raise StorageError("IPFS returned an empty CID")
        return cid

    def download_encrypted_record(self, reference: str) -> EncryptedEnvelope:
        if not isinstance(reference, str) or not reference.strip():
            raise ValueError("CID must be a non-empty string")
        status, body = self._request(
            "GET",
            f"{self.gateway_url}/ipfs/{quote(reference, safe='')}",
            {"Accept": "application/json"},
            None,
            self.timeout,
        )
        if status == 404:
            raise RecordNotFound(f"IPFS object not found: {reference}")
        if status < 200 or status >= 300:
            raise StorageError(f"IPFS download failed with HTTP {status}")
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StorageError("IPFS returned non-UTF-8 data") from error
        return parse_envelope_json(raw)
