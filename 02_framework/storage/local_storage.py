"""Filesystem backend for deterministic offline development and testing."""

from __future__ import annotations

import os
import re
import tempfile
import uuid
from pathlib import Path

try:
    from ..crypto.envelope import EncryptedEnvelope
except ImportError:  # pragma: no cover - direct framework imports.
    from crypto.envelope import EncryptedEnvelope

from .base import EncryptedRecordStore, RecordNotFound, StorageError, parse_envelope_json, validate_envelope


_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class LocalStorage(EncryptedRecordStore):
    """Store JSON envelopes below one controlled directory.

    Files are written atomically and references are opaque UUID-based names;
    patient identifiers are never used as filesystem paths.
    """

    backend_name = "local"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, reference: str) -> Path:
        if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
            raise StorageError("invalid storage reference")
        filename = reference if reference.endswith(".json") else f"{reference}.json"
        path = (self.root / filename).resolve()
        if path.parent != self.root:
            raise StorageError("storage reference escapes storage root")
        return path

    def upload_encrypted_record(self, envelope: EncryptedEnvelope) -> str:
        validate_envelope(envelope)
        reference = f"{uuid.uuid4().hex}.json"
        destination = self._path_for(reference)
        fd, temporary_name = tempfile.mkstemp(prefix=".upload-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(envelope.to_json())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        except Exception as error:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise StorageError("failed to store encrypted envelope") from error
        return reference

    def download_encrypted_record(self, reference: str) -> EncryptedEnvelope:
        path = self._path_for(reference)
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise RecordNotFound(f"encrypted record not found: {reference}") from error
        except OSError as error:
            raise StorageError("failed to read encrypted envelope") from error
        return parse_envelope_json(raw)
