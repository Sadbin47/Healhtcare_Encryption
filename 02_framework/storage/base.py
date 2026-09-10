"""Common contracts and errors for encrypted-record storage backends."""

from __future__ import annotations

from typing import Protocol

try:
    from ..crypto.envelope import EncryptedEnvelope
except ImportError:  # pragma: no cover - direct framework imports.
    from crypto.envelope import EncryptedEnvelope


class StorageError(RuntimeError):
    """Base error raised by a storage backend."""


class RecordNotFound(StorageError):
    """The requested encrypted record does not exist."""


class StorageIntegrityError(StorageError):
    """A retrieved object is not a valid, untampered encrypted envelope."""


class EncryptedRecordStore(Protocol):
    """Backend contract used by the application workflow."""

    backend_name: str

    def upload_encrypted_record(self, envelope: EncryptedEnvelope) -> str:
        """Persist an envelope and return an opaque backend reference."""

    def download_encrypted_record(self, reference: str) -> EncryptedEnvelope:
        """Retrieve and integrity-check an envelope by backend reference."""


def validate_envelope(envelope: EncryptedEnvelope) -> EncryptedEnvelope:
    if not isinstance(envelope, EncryptedEnvelope):
        raise TypeError("envelope must be an EncryptedEnvelope")
    if not envelope.verify_payload():
        raise StorageIntegrityError("encrypted envelope payload hash is invalid")
    return envelope


def parse_envelope_json(value: str) -> EncryptedEnvelope:
    """Parse stored JSON and normalize all corruption as an integrity error."""

    try:
        return validate_envelope(EncryptedEnvelope.from_json(value))
    except StorageIntegrityError:
        raise
    except (TypeError, ValueError, KeyError) as error:
        raise StorageIntegrityError("stored object is not a valid encrypted envelope") from error
