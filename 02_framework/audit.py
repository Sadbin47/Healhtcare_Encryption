"""Structured, hash-chained audit logging for the healthcare workflow."""

from __future__ import annotations

import json
import os
import re
import threading
import fcntl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

try:
    from .crypto.hashing import canonical_json_bytes, sha256_hex
except ImportError:  # pragma: no cover - direct framework imports.
    from crypto.hashing import canonical_json_bytes, sha256_hex


AUDIT_VERSION = 1
GENESIS_HASH = "0" * 64

RECORD_CREATED = "RECORD_CREATED"
ACCESS_GRANTED = "ACCESS_GRANTED"
ACCESS_DENIED = "ACCESS_DENIED"
RECORD_RETRIEVED = "RECORD_RETRIEVED"
DECRYPTION_SUCCESS = "DECRYPTION_SUCCESS"
DECRYPTION_FAILED = "DECRYPTION_FAILED"
ACCESS_REVOKED = "ACCESS_REVOKED"

KNOWN_OPERATIONS = frozenset(
    {
        RECORD_CREATED,
        ACCESS_GRANTED,
        ACCESS_DENIED,
        RECORD_RETRIEVED,
        DECRYPTION_SUCCESS,
        DECRYPTION_FAILED,
        ACCESS_REVOKED,
    }
)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class AuditError(RuntimeError):
    """Base error for audit persistence or verification failures."""


class AuditIntegrityError(AuditError):
    """Raised when the append-only audit chain is malformed or altered."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class AuditEvent:
    """Security-relevant metadata event; never include EHR or key material."""

    operation: str
    success: bool
    actor: str
    record_id: str
    patient_id: str | None = None
    algorithm: str | None = None
    reason: str | None = None
    backend: str | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        operation = _required_text(self.operation, "operation").upper()
        if operation not in KNOWN_OPERATIONS:
            raise ValueError(f"unsupported audit operation: {operation}")
        object.__setattr__(self, "operation", operation)
        if not isinstance(self.success, bool):
            raise TypeError("success must be a bool")
        object.__setattr__(self, "actor", _required_text(self.actor, "actor"))
        object.__setattr__(self, "record_id", _required_text(self.record_id, "record_id"))
        for name in ("patient_id", "algorithm", "reason", "backend"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _required_text(value, name))
        if not self.success and not self.reason:
            raise ValueError("failed audit events require a reason")
        timestamp = self.timestamp or utc_now()
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError as error:
            raise ValueError("timestamp must be ISO-8601") from error
        if parsed.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        object.__setattr__(self, "timestamp", timestamp)

    @property
    def action(self) -> str:
        return self.operation

    @property
    def outcome(self) -> str:
        if self.success:
            return "success"
        return "denied" if self.operation == ACCESS_DENIED else "failure"

    @property
    def detail(self) -> str | None:
        return self.reason

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuditEvent":
        if not isinstance(value, dict):
            raise AuditIntegrityError("audit event must be an object")
        try:
            return cls(**value)
        except (TypeError, ValueError) as error:
            raise AuditIntegrityError("audit event is invalid") from error


@dataclass(frozen=True)
class AuditEntry:
    version: int
    sequence: int
    event: AuditEvent
    previous_hash: str
    entry_hash: str

    @staticmethod
    def calculate_hash(version: int, sequence: int, event: AuditEvent, previous_hash: str) -> str:
        return sha256_hex(
            canonical_json_bytes(
                {
                    "version": version,
                    "sequence": sequence,
                    "event": event.to_dict(),
                    "previous_hash": previous_hash,
                }
            )
        )

    @classmethod
    def create(cls, sequence: int, event: AuditEvent, previous_hash: str) -> "AuditEntry":
        if sequence < 1:
            raise ValueError("audit sequence must be positive")
        if not _HEX_64.fullmatch(previous_hash):
            raise ValueError("previous_hash must be a lowercase SHA-256 digest")
        entry_hash = cls.calculate_hash(AUDIT_VERSION, sequence, event, previous_hash)
        return cls(AUDIT_VERSION, sequence, event, previous_hash, entry_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "sequence": self.sequence,
            "event": self.event.to_dict(),
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuditEntry":
        if not isinstance(value, dict):
            raise AuditIntegrityError("audit entry must be an object")
        try:
            entry = cls(
                version=int(value["version"]),
                sequence=int(value["sequence"]),
                event=AuditEvent.from_dict(value["event"]),
                previous_hash=str(value["previous_hash"]),
                entry_hash=str(value["entry_hash"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuditIntegrityError("audit entry is invalid") from error
        if entry.version != AUDIT_VERSION:
            raise AuditIntegrityError("unsupported audit version")
        if not _HEX_64.fullmatch(entry.previous_hash) or not _HEX_64.fullmatch(entry.entry_hash):
            raise AuditIntegrityError("audit hashes are invalid")
        expected = cls.calculate_hash(entry.version, entry.sequence, entry.event, entry.previous_hash)
        if entry.entry_hash != expected:
            raise AuditIntegrityError("audit entry hash does not match content")
        return entry


def verify_chain(entries: Iterable[AuditEntry]) -> list[AuditEntry]:
    verified: list[AuditEntry] = []
    previous_hash = GENESIS_HASH
    for expected_sequence, entry in enumerate(entries, start=1):
        if entry.sequence != expected_sequence:
            raise AuditIntegrityError("audit sequence is not contiguous")
        if entry.previous_hash != previous_hash:
            raise AuditIntegrityError("audit hash chain is broken")
        expected_hash = AuditEntry.calculate_hash(
            entry.version, entry.sequence, entry.event, entry.previous_hash
        )
        if entry.entry_hash != expected_hash:
            raise AuditIntegrityError("audit entry hash does not match content")
        verified.append(entry)
        previous_hash = entry.entry_hash
    return verified


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> AuditEntry:
        ...


class MemoryAuditSink:
    """Hash-chained in-memory sink for tests and short-lived prototypes."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    @property
    def events(self) -> list[AuditEvent]:
        return [entry.event for entry in self.entries]

    def record(self, event: AuditEvent) -> AuditEntry:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        with self._lock:
            previous_hash = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
            entry = AuditEntry.create(len(self.entries) + 1, event, previous_hash)
            self.entries.append(entry)
            return entry

    def verify(self) -> bool:
        verify_chain(self.entries)
        return True


class JsonlAuditSink:
    """Append-only, fsync-backed JSONL ledger with a SHA-256 hash chain.

    The chain detects content edits, insertion, reordering, and non-tail
    deletion. The live sink also detects unexpected truncation before its next
    append. It is not a digital signature; detecting offline tail truncation
    after restart requires an externally protected checkpoint of ``head_hash``.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        entries = self.read_entries()
        self._sequence = len(entries)
        self._head_hash = entries[-1].entry_hash if entries else GENESIS_HASH

    @staticmethod
    def _read_handle(handle: Any) -> list[AuditEntry]:
        entries: list[AuditEntry] = []
        handle.seek(0)
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise AuditIntegrityError(f"blank audit line at {line_number}")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise AuditIntegrityError(f"invalid audit JSON at line {line_number}") from error
            entries.append(AuditEntry.from_dict(value))
        return verify_chain(entries)

    def read_entries(self) -> list[AuditEntry]:
        if not self.path.exists():
            return []
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
                try:
                    return self._read_handle(handle)
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise AuditError("failed to read audit ledger") from error

    @property
    def events(self) -> list[AuditEvent]:
        return [entry.event for entry in self.read_entries()]

    @property
    def head_hash(self) -> str:
        return self._head_hash

    def record(self, event: AuditEvent) -> AuditEntry:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        with self._lock:
            try:
                with self.path.open("a+", encoding="utf-8") as handle:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    try:
                        current = self._read_handle(handle)
                        current_head = current[-1].entry_hash if current else GENESIS_HASH
                        if len(current) != self._sequence or current_head != self._head_hash:
                            raise AuditIntegrityError("audit ledger changed unexpectedly")
                        entry = AuditEntry.create(self._sequence + 1, event, self._head_hash)
                        serialized = json.dumps(
                            entry.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
                        )
                        handle.seek(0, os.SEEK_END)
                        handle.write(serialized + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    finally:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError as error:
                raise AuditError("failed to append audit event") from error
            self._sequence = entry.sequence
            self._head_hash = entry.entry_hash
            return entry

    def verify(self) -> bool:
        self.read_entries()
        return True
