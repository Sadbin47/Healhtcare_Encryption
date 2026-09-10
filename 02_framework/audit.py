"""Minimal audit-event sinks for the workflow service."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    action: str
    outcome: str
    record_id: str
    patient_id: str | None = None
    doctor_id: str | None = None
    backend: str | None = None
    detail: str | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            object.__setattr__(self, "timestamp", _utc_now())
        for name in ("action", "outcome", "record_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a non-empty string")


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        ...


class MemoryAuditSink:
    """Deterministic sink useful for tests and an in-process prototype."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        self.events.append(event)


class JsonlAuditSink:
    """Append-only JSONL sink containing metadata, never EHR plaintext."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), ensure_ascii=True, sort_keys=True) + "\n")
