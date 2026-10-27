"""Schema-v1 append-only evidence for local scan and lifecycle reports."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class EvidenceError(ValueError):
    """An evidence record or JSONL stream is invalid."""


SCHEMA_VERSION = 1
MAX_LINE_BYTES = 65_536
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
EVENT_TYPES = frozenset(
    {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "FINDING",
        "EXCEPTION_CREATED",
        "EXCEPTION_ACTIVATED",
        "EXCEPTION_EXPIRED",
        "EXCEPTION_REVOKED",
        "EXCEPTION_INCIDENT_REVOKED",
        "REMEDIATION_PLANNED",
        "REMEDIATION_DRY_RUN",
        "REMEDIATION_APPROVED",
        "REMEDIATION_EXECUTION",
        "REMEDIATION_RECOLLECTED",
        "REMEDIATION_VERIFIED",
        "REMEDIATION_FAILED",
        "INCIDENT_DETECTED",
        "INCIDENT_ESCALATED",
        "INCIDENT_CONTAINMENT",
        "INCIDENT_VERIFIED",
        "INCIDENT_VERIFICATION_FAILED",
        "VALIDATION_CASE",
    }
)
REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "timestamp",
        "event_type",
        "resource",
        "source",
        "data",
    }
)
RESOURCE_FIELDS = frozenset({"service", "name", "resource_group", "subscription_id"})
_append_lock = threading.Lock()


def _validate(event: object) -> dict:
    if not isinstance(event, dict) or set(event) != REQUIRED_FIELDS:
        raise EvidenceError("evidence event has missing or unknown fields")
    if event["schema_version"] != SCHEMA_VERSION or isinstance(
        event["schema_version"], bool
    ):
        raise EvidenceError("unsupported evidence schema version")
    if (
        not isinstance(event["event_type"], str)
        or event["event_type"] not in EVENT_TYPES
    ):
        raise EvidenceError("unknown evidence event type")
    for field in ("event_id", "run_id"):
        if not isinstance(event[field], str) or not event[field].strip():
            raise EvidenceError(f"{field} must be non-empty")
    try:
        stamp = datetime.fromisoformat(event["timestamp"])
        if stamp.tzinfo is None:
            raise ValueError("timezone required")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("invalid evidence timestamp") from exc
    resource = event["resource"]
    if resource is not None:
        if not isinstance(resource, dict) or not set(resource) <= RESOURCE_FIELDS:
            raise EvidenceError("invalid resource reference")
        if any(
            value is not None and not isinstance(value, str)
            for value in resource.values()
        ):
            raise EvidenceError("invalid resource reference field")
        if not all(
            isinstance(resource.get(key), str) and resource[key].strip()
            for key in ("service", "name", "resource_group")
        ):
            raise EvidenceError("resource reference is incomplete")
    source = event["source"]
    if not isinstance(source, dict) or not all(
        isinstance(source.get(key), str) and source[key].strip()
        for key in ("mode", "collector")
    ):
        raise EvidenceError("source metadata is incomplete")
    if not isinstance(event["data"], dict):
        raise EvidenceError("event data must be an object")
    try:
        encoded = json.dumps(event, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvidenceError("event is not JSON serializable") from exc
    if len(encoded.encode("utf-8")) + 1 > MAX_LINE_BYTES:
        raise EvidenceError("evidence event exceeds line size limit")
    return event


def make_event(
    event_type: str,
    *,
    run_id: str,
    resource: dict | None,
    source: dict,
    data: dict,
    now: datetime | None = None,
) -> dict:
    timestamp = now or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise EvidenceError("event timestamp must include a timezone")
    return _validate(
        {
            "schema_version": SCHEMA_VERSION,
            "event_id": str(uuid4()),
            "run_id": run_id,
            "timestamp": timestamp.astimezone(UTC).isoformat(),
            "event_type": event_type,
            "resource": resource,
            "source": source,
            "data": data,
        }
    )


def read_events(path: Path) -> list[dict]:
    events = []
    if Path(path).stat().st_size > MAX_EVIDENCE_BYTES:
        raise EvidenceError("evidence file exceeds size limit")
    with Path(path).open("rb") as stream:
        for number, raw in enumerate(stream, start=1):
            try:
                if len(raw) > MAX_LINE_BYTES or not raw.endswith(b"\n"):
                    raise EvidenceError("oversized or incomplete line")
                event = json.loads(raw)
                events.append(_validate(event))
            except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as exc:
                raise EvidenceError(
                    f"invalid evidence at line {number}: {exc}"
                ) from exc
    return events


def append_events(path: Path, events: list[dict]) -> None:
    if not events:
        return
    lines = []
    for event in events:
        validated = _validate(event)
        lines.append(
            (
                json.dumps(validated, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with _append_lock:
        existing_bytes = target.stat().st_size if target.exists() else 0
        if existing_bytes + sum(map(len, lines)) > MAX_EVIDENCE_BYTES:
            raise EvidenceError("evidence file exceeds size limit")
        if target.exists():
            read_events(target)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
        descriptor = os.open(target, flags, 0o600)
        try:
            for line in lines:
                if os.write(descriptor, line) != len(line):
                    raise EvidenceError("short evidence write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
