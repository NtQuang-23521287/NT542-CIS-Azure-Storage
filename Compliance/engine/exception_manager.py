"""Legacy monitor adapter for the SQLite exception repository.

The local admin command creates requests only. Activation requires the
separate reviewed `acg exception activate` command.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from config import EXCEPTIONS_DB, EXCEPTIONS_FILE, MAX_EXCEPTION_MINUTES

from azure_compliance_guard.exceptions import (
    ExceptionRepository,
    ExceptionStoreError,
    VersionConflict,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _repo() -> ExceptionRepository:
    if Path(EXCEPTIONS_FILE).exists():
        raise ExceptionStoreError("legacy JSON exceptions require explicit review")
    return ExceptionRepository(Path(EXCEPTIONS_DB))


def _legacy_view(record) -> dict:
    return {
        **record.to_dict(),
        "resource_type": record.resource_id.split(":", 2)[1]
        if record.resource_id.startswith("legacy:")
        else "unknown",
        "issue_name": record.rule_id,
        "status": record.status.lower(),
        "revoked_reason": record.closed_reason if record.status == "REVOKED" else None,
    }


def load_exceptions(refresh: bool = True) -> list[dict]:
    repo = _repo()
    if refresh:
        now = _now()
        for record in repo.list(status="ACTIVE"):
            if datetime.fromisoformat(record.expires_at) <= now:
                try:
                    repo.expire(record.id, expected_version=record.version, now=now)
                except VersionConflict:
                    pass
    return [_legacy_view(record) for record in repo.list()]


def create_exception(
    resource_type: str,
    resource_name: str,
    issue_name: str,
    duration_minutes: int,
    reason: str,
    severity: str = "CRITICAL",
    *,
    owner: str,
    ticket: str,
) -> dict:
    if duration_minutes <= 0 or duration_minutes > MAX_EXCEPTION_MINUTES:
        raise ValueError(
            f"Duration must be between 1 and {MAX_EXCEPTION_MINUTES} minutes"
        )
    del severity  # Severity belongs to the finding, not the exception lifecycle.
    now = _now()
    record = _repo().request(
        resource_id=f"legacy:{resource_type}:{resource_name}",
        resource_name=resource_name,
        rule_id=issue_name,
        owner=owner,
        reason=reason,
        ticket=ticket,
        expires_at=now + timedelta(minutes=duration_minutes),
        now=now,
    )
    return _legacy_view(record)


def find_active_exception(resource_name: str, issue_name: str) -> dict | None:
    now = _now()
    return next(
        (
            item
            for item in load_exceptions()
            if item["status"] == "active"
            and item["resource_name"] == resource_name
            and item["issue_name"] == issue_name
            and datetime.fromisoformat(item["expires_at"]) > now
        ),
        None,
    )


def find_active_exception_for_resource(resource_name: str) -> dict | None:
    now = _now()
    return next(
        (
            item
            for item in load_exceptions()
            if item["status"] == "active"
            and item["resource_name"] == resource_name
            and datetime.fromisoformat(item["expires_at"]) > now
        ),
        None,
    )


def revoke_active_exceptions_for_resource(
    resource_name: str, reason: str
) -> list[dict]:
    repo = _repo()
    now = _now()
    revoked = []
    for record in repo.list(status="ACTIVE"):
        if record.resource_name != resource_name:
            continue
        if datetime.fromisoformat(record.expires_at) <= now:
            try:
                repo.expire(record.id, expected_version=record.version, now=now)
            except VersionConflict:
                pass
            continue
        try:
            closed = repo.revoke(
                record.id,
                actor="incident-handler",
                reason=reason,
                expected_version=record.version,
                incident=True,
                now=now,
            )
        except VersionConflict:
            continue
        revoked.append(_legacy_view(closed))
    return revoked


def remaining_minutes(exception: dict) -> int:
    remaining = datetime.fromisoformat(exception["expires_at"]) - _now()
    return max(0, int(remaining.total_seconds() // 60))
