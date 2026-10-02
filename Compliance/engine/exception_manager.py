from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit_logger import log_exception_event
from config import EXCEPTIONS_FILE, MAX_EXCEPTION_MINUTES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_all() -> list[dict]:
    path = Path(EXCEPTIONS_FILE)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_all(exceptions: list[dict]) -> None:
    path = Path(EXCEPTIONS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(exceptions, indent=2), encoding="utf-8")


def _refresh_status(exception: dict, now: datetime | None = None) -> dict:
    now = now or _now()
    if exception.get("status") == "active" and _parse_time(exception["expires_at"]) <= now:
        exception["status"] = "expired"
    return exception


def load_exceptions(refresh: bool = True) -> list[dict]:
    exceptions = _load_all()
    if refresh:
        exceptions = [_refresh_status(item) for item in exceptions]
        _save_all(exceptions)
    return exceptions


def create_exception(
    resource_type: str,
    resource_name: str,
    issue_name: str,
    duration_minutes: int,
    reason: str,
    severity: str = "CRITICAL",
) -> dict:
    if duration_minutes <= 0:
        raise ValueError("Duration must be greater than 0 minutes.")
    if duration_minutes > MAX_EXCEPTION_MINUTES:
        raise ValueError(f"Duration cannot exceed {MAX_EXCEPTION_MINUTES} minutes.")

    created_at = _now()
    expires_at = created_at + timedelta(minutes=duration_minutes)
    exceptions = load_exceptions()
    exception = {
        "id": f"exc-{created_at.strftime('%Y%m%d-%H%M%S')}-{len(exceptions) + 1:03d}",
        "resource_type": resource_type,
        "resource_name": resource_name,
        "issue_name": issue_name,
        "severity": severity,
        "reason": reason,
        "duration_minutes": duration_minutes,
        "created_at": _format_time(created_at),
        "expires_at": _format_time(expires_at),
        "status": "active",
    }
    exceptions.append(exception)
    _save_all(exceptions)
    log_exception_event(
        "EXCEPTION_CREATED",
        {
            "Id": exception["id"],
            "Resource": f"{resource_type}/{resource_name}",
            "Issue": issue_name,
            "Duration": f"{duration_minutes} minutes",
            "Expires": exception["expires_at"],
            "Reason": reason,
        },
    )
    return exception


def find_active_exception(resource_name: str, issue_name: str) -> dict | None:
    now = _now()
    exceptions = load_exceptions()
    for exception in exceptions:
        if exception.get("status") != "active":
            continue
        if exception.get("resource_name") != resource_name:
            continue
        if exception.get("issue_name") != issue_name:
            continue
        if _parse_time(exception["expires_at"]) > now:
            return exception
    return None


def find_active_exception_for_resource(resource_name: str) -> dict | None:
    now = _now()
    exceptions = load_exceptions()
    for exception in exceptions:
        if exception.get("status") != "active":
            continue
        if exception.get("resource_name") != resource_name:
            continue
        if _parse_time(exception["expires_at"]) > now:
            return exception
    return None


def revoke_active_exceptions_for_resource(resource_name: str, reason: str) -> list[dict]:
    now = _now()
    revoked = []
    exceptions = load_exceptions()

    for exception in exceptions:
        if exception.get("status") != "active":
            continue
        if exception.get("resource_name") != resource_name:
            continue
        if _parse_time(exception["expires_at"]) <= now:
            exception["status"] = "expired"
            continue

        exception["status"] = "revoked"
        exception["revoked_at"] = _format_time(now)
        exception["revoked_reason"] = reason
        exception["duration_minutes"] = 0
        exception["expires_at"] = _format_time(now)
        revoked.append(exception.copy())

    _save_all(exceptions)

    for exception in revoked:
        log_exception_event(
            "EXCEPTION_REVOKED",
            {
                "Id": exception["id"],
                "Resource": f"{exception.get('resource_type', 'unknown')}/{resource_name}",
                "Issue": exception.get("issue_name", "unknown"),
                "Reason": reason,
                "Revoked": exception["revoked_at"],
            },
        )

    return revoked


def remaining_minutes(exception: dict) -> int:
    remaining = _parse_time(exception["expires_at"]) - _now()
    return max(0, int(remaining.total_seconds() // 60))
