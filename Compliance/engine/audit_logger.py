from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from config import (
    COMPLIANCE_LOG_FILE,
    EXCEPTION_LOG_FILE,
    INCIDENT_LOG_FILE,
    LOG_DIR,
)

LOG_FILES = {
    "compliance": COMPLIANCE_LOG_FILE,
    "incident": INCIDENT_LOG_FILE,
    "exception": EXCEPTION_LOG_FILE,
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp_for_log() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")


def timestamp_for_filename() -> str:
    return utc_now().strftime("%Y-%m-%d_%H-%M-%S")


def ensure_log_dir() -> None:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)


def append_log(log_type: str, title: str, fields: dict | None = None) -> None:
    ensure_log_dir()
    path = Path(LOG_FILES[log_type])
    lines = [
        "-" * 72,
        f"Time   : {timestamp_for_log()}",
        f"Event  : {title}",
    ]
    for key, value in (fields or {}).items():
        lines.append(f"{key:<7}: {value}")
    lines.append("")
    path.open("a", encoding="utf-8").write("\n".join(lines))


def log_compliance_event(title: str, fields: dict | None = None) -> None:
    append_log("compliance", title, fields)


def log_exception_event(title: str, fields: dict | None = None) -> None:
    append_log("exception", title, fields)


def log_incident_event(title: str, fields: dict | None = None) -> None:
    append_log("incident", title, fields)


def _tail_lines(path: Path, line_count: int) -> list[str]:
    if not path.exists():
        return ["No log file found."]
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-line_count:] if line_count > 0 else lines


def _section(title: str, body: Iterable[str]) -> list[str]:
    return [
        "=" * 72,
        f"[{title.upper()}]",
        "=" * 72,
        *body,
        "",
    ]


def export_logs(log_type: str = "all", lines: int = 100) -> str:
    ensure_log_dir()
    export_time = timestamp_for_log()
    filename = f"export_{log_type}_{timestamp_for_filename()}.log"
    export_path = Path(LOG_DIR) / filename

    selected_types = list(LOG_FILES) if log_type == "all" else [log_type]
    if any(item not in LOG_FILES for item in selected_types):
        valid = ", ".join(["all", *LOG_FILES.keys()])
        raise ValueError(f"Invalid log type. Use one of: {valid}")

    output = [
        "=" * 72,
        "AZURE COMPLIANCE MONITOR - LOG EXPORT",
        "=" * 72,
        f"Export time : {export_time}",
        f"Log type    : {log_type}",
        f"Lines       : {lines}",
        "",
    ]

    for item in selected_types:
        body = _tail_lines(Path(LOG_FILES[item]), lines)
        output.extend(_section(f"{item} log", body))

    export_path.write_text("\n".join(output), encoding="utf-8")
    return str(export_path)
