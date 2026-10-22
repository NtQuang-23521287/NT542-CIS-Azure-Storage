from __future__ import annotations

import shlex
import threading

from audit_logger import export_logs
from exception_manager import create_exception

CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def _parse_options(parts: list[str]) -> dict:
    options = {}
    index = 0
    while index < len(parts):
        item = parts[index]
        if item.startswith("--"):
            key = item[2:].replace("-", "_")
            if index + 1 >= len(parts) or parts[index + 1].startswith("--"):
                options[key] = "true"
                index += 1
            else:
                options[key] = parts[index + 1]
                index += 2
        else:
            index += 1
    return options


def _prompt_missing(options: dict, key: str, label: str) -> str:
    value = options.get(key)
    if value:
        return value
    return input(f"{CYAN}{label}: {RESET}").strip()


def _handle_exception(parts: list[str]) -> None:
    options = _parse_options(parts)
    resource_type = _prompt_missing(options, "resource_type", "resource_type")
    resource_name = _prompt_missing(options, "resource_name", "resource_name")
    issue_name = options.get("issue") or _prompt_missing(
        options, "issue_name", "issue_name"
    )
    duration_text = options.get("duration") or _prompt_missing(
        options, "duration_minutes", "duration_minutes"
    )
    reason = _prompt_missing(options, "reason", "reason")

    exception = create_exception(
        resource_type=resource_type,
        resource_name=resource_name,
        issue_name=issue_name,
        duration_minutes=int(duration_text),
        reason=reason,
    )
    print(
        f"{GREEN}Exception created: {exception['id']} "
        f"(expires {exception['expires_at']}){RESET}"
    )


def _handle_getlog(parts: list[str]) -> None:
    options = _parse_options(parts)
    log_type = options.get("type", "all")
    lines = int(options.get("lines", "100"))
    path = export_logs(log_type=log_type, lines=lines)
    print(f"{GREEN}Log exported: {path}{RESET}")


def listen_admin_commands() -> None:
    print(
        f"{CYAN}Admin commands enabled: /exception, /getlog. "
        "Use --duration in minutes for exceptions."
        f"{RESET}"
    )
    while True:
        try:
            raw = input().strip()
        except EOFError:
            return
        if not raw:
            continue
        try:
            parts = shlex.split(raw)
            command = parts[0].lower()
            if command == "/exception":
                _handle_exception(parts[1:])
            elif command == "/getlog":
                _handle_getlog(parts[1:])
            else:
                print(f"{YELLOW}Unknown command: {command}{RESET}")
        except Exception as exc:
            print(f"{YELLOW}Command failed: {exc}{RESET}")


def start_admin_listener() -> threading.Thread:
    thread = threading.Thread(target=listen_admin_commands, daemon=True)
    thread.start()
    return thread
