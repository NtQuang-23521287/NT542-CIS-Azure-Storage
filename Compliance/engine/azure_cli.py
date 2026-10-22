"""Safe Azure CLI execution helpers."""

from __future__ import annotations

import shutil
import subprocess
from uuid import UUID

from config import AZURE_SUBSCRIPTION_ID


def _scoped_args(args: list[str]) -> list[str]:
    if not args or any(not isinstance(arg, str) or not arg for arg in args):
        raise ValueError("Azure CLI arguments must be non-empty strings")
    if any(
        arg.lower() in {"--subscription", "-s"} or arg.lower().startswith("--subscription=")
        for arg in args
    ):
        raise ValueError("Azure CLI subscription cannot be overridden")
    try:
        subscription_id = str(UUID(AZURE_SUBSCRIPTION_ID or ""))
    except ValueError as exc:
        raise ValueError("AZURE_SUBSCRIPTION_ID must be a valid GUID") from exc
    return [*args, "--subscription", subscription_id]


def run_az(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run Azure CLI with an argument vector and no command shell."""
    scoped_args = _scoped_args(args)

    executable = shutil.which("az") or shutil.which("az.cmd") or shutil.which("az.exe")
    if not executable:
        raise RuntimeError("Azure CLI was not found in PATH. Install it or restart the terminal.")

    return subprocess.run(
        [executable, *scoped_args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def display_az_command(args: list[str]) -> str:
    """Render an argument vector for logs only; never execute this string."""
    return subprocess.list2cmdline(["az", *_scoped_args(args)])
