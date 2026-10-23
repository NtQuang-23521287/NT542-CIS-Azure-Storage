import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Mapping
from typing import Any


def _check(name: str, passed: bool, detail: str) -> dict[str, str]:
    return {"name": name, "status": "PASS" if passed else "FAIL", "detail": detail}


def _run_version(executable: str, args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    detail = (result.stdout or result.stderr).strip().splitlines()
    return result.returncode == 0, detail[0] if detail else "no version output"


def collect_doctor_checks(
    environ: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    env = os.environ if environ is None else environ
    version = sys.version_info
    python_ok = (version.major, version.minor) == (3, 14)
    checks = [
        _check(
            "python",
            python_ok,
            f"{version.major}.{version.minor}.{version.micro}; requires 3.14.x",
        )
    ]

    az = shutil.which("az", path=env.get("PATH"))
    checks.append(_check("azure_cli", bool(az), az or "not found on PATH"))
    subscription_id = env.get("AZURE_SUBSCRIPTION_ID", "").strip()
    checks.append(
        _check(
            "subscription",
            bool(subscription_id),
            "configured" if subscription_id else "AZURE_SUBSCRIPTION_ID is not set",
        )
    )
    if az and subscription_id:
        authenticated, _ = _run_version(
            az,
            [
                "account",
                "show",
                "--subscription",
                subscription_id,
                "--query",
                "id",
                "--output",
                "tsv",
            ],
        )
        checks.append(
            _check(
                "azure_auth",
                authenticated,
                "authenticated to configured subscription"
                if authenticated
                else "Azure CLI account query failed",
            )
        )
    else:
        checks.append(
            _check("azure_auth", False, "requires Azure CLI and subscription ID")
        )

    terraform = shutil.which("terraform", path=env.get("PATH"))
    if terraform:
        available, detail = _run_version(terraform, ["version"])
        checks.append(_check("terraform", available, detail))
    else:
        checks.append(_check("terraform", False, "not found on PATH"))

    checks.append(_check("sqlite", True, sqlite3.sqlite_version))
    analytics_enabled = env.get("ENABLE_LOG_ANALYTICS", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    workspace = env.get("LOG_ANALYTICS_WORKSPACE_ID", "").strip()
    if not analytics_enabled:
        analytics_detail = "disabled"
    elif workspace:
        analytics_detail = "configured"
    else:
        analytics_detail = "workspace ID missing"
    checks.append(
        _check(
            "log_analytics",
            not analytics_enabled or bool(workspace),
            analytics_detail,
        )
    )
    mutations_enabled = env.get("ALLOW_AZURE_MUTATIONS", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    checks.append(
        _check(
            "azure_mutations",
            not mutations_enabled,
            "disabled (plan-only)" if not mutations_enabled else "ENABLED",
        )
    )
    return checks
