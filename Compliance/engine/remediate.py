from __future__ import annotations

from dataclasses import dataclass

from engine.collector import run_az_command


@dataclass
class RemediationAction:
    control_id: str
    account_name: str
    title: str
    command_args: list[str]
    description: str
    requires_recreate: bool = False


def build_plan(report: dict) -> list[RemediationAction]:
    """Sinh remediation plan từ các check FAIL có metadata tự động."""
    plan: list[RemediationAction] = []
    for account in report.get("accounts", []):
        account_name = account.get("account_name", "unknown")
        for check in account.get("checks", []):
            if check.get("status") != "FAIL":
                continue
            spec = check.get("remediation_spec") or {}
            command_args = spec.get("command_args")
            if not command_args:
                continue
            plan.append(
                RemediationAction(
                    control_id=check.get("control_id", "unknown"),
                    account_name=account_name,
                    title=check.get("title", ""),
                    command_args=command_args,
                    description=spec.get("description", check.get("remediation", "")),
                    requires_recreate=spec.get("requires_recreate", False),
                )
            )
    return plan


def execute_plan(plan: list[RemediationAction], *, apply_changes: bool) -> list[dict]:
    """Chạy remediation plan hoặc chỉ dry-run."""
    results: list[dict] = []
    for action in plan:
        command_preview = " ".join(action.command_args)
        if not apply_changes:
            results.append(
                {
                    "control_id": action.control_id,
                    "account_name": action.account_name,
                    "title": action.title,
                    "mode": "dry-run",
                    "status": "PLANNED",
                    "description": action.description,
                    "command": command_preview,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "",
                    "requires_recreate": action.requires_recreate,
                }
            )
            continue

        command_result = run_az_command(action.command_args, expect_json=False, timeout=60)
        results.append(
            {
                "control_id": action.control_id,
                "account_name": action.account_name,
                "title": action.title,
                "mode": "apply",
                "status": "SUCCESS" if command_result["ok"] else "FAILED",
                "description": action.description,
                "command": " ".join(command_result["cmd"]),
                "returncode": command_result["returncode"],
                "stdout": command_result["stdout"],
                "stderr": command_result["stderr"],
                "requires_recreate": action.requires_recreate,
            }
        )
    return results
