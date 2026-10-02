"""
Handle compliance issues by severity.

WARNING:
  Log/report for admin review.
CRITICAL:
  Auto-remediate unless an active time-bound exception exists.
ESCALATED_CRITICAL:
  Trigger incident response. Exceptions cannot suppress incidents.
"""

import logging
import subprocess

from audit_logger import log_compliance_event, log_exception_event
from exception_manager import find_active_exception, remaining_minutes
from incident_response import handle_incident


REMEDIATION_COMMANDS = {
    "HTTPS traffic only setting mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--https-only true"
    ),
    "Minimum TLS version mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--minimum-tls-version TLS1_2"
    ),
    "Public Network Access mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--public-network-access Disabled"
    ),
    "Blob versioning disabled": (
        "az storage account blob-service-properties update "
        "--account-name {account} "
        "--resource-group {rg} "
        "--enable-versioning true"
    ),
    "Key Vault Public Network Access mismatch": (
        "az keyvault update "
        "--name {account} "
        "--resource-group {rg} "
        "--public-network-access Disabled"
    ),
    "Key Vault RBAC authorization disabled": (
        "az keyvault update "
        "--name {account} "
        "--resource-group {rg} "
        "--enable-rbac-authorization true"
    ),
    "Key Vault recoverability mismatch": (
        "az keyvault update "
        "--name {account} "
        "--resource-group {rg} "
        "--enable-purge-protection true"
    ),
    "SQL auditing disabled": (
        "az sql server audit-policy update "
        "--resource-group {rg} "
        "--name {account} "
        "--state Enabled"
    ),
    "Microsoft Defender for SQL disabled": (
        "az security pricing create "
        "--name SqlServers "
        "--tier Standard"
    ),
    "SQL Minimum TLS version mismatch": (
        "az sql server update "
        "--name {account} "
        "--resource-group {rg} "
        "--minimal-tls-version 1.2"
    ),
    "SQL Public Network Access mismatch": (
        "az sql server update "
        "--name {account} "
        "--resource-group {rg} "
        "--enable-public-network false"
    ),
}


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _run_command(cmd: str, issue_name: str, resource_name: str) -> bool:
    logging.info("[REMEDIATION] Running: %s", cmd)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        msg = f"[REMEDIATION] Success: {issue_name}"
        print(f"{GREEN}{msg}{RESET}")
        logging.info(msg)
        log_compliance_event(
            "AUTO_REMEDIATION_SUCCESS",
            {
                "Resource": resource_name,
                "Issue": issue_name,
                "Command": cmd,
                "Result": "SUCCESS",
            },
        )
        return True

    error = result.stderr.strip() or result.stdout.strip()
    msg = f"[REMEDIATION] Failed: {issue_name}. Error: {error}"
    print(f"{RED}{msg}{RESET}")
    logging.error(msg)
    log_compliance_event(
        "AUTO_REMEDIATION_FAILED",
        {
            "Resource": resource_name,
            "Issue": issue_name,
            "Command": cmd,
            "Result": "FAILED",
            "Error": error,
        },
    )
    return False


def _handle_warning(resource_name: str, issue: dict) -> None:
    name = issue["name"]
    print(
        f"\n{YELLOW}{BOLD}[WARNING] Configuration drift detected{RESET}\n"
        f"  Resource : {resource_name}\n"
        f"  Issue    : {name}\n"
        "  Action   : logged for report/admin review\n"
    )
    logging.warning("[WARNING] %s on %s", name, resource_name)
    log_compliance_event(
        "WARNING_DETECTED",
        {
            "Resource": resource_name,
            "Issue": name,
            "Action": "ADMIN_REVIEW_REQUIRED",
        },
    )


def _handle_critical(resource_group: str, resource_name: str, issue: dict) -> None:
    name = issue["name"]
    active_exception = find_active_exception(resource_name, name)
    if active_exception:
        remaining = remaining_minutes(active_exception)
        print(
            f"\n{YELLOW}{BOLD}[CRITICAL] Drift allowed by active exception{RESET}\n"
            f"  Resource : {resource_name}\n"
            f"  Issue    : {name}\n"
            f"  Exception: {active_exception['id']}\n"
            f"  Remaining: {remaining} minutes\n"
        )
        logging.warning(
            "[EXCEPTION] Skipped remediation for %s on %s via %s",
            name,
            resource_name,
            active_exception["id"],
        )
        log_exception_event(
            "REMEDIATION_SKIPPED",
            {
                "Resource": resource_name,
                "Issue": name,
                "Exception": active_exception["id"],
                "Remaining": f"{remaining} minutes",
                "Reason": active_exception.get("reason", ""),
            },
        )
        return

    cmd_template = REMEDIATION_COMMANDS.get(name)
    if not cmd_template:
        msg = f"No automatic remediation command for: {name}"
        print(f"{YELLOW}{msg}{RESET}")
        logging.warning("[REMEDIATION] %s", msg)
        log_compliance_event(
            "AUTO_REMEDIATION_UNAVAILABLE",
            {
                "Resource": resource_name,
                "Issue": name,
                "Action": "MANUAL_REVIEW_REQUIRED",
            },
        )
        return

    cmd = cmd_template.format(account=resource_name, rg=resource_group)
    print(
        f"\n{RED}{BOLD}[CRITICAL] Dangerous drift detected{RESET}\n"
        f"  Resource : {resource_name} ({resource_group})\n"
        f"  Issue    : {name}\n"
        "  Action   : auto-remediating back to baseline\n"
    )
    logging.warning("[CRITICAL] Auto-remediating %s on %s", name, resource_name)
    log_compliance_event(
        "CRITICAL_DETECTED",
        {
            "Resource": resource_name,
            "Issue": name,
            "Action": "AUTO_REMEDIATE",
            "Command": cmd,
        },
    )
    _run_command(cmd, name, resource_name)


def remediate_config(
    resource_group: str,
    resource_name: str,
    issues: list[dict],
):
    for issue in issues:
        severity = issue["severity"]
        if severity == "WARNING":
            _handle_warning(resource_name, issue)
        elif severity == "CRITICAL":
            _handle_critical(resource_group, resource_name, issue)
        elif severity == "ESCALATED_CRITICAL":
            handle_incident(resource_group, resource_name, issue)
        else:
            logging.warning("Unknown severity %s for issue %s", severity, issue)
