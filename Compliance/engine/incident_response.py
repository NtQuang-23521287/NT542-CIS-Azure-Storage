from __future__ import annotations

import logging
import subprocess

from audit_logger import log_incident_event
from exception_manager import (
    find_active_exception_for_resource,
    revoke_active_exceptions_for_resource,
)

RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


CONTAINMENT_COMMANDS = {
    "storage": (
        "az storage account update "
        "--name {resource} "
        "--resource-group {rg} "
        "--public-network-access Disabled"
    ),
    "key_vault": (
        "az keyvault update "
        "--name {resource} "
        "--resource-group {rg} "
        "--public-network-access Disabled"
    ),
    "sql": (
        "az sql server update "
        "--name {resource} "
        "--resource-group {rg} "
        "--enable-public-network false"
    ),
}


def _run_containment(resource_group: str, resource_name: str, issue: dict) -> tuple[str, str]:
    service = issue.get("service")
    command_template = CONTAINMENT_COMMANDS.get(service)
    if not command_template:
        return "SKIPPED", f"No containment command for service: {service}"

    command = command_template.format(resource=resource_name, rg=resource_group)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return "SUCCESS", command
    error = result.stderr.strip() or result.stdout.strip()
    return "FAILED", f"{command} | {error}"


def handle_incident(resource_group: str, resource_name: str, issue: dict) -> None:
    evidence = issue.get("evidence", {})
    active_exception = find_active_exception_for_resource(resource_name)
    exception_note = (
        f"Active exception present: {active_exception['id']}"
        if active_exception
        else "No active exception for this incident"
    )
    revoked = revoke_active_exceptions_for_resource(
        resource_name,
        f"Revoked because {issue['name']} was detected",
    )
    containment_status, containment_detail = _run_containment(resource_group, resource_name, issue)

    print(
        f"\n{RED}{BOLD}[ESCALATED_CRITICAL] Security incident detected{RESET}\n"
        f"  Resource : {resource_name} ({resource_group})\n"
        f"  Issue    : {issue['name']}\n"
        f"  Source IP: {evidence.get('source_ip', 'unknown')}\n"
        f"  Identity : {evidence.get('identity', 'unknown')}\n"
        f"  Operation: {evidence.get('operation', 'unknown')}\n"
        f"  Result   : {evidence.get('result', 'unknown')}\n"
        f"  Exception: revoked {len(revoked)} active exception(s)\n"
        f"  Contain  : {containment_status}\n"
        "  Action   : urgent review required; public exposure is contained when possible\n"
    )

    log_incident_event(
        "ESCALATED_CRITICAL_DETECTED",
        {
            "Resource": resource_name,
            "Issue": issue["name"],
            "Source": evidence.get("source_ip", "unknown"),
            "Identity": evidence.get("identity", "unknown"),
            "Operation": evidence.get("operation", "unknown"),
            "Result": evidence.get("result", "unknown"),
            "Exception": exception_note,
            "Revoked": f"{len(revoked)} active exception(s)",
            "Containment": containment_status,
            "ContainmentDetail": containment_detail,
            "Manual": (
                "Contain access, review audit logs, rotate secrets/keys if exposed, "
                "validate IAM and service principals."
            ),
        },
    )
    logging.critical(
        "[INCIDENT] %s on %s. Evidence=%s. %s",
        issue["name"],
        resource_name,
        evidence,
        exception_note,
    )
