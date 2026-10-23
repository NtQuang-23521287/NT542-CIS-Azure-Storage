"""
Handle compliance issues by severity.

WARNING:
  Log/report for admin review.
CRITICAL:
  Produce a plan. Execution belongs to the new exact-plan CLI workflow.
ESCALATED_CRITICAL:
  Trigger incident response. Azure containment is plan-only by default.
"""

import logging

from audit_logger import log_compliance_event, log_exception_event
from azure_cli import display_az_command
from exception_manager import find_active_exception, remaining_minutes
from incident_response import handle_incident

REMEDIATION_COMMANDS = {
    "HTTPS traffic only setting mismatch": (
        "storage",
        "account",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--https-only",
        "true",
    ),
    "Minimum TLS version mismatch": (
        "storage",
        "account",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--minimum-tls-version",
        "TLS1_2",
    ),
    "Public Network Access mismatch": (
        "storage",
        "account",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--public-network-access",
        "Disabled",
    ),
    "Blob versioning disabled": (
        "storage",
        "account",
        "blob-service-properties",
        "update",
        "--account-name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--enable-versioning",
        "true",
    ),
    "Key Vault Public Network Access mismatch": (
        "keyvault",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--public-network-access",
        "Disabled",
    ),
    "Key Vault RBAC authorization disabled": (
        "keyvault",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--enable-rbac-authorization",
        "true",
    ),
    "Key Vault recoverability mismatch": (
        "keyvault",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--enable-purge-protection",
        "true",
    ),
    "SQL auditing disabled": (
        "sql",
        "server",
        "audit-policy",
        "update",
        "--resource-group",
        "{rg}",
        "--name",
        "{account}",
        "--state",
        "Enabled",
    ),
    "SQL Minimum TLS version mismatch": (
        "sql",
        "server",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--minimal-tls-version",
        "1.2",
    ),
    "SQL Public Network Access mismatch": (
        "sql",
        "server",
        "update",
        "--name",
        "{account}",
        "--resource-group",
        "{rg}",
        "--enable-public-network",
        "false",
    ),
}

MANUAL_ONLY_REMEDIATIONS = {
    "Microsoft Defender for SQL disabled": (
        "Enabling Defender changes subscription-level pricing and requires explicit cost approval."
    ),
}


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _render_args(
    template: tuple[str, ...], resource_group: str, resource_name: str
) -> list[str]:
    return [part.format(account=resource_name, rg=resource_group) for part in template]


def _run_command(args: list[str], issue_name: str, resource_name: str) -> bool:
    raise RuntimeError(
        "Legacy remediation execution is disabled; use acg remediation apply"
    )


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


def _handle_critical(
    resource_group: str,
    resource_name: str,
    issue: dict,
    allow_mutation: bool,
) -> None:
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

    manual_reason = MANUAL_ONLY_REMEDIATIONS.get(name)
    if manual_reason:
        print(f"{YELLOW}Manual remediation required: {name}. {manual_reason}{RESET}")
        logging.warning("[REMEDIATION] Manual-only: %s. %s", name, manual_reason)
        log_compliance_event(
            "MANUAL_REMEDIATION_REQUIRED",
            {
                "Resource": resource_name,
                "Issue": name,
                "Action": "MANUAL_ONLY",
                "Reason": manual_reason,
            },
        )
        return

    command_template = REMEDIATION_COMMANDS.get(name)
    if not command_template:
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

    args = _render_args(command_template, resource_group, resource_name)
    command = display_az_command(args)
    print(
        f"\n{YELLOW}{BOLD}[CRITICAL] Legacy remediation suggestion{RESET}\n"
        f"  Resource : {resource_name} ({resource_group})\n"
        f"  Issue    : {name}\n"
        f"  Suggested: {command}\n"
        "  Action   : not executed; create an exact plan with acg remediation plan\n"
    )
    logging.warning(
        "[CRITICAL] Legacy plan-only remediation for %s on %s", name, resource_name
    )
    log_compliance_event(
        "REMEDIATION_PLAN_CREATED",
        {
            "Resource": resource_name,
            "Issue": name,
            "Action": "EXACT_PLAN_REQUIRED",
            "Command": command,
        },
    )


def remediate_config(
    resource_group: str,
    resource_name: str,
    issues: list[dict],
    allow_mutation: bool = False,
):
    for issue in issues:
        severity = issue["severity"]
        if severity == "WARNING":
            _handle_warning(resource_name, issue)
        elif severity == "CRITICAL":
            _handle_critical(resource_group, resource_name, issue, allow_mutation)
        elif severity == "ESCALATED_CRITICAL":
            handle_incident(
                resource_group,
                resource_name,
                issue,
                allow_mutation=allow_mutation,
            )
        else:
            logging.warning("Unknown severity %s for issue %s", severity, issue)
