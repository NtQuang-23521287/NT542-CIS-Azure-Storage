"""
main.py - Compliance monitoring loop for Azure Storage, Key Vault, and SQL.

Checks run every CHECK_INTERVAL seconds.
CRITICAL issues produce a remediation plan by default.
Azure mutation requires explicit operator opt-in through configuration.
WARNING issues require admin confirmation or manual follow-up.
"""

import logging
import os
import time

from admin_listener import start_admin_listener
from collector import (
    collect_key_vault_config,
    collect_key_vault_security_signals,
    collect_sql_config,
    collect_sql_security_signals,
    collect_storage_account_config,
    collect_storage_security_signals,
    initialize_azure_clients,
)
from config import (
    ALLOW_AZURE_MUTATIONS,
    CHECK_INTERVAL,
    COMPLIANCE_LOG_FILE,
    KEY_VAULT_NAME,
    LOG_DIR,
    RESOURCE_GROUP,
    SQL_SERVER_NAME,
    STORAGE_ACCOUNT_NAME,
)
from evaluator import evaluate_config, evaluate_key_vault_config, evaluate_sql_config
from incident_evaluator import (
    evaluate_key_vault_incidents,
    evaluate_sql_incidents,
    evaluate_storage_incidents,
)
from remediation import remediate_config

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=COMPLIANCE_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

EXPECTED_STORAGE_CONFIG = {
    "https_only": True,
    "min_tls_version": "TLS1_2",
    "public_network_access": "Disabled",
    "versioning_enabled": True,
}

EXPECTED_KEY_VAULT_CONFIG = {
    "public_network_access": "Disabled",
    "enable_rbac_authorization": True,
    "enable_purge_protection": True,
    "enable_soft_delete": True,
    "private_endpoint_enabled": True,
    "keys_have_expiry": True,
    "secrets_have_expiry": True,
}

EXPECTED_SQL_CONFIG = {
    "auditing_enabled": True,
    "defender_enabled": True,
    "min_tls_version": "1.2",
    "public_network_access": "Disabled",
    "private_endpoint_enabled": True,
    "azure_ad_admin_configured": True,
}


def monitor():
    _, storage_client = initialize_azure_clients()
    start_admin_listener()

    print(f"{BOLD}=== Azure Compliance Monitor ==={RESET}")
    print(f"  Resource Group  : {RESOURCE_GROUP}")
    print(f"  Storage Account : {STORAGE_ACCOUNT_NAME}")
    print(f"  Key Vault       : {KEY_VAULT_NAME}")
    print(f"  SQL Server      : {SQL_SERVER_NAME}")
    print(f"  Check interval  : {CHECK_INTERVAL}s\n")
    print(
        "  Azure mutations : "
        f"{'ENABLED (temporary P0 opt-in)' if ALLOW_AZURE_MUTATIONS else 'DISABLED (plan-only)'}\n"
    )
    logging.info("=== Compliance Monitor started ===")

    while True:
        checks = [
            (
                "Storage Account",
                STORAGE_ACCOUNT_NAME,
                lambda: collect_storage_account_config(
                    storage_client, RESOURCE_GROUP, STORAGE_ACCOUNT_NAME
                ),
                lambda config: evaluate_config(config, EXPECTED_STORAGE_CONFIG),
                lambda: collect_storage_security_signals(
                    RESOURCE_GROUP, STORAGE_ACCOUNT_NAME
                ),
                evaluate_storage_incidents,
            ),
            (
                "Key Vault",
                KEY_VAULT_NAME,
                lambda: collect_key_vault_config(RESOURCE_GROUP, KEY_VAULT_NAME),
                lambda config: evaluate_key_vault_config(
                    config, EXPECTED_KEY_VAULT_CONFIG
                ),
                lambda: collect_key_vault_security_signals(
                    RESOURCE_GROUP, KEY_VAULT_NAME
                ),
                evaluate_key_vault_incidents,
            ),
            (
                "SQL Server",
                SQL_SERVER_NAME,
                lambda: collect_sql_config(RESOURCE_GROUP, SQL_SERVER_NAME),
                lambda config: evaluate_sql_config(config, EXPECTED_SQL_CONFIG),
                lambda: collect_sql_security_signals(RESOURCE_GROUP, SQL_SERVER_NAME),
                evaluate_sql_incidents,
            ),
        ]

        for (
            service_name,
            resource_name,
            collect,
            evaluate,
            collect_signals,
            evaluate_incidents,
        ) in checks:
            logging.info("Checking %s %s", service_name, resource_name)

            try:
                current_config = collect()
                drift_detected, issues = evaluate(current_config)
                incident_detected, incident_issues = evaluate_incidents(
                    collect_signals()
                )
                all_issues = issues + incident_issues

                if drift_detected or incident_detected:
                    issue_names = [issue["name"] for issue in all_issues]
                    logging.warning(
                        "Issues detected on %s %s: %s",
                        service_name,
                        resource_name,
                        ", ".join(issue_names),
                    )
                    remediate_config(
                        RESOURCE_GROUP,
                        resource_name,
                        all_issues,
                        allow_mutation=ALLOW_AZURE_MUTATIONS,
                    )
                else:
                    msg = f"{service_name} {resource_name} is compliant."
                    print(f"{GREEN}{msg}{RESET}")
                    logging.info(msg)

            except Exception as exc:
                logging.error(
                    "Error while monitoring %s %s: %s",
                    service_name,
                    resource_name,
                    exc,
                    exc_info=True,
                )
                print(f"\033[91m[ERROR] {service_name} {resource_name}: {exc}\033[0m")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    monitor()
