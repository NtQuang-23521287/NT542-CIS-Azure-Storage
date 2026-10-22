"""
Compare collected resource configuration against the expected baseline.

Severity model:
  WARNING            -> log/report or admin review
  CRITICAL           -> auto-remediate unless an active exception exists
  ESCALATED_CRITICAL -> security incident response
"""

WARNING = "WARNING"
CRITICAL = "CRITICAL"
ESCALATED_CRITICAL = "ESCALATED_CRITICAL"


SEVERITY = {
    "HTTPS traffic only setting mismatch": CRITICAL,
    "Minimum TLS version mismatch": CRITICAL,
    "Public Network Access mismatch": CRITICAL,
    "Blob versioning disabled": WARNING,
    "Key Vault keys missing expiry date": WARNING,
    "Key Vault secrets missing expiry date": WARNING,
    "Key Vault recoverability mismatch": CRITICAL,
    "Key Vault RBAC authorization disabled": CRITICAL,
    "Key Vault Private Endpoint missing": CRITICAL,
    "Key Vault Public Network Access mismatch": CRITICAL,
    "SQL auditing disabled": CRITICAL,
    "Microsoft Defender for SQL disabled": CRITICAL,
    "SQL Minimum TLS version mismatch": CRITICAL,
    "SQL Public Network Access mismatch": CRITICAL,
    "SQL Private Endpoint missing": CRITICAL,
    "SQL Azure AD admin missing": WARNING,
    "Storage sensitive access from untrusted source": ESCALATED_CRITICAL,
    "Key Vault secret access from untrusted source": ESCALATED_CRITICAL,
    "SQL suspicious successful login": ESCALATED_CRITICAL,
}

STORAGE_FIELDS = {
    "https_only",
    "min_tls_version",
    "public_network_access",
    "versioning_enabled",
}
KEY_VAULT_FIELDS = {
    "public_network_access",
    "enable_rbac_authorization",
    "enable_soft_delete",
    "enable_purge_protection",
    "private_endpoint_enabled",
    "keys_have_expiry",
    "secrets_have_expiry",
}
SQL_FIELDS = {
    "auditing_enabled",
    "defender_enabled",
    "min_tls_version",
    "public_network_access",
    "private_endpoint_enabled",
    "azure_ad_admin_configured",
}


def _validate_config(actual: dict, expected: dict, fields: set[str]) -> None:
    for label, config in (("actual", actual), ("expected", expected)):
        if not isinstance(config, dict):
            raise TypeError(f"{label} configuration keys must be a dictionary")
        missing = fields - config.keys()
        unknown = config.keys() - fields
        if missing or unknown:
            raise ValueError(
                f"{label} configuration keys invalid: "
                f"missing={sorted(missing)}, unknown={sorted(unknown)}"
            )


def _add_issue(issues: list[dict], name: str, service: str | None = None) -> None:
    issue = {
        "name": name,
        "severity": SEVERITY.get(name, WARNING),
    }
    if service:
        issue["service"] = service
    issues.append(issue)


def evaluate_config(actual_config: dict, expected_config: dict):
    """Evaluate Storage Account baseline drift."""
    _validate_config(actual_config, expected_config, STORAGE_FIELDS)
    issues = []

    if actual_config["https_only"] != expected_config["https_only"]:
        _add_issue(issues, "HTTPS traffic only setting mismatch", "storage")

    if actual_config["min_tls_version"] != expected_config["min_tls_version"]:
        _add_issue(issues, "Minimum TLS version mismatch", "storage")

    if (
        actual_config["public_network_access"]
        != expected_config["public_network_access"]
    ):
        _add_issue(issues, "Public Network Access mismatch", "storage")

    if actual_config.get("versioning_enabled") != expected_config.get(
        "versioning_enabled"
    ):
        _add_issue(issues, "Blob versioning disabled", "storage")

    return bool(issues), issues


def evaluate_key_vault_config(actual_config: dict, expected_config: dict):
    """Evaluate Key Vault baseline drift."""
    _validate_config(actual_config, expected_config, KEY_VAULT_FIELDS)
    issues = []

    if (
        actual_config["public_network_access"]
        != expected_config["public_network_access"]
    ):
        _add_issue(issues, "Key Vault Public Network Access mismatch", "key_vault")

    if (
        actual_config["enable_rbac_authorization"]
        != expected_config["enable_rbac_authorization"]
    ):
        _add_issue(issues, "Key Vault RBAC authorization disabled", "key_vault")

    if (
        actual_config["enable_soft_delete"] != expected_config["enable_soft_delete"]
        or actual_config["enable_purge_protection"]
        != expected_config["enable_purge_protection"]
    ):
        _add_issue(issues, "Key Vault recoverability mismatch", "key_vault")

    if (
        actual_config["private_endpoint_enabled"]
        != expected_config["private_endpoint_enabled"]
    ):
        _add_issue(issues, "Key Vault Private Endpoint missing", "key_vault")

    if actual_config["keys_have_expiry"] != expected_config["keys_have_expiry"]:
        _add_issue(issues, "Key Vault keys missing expiry date", "key_vault")

    if actual_config["secrets_have_expiry"] != expected_config["secrets_have_expiry"]:
        _add_issue(issues, "Key Vault secrets missing expiry date", "key_vault")

    return bool(issues), issues


def evaluate_sql_config(actual_config: dict, expected_config: dict):
    """Evaluate Azure SQL baseline drift."""
    _validate_config(actual_config, expected_config, SQL_FIELDS)
    issues = []

    if actual_config["auditing_enabled"] != expected_config["auditing_enabled"]:
        _add_issue(issues, "SQL auditing disabled", "sql")

    if actual_config["defender_enabled"] != expected_config["defender_enabled"]:
        _add_issue(issues, "Microsoft Defender for SQL disabled", "sql")

    if actual_config["min_tls_version"] != expected_config["min_tls_version"]:
        _add_issue(issues, "SQL Minimum TLS version mismatch", "sql")

    if (
        actual_config["public_network_access"]
        != expected_config["public_network_access"]
    ):
        _add_issue(issues, "SQL Public Network Access mismatch", "sql")

    if (
        actual_config["private_endpoint_enabled"]
        != expected_config["private_endpoint_enabled"]
    ):
        _add_issue(issues, "SQL Private Endpoint missing", "sql")

    if (
        actual_config["azure_ad_admin_configured"]
        != expected_config["azure_ad_admin_configured"]
    ):
        _add_issue(issues, "SQL Azure AD admin missing", "sql")

    return bool(issues), issues
