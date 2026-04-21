from typing import Any

def _get(data: dict, *keys, default=None) -> Any:
    """Helper lấy nested key an toàn."""
    for key in keys:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
        if data is None:
            return default
    return data


def _make_result(
    *,
    control_id: str,
    title: str,
    status: str,
    actual: Any,
    expected: Any,
    remediation: str,
    command_args: list[str] | None = None,
    requires_recreate: bool = False,
) -> dict:
    result = {
        "control_id": control_id,
        "title": title,
        "status": status,
        "actual": actual,
        "expected": expected,
        "remediation": remediation,
    }
    if command_args:
        result["remediation_spec"] = {
            "description": remediation,
            "command_args": command_args,
            "requires_recreate": requires_recreate,
        }
    return result

def check_https_only(entry: dict) -> dict:
    """CIS 3.1 — Secure transfer (HTTPS only)."""
    val = _get(entry, "account", "supportsHttpsTrafficOnly")
    if val is None:
        val = _get(entry, "account", "enableHttpsTrafficOnly")
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.1",
        title="Storage Account phải bật HTTPS only",
        status="PASS" if val is True else "FAIL",
        actual=val,
        expected=True,
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --https-only true"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--https-only", "true",
        ],
    )

def check_tls_version(entry: dict) -> dict:
    """CIS 3.2 — Minimum TLS version >= 1.2."""
    val = _get(entry, "account", "minimumTlsVersion")
    passed = val in ("TLS1_2",)
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.2",
        title="TLS version tối thiểu phải là 1.2",
        status="PASS" if passed else "FAIL",
        actual=val,
        expected="TLS1_2",
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --min-tls-version TLS1_2"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--min-tls-version", "TLS1_2",
        ],
    )

def check_public_network_access(entry: dict) -> dict:
    """CIS 3.3 — Public network access disabled."""
    val = _get(entry, "account", "publicNetworkAccess")
    passed = val == "Disabled"
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.3",
        title="Public network access phải bị tắt",
        status="PASS" if passed else "FAIL",
        actual=val,
        expected="Disabled",
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --public-network-access Disabled"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--public-network-access", "Disabled",
        ],
    )

def check_default_network_deny(entry: dict) -> dict:
    """CIS 3.4 — Default network rule phải là Deny."""
    val = _get(entry, "account", "networkRuleSet", "defaultAction")
    passed = val == "Deny"
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.4",
        title="Network ACL default action phải là Deny",
        status="PASS" if passed else "FAIL",
        actual=val,
        expected="Deny",
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --default-action Deny"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--default-action", "Deny",
        ],
    )

def check_blob_anonymous_access(entry: dict) -> dict:
    """CIS 3.5 — Blob anonymous access disabled."""
    val = _get(entry, "account", "allowBlobPublicAccess")
    passed = val is False
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.5",
        title="Blob anonymous access phải bị tắt",
        status="PASS" if passed else "FAIL",
        actual=val,
        expected=False,
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --allow-blob-public-access false"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--allow-blob-public-access", "false",
        ],
    )

def check_soft_delete_blob(entry: dict) -> dict:
    """CIS 3.8 — Soft delete cho blob enabled >= 7 ngày."""
    enabled = _get(entry, "blob_service", "deleteRetentionPolicy", "enabled")
    days = _get(entry, "blob_service", "deleteRetentionPolicy", "days", default=0)
    passed = enabled is True and isinstance(days, int) and days >= 7
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.8",
        title="Blob soft delete phải bật và giữ >= 7 ngày",
        status="PASS" if passed else "FAIL",
        actual={"enabled": enabled, "days": days},
        expected={"enabled": True, "days": ">=7"},
        remediation=(
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> "
            "--enable-delete-retention true --delete-retention-days 7"
        ),
        command_args=[
            "storage", "account", "blob-service-properties", "update",
            "--account-name", account_name,
            "--resource-group", resource_group,
            "--enable-delete-retention", "true",
            "--delete-retention-days", "7",
        ],
    )

def check_soft_delete_container(entry: dict) -> dict:
    """CIS 3.9 — Soft delete cho container enabled >= 7 ngày."""
    enabled = _get(entry, "blob_service", "containerDeleteRetentionPolicy", "enabled")
    days = _get(entry, "blob_service", "containerDeleteRetentionPolicy", "days", default=0)
    passed = enabled is True and isinstance(days, int) and days >= 7
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.9",
        title="Container soft delete phải bật và giữ >= 7 ngày",
        status="PASS" if passed else "FAIL",
        actual={"enabled": enabled, "days": days},
        expected={"enabled": True, "days": ">=7"},
        remediation=(
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> "
            "--enable-container-delete-retention true --container-delete-retention-days 7"
        ),
        command_args=[
            "storage", "account", "blob-service-properties", "update",
            "--account-name", account_name,
            "--resource-group", resource_group,
            "--enable-container-delete-retention", "true",
            "--container-delete-retention-days", "7",
        ],
    )

def check_versioning(entry: dict) -> dict:
    """CIS 3.10 — Blob versioning enabled."""
    val = _get(entry, "blob_service", "isVersioningEnabled")
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.10",
        title="Blob versioning phải được bật",
        status="PASS" if val is True else "FAIL",
        actual=val,
        expected=True,
        remediation=(
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> --enable-versioning true"
        ),
        command_args=[
            "storage", "account", "blob-service-properties", "update",
            "--account-name", account_name,
            "--resource-group", resource_group,
            "--enable-versioning", "true",
        ],
    )

def check_infrastructure_encryption(entry: dict) -> dict:
    """CIS 3.11 — Infrastructure encryption enabled."""
    val = _get(entry, "account", "encryption", "requireInfrastructureEncryption")
    return _make_result(
        control_id="CIS-3.11",
        title="Infrastructure encryption phải được bật",
        status="PASS" if val is True else "FAIL",
        actual=val,
        expected=True,
        remediation=(
            "Không thể bật sau khi tạo — phải tạo lại storage account "
            "với infrastructure_encryption_enabled = true trong Terraform"
        ),
        requires_recreate=True,
    )

def check_cross_tenant_replication(entry: dict) -> dict:
    """CIS 3.12 — Cross-tenant replication disabled."""
    val = _get(entry, "account", "allowCrossTenantReplication")
    passed = val is False
    account_name = entry.get("name", "unknown")
    resource_group = entry.get("resource_group", "NT542-Group08")
    return _make_result(
        control_id="CIS-3.12",
        title="Cross-tenant replication phải bị tắt",
        status="PASS" if passed else "FAIL",
        actual=val,
        expected=False,
        remediation=(
            "az storage account update "
            "--name <account> --resource-group <rg> --allow-cross-tenant-replication false"
        ),
        command_args=[
            "storage", "account", "update",
            "--name", account_name,
            "--resource-group", resource_group,
            "--allow-cross-tenant-replication", "false",
        ],
    )

ALL_RULES = [
    check_https_only,
    check_tls_version,
    check_public_network_access,
    check_default_network_deny,
    check_blob_anonymous_access,
    check_soft_delete_blob,
    check_soft_delete_container,
    check_versioning,
    check_infrastructure_encryption,
    check_cross_tenant_replication,
]
