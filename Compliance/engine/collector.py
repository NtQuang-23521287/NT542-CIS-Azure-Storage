from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
import logging
import os
import json
from dotenv import load_dotenv
from azure_cli import display_az_command, run_az
from config import SECURITY_SIGNALS_FILE
load_dotenv()


def initialize_azure_clients():
    tenant_id     = os.getenv("AZURE_TENANT_ID")
    client_id     = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    resource_client = ResourceManagementClient(credential, os.getenv("AZURE_SUBSCRIPTION_ID"))
    storage_client  = StorageManagementClient(credential, os.getenv("AZURE_SUBSCRIPTION_ID"))

    return resource_client, storage_client


def collect_storage_account_config(storage_client, resource_group, storage_account_name):
    """Thu thập cấu hình storage account và blob service properties."""

    # Thông tin cơ bản của storage account
    storage_account = storage_client.storage_accounts.get_properties(
        resource_group, storage_account_name
    )

    # Thông tin blob service (versioning, soft-delete, ...)
    blob_props = storage_client.blob_services.get_service_properties(
        resource_group, storage_account_name
    )

    versioning_enabled = False
    if blob_props.is_versioning_enabled is not None:
        versioning_enabled = blob_props.is_versioning_enabled

    config = {
        # ── Account-level ──────────────────────────────────────────────────
        "https_only":            storage_account.enable_https_traffic_only,
        "min_tls_version":       storage_account.minimum_tls_version,
        "public_network_access": storage_account.public_network_access,

        # ── Blob-service-level ─────────────────────────────────────────────
        "versioning_enabled":    versioning_enabled,
    }

    return config


def _run_az_json(args: list[str]):
    """Run an Azure CLI command and parse its JSON output."""
    command = [*args, "--output", "json"]
    logging.info("[COLLECTOR] Running Azure CLI: %s", display_az_command(command))
    result = run_az(command)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout.lstrip("\ufeff \t\r\n"))


def _has_private_endpoint(resource_group: str, resource_name: str, resource_type: str) -> bool:
    connections = _run_az_json([
        "network",
        "private-endpoint-connection",
        "list",
        "--resource-group",
        resource_group,
        "--name",
        resource_name,
        "--type",
        resource_type,
    ])
    for conn in connections or []:
        state = conn.get("privateLinkServiceConnectionState") or (
            conn.get("properties", {}).get("privateLinkServiceConnectionState")
        ) or {}
        if str(state.get("status", "")).lower() == "approved":
            return True

    # Some Azure CLI resource providers return incomplete connection objects.
    # Fall back to scanning Private Endpoints in the resource group and matching
    # the target private link service ID.
    private_endpoints = _run_az_json([
        "network",
        "private-endpoint",
        "list",
        "--resource-group",
        resource_group,
    ])
    target_fragment = f"/providers/{resource_type}/{resource_name}".lower()

    for private_endpoint in private_endpoints or []:
        connections = (
            private_endpoint.get("privateLinkServiceConnections")
            or private_endpoint.get("properties", {}).get("privateLinkServiceConnections")
            or []
        )
        for connection in connections:
            properties = connection.get("properties", connection)
            service_id = str(properties.get("privateLinkServiceId", "")).lower()
            state = properties.get("privateLinkServiceConnectionState") or {}
            if target_fragment in service_id and str(state.get("status", "")).lower() == "approved":
                return True
    return False


def collect_key_vault_config(resource_group: str, key_vault_name: str):
    """Collect Key Vault settings required by the CIS checks."""
    vault = _run_az_json([
        "keyvault",
        "show",
        "--resource-group",
        resource_group,
        "--name",
        key_vault_name,
    ])
    keys = _run_az_json(["keyvault", "key", "list", "--vault-name", key_vault_name])
    secrets = _run_az_json(["keyvault", "secret", "list", "--vault-name", key_vault_name])

    return {
        "public_network_access": vault.get("properties", {}).get("publicNetworkAccess"),
        "enable_rbac_authorization": vault.get("properties", {}).get("enableRbacAuthorization"),
        "enable_purge_protection": vault.get("properties", {}).get("enablePurgeProtection"),
        "enable_soft_delete": vault.get("properties", {}).get("enableSoftDelete"),
        "private_endpoint_enabled": _has_private_endpoint(
            resource_group,
            key_vault_name,
            "Microsoft.KeyVault/vaults",
        ),
        "keys_have_expiry": all((item.get("attributes") or {}).get("expires") for item in keys or []),
        "secrets_have_expiry": all((item.get("attributes") or {}).get("expires") for item in secrets or []),
    }


def collect_sql_config(resource_group: str, sql_server_name: str):
    """Collect Azure SQL Server settings required by the CIS checks."""
    server = _run_az_json([
        "sql",
        "server",
        "show",
        "--resource-group",
        resource_group,
        "--name",
        sql_server_name,
    ])
    auditing = _run_az_json([
        "sql",
        "server",
        "audit-policy",
        "show",
        "--resource-group",
        resource_group,
        "--name",
        sql_server_name,
    ])
    ad_admins = _run_az_json([
        "sql",
        "server",
        "ad-admin",
        "list",
        "--resource-group",
        resource_group,
        "--server",
        sql_server_name,
    ])
    defender = _run_az_json(["security", "pricing", "show", "--name", "SqlServers"])

    return {
        "auditing_enabled": auditing.get("state") == "Enabled",
        "defender_enabled": defender.get("pricingTier") == "Standard",
        "min_tls_version": server.get("minimalTlsVersion"),
        "public_network_access": server.get("publicNetworkAccess"),
        "private_endpoint_enabled": _has_private_endpoint(
            resource_group,
            sql_server_name,
            "Microsoft.Sql/servers",
        ),
        "azure_ad_admin_configured": bool(ad_admins),
    }


def _load_security_signals() -> dict:
    if not os.path.exists(SECURITY_SIGNALS_FILE):
        return {}
    with open(SECURITY_SIGNALS_FILE, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def collect_storage_security_signals(resource_group: str, storage_account_name: str) -> list[dict]:
    """Read optional Storage incident signals from Compliance/data/security_signals.json."""
    signals = _load_security_signals()
    return signals.get("storage", {}).get(storage_account_name, [])


def collect_key_vault_security_signals(resource_group: str, key_vault_name: str) -> list[dict]:
    """Read optional Key Vault incident signals from Compliance/data/security_signals.json."""
    signals = _load_security_signals()
    return signals.get("key_vault", {}).get(key_vault_name, [])


def collect_sql_security_signals(resource_group: str, sql_server_name: str) -> list[dict]:
    """Read optional SQL incident signals from Compliance/data/security_signals.json."""
    signals = _load_security_signals()
    return signals.get("sql", {}).get(sql_server_name, [])
