from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
import logging
import os
from dotenv import load_dotenv
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