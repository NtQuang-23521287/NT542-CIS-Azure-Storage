# ─────────────────────────────────────────────────────────────────────────────
# storage.tf  –  Storage Account (HTTPS-only, TLS 1.2+, public access off)
# ─────────────────────────────────────────────────────────────────────────────

resource "azurerm_storage_account" "sa" {
  name                = var.storage_account_name
  resource_group_name = data.azurerm_resource_group.rg.name
  location            = var.location

  account_tier             = var.storage_tier        # "Standard"
  account_replication_type = var.storage_replication # "LRS"
  account_kind             = "StorageV2"

  # ── Security requirements ──────────────────────────────────────────────────
  # CIS Azure 3.1  – require HTTPS
  https_traffic_only_enabled = true

  # CIS Azure 3.2  – minimum TLS version
  min_tls_version = "TLS1_2"

  # CIS Azure 3.5  – disable public blob access
  allow_nested_items_to_be_public = false

  # Disable public network access entirely; traffic flows via Private Endpoint
  public_network_access_enabled = false

  # Shared Key auth can be disabled for stricter AAD-only access (optional)
  shared_access_key_enabled = true

  # ── Blob soft-delete (best practice) ──────────────────────────────────────
  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  # ── Network rules: deny all; Private Endpoint is the only entry point ──────
  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    ip_rules                   = []
    virtual_network_subnet_ids = []
  }

  tags = var.tags
}
