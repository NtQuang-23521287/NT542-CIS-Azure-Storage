locals {
  tags = {
    Project     = "NT542"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "PhaseKMinimalDemo"
    Owner       = var.owner
    ExpiresOn   = var.expires_on
  }
}

resource "azurerm_resource_group" "demo" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.tags
}

resource "azurerm_storage_account" "demo" {
  name                              = var.storage_account_name
  resource_group_name               = azurerm_resource_group.demo.name
  location                          = azurerm_resource_group.demo.location
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  infrastructure_encryption_enabled = true
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  allow_nested_items_to_be_public   = false
  public_network_access_enabled     = false
  shared_access_key_enabled         = false

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
    versioning_enabled = true
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    ip_rules                   = []
    virtual_network_subnet_ids = []
  }

  tags = local.tags
}

resource "azurerm_log_analytics_workspace" "demo" {
  name                = "${var.resource_group_name}-law"
  location            = azurerm_resource_group.demo.location
  resource_group_name = azurerm_resource_group.demo.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

# Diagnostic settings do not support Azure resource tags.
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                           = "phase-k-blob-diag"
  target_resource_id             = "${azurerm_storage_account.demo.id}/blobServices/default"
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.demo.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
  metric {
    category = "Transaction"
    enabled  = true
  }
}
