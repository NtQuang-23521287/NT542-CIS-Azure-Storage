# ─────────────────────────────────────────────────────────────────────────────
# monitoring.tf  –  Log Analytics Workspace + Diagnostic Settings
# ─────────────────────────────────────────────────────────────────────────────

# ── Log Analytics Workspace ───────────────────────────────────────────────────
resource "azurerm_log_analytics_workspace" "law" {
  name                = "${var.project}-law"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

# ── Diagnostic: Storage Account → Log Analytics ───────────────────────────────
resource "azurerm_monitor_diagnostic_setting" "storage_diag" {
  name                       = "${var.project}-storage-diag"
  target_resource_id         = "${azurerm_storage_account.sa.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

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

# ── Diagnostic: VNet → Log Analytics ─────────────────────────────────────────
resource "azurerm_monitor_diagnostic_setting" "vnet_diag" {
  name                       = "${var.project}-vnet-diag"
  target_resource_id         = azurerm_virtual_network.vnet.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "VMProtectionAlerts"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
