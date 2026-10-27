output "resource_group_name" {
  value = azurerm_resource_group.demo.name
}

output "storage_account_name" {
  value = azurerm_storage_account.demo.name
}

output "storage_account_id" {
  value = azurerm_storage_account.demo.id
}

output "log_analytics_workspace_customer_id" {
  value = azurerm_log_analytics_workspace.demo.workspace_id
}
