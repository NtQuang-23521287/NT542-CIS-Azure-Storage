# ─────────────────────────────────────────────────────────────────────────────
# outputs.tf
# ─────────────────────────────────────────────────────────────────────────────

output "resource_group_name" {
  description = "Name of the resource group"
  value       = data.azurerm_resource_group.rg.name
}

output "vnet_id" {
  description = "Resource ID of the Virtual Network"
  value       = azurerm_virtual_network.vnet.id
}

output "vnet_name" {
  description = "Name of the Virtual Network"
  value       = azurerm_virtual_network.vnet.name
}

output "subnet_gateway_id" {
  description = "Resource ID of GatewaySubnet"
  value       = azurerm_subnet.gateway.id
}

output "subnet_management_id" {
  description = "Resource ID of ManagementSubnet"
  value       = azurerm_subnet.management.id
}

output "subnet_private_endpoint_id" {
  description = "Resource ID of PrivateEndpointSubnet"
  value       = azurerm_subnet.private_endpoint.id
}

output "vpn_gateway_name" {
  description = "Name of the Point-to-Site VPN Gateway"
  value       = azurerm_virtual_network_gateway.vpn_gateway.name
}

output "vpn_gateway_public_ip" {
  description = "Public IP address used by the Point-to-Site VPN Gateway"
  value       = azurerm_public_ip.vpn_gateway_pip.ip_address
}

output "vpn_client_address_space" {
  description = "Address pool assigned to Point-to-Site VPN clients"
  value       = azurerm_virtual_network_gateway.vpn_gateway.vpn_client_configuration[0].address_space
}

output "storage_account_id" {
  description = "Resource ID of the Storage Account"
  value       = azurerm_storage_account.sa.id
}

output "storage_account_name" {
  description = "Name of the Storage Account"
  value       = azurerm_storage_account.sa.name
}

output "storage_primary_blob_endpoint" {
  description = "Primary blob endpoint (resolves via Private DNS inside VNet)"
  value       = azurerm_storage_account.sa.primary_blob_endpoint
}

output "private_endpoint_ip" {
  description = "Private IP assigned to the Blob Private Endpoint NIC"
  value       = azurerm_private_endpoint.blob_pe.private_service_connection[0].private_ip_address
}

output "private_dns_zone_name" {
  description = "Private DNS Zone for blob storage"
  value       = azurerm_private_dns_zone.blob.name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.law.id
}

output "log_analytics_workspace_customer_id" {
  description = "Workspace GUID used by the Azure Monitor Logs Query SDK"
  value       = azurerm_log_analytics_workspace.law.workspace_id
}

output "log_analytics_workspace_key" {
  description = "Primary shared key for the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.law.primary_shared_key
  sensitive   = true
}

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.kv.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.kv.vault_uri
}

output "key_vault_private_endpoint_ip" {
  description = "Private IP assigned to the Key Vault Private Endpoint NIC"
  value       = azurerm_private_endpoint.key_vault_pe.private_service_connection[0].private_ip_address
}

output "sql_server_name" {
  description = "Name of the Azure SQL logical server"
  value       = azurerm_mssql_server.sql.name
}

output "sql_database_name" {
  description = "Name of the Azure SQL Database"
  value       = azurerm_mssql_database.sqldb.name
}

output "sql_private_endpoint_ip" {
  description = "Private IP assigned to the SQL Private Endpoint NIC"
  value       = azurerm_private_endpoint.sql_pe.private_service_connection[0].private_ip_address
}

output "jumpbox_vm_name" {
  description = "Name of the private management VM"
  value       = azurerm_linux_virtual_machine.jumpbox.name
}

output "jumpbox_private_ip" {
  description = "Private IP of the management VM. Connect after Point-to-Site VPN is up."
  value       = azurerm_network_interface.jumpbox_nic.private_ip_address
}

output "jumpbox_admin_username" {
  description = "Administrator username for the private management VM"
  value       = azurerm_linux_virtual_machine.jumpbox.admin_username
}

output "sql_admin_password" {
  description = "Generated SQL admin password"
  value       = random_password.sql_admin.result
  sensitive   = true
}
