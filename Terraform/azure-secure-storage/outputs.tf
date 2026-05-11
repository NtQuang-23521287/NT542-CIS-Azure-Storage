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

output "vpn_gateway_id" {
  description = "Resource ID of the VPN Gateway"
  value       = azurerm_virtual_network_gateway.vpn.id
}

output "vpn_gateway_public_ip" {
  description = "Public IP address assigned to the VPN Gateway"
  value       = azurerm_public_ip.vpn_gateway.ip_address
}

output "management_vm_id" {
  description = "Resource ID of the management Linux VM"
  value       = azurerm_linux_virtual_machine.management.id
}

output "management_vm_private_ip" {
  description = "Private IP address of the management Linux VM"
  value       = azurerm_network_interface.management_vm.private_ip_address
}

output "management_vm_public_ip" {
  description = "Public IP address of the management Linux VM"
  value       = azurerm_public_ip.management_vm.ip_address
}

output "management_vm_ssh_command" {
  description = "SSH command for the management Linux VM"
  value       = "ssh ${var.vm_admin_username}@${azurerm_public_ip.management_vm.ip_address}"
}

output "deployment_complete_summary" {
  description = "Summary printed after Terraform finishes creating the lab resources"
  value = {
    status                    = "Deployment complete"
    resource_group            = data.azurerm_resource_group.rg.name
    vpn_gateway_name          = azurerm_virtual_network_gateway.vpn.name
    vpn_gateway_public_ip     = azurerm_public_ip.vpn_gateway.ip_address
    management_vm_name        = azurerm_linux_virtual_machine.management.name
    management_vm_private_ip  = azurerm_network_interface.management_vm.private_ip_address
    management_vm_public_ip   = azurerm_public_ip.management_vm.ip_address
    management_vm_ssh_command = "ssh ${var.vm_admin_username}@${azurerm_public_ip.management_vm.ip_address}"
    storage_account_name      = azurerm_storage_account.sa.name
    private_endpoint_ip       = azurerm_private_endpoint.blob_pe.private_service_connection[0].private_ip_address
  }
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

output "log_analytics_workspace_key" {
  description = "Primary shared key for the Log Analytics Workspace"
  value       = azurerm_log_analytics_workspace.law.primary_shared_key
  sensitive   = true
}
