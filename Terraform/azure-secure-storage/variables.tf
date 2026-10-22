variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "NT542-Group08_AUTO"
}

variable "location" {
  description = "Azure region to deploy resources"
  type        = string
  default     = "East US"
}

variable "project" {
  description = "Project prefix used for naming resources"
  type        = string
  default     = "nt542_auto"
}

variable "environment" {
  description = "Deployment environment (dev / staging / prod)"
  type        = string
  default     = "dev"
}

# ── Network ──────────────────────────────────────────────────────────────────

variable "vnet_address_space" {
  description = "Address space for the Virtual Network"
  type        = list(string)
  default     = ["10.1.0.0/16"]
}

variable "subnet_gateway" {
  description = "Address prefix for GatewaySubnet (must be named exactly 'GatewaySubnet')"
  type        = string
  default     = "10.1.1.0/27"
}

variable "subnet_management" {
  description = "Address prefix for ManagementSubnet"
  type        = string
  default     = "10.1.2.0/24"
}

variable "subnet_private_endpoint" {
  description = "Address prefix for PrivateEndpointSubnet"
  type        = string
  default     = "10.1.3.0/24"
}

# ── VPN Gateway ───────────────────────────────────────────────────────────────

variable "vpn_sku" {
  description = "SKU for the VPN Gateway. VpnGw1 is used for Point-to-Site OpenVPN support."
  type        = string
  default     = "VpnGw1"
}

variable "vpn_generation" {
  description = "VPN Gateway generation"
  type        = string
  default     = "Generation1"
}

variable "vpn_gateway_name" {
  description = "Name of the Point-to-Site VPN Gateway"
  type        = string
  default     = "nt542_auto-vpngw"
}

variable "vpn_gateway_public_ip_name" {
  description = "Name of the public IP assigned to the VPN Gateway"
  type        = string
  default     = "nt542_auto-vpngw-pip"
}

variable "vpn_gateway_public_ip_zones" {
  description = "Optional availability zones for the VPN Gateway public IP"
  type        = list(string)
  default     = []
}

variable "vpn_client_address_space" {
  description = "Address pool assigned to VPN Point-to-Site clients"
  type        = list(string)
  default     = ["172.16.1.0/24"]
}

variable "vpn_client_protocols" {
  description = "Point-to-Site VPN client protocols"
  type        = list(string)
  default     = ["OpenVPN"]
}

variable "vpn_client_root_certificate_name" {
  description = "Name of the uploaded VPN client root certificate"
  type        = string
  default     = "nt542_auto-p2s-root-cert"
}

variable "vpn_client_root_certificate_data" {
  description = "Base64 public certificate data for Point-to-Site root certificate"
  type        = string
  sensitive   = true
}

# ── Storage ───────────────────────────────────────────────────────────────────

variable "storage_account_name" {
  description = "Globally unique storage account name (3–24 lowercase alphanumeric)"
  type        = string
  default     = "nt542autostg08"
}

variable "storage_tier" {
  description = "Performance tier: Standard or Premium"
  type        = string
  default     = "Standard"
}

variable "storage_replication" {
  description = "Replication type: LRS | GRS | ZRS | GZRS"
  type        = string
  default     = "LRS"
}

variable "key_vault_name" {
  description = "Globally unique Key Vault name"
  type        = string
  default     = "nt542-auto-kv-g08"
}

variable "key_vault_sku" {
  description = "Key Vault SKU: standard or premium"
  type        = string
  default     = "standard"
}

variable "key_vault_soft_delete_retention_days" {
  description = "Soft delete retention period for Key Vault"
  type        = number
  default     = 7
}

variable "sql_server_name" {
  description = "Globally unique Azure SQL logical server name"
  type        = string
  default     = "nt542-auto-sqlserver-g08"
}

variable "sql_database_name" {
  description = "Azure SQL Database name"
  type        = string
  default     = "nt542-auto-sqldb"
}

variable "sql_admin_login" {
  description = "SQL administrator login used during server creation"
  type        = string
  default     = "nt542autosqladmin"
}

variable "sql_database_sku" {
  description = "Azure SQL Database SKU"
  type        = string
  default     = "Basic"
}

# ── Log Analytics ─────────────────────────────────────────────────────────────

variable "jumpbox_vm_name" {
  description = "Name of the private management VM"
  type        = string
  default     = "nt542_auto-vm-manage"
}

variable "jumpbox_vm_size" {
  description = "Size of the private management VM"
  type        = string
  default     = "Standard_B1s"
}

variable "jumpbox_admin_username" {
  description = "Administrator username for the private management VM"
  type        = string
  default     = "azureadmin"
}

variable "log_retention_days" {
  description = "Retention period in days for Log Analytics Workspace"
  type        = number
  default     = 30
}

# ── Tags ──────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "NT542"
    Group       = "Group08"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}
