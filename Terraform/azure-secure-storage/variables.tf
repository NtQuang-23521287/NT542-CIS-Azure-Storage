variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "NT542-Group08"
}

variable "location" {
  description = "Azure region to deploy resources"
  type        = string
  default     = "eastasia"
}

variable "project" {
  description = "Project prefix used for naming resources"
  type        = string
  default     = "nt542"
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
  default     = ["10.0.0.0/16"]
}

variable "subnet_gateway" {
  description = "Address prefix for GatewaySubnet (must be named exactly 'GatewaySubnet')"
  type        = string
  default     = "10.0.1.0/27"
}

variable "subnet_management" {
  description = "Address prefix for ManagementSubnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "subnet_private_endpoint" {
  description = "Address prefix for PrivateEndpointSubnet"
  type        = string
  default     = "10.0.3.0/24"
}

# ── VPN Gateway ───────────────────────────────────────────────────────────────

variable "vpn_sku" {
  description = "SKU for the VPN Gateway (Basic is cheapest)"
  type        = string
  default     = "Basic"
}

variable "vpn_generation" {
  description = "VPN Gateway generation"
  type        = string
  default     = "Generation1"
}

variable "vpn_gateway_public_ip_zones" {
  description = "Availability zones for the VPN Gateway Standard Public IP"
  type        = list(string)
  default     = ["1", "2", "3"]
}

variable "vpn_type" {
  description = "VPN Gateway type: RouteBased or PolicyBased"
  type        = string
  default     = "RouteBased"
}

variable "vpn_client_address_space" {
  description = "Client address pool for Point-to-Site VPN. Used only when vpn_client_root_certificate_data is set."
  type        = list(string)
  default     = ["172.16.0.0/24"]
}

variable "vpn_client_root_certificate_name" {
  description = "Name for the Point-to-Site VPN root certificate"
  type        = string
  default     = "p2s-root-cert"
}

variable "vpn_client_root_certificate_data" {
  description = "Base64 public root certificate data for Point-to-Site VPN. Leave empty to create only the gateway."
  type        = string
  default     = ""
}

variable "vm_size" {
  description = "Size for the management Linux VM"
  type        = string
  default     = "Standard_DS1_v2"
}

variable "vm_admin_username" {
  description = "Admin username for the management Linux VM"
  type        = string
  default     = "azureuser"
}

variable "vm_admin_ssh_public_key" {
  description = "SSH public key used to access the management Linux VM"
  type        = string
}

variable "vm_ssh_source_address_prefix" {
  description = "Source IP/CIDR allowed to SSH to the management Linux VM. Use your public IP with /32 for better security."
  type        = string
  default     = "*"
}

# ── Storage ───────────────────────────────────────────────────────────────────

variable "storage_account_name" {
  description = "Globally unique storage account name (3–24 lowercase alphanumeric)"
  type        = string
  default     = "stmedgroup08compliance"
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

# ── Log Analytics ─────────────────────────────────────────────────────────────

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
