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
