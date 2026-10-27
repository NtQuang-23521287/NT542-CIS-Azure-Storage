variable "subscription_id" {
  description = "Azure subscription GUID; pass explicitly after checking the active account"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be an Azure subscription GUID."
  }
}

variable "resource_group_name" {
  description = "New, dedicated Phase K resource group; never reuse the full-demo group"
  type        = string

  validation {
    condition     = can(regex("^nt542-phase-k-[a-z0-9-]{3,40}$", var.resource_group_name))
    error_message = "resource_group_name must start with nt542-phase-k- and contain 3-40 lowercase letters, digits or hyphens after the prefix."
  }
}

variable "storage_account_name" {
  description = "Globally unique Azure Storage account name, 3-24 lowercase alphanumeric characters"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "storage_account_name must be 3-24 lowercase letters or digits."
  }
}

variable "location" {
  description = "Azure region confirmed to support Storage and Log Analytics in this subscription"
  type        = string
}

variable "owner" {
  description = "Lab owner identifier for lifecycle review (avoid personal email if reports are shared)"
  type        = string

  validation {
    condition     = length(trimspace(var.owner)) > 0
    error_message = "owner must be nonempty."
  }
}

variable "expires_on" {
  description = "Planned cleanup date in YYYY-MM-DD, checked by the operator before apply"
  type        = string

  validation {
    condition     = can(regex("^20[0-9]{2}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])$", var.expires_on))
    error_message = "expires_on must be a YYYY-MM-DD date."
  }
}

variable "environment" {
  description = "Lifecycle environment tag"
  type        = string
  default     = "demo"
}

variable "log_retention_days" {
  description = "Log Analytics retention; verify current Azure price and minimum before apply"
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 90
    error_message = "log_retention_days must be between 30 and 90."
  }
}
