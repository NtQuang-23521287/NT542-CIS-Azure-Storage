terraform {
  required_version = ">= 1.3.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "subscription_id" {
  description = "Azure subscription ID for this Terraform deployment (required; no default)"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be an Azure subscription GUID."
  }
}

provider "azurerm" {
  # Pin the deployment target instead of inheriting the active Azure CLI subscription.
  subscription_id = var.subscription_id
  # AzureRM v3 otherwise auto-registers Resource Providers at subscription scope.
  # Source: https://github.com/hashicorp/terraform-provider-azurerm/blob/v3.117.1/website/docs/index.html.markdown
  skip_provider_registration = true

  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}
