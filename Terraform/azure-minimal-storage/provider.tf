terraform {
  required_version = ">= 1.3.0"

  # Use a distinct state key from azure-secure-storage; provide backend values at init.
  backend "azurerm" {}

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  subscription_id            = var.subscription_id
  skip_provider_registration = true

  features {}
}
