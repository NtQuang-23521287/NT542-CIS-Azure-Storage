variable "subscription_id" {
  type = string
}

variable "resource_group_name" {
  type    = string
  default = "rg-hospital-cis"
}

variable "location" {
  type    = string
  default = "southeastasia"
}

variable "storage_account_name" {
  type = string
}