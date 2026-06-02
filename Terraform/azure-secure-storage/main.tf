# ─────────────────────────────────────────────────────────────────────────────
# main.tf  –  Resource Group
# ─────────────────────────────────────────────────────────────────────────────

# Tạo Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# Data resource để tham chiếu đến Resource Group đã tạo
data "azurerm_resource_group" "rg" {
  name = azurerm_resource_group.rg.name  # Tham chiếu đến Resource Group đã tạo
}
