# ─────────────────────────────────────────────────────────────────────────────
# main.tf  –  Resource Group
# ─────────────────────────────────────────────────────────────────────────────

# Tạo Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "NT542-Group08_Automation"
  location = "East US"
}

# Data resource để tham chiếu đến Resource Group đã tạo
data "azurerm_resource_group" "rg" {
  name = azurerm_resource_group.rg.name  # Tham chiếu đến Resource Group đã tạo
}