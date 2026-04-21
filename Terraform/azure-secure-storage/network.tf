# ─────────────────────────────────────────────────────────────────────────────
# network.tf  –  VNet + Subnets
# ─────────────────────────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.project}-vnet"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

# ── GatewaySubnet (name must be exactly "GatewaySubnet" for VPN Gateway) ──────
resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = data.azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_gateway]
}

# ── ManagementSubnet ──────────────────────────────────────────────────────────
resource "azurerm_subnet" "management" {
  name                 = "ManagementSubnet"
  resource_group_name  = data.azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_management]
}

# ── PrivateEndpointSubnet ─────────────────────────────────────────────────────
resource "azurerm_subnet" "private_endpoint" {
  name                 = "PrivateEndpointSubnet"
  resource_group_name  = data.azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet_private_endpoint]

  # Required: disable network policies so Private Endpoint NIC can be placed here
  private_endpoint_network_policies = "Disabled"
}
