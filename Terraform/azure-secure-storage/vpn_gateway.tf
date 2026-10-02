# Point-to-Site VPN gateway for private admin access into the VNet.
# Client machines connect to this gateway, receive an address from
# var.vpn_client_address_space, then SSH/RDP to private resources such as the
# Management VM in ManagementSubnet.

resource "azurerm_public_ip" "vpn_gateway_pip" {
  name                = var.vpn_gateway_public_ip_name
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = var.vpn_gateway_public_ip_zones

  tags = var.tags
}

resource "azurerm_virtual_network_gateway" "vpn_gateway" {
  name                = var.vpn_gateway_name
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name

  type       = "Vpn"
  vpn_type   = "RouteBased"
  sku        = var.vpn_sku
  generation = var.vpn_generation

  active_active = false
  enable_bgp    = false

  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id          = azurerm_public_ip.vpn_gateway_pip.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.gateway.id
  }

  vpn_client_configuration {
    address_space        = var.vpn_client_address_space
    vpn_client_protocols = var.vpn_client_protocols

    root_certificate {
      name             = var.vpn_client_root_certificate_name
      public_cert_data = var.vpn_client_root_certificate_data
    }
  }

  tags = var.tags
}
