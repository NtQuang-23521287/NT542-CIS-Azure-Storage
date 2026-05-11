resource "azurerm_public_ip" "vpn_gateway" {
  name                = "${var.project}-vpn-gw-pip"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = var.vpn_gateway_public_ip_zones
  tags                = var.tags
}

resource "azurerm_virtual_network_gateway" "vpn" {
  name                = "${var.project}-vpn-gw"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name

  type       = "Vpn"
  vpn_type   = var.vpn_type
  sku        = var.vpn_sku
  generation = var.vpn_generation

  active_active = false
  enable_bgp    = false

  ip_configuration {
    name                          = "vpn-gateway-ipconfig"
    public_ip_address_id          = azurerm_public_ip.vpn_gateway.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.gateway.id
  }

  dynamic "vpn_client_configuration" {
    for_each = var.vpn_client_root_certificate_data == "" ? [] : [1]

    content {
      address_space = var.vpn_client_address_space

      root_certificate {
        name             = var.vpn_client_root_certificate_name
        public_cert_data = var.vpn_client_root_certificate_data
      }
    }
  }

  tags = var.tags

  timeouts {
    create = "60m"
    delete = "60m"
  }
}
