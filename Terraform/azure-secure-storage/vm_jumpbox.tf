# Private management VM used as a jumpbox after the admin workstation connects
# to the Point-to-Site VPN. This VM has no public IP.

resource "random_password" "jumpbox_admin" {
  length           = 20
  special          = true
  override_special = "_%@"
}

resource "azurerm_network_security_group" "jumpbox_nsg" {
  name                = "${var.jumpbox_vm_name}-nsg"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-SSH-From-P2S-VPN"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.vpn_client_address_space
    destination_address_prefix = "*"
  }

  tags = var.tags
}

resource "azurerm_network_interface" "jumpbox_nic" {
  name                = "${var.jumpbox_vm_name}-nic"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.management.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = var.tags
}

resource "azurerm_network_interface_security_group_association" "jumpbox_nsg_assoc" {
  network_interface_id      = azurerm_network_interface.jumpbox_nic.id
  network_security_group_id = azurerm_network_security_group.jumpbox_nsg.id
}

resource "azurerm_linux_virtual_machine" "jumpbox" {
  name                = var.jumpbox_vm_name
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  size                = var.jumpbox_vm_size
  computer_name       = replace(var.jumpbox_vm_name, "_", "-")
  admin_username      = var.jumpbox_admin_username
  admin_password      = random_password.jumpbox_admin.result

  disable_password_authentication = false

  network_interface_ids = [
    azurerm_network_interface.jumpbox_nic.id,
  ]

  os_disk {
    name                 = "${var.jumpbox_vm_name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  tags = var.tags
}
