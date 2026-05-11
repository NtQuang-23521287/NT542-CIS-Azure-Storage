resource "azurerm_public_ip" "management_vm" {
  name                = "${var.project}-mgmt-vm-pip"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_security_group" "management_vm" {
  name                = "${var.project}-mgmt-vm-nsg"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  tags                = var.tags

  security_rule {
    name                       = "Allow-SSH-Inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.vm_ssh_source_address_prefix
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-Internet-Outbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "Internet"
  }
}

resource "azurerm_network_interface" "management_vm" {
  name                = "${var.project}-mgmt-vm-nic"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  tags                = var.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.management.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.management_vm.id
  }
}

resource "azurerm_network_interface_security_group_association" "management_vm" {
  network_interface_id      = azurerm_network_interface.management_vm.id
  network_security_group_id = azurerm_network_security_group.management_vm.id
}

resource "azurerm_linux_virtual_machine" "management" {
  name                = "${var.project}-mgmt-vm"
  computer_name       = "${var.project}-mgmt-vm"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  size                = var.vm_size
  admin_username      = var.vm_admin_username
  tags                = var.tags

  disable_password_authentication = true
  network_interface_ids = [
    azurerm_network_interface.management_vm.id
  ]

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = var.vm_admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
