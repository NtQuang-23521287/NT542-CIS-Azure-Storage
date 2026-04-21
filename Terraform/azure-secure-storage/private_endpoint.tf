# ─────────────────────────────────────────────────────────────────────────────
# private_endpoint.tf  –  Blob Private Endpoint + Private DNS Zone
# ─────────────────────────────────────────────────────────────────────────────

# ── Private DNS Zone for blob storage ────────────────────────────────────────
resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = data.azurerm_resource_group.rg.name
  tags                = var.tags
}

# ── Link DNS zone to our VNet so VMs can resolve private IPs ─────────────────
resource "azurerm_private_dns_zone_virtual_network_link" "blob_link" {
  name                  = "${var.project}-blob-dns-link"
  resource_group_name   = data.azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
  registration_enabled  = false
  tags                  = var.tags
}

# ── Private Endpoint (blob sub-resource) ─────────────────────────────────────
resource "azurerm_private_endpoint" "blob_pe" {
  name                = "${var.project}-blob-pe"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private_endpoint.id

  private_service_connection {
    name                           = "${var.project}-blob-psc"
    private_connection_resource_id = azurerm_storage_account.sa.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  # Auto-register the NIC IP in the private DNS zone
  private_dns_zone_group {
    name                 = "blob-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }

  tags = var.tags
}
