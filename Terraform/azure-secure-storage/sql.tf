resource "random_password" "sql_admin" {
  length           = 24
  special          = true
  override_special = "_%@"
}

resource "azurerm_mssql_server" "sql" {
  name                          = var.sql_server_name
  resource_group_name           = data.azurerm_resource_group.rg.name
  location                      = var.location
  version                       = "12.0"
  administrator_login           = var.sql_admin_login
  administrator_login_password  = random_password.sql_admin.result
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false

  azuread_administrator {
    login_username              = "terraform-admin"
    object_id                   = data.azurerm_client_config.current.object_id
    azuread_authentication_only = true
  }

  tags = var.tags
}

resource "azurerm_mssql_database" "sqldb" {
  name      = var.sql_database_name
  server_id = azurerm_mssql_server.sql.id
  sku_name  = var.sql_database_sku

  tags = var.tags
}

resource "azurerm_mssql_server_extended_auditing_policy" "sql_audit" {
  server_id              = azurerm_mssql_server.sql.id
  log_monitoring_enabled = true
}

resource "azurerm_mssql_server_security_alert_policy" "sql_defender" {
  resource_group_name = data.azurerm_resource_group.rg.name
  server_name         = azurerm_mssql_server.sql.name
  state               = "Enabled"
}

resource "azurerm_private_dns_zone" "sql" {
  name                = "privatelink.database.windows.net"
  resource_group_name = data.azurerm_resource_group.rg.name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "sql_link" {
  name                  = "${var.project}-sql-dns-link"
  resource_group_name   = data.azurerm_resource_group.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.sql.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_endpoint" "sql_pe" {
  name                = "${var.project}-sql-pe"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private_endpoint.id

  private_service_connection {
    name                           = "${var.project}-sql-psc"
    private_connection_resource_id = azurerm_mssql_server.sql.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "sql-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.sql.id]
  }

  tags = var.tags
}
