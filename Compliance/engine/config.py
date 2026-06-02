import os

# Azure Credentials
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
AZURE_SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')

# Time settings for monitoring interval (in seconds)
CHECK_INTERVAL = 5  # Every 5 seconds

# Monitored resources. Defaults match the Terraform module.
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP", "NT542-Group08_Automation")
STORAGE_ACCOUNT_NAME = os.getenv("STORAGE_ACCOUNT_NAME", "group08compliance120526")
KEY_VAULT_NAME = os.getenv("KEY_VAULT_NAME", "nt542-kv-group08-120526")
SQL_SERVER_NAME = os.getenv("SQL_SERVER_NAME", "nt542-sqlserver-group08")
