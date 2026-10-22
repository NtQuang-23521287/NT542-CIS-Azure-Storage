import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    # Explicit process environment wins over local .env configuration.
    load_dotenv(override=False)
except ImportError:
    pass

# Azure Credentials
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

# Time settings for monitoring interval (in seconds)
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "5"))


def _boolean_env(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    value = raw_value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


# Temporary P0 safety gate. The long-term workflow is plan -> approval -> execute -> verify.
ALLOW_AZURE_MUTATIONS = _boolean_env("ALLOW_AZURE_MUTATIONS", default=False)

# Monitored resources. Defaults match the Terraform module.
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP", "NT542-Group08_AUTO")
STORAGE_ACCOUNT_NAME = os.getenv("STORAGE_ACCOUNT_NAME", "nt542autostg08")
KEY_VAULT_NAME = os.getenv("KEY_VAULT_NAME", "nt542-auto-kv-g08")
SQL_SERVER_NAME = os.getenv("SQL_SERVER_NAME", "nt542-auto-sqlserver-g08")

BASE_DIR = Path(__file__).resolve().parent
COMPLIANCE_DIR = BASE_DIR.parent
DATA_DIR = os.getenv("DATA_DIR", str(COMPLIANCE_DIR / "data"))
LOG_DIR = os.getenv("LOG_DIR", str(BASE_DIR / "logs"))

EXCEPTIONS_FILE = os.getenv("EXCEPTIONS_FILE", str(Path(DATA_DIR) / "exceptions.json"))
SECURITY_SIGNALS_FILE = os.getenv(
    "SECURITY_SIGNALS_FILE",
    str(Path(DATA_DIR) / "security_signals.json"),
)

COMPLIANCE_LOG_FILE = os.getenv(
    "COMPLIANCE_LOG_FILE",
    str(Path(LOG_DIR) / "compliance_monitor.log"),
)
INCIDENT_LOG_FILE = os.getenv("INCIDENT_LOG_FILE", str(Path(LOG_DIR) / "incidents.log"))
EXCEPTION_LOG_FILE = os.getenv(
    "EXCEPTION_LOG_FILE", str(Path(LOG_DIR) / "exceptions.log")
)

DEFAULT_EXCEPTION_MINUTES = int(os.getenv("DEFAULT_EXCEPTION_MINUTES", "30"))
MAX_EXCEPTION_MINUTES = int(os.getenv("MAX_EXCEPTION_MINUTES", "120"))

TRUSTED_ADMIN_IPS = {
    item.strip()
    for item in os.getenv("TRUSTED_ADMIN_IPS", "").split(",")
    if item.strip()
}
TRUSTED_IDENTITIES = {
    item.strip()
    for item in os.getenv("TRUSTED_IDENTITIES", "").split(",")
    if item.strip()
}

SENSITIVE_STORAGE_OPERATIONS = {
    "GetBlob",
    "ListBlob",
    "DeleteBlob",
    "PutBlob",
}
SENSITIVE_KEYVAULT_OPERATIONS = {
    "SecretGet",
    "SecretList",
    "KeyDecrypt",
    "KeyUnwrap",
}
SENSITIVE_SQL_OPERATIONS = {
    "Login",
    "Query",
    "DataExport",
}
