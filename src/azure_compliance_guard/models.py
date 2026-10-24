import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ResourceRef:
    service: str
    resource_group: str
    name: str
    subscription_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StorageState:
    resource: ResourceRef
    https_only: bool | None
    min_tls_version: str | None
    public_network_access: str | None
    versioning_enabled: bool

    def facts(self) -> dict[str, object]:
        return {
            "https_only": self.https_only,
            "min_tls_version": self.min_tls_version,
            "public_network_access": self.public_network_access,
            "versioning_enabled": self.versioning_enabled,
        }


@dataclass(frozen=True, slots=True)
class KeyVaultState:
    resource: ResourceRef
    public_network_access: str | None
    rbac_authorization_enabled: bool | None
    purge_protection_enabled: bool | None
    soft_delete_enabled: bool | None
    private_endpoint_enabled: bool
    keys_have_expiry: bool
    secrets_have_expiry: bool

    def facts(self) -> dict[str, object]:
        return {
            "public_network_access": self.public_network_access,
            "rbac_authorization_enabled": self.rbac_authorization_enabled,
            "purge_protection_enabled": self.purge_protection_enabled,
            "soft_delete_enabled": self.soft_delete_enabled,
            "private_endpoint_enabled": self.private_endpoint_enabled,
            "keys_have_expiry": self.keys_have_expiry,
            "secrets_have_expiry": self.secrets_have_expiry,
        }


@dataclass(frozen=True, slots=True)
class SqlState:
    resource: ResourceRef
    auditing_enabled: bool
    defender_enabled: bool
    min_tls_version: str | None
    public_network_access: str | None
    private_endpoint_enabled: bool
    azure_ad_admin_configured: bool

    def facts(self) -> dict[str, object]:
        return {
            "auditing_enabled": self.auditing_enabled,
            "defender_enabled": self.defender_enabled,
            "min_tls_version": self.min_tls_version,
            "public_network_access": self.public_network_access,
            "private_endpoint_enabled": self.private_endpoint_enabled,
            "azure_ad_admin_configured": self.azure_ad_admin_configured,
        }


ResourceState = StorageState | KeyVaultState | SqlState


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    service: str
    severity: str
    resource: ResourceRef
    actual: object
    expected: object

    @property
    def finding_id(self) -> str:
        identity = [self.rule_id, self.resource.to_dict(), self.actual]
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "service": self.service,
            "severity": self.severity,
            "resource": self.resource.to_dict(),
            "actual": self.actual,
            "expected": self.expected,
            "status": "FAIL",
        }
