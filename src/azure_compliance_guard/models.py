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
class Finding:
    rule_id: str
    title: str
    service: str
    severity: str
    resource: ResourceRef
    actual: object
    expected: object

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "service": self.service,
            "severity": self.severity,
            "resource": self.resource.to_dict(),
            "actual": self.actual,
            "expected": self.expected,
            "status": "FAIL",
        }
