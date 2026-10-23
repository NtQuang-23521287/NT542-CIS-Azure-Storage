import json
from pathlib import Path
from typing import Protocol

from azure_compliance_guard.models import KeyVaultState, ResourceRef, StorageState

MAX_FIXTURE_FILE_BYTES = 5 * 1_048_576


class InvalidFixtureError(ValueError):
    """A fixture does not match the normalized Storage input contract."""


class StorageCollector(Protocol):
    def collect(self) -> list[StorageState]: ...


class FixtureStorageCollector:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def collect(self) -> list[StorageState]:
        payload = _load_fixture(self.path)
        resource_group = _required_string(payload, "resource_group", "fixture")
        items = payload.get("storage_accounts")
        if not isinstance(items, list):
            raise InvalidFixtureError("fixture.storage_accounts must be a list")
        states = []
        for index, item in enumerate(items):
            label = f"fixture.storage_accounts[{index}]"
            if not isinstance(item, dict):
                raise InvalidFixtureError(f"{label} must be an object")
            account = _required_mapping(item, "account", label)
            blob_service = _required_mapping(item, "blob_service", label)
            https_only = account.get("supportsHttpsTrafficOnly")
            min_tls_version = account.get("minimumTlsVersion")
            public_network_access = account.get("publicNetworkAccess")
            versioning = blob_service.get("isVersioningEnabled", False)
            _optional_bool(https_only, f"{label}.account.supportsHttpsTrafficOnly")
            _optional_string(min_tls_version, f"{label}.account.minimumTlsVersion")
            _optional_string(
                public_network_access,
                f"{label}.account.publicNetworkAccess",
            )
            _optional_bool(versioning, f"{label}.blob_service.isVersioningEnabled")
            item_resource_group = item.get("resource_group", resource_group)
            if (
                not isinstance(item_resource_group, str)
                or not item_resource_group.strip()
            ):
                raise InvalidFixtureError(
                    f"{label}.resource_group must be a non-empty string"
                )
            states.append(
                StorageState(
                    resource=ResourceRef(
                        service="storage",
                        resource_group=item_resource_group,
                        name=_required_string(item, "name", label),
                    ),
                    https_only=https_only,
                    min_tls_version=min_tls_version,
                    public_network_access=public_network_access,
                    versioning_enabled=bool(versioning),
                )
            )
        return states


class FixtureKeyVaultCollector:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def collect(self) -> list[KeyVaultState]:
        payload = _load_fixture(self.path)
        resource_group = _required_string(payload, "resource_group", "fixture")
        items = payload.get("key_vaults")
        if not isinstance(items, list):
            raise InvalidFixtureError("fixture.key_vaults must be a list")

        states = []
        for index, item in enumerate(items):
            label = f"fixture.key_vaults[{index}]"
            if not isinstance(item, dict):
                raise InvalidFixtureError(f"{label} must be an object")
            properties = _required_mapping(item, "properties", label)
            public_network_access = properties.get("publicNetworkAccess")
            rbac_enabled = properties.get("enableRbacAuthorization")
            purge_enabled = properties.get("enablePurgeProtection")
            soft_delete_enabled = properties.get("enableSoftDelete")
            private_endpoint_enabled = item.get("private_endpoint_enabled", False)
            _optional_string(
                public_network_access, f"{label}.properties.publicNetworkAccess"
            )
            _optional_bool(rbac_enabled, f"{label}.properties.enableRbacAuthorization")
            _optional_bool(purge_enabled, f"{label}.properties.enablePurgeProtection")
            _optional_bool(soft_delete_enabled, f"{label}.properties.enableSoftDelete")
            _required_bool(
                private_endpoint_enabled, f"{label}.private_endpoint_enabled"
            )
            item_resource_group = item.get("resource_group", resource_group)
            if (
                not isinstance(item_resource_group, str)
                or not item_resource_group.strip()
            ):
                raise InvalidFixtureError(
                    f"{label}.resource_group must be a non-empty string"
                )
            states.append(
                KeyVaultState(
                    resource=ResourceRef(
                        service="key_vault",
                        resource_group=item_resource_group,
                        name=_required_string(item, "name", label),
                    ),
                    public_network_access=public_network_access,
                    rbac_authorization_enabled=rbac_enabled,
                    purge_protection_enabled=purge_enabled,
                    soft_delete_enabled=soft_delete_enabled,
                    private_endpoint_enabled=private_endpoint_enabled,
                    keys_have_expiry=_all_have_expiry(item, "keys", label),
                    secrets_have_expiry=_all_have_expiry(item, "secrets", label),
                )
            )
        return states


class AzureStorageCollector:
    def __init__(
        self,
        storage_client,
        resource_group: str,
        storage_account_name: str,
        subscription_id: str | None = None,
    ):
        self.storage_client = storage_client
        self.resource = ResourceRef(
            service="storage",
            resource_group=resource_group,
            name=storage_account_name,
            subscription_id=subscription_id,
        )

    def collect(self) -> list[StorageState]:
        account = self.storage_client.storage_accounts.get_properties(
            self.resource.resource_group, self.resource.name
        )
        blob_service = self.storage_client.blob_services.get_service_properties(
            self.resource.resource_group, self.resource.name
        )
        return [
            StorageState(
                resource=self.resource,
                https_only=account.enable_https_traffic_only,
                min_tls_version=account.minimum_tls_version,
                public_network_access=account.public_network_access,
                versioning_enabled=bool(blob_service.is_versioning_enabled),
            )
        ]


def _required_mapping(mapping: dict, key: str, label: str) -> dict:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise InvalidFixtureError(f"{label}.{key} must be an object")
    return value


def _load_fixture(path: Path) -> dict:
    if path.stat().st_size > MAX_FIXTURE_FILE_BYTES:
        raise InvalidFixtureError(
            f"fixture exceeds {MAX_FIXTURE_FILE_BYTES} byte limit"
        )
    with path.open(encoding="utf-8-sig") as file:
        payload = json.load(file)
    if not isinstance(payload, dict):
        raise InvalidFixtureError("fixture root must be an object")
    return payload


def _required_string(mapping: dict, key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidFixtureError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_bool(value: object, label: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise InvalidFixtureError(f"{label} must be a boolean or null")


def _required_bool(value: object, label: str) -> None:
    if not isinstance(value, bool):
        raise InvalidFixtureError(f"{label} must be a boolean")


def _optional_string(value: object, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise InvalidFixtureError(f"{label} must be a string or null")


def _all_have_expiry(mapping: dict, key: str, label: str) -> bool:
    items = mapping.get(key)
    if not isinstance(items, list):
        raise InvalidFixtureError(f"{label}.{key} must be a list")
    for index, item in enumerate(items):
        item_label = f"{label}.{key}[{index}]"
        if not isinstance(item, dict):
            raise InvalidFixtureError(f"{item_label} must be an object")
        attributes = item.get("attributes")
        if not isinstance(attributes, dict):
            raise InvalidFixtureError(f"{item_label}.attributes must be an object")
        if not attributes.get("expires"):
            return False
    return True
