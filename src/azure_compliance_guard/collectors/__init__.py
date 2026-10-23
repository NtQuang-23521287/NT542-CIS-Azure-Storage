import json
from pathlib import Path
from typing import Protocol

from azure_compliance_guard.models import ResourceRef, StorageState

MAX_FIXTURE_FILE_BYTES = 5 * 1_048_576


class InvalidFixtureError(ValueError):
    """A fixture does not match the normalized Storage input contract."""


class StorageCollector(Protocol):
    def collect(self) -> list[StorageState]: ...


class FixtureStorageCollector:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def collect(self) -> list[StorageState]:
        if self.path.stat().st_size > MAX_FIXTURE_FILE_BYTES:
            raise InvalidFixtureError(
                f"fixture exceeds {MAX_FIXTURE_FILE_BYTES} byte limit"
            )
        with self.path.open(encoding="utf-8-sig") as file:
            payload = json.load(file)

        if not isinstance(payload, dict):
            raise InvalidFixtureError("fixture root must be an object")
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


def _required_string(mapping: dict, key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidFixtureError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_bool(value: object, label: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise InvalidFixtureError(f"{label} must be a boolean or null")


def _optional_string(value: object, label: str) -> None:
    if value is not None and not isinstance(value, str):
        raise InvalidFixtureError(f"{label} must be a string or null")
