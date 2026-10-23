import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from azure_compliance_guard.collectors import (
    AzureStorageCollector,
    FixtureStorageCollector,
    InvalidFixtureError,
)
from azure_compliance_guard.models import ResourceRef, StorageState
from azure_compliance_guard.rules import load_default_rule_catalog
from azure_compliance_guard.scan import evaluate_states


def test_fixture_and_sdk_shape_share_the_storage_state_model(tmp_path):
    fixture = {
        "resource_group": "rg-demo",
        "storage_accounts": [
            {
                "name": "stdemo",
                "account": {
                    "supportsHttpsTrafficOnly": True,
                    "minimumTlsVersion": "TLS1_2",
                    "publicNetworkAccess": "Disabled",
                },
                "blob_service": {"isVersioningEnabled": True},
            }
        ],
    }
    path = tmp_path / "storage.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    states = FixtureStorageCollector(path).collect()

    assert states == [
        StorageState(
            resource=ResourceRef(
                service="storage", resource_group="rg-demo", name="stdemo"
            ),
            https_only=True,
            min_tls_version="TLS1_2",
            public_network_access="Disabled",
            versioning_enabled=True,
        )
    ]


def test_azure_sdk_collector_returns_the_same_storage_state_model():
    client = Mock()
    client.storage_accounts.get_properties.return_value = SimpleNamespace(
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        public_network_access="Disabled",
    )
    client.blob_services.get_service_properties.return_value = SimpleNamespace(
        is_versioning_enabled=True
    )

    states = AzureStorageCollector(client, "rg-demo", "stdemo", "sub-demo").collect()

    assert states == [
        StorageState(
            resource=ResourceRef(
                service="storage",
                resource_group="rg-demo",
                name="stdemo",
                subscription_id="sub-demo",
            ),
            https_only=True,
            min_tls_version="TLS1_2",
            public_network_access="Disabled",
            versioning_enabled=True,
        )
    ]


def test_rule_engine_reports_stable_rule_ids_for_fixture_drift(tmp_path):
    fixture = {
        "resource_group": "rg-demo",
        "storage_accounts": [
            {
                "name": "stdrift",
                "account": {
                    "supportsHttpsTrafficOnly": False,
                    "minimumTlsVersion": "TLS1_0",
                    "publicNetworkAccess": "Enabled",
                },
                "blob_service": {"isVersioningEnabled": False},
            }
        ],
    }
    path = tmp_path / "storage.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    findings = evaluate_states(
        FixtureStorageCollector(path).collect(), load_default_rule_catalog()
    )

    assert [finding.rule_id for finding in findings] == [
        "ACG-STO-001",
        "ACG-STO-002",
        "ACG-STO-003",
        "ACG-STO-004",
    ]
    assert {finding.resource.name for finding in findings} == {"stdrift"}


def test_rule_engine_has_no_azure_dependency_for_secure_fixture(tmp_path):
    fixture = {
        "resource_group": "rg-demo",
        "storage_accounts": [
            {
                "name": "stsecure",
                "account": {
                    "supportsHttpsTrafficOnly": True,
                    "minimumTlsVersion": "TLS1_2",
                    "publicNetworkAccess": "Disabled",
                },
                "blob_service": {"isVersioningEnabled": True},
            }
        ],
    }
    path = tmp_path / "storage.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    assert (
        evaluate_states(
            FixtureStorageCollector(path).collect(), load_default_rule_catalog()
        )
        == []
    )


def test_fixture_collector_rejects_string_boolean(tmp_path):
    fixture = {
        "resource_group": "rg-demo",
        "storage_accounts": [
            {
                "name": "stinvalid",
                "account": {
                    "supportsHttpsTrafficOnly": "yes",
                    "minimumTlsVersion": "TLS1_2",
                    "publicNetworkAccess": "Disabled",
                },
                "blob_service": {"isVersioningEnabled": True},
            }
        ],
    }
    path = tmp_path / "storage.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    with pytest.raises(InvalidFixtureError, match="supportsHttpsTrafficOnly"):
        FixtureStorageCollector(path).collect()
