import json
from subprocess import CompletedProcess, TimeoutExpired
from types import SimpleNamespace
from unittest.mock import Mock

import collector
import pytest


def test_storage_sdk_response_is_normalized():
    client = Mock()
    client.storage_accounts.get_properties.return_value = SimpleNamespace(
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        public_network_access="Disabled",
    )
    client.blob_services.get_service_properties.return_value = SimpleNamespace(
        is_versioning_enabled=True,
    )

    result = collector.collect_storage_account_config(client, "rg-demo", "st-demo")

    assert result == {
        "https_only": True,
        "min_tls_version": "TLS1_2",
        "public_network_access": "Disabled",
        "versioning_enabled": True,
    }
    client.storage_accounts.get_properties.assert_called_once_with("rg-demo", "st-demo")
    client.blob_services.get_service_properties.assert_called_once_with(
        "rg-demo", "st-demo"
    )


def test_storage_missing_optional_versioning_defaults_to_false():
    client = Mock()
    client.storage_accounts.get_properties.return_value = SimpleNamespace(
        enable_https_traffic_only=True,
        minimum_tls_version=None,
        public_network_access=None,
    )
    client.blob_services.get_service_properties.return_value = SimpleNamespace(
        is_versioning_enabled=None,
    )

    result = collector.collect_storage_account_config(client, "rg", "st")

    assert result["versioning_enabled"] is False
    assert result["min_tls_version"] is None
    assert result["public_network_access"] is None


def test_storage_sdk_exception_is_not_silenced():
    client = Mock()
    client.storage_accounts.get_properties.side_effect = RuntimeError("SDK unavailable")

    with pytest.raises(RuntimeError, match="SDK unavailable"):
        collector.collect_storage_account_config(client, "rg", "st")


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (CompletedProcess([], 0, '{"name":"demo"}', ""), {"name": "demo"}),
        (CompletedProcess([], 0, '  \ufeff{"name":"demo"}', ""), {"name": "demo"}),
        (CompletedProcess([], 0, "", ""), None),
    ],
)
def test_cli_adapter_parses_json_and_uses_argument_vector(
    monkeypatch, result, expected
):
    calls = []

    def fake_run(args):
        calls.append(args)
        return result

    monkeypatch.setattr(collector, "run_az", fake_run)
    monkeypatch.setattr(collector, "display_az_command", lambda args: "az test")

    assert collector._run_az_json(["keyvault", "show"]) == expected
    assert calls == [["keyvault", "show", "--output", "json"]]


def test_cli_adapter_reports_nonzero_exit(monkeypatch):
    monkeypatch.setattr(collector, "display_az_command", lambda args: "az test")
    monkeypatch.setattr(
        collector,
        "run_az",
        lambda args: CompletedProcess(args, 2, "", "permission denied"),
    )

    with pytest.raises(RuntimeError, match="permission denied"):
        collector._run_az_json(["sql", "server", "show"])


def test_cli_adapter_reports_invalid_json(monkeypatch):
    monkeypatch.setattr(collector, "display_az_command", lambda args: "az test")
    monkeypatch.setattr(
        collector,
        "run_az",
        lambda args: CompletedProcess(args, 0, "not-json", ""),
    )

    with pytest.raises(json.JSONDecodeError):
        collector._run_az_json(["sql", "server", "show"])


def test_cli_adapter_propagates_timeout(monkeypatch):
    monkeypatch.setattr(collector, "display_az_command", lambda args: "az test")

    def timeout(args):
        raise TimeoutExpired(args, 60)

    monkeypatch.setattr(collector, "run_az", timeout)

    with pytest.raises(TimeoutExpired):
        collector._run_az_json(["keyvault", "show"])


def test_key_vault_cli_results_are_normalized(monkeypatch):
    responses = {
        "show": {
            "properties": {
                "publicNetworkAccess": "Disabled",
                "enableRbacAuthorization": True,
                "enablePurgeProtection": True,
                "enableSoftDelete": True,
            }
        },
        "key": [{"attributes": {"expires": "2030-01-01"}}],
        "secret": [{"attributes": {"expires": "2030-01-01"}}],
    }

    def fake_json(args):
        return responses[args[1]]

    monkeypatch.setattr(collector, "_run_az_json", fake_json)
    monkeypatch.setattr(collector, "_has_private_endpoint", lambda *args: True)

    assert collector.collect_key_vault_config("rg", "kv") == {
        "public_network_access": "Disabled",
        "enable_rbac_authorization": True,
        "enable_purge_protection": True,
        "enable_soft_delete": True,
        "private_endpoint_enabled": True,
        "keys_have_expiry": True,
        "secrets_have_expiry": True,
    }


def test_sql_cli_results_are_normalized(monkeypatch):
    def fake_json(args):
        if args[:3] == ["sql", "server", "show"]:
            return {"minimalTlsVersion": "1.2", "publicNetworkAccess": "Disabled"}
        if args[:3] == ["sql", "server", "audit-policy"]:
            return {"state": "Enabled"}
        if args[:3] == ["sql", "server", "ad-admin"]:
            return [{"name": "admin"}]
        if args[:2] == ["security", "pricing"]:
            return {"pricingTier": "Standard"}
        raise AssertionError(args)

    monkeypatch.setattr(collector, "_run_az_json", fake_json)
    monkeypatch.setattr(collector, "_has_private_endpoint", lambda *args: True)

    assert collector.collect_sql_config("rg", "sql") == {
        "auditing_enabled": True,
        "defender_enabled": True,
        "min_tls_version": "1.2",
        "public_network_access": "Disabled",
        "private_endpoint_enabled": True,
        "azure_ad_admin_configured": True,
    }
