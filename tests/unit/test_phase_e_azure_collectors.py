import json
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import pytest

from azure_compliance_guard.azure_cli import AzureCliJsonRunner
from azure_compliance_guard.collectors import AzureKeyVaultCollector, AzureSqlCollector
from azure_compliance_guard.models import KeyVaultState, ResourceRef, SqlState

SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"


def test_azure_cli_json_runner_uses_scoped_argument_vector():
    completed = CompletedProcess(
        args=[], returncode=0, stdout=json.dumps({"name": "demo"}), stderr=""
    )
    with (
        patch(
            "azure_compliance_guard.azure_cli.shutil.which",
            return_value="C:/tools/az.cmd",
        ),
        patch(
            "azure_compliance_guard.azure_cli.subprocess.run",
            return_value=completed,
        ) as subprocess_run,
    ):
        result = AzureCliJsonRunner(SUBSCRIPTION_ID).run(
            ["keyvault", "show", "--name", "kv-demo"]
        )

    assert result == {"name": "demo"}
    subprocess_run.assert_called_once_with(
        [
            "C:/tools/az.cmd",
            "keyvault",
            "show",
            "--name",
            "kv-demo",
            "--subscription",
            SUBSCRIPTION_ID,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        shell=False,
    )


def test_azure_cli_json_runner_rejects_subscription_override():
    runner = AzureCliJsonRunner(SUBSCRIPTION_ID)

    with pytest.raises(ValueError, match="cannot be overridden"):
        runner.run(["group", "list", "--subscription", SUBSCRIPTION_ID])


def test_key_vault_cli_collector_returns_typed_state():
    runner = Mock()
    runner.run.side_effect = [
        {
            "properties": {
                "publicNetworkAccess": "Disabled",
                "enableRbacAuthorization": True,
                "enablePurgeProtection": True,
                "enableSoftDelete": True,
            }
        },
        [{"attributes": {"expires": "2027-01-01T00:00:00Z"}}],
        [{"attributes": {"expires": "2027-01-01T00:00:00Z"}}],
        [
            {
                "privateLinkServiceConnections": [
                    {
                        "privateLinkServiceId": (
                            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-demo/"
                            "providers/Microsoft.KeyVault/vaults/kv-demo"
                        ),
                        "privateLinkServiceConnectionState": {"status": "Approved"},
                    }
                ]
            }
        ],
    ]

    states = AzureKeyVaultCollector(
        runner, "rg-demo", "kv-demo", SUBSCRIPTION_ID
    ).collect()

    assert states == [
        KeyVaultState(
            resource=ResourceRef("key_vault", "rg-demo", "kv-demo", SUBSCRIPTION_ID),
            public_network_access="Disabled",
            rbac_authorization_enabled=True,
            purge_protection_enabled=True,
            soft_delete_enabled=True,
            private_endpoint_enabled=True,
            keys_have_expiry=True,
            secrets_have_expiry=True,
        )
    ]
    assert runner.run.call_count == 4


def test_sql_cli_collector_returns_typed_state_and_reads_pricing():
    runner = Mock()
    runner.run.side_effect = [
        {"minimalTlsVersion": "1.2", "publicNetworkAccess": "Disabled"},
        {"state": "Enabled"},
        [{"login": "admin-demo"}],
        {"pricingTier": "Standard"},
        [
            {
                "properties": {
                    "privateLinkServiceConnections": [
                        {
                            "properties": {
                                "privateLinkServiceId": (
                                    f"/subscriptions/{SUBSCRIPTION_ID}/"
                                    "resourceGroups/rg-demo/providers/"
                                    "Microsoft.Sql/servers/sql-demo"
                                ),
                                "privateLinkServiceConnectionState": {
                                    "status": "Approved"
                                },
                            }
                        }
                    ]
                }
            }
        ],
    ]

    states = AzureSqlCollector(runner, "rg-demo", "sql-demo", SUBSCRIPTION_ID).collect()

    assert states == [
        SqlState(
            resource=ResourceRef("sql", "rg-demo", "sql-demo", SUBSCRIPTION_ID),
            auditing_enabled=True,
            defender_enabled=True,
            min_tls_version="1.2",
            public_network_access="Disabled",
            private_endpoint_enabled=True,
            azure_ad_admin_configured=True,
        )
    ]
    assert runner.run.call_args_list[3].args[0] == [
        "security",
        "pricing",
        "show",
        "--name",
        "SqlServers",
    ]
