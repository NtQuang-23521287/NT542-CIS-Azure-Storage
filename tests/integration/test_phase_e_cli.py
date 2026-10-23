import json
from unittest.mock import Mock

from azure_compliance_guard import cli
from azure_compliance_guard.cli import main
from azure_compliance_guard.models import KeyVaultState, ResourceRef, SqlState


def test_doctor_reports_missing_offline_prerequisites_without_mutating(
    capsys, monkeypatch
):
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("ALLOW_AZURE_MUTATIONS", raising=False)

    exit_code = main(["doctor", "--format", "json"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    checks = {item["name"]: item for item in output["checks"]}
    assert checks["azure_cli"]["status"] == "FAIL"
    assert checks["subscription"]["status"] == "FAIL"
    assert checks["azure_mutations"]["status"] == "PASS"


def test_doctor_does_not_echo_subscription_id(capsys, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-secret-subscription")
    monkeypatch.setattr(
        "azure_compliance_guard.doctor.shutil.which",
        lambda command, path=None: f"C:/tools/{command}.exe",
    )

    def fake_command(executable, args):
        detail = (
            "00000000-secret-subscription"
            if args[:2] == ["account", "show"]
            else "Terraform v1.14.9"
        )
        return True, detail

    monkeypatch.setattr("azure_compliance_guard.doctor._run_version", fake_command)

    main(["doctor", "--format", "json"])

    assert "00000000-secret-subscription" not in capsys.readouterr().out


def test_fixture_scan_is_one_shot_and_returns_policy_exit_code(capsys):
    exit_code = main(["scan", "--source", "fixture", "--format", "json"])

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["summary"] == {"resources": 1, "findings": 4}
    assert [item["rule_id"] for item in output["findings"]] == [
        "ACG-STO-001",
        "ACG-STO-002",
        "ACG-STO-003",
        "ACG-STO-004",
    ]


def test_fixture_scan_can_select_key_vault(capsys):
    exit_code = main(
        [
            "scan",
            "--source",
            "fixture",
            "--service",
            "key-vault",
            "--format",
            "json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["summary"] == {"resources": 1, "findings": 7}
    assert [item["rule_id"] for item in output["findings"]] == [
        f"ACG-KV-{index:03d}" for index in range(1, 8)
    ]


def test_fixture_scan_can_select_sql(capsys):
    exit_code = main(
        [
            "scan",
            "--source",
            "fixture",
            "--service",
            "sql",
            "--format",
            "json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["summary"] == {"resources": 1, "findings": 6}
    assert [item["rule_id"] for item in output["findings"]] == [
        f"ACG-SQL-{index:03d}" for index in range(1, 7)
    ]


def test_fixture_scan_can_evaluate_all_services(capsys):
    exit_code = main(
        [
            "scan",
            "--source",
            "fixture",
            "--service",
            "all",
            "--format",
            "json",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["summary"] == {"resources": 3, "findings": 17}
    assert {item["service"] for item in output["findings"]} == {
        "storage",
        "key_vault",
        "sql",
    }


def test_azure_scan_uses_key_vault_read_only_adapter(capsys, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setenv("RESOURCE_GROUP", "rg-demo")
    monkeypatch.setenv("KEY_VAULT_NAME", "kv-demo")
    runner = object()
    monkeypatch.setattr(cli, "AzureCliJsonRunner", lambda subscription_id: runner)
    collector = Mock()
    collector.collect.return_value = [
        KeyVaultState(
            resource=ResourceRef("key_vault", "rg-demo", "kv-demo"),
            public_network_access="Disabled",
            rbac_authorization_enabled=True,
            purge_protection_enabled=True,
            soft_delete_enabled=True,
            private_endpoint_enabled=True,
            keys_have_expiry=True,
            secrets_have_expiry=True,
        )
    ]
    constructor = Mock(return_value=collector)
    monkeypatch.setattr(cli, "AzureKeyVaultCollector", constructor)

    exit_code = main(
        ["scan", "--source", "azure", "--service", "key-vault", "--format", "json"]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["summary"] == {
        "resources": 1,
        "findings": 0,
    }
    constructor.assert_called_once_with(
        runner,
        "rg-demo",
        "kv-demo",
        "00000000-0000-0000-0000-000000000001",
    )


def test_azure_scan_uses_sql_read_only_adapter(capsys, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setenv("RESOURCE_GROUP", "rg-demo")
    monkeypatch.setenv("SQL_SERVER_NAME", "sql-demo")
    runner = object()
    monkeypatch.setattr(cli, "AzureCliJsonRunner", lambda subscription_id: runner)
    collector = Mock()
    collector.collect.return_value = [
        SqlState(
            resource=ResourceRef("sql", "rg-demo", "sql-demo"),
            auditing_enabled=True,
            defender_enabled=True,
            min_tls_version="1.2",
            public_network_access="Disabled",
            private_endpoint_enabled=True,
            azure_ad_admin_configured=True,
        )
    ]
    constructor = Mock(return_value=collector)
    monkeypatch.setattr(cli, "AzureSqlCollector", constructor)

    exit_code = main(
        ["scan", "--source", "azure", "--service", "sql", "--format", "json"]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["summary"] == {
        "resources": 1,
        "findings": 0,
    }
    constructor.assert_called_once_with(
        runner,
        "rg-demo",
        "sql-demo",
        "00000000-0000-0000-0000-000000000001",
    )


def test_missing_fixture_is_an_operational_failure(capsys, tmp_path):
    missing = tmp_path / "missing.json"

    exit_code = main(["scan", "--source", "fixture", "--fixture", str(missing)])

    assert exit_code == 2
    assert "missing.json" in capsys.readouterr().err


def test_invalid_rule_set_has_configuration_exit_code(capsys, tmp_path):
    rules = tmp_path / "invalid.yaml"
    rules.write_text("schema_version: [", encoding="utf-8")

    exit_code = main(
        ["scan", "--source", "fixture", "--rules", str(rules), "--format", "json"]
    )

    assert exit_code == 3
    assert "Invalid rule set" in capsys.readouterr().err
