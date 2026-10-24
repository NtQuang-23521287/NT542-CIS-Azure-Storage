import json
from dataclasses import replace

from azure_compliance_guard import cli
from azure_compliance_guard.cli import main
from azure_compliance_guard.collectors import FixtureKeyVaultCollector
from azure_compliance_guard.remediation import (
    ExecutionResult,
    approve_plan,
    create_plan,
)
from azure_compliance_guard.rules import load_default_rule_catalog
from azure_compliance_guard.scan import evaluate_states


def test_cli_plan_approve_and_dry_run_never_execute(tmp_path, capsys, monkeypatch):
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"
    monkeypatch.setenv("ALLOW_AZURE_MUTATIONS", "false")

    assert (
        main(
            [
                "remediation",
                "plan",
                "--finding",
                "ACG-STO-001",
                "--source",
                "fixture",
                "--output",
                str(plan_path),
            ]
        )
        == 0
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["rule_id"] == "ACG-STO-001"
    assert plan["status"] == "PLANNED"

    assert (
        main(
            [
                "remediation",
                "approve",
                "--plan",
                str(plan_path),
                "--approver",
                "student-operator",
                "--confirm-hash",
                plan["plan_hash"],
                "--output",
                str(approval_path),
            ]
        )
        == 0
    )
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    assert approval["plan_hash"] == plan["plan_hash"]

    assert (
        main(
            [
                "remediation",
                "apply",
                "--plan",
                str(plan_path),
                "--dry-run",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert output["status"] == "DRY_RUN"
    assert output["desired"] == {"https_only": True}


def test_scan_finding_id_can_select_the_exact_plan(tmp_path, capsys):
    assert main(["scan", "--source", "fixture", "--format", "json"]) == 1
    scan = json.loads(capsys.readouterr().out)
    finding_id = scan["findings"][0]["finding_id"]
    plan_path = tmp_path / "exact-plan.json"

    assert (
        main(
            [
                "remediation",
                "plan",
                "--source",
                "fixture",
                "--finding",
                finding_id,
                "--output",
                str(plan_path),
            ]
        )
        == 0
    )

    assert json.loads(plan_path.read_text(encoding="utf-8"))["finding_id"] == finding_id


def test_cli_rejects_wrong_hash_and_fixture_execution(tmp_path, capsys):
    plan_path = tmp_path / "plan.json"
    assert (
        main(
            [
                "remediation",
                "plan",
                "--finding",
                "ACG-STO-001",
                "--source",
                "fixture",
                "--output",
                str(plan_path),
            ]
        )
        == 0
    )

    assert (
        main(
            [
                "remediation",
                "approve",
                "--plan",
                str(plan_path),
                "--approver",
                "student-operator",
                "--confirm-hash",
                "wrong",
            ]
        )
        == 3
    )
    assert (
        main(
            [
                "remediation",
                "apply",
                "--plan",
                str(plan_path),
                "--execute",
            ]
        )
        == 3
    )
    assert "live Azure plan" in capsys.readouterr().err


def test_cli_execute_checks_approval_and_exception_store_then_verifies_with_fake_azure(
    tmp_path, capsys, monkeypatch
):
    subscription = "00000000-0000-0000-0000-000000000001"
    state = FixtureKeyVaultCollector(
        "src/azure_compliance_guard/fixtures/key_vault_drift.json"
    ).collect()[0]
    state = replace(
        state, resource=replace(state.resource, subscription_id=subscription)
    )
    catalog = load_default_rule_catalog()
    finding = next(
        item
        for item in evaluate_states([state], catalog)
        if item.rule_id == "ACG-KV-001"
    )
    rule = next(item for item in catalog.rules if item.id == finding.rule_id)
    plan = create_plan(finding, state, rule, source="azure")
    approval = approve_plan(plan, "operator")
    plan_path = tmp_path / "plan.json"
    approval_path = tmp_path / "approval.json"
    exceptions_path = tmp_path / "exceptions.json"
    plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    approval_path.write_text(json.dumps(approval.to_dict()), encoding="utf-8")
    exceptions_path.write_text("[]", encoding="utf-8")
    corrected = replace(state, public_network_access="Disabled")
    observations = iter((state, corrected))
    monkeypatch.setattr(cli, "_azure_states", lambda _service: [next(observations)])
    executed = []

    class FakeExecutor:
        def __init__(self, **_kwargs):
            pass

        def execute(self, item):
            executed.append(item.plan_hash)
            return ExecutionResult(True, "fake", "accepted")

    monkeypatch.setattr(cli, "AzureExecutor", FakeExecutor)
    monkeypatch.setattr(
        cli, "AzureCliJsonRunner", lambda _subscription: type("Runner", (), {})()
    )
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", subscription)
    monkeypatch.setenv("ALLOW_AZURE_MUTATIONS", "true")

    exit_code = main(
        [
            "remediation",
            "apply",
            "--plan",
            str(plan_path),
            "--approval",
            str(approval_path),
            "--exceptions",
            str(exceptions_path),
            "--execute",
        ]
    )

    assert exit_code == 0
    assert executed == [plan.plan_hash]
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED"
