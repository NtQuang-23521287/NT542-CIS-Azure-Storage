"""Operator commands exercise the SQLite lifecycle through the public CLI."""

import json

from azure_compliance_guard.cli import EXIT_OK, EXIT_OPERATIONAL_ERROR, main


def invoke(capsys, *args):
    status = main(["exception", *args])
    output = capsys.readouterr()
    return status, output


def test_exception_cli_lifecycle_and_verify(tmp_path, capsys):
    db = str(tmp_path / "exceptions.sqlite3")
    common = ("--db", db)
    assert invoke(capsys, "init", *common)[0] == EXIT_OK

    status, output = invoke(
        capsys,
        "request",
        *common,
        "--resource-id",
        "/subscriptions/demo/resourcegroups/lab/providers/microsoft.storage/storageaccounts/demo",
        "--resource-name",
        "demo",
        "--rule-id",
        "ACG-STO-001",
        "--owner",
        "student",
        "--reason",
        "lab exercise",
        "--ticket",
        "LAB-1",
        "--minutes",
        "30",
    )
    assert status == EXIT_OK
    requested = json.loads(output.out)
    assert requested["status"] == "REQUESTED"

    status, output = invoke(
        capsys,
        "activate",
        *common,
        "--id",
        requested["id"],
        "--approved-by",
        "reviewer",
        "--expected-version",
        "1",
    )
    assert status == EXIT_OK
    assert json.loads(output.out)["status"] == "ACTIVE"

    status, output = invoke(capsys, "list", *common, "--status", "ACTIVE")
    assert status == EXIT_OK
    assert [item["id"] for item in json.loads(output.out)] == [requested["id"]]

    status, output = invoke(
        capsys,
        "revoke",
        *common,
        "--id",
        requested["id"],
        "--actor",
        "operator",
        "--reason",
        "closed",
        "--expected-version",
        "2",
    )
    assert status == EXIT_OK
    assert json.loads(output.out)["status"] == "REVOKED"

    status, output = invoke(capsys, "verify-chain", *common)
    assert status == EXIT_OK
    assert json.loads(output.out)["events"] == 3


def test_exception_cli_missing_database_is_operational_error(tmp_path, capsys):
    db = str(tmp_path / "missing.sqlite3")
    status, output = invoke(capsys, "list", "--db", db)
    assert status == EXIT_OPERATIONAL_ERROR
    assert "Operational failure" in output.err
    assert not (tmp_path / "missing.sqlite3").exists()
