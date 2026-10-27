import json
from datetime import UTC, datetime, timedelta

from azure_compliance_guard.cli import main
from azure_compliance_guard.evidence import read_events
from azure_compliance_guard.exceptions import ExceptionRepository

RESOURCE = (
    "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/lab"
    "/providers/Microsoft.Storage/storageAccounts/labstorage123"
)
COLUMNS = [
    "TimeGenerated",
    "AccountName",
    "OperationName",
    "StatusCode",
    "CallerIpAddress",
    "CorrelationId",
    "OperationCount",
    "RequesterObjectId",
    "_ResourceId",
]


def test_fixture_incident_cli_revokes_and_reports_without_azure(tmp_path, capsys):
    repo = ExceptionRepository(tmp_path / "exceptions.db")
    repo.initialize()
    pending = repo.request(
        resource_id=RESOURCE,
        resource_name="labstorage123",
        rule_id="ACG-STO-003",
        owner="owner",
        reason="lab",
        ticket="LAB-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
    )
    active = repo.activate(
        pending.id, approved_by="approver", expected_version=pending.version
    )
    fixture = tmp_path / "monitor.json"
    fixture.write_text(
        json.dumps(
            {
                "columns": COLUMNS,
                "rows": [
                    [
                        datetime.now(UTC).isoformat(),
                        "labstorage123",
                        "GetBlob",
                        "200",
                        "198.51.100.7:41234",
                        "corr-1",
                        0,
                        "",
                        RESOURCE,
                    ]
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence.jsonl"
    args = [
        "incident",
        "scan",
        "--source",
        "fixture",
        "--fixture",
        str(fixture),
        "--account",
        "labstorage123",
        "--resource-id",
        RESOURCE,
        "--trusted-cidr",
        "10.0.0.0/8",
        "--exceptions-db",
        str(repo.path),
        "--state-db",
        str(tmp_path / "state.db"),
        "--evidence",
        str(evidence),
    ]
    assert main(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["processed"] == 1
    assert result["escalated"] == 1
    assert repo.get(active.id).status == "REVOKED"
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["processed"] == 0
    assert len(read_events(evidence)) == 4
    html = tmp_path / "report.html"
    assert main(["report", "--input", str(evidence), "--output", str(html)]) == 0
    content = html.read_text(encoding="utf-8")
    assert "INCIDENT ESCALATED" in content
    assert "198.51.100.7" not in content
    capsys.readouterr()

    state_fixture = tmp_path / "storage-state.json"
    state_fixture.write_text(
        json.dumps(
            {
                "resource_group": "lab",
                "storage_accounts": [
                    {
                        "name": "labstorage123",
                        "account": {
                            "supportsHttpsTrafficOnly": True,
                            "minimumTlsVersion": "TLS1_2",
                            "publicNetworkAccess": "Enabled",
                        },
                        "blob_service": {"isVersioningEnabled": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    verify_args = [
        "incident",
        "verify",
        "--source",
        "fixture",
        "--fixture",
        str(state_fixture),
        "--resource-id",
        RESOURCE,
        "--event-key",
        result["results"][0]["event_key"],
        "--evidence",
        str(evidence),
    ]
    assert main(verify_args) == 1
    assert json.loads(capsys.readouterr().out)["verification"] == "FAILED"
    state = json.loads(state_fixture.read_text(encoding="utf-8"))
    state["storage_accounts"][0]["account"]["publicNetworkAccess"] = "Disabled"
    state_fixture.write_text(json.dumps(state), encoding="utf-8")
    assert main(verify_args) == 0
    assert json.loads(capsys.readouterr().out)["verification"] == "VERIFIED"
    assert read_events(evidence)[-1]["event_type"] == "INCIDENT_VERIFIED"
    state["storage_accounts"][0]["account"]["publicNetworkAccess"] = "Enabled"
    state_fixture.write_text(json.dumps(state), encoding="utf-8")
    assert main(verify_args) == 1
    assert json.loads(capsys.readouterr().out)["verification"] == "FAILED"
    assert read_events(evidence)[-1]["event_type"] == "INCIDENT_VERIFICATION_FAILED"


def test_incident_cli_rejects_bad_fixture_without_revocation(tmp_path, capsys):
    repo = ExceptionRepository(tmp_path / "exceptions.db")
    repo.initialize()
    fixture = tmp_path / "bad.json"
    fixture.write_text('{"columns": [], "rows": []}', encoding="utf-8")
    result = main(
        [
            "incident",
            "scan",
            "--source",
            "fixture",
            "--fixture",
            str(fixture),
            "--account",
            "labstorage123",
            "--resource-id",
            RESOURCE,
            "--trusted-cidr",
            "10.0.0.0/8",
            "--exceptions-db",
            str(repo.path),
            "--state-db",
            str(tmp_path / "state.db"),
            "--evidence",
            str(tmp_path / "evidence.jsonl"),
        ]
    )
    assert result == 2
    assert not (tmp_path / "evidence.jsonl").exists()
    capsys.readouterr()
