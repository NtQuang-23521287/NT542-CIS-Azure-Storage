from azure_compliance_guard.cli import EXIT_FINDINGS, main
from azure_compliance_guard.evidence import read_events


def test_aggregate_fixture_scan_writes_evidence_offline(tmp_path, capsys):
    output = tmp_path / "evidence.jsonl"
    status = main(
        [
            "scan",
            "--source",
            "fixtures/demo_environment.json",
            "--output",
            str(output),
            "--format",
            "json",
        ]
    )
    assert status == EXIT_FINDINGS
    assert "findings" in capsys.readouterr().out
    events = read_events(output)
    assert events[0]["event_type"] == "RUN_STARTED"
    assert len([event for event in events if event["event_type"] == "FINDING"]) == 17
    completed = events[-1]
    assert completed["event_type"] == "RUN_COMPLETED"
    assert completed["data"]["resources_scanned"] == 6
    assert completed["data"]["rules_evaluated"] == 34
    assert completed["data"]["findings"] == 17
    assert completed["data"]["duration_ms"] >= 0
    assert {event["run_id"] for event in events} == {completed["run_id"]}
