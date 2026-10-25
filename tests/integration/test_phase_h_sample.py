from azure_compliance_guard.evidence import read_events
from scripts.phase_h_sample import generate_sample


def test_sample_is_fixture_only_and_contains_full_lifecycle(tmp_path):
    evidence_path, report_path = generate_sample(tmp_path)
    events = read_events(evidence_path)
    kinds = {item["event_type"] for item in events}

    assert (
        len([item for item in events if item["event_type"] == "VALIDATION_CASE"]) == 6
    )
    assert len([item for item in events if item["event_type"] == "FINDING"]) == 17
    assert {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "EXCEPTION_ACTIVATED",
        "EXCEPTION_EXPIRED",
        "EXCEPTION_REVOKED",
        "EXCEPTION_INCIDENT_REVOKED",
        "REMEDIATION_PLANNED",
        "REMEDIATION_DRY_RUN",
        "REMEDIATION_APPROVED",
        "REMEDIATION_EXECUTION",
        "REMEDIATION_RECOLLECTED",
        "REMEDIATION_VERIFIED",
        "INCIDENT_DETECTED",
        "INCIDENT_ESCALATED",
    } <= kinds
    assert {item["source"]["mode"] for item in events} == {"fixture"}
    html = report_path.read_text(encoding="utf-8")
    assert "17 / 17 internal rules represented" in html
    assert "TP 17" in html and "TN 17" in html
    assert "Prowler Not run" in html
    assert "UNVERIFIED" in html
