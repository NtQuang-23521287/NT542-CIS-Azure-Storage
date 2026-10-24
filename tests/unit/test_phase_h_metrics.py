import base64
import hashlib
import re
from datetime import UTC, datetime, timedelta

from azure_compliance_guard.evidence import make_event
from azure_compliance_guard.report import build_report_context, render_report

NOW = datetime(2026, 10, 24, tzinfo=UTC)
SOURCE = {"mode": "fixture", "collector": "demo"}
RESOURCE = {"service": "storage", "name": "demo", "resource_group": "rg-demo"}


def event(kind, data, *, minute=0, resource=RESOURCE):
    return make_event(
        kind,
        run_id="fixture-run",
        resource=resource,
        source=SOURCE,
        data=data,
        now=NOW + timedelta(minutes=minute),
    )


def test_lifecycle_metrics_join_findings_and_show_unknown_denominators():
    events = [
        event(
            "RUN_COMPLETED",
            {
                "status": "COMPLETED",
                "resources_scanned": 1,
                "rules_evaluated": 2,
                "findings": 1,
                "duration_ms": 270,
            },
            resource=None,
        ),
        event(
            "FINDING",
            {
                "rule_id": "ACG-STO-001",
                "severity": "CRITICAL",
                "actual": False,
                "expected": True,
            },
        ),
        event(
            "EXCEPTION_ACTIVATED",
            {"exception_id": "exc-1", "rule_id": "ACG-STO-001"},
            minute=1,
        ),
        event(
            "EXCEPTION_INCIDENT_REVOKED",
            {"exception_id": "exc-1", "rule_id": "ACG-STO-001"},
            minute=5,
        ),
        event(
            "REMEDIATION_PLANNED",
            {"plan_id": "plan-1", "rule_id": "ACG-STO-001"},
            minute=2,
        ),
        event(
            "REMEDIATION_APPROVED",
            {"plan_id": "plan-1", "rule_id": "ACG-STO-001"},
            minute=3,
        ),
        event(
            "REMEDIATION_VERIFIED",
            {"plan_id": "plan-1", "rule_id": "ACG-STO-001", "verification_ms": 1200},
            minute=6,
        ),
        event(
            "REMEDIATION_FAILED",
            {"plan_id": "plan-2", "rule_id": "ACG-STO-002"},
            minute=7,
        ),
        event("INCIDENT_DETECTED", {"security_events_evaluated": 8}, minute=4),
        event("INCIDENT_ESCALATED", {}, minute=5),
    ]
    context = build_report_context(events)
    assert context["summary"]["compliance"] == "50.0%"
    assert context["remediation"] == {
        "planned": 1,
        "approved": 1,
        "verified": 1,
        "failed": 1,
        "success_rate": "50.0%",
        "mean_verification_ms": 1200,
    }
    assert context["exceptions"] == {
        "active": 0,
        "expired": 0,
        "revoked": 0,
        "incident_revoked": 1,
    }
    assert context["incidents"] == {"security_events_evaluated": 8, "escalated": 1}
    assert context["findings"][0]["exception_state"] == "INCIDENT REVOKED"
    assert context["findings"][0]["remediation_state"] == "VERIFIED"
    assert (
        build_report_context([event("RUN_STARTED", {}, resource=None)])["remediation"][
            "success_rate"
        ]
        == "N/A"
    )


def test_validation_appendix_keeps_all_cases_and_unknown_comparators():
    events = [
        event(
            "VALIDATION_CASE",
            {
                "case_id": "ACG-VAL-STO-SECURE-001",
                "tp": 0,
                "tn": 4,
                "fp": 0,
                "fn": 0,
                "covered_rules": [
                    "ACG-STO-001",
                    "ACG-STO-002",
                    "ACG-STO-003",
                    "ACG-STO-004",
                ],
                "mapping_status": "UNVERIFIED",
            },
            resource=None,
        ),
        event(
            "VALIDATION_CASE",
            {
                "case_id": "ACG-VAL-STO-DRIFT-001",
                "tp": 4,
                "tn": 0,
                "fp": 0,
                "fn": 0,
                "covered_rules": [
                    "ACG-STO-001",
                    "ACG-STO-002",
                    "ACG-STO-003",
                    "ACG-STO-004",
                ],
                "mapping_status": "PARTIAL",
            },
            resource=None,
        ),
    ]
    context = build_report_context(events)
    assert context["validation"]["case_count"] == 2
    assert context["validation"]["tp"] == 4
    assert context["validation"]["tn"] == 4
    assert context["validation"]["covered_rules"] == 4
    assert context["validation"]["exact_agreement"] == "UNVERIFIED"
    assert [case["mapping_status"] for case in context["validation"]["cases"]] == [
        "UNVERIFIED",
        "PARTIAL",
    ]


def test_filter_controls_use_a_matching_csp_script_hash():
    html = render_report(
        [event("FINDING", {"rule_id": "ACG-STO-001", "severity": "CRITICAL"})]
    )
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    expected_hash = base64.b64encode(
        hashlib.sha256(script.encode("utf-8")).digest()
    ).decode("ascii")
    assert f"script-src 'sha256-{expected_hash}'" in html
    assert 'id="service-filter"' in html
    assert 'id="severity-filter"' in html
    assert 'id="status-filter"' in html
    assert 'data-service="storage"' in html
