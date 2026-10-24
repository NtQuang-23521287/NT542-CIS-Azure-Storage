from datetime import UTC, datetime

from azure_compliance_guard.evidence import make_event
from azure_compliance_guard.report import public_events, render_report

NOW = datetime(2026, 10, 24, tzinfo=UTC)
SOURCE = {"mode": "fixture", "collector": "storage", "catalog_version": 1}


def test_public_report_omits_sensitive_fields_and_uses_static_assets():
    secret_subscription = "12345678-1234-1234-1234-123456789abc"
    secret_resource = "storage-account-private"
    secret_identity = "person@example.test"
    secret_uri = "https://private.example.test/secret-object"
    event = make_event(
        "FINDING",
        run_id="run-secret",
        resource={
            "service": "storage",
            "resource_group": "private-resource-group",
            "name": secret_resource,
            "subscription_id": secret_subscription,
        },
        source=SOURCE,
        data={
            "rule_id": "ACG-STO-001",
            "title": "<script>alert(1)</script>",
            "severity": "CRITICAL",
            "actual": secret_uri,
            "expected": "Enabled",
            "status": "FAIL",
            "tenant_id": "private-tenant",
            "upn": secret_identity,
            "source_ip": "192.0.2.44",
            "object_key": "secret-object",
            "reason": "private exception reason",
        },
        now=NOW,
    )
    public = public_events([event])
    html = render_report([event])

    assert public[0]["resource"]["name"].startswith("storage-")
    assert "sub-" in public[0]["resource"]["subscription"]
    for secret in (
        secret_subscription,
        secret_resource,
        secret_identity,
        secret_uri,
        "private-tenant",
        "192.0.2.44",
        "private exception reason",
        "<script>alert(1)</script>",
    ):
        assert secret not in html
    assert "Content-Security-Policy" in html
    assert "<style>" in html
    assert "https://cdn" not in html


def test_ip_mask_and_exception_reason_redaction():
    event = make_event(
        "INCIDENT_ESCALATED",
        run_id="run-1",
        resource=None,
        source={"mode": "azure", "collector": "storage"},
        data={"source_ip": "203.0.113.91", "identity": "admin@example.test"},
        now=NOW,
    )
    exception = make_event(
        "EXCEPTION_CREATED",
        run_id="run-1",
        resource=None,
        source={"mode": "azure", "collector": "storage"},
        data={"reason": "password=topsecret"},
        now=NOW,
    )
    public = public_events([event, exception])
    assert public[0]["data"]["source_ip"] == "203.0.113.x"
    assert public[0]["data"]["identity"].startswith("identity-")
    assert public[1]["data"]["reason"] == "Redacted"
