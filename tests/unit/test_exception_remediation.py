from datetime import UTC, datetime, timedelta

import exception_manager
import incident_evaluator
import incident_response
import pytest
import remediation

from azure_compliance_guard.exceptions import ExceptionRepository, ExceptionStoreError


@pytest.fixture
def exception_store(tmp_path, monkeypatch):
    path = tmp_path / "exceptions.sqlite3"
    now = datetime(2030, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(exception_manager, "EXCEPTIONS_DB", str(path))
    monkeypatch.setattr(
        exception_manager, "EXCEPTIONS_FILE", str(tmp_path / "exceptions.json")
    )
    monkeypatch.setattr(exception_manager, "_now", lambda: now)
    ExceptionRepository(path).initialize()
    return path, now


def test_active_exception_is_found_and_expired_exception_is_not(exception_store):
    path, now = exception_store
    requested = exception_manager.create_exception(
        "storage",
        "storage-demo",
        "TLS drift",
        15,
        "lab",
        owner="student",
        ticket="LAB-1",
    )
    assert requested["status"] == "requested"
    assert exception_manager.find_active_exception("storage-demo", "TLS drift") is None
    ExceptionRepository(path).activate(
        requested["id"], approved_by="reviewer", expected_version=1, now=now
    )

    assert (
        exception_manager.find_active_exception("storage-demo", "TLS drift")["id"]
        == requested["id"]
    )
    assert exception_manager.find_active_exception("storage-demo", "PNA drift") is None
    assert [item["status"] for item in exception_manager.load_exceptions()] == [
        "active"
    ]


def test_revoking_active_exception_records_reason(exception_store):
    path, now = exception_store
    requested = exception_manager.create_exception(
        "storage",
        "storage-demo",
        "TLS drift",
        15,
        "lab",
        owner="student",
        ticket="LAB-1",
    )
    ExceptionRepository(path).activate(
        requested["id"], approved_by="reviewer", expected_version=1, now=now
    )

    revoked = exception_manager.revoke_active_exceptions_for_resource(
        "storage-demo", "incident"
    )

    assert len(revoked) == 1
    assert revoked[0]["status"] == "revoked"
    assert revoked[0]["revoked_reason"] == "incident"
    assert exception_manager.find_active_exception_for_resource("storage-demo") is None
    assert ExceptionRepository(path).verify_chain() == 3


def test_legacy_json_requires_review_and_missing_db_fails_closed(exception_store):
    path, _ = exception_store
    legacy = path.with_suffix(".json")
    legacy.write_text("[]", encoding="utf-8")
    with pytest.raises(ExceptionStoreError, match="legacy JSON"):
        exception_manager.load_exceptions()
    legacy.unlink()
    path.unlink()
    with pytest.raises(ExceptionStoreError, match="unavailable"):
        exception_manager.find_active_exception_for_resource("storage-demo")


def test_legacy_refresh_expires_active_request_with_audit(exception_store, monkeypatch):
    path, now = exception_store
    requested = exception_manager.create_exception(
        "storage",
        "storage-demo",
        "TLS drift",
        15,
        "lab",
        owner="student",
        ticket="LAB-1",
    )
    repo = ExceptionRepository(path)
    repo.activate(requested["id"], approved_by="reviewer", expected_version=1, now=now)
    monkeypatch.setattr(exception_manager, "_now", lambda: now + timedelta(minutes=16))

    assert exception_manager.find_active_exception("storage-demo", "TLS drift") is None
    assert repo.get(requested["id"]).status == "EXPIRED"
    assert repo.verify_chain() == 3


def test_sensitive_successful_access_escalates_with_evidence():
    signals = [
        {
            "untrusted_source": True,
            "result": "Success",
            "operation": "GetBlob",
            "source_ip": "192.0.2.10",
        },
        {"untrusted_source": False, "result": "Success", "operation": "GetBlob"},
        {"untrusted_source": True, "result": "Failure", "operation": "GetBlob"},
    ]

    escalated, issues = incident_evaluator.evaluate_storage_incidents(signals)

    assert escalated is True
    assert len(issues) == 1
    assert issues[0]["severity"] == "ESCALATED_CRITICAL"
    assert issues[0]["evidence"]["source_ip"] == "192.0.2.10"


def test_incident_revokes_exception_and_logs_plan_without_azure(monkeypatch):
    events = []
    revoked = []
    monkeypatch.setattr(
        incident_response,
        "find_active_exception_for_resource",
        lambda name: {"id": "exc-1"},
    )
    monkeypatch.setattr(
        incident_response,
        "revoke_active_exceptions_for_resource",
        lambda name, reason: revoked.append((name, reason)) or [{"id": "exc-1"}],
    )
    monkeypatch.setattr(
        incident_response,
        "_run_containment",
        lambda *args, **kwargs: ("PLANNED", "az storage account update"),
    )
    monkeypatch.setattr(
        incident_response,
        "log_incident_event",
        lambda title, fields: events.append((title, fields)),
    )

    incident_response.handle_incident(
        "rg-demo",
        "storage-demo",
        {"name": "Suspicious access", "service": "storage"},
    )

    assert revoked[0][0] == "storage-demo"
    assert events[0][0] == "ESCALATED_CRITICAL_DETECTED"
    assert events[0][1]["Containment"] == "PLANNED"
    assert events[0][1]["Revoked"] == "1 active exception(s)"


def test_legacy_remediation_executor_is_disabled():
    with pytest.raises(RuntimeError, match="Legacy remediation execution is disabled"):
        remediation._run_command(
            ["storage", "account", "update"], "PNA drift", "storage-demo"
        )


def test_active_exception_skips_remediation_and_records_evidence(monkeypatch):
    events = []
    monkeypatch.setattr(
        remediation,
        "find_active_exception",
        lambda *args: {"id": "exc-1", "reason": "approved lab"},
    )
    monkeypatch.setattr(remediation, "remaining_minutes", lambda exception: 10)
    monkeypatch.setattr(
        remediation,
        "_run_command",
        lambda *args: pytest.fail("Azure mutation attempted"),
    )
    monkeypatch.setattr(
        remediation,
        "log_exception_event",
        lambda title, fields: events.append((title, fields)),
    )

    remediation.remediate_config(
        "rg-demo",
        "storage-demo",
        [
            {"name": "Public Network Access mismatch", "severity": "CRITICAL"},
        ],
        allow_mutation=True,
    )

    assert events[0][0] == "REMEDIATION_SKIPPED"
    assert events[0][1]["Exception"] == "exc-1"
