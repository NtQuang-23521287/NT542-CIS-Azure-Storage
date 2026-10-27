from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from azure_compliance_guard.evidence import read_events
from azure_compliance_guard.exceptions import ExceptionRepository
from azure_compliance_guard.incident import (
    TrustedNetworks,
    evaluate_incident,
    process_incidents,
)
from azure_compliance_guard.monitor import IncidentEvent

RESOURCE = (
    "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/lab"
    "/providers/Microsoft.Storage/storageAccounts/labstorage123"
).lower()


def event(ip="198.51.100.7", operation="GetBlob", status=200):
    return IncidentEvent(
        occurred_at=datetime.now(UTC),
        account="labstorage123",
        resource_id=RESOURCE,
        operation=operation,
        status_code=status,
        source_ip=ip,
        correlation_id="corr-1",
        operation_count=0,
        requester_object_id="",
        key="event-key",
    )


def test_trusted_network_classifier_handles_ipv4_ipv6_and_malformed():
    policy = TrustedNetworks(["10.0.0.0/8", "2001:db8::/32"])
    assert policy.classify("10.2.3.4") == "trusted"
    assert policy.classify("198.51.100.7") == "untrusted"
    assert policy.classify("2001:db8::1") == "trusted"
    assert policy.classify("2001:4860::1") == "untrusted"
    assert policy.classify("bad-ip") == "unknown"
    with pytest.raises(ValueError):
        TrustedNetworks(["not-a-network"])
    with pytest.raises(ValueError):
        TrustedNetworks(["10.2.3.4/8"])


def test_evaluator_escalates_only_successful_sensitive_untrusted_event_with_exception():
    policy = TrustedNetworks(["10.0.0.0/8"])
    assert (
        evaluate_incident(event(), policy, active_exception=True)
        == "ESCALATED_CRITICAL"
    )
    assert evaluate_incident(event(), policy, active_exception=False) == "SUSPICIOUS"
    assert (
        evaluate_incident(event("10.2.3.4"), policy, active_exception=True) == "NORMAL"
    )
    assert (
        evaluate_incident(event("bad-ip"), policy, active_exception=True)
        == "SUSPICIOUS"
    )
    assert (
        evaluate_incident(
            event(operation="GetAccountInfo"), policy, active_exception=True
        )
        == "NORMAL"
    )
    assert (
        evaluate_incident(event(status=403), policy, active_exception=True) == "NORMAL"
    )


def test_incident_revokes_only_applicable_exception_and_deduplicates(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.db")
    repo.initialize()
    network = repo.request(
        resource_id=RESOURCE,
        resource_name="labstorage123",
        rule_id="ACG-STO-003",
        owner="lab-owner",
        reason="temporary lab access",
        ticket="LAB-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
    )
    network = repo.activate(
        network.id, approved_by="lab-approver", expected_version=network.version
    )
    unrelated = repo.request(
        resource_id=RESOURCE,
        resource_name="labstorage123",
        rule_id="ACG-STO-001",
        owner="lab-owner",
        reason="different control",
        ticket="LAB-2",
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
    )
    unrelated = repo.activate(
        unrelated.id, approved_by="lab-approver", expected_version=unrelated.version
    )
    evidence = tmp_path / "evidence.jsonl"
    state = tmp_path / "incident-state.db"
    policy = TrustedNetworks(["10.0.0.0/8"])
    result = process_incidents([event()], policy, repo, state, evidence, mode="fixture")
    assert result[0]["severity"] == "ESCALATED_CRITICAL"
    assert result[0]["containment_plan"]["action"] == "disable_public_network_access"
    assert result[0]["containment_plan"]["execution"] == "APPROVAL_REQUIRED"
    assert result[0]["containment_plan"]["verification"] == "PENDING"
    assert repo.get(network.id).status == "REVOKED"
    assert repo.get(unrelated.id).status == "ACTIVE"
    assert repo.verify_chain() > 0
    assert [item["event_type"] for item in read_events(evidence)] == [
        "INCIDENT_DETECTED",
        "INCIDENT_ESCALATED",
        "EXCEPTION_INCIDENT_REVOKED",
        "INCIDENT_CONTAINMENT",
    ]
    assert (
        process_incidents([event()], policy, repo, state, evidence, mode="fixture")
        == []
    )
    assert len(read_events(evidence)) == 4


def test_incident_does_not_revoke_for_malformed_ip_or_old_event(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.db")
    repo.initialize()
    requested = repo.request(
        resource_id=RESOURCE,
        resource_name="labstorage123",
        rule_id="ACG-STO-003",
        owner="lab-owner",
        reason="temporary lab access",
        ticket="LAB-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=60),
    )
    active = repo.activate(
        requested.id, approved_by="lab-approver", expected_version=requested.version
    )
    old = replace(
        event(), occurred_at=datetime.now(UTC) - timedelta(minutes=30), key="old-event"
    )
    unknown = replace(event(), source_ip="bad-ip", key="unknown-event")
    outcomes = process_incidents(
        [old, unknown],
        TrustedNetworks(["10.0.0.0/8"]),
        repo,
        tmp_path / "state.db",
        tmp_path / "evidence.jsonl",
        mode="fixture",
    )
    assert [outcome["severity"] for outcome in outcomes] == ["SUSPICIOUS", "SUSPICIOUS"]
    assert repo.get(active.id).status == "ACTIVE"
