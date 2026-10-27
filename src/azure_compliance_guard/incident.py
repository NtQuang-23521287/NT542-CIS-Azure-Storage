"""Source trust and severity decisions for normalized Blob operations."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from azure_compliance_guard.evidence import append_events, make_event, read_events
from azure_compliance_guard.exceptions import ExceptionRepository
from azure_compliance_guard.models import StorageState
from azure_compliance_guard.monitor import SENSITIVE_OPERATIONS, IncidentEvent


class TrustedNetworks:
    def __init__(self, cidrs: list[str]):
        if not cidrs:
            raise ValueError("at least one trusted CIDR is required")
        self.networks = tuple(
            ipaddress.ip_network(value, strict=True) for value in cidrs
        )

    def classify(self, source_ip: str) -> str:
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return "unknown"
        return (
            "trusted"
            if any(address in network for network in self.networks)
            else "untrusted"
        )


def evaluate_incident(
    event: IncidentEvent, policy: TrustedNetworks, *, active_exception: bool
) -> str:
    if (
        event.operation not in SENSITIVE_OPERATIONS
        or not 200 <= event.status_code <= 299
    ):
        return "NORMAL"
    trust = policy.classify(event.source_ip)
    if trust == "trusted":
        return "NORMAL"
    if trust == "unknown":
        return "SUSPICIOUS"
    return "ESCALATED_CRITICAL" if active_exception else "SUSPICIOUS"


NETWORK_RULE = "ACG-STO-003"
_STORAGE_ID = re.compile(
    r"^/subscriptions/([0-9a-f-]{36})/resourcegroups/([^/]+)"
    r"/providers/microsoft\.storage/storageaccounts/([a-z0-9]{3,24})$",
    re.IGNORECASE,
)


def _resource_reference(event: IncidentEvent) -> dict:
    match = _STORAGE_ID.fullmatch(event.resource_id)
    if not match or match.group(3).lower() != event.account:
        raise ValueError("incident resource must be the requested Storage account")
    return {
        "service": "storage",
        "name": event.account,
        "resource_group": match.group(2).lower(),
        "subscription_id": match.group(1).lower(),
    }


def _active_network_exception(
    repo: ExceptionRepository, event: IncidentEvent, now: datetime
):
    for record in repo.list(status="ACTIVE", resource_id=event.resource_id):
        if (
            record.rule_id == NETWORK_RULE
            and record.resource_name.lower() == event.account
            and record.approved_at is not None
            and datetime.fromisoformat(record.approved_at) <= event.occurred_at
            and datetime.fromisoformat(record.expires_at) > now
        ):
            return record
    return None


def _containment_plan(event: IncidentEvent) -> dict:
    # This is advice, not a Phase F executable plan. The operator first re-collects
    # current state and creates an exact approved remediation plan from that state.
    return {
        "incident_key": event.key,
        "resource_id": event.resource_id,
        "rule_id": NETWORK_RULE,
        "action": "disable_public_network_access",
        "execution": "APPROVAL_REQUIRED",
        "verification": "PENDING",
        "steps": [
            "Review incident evidence and confirm dedicated lab scope",
            "Re-collect current Storage state and create a Phase F remediation plan",
            "Approve and apply the exact Phase F plan under its existing gates",
            "Re-collect Storage state and verify public network access is disabled",
        ],
    }


def process_incidents(
    events: list[IncidentEvent],
    policy: TrustedNetworks,
    exceptions: ExceptionRepository,
    state_path: Path,
    evidence_path: Path,
    *,
    mode: str,
) -> list[dict]:
    """Process one batch with a durable key for each fully recorded event.

    The exception transition itself is atomic in ExceptionRepository. Evidence
    and dedup live in separate files, so a process crash between those writes
    still requires operator reconciliation of the private audit trail.
    """
    if mode not in {"azure", "fixture"}:
        raise ValueError("incident mode must be azure or fixture")
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid4())
    now = datetime.now(UTC)
    results = []
    with closing(sqlite3.connect(state_path, timeout=5, autocommit=True)) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS processed_incidents (
            event_key TEXT PRIMARY KEY, processed_at TEXT NOT NULL
            )"""
        )
        db.execute(
            "DELETE FROM processed_incidents WHERE processed_at < ?",
            ((now - timedelta(days=30)).isoformat(),),
        )
        for event in events:
            if not isinstance(event.key, str) or not 1 <= len(event.key) <= 128:
                raise ValueError("incident key is invalid")
            reference = _resource_reference(event)
            if event.occurred_at.tzinfo is None:
                raise ValueError("incident timestamp must include a timezone")
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute(
                    "SELECT 1 FROM processed_incidents WHERE event_key = ?",
                    (event.key,),
                ).fetchone():
                    db.execute("COMMIT")
                    continue
                active = _active_network_exception(exceptions, event, now)
                # Future or stale timestamps can be investigated, but cannot
                # revoke an exception based on a questionable temporal link.
                temporal_match = now - timedelta(days=1) <= event.occurred_at <= now
                severity = evaluate_incident(
                    event,
                    policy,
                    active_exception=active is not None and temporal_match,
                )
                data = {
                    "event_key": event.key,
                    "source_ip": event.source_ip,
                    "identity": event.requester_object_id or None,
                    "operation": event.operation,
                    "severity": severity,
                    "security_events_evaluated": 1,
                }
                source = {
                    "mode": mode,
                    "collector": "azure_monitor"
                    if mode == "azure"
                    else "monitor_fixture",
                }
                evidence = [
                    make_event(
                        "INCIDENT_DETECTED",
                        run_id=run_id,
                        resource=reference,
                        source=source,
                        data=data,
                    )
                ]
                plan = None
                revoked = []
                if severity == "ESCALATED_CRITICAL":
                    evidence.append(
                        make_event(
                            "INCIDENT_ESCALATED",
                            run_id=run_id,
                            resource=reference,
                            source=source,
                            data=data,
                        )
                    )
                    reason = (
                        f"Successful {event.operation} from untrusted source; "
                        f"incident key {event.key}"
                    )
                    closed = exceptions.revoke(
                        active.id,
                        actor="acg-incident",
                        reason=reason,
                        expected_version=active.version,
                        incident=True,
                    )
                    revoked.append(closed.id)
                    evidence.append(
                        make_event(
                            "EXCEPTION_INCIDENT_REVOKED",
                            run_id=run_id,
                            resource=reference,
                            source=source,
                            data={
                                "exception_id": closed.id,
                                "rule_id": closed.rule_id,
                                "actor": "acg-incident",
                                "reason": reason,
                                "event_key": event.key,
                            },
                        )
                    )
                    plan = _containment_plan(event)
                    evidence.append(
                        make_event(
                            "INCIDENT_CONTAINMENT",
                            run_id=run_id,
                            resource=reference,
                            source=source,
                            data={
                                **data,
                                "action": plan["action"],
                                "execution": plan["execution"],
                                "verification": plan["verification"],
                            },
                        )
                    )
                append_events(evidence_path, evidence)
                db.execute(
                    "INSERT INTO processed_incidents VALUES (?, ?)",
                    (event.key, now.isoformat()),
                )
                db.execute("COMMIT")
                results.append(
                    {
                        "event_key": event.key,
                        "severity": severity,
                        "revoked_exception_ids": revoked,
                        "containment_plan": plan,
                    }
                )
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
    return results


def verify_containment(
    event_key: str,
    resource_id: str,
    state: StorageState,
    evidence_path: Path,
    *,
    mode: str,
) -> str:
    """Record a fresh state check after the approved containment is applied."""
    if not re.fullmatch(r"[0-9a-f]{64}", event_key):
        raise ValueError("incident key must be a SHA-256 digest")
    if mode not in {"azure", "fixture"}:
        raise ValueError("verification mode must be azure or fixture")
    match = _STORAGE_ID.fullmatch(resource_id)
    if match is None:
        raise ValueError("invalid Storage resource ID")
    reference = {
        "service": "storage",
        "name": match.group(3).lower(),
        "resource_group": match.group(2).lower(),
        "subscription_id": match.group(1).lower(),
    }
    if (
        state.resource.service != "storage"
        or state.resource.name.lower() != reference["name"]
        or state.resource.resource_group.lower() != reference["resource_group"].lower()
        or (
            mode == "azure"
            and state.resource.subscription_id != reference["subscription_id"]
        )
    ):
        raise ValueError("collected state is for another Storage resource")
    history = read_events(evidence_path)
    matching = [
        item
        for item in history
        if item["event_type"] == "INCIDENT_CONTAINMENT"
        and item["data"].get("event_key") == event_key
        and item["source"]["mode"] == mode
        and item["resource"] == reference
    ]
    if len(matching) != 1:
        raise ValueError("matching containment evidence is missing or ambiguous")
    result = "VERIFIED" if state.public_network_access == "Disabled" else "FAILED"
    append_events(
        evidence_path,
        [
            make_event(
                "INCIDENT_VERIFIED"
                if result == "VERIFIED"
                else "INCIDENT_VERIFICATION_FAILED",
                run_id=str(uuid4()),
                resource=reference,
                source={
                    "mode": mode,
                    "collector": "azure_storage"
                    if mode == "azure"
                    else "storage_fixture",
                },
                data={
                    "event_key": event_key,
                    "action": "disable_public_network_access",
                    "verification": result,
                },
            )
        ],
    )
    return result
