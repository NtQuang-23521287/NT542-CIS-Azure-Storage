"""Generate a reproducible fixture-only Phase H portfolio sample."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from azure_compliance_guard.collectors import (
    FixtureKeyVaultCollector,
    FixtureSqlCollector,
    FixtureStorageCollector,
)
from azure_compliance_guard.evidence import append_events, make_event
from azure_compliance_guard.report import render_report
from azure_compliance_guard.rules import load_default_rule_catalog
from azure_compliance_guard.scan import evaluate_states

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
RUN_ID = "phase-h-fixture-demo-2026-10-24"
COLLECTORS = {
    "storage": FixtureStorageCollector,
    "key_vault": FixtureKeyVaultCollector,
    "sql": FixtureSqlCollector,
}


def generate_sample(output_dir: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    evidence_path = output_dir / "phase-h-evidence.jsonl"
    report_path = output_dir / "phase-h-report.html"
    if evidence_path.exists() or report_path.exists():
        raise FileExistsError("sample output already exists")
    output_dir.mkdir(parents=True, exist_ok=True)
    catalog = load_default_rule_catalog()
    demo = ROOT / "fixtures" / "demo_environment.json"
    states = [
        state
        for collector in COLLECTORS.values()
        for state in collector(demo).collect()
    ]
    findings = evaluate_states(states, catalog)
    events = []

    def add(
        kind: str,
        data: dict,
        *,
        minute: int,
        resource: dict | None = None,
        collector: str = "demo_environment",
    ) -> None:
        event = make_event(
            kind,
            run_id=RUN_ID,
            resource=resource,
            source={
                "mode": "fixture",
                "collector": collector,
                "catalog_version": catalog.schema_version,
            },
            data=data,
            now=NOW + timedelta(minutes=minute),
        )
        event["event_id"] = str(uuid5(NAMESPACE_URL, f"{RUN_ID}:{len(events)}:{kind}"))
        events.append(event)

    add("RUN_STARTED", {}, minute=0)
    for finding in findings:
        add(
            "FINDING",
            {
                key: value
                for key, value in finding.to_dict().items()
                if key != "resource"
            },
            minute=1,
            resource=finding.resource.to_dict(),
        )
    add(
        "RUN_COMPLETED",
        {
            "status": "COMPLETED",
            "resources_scanned": len(states),
            "rules_evaluated": sum(
                rule.service == state.resource.service
                for state in states
                for rule in catalog.rules
            ),
            "findings": len(findings),
            "duration_ms": 420,
        },
        minute=2,
    )

    manifest = json.loads(
        (ROOT / "tests" / "fixtures" / "validation" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    for index, case in enumerate(manifest["cases"], start=3):
        service = case["service"]
        state = COLLECTORS[service](
            ROOT / "tests" / "fixtures" / "validation" / case["fixture"]
        ).collect()
        observed = {finding.rule_id for finding in evaluate_states(state, catalog)}
        expected = set(case["expected_finding_ids"])
        covered = {rule.id for rule in catalog.rules if rule.service == service}
        add(
            "VALIDATION_CASE",
            {
                "case_id": case["id"],
                "tp": len(observed & expected),
                "tn": len(covered - observed - expected),
                "fp": len(observed - expected),
                "fn": len(expected - observed),
                "covered_rules": sorted(covered),
                "mapping_status": "UNVERIFIED",
            },
            minute=index,
            collector="validation_fixture",
        )

    resource = {
        "service": "storage",
        "resource_group": "rg-acg-demo",
        "name": "stdriftcase",
    }
    rule = "ACG-STO-001"
    add(
        "EXCEPTION_CREATED",
        {
            "exception_id": "demo-exception-1",
            "rule_id": rule,
            "reason": "Fixture drill",
            "fixture_sanitized": True,
        },
        minute=10,
        resource=resource,
        collector="simulated_lifecycle",
    )
    add(
        "EXCEPTION_ACTIVATED",
        {
            "exception_id": "demo-exception-1",
            "rule_id": rule,
            "actor": "fixture-reviewer",
        },
        minute=11,
        resource=resource,
        collector="simulated_lifecycle",
    )
    add(
        "INCIDENT_DETECTED",
        {"security_events_evaluated": 5, "source_ip": "192.0.2.44"},
        minute=12,
        resource=resource,
        collector="simulated_lifecycle",
    )
    add(
        "INCIDENT_ESCALATED",
        {"source_ip": "192.0.2.44"},
        minute=13,
        resource=resource,
        collector="simulated_lifecycle",
    )
    add(
        "EXCEPTION_INCIDENT_REVOKED",
        {"exception_id": "demo-exception-1", "rule_id": rule},
        minute=14,
        resource=resource,
        collector="simulated_lifecycle",
    )
    add(
        "INCIDENT_CONTAINMENT",
        {},
        minute=15,
        resource=resource,
        collector="simulated_lifecycle",
    )
    for minute, kind, data in (
        (16, "REMEDIATION_PLANNED", {"plan_id": "demo-plan-1", "rule_id": rule}),
        (17, "REMEDIATION_DRY_RUN", {"plan_id": "demo-plan-1", "rule_id": rule}),
        (18, "REMEDIATION_APPROVED", {"plan_id": "demo-plan-1", "rule_id": rule}),
        (19, "REMEDIATION_EXECUTION", {"plan_id": "demo-plan-1", "rule_id": rule}),
        (20, "REMEDIATION_RECOLLECTED", {"plan_id": "demo-plan-1", "rule_id": rule}),
        (
            21,
            "REMEDIATION_VERIFIED",
            {"plan_id": "demo-plan-1", "rule_id": rule, "verification_ms": 1200},
        ),
    ):
        add(
            kind,
            data,
            minute=minute,
            resource=resource,
            collector="simulated_lifecycle",
        )
    for number, kind, minute in (
        (2, "EXCEPTION_EXPIRED", 22),
        (3, "EXCEPTION_REVOKED", 25),
    ):
        add(
            "EXCEPTION_CREATED",
            {"exception_id": f"demo-exception-{number}", "rule_id": "ACG-STO-002"},
            minute=minute,
            resource=resource,
            collector="simulated_lifecycle",
        )
        add(
            "EXCEPTION_ACTIVATED",
            {"exception_id": f"demo-exception-{number}", "rule_id": "ACG-STO-002"},
            minute=minute + 1,
            resource=resource,
            collector="simulated_lifecycle",
        )
        add(
            kind,
            {"exception_id": f"demo-exception-{number}", "rule_id": "ACG-STO-002"},
            minute=minute + 2,
            resource=resource,
            collector="simulated_lifecycle",
        )

    append_events(evidence_path, events)
    report_path.write_text(render_report(events), encoding="utf-8")
    return evidence_path, report_path


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "docs" / "samples"
    evidence, report = generate_sample(destination)
    print(f"Created {evidence} and {report}")
