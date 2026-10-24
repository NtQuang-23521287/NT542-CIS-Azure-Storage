"""Public, sanitized projection and static HTML rendering of evidence."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime

from jinja2 import Environment, PackageLoader, StrictUndefined

from azure_compliance_guard.evidence import EvidenceError
from azure_compliance_guard.rules import load_default_rule_catalog

_RULE_TITLES = {rule.id: rule.title for rule in load_default_rule_catalog().rules}
_SAFE_VALUES = frozenset(
    {
        "Enabled",
        "Disabled",
        "TLS1_0",
        "TLS1_1",
        "TLS1_2",
        "TLS1_3",
        "1.0",
        "1.1",
        "1.2",
        "1.3",
        "Free",
        "Standard",
    }
)
_SAFE_SERVICES = frozenset({"storage", "key_vault", "sql"})
_SAFE_SEVERITIES = frozenset({"PASS", "WARNING", "CRITICAL", "ESCALATED_CRITICAL"})


def _label(value: object, prefix: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _mask_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError, TypeError:
        return "Redacted"
    if isinstance(address, ipaddress.IPv4Address):
        octets = str(address).split(".")
        return ".".join([*octets[:3], "x"])
    return f"{ipaddress.IPv6Network((address, 64), strict=False).network_address}/64"


def _safe_value(value: object) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value) if abs(value) < 1_000_000 else "Redacted"
    if isinstance(value, str) and value in _SAFE_VALUES:
        return value
    return "Redacted"


def _count(value: object) -> int | None:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value < 1_000_000
    ):
        return value
    return None


def _public_data(event_type: str, raw: dict) -> dict:
    if event_type == "FINDING":
        rule_id = raw.get("rule_id")
        if not isinstance(rule_id, str) or rule_id not in _RULE_TITLES:
            rule_id = "CUSTOM-RULE"
        severity = raw.get("severity")
        return {
            "rule_id": rule_id,
            "title": _RULE_TITLES.get(rule_id, "Custom rule"),
            "severity": severity
            if isinstance(severity, str) and severity in _SAFE_SEVERITIES
            else "WARNING",
            "status": "FAIL",
            "actual": _safe_value(raw.get("actual")),
            "expected": _safe_value(raw.get("expected")),
        }
    if event_type == "RUN_COMPLETED":
        raw_status = raw.get("status")
        return {
            "status": raw_status
            if isinstance(raw_status, str) and raw_status in {"COMPLETED", "ERROR"}
            else "ERROR",
            **{
                key: _count(raw.get(key))
                for key in (
                    "resources_scanned",
                    "rules_evaluated",
                    "findings",
                    "duration_ms",
                )
            },
        }
    if event_type.startswith("EXCEPTION_"):
        return {
            "reason": "Sanitized fixture reason"
            if raw.get("reason") and raw.get("fixture_sanitized") is True
            else "Redacted",
            "actor": _label(raw["actor"], "identity") if raw.get("actor") else None,
            "exception": _label(raw["exception_id"], "exception")
            if raw.get("exception_id")
            else None,
        }
    if event_type.startswith("INCIDENT_"):
        return {
            "source_ip": _mask_ip(raw.get("source_ip"))
            if raw.get("source_ip")
            else None,
            "identity": _label(raw["identity"], "identity")
            if raw.get("identity")
            else None,
            "security_events_evaluated": _count(raw.get("security_events_evaluated")),
        }
    if event_type.startswith("REMEDIATION_"):
        return {
            "plan": _label(raw["plan_id"], "plan") if raw.get("plan_id") else None,
            "verification_ms": _count(raw.get("verification_ms")),
        }
    return {}


def public_events(events: list[dict]) -> list[dict]:
    """Discard unrecognized fields before any public HTML is rendered."""
    projected = []
    for event in events:
        raw_resource = event["resource"]
        service = raw_resource.get("service") if raw_resource else None
        safe_service = service if service in _SAFE_SERVICES else "resource"
        resource = None
        if raw_resource:
            resource = {
                "service": safe_service,
                "name": _label(raw_resource["name"], safe_service),
                "group": _label(raw_resource["resource_group"], "group"),
                "subscription": _label(raw_resource["subscription_id"], "sub")
                if raw_resource.get("subscription_id")
                else "Not recorded",
            }
        mode = event["source"].get("mode")
        projected.append(
            {
                "event_id": _label(event["event_id"], "event"),
                "run_id": _label(event["run_id"], "run"),
                "timestamp": datetime.fromisoformat(event["timestamp"]).isoformat(),
                "event_type": event["event_type"],
                "resource": resource,
                "source": "fixture"
                if mode == "fixture"
                else "azure"
                if mode == "azure"
                else "unknown",
                "data": _public_data(event["event_type"], event["data"]),
            }
        )
    return projected


def render_report(events: list[dict]) -> str:
    if not events:
        raise EvidenceError("evidence stream is empty")
    projected = public_events(events)
    completed = [
        event["data"]
        for event in projected
        if event["event_type"] == "RUN_COMPLETED"
        and event["data"]["status"] == "COMPLETED"
    ]
    rules_evaluated = sum(item["rules_evaluated"] or 0 for item in completed)
    finding_rows = [event for event in projected if event["event_type"] == "FINDING"]
    findings = len(finding_rows)
    passing = max(0, rules_evaluated - findings)
    summary = {
        "compliance": f"{passing / rules_evaluated * 100:.1f}%"
        if rules_evaluated
        else "N/A",
        "pass": passing if rules_evaluated else "N/A",
        "warning": sum(item["data"]["severity"] == "WARNING" for item in finding_rows),
        "critical": sum(
            item["data"]["severity"] in {"CRITICAL", "ESCALATED_CRITICAL"}
            for item in finding_rows
        ),
        "resources": sum(item["resources_scanned"] or 0 for item in completed),
        "rules": rules_evaluated,
        "duration_ms": sum(item["duration_ms"] or 0 for item in completed),
    }
    # Jinja's official API recommends explicitly enabling autoescape.
    # https://jinja.palletsprojects.com/en/stable/api/#autoescaping
    environment = Environment(
        loader=PackageLoader("azure_compliance_guard", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
    )
    return environment.get_template("report.html.j2").render(
        summary=summary,
        findings=finding_rows,
        timeline=sorted(projected, key=lambda item: item["timestamp"]),
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        source_label="Fixture demonstration"
        if all(item["source"] == "fixture" for item in projected)
        else "Local evidence",
    )
