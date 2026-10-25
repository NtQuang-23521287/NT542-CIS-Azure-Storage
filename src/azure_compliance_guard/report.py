"""Public, sanitized projection and static HTML rendering of evidence."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

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
_MAPPING_STATES = frozenset({"EXACT", "PARTIAL", "NOT_COMPARABLE", "UNVERIFIED"})


def _known_rule(value: object) -> str | None:
    return value if isinstance(value, str) and value in _RULE_TITLES else None


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
            "rule_id": _known_rule(raw.get("rule_id")),
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
            "rule_id": _known_rule(raw.get("rule_id")),
            "plan": _label(raw["plan_id"], "plan") if raw.get("plan_id") else None,
            "verification_ms": _count(raw.get("verification_ms")),
        }
    if event_type == "VALIDATION_CASE":
        case_id = raw.get("case_id")
        status = raw.get("mapping_status")
        covered = raw.get("covered_rules")
        return {
            "case_id": case_id
            if isinstance(case_id, str)
            and re.fullmatch(r"ACG-VAL-[A-Z0-9-]{1,72}", case_id)
            else _label(case_id, "case"),
            "tp": _count(raw.get("tp")),
            "tn": _count(raw.get("tn")),
            "fp": _count(raw.get("fp")),
            "fn": _count(raw.get("fn")),
            "covered_rules": [rule for rule in covered if _known_rule(rule)]
            if isinstance(covered, list)
            else [],
            "mapping_status": status
            if isinstance(status, str) and status in _MAPPING_STATES
            else "UNVERIFIED",
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
        collector = event["source"].get("collector")
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
                "collector": "Simulated lifecycle"
                if collector == "simulated_lifecycle"
                else "Fixture validation"
                if collector == "validation_fixture"
                else "Scan",
                "data": _public_data(event["event_type"], event["data"]),
            }
        )
    return projected


def build_report_context(events: list[dict]) -> dict:
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
    kinds = [item["event_type"] for item in projected]
    verification_times = [
        item["data"]["verification_ms"]
        for item in projected
        if item["event_type"] == "REMEDIATION_VERIFIED"
        and item["data"]["verification_ms"] is not None
    ]
    verified = kinds.count("REMEDIATION_VERIFIED")
    failed = kinds.count("REMEDIATION_FAILED")
    remediation = {
        "planned": kinds.count("REMEDIATION_PLANNED"),
        "approved": kinds.count("REMEDIATION_APPROVED"),
        "verified": verified,
        "failed": failed,
        "success_rate": f"{verified / (verified + failed) * 100:.1f}%"
        if verified + failed
        else "N/A",
        "mean_verification_ms": round(sum(verification_times) / len(verification_times))
        if verification_times
        else "N/A",
    }
    exception_states = {}
    exception_by_finding = {}
    remediation_by_finding = {}
    for item in sorted(projected, key=lambda value: value["timestamp"]):
        kind = item["event_type"]
        data = item["data"]
        resource = item["resource"]
        key = (resource["name"], data.get("rule_id")) if resource else None
        if kind.startswith("EXCEPTION_"):
            state = kind.removeprefix("EXCEPTION_").replace("_", " ")
            if data.get("exception"):
                exception_states[data["exception"]] = state
            if key and data.get("rule_id"):
                exception_by_finding[key] = state
        if kind.startswith("REMEDIATION_") and key and data.get("rule_id"):
            remediation_by_finding[key] = kind.removeprefix("REMEDIATION_").replace(
                "_", " "
            )
    for item in finding_rows:
        key = (item["resource"]["name"], item["data"]["rule_id"])
        item["exception_state"] = exception_by_finding.get(key, "None recorded")
        item["remediation_state"] = remediation_by_finding.get(key, "None recorded")
    exceptions = {
        "active": sum(state == "ACTIVATED" for state in exception_states.values()),
        "expired": kinds.count("EXCEPTION_EXPIRED"),
        "revoked": kinds.count("EXCEPTION_REVOKED"),
        "incident_revoked": kinds.count("EXCEPTION_INCIDENT_REVOKED"),
    }
    incidents = {
        "security_events_evaluated": sum(
            item["data"]["security_events_evaluated"] or 0
            for item in projected
            if item["event_type"] == "INCIDENT_DETECTED"
        ),
        "escalated": kinds.count("INCIDENT_ESCALATED"),
    }
    cases = [item for item in projected if item["event_type"] == "VALIDATION_CASE"]
    covered_rules = {rule for item in cases for rule in item["data"]["covered_rules"]}
    try:
        acg_version = version("nt542-cis-azure-storage")
    except PackageNotFoundError:
        acg_version = "local checkout"
    validation = {
        "scope": "Offline fixture" if cases else "No validation cases recorded",
        "case_count": len(cases),
        "run_at": min((item["timestamp"] for item in cases), default="Not recorded"),
        "acg_version": acg_version,
        "catalog_version": 1,
        "prowler_version": "Not run",
        "azure_policy_version": "Not run",
        "covered_rules": len(covered_rules),
        "catalog_rules": len(_RULE_TITLES),
        **{
            key: sum(item["data"][key] or 0 for item in cases)
            for key in ("tp", "tn", "fp", "fn")
        },
        "exact_agreement": "UNVERIFIED",
        "cases": [{"timestamp": item["timestamp"], **item["data"]} for item in cases],
    }
    return {
        "summary": summary,
        "findings": finding_rows,
        "timeline": sorted(projected, key=lambda item: item["timestamp"]),
        "remediation": remediation,
        "exceptions": exceptions,
        "incidents": incidents,
        "validation": validation,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "source_label": "Fixture demonstration"
        if all(item["source"] == "fixture" for item in projected)
        else "Local evidence",
    }


def render_report(events: list[dict]) -> str:
    context = build_report_context(events)
    # Jinja's official API recommends explicitly enabling autoescape.
    # https://jinja.palletsprojects.com/en/stable/api/#autoescaping
    environment = Environment(
        loader=PackageLoader("azure_compliance_guard", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    source = environment.loader.get_source(environment, "report.html.j2")[0]
    script = re.search(r"<script>(.*?)</script>", source, re.S)
    if script is None:
        raise EvidenceError("report filter script is missing")
    # CSP hash covers only this trusted, static script; no evidence is embedded.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src
    context["script_hash"] = base64.b64encode(
        hashlib.sha256(script.group(1).encode("utf-8")).digest()
    ).decode("ascii")
    return environment.get_template("report.html.j2").render(**context)
