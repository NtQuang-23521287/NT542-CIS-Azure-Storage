import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml


class InvalidRuleSetError(ValueError):
    """The rule catalog is malformed or violates the supported schema."""


MAX_RULE_FILE_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class Framework:
    name: str
    version: str
    control: str | None


@dataclass(frozen=True, slots=True)
class Assertion:
    operator: str
    expected: object


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    service: str
    severity: str
    framework: Framework
    field: str
    assertion: Assertion
    remediation_handler: str
    remediation_default_mode: str
    evidence_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuleCatalog:
    schema_version: int
    rules: tuple[Rule, ...]


def load_rule_catalog(path: str | Path) -> RuleCatalog:
    source = Path(path)
    if source.stat().st_size > MAX_RULE_FILE_BYTES:
        raise InvalidRuleSetError(
            f"rule catalog exceeds {MAX_RULE_FILE_BYTES} byte limit"
        )
    try:
        with source.open(encoding="utf-8-sig") as file:
            payload = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise InvalidRuleSetError(f"invalid YAML in {source}: {exc}") from exc

    return _parse_catalog(payload)


def load_default_rule_catalog() -> RuleCatalog:
    path = files("azure_compliance_guard").joinpath("rules/storage.yaml")
    with path.open(encoding="utf-8") as file:
        try:
            return _parse_catalog(yaml.safe_load(file))
        except yaml.YAMLError as exc:
            raise InvalidRuleSetError(f"invalid YAML in packaged rules: {exc}") from exc


ALLOWED_OPERATORS = {"equals"}
ALLOWED_HANDLERS = {
    "enable_https_only",
    "set_minimum_tls_1_2",
    "disable_public_network_access",
    "enable_blob_versioning",
}
STORAGE_FIELDS = {
    "https_only",
    "min_tls_version",
    "public_network_access",
    "versioning_enabled",
}
EXPECTED_TYPES = {
    "https_only": bool,
    "min_tls_version": str,
    "public_network_access": str,
    "versioning_enabled": bool,
}
RULE_ID_PATTERN = re.compile(r"^ACG-[A-Z]+-[0-9]{3}$")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidRuleSetError(f"{label} must be a mapping")
    return value


def _required(mapping: dict[str, Any], key: str, label: str) -> Any:
    if key not in mapping:
        raise InvalidRuleSetError(f"{label}.{key} is required")
    return mapping[key]


def _only_keys(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(mapping.keys() - allowed)
    if unknown:
        raise InvalidRuleSetError(f"{label} has unknown keys: {unknown}")


def _required_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = _required(mapping, key, label)
    if not isinstance(value, str) or not value.strip():
        raise InvalidRuleSetError(f"{label}.{key} must be a non-empty string")
    return value


def _parse_catalog(payload: Any) -> RuleCatalog:
    root = _mapping(payload, "catalog")
    _only_keys(root, {"schema_version", "rules"}, "catalog")
    schema_version = _required(root, "schema_version", "catalog")
    if schema_version != 1:
        raise InvalidRuleSetError(f"unsupported schema_version: {schema_version!r}")

    raw_rules = _required(root, "rules", "catalog")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise InvalidRuleSetError("catalog.rules must be a non-empty list")

    rules = tuple(_parse_rule(item, index) for index, item in enumerate(raw_rules))
    identifiers = set()
    duplicates = set()
    for rule in rules:
        if rule.id in identifiers:
            duplicates.add(rule.id)
        identifiers.add(rule.id)
    if duplicates:
        raise InvalidRuleSetError(f"duplicate rule ID: {', '.join(sorted(duplicates))}")
    return RuleCatalog(schema_version=schema_version, rules=rules)


def _parse_rule(value: Any, index: int) -> Rule:
    label = f"rules[{index}]"
    raw = _mapping(value, label)
    _only_keys(
        raw,
        {
            "id",
            "title",
            "service",
            "severity",
            "framework",
            "selector",
            "assertion",
            "remediation",
            "evidence",
        },
        label,
    )
    framework = _mapping(_required(raw, "framework", label), f"{label}.framework")
    selector = _mapping(_required(raw, "selector", label), f"{label}.selector")
    assertion = _mapping(_required(raw, "assertion", label), f"{label}.assertion")
    remediation = _mapping(_required(raw, "remediation", label), f"{label}.remediation")
    evidence = _mapping(_required(raw, "evidence", label), f"{label}.evidence")
    _only_keys(framework, {"name", "version", "control"}, f"{label}.framework")
    _only_keys(selector, {"field"}, f"{label}.selector")
    _only_keys(assertion, {"operator", "expected"}, f"{label}.assertion")
    _only_keys(
        remediation,
        {"handler", "default_mode"},
        f"{label}.remediation",
    )
    _only_keys(evidence, {"fields"}, f"{label}.evidence")

    operator = _required(assertion, "operator", f"{label}.assertion")
    if operator not in ALLOWED_OPERATORS:
        raise InvalidRuleSetError(f"unknown assertion operator: {operator!r}")

    handler = _required(remediation, "handler", f"{label}.remediation")
    if handler not in ALLOWED_HANDLERS:
        raise InvalidRuleSetError(f"unknown remediation handler: {handler!r}")

    field = _required(selector, "field", f"{label}.selector")
    if field not in STORAGE_FIELDS:
        raise InvalidRuleSetError(f"unknown storage selector field: {field!r}")

    evidence_fields = _required(evidence, "fields", f"{label}.evidence")
    if not isinstance(evidence_fields, list) or not evidence_fields:
        raise InvalidRuleSetError(f"{label}.evidence.fields must be a non-empty list")
    if any(item not in STORAGE_FIELDS for item in evidence_fields):
        raise InvalidRuleSetError(f"{label}.evidence.fields contains an unknown field")

    rule_id = _required(raw, "id", label)
    if not isinstance(rule_id, str) or not RULE_ID_PATTERN.fullmatch(rule_id):
        raise InvalidRuleSetError(f"{label} has invalid rule ID")
    service = _required_string(raw, "service", label)
    if service != "storage":
        raise InvalidRuleSetError(f"{label}.service must be 'storage'")
    severity = _required_string(raw, "severity", label)
    if severity not in {"WARNING", "CRITICAL"}:
        raise InvalidRuleSetError(f"{label}.severity is unsupported")
    default_mode = _required_string(remediation, "default_mode", f"{label}.remediation")
    if default_mode not in {"plan_only", "manual_only"}:
        raise InvalidRuleSetError(f"{label}.remediation.default_mode is unsupported")
    expected = _required(assertion, "expected", f"{label}.assertion")
    if not isinstance(expected, EXPECTED_TYPES[field]):
        raise InvalidRuleSetError(f"{label}.assertion has invalid expected value type")
    control = framework.get("control")
    if control is not None and not isinstance(control, str):
        raise InvalidRuleSetError(f"{label}.framework.control must be a string or null")

    return Rule(
        id=rule_id,
        title=_required_string(raw, "title", label),
        service=service,
        severity=severity,
        framework=Framework(
            name=_required_string(framework, "name", f"{label}.framework"),
            version=_required_string(framework, "version", f"{label}.framework"),
            control=control,
        ),
        field=field,
        assertion=Assertion(
            operator=operator,
            expected=expected,
        ),
        remediation_handler=handler,
        remediation_default_mode=default_mode,
        evidence_fields=tuple(evidence_fields),
    )
