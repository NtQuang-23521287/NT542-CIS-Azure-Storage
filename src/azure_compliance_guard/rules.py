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
    packaged_rules = files("azure_compliance_guard").joinpath("rules")
    catalogs = []
    for name in ("storage.yaml", "key_vault.yaml"):
        path = packaged_rules.joinpath(name)
        with path.open(encoding="utf-8") as file:
            try:
                catalogs.append(_parse_catalog(yaml.safe_load(file)))
            except yaml.YAMLError as exc:
                raise InvalidRuleSetError(
                    f"invalid YAML in packaged rule {name}: {exc}"
                ) from exc
    rules = tuple(rule for catalog in catalogs for rule in catalog.rules)
    _reject_duplicate_rule_ids(rules)
    return RuleCatalog(schema_version=1, rules=rules)


ALLOWED_OPERATORS = {"equals"}
SERVICE_FIELD_TYPES = {
    "storage": {
        "https_only": bool,
        "min_tls_version": str,
        "public_network_access": str,
        "versioning_enabled": bool,
    },
    "key_vault": {
        "public_network_access": str,
        "rbac_authorization_enabled": bool,
        "purge_protection_enabled": bool,
        "soft_delete_enabled": bool,
        "private_endpoint_enabled": bool,
        "keys_have_expiry": bool,
        "secrets_have_expiry": bool,
    },
    "sql": {
        "auditing_enabled": bool,
        "defender_enabled": bool,
        "min_tls_version": str,
        "public_network_access": str,
        "private_endpoint_enabled": bool,
        "azure_ad_admin_configured": bool,
    },
}
SERVICE_HANDLERS = {
    "storage": {
        "enable_https_only",
        "set_minimum_tls_1_2",
        "disable_public_network_access",
        "enable_blob_versioning",
    },
    "key_vault": {
        "disable_key_vault_public_network_access",
        "enable_key_vault_rbac",
        "enable_key_vault_purge_protection",
        "enable_key_vault_soft_delete",
        "configure_key_vault_private_endpoint",
        "set_key_expiry",
        "set_secret_expiry",
    },
    "sql": {
        "enable_sql_auditing",
        "enable_defender_for_sql",
        "set_sql_minimum_tls_1_2",
        "disable_sql_public_network_access",
        "configure_sql_private_endpoint",
        "configure_sql_azure_ad_admin",
    },
}
SERVICE_ID_PREFIX = {
    "storage": "ACG-STO-",
    "key_vault": "ACG-KV-",
    "sql": "ACG-SQL-",
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
    _reject_duplicate_rule_ids(rules)
    return RuleCatalog(schema_version=schema_version, rules=rules)


def _reject_duplicate_rule_ids(rules: tuple[Rule, ...]) -> None:
    identifiers = set()
    duplicates = set()
    for rule in rules:
        if rule.id in identifiers:
            duplicates.add(rule.id)
        identifiers.add(rule.id)
    if duplicates:
        raise InvalidRuleSetError(f"duplicate rule ID: {', '.join(sorted(duplicates))}")


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

    service = _required_string(raw, "service", label)
    if service not in SERVICE_FIELD_TYPES:
        raise InvalidRuleSetError(f"{label}.service is unsupported")
    service_fields = SERVICE_FIELD_TYPES[service]
    field = _required(selector, "field", f"{label}.selector")
    if field not in service_fields:
        raise InvalidRuleSetError(f"unknown {service} selector field: {field!r}")

    handler = _required(remediation, "handler", f"{label}.remediation")
    if handler not in SERVICE_HANDLERS[service]:
        raise InvalidRuleSetError(f"unknown remediation handler: {handler!r}")

    evidence_fields = _required(evidence, "fields", f"{label}.evidence")
    if not isinstance(evidence_fields, list) or not evidence_fields:
        raise InvalidRuleSetError(f"{label}.evidence.fields must be a non-empty list")
    if any(item not in service_fields for item in evidence_fields):
        raise InvalidRuleSetError(f"{label}.evidence.fields contains an unknown field")

    rule_id = _required(raw, "id", label)
    if not isinstance(rule_id, str) or not RULE_ID_PATTERN.fullmatch(rule_id):
        raise InvalidRuleSetError(f"{label} has invalid rule ID")
    if not rule_id.startswith(SERVICE_ID_PREFIX[service]):
        raise InvalidRuleSetError(f"{label} rule ID does not match its service")
    severity = _required_string(raw, "severity", label)
    if severity not in {"WARNING", "CRITICAL"}:
        raise InvalidRuleSetError(f"{label}.severity is unsupported")
    default_mode = _required_string(remediation, "default_mode", f"{label}.remediation")
    if default_mode not in {"plan_only", "manual_only"}:
        raise InvalidRuleSetError(f"{label}.remediation.default_mode is unsupported")
    expected = _required(assertion, "expected", f"{label}.assertion")
    if not isinstance(expected, service_fields[field]):
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
