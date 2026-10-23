"""Offline-safe remediation plans and their integrity boundary."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from azure_compliance_guard.models import Finding, ResourceState
from azure_compliance_guard.rules import SERVICE_HANDLERS, Rule, RuleCatalog
from azure_compliance_guard.scan import evaluate_states


class InvalidPlanError(ValueError):
    """A plan is malformed, changed, or unsupported."""


# Only these single-property changes may reach an executor. Other YAML handlers
# remain planable but manual-only until their operational prerequisites exist.
EXECUTABLE_ACTIONS = {
    "enable_https_only": ("storage", "https_only", True),
    "set_minimum_tls_1_2": ("storage", "min_tls_version", "TLS1_2"),
    "disable_public_network_access": (
        "storage",
        "public_network_access",
        "Disabled",
    ),
    "disable_key_vault_public_network_access": (
        "key_vault",
        "public_network_access",
        "Disabled",
    ),
    "enable_key_vault_rbac": ("key_vault", "rbac_authorization_enabled", True),
    "set_sql_minimum_tls_1_2": ("sql", "min_tls_version", "1.2"),
    "disable_sql_public_network_access": (
        "sql",
        "public_network_access",
        "Disabled",
    ),
}


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _policy(
    action: str, service: str, field: str, expected: object, actual: object
) -> tuple[str, str, str]:
    executable = actual is not None and EXECUTABLE_ACTIONS.get(action) == (
        service,
        field,
        expected,
    )
    return (
        "APPROVAL_REQUIRED" if executable else "MANUAL_ONLY",
        "HIGH" if "public_network" in action or "rbac" in action else "MEDIUM",
        "COST_APPROVAL_REQUIRED" if "defender" in action else "NO_DIRECT_COST",
    )


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    plan_id: str
    finding_id: str
    rule_id: str
    created_at: str
    expires_at: str
    source: str
    resource: dict
    resource_hash: str
    before: dict
    desired: dict
    action_id: str
    risk_class: str
    approval_requirement: str
    estimated_cost_effect: str
    idempotency_key: str
    status: str
    plan_hash: str

    def to_dict(self) -> dict:
        return asdict(self)


def create_plan(
    finding: Finding,
    state: ResourceState,
    rule: Rule,
    *,
    source: str,
    now: datetime | None = None,
) -> RemediationPlan:
    if source not in {"azure", "fixture"}:
        raise InvalidPlanError("source must be azure or fixture")
    if source == "azure":
        try:
            UUID(state.resource.subscription_id)
        except (TypeError, ValueError) as exc:
            raise InvalidPlanError("live plan requires a subscription GUID") from exc
    if finding.rule_id != rule.id or finding.resource != state.resource:
        raise InvalidPlanError("finding, rule and state must match")
    if rule.service != state.resource.service or rule.field not in state.facts():
        raise InvalidPlanError("rule does not apply to the resource")
    if state.facts()[rule.field] != finding.actual:
        raise InvalidPlanError("finding no longer matches the collected state")
    if rule.assertion.expected != finding.expected:
        raise InvalidPlanError("finding does not match the enabled rule")

    created = (now or datetime.now(UTC)).astimezone(UTC)
    resource = state.resource.to_dict()
    before = state.facts()
    desired = {rule.field: rule.assertion.expected}
    action = rule.remediation_handler
    approval, risk, cost = _policy(
        action, rule.service, rule.field, rule.assertion.expected, finding.actual
    )
    payload = {
        "plan_id": str(uuid4()),
        "finding_id": finding.finding_id,
        "rule_id": rule.id,
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(minutes=15)).isoformat(),
        "source": source,
        "resource": resource,
        "resource_hash": _digest(resource),
        "before": before,
        "desired": desired,
        "action_id": action,
        "risk_class": risk,
        "approval_requirement": approval,
        "estimated_cost_effect": cost,
        "idempotency_key": _digest([resource, rule.id, desired]),
        "status": "PLANNED",
    }
    return RemediationPlan(**payload, plan_hash=_digest(payload))


def read_plan(payload: object) -> RemediationPlan:
    if not isinstance(payload, dict):
        raise InvalidPlanError("plan must be a JSON object")
    expected_keys = set(RemediationPlan.__dataclass_fields__)
    if set(payload) != expected_keys:
        raise InvalidPlanError("plan fields are missing or unknown")
    if any(
        not isinstance(payload[key], str)
        for key in expected_keys - {"resource", "before", "desired"}
    ):
        raise InvalidPlanError("plan metadata must be strings")
    if any(
        not isinstance(payload[key], dict) for key in ("resource", "before", "desired")
    ):
        raise InvalidPlanError("plan state must be JSON objects")
    try:
        UUID(payload["plan_id"])
        created = datetime.fromisoformat(payload["created_at"])
        expires = datetime.fromisoformat(payload["expires_at"])
        if created.tzinfo is None or expires.tzinfo is None:
            raise ValueError("timezone is required")
    except ValueError as exc:
        raise InvalidPlanError("invalid plan ID or timestamp") from exc
    if expires <= created or expires - created > timedelta(minutes=15):
        raise InvalidPlanError("invalid plan expiry")
    if payload["status"] != "PLANNED" or payload["source"] not in {"azure", "fixture"}:
        raise InvalidPlanError("invalid plan status or source")
    if set(payload["resource"]) != {
        "service",
        "resource_group",
        "name",
        "subscription_id",
    }:
        raise InvalidPlanError("invalid resource identity fields")
    if payload["source"] == "azure":
        try:
            UUID(payload["resource"]["subscription_id"])
        except (TypeError, ValueError) as exc:
            raise InvalidPlanError("live plan requires a subscription GUID") from exc
    if payload["resource_hash"] != _digest(payload["resource"]):
        raise InvalidPlanError("resource hash mismatch")
    if payload["plan_hash"] != _digest(
        {key: value for key, value in payload.items() if key != "plan_hash"}
    ):
        raise InvalidPlanError("plan hash mismatch")
    service = payload["resource"].get("service")
    action = payload["action_id"]
    if service not in SERVICE_HANDLERS or action not in SERVICE_HANDLERS[service]:
        raise InvalidPlanError("action is not allowlisted for the service")
    if len(payload["desired"]) != 1:
        raise InvalidPlanError("plan must change exactly one field")
    field, desired = next(iter(payload["desired"].items()))
    if field not in payload["before"]:
        raise InvalidPlanError("before state is missing the planned field")
    expected_policy = _policy(action, service, field, desired, payload["before"][field])
    if (
        payload["approval_requirement"],
        payload["risk_class"],
        payload["estimated_cost_effect"],
    ) != expected_policy:
        raise InvalidPlanError(
            "risk, approval or cost policy does not match the action"
        )
    if payload["idempotency_key"] != _digest(
        [payload["resource"], payload["rule_id"], payload["desired"]]
    ):
        raise InvalidPlanError("idempotency key mismatch")
    if payload["finding_id"] != _digest(
        [payload["rule_id"], payload["resource"], payload["before"].get(field)]
    ):
        raise InvalidPlanError("finding ID mismatch")
    return RemediationPlan(**payload)


@dataclass(frozen=True, slots=True)
class Approval:
    plan_id: str
    plan_hash: str
    approved_by: str
    approved_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def approve_plan(
    plan: RemediationPlan, approved_by: str, *, now: datetime | None = None
) -> Approval:
    read_plan(plan.to_dict())
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not approved_by.strip():
        raise InvalidPlanError("approver is required")
    if current >= datetime.fromisoformat(plan.expires_at):
        raise InvalidPlanError("expired plan cannot be approved")
    if plan.approval_requirement != "APPROVAL_REQUIRED":
        raise InvalidPlanError("manual-only plan cannot be approved for execution")
    return Approval(
        plan.plan_id, plan.plan_hash, approved_by.strip(), current.isoformat()
    )


def read_approval(payload: object) -> Approval:
    if not isinstance(payload, dict) or set(payload) != set(
        Approval.__dataclass_fields__
    ):
        raise InvalidPlanError("invalid approval artifact")
    if any(not isinstance(value, str) or not value for value in payload.values()):
        raise InvalidPlanError("approval fields must be non-empty strings")
    try:
        approved_at = datetime.fromisoformat(payload["approved_at"])
        if approved_at.tzinfo is None:
            raise ValueError("timezone is required")
    except ValueError as exc:
        raise InvalidPlanError("invalid approval timestamp") from exc
    return Approval(**payload)


def has_active_exception_file(
    plan: RemediationPlan, path: Path, *, now: datetime | None = None
) -> bool:
    """Read the legacy exception store strictly; Phase G will replace it."""
    if path.stat().st_size > 1_048_576:
        raise InvalidPlanError("exception store exceeds 1 MiB")
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidPlanError("invalid exception store JSON") from exc
    if not isinstance(entries, list):
        raise InvalidPlanError("exception store must be a list")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("status"), str):
            raise InvalidPlanError("invalid exception entry")
        if entry["status"] != "active":
            continue
        try:
            expiry = datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None or not isinstance(entry.get("resource_name"), str):
                raise ValueError("invalid active exception")
        except (KeyError, AttributeError, ValueError) as exc:
            raise InvalidPlanError("invalid active exception") from exc
        if (
            entry["resource_name"].lower() == plan.resource["name"].lower()
            and expiry > current
        ):
            return True
    return False


@dataclass(frozen=True, slots=True)
class ApplyResult:
    status: str
    detail: str
    attempts: int
    before: dict
    desired: dict
    risk_class: str
    estimated_cost_effect: str
    execution: dict | None

    def to_dict(self) -> dict:
        return asdict(self)


def apply_plan(
    plan: RemediationPlan,
    *,
    approval: Approval | None,
    catalog: RuleCatalog,
    collect: Callable[[], ResourceState],
    execute: Callable[[RemediationPlan], bool | ExecutionResult],
    has_active_exception: Callable[[RemediationPlan], bool],
    dry_run: bool = False,
    now: datetime | None = None,
    max_attempts: int = 3,
    delay_seconds: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> ApplyResult:
    read_plan(plan.to_dict())
    execution_result = None

    def result(status: str, detail: str, attempts: int = 0) -> ApplyResult:
        return ApplyResult(
            status,
            detail,
            attempts,
            plan.before,
            plan.desired,
            plan.risk_class,
            plan.estimated_cost_effect,
            (
                execution_result.to_dict()
                if isinstance(execution_result, ExecutionResult)
                else None
            ),
        )

    if dry_run:
        return result("DRY_RUN", "No Azure mutation requested")
    if max_attempts < 1 or delay_seconds < 0:
        raise ValueError("verification policy must be bounded and non-negative")
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if current_time >= datetime.fromisoformat(plan.expires_at):
        return result("REJECTED", "Plan expired")
    if plan.approval_requirement != "APPROVAL_REQUIRED":
        return result("REJECTED", "Action is manual-only")
    if approval is None:
        return result("REJECTED", "Exact-plan approval is required")
    read_approval(approval.to_dict())
    approved_at = datetime.fromisoformat(approval.approved_at)
    if (
        approval.plan_id != plan.plan_id
        or approval.plan_hash != plan.plan_hash
        or approved_at < datetime.fromisoformat(plan.created_at)
        or approved_at > current_time
        or approved_at >= datetime.fromisoformat(plan.expires_at)
    ):
        return result("REJECTED", "Approval does not match this valid plan")

    matching = [rule for rule in catalog.rules if rule.id == plan.rule_id]
    if len(matching) != 1:
        return result("REJECTED", "Rule is no longer enabled")
    rule = matching[0]
    field, desired = next(iter(plan.desired.items()))
    if (
        rule.service != plan.resource.get("service")
        or rule.field != field
        or rule.assertion.expected != desired
        or rule.remediation_handler != plan.action_id
        or rule.remediation_default_mode == "manual_only"
    ):
        return result("REJECTED", "Rule or handler changed since planning")
    try:
        if has_active_exception(plan):
            return result("REJECTED", "Active exception suppresses remediation")
        current_state = collect()
    except (OSError, RuntimeError, ValueError) as exc:
        return result("REJECTED", f"Precondition check failed ({type(exc).__name__})")
    if (
        current_state.resource.to_dict() != plan.resource
        or current_state.facts() != plan.before
    ):
        return result("STALE", "Resource identity or state changed")
    if (now or datetime.now(UTC)).astimezone(UTC) >= datetime.fromisoformat(
        plan.expires_at
    ):
        return result("REJECTED", "Plan expired during precondition checks")
    try:
        if has_active_exception(plan):
            return result("REJECTED", "Active exception suppresses remediation")
    except (OSError, RuntimeError, ValueError) as exc:
        return result("REJECTED", f"Exception check failed ({type(exc).__name__})")

    try:
        execution_result = execute(plan)
    except (OSError, RuntimeError, ValueError) as exc:
        return result("EXECUTION_FAILED", f"Executor failed ({type(exc).__name__})")
    accepted = (
        execution_result.accepted
        if isinstance(execution_result, ExecutionResult)
        else execution_result
    )
    if not accepted:
        return result("EXECUTION_FAILED", "Executor rejected the update")

    detail = "Rule still fails after accepted update"
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            sleep(delay_seconds)
        try:
            observed = collect()
            if observed.resource.to_dict() != plan.resource:
                detail = "Collector returned a different resource"
                continue
            if not evaluate_states(
                [observed], RuleCatalog(catalog.schema_version, (rule,))
            ):
                return result(
                    "VERIFIED", "Re-collected state passes the same rule", attempt
                )
        except (OSError, RuntimeError, ValueError) as exc:
            detail = f"Post-update collection failed ({type(exc).__name__})"
    return result("VERIFICATION_FAILED", detail, max_attempts)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    accepted: bool
    mechanism: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class AzureExecutor:
    """Execute only reviewed actions; Storage uses SDK, KV/SQL use scoped CLI."""

    def __init__(self, *, storage_client=None, cli_runner=None):
        self.storage_client = storage_client
        self.cli_runner = cli_runner

    def execute(self, plan: RemediationPlan) -> ExecutionResult:
        read_plan(plan.to_dict())
        if plan.source != "azure":
            raise InvalidPlanError("executor requires a live Azure plan")
        if plan.approval_requirement != "APPROVAL_REQUIRED":
            raise InvalidPlanError("manual-only action cannot be executed")
        resource = plan.resource
        group = resource.get("resource_group")
        name = resource.get("name")
        subscription = resource.get("subscription_id")
        if (
            not isinstance(group, str)
            or not re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", group)
            or not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9-]{3,63}", name)
        ):
            raise InvalidPlanError("invalid Azure resource identity")
        try:
            UUID(subscription)
        except (TypeError, ValueError) as exc:
            raise InvalidPlanError("plan must bind a subscription GUID") from exc

        action = plan.action_id
        if action not in EXECUTABLE_ACTIONS:
            raise InvalidPlanError("action has no executor")
        if resource["service"] == "storage":
            if self.storage_client is None:
                raise RuntimeError("Storage SDK client is unavailable")
            from azure.mgmt.storage.models import (
                StorageAccountPropertiesUpdateParameters,
                StorageAccountUpdateParameters,
            )

            property_name = {
                "enable_https_only": "enable_https_traffic_only",
                "set_minimum_tls_1_2": "minimum_tls_version",
                "disable_public_network_access": "public_network_access",
            }.get(action)
            if property_name is None:
                raise InvalidPlanError("unsupported Storage action")
            parameters = StorageAccountUpdateParameters(
                properties=StorageAccountPropertiesUpdateParameters(
                    **{property_name: next(iter(plan.desired.values()))}
                )
            )
            self.storage_client.storage_accounts.update(group, name, parameters)
            return ExecutionResult(True, "azure_sdk", "Update request accepted")

        if self.cli_runner is None or self.cli_runner.subscription_id != subscription:
            raise RuntimeError("subscription-scoped Azure CLI runner is unavailable")
        arguments = {
            "disable_key_vault_public_network_access": [
                "keyvault",
                "update",
                "--resource-group",
                group,
                "--name",
                name,
                "--public-network-access",
                "Disabled",
            ],
            "enable_key_vault_rbac": [
                "keyvault",
                "update",
                "--resource-group",
                group,
                "--name",
                name,
                "--enable-rbac-authorization",
                "true",
            ],
            "set_sql_minimum_tls_1_2": [
                "sql",
                "server",
                "update",
                "--resource-group",
                group,
                "--name",
                name,
                "--minimal-tls-version",
                "1.2",
            ],
            "disable_sql_public_network_access": [
                "sql",
                "server",
                "update",
                "--resource-group",
                group,
                "--name",
                name,
                "--enable-public-network",
                "false",
            ],
        }.get(action)
        if arguments is None:
            raise InvalidPlanError("unsupported CLI action")
        self.cli_runner.run(arguments)
        return ExecutionResult(True, "azure_cli", "Update request accepted")
