from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from azure_compliance_guard.collectors import FixtureStorageCollector
from azure_compliance_guard.models import ResourceRef
from azure_compliance_guard.remediation import (
    AzureExecutor,
    InvalidPlanError,
    apply_plan,
    approve_plan,
    create_plan,
    has_active_exception_file,
    read_plan,
)
from azure_compliance_guard.rules import load_default_rule_catalog
from azure_compliance_guard.scan import evaluate_states


def _storage_finding():
    states = FixtureStorageCollector(
        "src/azure_compliance_guard/fixtures/storage_drift.json"
    ).collect()
    catalog = load_default_rule_catalog()
    finding = next(
        item
        for item in evaluate_states(states, catalog)
        if item.rule_id == "ACG-STO-001"
    )
    rule = next(item for item in catalog.rules if item.id == finding.rule_id)
    return states[0], finding, rule


def test_plan_is_hashable_json_and_contains_full_before_state():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)

    plan = create_plan(finding, state, rule, source="fixture", now=now)
    decoded = read_plan(plan.to_dict())

    assert decoded.to_dict() == plan.to_dict()
    assert plan.finding_id
    assert plan.before == state.facts()
    assert plan.desired == {"https_only": True}
    assert plan.action_id == "enable_https_only"
    assert plan.approval_requirement == "APPROVAL_REQUIRED"
    assert plan.expires_at == (now + timedelta(minutes=15)).isoformat()
    assert len(plan.plan_hash) == 64
    assert len(plan.idempotency_key) == 64


def test_modified_plan_is_rejected_even_when_status_is_changed():
    state, finding, rule = _storage_finding()
    payload = create_plan(finding, state, rule, source="fixture").to_dict()
    payload["status"] = "VERIFIED"

    with pytest.raises(InvalidPlanError, match="status"):
        read_plan(payload)


def test_unlisted_action_cannot_be_promoted_to_executable():
    state, finding, rule = _storage_finding()
    payload = create_plan(finding, state, rule, source="fixture").to_dict()
    payload["action_id"] = "arbitrary_command"

    with pytest.raises(InvalidPlanError):
        read_plan(payload)


def test_dry_run_shows_change_without_reading_or_mutating():
    state, finding, rule = _storage_finding()
    plan = create_plan(finding, state, rule, source="fixture")

    def forbidden():
        raise AssertionError("dry-run must not collect or execute")

    result = apply_plan(
        plan,
        approval=None,
        catalog=load_default_rule_catalog(),
        collect=forbidden,
        execute=lambda _plan: forbidden(),
        has_active_exception=lambda _plan: forbidden(),
        dry_run=True,
    )

    assert result.status == "DRY_RUN"
    assert result.before["https_only"] is False
    assert result.desired == {"https_only": True}


def test_unapproved_and_wrong_plan_approval_are_rejected_without_mutation():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    other = create_plan(finding, state, rule, source="fixture", now=now)
    executions = []

    for approval in (None, approve_plan(other, "operator", now=now)):
        result = apply_plan(
            plan,
            approval=approval,
            catalog=load_default_rule_catalog(),
            collect=lambda: state,
            execute=lambda item: executions.append(item),
            has_active_exception=lambda _plan: False,
            now=now,
        )
        assert result.status == "REJECTED"
    assert executions == []


def test_state_change_makes_plan_stale_before_executor_runs():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    altered = type(state)(
        resource=state.resource,
        https_only=True,
        min_tls_version=state.min_tls_version,
        public_network_access=state.public_network_access,
        versioning_enabled=state.versioning_enabled,
    )
    executions = []

    result = apply_plan(
        plan,
        approval=approve_plan(plan, "operator", now=now),
        catalog=load_default_rule_catalog(),
        collect=lambda: altered,
        execute=lambda item: executions.append(item),
        has_active_exception=lambda _plan: False,
        now=now,
    )

    assert result.status == "STALE"
    assert executions == []


def test_accepted_update_is_verified_only_after_rule_passes():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    corrected = type(state)(
        resource=state.resource,
        https_only=True,
        min_tls_version=state.min_tls_version,
        public_network_access=state.public_network_access,
        versioning_enabled=state.versioning_enabled,
    )
    states = iter((state, state, corrected))
    executions = []

    result = apply_plan(
        plan,
        approval=approve_plan(plan, "operator", now=now),
        catalog=load_default_rule_catalog(),
        collect=lambda: next(states),
        execute=lambda item: executions.append(item) or True,
        has_active_exception=lambda _plan: False,
        now=now,
        sleep=lambda _seconds: None,
    )

    assert result.status == "VERIFIED"
    assert result.attempts == 2
    assert executions == [plan]


@pytest.mark.parametrize("failure", ["still_failed", "collector_error"])
def test_accepted_update_without_pass_is_not_verified(failure):
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    calls = 0

    def collect():
        nonlocal calls
        calls += 1
        if calls > 1 and failure == "collector_error":
            raise RuntimeError("collector unavailable")
        return state

    result = apply_plan(
        plan,
        approval=approve_plan(plan, "operator", now=now),
        catalog=load_default_rule_catalog(),
        collect=collect,
        execute=lambda _plan: True,
        has_active_exception=lambda _plan: False,
        now=now,
        sleep=lambda _seconds: None,
        max_attempts=2,
    )

    assert result.status == "VERIFICATION_FAILED"
    assert result.attempts == 2


def test_expired_plan_and_active_exception_never_reach_executor():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    approval = approve_plan(plan, "operator", now=now)
    executor = Mock(return_value=True)

    expired = apply_plan(
        plan,
        approval=approval,
        catalog=load_default_rule_catalog(),
        collect=lambda: state,
        execute=executor,
        has_active_exception=lambda _plan: False,
        now=now + timedelta(minutes=16),
    )
    suppressed = apply_plan(
        plan,
        approval=approval,
        catalog=load_default_rule_catalog(),
        collect=lambda: state,
        execute=executor,
        has_active_exception=lambda _plan: True,
        now=now,
    )

    assert expired.status == suppressed.status == "REJECTED"
    executor.assert_not_called()


def test_storage_executor_uses_sdk_with_only_the_planned_field():
    state, finding, rule = _storage_finding()
    resource = ResourceRef(
        "storage",
        state.resource.resource_group,
        state.resource.name,
        "00000000-0000-0000-0000-000000000001",
    )
    state = replace(state, resource=resource)
    finding = replace(finding, resource=resource)
    plan = create_plan(finding, state, rule, source="azure")
    client = Mock()

    accepted = AzureExecutor(storage_client=client).execute(plan)

    assert accepted.accepted is True
    assert accepted.mechanism == "azure_sdk"
    args = client.storage_accounts.update.call_args.args
    assert args[:2] == (state.resource.resource_group, state.resource.name)
    assert args[2].properties.enable_https_traffic_only is True
    assert args[2].properties.minimum_tls_version is None


def test_fixture_plan_cannot_reach_azure_executor():
    state, finding, rule = _storage_finding()
    plan = create_plan(finding, state, rule, source="fixture")
    client = Mock()

    with pytest.raises(InvalidPlanError, match="live Azure plan"):
        AzureExecutor(storage_client=client).execute(plan)

    client.storage_accounts.update.assert_not_called()


def test_active_legacy_exception_blocks_resource_and_malformed_store_fails_closed(
    tmp_path,
):
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    store = tmp_path / "exceptions.json"
    store.write_text(
        '[{"status":"active","resource_name":"stintentionaldrift",'
        '"expires_at":"2026-10-23T01:00:00+00:00"}]',
        encoding="utf-8",
    )

    assert has_active_exception_file(plan, store, now=now) is True
    store.write_text("{broken", encoding="utf-8")
    with pytest.raises(InvalidPlanError, match="exception"):
        has_active_exception_file(plan, store, now=now)


def test_changed_before_state_fails_plan_hash_check():
    state, finding, rule = _storage_finding()
    payload = create_plan(finding, state, rule, source="fixture").to_dict()
    payload["before"]["https_only"] = True

    with pytest.raises(InvalidPlanError, match="hash"):
        read_plan(payload)


def test_disabled_rule_rejects_approved_plan_without_mutation():
    state, finding, rule = _storage_finding()
    now = datetime(2026, 10, 23, tzinfo=UTC)
    plan = create_plan(finding, state, rule, source="fixture", now=now)
    executor = Mock()

    result = apply_plan(
        plan,
        approval=approve_plan(plan, "operator", now=now),
        catalog=type(load_default_rule_catalog())(1, ()),
        collect=lambda: state,
        execute=executor,
        has_active_exception=lambda _plan: False,
        now=now,
    )

    assert result.status == "REJECTED"
    executor.assert_not_called()


def test_manual_only_defender_plan_cannot_be_approved():
    from azure_compliance_guard.collectors import FixtureSqlCollector

    state = FixtureSqlCollector(
        "src/azure_compliance_guard/fixtures/sql_drift.json"
    ).collect()[0]
    catalog = load_default_rule_catalog()
    finding = next(
        item
        for item in evaluate_states([state], catalog)
        if item.rule_id == "ACG-SQL-002"
    )
    rule = next(item for item in catalog.rules if item.id == finding.rule_id)
    plan = create_plan(finding, state, rule, source="fixture")

    assert plan.approval_requirement == "MANUAL_ONLY"
    assert plan.estimated_cost_effect == "COST_APPROVAL_REQUIRED"
    with pytest.raises(InvalidPlanError, match="manual-only"):
        approve_plan(plan, "operator")


def test_unknown_current_value_is_manual_only():
    state, finding, rule = _storage_finding()
    state = replace(state, https_only=None)
    finding = replace(finding, actual=None)

    plan = create_plan(finding, state, rule, source="fixture")

    assert plan.approval_requirement == "MANUAL_ONLY"
    assert read_plan(plan.to_dict()) == plan


def test_key_vault_executor_uses_fixed_scoped_cli_arguments():
    from azure_compliance_guard.collectors import FixtureKeyVaultCollector

    state = FixtureKeyVaultCollector(
        "src/azure_compliance_guard/fixtures/key_vault_drift.json"
    ).collect()[0]
    resource = replace(
        state.resource, subscription_id="00000000-0000-0000-0000-000000000001"
    )
    state = replace(state, resource=resource)
    catalog = load_default_rule_catalog()
    finding = next(
        item
        for item in evaluate_states([state], catalog)
        if item.rule_id == "ACG-KV-001"
    )
    rule = next(item for item in catalog.rules if item.id == finding.rule_id)
    plan = create_plan(finding, state, rule, source="azure")
    runner = Mock(subscription_id=resource.subscription_id)

    assert AzureExecutor(cli_runner=runner).execute(plan).mechanism == "azure_cli"
    assert runner.run.call_args.args[0] == [
        "keyvault",
        "update",
        "--resource-group",
        resource.resource_group,
        "--name",
        resource.name,
        "--public-network-access",
        "Disabled",
    ]
