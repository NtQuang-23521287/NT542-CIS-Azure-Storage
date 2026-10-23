from collections.abc import Iterable

from azure_compliance_guard.models import Finding, StorageState
from azure_compliance_guard.rules import RuleCatalog


def evaluate_states(
    states: Iterable[StorageState], catalog: RuleCatalog
) -> list[Finding]:
    findings = []
    for state in states:
        facts = state.facts()
        for rule in catalog.rules:
            if rule.service != state.resource.service:
                continue
            actual = facts[rule.field]
            if (
                rule.assertion.operator == "equals"
                and actual != rule.assertion.expected
            ):
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        service=rule.service,
                        severity=rule.severity,
                        resource=state.resource,
                        actual=actual,
                        expected=rule.assertion.expected,
                    )
                )
    return findings
