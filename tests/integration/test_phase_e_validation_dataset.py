import json
from pathlib import Path

from azure_compliance_guard.collectors import FixtureStorageCollector
from azure_compliance_guard.rules import load_default_rule_catalog
from azure_compliance_guard.scan import evaluate_states


def test_storage_validation_cases_match_reviewed_ground_truth():
    validation_dir = Path(__file__).parents[1] / "fixtures" / "validation"
    manifest = json.loads(
        (validation_dir / "manifest.json").read_text(encoding="utf-8")
    )
    catalog = load_default_rule_catalog()

    observed = {}
    expected = {}
    for case in manifest["cases"]:
        states = FixtureStorageCollector(validation_dir / case["fixture"]).collect()
        findings = evaluate_states(states, catalog)
        observed[case["id"]] = [finding.rule_id for finding in findings]
        expected[case["id"]] = case["expected_finding_ids"]

    assert observed == expected
