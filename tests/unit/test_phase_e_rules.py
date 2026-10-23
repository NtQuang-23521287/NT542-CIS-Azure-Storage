from pathlib import Path

import pytest

from azure_compliance_guard.rules import InvalidRuleSetError, load_rule_catalog

VALID_RULE = """
schema_version: 1
rules:
  - id: ACG-STO-001
    title: Require HTTPS traffic only
    service: storage
    severity: CRITICAL
    framework:
      name: CIS Microsoft Azure Storage Services Benchmark
      version: 2.0.0
      control: null
    selector:
      field: https_only
    assertion:
      operator: equals
      expected: true
    remediation:
      handler: enable_https_only
      default_mode: plan_only
    evidence:
      fields: [https_only]
"""


def _write_rule_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_rule_loader_returns_typed_versioned_rules(tmp_path):
    catalog = load_rule_catalog(_write_rule_file(tmp_path, VALID_RULE))

    assert catalog.schema_version == 1
    assert [rule.id for rule in catalog.rules] == ["ACG-STO-001"]
    assert catalog.rules[0].assertion.operator == "equals"
    assert catalog.rules[0].framework.control is None


def test_rule_loader_rejects_malformed_yaml(tmp_path):
    path = _write_rule_file(tmp_path, "schema_version: [")

    with pytest.raises(InvalidRuleSetError, match="YAML"):
        load_rule_catalog(path)


def test_rule_loader_rejects_duplicate_ids(tmp_path):
    duplicate = VALID_RULE + VALID_RULE.split("rules:\n", maxsplit=1)[1]

    with pytest.raises(InvalidRuleSetError, match="duplicate rule ID"):
        load_rule_catalog(_write_rule_file(tmp_path, duplicate))


def test_rule_loader_rejects_unknown_operator(tmp_path):
    content = VALID_RULE.replace("operator: equals", "operator: execute")

    with pytest.raises(InvalidRuleSetError, match="unknown assertion operator"):
        load_rule_catalog(_write_rule_file(tmp_path, content))


def test_rule_loader_rejects_non_allowlisted_remediation_handler(tmp_path):
    content = VALID_RULE.replace(
        "handler: enable_https_only", "handler: az storage account update"
    )

    with pytest.raises(InvalidRuleSetError, match="remediation handler"):
        load_rule_catalog(_write_rule_file(tmp_path, content))


def test_rule_loader_rejects_arbitrary_remediation_command(tmp_path):
    content = VALID_RULE.replace(
        "handler: enable_https_only",
        "handler: enable_https_only\n      command: az storage account update",
    )

    with pytest.raises(InvalidRuleSetError, match="unknown keys.*command"):
        load_rule_catalog(_write_rule_file(tmp_path, content))


def test_rule_loader_rejects_oversized_catalog_before_parsing(tmp_path):
    path = _write_rule_file(tmp_path, VALID_RULE + ("# padding\n" * 120_000))

    with pytest.raises(InvalidRuleSetError, match="exceeds"):
        load_rule_catalog(path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (VALID_RULE.replace("id: ACG-STO-001", "id: 123"), "rule ID"),
        (
            VALID_RULE.replace("expected: true", "expected: TLS1_2"),
            "expected value",
        ),
        (
            VALID_RULE.replace("default_mode: plan_only", "default_mode: execute"),
            "default_mode",
        ),
    ],
)
def test_rule_loader_rejects_invalid_typed_contract(tmp_path, content, message):
    with pytest.raises(InvalidRuleSetError, match=message):
        load_rule_catalog(_write_rule_file(tmp_path, content))
