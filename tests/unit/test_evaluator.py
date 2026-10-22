import pytest
from evaluator import evaluate_config, evaluate_key_vault_config, evaluate_sql_config


@pytest.fixture
def storage_expected():
    return {
        "https_only": True,
        "min_tls_version": "TLS1_2",
        "public_network_access": "Disabled",
        "versioning_enabled": True,
    }


def test_matching_storage_configuration_passes(storage_expected):
    assert evaluate_config(storage_expected.copy(), storage_expected) == (False, [])


def test_storage_drift_fails_with_configured_severity(storage_expected):
    actual = {**storage_expected, "https_only": False, "versioning_enabled": False}

    failed, issues = evaluate_config(actual, storage_expected)

    assert failed is True
    assert [(issue["name"], issue["severity"]) for issue in issues] == [
        ("HTTPS traffic only setting mismatch", "CRITICAL"),
        ("Blob versioning disabled", "WARNING"),
    ]


@pytest.mark.parametrize(
    ("actual", "error"),
    [(None, TypeError), ([], TypeError), ({"https_only": True}, ValueError)],
)
def test_malformed_storage_configuration_fails_clearly(storage_expected, actual, error):
    with pytest.raises(error, match="configuration keys"):
        evaluate_config(actual, storage_expected)


def test_unknown_storage_property_does_not_silently_pass(storage_expected):
    with pytest.raises(ValueError, match="unknown"):
        evaluate_config({**storage_expected, "unknown": False}, storage_expected)


@pytest.mark.parametrize(
    ("evaluate", "expected", "changed_key", "issue_name"),
    [
        (
            evaluate_key_vault_config,
            {
                "public_network_access": "Disabled",
                "enable_rbac_authorization": True,
                "enable_soft_delete": True,
                "enable_purge_protection": True,
                "private_endpoint_enabled": True,
                "keys_have_expiry": True,
                "secrets_have_expiry": True,
            },
            "enable_rbac_authorization",
            "Key Vault RBAC authorization disabled",
        ),
        (
            evaluate_sql_config,
            {
                "auditing_enabled": True,
                "defender_enabled": True,
                "min_tls_version": "1.2",
                "public_network_access": "Disabled",
                "private_endpoint_enabled": True,
                "azure_ad_admin_configured": True,
            },
            "auditing_enabled",
            "SQL auditing disabled",
        ),
    ],
)
def test_other_services_pass_and_report_critical_drift(
    evaluate, expected, changed_key, issue_name
):
    assert evaluate(expected.copy(), expected) == (False, [])

    failed, issues = evaluate({**expected, changed_key: False}, expected)

    assert failed is True
    assert issues == [
        {
            "name": issue_name,
            "severity": "CRITICAL",
            "service": "key_vault"
            if changed_key == "enable_rbac_authorization"
            else "sql",
        }
    ]
