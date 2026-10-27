from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from azure_compliance_guard.monitor import (
    MonitorQueryError,
    build_storage_query,
    normalize_storage_rows,
    query_storage_events,
)

ACCOUNT = "labstorage123"
RESOURCE = (
    "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/lab"
    "/providers/Microsoft.Storage/storageAccounts/labstorage123"
)
COLUMNS = (
    "TimeGenerated",
    "AccountName",
    "OperationName",
    "StatusCode",
    "CallerIpAddress",
    "CorrelationId",
    "OperationCount",
    "RequesterObjectId",
    "_ResourceId",
)


def test_kql_bounds_scope_and_projects_only_needed_columns():
    query = build_storage_query(ACCOUNT, 45)
    assert query.startswith("StorageBlobLogs\n")
    assert "ago(45m)" in query
    assert 'AccountName == "labstorage123"' in query
    assert "StatusCode" in query and "between (200 .. 299)" in query
    assert '"ListBlobs"' in query
    assert "CallerIpAddress" in query and "CorrelationId" in query
    assert "Uri" not in query and "ObjectKey" not in query
    with pytest.raises(ValueError):
        build_storage_query('x" | union AzureActivity', 45)
    with pytest.raises(ValueError):
        build_storage_query(ACCOUNT, 0)


def test_normalization_checks_scope_and_preserves_distinct_operation_counts():
    rows = [
        [
            datetime(2026, 10, 27, tzinfo=UTC),
            ACCOUNT,
            "GetBlob",
            "200",
            "198.51.100.4:49221",
            "corr-1",
            0,
            "object-id",
            RESOURCE,
        ],
        [
            datetime(2026, 10, 27, tzinfo=UTC),
            ACCOUNT,
            "GetBlob",
            "200",
            "198.51.100.4:49221",
            "corr-1",
            1,
            "object-id",
            RESOURCE,
        ],
    ]
    events = normalize_storage_rows(COLUMNS, rows, ACCOUNT, RESOURCE)
    assert len(events) == 2
    assert events[0].source_ip == "198.51.100.4"
    assert events[0].key != events[1].key
    assert events[0].resource_id == RESOURCE.lower()


def test_normalization_rejects_unexpected_account_or_resource():
    row = [
        datetime(2026, 10, 27, tzinfo=UTC),
        "otheraccount",
        "GetBlob",
        "200",
        "198.51.100.4",
        "corr-1",
        0,
        "",
        RESOURCE,
    ]
    with pytest.raises(MonitorQueryError):
        normalize_storage_rows(COLUMNS, [row], ACCOUNT, RESOURCE)


def test_normalization_accepts_blob_service_scope_and_ipv6_port():
    row = [
        datetime(2026, 10, 27, tzinfo=UTC),
        ACCOUNT,
        "ListBlobs",
        "200",
        "[2001:db8::1]:49152",
        "corr-2",
        0,
        "",
        RESOURCE + "/blobServices/default",
    ]
    normalized = normalize_storage_rows(COLUMNS, [row], ACCOUNT, RESOURCE)
    assert normalized[0].source_ip == "2001:db8::1"
    row[5] = "x" * 257
    with pytest.raises(MonitorQueryError):
        normalize_storage_rows(COLUMNS, [row], ACCOUNT, RESOURCE)
    row[1] = ACCOUNT
    row[-1] = RESOURCE.replace("labstorage123", "otheraccount")
    with pytest.raises(MonitorQueryError):
        normalize_storage_rows(COLUMNS, [row], ACCOUNT, RESOURCE)


def test_query_handles_empty_full_success_and_rejects_partial():
    client = SimpleNamespace(
        query_workspace=lambda *args, **kwargs: SimpleNamespace(
            status="Success", tables=[SimpleNamespace(columns=list(COLUMNS), rows=[])]
        )
    )
    assert (
        query_storage_events(
            client, "11111111-1111-4111-8111-111111111111", ACCOUNT, RESOURCE, 45
        )
        == []
    )
    partial = SimpleNamespace(
        query_workspace=lambda *args, **kwargs: SimpleNamespace(
            status="PartialError", partial_data=[]
        )
    )
    with pytest.raises(MonitorQueryError):
        query_storage_events(
            partial, "11111111-1111-4111-8111-111111111111", ACCOUNT, RESOURCE, 45
        )
    failure = SimpleNamespace(query_workspace=lambda *args, **kwargs: 1 / 0)
    with pytest.raises(MonitorQueryError, match="query failed"):
        query_storage_events(
            failure, "11111111-1111-4111-8111-111111111111", ACCOUNT, RESOURCE, 45
        )
