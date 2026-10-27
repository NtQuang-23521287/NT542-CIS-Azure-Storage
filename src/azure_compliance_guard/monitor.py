"""Bounded Azure Monitor query for Storage Blob incident signals."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID


class MonitorQueryError(RuntimeError):
    """The query or its projected result cannot be trusted as complete."""


SENSITIVE_OPERATIONS = frozenset({"GetBlob", "ListBlobs", "PutBlob", "DeleteBlob"})
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
MAX_EVENTS = 1000


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    occurred_at: datetime
    account: str
    resource_id: str
    operation: str
    status_code: int
    source_ip: str
    correlation_id: str
    operation_count: int
    requester_object_id: str
    key: str


def build_storage_query(account: str, lookback_minutes: int) -> str:
    if not isinstance(account, str) or not re.fullmatch(r"[a-z0-9]{3,24}", account):
        raise ValueError("storage account name is invalid")
    if type(lookback_minutes) is not int or not 1 <= lookback_minutes <= 1440:
        raise ValueError("lookback must be 1-1440 minutes")
    operations = ", ".join(f'"{name}"' for name in sorted(SENSITIVE_OPERATIONS))
    return (
        "StorageBlobLogs\n"
        f"| where TimeGenerated > ago({lookback_minutes}m)\n"
        f'| where AccountName == "{account}"\n'
        "| where toint(StatusCode) between (200 .. 299)\n"
        f"| where OperationName in ({operations})\n"
        f"| project {', '.join(COLUMNS)}\n"
        f"| order by TimeGenerated asc\n| take {MAX_EVENTS + 1}"
    )


def _source_ip(value: str) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise MonitorQueryError("invalid caller address field")
    source = value.strip()
    if source.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::\d{1,5})?", source)
        return match.group(1) if match else source
    try:
        ipaddress.ip_address(source)
        return source
    except ValueError:
        match = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}", source)
        return match.group(1) if match else source


def normalize_storage_rows(
    columns: list[str] | tuple[str, ...],
    rows: list[list],
    account: str,
    resource_id: str,
) -> list[IncidentEvent]:
    build_storage_query(account, 1)
    if (
        not isinstance(resource_id, str)
        or not resource_id.strip()
        or len(resource_id) > 2048
    ):
        raise ValueError("storage resource ID is required")
    if not set(COLUMNS) <= set(columns) or len(columns) != len(set(columns)):
        raise MonitorQueryError("StorageBlobLogs query returned an unexpected schema")
    if len(rows) > MAX_EVENTS:
        raise MonitorQueryError("StorageBlobLogs query exceeded event limit")
    result = []
    for values in rows:
        if len(values) != len(columns):
            raise MonitorQueryError("StorageBlobLogs row length is invalid")
        row = dict(zip(columns, values, strict=True))
        logged_resource = row["_ResourceId"]
        if (
            row["AccountName"] != account
            or not isinstance(logged_resource, str)
            or logged_resource.lower().removesuffix("/blobservices/default")
            != resource_id.lower()
        ):
            raise MonitorQueryError("StorageBlobLogs row is outside requested resource")
        occurred = row["TimeGenerated"]
        if isinstance(occurred, str):
            try:
                occurred = datetime.fromisoformat(occurred.replace("Z", "+00:00"))
            except ValueError as exc:
                raise MonitorQueryError("invalid StorageBlobLogs timestamp") from exc
        if not isinstance(occurred, datetime) or occurred.tzinfo is None:
            raise MonitorQueryError("invalid StorageBlobLogs timestamp")
        operation = row["OperationName"]
        try:
            status = int(row["StatusCode"])
            count = int(row["OperationCount"])
        except (TypeError, ValueError) as exc:
            raise MonitorQueryError("invalid StorageBlobLogs status or count") from exc
        if (
            operation not in SENSITIVE_OPERATIONS
            or not 200 <= status <= 299
            or count < 0
        ):
            raise MonitorQueryError("StorageBlobLogs row violates query filters")
        correlation = row["CorrelationId"]
        requester = row["RequesterObjectId"]
        if (
            not isinstance(correlation, str)
            or not isinstance(requester, str)
            or len(correlation) > 256
            or len(requester) > 256
        ):
            raise MonitorQueryError("invalid StorageBlobLogs identity fields")
        source_ip = _source_ip(row["CallerIpAddress"])
        occurred = occurred.astimezone(UTC)
        resource = resource_id.lower()
        key_fields = [
            resource,
            occurred.isoformat(),
            operation,
            status,
            source_ip,
            correlation,
            count,
            requester,
        ]
        key = hashlib.sha256(
            json.dumps(key_fields, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        result.append(
            IncidentEvent(
                occurred,
                account,
                resource,
                operation,
                status,
                source_ip,
                correlation,
                count,
                requester,
                key,
            )
        )
    return result


def query_storage_events(
    client: object,
    workspace_id: str,
    account: str,
    resource_id: str,
    lookback_minutes: int = 45,
) -> list[IncidentEvent]:
    try:
        UUID(workspace_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("workspace ID must be a GUID") from exc
    query = build_storage_query(account, lookback_minutes)
    try:
        response = client.query_workspace(
            workspace_id,
            query,
            timespan=timedelta(minutes=lookback_minutes),
            server_timeout=30,
        )
    except Exception as exc:
        raise MonitorQueryError("Log Analytics query failed") from exc
    status = getattr(response, "status", None)
    if status != "Success" and getattr(status, "value", None) != "Success":
        raise MonitorQueryError("Log Analytics query was not fully successful")
    tables = getattr(response, "tables", None)
    if not isinstance(tables, list):
        raise MonitorQueryError("Log Analytics query returned no table collection")
    events = []
    for table in tables:
        columns = [getattr(column, "name", column) for column in table.columns]
        events.extend(normalize_storage_rows(columns, table.rows, account, resource_id))
    if len(events) > MAX_EVENTS:
        raise MonitorQueryError("StorageBlobLogs query exceeded event limit")
    return events


def make_logs_client():
    """Use Azure's credential chain only when a live query is requested."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient

    credential = DefaultAzureCredential()
    return LogsQueryClient(
        credential, connection_timeout=10, read_timeout=45, retry_total=2
    )
