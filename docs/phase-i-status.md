# Phase I — Azure Monitor Storage incident signal

## Implemented offline

- The Blob service diagnostic setting exports `StorageRead`, `StorageWrite`, and `StorageDelete` to the provisioned Log Analytics workspace in resource-specific (`Dedicated`) mode. The query expects `StorageBlobLogs`. Terraform now exposes the workspace **customer/workspace GUID** separately from its ARM resource ID.
- `acg incident scan` queries the previous 45 minutes by default (configurable from 1 to 1440). It filters one account, HTTP 2xx, and `GetBlob`, `ListBlobs`, `PutBlob`, `DeleteBlob`; it projects only time, account, operation, status, caller address, correlation/count, object ID, and resource ID. The Python boundary checks every row again. Partial/failed queries and result overflow stop the run.
- Explicit trusted CIDRs are evaluated in Python. A successful sensitive operation from an untrusted address is `SUSPICIOUS`; when the matching public-network exception (`ACG-STO-003`) was active at event time and remains active, it is `ESCALATED_CRITICAL`. Unknown/malformed addresses remain suspicious for review and cannot automatically revoke an exception.
- The Phase G SQLite repository transactionally revokes only that matching exception and records a reason containing the incident digest. The Phase H private JSONL stream records detection, escalation, revocation, a review-only containment plan, and later verification. A separate SQLite table remembers processed event digests across runs; entries older than 30 days are removed.
- The incident path never executes an Azure mutation. The proposed `disable_public_network_access` action requires a fresh Phase F plan, exact approval, and Phase F's existing execution gates. `acg incident verify` re-collects Storage state and records whether public network access is disabled.

## Offline reproduction

First initialize an exception database and create/activate a temporary `ACG-STO-003` exception using `acg exception ...`; use an account/resource ID that matches the fixture. Keep the fixture and all generated files under `build/` or another private folder. A monitor fixture is JSON with exactly `columns` and `rows`, using the projected `StorageBlobLogs` column names listed above. The event time must fall after exception activation.

```powershell
acg incident scan --source fixture --fixture build/monitor-blob.json --account <storage-name> --resource-id <storage-arm-id> --trusted-cidr 10.0.0.0/8 --exceptions-db build/exceptions.db --state-db build/incidents.db --evidence build/evidence.jsonl
acg incident verify --source fixture --fixture build/current-storage.json --resource-id <storage-arm-id> --event-key <digest-from-scan> --evidence build/evidence.jsonl
acg report --input build/evidence.jsonl --output build/incident-report.html
```

`scan` exits `1` when it finds a suspicious/escalated event, `0` for no new finding, `2` for an operational failure, and `3` for invalid configuration. `verify` exits `1` while the public-network setting remains enabled and `0` after it is observed disabled. The HTML timeline shows safe operation/severity/status labels and masks source IPs and identities.

## Real lab checkpoint — pending

1. Apply the reviewed Terraform changes in a dedicated lab. Confirm the Blob diagnostic setting uses resource-specific mode and points to the expected workspace. Generate one Blob operation, wait for ingestion, and check that `StorageBlobLogs` exists with `AccountName`, `OperationName`, `StatusCode`, `CallerIpAddress`, `CorrelationId`, `OperationCount`, `RequesterObjectId`, and `_ResourceId`. Existing records in `AzureDiagnostics` are not migrated by changing mode.
2. Give the running identity Log Analytics query permission (for example, **Log Analytics Data Reader**) on that workspace. Use Terraform's `log_analytics_workspace_customer_id` output for `--workspace-id` and `storage_account_id` for `--resource-id`. Supply trusted network ranges explicitly; do not use broad CIDRs just to force a green result.
3. Create and activate a temporary `ACG-STO-003` exception for the same Storage account. Perform a successful sensitive Blob operation from an untrusted lab source while the exception is active. Resource logs commonly take several minutes to become queryable, so poll with an overlapping lookback window.
4. Run the command below. Review the private evidence and the `APPROVAL_REQUIRED` containment proposal. Re-collect current Storage state, create and approve an exact Phase F remediation plan, and apply it only inside the dedicated lab under the established gates.
5. Run `acg incident verify --source azure ...` and render the HTML report. Save evidence of the actual Log Analytics row, exception audit transition, Phase F result, post-change Storage state, and incident timeline before marking Checkpoint I complete.

```powershell
acg incident scan --source azure --workspace-id <workspace-customer-guid> --account <storage-name> --resource-id <storage-arm-id> --trusted-cidr <lab-trusted-cidr> --exceptions-db build/exceptions.db --state-db build/incidents.db --evidence build/evidence.jsonl
acg incident verify --source azure --resource-id <storage-arm-id> --event-key <digest-from-scan> --evidence build/evidence.jsonl
```

No live Azure query, Terraform apply, or real Blob operation was performed in this phase's offline implementation. The live checkpoint therefore remains open. Query logs are delayed and can be incomplete; an empty response is not proof that no operation occurred. The local exception audit, JSONL evidence, and dedup database are separate files, so a crash between their writes needs manual reconciliation. `VERIFIED` records only the observed public-network setting after containment, not a complete incident closure. Private outputs may contain IPs and resource identifiers; keep them out of Git and remove them under the lab's 30-day retention procedure.

## Sources

- [Azure Monitor resource logs and collection modes](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs)
- [Azure Monitor diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/diagnostic-settings)
- [StorageBlobLogs columns](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs)
- [Azure Monitor query SDK for Python](https://learn.microsoft.com/en-us/python/api/overview/azure/monitor-query-readme)
- [Log data ingestion time](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time)
- [Terraform diagnostic setting destination type](https://registry.terraform.io/providers/hashicorp/azurerm/3.117.1/docs/resources/monitor_diagnostic_setting)
