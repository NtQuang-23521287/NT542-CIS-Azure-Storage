# Initial Storage control crosswalk

Status: candidates only, updated 2026-10-23. The Storage catalog now has stable ACG IDs under rule schema version 1, but every external mapping remains `UNVERIFIED` until the pinned definitions and Prowler 5.45.0 implementations are inspected and secure/drift cases are compared against live ARM ground truth. Do not infer a CIS control number from a similar title; the YAML framework control values intentionally remain null.

| ACG rule (schema v1) | Observed ARM/SDK property; expected state | Azure Policy built-in candidate | Prowler Azure candidate | Status |
|---|---|---|---|---|
| `ACG-STO-001` | Storage account `supportsHttpsTrafficOnly` / SDK `enable_https_traffic_only` = `true` | `Secure transfer to storage accounts should be enabled` (2.0.0) | Check ID to verify in pinned release | `UNVERIFIED` |
| `ACG-STO-002` | Storage account `minimumTlsVersion` = `TLS1_2` | `Storage accounts should have the specified minimum TLS version` (1.0.0); verify assignment parameter | Check ID to verify in pinned release | `UNVERIFIED` |
| `ACG-STO-003` | Storage account `publicNetworkAccess` = `Disabled` | `Storage accounts should disable public network access` (1.1.0) | `storage_account_public_network_access_disabled` | `UNVERIFIED` |
| `ACG-STO-004` | Blob service `isVersioningEnabled` = `true` | `Configure your Storage account to enable blob versioning` (1.0.0, Audit effect) | `storage_blob_versioning_is_enabled` | `UNVERIFIED` |

Sources: [Azure Storage Policy built-ins](https://learn.microsoft.com/azure/storage/common/policy-reference), [Prowler public network check](https://hub.prowler.com/check/storage_account_public_network_access_disabled), [Prowler blob versioning check](https://hub.prowler.com/check/storage_blob_versioning_is_enabled), [CIS Azure benchmark](https://www.cisecurity.org/benchmark/azure). Prowler Hub describes current checks, not proof of identical behavior in version 5.45.0.

`EXACT` requires matching resource scope, property, expected value, applicability and evaluated time window. Use `PARTIAL` when any of those differ, `NOT_COMPARABLE` when no sound comparator exists, and keep `UNVERIFIED` until direct review and cases are complete. Never count `PARTIAL` or `NOT_COMPARABLE` as exact agreement.
