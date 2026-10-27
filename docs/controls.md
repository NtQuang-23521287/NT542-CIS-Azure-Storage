# Rule catalog and control status

This table mirrors the packaged schema-v1 YAML in `src/azure_compliance_guard/rules/`. `plan_only` means the rule advertises a plan; only the Phase F executor's narrower allowlist can execute a live action after its gates. `manual_only` never executes through that path. Collector values are normalized fields, not raw Azure API property names.

| Rule ID | Service | Severity | Benchmark / version | Collector field | Expected state | Remediation policy |
| --- | --- | --- | --- | --- | --- | --- |
| ACG-STO-001 | Storage | CRITICAL | CIS Azure Storage Services 2.0.0 candidate | `https_only` | `true` | `plan_only`; Phase F executable |
| ACG-STO-002 | Storage | CRITICAL | CIS Azure Storage Services 2.0.0 candidate | `min_tls_version` | `TLS1_2` | `plan_only`; Phase F executable |
| ACG-STO-003 | Storage | CRITICAL | CIS Azure Storage Services 2.0.0 candidate | `public_network_access` | `Disabled` | `plan_only`; Phase F executable |
| ACG-STO-004 | Storage | WARNING | CIS Azure Storage Services 2.0.0 candidate | `versioning_enabled` | `true` | `plan_only`; manual execution today |
| ACG-KV-001 | Key Vault | CRITICAL | ACG internal baseline 1 | `public_network_access` | `Disabled` | `plan_only`; Phase F executable |
| ACG-KV-002 | Key Vault | CRITICAL | ACG internal baseline 1 | `rbac_authorization_enabled` | `true` | `plan_only`; Phase F executable |
| ACG-KV-003 | Key Vault | CRITICAL | ACG internal baseline 1 | `purge_protection_enabled` | `true` | `plan_only`; manual execution today |
| ACG-KV-004 | Key Vault | CRITICAL | ACG internal baseline 1 | `soft_delete_enabled` | `true` | `plan_only`; manual execution today |
| ACG-KV-005 | Key Vault | CRITICAL | ACG internal baseline 1 | `private_endpoint_enabled` | `true` | `manual_only` |
| ACG-KV-006 | Key Vault | WARNING | ACG internal baseline 1 | `keys_have_expiry` | `true` | `manual_only` |
| ACG-KV-007 | Key Vault | WARNING | ACG internal baseline 1 | `secrets_have_expiry` | `true` | `manual_only` |
| ACG-SQL-001 | SQL | CRITICAL | ACG internal baseline 1 | `auditing_enabled` | `true` | `plan_only`; manual execution today |
| ACG-SQL-002 | SQL | CRITICAL | ACG internal baseline 1 | `defender_enabled` | `true` | `manual_only`; may change subscription pricing |
| ACG-SQL-003 | SQL | CRITICAL | ACG internal baseline 1 | `min_tls_version` | `1.2` | `plan_only`; Phase F executable |
| ACG-SQL-004 | SQL | CRITICAL | ACG internal baseline 1 | `public_network_access` | `Disabled` | `plan_only`; Phase F executable |
| ACG-SQL-005 | SQL | CRITICAL | ACG internal baseline 1 | `private_endpoint_enabled` | `true` | `manual_only` |
| ACG-SQL-006 | SQL | WARNING | ACG internal baseline 1 | `azure_ad_admin_configured` | `true` | `manual_only` |

The Storage benchmark name and version are reference metadata, but each exact control number remains `null` and **UNVERIFIED**. Do not claim CIS certification or exact Prowler/Azure Policy equivalence. The Key Vault/SQL rows use an internal baseline, not a CIS mapping. See [validation crosswalk](validation/control-crosswalk.md) and [methodology](validation/methodology.md). The minimal profile deploys only Storage, so Key Vault/SQL rules need fixtures or the separate full lab.
