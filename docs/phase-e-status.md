# Phase E implementation status

Updated 2026-10-23. The offline Phase E implementation is complete for the
current Storage, Key Vault, and SQL scope. The full Phase E credibility gate is
not complete because the live Azure Policy/Prowler comparison still requires a
dedicated lab, read-only access, and reviewed external mappings.

## Delivered

| Roadmap item | Status | Evidence |
|---|---|---|
| E1 package migration | Partial by design | The installable `src/azure_compliance_guard` package owns the new CLI. The legacy monitor remains available until later workflow phases migrate remediation, incidents, and evidence. |
| E2 typed models | Complete for scan scope | `ResourceRef`, `StorageState`, `KeyVaultState`, `SqlState`, and `Finding` define the scan boundary. Workflow models are deferred to their owning phases. |
| E3 collector interface | Complete for scan scope | Fixture and read-only Azure collectors return the same typed state models for Storage, Key Vault, and SQL. |
| E4/E5 YAML rules | Complete for internal baseline | Schema-v1 catalogs contain 17 stable `ACG-*` rules with safe parsing, service/field/type validation, duplicate/operator checks, and allowlisted handlers. External framework control values intentionally remain null. |
| E6 CLI surface | Complete for Phase E | `acg doctor`, one-shot `acg scan`, and explicit `acg watch` are implemented with stable exit codes. Reporting, exceptions, and remediation remain later-phase commands. |
| E7 doctor | Complete for current config | Read-only checks cover runtime, Azure CLI/auth/subscription, Terraform, SQLite, optional Log Analytics configuration, and mutation safety. |
| E8 one-shot/watch split | Complete | `scan` always exits. `watch` repeats at an explicit interval and supports bounded `--iterations` plus stream-safe JSONL. |
| E9 crosswalk | Partial | Stable ACG IDs and schema version are recorded; all CIS/Azure Policy/Prowler mappings remain `UNVERIFIED`. |
| E10/E11 offline validation | Complete for current internal baseline | Six reviewed secure/drift fixtures cover all three services and all 17 rules without Azure credentials. |
| E11 live comparison/E12 full credibility gate | Deferred | Requires a dedicated lab scope, read-only identities, pinned comparator inspection, evaluation-latency handling, and sanitized evidence. |

## Verification snapshot

- Python 3.14.3: package and test environment resolved from the hashed development lock.
- `acg scan --source fixture --service all --format json`: deterministic offline path covers three resources and 17 intentional findings.
- `acg watch`: bounded text/JSONL behavior is covered by integration tests; it sleeps only between cycles.
- Offline suite: 81 tests plus 2 subtests passed.
- CI-scoped coverage: 81.31% (required threshold: 80%).
- Ruff lint and format: passed.
- The Azure CLI adapter uses argument vectors, an explicit validated subscription, a timeout, JSON output, and `shell=False`.
- No live Azure read, mutation, Terraform apply/destroy, policy assignment, or paid Defender activation was performed.

## Offline validation metrics

The six sanitized cases contain a secure and intentional-drift fixture for each
service. Across 34 rule-case evaluations, the result is 17 true positives, 17
true negatives, zero false positives, and zero false negatives. These figures
measure deterministic fixture behavior only; they do not establish live Azure
accuracy or CIS/Azure Policy/Prowler agreement.

## Deferred backlog

1. Inspect the pinned CIS benchmark text, Azure Policy definition JSON, and Prowler 5.45.0 implementations before assigning control IDs or `EXACT` mappings.
2. Run read-only comparison on a dedicated, cost-reviewed lab scope and publish only sanitized artifacts.
3. Record Policy evaluation latency, comparator versions, TP/TN/FP/FN, and every disagreement before claiming the full credibility gate.
4. Define `IncidentEvent`, `ExceptionRecord`, `RemediationPlan`, and `EvidenceEvent` only when their owning workflow phases are implemented.
5. Migrate the remaining legacy monitor, remediation, incident, exception, and evidence workflows incrementally in their owning phases.

No item above authorizes Azure mutation, policy assignment, paid Defender
enablement, Terraform apply, or use of a production subscription.
