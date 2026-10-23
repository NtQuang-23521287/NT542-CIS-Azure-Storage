# Phase E implementation status

Updated 2026-10-23. Phase E is partially complete as a Storage-first offline
vertical slice. This document is the restart point for work intentionally
deferred because it is too large, requires live Azure access, or belongs to a
later safety phase.

## Delivered

| Roadmap item | Status | Evidence |
|---|---|---|
| E1 package migration | Partial | Installable `src/azure_compliance_guard` package added; legacy monitor retained to avoid a big-bang rewrite. |
| E2 typed models | Partial | `ResourceRef`, `StorageState`, and `Finding` cover the Storage scan slice. Other service/workflow models are deferred. |
| E3 collector interface | Partial | Fixture and Azure SDK collectors both return `StorageState`; Key Vault and SQL still use legacy dictionaries. |
| E4/E5 YAML rules | Storage complete | Schema v1 catalog has stable `ACG-STO-*` IDs, null unverified CIS controls, safe YAML parsing, duplicate/operator checks, and allowlisted handler IDs. |
| E6 CLI surface | Partial | `acg doctor` and one-shot `acg scan` are implemented with exit codes 0/1/2/3. |
| E7 doctor | Complete for current config | Read-only checks cover runtime, Azure CLI/auth/subscription, Terraform, SQLite, Log Analytics configuration, and mutation safety. |
| E8 one-shot/watch split | Partial | `scan` is one-shot. No watch command has been added yet. |
| E9 crosswalk | Partial | Stable ACG IDs and schema version are recorded; all external mappings remain `UNVERIFIED`. |
| E10/E11 offline validation | Storage baseline complete | Secure and drift fixtures are checked against reviewed expected rule IDs without Azure credentials. |
| E11 live comparison/E12 full credibility gate | Deferred | Requires dedicated lab scope, read-only identities, pinned comparator inspection, evaluation latency handling, and sanitized evidence. |

## Verification snapshot

- Python 3.14.3: editable install passed in a clean temporary virtual environment.
- `acg --help`: passed.
- `acg doctor --format json`: ran successfully and returned exit 2 because no subscription ID/auth context was supplied; mutation remained disabled.
- `acg scan --source fixture --format json`: returned the expected four findings and exit 1.
- Offline suite: 54 tests plus 2 subtests passed; CI-scoped coverage was 81.31% (threshold 80%).
- Ruff lint and format: passed.
- Runtime lockfile audit: no known vulnerabilities reported by `pip-audit` on 2026-10-23.

## Deferred backlog

1. Migrate Key Vault and SQL collectors/evaluators to typed package models.
2. Define `IncidentEvent`, `ExceptionRecord`, `RemediationPlan`, and `EvidenceEvent` when their owning workflows are implemented; do not invent unstable fields early.
3. Add `report`, `exceptions`, `remediation`, `monitor`, and explicit `watch` commands in their owning phases.
4. Inspect the pinned CIS benchmark text, Azure Policy definition JSON, and Prowler 5.45.0 implementations before assigning control IDs or `EXACT` mappings.
5. Run read-only live validation on a dedicated, cost-reviewed lab scope and publish only sanitized artifacts.
6. Populate reproducible live metrics and resolve comparator disagreements before claiming the full Phase E credibility gate.

No item above authorizes Azure mutation, policy assignment, paid Defender enablement,
Terraform apply, or use of a production subscription.
