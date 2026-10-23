# Phase F implementation status

Updated 2026-10-23. The Phase F safety workflow has offline tests. No live
Azure remediation has been attempted or verified.

## Implemented

- A JSON `RemediationPlan` binds one finding, rule, resource identity, full
  before state, desired field, fixed action, risk/cost policy, expiry,
  idempotency key, and SHA-256 hash. The plan is revalidated when read or used.
- `acg remediation plan` reads the current finding without mutation.
- `acg remediation apply --dry-run` displays before, desired, risk and cost
  without collecting from Azure or calling an executor.
- `acg remediation approve` requires the operator to repeat the exact plan
  hash. Approval records the plan ID, hash, approver label and timestamp.
- Execution rejects expired, unapproved, changed, manual-only and stale plans.
  It checks the current rule, resource identity, full before state and a
  reviewed local exception file before updating. An accepted update is
  re-collected and the same rule is evaluated with bounded retries.
- Storage account HTTPS, TLS and public-network changes use the Storage
  management SDK. Key Vault public-network/RBAC and SQL TLS/public-network
  changes use fixed, subscription-scoped Azure CLI argument vectors. Other
  rule handlers, including Defender pricing, are manual-only.
- The legacy monitor and incident containment path are plan-only even when
  `ALLOW_AZURE_MUTATIONS=true` is set.

## Boundaries

- Exact CIS/Azure Policy/Prowler mappings and live comparator evidence remain
  open from Phase E. Offline fixture results do not prove live accuracy.
- Approval is a local, self-declared operator action. The file has no digital
  signature or independent identity check; protect plan/approval files with
  operating-system permissions. A separate identity system belongs to later
  operational work.
- SHA-256 detects accidental or unreviewed plan edits but is not an
  authentication signature. An authorized operator can create a new plan and
  approval. The idempotency key identifies an intent, but there is not yet a
  durable execution ledger for crashes or concurrent operators.
- Precondition re-collection narrows the check/use gap but cannot make Azure
  state updates atomic with the read. Live execution requires a dedicated,
  cost-reviewed lab and operator review of network/RBAC impact.
- The local exception JSON check is fail-closed and intentionally temporary;
  Phase G will replace it with transactional SQLite governance.

`VERIFIED` means the same rule passed after re-collection. An Azure SDK or CLI
success response alone never produces `VERIFIED`.
