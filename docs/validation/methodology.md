# Validation baseline (Phase E)

Status: offline Storage, Key Vault, and SQL cases implemented 2026-10-23. No live comparison has been run and no rule is claimed as CIS-validated.

## References and order of evidence

1. **Ground truth:** create a dedicated lab Storage state, read the relevant properties directly from ARM/SDK, and record the expected result before looking at comparator output.
2. **Platform comparator:** an assigned Azure Policy built-in definition with matching applicability and effect. A definition merely existing is not an evaluation result.
3. **Independent comparator:** Prowler Open Source for Azure, restricted to allowlisted Storage checks on the same lab scope.
4. **Optional only:** Defender for Cloud regulatory compliance, after a separate permission and cost review. Never enable a paid Defender plan to satisfy this comparison.

Reference versions selected for reproducibility: [CIS Microsoft Azure Storage Services Benchmark 2.0.0](https://www.cisecurity.org/benchmark/azure) as the primary Storage benchmark and [Prowler 5.45.0](https://github.com/prowler-cloud/prowler/releases/tag/5.45.0) as the peer tool. Azure Foundations 6.0.0 is background context, not a second coverage claim. This selects versions, **not** CIS control numbers or verified Prowler check semantics; the benchmark text must be reviewed before assigning control IDs. Record the actual Prowler binary version and Azure Policy definition ID/version again when live validation runs.

## Initial scope and cases

The offline baseline covers all 17 current internal rules with a secure and an
intentional-drift fixture for each service. The initial external comparator
candidates remain the four Storage findings in
[control-crosswalk.md](control-crosswalk.md). Before extending external mappings
to Key Vault or SQL, inspect the pinned source implementations. For every live
case, record case ID, setup, raw and normalized ARM observations, expected
`PASS`/`FAIL` or `NOT_APPLICABLE`, cleanup path, and timestamps. Do not decide
expected results from agreement between tools.

Offline CI may evaluate sanitized fixtures with no Azure credentials. Live ACG/Prowler/Policy comparison is manual, read-only, and must not trigger remediation. Compare the same resource and policy semantics, account for Azure Policy evaluation delay, and classify missing/failed results as `ERROR` or `NOT_COMPARABLE`, never `PASS`. Keep raw output private; publish only sanitized evidence and explained disagreements.

The current offline dataset is versioned under `tests/fixtures/validation/` and
contains one reviewed secure case plus one intentional-drift case for each of
Storage, Key Vault, and SQL. Run it with:

```powershell
python -m pytest tests/integration/test_phase_e_validation_dataset.py -q
```

## Access and cost preflight for a later live run

| Reference | Minimum access to check before running | Cost boundary |
|---|---|---|
| Direct ARM/SDK observation | Read access to the dedicated lab Storage account and blob-service properties. | The lab Storage resource and any deployed supporting infrastructure can incur charges. |
| Azure Policy | Reader can inspect policy objects and compliance state at its scope; an operator with policy-assignment authority is needed if no suitable assignment exists. Use an `Audit` effect, not `Deny` or `Modify`, for comparison. | Do not create or alter an assignment without an explicit lab review; account for evaluation delay. |
| Prowler Open Source | Dedicated read-only Azure identity, scoped to the lab where feasible. Verify check-specific read permissions before execution; do not give it write privileges. | Run locally; the Azure lab resources remain the relevant cloud cost. Do not send credentials to Prowler Cloud. |
| Defender for Cloud | Optional; separately review subscription rights and pricing. | Paid plans are out of scope for Phase A and P0. |

Before any live comparison, verify the target subscription, budget, quota, identity, and teardown plan. Do not reuse the old Terraform state. Sources: [Azure Policy permissions](https://learn.microsoft.com/azure/governance/policy/overview), [Azure Policy evaluation timing](https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data), [Prowler Azure read-only assessment](https://prowler.com/cloud-security-solutions/azure-security-assessment), [Defender for SQL costs](https://learn.microsoft.com/azure/synapse-analytics/sql/azure-defender-for-sql).

## Exit criteria for Phase E validation

Pin the exact Azure Policy definition IDs/versions and Prowler check implementations, review `EXACT` versus `PARTIAL` mappings, run the cases, report TP/TN/FP/FN against ground truth, and explain every disagreement. Until then, all entries remain `UNVERIFIED` and no CIS coverage claim is made.
