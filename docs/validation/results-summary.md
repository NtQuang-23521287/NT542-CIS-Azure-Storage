# Storage validation results summary

Status: offline-only baseline, 2026-10-23. No Azure Policy or Prowler live
comparison has been run.

The schema-v1 Storage catalog was evaluated against two sanitized fixtures whose
expected results were recorded in `tests/fixtures/validation/manifest.json`.
The secure case produced no findings. The intentional-drift case produced
`ACG-STO-001` through `ACG-STO-004` as expected.

| Metric | Offline result |
|---|---:|
| Cases | 2 |
| Rule-case evaluations | 8 |
| True positive | 4 |
| True negative | 4 |
| False positive | 0 |
| False negative | 0 |
| Critical false negative | 0 |
| External exact-mapping agreement | Not measured |

These numbers prove only deterministic behavior for the published fixture set.
They are not evidence of full CIS coverage, live Azure accuracy, or agreement
with Azure Policy/Prowler. Reproduce the result with:

```powershell
python -m pytest tests/integration/test_phase_e_validation_dataset.py -q
```
