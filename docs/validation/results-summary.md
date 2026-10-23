# Offline validation results summary

Status: offline-only baseline, 2026-10-23. No Azure Policy or Prowler live
comparison has been run.

The schema-v1 Storage, Key Vault, and SQL catalogs were evaluated against six
sanitized fixtures whose expected results are recorded in
`tests/fixtures/validation/manifest.json`. Each service has one secure case and
one intentional-drift case. Secure cases produced no findings; drift cases
produced all 17 expected ACG rule IDs.

| Metric | Offline result |
|---|---:|
| Services | 3 |
| Cases | 6 |
| Rule-case evaluations | 34 |
| True positive | 17 |
| True negative | 17 |
| False positive | 0 |
| False negative | 0 |
| Critical false negative | 0 |
| External exact-mapping agreement | Not measured |

The rule-case denominator is 17 rules applied once to the matching secure
fixture and once to the matching drift fixture. These numbers prove only
deterministic behavior for the published fixture set. They are not evidence of
full CIS coverage, live Azure accuracy, or agreement with Azure Policy/Prowler.
Reproduce the result with:

```powershell
python -m pytest -p no:cacheprovider tests/integration/test_phase_e_validation_dataset.py -q
```
