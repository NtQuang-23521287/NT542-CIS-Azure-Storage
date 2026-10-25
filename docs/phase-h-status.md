# Phase H implementation status

Updated 2026-10-24. This phase was exercised offline. No live Azure scan,
remediation, Prowler run, or Azure Policy comparison was performed.

## Implemented

- `acg scan --output` appends schema-v1 `RUN_STARTED`, `FINDING`, and
  `RUN_COMPLETED` events to local JSONL. Every record has an event ID, run ID,
  UTC timestamp, structured resource reference, source metadata, and event data.
  The reader validates each line and reports its number on error. A malformed
  existing file blocks further appends. The writer uses local append mode and
  one write per line, followed by `fsync`. The reader and writer cap a stream
  at 32 MiB to keep report generation bounded.
- `acg report --input ... --output ... --redact` creates a standalone HTML file
  with Jinja autoescaping, a script hash CSP, field allowlists, pseudonymized
  resource/identity identifiers, masked IPs, and redacted exception reasons.
  Redaction is always on, including when `--redact` is omitted. The report has
  overview and lifecycle metrics, finding filters, a timestamped timeline, and
  a validation appendix.
- The [sample evidence](samples/phase-h-evidence.jsonl) and
  [sample report](samples/phase-h-report.html) are generated only from committed
  synthetic fixtures. The sample generator derives 17 TP, 17 TN, 0 FP, and
  0 FN from all six internal validation cases. Lifecycle examples carry the
  source label `Simulated lifecycle` in the report; they are demonstration
  events, not records from the live Phase F/G workflows.

## Reproduce

From the repository root with the Python 3.14 package installed:

```powershell
acg scan --source fixtures/demo_environment.json --output build/evidence.jsonl
acg report --input build/evidence.jsonl --output build/report.html --redact
```

The fixture scan deliberately returns exit code `1` because it detects drift.
Inspect `build/report.html` by opening it locally. To regenerate the portfolio
sample, choose a new empty directory and run:

```powershell
python -m scripts.phase_h_sample <directory>
```

The scan output contains raw structured resource references and is **private**
evidence. Store it under ignored `build/` or `reports/private/`; restrict local
access, retain it for at most 30 days in this lab, and then remove it using the
operator's local retention procedure. Do not commit operational evidence or
publish reports to GitHub Pages. Only the sanitized fixture sample belongs in
this repository.

## Validation and limits

The validation appendix identifies its offline fixture scope, case count,
time, ACG package version, and rule catalog schema. `Prowler: Not run`,
`Azure Policy: Not run`, and `UNVERIFIED` exact mapping are deliberate. Internal
fixture agreement is not an external comparator result. The Phase E live
comparison and pinned control mapping remain open.

Only scan events are emitted automatically into JSONL. Exception events live in
the Phase G SQLite audit chain; remediation and incident evidence still need
an authenticated export or direct integration before an operational end-to-end
lifecycle report is possible. The sample lifecycle is explicitly simulated.
Local append mode and `fsync` do not provide tamper resistance, cross-process
transaction guarantees, or off-host retention. Protect and back up private
evidence accordingly. A report is a redacted view of supplied records; it does
not prove those records are authentic.
