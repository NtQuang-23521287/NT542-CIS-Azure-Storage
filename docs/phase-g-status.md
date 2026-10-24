# Phase G implementation status

Updated 2026-10-24. This phase was verified offline; no Azure mutation was run.

## Implemented

- SQLite `exceptions` and `exception_events` store the lifecycle
  `REQUESTED → ACTIVE → EXPIRED/REVOKED`, with an `INCIDENT_REVOKED` event for
  incident handling. Every transition is one transaction and increments the
  record version. A partial unique index allows one `ACTIVE` row per resource
  and rule.
- Requests include owner, reason, ticket, and expiry (at most 120 minutes).
  Activation records an approver. The CLI exposes `init`, `request`, `activate`,
  `expire`, `revoke`, `list`, and `verify-chain` under `acg exception`.
- Events contain canonical JSON, `previous_hash`, SHA-256 `event_hash`, and
  the resulting record hash. Reads and writes verify the chain and current
  record state. A hash chain is tamper evident, not an authentication mechanism.
- Phase F `--execute` reads `--exceptions-db` for the exact ARM resource and
  rule. Missing, corrupt, locked, or altered state produces an operational
  error or rejection before Azure execution. Dry runs remain offline.
- The legacy admin command now creates a request only; approval must happen
  through `acg exception activate`. The legacy monitor reads and updates the
  same SQLite store. It no longer writes whole-file JSON exception state.

## Local operator sequence

```powershell
$db = "Compliance/data/exceptions.sqlite3"
acg exception init --db $db
acg exception request --db $db --resource-id "/subscriptions/<guid>/resourceGroups/<group>/providers/Microsoft.Storage/storageAccounts/<name>" --resource-name "<name>" --rule-id ACG-STO-001 --owner "<operator>" --reason "<why>" --ticket "<ticket>" --minutes 30
acg exception list --db $db --status REQUESTED
acg exception activate --db $db --id "<request-id>" --approved-by "<reviewer>" --expected-version 1
acg exception verify-chain --db $db
```

Use `--incident` with `acg exception revoke` for an incident revocation. The
CLI prints the current `version`; pass it to the next transition. An expired
active exception still has status `ACTIVE` until `expire` or the legacy
monitor's refresh runs, but its timestamp stops suppression immediately.

## Existing JSON and limits

An existing sibling `exceptions.json` blocks Phase F execution. The legacy
monitor also blocks on its configured `EXCEPTIONS_FILE`. Review those entries
manually, create equivalent requests in SQLite and approve each one, then
archive the JSON outside the configured path. There is no automatic import.
The repository does not change or remove the current JSON data.

SQLite serializes local transactions, but it is not a distributed approval
service. The hash chain cannot prove authenticity if an attacker can rewrite
the database and all hashes or truncate its end. Keep independent backups and
restrict file access. Live remediation still requires the Phase F gates and
dedicated lab review; Phase G tests cover local behavior only.
