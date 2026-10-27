# Threat model

Scope: a dedicated teaching lab, its Terraform state, Azure scanner/remediator identities, local exception/evidence files, and any published sample report. The Phase K `minimal` root lowers cost and scope; it does not turn local files into a trusted approval service.

| Threat | Boundary and impact | Current control | Remaining risk / operator action |
| --- | --- | --- | --- |
| Malicious or edited rule file | Repository or `--rules` input could change expected state or handler | Versioned catalog schema and allowlisted executable actions | Review rule diffs and pin a trusted commit before live runs; no signed rule bundle. |
| Shell injection | Resource names or CLI arguments could escape into a shell | Azure CLI calls use argument vectors, explicit subscription, fixed command templates and `shell=False` | Keep that pattern for new adapters; never concatenate untrusted strings into a shell command. |
| Stale remediation plan | Another actor changes a resource after planning | Plan expiry, hash, exact resource identity and full before-state re-collection | Read/update is not atomic; stop and re-plan on mismatch or ambiguous result. |
| Stolen CI credential | An attacker could read state or Azure configuration | Offline PR CI has no Azure secrets; manual Phase J plan uses environment-scoped OIDC and read-only lab role | Configure the external environment/federation and protect state access; revoke compromised identity and inspect activity logs. |
| Overly broad RBAC | Scanner/remediator or operator could affect other resources | Scanner Reader; documented remediator custom read/write at exact resource scope | Azure write actions are wider than individual fields. Review assignments and never give subscription Contributor for convenience. |
| Evidence tampering | Local JSONL could be edited, truncated or replaced | Schema validation, bounded reads, append plus fsync | No authenticated off-host ledger. Restrict local file access and back up private evidence if audit assurance is needed. |
| Exception DB corruption | Missing or modified SQLite state could bypass a guard | Fail-closed reads, transactions, per-record version and hash chain | Hashes are not signatures and a writer can rewrite the whole DB; keep an independent backup and separate reviewer. |
| Sensitive report publication | IPs, IDs, tickets or secrets could leak from a report or Terraform plan | Redacted HTML field allowlist and CSP; ignored private output paths | Do not publish raw JSONL, state, plans, DB, or operational reports. Share only reviewed synthetic samples. |
| Wrong state key or RG during cleanup | `destroy` could affect a different lab | Dedicated `nt542-phase-k-` RG name, tags, isolated state key and reviewed destroy plan | Terraform state is the authority for destroy. Compare every planned deletion with the dedicated RG before applying it. No arbitrary RG cleanup wrapper exists. |

The trust boundaries and operator sequence are in [architecture.md](architecture.md) and [demo.md](demo.md). This is a risk inventory, not a certification or claim that Azure live controls have been validated.
