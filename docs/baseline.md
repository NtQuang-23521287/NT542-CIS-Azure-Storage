# P0 technical audit — 2026-10-18

Updated 2026-10-22 for Phase A/B review. The P0 changes are committed locally on `main`; they have not been pushed to `origin/main`. Unrelated user artifacts remain untouched.

## Repository snapshot

- Branch: `main`, tracking `origin/main`.
- Baseline commit: `efc18a9` (`restart project, prepare for update`).
- Working tree đã có thay đổi/untracked artifacts của người dùng trước P0; chúng được giữ nguyên.
- Python entrypoint: `Compliance/engine/main.py`.
- Terraform root: `Terraform/azure-secure-storage`.

## Control flow

```text
config
  -> collector (Azure SDK / Azure CLI / local signal fixture)
  -> evaluator + incident evaluator
  -> remediation decision
  -> plan-only by default / explicit mutation gate
  -> local audit logs
```

Detailed path: `main.monitor()` initializes a Storage SDK client, starts the local admin-command listener, then loops over Storage, Key Vault and SQL every `CHECK_INTERVAL` (default 5 seconds). `collector.py` reads Storage via SDK and Key Vault/SQL via Azure CLI. `evaluator.py` compares hard-coded expected dictionaries and creates findings. `incident_evaluator.py` evaluates signals from the local `Compliance/data/security_signals.json` fixture, **not** Azure Monitor. `remediation.py` checks local JSON exceptions, renders a plan by default, and can call `azure_cli.run_az()` only if the temporary `ALLOW_AZURE_MUTATIONS` gate is explicitly enabled. `incident_response.py` can revoke local exceptions and plan/execute containment. `audit_logger.py` writes local text logs; there is no JSONL/HTML report yet.

The exception reader currently treats malformed JSON as an empty exception list and refreshes status by rewriting the file. It is not transactional or fail-closed. Azure CLI success is logged as remediation success without re-collecting and re-evaluating the rule. These are Phase G/F gaps, not completed P0 guarantees.

## Repository and Terraform inventory

```text
Compliance/engine/main.py             monitor entrypoint and hard-coded expected state
Compliance/engine/{collector,evaluator,remediation,incident_response}.py
Compliance/engine/{exception_manager,audit_logger,admin_listener}.py
Compliance/data/                     local mock signals and exception data
Terraform/azure-secure-storage/      Terraform root (Storage, Key Vault, SQL,
                                      VNet/private endpoints/DNS, Log Analytics,
                                      VPN gateway and jumpbox VM)
tests/                               seven offline P0 safety tests
docs/validation/                     candidate external-comparator methodology
```

The Terraform full profile is unconditional. The higher-cost or long-running candidates are VPN Gateway, jumpbox VM, Azure SQL, Private Endpoints, Log Analytics ingestion/retention and the associated public IP. `sql.tf` also enables a SQL server security alert policy; its billing implications need confirmation before apply. A future `minimal` profile should retain only resources needed for the Storage drift demo; classification here does **not** mean feature flags already exist. A speculative plan against the new student subscription on 2026-10-22 proposed 31 creates, 0 updates and 0 deletes; it was not applied. The old state is archived outside the active root, and `provider.tf` requires an explicit subscription ID. Do not use the full profile with the $100 credit before cost review.

## Identity and scope at audit time

- Storage collection uses `ClientSecretCredential` from local environment variables. Terraform also uses an explicit subscription ID; the new ID differs from the archived old state.
- Key Vault/SQL collection and optional CLI mutation use the **separate Azure CLI identity**. Every CLI call now explicitly passes the configured `AZURE_SUBSCRIPTION_ID` and rejects an override, so it cannot silently fall back to a previously selected subscription. `az account show` did not resolve an active subscription in this shell on 2026-10-22, so the full monitor cannot be claimed live-ready.
- The service principal has enough read permission for Terraform `plan` on the new subscription, but `Reader` does not authorize `apply` or remediation. A future scanner should be scoped to the dedicated lab RG/resource; a future remediator needs only narrowly scoped write actions. No broad subscription `Contributor` is recommended.
- `.env`, private `*.tfvars`, Terraform state, logs and evidence must remain local and untracked. The client secret is still a local development credential; OIDC is deferred to Phase J.

## External validation boundary

Phase A5 selected CIS Azure Storage Services 2.0.0 and Prowler 5.45.0 as versioned references. [Methodology](validation/methodology.md) and [initial Storage crosswalk](validation/control-crosswalk.md) list candidate Azure Policy/Prowler comparators. All mappings remain `UNVERIFIED`: no live Prowler/Policy evaluation or benchmark control-number verification has happened. Ground truth will be direct ARM/SDK observation of secure and intentional-drift lab cases.

## Phase B checkpoint (2026-10-22)

- `terraform fmt -check -recursive`: PASS.
- `terraform init -backend=false -input=false -lockfile=readonly` using the existing offline provider cache: PASS (AzureRM 3.117.1, random 3.9.0).
- `terraform validate -no-color`: PASS.
- Fresh local clone after the A/B commits: `terraform init -backend=false -input=false -lockfile=readonly` and `terraform validate -no-color` PASS using the existing offline provider directory. This verifies locked provider versions in a clean checkout, not a fresh registry download or provider-signature check.
- `.venv/Scripts/python.exe -m unittest discover -s tests -v`: 7/7 PASS; no Azure calls.
- `.gitignore` excludes bytecode/runtime state and does **not** exclude `.terraform.lock.hcl`; nine formerly tracked `.pyc` files were removed from Git's index.
- Paid Defender-for-SQL remediation is `MANUAL_ONLY`; all Azure CLI reads and mutations use argument vectors and the configured subscription, not `shell=True` or the session's default subscription; the monitor defaults to plan-only.
- README labels mock incident signals, the temporary mutation gate, cost risk and non-production status.
- **Git checkpoint:** the Terraform lockfile, safety changes and bytecode cleanup are in scoped local commits on `main`. No branch or push was performed; the next development branch is deferred until the user reviews Phase A/B.

## Trust and mutation boundaries

| Boundary | Current mechanism | Risk / P0 decision |
|---|---|---|
| Environment -> Storage SDK | Client secret credential | Secret must remain local; identity differs from CLI session |
| Process -> Azure CLI collectors | Argument vector, explicit subscription, JSON output | Read path depends on CLI identity access to that subscription |
| Finding -> remediation | Allowlisted argument templates | Plan-only by default; no command shell |
| Incident -> containment | Allowlisted argument templates | Plan-only by default |
| SQL Defender finding -> pricing | Subscription-level paid plan | Always manual-only with cost approval |
| Local JSON -> incident evaluator | Mock signal file | Not Azure Monitor evidence; must be labeled mock |

## P0 findings

1. `vpn_gateway.tf` referenced an undeclared `vpn_gateway_public_ip_zones` variable.
2. `.terraform.lock.hcl` existed locally but `.gitignore` hid it.
3. Nine `Compliance/engine/__pycache__/*.pyc` files were tracked.
4. CRITICAL findings could mutate Azure automatically.
5. Defender for SQL remediation could enable a paid subscription-scope plan.
6. Remediation and containment executed formatted strings with `shell=True`.
7. README described only Storage, stale paths and broad Contributor guidance.
8. No automated tests or CI existed at baseline.

## P0 resolution and evidence

- Terraform variable declared with default `[]`.
- Lockfile is tracked; previously tracked bytecode is removed from the Git index.
- Azure mutation defaults to disabled/plan-only.
- Defender for SQL is `MANUAL_ONLY` even when the temporary mutation gate is enabled.
- Azure CLI reads and mutations use `list[str]`, explicit subscription binding, fixed executable lookup and a 60-second timeout.
- Offline safety tests cover default plan-only behavior, incident containment, Defender policy, shell-free execution, and rejection of missing/overridden subscription IDs.
- `terraform fmt -check -recursive`, backend-free init and validate pass.

No Azure API mutation, Terraform apply or Terraform destroy was executed during this audit.

## Deferred after P0

- Replace temporary global opt-in with exact plan/hash approval and stale-state checks.
- Re-collect and re-evaluate before recording remediation as verified.
- Normalize packaging, pytest/Ruff/coverage and GitHub Actions.
- Replace local incident signals with Azure Monitor/KQL.
- Split scanner and remediator identities with least privilege/OIDC.
