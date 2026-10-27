# Phase K demo and cleanup runbook

This runbook separates the repeatable offline story from the short, owner-approved Azure lab. The `minimal` root is the default. Its Terraform state key and resource group must be unique and different from the existing `full-demo` root. None of the commands here have been run against Azure for Phase K yet.

## 1. Prerequisites and cost gate

Use Python 3.14, the locked Python dependencies, Terraform 1.14.x, Azure CLI, a dedicated lab subscription and an operator who can create only the intended resource group/resources. The scanner uses a separate read-only Storage management identity; the remediator uses a separately scoped write identity as described in [Phase J operations](phase-j-operations.md). Terraform state needs its own existing private Storage container and identity with container-scoped blob access. Keep the backend state account outside the Phase K resource group, or its state will disappear during cleanup.

Before any live `plan` or `apply`:

1. Run `acg doctor` and `az account show --subscription <subscription-guid> --query '{id:id,name:name,tenantId:tenantId}' -o json`. Confirm the same GUID in `AZURE_SUBSCRIPTION_ID`, `ARM_SUBSCRIPTION_ID`, and `TF_VAR_subscription_id`. `doctor` checks runtime and login readiness; it does **not** check credit, SKU, quota or price.
2. Open the actual subscription in Azure Cost Management. Check remaining credit, spending limit eligibility, current spend, forecast and any existing budget. Do not infer entitlement from the phrase “Azure for Students.” If budgets are available, set an alert below the amount you are willing to spend; an alert is a notification, not a hard spending cap. Set a cleanup date and an operator reminder. [Student cost view](https://learn.microsoft.com/en-us/azure/education-hub/navigate-costs), [spending limit](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit), [budget alerts](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/cost-mgt-alerts-monitor-usage-spending).
3. Verify the selected region and subscription permit `Microsoft.Storage` and `Microsoft.OperationalInsights`, and that the intended Storage SKU and Log Analytics workspace are available. Use Azure Portal/CLI provider and quota views before assuming the template can deploy. Estimate charges for Storage capacity/transactions, diagnostic log ingestion and Log Analytics retention; the separate remote state account also has storage/transaction charges. A budget amount is a decision based on current pricing and anticipated log volume, not a constant in this repo. [Azure quota overview](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits).
4. Check that the proposed `nt542-phase-k-...` resource group does not exist. Choose a globally unique Storage name. Review the mandatory `Owner` and `ExpiresOn` tags; they are reminders, not an automatic deletion mechanism. Keep full-demo SQL, VPN Gateway, jumpbox, Private Endpoints and extra public IPs out of this run. The full root is a separate, short-lived exercise only after an explicit price/quota review.

## 2. Offline rehearsal

From the repository root, install the project in an isolated Python 3.14 environment using the locked dependencies, then run:

```powershell
acg doctor
terraform -chdir=Terraform/azure-minimal-storage fmt -check -recursive
terraform -chdir=Terraform/azure-minimal-storage init -backend=false -input=false -lockfile=readonly
terraform -chdir=Terraform/azure-minimal-storage validate -no-color
New-Item -ItemType Directory -Force build | Out-Null
acg scan --source fixtures/demo_environment.json --output build/phase-k-evidence.jsonl
acg report --input build/phase-k-evidence.jsonl --output build/phase-k-report.html --redact
```

The fixture deliberately has findings, so `acg scan` exits `1`; its JSONL file can still be used by `report`. Label the HTML as a synthetic, offline demonstration. `terraform init` may need the provider registry on a fresh machine. The project has a pinned provider lockfile; do not run `terraform apply` during the offline rehearsal.

## 3. Minimal Azure deployment — manual, after cost approval

Use a fresh PowerShell session and fill in values for the **dedicated** lab. Keep real `.tfvars`, backend credentials, plans and state out of Git. Backend auth uses the Azure CLI/Entra ID and a unique key; [HashiCorp documents the required AzureRM backend options](https://developer.hashicorp.com/terraform/language/backend/azurerm). If the remote state container is network restricted, run from a trusted network rather than broadening its firewall for convenience.

```powershell
$env:AZURE_SUBSCRIPTION_ID = '<lab-subscription-guid>'
$env:ARM_SUBSCRIPTION_ID = $env:AZURE_SUBSCRIPTION_ID
$env:TF_VAR_subscription_id = $env:AZURE_SUBSCRIPTION_ID
$env:TF_VAR_resource_group_name = 'nt542-phase-k-<unique-lab-suffix>'
$env:TF_VAR_storage_account_name = '<globally-unique-lowercase-name>'
$env:TF_VAR_location = '<verified-azure-region>'
$env:TF_VAR_owner = '<lab-owner-id>'
$env:TF_VAR_expires_on = '<YYYY-MM-DD-cleanup-date>'
$env:ARM_USE_AZUREAD = 'true'
$env:ARM_USE_CLI = 'true'
$stateAccount = '<existing-private-state-account>'
$stateContainer = '<existing-state-container>'
$stateKey = 'nt542-phase-k-minimal.tfstate'
az account show --subscription $env:AZURE_SUBSCRIPTION_ID --query '{id:id,name:name,tenantId:tenantId}' -o json
az group exists --subscription $env:AZURE_SUBSCRIPTION_ID --name $env:TF_VAR_resource_group_name
```

Stop unless `az group exists` returns `false` and the subscription, region, names, owner, expiry, state account and state key match the approved plan. Do not reuse a state key that already tracks resources. From the repository root:

```powershell
terraform -chdir=Terraform/azure-minimal-storage init -input=false -lockfile=readonly -backend-config="resource_group_name=<state-resource-group>" -backend-config="storage_account_name=$stateAccount" -backend-config="container_name=$stateContainer" -backend-config="key=$stateKey" -backend-config="use_azuread_auth=true" -backend-config="use_cli=true"
terraform -chdir=Terraform/azure-minimal-storage plan -out=../../build/phase-k-minimal.tfplan
terraform -chdir=Terraform/azure-minimal-storage show ../../build/phase-k-minimal.tfplan
```

Review that the plan creates only the dedicated RG, Storage, Log Analytics and Blob diagnostic setting, with **zero updates/deletions** and no SQL/VPN/VM/Private Endpoint. Also inspect the backend state and resource names. Stop on unexpected resources or costs. Once the owner has approved this exact plan, run `terraform -chdir=Terraform/azure-minimal-storage apply ../../build/phase-k-minimal.tfplan`. The plan file can contain sensitive values and stays private. Record the RG, Storage ID, workspace customer ID and applied timestamp in private evidence.

The minimal Storage account has public network access disabled and no Private Endpoint. It supports ARM configuration scanning but does not allow a laptop to issue Blob data-plane operations. The diagnostic setting alone therefore does not prove that `StorageBlobLogs` contains events. See [Phase I status](phase-i-status.md) for the separate live ingestion checkpoint.

## 4. Scan, drift and remediation story

Start with `acg scan --source azure --service storage --output build/phase-k-evidence.jsonl` after setting `RESOURCE_GROUP` to the dedicated RG and the Storage SDK's `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` for a **read-only** lab identity. Observe the secure baseline. Do not print the secret or put it in a tracked file.

If a controlled live drift test is approved, use a separate operator session with rights only on that Storage account. One reversible example is `az storage account update --subscription $env:AZURE_SUBSCRIPTION_ID --resource-group $env:TF_VAR_resource_group_name --name $env:TF_VAR_storage_account_name --https-only false`. This weakens the secure-transfer configuration even though the minimal profile still blocks public data-plane access, so do it only in the dedicated lab and restore it promptly. [Azure CLI parameter reference](https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest). Re-run `acg scan --source azure --service storage --output build/phase-k-evidence.jsonl` and confirm `ACG-STO-001` is found.

```powershell
acg remediation plan --source azure --service storage --finding ACG-STO-001 --output build/phase-k-plan.json
$plan = Get-Content build/phase-k-plan.json -Raw | ConvertFrom-Json
acg remediation apply --plan build/phase-k-plan.json --dry-run
acg remediation approve --plan build/phase-k-plan.json --approver '<reviewer-id>' --confirm-hash $plan.plan_hash --output build/phase-k-approval.json
```

The approver compares the resource ID, before state, desired state, expiry, hash and cost/risk fields. A fixture plan cannot be executed against Azure. For a **separately approved live remediation**, initialize an empty lab exception DB (`acg exception init --db build/phase-k-exceptions.db`), check narrow remediator RBAC, then set `ALLOW_AZURE_MUTATIONS=true` only in that operator session and run `acg remediation apply --plan build/phase-k-plan.json --approval build/phase-k-approval.json --exceptions-db build/phase-k-exceptions.db --execute`. Re-scan and inspect the verification result. If execution is not approved, restore the secure setting manually with `az storage account update ... --https-only true`, then re-scan. Never leave the controlled drift in place.

For an exception demonstration, use `acg exception request`, `activate`, `list`, `verify-chain`, and `revoke` with the exact Storage ARM ID and rule; [Phase G status](phase-g-status.md) gives the arguments and version checks. An active exception for the same resource/rule blocks Phase F execution; close it before attempting remediation. For the incident flow, use a clearly labeled monitor fixture and the `acg incident scan --source fixture` / `acg incident verify --source fixture` sequence in [Phase I status](phase-i-status.md); use a fresh event time after exception activation. Do not claim an Azure Monitor detection from a fixture. A real incident demo needs a separate private data-plane path, successful Blob operation, ingestion evidence, query permission and a follow-up verification.

Run `acg report --input build/phase-k-evidence.jsonl --output build/phase-k-report.html --redact` for the local report. Phase H automatically emits scan events; exception/remediation/incident events are not automatically exported into that same JSONL, so do not present the HTML as a complete lifecycle audit. Keep all real evidence private for at most 30 days as described in [Phase H status](phase-h-status.md).

## 5. Safe cleanup and verification

Use the **same** minimal root and remote state key. First inspect `az group show --subscription $env:AZURE_SUBSCRIPTION_ID --name $env:TF_VAR_resource_group_name --query '{id:id,tags:tags}' -o json` and `az resource list --subscription $env:AZURE_SUBSCRIPTION_ID --resource-group $env:TF_VAR_resource_group_name --query '[].{id:id,type:type}' -o json`. Require the exact approved RG name plus `Project=NT542`, `Purpose=PhaseKMinimalDemo`, `ManagedBy=Terraform`, the expected `Owner`, and the planned `ExpiresOn`. Check the RG inventory for anything added outside Terraform: deleting a resource group can also remove resources absent from the state and destroy plan. If tags, inventory or state are unexpected, stop and investigate; do not delete a broadly selected RG.

```powershell
terraform -chdir=Terraform/azure-minimal-storage state list
terraform -chdir=Terraform/azure-minimal-storage plan -destroy -out=../../build/phase-k-destroy.tfplan
terraform -chdir=Terraform/azure-minimal-storage show ../../build/phase-k-destroy.tfplan
```

Check that the destroy plan contains **only** the four Phase K resources in the dedicated RG and no state/backend resources. Have the owner approve that exact plan, then run `terraform -chdir=Terraform/azure-minimal-storage apply ../../build/phase-k-destroy.tfplan`. This is the reviewed equivalent of `terraform destroy`; direct `terraform destroy` is appropriate only after the same state/RG/resource review. Confirm `az group exists --subscription $env:AZURE_SUBSCRIPTION_ID --name $env:TF_VAR_resource_group_name` returns `false`, inspect the state list and current Cost Management view, and record the cleanup timestamp. If Azure reports residual resources or retention charges, investigate them explicitly. Do not remove the state container until state retention requirements are understood. There is no arbitrary RG deletion wrapper.

Phase K is complete only after the live apply, core demo, reviewed destroy and post-destroy checks are recorded. A green PR CI run verifies offline syntax/tests, not the subscription's prices, quotas, deployment or cleanup.
