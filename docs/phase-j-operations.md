# Phase J: identities, manual plan, and release

Phase J keeps pull request CI offline. `.github/workflows/azure-plan.yml` is a separate `workflow_dispatch` job, gated to the `main` branch and the `azure-plan` environment. It can only run `terraform plan`; no workflow runs `apply` or `destroy`. Configure the environment before dispatching it. Until the Azure setup and one successful manual run are recorded, the Azure checkpoint is **pending**.

## 1. Prepare Azure plan identity and environment

Create a dedicated Microsoft Entra application/service principal named for the GitHub plan job. Give it **Reader** only on the dedicated lab resource group to start. Test its plan against actual state; if AzureRM needs a further read action, review that exact API call before adding a scoped permission. Do not assign subscription Contributor or use this identity for remediation. The Terraform root manages the resource group itself, so resource-group read access must also be tested; failures may require a narrowly scoped parent read assignment.

Configure one federated credential on that application:

| Claim | Value |
| --- | --- |
| Issuer | `https://token.actions.githubusercontent.com` |
| Subject | `repo:NtQuang-23521287/NT542-CIS-Azure-Storage:environment:azure-plan` |
| Audience | `api://AzureADTokenExchange` |

The environment name and case must match. In GitHub **Settings → Environments**, create `azure-plan`, allow only `main`, and add required reviewers if the repository plan permits. Prevent self-approval where available. An environment reference alone does not create a reviewer gate. Set these **environment secrets**: `AZURE_PLAN_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `TF_VAR_VPN_CLIENT_ROOT_CERTIFICATE_DATA`, and `TF_VAR_JUMPBOX_SSH_PUBLIC_KEY`. The last two hold the public certificate body and public SSH key required by this Terraform root. Do not put an Azure client secret in Actions.

State is separate from the lab stack. Provision a private Azure Storage container for state outside this Terraform root. Give the **plan service principal** `Storage Blob Data Contributor` at that container scope only; Terraform needs a state lease even for a locked plan. Set environment variables `TF_STATE_ACCOUNT`, `TF_STATE_CONTAINER`, and `TF_STATE_KEY` (for example, `lab.terraform.tfstate`). The workflow checks that the named blob exists before `terraform init`, so an empty backend cannot silently produce a create-everything plan. Migrate the existing local lab state into that blob from a trusted operator machine, back it up securely first, and verify the state lineage/resource count. Never upload or commit state, plan files, `.terraform/`, or `*.tfvars`. A state account with network restrictions must be reachable by the chosen runner; change runner/network design rather than opening the state account publicly as a shortcut.

The Azure owner can use the following PowerShell outline in the dedicated lab after checking that these app names and scopes are unused. It creates no password credential. Set the placeholders from the lab and keep the generated federation JSON under ignored `build/`:

```powershell
$subscriptionId = '<lab-subscription-guid>'
$labRg = '<dedicated-lab-resource-group>'
$stateRg = '<state-resource-group>'
$stateAccount = '<state-storage-account>'
$stateContainer = '<state-container>'
$appId = az ad app create --display-name 'nt542-github-plan' --query appId -o tsv
$planObjectId = az ad sp create --id $appId --query id -o tsv
New-Item -ItemType Directory -Force build | Out-Null
@{
  name = 'github-azure-plan'
  issuer = 'https://token.actions.githubusercontent.com'
  subject = 'repo:NtQuang-23521287/NT542-CIS-Azure-Storage:environment:azure-plan'
  audiences = @('api://AzureADTokenExchange')
} | ConvertTo-Json | Set-Content -Encoding utf8 build/phase-j-federation.json
az ad app federated-credential create --id $appId --parameters build/phase-j-federation.json
$labScope = "/subscriptions/$subscriptionId/resourceGroups/$labRg"
$containerScope = "/subscriptions/$subscriptionId/resourceGroups/$stateRg/providers/Microsoft.Storage/storageAccounts/$stateAccount/blobServices/default/containers/$stateContainer"
az role assignment create --assignee-object-id $planObjectId --assignee-principal-type ServicePrincipal --role Reader --scope $labScope
az role assignment create --assignee-object-id $planObjectId --assignee-principal-type ServicePrincipal --role 'Storage Blob Data Contributor' --scope $containerScope
```

Use `$appId` as `AZURE_PLAN_CLIENT_ID` and the matching tenant/subscription IDs as the other environment secrets. The owner must have permission to register applications and assign these roles. Verify the resulting role assignments and federated credential in Azure before dispatching; do not copy the plan identity into the scanner or remediator configuration. Sources: [Azure CLI federated credential](https://learn.microsoft.com/en-us/cli/azure/ad/app/federated-credential), [Azure CLI role assignment](https://learn.microsoft.com/en-us/cli/azure/role/assignment), [container scope](https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access).

Run **Actions → Manual Azure plan → Run workflow** on `main` only after the environment, federation, scoped roles, state, and public input values are ready. Review the GitHub run and Azure sign-in/activity logs. A successful Terraform plan is a configuration and drift preview against the shared state, not permission to apply it. Only an explicit operator on a trusted machine may run `apply` or `destroy` after reviewing the plan and cost. The Terraform stack contains paid VM, VPN Gateway, SQL, Private Endpoint, and Log Analytics resources.

Sources: [GitHub OIDC for Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure), [Azure Login OIDC](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect), [GitHub environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments), [AzureRM backend and container role](https://developer.hashicorp.com/terraform/language/backend/azurerm), [Terraform partial backend and state migration](https://developer.hashicorp.com/terraform/language/backend).

## 2. Separate scanner and remediator

Use **three different principals**: GitHub plan, local scanner, and local remediator. They must have different client IDs and must never share one broad subscription role. The scanner and remediator run from separate operator sessions or machines with separate Azure CLI logins and environment files; the current local CLI uses an SDK service principal for Storage and the Azure CLI identity for Key Vault/SQL. Check both credentials before any live run. The Phase F `--execute` path still requires a local approval file, an exceptions database, and `ALLOW_AZURE_MUTATIONS=true`; those are workflow checks, not replacements for Azure RBAC.

| Principal | Required scope | Candidate permissions | Boundary |
| --- | --- | --- | --- |
| Scanner | Dedicated lab resource group | Reader | Storage, SQL, Key Vault and network control-plane reads; no writes. |
| Scanner | The one Log Analytics workspace | Log Analytics Data Reader | Query `StorageBlobLogs` for Phase I. Validate table access in lab. |
| Scanner | The one Key Vault | Key Vault Reader | List key/secret metadata only; no values. |
| Remediator | Each exact lab Storage account, Key Vault, SQL server | Custom role with `Microsoft.Storage/storageAccounts/read`, `Microsoft.Storage/storageAccounts/write`, `Microsoft.KeyVault/vaults/read`, `Microsoft.KeyVault/vaults/write`, `Microsoft.Sql/servers/read`, `Microsoft.Sql/servers/write` as applicable | Assign on each resource, not the subscription or whole lab RG; include only the resource type's read/write in each role. |

The executable remediation allowlist currently changes only Storage HTTPS/TLS/public network, Key Vault public network/RBAC, and SQL TLS/public network. Azure RBAC `*/write` applies to a whole resource type, not individual fields; this role is still broader than the seven application actions. Keep the per-resource scope and reviewed plan/approval checks, and verify exact operations in a disposable lab before granting the role. Never grant `Owner`, `Contributor`, `User Access Administrator`, `listKeys`, Key Vault secret values, or wildcard write as a shortcut. The legacy SQL Defender check calls subscription-level `az security pricing show`; RG Reader cannot satisfy it. Leave that control unverified until a dedicated subscription read action or revised collector is reviewed.

Sources: [Azure custom roles and action limits](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles), [Log Analytics access](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/manage-access), [Key Vault Reader metadata scope](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/security).

## 3. Repository security and release

Dependabot tracks Python, Actions, and Terraform. Review provider and action updates with CI; regenerate both hash lockfiles when Python dependencies change. In repository settings, enable Dependabot alerts/security updates, CodeQL default setup, secret scanning/push protection, and required CI checks on `main` wherever the account supports them. These settings are not enabled merely by files in the branch.

`pyproject.toml` already declares version `0.2.0`; Phase J does not reset it to `0.1.0`. Before releasing, update the version and `CHANGELOG.md` if needed, merge a reviewed PR after offline CI, then create an annotated `vX.Y.Z` tag pointing to that `main` commit. Protect `v*` tags with a repository ruleset where available. A tag triggers the release workflow, which checks tag/version/branch reachability, builds wheel and source archive, creates an SPDX JSON SBOM for the wheel, attests the artifacts, and creates a **draft** GitHub release. Review its assets and attestations before publishing the draft. No Azure token is involved. The release job requires `contents: write`, `id-token: write`, and `attestations: write` only on the tag workflow. Artifact attestations require a supported repository plan; public repositories on current GitHub plans are supported. Check the run before treating provenance as complete.

For the first `0.2.0` release, after confirming the tag does not already exist and the checked-out commit is the reviewed `main` head, a maintainer can run:

```bash
git tag -a v0.2.0 -m "Release 0.2.0"
git push origin v0.2.0
```

After downloading a release wheel, verify its origin and SBOM attestation:

```bash
gh attestation verify dist/nt542_cis_azure_storage-*.whl -R NtQuang-23521287/NT542-CIS-Azure-Storage
gh attestation verify dist/nt542_cis_azure_storage-*.whl -R NtQuang-23521287/NT542-CIS-Azure-Storage --predicate-type https://spdx.dev/Document/v2.3
```

Inspect the returned repository, tag, commit SHA, workflow and digest against the intended release. A passing local build without a GitHub attestation does **not** prove provenance. Source: [GitHub artifact attestation and verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
