# Phase J — DevSecOps maturity status

## Implemented in the branch

- PR CI remains offline with read-only repository access, Python lint/tests, Terraform validation, and Trivy IaC scan.
- Manual `azure-plan` workflow uses short-lived OIDC, a protected-environment hook, a `main` guard, an existing shared state requirement, and plan only. It never uploads plan or state.
- The scanner, remediator, and plan identities and their intended resource scopes are documented in [Phase J operations](phase-j-operations.md). Actual Entra apps, RBAC, and federation are not yet configured or verified.
- Terraform backend is partial and uses Azure AD/OIDC from the workflow. Dependabot also tracks Terraform.
- Release policy, changelog, contribution guide, security policy, and a tag-triggered draft release workflow with SPDX SBOM and GitHub attestations are present. No release tag or attestations have been created yet.
- Optional Docker image (J7) is deferred; it is not needed for the CLI or release checkpoint.

## Pending external acceptance

1. Configure and protect `azure-plan` in GitHub; set its secrets and variables.
2. Create the separate Entra plan, scanner, and remediator principals; add one exact GitHub environment federated credential; assign only the reviewed scopes.
3. Provision a private state container, migrate the existing lab state safely, and prove the workflow can reach it.
4. Dispatch the plan on `main`, capture a successful OIDC login and plan result, and verify no Azure token is issued to PR jobs.
5. After merge and green CI, create a version tag from `main`; verify wheel, SBOM, attestation provenance, and draft release before publishing.
6. Confirm Dependabot, CodeQL, secret scanning/push protection and branch/tag rules in GitHub Settings where available.

The Terraform root has paid resources and sensitive state. No live Azure resource or repository security setting was changed by these branch edits.
