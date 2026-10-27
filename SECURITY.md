# Security policy

This is an educational Azure lab. The currently declared Python version is `0.2.0`; it has no production support promise. Security fixes are reviewed on `main` and documented in `CHANGELOG.md`.

Report suspected vulnerabilities privately through this repository's **Security → Report a vulnerability** form when private vulnerability reporting is enabled. If that form is unavailable, open an issue asking the maintainers for a private contact method **without including exploit details, tokens, or resource identifiers**. Do not post secrets in issues or pull requests.

If a credential, Terraform state, plan file, or private evidence is exposed, revoke or rotate the credential first, then remove the exposed data and review the Azure/GitHub audit logs. Git history removal alone does not invalidate a leaked credential. Keep Azure credentials in local environment files or protected GitHub environment secrets; the plan workflow uses OIDC and never stores `AZURE_CLIENT_SECRET`.

See [Phase J operations](docs/phase-j-operations.md) for the trust boundaries and current lab limitations.
