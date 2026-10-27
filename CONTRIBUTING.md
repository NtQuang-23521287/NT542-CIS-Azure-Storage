# Contributing

Open an issue or a focused pull request against `main`. Keep Azure lab resources and credentials out of pull requests. Include the problem, intended behavior, and offline evidence with code changes.

Run the same checks as PR CI:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
ruff check .
ruff format --check .
python -m pytest -m "not live" -q --cov=evaluator --cov=remediation --cov=incident_response --cov=azure_cli --cov-fail-under=80
cd Terraform/azure-secure-storage
terraform fmt -check -recursive
terraform init -backend=false -input=false -lockfile=readonly
terraform validate -no-color
```

Do not run Terraform `apply` or `destroy` as part of a PR. Azure plans use the separate manual workflow after the lab environment and remote state are configured. Review `.github/workflows/ci.yml` and [Phase J operations](docs/phase-j-operations.md) before changing workflow permissions. Keep `requirements.lock` and `requirements-dev.lock` synchronized with `pyproject.toml` when dependencies change. Release changes update both `pyproject.toml` and `CHANGELOG.md`; a maintainer tags the reviewed `main` commit as `vX.Y.Z`.
