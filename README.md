# NT542 Azure Compliance Guard

Một lab DevSecOps phát hiện configuration drift trên Azure Storage, Key Vault và SQL, đánh giá mức độ nghiêm trọng, tạo bằng chứng audit và chuẩn bị remediation có kiểm soát.

> Trạng thái hiện tại: educational lab đang được harden theo hướng portfolio. Dự án chưa production-ready và chưa nên chạy mutation trên subscription quan trọng.

## Giá trị chính

- Terraform tạo baseline private-first gồm VNet, Private Endpoint/DNS, Storage, Key Vault, SQL, Log Analytics, VPN Gateway và jumpbox.
- Python engine thu thập trạng thái thực tế, so sánh với baseline và phân loại `WARNING`, `CRITICAL`, `ESCALATED_CRITICAL`.
- Exception có thời hạn và incident có thể revoke exception.
- Remediation mặc định ở chế độ plan-only; không có Azure mutation nếu operator chưa chủ động bật gate tạm thời.

## Safety baseline

- Azure CLI luôn được gọi bằng argument vector, kèm `--subscription` lấy từ `AZURE_SUBSCRIPTION_ID`; không dùng `shell=True`.
- `ALLOW_AZURE_MUTATIONS` mặc định là `false`.
- Microsoft Defender for SQL luôn là `MANUAL_ONLY` vì thao tác này thay đổi pricing ở scope subscription.
- Incident containment cũng chỉ tạo plan khi mutation chưa được bật.
- Không có `terraform apply` hoặc `terraform destroy` trong test/CI offline.

`ALLOW_AZURE_MUTATIONS=true` chỉ là gate tạm thời của P0 cho lab có kiểm soát. Nó chưa thay thế workflow mục tiêu `Plan -> Approval -> Execute -> Verify`, vì chưa có plan hash, approval binding, stale-state check và post-remediation verification.

## Luồng hiện tại

```text
Terraform baseline
      |
Azure SDK / Azure CLI collectors
      |
normalized configuration + local incident signals
      |
evaluator -> WARNING / CRITICAL / ESCALATED_CRITICAL
      |
plan-only remediation (default) -> audit logs
```

Storage được đọc bằng Azure SDK. Key Vault và SQL hiện dùng Azure CLI. Incident signals hiện vẫn được đọc từ file local `Compliance/data/security_signals.json`; chúng chưa đến từ Azure Monitor/KQL.

## Cấu trúc repository

```text
Compliance/engine/                 Python monitoring engine
Terraform/azure-secure-storage/   Terraform root module
tests/                             Offline safety tests
docs/                              Audit, architecture và report gốc
```

Entrypoint hiện tại là `Compliance/engine/main.py`. Terraform root là `Terraform/azure-secure-storage`.

## Kiểm chứng offline

Các lệnh này không tạo tài nguyên Azure:

Chạy tại repository root với Python 3.14 (`python --version`). `.venv` phải là môi trường mới; không dùng lại `.venv` Python 3.13 cũ.

```powershell
if (Test-Path .venv) { throw 'Move or remove the existing .venv before this clean-environment check.' }
python -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.venv\Scripts\python.exe -m pip check
.venv\Scripts\ruff.exe check .
.venv\Scripts\ruff.exe format --check .
.venv\Scripts\python.exe -m pytest -m "not live" -q --cov=evaluator --cov=remediation --cov=incident_response --cov=azure_cli --cov-report=term-missing --cov-report=xml:coverage.xml --cov-fail-under=80

Set-Location Terraform\azure-secure-storage
terraform fmt -check -recursive
terraform init -backend=false -input=false -lockfile=readonly
terraform validate -no-color
```

`terraform init` cần truy cập Terraform Registry nếu provider chưa có trong cache. File `.terraform.lock.hcl` phải được commit cùng P0 để pin provider đã resolve.

`pyproject.toml` là nguồn khai báo dependency trực tiếp. `requirements.lock` khóa runtime; `requirements-dev.lock` khóa runtime cùng công cụ test/lint cho Python 3.14. Cả hai pin version và SHA-256; `Compliance/engine/requirements.txt` chỉ giữ vai trò tương thích với lệnh cài cũ và trỏ về runtime lock. Khi chủ động nâng dependency, tạo lại hai lock bằng `uv` từ repository root rồi cài và chạy test trong một virtual environment mới:

```powershell
.venv\Scripts\uv.exe pip compile pyproject.toml --generate-hashes --python-version 3.14 --output-file requirements.lock
.venv\Scripts\uv.exe pip compile pyproject.toml --extra dev --generate-hashes --python-version 3.14 --output-file requirements-dev.lock
```

Pytest mặc định bỏ qua test gắn marker `live`; dùng `python -m pytest -m "not live"` để kiểm tra tường minh. Các test Phase C dùng fixture/mock và không đăng nhập hay tạo tài nguyên Azure.

## Offline CI (Phase D)

`.github/workflows/ci.yml` chạy trên mọi pull request và mỗi push vào `main`: Ruff lint/format, pytest offline với ngưỡng coverage 80% cho bốn module quyết định, Terraform fmt/init/validate và Trivy config scan (chặn finding `HIGH`/`CRITICAL`). Workflow không khai báo Azure credential, không gọi `az login`, `terraform plan`, `apply` hoặc `destroy`. `terraform validate` kiểm tra cấu hình nội bộ, không chứng minh tài nguyên live hoặc mức độ tuân thủ CIS.

Các action được pin theo commit SHA và token chỉ có `contents: read`. `.github/dependabot.yml` theo dõi Python và GitHub Actions; khi Dependabot cập nhật `pyproject.toml`, phải tạo lại cả hai file `requirements*.lock` bằng `uv`, kiểm tra diff rồi chạy CI trước khi merge. Không merge PR chỉ thay manifest mà lockfile chưa đồng bộ.

Chỉ sau khi workflow chạy thành công trên GitHub mới có thể coi CI là xanh. Trong repository public, bật **Settings → Advanced Security → CodeQL analysis → Default setup**, **Secret scanning** và **Push protection** nếu các tùy chọn hiện ra; bật required status checks và review trên nhánh `main` trong **Settings → Rules**. Các thiết lập này cần chủ repo thực hiện trên GitHub; file workflow không tự bật chúng.

## Chạy monitor trong lab

Python engine hiện dùng hai nguồn identity khác nhau:

- Storage SDK: service principal từ biến môi trường.
- Key Vault/SQL collectors và remediation: identity đã đăng nhập Azure CLI, nhưng mọi lệnh được scope bằng `AZURE_SUBSCRIPTION_ID` trong `.env`.

Đây là limitation đã biết. Chỉ chạy trong lab riêng, với identity và RBAC tối thiểu phù hợp từng thao tác. Không cấp `Contributor` ở subscription chỉ để monitor hoạt động.
Trước khi chạy monitor, kiểm tra `az account show --subscription <subscription-id-from-.env> --query id -o tsv` truy cập được subscription mới; nếu Azure CLI chưa đăng nhập hoặc identity không có quyền ở subscription đó, các collector Key Vault/SQL sẽ không hoạt động dù Storage SDK có credential riêng. Engine từ chối lệnh CLI khi ID thiếu/sai định dạng hoặc có tham số cố override subscription.

```powershell
Set-Location Compliance\engine
python -m pip install -r requirements.txt
python main.py
```

Các biến cấu hình chính:

```text
AZURE_TENANT_ID
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET
AZURE_SUBSCRIPTION_ID
RESOURCE_GROUP
STORAGE_ACCOUNT_NAME
KEY_VAULT_NAME
SQL_SERVER_NAME
ALLOW_AZURE_MUTATIONS=false
```

Không commit `.env`, Terraform state, `*.tfvars`, log, database hoặc private evidence.

## Known limitations

- Chưa có CLI chuẩn hóa; monitor vẫn là vòng lặp liên tục.
- Rule và expected state còn hard-code trong Python, chưa chuyển sang YAML có schema.
- Chưa có approval artifact, stale-plan protection, rollback hoặc verification loop.
- Incident detection vẫn dựa trên fixture local, chưa phải Azure Monitor/KQL.
- Exception state và evidence còn dùng file local; chưa có SQLite/HTML report.
- Offline CI và IaC scan đã được cấu hình ở Phase D nhưng chưa xác nhận run xanh trên GitHub; OIDC và CodeQL/default secret scanning vẫn cần triển khai hoặc bật trong GitHub Settings.
- Terraform full profile gồm tài nguyên có chi phí như VPN Gateway, VM, SQL, Private Endpoint và Log Analytics.
- Chưa có kết quả đối chiếu live với Azure Policy/Prowler; chưa claim coverage theo một CIS control cụ thể.

## Mốc demo mục tiêu

```text
Create intentional Storage drift
  -> detect violation
  -> generate remediation plan
  -> approve exact plan
  -> execute allowlisted action
  -> re-scan and verify PASS
  -> export HTML evidence report
```

Roadmap dài hạn nằm ở `NT542_Azure_Compliance_Guard_Upgrade_Roadmap.md`. Checklist thực thi ngắn hạn được quản lý riêng trong `tasks/` và không commit.
Baseline phương pháp đối chiếu nằm ở [`docs/validation/methodology.md`](docs/validation/methodology.md); các mapping Storage ban đầu trong [`docs/validation/control-crosswalk.md`](docs/validation/control-crosswalk.md) đều đang `UNVERIFIED`.

## Tài liệu tham khảo

- [CIS Microsoft Azure Storage Services Benchmark](https://www.cisecurity.org/benchmark/azure)
- [AzureRM Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Azure SDK for Python](https://learn.microsoft.com/azure/developer/python/)
- [Azure Storage security recommendations](https://learn.microsoft.com/azure/storage/blobs/security-recommendations)
