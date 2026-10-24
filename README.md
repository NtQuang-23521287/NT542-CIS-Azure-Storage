# NT542 Azure Compliance Guard

Một lab DevSecOps phát hiện configuration drift trên Azure Storage, Key Vault và SQL, đánh giá mức độ nghiêm trọng, tạo bằng chứng audit và chuẩn bị remediation có kiểm soát.

> Trạng thái hiện tại: educational lab đang được harden theo hướng portfolio. Dự án chưa production-ready và chưa nên chạy mutation trên subscription quan trọng.

## Giá trị chính

- Terraform tạo baseline private-first gồm VNet, Private Endpoint/DNS, Storage, Key Vault, SQL, Log Analytics, VPN Gateway và jumpbox.
- Python engine thu thập trạng thái thực tế, so sánh với baseline và phân loại `WARNING`, `CRITICAL`, `ESCALATED_CRITICAL`.
- Exception có thời hạn và incident có thể revoke exception.
- Legacy monitor chỉ tạo gợi ý remediation. CLI Phase F tạo plan, dry-run, phê duyệt đúng hash, kiểm tra điều kiện, thực thi action cho phép và re-scan.

## Safety baseline

- Azure CLI luôn được gọi bằng argument vector, kèm `--subscription` lấy từ `AZURE_SUBSCRIPTION_ID`; không dùng `shell=True`.
- `ALLOW_AZURE_MUTATIONS` mặc định là `false` và chỉ là một gate bổ sung cho `acg remediation apply --execute`.
- Microsoft Defender for SQL luôn là `MANUAL_ONLY` vì thao tác này thay đổi pricing ở scope subscription.
- Legacy incident containment luôn chỉ tạo gợi ý, kể cả khi mutation gate được bật.
- Không có `terraform apply` hoặc `terraform destroy` trong test/CI offline.

Monitor cũ không còn thực thi Azure mutation dù `ALLOW_AZURE_MUTATIONS=true`. CLI Phase F yêu cầu plan Azure còn hạn, approval đúng `plan_id/hash`, exception store hợp lệ và trạng thái tài nguyên chưa đổi trước khi gọi executor.

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
src/azure_compliance_guard/       Installable CLI and typed scan engine
Compliance/engine/                Legacy monitoring/remediation workflows
Terraform/azure-secure-storage/   Terraform root module
tests/                             Offline safety tests
docs/                              Audit, architecture và report gốc
```

Entrypoint Phase E là `acg`; legacy monitor vẫn ở `Compliance/engine/main.py` trong thời gian migrate tăng dần. Terraform root là `Terraform/azure-secure-storage`.

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

## Phase E CLI (offline scan scope)

The installable CLI uses the `src/azure_compliance_guard` package while the
legacy monitor remains available during the incremental migration. Install the
project with Python 3.14, then inspect the command surface:

```powershell
python -m pip install -e .
acg --help
```

`doctor` is read-only. It checks the Python runtime, Azure CLI and authentication,
subscription selection, Terraform, SQLite, optional Log Analytics configuration,
and confirms that Azure mutation is disabled by default:

```powershell
acg doctor
```

The deterministic offline scan supports Storage, Key Vault, SQL, or all three
services. It uses packaged intentional-drift fixtures and schema-v1 rule
catalogs by default:

```powershell
acg scan --source fixture
acg scan --source fixture --format json
acg scan --source fixture --service all --format json
acg watch --source fixture --service all --interval 60
acg watch --source fixture --service sql --format jsonl --iterations 2
```

`scan` always performs one collection cycle and exits. `watch` is the explicit
continuous mode; `--iterations` makes it bounded for automation and `jsonl`
emits one complete JSON document per cycle. Azure mode uses the Storage SDK and
read-only Azure CLI adapters for Key Vault and SQL. Every CLI call is bound to
the validated `AZURE_SUBSCRIPTION_ID` and uses `shell=False`.

CLI exit codes are stable: `0` means no blocking findings, `1` means policy
findings were detected, `2` means an operational/runtime failure, and `3` means
invalid configuration or rules. The packaged drift fixture intentionally exits
with `1`. Current offline scope and deferred live-validation work are recorded in
[`docs/phase-e-status.md`](docs/phase-e-status.md).

## Phase H evidence report (offline)

Install the project, then run the roadmap checkpoint from the repository root:

```powershell
acg scan --source fixtures/demo_environment.json --output build/evidence.jsonl
acg report --input build/evidence.jsonl --output build/report.html --redact
```

The demo fixture intentionally produces findings, so `scan` exits with code `1`;
the JSONL evidence is still written and `report` exits with `0`. Open
`build/report.html` locally. The committed [sample report](docs/samples/phase-h-report.html)
and [sample evidence](docs/samples/phase-h-evidence.jsonl) include fixture-only
validation and explicitly simulated lifecycle events. Generate them again in a
fresh directory with `python -m scripts.phase_h_sample <directory>`.

The report always applies public redaction. Keep evidence generated from an
Azure subscription and any operational report private under `build/` or
`reports/private/`. Retain them for at most 30 days for this lab, then remove
them according to your local retention procedure. There is no automatic upload
or GitHub Pages publication. See [Phase H status](docs/phase-h-status.md) for
data provenance, validation scope, and current limits.

## Phase F remediation workflow

Có thể kiểm tra lập kế hoạch và dry-run mà không cần Azure:

```powershell
$planPath = Join-Path $env:TEMP "acg-plan-$PID.json"
$approvalPath = Join-Path $env:TEMP "acg-approval-$PID.json"
acg remediation plan --finding ACG-STO-001 --source fixture --output $planPath
$plan = Get-Content $planPath -Raw | ConvertFrom-Json
acg remediation approve --plan $planPath --approver $env:USERNAME --confirm-hash $plan.plan_hash --output $approvalPath
acg remediation apply --plan $planPath --dry-run
```

`--finding` nhận `finding_id` từ kết quả `acg scan --format json`, hoặc rule ID nếu chỉ có một finding khớp; thêm `--resource` để chọn tài nguyên khi cần. Plan và approval là JSON riêng, không ghi đè file có sẵn. Plan từ fixture không thể được thực thi trên Azure.

Live lab execution requires an Azure plan, exact approval, `ALLOW_AZURE_MUTATIONS=true`, and `--exceptions-db` pointing to an initialized SQLite database. The CLI checks the subscription, rule, handler, plan hash, expiry, approval, active exceptions and full before state before mutation. See [Phase F status](docs/phase-f-status.md) and [Phase G status](docs/phase-g-status.md) for the current boundaries.

## Jumpbox SSH key

Jumpbox private cần `jumpbox_ssh_public_key` và không cho đăng nhập bằng mật khẩu. Trước lần `terraform plan/apply` sau này, tạo cặp khóa trên máy của bạn; chỉ đưa public key cho Terraform. Trong PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
ssh-keygen -t rsa -b 4096 -f "$env:USERPROFILE\.ssh\nt542_jumpbox"
$env:TF_VAR_jumpbox_ssh_public_key = (Get-Content "$env:USERPROFILE\.ssh\nt542_jumpbox.pub" -Raw).Trim()
```

Giữ private key và passphrase ngoài Git, `.tfvars` và Terraform state. Biến môi trường trên chỉ tồn tại trong phiên terminal hiện tại. VM không có public IP; kết nối qua Point-to-Site VPN. Nếu VM đã tồn tại, đổi từ mật khẩu sang SSH key có thể khiến Terraform thay thế VM; phải đọc plan trước khi apply.

## Offline CI (Phase D)

`.github/workflows/ci.yml` chạy trên mọi pull request và mỗi push vào `main`: Ruff lint/format, pytest offline với ngưỡng coverage 80% cho bốn module quyết định, Terraform fmt/init/validate và Trivy config scan (chặn finding `HIGH`/`CRITICAL`). Workflow không khai báo Azure credential, không gọi `az login`, `terraform plan`, `apply` hoặc `destroy`. `terraform validate` kiểm tra cấu hình nội bộ, không chứng minh tài nguyên live hoặc mức độ tuân thủ CIS.

Các action được pin theo commit SHA và token chỉ có `contents: read`. `.github/dependabot.yml` theo dõi Python và GitHub Actions; khi Dependabot cập nhật `pyproject.toml`, phải tạo lại cả hai file `requirements*.lock` bằng `uv`, kiểm tra diff rồi chạy CI trước khi merge. Không merge PR chỉ thay manifest mà lockfile chưa đồng bộ.

Chỉ sau khi workflow chạy thành công trên GitHub mới có thể coi CI là xanh. Trong repository public, bật **Settings → Advanced Security → CodeQL analysis → Default setup**, **Secret scanning** và **Push protection** nếu các tùy chọn hiện ra; bật required status checks và review trên nhánh `main` trong **Settings → Rules**. Các thiết lập này cần chủ repo thực hiện trên GitHub; file workflow không tự bật chúng.

## Chạy monitor trong lab

Python engine hiện dùng hai nguồn identity khác nhau:

- Storage SDK: service principal từ biến môi trường.
- Key Vault/SQL collectors và executor Phase F: identity đã đăng nhập Azure CLI, nhưng mọi lệnh được scope bằng `AZURE_SUBSCRIPTION_ID` trong `.env`. Legacy monitor chỉ đọc và tạo gợi ý.

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
```

`ALLOW_AZURE_MUTATIONS=true` chỉ dùng khi chủ động chạy `acg remediation apply --execute`, không bật mutation cho monitor cũ.

Không commit `.env`, Terraform state, `*.tfvars`, log, database hoặc private evidence.

## Known limitations

- The CLI provides `doctor`, `scan`, `watch`, Phase F remediation, Phase G SQLite exception governance, and Phase H local JSONL/HTML reporting. Automated lifecycle export is still pending.
- Storage, Key Vault và SQL đã có 17 rule YAML schema-v1; mapping CIS/Azure Policy/Prowler vẫn chưa được xác minh bằng nguồn pinned và lab live.
- Approval file Phase F là xác nhận cục bộ tự khai báo, chưa có xác thực danh tính hoặc chữ ký số. Chưa có rollback hay ledger bền vững chống chạy lặp sau lỗi không rõ kết quả.
- Incident detection vẫn dựa trên fixture local, chưa phải Azure Monitor/KQL.
- Exception state uses local SQLite. Evidence and sanitized HTML reports are local files; there is no remote audit store or authenticated publication workflow.
- Offline CI và IaC scan đã được cấu hình ở Phase D; Phase G PR đã qua CI theo kết quả được báo cáo. Phase H cần CI trên PR mới; OIDC và CodeQL/default secret scanning vẫn cần triển khai hoặc bật trong GitHub Settings.
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
