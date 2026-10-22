# NT542-CIS-Azure-Storage — Master Upgrade Roadmap A→Z

> Mục tiêu: nâng cấp đồ án từ một bài lab/script kiểm tra cấu hình Azure thành một **Azure continuous-compliance & controlled-remediation system** có thể demo được, vận hành có kỷ luật, có bằng chứng kỹ thuật rõ ràng và đủ tốt để đưa vào CV/portfolio.

> Trạng thái thực thi 2026-10-22: dùng **Implementation-first, Learning-on-demand**. Phase A được rút thành technical audit; Phase B/P0 đã có kiểm chứng offline và các commit cục bộ trên `main`. Xem `docs/baseline.md` để biết bằng chứng và giới hạn. Các ô “Học/Phải trả lời được” dưới đây vẫn là câu hỏi tự kiểm tra của người học, không được tự động đánh dấu chỉ vì code đã thay đổi. Chưa tạo nhánh mới hoặc push lên GitHub.

**Baseline chính:** `deep-research-report (2).md`<br>
**Cách dùng tài liệu này:** đây không phải danh sách “code thật nhanh cho xong”. Mỗi chặng đều có phần **Học → Hiểu → Làm → Kiểm tra → Điều kiện qua chặng** để người thực hiện hiểu vì sao hệ thống được thiết kế như vậy.

---

## 0. Quy ước của roadmap

- **[DR]**: nội dung bám trực tiếp theo hướng đề xuất trong deep-research.
- **[ADD]**: bổ sung từ quá trình thiết kế roadmap này để tăng giá trị vận hành/CV nhưng không làm thay đổi kiến trúc lõi.
- **[OPTIONAL]**: chỉ làm sau khi core system đã ổn định.
- Mỗi task chỉ nên được đánh dấu hoàn thành khi **có cách kiểm chứng**.
- Không triển khai nhiều subsystem cùng lúc. Hoàn thành checkpoint rồi mới đi tiếp.

### Nguyên tắc bất biến của hệ thống

- [ ] Scan **không được** làm thay đổi Azure.
- [ ] Finding **không đồng nghĩa** với remediation.
- [ ] Mọi mutation phải đi qua: `Finding → Policy → Plan → Approval/Policy Gate → Execute → Re-collect → Verify`.
- [ ] Exit code `0` của Azure CLI/SDK không đồng nghĩa remediation thành công; chỉ **rule re-evaluation PASS** mới được tính là `VERIFIED`.
- [ ] Pull-request CI không dùng Azure credential và không tạo chi phí Azure.
- [ ] Không lưu long-lived Azure client secret trong GitHub Actions nếu có thể dùng OIDC.
- [ ] Public report phải redact dữ liệu nhạy cảm.
- [ ] Tác vụ có khả năng phát sinh chi phí subscription-level phải là `MANUAL_ONLY` hoặc cần explicit cost approval.
- [ ] Core engine phải chạy được bằng fixture, không phụ thuộc Azure thật.
- [ ] Rule chỉ được claim là đã kiểm chứng khi có ground truth rõ ràng và kết quả được đối chiếu với reference implementation/tool phù hợp.
- [ ] External tool agreement là bằng chứng bổ sung, không thay thế ground truth; mọi bất đồng phải được phân tích thay vì chọn kết quả thuận lợi.

---

# 1. Hệ thống cuối cùng phải trông như thế nào?

```text
Terraform Secure Baseline
          ↓
      Azure Resources
 Storage / Key Vault / SQL
          ↓
      Collectors
 ARM/SDK/CLI + Azure Monitor
          ↓
    Normalized State
          ↓
 Versioned YAML Rules
          ↓
      Rule Engine
          ↓
       Findings
          ↓
 Decision / Policy Engine
     ↙           ↘
Exceptions     Incident Signals
(SQLite)      (Log Analytics/KQL)
     ↘           ↙
   Remediation Planner
          ↓
       Dry Run
          ↓
       Approval
          ↓
       Executor
          ↓
      Re-collect
          ↓
       Verify
          ↓
 append-only evidence.jsonl
          ↓
 self-contained report.html
```

### Core product identity đề xuất

**Azure Compliance Guard (ACG)**<br>
Continuous compliance, drift detection, evidence reporting, exception governance, and controlled remediation for Azure.

---

# 2. A→Z quick index

| Letter | Chủ đề | Kết quả cần đạt |
|---|---|---|
| A | Audit current repository | Hiểu chính xác hệ thống hiện tại |
| B | Baseline correctness | Terraform/Python chạy ở trạng thái có thể tin cậy |
| C | Clean Git/reproducibility | Repo sạch, lockfile đúng, không tracked runtime junk |
| D | Dependencies | Python dependency reproducible |
| E | Engine tests | Rule/decision logic được kiểm thử |
| F | Fixtures | Chạy demo/test không cần Azure |
| G | GitHub Actions | CI offline có quality gates |
| H | Harden remediation | Không còn shell command nguy hiểm/auto mutation mù |
| I | Identity | OIDC + least privilege |
| J | JSONL evidence | Audit trail machine-readable |
| K | KQL/Monitor | Security signal thật từ Azure Storage |
| L | CLI | `acg doctor/scan/report/remediation/...` |
| M | Models | Typed normalized domain models |
| N | Normalized collectors | Storage/Key Vault/SQL về cùng model contract |
| O | Observability | Metrics + timeline + operational report |
| P | Policy-as-data | Rule YAML có version/schema |
| Q | Quality gates | pytest/Ruff/Terraform/Trivy/TFLint |
| R | Reporting | Static HTML dashboard/report |
| S | SQLite | Exception state transactional |
| T | Terraform profiles | `minimal` / `full-demo` |
| U | User/operator experience | Dry-run, clear output, safe commands |
| V | Validation + verification | Đối chiếu external baseline và re-scan sau mutation |
| W | Well-Architected mapping | Chứng minh tư duy kiến trúc Azure |
| X | eXception governance | Lifecycle exception rõ ràng |
| Y | YAML rules | Rules tách khỏi Python code |
| Z | Zero-cost/repeatable demo | Fixture-first + destroy sau live demo |

---

# PHASE A — HIỂU HỆ THỐNG HIỆN TẠI TRƯỚC KHI SỬA

> Không refactor ở phase này. Mục tiêu là dựng mental model chính xác.
>
> Hướng dẫn học và thực hành chi tiết theo repository hiện tại: `tasks/plan.md`. Theo dõi tiến độ tại `tasks/todo.md`.

## A1. Chụp baseline repository

### Học
- Git working tree, branch, commit, tracked/untracked files.
- Sự khác nhau giữa source code, runtime state, generated artifact và secret.

### Làm
- [ ] Checkout branch dùng làm baseline.
- [ ] Ghi commit SHA hiện tại vào `docs/baseline.md` hoặc ghi chú cá nhân.
- [ ] Chạy `git status`.
- [ ] Chụp cây thư mục ở mức cần thiết.
- [ ] Xác định Python entrypoint hiện tại.
- [ ] Xác định Terraform root module.
- [ ] Liệt kê file cấu hình/runtime state hiện có.

### Phải trả lời được
- Chương trình bắt đầu ở file nào?
- Terraform đang tạo những resource nào?
- File nào là source, file nào là runtime-generated?
- Hiện repo có thứ gì đáng lẽ không nên commit?

### Done khi
- [ ] Có sơ đồ thư mục hiện tại.
- [ ] Có danh sách entrypoint, collectors, remediation, exception, Terraform modules.

---

## A2. Trace luồng chạy Python từ đầu đến cuối

### Học
- Function call flow.
- Data flow khác control flow như thế nào.
- Azure management plane vs data plane ở mức khái niệm.

### Làm
- [ ] Đọc `main.py` từ trên xuống.
- [ ] Trace Storage check.
- [ ] Trace Key Vault check.
- [ ] Trace SQL check.
- [ ] Trace finding được tạo ở đâu.
- [ ] Trace exception được đọc/áp dụng ở đâu.
- [ ] Trace remediation được gọi ở đâu.
- [ ] Trace incident/security signal được lấy từ đâu.
- [ ] Trace log/output được sinh ra ở đâu.

### Tự vẽ được

```text
main
 ↓
collect
 ↓
evaluate
 ↓
finding
 ↓
exception/policy
 ↓
remediation
 ↓
log
```

### Done khi
- [ ] Bạn có thể giải thích luồng chạy mà không cần mở code.
- [ ] Bạn biết chính xác chỗ nào đang dùng mock signal.
- [ ] Bạn biết chỗ nào đang mutation Azure.

---

## A3. Hiểu Terraform hiện tại

### Học
- Terraform provider.
- Resource vs data source.
- Variable / local / output.
- State.
- `.terraform.lock.hcl`.
- `terraform init`, `fmt`, `validate`, `plan`, `apply`, `destroy` khác nhau thế nào.

### Làm
- [ ] Đọc `provider.tf`.
- [ ] Đọc `variables.tf`.
- [ ] Đọc `main.tf`.
- [ ] Đọc Storage/Key Vault/SQL/networking/monitoring resources.
- [ ] Đánh dấu resource nào có chi phí đáng kể.
- [ ] Đánh dấu resource nào cần cho `minimal` demo và resource nào chỉ cần cho `full-demo`.

### Phải trả lời được
- Vì sao `terraform validate` không đảm bảo Azure sẽ deploy thành công?
- Vì sao lockfile cần commit?
- Vì sao PR CI không nên `terraform apply`?
- Resource nào tạo ra Log Analytics signal cho Storage?

---

## A4. Hiểu identity/security model hiện tại

### Học
- Azure tenant / subscription / resource group.
- Service principal.
- Azure RBAC.
- `DefaultAzureCredential`.
- GitHub OIDC ở mức khái niệm.
- Least privilege.

### Làm
- [ ] Xác định cách local code login Azure hiện tại.
- [ ] Xác định README hiện tại khuyên dùng client secret hay cách nào khác.
- [ ] Xác định role/scope đang được đề xuất.
- [ ] Xác định scanner cần quyền đọc gì.
- [ ] Xác định remediator cần quyền mutation gì.

### Done khi
- [ ] Bạn phân biệt được scanner identity và remediator identity.
- [ ] Bạn hiểu vì sao không nên dùng broad Contributor ở subscription scope cho toàn hệ thống.

---

## A5. Chọn external credibility baseline và phạm vi đối chiếu

### Vì sao cần bước này

Tests, fixtures và CI chỉ chứng minh implementation chạy ổn định theo kỳ vọng nội bộ. Chúng chưa đủ để chứng minh kết quả compliance của ACG phù hợp với trạng thái Azure thực tế hoặc với cách một công cụ uy tín đánh giá cùng control.

### Reference hierarchy

1. **Ground truth:** trạng thái tài nguyên được dựng có chủ đích và đọc trực tiếp từ ARM/SDK/API.
2. **Platform reference:** Azure Policy built-in definition/compliance state khi có policy tương đương.
3. **Independent peer comparator:** Prowler for Azure với check/compliance framework tương đương.
4. **Optional corroboration:** Microsoft Defender for Cloud Regulatory Compliance nếu subscription, quyền và chi phí cho phép.

> Không coi Prowler, Azure Policy hay Defender for Cloud là chân lý tuyệt đối. Hai công cụ cùng kết quả vẫn có thể cùng sai; ground truth và semantics của từng control mới là cơ sở kết luận.

### Reference documentation

- Azure Policy compliance states: <https://learn.microsoft.com/azure/governance/policy/concepts/compliance-states>
- Azure Policy CLI state/trigger scan: <https://learn.microsoft.com/cli/azure/policy/state>
- Prowler compliance usage: <https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/compliance>
- Defender for Cloud Regulatory Compliance: <https://learn.microsoft.com/azure/defender-for-cloud/concept-regulatory-compliance-standards/>

### Làm

- [ ] Chọn phiên bản cụ thể của CIS/Azure benchmark dùng cho project.
- [ ] Pin hoặc ghi lại phiên bản Prowler dùng để so sánh.
- [ ] Lập danh sách control Storage có semantics tương đương giữa ACG, Azure Policy và Prowler.
- [ ] Xác định control nào không có comparator phù hợp và ghi rõ `NOT_COMPARABLE` thay vì ép mapping.
- [ ] Chọn tập case tối thiểu gồm cả secure state và intentional drift.
- [ ] Ghi rõ quyền Azure và chi phí cần thiết để chạy từng reference tool.

### Artifacts dự kiến

```text
docs/validation/
├── methodology.md
├── control-crosswalk.md
├── results-summary.md
└── disagreements.md
```

### Done khi

- [ ] Có reference hierarchy và scope được ghi thành tài liệu.
- [ ] Có control crosswalk ban đầu cho Storage.
- [ ] Có thể giải thích vì sao Azure Policy và Prowler được chọn, và giới hạn của từng nguồn.

---

## CHECKPOINT A — Knowledge baseline

Chưa được qua Phase B nếu chưa trả lời được:

- [ ] “Project hiện tại đang giải quyết bài toán gì?”
- [ ] “Từng bước từ `main.py` đến finding/remediation diễn ra ở đâu?”
- [ ] “Terraform đang tạo gì và thứ gì tốn tiền?”
- [ ] “Mock signal hiện nằm ở đâu?”
- [ ] “Tại sao current remediation chưa an toàn?”
- [ ] “Exception JSON hiện có rủi ro gì?”
- [ ] “Kết quả rule sẽ được đối chiếu với ground truth và reference tool nào?”

---

# PHASE B — P0: STOP-THE-LINE CORRECTNESS [DR]

> Không thêm feature trước khi baseline sạch và validate được.

## B1. Sửa Terraform variable blocker

### Học
- Variable declaration vs variable reference.
- Optional availability zone configuration.

### Làm
- [ ] Tìm mọi reference tới `vpn_gateway_public_ip_zones`.
- [ ] Quyết định: khai báo variable với default `[]` hoặc loại bỏ `zones` khỏi minimal profile.
- [ ] Chạy format.
- [ ] Init backend-free.
- [ ] Validate.

### Verify

```bash
cd Terraform/azure-secure-storage
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate -no-color
```

### Done khi
- [ ] Cả 3 command PASS.

---

## B2. Làm sạch `.gitignore` và tracked junk

### Học
- Generated file vs source-controlled file.
- Terraform state sensitivity.

### Làm
- [ ] Ignore `__pycache__/`, `*.py[cod]`, `.pytest_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`, `.venv/`.
- [ ] Ignore local evidence/private report, `.db`, WAL/SHM files.
- [ ] Ignore `.terraform/`, state, tfplan.
- [ ] Ignore local `*.tfvars` nếu chứa secret/config private.
- [ ] **Không ignore `.terraform.lock.hcl`.**
- [ ] Remove tracked `__pycache__`/`.pyc` khỏi Git index.

### Verify
- [ ] `git status` không còn bytecode/runtime artifacts.
- [ ] `.terraform.lock.hcl` có thể được track.

---

## B3. Commit Terraform dependency lock

### Học
- Provider version constraint vs resolved provider lock.

### Làm

```bash
cd Terraform/azure-secure-storage
terraform init
```

- [ ] Review `.terraform.lock.hcl`.
- [ ] Commit file này.

### Done khi
- [ ] Clone mới + `terraform init` resolve provider reproducibly theo lock.

---

## B4. Dừng remediation có tác động subscription/cost nguy hiểm

### Học
- Resource-level mutation vs subscription-level service/pricing change.
- Cost guardrail.

### Làm
- [ ] Tìm remediation “Microsoft Defender for SQL disabled”.
- [ ] Không để command enable Defender plan chạy tự động.
- [ ] Chuyển sang `MANUAL_ONLY` hoặc cost-approved policy.
- [ ] Ghi rõ lý do trong docs/code comment phù hợp.

### Done khi
- [ ] Không có path tự động nào có thể bật paid Defender plan ở subscription scope.

---

## B5. Sửa README để không mô tả sai hiện trạng

### Học
- Documentation phải phản ánh implementation hiện tại, không phản ánh “ý định”.

### Làm
- [ ] Ghi đúng phạm vi Storage + Key Vault + SQL hiện tại.
- [ ] Ghi rõ incident signal còn mock nếu chưa P6.
- [ ] Không quảng bá project là production-ready.
- [ ] Không hướng dẫn broad Contributor/client secret như target architecture.
- [ ] Ghi known limitations.

### Done khi
- [ ] Reviewer đọc README không bị hiểu nhầm khả năng hiện tại.

---

## CHECKPOINT B — P0 acceptance

- [ ] `terraform fmt -check -recursive` PASS.
- [ ] `terraform init -backend=false -input=false` PASS.
- [ ] `terraform validate -no-color` PASS.
- [ ] Không tracked `__pycache__`.
- [ ] `.terraform.lock.hcl` tracked.
- [ ] Dangerous paid remediation disabled/manual-only.
- [ ] README không overclaim.

---

# PHASE C — PYTHON REPRODUCIBILITY + TEST FOUNDATION

## C1. Chuẩn hóa dependency management [DR]

### Học
- `pyproject.toml`.
- Runtime dependency vs dev dependency.
- Lock file.
- Reproducible environment.

### Làm
- [x] Tạo `pyproject.toml`.
- [x] Khai báo project metadata.
- [x] Khai báo runtime dependencies.
- [x] Khai báo dev dependencies: pytest, pytest-cov, Ruff, pip-tools hoặc cơ chế lock tương đương.
- [x] Sinh exact tested lock, không copy version ngẫu nhiên từ report.

### Verify
- [x] Tạo virtual environment mới.
- [x] Install từ locked dependencies.
- [x] Existing app vẫn import/run được.

---

## C2. Tạo `tests/` và fixture strategy [DR]

### Học
- Unit test vs integration test vs live test.
- Fixture.
- Mock/monkeypatch.
- Deterministic test.

### Làm

```text
tests/
├── unit/
├── integration/
├── fixtures/
└── live/
```

- [x] Định nghĩa marker `integration`.
- [x] Định nghĩa marker `live`.
- [x] Pytest mặc định chạy `not live`; workflow CI thực tế thuộc Phase D.

### Done khi
- [x] `pytest -m "not live"` chạy được dù chưa có Azure login.

---

## C3. Test rule/evaluation logic trước [DR]

### Học
- Arrange / Act / Assert.
- Boundary cases.

### Test tối thiểu
- [x] expected == actual → PASS.
- [x] expected != actual → FAIL.
- [x] severity được giữ đúng.
- [x] malformed input fail rõ ràng.
- [x] unknown property không bị silently PASS.

### Done khi
- [x] Core decision logic có test deterministic.

---

## C4. Test collectors bằng mock/fixture [DR]

### Storage
- [x] SDK response → normalized config.
- [x] Missing/None fields.
- [x] Azure exception.

### Key Vault / SQL CLI adapters
- [x] Argument vector đúng.
- [x] JSON parse đúng.
- [x] Non-zero exit.
- [x] Invalid JSON.
- [x] Timeout.

### Done khi
- [x] Collector test không gọi Azure thật.

---

## C5. Test current exception/remediation behavior trước khi refactor [DR]

### Mục tiêu
Tạo regression net trước khi thay đổi implementation.

- [x] Exception active/expired behavior.
- [x] Incident escalation behavior.
- [x] Remediation success/failure behavior hiện tại.
- [x] Log/evidence behavior hiện tại nếu có.

### Done khi
- [x] Bạn có test mô tả current behavior, kể cả behavior chuẩn bị thay thế.

---

# PHASE D — P1: OFFLINE CI + QUALITY GATES [DR]

## D1. Ruff lint/format

### Học
- Static analysis khác test runtime như thế nào.

### Làm
- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] Sửa lỗi thực, không spam suppressions.

---

## D2. Pytest + coverage

### Làm
- [ ] Chạy test `not live` trong CI.
- [ ] Sinh `coverage.xml`.
- [ ] Thiết lập coverage gate cho core decision modules.
- [ ] Không dùng coverage % như mục tiêu duy nhất; ưu tiên state transitions và unsafe paths.

---

## D3. Terraform CI

### Pipeline
- [ ] `terraform fmt -check -recursive`.
- [ ] `terraform init -backend=false -input=false`.
- [ ] `terraform validate -no-color`.

### Safety
- [ ] Không Azure login.
- [ ] Không plan/apply trong PR job thông thường.

---

## D4. IaC security scanning [DR]

### Học
- `terraform validate` kiểm syntax/internal consistency.
- IaC scanner kiểm security/misconfiguration khác loại lỗi.

### Làm
- [ ] Thêm Trivy config scan.
- [ ] Thêm TFLint nếu phù hợp.
- [ ] Define severity gate rõ ràng.

---

## D5. GitHub Actions hardening [DR]

- [ ] `permissions: contents: read` hoặc minimum cần thiết.
- [ ] Có `concurrency` để cancel stale runs.
- [ ] Third-party actions được review/pin phù hợp trước production-quality claim.
- [ ] Không đưa Azure secret vào PR CI.

---

## D6. Dependabot / CodeQL / secret scanning [DR]

- [ ] Dependabot cho Python dependencies.
- [ ] Dependabot cho GitHub Actions.
- [ ] CodeQL/default code scanning nếu account/repo hỗ trợ.
- [ ] Secret scanning/push protection nếu khả dụng.

---

## CHECKPOINT D — P1 acceptance

- [ ] `pytest -m "not live"` PASS.
- [ ] Ruff PASS.
- [ ] Terraform validation PASS.
- [ ] IaC scan policy PASS.
- [ ] PR CI cần **0 Azure credential**.
- [ ] CI badge green.

---

# PHASE E — P2: BIẾN SCRIPT THÀNH SẢN PHẨM CLI [DR]

## E1. Chuyển sang `src/` package structure

### Học
- Python package.
- Module boundary.
- Console entrypoint.

### Target

```text
src/azure_compliance_guard/
├── cli.py
├── models.py
├── config.py
├── collectors/
├── evaluator/
├── exceptions/
├── remediation/
├── incidents/
├── evidence/
└── reporting/
```

### Làm
- [ ] Di chuyển code từng slice nhỏ.
- [ ] Không big-bang rewrite.
- [ ] Giữ tests green sau mỗi move.

---

## E2. Tạo typed normalized domain models [DR]

### Học
- Separation of concerns.
- Collector fact vs policy conclusion.
- Dataclass/type model.

### Models nên có
- [ ] `ResourceRef`.
- [ ] `StorageState`.
- [ ] `KeyVaultState`.
- [ ] `SqlState`.
- [ ] `Finding`.
- [ ] `IncidentEvent`.
- [ ] `ExceptionRecord`.
- [ ] `RemediationPlan`.
- [ ] `EvidenceEvent`.

### Nguyên tắc

```text
Collector output = fact
Rule engine output = conclusion
```

### Done khi
- [ ] Fixture collector và Azure collector có thể tạo cùng loại normalized model.

---

## E3. Chuẩn hóa collector interface

### Học
- Adapter pattern vừa đủ dùng.
- Dependency inversion ở mức thực tế, không over-engineer.

### Làm
- [ ] Storage SDK collector trả typed state.
- [ ] Key Vault adapter trả typed state.
- [ ] SQL adapter trả typed state.
- [ ] CLI fallback luôn dùng argument array + `shell=False`.

### Done khi
- [ ] Rule engine không biết state đến từ SDK, CLI hay fixture.

---

## E4. Chuyển rules khỏi Python sang versioned YAML [DR]

### Học
- Policy-as-data.
- Schema versioning.
- Stable internal rule ID.
- Benchmark metadata khác internal ID.

### Rule schema cần có
- [ ] `schema_version`.
- [ ] `id`.
- [ ] `title`.
- [ ] `service`.
- [ ] `severity`.
- [ ] `framework.name/version/control`.
- [ ] `selector`.
- [ ] `assertion`.
- [ ] `remediation.handler`.
- [ ] `remediation.default_mode`.
- [ ] evidence fields.

### Quan trọng
- [ ] Không tự khẳng định CIS control number nếu chưa verify đúng benchmark/version.
- [ ] Internal ID như `ACG-STO-001` phải ổn định dù benchmark mapping thay đổi.

---

## E5. Viết rule loader + schema validation

- [ ] Reject malformed YAML.
- [ ] Reject duplicate rule IDs.
- [ ] Reject unknown operators.
- [ ] Reject arbitrary remediation command.
- [ ] Chỉ chấp nhận allowlisted handler identifier.

---

## E6. Tạo CLI surface [DR]

### Target ban đầu

```text
acg doctor
acg scan
acg scan --source fixture
acg report ...
acg exceptions list/create/revoke
acg remediation plan ...
acg remediation apply ...
acg monitor query-storage
```

### Học
- CLI UX.
- Exit codes.
- Composable tools.

### Exit codes đề xuất từ baseline

```text
0 = no blocking findings
1 = policy findings detected
2 = operational/runtime failure
3 = invalid configuration/rule set
```

---

## E7. `acg doctor` [DR]

### Check nên có
- [ ] Python/runtime version.
- [ ] Azure CLI available nếu dùng fallback.
- [ ] Azure authentication status.
- [ ] Subscription ID resolved.
- [ ] Terraform availability/version.
- [ ] SQLite version.
- [ ] Log Analytics config nếu monitor được bật.
- [ ] Dangerous subscription-level remediation đang disabled/manual-only.

### Done khi
- [ ] Trước demo, một command cho biết môi trường có sẵn sàng không.

---

## E8. Tách one-shot scan và watch mode [DR]

- [ ] `acg scan` chạy 1 lần rồi exit.
- [ ] `acg watch --interval N` mới lặp.
- [ ] Không để endless 5-second loop là core architecture.

### Hiểu
Điều này giúp CLI composable với cron, Task Scheduler, GitHub Actions hoặc future scheduler.

---

## E9. Tạo control crosswalk với Azure Policy và Prowler [ADD]

### Mục tiêu

Chứng minh mỗi rule được so sánh trên cùng semantics, không chỉ vì title hoặc CIS control number trông giống nhau.

### Mỗi mapping cần có

- [ ] ACG internal rule ID và rule schema version.
- [ ] Azure resource type/property/path được quan sát.
- [ ] Expected secure state và normalization rule.
- [ ] Benchmark name/version/control đã được xác minh.
- [ ] Azure Policy definition ID/version nếu có semantics tương đương.
- [ ] Prowler check ID và Prowler version nếu có semantics tương đương.
- [ ] Phạm vi, điều kiện applicability và known differences.
- [ ] Trạng thái mapping: `EXACT`, `PARTIAL`, `NOT_COMPARABLE`, `UNVERIFIED`.

### Guardrails

- [ ] Không map chỉ dựa trên title giống nhau.
- [ ] `PARTIAL` không được báo cáo như exact agreement.
- [ ] Không có comparator phù hợp phải ghi `NOT_COMPARABLE`, không loại bỏ rule chỉ để tăng agreement rate.
- [ ] Không claim CIS coverage cho mapping `UNVERIFIED`.

---

## E10. Tạo validation dataset có ground truth [ADD]

### Bắt đầu nhỏ

Ưu tiên một tập Storage controls có phần giao rõ ràng giữa ACG, Azure Policy và Prowler. Chỉ mở rộng sang Key Vault/SQL sau khi phương pháp đã ổn định.

### Mỗi validation case phải có

- [ ] Stable case ID.
- [ ] Dedicated lab resource/scope.
- [ ] Setup hoặc fixture mô tả trạng thái trước khi scan.
- [ ] Raw/normalized ARM state dùng làm ground truth.
- [ ] Expected applicability và expected `PASS`/`FAIL`.
- [ ] Ít nhất một secure case và một intentional-drift case cho mỗi control được hỗ trợ.
- [ ] Restore/cleanup path.
- [ ] Không chứa subscription ID, tenant ID, UPN, IP hoặc resource ID thật trong public artifact.

### Nguyên tắc

```text
Intentional resource state
          ↓
Direct ARM/SDK observation
          ↓
Human-reviewed expected result
          ↓
ACG / Azure Policy / Prowler comparison
```

> Tool agreement không tự tạo ra ground truth. Expected result phải được xác lập trước khi xem output của comparator để tránh chọn nhãn theo kết quả thuận lợi.

---

## E11. Chạy differential validation [ADD]

### Offline track — bắt buộc trong normal CI

- [ ] ACG chạy trên validation fixtures.
- [ ] Output được so với expected result đã review.
- [ ] Không Azure credential.
- [ ] Không gọi Prowler/Azure Policy live trong PR CI.

### Live comparison track — manual/controlled

- [ ] Chạy ACG trên dedicated lab scope.
- [ ] Chạy allowlisted Prowler checks trên cùng scope và cùng thời điểm hợp lý.
- [ ] Trigger/query Azure Policy evaluation khi có exact/partial mapping.
- [ ] Ghi nhận evaluation/ingestion latency thay vì coi delayed result là disagreement ngay lập tức.
- [ ] Normalize kết quả về `PASS`, `FAIL`, `NOT_APPLICABLE`, `ERROR`, `NOT_COMPARABLE`.
- [ ] Không remediation trong bước comparison; đây vẫn là read-only validation.

### Reproducibility

- [ ] Record ACG commit SHA, rule catalog version, Prowler version, policy definition/version và timestamp.
- [ ] Lưu raw private output theo retention policy.
- [ ] Sinh sanitized comparison artifact cho portfolio.

---

## E12. Phân tích kết quả và đặt credibility gate [ADD]

### Metrics

- [ ] Supported-control coverage.
- [ ] True positive / true negative theo ground truth.
- [ ] False positive / false negative theo ground truth.
- [ ] Exact-mapping agreement rate với từng comparator.
- [ ] Số `PARTIAL`, `NOT_COMPARABLE`, `UNVERIFIED`.
- [ ] Danh sách disagreement kèm nguyên nhân và disposition.

### Credibility gate ban đầu

- [ ] ACG khớp expected result cho toàn bộ validation cases được công bố.
- [ ] Không có false negative ở CRITICAL cases trong supported validation set.
- [ ] Mọi disagreement với exact comparator đều được reproduce và giải thích.
- [ ] Không gộp `ERROR`/`NOT_APPLICABLE` vào `PASS`.
- [ ] Không dùng agreement rate làm accuracy nếu chưa có independent ground truth.
- [ ] Public report ghi rõ sample size, scope và giới hạn; không suy rộng thành “full CIS compliant”.

### Done khi

- [ ] `docs/validation/control-crosswalk.md` tồn tại.
- [ ] `docs/validation/methodology.md` mô tả cách dựng ground truth và chạy comparator.
- [ ] `docs/validation/results-summary.md` có kết quả có thể tái lập.
- [ ] `docs/validation/disagreements.md` không bỏ qua các khác biệt chưa giải quyết.

---

## CHECKPOINT E — P2 acceptance

- [ ] `pip install -e .` PASS.
- [ ] `acg --help` hoạt động.
- [ ] `acg doctor` hoạt động.
- [ ] `acg scan --source fixture` hoạt động.
- [ ] YAML rule validation có test.
- [ ] Rule engine không phụ thuộc Azure.
- [ ] Storage rule crosswalk có status và version rõ ràng.
- [ ] Offline validation cases khớp independent expected results.
- [ ] Manual live comparison với Prowler và/hoặc Azure Policy có reproducible sanitized evidence.
- [ ] Không có unexplained disagreement cho exact-mapped CRITICAL controls trước khi dùng chúng để remediation.

---

# PHASE F — P3: SAFE REMEDIATION [DR]

> Đây là phase quan trọng nhất để project có giá trị vận hành thật.

## F1. Thiết kế `RemediationPlan` như first-class artifact

### Học
- Plan vs execute.
- TOCTOU (time-of-check/time-of-use).
- Idempotency.

### Plan phải chứa
- [ ] `plan_id`.
- [ ] `finding_id`.
- [ ] `rule_id`.
- [ ] created/expires timestamp.
- [ ] resource identity/hash.
- [ ] before state.
- [ ] desired state.
- [ ] allowlisted action ID.
- [ ] risk class.
- [ ] approval requirement.
- [ ] estimated cost effect.
- [ ] idempotency key.
- [ ] plan status.

---

## F2. Planner không được mutation Azure

### Làm
- [ ] `acg remediation plan --finding ...` chỉ sinh plan.
- [ ] Không gọi Azure update.
- [ ] Plan serializable thành JSON.
- [ ] Có deterministic/hashable representation phù hợp.

---

## F3. Dry-run

- [ ] `acg remediation apply --plan ... --dry-run`.
- [ ] Hiển thị before → desired.
- [ ] Hiển thị risk/cost policy.
- [ ] Không mutation Azure.

### Done khi
- [ ] Có test chứng minh dry-run không gọi executor mutation.

---

## F4. Approval gate

### Học
- Human-in-the-loop.
- Approval scope.

### Làm
- [ ] Approval phải gắn với exact `plan_id/hash`.
- [ ] Plan hết hạn thì approval invalid.
- [ ] Không dùng global “yes” cho mọi mutation.

---

## F5. Precondition check

Trước mutation, verify:

- [ ] Plan hash không đổi.
- [ ] Plan chưa expire.
- [ ] Rule vẫn enabled.
- [ ] Resource identity đúng.
- [ ] Current state vẫn bằng `plan.before`.
- [ ] Không có active exception suppressing remediation.
- [ ] Approval match exact plan.
- [ ] Handler allowlisted.
- [ ] Cost policy cho phép.

### Done khi
- [ ] State thay đổi sau scan → plan trở thành `STALE`, không mutation.

---

## F6. Executor: SDK-first, CLI fallback safe

### Học
- SDK client.
- `DefaultAzureCredential`.
- subprocess argument vector.

### Làm
- [ ] Không format arbitrary shell string.
- [ ] Không `shell=True`.
- [ ] CLI fallback dùng `list[str]`.
- [ ] Fixed executable lookup.
- [ ] Timeout.
- [ ] Structured execution result.

### Done khi
- [ ] YAML không thể biến thành generic command execution primitive.

---

## F7. Verification loop

### Flow

```text
Execute
  ↓
Azure accepted request
  ↓
wait/retry with bounded policy
  ↓
re-collect state
  ↓
run same rule
  ↓
PASS → VERIFIED
FAIL → VERIFICATION_FAILED
```

### Test
- [ ] immediate success.
- [ ] eventual success.
- [ ] timeout.
- [ ] update accepted nhưng rule vẫn fail.
- [ ] collector failure sau mutation.

---

## F8. Remediation policy matrix

### Default
- [ ] Read config → automatic.
- [ ] Generate plan → automatic.
- [ ] Dry-run → automatic.
- [ ] Storage access/TLS mutation → approval-required ban đầu.
- [ ] Key Vault access model → approval-required.
- [ ] SQL network mutation → approval-required.
- [ ] Defender pricing → manual-only/cost approval.
- [ ] Subscription-wide mutation → never automatic trong student profile.
- [ ] Terraform apply/destroy → explicit operator action.

---

## CHECKPOINT F — P3 acceptance

- [ ] CRITICAL finding sinh được plan mà không mutation.
- [ ] Dry-run không mutation.
- [ ] Stale plan bị reject.
- [ ] Unapproved plan bị reject.
- [ ] Executor không dùng `shell=True`.
- [ ] Success chỉ là `VERIFIED` sau re-scan PASS.

---

# PHASE G — P4: EXCEPTION GOVERNANCE VỚI SQLITE [DR]

## G1. Hiểu exception như một state machine

### Học
- Exception không phải “ignore rule”.
- Lifecycle/state transition.
- Transaction.

### States

```text
REQUESTED → ACTIVE → EXPIRED
              ↓
           REVOKED
```

---

## G2. Thiết kế SQLite schema

### Tables tối thiểu
- [ ] `exceptions`.
- [ ] `exception_events`.

### Constraints
- [ ] Primary key.
- [ ] Status CHECK constraint.
- [ ] timestamps.
- [ ] owner/reason/approved_by/ticket.
- [ ] version column.
- [ ] Unique active exception per `(resource_id, rule_id)`.

---

## G3. Repository layer + transactions

### Học
- Atomic transaction.
- Optimistic concurrency/version check.

### Làm
- [ ] Create exception transactionally.
- [ ] Activate.
- [ ] Expire.
- [ ] Revoke.
- [ ] List/filter.
- [ ] Duplicate-active prevention.

---

## G4. Fail-closed behavior

### Cực kỳ quan trọng
Nếu exception state không đọc được:

- [ ] Emit operational error.
- [ ] Không coi như `[]`.
- [ ] Không destructive auto-remediation dựa trên assumption “không có exception”.

---

## G5. Concurrency tests

- [ ] Hai create cùng resource/rule.
- [ ] Revoke đồng thời expire.
- [ ] Optimistic version conflict.
- [ ] DB locked/error path.

---

## G6. Exception audit events

- [ ] CREATED.
- [ ] APPROVED/ACTIVATED.
- [ ] EXPIRED.
- [ ] REVOKED.
- [ ] INCIDENT_REVOKED.

---

## G7. Tamper-evident event hash [DR]

### Học
- Tamper-evident ≠ tamper-proof.

### Làm
- [ ] Event có `previous_hash`.
- [ ] Canonical JSON.
- [ ] `event_hash = SHA256(event_without_hash + previous_hash)`.
- [ ] Tool verify chain.

---

## CHECKPOINT G — P4 acceptance

- [ ] Không còn exception mutable state bằng whole-file JSON.
- [ ] Concurrent mutation không silent overwrite.
- [ ] Corrupt/unavailable state fail closed.
- [ ] Exception lifecycle queryable.
- [ ] Audit events tồn tại cho mọi transition.

---

# PHASE H — P5: EVIDENCE + STATIC HTML REPORT [DR + ADD]

## H1. Thiết kế evidence schema

### Học
- Event sourcing ở mức tối thiểu.
- Append-only audit evidence.
- Mutable state khác append-only history.

### Event types nên có
- [ ] RUN_STARTED / RUN_COMPLETED.
- [ ] FINDING.
- [ ] EXCEPTION_CREATED/ACTIVATED/EXPIRED/REVOKED.
- [ ] REMEDIATION_PLANNED.
- [ ] REMEDIATION_APPROVED.
- [ ] REMEDIATION_EXECUTION.
- [ ] REMEDIATION_VERIFIED/FAILED.
- [ ] INCIDENT_DETECTED/ESCALATED.

---

## H2. `evidence.jsonl`

### Làm
- [ ] Mỗi dòng là JSON object độc lập.
- [ ] Có `schema_version`.
- [ ] Có `event_id`, `run_id`, timestamp.
- [ ] Có resource reference sanitized/structured.
- [ ] Có source/collector metadata.

### Verify
- [ ] Invalid line báo line number rõ ràng.
- [ ] Writer append an toàn cho use case local tool.

---

## H3. Redaction policy

### Public portfolio report
- [ ] subscription ID → hash/redact.
- [ ] tenant ID → omit.
- [ ] resource ID → hash.
- [ ] UPN/identity → pseudonym.
- [ ] IP → mask.
- [ ] URI/object key → omit/truncate.
- [ ] exception reason → fixture/sanitized.

### Private report
- [ ] Retention policy rõ ràng.
- [ ] Không publish lên GitHub Pages mặc định.

---

## H4. Jinja self-contained report

### Học
- Server-rendered static HTML.
- Autoescaping/XSS.
- CSP ở mức cơ bản.

### Làm
- [ ] Template `report.html.j2`.
- [ ] Autoescape enabled.
- [ ] Không `|safe` cho Azure/error/user-controlled fields.
- [ ] Report mở được bằng double-click khi có thể.

---

## H5. Dashboard-like summary [ADD]

> Đây là bổ sung để report có giá trị trình diễn/operations cao hơn mà không cần web server.

### Summary cards
- [ ] Compliance %.
- [ ] PASS/WARNING/CRITICAL.
- [ ] Resources scanned.
- [ ] Rules evaluated.
- [ ] Scan duration.

### Remediation metrics
- [ ] Plans generated.
- [ ] Approved.
- [ ] Verified.
- [ ] Verification failed.
- [ ] Remediation success rate.
- [ ] Mean verification time nếu đủ data.

### Exception metrics
- [ ] Active.
- [ ] Expired.
- [ ] Revoked.
- [ ] Incident-revoked.

### Incident metrics
- [ ] Security events evaluated.
- [ ] Escalated events.

---

## H6. Findings table

- [ ] Filter theo service.
- [ ] Filter severity/status.
- [ ] Rule ID/title.
- [ ] Resource.
- [ ] Expected vs actual.
- [ ] Exception state.
- [ ] Remediation state.

> Có thể dùng vanilla JS nhỏ cho filter/sort. Không cần React.

---

## H7. Timeline view [ADD]

Hiển thị câu chuyện:

```text
Detected → Planned → Dry-run → Approved → Executed → Re-collected → Verified
```

Và cho incident:

```text
Exception ACTIVE → Security Event → ESCALATED_CRITICAL → Exception REVOKED → Containment → VERIFIED
```

---

## H8. Fixture-only sample report

### Làm
- [ ] Có fixture demo environment.
- [ ] Generate `evidence.jsonl`.
- [ ] Generate sanitized `report.html`.
- [ ] Commit sample screenshot/report phù hợp portfolio nếu không chứa dữ liệu thật.

### Done khi
- [ ] Recruiter xem UI không cần Azure account.

---

## H9. External validation appendix [ADD]

Report portfolio nên có một phần tóm tắt credibility nhưng không trộn lẫn detection validation với remediation lifecycle.

- [ ] Nêu validation scope, case count và thời điểm chạy.
- [ ] Nêu ACG/rule catalog/Prowler/Azure Policy versions.
- [ ] Hiển thị supported coverage, TP/TN/FP/FN và exact-mapping agreement.
- [ ] Link hoặc nhúng danh sách disagreement đã giải thích.
- [ ] Hiển thị rõ `PARTIAL`, `NOT_COMPARABLE`, `UNVERIFIED`; không biến chúng thành `PASS`.
- [ ] Không chỉ chọn các case đồng thuận để đưa vào public report.

---

## CHECKPOINT H — P5 acceptance

```bash
acg scan --source fixtures/demo_environment.json --output build/evidence.jsonl
acg report --input build/evidence.jsonl --output build/report.html --redact
```

- [ ] Chạy thành công offline.
- [ ] Report không lộ sensitive fields.
- [ ] Report thể hiện được lifecycle chứ không chỉ bảng PASS/FAIL.

---

# PHASE I — P6: REAL AZURE MONITOR / KQL SIGNAL [DR]

> Chỉ Storage cần real telemetry ở phase đầu. Không mở rộng shallow sang mọi service.

## I1. Hiểu Azure Monitor logging path

### Học

```text
Storage operation
   ↓
Resource log
   ↓
Diagnostic setting
   ↓
Log Analytics
   ↓
KQL
```

### Phải hiểu
- Resource logs không tự có nếu chưa configure diagnostic setting.
- Log ingestion có latency.
- Monitoring này không phải strict real-time event bus.

---

## I2. Verify Terraform diagnostic settings

- [ ] Storage Blob read/write/delete categories được route tới Log Analytics.
- [ ] Workspace được provision trong profile cần thiết.
- [ ] Verify table/mode thực tế tạo `StorageBlobLogs` hoặc điều chỉnh query theo output thật.

---

## I3. Viết KQL candidate query

### Query chỉ nên làm
- [ ] Lookback window.
- [ ] Filter account.
- [ ] Filter successful operations.
- [ ] Filter operation names cần quan tâm.
- [ ] Project fields cần thiết.

### Không nên
- [ ] Nhồi phức tạp CIDR/trusted network logic vào KQL chỉ để “trông xịn”.

---

## I4. `LogsQueryClient` collector

### Học
- Azure Monitor Query SDK.
- Token credential.
- Query success/partial/error semantics.

### Làm
- [ ] `DefaultAzureCredential`.
- [ ] Query workspace.
- [ ] Normalize result thành `IncidentEvent`.
- [ ] Handle empty result.
- [ ] Handle query failure.

---

## I5. Trusted network classifier trong Python

### Học
- `ipaddress.ip_address`.
- `ipaddress.ip_network`.
- IPv4/IPv6 normalization.

### Test
- [ ] trusted IPv4.
- [ ] untrusted IPv4.
- [ ] IPv6.
- [ ] malformed address.

---

## I6. Lookback + dedup

### Vì sao
Log Analytics có ingestion latency nên không được giả định “event phải tới trong 5 giây”.

### Làm
- [ ] Query last N minutes.
- [ ] Tạo dedup key/correlation key.
- [ ] Không xử lý lại một event mãi mãi.

---

## I7. Incident evaluator

### Input
- normalized Storage event.
- trusted source policy.
- active exception context.

### Output
- [ ] normal event.
- [ ] suspicious event.
- [ ] `ESCALATED_CRITICAL`.

---

## I8. Incident revokes applicable exception

### Flow

```text
Exception ACTIVE
      +
Suspicious successful Storage operation
      ↓
ESCALATED_CRITICAL
      ↓
Exception REVOKED
      ↓
Evidence event
```

### Done khi
- [ ] Transition là transactional.
- [ ] Audit event có lý do rõ ràng.

---

## I9. Containment plan

- [ ] Incident không trực tiếp execute arbitrary command.
- [ ] Sinh containment/remediation plan.
- [ ] Policy quyết định auto/approval based on dedicated lab scope.
- [ ] Re-collect + verify sau containment.

---

## CHECKPOINT I — P6 acceptance

Demo thật phải chứng minh được:

```text
active temporary exception
        +
real Storage operation from untrusted source
        ↓
Log Analytics sees event
        ↓
ESCALATED_CRITICAL
        ↓
exception ACTIVE → REVOKED
        ↓
containment plan
        ↓
verification
        ↓
HTML incident timeline
```

---

# PHASE J — P7: DEVSECOPS MATURITY [DR]

## J1. Tách Azure-authenticated workflow khỏi PR CI

### Workflow 1: normal CI
- [ ] No Azure identity.
- [ ] Tests/lint/validate/security scan.

### Workflow 2: manual Azure plan
- [ ] `workflow_dispatch`.
- [ ] Protected environment nếu khả dụng.
- [ ] `id-token: write`.
- [ ] OIDC Azure login.
- [ ] `terraform plan` only.

---

## J2. GitHub OIDC

### Học
- Federated identity.
- Short-lived token.
- Workflow identity claims.

### Làm
- [ ] Tạo Azure app/identity cho GitHub workflow.
- [ ] Configure federated credential.
- [ ] Không lưu `AZURE_CLIENT_SECRET` cho CI.
- [ ] Scope role tối thiểu cho plan/read use case.

---

## J3. Split scanner/remediator identities

### Scanner
- [ ] Reader ở dedicated lab RG/resource scope.
- [ ] Query permission cho Log Analytics workspace.

### Remediator
- [ ] Narrow custom/built-in role phù hợp.
- [ ] Chỉ exact actions cần thiết.
- [ ] Scope lab resource group/resource.

---

## J4. No automatic `terraform apply` trong CI ban đầu

- [ ] Không PR apply.
- [ ] Không arbitrary fork nhận Azure token.
- [ ] Apply/destroy do explicit operator thực hiện.

---

## J5. Release engineering cơ bản [DR]

- [ ] Version bắt đầu phù hợp như `0.1.0`.
- [ ] `CHANGELOG.md`.
- [ ] `CONTRIBUTING.md`.
- [ ] `SECURITY.md`.
- [ ] Git tag/release conventions.

---

## J6. SBOM + artifact attestation [ADD]

> Bổ sung sau khi CI/release ổn định; mục tiêu là supply-chain credibility, không phải feature chính.

- [ ] Build Python package/release artifact.
- [ ] Generate SBOM cho release.
- [ ] Generate provenance/artifact attestation nếu GitHub plan/capability hỗ trợ.
- [ ] Document cách verify release artifact.

### Done khi
- [ ] Có thể chứng minh artifact release đến từ commit/workflow nào.

---

## J7. Docker image [OPTIONAL][ADD]

Chỉ làm nếu CLI/package đã ổn định.

### Mục tiêu

```bash
docker run ... acg scan --source fixture
```

### Không được
- [ ] Dùng Docker để che dependency/package problem.
- [ ] Bắt Docker trở thành requirement của core tool.

---

## CHECKPOINT J — P7 acceptance

- [ ] PR CI offline.
- [ ] Azure plan manual + OIDC.
- [ ] Long-lived CI Azure secret không còn.
- [ ] Scanner/remediator permission boundaries documented.
- [ ] Dependabot/security scanning active ở mức account cho phép.
- [ ] Release process documented.

---

# PHASE K — P8: AZURE STUDENT COST + OPERATIONAL ACCEPTANCE [DR]

## K1. Terraform feature flags / profiles

### `minimal` default
- [ ] Storage: yes.
- [ ] Log Analytics: yes.
- [ ] Key Vault: optional/yes tùy demo.
- [ ] SQL: no mặc định.
- [ ] VPN: no.
- [ ] Jumpbox: no.
- [ ] Private endpoint: optional tùy quota/demo.

### `full-demo`
- [ ] Storage.
- [ ] Key Vault.
- [ ] SQL.
- [ ] Log Analytics.
- [ ] Private networking.
- [ ] VPN/Jumpbox chỉ khi thật sự cần và subscription cho phép.

---

## K2. Tags và lifecycle metadata

Mỗi resource/resource group nên có:
- [ ] Project.
- [ ] Environment.
- [ ] ManagedBy.
- [ ] Purpose.
- [ ] Owner.
- [ ] ExpiresOn.

---

## K3. Cost guardrails

### Học
- Azure Students credit/quota không được giả định.
- SKU/region/quota phải được probe/verify thực tế.

### Làm
- [ ] Document resource nào có cost đáng kể.
- [ ] `acg doctor` hoặc runbook nhắc quota/cost precheck.
- [ ] Budget/alert nếu account cho phép và phù hợp.
- [ ] Full demo là short-lived.

---

## K4. Safe cleanup

### Làm
- [ ] Document `terraform destroy`.
- [ ] Nếu có cleanup wrapper, chỉ delete RG đúng naming/tag convention.
- [ ] Không chấp nhận arbitrary RG argument rồi xóa mù.

---

## K5. Demo runbook

File đề xuất:

```text
docs/demo.md
```

Bao gồm:
- [ ] prerequisites.
- [ ] `acg doctor`.
- [ ] fixture demo.
- [ ] Terraform validate.
- [ ] minimal deploy.
- [ ] drift injection.
- [ ] scan.
- [ ] remediation plan/dry-run/approve/verify.
- [ ] exception flow.
- [ ] incident flow.
- [ ] report generation.
- [ ] cleanup.

---

## K6. Architecture/threat model/control docs

Tạo:

```text
docs/architecture.md
docs/threat-model.md
docs/controls.md
docs/demo.md
```

### `architecture.md`
- [ ] component diagram.
- [ ] data flow.
- [ ] trust boundaries.
- [ ] design guarantees.

### `threat-model.md`
- [ ] malicious/modified rule file.
- [ ] shell injection.
- [ ] stale remediation plan.
- [ ] stolen CI credential.
- [ ] overly broad RBAC.
- [ ] evidence tampering.
- [ ] exception state corruption.
- [ ] sensitive report publication.

### `controls.md`
- [ ] internal rule ID.
- [ ] service.
- [ ] severity.
- [ ] benchmark/version metadata.
- [ ] collector field.
- [ ] expected state.
- [ ] remediation policy.

---

## CHECKPOINT K — P8 acceptance

- [ ] Minimal profile deploy được trong environment thực tế được hỗ trợ.
- [ ] Demo không phụ thuộc VPN/VM/SQL để chứng minh core value.
- [ ] Cleanup documented/tested.
- [ ] Architecture, threat model, controls, demo runbook tồn tại.
- [ ] README phản ánh architecture mới.

---

# PHASE L — P9: PORTFOLIO / OPERABILITY ENHANCEMENTS [ADD]

> Phase này không thay đổi core architecture. Nó làm cho project dễ chứng minh hơn trong CV/interview.

## L1. Architecture Decision Records (ADR)

Tạo thư mục:

```text
docs/adr/
```

ADR đề xuất:

- [ ] ADR-001 — Static HTML over runtime dashboard.
- [ ] ADR-002 — SQLite for exception state.
- [ ] ADR-003 — No automatic Terraform apply in normal CI.
- [ ] ADR-004 — YAML policy catalog.
- [ ] ADR-005 — OIDC over long-lived client secret.
- [ ] ADR-006 — SDK-first, CLI fallback with `shell=False`.
- [ ] ADR-007 — Fixture-first core engine.

### Mỗi ADR trả lời
- Context?
- Decision?
- Alternatives?
- Consequences?

---

## L2. Azure Well-Architected mapping [ADD]

Tạo:

```text
docs/well-architected.md
```

Map project vào:
- [ ] Security.
- [ ] Reliability.
- [ ] Operational Excellence.
- [ ] Cost Optimization.
- [ ] Performance Efficiency.

### Ví dụ nội dung
- Security → RBAC, OIDC, controlled remediation.
- Reliability → re-collect + verification, fail-closed exception handling.
- Operational Excellence → CI, evidence, runbook, observability.
- Cost Optimization → minimal/full profiles, no Azure PR CI.
- Performance Efficiency → bounded queries/collectors, scan duration metrics.

---

## L3. Deterministic drift lab [ADD]

### Mục tiêu
Biến demo drift thành thao tác repeatable thay vì click thủ công lung tung.

Ví dụ target UX:

```bash
acg lab drift storage-public-access
```

hoặc script riêng nếu không muốn đưa lab command vào production CLI.

### Safeguards
- [ ] Chỉ chạy với dedicated lab resource.
- [ ] Validate resource tags/name.
- [ ] In rõ thay đổi sắp tạo.
- [ ] Có restore/remediation path.

---

## L4. Operational metrics [ADD]

Đảm bảo report/evidence có đủ dữ liệu để tính:

- [ ] scan duration.
- [ ] resources scanned.
- [ ] rules evaluated.
- [ ] findings detected.
- [ ] plans generated.
- [ ] remediation verified/failed.
- [ ] verification duration.
- [ ] active/expired/revoked exceptions.
- [ ] incident escalations.

> Đây là observability của chính compliance tool, không chỉ observability của Azure target.

---

## L5. Golden demo script [ADD]

### Demo 5 phút

```text
Terraform baseline
   ↓
Introduce Storage drift
   ↓
acg scan → CRITICAL
   ↓
Generate remediation plan
   ↓
Dry-run
   ↓
Approve
   ↓
Azure mutation
   ↓
Re-collect
   ↓
VERIFIED
   ↓
HTML timeline
```

### Demo 12–15 phút

```text
Fixture scan
   ↓
CI proof
   ↓
Azure baseline
   ↓
Drift
   ↓
Detect
   ↓
Plan / Dry-run / Approve / Verify
   ↓
HTML report
   ↓
Temporary exception
   ↓
Real Storage event from untrusted source
   ↓
Log Analytics / KQL
   ↓
ESCALATED_CRITICAL
   ↓
Exception revoked
   ↓
Containment verified
   ↓
Final HTML incident timeline
   ↓
Destroy lab
```

---

## L6. Portfolio-safe demo assets

- [ ] Architecture diagram.
- [ ] Sanitized HTML sample report.
- [ ] Screenshot/GIF/video ngắn của golden path nếu cần.
- [ ] CI screenshot/badge.
- [ ] Không có subscription ID/IP/UPN thật.

---

## L7. Final CV framing

Chỉ claim những gì thực sự hoàn thành.

### Sau P5 có thể claim
- Continuous compliance scanning.
- Policy-as-data.
- Controlled remediation planning.
- Transactional exceptions nếu P4 done.
- Portable audit evidence/reporting.
- CI/IaC checks.

### Sau P6/P7 mới claim
- Real Log Analytics/KQL security signals.
- Incident-driven exception revocation.
- OIDC/least-privilege CI.
- Verified containment.

### Không claim
- “Enterprise production platform” nếu chưa có operational evidence tương ứng.
- “Full CIS compliant” nếu control mappings chưa verify đúng benchmark/version.

---

# 3. RECOMMENDED IMPLEMENTATION ORDER — KHÔNG ĐẢO THỨ TỰ

```text
A  Understand current system
      ↓
B  P0 Correctness
      ↓
C  Dependency + test foundation
      ↓
D  P1 Offline CI
      ↓
E  P2 Package + CLI + YAML rules + external credibility validation
      ↓
F  P3 Safe remediation
      ↓
G  P4 SQLite exceptions
      ↓
H  P5 Evidence + HTML report
      ↓
I  P6 Real Azure Monitor/KQL
      ↓
J  P7 OIDC + DevSecOps
      ↓
K  P8 Cost/operational acceptance
      ↓
L  P9 Portfolio/release polish
```

### Vì sao order này quan trọng?

- Không có tests → refactor dễ phá behavior.
- Detection chưa có ground-truth/external validation → remediation có thể tự động hóa một kết luận sai.
- Chưa tách Finding/Plan → remediation không an toàn.
- Exception chưa transactional → incident revoke không đáng tin.
- Evidence chưa chuẩn → report chỉ là UI trang trí.
- Chưa có evidence → dashboard không có data model ổn định.
- Chưa có core ổn định → Docker/release/dashboard chỉ tăng bloat.

---

# 4. LEARNING PATH — HỌC ĐÚNG THỨ CẦN DÙNG

## Level 1 — Azure/Terraform fundamentals

Phải hiểu trước P0–P1:
- [ ] Subscription / Resource Group / Resource ID.
- [ ] Azure management plane.
- [ ] RBAC scope/role.
- [ ] Terraform resource/data/variable/local/output.
- [ ] State.
- [ ] Lockfile.
- [ ] init/validate/plan/apply/destroy.

### Bài tự kiểm tra
Giải thích được vì sao `terraform validate` PASS vẫn chưa chứng minh Azure deploy được.

---

## Level 2 — Python engineering

Phải hiểu trước P2:
- [ ] Package/module/import.
- [ ] `pyproject.toml`.
- [ ] typing/dataclass.
- [ ] dependency injection ở mức đơn giản.
- [ ] exception handling.
- [ ] subprocess safety.

### Bài tự kiểm tra
Giải thích được vì sao rule engine không nên gọi Azure trực tiếp.

---

## Level 3 — Testing/CI

Phải hiểu trước P1/P2 refactor lớn:
- [ ] Unit/integration/live test.
- [ ] fixture.
- [ ] mock/monkeypatch.
- [ ] coverage limitations.
- [ ] GitHub Actions job/step/permissions.

### Bài tự kiểm tra
Thiết kế được test cho Azure collector mà không login Azure.

---

## Level 4 — Policy/compliance architecture

Phải hiểu trước YAML rules/remediation:
- [ ] Fact vs policy conclusion.
- [ ] Rule ID vs external benchmark mapping.
- [ ] Severity.
- [ ] Exception.
- [ ] Remediation policy.
- [ ] Ground truth vs external tool agreement.
- [ ] Exact/partial/not-comparable control mapping.

### Bài tự kiểm tra
Phân biệt:

```text
StorageState(public_network_access="Enabled")
```

và:

```text
Finding(rule_id="ACG-STO-001", status="FAIL")
```

Giải thích được vì sao hai rule có cùng CIS title/control number vẫn chưa đủ để kết luận chúng có cùng semantics, và vì sao agreement giữa hai tools không tự động chứng minh accuracy.

---

## Level 5 — Safe mutation/remediation

Phải hiểu trước P3:
- [ ] Plan/execute separation.
- [ ] dry-run.
- [ ] approval.
- [ ] idempotency.
- [ ] precondition.
- [ ] stale plan/TOCTOU.
- [ ] verification.

### Bài tự kiểm tra
Giải thích được tại sao Azure CLI exit code 0 chưa đủ để nói remediation thành công.

---

## Level 6 — State/transactions

Phải hiểu trước P4:
- [ ] SQLite transaction.
- [ ] constraints/index.
- [ ] optimistic concurrency.
- [ ] fail-closed.
- [ ] append-only audit log.

### Bài tự kiểm tra
Giải thích được tại sao malformed `exceptions.json` không được biến thành `[]`.

---

## Level 7 — Monitoring/KQL

Phải hiểu trước P6:
- [ ] Azure diagnostic settings.
- [ ] Log Analytics workspace.
- [ ] KQL basics.
- [ ] ingestion latency.
- [ ] lookback window.
- [ ] deduplication.

### Bài tự kiểm tra
Giải thích được vì sao polling mỗi 5 giây không biến Log Analytics thành real-time event bus.

---

## Level 8 — DevSecOps identity/supply chain

Phải hiểu trước P7:
- [ ] OIDC/federated credentials.
- [ ] least privilege.
- [ ] GitHub token permissions.
- [ ] dependency update automation.
- [ ] SBOM/provenance ở mức khái niệm.

### Bài tự kiểm tra
Giải thích được tại sao OIDC tốt hơn lưu client secret dài hạn trong GitHub Secrets cho use case này.

---

# 5. CHECKPOINTS LỚN — DỪNG LẠI VÀ TỰ DEMO

## Milestone M0 — “Repo không còn fragile”

Hoàn thành B.

Demo:

```bash
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate -no-color
```

Kể được mọi blocker vừa sửa.

---

## Milestone M1 — “Engineering baseline”

Hoàn thành C + D.

Demo:

```text
PR → lint → tests → terraform validate → IaC scan → green
```

Không Azure credential.

---

## Milestone M2 — “Real product core”

Hoàn thành E.

Demo:

```bash
acg doctor
acg scan --source fixture
```

Có YAML rules, typed findings, control crosswalk và evidence đối chiếu với Prowler/Azure Policy cho validation scope đã công bố.

---

## Milestone M3 — “Safe remediation”

Hoàn thành F.

Demo:

```text
FAIL → plan → dry-run → approval → execute → re-scan → VERIFIED
```

---

## Milestone M4 — “Governance + evidence”

Hoàn thành G + H.

Demo:

```text
exception lifecycle + evidence.jsonl + report.html
```

---

## Milestone M5 — “Real Azure operations story”

Hoàn thành I.

Demo:

```text
real Storage event → Log Analytics → escalation → revoke exception → containment
```

---

## Milestone M6 — “CV-ready DevSecOps project”

Hoàn thành J + K + L core items.

Demo được toàn golden path và cleanup.

---

# 6. DEFINITION OF DONE CHO MỖI TASK

Một task chỉ được tick khi:

- [ ] Code/config thay đổi nhỏ và có mục đích rõ ràng.
- [ ] Có test hoặc verification command.
- [ ] Existing relevant tests vẫn pass.
- [ ] Không thêm secret vào repository.
- [ ] Không tăng Azure cost ngoài ý muốn.
- [ ] Documentation được cập nhật nếu behavior/public interface đổi.
- [ ] Rule mới hoặc rule đổi semantics phải cập nhật control crosswalk và validation cases liên quan.
- [ ] Claim về benchmark/compliance phải kèm version, scope và evidence đối chiếu phù hợp.
- [ ] Không thêm abstraction/dependency nếu stdlib/native mechanism đã đủ.
- [ ] Không dùng “temporary bypass” làm trạng thái cuối như skipped tests, silent exception swallowing hoặc security suppression không giải thích.

---

# 7. FINAL REPOSITORY TARGET

```text
NT542-CIS-Azure-Storage/
│
├── src/
│   └── azure_compliance_guard/
│       ├── cli.py
│       ├── models.py
│       ├── config.py
│       ├── collectors/
│       │   ├── storage.py
│       │   ├── keyvault.py
│       │   ├── sql.py
│       │   └── monitor.py
│       ├── evaluator/
│       │   ├── engine.py
│       │   └── operators.py
│       ├── exceptions/
│       │   ├── repository.py
│       │   └── schema.sql
│       ├── remediation/
│       │   ├── planner.py
│       │   ├── executor.py
│       │   ├── storage.py
│       │   ├── keyvault.py
│       │   └── sql.py
│       ├── incidents/
│       │   ├── evaluator.py
│       │   └── response.py
│       ├── evidence/
│       │   ├── writer.py
│       │   └── integrity.py
│       └── reporting/
│           ├── renderer.py
│           └── redaction.py
│
├── rules/
│   ├── storage.yaml
│   ├── keyvault.yaml
│   └── sql.yaml
│
├── templates/
│   └── report.html.j2
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   └── validation/
│   └── live/
│
├── Terraform/
│   └── azure-secure-storage/
│       ├── .terraform.lock.hcl
│       └── ...
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── controls.md
│   ├── demo.md
│   ├── well-architected.md
│   ├── validation/
│   │   ├── methodology.md
│   │   ├── control-crosswalk.md
│   │   ├── results-summary.md
│   │   └── disagreements.md
│   ├── adr/
│   └── sample-report/
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── azure-plan.yml
│   │   └── release.yml          # khi release engineering được thêm
│   └── dependabot.yml
│
├── pyproject.toml
├── requirements.lock
├── requirements-dev.lock
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

---

# 8. GOLDEN DEMO ACCEPTANCE TEST

Project chưa được xem là hoàn tất nếu chưa demo repeatably được câu chuyện sau:

## Part 1 — Offline proof

- [ ] `acg doctor`.
- [ ] `acg scan --source fixture`.
- [ ] CI green.
- [ ] Sample HTML report mở được.
- [ ] Validation fixtures khớp expected ground-truth results.
- [ ] Sanitized validation summary nêu rõ scope, sample size và tool versions.

## Part 2 — Azure drift/remediation

- [ ] Deploy `minimal` profile.
- [ ] Baseline scan PASS.
- [ ] Introduce controlled Storage drift.
- [ ] Scan phát hiện CRITICAL.
- [ ] Prowler và/hoặc Azure Policy phát hiện cùng drift nếu control có exact mapping.
- [ ] Nếu comparator khác kết quả, disagreement được lưu và giải thích trước khi tiếp tục remediation.
- [ ] Generate plan.
- [ ] Dry-run.
- [ ] Explicit approval.
- [ ] Execute.
- [ ] Re-collect.
- [ ] Same rule PASS.
- [ ] Result = `VERIFIED`.
- [ ] HTML timeline chứa toàn lifecycle.

## Part 3 — Exception + incident

- [ ] Tạo temporary exception có expiry.
- [ ] Rule failure chuyển thành governed exception state.
- [ ] Tạo real Storage activity từ source được thiết kế cho lab scenario.
- [ ] Log Analytics query thu được event.
- [ ] Python classify source/event.
- [ ] Severity escalates.
- [ ] Applicable exception `ACTIVE → REVOKED`.
- [ ] Containment plan được tạo/thực thi theo policy.
- [ ] Verification PASS.
- [ ] Final report thể hiện incident timeline.

## Part 4 — Cleanup

- [ ] Destroy lab resources.
- [ ] Verify resource group/resources không còn theo runbook.
- [ ] Không để costly service chạy quên sau demo.

---

# 9. NHỮNG THỨ CỐ Ý KHÔNG LÀM Ở GIAI ĐOẠN NÀY

Để tránh over-engineering:

- [ ] Không Kubernetes.
- [ ] Không Kafka/message broker.
- [ ] Không microservices.
- [ ] Không multi-cloud abstraction.
- [ ] Không React + FastAPI chỉ để hiển thị report.
- [ ] Không managed database chỉ để lưu exception local.
- [ ] Không auto `terraform apply` từ normal PR CI.
- [ ] Không live telemetry cho cả Storage + Key Vault + SQL cùng lúc ở P6.
- [ ] Không thêm complex scheduler nếu `scan` + `watch` + external scheduler đã đủ.

Chỉ thêm chúng khi có **requirement thực tế** mà kiến trúc hiện tại không đáp ứng được.

---

# 10. THỨ TỰ COMMIT/PR ĐỀ XUẤT

Để lịch sử Git cũng thể hiện engineering maturity:

1. [ ] `fix(terraform): restore validation baseline`
2. [ ] `chore(repo): clean generated files and track terraform lock`
3. [ ] `build(python): add project metadata and dependency lock`
4. [ ] `test(core): add deterministic evaluator and collector fixtures`
5. [ ] `ci: add offline python and terraform quality gates`
6. [ ] `refactor(core): introduce normalized domain models`
7. [ ] `feat(rules): load versioned yaml policy catalog`
8. [ ] `feat(cli): add doctor and one-shot scan commands`
9. [ ] `test(validation): cross-check storage rules with reference tools`
10. [ ] `feat(remediation): add plan and dry-run workflow`
11. [ ] `feat(remediation): add approval preconditions and verification`
12. [ ] `feat(exceptions): migrate state from json to sqlite`
13. [ ] `feat(evidence): add append-only event schema`
14. [ ] `feat(report): generate redacted self-contained html report`
15. [ ] `feat(monitor): query storage signals from log analytics`
16. [ ] `feat(incidents): revoke exceptions on validated escalation`
17. [ ] `ci(azure): add manual oidc terraform plan workflow`
18. [ ] `docs: add architecture threat model controls and demo runbook`
19. [ ] `feat(terraform): add minimal and full-demo profiles`
20. [ ] `docs(portfolio): add adrs and well-architected mapping`
21. [ ] `release: add changelog sbom/provenance workflow` nếu phù hợp.

> Không bắt buộc đúng 21 PR; mục tiêu là mỗi PR đủ nhỏ để review/test và không trộn nhiều subsystem độc lập.

---

# 11. FINAL CV-READY CHECKLIST

## Engineering
- [ ] Installable Python package.
- [ ] Typed domain models.
- [ ] Unit + integration fixtures.
- [ ] Offline CI.
- [ ] Reproducible dependencies.

## IaC
- [ ] Terraform validates.
- [ ] Provider lock tracked.
- [ ] Minimal/full profiles.
- [ ] IaC security scanning.
- [ ] Cost/cleanup discipline.

## Cloud security
- [ ] Versioned compliance rules.
- [ ] Least privilege documented.
- [ ] OIDC for controlled GitHub→Azure auth.
- [ ] Public report redaction.
- [ ] Threat model.

## External validation
- [ ] Ground-truth validation cases cho supported Storage controls.
- [ ] Versioned ACG ↔ Azure Policy ↔ Prowler control crosswalk.
- [ ] False-positive/false-negative results theo published validation scope.
- [ ] Mọi exact-mapping disagreement được reproduce và giải thích.
- [ ] Sanitized, reproducible validation summary.

## Operations
- [ ] Drift detection.
- [ ] Plan/dry-run/approval.
- [ ] Precondition validation.
- [ ] Re-collect verification.
- [ ] Transactional exception lifecycle.
- [ ] Real Storage signal via Log Analytics/KQL.

## Auditability
- [ ] JSONL evidence.
- [ ] Event linkage/run IDs.
- [ ] Exception event history.
- [ ] Tamper-evident hash chain nếu triển khai.
- [ ] HTML timeline.

## Portfolio
- [ ] Architecture diagram.
- [ ] Sample sanitized report.
- [ ] Golden demo.
- [ ] ADRs.
- [ ] Well-Architected mapping.
- [ ] README có “what/why/how/demo/limitations”.
- [ ] CV bullet chỉ claim feature đã verify.

---

# 12. PROJECT COMPLETION CRITERIA

Đồ án được xem là “đàng hoàng và có giá trị CV” khi bạn có thể trả lời và **chứng minh bằng code/evidence** các câu hỏi sau:

1. **What problem does it solve?**<br>
   → Continuous Azure compliance, drift detection, governed exceptions, controlled remediation and evidence.

2. **Can it run without Azure?**<br>
   → Yes, fixture mode powers deterministic CI/demo/tests.

3. **Can it detect real Azure drift?**<br>
   → Demonstrated with controlled Storage drift.

4. **Can it remediate safely?**<br>
   → Plan → dry-run → approval → preconditions → execute → re-collect → verify.

5. **What happens if state changes before remediation?**<br>
   → Plan becomes stale and mutation is blocked.

6. **How are exceptions governed?**<br>
   → Transactional SQLite state + lifecycle + audit events + expiry/revocation.

7. **Can an incident override an exception?**<br>
   → Real Storage signal can escalate and revoke applicable exception according to policy.

8. **How do you prove what happened?**<br>
   → Append-only JSONL evidence + sanitized HTML report/timeline.

9. **How is CI secured?**<br>
   → PR CI has no Azure credential; controlled Azure plan uses OIDC + least privilege.

10. **How do you control student Azure cost?**<br>
    → Minimal profile, manual live workflows, cost-sensitive operations manual-only, explicit cleanup.

11. **Why no full web dashboard/Kubernetes/microservices?**<br>
    → They do not solve a current requirement; static report + local-first CLI gives higher operational value with lower attack/maintenance surface.

12. **Can another engineer reproduce your demo?**<br>
    → Yes, using documented runbook, fixtures, pinned dependencies, Terraform lock, and cleanup steps.

13. **How do you know the compliance findings are correct?**<br>
    → Each supported rule is tested against pre-declared ground truth and, where semantics match, cross-checked with versioned Azure Policy/Prowler results; disagreements are retained and explained.

Khi 13 câu này đều có câu trả lời bằng **working implementation + tests + evidence**, project đã vượt khỏi mức “bài tập môn học” và trở thành một portfolio project có câu chuyện Cloud Security/DevSecOps rõ ràng.

---

# 13. NEXT ACTION — BẮT ĐẦU Ở ĐÂU?

Không bắt đầu bằng dashboard, KQL hay OIDC.

Bắt đầu tuần tự:

```text
1. Phase A — hiểu current code
2. Phase B — P0 correctness
3. Phase C/D — tests + CI
4. Checkpoint
5. Phase E — package/CLI/rules + external credibility validation
6. Checkpoint
7. Phase F — remediation safety
8. Phase G — exception durability
9. Phase H — evidence/report
10. Phase I — real Azure signal
11. Phase J/K — DevSecOps + operations
12. Phase L — portfolio polish
```

**Rule cuối:** nếu tại bất kỳ phase nào bạn không thể giải thích “vì sao ta cần bước này” và “làm sao chứng minh nó hoạt động”, chưa nên chuyển sang phase tiếp theo.
