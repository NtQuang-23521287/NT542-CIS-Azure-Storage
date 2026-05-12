# NT542 – CIS Azure Storage Compliance Monitor

---

## 📖 Mô tả đồ án

Đồ án xây dựng hệ thống **giám sát và tự động phục hồi cấu hình** (Compliance Monitoring & Auto-Remediation) cho Azure Storage Account theo chuẩn **CIS Microsoft Azure Foundations Benchmark**.

### Mục tiêu
- Triển khai hạ tầng Azure an toàn bằng **Terraform** (Infrastructure as Code)
- Xây dựng tool Python chạy liên tục, phát hiện sai lệch cấu hình so với chính sách CIS
- Tự động sửa lỗi hoặc hỏi admin tùy theo mức độ nghiêm trọng

### Các chính sách CIS được giám sát

| Chính sách | Giá trị yêu cầu | Mức độ |
|---|---|---|
| CIS 3.1 – HTTPS Only | `true` | CRITICAL |
| CIS 3.2 – Minimum TLS Version | `TLS1_2` | CRITICAL |
| CIS 3.5 – Public Network Access | `Disabled` | CRITICAL |
| Blob Versioning | `Enabled` | WARNING |

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────┐
│                  Azure (East US)                     │
│                                                      │
│  Resource Group: NT542-Group08_Automation            │
│  ┌──────────────────────────────────────────────┐   │
│  │  Virtual Network (10.0.0.0/16)               │   │
│  │  ├── GatewaySubnet        (10.0.1.0/27)      │   │
│  │  ├── ManagementSubnet     (10.0.2.0/24)      │   │
│  │  └── PrivateEndpointSubnet(10.0.3.0/24)      │   │
│  └──────────────────────────────────────────────┘   │
│           │ Private Endpoint                         │
│  ┌────────▼──────────┐   ┌──────────────────────┐   │
│  │  Storage Account  │   │  Log Analytics       │   │
│  │  (Blob Storage)   │   │  Workspace           │   │
│  │  HTTPS + TLS1.2   │   │  (Diagnostic Logs)   │   │
│  │  Public: Disabled │   └──────────────────────┘   │
│  └───────────────────┘                               │
│  Private DNS Zone: privatelink.blob.core.windows.net │
└─────────────────────────────────────────────────────┘
         ▲
         │ Azure SDK (Python)
┌────────┴────────────────┐
│  Compliance Monitor     │
│  (chạy local / VM)      │
│  - Thu thập config      │
│  - Đánh giá sai lệch    │
│  - Tự động remediate    │
└─────────────────────────┘
```

---

## 📁 Cấu trúc thư mục

```
NT542-CIS-Azure-Storage/
├── terraform/
│   ├── provider.tf          # Provider AzureRM ~3.90
│   ├── variables.tf         # Biến cấu hình
│   ├── main.tf              # Resource Group
│   ├── network.tf           # VNet + Subnets
│   ├── storage.tf           # Storage Account (CIS hardened)
│   ├── private_endpoint.tf  # Private Endpoint + DNS Zone
│   ├── monitoring.tf        # Log Analytics + Diagnostic Settings
│   └── outputs.tf           # Output values
├── python/
│   ├── main.py              # Entry point – vòng lặp giám sát
│   ├── collector.py         # Thu thập cấu hình từ Azure
│   ├── evaluator.py         # Đánh giá sai lệch + phân loại severity
│   ├── remediation.py       # Xử lý sửa lỗi (auto / confirm)
│   ├── logger.py            # Cấu hình logging
│   ├── config.py            # Biến môi trường
│   └── .env                 # Azure credentials
├── logs/
│   └── compliance_monitor.log
└── README.md
```

---

## ⚙️ Yêu cầu môi trường

### Terraform
- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.3.0
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) đã đăng nhập (`az login`)
- Tài khoản Azure có quyền `Contributor` trên Subscription

### Python Tool
- Python >= 3.10
- Azure CLI đã cài và đăng nhập
- Các thư viện Python (xem phần cài đặt bên dưới)

---

## 🚀 Hướng dẫn chạy Terraform

### Bước 1 – Đăng nhập Azure

```bash
az login
az account set --subscription "<SUBSCRIPTION_ID>"
```

### Bước 2 – Di chuyển vào thư mục Terraform

```bash
cd terraform/
```

### Bước 3 – Khởi tạo Terraform

```bash
terraform init
```

Lệnh này tải provider `hashicorp/azurerm ~3.90` về máy.

### Bước 4 – Xem trước thay đổi

```bash
terraform plan
```

Kiểm tra danh sách tài nguyên sẽ được tạo:
- 1 Resource Group
- 1 Virtual Network + 3 Subnets
- 1 Storage Account (CIS hardened)
- 1 Private Endpoint + Private DNS Zone
- 1 Log Analytics Workspace + 2 Diagnostic Settings

### Bước 5 – Triển khai hạ tầng

```bash
terraform apply
```

Nhập `yes` khi được hỏi xác nhận. Quá trình mất khoảng **5–10 phút**.

### Bước 6 – Kiểm tra output

```bash
terraform output
```

Kết quả mẫu:
```
resource_group_name         = "resource_group_name"
storage_account_name        = "storage_account_name"
storage_primary_blob_endpoint = "https://storage_account_name.blob.core.windows.net/"
private_endpoint_ip         = "10.0.3.4"
log_analytics_workspace_id  = "/subscriptions/.../workspaces/nt542-law"
```

### Dọn dẹp tài nguyên (khi không dùng nữa)

```bash
terraform destroy
```

---

## 🐍 Hướng dẫn chạy Python Compliance Monitor

### Bước 1 – Cài đặt thư viện

```bash
cd Compliance/engine
pip install -r requirements.txt
```

### Bước 2 – Tạo file `.env`

Tạo file `python/.env` với nội dung:

```env
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<client-id>
AZURE_CLIENT_SECRET=<client-secret>
AZURE_SUBSCRIPTION_ID=<subscription-id>
```

> **Lưu ý:** Lấy các giá trị này từ Azure Portal → App Registrations → tạo Service Principal, cấp quyền `Contributor` cho Storage Account.

### Bước 3 – Tạo thư mục logs

```bash
mkdir logs
```

### Bước 4 – Chạy tool

```bash
python main.py
```

Tool sẽ chạy liên tục, kiểm tra cấu hình mỗi **5 giây** và in kết quả ra terminal.

**Output khi hệ thống tuân thủ:**
```
=== Azure Storage Compliance Monitor ===
  Storage Account : storage_account_name
  Resource Group  : resource_group_name
  Chu kỳ kiểm tra : 5s

✅ storage_account_name đang tuân thủ chính sách.
✅ storage_account_name đang tuân thủ chính sách.
```

---

## 🧪 Kịch bản kiểm thử

### Kịch bản 1 – WARNING: Tắt Blob Versioning

Mô phỏng user tắt versioning (vi phạm mức WARNING):

```powershell
az storage account blob-service-properties update `
  --account-name storage_account_name `
  --resource-group resource_group_name `
  --enable-versioning false
```

**Phản ứng của tool:**
```
⚠ WARNING  Phát hiện thay đổi cấu hình!
  Vấn đề   : Blob versioning disabled
  Tài nguyên: storage_account_name (resource_group_name)

  Admin có muốn khôi phục cấu hình đúng không? [yes/no]: _
```

- Nhập `yes` → tool tự chạy lệnh bật lại versioning và in kết quả
- Nhập `no` → tool bỏ qua, ghi log lại quyết định của admin

---

### Kịch bản 2 – CRITICAL: Bật Public Network Access

Mô phỏng user mở public access (vi phạm mức CRITICAL – nguy hiểm):

```powershell
az storage account update `
  --name storage_account_name `
  --resource-group resource_group_name `
  --public-network-access Enabled
```

**Phản ứng của tool:**
```
⚠ CRITICAL  Phát hiện thay đổi NGUY HIỂM!
  Vấn đề   : Public Network Access mismatch
  Tài nguyên: storage_account_name (resource_group_name)
  → Đang tự động sửa ngay để đảm bảo an toàn bảo mật...

✅ Sửa thành công: Public Network Access mismatch
```

Tool **không hỏi admin** mà tự động chạy lệnh sửa ngay lập tức.

---

## 📝 Xem nhật ký (Logs)

Toàn bộ sự kiện được ghi vào `logs/compliance_monitor.log`:

```bash
# Xem log realtime
tail -f logs/compliance_monitor.log
```

---

## 📚 Tài liệu tham khảo

- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure Provider – Terraform Registry](https://registry.terraform.io/providers/hashicorp/azurerm/latest)
- [Azure SDK for Python](https://learn.microsoft.com/en-us/azure/developer/python/)
- [Azure Storage Security Guide](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)