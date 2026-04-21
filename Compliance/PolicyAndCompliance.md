<aside>

# Outline plan

## **Phần 1 — Azure Policy (độc lập hoàn toàn)**

<aside>

### **1. Tạo 5–8 Azure Policy definitions**

Vào Azure Portal → Policy → Definitions → tạo custom policy cho HTTPS only, TLS >= 1.2, disable public access, soft delete, versioning...

`Azure Portal`

</aside>

<aside>

### **2. Tạo Policy Initiative + gán lên subscription**

Gom 5–8 policies vào 1 initiative → Assign lên subscription → xem compliance dashboard

`Azure Portal`

</aside>

<aside>

### **3. Viết collector.py**

Gọi Azure CLI, lấy JSON config của Storage Account — chạy được ngay với storage account test bất kỳ

`collector.py`

</aside>

<aside>

### **4. Viết rules.py — định nghĩa 20 CIS controls**

Mỗi rule là 1 hàm Python kiểm tra 1 thuộc tính JSON: allowBlobPublicAccess, minimumTlsVersion, supportsHttpsTrafficOnly...

`rules.py`

</aside>

<aside>

### 5. **Viết evaluator.py + reporter.py**

Evaluator so sánh JSON thực tế vs rule → PASS/FAIL. Reporter xuất file JSON + HTML đẹp

`evaluator.pyreporter.py`

</aside>

<aside>

### 6. **Tạo mock JSON để test engine ngay**

Không cần đợi Hậu — tự tạo file JSON giả lập output của Azure CLI để test toàn bộ pipeline

`mock_storage.json`

</aside>

## **Phần 2 — Kết nối vào hệ thống thật**

<aside>

### 7. **Chạy collector.py lấy config thật**

Thay mock JSON bằng output thật từ Storage Account Hậu tạo — 1 dòng lệnh thay đổi

</aside>

<aside>

### 8. **Kiểm tra tuân thủ khi hệ thống đang chạy**

So sánh trạng thái hiện tại vs baseline ban đầu → phát hiện configuration drift (nhóm trưởng yêu cầu)

</aside>

<aside>

### 9. **Làm bảng mapping control → policy → rule**

Chứng minh tính hệ thống: mỗi CIS control được kiểm tra bởi cả Azure Policy lẫn Python engine

`mapping_table.md`

</aside>

<aside>

### 10. **Bàn giao output (remediation)**

reporter.py xuất JSON chuẩn → Quang đọc vào để biết rule nào FAIL → tự động fix

`compliance_report.json`

</aside>

</aside>

---

# Phần 1: Azure Policy

## Bước 1 — Vào Azure Policy

Truy cập [portal.azure.com](https://portal.azure.com/) → tìm kiếm **"Policy"** trên thanh tìm kiếm trên cùng → vào mục **Definitions** ở sidebar trái.Bấm từng tab để xem hướng dẫn từng policy, JSON đã sẵn sàng để copy thẳng vào Portal.

<aside>

### **Các bước tạo trên Portal**

1. Vào **Policy → Definitions → + Policy definition**
2. Definition location: chọn **Subscription** của bạn
3. Điền Name, Display name, Description như trên
4. Category: gõ **Storage** (tạo mới nếu chưa có)
5. Xóa toàn bộ nội dung trong ô **Policy rule**, dán JSON ở trên vào
6. Nhấn **Save** → policy xuất hiện trong danh sách Definitions
</aside>

<aside>

## Policy 1 — HTTPS only

Definition name

```bash
NT542-Storage-HTTPS-Only
```

Display name

```bash
[NT542] Storage Account must use HTTPS only
```

Category

```bash
Storage
```

Description

```bash
Đảm bảo Storage Account chỉ chấp nhận kết nối HTTPS, từ chối HTTP. Theo CIS Azure Benchmark 3.1.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
        "notEquals": true
      }
    ]
  },
  "then": {
    "effect": "Deny"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
          "notEquals": true
        }
      ]
    },
    "then": {
      "effect": "audit"
    }
  }
}
```

<aside>
🚨

Dùng effect "Audit" thay vì "Deny" trong lúc test để không bị chặn tạo resource. Chuyển sang "Deny" khi demo chính thức.

</aside>

</aside>

<aside>

## Policy 3 — Disable Public Access

Definition name

```bash
NT542-Storage-No-Public-Access
```

Display name

```bash
[NT542] Storage Account must disable public network access
```

Category

```bash
Storage
```

Description

```bash
Cấm truy cập công khai từ Internet vào Storage Account. Dữ liệu chỉ được truy cập qua Private Endpoint. Theo CIS Azure Benchmark 3.3.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/publicNetworkAccess",
        "notEquals": "Disabled"
      }
    ]
  },
  "then": {
    "effect": "Deny"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/publicNetworkAccess",
          "notEquals": "Disabled"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

<aside>
🚨

Policy này nếu để "Deny" sẽ chặn luôn việc Hậu tạo Storage Account nếu chưa set đúng. Dùng "Audit" trước khi Hậu deploy Terraform xong.

</aside>

</aside>

<aside>

## Policy 5 — Soft delete blob

Definition name

```bash
NT542-Storage-SoftDelete-Blob
```

Display name

```bash
[NT542] Storage Account blob soft delete must be enabled
```

Category

```bash
Storage
```

Description

```bash
Bật soft delete cho blob — dữ liệu bị xóa được giữ lại trong 7 ngày trước khi xóa hẳn, bảo vệ khỏi xóa nhầm hoặc ransomware. Theo CIS Azure Benchmark 3.8.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts/blobServices"
      },
      {
        "anyOf": [
          {
            "field": "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled",
            "notEquals": true
          },
          {
            "field": "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.days",
            "less": 7
          }
        ]
      }
    ]
  },
  "then": {
    "effect": "Audit"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts/blobServices"
        },
        {
          "anyOf": [
	          {
	            "field": "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.enabled",
	            "notEquals": true
	          },
	          {
	            "field": "Microsoft.Storage/storageAccounts/blobServices/deleteRetentionPolicy.days",
	            "less": 7
	          }
	        ]
        }
      ]
    },
    "then": {
      "effect": "audit"
    }
  }
}
```

<aside>
🚨

Policy này dùng "Audit" thay vì "Deny" vì soft delete thuộc blobServices — resource type con, không phải storageAccounts trực tiếp. Deny ở đây sẽ không hoạt động đúng.

</aside>

</aside>

<aside>

## Policy 7 — Versioning

Definition name

```bash
NT542-Storage-Versioning-Enabled
```

Display name

```bash
[NT542] Storage Account blob soft delete must be enabled
```

Category

```bash
Storage
```

Description

```bash
Bật versioning để lưu lịch sử các phiên bản blob — có thể phục hồi về bất kỳ phiên bản nào trước đó. Theo CIS Azure Benchmark 3.10.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts/blobServices"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/blobServices/isVersioningEnabled",
        "notEquals": true
      }
    ]
  },
  "then": {
    "effect": "Audit"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts/blobServices"
        },
        {
	        "field": "Microsoft.Storage/storageAccounts/blobServices/isVersioningEnabled",
	        "notEquals": true
	      }
      ]
    },
    "then": {
      "effect": "audit"
    }
  }
}
```

<aside>
🚨

Versioning tốn thêm storage cost — mỗi phiên bản cũ đều được tính phí. Trong môi trường lab/free account cần chú ý, đặt retention policy để tự xóa phiên bản cũ sau 30 ngày.

</aside>

</aside>

<aside>

## Policy 2 — TLS 1.2

Definition name

```bash
NT542-Storage-TLS-Minimum
```

Display name

```bash
[NT542] Storage Account minimum TLS version must be 1.2
```

Category

```bash
Storage
```

Description

```bash
Yêu cầu Storage Account phải dùng TLS 1.2 trở lên. Ngăn chặn TLS 1.0 và 1.1 dễ bị tấn công. Theo CIS Azure Benchmark 3.2.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/minimumTlsVersion",
        "notEquals": "TLS1_2"
      }
    ]
  },
  "then": {
    "effect": "Deny"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/minimumTlsVersion",
          "notEquals": "TLS1_2"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

<aside>
🚨

Azure mặc định đã set TLS1_2 cho storage account mới tạo từ 2023. Policy này vẫn cần để block trường hợp ai đó hạ xuống TLS1_0.

</aside>

</aside>

<aside>

## Policy 4 — Blob anonymous

Definition name

```bash
NT542-Storage-No-Blob-Anonymous
```

Display name

```bash
[NT542] Storage Account must disable blob anonymous access
```

Category

```bash
Storage
```

Description

```bash
Ngăn chặn truy cập ẩn danh vào Blob — bất kỳ ai có URL cũng đọc được nếu bật. Theo CIS Azure Benchmark 3.5.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
        "notEquals": false
      }
    ]
  },
  "then": {
    "effect": "Deny"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
          "notEquals": false
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

<aside>
🚨

Khác với Policy 3 (public network access) — policy này chặn riêng việc cho phép truy cập blob ẩn danh, dù network vẫn public. Cả 2 đều cần thiết.

</aside>

</aside>

<aside>

## Policy 6 — Soft delete container

Definition name

```bash
NT542-Storage-SoftDelete-Container
```

Display name

```bash
[NT542] Storage Account container soft delete must be enabled
```

Category

```bash
Storage
```

Description

```bash
Bật soft delete ở cấp container — toàn bộ container bị xóa vẫn phục hồi được. Theo CIS Azure Benchmark 3.9.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts/blobServices"
      },
      {
        "anyOf": [
          {
            "field": "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.enabled",
            "notEquals": true
          },
          {
            "field": "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.days",
            "less": 7
          }
        ]
      }
    ]
  },
  "then": {
    "effect": "Audit"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts/blobServices"
        },
        {
	        "anyOf": [
	          {
	            "field": "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.enabled",
	            "notEquals": true
	          },
	          {
	            "field": "Microsoft.Storage/storageAccounts/blobServices/containerDeleteRetentionPolicy.days",
	            "less": 7
	          }
	        ]
	      }
      ]
    },
    "then": {
      "effect": "audit"
    }
  }
}
```

<aside>
🚨

P5 bảo vệ từng blob riêng lẻ, P6 bảo vệ cả container. Cần cả 2 để đủ coverage theo CIS.

</aside>

</aside>

<aside>

## Policy 8 — Infra encryption

Definition name

```bash
NT542-Storage-Infra-Encryption
```

Display name

```bash
[NT542] Storage Account infrastructure encryption must be enabled
```

Category

```bash
Storage
```

Description

```bash
Bật mã hóa hạ tầng 2 lớp cho dữ liệu lưu trữ — data at rest được mã hóa 2 lần ở cấp hardware lẫn software. Theo CIS Azure Benchmark 3.11.
```

Policy Rule (dán vào ô "Policy rule" trên Portal)

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      {
        "field": "Microsoft.Storage/storageAccounts/encryption.requireInfrastructureEncryption",
        "notEquals": true
      }
    ]
  },
  "then": {
    "effect": "Deny"
  }
}
```

Kết quả

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
	        "field": "Microsoft.Storage/storageAccounts/encryption.requireInfrastructureEncryption",
	        "notEquals": true
	      }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

<aside>
🚨

Infrastructure encryption chỉ được bật khi TẠO storage account — không thể bật sau khi đã tạo rồi. Hậu cần biết điều này để set trong Terraform từ đầu: infrastructure_encryption_enabled = true.

</aside>

</aside>

---

## Bước 2: Tạo Initiative

<aside>

## **Tạo Initiative**

**Tạo Initiative gom 8 policy lại**

1. Policy → Definitions → **+ Initiative definition**
2. Điền tên initiative: `NT542-CIS-Storage-Compliance`
3. Tab **Policies** → nhấn **+ Add policy definition** → tìm và thêm 3 policy vừa tạo
4. Tab **Initiative parameters**: để trống (không cần tham số)
5. Nhấn **Review + create** → **Create**
6. Vào **Assignments → + Assign initiative** → chọn initiative vừa tạo → Scope: chọn Resource Group `NT542-Group08`
7. Nhấn **Review + create** → **Create**

Sau khi assign xong, vào **Policy → Compliance** để xem dashboard — sẽ thấy resource nào COMPLIANT / NON_COMPLIANT.

</aside>

Bảng thống kê các Policy đã tạo

|  | Policy | Effect | Lý do |
| --- | --- | --- | --- |
| P1 | HTTPS only | Deny | Bảo mật truyền tải  |
| P2 | TLS 1.2 | Deny | Bảo mật giao thức  |
| P3 | Public network access | Deny | Bề mặt tấn công  |
| P4 | Blob anonymous | Deny | Rò rỉ dữ liệu  |
| P5 | Soft delete blob | Audit | Sub-resource type  |
| P6 | Soft delete container | Audit | Sub-resource type  |
| P7 | Versioning | Audit | Sub-resource type  |
| P8 | Infra encryption | Deny | Phải set lúc tạo  |

---

# Phần 2: Python Compliance Engine Modules

## Cấu trúc thư mục

```json
NT542-Compliance/
├── engine/
│   ├── __init__.py        ← file rỗng
│   ├── collector.py       ← làm bước này
│   ├── rules.py           ← làm tiếp theo
│   ├── evaluator.py
│   └── reporter.py
├── data/
│   ├── mock_storage.json  ← test không cần Azure
│   └── mock_blob.json
├── output/
│   ├── report.json
│   └── report.html
├── main.py
└── requirements.txt
```

<aside>

## Cài đặt

1. Tạo cấu trúc thư mục trước

Mở Anaconda Prompt, tạo environment mới:

```bash
conda create -n compliance python=3.11 -y
conda activate compliance
```

1. Tạo thư mục project:

```bash
mkdir C:\NT542-Compliance && cd C:\NT542-Compliance
```

1. Cài thư viện cần thiết:

```bash
pip install jinja2
```

</aside>

<aside>

### Module đầu tiên — nhiệm vụ là gọi Azure CLI và trả về JSON config của Storage Account.

`colector.py`

```bash
import subprocess
import json
import sys
import shutil
import os

RESOURCE_GROUP = "NT542-Group08"
SUBSCRIPTION_ID = "37108e0d-2f5f-4ecd-87d8-2cd7e40efb4f"

def _run_az(args: list[str]) -> dict | list | None:
    """Chạy lệnh az CLI, trả về JSON hoặc None nếu lỗi."""

    az_path = r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"

    if not os.path.exists(az_path):
        print("[collector] Không tìm thấy az CLI", file=sys.stderr)
        return None

    cmd = [az_path] + args + [
        "--subscription", SUBSCRIPTION_ID,
        "--output", "json"
    ]

    print("[DEBUG] CMD:", " ".join(cmd))

    try:
        env = os.environ.copy()
        env["AZURE_CONFIG_DIR"] = os.path.expanduser("~/.azure")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )

        print("[DEBUG] RETURN CODE:", result.returncode)
        print("[DEBUG] STDOUT:", result.stdout[:200])
        print("[DEBUG] STDERR:", result.stderr)

        if result.returncode != 0:
            return None

        return json.loads(result.stdout) if result.stdout.strip() else []

    except Exception as e:
        print("[collector] ERROR:", e, file=sys.stderr)
        return None

def get_storage_accounts(resource_group: str = RESOURCE_GROUP) -> list[dict]:
    """Lấy danh sách tất cả Storage Account trong resource group."""
    print(f"[collector] Đang lấy storage accounts trong '{resource_group}'...")
    accounts = _run_az([
        "storage", "account", "list",
        "--resource-group", resource_group
    ])
    if not accounts:
        return []
    print(f"[collector] Tìm thấy {len(accounts)} storage account(s).")
    print(accounts)
    return accounts

def get_blob_service_properties(account_name: str, resource_group: str = RESOURCE_GROUP) -> dict | None:
    """Lấy blob service properties (soft delete, versioning...)."""
    print(f"[collector] Đang lấy blob properties của '{account_name}'...")
    return _run_az([
        "storage", "account", "blob-service-properties", "show",
        "--account-name", account_name,
        "--resource-group", resource_group
    ])

def collect_all(resource_group: str = RESOURCE_GROUP) -> dict:
    """
    Thu thập toàn bộ config cần thiết.
    Trả về dict chuẩn để đưa vào evaluator.
    """
    accounts = get_storage_accounts(resource_group)

    result = {
        "resource_group": resource_group,
        "storage_accounts": []
    }

    for acc in accounts:
        name = acc.get("name", "unknown")
        blob_props = get_blob_service_properties(name, resource_group)

        result["storage_accounts"].append({
            "name": name,
            "account": acc,
            "blob_service": blob_props
        })

    return result

def collect_from_file(filepath: str) -> dict:
    """Load mock JSON từ file — dùng khi chưa có Azure thật."""
    print(f"[collector] Đang load mock data từ '{filepath}'...")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    data = collect_all()
    print(json.dumps(data, indent=2, ensure_ascii=False))
```

`mock_storage.json`

```bash
{
  "resource_group": "NT542-Group08",
  "storage_accounts": [
    {
      "name": "nt542hospstorage001",
      "account": {
        "name": "nt542hospstorage001",
        "location": "southeastasia",
        "supportsHttpsTrafficOnly": true,
        "minimumTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Disabled",
        "allowBlobPublicAccess": false,
        "allowCrossTenantReplication": false,
        "encryption": {
          "requireInfrastructureEncryption": true,
          "services": {
            "blob": { "enabled": true },
            "file": { "enabled": true }
          }
        },
        "networkRuleSet": {
          "defaultAction": "Deny",
          "bypass": ["AzureServices"]
        }
      },
      "blob_service": {
        "deleteRetentionPolicy": {
          "enabled": true,
          "days": 7
        },
        "containerDeleteRetentionPolicy": {
          "enabled": false,
          "days": 0
        },
        "isVersioningEnabled": false
      }
    }
  ]
}
```

#### **Chạy thật với Azure (sau khi Hậu deploy):**

```bash
az login
python -c "
from engine.collector import collect_all
import json
data = collect_all('NT542-Group08')
print(json.dumps(data, indent=2, ensure_ascii=False))
"
```

</aside>

<aside>

### Cấc Module còn lại

`rules.py`

```bash
"""
rules.py — Định nghĩa các CIS control checks cho Storage Account.
Mỗi rule nhận vào 1 storage account entry từ collector và trả về:
{
    "control_id": "CIS-3.1",
    "title": "...",
    "status": "PASS" | "FAIL" | "ERROR",
    "actual": ...,
    "expected": ...,
    "remediation": "..."
}
"""

from typing import Any

def _get(data: dict, *keys, default=None) -> Any:
    """Helper lấy nested key an toàn."""
    for key in keys:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
        if data is None:
            return default
    return data

def check_https_only(entry: dict) -> dict:
    """CIS 3.1 — Secure transfer (HTTPS only)."""
    val = _get(entry, "account", "supportsHttpsTrafficOnly")
    return {
        "control_id": "CIS-3.1",
        "title": "Storage Account phải bật HTTPS only",
        "status": "PASS" if val is True else "FAIL",
        "actual": val,
        "expected": True,
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --https-only true"
        )
    }

def check_tls_version(entry: dict) -> dict:
    """CIS 3.2 — Minimum TLS version >= 1.2."""
    val = _get(entry, "account", "minimumTlsVersion")
    # Chấp nhận TLS1_2 trở lên (Azure hiện chỉ có TLS1_0, TLS1_1, TLS1_2)
    passed = val in ("TLS1_2",)
    return {
        "control_id": "CIS-3.2",
        "title": "TLS version tối thiểu phải là 1.2",
        "status": "PASS" if passed else "FAIL",
        "actual": val,
        "expected": "TLS1_2",
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --min-tls-version TLS1_2"
        )
    }

def check_public_network_access(entry: dict) -> dict:
    """CIS 3.3 — Public network access disabled."""
    val = _get(entry, "account", "publicNetworkAccess")
    passed = val == "Disabled"
    return {
        "control_id": "CIS-3.3",
        "title": "Public network access phải bị tắt",
        "status": "PASS" if passed else "FAIL",
        "actual": val,
        "expected": "Disabled",
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --public-network-access Disabled"
        )
    }

def check_default_network_deny(entry: dict) -> dict:
    """CIS 3.4 — Default network rule phải là Deny."""
    val = _get(entry, "account", "networkRuleSet", "defaultAction")
    passed = val == "Deny"
    return {
        "control_id": "CIS-3.4",
        "title": "Network ACL default action phải là Deny",
        "status": "PASS" if passed else "FAIL",
        "actual": val,
        "expected": "Deny",
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --default-action Deny"
        )
    }

def check_blob_anonymous_access(entry: dict) -> dict:
    """CIS 3.5 — Blob anonymous access disabled."""
    val = _get(entry, "account", "allowBlobPublicAccess")
    passed = val is False
    return {
        "control_id": "CIS-3.5",
        "title": "Blob anonymous access phải bị tắt",
        "status": "PASS" if passed else "FAIL",
        "actual": val,
        "expected": False,
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --allow-blob-public-access false"
        )
    }

def check_soft_delete_blob(entry: dict) -> dict:
    """CIS 3.8 — Soft delete cho blob enabled >= 7 ngày."""
    enabled = _get(entry, "blob_service", "deleteRetentionPolicy", "enabled")
    days = _get(entry, "blob_service", "deleteRetentionPolicy", "days", default=0)
    passed = enabled is True and isinstance(days, int) and days >= 7
    return {
        "control_id": "CIS-3.8",
        "title": "Blob soft delete phải bật và giữ >= 7 ngày",
        "status": "PASS" if passed else "FAIL",
        "actual": {"enabled": enabled, "days": days},
        "expected": {"enabled": True, "days": ">=7"},
        "remediation": (
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> "
            "--enable-delete-retention true --delete-retention-days 7"
        )
    }

def check_soft_delete_container(entry: dict) -> dict:
    """CIS 3.9 — Soft delete cho container enabled >= 7 ngày."""
    enabled = _get(entry, "blob_service", "containerDeleteRetentionPolicy", "enabled")
    days = _get(entry, "blob_service", "containerDeleteRetentionPolicy", "days", default=0)
    passed = enabled is True and isinstance(days, int) and days >= 7
    return {
        "control_id": "CIS-3.9",
        "title": "Container soft delete phải bật và giữ >= 7 ngày",
        "status": "PASS" if passed else "FAIL",
        "actual": {"enabled": enabled, "days": days},
        "expected": {"enabled": True, "days": ">=7"},
        "remediation": (
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> "
            "--enable-container-delete-retention true --container-delete-retention-days 7"
        )
    }

def check_versioning(entry: dict) -> dict:
    """CIS 3.10 — Blob versioning enabled."""
    val = _get(entry, "blob_service", "isVersioningEnabled")
    return {
        "control_id": "CIS-3.10",
        "title": "Blob versioning phải được bật",
        "status": "PASS" if val is True else "FAIL",
        "actual": val,
        "expected": True,
        "remediation": (
            "az storage account blob-service-properties update "
            "--account-name <account> --resource-group <rg> --enable-versioning true"
        )
    }

def check_infrastructure_encryption(entry: dict) -> dict:
    """CIS 3.11 — Infrastructure encryption enabled."""
    val = _get(entry, "account", "encryption", "requireInfrastructureEncryption")
    return {
        "control_id": "CIS-3.11",
        "title": "Infrastructure encryption phải được bật",
        "status": "PASS" if val is True else "FAIL",
        "actual": val,
        "expected": True,
        "remediation": (
            "Không thể bật sau khi tạo — phải tạo lại storage account "
            "với infrastructure_encryption_enabled = true trong Terraform"
        )
    }

def check_cross_tenant_replication(entry: dict) -> dict:
    """CIS 3.12 — Cross-tenant replication disabled."""
    val = _get(entry, "account", "allowCrossTenantReplication")
    passed = val is False
    return {
        "control_id": "CIS-3.12",
        "title": "Cross-tenant replication phải bị tắt",
        "status": "PASS" if passed else "FAIL",
        "actual": val,
        "expected": False,
        "remediation": (
            "az storage account update "
            "--name <account> --resource-group <rg> --allow-cross-tenant-replication false"
        )
    }

ALL_RULES = [
    check_https_only,
    check_tls_version,
    check_public_network_access,
    check_default_network_deny,
    check_blob_anonymous_access,
    check_soft_delete_blob,
    check_soft_delete_container,
    check_versioning,
    check_infrastructure_encryption,
    check_cross_tenant_replication,
]
```

`main.py`

```bash
"""
main.py — Entry point của Compliance Engine.
Dùng: python main.py [--mock] [--rg RESOURCE_GROUP]
"""

import argparse
import json
import sys
from engine.collector import collect_all, collect_from_file
from engine.evaluator import evaluate
from engine.reporter import generate

def main():
    parser = argparse.ArgumentParser(description="NT542 CIS Compliance Engine")
    parser.add_argument("--mock", action="store_true",
                        help="Dùng mock data thay vì Azure thật")
    parser.add_argument("--mock-file", default="data/mock_storage.json",
                        help="Đường dẫn file mock JSON")
    parser.add_argument("--rg", default="NT542-Group08",
                        help="Azure Resource Group name")
    args = parser.parse_args()

    print("=" * 50)
    print("  NT542 CIS Compliance Engine")
    print("=" * 50)

    if args.mock:
        print(f"[main] Chế độ: MOCK ({args.mock_file})")
        data = collect_from_file(args.mock_file)
    else:
        print(f"[main] Chế độ: AZURE THẬT (RG: {args.rg})")
        data = collect_all(args.rg)

    if not data.get("storage_accounts"):
        print("[main] Không tìm thấy storage account nào. Thoát.")
        sys.exit(1)

    print("[main] Đang đánh giá compliance...")
    report = evaluate(data)

    score = report.get("overall_score_pct", 0)
    summary = report.get("overall_summary", {})
    print(f"\n[main] Kết quả: {score}% compliance")
    print(f"       PASS: {summary.get('passed',0)} | FAIL: {summary.get('failed',0)} | Total: {summary.get('total',0)}")

    json_path, html_path = generate(report)
    print(f"\n[main] Báo cáo đã lưu:")
    print(f"       JSON: {json_path}")
    print(f"       HTML: {html_path}")
    print("\nMở file HTML trong trình duyệt để xem báo cáo trực quan!")

if __name__ == "__main__":
    main()
```

`evaluator.py`

```bash
"""
evaluator.py — Chạy tất cả rules lên từng storage account,
tổng hợp kết quả và tính điểm compliance.
"""

from engine.rules import ALL_RULES
from datetime import datetime, timezone

def evaluate(collected_data: dict) -> dict:
    """
    Nhận output từ collector, chạy tất cả rules.
    Trả về report dict đầy đủ.
    """
    accounts = collected_data.get("storage_accounts", [])
    resource_group = collected_data.get("resource_group", "unknown")

    account_results = []

    for entry in accounts:
        account_name = entry.get("name", "unknown")
        checks = []

        for rule_fn in ALL_RULES:
            try:
                result = rule_fn(entry)
                result["account_name"] = account_name
                checks.append(result)
            except Exception as e:
                checks.append({
                    "control_id": rule_fn.__name__,
                    "title": rule_fn.__doc__ or rule_fn.__name__,
                    "status": "ERROR",
                    "actual": None,
                    "expected": None,
                    "remediation": f"Lỗi khi chạy rule: {e}",
                    "account_name": account_name
                })

        total = len(checks)
        passed = sum(1 for c in checks if c["status"] == "PASS")
        failed = sum(1 for c in checks if c["status"] == "FAIL")
        errors = sum(1 for c in checks if c["status"] == "ERROR")
        score = round(passed / total * 100, 1) if total > 0 else 0

        account_results.append({
            "account_name": account_name,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "score_pct": score
            },
            "checks": checks
        })

    all_checks = [c for ar in account_results for c in ar["checks"]]
    total_all = len(all_checks)
    passed_all = sum(1 for c in all_checks if c["status"] == "PASS")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "resource_group": resource_group,
        "overall_score_pct": round(passed_all / total_all * 100, 1) if total_all > 0 else 0,
        "overall_summary": {
            "total": total_all,
            "passed": passed_all,
            "failed": total_all - passed_all
        },
        "accounts": account_results
    }
```

`reporter.py`

```bash
"""
reporter.py — Xuất kết quả evaluator ra JSON và HTML.
"""

import json
import os
from datetime import datetime

OUTPUT_DIR = "output"

def save_json(report: dict, filepath: str = None) -> str:
    """Lưu report ra file JSON."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not filepath:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(OUTPUT_DIR, f"report_{ts}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[reporter] JSON saved: {filepath}")
    return filepath

def save_html(report: dict, filepath: str = None) -> str:
    """Tạo báo cáo HTML trực quan."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not filepath:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(OUTPUT_DIR, f"report_{ts}.html")

    score = report.get("overall_score_pct", 0)
    summary = report.get("overall_summary", {})
    generated = report.get("generated_at", "")
    rg = report.get("resource_group", "")

    if score >= 80:
        score_color = "#1D9E75"
        score_bg = "#E1F5EE"
    elif score >= 50:
        score_color = "#BA7517"
        score_bg = "#FAEEDA"
    else:
        score_color = "#E24B4A"
        score_bg = "#FCEBEB"

    rows = ""
    for acc in report.get("accounts", []):
        for chk in acc.get("checks", []):
            status = chk.get("status", "ERROR")
            if status == "PASS":
                badge_bg = "#E1F5EE"
                badge_color = "#0F6E56"
            elif status == "FAIL":
                badge_bg = "#FCEBEB"
                badge_color = "#A32D2D"
            else:
                badge_bg = "#FAEEDA"
                badge_color = "#854F0B"

            actual_raw = chk.get("actual")
            actual = json.dumps(actual_raw, ensure_ascii=False) if actual_raw is not None else "—"
            remediation = chk.get("remediation", "") if status != "PASS" else "—"

            rows += f"""
            <tr>
              <td style="font-weight:500;white-space:nowrap">{chk.get('control_id','')}</td>
              <td>{chk.get('title','')}</td>
              <td style="white-space:nowrap">{acc.get('account_name','')}</td>
              <td>
                <span style="background:{badge_bg};color:{badge_color};padding:2px 10px;border-radius:12px;font-size:12px;font-weight:500">
                  {status}
                </span>
              </td>
              <td style="font-family:monospace;font-size:12px">{actual}</td>
              <td style="font-size:12px;color:#666">{remediation}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NT542 CIS Compliance Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #222; padding: 24px; }}
    .header {{ background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #e0e0e0; }}
    h1 {{ font-size: 20px; font-weight: 600; margin-bottom: 4px; }}
    .meta {{ font-size: 13px; color: #888; margin-bottom: 20px; }}
    .stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .stat {{ background: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 10px; padding: 14px 22px; text-align: center; min-width: 110px; }}
    .stat .num {{ font-size: 30px; font-weight: 700; color: {score_color}; }}
    .stat.neutral .num {{ color: #444; }}
    .stat.pass-stat .num {{ color: #1D9E75; }}
    .stat.fail-stat .num {{ color: #E24B4A; }}
    .stat .lbl {{ font-size: 12px; color: #888; margin-top: 3px; }}
    .card {{ background: #fff; border-radius: 12px; overflow: hidden; border: 1px solid #e0e0e0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #f7f7f7; padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: #555; border-bottom: 1px solid #e0e0e0; white-space: nowrap; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #f2f2f2; font-size: 13px; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #fafafa; }}
    .score-badge {{ display: inline-block; background: {score_bg}; color: {score_color}; border-radius: 8px; padding: 2px 10px; font-size: 13px; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>NT542 — CIS Compliance Report</h1>
    <p class="meta">Resource Group: <strong>{rg}</strong> &nbsp;|&nbsp; Generated: {generated}</p>
    <div class="stats">
      <div class="stat">
        <div class="num">{score}%</div>
        <div class="lbl">Overall score</div>
      </div>
      <div class="stat pass-stat">
        <div class="num">{summary.get('passed', 0)}</div>
        <div class="lbl">PASS</div>
      </div>
      <div class="stat fail-stat">
        <div class="num">{summary.get('failed', 0)}</div>
        <div class="lbl">FAIL</div>
      </div>
      <div class="stat neutral">
        <div class="num">{summary.get('total', 0)}</div>
        <div class="lbl">Total checks</div>
      </div>
    </div>
  </div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th>Control ID</th>
          <th>Mô tả</th>
          <th>Account</th>
          <th>Status</th>
          <th>Actual value</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[reporter] HTML saved: {filepath}")
    return filepath

def generate(report: dict) -> tuple[str, str]:
    """Xuất cả JSON lẫn HTML, trả về 2 filepath."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = save_json(report, os.path.join(OUTPUT_DIR, f"report_{ts}.json"))
    html_path = save_html(report, os.path.join(OUTPUT_DIR, f"report_{ts}.html"))
    return json_path, html_path
```

<aside>

**Chạy với mock (test ngay)**

```bash
cd C:\NT542-Compliance
conda activate compliance
python main.py --mock
```

**Kết quả terminal mong đợi**

```bash
==================================================
  NT542 CIS Compliance Engine
==================================================
[main] Chế độ: MOCK (data/mock_storage.json)
[collector] Đang load mock data từ 'data/mock_storage.json'...
[main] Đang đánh giá compliance...

[main] Kết quả: 70.0% compliance
       PASS: 7 | FAIL: 3 | Total: 10

[main] Báo cáo đã lưu:
       JSON: output/report_20260421_103045.json
       HTML: output/report_20260421_103045.html

Mở file HTML trong trình duyệt để xem báo cáo trực quan!
```

**Chạy thật sau khi deploy Terraform**

```bash
az login
python main.py --rg NT542-Group08
```

</aside>

</aside>

<aside>

# NT542 — CIS Control Mapping Table

Bảng ánh xạ chứng minh tính hệ thống: mỗi CIS control được kiểm tra bởi cả Azure Policy lẫn Python Compliance Engine.

| # | CIS Control ID | Mô tả | Azure Policy | Python Rule | Effect | Remediation CLI |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | CIS-3.1 | Secure transfer (HTTPS only) | `NT542-Storage-HTTPS-Only` | `check_https_only` | Deny | `az storage account update --https-only true` |
| 2 | CIS-3.2 | Minimum TLS version >= 1.2 | `NT542-Storage-TLS-Minimum` | `check_tls_version` | Deny | `az storage account update --min-tls-version TLS1_2` |
| 3 | CIS-3.3 | Public network access disabled | `NT542-Storage-No-Public-Access` | `check_public_network_access` | Deny | `az storage account update --public-network-access Disabled` |
| 4 | CIS-3.4 | Default network ACL = Deny | *(Azure CLI / Terraform)* | `check_default_network_deny` | Audit | `az storage account update --default-action Deny` |
| 5 | CIS-3.5 | Blob anonymous access disabled | `NT542-Storage-No-Blob-Anonymous` | `check_blob_anonymous_access` | Deny | `az storage account update --allow-blob-public-access false` |
| 6 | CIS-3.8 | Blob soft delete >= 7 ngày | `NT542-Storage-SoftDelete-Blob` | `check_soft_delete_blob` | Audit | `az storage account blob-service-properties update --enable-delete-retention true --delete-retention-days 7` |
| 7 | CIS-3.9 | Container soft delete >= 7 ngày | `NT542-Storage-SoftDelete-Container` | `check_soft_delete_container` | Audit | `az storage account blob-service-properties update --enable-container-delete-retention true --container-delete-retention-days 7` |
| 8 | CIS-3.10 | Blob versioning enabled | `NT542-Storage-Versioning-Enabled` | `check_versioning` | Audit | `az storage account blob-service-properties update --enable-versioning true` |
| 9 | CIS-3.11 | Infrastructure encryption enabled | `NT542-Storage-Infra-Encryption` | `check_infrastructure_encryption` | Deny | *(Phải set lúc tạo — không thể bật sau)* |
| 10 | CIS-3.12 | Cross-tenant replication disabled | *(Python only)* | `check_cross_tenant_replication` | Audit | `az storage account update --allow-cross-tenant-replication false` |

---

## Ghi chú Effect

| Effect | Ý nghĩa |
| --- | --- |
| **Deny** | Azure Policy chặn việc tạo/sửa resource vi phạm ngay lập tức |
| **Audit** | Azure Policy ghi nhận vi phạm vào compliance dashboard, không chặn |

## Lý do một số control chỉ có Python, không có Azure Policy

- **CIS-3.4** (default network deny): Thuộc `networkRuleSet`, Azure Policy hỗ trợ nhưng phức tạp hơn — kiểm tra qua Python rule và Terraform đủ coverage.
- **CIS-3.12** (cross-tenant replication): Thuộc tính ít thay đổi, kiểm tra định kỳ qua Python rule là phù hợp.

## Azure Policy Initiative

Tất cả 8 policy definitions trên được gom vào initiative:

```
Name:  NT542-CIS-Storage-Compliance
Scope: Subscription → Resource Group NT542-Group08
```

## Cấu trúc file Python Compliance Engine

```
NT542-Compliance/
├── engine/
│   ├── __init__.py        ← package marker
│   ├── collector.py       ← gọi Azure CLI, lấy JSON config
│   ├── rules.py           ← 10 CIS control functions
│   ├── evaluator.py       ← PASS / FAIL logic
│   └── reporter.py        ← xuất JSON + HTML
├── data/
│   └── mock_storage.json  ← test không cần Azure thật
├── output/                ← báo cáo sinh ra ở đây
├── main.py                ← entry point
└── requirements.txt
```

</aside>