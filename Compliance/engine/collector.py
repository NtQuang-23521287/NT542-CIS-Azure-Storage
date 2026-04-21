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