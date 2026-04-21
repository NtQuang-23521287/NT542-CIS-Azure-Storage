import json
import os
import shutil
import subprocess
import sys

RESOURCE_GROUP = "NT542-Group08"
SUBSCRIPTION_ID = "37108e0d-2f5f-4ecd-87d8-2cd7e40efb4f"
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
AZ_PATHS = [
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
    r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az",
    r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az",
    "az.cmd",
    "az",
]


def get_az_path() -> str | None:
    """Tìm binary Azure CLI khả dụng."""
    for candidate in AZ_PATHS:
        if os.path.isabs(candidate) and os.path.exists(candidate):
            return candidate
        if not os.path.isabs(candidate):
            found = shutil.which(candidate)
            if found:
                return found
    return None


def run_az_command(
    args: list[str],
    *,
    expect_json: bool = True,
    timeout: int = 30,
) -> dict:
    """Chạy Azure CLI và trả về metadata của command."""
    az_path = get_az_path()
    if not az_path:
        return {
            "ok": False,
            "cmd": [],
            "returncode": None,
            "stdout": "",
            "stderr": "[collector] Không tìm thấy az CLI",
            "data": None,
        }

    cmd = [az_path] + args + ["--subscription", SUBSCRIPTION_ID]
    if expect_json:
        cmd += ["--output", "json"]

    print("[DEBUG] CMD:", " ".join(cmd))

    try:
        env = os.environ.copy()
        env["AZURE_CONFIG_DIR"] = os.path.expanduser("~/.azure")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )

        print("[DEBUG] RETURN CODE:", result.returncode)
        print("[DEBUG] STDOUT:", result.stdout[:200])
        print("[DEBUG] STDERR:", result.stderr)

        data = None
        if result.returncode == 0 and expect_json:
            try:
                data = json.loads(result.stdout) if result.stdout.strip() else []
            except json.JSONDecodeError as exc:
                return {
                    "ok": False,
                    "cmd": cmd,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": f"{result.stderr}\n[collector] JSON decode error: {exc}",
                    "data": None,
                }

        return {
            "ok": result.returncode == 0,
            "cmd": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "data": data,
        }

    except Exception as e:
        print(f"[collector] ERROR khi chạy Azure CLI ({az_path}): {e}", file=sys.stderr)
        return {
            "ok": False,
            "cmd": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": str(e),
            "data": None,
        }


def run_az_json(args: list[str], *, timeout: int = 30) -> dict | list | None:
    """Chạy Azure CLI và trả về payload JSON hoặc None nếu lỗi."""
    result = run_az_command(args, expect_json=True, timeout=timeout)
    if not result["ok"]:
        return None
    return result["data"]

def get_storage_accounts(resource_group: str = RESOURCE_GROUP) -> list[dict]:
    """Lấy danh sách tất cả Storage Account trong resource group."""
    print(f"[collector] Đang lấy storage accounts trong '{resource_group}'...")
    accounts = run_az_json([
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
    return run_az_json([
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
            "resource_group": resource_group,
            "account": acc,
            "blob_service": blob_props
        })

    return result

def collect_from_file(filepath: str) -> dict:
    """Load mock JSON từ file — dùng khi chưa có Azure thật."""
    if not os.path.isabs(filepath) and not os.path.exists(filepath):
        filepath = os.path.join(BASE_DIR, filepath)
    print(f"[collector] Đang load mock data từ '{filepath}'...")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    resource_group = data.get("resource_group", RESOURCE_GROUP)
    for entry in data.get("storage_accounts", []):
        entry.setdefault("resource_group", resource_group)
    return data

if __name__ == "__main__":
    data = collect_all()
    print(json.dumps(data, indent=2, ensure_ascii=False))
