"""
remediation.py – Xử lý sửa lỗi cấu hình.

Luồng xử lý theo mức độ:
  CRITICAL → tự động sửa ngay, in thông báo ra terminal
  WARNING  → hỏi admin có muốn sửa không, chờ xác nhận
"""

import os
import subprocess
import logging


# ── Lệnh sửa lỗi tương ứng với từng vấn đề ───────────────────────────────────
REMEDIATION_COMMANDS = {
    "HTTPS traffic only setting mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--https-only true"
    ),
    "Minimum TLS version mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--minimum-tls-version TLS1_2"
    ),
    "Public Network Access mismatch": (
        "az storage account update "
        "--name {account} "
        "--resource-group {rg} "
        "--public-network-access Disabled"
    ),
    "Blob versioning disabled": (
        "az storage account blob-service-properties update "
        "--account-name {account} "
        "--resource-group {rg} "
        "--enable-versioning true"
    ),
}

# ── Màu ANSI để in terminal dễ đọc ───────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def _run_command(cmd: str, issue_name: str) -> bool:
    """Chạy lệnh Azure CLI và trả về True nếu thành công."""
    logging.info(f"[REMEDIATION] Đang chạy: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        msg = f"[REMEDIATION] ✅ Sửa thành công: {issue_name}"
        print(f"{GREEN}{msg}{RESET}")
        logging.info(msg)
        return True
    else:
        msg = f"[REMEDIATION] ❌ Sửa THẤT BẠI: {issue_name}\n  Lỗi: {result.stderr.strip()}"
        print(f"{RED}{msg}{RESET}")
        logging.error(msg)
        return False


def remediate_config(
    resource_group: str,
    storage_account_name: str,
    issues: list[dict],
):
    """
    Xử lý từng vấn đề theo mức độ nghiêm trọng.

    Parameters
    ----------
    resource_group         : tên Resource Group trên Azure
    storage_account_name   : tên Storage Account
    issues                 : danh sách dict {"name": str, "severity": str}
    """

    for issue in issues:
        name     = issue["name"]
        severity = issue["severity"]

        cmd_template = REMEDIATION_COMMANDS.get(name)
        if not cmd_template:
            logging.warning(f"[REMEDIATION] Không có lệnh sửa cho: {name}")
            continue

        cmd = cmd_template.format(account=storage_account_name, rg=resource_group)

        # ── CRITICAL: tự động sửa ngay ───────────────────────────────────────
        if severity == "CRITICAL":
            header = (
                f"\n{RED}{BOLD}[⚠ CRITICAL] Phát hiện thay đổi NGUY HIỂM!{RESET}\n"
                f"  Vấn đề   : {name}\n"
                f"  Tài nguyên: {storage_account_name} ({resource_group})\n"
                f"  → Đang tự động sửa ngay để đảm bảo an toàn bảo mật...\n"
            )
            print(header)
            logging.warning(
                f"[CRITICAL] '{name}' trên {storage_account_name} – "
                f"tự động remediate."
            )
            _run_command(cmd, name)

        # ── WARNING: hỏi admin ────────────────────────────────────────────────
        elif severity == "WARNING":
            header = (
                f"\n{YELLOW}{BOLD}[⚠ WARNING] Phát hiện thay đổi cấu hình!{RESET}\n"
                f"  Vấn đề   : {name}\n"
                f"  Tài nguyên: {storage_account_name} ({resource_group})\n"
            )
            print(header)
            logging.warning(
                f"[WARNING] '{name}' trên {storage_account_name} – "
                f"chờ xác nhận admin."
            )

            try:
                answer = input(
                    f"{CYAN}  Admin có muốn khôi phục cấu hình đúng không? "
                    f"[yes/no]: {RESET}"
                ).strip().lower()
            except EOFError:
                answer = "no"

            if answer in ("yes", "y"):
                logging.info(
                    f"[REMEDIATION] Admin đồng ý sửa: {name}"
                )
                _run_command(cmd, name)
            else:
                msg = f"[REMEDIATION] Admin từ chối sửa: {name}"
                print(f"{YELLOW}  → Bỏ qua sửa lỗi theo yêu cầu admin.{RESET}\n")
                logging.info(msg)