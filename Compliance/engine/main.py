"""
main.py – Vòng lặp giám sát tuân thủ cấu hình Azure Storage.

Kiểm tra định kỳ mỗi CHECK_INTERVAL giây.
Phân loại và xử lý vi phạm theo mức độ:
  CRITICAL → tự sửa ngay
  WARNING  → hỏi admin
"""

import time
import logging
import os
from collector   import initialize_azure_clients, collect_storage_account_config
from evaluator   import evaluate_config
from remediation import remediate_config
from config      import CHECK_INTERVAL

# ── Cấu hình logging ──────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/compliance_monitor.log",
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Màu ANSI ──────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
BOLD  = "\033[1m"
RESET = "\033[0m"

# ── Cấu hình mong muốn (theo chính sách CIS) ─────────────────────────────────
EXPECTED_CONFIG = {
    "https_only":            True,
    "min_tls_version":       "TLS1_2",
    "public_network_access": "Disabled",
    "versioning_enabled":    True,
}

RESOURCE_GROUP        = "NT542-Group08_Automation"
STORAGE_ACCOUNT_NAME  = "group08compliance120526"


def monitor():
    resource_client, storage_client = initialize_azure_clients()

    print(f"{BOLD}=== Azure Storage Compliance Monitor ==={RESET}")
    print(f"  Storage Account : {STORAGE_ACCOUNT_NAME}")
    print(f"  Resource Group  : {RESOURCE_GROUP}")
    print(f"  Chu kỳ kiểm tra : {CHECK_INTERVAL}s\n")
    logging.info("=== Compliance Monitor khởi động ===")

    while True:
        logging.info(f"Bắt đầu kiểm tra: {STORAGE_ACCOUNT_NAME}")

        try:
            # 1. Thu thập cấu hình hiện tại
            current_config = collect_storage_account_config(
                storage_client, RESOURCE_GROUP, STORAGE_ACCOUNT_NAME
            )

            # 2. Đánh giá sai lệch
            drift_detected, issues = evaluate_config(current_config, EXPECTED_CONFIG)

            if drift_detected:
                issue_names = [i["name"] for i in issues]
                logging.warning(
                    f"Drift detected trên {STORAGE_ACCOUNT_NAME}: "
                    + ", ".join(issue_names)
                )

                # 3. Xử lý sửa lỗi (CRITICAL tự động, WARNING hỏi admin)
                remediate_config(RESOURCE_GROUP, STORAGE_ACCOUNT_NAME, issues)

            else:
                msg = f"✅ {STORAGE_ACCOUNT_NAME} đang tuân thủ chính sách."
                print(f"{GREEN}{msg}{RESET}")
                logging.info(msg)

        except Exception as exc:
            logging.error(f"Lỗi trong quá trình giám sát: {exc}", exc_info=True)
            print(f"\033[91m[ERROR] {exc}\033[0m")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    monitor()