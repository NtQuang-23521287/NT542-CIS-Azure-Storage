"""
evaluator.py – So sánh cấu hình thực tế với cấu hình mong muốn.

Mỗi vấn đề được gắn mức độ nghiêm trọng:
  - CRITICAL : tự động sửa ngay, không cần admin xác nhận
  - WARNING  : hỏi admin trước khi sửa
"""

# ── Định nghĩa mức độ nghiêm trọng cho từng loại vi phạm ─────────────────────
SEVERITY = {
    "HTTPS traffic only setting mismatch":  "CRITICAL",
    "Minimum TLS version mismatch":         "CRITICAL",
    "Public Network Access mismatch":       "CRITICAL",   # kịch bản 2 – nguy hiểm
    "Blob versioning disabled":             "WARNING",    # kịch bản 1 – cần xác nhận
    "Key Vault keys missing expiry date":    "WARNING",
    "Key Vault secrets missing expiry date": "WARNING",
    "Key Vault recoverability mismatch":     "CRITICAL",
    "Key Vault RBAC authorization disabled": "CRITICAL",
    "Key Vault Private Endpoint missing":    "CRITICAL",
    "Key Vault Public Network Access mismatch": "CRITICAL",
    "SQL auditing disabled":                 "CRITICAL",
    "Microsoft Defender for SQL disabled":   "CRITICAL",
    "SQL Minimum TLS version mismatch":      "CRITICAL",
    "SQL Public Network Access mismatch":    "CRITICAL",
    "SQL Private Endpoint missing":          "CRITICAL",
    "SQL Azure AD admin missing":            "WARNING",
}


def evaluate_config(actual_config: dict, expected_config: dict):
    """
    So sánh actual vs expected.

    Trả về:
        drift_detected (bool)
        issues         (list[dict])  –  mỗi phần tử: {"name": str, "severity": str}
    """
    drift_detected = False
    issues = []

    def add_issue(name: str):
        nonlocal drift_detected
        drift_detected = True
        issues.append({
            "name":     name,
            "severity": SEVERITY.get(name, "WARNING"),
        })

    # ── Account-level checks ──────────────────────────────────────────────────

    if actual_config["https_only"] != expected_config["https_only"]:
        add_issue("HTTPS traffic only setting mismatch")

    if actual_config["min_tls_version"] != expected_config["min_tls_version"]:
        add_issue("Minimum TLS version mismatch")

    if actual_config["public_network_access"] != expected_config["public_network_access"]:
        add_issue("Public Network Access mismatch")

    # ── Blob-service-level checks ─────────────────────────────────────────────

    if actual_config.get("versioning_enabled") != expected_config.get("versioning_enabled"):
        add_issue("Blob versioning disabled")

    return drift_detected, issues


def evaluate_key_vault_config(actual_config: dict, expected_config: dict):
    drift_detected = False
    issues = []

    def add_issue(name: str):
        nonlocal drift_detected
        drift_detected = True
        issues.append({
            "name": name,
            "severity": SEVERITY.get(name, "WARNING"),
            "service": "key_vault",
        })

    if actual_config["public_network_access"] != expected_config["public_network_access"]:
        add_issue("Key Vault Public Network Access mismatch")

    if actual_config["enable_rbac_authorization"] != expected_config["enable_rbac_authorization"]:
        add_issue("Key Vault RBAC authorization disabled")

    if (
        actual_config["enable_soft_delete"] != expected_config["enable_soft_delete"]
        or actual_config["enable_purge_protection"] != expected_config["enable_purge_protection"]
    ):
        add_issue("Key Vault recoverability mismatch")

    if actual_config["private_endpoint_enabled"] != expected_config["private_endpoint_enabled"]:
        add_issue("Key Vault Private Endpoint missing")

    if actual_config["keys_have_expiry"] != expected_config["keys_have_expiry"]:
        add_issue("Key Vault keys missing expiry date")

    if actual_config["secrets_have_expiry"] != expected_config["secrets_have_expiry"]:
        add_issue("Key Vault secrets missing expiry date")

    return drift_detected, issues


def evaluate_sql_config(actual_config: dict, expected_config: dict):
    drift_detected = False
    issues = []

    def add_issue(name: str):
        nonlocal drift_detected
        drift_detected = True
        issues.append({
            "name": name,
            "severity": SEVERITY.get(name, "WARNING"),
            "service": "sql",
        })

    if actual_config["auditing_enabled"] != expected_config["auditing_enabled"]:
        add_issue("SQL auditing disabled")

    if actual_config["defender_enabled"] != expected_config["defender_enabled"]:
        add_issue("Microsoft Defender for SQL disabled")

    if actual_config["min_tls_version"] != expected_config["min_tls_version"]:
        add_issue("SQL Minimum TLS version mismatch")

    if actual_config["public_network_access"] != expected_config["public_network_access"]:
        add_issue("SQL Public Network Access mismatch")

    if actual_config["private_endpoint_enabled"] != expected_config["private_endpoint_enabled"]:
        add_issue("SQL Private Endpoint missing")

    if actual_config["azure_ad_admin_configured"] != expected_config["azure_ad_admin_configured"]:
        add_issue("SQL Azure AD admin missing")

    return drift_detected, issues
