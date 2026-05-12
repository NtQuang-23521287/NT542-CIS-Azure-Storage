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