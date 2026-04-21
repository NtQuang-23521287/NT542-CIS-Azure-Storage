from engine.rules import ALL_RULES
from datetime import datetime, timezone


def evaluate(collected_data: dict) -> dict:
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