import argparse
import sys
from engine.collector import collect_all, collect_from_file
from engine.evidence import build_manifest, create_run_dir, save_command_logs, write_json
from engine.evaluator import evaluate
from engine.remediate import build_plan, execute_plan
from engine.reporter import generate, generate_bundle

def main():
    parser = argparse.ArgumentParser(description="NT542 CIS Compliance Engine")
    parser.add_argument("--mock", action="store_true", help="Dùng mock data thay vì Azure thật")
    parser.add_argument("--mock-file", default="data/mock_storage.json", help="Đường dẫn file mock JSON")
    parser.add_argument("--rg", default="NT542-Group08", help="Azure Resource Group name")
    parser.add_argument("--remediate", action="store_true", help="Bật pipeline drift detection -> remediation -> evidence")
    parser.add_argument("--apply", action="store_true", help="Thực thi remediation thật thay vì chỉ dry-run")
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

    if not args.remediate:
        json_path, html_path = generate(report)
        print(f"\n[main] Báo cáo đã lưu:")
        print(f"       JSON: {json_path}")
        print(f"       HTML: {html_path}")
        print("\nMở file HTML trong trình duyệt để xem báo cáo trực quan!")
        return

    print("\n[main] Bật remediation pipeline...")
    run_dir = create_run_dir()
    before_snapshot_path = write_json(run_dir, "snapshot_before.json", data)
    before_report_path = write_json(run_dir, "report_before.json", report)

    plan = build_plan(report)
    remediation_results = execute_plan(plan, apply_changes=args.apply)
    command_logs = save_command_logs(run_dir, remediation_results)

    after_data = None
    after_report = None
    after_snapshot_path = None
    after_report_path = None

    if args.apply and not args.mock:
        print("[main] Thu thập lại trạng thái sau remediation...")
        after_data = collect_all(args.rg)
        after_report = evaluate(after_data)
        after_snapshot_path = write_json(run_dir, "snapshot_after.json", after_data)
        after_report_path = write_json(run_dir, "report_after.json", after_report)

    bundle = {
        "generated_at": report.get("generated_at"),
        "resource_group": args.rg,
        "mode": "apply" if args.apply else "dry-run",
        "drift_detected": report.get("drift_detected", False),
        "before_report": report,
        "after_report": after_report,
        "remediation_summary": {
            "planned": len(plan),
            "executed": sum(1 for item in remediation_results if item["mode"] == "apply"),
            "succeeded": sum(1 for item in remediation_results if item["status"] == "SUCCESS"),
            "failed": sum(1 for item in remediation_results if item["status"] == "FAILED"),
        },
        "remediation_results": remediation_results,
    }
    bundle["evidence_manifest"] = build_manifest(
        run_dir=run_dir,
        before_snapshot=before_snapshot_path,
        before_report=before_report_path,
        after_snapshot=after_snapshot_path,
        after_report=after_report_path,
        remediation_results=remediation_results,
        command_logs=command_logs,
    )

    bundle_json, bundle_html = generate_bundle(bundle, run_dir=run_dir)
    print(f"\n[main] Evidence bundle đã lưu:")
    print(f"       Run dir: {run_dir}")
    print(f"       Bundle JSON: {bundle_json}")
    print(f"       Bundle HTML: {bundle_html}")

if __name__ == "__main__":
    main()
