import argparse
import json
import sys
from engine.collector import collect_all, collect_from_file
from engine.evaluator import evaluate
from engine.reporter import generate

def main():
    parser = argparse.ArgumentParser(description="NT542 CIS Compliance Engine")
    parser.add_argument("--mock", action="store_true", help="Dùng mock data thay vì Azure thật")
    parser.add_argument("--mock-file", default="data/mock_storage.json", help="Đường dẫn file mock JSON")
    parser.add_argument("--rg", default="NT542-Group08", help="Azure Resource Group name")
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