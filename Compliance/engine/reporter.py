import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def _resolve_output_dir() -> str:
    cwd = os.getcwd().lower()
    if os.path.basename(cwd) == "compliance":
        return os.path.join(cwd, "output")
    compliance_dir = os.path.join(cwd, "compliance")
    if os.path.isdir(compliance_dir):
        return os.path.join(compliance_dir, "output")
    return os.path.join(BASE_DIR.lower(), "output")


OUTPUT_DIR = _resolve_output_dir()

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


def save_bundle_html(bundle: dict, filepath: str) -> str:
    """Tạo HTML tổng hợp drift, remediation và evidence."""
    before = bundle.get("before_report") or {}
    after = bundle.get("after_report") or {}
    summary_before = before.get("overall_summary", {})
    summary_after = after.get("overall_summary", {})

    rows = ""
    for item in bundle.get("remediation_results", []):
        rows += f"""
        <tr>
          <td>{item.get('control_id', '')}</td>
          <td>{item.get('account_name', '')}</td>
          <td>{item.get('mode', '')}</td>
          <td>{item.get('status', '')}</td>
          <td style="font-family:monospace;font-size:12px">{item.get('command', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NT542 Remediation Evidence Bundle</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background:#f5f5f5; color:#222; padding:24px; }}
    .card {{ background:#fff; border:1px solid #ddd; border-radius:12px; padding:20px; margin-bottom:16px; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; }}
    .stat {{ background:#fafafa; border:1px solid #eee; border-radius:10px; padding:14px; }}
    table {{ width:100%; border-collapse: collapse; }}
    th, td {{ border-bottom:1px solid #eee; padding:10px; text-align:left; vertical-align: top; }}
    th {{ background:#fafafa; }}
    code {{ font-family: monospace; font-size:12px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>NT542 Drift Remediation Bundle</h1>
    <p>Mode: <strong>{bundle.get('mode', '')}</strong> | Resource Group: <strong>{bundle.get('resource_group', '')}</strong></p>
  </div>
  <div class="card">
    <h2>Before</h2>
    <div class="grid">
      <div class="stat">Score: <strong>{before.get('overall_score_pct', 0)}%</strong></div>
      <div class="stat">PASS: <strong>{summary_before.get('passed', 0)}</strong></div>
      <div class="stat">FAIL: <strong>{summary_before.get('failed', 0)}</strong></div>
      <div class="stat">ERROR: <strong>{summary_before.get('errors', 0)}</strong></div>
    </div>
  </div>
  <div class="card">
    <h2>After</h2>
    <div class="grid">
      <div class="stat">Score: <strong>{after.get('overall_score_pct', 'N/A')}</strong></div>
      <div class="stat">PASS: <strong>{summary_after.get('passed', 'N/A')}</strong></div>
      <div class="stat">FAIL: <strong>{summary_after.get('failed', 'N/A')}</strong></div>
      <div class="stat">ERROR: <strong>{summary_after.get('errors', 'N/A')}</strong></div>
    </div>
  </div>
  <div class="card">
    <h2>Remediation Actions</h2>
    <table>
      <thead>
        <tr>
          <th>Control</th>
          <th>Account</th>
          <th>Mode</th>
          <th>Status</th>
          <th>Command</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Evidence Manifest</h2>
    <pre>{json.dumps(bundle.get('evidence_manifest', {}), indent=2, ensure_ascii=False)}</pre>
  </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as file_obj:
        file_obj.write(html)
    print(f"[reporter] Bundle HTML saved: {filepath}")
    return filepath


def generate_bundle(bundle: dict, *, run_dir: str) -> tuple[str, str]:
    """Xuất bundle JSON + HTML vào evidence directory."""
    json_path = os.path.join(run_dir, "bundle.json")
    html_path = os.path.join(run_dir, "bundle.html")
    save_json(bundle, json_path)
    save_bundle_html(bundle, html_path)
    return json_path, html_path
