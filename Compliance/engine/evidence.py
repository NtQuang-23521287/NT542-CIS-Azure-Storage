from __future__ import annotations

import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def _resolve_output_root() -> str:
    cwd = os.getcwd().lower()
    if os.path.basename(cwd) == "compliance":
        return os.path.join(cwd, "output")
    compliance_dir = os.path.join(cwd, "compliance")
    if os.path.isdir(compliance_dir):
        return os.path.join(compliance_dir, "output")
    return os.path.join(BASE_DIR.lower(), "output")


OUTPUT_ROOT = _resolve_output_root()


def create_run_dir() -> str:
    """Tạo thư mục evidence cho một lần chạy."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_ROOT, f"run_{ts}")
    os.makedirs(path, exist_ok=True)
    return path


def write_json(run_dir: str, filename: str, payload: dict) -> str:
    filepath = os.path.join(run_dir, filename)
    with open(filepath, "w", encoding="utf-8") as file_obj:
        json.dump(payload, file_obj, indent=2, ensure_ascii=False)
    return filepath


def write_text(run_dir: str, filename: str, content: str) -> str:
    filepath = os.path.join(run_dir, filename)
    with open(filepath, "w", encoding="utf-8") as file_obj:
        file_obj.write(content)
    return filepath


def save_command_logs(run_dir: str, remediation_results: list[dict]) -> list[str]:
    paths: list[str] = []
    for index, result in enumerate(remediation_results, start=1):
        filename = f"command_{index:02d}_{result['control_id']}_{result['account_name']}.log"
        content = "\n".join(
            [
                f"status: {result['status']}",
                f"mode: {result['mode']}",
                f"command: {result['command']}",
                f"returncode: {result['returncode']}",
                "",
                "[stdout]",
                result.get("stdout", ""),
                "",
                "[stderr]",
                result.get("stderr", ""),
            ]
        ).strip() + "\n"
        paths.append(write_text(run_dir, filename, content))
    return paths


def build_manifest(
    *,
    run_dir: str,
    before_snapshot: str,
    before_report: str,
    after_snapshot: str | None,
    after_report: str | None,
    remediation_results: list[dict],
    command_logs: list[str],
) -> dict:
    """Tạo evidence manifest cho lần chạy."""
    return {
        "run_dir": run_dir,
        "before_snapshot": before_snapshot,
        "before_report": before_report,
        "after_snapshot": after_snapshot,
        "after_report": after_report,
        "remediation_results": remediation_results,
        "command_logs": command_logs,
    }
