from azure_compliance_guard.cli import EXIT_OK, main


def test_scan_then_report_command_generates_self_contained_html(tmp_path):
    evidence = tmp_path / "evidence.jsonl"
    report = tmp_path / "report.html"
    assert (
        main(
            [
                "scan",
                "--source",
                "fixtures/demo_environment.json",
                "--output",
                str(evidence),
            ]
        )
        == 1
    )
    assert (
        main(["report", "--input", str(evidence), "--output", str(report), "--redact"])
        == EXIT_OK
    )
    html = report.read_text(encoding="utf-8")
    assert "Compliance" in html
    assert "Findings" in html
    assert "Timeline" in html
    assert "External validation" in html
    assert "UNVERIFIED" in html
