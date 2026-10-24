import json
from datetime import UTC, datetime

import pytest

from azure_compliance_guard.evidence import (
    EvidenceError,
    append_events,
    make_event,
    read_events,
)


def test_jsonl_append_round_trip_and_line_error(tmp_path):
    path = tmp_path / "evidence.jsonl"
    event = make_event(
        "RUN_STARTED",
        run_id="run-1",
        resource=None,
        source={"mode": "fixture", "collector": "fixture", "catalog_version": 1},
        data={},
        now=datetime(2026, 10, 24, tzinfo=UTC),
    )
    append_events(path, [event])
    append_events(path, [event])
    assert [item["event_id"] for item in read_events(path)] == [
        event["event_id"],
        event["event_id"],
    ]
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2

    with path.open("a", encoding="utf-8") as stream:
        stream.write("{bad}\n")
    with pytest.raises(EvidenceError, match="line 3"):
        read_events(path)


def test_evidence_rejects_unknown_type_and_missing_fields(tmp_path):
    with pytest.raises(EvidenceError):
        make_event(
            "UNKNOWN",
            run_id="run-1",
            resource=None,
            source={"mode": "fixture", "collector": "fixture"},
            data={},
        )
    path = tmp_path / "evidence.jsonl"
    path.write_text(json.dumps({"event_type": "FINDING"}) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceError, match="line 1"):
        read_events(path)
