"""SQLite exception governance uses real temporary databases, never Azure."""

from datetime import UTC, datetime, timedelta

import pytest

from azure_compliance_guard.exceptions import (
    ActiveExceptionConflict,
    ExceptionRepository,
    ExceptionStoreError,
    VersionConflict,
)

NOW = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
RESOURCE = "/subscriptions/demo/resourcegroups/lab/providers/microsoft.storage/storageaccounts/demo"


def request(repo, *, ticket="LAB-1"):
    return repo.request(
        resource_id=RESOURCE,
        resource_name="demo",
        rule_id="ACG-STO-001",
        owner="student",
        reason="Approved drift exercise",
        ticket=ticket,
        expires_at=NOW + timedelta(minutes=30),
        now=NOW,
    )


def test_request_activate_and_filter_are_persistent(tmp_path):
    path = tmp_path / "exceptions.sqlite3"
    repo = ExceptionRepository(path)
    repo.initialize()

    pending = request(repo)
    assert (pending.status, pending.version, pending.approved_by) == (
        "REQUESTED",
        1,
        None,
    )
    assert [
        row.status for row in ExceptionRepository(path).list(status="REQUESTED")
    ] == ["REQUESTED"]

    active = repo.activate(
        pending.id, approved_by="reviewer", expected_version=1, now=NOW
    )
    assert (active.status, active.version, active.approved_by) == (
        "ACTIVE",
        2,
        "reviewer",
    )
    assert [row.id for row in repo.list(status="ACTIVE", resource_id=RESOURCE)] == [
        pending.id
    ]
    assert repo.list(status="REQUESTED") == []


def test_duplicate_active_is_rejected_without_changing_second_request(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3")
    repo.initialize()
    first = request(repo, ticket="LAB-1")
    second = request(repo, ticket="LAB-2")
    repo.activate(first.id, approved_by="reviewer", expected_version=1, now=NOW)

    with pytest.raises(ActiveExceptionConflict):
        repo.activate(second.id, approved_by="reviewer", expected_version=1, now=NOW)

    assert (repo.get(second.id).status, repo.get(second.id).version) == ("REQUESTED", 1)
    assert len(repo.list(status="ACTIVE")) == 1


def test_optimistic_version_conflict_preserves_state(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3")
    repo.initialize()
    pending = request(repo)

    with pytest.raises(VersionConflict):
        repo.activate(pending.id, approved_by="reviewer", expected_version=2, now=NOW)

    assert (repo.get(pending.id).status, repo.get(pending.id).version) == (
        "REQUESTED",
        1,
    )


def test_missing_store_and_invalid_request_fail_closed(tmp_path):
    repo = ExceptionRepository(tmp_path / "missing.sqlite3")
    with pytest.raises(ExceptionStoreError):
        repo.list()
    assert not repo.path.exists()

    repo.initialize()
    with pytest.raises(ValueError):
        repo.request(
            resource_id=RESOURCE,
            resource_name="demo",
            rule_id="ACG-STO-001",
            owner="student",
            reason=" ",
            ticket="LAB-1",
            expires_at=NOW + timedelta(minutes=30),
            now=NOW,
        )
    assert repo.list() == []
