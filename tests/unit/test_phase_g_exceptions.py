"""SQLite exception governance uses real temporary databases, never Azure."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta

import pytest

from azure_compliance_guard.exceptions import (
    ActiveExceptionConflict,
    ExceptionRepository,
    ExceptionStoreError,
    InvalidTransition,
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
    assert repo.has_active(RESOURCE, "ACG-STO-001", now=NOW)
    assert not repo.has_active(RESOURCE, "OTHER-RULE", now=NOW)
    assert not repo.has_active(RESOURCE, "ACG-STO-001", now=NOW + timedelta(minutes=31))


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


def test_expire_revoke_and_incident_revoke_write_distinct_events(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3")
    repo.initialize()

    expired = repo.activate(
        request(repo).id, approved_by="reviewer", expected_version=1, now=NOW
    )
    with pytest.raises(InvalidTransition):
        repo.expire(expired.id, expected_version=2, now=NOW)
    closed = repo.expire(
        expired.id, expected_version=2, now=NOW + timedelta(minutes=31)
    )
    assert (closed.status, closed.version) == ("EXPIRED", 3)

    regular = repo.activate(
        request(repo, ticket="LAB-2").id,
        approved_by="reviewer",
        expected_version=1,
        now=NOW,
    )
    revoked = repo.revoke(
        regular.id,
        actor="operator",
        reason="risk accepted no longer",
        expected_version=2,
        now=NOW,
    )
    assert (revoked.status, revoked.version, revoked.closed_reason) == (
        "REVOKED",
        3,
        "risk accepted no longer",
    )

    incident = repo.activate(
        request(repo, ticket="LAB-3").id,
        approved_by="reviewer",
        expected_version=1,
        now=NOW,
    )
    repo.revoke(
        incident.id,
        actor="incident-handler",
        reason="suspicious access",
        expected_version=2,
        incident=True,
        now=NOW,
    )
    assert repo.verify_chain() == 9
    with closing(sqlite3.connect(repo.path)) as db:
        kinds = [
            row[0] for row in db.execute("SELECT event_type FROM exception_events")
        ]
    assert kinds == [
        "CREATED",
        "ACTIVATED",
        "EXPIRED",
        "CREATED",
        "ACTIVATED",
        "REVOKED",
        "CREATED",
        "ACTIVATED",
        "INCIDENT_REVOKED",
    ]


def test_hash_verifier_detects_event_and_state_tampering(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3")
    repo.initialize()
    active = repo.activate(
        request(repo).id, approved_by="reviewer", expected_version=1, now=NOW
    )
    assert repo.verify_chain() == 2

    with closing(sqlite3.connect(repo.path)) as db:
        db.execute("UPDATE exception_events SET actor = 'forged' WHERE event_id = 1")
        db.commit()
    with pytest.raises(ExceptionStoreError, match="hash chain"):
        repo.verify_chain()

    with closing(sqlite3.connect(repo.path)) as db:
        db.execute("UPDATE exception_events SET actor = 'student' WHERE event_id = 1")
        db.execute("UPDATE exceptions SET reason = 'forged' WHERE id = ?", (active.id,))
        db.commit()
    with pytest.raises(ExceptionStoreError, match="state does not match"):
        repo.verify_chain()
    with pytest.raises(ExceptionStoreError, match="state does not match"):
        repo.has_active(RESOURCE, "ACG-STO-001", now=NOW)
    with pytest.raises(ExceptionStoreError, match="state does not match"):
        repo.revoke(
            active.id,
            actor="operator",
            reason="test",
            expected_version=2,
            now=NOW,
        )


def test_concurrent_activation_has_one_winner(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3", timeout=5)
    repo.initialize()
    ids = [request(repo, ticket=f"LAB-{number}").id for number in (1, 2)]

    def activate(exception_id):
        try:
            return repo.activate(
                exception_id, approved_by="reviewer", expected_version=1, now=NOW
            ).status
        except ActiveExceptionConflict:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(activate, ids))
    assert sorted(results) == ["ACTIVE", "CONFLICT"]
    assert len(repo.list(status="ACTIVE")) == 1
    assert repo.verify_chain() == 3


def test_concurrent_requests_do_not_overwrite_each_other(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3", timeout=5)
    repo.initialize()

    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(lambda n: request(repo, ticket=f"LAB-{n}"), (1, 2)))

    assert len({record.id for record in records}) == 2
    assert {record.ticket for record in repo.list(status="REQUESTED")} == {
        "LAB-1",
        "LAB-2",
    }
    assert repo.verify_chain() == 2


def test_concurrent_revoke_and_expire_cannot_overwrite_each_other(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3", timeout=5)
    repo.initialize()
    active = repo.activate(
        request(repo).id, approved_by="reviewer", expected_version=1, now=NOW
    )

    def close(kind):
        try:
            if kind == "expire":
                return repo.expire(
                    active.id, expected_version=2, now=NOW + timedelta(minutes=31)
                ).status
            return repo.revoke(
                active.id,
                actor="operator",
                reason="incident",
                expected_version=2,
                now=NOW + timedelta(minutes=31),
            ).status
        except VersionConflict:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(close, ("expire", "revoke")))
    assert "CONFLICT" in outcomes
    assert set(outcomes) & {"EXPIRED", "REVOKED"}
    assert repo.get(active.id).version == 3
    assert repo.verify_chain() == 3


def test_locked_database_is_an_operational_error(tmp_path):
    repo = ExceptionRepository(tmp_path / "exceptions.sqlite3", timeout=0)
    repo.initialize()
    with closing(sqlite3.connect(repo.path, autocommit=True)) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(ExceptionStoreError):
            request(repo)
        blocker.execute("ROLLBACK")
    assert repo.list() == []


def test_corrupt_database_is_not_treated_as_empty(tmp_path):
    path = tmp_path / "exceptions.sqlite3"
    path.write_bytes(b"not a SQLite database")
    repo = ExceptionRepository(path)

    with pytest.raises(ExceptionStoreError):
        repo.list()
    with pytest.raises(ExceptionStoreError):
        repo.has_active(RESOURCE, "ACG-STO-001", now=NOW)
    assert path.read_bytes() == b"not a SQLite database"
