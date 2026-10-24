"""Transactional SQLite exception state and append-only transition events."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4


class ExceptionStoreError(RuntimeError):
    """Exception state is unavailable or a requested transition is unsafe."""


class VersionConflict(ExceptionStoreError):
    """The record changed after the caller read it."""


class ActiveExceptionConflict(ExceptionStoreError):
    """Another active exception already covers this resource and rule."""


class InvalidTransition(ExceptionStoreError):
    """The current lifecycle state does not allow this transition."""


SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
STATUSES = frozenset({"REQUESTED", "ACTIVE", "EXPIRED", "REVOKED"})


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
    id: str
    resource_id: str
    resource_name: str
    rule_id: str
    status: str
    owner: str
    reason: str
    ticket: str
    created_at: str
    expires_at: str
    approved_by: str | None
    approved_at: str | None
    closed_at: str | None
    closed_reason: str | None
    version: int

    def to_dict(self) -> dict:
        return asdict(self)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


def _text(value: str, name: str, limit: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty and at most {limit} characters")
    return value.strip()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class ExceptionRepository:
    def __init__(self, path: Path, *, timeout: float = 1.0):
        self.path = Path(path)
        if timeout < 0:
            raise ValueError("timeout must be non-negative")
        self.timeout = timeout

    def initialize(self) -> None:
        """Explicitly create a new database; normal reads never create one."""
        if self.path.exists():
            raise ExceptionStoreError("exception database already exists")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with closing(
                sqlite3.connect(self.path, autocommit=True, timeout=self.timeout)
            ) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """CREATE TABLE exceptions (
                        id TEXT PRIMARY KEY,
                        resource_id TEXT NOT NULL CHECK(length(resource_id) > 0),
                        resource_name TEXT NOT NULL CHECK(length(resource_name) > 0),
                        rule_id TEXT NOT NULL CHECK(length(rule_id) > 0),
                        status TEXT NOT NULL CHECK(status IN
                            ('REQUESTED', 'ACTIVE', 'EXPIRED', 'REVOKED')),
                        owner TEXT NOT NULL CHECK(length(owner) > 0),
                        reason TEXT NOT NULL CHECK(length(reason) > 0),
                        ticket TEXT NOT NULL CHECK(length(ticket) > 0),
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        approved_by TEXT,
                        approved_at TEXT,
                        closed_at TEXT,
                        closed_reason TEXT,
                        version INTEGER NOT NULL CHECK(version > 0),
                        CHECK(status != 'ACTIVE' OR approved_by IS NOT NULL)
                    )"""
                )
                # SQLite unique partial index: https://www.sqlite.org/partialindex.html
                db.execute(
                    """CREATE UNIQUE INDEX one_active_exception
                    ON exceptions(resource_id, rule_id) WHERE status = 'ACTIVE'"""
                )
                db.execute(
                    """CREATE TABLE exception_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        exception_id TEXT NOT NULL REFERENCES exceptions(id),
                        event_type TEXT NOT NULL CHECK(event_type IN
                            ('CREATED', 'ACTIVATED', 'EXPIRED', 'REVOKED',
                             'INCIDENT_REVOKED')),
                        occurred_at TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL
                    )"""
                )
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                db.execute("COMMIT")
        except sqlite3.Error as exc:
            raise ExceptionStoreError(
                "could not initialize exception database"
            ) from exc

    def _open(self) -> sqlite3.Connection:
        # mode=rw is essential: a missing DB must never mean "no exceptions".
        db = None
        try:
            uri = self.path.resolve().as_uri() + "?mode=rw"
            db = sqlite3.connect(uri, uri=True, timeout=self.timeout, autocommit=True)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ExceptionStoreError("unsupported exception database schema")
            return db
        except sqlite3.Error as exc:
            if db is not None:
                db.close()
            raise ExceptionStoreError(
                "exception database unavailable or corrupt"
            ) from exc
        except Exception:
            if db is not None:
                db.close()
            raise

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        db = self._open()
        try:
            # BEGIN IMMEDIATE serializes read-then-write transitions and the
            # global hash chain. See https://www.sqlite.org/lang_transaction.html
            db.execute("BEGIN IMMEDIATE")
            self._verify_chain(db)
            yield db
            db.execute("COMMIT")
        except BaseException as exc:
            if db.in_transaction:
                db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise ExceptionStoreError("exception database write failed") from exc
            raise
        finally:
            db.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> ExceptionRecord:
        return ExceptionRecord(**dict(row))

    @staticmethod
    def _event(
        db: sqlite3.Connection,
        exception_id: str,
        event_type: str,
        occurred_at: str,
        actor: str,
        details: dict,
    ) -> None:
        state = db.execute(
            "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
        ).fetchone()
        if state is None:
            raise ExceptionStoreError("event has no exception state")
        details = {
            **details,
            "record_hash": hashlib.sha256(
                _canonical(dict(state)).encode("utf-8")
            ).hexdigest(),
        }
        previous = db.execute(
            "SELECT event_hash FROM exception_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else GENESIS_HASH
        payload = {
            "exception_id": exception_id,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "actor": actor,
            "details": details,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
        db.execute(
            """INSERT INTO exception_events
            (exception_id, event_type, occurred_at, actor, details_json,
             previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                exception_id,
                event_type,
                occurred_at,
                actor,
                _canonical(details),
                previous_hash,
                event_hash,
            ),
        )

    def request(
        self,
        *,
        resource_id: str,
        resource_name: str,
        rule_id: str,
        owner: str,
        reason: str,
        ticket: str,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> ExceptionRecord:
        current = _utc(now or datetime.now(UTC))
        expiry = _utc(expires_at)
        if not current < expiry <= current + timedelta(minutes=120):
            raise ValueError("expiry must be within the next 120 minutes")
        identity = _text(resource_id, "resource_id").lower()
        name = _text(resource_name, "resource_name", 255)
        rule = _text(rule_id, "rule_id", 255)
        requester = _text(owner, "owner", 255)
        justification = _text(reason, "reason", 2000)
        reference = _text(ticket, "ticket", 255)
        record = ExceptionRecord(
            id=str(uuid4()),
            resource_id=identity,
            resource_name=name,
            rule_id=rule,
            status="REQUESTED",
            owner=requester,
            reason=justification,
            ticket=reference,
            created_at=current.isoformat(),
            expires_at=expiry.isoformat(),
            approved_by=None,
            approved_at=None,
            closed_at=None,
            closed_reason=None,
            version=1,
        )
        with self._write() as db:
            db.execute(
                """INSERT INTO exceptions VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                tuple(record.to_dict().values()),
            )
            self._event(
                db,
                record.id,
                "CREATED",
                record.created_at,
                requester,
                {"resource_id": identity, "rule_id": rule, "ticket": reference},
            )
        return record

    def activate(
        self,
        exception_id: str,
        *,
        approved_by: str,
        expected_version: int,
        now: datetime | None = None,
    ) -> ExceptionRecord:
        reviewer = _text(approved_by, "approved_by", 255)
        current = _utc(now or datetime.now(UTC))
        with self._write() as db:
            row = db.execute(
                "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
            ).fetchone()
            if row is None:
                raise ExceptionStoreError("exception does not exist")
            if row["version"] != expected_version:
                raise VersionConflict("exception version changed")
            if row["status"] != "REQUESTED":
                raise InvalidTransition("only requested exceptions may be activated")
            if datetime.fromisoformat(row["expires_at"]) <= current:
                raise InvalidTransition("expired request cannot be activated")
            try:
                db.execute(
                    """UPDATE exceptions SET status = 'ACTIVE', approved_by = ?,
                    approved_at = ?, version = version + 1 WHERE id = ?""",
                    (reviewer, current.isoformat(), exception_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ActiveExceptionConflict(
                    "active exception already exists for resource and rule"
                ) from exc
            self._event(
                db,
                exception_id,
                "ACTIVATED",
                current.isoformat(),
                reviewer,
                {"expected_version": expected_version},
            )
            updated = db.execute(
                "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
            ).fetchone()
            return self._record(updated)

    def expire(
        self,
        exception_id: str,
        *,
        expected_version: int,
        now: datetime | None = None,
    ) -> ExceptionRecord:
        return self._close(
            exception_id,
            expected_version=expected_version,
            event_type="EXPIRED",
            actor="system",
            reason="time limit reached",
            now=now,
        )

    def revoke(
        self,
        exception_id: str,
        *,
        actor: str,
        reason: str,
        expected_version: int,
        incident: bool = False,
        now: datetime | None = None,
    ) -> ExceptionRecord:
        return self._close(
            exception_id,
            expected_version=expected_version,
            event_type="INCIDENT_REVOKED" if incident else "REVOKED",
            actor=_text(actor, "actor", 255),
            reason=_text(reason, "reason", 2000),
            now=now,
        )

    def _close(
        self,
        exception_id: str,
        *,
        expected_version: int,
        event_type: str,
        actor: str,
        reason: str,
        now: datetime | None,
    ) -> ExceptionRecord:
        current = _utc(now or datetime.now(UTC))
        with self._write() as db:
            row = db.execute(
                "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
            ).fetchone()
            if row is None:
                raise ExceptionStoreError("exception does not exist")
            if row["version"] != expected_version:
                raise VersionConflict("exception version changed")
            if row["status"] != "ACTIVE":
                raise InvalidTransition("only active exceptions may be closed")
            if (
                event_type == "EXPIRED"
                and datetime.fromisoformat(row["expires_at"]) > current
            ):
                raise InvalidTransition("active exception has not reached expiry")
            status = "EXPIRED" if event_type == "EXPIRED" else "REVOKED"
            db.execute(
                """UPDATE exceptions SET status = ?, closed_at = ?,
                closed_reason = ?, version = version + 1 WHERE id = ?""",
                (status, current.isoformat(), reason, exception_id),
            )
            self._event(
                db,
                exception_id,
                event_type,
                current.isoformat(),
                actor,
                {"reason": reason, "expected_version": expected_version},
            )
            updated = db.execute(
                "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
            ).fetchone()
            return self._record(updated)

    @staticmethod
    def _verify_chain(db: sqlite3.Connection) -> int:
        previous_hash = GENESIS_HASH
        last_record_hashes = {}
        count = 0
        for row in db.execute("SELECT * FROM exception_events ORDER BY event_id"):
            count += 1
            if row["event_id"] != count or row["previous_hash"] != previous_hash:
                raise ExceptionStoreError("exception event hash chain is broken")
            try:
                details = json.loads(row["details_json"])
                if not isinstance(details, dict) or row["details_json"] != _canonical(
                    details
                ):
                    raise ValueError("noncanonical event details")
            except (ValueError, TypeError) as exc:
                raise ExceptionStoreError(
                    "exception event hash chain is invalid"
                ) from exc
            payload = {
                "exception_id": row["exception_id"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "actor": row["actor"],
                "details": details,
                "previous_hash": previous_hash,
            }
            computed = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
            if computed != row["event_hash"]:
                raise ExceptionStoreError("exception event hash chain is broken")
            last_record_hashes[row["exception_id"]] = details.get("record_hash")
            previous_hash = computed
        record_ids = set()
        for row in db.execute("SELECT * FROM exceptions"):
            record_ids.add(row["id"])
            current_hash = hashlib.sha256(
                _canonical(dict(row)).encode("utf-8")
            ).hexdigest()
            if last_record_hashes.get(row["id"]) != current_hash:
                raise ExceptionStoreError("exception state does not match audit events")
        if record_ids != set(last_record_hashes):
            raise ExceptionStoreError("exception state does not match audit events")
        return count

    def verify_chain(self) -> int:
        db = self._open()
        try:
            db.execute("BEGIN")
            return self._verify_chain(db)
        except sqlite3.Error as exc:
            raise ExceptionStoreError("exception database read failed") from exc
        finally:
            db.close()

    def get(self, exception_id: str) -> ExceptionRecord | None:
        db = self._open()
        try:
            db.execute("BEGIN")
            self._verify_chain(db)
            row = db.execute(
                "SELECT * FROM exceptions WHERE id = ?", (exception_id,)
            ).fetchone()
            return self._record(row) if row else None
        except sqlite3.Error as exc:
            raise ExceptionStoreError("exception database read failed") from exc
        finally:
            db.close()

    def list(
        self, *, status: str | None = None, resource_id: str | None = None
    ) -> list[ExceptionRecord]:
        if status is not None and status not in STATUSES:
            raise ValueError("invalid exception status")
        clauses = []
        values = []
        if status is not None:
            clauses.append("status = ?")
            values.append(status)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            values.append(resource_id.lower())
        query = "SELECT * FROM exceptions"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at, id"
        db = self._open()
        try:
            db.execute("BEGIN")
            self._verify_chain(db)
            return [self._record(row) for row in db.execute(query, values)]
        except sqlite3.Error as exc:
            raise ExceptionStoreError("exception database read failed") from exc
        finally:
            db.close()

    def has_active(
        self, resource_id: str, rule_id: str, *, now: datetime | None = None
    ) -> bool:
        current = _utc(now or datetime.now(UTC))
        db = self._open()
        try:
            db.execute("BEGIN")
            self._verify_chain(db)
            rows = db.execute(
                """SELECT expires_at FROM exceptions
                WHERE resource_id = ? AND rule_id = ? AND status = 'ACTIVE'""",
                (resource_id.lower(), rule_id),
            )
            return any(datetime.fromisoformat(row[0]) > current for row in rows)
        except sqlite3.Error as exc:
            raise ExceptionStoreError("exception database read failed") from exc
        finally:
            db.close()
