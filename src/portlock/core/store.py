"""PortLock's durable state: what it has seen and decided, and how to undo what it did.

Two stores, deliberately different (``docs/ARCHITECTURE.md`` section 3.1):

* :class:`StateStore` keeps the queryable state in SQLite: devices seen, connections,
  decisions, scans, enrolments (fingerprint plus port), the closed set of runtime
  settings, the lockdown state with its history, and the changes waiting for
  commit-confirm. Every method that changes more than one row does it in one
  transaction, so a crash leaves either all of a change or none of it.
* :class:`RecoveryJournal` is the enforcement journal, a plain append-only file of typed
  records. ``portlock recover`` must work without the service and without the database
  (``docs/DESIGN.md`` section 11), and a record written ahead of an operating-system
  change must survive a damaged database. Every record is validated when the file is
  replayed: restoring is a privileged write, so a line that does not describe a change
  PortLock could have made is skipped and counted, never acted on (section 14.17).

Neither store holds policy or makes a decision.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import sqlite3
import threading
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from portlock.core.canonical import canonicalize, parse_canonical
from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.db import Database
from portlock.core.errors import CanonicalError, StoreError
from portlock.core.fsutil import atomic_write_bytes
from portlock.core.models import (
    Access,
    Confidence,
    Decision,
    Fingerprint,
    Mode,
    UsbDevice,
)
from portlock.guard.base import Action, EnforcementResult, JournalEntry, JournalKind, Tier

__all__ = [
    "GLOBAL_KINDS",
    "GLOBAL_SCOPE",
    "JOURNAL_FILE_NAME",
    "LOCKDOWN_END_REASONS",
    "LOCKDOWN_STATES",
    "PENDING_STATUSES",
    "RESTRICTING",
    "SETTING_KEYS",
    "STORE_COMPONENT",
    "VOLATILE_KINDS",
    "ConnectionRecord",
    "ConnectionState",
    "DecisionRecord",
    "DeviceRecord",
    "EnrolmentRecord",
    "JournalRecord",
    "LockdownHistoryRecord",
    "LockdownRecord",
    "Outcome",
    "PendingChangeRecord",
    "RecoveryJournal",
    "ScanRecord",
    "ScanState",
    "StateStore",
    "check_journal_entry",
]

_LOG = logging.getLogger(__name__)

#: The component name under which :class:`StateStore` registers its migrations.
STORE_COMPONENT = "store"
#: Name of the enforcement journal inside the state directory.
JOURNAL_FILE_NAME = "journal.jsonl"

#: The scope of a journal record that concerns no single device.
GLOBAL_SCOPE = "global"
#: Journal kinds the operating system forgets when the device disconnects. A Windows disk
#: attribute belongs here too: it is set without ``Persist`` and goes away with the disk,
#: and the next disk may be given the same ``PhysicalDriveN``.
VOLATILE_KINDS: frozenset[str] = frozenset(
    {
        JournalKind.SYSFS_AUTHORIZED.value,
        JournalKind.BLOCK_READ_ONLY.value,
        JournalKind.WIN_DISK_READ_ONLY.value,
        JournalKind.FAKE.value,
    }
)
#: Journal kinds whose value is shared by several devices; always stored with global scope.
GLOBAL_KINDS: frozenset[str] = frozenset(
    {
        JournalKind.SYSFS_AUTHORIZED_DEFAULT.value,
        JournalKind.UDEV_RULE.value,
        JournalKind.WIN_POLICY_VALUE.value,
    }
)
#: Actions that take access away. Only these may open a journal record over an existing
#: value: restoring the baseline of a releasing call would restrict.
RESTRICTING: frozenset[Action] = frozenset({Action.BLOCK, Action.READ_ONLY, Action.DEFAULT_DENY_ON})

#: States of the single lockdown row (``lockdown.manager`` gives them names).
LOCKDOWN_STATES: tuple[str, ...] = ("idle", "engaging", "active", "lifting")
#: Why a lockdown ended.
LOCKDOWN_END_REASONS: tuple[str, ...] = (
    "lifted",
    "expired",
    "killswitch",
    "clock_anomaly",
    "unconfirmed",
    "recovered",
)
#: States of a change waiting for commit-confirm: being applied, or applied and waiting.
PENDING_STATUSES: tuple[str, ...] = ("applying", "awaiting")

# Mirrors portlock.core.config.SCOPES; core.store may not import core.config
# (ARCHITECTURE.md section 1.2). A test keeps the two equal.
_SCOPES: tuple[str, ...] = ("storage", "storage_and_unknown", "all_except_protected")
# core.fingerprint: "plk1:" and 32 characters of lowercase base32.
_FINGERPRINT_PATTERN = re.compile(r"plk1:[a-z2-7]{32}\Z")
_RUN_ID_PATTERN = re.compile(r"[0-9a-f]{16}\Z")
_RECORD_ID_PATTERN = re.compile(r"[0-9a-f]{16}\Z")
_CHANGE_KIND_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_MAX_LIMIT = 500
_MAX_ACTOR = 128
_MAX_TEXT = 1024
_MAX_LOCKDOWN_MINUTES = 10_080
_CLOSE_REASONS = ("removed", "resync", "service_stop", "service_restart")


class ConnectionState(StrEnum):
    """What PortLock has made of one connection."""

    NEW = "new"
    PROTECTED = "protected"
    ALLOWED = "allowed"
    READ_ONLY = "read_only"
    PENDING = "pending"
    DENIED = "denied"


class ScanState(StrEnum):
    """Where the content scan of one connection stands."""

    NONE = "none"
    WAITING = "waiting"
    QUEUED = "queued"
    RUNNING = "running"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class Outcome(StrEnum):
    """What became of enforcing one decision."""

    UNDETERMINED = "undetermined"
    NOT_NEEDED = "not_needed"
    APPLIED = "applied"
    WOULD_APPLY = "would_apply"
    FAILED = "failed"
    REFUSED = "refused"
    UNSUPPORTED = "unsupported"


# --- records -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    """A device PortLock has seen, keyed by fingerprint, as of its latest sighting."""

    fingerprint: Fingerprint
    device: UsbDevice
    storage_identity: str | None
    first_seen: datetime
    last_seen: datetime
    connection_count: int


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    """One continuous presence of one device during one service run.

    Attributes:
        id: PortLock's integer connection id.
        connection_token: the backend's per-connection token
            (``UsbDevice.connection_id``), which unlike ``instance_id`` changes on a
            re-plug; ``None`` if the backend supplies none.
    """

    id: int
    fingerprint: Fingerprint
    device: UsbDevice
    instance_id: str
    bus_path: str | None
    connection_token: str | None
    run_id: str
    present_at_start: bool
    connected_at: datetime
    removed_at: datetime | None
    close_reason: str | None
    state: ConnectionState
    provisional: bool
    resolution: Mapping[str, Any] | None
    scan_state: ScanState
    last_scan_id: int | None
    decision_id: int | None

    @property
    def is_open(self) -> bool:
        return self.removed_at is None


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """One decision about one connection, with what enforcing it achieved."""

    id: int
    connection_id: int
    fingerprint: str
    decided_at: datetime
    trigger: str
    decision: Decision
    policy_hash: str
    mode: Mode
    outcome: Outcome
    mechanism: str | None
    tier: Tier
    detail: str | None
    error: str | None
    enforced_at: datetime | None


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """One scan of one mounted volume."""

    id: int
    connection_id: int
    fingerprint: str
    mount_point: str
    trigger: str
    requested_by: str
    state: str
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    verdict: str | None
    report: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class EnrolmentRecord:
    """An input device an administrator enrolled: protected on exactly this port."""

    fingerprint: str
    bus_path: str
    label: str | None
    enrolled_at: datetime
    enrolled_by: str


@dataclass(frozen=True, slots=True)
class LockdownRecord:
    """The persisted lockdown state (one row).

    Attributes:
        state: one of :data:`LOCKDOWN_STATES`.
        minutes: the duration last set by engage or renew.
        expires_at: when the lockdown ends by the wall clock, for display and for the
            operating-system timer. The countdown itself runs on the monotonic clock.
        remaining_seconds: the time left at ``checkpoint_at``; what a restart resumes.
        change_id: the commit-confirm change that engaged it, while unconfirmed.
        timer_armed: True from just before the operating-system timer is armed until
            it is known to be cancelled.
        end_reason / ended_by: set while ``lifting``.
    """

    state: str = "idle"
    engaged_at: datetime | None = None
    engaged_by: str | None = None
    reason: str | None = None
    minutes: int | None = None
    expires_at: datetime | None = None
    remaining_seconds: int | None = None
    checkpoint_at: datetime | None = None
    renewed_at: datetime | None = None
    renew_count: int = 0
    change_id: str | None = None
    timer_armed: bool = False
    end_reason: str | None = None
    ended_by: str | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class LockdownHistoryRecord:
    """One lockdown that has ended."""

    id: int
    engaged_at: datetime
    engaged_by: str
    reason: str
    ended_at: datetime
    ended_by: str
    end_reason: str
    renew_count: int


@dataclass(frozen=True, slots=True)
class PendingChangeRecord:
    """A change applied under commit-confirm and not yet confirmed (section 14.15).

    Attributes:
        channel: SHA-256 of the channel identity the change arrived on; confirmation
            must arrive on the same one.
        params: what the change's handler needs to apply and revert it.
        preview: what the change would block, as listed before it was applied.
        result: what applying it reported, once applied.
        deadline_at: wall-clock time by which it must be confirmed (display only; the
            deadline is enforced on the monotonic clock).
    """

    id: str
    kind: str
    status: str
    actor: str
    channel: str
    params: Mapping[str, Any]
    preview: tuple[Mapping[str, Any], ...]
    result: Mapping[str, Any] | None
    created_at: datetime
    deadline_at: datetime
    timeout_seconds: int


# --- schema ------------------------------------------------------------------------------

_MIGRATIONS: tuple[str, ...] = (
    """
CREATE TABLE devices (
  fingerprint      TEXT PRIMARY KEY,
  confidence       TEXT NOT NULL CHECK (confidence IN ('high','low')),
  basis            TEXT NOT NULL,
  vendor_id        INTEGER NOT NULL,
  product_id       INTEGER NOT NULL,
  serial           TEXT,
  manufacturer     TEXT,
  product          TEXT,
  categories       TEXT NOT NULL,
  storage_identity TEXT,
  description      TEXT NOT NULL,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  connection_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX devices_by_last_seen ON devices(last_seen, fingerprint);

CREATE TABLE connections (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint      TEXT NOT NULL REFERENCES devices(fingerprint),
  instance_id      TEXT NOT NULL,
  bus_path         TEXT,
  connection_token TEXT,
  run_id           TEXT NOT NULL,
  present_at_start INTEGER NOT NULL CHECK (present_at_start IN (0,1)),
  connected_at     TEXT NOT NULL,
  removed_at       TEXT,
  close_reason     TEXT CHECK (close_reason IN
                     ('removed','resync','service_stop','service_restart')),
  state            TEXT NOT NULL CHECK (state IN
                     ('new','protected','allowed','read_only','pending','denied')),
  provisional      INTEGER NOT NULL DEFAULT 0 CHECK (provisional IN (0,1)),
  resolution       TEXT,
  scan_state       TEXT NOT NULL DEFAULT 'none' CHECK (scan_state IN
                     ('none','waiting','queued','running','clean','suspicious',
                      'malicious','incomplete','error')),
  last_scan_id     INTEGER,
  description      TEXT NOT NULL,
  decision_id      INTEGER
);
CREATE INDEX connections_open ON connections(instance_id) WHERE removed_at IS NULL;
CREATE INDEX connections_by_fp ON connections(fingerprint, id);
CREATE INDEX connections_by_token ON connections(connection_token)
  WHERE connection_token IS NOT NULL;

CREATE TABLE decisions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER NOT NULL REFERENCES connections(id),
  fingerprint   TEXT NOT NULL,
  decided_at    TEXT NOT NULL,
  trigger       TEXT NOT NULL,
  access        TEXT NOT NULL,
  source        TEXT NOT NULL,
  rule_id       TEXT,
  grant_id      TEXT,
  scan          TEXT NOT NULL,
  alert         INTEGER NOT NULL CHECK (alert IN (0,1)),
  expires_at    TEXT,
  reasons       TEXT NOT NULL,
  policy_hash   TEXT NOT NULL,
  mode          TEXT NOT NULL,
  outcome       TEXT NOT NULL DEFAULT 'undetermined' CHECK (outcome IN
                  ('undetermined','not_needed','applied','would_apply','failed',
                   'refused','unsupported')),
  mechanism     TEXT,
  tier          TEXT NOT NULL DEFAULT 'none',
  detail        TEXT,
  error         TEXT,
  enforced_at   TEXT
);
CREATE INDEX decisions_by_connection ON decisions(connection_id, id);
CREATE INDEX decisions_by_fp ON decisions(fingerprint, id);

CREATE TABLE scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER NOT NULL REFERENCES connections(id),
  fingerprint   TEXT NOT NULL,
  mount_point   TEXT NOT NULL,
  trigger       TEXT NOT NULL CHECK (trigger IN ('policy','manual')),
  requested_by  TEXT NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('queued','running','done','cancelled')),
  queued_at     TEXT NOT NULL,
  started_at    TEXT,
  finished_at   TEXT,
  verdict       TEXT,
  report        TEXT
);
CREATE INDEX scans_by_connection ON scans(connection_id, id);

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE enrolments (
  fingerprint TEXT NOT NULL,
  bus_path    TEXT NOT NULL,
  label       TEXT,
  enrolled_at TEXT NOT NULL,
  enrolled_by TEXT NOT NULL,
  PRIMARY KEY (fingerprint, bus_path)
);

CREATE TABLE lockdown_state (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  state             TEXT NOT NULL CHECK (state IN ('idle','engaging','active','lifting')),
  engaged_at        TEXT,
  engaged_by        TEXT,
  reason            TEXT,
  minutes           INTEGER,
  expires_at        TEXT,
  remaining_seconds INTEGER,
  checkpoint_at     TEXT,
  renewed_at        TEXT,
  renew_count       INTEGER NOT NULL DEFAULT 0,
  change_id         TEXT,
  timer_armed       INTEGER NOT NULL DEFAULT 0 CHECK (timer_armed IN (0,1)),
  end_reason        TEXT,
  ended_by          TEXT,
  updated_at        TEXT NOT NULL
);
INSERT INTO lockdown_state (id, state, updated_at)
  VALUES (1, 'idle', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

CREATE TABLE lockdown_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  engaged_at  TEXT NOT NULL,
  engaged_by  TEXT NOT NULL,
  reason      TEXT NOT NULL,
  ended_at    TEXT NOT NULL,
  ended_by    TEXT NOT NULL,
  end_reason  TEXT NOT NULL CHECK (end_reason IN
                ('lifted','expired','killswitch','clock_anomaly','unconfirmed','recovered')),
  renew_count INTEGER NOT NULL
);

CREATE TABLE pending_changes (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('applying','awaiting')),
  actor           TEXT NOT NULL,
  channel         TEXT NOT NULL,
  params          TEXT NOT NULL,
  preview         TEXT NOT NULL,
  result          TEXT,
  created_at      TEXT NOT NULL,
  deadline_at     TEXT NOT NULL,
  timeout_seconds INTEGER NOT NULL
);
""",
)


# --- settings ----------------------------------------------------------------------------


def _check_mode(value: Any) -> None:
    if value not in (Mode.MONITOR.value, Mode.ENFORCE.value):
        raise ValueError('must be "monitor" or "enforce"')


def _check_fingerprints(value: Any) -> None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and _FINGERPRINT_PATTERN.match(item) for item in value
    ):
        raise ValueError("must be an array of fingerprint strings")
    if len(set(value)) != len(value):
        raise ValueError("must not repeat a fingerprint")


def _check_bool(value: Any) -> None:
    if not isinstance(value, bool):
        raise ValueError("must be true or false")


def _check_minutes(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("must be an integer")
    if not 1 <= value <= _MAX_LOCKDOWN_MINUTES:
        raise ValueError(f"must be between 1 and {_MAX_LOCKDOWN_MINUTES}")


def _check_service_run(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"run_id", "started_at"}:
        raise ValueError('must be {"run_id", "started_at"}')
    if not isinstance(value["run_id"], str) or not _RUN_ID_PATTERN.match(value["run_id"]):
        raise ValueError("run_id must be 16 lowercase hex characters")
    parse_utc_iso(value["started_at"])


def _check_last_good(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"hash", "policy"}:
        raise ValueError('must be {"hash", "policy"}')
    if not isinstance(value["hash"], str) or not value["hash"]:
        raise ValueError("hash must be a non-empty string")
    if not isinstance(value["policy"], dict):
        raise ValueError("policy must be an object")


def _check_scope(value: Any) -> None:
    if value not in _SCOPES:
        raise ValueError(f"must be one of {_SCOPES}")


_SETTINGS: Mapping[str, Any] = {
    "mode": _check_mode,
    "protected_fingerprints": _check_fingerprints,
    "scan.enabled": _check_bool,
    "lockdown.default_minutes": _check_minutes,
    "service.run": _check_service_run,
    "policy.last_good": _check_last_good,
    "scope": _check_scope,
    "default_deny": _check_bool,
}
#: The closed set of keys :meth:`StateStore.set_setting` accepts.
SETTING_KEYS: frozenset[str] = frozenset(_SETTINGS)


# --- the state store ---------------------------------------------------------------------


class StateStore:
    """Persisted devices, connections, decisions, scans, enrolments, settings and lockdown.

    Every public method runs as one transaction. ``limit`` arguments are clamped to
    1..500. Unknown change keys, unknown setting keys, values a column cannot hold and
    unknown ids raise :class:`StoreError`: they are programming errors. A row that cannot
    be parsed (damaged JSON) is skipped by the list methods and reported as
    :class:`StoreError` by the get methods, so one bad row never hides the rest.

    Thread-safe: every method goes through the :class:`Database` lock.

    Args:
        db: the database; the store's tables are migrated on construction.
        clock: supplies ``updated_at`` and similar timestamps.
    """

    def __init__(self, db: Database, *, clock: Clock) -> None:
        self._db = db
        self._clock = clock
        db.migrate(STORE_COMPONENT, _MIGRATIONS)

    @property
    def db(self) -> Database:
        """The database this store writes to."""
        return self._db

    # --- devices ---------------------------------------------------------------------

    def record_sighting(
        self, device: UsbDevice, fingerprint: Fingerprint, *, storage_identity: str | None
    ) -> DeviceRecord:
        """Insert or refresh the device row for a ``CHANGED`` event (no new connection)."""
        with self._db.transaction():
            self._upsert_device(device, fingerprint, storage_identity, self._clock.now(), 0)
            return self._get_device_locked(fingerprint.value)

    def get_device(self, fingerprint: str) -> DeviceRecord | None:
        row = self._db.query_one("SELECT * FROM devices WHERE fingerprint = ?", (fingerprint,))
        return None if row is None else _parse_or_raise(_device_record, row, "device")

    def list_devices(
        self, *, limit: int = 100, before: str | None = None, text: str | None = None
    ) -> list[DeviceRecord]:
        """Devices, most recently seen first.

        Args:
            before: a fingerprint from a previous page; the page starts after it.
            text: case-insensitive substring of the serial, manufacturer, product or
                fingerprint.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if before is not None:
            clauses.append(
                "(last_seen, fingerprint) < "
                "(SELECT last_seen, fingerprint FROM devices WHERE fingerprint = ?)"
            )
            params.append(before)
        if text:
            pattern = "%" + _escape_like(text) + "%"
            clauses.append(
                "(serial LIKE ? ESCAPE '\\' OR manufacturer LIKE ? ESCAPE '\\' "
                "OR product LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.query(
            f"SELECT * FROM devices {where} ORDER BY last_seen DESC, fingerprint DESC LIMIT ?",  # noqa: S608 - clauses are constants
            (*params, _clamp(limit)),
        )
        return _parse_all(_device_record, rows, "device")

    # --- connections -----------------------------------------------------------------

    def open_connection(
        self,
        device: UsbDevice,
        fingerprint: Fingerprint,
        *,
        run_id: str,
        present_at_start: bool,
        connected_at: datetime,
        storage_identity: str | None = None,
    ) -> ConnectionRecord:
        """Record an arrival: refresh the device row and open a connection, atomically.

        Idempotent per physical connection: a backend may report one arrival twice, so
        if a connection is already open for the same instance id and the same backend
        token (or neither has a token), that connection is returned unchanged. An open
        connection for the same instance id with a *different* token is stale (the
        removal was missed) and is closed with reason ``resync`` first.
        """
        if not isinstance(run_id, str) or not _RUN_ID_PATTERN.match(run_id):
            raise StoreError("run_id must be 16 lowercase hex characters")
        with self._db.transaction():
            existing = self._open_rows_for(device.instance_id)
            for row in existing:
                if row["connection_token"] == device.connection_id:
                    return self._get_connection_locked(int(row["id"]))
            for row in existing:
                self._db.execute(
                    "UPDATE connections SET removed_at = ?, close_reason = 'resync' WHERE id = ?",
                    (utc_iso(connected_at), int(row["id"])),
                )
            self._upsert_device(device, fingerprint, storage_identity, connected_at, 1)
            result = self._db.execute(
                "INSERT INTO connections (fingerprint, instance_id, bus_path, connection_token,"
                " run_id, present_at_start, connected_at, state, description)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'new', ?)",
                (
                    fingerprint.value,
                    device.instance_id,
                    device.bus_path,
                    device.connection_id,
                    run_id,
                    int(bool(present_at_start)),
                    utc_iso(connected_at),
                    _json(device.to_dict()),
                ),
            )
            if result.lastrowid is None:
                raise StoreError("the new connection got no id")
            return self._get_connection_locked(result.lastrowid)

    def find_open_connection(
        self, instance_id: str, connection_token: str | None = None
    ) -> ConnectionRecord | None:
        """The open connection at ``instance_id``; with a token, only if it matches."""
        for row in self._open_rows_for(instance_id):
            if connection_token is None or row["connection_token"] == connection_token:
                return self.get_connection(int(row["id"]))
        return None

    def update_connection(self, connection_id: int, **changes: Any) -> ConnectionRecord:
        """Change some fields of a connection.

        Accepted keys: ``device``, ``state``, ``provisional``, ``resolution``,
        ``scan_state``, ``last_scan_id``, ``decision_id``.
        """
        columns: dict[str, Any] = {}
        for key, value in changes.items():
            if key == "device":
                if not isinstance(value, UsbDevice):
                    raise StoreError("device must be a UsbDevice")
                columns["description"] = _json(value.to_dict())
                columns["bus_path"] = value.bus_path
            elif key == "state":
                columns["state"] = _enum(ConnectionState, value, "state").value
            elif key == "provisional":
                columns["provisional"] = int(_bool(value, "provisional"))
            elif key == "resolution":
                columns["resolution"] = None if value is None else _json(_mapping(value, key))
            elif key == "scan_state":
                columns["scan_state"] = _enum(ScanState, value, "scan_state").value
            elif key in ("last_scan_id", "decision_id"):
                columns[key] = _optional_int(value, key)
            else:
                raise StoreError(f"update_connection does not accept {key!r}")
        with self._db.transaction():
            self._update_row("connections", connection_id, columns)
            return self._get_connection_locked(connection_id)

    def close_connection(
        self, connection_id: int, *, removed_at: datetime, reason: str
    ) -> ConnectionRecord:
        """Mark a connection removed. Closing a closed connection changes nothing."""
        _choice(reason, _CLOSE_REASONS, "reason")
        with self._db.transaction():
            record = self._get_connection_locked(connection_id)
            if record.removed_at is None:
                self._db.execute(
                    "UPDATE connections SET removed_at = ?, close_reason = ? WHERE id = ?",
                    (utc_iso(removed_at), reason, connection_id),
                )
                record = self._get_connection_locked(connection_id)
            return record

    def close_open_connections(self, *, removed_at: datetime, reason: str) -> int:
        """Close every open connection (at start-up: those of a run that crashed)."""
        _choice(reason, _CLOSE_REASONS, "reason")
        with self._db.transaction():
            return self._db.execute(
                "UPDATE connections SET removed_at = ?, close_reason = ? WHERE removed_at IS NULL",
                (utc_iso(removed_at), reason),
            ).rowcount

    def get_connection(self, connection_id: int) -> ConnectionRecord | None:
        row = self._connection_row(connection_id)
        return None if row is None else _parse_or_raise(_connection_record, row, "connection")

    def open_connections(self) -> list[ConnectionRecord]:
        """Every open connection, oldest first."""
        rows = self._db.query(_CONNECTION_SELECT + " WHERE c.removed_at IS NULL ORDER BY c.id ASC")
        return _parse_all(_connection_record, rows, "connection")

    def list_connections(
        self,
        *,
        open_only: bool = False,
        fingerprint: str | None = None,
        before_id: int | None = None,
        limit: int = 100,
    ) -> list[ConnectionRecord]:
        """Connections, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if open_only:
            clauses.append("c.removed_at IS NULL")
        if fingerprint is not None:
            clauses.append("c.fingerprint = ?")
            params.append(fingerprint)
        if before_id is not None:
            clauses.append("c.id < ?")
            params.append(_int(before_id, "before_id"))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.query(
            _CONNECTION_SELECT + where + " ORDER BY c.id DESC LIMIT ?",
            (*params, _clamp(limit)),
        )
        return _parse_all(_connection_record, rows, "connection")

    # --- decisions -------------------------------------------------------------------

    def add_decision(
        self,
        connection_id: int,
        decision: Decision,
        *,
        trigger: str,
        policy_hash: str,
        mode: Mode,
        decided_at: datetime,
    ) -> DecisionRecord:
        """Record a decision and make it the connection's current one, atomically."""
        if not isinstance(decision, Decision):
            raise StoreError("decision must be a Decision")
        _text(trigger, "trigger")
        _text(policy_hash, "policy_hash")
        mode = _enum(Mode, mode, "mode")
        with self._db.transaction():
            fingerprint = self._get_connection_locked(connection_id).fingerprint.value
            result = self._db.execute(
                "INSERT INTO decisions (connection_id, fingerprint, decided_at, trigger, access,"
                " source, rule_id, grant_id, scan, alert, expires_at, reasons, policy_hash, mode)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    connection_id,
                    fingerprint,
                    utc_iso(decided_at),
                    trigger,
                    decision.access.value,
                    decision.source.value,
                    decision.rule_id,
                    decision.grant_id,
                    decision.scan.value,
                    int(decision.alert),
                    utc_iso(decision.expires_at) if decision.expires_at is not None else None,
                    _json(list(decision.reasons)),
                    policy_hash,
                    mode.value,
                ),
            )
            decision_id = result.lastrowid
            if decision_id is None:
                raise StoreError("the new decision got no id")
            self._db.execute(
                "UPDATE connections SET decision_id = ? WHERE id = ?", (decision_id, connection_id)
            )
            return self._get_decision_locked(decision_id)

    def set_outcome(
        self,
        decision_id: int,
        *,
        outcome: Outcome,
        mechanism: str | None,
        tier: Tier,
        detail: str | None,
        error: str | None,
        enforced_at: datetime,
    ) -> None:
        """Record what enforcing a decision achieved (updated in place)."""
        columns = {
            "outcome": _enum(Outcome, outcome, "outcome").value,
            "mechanism": mechanism,
            "tier": _enum(Tier, tier, "tier").value,
            "detail": detail,
            "error": error,
            "enforced_at": utc_iso(enforced_at),
        }
        with self._db.transaction():
            self._update_row("decisions", decision_id, columns)

    def get_decision(self, decision_id: int) -> DecisionRecord | None:
        row = self._db.query_one("SELECT * FROM decisions WHERE id = ?", (decision_id,))
        return None if row is None else _parse_or_raise(_decision_record, row, "decision")

    def list_decisions(
        self,
        *,
        connection_id: int | None = None,
        fingerprint: str | None = None,
        access: Access | None = None,
        before_id: int | None = None,
        limit: int = 100,
    ) -> list[DecisionRecord]:
        """Decisions, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if connection_id is not None:
            clauses.append("connection_id = ?")
            params.append(_int(connection_id, "connection_id"))
        if fingerprint is not None:
            clauses.append("fingerprint = ?")
            params.append(fingerprint)
        if access is not None:
            clauses.append("access = ?")
            params.append(_enum(Access, access, "access").value)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(_int(before_id, "before_id"))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.query(
            "SELECT * FROM decisions" + where + " ORDER BY id DESC LIMIT ?",  # noqa: S608
            (*params, _clamp(limit)),
        )
        return _parse_all(_decision_record, rows, "decision")

    # --- scans -----------------------------------------------------------------------

    def add_scan(
        self,
        connection_id: int,
        fingerprint: str,
        mount_point: str,
        *,
        trigger: str,
        requested_by: str,
        queued_at: datetime,
    ) -> ScanRecord:
        """Queue a scan of one volume of a connection."""
        _choice(trigger, ("policy", "manual"), "trigger")
        _text(mount_point, "mount_point")
        _text(requested_by, "requested_by", limit=_MAX_ACTOR)
        with self._db.transaction():
            self._get_connection_locked(connection_id)
            result = self._db.execute(
                "INSERT INTO scans (connection_id, fingerprint, mount_point, trigger,"
                " requested_by, state, queued_at) VALUES (?, ?, ?, ?, ?, 'queued', ?)",
                (
                    connection_id,
                    fingerprint,
                    mount_point,
                    trigger,
                    requested_by,
                    utc_iso(queued_at),
                ),
            )
            if result.lastrowid is None:
                raise StoreError("the new scan got no id")
            return self._get_scan_locked(result.lastrowid)

    def update_scan(self, scan_id: int, **changes: Any) -> ScanRecord:
        """Accepted keys: ``state``, ``started_at``, ``finished_at``, ``verdict``, ``report``."""
        columns: dict[str, Any] = {}
        for key, value in changes.items():
            if key == "state":
                columns["state"] = _choice(value, ("queued", "running", "done", "cancelled"), key)
            elif key in ("started_at", "finished_at"):
                columns[key] = None if value is None else utc_iso(_datetime(value, key))
            elif key == "verdict":
                columns[key] = None if value is None else _text(value, key)
            elif key == "report":
                columns[key] = None if value is None else _json(_mapping(value, key))
            else:
                raise StoreError(f"update_scan does not accept {key!r}")
        with self._db.transaction():
            self._update_row("scans", scan_id, columns)
            return self._get_scan_locked(scan_id)

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self._db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return None if row is None else _parse_or_raise(_scan_record, row, "scan")

    def list_scans(
        self,
        *,
        connection_id: int | None = None,
        fingerprint: str | None = None,
        before_id: int | None = None,
        limit: int = 100,
    ) -> list[ScanRecord]:
        """Scans, newest first."""
        clauses: list[str] = []
        params: list[Any] = []
        if connection_id is not None:
            clauses.append("connection_id = ?")
            params.append(_int(connection_id, "connection_id"))
        if fingerprint is not None:
            clauses.append("fingerprint = ?")
            params.append(fingerprint)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(_int(before_id, "before_id"))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.query(
            "SELECT * FROM scans" + where + " ORDER BY id DESC LIMIT ?",  # noqa: S608
            (*params, _clamp(limit)),
        )
        return _parse_all(_scan_record, rows, "scan")

    # --- enrolments ------------------------------------------------------------------

    def add_enrolment(
        self, fingerprint: str, bus_path: str, *, by: str, label: str | None = None
    ) -> EnrolmentRecord:
        """Enrol a device on one port (``docs/DESIGN.md`` section 14.1).

        Enrolling the same fingerprint on the same port again keeps the original record.
        """
        _fingerprint_value(fingerprint)
        _text(bus_path, "bus_path", limit=128)
        _text(by, "by", limit=_MAX_ACTOR)
        if label is not None:
            _text(label, "label", limit=128)
        with self._db.transaction():
            self._db.execute(
                "INSERT INTO enrolments (fingerprint, bus_path, label, enrolled_at, enrolled_by)"
                " VALUES (?, ?, ?, ?, ?) ON CONFLICT (fingerprint, bus_path) DO NOTHING",
                (fingerprint, bus_path, label, utc_iso(self._clock.now()), by),
            )
            row = self._db.query_one(
                "SELECT * FROM enrolments WHERE fingerprint = ? AND bus_path = ?",
                (fingerprint, bus_path),
            )
            if row is None:
                raise StoreError("the enrolment was not stored")
            return _parse_or_raise(_enrolment_record, row, "enrolment")

    def remove_enrolment(self, fingerprint: str, bus_path: str | None = None) -> int:
        """Remove one enrolment, or every port of a fingerprint. Returns how many went."""
        if bus_path is None:
            return self._db.execute(
                "DELETE FROM enrolments WHERE fingerprint = ?", (fingerprint,)
            ).rowcount
        return self._db.execute(
            "DELETE FROM enrolments WHERE fingerprint = ? AND bus_path = ?",
            (fingerprint, bus_path),
        ).rowcount

    def list_enrolments(self) -> list[EnrolmentRecord]:
        rows = self._db.query(
            "SELECT * FROM enrolments ORDER BY enrolled_at, fingerprint, bus_path"
        )
        return _parse_all(_enrolment_record, rows, "enrolment")

    def enrolled_pairs(self) -> frozenset[tuple[str, str]]:
        """``(fingerprint, bus path)`` pairs, the form ``SafetyContext.enrolled`` takes."""
        return frozenset((r.fingerprint, r.bus_path) for r in self.list_enrolments())

    # --- settings --------------------------------------------------------------------

    def get_setting(self, key: str, default: Any = None) -> Any:
        """A setting's value, or ``default`` if unset. A damaged value raises."""
        _setting_key(key)
        row = self._db.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        if row is None:
            return default
        try:
            value = json.loads(row["value"])
            _SETTINGS[key](value)
        except (ValueError, TypeError) as exc:
            raise StoreError(f"setting {key!r} holds an unusable value: {exc}") from exc
        return value

    def set_setting(self, key: str, value: Any, *, by: str) -> None:
        """Store a setting. ``value`` is validated for its key."""
        _setting_key(key)
        _text(by, "by", limit=_MAX_ACTOR)
        try:
            _SETTINGS[key](value)
        except (ValueError, TypeError) as exc:
            raise StoreError(f"setting {key!r} {exc}") from exc
        self._db.execute(
            "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (key, _json(value), utc_iso(self._clock.now()), by),
        )

    def delete_setting(self, key: str) -> None:
        _setting_key(key)
        self._db.execute("DELETE FROM settings WHERE key = ?", (key,))

    def settings(self) -> dict[str, Any]:
        """Every stored setting whose value is usable."""
        result: dict[str, Any] = {}
        for row in self._db.query("SELECT key, value FROM settings ORDER BY key"):
            key = row["key"]
            try:
                value = json.loads(row["value"])
                _SETTINGS[key](value)
            except (KeyError, ValueError, TypeError):
                _LOG.warning("skipping unusable setting %r", key)
                continue
            result[key] = value
        return result

    # --- lockdown --------------------------------------------------------------------

    def get_lockdown(self) -> LockdownRecord:
        """The lockdown row.

        Raises:
            StoreError: if the row is missing or unusable.
        """
        row = self._db.query_one("SELECT * FROM lockdown_state WHERE id = 1")
        if row is None:
            raise StoreError("the lockdown state row is missing")
        return _parse_or_raise(_lockdown_record, row, "lockdown state")

    def save_lockdown(
        self,
        record: LockdownRecord,
        *,
        expect: Collection[str] | None = None,
        history_end: tuple[datetime, str, str] | None = None,
        delete_change: str | None = None,
    ) -> LockdownRecord:
        """Replace the lockdown row, atomically with the steps that go with it.

        Args:
            record: the new row; ``updated_at`` is set here.
            expect: if given, the stored state must be one of these, or nothing is
                written (compare-and-set against a concurrent change or a second process).
            history_end: ``(ended_at, ended_by, end_reason)``: also append a history row
                for the lockdown the *stored* row describes.
            delete_change: also delete this pending change.

        Raises:
            StoreError: code ``lockdown_conflict`` if ``expect`` does not hold; plain
                ``store_error`` for an invalid record.
        """
        values = _lockdown_columns(record, self._clock.now())
        with self._db.transaction():
            current = self.get_lockdown()
            if expect is not None and current.state not in expect:
                raise StoreError(
                    f"the lockdown is {current.state}, expected one of {sorted(expect)}",
                    code="lockdown_conflict",
                )
            if history_end is not None:
                ended_at, ended_by, end_reason = history_end
                _choice(end_reason, LOCKDOWN_END_REASONS, "end_reason")
                if current.engaged_at is not None:
                    self._db.execute(
                        "INSERT INTO lockdown_history (engaged_at, engaged_by, reason, ended_at,"
                        " ended_by, end_reason, renew_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            utc_iso(current.engaged_at),
                            current.engaged_by or "unknown",
                            current.reason or "",
                            utc_iso(ended_at),
                            _text(ended_by, "ended_by", limit=_MAX_ACTOR),
                            end_reason,
                            current.renew_count,
                        ),
                    )
            if delete_change is not None:
                self._db.execute("DELETE FROM pending_changes WHERE id = ?", (delete_change,))
            assignments = ", ".join(f"{name} = ?" for name in values)
            self._db.execute(
                f"UPDATE lockdown_state SET {assignments} WHERE id = 1",  # noqa: S608 - fixed column names
                tuple(values.values()),
            )
            return self.get_lockdown()

    def lockdown_history(self, *, limit: int = 100) -> list[LockdownHistoryRecord]:
        """Lockdowns that have ended, newest first."""
        rows = self._db.query(
            "SELECT * FROM lockdown_history ORDER BY id DESC LIMIT ?", (_clamp(limit),)
        )
        return _parse_all(_history_record, rows, "lockdown history")

    # --- pending changes (commit-confirm) --------------------------------------------

    def add_pending_change(self, record: PendingChangeRecord) -> PendingChangeRecord:
        """Store a change about to be applied under commit-confirm (written ahead)."""
        if not _RECORD_ID_PATTERN.match(record.id):
            raise StoreError("a pending change id is 16 lowercase hex characters")
        if not _CHANGE_KIND_PATTERN.match(record.kind):
            raise StoreError(f"invalid change kind {record.kind!r}")
        _choice(record.status, PENDING_STATUSES, "status")
        _text(record.actor, "actor", limit=_MAX_ACTOR)
        _text(record.channel, "channel", limit=128)
        if isinstance(record.timeout_seconds, bool) or not isinstance(record.timeout_seconds, int):
            raise StoreError("timeout_seconds must be an integer")
        with self._db.transaction():
            self._db.execute(
                "INSERT INTO pending_changes (id, kind, status, actor, channel, params, preview,"
                " result, created_at, deadline_at, timeout_seconds)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.kind,
                    record.status,
                    record.actor,
                    record.channel,
                    _json(_mapping(record.params, "params")),
                    _json([_mapping(item, "preview") for item in record.preview]),
                    None if record.result is None else _json(_mapping(record.result, "result")),
                    utc_iso(record.created_at),
                    utc_iso(record.deadline_at),
                    record.timeout_seconds,
                ),
            )
            return self._get_pending_locked(record.id)

    def set_pending_status(
        self, change_id: str, status: str, *, result: Mapping[str, Any] | None = None
    ) -> PendingChangeRecord:
        """Move a pending change to ``status``, optionally recording its result."""
        _choice(status, PENDING_STATUSES, "status")
        with self._db.transaction():
            self._get_pending_locked(change_id)
            self._db.execute(
                "UPDATE pending_changes SET status = ?, result = COALESCE(?, result) WHERE id = ?",
                (status, None if result is None else _json(_mapping(result, "result")), change_id),
            )
            return self._get_pending_locked(change_id)

    def delete_pending_change(self, change_id: str) -> bool:
        """Forget a pending change. Returns False if there was none."""
        return (
            self._db.execute("DELETE FROM pending_changes WHERE id = ?", (change_id,)).rowcount > 0
        )

    def get_pending_change(self, change_id: str) -> PendingChangeRecord | None:
        row = self._db.query_one("SELECT * FROM pending_changes WHERE id = ?", (change_id,))
        return None if row is None else _parse_or_raise(_pending_record, row, "pending change")

    def pending_changes(self, *, kind: str | None = None) -> list[PendingChangeRecord]:
        """Pending changes, oldest first. A damaged row is skipped (and logged)."""
        if kind is None:
            rows = self._db.query("SELECT * FROM pending_changes ORDER BY created_at, id")
        else:
            rows = self._db.query(
                "SELECT * FROM pending_changes WHERE kind = ? ORDER BY created_at, id", (kind,)
            )
        return _parse_all(_pending_record, rows, "pending change")

    def pending_change_ids(self) -> list[str]:
        """The id of every pending change row, damaged ones included."""
        return [str(row["id"]) for row in self._db.query("SELECT id FROM pending_changes")]

    # --- internals -------------------------------------------------------------------

    def _upsert_device(
        self,
        device: UsbDevice,
        fingerprint: Fingerprint,
        storage_identity: str | None,
        seen_at: datetime,
        increment: int,
    ) -> None:
        if not isinstance(device, UsbDevice) or not isinstance(fingerprint, Fingerprint):
            raise StoreError("a device sighting needs a UsbDevice and its Fingerprint")
        _fingerprint_value(fingerprint.value)
        seen = utc_iso(seen_at)
        self._db.execute(
            "INSERT INTO devices (fingerprint, confidence, basis, vendor_id, product_id, serial,"
            " manufacturer, product, categories, storage_identity, description, first_seen,"
            " last_seen, connection_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (fingerprint) DO UPDATE SET confidence = excluded.confidence,"
            " basis = excluded.basis, serial = excluded.serial,"
            " manufacturer = excluded.manufacturer, product = excluded.product,"
            " categories = excluded.categories,"
            " storage_identity = COALESCE(excluded.storage_identity, devices.storage_identity),"
            " description = excluded.description, last_seen = excluded.last_seen,"
            " connection_count = devices.connection_count + ?",
            (
                fingerprint.value,
                Confidence(fingerprint.confidence).value,
                _json(list(fingerprint.basis)),
                device.vendor_id,
                device.product_id,
                device.serial,
                device.manufacturer,
                device.product,
                _json(sorted(category.value for category in device.categories)),
                storage_identity,
                _json(device.to_dict()),
                seen,
                seen,
                increment,
                increment,
            ),
        )

    def _get_device_locked(self, fingerprint: str) -> DeviceRecord:
        row = self._db.query_one("SELECT * FROM devices WHERE fingerprint = ?", (fingerprint,))
        if row is None:
            raise StoreError(f"unknown device {fingerprint!r}")
        return _parse_or_raise(_device_record, row, "device")

    def _open_rows_for(self, instance_id: str) -> list[sqlite3.Row]:
        return self._db.query(
            "SELECT id, connection_token FROM connections"
            " WHERE instance_id = ? AND removed_at IS NULL ORDER BY id",
            (instance_id,),
        )

    def _connection_row(self, connection_id: int) -> sqlite3.Row | None:
        return self._db.query_one(_CONNECTION_SELECT + " WHERE c.id = ?", (connection_id,))

    def _get_connection_locked(self, connection_id: int) -> ConnectionRecord:
        row = self._connection_row(connection_id)
        if row is None:
            raise StoreError(f"unknown connection {connection_id!r}")
        return _parse_or_raise(_connection_record, row, "connection")

    def _get_decision_locked(self, decision_id: int) -> DecisionRecord:
        record = self.get_decision(decision_id)
        if record is None:
            raise StoreError(f"unknown decision {decision_id!r}")
        return record

    def _get_scan_locked(self, scan_id: int) -> ScanRecord:
        record = self.get_scan(scan_id)
        if record is None:
            raise StoreError(f"unknown scan {scan_id!r}")
        return record

    def _get_pending_locked(self, change_id: str) -> PendingChangeRecord:
        record = self.get_pending_change(change_id)
        if record is None:
            raise StoreError(f"unknown pending change {change_id!r}")
        return record

    def _update_row(self, table: str, row_id: int, columns: Mapping[str, Any]) -> None:
        _int(row_id, "id")
        if not columns:
            if self._db.query_one(f"SELECT id FROM {table} WHERE id = ?", (row_id,)) is None:  # noqa: S608 - table names are constants
                raise StoreError(f"unknown {table[:-1]} {row_id!r}")
            return
        assignments = ", ".join(f"{name} = ?" for name in columns)
        result = self._db.execute(
            f"UPDATE {table} SET {assignments} WHERE id = ?",  # noqa: S608 - names are constants
            (*columns.values(), row_id),
        )
        if result.rowcount == 0:
            raise StoreError(f"unknown {table[:-1]} {row_id!r}")


_CONNECTION_SELECT = (
    "SELECT c.*, d.confidence AS fp_confidence, d.basis AS fp_basis"
    " FROM connections c JOIN devices d ON d.fingerprint = c.fingerprint"
)


# --- row parsing -------------------------------------------------------------------------


def _device_record(row: sqlite3.Row) -> DeviceRecord:
    return DeviceRecord(
        fingerprint=Fingerprint(
            row["fingerprint"], Confidence(row["confidence"]), tuple(json.loads(row["basis"]))
        ),
        device=UsbDevice.from_dict(json.loads(row["description"])),
        storage_identity=row["storage_identity"],
        first_seen=parse_utc_iso(row["first_seen"]),
        last_seen=parse_utc_iso(row["last_seen"]),
        connection_count=int(row["connection_count"]),
    )


def _connection_record(row: sqlite3.Row) -> ConnectionRecord:
    resolution = row["resolution"]
    return ConnectionRecord(
        id=int(row["id"]),
        fingerprint=Fingerprint(
            row["fingerprint"], Confidence(row["fp_confidence"]), tuple(json.loads(row["fp_basis"]))
        ),
        device=UsbDevice.from_dict(json.loads(row["description"])),
        instance_id=row["instance_id"],
        bus_path=row["bus_path"],
        connection_token=row["connection_token"],
        run_id=row["run_id"],
        present_at_start=bool(row["present_at_start"]),
        connected_at=parse_utc_iso(row["connected_at"]),
        removed_at=_optional_time(row["removed_at"]),
        close_reason=row["close_reason"],
        state=ConnectionState(row["state"]),
        provisional=bool(row["provisional"]),
        resolution=None if resolution is None else _loaded_mapping(resolution),
        scan_state=ScanState(row["scan_state"]),
        last_scan_id=row["last_scan_id"],
        decision_id=row["decision_id"],
    )


def _decision_record(row: sqlite3.Row) -> DecisionRecord:
    decision = Decision.from_dict(
        {
            "access": row["access"],
            "source": row["source"],
            "reasons": json.loads(row["reasons"]),
            "rule_id": row["rule_id"],
            "grant_id": row["grant_id"],
            "scan": row["scan"],
            "alert": bool(row["alert"]),
            "expires_at": row["expires_at"],
        }
    )
    return DecisionRecord(
        id=int(row["id"]),
        connection_id=int(row["connection_id"]),
        fingerprint=row["fingerprint"],
        decided_at=parse_utc_iso(row["decided_at"]),
        trigger=row["trigger"],
        decision=decision,
        policy_hash=row["policy_hash"],
        mode=Mode(row["mode"]),
        outcome=Outcome(row["outcome"]),
        mechanism=row["mechanism"],
        tier=Tier(row["tier"]),
        detail=row["detail"],
        error=row["error"],
        enforced_at=_optional_time(row["enforced_at"]),
    )


def _scan_record(row: sqlite3.Row) -> ScanRecord:
    report = row["report"]
    return ScanRecord(
        id=int(row["id"]),
        connection_id=int(row["connection_id"]),
        fingerprint=row["fingerprint"],
        mount_point=row["mount_point"],
        trigger=row["trigger"],
        requested_by=row["requested_by"],
        state=row["state"],
        queued_at=parse_utc_iso(row["queued_at"]),
        started_at=_optional_time(row["started_at"]),
        finished_at=_optional_time(row["finished_at"]),
        verdict=row["verdict"],
        report=None if report is None else _loaded_mapping(report),
    )


def _enrolment_record(row: sqlite3.Row) -> EnrolmentRecord:
    return EnrolmentRecord(
        fingerprint=row["fingerprint"],
        bus_path=row["bus_path"],
        label=row["label"],
        enrolled_at=parse_utc_iso(row["enrolled_at"]),
        enrolled_by=row["enrolled_by"],
    )


def _lockdown_record(row: sqlite3.Row) -> LockdownRecord:
    state = row["state"]
    if state not in LOCKDOWN_STATES:
        raise ValueError(f"unknown lockdown state {state!r}")
    end_reason = row["end_reason"]
    if end_reason is not None and end_reason not in LOCKDOWN_END_REASONS:
        raise ValueError(f"unknown end reason {end_reason!r}")
    return LockdownRecord(
        state=state,
        engaged_at=_optional_time(row["engaged_at"]),
        engaged_by=row["engaged_by"],
        reason=row["reason"],
        minutes=row["minutes"],
        expires_at=_optional_time(row["expires_at"]),
        remaining_seconds=row["remaining_seconds"],
        checkpoint_at=_optional_time(row["checkpoint_at"]),
        renewed_at=_optional_time(row["renewed_at"]),
        renew_count=int(row["renew_count"]),
        change_id=row["change_id"],
        timer_armed=bool(row["timer_armed"]),
        end_reason=end_reason,
        ended_by=row["ended_by"],
        updated_at=parse_utc_iso(row["updated_at"]),
    )


def _history_record(row: sqlite3.Row) -> LockdownHistoryRecord:
    return LockdownHistoryRecord(
        id=int(row["id"]),
        engaged_at=parse_utc_iso(row["engaged_at"]),
        engaged_by=row["engaged_by"],
        reason=row["reason"],
        ended_at=parse_utc_iso(row["ended_at"]),
        ended_by=row["ended_by"],
        end_reason=row["end_reason"],
        renew_count=int(row["renew_count"]),
    )


def _pending_record(row: sqlite3.Row) -> PendingChangeRecord:
    preview = json.loads(row["preview"])
    if not isinstance(preview, list) or not all(isinstance(item, dict) for item in preview):
        raise ValueError("preview must be a list of objects")
    result = row["result"]
    return PendingChangeRecord(
        id=row["id"],
        kind=row["kind"],
        status=row["status"],
        actor=row["actor"],
        channel=row["channel"],
        params=_loaded_mapping(row["params"]),
        preview=tuple(preview),
        result=None if result is None else _loaded_mapping(result),
        created_at=parse_utc_iso(row["created_at"]),
        deadline_at=parse_utc_iso(row["deadline_at"]),
        timeout_seconds=int(row["timeout_seconds"]),
    )


def _lockdown_columns(record: LockdownRecord, now: datetime) -> dict[str, Any]:
    if not isinstance(record, LockdownRecord):
        raise StoreError("expected a LockdownRecord")
    _choice(record.state, LOCKDOWN_STATES, "state")
    if record.end_reason is not None:
        _choice(record.end_reason, LOCKDOWN_END_REASONS, "end_reason")
    for name in ("minutes", "remaining_seconds"):
        value = getattr(record, name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise StoreError(f"{name} must be an integer")
    if record.change_id is not None and not _RECORD_ID_PATTERN.match(record.change_id):
        raise StoreError("change_id must be 16 lowercase hex characters")
    for name in ("engaged_by", "ended_by"):
        value = getattr(record, name)
        if value is not None:
            _text(value, name, limit=_MAX_ACTOR)
    if record.reason is not None and len(record.reason) > _MAX_TEXT:
        raise StoreError("reason is too long")

    def when(value: datetime | None) -> str | None:
        return None if value is None else utc_iso(value)

    return {
        "state": record.state,
        "engaged_at": when(record.engaged_at),
        "engaged_by": record.engaged_by,
        "reason": record.reason,
        "minutes": record.minutes,
        "expires_at": when(record.expires_at),
        "remaining_seconds": record.remaining_seconds,
        "checkpoint_at": when(record.checkpoint_at),
        "renewed_at": when(record.renewed_at),
        "renew_count": int(record.renew_count),
        "change_id": record.change_id,
        "timer_armed": int(bool(record.timer_armed)),
        "end_reason": record.end_reason,
        "ended_by": record.ended_by,
        "updated_at": utc_iso(now),
    }


_ROW_ERRORS = (KeyError, ValueError, TypeError, IndexError)


def _parse_or_raise(parse: Any, row: sqlite3.Row, what: str) -> Any:
    try:
        return parse(row)
    except _ROW_ERRORS as exc:
        raise StoreError(f"the stored {what} cannot be read: {exc}") from exc


def _parse_all(parse: Any, rows: Iterable[sqlite3.Row], what: str) -> list[Any]:
    records: list[Any] = []
    for row in rows:
        try:
            records.append(parse(row))
        except _ROW_ERRORS as exc:
            _LOG.warning("skipping an unreadable %s row: %s", what, exc)
    return records


# --- validation helpers ------------------------------------------------------------------


def _json(value: Any) -> str:
    try:
        return canonicalize(value)
    except CanonicalError as exc:
        raise StoreError(f"value cannot be stored: {exc}") from exc


def _loaded_mapping(text: str) -> Mapping[str, Any]:
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def _optional_time(value: str | None) -> datetime | None:
    return None if value is None else parse_utc_iso(value)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _clamp(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise StoreError("limit must be an integer")
    return max(1, min(_MAX_LIMIT, limit))


def _int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StoreError(f"{name} must be an integer")
    return value


def _optional_int(value: Any, name: str) -> int | None:
    return None if value is None else _int(value, name)


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise StoreError(f"{name} must be True or False")
    return value


def _text(value: Any, name: str, *, limit: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise StoreError(f"{name} must be a non-empty string of at most {limit} characters")
    return value


def _choice(value: Any, choices: Sequence[str], name: str) -> str:
    if value not in choices:
        raise StoreError(f"{name} must be one of {tuple(choices)}, got {value!r}")
    return str(value)


def _enum(kind: Any, value: Any, name: str) -> Any:
    try:
        return kind(value)
    except ValueError as exc:
        raise StoreError(f"invalid {name}: {value!r}") from exc


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StoreError(f"{name} must be a mapping")
    return dict(value)


def _datetime(value: Any, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise StoreError(f"{name} must be a datetime")
    return value


def _fingerprint_value(value: Any) -> str:
    if not isinstance(value, str) or not _FINGERPRINT_PATTERN.match(value):
        raise StoreError(f"not a fingerprint: {value!r}")
    return value


def _setting_key(key: Any) -> None:
    if key not in _SETTINGS:
        raise StoreError(f"unknown setting {key!r}; known settings are {sorted(_SETTINGS)}")


# --- the recovery journal ----------------------------------------------------------------

# A journal line is a small object; anything longer is not one PortLock wrote.
_MAX_LINE_BYTES = 16 * 1024
_MAX_TARGET = 1024
_MAX_VALUE = 4096
_MAX_SCOPE = 512
_COMPACT_AFTER_CLOSED = 1000
_OPEN_KEYS = frozenset({"op", "id", "ts", "scope", "action", "fp", "entry"})
_HOLD_KEYS = frozenset({"op", "id", "ts", "scope", "action", "fp"})
_CLOSE_KEYS = frozenset({"op", "id", "ts", "reason"})
_ENTRY_KEYS = frozenset({"kind", "target", "previous", "applied"})
# A journal record describes a change one of these calls made.
_JOURNALED_ACTIONS = frozenset(
    {
        Action.BLOCK,
        Action.UNBLOCK,
        Action.READ_ONLY,
        Action.READ_WRITE,
        Action.DEFAULT_DENY_ON,
        Action.DEFAULT_DENY_OFF,
    }
)
_UDEV_RULE_DIRS = ("/etc/udev/rules.d", "/run/udev/rules.d")


@dataclass(frozen=True, slots=True)
class JournalRecord:
    """One open record of the enforcement journal.

    Attributes:
        id: 16 lowercase hex characters.
        ts: when it was written.
        scope: the device instance id it concerns, or :data:`GLOBAL_SCOPE`.
        action: the enforcement call that wrote it.
        fingerprint: the device's fingerprint value, if it concerns one device.
        entry: the change and its baseline; ``None`` for a *hold* (a marker that the
            service keeps the device at ``scope`` blocked, released by unblocking it).
    """

    id: str
    ts: datetime
    scope: str
    action: Action
    fingerprint: str | None
    entry: JournalEntry | None

    @property
    def is_hold(self) -> bool:
        return self.entry is None

    @property
    def key(self) -> tuple[str, str] | None:
        """``(kind, target)``: at most one open record per key. ``None`` for a hold."""
        return None if self.entry is None else (self.entry.kind, self.entry.target)

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "op": "hold" if self.entry is None else "open",
            "id": self.id,
            "ts": utc_iso(self.ts),
            "scope": self.scope,
            "action": self.action.value,
            "fp": self.fingerprint,
        }
        if self.entry is not None:
            data["entry"] = self.entry.to_dict()
        return data


def check_journal_entry(entry: JournalEntry) -> None:
    """Refuse a journal entry that does not describe a change PortLock could have made.

    The kind is already one of :class:`~portlock.guard.base.JournalKind`. On top of that
    the target must have the shape its kind allows, so a tampered journal cannot steer
    a privileged restore at an arbitrary file, device node or registry key. Enforcers
    validate again, against their exact grammar, before they write anything.

    Raises:
        ValueError: naming what is wrong.
    """
    target = entry.target
    if len(target) > _MAX_TARGET or _has_control(target):
        raise ValueError("the target is too long or contains control characters")
    for name in ("previous", "applied"):
        value = getattr(entry, name)
        if value is not None and (
            not isinstance(value, str) or len(value) > _MAX_VALUE or "\x00" in value
        ):
            raise ValueError(f"the {name} value is not a string of at most {_MAX_VALUE} characters")
    kind = JournalKind(entry.kind)
    if kind in (JournalKind.SYSFS_AUTHORIZED, JournalKind.SYSFS_AUTHORIZED_DEFAULT):
        _posix_path_under(target, ("/sys",))
    elif kind is JournalKind.BLOCK_READ_ONLY:
        _posix_path_under(target, ("/dev",))
    elif kind is JournalKind.UDEV_RULE:
        path = _posix_path_under(target, _UDEV_RULE_DIRS)
        if str(path.parent) not in _UDEV_RULE_DIRS or not path.name.endswith(".rules"):
            raise ValueError(f"{target!r} is not a rules file in a udev rules directory")
    elif kind is JournalKind.WIN_DEVNODE and not target.casefold().startswith("usb\\"):
        raise ValueError(f"{target!r} is not a USB device instance id")
    elif kind is JournalKind.WIN_POLICY_VALUE and (
        "\\policies\\" not in target.casefold() or "\\..\\" in target
    ):
        raise ValueError(f"{target!r} is not under a Policies registry key")


def _posix_path_under(target: str, roots: Sequence[str]) -> PurePosixPath:
    path = PurePosixPath(target)
    if not path.is_absolute() or ".." in path.parts or "//" in target:
        raise ValueError(f"{target!r} is not a normalized absolute path")
    if not any(target.startswith(root + "/") for root in roots):
        raise ValueError(f"{target!r} is outside {', '.join(roots)}")
    return path


def _has_control(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


@dataclass(slots=True)
class _Recording:
    scope: str
    action: Action
    fingerprint: str | None
    opened: set[str] = field(default_factory=set)


class RecoveryJournal:
    """The enforcement journal: the baseline of every operating-system value PortLock changed.

    **The journal rule.** At most one record is open per ``(kind, target)``; its
    ``previous`` is the baseline, the value before PortLock first touched the target.
    :meth:`write_ahead` appends and ``fsync``s the record *before* the enforcer writes
    (``docs/ARCHITECTURE.md`` 2.2, E2), so there is no moment at which the operating
    system was changed and the journal does not know. :meth:`record` closes what the
    call returned to its baseline and what it did not, after all, change.

    **Replay.** Loading reads the file line by line. A line that is not canonical JSON,
    does not have exactly the fields of an ``open``, ``hold`` or ``close`` record, names
    an action, kind or target outside the closed lists, repeats an id, or opens a second
    record for a ``(kind, target)`` that is already open, is skipped and counted in
    :attr:`corrupt_lines`; so is a torn final line. Every valid record is honoured.
    Loading never raises because of the file's contents.

    **Threading.** One lock around every method. The current :meth:`recording` context is
    an attribute of the journal, not of a thread: enforcement is serialized by the
    service, and entering a second recording while one is active raises.

    **Failures.** A write that fails raises :class:`StoreError`; because the enforcer is
    told before it writes, the operating-system change is then not made. Reads never
    raise.

    Args:
        path: the journal file (created owner-only on first write).
        clock: timestamps for new records.
        read_only: never write the file (a watch-only process, DESIGN 14.28): every
            write raises :class:`StoreError` and compaction does nothing, so lines this
            version cannot parse stay for a PortLock that can.
    """

    def __init__(
        self, path: str | os.PathLike[str], *, clock: Clock, read_only: bool = False
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._read_only = read_only is True
        self._lock = threading.Lock()
        # Open records by id, oldest first (dicts keep insertion order).
        self._open: dict[str, JournalRecord] = {}
        self._by_key: dict[tuple[str, str], str] = {}
        self._seen_ids: set[str] = set()
        self._closed_since_compaction = 0
        self._corrupt = 0
        self._needs_newline = False
        self._recording: _Recording | None = None
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def read_only(self) -> bool:
        """True if this handle never writes the file."""
        return self._read_only

    @property
    def corrupt_lines(self) -> int:
        """Lines skipped while loading because they were torn, malformed or invalid."""
        with self._lock:
            return self._corrupt

    def open_records(
        self, *, scope: str | None = None, actions: Collection[Action] | None = None
    ) -> list[JournalRecord]:
        """Open records, newest first, optionally only of one scope or some actions."""
        with self._lock:
            return [
                record
                for record in reversed(self._open.values())
                if (scope is None or record.scope == scope)
                and (actions is None or record.action in actions)
            ]

    def has_open(
        self, *, scope: str | None = None, actions: Collection[Action] | None = None
    ) -> bool:
        return bool(self.open_records(scope=scope, actions=actions))

    @contextmanager
    def recording(self, *, scope: str, action: Action, fingerprint: str | None) -> Iterator[None]:
        """Bracket one enforcement call so :meth:`write_ahead` knows what it is for."""
        _check_scope(scope)
        action = Action(action)
        if fingerprint is not None and not _FINGERPRINT_PATTERN.match(fingerprint):
            raise StoreError(f"not a fingerprint: {fingerprint!r}")
        with self._lock:
            if self._recording is not None:
                raise StoreError("a journal recording is already active")
            self._recording = _Recording(scope, action, fingerprint)
        try:
            yield
        finally:
            with self._lock:
                self._recording = None

    def write_ahead(self, entry: JournalEntry) -> None:
        """The hook handed to enforcers: journal ``entry`` before the change is made.

        Raises:
            StoreError: outside :meth:`recording`, for an entry that fails
                :func:`check_journal_entry`, or if the record cannot be written. The
                enforcer must then not make the change.
        """
        with self._lock:
            recording = self._require_recording()
            self._check_entry(entry)
            if (entry.kind, entry.target) in self._by_key:
                return
            if recording.action in RESTRICTING or entry.previous is None:
                record = self._new_record(recording, entry)
                self._append_locked([record.to_json()])
                self._add_open_locked(record)
                recording.opened.add(record.id)

    def record(self, result: EnforcementResult) -> None:
        """Settle the journal after an enforcer returned, inside :meth:`recording`.

        Closes each open record whose target ``result.undo`` returned to its baseline,
        opens records for changes an enforcer without the write-ahead hook made, and
        closes records written ahead for changes that did not happen.
        """
        with self._lock:
            recording = self._require_recording()
            for entry in result.undo:
                self._check_entry(entry)
            undone = {(entry.kind, entry.target) for entry in result.undo}
            # Record id -> why it closes. Insertion order is the order of the close lines.
            to_close: dict[str, str] = {}
            to_open: list[JournalRecord] = []
            for entry in result.undo:
                key = (entry.kind, entry.target)
                record_id = self._by_key.get(key)
                if record_id is not None:
                    baseline = self._open[record_id].entry
                    if baseline is not None and entry.applied == baseline.previous:
                        to_close[record_id] = "returned to baseline"
                elif (recording.action in RESTRICTING or entry.previous is None) and all(
                    record.key != key for record in to_open
                ):
                    to_open.append(self._new_record(recording, entry))
            for record_id in recording.opened:
                record = self._open.get(record_id)
                if record is not None and record.key not in undone:
                    # Written ahead, but the enforcer reports no such change (E3).
                    to_close[record_id] = "not applied"
            if not to_open and not to_close:
                return
            now = utc_iso(self._clock.now())
            lines = [record.to_json() for record in to_open]
            lines.extend(
                {"op": "close", "id": record_id, "ts": now, "reason": reason}
                for record_id, reason in to_close.items()
            )
            self._append_locked(lines)
            for record in to_open:
                self._add_open_locked(record)
            for record_id in to_close:
                self._remove_open_locked(record_id)
            self._maybe_compact_locked()

    def add_hold(self, *, scope: str, fingerprint: str | None) -> JournalRecord:
        """Record that the device at ``scope`` is held blocked by the service.

        Returns the existing hold if that scope already has one.
        """
        _check_scope(scope)
        if scope == GLOBAL_SCOPE:
            raise StoreError("a hold is about one device, not the global scope")
        if fingerprint is not None and not _FINGERPRINT_PATTERN.match(fingerprint):
            raise StoreError(f"not a fingerprint: {fingerprint!r}")
        with self._lock:
            for record in self._open.values():
                if record.is_hold and record.scope == scope:
                    return record
            record = JournalRecord(
                id=self._new_id(),
                ts=self._clock.now(),
                scope=scope,
                action=Action.BLOCK,
                fingerprint=fingerprint,
                entry=None,
            )
            self._append_locked([record.to_json()])
            self._add_open_locked(record)
            return record

    def close(self, ids: Iterable[str], *, reason: str) -> None:
        """Close open records. Unknown or already closed ids are ignored."""
        if not isinstance(reason, str) or not reason or len(reason) > _MAX_SCOPE:
            raise StoreError("a close reason is a non-empty string of at most 512 characters")
        with self._lock:
            wanted = [record_id for record_id in dict.fromkeys(ids) if record_id in self._open]
            if not wanted:
                return
            now = utc_iso(self._clock.now())
            self._append_locked(
                [{"op": "close", "id": rid, "ts": now, "reason": reason} for rid in wanted]
            )
            for record_id in wanted:
                self._remove_open_locked(record_id)
            self._maybe_compact_locked()

    def discard_volatile(self, scope: str, *, reason: str) -> list[JournalRecord]:
        """Close the records of ``scope`` that the OS forgot when the device left."""
        with self._lock:
            records = [
                record
                for record in self._open.values()
                if record.scope == scope
                and (record.entry is None or record.entry.kind in VOLATILE_KINDS)
            ]
        self.close((record.id for record in records), reason=reason)
        return records

    def compact(self) -> None:
        """Rewrite the file with only the open records (atomically)."""
        with self._lock:
            self._compact_locked()

    # --- internals -------------------------------------------------------------------

    def _require_recording(self) -> _Recording:
        if self._recording is None:
            raise StoreError("journal writes must happen inside recording()")
        return self._recording

    def _check_entry(self, entry: JournalEntry) -> None:
        if not isinstance(entry, JournalEntry):
            raise StoreError("expected a JournalEntry")
        try:
            check_journal_entry(entry)
        except ValueError as exc:
            raise StoreError(f"refusing to journal an invalid entry: {exc}") from exc

    def _new_id(self) -> str:
        while True:
            candidate = secrets.token_hex(8)
            if candidate not in self._seen_ids:
                return candidate

    def _new_record(self, recording: _Recording, entry: JournalEntry) -> JournalRecord:
        scope = GLOBAL_SCOPE if entry.kind in GLOBAL_KINDS else recording.scope
        return JournalRecord(
            id=self._new_id(),
            ts=self._clock.now(),
            scope=scope,
            action=recording.action,
            fingerprint=None if scope == GLOBAL_SCOPE else recording.fingerprint,
            entry=entry,
        )

    def _add_open_locked(self, record: JournalRecord) -> None:
        self._open[record.id] = record
        self._seen_ids.add(record.id)
        if record.key is not None:
            self._by_key[record.key] = record.id

    def _remove_open_locked(self, record_id: str) -> None:
        record = self._open.pop(record_id, None)
        if record is None:
            return
        if record.key is not None and self._by_key.get(record.key) == record_id:
            del self._by_key[record.key]
        self._closed_since_compaction += 1

    def _append_locked(self, records: Sequence[Mapping[str, Any]]) -> None:
        if self._read_only:
            raise StoreError(f"the enforcement journal {self._path} is read-only here")
        data = b"".join(canonicalize(record).encode("utf-8") + b"\n" for record in records)
        if self._needs_newline:
            data = b"\n" + data
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, flags, 0o600)
            try:
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise StoreError(f"cannot write the enforcement journal {self._path}: {exc}") from exc
        self._needs_newline = False

    def _maybe_compact_locked(self) -> None:
        if self._closed_since_compaction > _COMPACT_AFTER_CLOSED or (
            not self._open and self._closed_since_compaction
        ):
            try:
                self._compact_locked()
            except StoreError as exc:
                # The append-only file is still complete and correct; only longer.
                _LOG.warning("journal compaction failed: %s", exc)

    def _compact_locked(self) -> None:
        if self._read_only:
            return
        data = b"".join(
            canonicalize(record.to_json()).encode("utf-8") + b"\n" for record in self._open.values()
        )
        try:
            if not data and not self._path.exists():
                return
            atomic_write_bytes(self._path, data)
        except OSError as exc:
            raise StoreError(f"cannot compact the enforcement journal: {exc}") from exc
        self._closed_since_compaction = 0
        self._needs_newline = False
        self._seen_ids = set(self._open)

    def _load(self) -> None:
        try:
            stream = open(self._path, "rb")  # noqa: SIM115 - closed below
        except FileNotFoundError:
            return
        except OSError as exc:
            _LOG.error("cannot read the enforcement journal %s: %s", self._path, exc)
            self._corrupt += 1
            return
        with stream:
            while True:
                try:
                    line = stream.readline(_MAX_LINE_BYTES + 1)
                except OSError as exc:
                    _LOG.error("reading the enforcement journal failed: %s", exc)
                    self._corrupt += 1
                    return
                if not line:
                    return
                if not line.endswith(b"\n"):
                    if len(line) > _MAX_LINE_BYTES:
                        # An over-long line: skip the rest of it.
                        while line and not line.endswith(b"\n"):
                            line = stream.readline(_MAX_LINE_BYTES + 1)
                        self._corrupt += 1
                        if not line:
                            self._needs_newline = True
                            return
                        continue
                    # A torn final line: the write that made it never completed.
                    self._corrupt += 1
                    self._needs_newline = True
                    return
                self._replay_line(line[:-1])

    def _replay_line(self, raw: bytes) -> None:
        try:
            op, value = _parse_line(raw)
        except (CanonicalError, ValueError, TypeError, KeyError) as exc:
            _LOG.warning("skipping an invalid journal line: %s", exc)
            self._corrupt += 1
            return
        if op == "close":
            record_id = str(value)
            if record_id in self._open:
                self._remove_open_locked(record_id)
            return
        record: JournalRecord = value
        if record.id in self._seen_ids or (record.key is not None and record.key in self._by_key):
            # A repeated id, or a second baseline for a target that already has one:
            # the journal rule says this cannot have been written by PortLock.
            _LOG.warning("skipping journal record %s: it duplicates an open record", record.id)
            self._corrupt += 1
            return
        self._add_open_locked(record)


def _check_scope(scope: Any) -> None:
    if not isinstance(scope, str) or not scope or len(scope) > _MAX_SCOPE or _has_control(scope):
        raise StoreError("a journal scope is a non-empty string without control characters")


def _parse_line(raw: bytes) -> tuple[str, Any]:
    """Validate one journal line. Returns ``("close", id)`` or ``(op, JournalRecord)``."""
    data = parse_canonical(raw)
    if not isinstance(data, dict):
        raise ValueError("a journal line must be an object")
    op = data.get("op")
    expected = {"open": _OPEN_KEYS, "hold": _HOLD_KEYS, "close": _CLOSE_KEYS}.get(op)
    if expected is None or set(data) != expected:
        raise ValueError(f"unexpected fields for a {op!r} record")
    record_id = data["id"]
    if not isinstance(record_id, str) or not _RECORD_ID_PATTERN.match(record_id):
        raise ValueError("invalid record id")
    ts = parse_utc_iso(data["ts"])
    if op == "close":
        reason = data["reason"]
        if not isinstance(reason, str) or len(reason) > _MAX_SCOPE:
            raise ValueError("invalid close reason")
        return "close", record_id
    scope = data["scope"]
    if not isinstance(scope, str) or not scope or len(scope) > _MAX_SCOPE or _has_control(scope):
        raise ValueError("invalid scope")
    action = Action(data["action"])
    fingerprint = data["fp"]
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.match(fingerprint)
    ):
        raise ValueError("invalid fingerprint")
    if op == "hold":
        if action is not Action.BLOCK or scope == GLOBAL_SCOPE:
            raise ValueError("a hold blocks one device")
        return "hold", JournalRecord(record_id, ts, scope, action, fingerprint, None)
    if action not in _JOURNALED_ACTIONS:
        raise ValueError(f"{action.value!r} does not write journal records")
    raw_entry = data["entry"]
    if not isinstance(raw_entry, dict) or set(raw_entry) != _ENTRY_KEYS:
        raise ValueError("invalid entry")
    for name in ("kind", "target"):
        if not isinstance(raw_entry[name], str):
            raise ValueError(f"entry {name} must be a string")
    entry = JournalEntry.from_dict(raw_entry)
    for name in ("previous", "applied"):
        if raw_entry[name] is not None and not isinstance(raw_entry[name], str):
            raise ValueError(f"entry {name} must be a string or null")
    check_journal_entry(entry)
    if entry.kind in GLOBAL_KINDS and scope != GLOBAL_SCOPE:
        raise ValueError("a global kind must have the global scope")
    return "open", JournalRecord(record_id, ts, scope, action, fingerprint, entry)
