"""The tamper-evident audit log.

An append-only SQLite table in which every record carries the hash of the one before it:

    hash = SHA-256( bytes.fromhex(prev_hash)
                    || canonical_json({"seq", "ts", "event_type", "severity",
                                       "actor", "device_fp", "data"}) )

The first record's ``prev_hash`` is :data:`GENESIS_HASH`, SHA-256 of
``b"portlock-audit-v1"``. Canonical JSON is :mod:`portlock.core.canonical`, so the bytes
are reproducible in any language and floats can never be stored.

**What the chain gives.** Editing, deleting, inserting or reordering a past record breaks
every later hash, and :meth:`AuditLog.verify` reports the first record that does not fit.
Anyone holding a later ``(seq, hash)`` pair (:meth:`AuditLog.head`,
:meth:`AuditLog.checkpoint`) can also detect truncation and wholesale replacement.

**What the chain alone does not give.** Someone who can rewrite the whole database can
rebuild a consistent chain. Three mitigations follow (``docs/DESIGN.md`` sections 10 and
14.22); none is free.

Forward-secure MACs
-------------------

With an :class:`AuditKeyStore`, record ``i`` also carries a MAC under a key that changes
with every record::

    mac_i   = HMAC-SHA256(k_i, bytes.fromhex(hash_i))
    k_(i+1) = SHA-256(b"portlock-audit-ratchet" || k_i)

The key store is one small owner-only file that holds the key for the *next* record and
nothing else. When record ``i`` has been committed, ``k_(i+1)`` replaces ``k_i`` in that
file (written to a temporary file and renamed over it) and PortLock keeps ``k_i`` nowhere.
The initial key ``k_0`` is returned once, by :meth:`AuditKeyStore.create`, as an
:class:`AuditKey` for the administrator to keep offline; it is never written to disk.
``AuditLog.verify(initial_key=...)`` re-derives every key from it and checks every MAC.

What the MACs protect against:

* Someone who takes over the machine later (root, a copied disk) and reads the current
  key. SHA-256 cannot be run backwards, so the keys of records already written cannot be
  computed from it: every earlier record they modify, delete, insert or reorder fails
  verification with ``k_0``, even after they rebuild the hash chain around it.
* Someone who can write the database but cannot read the key file: they cannot produce a
  valid MAC for any record.

What they do not protect against:

* Records written after the key was taken: the holder of the current key can forge
  those, and can append records that verify.
* Truncation. Dropping the newest records leaves a prefix whose MACs all verify. The
  head file below and checkpoints kept off the machine exist for that.
* Anyone holding ``k_0``: they can forge the whole log. Keep it offline.
* The running service cannot check past MACs by itself (it only holds the next key):
  ``verify()`` without ``initial_key`` checks the chain only.
* A short window after each commit: if the process dies between committing record ``i``
  and replacing the key file, ``k_i`` stays in the file until the next append, so record
  ``i`` alone can be re-MACed by whoever reads the file meanwhile. Two processes
  appending at the same moment can likewise leave a key one or two records old in the
  file until the next append; the keys are derived, never stored, so nothing breaks.
* Physical remanence. "Discarded" means no file holds the old key any more. Copy-on-write
  and journaling filesystems and SSD wear levelling can keep old blocks readable to
  someone with raw disk access, and Python cannot wipe bytes it once held in memory.
* ``append`` inside a caller's own ``db.transaction()``: the key file is advanced when
  ``append`` returns, so a caller who then rolls back leaves the key store ahead of the
  log, and further appends are refused (``audit_key_ahead``) until a new key store is
  created. Do not append inside a transaction you might roll back.

The head file
-------------

With ``head_path``, ``{"seq", "hash"}`` of the newest record is written to a separate
small file (atomically, owner-only) after every append, and :meth:`AuditLog.verify`
compares the log with it. A database that ends before that record (truncated, or an old
copy put back) or holds a different record there (replaced) fails verification, and so
does a key store that has moved past the end of the log. This protects against a
database replaced or truncated by anything that does not also rewrite the head file: a
restored backup, a damaged file, a writer who can reach the database but not the state
directory. It does not protect against someone who rewrites both; only checkpoints
exported off the machine do (:meth:`AuditLog.checkpoint`, signed with
:mod:`portlock.audit.signing`, and the external sinks of :mod:`portlock.audit.sinks`).

Starting again after damage
---------------------------

:meth:`AuditLog.start_fresh` begins a new log in a new database after a damaged one was
moved aside (``docs/DESIGN.md`` section 14.23). Its first record, ``store.recovered``,
names the SHA-256 of the damaged file and its last known head, so the two logs stay
linked and the damaged file can later be shown to be the one that was set aside.

Triggers
--------

The table also carries SQL triggers that refuse ``UPDATE``, ``DELETE`` and any ``INSERT``
that is not the next sequence number. That is defence in depth against bugs and casual
edits only: an attacker with write access to the database file can drop the triggers, or
edit the file directly. Detection rests on the chain, not on the triggers.

**Secrets are never logged.** No password, session token, recovery code or key material
may be passed as audit data. As a safety net, :meth:`AuditLog.append` runs every ``data``
through :func:`redact` with :data:`DEFAULT_SECRET_KEYS`, which replaces the values of
secret-bearing keys; callers logging anything unusual should call :func:`redact`
themselves with their own key list. Redaction is by key name, so a secret placed under
an innocent key, or inside a free-text message, is *not* caught: do not put it there.

There is deliberately no import: records enter the log only through
:meth:`AuditLog.append`, with the sequence number, time and hashes assigned here.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import heapq
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import IO, TYPE_CHECKING, Any, TypeVar

from portlock.audit.events import (
    DEFAULT_SECRET_KEYS,
    MAX_EVENT_TYPE_LENGTH,
    REGISTRY,
    STORE_RECOVERED,
    AuditError,
    EventRegistry,
    coerce_severity,
    redact,
)
from portlock.core.canonical import canonical_bytes, canonicalize, parse_canonical
from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.db import Database
from portlock.core.errors import CanonicalError, StoreError
from portlock.core.fsutil import atomic_write_bytes, ensure_private_dir, exclusive_lock
from portlock.core.models import Severity

if TYPE_CHECKING:
    from portlock.audit.sinks import AuditSink

__all__ = [
    "DEFAULT_SECRET_KEYS",
    "GENESIS_HASH",
    "MAC_KEY_BYTES",
    "MAX_DATA_BYTES",
    "MAX_QUERY_LIMIT",
    "RATCHET_DOMAIN",
    "AuditError",
    "AuditKey",
    "AuditKeyStore",
    "AuditLog",
    "AuditRecord",
    "FreshLog",
    "VerifyResult",
    "ratchet_key",
    "read_head_file",
    "record_hash",
    "record_mac",
    "redact",
]

#: ``prev_hash`` of the first record.
GENESIS_HASH = hashlib.sha256(b"portlock-audit-v1").hexdigest()

#: Largest canonical encoding of one record's ``data``.
MAX_DATA_BYTES = 64 * 1024

#: Most records one :meth:`AuditLog.query` or :meth:`AuditLog.tail` returns.
MAX_QUERY_LIMIT = 1000

#: Domain separator of the MAC key ratchet: ``k_(i+1) = SHA-256(RATCHET_DOMAIN || k_i)``.
RATCHET_DOMAIN = b"portlock-audit-ratchet"

#: Length of every MAC key, ``k_0`` included.
MAC_KEY_BYTES = 32

# SQLite stores ``seq`` as a signed 64-bit integer. A larger number can never name a
# record, and binding one raises OverflowError instead of a database error, so every
# sequence number that comes from a caller is checked against this first.
_MAX_SEQ = 2**63 - 1
# A key store this far behind the log was not left behind by a crash or a slow writer
# (those leave it one or two records behind); deriving forward that far is refused.
_MAX_RATCHET_STEPS = 1_000_000
# The key store and the head file are a few dozen bytes; anything larger is not ours.
_STATE_FILE_LIMIT = 4096
_STATE_FORMAT = 1
_KEY_TEXT_PREFIX = "plak1"
_KEY_HEX_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_KEY_TEXT_PATTERN = re.compile(r"plak1-(0|[1-9][0-9]{0,18})-([0-9a-f]{64})\Z")
_HASH_CHUNK = 1024 * 1024
# Windows sharing violations on the state files last as long as another process takes
# to read or rename a few dozen bytes; this bounds the wait at about a second.
_SHARING_RETRIES = 100
_SHARING_RETRY_SECONDS = 0.01

_T = TypeVar("_T")
_MAX_LABEL_LENGTH = 256
_MAX_TEXT_LENGTH = 256
_MAX_EVENT_TYPE_FILTERS = 64
_BATCH = 500

_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_TS_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
# No C0 controls, DEL or C1 controls in the indexed labels: they are shown in terminals
# and written to syslog headers.
_LABEL_PATTERN = re.compile(r"[^\x00-\x1f\x7f-\x9f]+\Z")
_TYPE_PREFIX_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\Z")

# Statement text is assembled only from these constants and fixed fragments; every value
# is bound as a parameter.
_SELECT = (
    "SELECT seq, ts, event_type, severity, actor, device_fp, data, prev_hash, hash, mac"
    " FROM audit_log"
)
_SELECT_TAIL = "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
_TEXT_CLAUSE = (
    "(event_type LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\'"
    " OR device_fp LIKE ? ESCAPE '\\' OR data LIKE ? ESCAPE '\\')"
)
_INSERT = (
    "INSERT INTO audit_log"
    " (seq, ts, event_type, severity, actor, device_fp, data, prev_hash, hash, mac)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

# Published migrations are never edited; append new ones.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE audit_log (
        seq        INTEGER PRIMARY KEY CHECK (seq >= 1),
        ts         TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity   TEXT NOT NULL,
        actor      TEXT,
        device_fp  TEXT,
        data       TEXT NOT NULL,
        prev_hash  TEXT NOT NULL CHECK (length(prev_hash) = 64),
        hash       TEXT NOT NULL CHECK (length(hash) = 64),
        mac        TEXT CHECK (mac IS NULL OR length(mac) = 64)
    );
    CREATE INDEX audit_log_ts ON audit_log (ts);
    CREATE INDEX audit_log_event_type ON audit_log (event_type, seq);
    CREATE INDEX audit_log_device_fp ON audit_log (device_fp, seq)
        WHERE device_fp IS NOT NULL;
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE refused');
    END;
    CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: DELETE refused');
    END;
    CREATE TRIGGER audit_log_next_seq_only BEFORE INSERT ON audit_log
    WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log)
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: INSERT out of sequence refused');
    END;
    """,
)


def record_hash(
    prev_hash: str,
    *,
    seq: int,
    ts: str,
    event_type: str,
    severity: str,
    actor: str | None,
    device_fp: str | None,
    data: Mapping[str, Any],
) -> str:
    """Compute the chain hash of one record, as lowercase hex.

    This is the whole definition of the chain; an independent verifier needs nothing
    else.

    Args:
        prev_hash: the previous record's hash (:data:`GENESIS_HASH` for record 1).
        seq, ts, event_type, severity, actor, device_fp, data: the record's contents.

    Raises:
        AuditError: if ``prev_hash`` is not 64 lowercase hex characters, or the contents
            cannot be written as canonical JSON.
    """
    if not isinstance(prev_hash, str) or not _HASH_PATTERN.match(prev_hash):
        raise AuditError("prev_hash must be 64 lowercase hexadecimal characters")
    body = {
        "seq": seq,
        "ts": ts,
        "event_type": event_type,
        "severity": severity,
        "actor": actor,
        "device_fp": device_fp,
        "data": dict(data),
    }
    try:
        encoded = canonical_bytes(body)
    except CanonicalError as exc:
        raise AuditError(f"the record cannot be written as canonical JSON: {exc}") from exc
    return hashlib.sha256(bytes.fromhex(prev_hash) + encoded).hexdigest()


def record_mac(hmac_key: bytes, record_hash_hex: str) -> str:
    """Compute a record's MAC, HMAC-SHA256 over the raw hash bytes, as lowercase hex.

    Raises:
        AuditError: if the hash is not 64 lowercase hex characters.
    """
    if not isinstance(record_hash_hex, str) or not _HASH_PATTERN.match(record_hash_hex):
        raise AuditError("hash must be 64 lowercase hexadecimal characters")
    return hmac.new(hmac_key, bytes.fromhex(record_hash_hex), hashlib.sha256).hexdigest()


def ratchet_key(key: bytes, steps: int = 1) -> bytes:
    """Move a MAC key forward: ``k_(i+1) = SHA-256(RATCHET_DOMAIN || k_i)``, ``steps`` times.

    One-way: nothing about ``k_i`` can be computed from ``k_(i+1)``.

    Raises:
        AuditError: if the key is not :data:`MAC_KEY_BYTES` bytes or ``steps`` is negative.
    """
    if not isinstance(key, bytes | bytearray) or len(key) != MAC_KEY_BYTES:
        raise AuditError(f"a MAC key is exactly {MAC_KEY_BYTES} bytes")
    if not _is_int(steps) or steps < 0:
        raise AuditError("steps must be a non-negative integer")
    current = bytes(key)
    for _ in range(steps):
        current = hashlib.sha256(RATCHET_DOMAIN + current).digest()
    return current


@dataclass(frozen=True, slots=True)
class AuditKey:
    """The initial MAC key ``k_0`` of a key store and the record it is anchored at.

    ``k_0`` belongs to record ``anchor_seq``: record ``anchor_seq + j`` is MACed with
    ``k_j``, which is ``k_0`` ratcheted ``j`` times. For a log keyed from its first record
    the anchor is 0, so record ``i`` uses ``k_i``. Records up to the anchor were written
    before the key existed and carry no MAC.

    Whoever holds this can forge MACs for the whole log: keep it offline. ``repr`` never
    shows the key; :meth:`encode` is the one way to get it as text.

    Attributes:
        anchor_seq: the record ``k_0`` belongs to (the log's head when the key was made).
        key: ``k_0``, :data:`MAC_KEY_BYTES` bytes.

    Raises:
        AuditError: if either value is malformed.
    """

    anchor_seq: int
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _is_int(self.anchor_seq) or not 0 <= self.anchor_seq < _MAX_SEQ:
            raise AuditError(f"anchor_seq must be an integer from 0 to {_MAX_SEQ - 1}")
        if not isinstance(self.key, bytes | bytearray) or len(self.key) != MAC_KEY_BYTES:
            raise AuditError(f"a MAC key is exactly {MAC_KEY_BYTES} bytes")
        object.__setattr__(self, "key", bytes(self.key))

    def key_for(self, seq: int) -> bytes:
        """The MAC key of record ``seq``, which must come after the anchor.

        Raises:
            AuditError: if ``seq`` is malformed or not after the anchor.
        """
        steps = _check_seq("seq", seq) - self.anchor_seq
        if steps < 1:
            raise AuditError(f"record {seq} is not after the key's anchor, {self.anchor_seq}")
        return ratchet_key(self.key, steps)

    def encode(self) -> str:
        """The key as text to write down or store offline: ``plak1-<anchor>-<64 hex>``."""
        return f"{_KEY_TEXT_PREFIX}-{self.anchor_seq}-{self.key.hex()}"

    @classmethod
    def parse(cls, text: str) -> AuditKey:
        """Read the form written by :meth:`encode`. Surrounding whitespace is ignored.

        Raises:
            AuditError: if the text is not exactly that form.
        """
        match = _KEY_TEXT_PATTERN.match(text.strip()) if isinstance(text, str) else None
        if match is None:
            raise AuditError("not an audit key: expected plak1-<anchor>-<64 hex digits>")
        return cls(int(match.group(1)), bytes.fromhex(match.group(2)))


def _read_state_file(path: Path, what: str, *, forbidden_mode: int) -> bytes | None:
    """Read a small state file; ``None`` if it does not exist.

    Refuses anything but a regular file (a symbolic link could point anywhere) and, on
    POSIX, a file whose mode grants any of ``forbidden_mode``. Windows permissions come
    from the state directory's access control list.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditError(f"cannot read the {what} {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise AuditError(f"the {what} {path.name} is not a regular file")
    if sys.platform != "win32" and info.st_mode & forbidden_mode:
        raise AuditError(
            f"the {what} {path.name} is accessible to other users "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); it must be 0600"
        )
    try:
        data = _retry_sharing_violation(lambda: _read_bounded(path))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditError(f"cannot read the {what} {path.name}: {exc}") from exc
    if len(data) > _STATE_FILE_LIMIT:
        raise AuditError(f"the {what} {path.name} is too large to be one")
    return data


def _read_bounded(path: Path) -> bytes:
    with open(path, "rb") as stream:
        return stream.read(_STATE_FILE_LIMIT + 1)


def _write_state(path: Path, data: bytes) -> None:
    """Replace a state file atomically, owner-only."""
    _retry_sharing_violation(lambda: atomic_write_bytes(path, data, private=True))


def _retry_sharing_violation(operation: Callable[[], _T]) -> _T:
    """Run a file operation, retrying briefly while Windows reports a sharing violation.

    On Windows, renaming a file over one that another process has open, or opening one
    that is being renamed over, fails with a permission error for the moment the other
    side holds it. Writers in several processes (the service and the CLI) meet that
    routinely here, and the files are tiny, so a short retry resolves it. Anywhere else,
    and once the retries are spent, the error is raised.
    """
    retries = _SHARING_RETRIES if sys.platform == "win32" else 0
    for _ in range(retries):
        try:
            return operation()
        except PermissionError:
            time.sleep(_SHARING_RETRY_SECONDS)
    return operation()


def _parse_state(data: bytes, what: str, members: frozenset[str]) -> dict[str, Any]:
    """Parse a state file: canonical JSON with exactly ``members`` and format version 1."""
    try:
        value = parse_canonical(data)
    except CanonicalError as exc:
        raise AuditError(f"the {what} is not in the stored format: {exc}") from exc
    if (
        not isinstance(value, dict)
        or set(value) != members
        or not _is_int(value["v"])
        or value["v"] != _STATE_FORMAT
    ):
        raise AuditError(f"the {what} is not in the stored format")
    return value


_KEY_MEMBERS = frozenset({"key", "seq", "v"})
_HEAD_MEMBERS = frozenset({"hash", "seq", "v"})


def _encode_key_state(seq: int, key: bytes) -> bytes:
    return canonical_bytes({"key": key.hex(), "seq": seq, "v": _STATE_FORMAT})


def _publish_new(path: Path, data: bytes, what: str) -> None:
    """Create ``path`` holding ``data``, owner-only, failing if it already exists."""
    if not path.parent.exists():
        ensure_private_dir(path.parent)
    staging = path.with_name(f".{path.name}.{secrets.token_hex(8)}.new")
    try:
        # Complete, flushed and owner-only before it can be seen under its real name.
        atomic_write_bytes(staging, data, private=True)
        try:
            # A hard link creates the name or fails because it exists, so a live key
            # store is never replaced, even by two creators racing each other.
            os.link(staging, path)
        except FileExistsError:
            raise AuditError(f"the {what} {path.name} already exists") from None
        except OSError:
            # No hard links on this filesystem: check, then rename.
            if os.path.lexists(path):
                raise AuditError(f"the {what} {path.name} already exists") from None
            os.replace(staging, path)
    except OSError as exc:
        raise AuditError(f"cannot create the {what} {path.name}: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(staging)


class AuditKeyStore:
    """The current audit MAC key, in one owner-only file, ratcheted after every record.

    The file holds ``{"key": <64 hex>, "seq": n, "v": 1}`` in canonical JSON: the key for
    record ``n``, the next one to be written. It may lag a record or two behind the log
    (see the module documentation); the key for a later record is then derived from it.
    It is never allowed to be ahead.

    Several :class:`AuditLog` objects, in one process or several, may share one key
    store path as long as they write to the same log. Thread-safe.

    Args:
        path: the key store file. It must already exist: see :meth:`create`.

    Raises:
        AuditError: if the file is missing, not a regular owner-only file, or malformed.
    """

    _WHAT = "audit MAC key store"

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._read()  # Fail now, not at the first append.

    @classmethod
    def create(
        cls, path: str | os.PathLike[str], *, anchor_seq: int = 0
    ) -> tuple[AuditKeyStore, AuditKey]:
        """Make a new key store and return it with its initial key.

        ``k_0`` is generated here and returned, never written: the file starts at
        ``k_1``, the key of record ``anchor_seq + 1``. This is the only time ``k_0``
        exists; give it to the administrator to keep offline.

        Args:
            path: where to create the file. An existing file is never replaced.
            anchor_seq: the log's current head, so that the next record is the first
                one with a MAC (0 for a new log).

        Raises:
            AuditError: if the file exists or cannot be created, or ``anchor_seq`` is
                malformed.
        """
        initial = AuditKey(anchor_seq, secrets.token_bytes(MAC_KEY_BYTES))
        first = anchor_seq + 1
        _publish_new(Path(path), _encode_key_state(first, initial.key_for(first)), cls._WHAT)
        return cls(path), initial

    @property
    def path(self) -> Path:
        """The key store file."""
        return self._path

    @property
    def position(self) -> int:
        """The record the stored key belongs to: the next record, or slightly before it.

        Raises:
            AuditError: if the file cannot be read or is malformed.
        """
        return self._read()[0]

    def key_for(self, seq: int) -> bytes:
        """The MAC key of record ``seq``, derived forward from the stored key.

        Raises:
            AuditError: ``audit_key_ahead`` if the store has already moved past ``seq``
                (the log lost records, or the store belongs to another log);
                ``audit_key_behind`` if it is implausibly far behind; or the file is
                unreadable.
        """
        position, key = self._read()
        if position > seq:
            raise AuditError(
                f"the audit MAC key store is at record {position} but the next record is "
                f"{seq}: records were removed from the log, or the key store belongs to "
                "another log. Create a new key store to resume MACs.",
                code="audit_key_ahead",
            )
        if seq - position > _MAX_RATCHET_STEPS:
            raise AuditError(
                f"the audit MAC key store is at record {position}, far behind record {seq}; "
                "it was replaced with an old copy",
                code="audit_key_behind",
            )
        return ratchet_key(key, seq - position)

    def advance_past(self, seq: int, key: bytes) -> None:
        """Replace the stored key with the one after record ``seq``'s ``key``.

        Called once record ``seq`` is committed. Does nothing if the store is already
        past ``seq`` (another writer got there first), so it never moves backwards
        because of this process.

        Raises:
            AuditError: if the file is unreadable or malformed.
            OSError: if the new file cannot be written.
        """
        with self._lock:
            position, _ = self._read()
            if position > seq:
                return
            _write_state(self._path, _encode_key_state(seq + 1, ratchet_key(key)))

    def _read(self) -> tuple[int, bytes]:
        data = _read_state_file(self._path, self._WHAT, forbidden_mode=0o077)
        if data is None:
            raise AuditError(f"the {self._WHAT} {self._path.name} does not exist")
        state = _parse_state(data, self._WHAT, _KEY_MEMBERS)
        seq, key = state["seq"], state["key"]
        if not _is_int(seq) or seq < 1 or not isinstance(key, str):
            raise AuditError(f"the {self._WHAT} is not in the stored format")
        if not _KEY_HEX_PATTERN.match(key):
            raise AuditError(f"the {self._WHAT} is not in the stored format")
        return seq, bytes.fromhex(key)

    def __repr__(self) -> str:
        return f"AuditKeyStore({str(self._path)!r})"


def read_head_file(path: str | os.PathLike[str]) -> tuple[int, str] | None:
    """Read a head file written by :class:`AuditLog`: ``(seq, hash)``, or ``None`` if absent.

    Raises:
        AuditError: if the file exists but is not a regular file, is writable by other
            users (POSIX), or is malformed.
    """
    target = Path(path)
    data = _read_state_file(target, "audit head file", forbidden_mode=0o022)
    if data is None:
        return None
    state = _parse_state(data, "audit head file", _HEAD_MEMBERS)
    seq, digest = state["seq"], state["hash"]
    if not _is_int(seq) or seq < 1 or not isinstance(digest, str):
        raise AuditError("the audit head file is not in the stored format")
    if not _HASH_PATTERN.match(digest):
        raise AuditError("the audit head file is not in the stored format")
    return seq, digest


def _remove_state_file(path: Path, what: str) -> None:
    """Delete a key store or head file if it exists."""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AuditError(f"cannot remove the {what} {path.name}: {exc}") from exc


def _file_sha256(path: Path) -> tuple[str, int]:
    """SHA-256 and size of a regular file, read in bounded chunks."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise AuditError(f"{path.name} is not a regular file")
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as stream:
            while chunk := stream.read(_HASH_CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise AuditError(f"cannot read {path.name}: {exc}") from exc
    return digest.hexdigest(), size


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One stored audit record.

    Attributes:
        seq: position in the log, starting at 1 with no gaps.
        ts: when it was recorded, ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` (UTC, fixed width).
        event_type: a catalogue event type (:mod:`portlock.audit.events`).
        severity: the event's severity.
        actor: who caused it (a user name, ``system``), if anyone.
        device_fp: the fingerprint of the device it concerns, if any.
        data: event details: a read-only JSON object, already redacted.
        prev_hash: the hash of record ``seq - 1``.
        hash: this record's chain hash.
        mac: HMAC of ``hash``, if the log had a key when the record was written.
    """

    seq: int
    ts: str
    event_type: str
    severity: Severity
    actor: str | None
    device_fp: str | None
    data: Mapping[str, Any] = field(hash=False)
    prev_hash: str
    hash: str
    mac: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))

    @property
    def timestamp(self) -> datetime:
        """``ts`` as an aware UTC datetime."""
        return parse_utc_iso(self.ts)

    def to_dict(self) -> dict[str, Any]:
        """The record as plain JSON types. This is what exports and file sinks write."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "actor": self.actor,
            "device_fp": self.device_fp,
            "data": copy.deepcopy(dict(self.data)),
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "mac": self.mac,
        }


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """The outcome of walking the chain.

    Attributes:
        ok: True if every record examined fits and the expected head, if given, matched.
        checked: how many records were verified before stopping.
        first_bad_seq: the first sequence number that does not fit; for a missing record
            this is the number that should have been there. ``None`` when ``ok``.
        reason: what is wrong with it, for the operator. ``None`` when ``ok``.
        macs_checked: how many MACs were verified. Zero when no initial key was given,
            which means a rebuilt chain would *not* have been noticed by this run.
        head: ``(seq, hash)`` of the last record that verified, or ``None`` if none did.
        head_checked: True if the log was compared with its head file and matched.
            False when the log keeps no head file, is empty, or did not verify.
    """

    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
    macs_checked: int = 0
    head: tuple[int, str] | None = None
    head_checked: bool = False


@dataclass(frozen=True, slots=True)
class FreshLog:
    """What :meth:`AuditLog.start_fresh` made.

    Attributes:
        log: the new log, ready for appends.
        record: its first record, ``store.recovered``.
        initial_key: the new key store's ``k_0`` (keep it offline), or ``None`` when the
            new log has no key store.
    """

    log: AuditLog
    record: AuditRecord
    initial_key: AuditKey | None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_label(name: str, value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= _MAX_LABEL_LENGTH
        or not _LABEL_PATTERN.match(value)
    ):
        raise AuditError(
            f"{name} must be 1 to {_MAX_LABEL_LENGTH} characters with no control characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditError(f"{name} must be well-formed Unicode") from exc
    return value


def _check_seq(name: str, value: object, *, least: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= _MAX_SEQ:
        raise AuditError(f"{name} must be an integer from {least} to {_MAX_SEQ}")
    return value


def _check_seq_bound(name: str, value: object) -> int | None:
    return None if value is None else _check_seq(name, value, least=0)


def _check_time_bound(name: str, value: object) -> str | None:
    if value is None:
        return None
    try:
        if isinstance(value, datetime):
            return utc_iso(value)
        if isinstance(value, str):
            # Re-format so the comparison string has the stored fixed width.
            return utc_iso(parse_utc_iso(value))
    except ValueError as exc:
        raise AuditError(f"{name}: {exc}") from exc
    raise AuditError(f"{name} must be an aware datetime or a UTC timestamp string")


def _like_pattern(needle: str) -> str:
    escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class AuditLog:
    """The hash-chained audit log stored in one SQLite table.

    Thread-safe. Several ``AuditLog`` objects, in this process or another, may share one
    database file: each append reads the tail and inserts inside one ``BEGIN IMMEDIATE``
    transaction, so the chain cannot fork.

    Args:
        db: the database. Its ``audit_log`` table is created or migrated here.
        clock: the time source for record timestamps.
        key_store: the forward-secure MAC key store, or ``None`` for a log without
            MACs. With one, every appended record gets a MAC under the current key and
            the key is ratcheted forward once the record is committed. Records written
            through it can only be checked with its initial key (:meth:`verify`).
        head_path: the head file, or ``None`` for none. When given, the newest record's
            ``(seq, hash)`` is written there after every append and :meth:`verify`
            compares the log with it.
        registry: the event types accepted (default: the strict process-wide
            :data:`portlock.audit.events.REGISTRY`).
        sink: where each committed record is forwarded, usually a
            :class:`portlock.audit.sinks.FanOut`. Records reach it in sequence order.
            A sink that raises is counted (:attr:`sink_failures`) and never disturbs
            the append.

    Raises:
        AuditError: if ``key_store`` is not an :class:`AuditKeyStore`.
        StoreError: if the table cannot be created or is from a newer PortLock.
    """

    def __init__(
        self,
        db: Database,
        *,
        clock: Clock,
        key_store: AuditKeyStore | None = None,
        head_path: str | os.PathLike[str] | None = None,
        registry: EventRegistry | None = None,
        sink: AuditSink | None = None,
    ) -> None:
        if key_store is not None and not isinstance(key_store, AuditKeyStore):
            raise AuditError("key_store must be an AuditKeyStore")
        self._db = db
        self._clock = clock
        self._key_store = key_store
        self._head_path = Path(head_path) if head_path is not None else None
        self._registry = registry if registry is not None else REGISTRY
        self._sink = sink
        # Orders this process's updates of the key store and the head file, which
        # happen after the commit and therefore outside the database lock.
        self._state_lock = threading.Lock()
        self._state_failures = 0
        # Ordered hand-off to the sink without holding any lock while the sink runs:
        # sequence numbers are claimed under the database lock, become ready once their
        # transaction has committed, and one thread at a time drains them in order.
        self._emit_lock = threading.Lock()
        self._in_flight: set[int] = set()
        self._ready: list[tuple[int, AuditRecord]] = []
        self._emitting = False
        self._sink_failures = 0
        db.migrate("audit", _MIGRATIONS)

    @property
    def keyed(self) -> bool:
        """True if this log writes MACs (it has a key store)."""
        return self._key_store is not None

    @property
    def head_path(self) -> Path | None:
        """The head file, if this log keeps one."""
        return self._head_path

    @property
    def sink_failures(self) -> int:
        """How many times the configured sink raised instead of accepting a record."""
        return self._sink_failures

    @property
    def state_failures(self) -> int:
        """How many times the key store or the head file could not be updated after a commit.

        The record itself was committed each time. A key store left behind is moved
        forward by the next append, but until then it still holds a key that can re-MAC
        the newest records, so a non-zero count deserves an alert.
        """
        return self._state_failures

    # --- writing ---------------------------------------------------------------------

    def append(
        self,
        event_type: str,
        severity: Severity | str | None = None,
        *,
        actor: str | None = None,
        device_fp: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> AuditRecord:
        """Add one record to the end of the chain and return it.

        Reading the tail and inserting happen in one transaction, so concurrent callers
        (threads, or other processes with their own database handle) each get the next
        sequence number and the chain never forks.

        If this is called inside a caller's own ``db.transaction()`` the record becomes
        part of that transaction, but it is handed to the sink, the key store is
        ratcheted and the head file written at once: do not append inside a transaction
        you might roll back (see the module documentation).

        With a key store the record's MAC uses the key for its sequence number; once the
        record is committed the key store moves on to the next key. A failure to update
        the key store or the head file after the commit does not undo the record; it is
        counted in :attr:`state_failures`.

        Args:
            event_type: a registered event type (:mod:`portlock.audit.events`).
            severity: overrides the catalogue default for this event type.
            actor: who caused the event, if anyone.
            device_fp: the fingerprint of the device concerned, if any.
            data: event details: a JSON object of strings, integers, booleans, nulls,
                arrays and objects with ASCII keys. No floats. At most
                :data:`MAX_DATA_BYTES` once encoded. Values under secret-bearing keys
                are replaced (see the module docstring); never pass secrets at all.

        Raises:
            AuditError: if the event type is unknown or anything is malformed or too
                large, the stored tail is corrupt (``code == "audit_corrupt"``), or the
                key store is unusable (``audit_key_ahead``, ``audit_key_behind``, or
                unreadable).
            StoreError: if the database cannot be written.
        """
        name, level = self._registry.resolve(event_type, severity)
        actor = _check_label("actor", actor)
        device_fp = _check_label("device_fp", device_fp)
        clean, data_text = _prepare_data(data)

        mac_key: bytes | None = None
        claimed: int | None = None
        try:
            with self._db.transaction():
                tail = self._db.query_one(_SELECT_TAIL)
                if tail is None:
                    seq, prev_hash = 1, GENESIS_HASH
                else:
                    seq, prev_hash = int(tail["seq"]) + 1, tail["hash"]
                    if not isinstance(prev_hash, str) or not _HASH_PATTERN.match(prev_hash):
                        raise AuditError(
                            f"audit record {seq - 1} has a malformed hash: the log is corrupt "
                            "and cannot be extended; run 'portlock audit verify'",
                            code="audit_corrupt",
                        )
                # Read the clock inside the transaction so timestamps follow sequence order.
                ts = utc_iso(self._clock.now())
                digest = record_hash(
                    prev_hash,
                    seq=seq,
                    ts=ts,
                    event_type=name,
                    severity=level.value,
                    actor=actor,
                    device_fp=device_fp,
                    data=clean,
                )
                if self._key_store is not None:
                    mac_key = self._key_store.key_for(seq)
                mac = record_mac(mac_key, digest) if mac_key is not None else None
                self._db.execute(
                    _INSERT,
                    (
                        seq,
                        ts,
                        name,
                        level.value,
                        actor,
                        device_fp,
                        data_text,
                        prev_hash,
                        digest,
                        mac,
                    ),
                )
                if self._sink is not None:
                    with self._emit_lock:
                        self._in_flight.add(seq)
                    claimed = seq
        except BaseException:
            if claimed is not None:
                with self._emit_lock:
                    self._in_flight.discard(claimed)
                self._drain()
            raise

        self._after_commit(seq, digest, mac_key)
        record = AuditRecord(seq, ts, name, level, actor, device_fp, clean, prev_hash, digest, mac)
        if claimed is not None:
            with self._emit_lock:
                self._in_flight.discard(claimed)
                heapq.heappush(self._ready, (seq, record))
            self._drain()
        return record

    def _after_commit(self, seq: int, digest: str, mac_key: bytes | None) -> None:
        """Ratchet the key store past record ``seq`` and record it in the head file.

        Runs after the commit, so a failure here cannot lose the record; it is counted
        instead. Each file only ever moves forward: a writer that finds it already past
        ``seq`` leaves it alone.
        """
        if self._key_store is None and self._head_path is None:
            return
        with self._state_lock, contextlib.ExitStack() as guard:
            if self._head_path is not None:
                # The lock above is per AuditLog. Two logs on one database (the service
                # and the command line, say) each compare and then write, so the one that
                # appended the older record could write last and leave the files a record
                # behind. A lock shared through the filesystem makes compare-and-write
                # atomic for all of them. If it cannot be taken the write still happens:
                # a state file that is briefly stale is better than none.
                lock_path = self._head_path.with_name(self._head_path.name + ".lock")
                try:
                    guard.enter_context(exclusive_lock(lock_path))
                except OSError:
                    self._state_failures += 1
            if self._key_store is not None and mac_key is not None:
                try:
                    self._key_store.advance_past(seq, mac_key)
                except (OSError, AuditError):
                    self._state_failures += 1
            if self._head_path is not None:
                try:
                    current = read_head_file(self._head_path)
                    if current is None or current[0] < seq:
                        _write_state(
                            self._head_path,
                            canonical_bytes({"hash": digest, "seq": seq, "v": _STATE_FORMAT}),
                        )
                except (OSError, AuditError):
                    # A malformed head file is left as it is for verify() to report.
                    self._state_failures += 1

    def _drain(self) -> None:
        """Hand committed records to the sink in sequence order, one thread at a time."""
        sink = self._sink
        if sink is None:
            return
        while True:
            with self._emit_lock:
                if self._emitting or not self._ready:
                    return
                # A lower sequence number is still committing on another thread; that
                # thread drains when it finishes, so order is kept without waiting here.
                if self._in_flight and min(self._in_flight) < self._ready[0][0]:
                    return
                _, record = heapq.heappop(self._ready)
                self._emitting = True
            try:
                sink.emit(record)
            except Exception:
                # A sink must never break auditing; the record is safely in the database.
                with self._emit_lock:
                    self._sink_failures += 1
            finally:
                with self._emit_lock:
                    self._emitting = False

    # --- reading ---------------------------------------------------------------------

    def get(self, seq: int) -> AuditRecord | None:
        """Return record ``seq``, or ``None`` if there is no such record.

        Raises:
            AuditError: if ``seq`` is not an integer, or the stored record is corrupt.
        """
        if not _is_int(seq):
            raise AuditError("seq must be an integer")
        if not 1 <= seq <= _MAX_SEQ:
            return None
        row = self._db.query_one(_SELECT + " WHERE seq = ?", (seq,))
        return _record_from_row(row) if row is not None else None

    def count(self) -> int:
        """The number of records in the log."""
        row = self._db.query_one("SELECT COUNT(*) AS n FROM audit_log")
        return int(row["n"]) if row is not None else 0

    def newest_timestamp(self) -> datetime | None:
        """The latest ``ts`` of any record, ``None`` for an empty log.

        This is the highest *time*, not the time of the last record: after the clock was
        set back, records written later carry earlier times. Expiries are judged against
        this value (DESIGN 14.12), so it is what a restart must learn.

        Raises:
            AuditError: if a stored timestamp is malformed (``code == "audit_corrupt"``).
        """
        row = self._db.query_one("SELECT MAX(ts) AS ts FROM audit_log")
        if row is None or row["ts"] is None:
            return None
        try:
            return parse_utc_iso(str(row["ts"]))
        except ValueError as exc:
            raise AuditError(
                "the newest audit timestamp is malformed", code="audit_corrupt"
            ) from exc

    def head(self) -> tuple[int, str]:
        """``(seq, hash)`` of the newest record; ``(0, GENESIS_HASH)`` for an empty log.

        Keep this pair somewhere the log's owner cannot rewrite it and pass it to
        :meth:`verify` later to detect truncation and wholesale replacement.

        Raises:
            AuditError: if the stored hash is malformed (``code == "audit_corrupt"``).
        """
        row = self._db.query_one(_SELECT_TAIL)
        if row is None:
            return 0, GENESIS_HASH
        return int(row["seq"]), _stored_hash(row["seq"], row["hash"])

    def tail(self, n: int = 20) -> list[AuditRecord]:
        """The newest ``n`` records, oldest first (at most :data:`MAX_QUERY_LIMIT`).

        Raises:
            AuditError: if ``n`` is not a positive integer, or a record is corrupt.
        """
        return self.query(limit=n, descending=True)[::-1]

    def query(
        self,
        *,
        since_seq: int | None = None,
        until_seq: int | None = None,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        event_types: Collection[str] | str | None = None,
        min_severity: Severity | str | None = None,
        device_fp: str | None = None,
        actor: str | None = None,
        text: str | None = None,
        limit: int = 100,
        descending: bool = True,
    ) -> list[AuditRecord]:
        """Search the log. All filters must hold; every value is bound as a parameter.

        Args:
            since_seq, until_seq: sequence-number bounds, both inclusive.
            since, until: time bounds as aware datetimes or UTC timestamp strings;
                ``since`` is inclusive and ``until`` exclusive, so consecutive windows
                do not overlap.
            event_types: event types to include. An entry ending in ``.*`` matches a
                whole area, e.g. ``auth.*``. An empty collection matches nothing.
            min_severity: the least severity to include.
            device_fp: exact device fingerprint.
            actor: exact actor.
            text: a substring to look for in the event type, actor, fingerprint and
                ``data``. ASCII letters match without regard to case. ``data`` is
                searched as its stored JSON text, so the match also sees key names,
                numbers and punctuation: it is a filter for people, not an exact test.
            limit: the most records to return, at least 1; values above
                :data:`MAX_QUERY_LIMIT` are capped there. Page with the sequence bounds.
            descending: newest first if True, oldest first otherwise.

        Raises:
            AuditError: if a filter is malformed, or a matching record is corrupt.
            StoreError: if the database cannot be read.
        """
        if not _is_int(limit) or limit < 1:
            raise AuditError("limit must be a positive integer")
        where: list[str] = []
        params: list[Any] = []

        for column, operator, value in (
            ("seq", ">=", _check_seq_bound("since_seq", since_seq)),
            ("seq", "<=", _check_seq_bound("until_seq", until_seq)),
            ("ts", ">=", _check_time_bound("since", since)),
            ("ts", "<", _check_time_bound("until", until)),
            ("device_fp", "=", _check_label("device_fp", device_fp)),
            ("actor", "=", _check_label("actor", actor)),
        ):
            if value is not None:
                where.append(f"{column} {operator} ?")
                params.append(value)

        if event_types is not None:
            clause, values = _event_type_filter(event_types)
            if clause is None:
                return []
            where.append(clause)
            params.extend(values)

        if min_severity is not None:
            floor = coerce_severity(min_severity)
            if floor.rank > 0:
                wanted = [level.value for level in Severity if level.rank >= floor.rank]
                where.append(f"severity IN ({', '.join('?' * len(wanted))})")
                params.extend(wanted)

        if text is not None:
            if not isinstance(text, str) or not 0 < len(text) <= _MAX_TEXT_LENGTH:
                raise AuditError(f"text must be 1 to {_MAX_TEXT_LENGTH} characters")
            try:
                text.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AuditError("text must be well-formed Unicode") from exc
            # ``data`` is stored as JSON text, where quotes, backslashes and control
            # characters are escaped, so the needle is escaped the same way for that
            # column. (Looking for the raw needle there would let a lone backslash
            # match every escape sequence.)
            plain = _like_pattern(text)
            as_json = _like_pattern(json.dumps(text, ensure_ascii=False)[1:-1])
            where.append(_TEXT_CLAUSE)
            params.extend((plain, plain, plain, as_json))

        sql = (
            _SELECT
            + (" WHERE " + " AND ".join(where) if where else "")
            + (" ORDER BY seq DESC LIMIT ?" if descending else " ORDER BY seq ASC LIMIT ?")
        )
        params.append(min(limit, MAX_QUERY_LIMIT))
        return [_record_from_row(row) for row in self._db.query(sql, params)]

    def iterate(self, *, since_seq: int = 1) -> Iterator[AuditRecord]:
        """Yield records from ``since_seq`` onward, oldest first, in bounded batches.

        Raises:
            AuditError: if ``since_seq`` is malformed, or a record is corrupt.
            StoreError: if the database cannot be read.
        """
        for row in self._rows(_check_seq("since_seq", since_seq)):
            yield _record_from_row(row)

    def _rows(self, since_seq: int) -> Iterator[sqlite3.Row]:
        """Stream raw rows in sequence order without holding the whole log in memory."""
        after = since_seq - 1
        size = _BATCH
        while True:
            try:
                batch = self._db.query(
                    _SELECT + " WHERE seq > ? ORDER BY seq LIMIT ?", (after, size)
                )
            except StoreError:
                if size == 1:
                    raise
                # One unreadable row spoils its whole batch. Step through one at a time
                # so every readable row before it is still delivered, and the error is
                # raised exactly at the row that causes it.
                size = 1
                continue
            if not batch:
                return
            yield from batch
            after = int(batch[-1]["seq"])

    def _first_seq_after(self, after: int) -> int | None:
        """The lowest sequence number above ``after``, read without touching text columns."""
        try:
            row = self._db.query_one(
                "SELECT seq FROM audit_log WHERE seq > ? ORDER BY seq LIMIT 1", (after,)
            )
        except StoreError:
            return None
        return int(row["seq"]) if row is not None else None

    # --- verification ----------------------------------------------------------------

    def verify(
        self,
        *,
        start_seq: int = 1,
        expected_head: tuple[int, str] | None = None,
        initial_key: AuditKey | None = None,
    ) -> VerifyResult:
        """Walk the chain and report the first record that does not fit.

        Every hash is recomputed from the stored contents. Detected: a modified field, a
        deleted or inserted record (a gap or a broken link), reordered records, and a
        truncated tail or a replaced log when ``expected_head`` is given or the log has a
        head file. With ``initial_key``, every record after its anchor must carry a MAC
        under the key re-derived for it, which also detects a chain rebuilt by anyone
        who did not hold the key of every record they changed: in particular by someone
        holding only a later key.

        The log is read in batches, never as a whole, and corrupt or unreadable data is
        *reported*, never raised.

        This method records nothing. The caller logs ``audit.verified`` or
        ``audit.verification_failed`` with the result.

        Args:
            start_seq: the first record to check. When greater than 1, the record before
                it must exist and is trusted as the anchor.
            expected_head: a ``(seq, hash)`` pair saved earlier from :meth:`head` or
                :meth:`checkpoint`. The log must still contain exactly that record.
            initial_key: the ``k_0`` returned when the key store was created. Without
                it no MAC is checked.

        Raises:
            AuditError: only for malformed arguments, never for what is in the log.
        """
        _check_seq("start_seq", start_seq)
        if expected_head is not None and (
            not isinstance(expected_head, tuple)
            or len(expected_head) != 2
            or not _is_int(expected_head[0])
            or not 0 <= expected_head[0] <= _MAX_SEQ
            or not isinstance(expected_head[1], str)
            or not _HASH_PATTERN.match(expected_head[1])
        ):
            raise AuditError("expected_head must be (seq, 64 lowercase hex characters)")
        if initial_key is not None and not isinstance(initial_key, AuditKey):
            raise AuditError("initial_key must be an AuditKey")
        try:
            return self._verify(start_seq, expected_head, initial_key)
        except StoreError as exc:
            return VerifyResult(False, 0, None, f"the audit log could not be read: {exc}")

    def _verify(
        self,
        start_seq: int,
        expected_head: tuple[int, str] | None,
        initial_key: AuditKey | None,
    ) -> VerifyResult:
        checked = macs_checked = 0
        head: tuple[int, str] | None = None

        def fail(seq: int | None, reason: str) -> VerifyResult:
            return VerifyResult(False, checked, seq, reason, macs_checked, head)

        # The first record that must carry a MAC, and the key it must carry it under.
        first_keyed = _MAX_SEQ
        mac_key: bytes | None = None
        if initial_key is not None:
            first_keyed = max(start_seq, initial_key.anchor_seq + 1)
            mac_key = initial_key.key_for(first_keyed)

        if expected_head is not None and expected_head[0] == 0:
            if expected_head[1] != GENESIS_HASH:
                return fail(None, "the expected head names record 0 but not the genesis hash")
            expected_head = None  # Every log extends the empty one.

        if start_seq == 1:
            prev_hash = GENESIS_HASH
        else:
            anchor = self._db.query_one(
                "SELECT hash FROM audit_log WHERE seq = ?", (start_seq - 1,)
            )
            if anchor is None:
                return fail(start_seq - 1, f"record {start_seq - 1} is missing")
            prev_hash = anchor["hash"]
            if not isinstance(prev_hash, str) or not _HASH_PATTERN.match(prev_hash):
                return fail(start_seq - 1, f"record {start_seq - 1} has a malformed hash")

        if expected_head is not None and expected_head[0] < start_seq:
            # Outside the walk: compare that one record directly.
            pinned = self._db.query_one(
                "SELECT hash FROM audit_log WHERE seq = ?", (expected_head[0],)
            )
            if pinned is None:
                return fail(expected_head[0], f"record {expected_head[0]} is missing")
            if pinned["hash"] != expected_head[1]:
                return fail(
                    expected_head[0],
                    f"record {expected_head[0]} does not have the expected hash: "
                    "the log was rewritten",
                )

        expected_seq = start_seq
        rows = self._rows(start_seq)
        while True:
            try:
                row = next(rows, None)
            except StoreError as exc:
                unreadable = self._first_seq_after(expected_seq - 1)
                if unreadable is None:
                    return fail(None, f"the audit log could not be read: {exc}")
                return fail(unreadable, f"record {unreadable} cannot be read: {exc}")
            if row is None:
                break
            seq = int(row["seq"])
            if seq != expected_seq:
                return fail(
                    expected_seq,
                    f"record {expected_seq} is missing (the next record present is {seq})",
                )
            problem = _row_problem(row)
            if problem is not None:
                return fail(seq, f"record {seq} is malformed: {problem}")
            if row["prev_hash"] != prev_hash:
                return fail(
                    seq,
                    f"record {seq} does not link to record {seq - 1}: "
                    "a record was altered, removed, inserted or reordered",
                )
            try:
                data = parse_canonical(row["data"])
                if not isinstance(data, dict):
                    raise CanonicalError("data is not an object")
                digest = record_hash(
                    prev_hash,
                    seq=seq,
                    ts=row["ts"],
                    event_type=row["event_type"],
                    severity=row["severity"],
                    actor=row["actor"],
                    device_fp=row["device_fp"],
                    data=data,
                )
            except (CanonicalError, AuditError) as exc:
                return fail(seq, f"record {seq} is malformed: {exc}")
            if not hmac.compare_digest(digest, row["hash"]):
                return fail(seq, f"record {seq} was altered: its hash does not match its contents")
            if mac_key is not None and seq >= first_keyed:
                if row["mac"] is None:
                    return fail(
                        seq, f"record {seq} has no MAC although the log is keyed from {first_keyed}"
                    )
                if not hmac.compare_digest(record_mac(mac_key, digest), row["mac"]):
                    return fail(
                        seq,
                        f"record {seq} has a MAC that does not match: it was altered or "
                        "re-chained by someone without its key, or the wrong initial key "
                        "was given",
                    )
                macs_checked += 1
                mac_key = ratchet_key(mac_key)
            if expected_head is not None and seq == expected_head[0] and digest != expected_head[1]:
                return fail(
                    seq, f"record {seq} does not have the expected hash: the log was rewritten"
                )
            checked += 1
            head = (seq, digest)
            prev_hash = digest
            expected_seq += 1

        if expected_head is not None and expected_head[0] >= expected_seq:
            return fail(
                expected_seq,
                f"the log ends at record {expected_seq - 1} but record {expected_head[0]} "
                "was expected: the tail was truncated",
            )
        problem = self._state_problem()
        if problem is not None:
            return fail(*problem)
        head_checked = self._head_path is not None and checked + start_seq > 1
        return VerifyResult(True, checked, None, None, macs_checked, head, head_checked)

    def _state_problem(self) -> tuple[int | None, str] | None:
        """Compare the log with its head file and its key store; say what does not fit.

        Both files are read *before* the end of the log, and each is written only after
        the record it names was committed. A record appended by someone else while this
        runs can therefore never look like a missing one. An empty log with no head file
        yet is consistent.
        """
        pinned: tuple[int, str] | None = None
        position: int | None = None
        if self._head_path is not None:
            try:
                pinned = read_head_file(self._head_path)
            except AuditError as exc:
                return None, f"the head file cannot be used: {exc}"
        if self._key_store is not None:
            try:
                position = self._key_store.position
            except AuditError as exc:
                return None, f"the MAC key store cannot be used: {exc}"
        tail = self._db.query_one(_SELECT_TAIL)
        last = int(tail["seq"]) if tail is not None else 0

        if self._head_path is not None:
            if pinned is None:
                if last > 0:
                    return None, (
                        "the head file is missing although the log has records: it was "
                        "deleted, or the database was replaced"
                    )
            elif pinned[0] > last:
                return last + 1, (
                    f"the log ends at record {last} but the head file names record "
                    f"{pinned[0]}: records were removed, or the database was replaced by "
                    "an older copy"
                )
            else:
                row = self._db.query_one("SELECT hash FROM audit_log WHERE seq = ?", (pinned[0],))
                if row is None or row["hash"] != pinned[1]:
                    return pinned[0], (
                        f"record {pinned[0]} does not match the head file: the log was "
                        "rewritten or replaced"
                    )
        if position is not None and position > last + 1:
            return last + 1, (
                f"the MAC key store has moved on to record {position} but the log ends at "
                f"record {last}: records were removed, or the database was replaced"
            )
        return None

    # --- starting again after damage -------------------------------------------------

    @classmethod
    def start_fresh(
        cls,
        db: Database,
        *,
        clock: Clock,
        damaged_path: str | os.PathLike[str],
        key_store_path: str | os.PathLike[str] | None = None,
        head_path: str | os.PathLike[str] | None = None,
        last_known_head: tuple[int, str] | None = None,
        reason: str | None = None,
        registry: EventRegistry | None = None,
        sink: AuditSink | None = None,
    ) -> FreshLog:
        """Begin a new log after a damaged database was moved aside (DESIGN.md 14.23).

        The new log's first record is ``store.recovered``. Its data names the damaged
        file (``damaged_file``, the name only), its SHA-256 and size
        (``damaged_sha256``, ``damaged_bytes``), and its last known head
        (``last_known_head``: ``{"seq", "hash"}`` or ``null``), with ``head_source``
        saying where that head came from: ``caller``, ``head_file``,
        ``head_file_unreadable`` or ``none``. Only the main database file is hashed;
        SQLite's ``-wal`` and ``-shm`` companions, if any, are the caller's to keep.

        Moving the damaged file aside (never deleting it) is the caller's job; this
        reads it and nothing else.

        Args:
            db: the new database. Its audit log must be empty.
            clock: the time source.
            damaged_path: the damaged database file, already renamed aside.
            key_store_path: where the new log keeps its MAC key store. A key store left
                there by the damaged log is removed first: it only held the damaged
                log's next key, which can verify nothing. A new ``k_0`` is generated and
                returned in the result.
            head_path: the head file. If ``last_known_head`` is not given, the head
                file still describes the damaged log and is read for it; the new log
                then takes it over.
            last_known_head: the damaged log's ``(seq, hash)`` if the caller knows it
                better (for instance from an exported checkpoint).
            reason: a short note for the record, such as the integrity check's message.
            registry: the event types accepted (default: the strict registry).
            sink: where committed records are forwarded.

        Returns:
            The new log, its first record and the new initial key (``None`` without a
            key store).

        Raises:
            AuditError: if the new log is not empty, the damaged file cannot be read, or
                an argument is malformed.
            StoreError: if the new database cannot be written.
        """
        damaged = Path(damaged_path)
        if last_known_head is not None and (
            not isinstance(last_known_head, tuple)
            or len(last_known_head) != 2
            or not _is_int(last_known_head[0])
            or not 1 <= last_known_head[0] <= _MAX_SEQ
            or not isinstance(last_known_head[1], str)
            or not _HASH_PATTERN.match(last_known_head[1])
        ):
            raise AuditError("last_known_head must be (seq >= 1, 64 lowercase hex characters)")
        note = _check_label("reason", reason)
        probe = cls(db, clock=clock, registry=registry)
        if probe.count() != 0:
            raise AuditError("a fresh log can only be started in an empty database")
        digest, size = _file_sha256(damaged)

        source = "caller"
        known = last_known_head
        if known is None:
            source = "none"
            if head_path is not None:
                try:
                    known = read_head_file(head_path)
                except AuditError:
                    source = "head_file_unreadable"
                else:
                    source = "head_file" if known is not None else "none"

        key_store: AuditKeyStore | None = None
        initial_key: AuditKey | None = None
        if key_store_path is not None:
            _remove_state_file(Path(key_store_path), "old key store")
            key_store, initial_key = AuditKeyStore.create(key_store_path, anchor_seq=0)
        if head_path is not None:
            # The new log's first append writes the head file only if it is behind, and
            # the damaged log's head is ahead of record 1: clear it now that it is read.
            _remove_state_file(Path(head_path), "old head file")

        data: dict[str, Any] = {
            "damaged_file": damaged.name,
            "damaged_sha256": digest,
            "damaged_bytes": size,
            "last_known_head": ({"seq": known[0], "hash": known[1]} if known is not None else None),
            "head_source": source,
        }
        if note is not None:
            data["reason"] = note
        log = cls(
            db,
            clock=clock,
            key_store=key_store,
            head_path=head_path,
            registry=registry,
            sink=sink,
        )
        record = log.append(STORE_RECOVERED, actor="system", data=data)
        return FreshLog(log, record, initial_key)

    # --- export ----------------------------------------------------------------------

    def checkpoint(self) -> dict[str, Any]:
        """A snapshot of the log's head: ``{"seq", "hash", "ts", "count"}``.

        ``seq`` and ``hash`` are :meth:`head`, ``count`` the number of records, and
        ``ts`` the time the checkpoint was taken. The result is canonical-JSON-safe, so
        it can be exported as it is. Kept off the machine, it is what makes truncation
        and wholesale replacement detectable: pass ``(seq, hash)`` back to
        :meth:`verify` as ``expected_head``.

        For a *signed* checkpoint, sign the envelope of the head record,
        ``signer.sign_event(security_event_from_record(log.get(seq), host=...))``: its
        ``chain`` member is this same ``(seq, hash)``. An empty log has no record to
        sign.

        Raises:
            AuditError: if the stored head is malformed (``code == "audit_corrupt"``).
        """
        # One statement, so the three values come from one consistent snapshot.
        row = self._db.query_one(
            "SELECT (SELECT COUNT(*) FROM audit_log) AS n, seq, hash FROM audit_log"
            " ORDER BY seq DESC LIMIT 1"
        )
        ts = utc_iso(self._clock.now())
        if row is None:
            return {"seq": 0, "hash": GENESIS_HASH, "ts": ts, "count": 0}
        return {
            "seq": int(row["seq"]),
            "hash": _stored_hash(row["seq"], row["hash"]),
            "ts": ts,
            "count": int(row["n"]),
        }

    def export_jsonl(self, stream: IO[Any], *, since_seq: int = 1) -> int:
        """Write records from ``since_seq`` onward, one canonical JSON object per line.

        Each line is :meth:`AuditRecord.to_dict` in canonical JSON followed by ``\\n``.
        Canonical JSON escapes control characters, so a record never spans lines.
        Prefer a binary stream: a text stream must be UTF-8 and must not translate
        newlines.

        Args:
            stream: where to write; text streams get ``str``, anything else ``bytes``.
            since_seq: the first record to export.

        Returns:
            The number of records written.

        Raises:
            AuditError: if ``since_seq`` is malformed or a record is corrupt; records
                before the corrupt one have already been written.
            StoreError: if the database cannot be read.
        """
        as_text = isinstance(stream, io.TextIOBase)
        written = 0
        for record in self.iterate(since_seq=since_seq):
            line = canonicalize(record.to_dict()) + "\n"
            stream.write(line if as_text else line.encode("utf-8"))
            written += 1
        return written


def _prepare_data(data: Mapping[str, Any] | None) -> tuple[dict[str, Any], str]:
    """Validate, normalise and redact ``data``; return it with its canonical text."""
    if data is None:
        return {}, "{}"
    if not isinstance(data, Mapping):
        raise AuditError("data must be an object (a mapping with string keys) or None")
    try:
        # Encoding first proves the value is canonical-safe (and finite: a value that
        # contains itself hits the depth limit); decoding yields plain JSON types that
        # are safe to walk and are no longer shared with the caller.
        plain = json.loads(canonicalize(dict(data)))
        clean = redact(plain, DEFAULT_SECRET_KEYS)
        text = canonicalize(clean)
    except CanonicalError as exc:
        raise AuditError(
            f"data cannot be stored: {exc} (allowed: objects with ASCII keys, arrays, "
            "strings, integers, booleans and null; no floats)"
        ) from exc
    size = len(text.encode("utf-8"))
    if size > MAX_DATA_BYTES:
        raise AuditError(f"data is {size} bytes once encoded; the limit is {MAX_DATA_BYTES}")
    return clean, text


def _stored_hash(seq: object, value: object) -> str:
    if not isinstance(value, str) or not _HASH_PATTERN.match(value):
        raise AuditError(
            f"audit record {seq} has a malformed hash; run 'portlock audit verify'",
            code="audit_corrupt",
        )
    return value


def _row_problem(row: sqlite3.Row) -> str | None:
    """Say what is structurally wrong with a stored row, or ``None`` if nothing is."""
    for column, pattern in (
        ("ts", _TS_PATTERN),
        ("prev_hash", _HASH_PATTERN),
        ("hash", _HASH_PATTERN),
    ):
        value = row[column]
        if not isinstance(value, str) or not pattern.match(value):
            return f"{column} is not in the stored format"
    for column in ("event_type", "severity", "data"):
        if not isinstance(row[column], str):
            return f"{column} is not text"
    for column in ("actor", "device_fp"):
        if row[column] is not None and not isinstance(row[column], str):
            return f"{column} is not text"
    mac = row["mac"]
    if mac is not None and (not isinstance(mac, str) or not _HASH_PATTERN.match(mac)):
        return "mac is not in the stored format"
    return None


def _record_from_row(row: sqlite3.Row) -> AuditRecord:
    """Turn a stored row into a record, refusing one that does not parse."""
    seq = row["seq"]
    problem = _row_problem(row)
    try:
        if problem is not None:
            raise ValueError(problem)
        data = parse_canonical(row["data"])
        if not isinstance(data, dict):
            raise ValueError("data is not an object")
        severity = Severity(row["severity"])
    except (ValueError, CanonicalError) as exc:
        raise AuditError(
            f"audit record {seq} is corrupt ({exc}); run 'portlock audit verify'",
            code="audit_corrupt",
        ) from exc
    return AuditRecord(
        int(seq),
        row["ts"],
        row["event_type"],
        severity,
        row["actor"],
        row["device_fp"],
        data,
        row["prev_hash"],
        row["hash"],
        row["mac"],
    )


def _event_type_filter(event_types: Collection[str] | str) -> tuple[str | None, list[Any]]:
    """Build the WHERE fragment for an event-type filter; ``None`` if nothing can match."""
    names = [event_types] if isinstance(event_types, str) else list(event_types)
    if len(names) > _MAX_EVENT_TYPE_FILTERS:
        raise AuditError(f"at most {_MAX_EVENT_TYPE_FILTERS} event types can be filtered at once")
    exact: list[str] = []
    prefixes: list[str] = []
    for name in names:
        if not isinstance(name, str) or len(name) > MAX_EVENT_TYPE_LENGTH + 2:
            raise AuditError(f"invalid event type filter: {name!r}")
        stem = name[:-2] if name.endswith(".*") else name
        if not _TYPE_PREFIX_PATTERN.match(stem):
            raise AuditError(f"invalid event type filter: {name!r}")
        if name.endswith(".*"):
            prefixes.append(stem + ".")
        else:
            exact.append(name)
    parts: list[str] = []
    params: list[Any] = []
    if exact:
        parts.append(f"event_type IN ({', '.join('?' * len(exact))})")
        params.extend(exact)
    for prefix in prefixes:
        parts.append("substr(event_type, 1, ?) = ?")
        params.extend((len(prefix), prefix))
    if not parts:
        return None, []
    return "(" + " OR ".join(parts) + ")", params
