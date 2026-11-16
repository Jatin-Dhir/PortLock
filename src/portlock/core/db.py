"""SQLite plumbing shared by every PortLock store.

One :class:`Database` wraps one connection. The connection is shared between threads
(the device monitor, the API server and timers all write) and guarded by a re-entrant
lock, so callers never see ``database is locked`` from inside the process. A separate
process, such as the CLI while the service runs, opens its own :class:`Database` on the
same file; write-ahead logging (where the filesystem supports it) and a busy timeout make
that safe, and :meth:`Database.migrate` re-checks what another process has applied.

Each component (audit, auth, grants, ...) owns its tables and registers its own ordered
list of migrations under its own name, so components evolve independently.

No statement leaves a cursor open: :meth:`Database.execute` finishes its statement
before returning and :meth:`Database.query_one` closes its cursor after the first row,
because an unfinished read statement keeps a read transaction open, which blocks WAL
checkpoints and, without WAL, every writer in every process.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from portlock.core.errors import StoreError

__all__ = ["Database", "ExecuteResult"]

_LOG = logging.getLogger(__name__)
_COMPONENT_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
# PRAGMA quick_check reports at most this many problems; more add nothing actionable.
_MAX_CHECK_PROBLEMS = 100

_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    component  TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    applied_at TEXT    NOT NULL,
    PRIMARY KEY (component, version)
)
"""

_VERSION_QUERY = (
    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations WHERE component = ?"
)


@dataclass(frozen=True, slots=True)
class ExecuteResult:
    """What a statement run by :meth:`Database.execute` did.

    Attributes:
        rowcount: rows changed by an ``INSERT``, ``UPDATE`` or ``DELETE``; -1 otherwise.
        lastrowid: the rowid of the last row inserted, if any.
    """

    rowcount: int
    lastrowid: int | None


class Database:
    """A thread-safe handle on one SQLite database.

    Args:
        path: database file. ``None`` gives a private in-memory database (tests).
        read_only: open without the ability to write; the file must already exist.

    Raises:
        StoreError: if the database cannot be opened or initialised.
    """

    def __init__(
        self, path: str | os.PathLike[str] | None = None, *, read_only: bool = False
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._read_only = read_only
        self._lock = threading.RLock()
        self._depth = 0
        # The thread inside the outermost transaction() block, if any. Only that thread
        # can be inside it (the block holds the lock), so in_transaction compares against
        # it rather than reading _depth, which another thread's transaction also raises.
        self._transaction_thread: int | None = None
        try:
            if self._path is None:
                self._conn = sqlite3.connect(
                    ":memory:", check_same_thread=False, isolation_level=None
                )
            elif read_only:
                uri = f"{self._path.resolve().as_uri()}?mode=ro"
                self._conn = sqlite3.connect(
                    uri, uri=True, check_same_thread=False, isolation_level=None
                )
            else:
                self._conn = sqlite3.connect(
                    self._path, check_same_thread=False, isolation_level=None
                )
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open database {self._path}: {exc}") from exc
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA busy_timeout = 5000")
            self._conn.execute("PRAGMA trusted_schema = OFF")
            if read_only or self._path is None:
                self._journal_mode = self._pragma_text("PRAGMA journal_mode")
            else:
                self._journal_mode = self._enable_wal()
            if not read_only:
                # FULL: a committed audit record survives power loss.
                self._conn.execute("PRAGMA synchronous = FULL")
                self._conn.execute(_MIGRATIONS_TABLE)
        except (sqlite3.Error, StoreError) as exc:
            self._conn.close()
            raise StoreError(f"cannot initialise database {self._path}: {exc}") from exc

    def _pragma_text(self, sql: str) -> str:
        with closing(self._conn.execute(sql)) as cursor:
            row = cursor.fetchone()
        if row is None or not isinstance(row[0], str):
            raise StoreError(f"{sql} returned {row[0] if row else None!r}")
        return row[0].lower()

    def _enable_wal(self) -> str:
        mode = self._pragma_text("PRAGMA journal_mode = WAL")
        if mode != "wal":
            # SQLite answers with the mode it kept when WAL is unavailable (a network
            # share, a filesystem without shared memory). Every write is still atomic
            # and durable; readers just wait for writers. Say so rather than pretend.
            _LOG.warning(
                "write-ahead logging is unavailable for %s; using journal mode %r",
                self._path,
                mode,
            )
        return mode

    @property
    def path(self) -> Path | None:
        """The database file, or ``None`` for an in-memory database."""
        return self._path

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def journal_mode(self) -> str:
        """The journal mode SQLite actually uses, lower-case: ``wal`` for a writable
        file where the filesystem allows it, ``memory`` for an in-memory database,
        otherwise what SQLite kept (typically ``delete``)."""
        return self._journal_mode

    @property
    def in_transaction(self) -> bool:
        """True while the *calling thread* is inside a :meth:`transaction` block.

        For code that must never run inside one: an enforcement call or an
        operating-system timer can take seconds, and holding the database's write lock
        for that long stalls every other writer (``docs/ARCHITECTURE.md`` section 1.4).
        Another thread's open transaction does not count.
        """
        return self._transaction_thread == threading.get_ident()

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> ExecuteResult:
        """Run one statement to completion. Outside :meth:`transaction` it commits
        immediately.

        Any rows the statement produces are discarded and the cursor is closed before
        this returns, so no read stays open; use :meth:`query` to read.

        Raises:
            StoreError: if SQLite reports an error.
        """
        with self._lock:
            try:
                with closing(self._conn.execute(sql, params)) as cursor:
                    if cursor.description is not None:
                        cursor.fetchall()
                    return ExecuteResult(rowcount=cursor.rowcount, lastrowid=cursor.lastrowid)
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        """Run a query and return every row."""
        with self._lock:
            try:
                with closing(self._conn.execute(sql, params)) as cursor:
                    return cursor.fetchall()
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def query_one(
        self, sql: str, params: Sequence[Any] | dict[str, Any] = ()
    ) -> sqlite3.Row | None:
        """Run a query and return the first row, or ``None``. The rest are discarded."""
        with self._lock:
            try:
                with closing(self._conn.execute(sql, params)) as cursor:
                    return cursor.fetchone()
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[Database]:
        """Group statements so they all commit or all roll back.

        Holds the lock for the duration, so a read-then-write inside the block cannot be
        interleaved with another thread. The outermost block takes the write lock at
        once (``BEGIN IMMEDIATE``), so its reads see the latest committed state of every
        process. Nesting is allowed; an inner block that raises rolls back only its own
        work.

        If the block raises, the work is rolled back and *that* exception propagates.
        A rollback is attempted only while SQLite still has a transaction open (some
        errors end it themselves), and a failure of the rollback itself is logged, never
        allowed to replace the original exception.
        """
        with self._lock:
            outermost = self._depth == 0
            savepoint = f"portlock_sp_{self._depth}"
            try:
                self._conn.execute("BEGIN IMMEDIATE" if outermost else f"SAVEPOINT {savepoint}")
            except sqlite3.Error as exc:
                raise StoreError(f"cannot begin transaction: {exc}") from exc
            self._depth += 1
            if outermost:
                self._transaction_thread = threading.get_ident()
            try:
                try:
                    yield self
                except BaseException:
                    self._depth -= 1
                    self._roll_back(outermost, savepoint)
                    raise
                self._depth -= 1
                try:
                    self._conn.execute("COMMIT" if outermost else f"RELEASE SAVEPOINT {savepoint}")
                except sqlite3.Error as exc:
                    if outermost:
                        self._roll_back(outermost, savepoint)
                    raise StoreError(f"cannot commit transaction: {exc}") from exc
            finally:
                if outermost:
                    self._transaction_thread = None

    def _roll_back(self, outermost: bool, savepoint: str) -> None:
        if not self._conn.in_transaction:
            # SQLite already rolled the transaction back (for instance on a full disk or
            # an I/O error); a ROLLBACK now would only fail.
            return
        try:
            if outermost:
                self._conn.execute("ROLLBACK")
            else:
                self._conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        except sqlite3.Error as exc:
            _LOG.error("rollback failed; the original error is reported instead", exc_info=exc)

    def migrate(self, component: str, migrations: Sequence[str]) -> int:
        """Bring one component's tables up to date.

        ``migrations[i]`` is the SQL (one or more statements) that takes the component
        from version ``i`` to ``i + 1``. Each migration runs in its own transaction.
        Published migrations must never be edited or reordered; append new ones.

        Safe when several processes migrate the same file at once: the version is read
        again inside each ``BEGIN IMMEDIATE`` (which takes the write lock), so a
        migration another process has applied in the meantime is skipped, not repeated.

        Returns:
            The component's schema version after migrating.

        Raises:
            StoreError: if the database is newer than this code, or a migration fails.
        """
        if not _COMPONENT_PATTERN.match(component):
            raise StoreError(f"invalid component name: {component!r}")
        target = len(migrations)
        with self._lock:
            while True:
                version = 0
                try:
                    with self.transaction():
                        current = self._version_locked(component)
                        if current > target:
                            raise StoreError(
                                f"the {component} tables are at version {current}, but this "
                                f"version of PortLock only knows version {target}; upgrade "
                                "PortLock"
                            )
                        if current == target:
                            return target
                        version = current + 1
                        for statement in _split_statements(migrations[version - 1]):
                            self._conn.execute(statement)
                        self._conn.execute(
                            "INSERT INTO schema_migrations (component, version, applied_at)"
                            " VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                            (component, version),
                        )
                except sqlite3.Error as exc:
                    raise StoreError(f"migration {version} of {component} failed: {exc}") from exc

    def _version_locked(self, component: str) -> int:
        with closing(self._conn.execute(_VERSION_QUERY, (component,))) as cursor:
            row = cursor.fetchone()
        return int(row["version"]) if row is not None else 0

    def schema_version(self, component: str) -> int:
        """The applied schema version of a component (0 if it has no tables yet)."""
        row = self.query_one(_VERSION_QUERY, (component,))
        return int(row["version"]) if row is not None else 0

    def quick_check(self) -> list[str]:
        """Run ``PRAGMA quick_check`` and return the problems it finds.

        Returns:
            One line per problem; empty when the database is healthy. A database too
            damaged to be checked at all yields one line saying why. Never raises for
            a damaged database.
        """
        with self._lock:
            return _quick_check(self._conn)

    @staticmethod
    def check_file(path: str | os.PathLike[str]) -> list[str]:
        """Check a database file without opening it as a :class:`Database`.

        For the start-up check (``docs/DESIGN.md`` section 14.23): the file is opened
        read-only, nothing is created or changed, and a file too damaged for the
        :class:`Database` constructor is still reported rather than raising.

        Returns:
            The problems ``PRAGMA quick_check`` finds; empty when the file is healthy.

        Raises:
            StoreError: if the file does not exist (a missing database is not a damaged
                one: there is nothing to rename aside).
        """
        target = Path(path)
        if not target.is_file():
            raise StoreError(f"database file not found: {target}")
        try:
            conn = sqlite3.connect(
                f"{target.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None
            )
        except sqlite3.Error as exc:
            return [f"cannot open {target.name}: {exc}"]
        try:
            return _quick_check(conn)
        finally:
            conn.close()

    def close(self) -> None:
        """Close the connection. Safe to call more than once."""
        with self._lock, suppress(sqlite3.Error):
            self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _quick_check(conn: sqlite3.Connection) -> list[str]:
    try:
        with closing(conn.execute(f"PRAGMA quick_check({_MAX_CHECK_PROBLEMS})")) as cursor:
            lines = [str(row[0]) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        # "file is not a database", "database disk image is malformed", ...: the check
        # could not even run, which is itself the finding.
        return [f"the database cannot be checked: {exc}"]
    return [] if lines == ["ok"] else lines


def _split_statements(script: str) -> list[str]:
    """Split a migration script into statements using SQLite's own tokenizer.

    A semicolon ends a statement only where SQLite agrees the text so far is complete,
    so semicolons inside string literals, comments and trigger bodies are left alone.
    """
    statements: list[str] = []
    start = 0
    for index, char in enumerate(script):
        if char != ";":
            continue
        candidate = script[start : index + 1]
        if sqlite3.complete_statement(candidate):
            if candidate.strip(" \t\r\n;"):
                statements.append(candidate.strip())
            start = index + 1
    tail = script[start:].strip()
    if tail:
        statements.append(tail)
    return statements
