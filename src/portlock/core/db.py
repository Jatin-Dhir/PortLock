"""SQLite plumbing shared by every PortLock store.

One :class:`Database` wraps one connection. The connection is shared between threads
(the device monitor, the API server and timers all write) and guarded by a re-entrant
lock, so callers never see ``database is locked`` from inside the process. A separate
process, such as the CLI while the service runs, opens its own :class:`Database` on the
same file; write-ahead logging and a busy timeout make that safe.

Each component (audit, auth, grants, ...) owns its tables and registers its own ordered
list of migrations under its own name, so components evolve independently.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from portlock.core.errors import StoreError

__all__ = ["Database"]

_COMPONENT_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")

_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    component  TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    applied_at TEXT    NOT NULL,
    PRIMARY KEY (component, version)
)
"""


class Database:
    """A thread-safe handle on one SQLite database.

    Args:
        path: database file. ``None`` gives a private in-memory database (tests).
        read_only: open without the ability to write; the file must already exist.
    """

    def __init__(
        self, path: str | os.PathLike[str] | None = None, *, read_only: bool = False
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._read_only = read_only
        self._lock = threading.RLock()
        self._depth = 0
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
            if not read_only:
                # FULL: a committed audit record survives power loss.
                self._conn.execute("PRAGMA synchronous = FULL")
                if self._path is not None:
                    self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute(_MIGRATIONS_TABLE)
        except sqlite3.Error as exc:
            self._conn.close()
            raise StoreError(f"cannot initialise database {self._path}: {exc}") from exc

    @property
    def path(self) -> Path | None:
        """The database file, or ``None`` for an in-memory database."""
        return self._path

    @property
    def read_only(self) -> bool:
        return self._read_only

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Cursor:
        """Run one statement. Outside :meth:`transaction` it commits immediately."""
        with self._lock:
            try:
                return self._conn.execute(sql, params)
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def query(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        """Run a query and return every row."""
        with self._lock:
            try:
                return self._conn.execute(sql, params).fetchall()
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    def query_one(
        self, sql: str, params: Sequence[Any] | dict[str, Any] = ()
    ) -> sqlite3.Row | None:
        """Run a query and return the first row, or ``None``."""
        with self._lock:
            try:
                return self._conn.execute(sql, params).fetchone()
            except sqlite3.Error as exc:
                raise StoreError(f"database error: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[Database]:
        """Group statements so they all commit or all roll back.

        Holds the lock for the duration, so a read-then-write inside the block cannot be
        interleaved with another thread. Nesting is allowed; an inner block that raises
        rolls back only its own work.
        """
        with self._lock:
            outermost = self._depth == 0
            savepoint = f"portlock_sp_{self._depth}"
            try:
                self._conn.execute("BEGIN IMMEDIATE" if outermost else f"SAVEPOINT {savepoint}")
            except sqlite3.Error as exc:
                raise StoreError(f"cannot begin transaction: {exc}") from exc
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                if outermost:
                    self._conn.execute("ROLLBACK")
                else:
                    self._conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self._conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                self._depth -= 1
                try:
                    self._conn.execute("COMMIT" if outermost else f"RELEASE SAVEPOINT {savepoint}")
                except sqlite3.Error as exc:
                    if outermost:
                        self._conn.execute("ROLLBACK")
                    raise StoreError(f"cannot commit transaction: {exc}") from exc

    def migrate(self, component: str, migrations: Sequence[str]) -> int:
        """Bring one component's tables up to date.

        ``migrations[i]`` is the SQL (one or more statements) that takes the component
        from version ``i`` to ``i + 1``. Each migration runs in its own transaction.
        Published migrations must never be edited or reordered; append new ones.

        Returns:
            The component's schema version after migrating.

        Raises:
            StoreError: if the database is newer than this code, or a migration fails.
        """
        if not _COMPONENT_PATTERN.match(component):
            raise StoreError(f"invalid component name: {component!r}")
        with self._lock:
            row = self.query_one(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                " WHERE component = ?",
                (component,),
            )
            current = int(row["version"]) if row is not None else 0
            if current > len(migrations):
                raise StoreError(
                    f"the {component} tables are at version {current}, but this version of "
                    f"PortLock only knows version {len(migrations)}; upgrade PortLock"
                )
            for version in range(current + 1, len(migrations) + 1):
                try:
                    with self.transaction():
                        for statement in _split_statements(migrations[version - 1]):
                            self._conn.execute(statement)
                        self._conn.execute(
                            "INSERT INTO schema_migrations (component, version, applied_at)"
                            " VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                            (component, version),
                        )
                except sqlite3.Error as exc:
                    raise StoreError(f"migration {version} of {component} failed: {exc}") from exc
            return len(migrations)

    def schema_version(self, component: str) -> int:
        """The applied schema version of a component (0 if it has no tables yet)."""
        row = self.query_one(
            "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
            " WHERE component = ?",
            (component,),
        )
        return int(row["version"]) if row is not None else 0

    def close(self) -> None:
        """Close the connection. Safe to call more than once."""
        with self._lock, suppress(sqlite3.Error):
            self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


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
