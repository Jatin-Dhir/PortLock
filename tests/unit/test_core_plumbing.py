"""Clock, database and filesystem helpers."""

from __future__ import annotations

import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import portlock.core.db as db_module
from portlock.core.clock import (
    FakeClock,
    SystemClock,
    format_duration,
    parse_duration,
    parse_utc_iso,
    utc_iso,
)
from portlock.core.db import Database, ExecuteResult
from portlock.core.errors import StoreError
from portlock.core.fsutil import atomic_write_bytes, atomic_write_text, ensure_private_dir

# --- clock ---------------------------------------------------------------------------


def test_fake_clock_only_moves_when_advanced() -> None:
    clock = FakeClock()
    start, mono = clock.now(), clock.monotonic()
    assert clock.now() == start
    clock.advance(90)
    assert clock.now() - start == timedelta(seconds=90)
    assert clock.monotonic() - mono == 90
    clock.advance(timedelta(hours=1))
    assert clock.now() - start == timedelta(hours=1, seconds=90)


def test_fake_clock_refuses_to_go_backwards_or_take_naive_times() -> None:
    clock = FakeClock()
    with pytest.raises(ValueError):
        clock.advance(-1)
    with pytest.raises(ValueError):
        clock.set(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        FakeClock(datetime(2026, 1, 1))


def test_setting_the_wall_clock_leaves_monotonic_time_alone() -> None:
    clock = FakeClock()
    mono = clock.monotonic()
    clock.set(datetime(2020, 1, 1, tzinfo=UTC))
    assert clock.now() == datetime(2020, 1, 1, tzinfo=UTC)
    assert clock.monotonic() == mono


def test_system_clock_is_utc_and_aware() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None and now.utcoffset() == timedelta(0)


def test_utc_iso_round_trips_and_sorts_chronologically() -> None:
    early = datetime(2026, 3, 1, 9, 5, 7, 123, tzinfo=UTC)
    late = early + timedelta(microseconds=1)
    assert utc_iso(early) == "2026-03-01T09:05:07.000123Z"
    assert parse_utc_iso(utc_iso(early)) == early
    assert utc_iso(early) < utc_iso(late)
    assert parse_utc_iso("2026-03-01T09:05:07Z") == datetime(2026, 3, 1, 9, 5, 7, tzinfo=UTC)


def test_utc_iso_converts_other_zones_and_rejects_naive() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    assert utc_iso(datetime(2026, 1, 1, 5, 30, tzinfo=ist)) == "2026-01-01T00:00:00.000000Z"
    with pytest.raises(ValueError):
        utc_iso(datetime(2026, 1, 1))


@pytest.mark.parametrize(
    "text", ["", "2026-01-01", "2026-01-01T00:00:00", "2026-01-01T00:00:00+00:00", "nonsense"]
)
def test_parse_utc_iso_rejects_other_formats(text: str) -> None:
    with pytest.raises(ValueError):
        parse_utc_iso(text)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("90s", 90), ("30m", 1800), ("2h", 7200), ("7d", 604800), ("1w", 604800), (" 5 M ", 300)],
)
def test_parse_duration(text: str, seconds: int) -> None:
    assert parse_duration(text) == timedelta(seconds=seconds)


@pytest.mark.parametrize("text", ["", "0m", "-5m", "5", "5x", "1.5h", "five minutes"])
def test_parse_duration_rejects_bad_input(text: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(text)


def test_format_duration() -> None:
    assert format_duration(timedelta(seconds=45)) == "45s"
    assert format_duration(timedelta(hours=2, minutes=5, seconds=9)) == "2h 5m"
    assert format_duration(timedelta(days=3)) == "3d"
    assert format_duration(timedelta(seconds=-5)) == "0s"


# --- database ------------------------------------------------------------------------

MIGRATIONS = [
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
    "ALTER TABLE notes ADD COLUMN author TEXT; CREATE INDEX notes_author ON notes (author);",
]


def test_migrations_apply_once_and_in_order(db: Database) -> None:
    assert db.schema_version("notes") == 0
    assert db.migrate("notes", MIGRATIONS[:1]) == 1
    assert db.migrate("notes", MIGRATIONS) == 2
    assert db.migrate("notes", MIGRATIONS) == 2
    db.execute("INSERT INTO notes (body, author) VALUES (?, ?)", ("hello", "ana"))
    assert db.query_one("SELECT author FROM notes")["author"] == "ana"


def test_components_migrate_independently(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    db.migrate("other", ["CREATE TABLE other_things (id INTEGER PRIMARY KEY);"])
    assert db.schema_version("notes") == 2
    assert db.schema_version("other") == 1


def test_a_failing_migration_changes_nothing(db: Database) -> None:
    with pytest.raises(StoreError):
        db.migrate("broken", ["CREATE TABLE ok_table (id INTEGER); CREATE TABLE (;"])
    assert db.schema_version("broken") == 0
    assert db.query("SELECT name FROM sqlite_master WHERE name = 'ok_table'") == []


def test_a_database_from_a_newer_version_is_refused(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    with pytest.raises(StoreError, match="upgrade PortLock"):
        db.migrate("notes", MIGRATIONS[:1])


def test_component_names_are_validated(db: Database) -> None:
    with pytest.raises(StoreError):
        db.migrate("Robert'); DROP TABLE notes;--", [])


def test_transaction_commits_together_and_rolls_back_together(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    with db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('a')")
        db.execute("INSERT INTO notes (body) VALUES ('b')")
    assert len(db.query("SELECT * FROM notes")) == 2

    with pytest.raises(RuntimeError), db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('c')")
        raise RuntimeError("boom")
    assert len(db.query("SELECT * FROM notes")) == 2


def test_nested_transaction_rolls_back_only_its_own_work(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    with db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('outer')")
        with pytest.raises(RuntimeError), db.transaction():
            db.execute("INSERT INTO notes (body) VALUES ('inner')")
            raise RuntimeError("boom")
        db.execute("INSERT INTO notes (body) VALUES ('outer again')")
    assert [row["body"] for row in db.query("SELECT body FROM notes ORDER BY id")] == [
        "outer",
        "outer again",
    ]


def test_in_transaction_is_true_only_inside_a_block_on_the_calling_thread(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    assert db.in_transaction is False
    with db.transaction():
        assert db.in_transaction is True
        with db.transaction():
            assert db.in_transaction is True
        # Leaving a nested block does not end the outer one.
        assert db.in_transaction is True
    assert db.in_transaction is False

    with pytest.raises(RuntimeError), db.transaction():
        assert db.in_transaction is True
        raise RuntimeError("boom")
    assert db.in_transaction is False

    # Another thread's open transaction is not the caller's.
    inside, release = threading.Event(), threading.Event()
    seen: list[bool] = []

    def hold() -> None:
        with db.transaction():
            seen.append(db.in_transaction)
            inside.set()
            release.wait(5)

    worker = threading.Thread(target=hold)
    worker.start()
    try:
        assert inside.wait(5)
        assert db.in_transaction is False
    finally:
        release.set()
        worker.join(5)
    assert seen == [True]
    assert db.in_transaction is False


def test_concurrent_writers_do_not_lose_updates(db: Database) -> None:
    db.execute("CREATE TABLE counter (n INTEGER NOT NULL)")
    db.execute("INSERT INTO counter VALUES (0)")

    def bump() -> None:
        for _ in range(200):
            with db.transaction():
                current = db.query_one("SELECT n FROM counter")["n"]
                db.execute("UPDATE counter SET n = ?", (current + 1,))

    threads = [threading.Thread(target=bump) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert db.query_one("SELECT n FROM counter")["n"] == 800


def test_file_database_persists_and_read_only_refuses_writes(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    with Database(path) as writer:
        writer.migrate("notes", MIGRATIONS)
        writer.execute("INSERT INTO notes (body) VALUES ('kept')")
    with Database(path, read_only=True) as reader:
        assert reader.query_one("SELECT body FROM notes")["body"] == "kept"
        with pytest.raises(StoreError):
            reader.execute("INSERT INTO notes (body) VALUES ('nope')")


def test_two_handles_on_one_file_see_each_others_commits(tmp_path: Path) -> None:
    path = tmp_path / "shared.db"
    with Database(path) as first, Database(path) as second:
        first.migrate("notes", MIGRATIONS)
        first.execute("INSERT INTO notes (body) VALUES ('from first')")
        assert second.query_one("SELECT body FROM notes")["body"] == "from first"


def test_opening_a_missing_read_only_database_fails_cleanly(tmp_path: Path) -> None:
    with pytest.raises(StoreError):
        Database(tmp_path / "absent.db", read_only=True)


# --- database: transactions that fail awkwardly ---------------------------------------


class _FailingConnection:
    """Wraps a real connection and fails chosen statements, as a sick disk would."""

    def __init__(self, real: sqlite3.Connection, failing: str) -> None:
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_failing", failing)

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if sql.startswith(self._failing):
            raise sqlite3.OperationalError(f"disk I/O error during {sql}")
        return self._real.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._real, name, value)


def test_the_original_error_survives_a_transaction_that_sqlite_already_ended(
    db: Database,
) -> None:
    db.migrate("notes", MIGRATIONS)
    with pytest.raises(RuntimeError, match="the real problem"), db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('lost')")
        # SQLite ends a transaction itself on some errors; here it is ended by hand.
        db.execute("ROLLBACK")
        raise RuntimeError("the real problem")
    assert db.query("SELECT * FROM notes") == []
    # The handle is consistent afterwards: nesting depth and transactions work again.
    with db.transaction(), db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('kept')")
    assert [row["body"] for row in db.query("SELECT body FROM notes")] == ["kept"]


def test_a_nested_block_after_the_transaction_ended_keeps_the_original_error(
    db: Database,
) -> None:
    db.migrate("notes", MIGRATIONS)
    with pytest.raises(ValueError, match="inner failure"), db.transaction():
        db.execute("INSERT INTO notes (body) VALUES ('outer')")
        with db.transaction():
            db.execute("ROLLBACK")
            raise ValueError("inner failure")
    assert db.query("SELECT * FROM notes") == []


def test_a_failing_rollback_never_replaces_the_original_error(
    db: Database, caplog: pytest.LogCaptureFixture
) -> None:
    db.migrate("notes", MIGRATIONS)
    # The connection is the seam through which a failing disk would act.
    real = db._conn
    db._conn = _FailingConnection(real, "ROLLBACK")  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="the real problem"), db.transaction():
            db.execute("INSERT INTO notes (body) VALUES ('x')")
            raise RuntimeError("the real problem")
    finally:
        db._conn = real
    assert "rollback failed" in caplog.text
    real.execute("ROLLBACK")


def test_a_failing_commit_rolls_back_and_reports_a_store_error(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    # The connection is the seam through which a failing disk would act.
    real = db._conn
    db._conn = _FailingConnection(real, "COMMIT")  # type: ignore[assignment]
    try:
        with pytest.raises(StoreError, match="cannot commit transaction"), db.transaction():
            db.execute("INSERT INTO notes (body) VALUES ('never committed')")
    finally:
        db._conn = real
    assert real.in_transaction is False
    assert db.query("SELECT * FROM notes") == []


# --- database: several processes migrating one file -------------------------------------

STRICT_MIGRATIONS = [
    # No IF NOT EXISTS: running any of these twice fails, so a repeat cannot hide.
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);",
    "ALTER TABLE notes ADD COLUMN author TEXT;",
    "CREATE INDEX notes_author ON notes (author);",
    "CREATE TABLE tags (note_id INTEGER NOT NULL REFERENCES notes (id), tag TEXT NOT NULL);",
    "CREATE UNIQUE INDEX tags_unique ON tags (note_id, tag);",
]


def _applied(path: Path, component: str) -> list[int]:
    with Database(path, read_only=True) as reader:
        rows = reader.query(
            "SELECT version FROM schema_migrations WHERE component = ? ORDER BY version",
            (component,),
        )
    return [row["version"] for row in rows]


def test_a_migration_applied_by_another_process_meanwhile_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "race.db"
    with Database(path) as first, Database(path) as second:
        assert second.schema_version("notes") == 0
        real_transaction = second.transaction
        entered = [0]

        @contextmanager
        def racing() -> Iterator[Database]:
            entered[0] += 1
            if entered[0] == 1:
                # After the second process decided to migrate, and before it takes the
                # write lock, the first process does the whole job.
                assert first.migrate("notes", STRICT_MIGRATIONS[:3]) == 3
            with real_transaction() as handle:
                yield handle

        monkeypatch.setattr(second, "transaction", racing)
        assert second.migrate("notes", STRICT_MIGRATIONS) == 5
        monkeypatch.undo()
        assert first.schema_version("notes") == second.schema_version("notes") == 5
    assert _applied(path, "notes") == [1, 2, 3, 4, 5]


def test_several_processes_migrating_at_once_apply_each_migration_once(tmp_path: Path) -> None:
    path = tmp_path / "busy.db"
    handles = [Database(path) for _ in range(4)]
    start = threading.Barrier(len(handles))
    results: list[int] = []
    failures: list[BaseException] = []

    def run(handle: Database) -> None:
        try:
            start.wait(timeout=10)
            results.append(handle.migrate("notes", STRICT_MIGRATIONS))
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=run, args=(handle,)) for handle in handles]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
    finally:
        for handle in handles:
            handle.close()
    assert failures == []
    assert results == [5, 5, 5, 5]
    assert _applied(path, "notes") == [1, 2, 3, 4, 5]


# --- database: journal mode -------------------------------------------------------------


def test_the_journal_mode_is_checked_and_exposed(tmp_path: Path) -> None:
    path = tmp_path / "wal.db"
    with Database(path) as writer:
        assert writer.journal_mode == "wal"
        writer.migrate("notes", MIGRATIONS)
    with Database(path, read_only=True) as reader:
        assert reader.journal_mode == "wal"
    with Database() as memory:
        assert memory.journal_mode == "memory"


class _NoWalConnection(_FailingConnection):
    """A connection on a filesystem where SQLite cannot use write-ahead logging."""

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if sql == "PRAGMA journal_mode = WAL":
            # What SQLite does when WAL is unavailable: keep the old mode and say which.
            sql = "PRAGMA journal_mode"
        return self._real.execute(sql, *args)


def test_a_filesystem_without_wal_is_reported_not_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real_connect = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> Any:
        return _NoWalConnection(real_connect(*args, **kwargs), "")

    monkeypatch.setattr(db_module.sqlite3, "connect", connect)
    with Database(tmp_path / "share.db") as database:
        assert database.journal_mode == "delete"
        database.migrate("notes", MIGRATIONS)
        database.execute("INSERT INTO notes (body) VALUES ('still works')")
        assert database.query_one("SELECT body FROM notes")["body"] == "still works"
    assert "write-ahead logging is unavailable" in caplog.text


# --- database: no read is left open ------------------------------------------------------


def _checkpoint_is_blocked(path: Path) -> bool:
    """True if some connection still holds a read open on ``path``."""
    with Database(path) as other:
        other.execute("INSERT INTO notes (body) VALUES ('from another process')")
        other.execute("PRAGMA busy_timeout = 0")
        row = other.query_one("PRAGMA wal_checkpoint(TRUNCATE)")
        assert row is not None
        return bool(row[0])


@pytest.mark.parametrize(
    "read",
    [
        lambda database: database.execute("SELECT * FROM notes"),
        lambda database: database.query_one("SELECT * FROM notes"),
        lambda database: database.query("SELECT * FROM notes"),
    ],
    ids=["execute", "query_one", "query"],
)
def test_no_statement_leaves_a_read_open(
    tmp_path: Path, read: Callable[[Database], object]
) -> None:
    path = tmp_path / "reads.db"
    with Database(path) as database:
        database.migrate("notes", MIGRATIONS)
        for index in range(200):
            database.execute("INSERT INTO notes (body) VALUES (?)", (f"note {index}",))
        kept = read(database)  # held, as a careless caller would
        assert kept is not None
        assert _checkpoint_is_blocked(path) is False


def test_execute_reports_what_the_statement_did(db: Database) -> None:
    db.migrate("notes", MIGRATIONS)
    inserted = db.execute("INSERT INTO notes (body) VALUES ('a')")
    assert inserted == ExecuteResult(rowcount=1, lastrowid=1)
    db.execute("INSERT INTO notes (body) VALUES ('b')")
    assert db.execute("UPDATE notes SET author = 'x'").rowcount == 2
    assert db.execute("DELETE FROM notes WHERE body = 'zzz'").rowcount == 0
    assert db.execute("SELECT * FROM notes").rowcount == -1


# --- database: integrity check ------------------------------------------------------------


def _populated(path: Path) -> None:
    with Database(path) as database:
        database.migrate("notes", MIGRATIONS)
        with database.transaction():
            for index in range(3000):
                database.execute(
                    "INSERT INTO notes (body, author) VALUES (?, ?)",
                    (f"note {index} " + "x" * 200, f"author {index % 7}"),
                )


def test_a_healthy_database_passes_its_check(tmp_path: Path) -> None:
    path = tmp_path / "healthy.db"
    _populated(path)
    assert Database.check_file(path) == []
    with Database(path) as database:
        assert database.quick_check() == []
    with Database() as memory:
        assert memory.quick_check() == []


def test_a_damaged_database_is_reported_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "damaged.db"
    _populated(path)
    data = bytearray(path.read_bytes())
    page_size = int.from_bytes(data[16:18], "big")
    assert len(data) > page_size * 40
    # Leave the header and the schema page alone and scribble over pages further in.
    for page in range(5, 30, 3):
        offset = page * page_size
        data[offset : offset + page_size] = bytes([0xA5]) * page_size
    path.write_bytes(bytes(data))

    problems = Database.check_file(path)
    assert problems and all(isinstance(problem, str) and problem for problem in problems)
    # Checking the file read it and changed nothing (it is evidence, to be renamed aside).
    assert path.read_bytes() == bytes(data)
    with Database(path) as database:
        assert database.quick_check() == problems


@pytest.mark.parametrize(
    "content",
    [b"this is not a database at all\n" * 100, b"SQLite format 3\x00" + b"\xff" * 2000, b""],
    ids=["text", "bad-header", "empty"],
)
def test_a_file_that_is_not_a_database_is_reported(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "junk.db"
    path.write_bytes(content)
    problems = Database.check_file(path)
    if content:
        assert len(problems) == 1 and "cannot be checked" in problems[0]
    else:
        # SQLite treats an empty file as an empty database, which is healthy.
        assert problems == []
    assert path.read_bytes() == content


def test_checking_a_missing_file_is_an_error_not_damage(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="not found"):
        Database.check_file(tmp_path / "absent.db")
    assert not (tmp_path / "absent.db").exists()


# --- filesystem ----------------------------------------------------------------------


def test_atomic_write_replaces_content_and_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    atomic_write_text(target, "first")
    atomic_write_bytes(target, b"second")
    assert target.read_bytes() == b"second"
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]


def test_atomic_write_failure_keeps_the_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "policy.json"
    atomic_write_text(target, "original")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", explode)
    with pytest.raises(OSError, match="disk full"):
        atomic_write_text(target, "replacement")
    assert target.read_text() == "original"
    assert [p.name for p in tmp_path.iterdir()] == ["policy.json"]


def test_ensure_private_dir_creates_parents(tmp_path: Path) -> None:
    directory = ensure_private_dir(tmp_path / "a" / "b")
    assert directory.is_dir()
    ensure_private_dir(directory)  # idempotent


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_private_files_and_dirs_are_owner_only(tmp_path: Path) -> None:
    directory = ensure_private_dir(tmp_path / "private")
    assert directory.stat().st_mode & 0o777 == 0o700
    target = directory / "secret"
    atomic_write_text(target, "x")
    assert target.stat().st_mode & 0o777 == 0o600
