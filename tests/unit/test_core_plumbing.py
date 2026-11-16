"""Clock, database and filesystem helpers."""

from __future__ import annotations

import sys
import threading
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from portlock.core.clock import (
    FakeClock,
    SystemClock,
    format_duration,
    parse_duration,
    parse_utc_iso,
    utc_iso,
)
from portlock.core.db import Database
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
