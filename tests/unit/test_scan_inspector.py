"""The bounded read-only walk and file hashing, against real temporary directory trees."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from portlock.core.clock import FakeClock
from portlock.core.errors import ConfigError, ScanError
from portlock.scan import inspector
from portlock.scan.inspector import (
    HEAD_BYTES,
    FileEntry,
    FileTooLargeError,
    NotRegularFileError,
    ScanInterrupted,
    ScanLimits,
    Walk,
    digest_file,
    extension_of,
    hash_file,
    open_regular,
    read_prefix,
    walk,
)
from portlock.scan.report import IssueKind

IS_WINDOWS = sys.platform == "win32"
RLO = chr(0x202E)


def run_walk(root: Path, clock: FakeClock, **limits: Any) -> tuple[dict[str, FileEntry], Walk]:
    """Walk ``root`` to the end; returns the entries by relative path, and the walk."""
    walker = walk(root, ScanLimits(**limits), clock=clock)
    entries = {entry.path: entry for entry in walker}
    return entries, walker


def make_symlink(target: Path, link: Path, *, directory: bool = False) -> None:
    """Create a symbolic link, or skip the test where the platform will not allow it."""
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symbolic links here: {exc}")


def snapshot(root: Path) -> dict[str, tuple[int, int, bytes | None]]:
    """Every path under ``root`` with its size, modification time and content digest."""
    result: dict[str, tuple[int, int, bytes | None]] = {}
    for path in sorted(root.rglob("*")):
        status = path.lstat()
        content = hashlib.sha256(path.read_bytes()).digest() if path.is_file() else None
        result[path.relative_to(root).as_posix()] = (status.st_size, status.st_mtime_ns, content)
    return result


# -- what the walk reports ----------------------------------------------------------


def test_walk_reports_files_and_directories_with_their_metadata(
    tmp_path: Path, clock: FakeClock
) -> None:
    (tmp_path / "Notes.TXT").write_bytes(b"hello")
    (tmp_path / "sub").mkdir()
    big = bytes(range(256)) * 3
    (tmp_path / "sub" / "data.bin").write_bytes(big)

    entries, walker = run_walk(tmp_path, clock)

    assert set(entries) == {"Notes.TXT", "sub", "sub/data.bin"}
    notes = entries["Notes.TXT"]
    assert (notes.size, notes.head, notes.extension) == (5, b"hello", ".txt")
    assert (notes.name, notes.parent, notes.depth) == ("Notes.TXT", "", 0)
    assert notes.opened and not notes.is_dir and not notes.is_symlink
    assert notes.mtime == pytest.approx((tmp_path / "Notes.TXT").stat().st_mtime, abs=1)
    data = entries["sub/data.bin"]
    assert data.size == 768 and data.head == big[:HEAD_BYTES] and len(data.head) == 512
    assert (data.name, data.parent, data.depth) == ("data.bin", "sub", 1)
    folder = entries["sub"]
    assert folder.is_dir and folder.head == b"" and not folder.opened and folder.extension == ""
    assert (walker.files_seen, walker.dirs_seen, walker.special_skipped) == (2, 1, 0)
    assert walker.bytes_read == 5 + 512
    assert not walker.truncated and walker.truncated_reason is None
    assert walker.issues == [] and walker.issues_dropped == 0


def test_walk_is_breadth_first_so_shallow_entries_come_first(
    tmp_path: Path, clock: FakeClock
) -> None:
    (tmp_path / "d1" / "d2").mkdir(parents=True)
    (tmp_path / "d1" / "d2" / "deepest.txt").write_bytes(b"3")
    (tmp_path / "d1" / "middle.txt").write_bytes(b"2")
    (tmp_path / "top.txt").write_bytes(b"1")

    order = [entry.path for entry in walk(tmp_path, ScanLimits(), clock=clock)]

    assert set(order[:2]) == {"top.txt", "d1"}
    assert set(order[2:4]) == {"d1/middle.txt", "d1/d2"}
    assert order[4] == "d1/d2/deepest.txt"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a.TXT", ".txt"),
        ("archive.tar.gz", ".gz"),
        ("noextension", ""),
        ("report.exe .", ".exe"),
        ("report.exe   ", ".exe"),
        ("trailing.", ""),
        (".exe", ".exe"),
        (".profile", ".profile"),
        ("", ""),
    ],
)
def test_extension_is_what_windows_would_act_on(name: str, expected: str) -> None:
    assert extension_of(name) == expected


def test_a_missing_root_yields_nothing_and_is_a_failure(tmp_path: Path, clock: FakeClock) -> None:
    entries, walker = run_walk(tmp_path / "absent", clock)

    assert entries == {}
    assert [issue.kind for issue in walker.issues] == [IssueKind.FAILED]
    assert "cannot read the scan root" in walker.issues[0].message


def test_a_root_that_is_a_file_is_a_failure(tmp_path: Path, clock: FakeClock) -> None:
    target = tmp_path / "file.txt"
    target.write_bytes(b"x")

    entries, walker = run_walk(target, clock)

    assert entries == {}
    assert [(issue.kind, issue.message) for issue in walker.issues] == [
        (IssueKind.FAILED, "the scan root is not a directory")
    ]


def test_walking_changes_nothing_and_opens_read_only(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.txt").write_bytes(b"alpha")
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "b.bin").write_bytes(os.urandom(2000))
    before = snapshot(tmp_path)
    opened: list[int] = []
    real_open = os.open

    def recording_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(inspector.os, "open", recording_open)
    entries, _walker = run_walk(tmp_path, clock)
    digest = hash_file(tmp_path / "dir" / "b.bin", max_bytes=10_000)
    monkeypatch.undo()

    assert len(entries) == 3 and len(digest) == 64
    assert opened, "the walk must have opened the files it read"
    write_bits = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    assert all(flags & write_bits == 0 for flags in opened)
    assert all(flags & getattr(os, "O_BINARY", 0) == getattr(os, "O_BINARY", 0) for flags in opened)
    assert snapshot(tmp_path) == before


# -- limits -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "limits",
    [
        {"max_files": 0},
        {"max_files": True},
        {"max_dirs": 0},
        {"max_bytes": -1},
        {"max_bytes": 1.5},
        {"max_seconds": 0},
        {"max_seconds": float("nan")},
        {"max_seconds": float("inf")},
        {"max_seconds": "60"},
        {"max_depth": -1},
        {"max_file_bytes": 0},
        {"max_findings": 0},
        {"max_errors": 0},
        {"follow_symlinks": 1},
    ],
)
def test_limits_that_make_no_sense_are_rejected(limits: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        ScanLimits(**limits)


def test_limits_default_to_following_no_links() -> None:
    limits = ScanLimits()
    assert limits.follow_symlinks is False
    assert limits.max_depth == 32 and limits.max_file_bytes is None


def deep_tree(root: Path, levels: int) -> None:
    """``root/f0.txt``, ``root/d/f1.txt``, ``root/d/d/f2.txt`` and so on."""
    current = root
    for level in range(levels + 1):
        (current / f"f{level}.txt").write_bytes(b"x")
        if level < levels:
            current = current / "d"
            current.mkdir()


def test_max_depth_stops_the_descent_and_says_so(tmp_path: Path, clock: FakeClock) -> None:
    deep_tree(tmp_path, 40)

    entries, walker = run_walk(tmp_path, clock, max_depth=5)

    files = sorted(entry.depth for entry in entries.values() if not entry.is_dir)
    assert files == [0, 1, 2, 3, 4, 5]
    assert walker.truncated and walker.truncated_reason == "max_depth"


def test_a_deep_tree_within_max_depth_is_walked_in_full(tmp_path: Path, clock: FakeClock) -> None:
    deep_tree(tmp_path, 40)

    entries, walker = run_walk(tmp_path, clock, max_depth=40)

    assert sum(1 for entry in entries.values() if not entry.is_dir) == 41
    assert walker.dirs_seen == 40 and not walker.truncated


def test_max_depth_zero_examines_only_the_root(tmp_path: Path, clock: FakeClock) -> None:
    deep_tree(tmp_path, 2)

    entries, walker = run_walk(tmp_path, clock, max_depth=0)

    assert set(entries) == {"f0.txt", "d"}
    assert walker.truncated_reason == "max_depth"


def test_max_files_is_exact(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(3):
        (tmp_path / f"f{index}.txt").write_bytes(b"x")

    _entries, exact = run_walk(tmp_path, clock, max_files=3)
    _entries, short = run_walk(tmp_path, clock, max_files=2)

    assert (exact.files_seen, exact.truncated) == (3, False)
    assert (short.files_seen, short.truncated_reason) == (2, "max_files")


def test_max_dirs_bounds_the_directories_entered(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(5):
        (tmp_path / f"d{index}").mkdir()
        (tmp_path / f"d{index}" / "f.txt").write_bytes(b"x")

    entries, walker = run_walk(tmp_path, clock, max_dirs=3)

    assert walker.truncated_reason == "max_dirs"
    # The root and two more directories were queued; the walk stopped at the third.
    assert walker.dirs_seen == 2
    assert not any(entry.depth > 0 for entry in entries.values())


def test_max_seconds_is_measured_on_the_injected_clock(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(10):
        (tmp_path / f"f{index}.txt").write_bytes(b"x")
    walker = walk(tmp_path, ScanLimits(max_seconds=2.5), clock=clock)

    seen = 0
    for _entry in walker:
        seen += 1
        clock.advance(1)

    assert seen == 3
    assert walker.truncated_reason == "max_seconds"
    assert walker.stop_reason() == "max_seconds"


def test_max_bytes_bounds_what_is_read(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(6):
        (tmp_path / f"f{index}.bin").write_bytes(b"\xaa" * 2048)

    _entries, walker = run_walk(tmp_path, clock, max_bytes=1024)

    assert walker.files_seen == 2
    assert walker.bytes_read == 1024 and walker.remaining_bytes == 0
    assert walker.truncated_reason == "max_bytes"


def test_bytes_charged_by_the_caller_count_against_the_budget(
    tmp_path: Path, clock: FakeClock
) -> None:
    for index in range(4):
        (tmp_path / f"f{index}.bin").write_bytes(b"x")
    walker = walk(tmp_path, ScanLimits(max_bytes=100), clock=clock)

    first = next(walker)
    walker.charge(99)
    rest = list(walker)

    assert first.head == b"x" and rest == []
    assert walker.truncated_reason == "max_bytes"


def test_cancellation_stops_the_walk_at_the_next_entry(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(10):
        (tmp_path / f"f{index}.txt").write_bytes(b"x")
    cancel = threading.Event()
    walker = walk(tmp_path, ScanLimits(), cancel=cancel, clock=clock)

    seen = 0
    for _entry in walker:
        seen += 1
        cancel.set()

    assert seen == 1
    assert walker.truncated_reason == "cancelled"


def test_a_walk_cancelled_before_it_starts_reads_nothing(tmp_path: Path, clock: FakeClock) -> None:
    (tmp_path / "f.txt").write_bytes(b"x")
    cancel = threading.Event()
    cancel.set()

    walker = walk(tmp_path, ScanLimits(), cancel=cancel, clock=clock)

    assert list(walker) == []
    assert walker.truncated_reason == "cancelled" and walker.bytes_read == 0


def test_closing_a_walk_early_is_safe(tmp_path: Path, clock: FakeClock) -> None:
    for index in range(5):
        (tmp_path / f"f{index}.txt").write_bytes(b"x")
    walker = walk(tmp_path, ScanLimits(), clock=clock)

    next(walker)
    walker.close()
    walker.close()

    assert list(walker) == []
    assert walker.files_seen == 1


@pytest.fixture(scope="module")
def ten_thousand_files(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Ten directories of a thousand empty files each. Built once: it is the slow part."""
    root = tmp_path_factory.mktemp("tenk")
    flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    for directory in range(10):
        folder = root / f"d{directory}"
        folder.mkdir()
        for index in range(1000):
            os.close(os.open(folder / f"f{index:04d}", flags))
    return root


@pytest.mark.parametrize(
    ("max_files", "expected", "reason"),
    [(10_000, 10_000, None), (9_999, 9_999, "max_files"), (250, 250, "max_files")],
)
def test_ten_thousand_files_against_the_file_limit(
    ten_thousand_files: Path, max_files: int, expected: int, reason: str | None
) -> None:
    walker = walk(ten_thousand_files, ScanLimits(max_files=max_files), clock=FakeClock())

    count = sum(1 for entry in walker if not entry.is_dir)

    assert count == expected == walker.files_seen
    assert walker.truncated_reason == reason
    assert walker.issues == []


def test_ten_thousand_files_against_the_time_limit(ten_thousand_files: Path) -> None:
    clock = FakeClock()
    walker = walk(ten_thousand_files, ScanLimits(max_seconds=60), clock=clock)

    seen = 0
    for _entry in walker:
        seen += 1
        clock.advance(0.5)

    assert seen == 120
    assert walker.truncated_reason == "max_seconds"


# -- links --------------------------------------------------------------------------


def test_links_are_not_followed_by_default(tmp_path: Path, clock: FakeClock) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"not on the volume")
    root = tmp_path / "volume"
    root.mkdir()
    (root / "real.txt").write_bytes(b"on the volume")
    make_symlink(outside, root / "dirlink", directory=True)
    make_symlink(outside / "secret.txt", root / "filelink.txt")

    entries, walker = run_walk(root, clock)

    assert set(entries) == {"real.txt", "dirlink", "filelink.txt"}
    for name in ("dirlink", "filelink.txt"):
        link = entries[name]
        assert link.is_symlink and not link.is_dir and not link.opened and link.head == b""
    assert entries["filelink.txt"].extension == ".txt"
    assert walker.files_seen == 3 and walker.dirs_seen == 0
    assert walker.issues == [] and not walker.truncated


def test_a_link_loop_does_not_trap_the_walk(tmp_path: Path, clock: FakeClock) -> None:
    root = tmp_path / "volume"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "file.txt").write_bytes(b"x")
    make_symlink(root, root / "a" / "b" / "up", directory=True)
    make_symlink(root / "a" / "b" / "self", root / "a" / "b" / "self", directory=True)

    default_entries, default_walk = run_walk(root, clock)
    followed_entries, followed_walk = run_walk(root, clock, follow_symlinks=True)

    for entries, walker in ((default_entries, default_walk), (followed_entries, followed_walk)):
        regular = [path for path, entry in entries.items() if entry.opened]
        assert regular == ["a/b/file.txt"]
        assert not walker.truncated and walker.issues == []
    assert followed_entries["a/b/up"].is_dir and followed_entries["a/b/up"].is_symlink
    assert not followed_entries["a/b/self"].is_dir


def test_followed_links_stay_inside_the_root(tmp_path: Path, clock: FakeClock) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"not on the volume")
    root = tmp_path / "volume"
    (root / "real").mkdir(parents=True)
    (root / "real" / "inner.txt").write_bytes(b"inner content")
    make_symlink(outside, root / "escape", directory=True)
    make_symlink(outside / "secret.txt", root / "escape.txt")
    make_symlink(root / "real", root / "alias", directory=True)
    make_symlink(root / "real" / "inner.txt", root / "shortcut.txt")
    make_symlink(root / "nowhere", root / "broken")

    entries, walker = run_walk(root, clock, follow_symlinks=True)

    assert not any("secret" in path for path in entries)
    assert not entries["escape"].is_dir and not entries["escape.txt"].opened
    assert not entries["broken"].opened and entries["broken"].is_symlink
    assert entries["alias"].is_dir and entries["alias"].is_symlink
    followed = entries["shortcut.txt"]
    assert followed.is_symlink and followed.opened and followed.head == b"inner content"
    # The directory is entered once, whichever of its two names the walk met first.
    inner = [path for path in entries if path.endswith("inner.txt")]
    assert len(inner) == 1 and inner[0] in ("real/inner.txt", "alias/inner.txt")
    assert walker.issues == []


@pytest.mark.windows_only
def test_a_junction_is_never_entered(tmp_path: Path, clock: FakeClock) -> None:
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"not on the volume")
    root = tmp_path / "volume"
    root.mkdir()
    (root / "real.txt").write_bytes(b"x")
    junction = root / "junction"
    _winapi.CreateJunction(str(outside), str(junction))
    try:
        default_entries, _walker = run_walk(root, clock)
        followed_entries, _walker = run_walk(root, clock, follow_symlinks=True)
    finally:
        os.rmdir(junction)

    for entries in (default_entries, followed_entries):
        assert set(entries) == {"real.txt", "junction"}
        assert entries["junction"].is_symlink and not entries["junction"].is_dir
    assert (outside / "secret.txt").read_bytes() == b"not on the volume"


def test_a_directory_reached_twice_without_links_is_reported_as_a_loop(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crafted filesystem can link a directory into itself; identity catches it."""
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "inner.txt").write_bytes(b"x")
    (tmp_path / "a" / "outer.txt").write_bytes(b"x")
    real_lstat = os.lstat

    class SameAsParent:
        def __init__(self, status: os.stat_result, identity: os.stat_result) -> None:
            self._status = status
            self.st_ino = identity.st_ino or 4242
            self.st_dev = identity.st_dev

        def __getattr__(self, name: str) -> Any:
            return getattr(self._status, name)

    def lying_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        status = real_lstat(path, *args, **kwargs)
        text = os.fsdecode(path)
        if text.endswith(("a", "b")) and stat.S_ISDIR(status.st_mode):
            return SameAsParent(status, real_lstat(tmp_path / "a"))
        return status

    monkeypatch.setattr(inspector.os, "lstat", lying_lstat)
    entries, walker = run_walk(tmp_path, clock)
    monkeypatch.undo()

    assert "a/outer.txt" in entries and "a/b/inner.txt" not in entries
    assert [(issue.path, issue.message) for issue in walker.issues] == [
        ("a/b", "directory loop on the volume; not re-entered")
    ]


# -- things that go wrong mid-walk --------------------------------------------------


def deny(monkeypatch: pytest.MonkeyPatch, function: str, suffixes: tuple[str, ...]) -> None:
    """Make ``os.<function>`` fail with "permission denied" for paths ending in ``suffixes``."""
    real = getattr(os, function)

    def guarded(path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, str | bytes | os.PathLike) and os.fsdecode(path).endswith(suffixes):
            raise PermissionError(13, "Permission denied")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(inspector.os, function, guarded)


def test_an_unreadable_file_is_recorded_and_the_walk_goes_on(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "locked.exe").write_bytes(b"MZ secret")
    (tmp_path / "open.txt").write_bytes(b"fine")
    deny(monkeypatch, "open", ("locked.exe",))

    entries, walker = run_walk(tmp_path, clock)
    monkeypatch.undo()

    locked = entries["locked.exe"]
    assert not locked.opened and locked.head == b"" and locked.extension == ".exe"
    assert entries["open.txt"].head == b"fine"
    assert [(issue.source, issue.path, issue.kind) for issue in walker.issues] == [
        ("walk", "locked.exe", IssueKind.UNREAD)
    ]
    assert "Permission denied" in walker.issues[0].message
    assert str(tmp_path) not in walker.issues[0].message
    assert walker.files_seen == 2 and not walker.truncated


def test_an_unreadable_directory_is_recorded_and_the_walk_goes_on(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "hidden.txt").write_bytes(b"x")
    (tmp_path / "open").mkdir()
    (tmp_path / "open" / "seen.txt").write_bytes(b"x")
    deny(monkeypatch, "scandir", ("locked",))

    entries, walker = run_walk(tmp_path, clock)
    monkeypatch.undo()

    assert "open/seen.txt" in entries and "locked/hidden.txt" not in entries
    assert [(issue.path, issue.kind) for issue in walker.issues] == [("locked", IssueKind.UNREAD)]


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX permission bits")
def test_real_permission_bits_are_tolerated(tmp_path: Path, clock: FakeClock) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    secret = tmp_path / "secret.bin"
    secret.write_bytes(b"x")
    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "inside.txt").write_bytes(b"x")
    (tmp_path / "plain.txt").write_bytes(b"plain")
    secret.chmod(0)
    closed.chmod(0)
    try:
        entries, walker = run_walk(tmp_path, clock)
    finally:
        secret.chmod(0o600)
        closed.chmod(0o700)

    assert entries["plain.txt"].head == b"plain"
    assert not entries["secret.bin"].opened
    assert "closed/inside.txt" not in entries
    assert sorted(issue.path for issue in walker.issues) == ["closed", "secret.bin"]
    assert all(issue.kind is IssueKind.UNREAD for issue in walker.issues)


def test_the_number_of_recorded_issues_is_bounded(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(5):
        (tmp_path / f"f{index}.locked").write_bytes(b"x")
    deny(monkeypatch, "open", (".locked",))

    _entries, walker = run_walk(tmp_path, clock, max_errors=2)
    monkeypatch.undo()

    assert len(walker.issues) == 2 and walker.issues_dropped == 3
    assert walker.files_seen == 5


def test_a_file_that_vanishes_before_it_is_opened_is_recorded(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ghost.txt").write_bytes(b"soon gone")
    (tmp_path / "stays.txt").write_bytes(b"still here")
    real_open_regular = inspector.open_regular

    def vanishing(path: Any) -> tuple[int, os.stat_result]:
        if os.fsdecode(path).endswith("ghost.txt"):
            os.unlink(tmp_path / "ghost.txt")
        return real_open_regular(path)

    monkeypatch.setattr(inspector, "open_regular", vanishing)
    entries, walker = run_walk(tmp_path, clock)
    monkeypatch.undo()

    assert not entries["ghost.txt"].opened and entries["ghost.txt"].head == b""
    assert entries["stays.txt"].head == b"still here"
    assert [(issue.path, issue.kind) for issue in walker.issues] == [
        ("ghost.txt", IssueKind.UNREAD)
    ]


def test_files_deleted_while_their_directory_is_being_read(
    tmp_path: Path, clock: FakeClock
) -> None:
    names = {f"f{index:02d}.txt" for index in range(30)}
    for name in names:
        (tmp_path / name).write_bytes(b"content")
    walker = walk(tmp_path, ScanLimits(), clock=clock)

    first = next(walker)
    doomed = sorted(names - {first.name})[:20]
    for name in doomed:
        os.unlink(tmp_path / name)
    rest = list(walker)

    read = {entry.path for entry in [first, *rest] if entry.opened}
    reported = {issue.path for issue in walker.issues}
    assert read.isdisjoint(doomed)
    assert read == names - set(doomed)
    # A deleted file was either never listed, or listed and then reported as unreadable.
    assert reported <= set(doomed)
    assert all(issue.kind is IssueKind.UNREAD for issue in walker.issues)
    assert not walker.truncated


def test_a_directory_that_vanishes_before_it_is_entered_is_recorded(
    tmp_path: Path, clock: FakeClock
) -> None:
    (tmp_path / "later").mkdir()
    (tmp_path / "later" / "inside.txt").write_bytes(b"x")
    (tmp_path / "top.txt").write_bytes(b"x")
    walker = walk(tmp_path, ScanLimits(), clock=clock)

    paths = []
    for entry in walker:
        paths.append(entry.path)
        if entry.path == "later":
            shutil.rmtree(tmp_path / "later")

    assert sorted(paths) == ["later", "top.txt"]
    assert [(issue.path, issue.kind) for issue in walker.issues] == [("later", IssueKind.UNREAD)]


# -- hostile names and special files ------------------------------------------------


def test_names_built_to_confuse_a_display_are_escaped(tmp_path: Path, clock: FakeClock) -> None:
    spoofed = f"photo{RLO}gpj.exe"
    padded = "invoice.pdf" + " " * 40 + ".exe"
    try:
        (tmp_path / spoofed).write_bytes(b"MZ")
        (tmp_path / padded).write_bytes(b"MZ")
    except OSError as exc:
        pytest.skip(f"this filesystem refuses the names: {exc}")

    entries, _walker = run_walk(tmp_path, clock)

    assert set(entries) == {spoofed, padded}
    assert entries[spoofed].display_path == "photo\\u202egpj.exe"
    assert entries[spoofed].extension == ".exe" and entries[padded].extension == ".exe"
    assert entries[padded].display_path == padded


@pytest.mark.linux_only
def test_names_that_are_not_text_are_walked_hashed_and_escaped(
    tmp_path: Path, clock: FakeClock
) -> None:
    raw_root = os.fsencode(tmp_path)
    names = [b"bad\xff\xfe.bin", b"two\nlines.txt", b"x" * 255, b"tab\there\x1b[31m.txt"]
    for index, name in enumerate(names):
        descriptor = os.open(os.path.join(raw_root, name), os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(descriptor, b"content %d" % index)
        os.close(descriptor)

    entries, walker = run_walk(tmp_path, clock)

    assert len(entries) == 4 and walker.issues == []
    displays = sorted(entry.display_path for entry in entries.values())
    assert displays == sorted(
        ["bad\\xff\\xfe.bin", "two\\x0alines.txt", "x" * 255, "tab\\x09here\\x1b[31m.txt"]
    )
    for entry in entries.values():
        # Safe to print, encode and store, whatever the name was.
        json.dumps(entry.display_path).encode("utf-8")
        assert entry.display_path.isprintable()
        assert entry.opened and entry.head.startswith(b"content ")
        assert hash_file(entry.os_path, max_bytes=100) == hashlib.sha256(entry.head).hexdigest()


@pytest.mark.windows_only
def test_names_win32_would_misread_are_opened_as_the_files_they_are(
    tmp_path: Path, clock: FakeClock
) -> None:
    """Device names, trailing dots and lone surrogates, created through the raw path form."""
    prefix = "\\\\?\\" + str(tmp_path) + "\\"
    names = ["NUL", "COM1.txt", "trailing dot.", "trailing space ", "lone" + chr(0xD800) + ".txt"]
    created = []
    try:
        for index, name in enumerate(names):
            with open(prefix + name, "wb") as stream:
                stream.write(b"real file %d" % index)
            created.append(name)
        entries, walker = run_walk(tmp_path, clock)
        digests = {name: hash_file(entries[name].os_path, max_bytes=100) for name in names}
    finally:
        for name in created:
            os.unlink(prefix + name)

    assert set(entries) == set(names) and walker.issues == []
    for index, name in enumerate(names):
        content = b"real file %d" % index
        assert entries[name].opened and entries[name].head == content
        assert digests[name] == hashlib.sha256(content).hexdigest()
    assert entries["lone" + chr(0xD800) + ".txt"].display_path == "lone\\ud800.txt"
    assert entries["trailing dot."].extension == ""
    assert walker.special_skipped == 0


@pytest.mark.skipif(IS_WINDOWS, reason="FIFOs and UNIX sockets")
def test_special_files_are_counted_and_never_opened(tmp_path: Path, clock: FakeClock) -> None:
    os.mkfifo(tmp_path / "pipe")
    listener = socket.socket(socket.AF_UNIX)
    try:
        listener.bind(str(tmp_path / "sock"))
    except OSError as exc:
        listener.close()
        pytest.skip(f"cannot bind a UNIX socket here: {exc}")
    (tmp_path / "plain.txt").write_bytes(b"plain")
    try:
        entries, walker = run_walk(tmp_path, clock)
        with pytest.raises(NotRegularFileError):
            hash_file(tmp_path / "pipe", max_bytes=10)
        with pytest.raises(NotRegularFileError):
            read_prefix(tmp_path / "sock", 10)
    finally:
        listener.close()

    assert set(entries) == {"plain.txt"}
    assert (walker.files_seen, walker.special_skipped) == (1, 2)
    assert walker.issues == [] and not walker.truncated


@pytest.mark.skipif(IS_WINDOWS, reason="FIFOs")
def test_a_file_swapped_for_a_fifo_after_listing_is_not_read(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "swap.bin"
    victim.write_bytes(b"regular when listed")
    real_open_regular = inspector.open_regular

    def swapping(path: Any) -> tuple[int, os.stat_result]:
        if os.fsdecode(path).endswith("swap.bin"):
            os.unlink(victim)
            os.mkfifo(victim)
        return real_open_regular(path)

    monkeypatch.setattr(inspector, "open_regular", swapping)
    entries, walker = run_walk(tmp_path, clock)
    monkeypatch.undo()

    assert entries == {}
    assert (walker.files_seen, walker.special_skipped) == (0, 1)


def test_special_files_count_against_the_file_limit(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory of a million device nodes must not be free to list."""
    for index in range(6):
        (tmp_path / f"f{index}.txt").write_bytes(b"x")

    def refuse(path: Any) -> tuple[int, os.stat_result]:
        raise NotRegularFileError("is a special file; not opened")

    monkeypatch.setattr(inspector, "open_regular", refuse)
    entries, walker = run_walk(tmp_path, clock, max_files=4)
    monkeypatch.undo()

    assert entries == {}
    assert walker.special_skipped == 4 and walker.truncated_reason == "max_files"


# -- attributes ---------------------------------------------------------------------


@pytest.mark.windows_only
def test_dos_attributes_are_read_on_windows(tmp_path: Path, clock: FakeClock) -> None:
    import ctypes

    hidden = tmp_path / "hidden.exe"
    hidden.write_bytes(b"MZ")
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"x")
    folder = tmp_path / "Photos"
    folder.mkdir()
    set_attributes = ctypes.windll.kernel32.SetFileAttributesW  # type: ignore[attr-defined]
    assert set_attributes(str(hidden), 0x2 | 0x4 | 0x1)
    assert set_attributes(str(folder), 0x2 | 0x10)
    try:
        entries, _walker = run_walk(tmp_path, clock)
    finally:
        set_attributes(str(hidden), 0x80)
        set_attributes(str(folder), 0x10)

    assert (entries["hidden.exe"].hidden, entries["hidden.exe"].system) == (True, True)
    assert entries["hidden.exe"].read_only is True and entries["hidden.exe"].head == b"MZ"
    assert (entries["plain.txt"].hidden, entries["plain.txt"].system) == (False, False)
    assert entries["plain.txt"].read_only is False
    assert entries["Photos"].hidden is True and entries["Photos"].system is False


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX naming convention")
def test_a_leading_dot_means_hidden_where_there_are_no_dos_attributes(
    tmp_path: Path, clock: FakeClock
) -> None:
    (tmp_path / ".stash").mkdir()
    (tmp_path / ".tool.exe").write_bytes(b"MZ")
    (tmp_path / "plain.txt").write_bytes(b"x")

    entries, _walker = run_walk(tmp_path, clock)

    assert entries[".stash"].hidden is True and entries[".tool.exe"].hidden is True
    assert entries["plain.txt"].hidden is False
    assert entries["plain.txt"].system is None and entries["plain.txt"].read_only is None


@pytest.mark.linux_only
def test_fat_attributes_are_combined_with_the_dot_convention(tmp_path: Path) -> None:
    target = tmp_path / "file.exe"
    target.write_bytes(b"x")
    status = target.stat()

    assert inspector._attributes("dir/file.exe", status, 0x02 | 0x04) == (True, True, False)
    assert inspector._attributes("dir/file.exe", status, 0x01) == (False, False, True)
    assert inspector._attributes("dir/.file.exe", status, 0x00) == (True, False, False)
    assert inspector._attributes("dir/file.exe", status, None) == (False, None, None)
    # The temporary directory is not a FAT volume, so the query has no answer here.
    descriptor, _status = open_regular(target)
    try:
        assert inspector._dos_attributes(descriptor) is None
    finally:
        os.close(descriptor)


# -- hashing ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ],
)
def test_hash_file_matches_published_sha256_vectors(
    tmp_path: Path, content: bytes, expected: str
) -> None:
    target = tmp_path / "vector.bin"
    target.write_bytes(content)

    assert hash_file(target, max_bytes=1024) == expected
    assert digest_file(target, max_bytes=1024).size == len(content)


def test_hash_file_reads_in_chunks(tmp_path: Path) -> None:
    content = bytes(range(256)) * 12
    target = tmp_path / "chunks.bin"
    target.write_bytes(content)

    assert hash_file(target, max_bytes=len(content), chunk=7) == hashlib.sha256(content).hexdigest()
    assert hash_file(target, max_bytes=len(content), chunk=10**12) == (
        hashlib.sha256(content).hexdigest()
    )


def test_hash_file_refuses_a_file_over_the_cap(tmp_path: Path) -> None:
    target = tmp_path / "hundred.bin"
    target.write_bytes(b"\x01" * 100)

    assert len(hash_file(target, max_bytes=100)) == 64
    with pytest.raises(FileTooLargeError) as caught:
        hash_file(target, max_bytes=99)
    assert caught.value.code == "file_too_large"
    assert isinstance(caught.value, ScanError)


def test_hash_file_counts_bytes_when_the_filesystem_lies_about_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "liar.bin"
    target.write_bytes(b"\x02" * 5000)
    real_fstat = os.fstat

    class ClaimsEmpty:
        st_size = 0

        def __init__(self, status: os.stat_result) -> None:
            self.st_mode = status.st_mode

    monkeypatch.setattr(inspector.os, "fstat", lambda fd: ClaimsEmpty(real_fstat(fd)))
    with pytest.raises(FileTooLargeError, match="grew past the limit"):
        hash_file(target, max_bytes=1000, chunk=64)
    monkeypatch.undo()


@pytest.mark.linux_only
def test_an_enormous_sparse_file_costs_nothing(tmp_path: Path, clock: FakeClock) -> None:
    target = tmp_path / "sparse.img"
    with open(target, "wb") as stream:
        stream.truncate(2**40)

    entries, walker = run_walk(tmp_path, clock)

    assert entries["sparse.img"].size == 2**40
    assert entries["sparse.img"].head == bytes(512) and walker.bytes_read == 512
    with pytest.raises(FileTooLargeError):
        hash_file(target, max_bytes=2**20)


def test_hashing_can_be_interrupted_between_reads(tmp_path: Path) -> None:
    target = tmp_path / "long.bin"
    target.write_bytes(b"\x03" * 1000)
    calls: list[int] = []

    def stop_after_two() -> str | None:
        calls.append(1)
        return "cancelled" if len(calls) > 2 else None

    with pytest.raises(ScanInterrupted) as caught:
        digest_file(target, max_bytes=1000, chunk=100, should_stop=stop_after_two)

    assert caught.value.reason == "cancelled" and len(calls) == 3


def test_hash_file_validates_its_arguments(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")

    with pytest.raises(ValueError, match="max_bytes"):
        hash_file(target, max_bytes=-1)
    with pytest.raises(ValueError, match="chunk"):
        hash_file(target, max_bytes=10, chunk=0)
    with pytest.raises(ValueError, match="max_bytes"):
        read_prefix(target, -1)
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "absent.bin", max_bytes=10)


def test_only_regular_files_are_opened(tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    target = tmp_path / "real.txt"
    target.write_bytes(b"real")

    with pytest.raises(NotRegularFileError) as caught:
        hash_file(tmp_path / "dir", max_bytes=10)
    assert caught.value.code == "not_regular_file"
    with pytest.raises(NotRegularFileError):
        read_prefix(tmp_path / "dir", 10)
    assert read_prefix(target, 2) == b"re" and read_prefix(target, 100) == b"real"

    make_symlink(target, tmp_path / "link.txt")
    with pytest.raises(NotRegularFileError):
        hash_file(tmp_path / "link.txt", max_bytes=10)
    with pytest.raises(NotRegularFileError):
        read_prefix(tmp_path / "link.txt", 10)


def test_open_regular_returns_a_usable_read_only_descriptor(tmp_path: Path) -> None:
    content = b"\r\n\x1a binary stays binary"
    target = tmp_path / "f.bin"
    target.write_bytes(content)

    descriptor, status = open_regular(target)
    try:
        assert stat.S_ISREG(status.st_mode) and status.st_size == len(content)
        assert os.read(descriptor, 100) == content
        # The errno differs by platform; that the write is refused does not.
        with pytest.raises(OSError):
            os.write(descriptor, b"x")
    finally:
        os.close(descriptor)
    assert target.read_bytes() == content


def iter_names(walker: Walk) -> Iterator[str]:
    for entry in walker:
        yield entry.path


def test_a_bytes_root_is_accepted(tmp_path: Path, clock: FakeClock) -> None:
    (tmp_path / "f.txt").write_bytes(b"x")

    walker = walk(os.fsencode(tmp_path), ScanLimits(), clock=clock)

    assert list(iter_names(walker)) == ["f.txt"]
