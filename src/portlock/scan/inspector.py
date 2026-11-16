"""A bounded, read-only walk of a directory tree that assumes the tree is hostile.

The volume being scanned comes from a device nobody vouches for. Its filesystem may be
crafted: directories nested without end or linked into loops, millions of entries, files
that claim to be terabytes long, names chosen to confuse a terminal or a path parser,
links that point at the rest of the machine, device nodes and FIFOs that block whoever
opens them. This module reads such a tree without hanging, without unbounded memory and
without ever leaving it:

* every open is read-only and binary, and nothing here writes, renames or deletes;
* symbolic links, junctions and other reparse points are not followed unless
  :attr:`ScanLimits.follow_symlinks` is set, and even then only to targets that resolve
  inside the scan root on the same filesystem;
* only regular files are opened. The type is checked before opening and again on the
  open handle, and the open itself cannot block on a FIFO;
* the walk is breadth-first and lazy, so the root and the shallow levels are examined
  first and a directory with millions of entries is never held in memory;
* the walk stops at the first of ``max_files``, ``max_dirs``, ``max_bytes``,
  ``max_seconds`` or a cancellation, does not descend past ``max_depth``, and says which
  limit it hit;
* a directory already visited, or one on another filesystem, is not entered;
* permission errors and files that vanish mid-walk are recorded and the walk carries on.

What it cannot do is interrupt a single ``read`` that the device never answers; see
``docs/SCANNING.md``.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import struct
import sys
import threading
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import ConfigError, ScanError
from portlock.scan.report import IssueKind, ScanIssue, safe_text

__all__ = [
    "HEAD_BYTES",
    "FileDigest",
    "FileEntry",
    "FileTooLargeError",
    "NotRegularFileError",
    "ScanInterrupted",
    "ScanLimits",
    "Walk",
    "digest_file",
    "extension_of",
    "hash_file",
    "open_regular",
    "read_prefix",
    "walk",
]

#: How many leading bytes of each file the walk captures for magic-number checks.
HEAD_BYTES = 512

_IS_WINDOWS = sys.platform == "win32"
_IS_LINUX = sys.platform.startswith("linux")

# Read-only, binary, never following a link in the final component, never blocking on a
# FIFO, never acquiring a controlling terminal, not inherited by child processes. Flags
# that a platform lacks are simply absent there.
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOCTTY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOINHERIT", 0)
)
_DIR_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)

_READ_BLOCK = 64 * 1024
_MAX_CHUNK = 16 * 1024 * 1024
_DEFAULT_CHUNK = 1024 * 1024

# FAT_IOCTL_GET_ATTRIBUTES from <linux/msdos_fs.h>: _IOR('r', 0x10, __u32). A read-only
# query that the vfat and exfat drivers answer with the DOS attribute byte, which is the
# only way to learn on Linux that a file on a FAT volume is marked hidden or system.
_FAT_IOCTL_GET_ATTRIBUTES = 0x80047210
_DOS_READ_ONLY = 0x01
_DOS_HIDDEN = 0x02
_DOS_SYSTEM = 0x04

_EXTENDED_PREFIX = "\\\\?\\"
_DEVICE_PREFIX = "\\\\.\\"


class FileTooLargeError(ScanError):
    """A file is larger than the size cap it was to be read under."""

    code = "file_too_large"


class NotRegularFileError(ScanError):
    """A path is a link, a directory, a device, a FIFO or a socket; it was not read."""

    code = "not_regular_file"


class ScanInterrupted(ScanError):
    """A read was abandoned because the scan was cancelled or ran out of budget.

    Attributes:
        reason: ``cancelled``, ``max_seconds`` or ``max_bytes``.
    """

    code = "scan_interrupted"

    def __init__(self, reason: str) -> None:
        super().__init__(f"interrupted: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """How much work one scan may do. Every limit is a hard upper bound.

    Attributes:
        max_files: files, links and special files examined before the walk stops.
        max_dirs: directories met before the walk stops, the root included, whether
            or not they are entered (one below ``max_depth`` is met but not entered).
        max_bytes: bytes read from the volume in total (file heads, rule input and
            hashing) before the scan stops reading.
        max_seconds: the overall time budget, measured on the injected clock.
        max_depth: how many directory levels below the root are entered; ``0`` examines
            the root's own entries only.
        max_file_bytes: the largest single file that is hashed; ``None`` leaves that to
            ``max_bytes``. A larger file is reported as not examined.
        follow_symlinks: follow links whose target resolves inside the scan root, on the
            same filesystem. Off by default: nothing is followed.
        max_findings: findings kept in a report (malicious findings have a separate
            allowance of the same size, so they are never crowded out).
        max_errors: unreadable-file records kept; further ones are counted, not stored.

    Raises:
        ConfigError: if a limit is not a positive number (``max_depth`` may be zero).
    """

    max_files: int = 100_000
    max_dirs: int = 20_000
    max_bytes: int = 4 * 1024**3
    max_seconds: float = 300.0
    max_depth: int = 32
    max_file_bytes: int | None = None
    follow_symlinks: bool = False
    max_findings: int = 5_000
    max_errors: int = 1_000

    def __post_init__(self) -> None:
        for name in ("max_files", "max_dirs", "max_bytes", "max_findings", "max_errors"):
            _require_int(name, getattr(self, name), minimum=1)
        _require_int("max_depth", self.max_depth, minimum=0)
        if self.max_file_bytes is not None:
            _require_int("max_file_bytes", self.max_file_bytes, minimum=1)
        seconds = self.max_seconds
        if isinstance(seconds, bool) or not isinstance(seconds, int | float):
            raise ConfigError(f"max_seconds must be a number, got {seconds!r}")
        # The comparison is written so that NaN fails it.
        if not 0 < seconds < float("inf"):
            raise ConfigError(f"max_seconds must be positive and finite, got {seconds!r}")
        if not isinstance(self.follow_symlinks, bool):
            raise ConfigError("follow_symlinks must be true or false")


def _require_int(name: str, value: object, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{name} must be an integer of at least {minimum}, got {value!r}")


def extension_of(name: str) -> str:
    """The extension Windows would act on for ``name``: lowercase, with its dot.

    Trailing dots and spaces are ignored, as the Win32 layer ignores them when a file is
    opened, so ``report.exe .`` has the extension ``.exe``. A name that is nothing but
    an extension (``.exe``) keeps it. Returns an empty string if there is none.
    """
    trimmed = name.rstrip(" .")
    dot = trimmed.rfind(".")
    if dot < 0:
        return ""
    return trimmed[dot:].lower()


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One file, link or directory met during a walk.

    Attributes:
        path: location relative to the scan root, ``/``-separated, exactly as the
            filesystem reports the names. It may hold control characters, bidirectional
            overrides and undecodable bytes; use :attr:`display_path` to show it.
        os_path: the path to open. Never store or display it.
        size: length in bytes as the filesystem reports it (zero for a directory).
        mtime: modification time, seconds since the epoch, as reported.
        is_dir: True for a directory. Directories are yielded so that rules can compare
            a folder with its neighbours; they carry no content.
        is_symlink: True for a symbolic link, a junction or any other reparse point.
        hidden / system / read_only: the DOS attributes where the platform exposes them
            (Windows always; Linux on FAT and exFAT volumes). On other filesystems
            ``hidden`` reflects a leading dot and the other two are ``None``.
        extension: see :func:`extension_of`.
        head: the first :data:`HEAD_BYTES` bytes, or fewer for a short file. Empty for
            directories, for links that were not followed and for unreadable files.
        opened: True if the walk opened the file and read its head: a regular file, or
            the in-root target of a followed link. False for directories, for links
            that were not followed, and for files that could not be read (those are
            also recorded as issues by the walk). Only opened entries are read again.
    """

    path: str
    os_path: str
    size: int = 0
    mtime: float = 0.0
    is_dir: bool = False
    is_symlink: bool = False
    hidden: bool | None = None
    system: bool | None = None
    read_only: bool | None = None
    extension: str = ""
    head: bytes = b""
    opened: bool = False

    @property
    def name(self) -> str:
        """The final path component, raw."""
        return self.path.rpartition("/")[2]

    @property
    def parent(self) -> str:
        """The containing directory relative to the root; empty for a root entry."""
        return self.path.rpartition("/")[0]

    @property
    def depth(self) -> int:
        """How many directories lie between the root and this entry (0 at the root)."""
        return self.path.count("/")

    @property
    def display_path(self) -> str:
        """:attr:`path` made safe to print, log and store."""
        return safe_text(self.path)


@dataclass(frozen=True, slots=True)
class FileDigest:
    """A SHA-256 digest together with the number of bytes that went into it."""

    sha256: str
    size: int


def _extended_path(path: str) -> str:
    """On Windows, the extended-length form of ``path``; elsewhere, ``path`` unchanged.

    The ``\\\\?\\`` prefix turns off Win32 path normalisation. Without it a file named
    ``NUL`` or ``COM1`` on the volume would open the *device* of that name, a name ending
    in a dot or a space could not be opened at all, and paths past 260 characters fail.
    """
    if not _IS_WINDOWS or path.startswith((_EXTENDED_PREFIX, _DEVICE_PREFIX)):
        return path
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\"):
        return _EXTENDED_PREFIX + "UNC\\" + absolute[2:]
    return _EXTENDED_PREFIX + absolute


def _is_reparse_point(status: os.stat_result) -> bool:
    return bool(getattr(status, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def open_regular(path: str | os.PathLike[str]) -> tuple[int, os.stat_result]:
    """Open a regular file read-only and return its descriptor and status.

    The caller must close the descriptor. The type is verified on the open handle, so a
    path that was swapped for something else after it was listed is still caught. A link
    in the final path component is refused, not followed.

    Raises:
        NotRegularFileError: if the path is a link, directory, device, FIFO or socket.
        OSError: if the file cannot be opened (missing, permission denied, I/O error).
    """
    target = _extended_path(os.fsdecode(path))
    if _IS_WINDOWS:
        # Windows has no O_NOFOLLOW; refuse links and other reparse points up front.
        listed = os.lstat(target)
        if _is_reparse_point(listed) or not stat.S_ISREG(listed.st_mode):
            raise NotRegularFileError("is a link, a directory or a special file; not opened")
    try:
        descriptor = os.open(target, _OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            # What O_NOFOLLOW reports for a symbolic link (EMLINK on some BSDs).
            raise NotRegularFileError("is a symbolic link; not opened") from exc
        if exc.errno in (errno.ENXIO, errno.ENODEV, errno.EOPNOTSUPP):
            # A FIFO with no writer, a socket, or a device node without a device.
            raise NotRegularFileError("is a special file; not opened") from exc
        raise
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise NotRegularFileError("is not a regular file; not read")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, status


def _read_up_to(descriptor: int, limit: int) -> bytes:
    """Read at most ``limit`` bytes from the current position; stops early only at EOF."""
    blocks: list[bytes] = []
    remaining = limit
    while remaining > 0:
        block = os.read(descriptor, min(remaining, _READ_BLOCK))
        if not block:
            break
        blocks.append(block)
        remaining -= len(block)
    return b"".join(blocks)


def read_prefix(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    """Return the first ``max_bytes`` bytes of a regular file (all of a shorter one).

    Raises:
        ValueError: if ``max_bytes`` is negative.
        NotRegularFileError: if the path is not a regular file.
        OSError: if the file cannot be opened or read.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    descriptor, _status = open_regular(path)
    try:
        return _read_up_to(descriptor, max_bytes)
    finally:
        os.close(descriptor)


def digest_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    chunk: int = _DEFAULT_CHUNK,
    should_stop: Callable[[], str | None] | None = None,
) -> FileDigest:
    """Compute the SHA-256 of a regular file, reading no more than ``max_bytes``.

    A file larger than the cap is refused rather than partially hashed: a digest of the
    first part of a file identifies nothing. The declared size is checked first, so a
    sparse file that claims to be enormous costs nothing, and the bytes actually read are
    counted as well, in case the filesystem lies about the size.

    Args:
        path: the file.
        max_bytes: the largest file that will be hashed.
        chunk: read size; values above 16 MiB are reduced to it.
        should_stop: called before each read; a non-empty return value abandons the
            read and is raised as the reason.

    Returns:
        The digest in lowercase hex, and the number of bytes read.

    Raises:
        ValueError: if ``max_bytes`` is negative or ``chunk`` is not positive.
        FileTooLargeError: if the file exceeds ``max_bytes``.
        NotRegularFileError: if the path is not a regular file.
        ScanInterrupted: if ``should_stop`` asked for the read to end.
        OSError: if the file cannot be opened or read.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    if chunk <= 0:
        raise ValueError("chunk must be positive")
    block_size = min(chunk, _MAX_CHUNK)
    descriptor, status = open_regular(path)
    try:
        if status.st_size > max_bytes:
            raise FileTooLargeError(
                f"file is {status.st_size} bytes, over the limit of {max_bytes}"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            if should_stop is not None:
                reason = should_stop()
                if reason:
                    raise ScanInterrupted(reason)
            # One byte past the cap is enough to learn that the file is too large.
            block = os.read(descriptor, min(block_size, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise FileTooLargeError(f"file grew past the limit of {max_bytes} bytes")
            digest.update(block)
    finally:
        os.close(descriptor)
    return FileDigest(digest.hexdigest(), total)


def hash_file(path: str | os.PathLike[str], *, max_bytes: int, chunk: int = _DEFAULT_CHUNK) -> str:
    """Return the SHA-256 of a regular file in lowercase hex. See :func:`digest_file`.

    Raises:
        ValueError, FileTooLargeError, NotRegularFileError, OSError: as
            :func:`digest_file`.
    """
    return digest_file(path, max_bytes=max_bytes, chunk=chunk).sha256


def _describe(exc: OSError) -> str:
    """A short, path-free description of an OS error (the path is recorded separately)."""
    return exc.strerror or type(exc).__name__


def _is_within(path: str, root: str) -> bool:
    candidate, base = os.path.normcase(path), os.path.normcase(root)
    try:
        return os.path.commonpath([candidate, base]) == base
    except ValueError:
        # Different drives, or a mix of absolute and relative paths.
        return False


class Walk(Iterator[FileEntry]):
    """An in-progress walk: iterate it for entries, then read its counters.

    The object also carries the scan's shared budget. A caller that reads more from the
    volume (hashing, rule input) reports those bytes with :meth:`charge`, and asks
    :meth:`stop_reason` whether to carry on, so the walk and its consumer stop together.

    Attributes:
        files_seen: files and links yielded so far.
        dirs_seen: directories yielded so far.
        special_skipped: devices, FIFOs and sockets that were met and not opened.
        bytes_read: bytes read from the volume so far, including charged ones.
        issues: what could not be examined (at most ``limits.max_errors`` records).
        issues_dropped: further issues that were counted but not stored.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        limits: ScanLimits,
        *,
        cancel: threading.Event | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._root = os.fsdecode(root)
        self._limits = limits
        self._cancel = cancel
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._started = self._clock.monotonic()
        self._reasons: list[str] = []
        self._entries = 0
        self._dirs_met = 0
        self._visited: set[tuple[int, int]] = set()
        self._root_dev = 0
        self._root_real = ""
        self._dos_attributes_work = False
        self.files_seen = 0
        self.dirs_seen = 0
        self.special_skipped = 0
        self.bytes_read = 0
        self.issues: list[ScanIssue] = []
        self.issues_dropped = 0
        self._iterator = self._run()

    def __iter__(self) -> Walk:
        return self

    def __next__(self) -> FileEntry:
        return next(self._iterator)

    def close(self) -> None:
        """Stop the walk and release any open directory handle. Safe to call twice."""
        self._iterator.close()

    @property
    def truncated(self) -> bool:
        """True if a limit or a cancellation kept the walk from examining everything."""
        return bool(self._reasons)

    @property
    def truncation_reasons(self) -> tuple[str, ...]:
        """The limits that were hit, in the order they were hit."""
        return tuple(self._reasons)

    @property
    def truncated_reason(self) -> str | None:
        """:attr:`truncation_reasons` as one comma-separated string, or ``None``."""
        return ", ".join(self._reasons) if self._reasons else None

    @property
    def remaining_bytes(self) -> int:
        """How much of the byte budget is left."""
        return max(0, self._limits.max_bytes - self.bytes_read)

    def elapsed(self) -> float:
        """Seconds since the walk was created, on the injected clock."""
        return self._clock.monotonic() - self._started

    def charge(self, count: int) -> None:
        """Count ``count`` bytes read by the caller against the byte budget."""
        self.bytes_read += max(0, count)

    def stop_reason(self) -> str | None:
        """Why reading should stop now, or ``None`` to carry on.

        ``cancelled`` if the cancel event is set, ``max_seconds`` if the time budget is
        spent, ``max_bytes`` if the byte budget is spent.
        """
        if self._cancel is not None and self._cancel.is_set():
            return "cancelled"
        if self.elapsed() >= self._limits.max_seconds:
            return "max_seconds"
        if self.bytes_read >= self._limits.max_bytes:
            return "max_bytes"
        return None

    def note_truncated(self, reason: str) -> None:
        """Record that ``reason`` kept part of the volume from being examined."""
        if reason not in self._reasons:
            self._reasons.append(reason)

    def record_issue(
        self, source: str, path: str, message: str, kind: IssueKind = IssueKind.UNREAD
    ) -> None:
        """Record something that could not be examined, within the ``max_errors`` cap.

        A failure of the scan as a whole (kind ``failed``) is always kept.
        """
        if kind is IssueKind.UNREAD and len(self.issues) >= self._limits.max_errors:
            self.issues_dropped += 1
            return
        self.issues.append(ScanIssue(source, path, message, kind))

    # -- the walk itself ------------------------------------------------------------

    def _run(self) -> Iterator[FileEntry]:
        # Absolute from the start, so a later change of working directory cannot move it.
        root_os = _extended_path(self._root) if _IS_WINDOWS else os.path.abspath(self._root)
        try:
            # The root is followed if it is itself a link: naming it was the caller's
            # decision. Nothing below it is followed without the containment checks.
            root_status = os.stat(root_os)
        except (OSError, ValueError) as exc:
            reason = _describe(exc) if isinstance(exc, OSError) else str(exc)
            self.record_issue("walk", "", f"cannot read the scan root: {reason}", IssueKind.FAILED)
            return
        if not stat.S_ISDIR(root_status.st_mode):
            self.record_issue("walk", "", "the scan root is not a directory", IssueKind.FAILED)
            return
        self._root_dev = root_status.st_dev
        if root_status.st_ino:
            self._visited.add((root_status.st_dev, root_status.st_ino))
        if self._limits.follow_symlinks:
            self._root_real = os.path.realpath(root_os)
        self._dos_attributes_work = self._probe_dos_attributes(root_os)

        pending: deque[tuple[str, str, int]] = deque([(root_os, "", 0)])
        self._dirs_met = 1
        while pending:
            dir_os, dir_rel, depth = pending.popleft()
            if dir_rel and not self._may_enter(dir_os, dir_rel):
                continue
            try:
                listing = os.scandir(dir_os)
            except OSError as exc:
                self._unreadable(dir_rel, exc, fatal=not dir_rel)
                continue
            with listing:
                while True:
                    reason = self.stop_reason()
                    if reason is not None:
                        self.note_truncated(reason)
                        return
                    try:
                        item = next(listing)
                    except StopIteration:
                        break
                    except OSError as exc:
                        self._unreadable(dir_rel, exc, fatal=False)
                        break
                    rel = f"{dir_rel}/{item.name}" if dir_rel else item.name
                    try:
                        status = item.stat(follow_symlinks=False)
                    except OSError as exc:
                        self._unreadable(rel, exc, fatal=False)
                        continue
                    is_link = stat.S_ISLNK(status.st_mode) or _is_reparse_point(status)
                    is_dir = not is_link and stat.S_ISDIR(status.st_mode)
                    if not is_dir:
                        # Tested before the file is opened, and only once there is a
                        # further entry to refuse, so a volume holding exactly max_files
                        # files is read in full and is not called truncated.
                        if self._entries >= self._limits.max_files:
                            self.note_truncated("max_files")
                            return
                        self._entries += 1

                    entry: FileEntry | None
                    descend: str | None = None
                    if is_link:
                        entry, descend = self._link_entry(item.path, rel, status)
                    elif is_dir:
                        entry, descend = self._dir_entry(item.path, rel, status), item.path
                    elif stat.S_ISREG(status.st_mode):
                        entry = self._file_entry(item.path, rel, status)
                    else:
                        entry = None
                    if entry is None:
                        # A device, FIFO or socket: counted, never opened.
                        self.special_skipped += 1
                        continue

                    if descend is not None:
                        # Every directory met counts, including one too deep to enter:
                        # otherwise a directory at the depth limit could hold any number
                        # of subdirectories and none of the limits would ever apply.
                        if self._dirs_met >= self._limits.max_dirs:
                            self.note_truncated("max_dirs")
                            return
                        self._dirs_met += 1
                        if depth + 1 > self._limits.max_depth:
                            self.note_truncated("max_depth")
                        else:
                            pending.append((descend, rel, depth + 1))
                    if entry.is_dir:
                        self.dirs_seen += 1
                    else:
                        self.files_seen += 1
                    yield entry

    def _unreadable(self, rel: str, exc: OSError, *, fatal: bool) -> None:
        if fatal:
            self.record_issue(
                "walk", rel, f"cannot list the scan root: {_describe(exc)}", IssueKind.FAILED
            )
        else:
            self.record_issue("walk", rel, f"not examined: {_describe(exc)}")

    def _may_enter(self, dir_os: str, rel: str) -> bool:
        """Decide, at the moment of entering, whether a queued directory is walked."""
        try:
            status = os.lstat(dir_os)
        except OSError as exc:
            self._unreadable(rel, exc, fatal=False)
            return False
        if not stat.S_ISDIR(status.st_mode) or _is_reparse_point(status):
            self.record_issue("walk", rel, "changed while it was being scanned; not entered")
            return False
        if status.st_dev != self._root_dev:
            self.record_issue("walk", rel, "is on a different filesystem; not entered")
            return False
        if status.st_ino:
            identity = (status.st_dev, status.st_ino)
            if identity in self._visited:
                if not self._limits.follow_symlinks:
                    # Without links a directory can only be reached twice on a
                    # filesystem that is corrupt or crafted. Say so.
                    self.record_issue("walk", rel, "directory loop on the volume; not re-entered")
                return False
            self._visited.add(identity)
        return True

    def _dir_entry(self, os_path: str, rel: str, status: os.stat_result) -> FileEntry:
        dos = self._dos_attributes_of_dir(os_path) if self._dos_attributes_work else None
        hidden, system, read_only = _attributes(rel, status, dos)
        return FileEntry(
            path=rel,
            os_path=os_path,
            mtime=status.st_mtime,
            is_dir=True,
            hidden=hidden,
            system=system,
            read_only=read_only,
        )

    def _file_entry(self, os_path: str, rel: str, status: os.stat_result) -> FileEntry | None:
        """Build the entry for a regular file, reading its head. ``None`` if it is not one."""
        size, mtime = status.st_size, status.st_mtime
        head = b""
        dos: int | None = None
        opened_ok = False
        try:
            descriptor, opened = open_regular(os_path)
        except NotRegularFileError:
            # It was a regular file when listed and is not one now. Treat it as the
            # special file it has become: counted, not opened.
            return None
        except OSError as exc:
            self._unreadable(rel, exc, fatal=False)
        else:
            try:
                size, mtime = opened.st_size, opened.st_mtime
                head = _read_up_to(descriptor, HEAD_BYTES)
                self.bytes_read += len(head)
                if self._dos_attributes_work:
                    dos = _dos_attributes(descriptor)
                opened_ok = True
            except OSError as exc:
                self._unreadable(rel, exc, fatal=False)
                head = b""
            finally:
                os.close(descriptor)
        hidden, system, read_only = _attributes(rel, status, dos)
        return FileEntry(
            path=rel,
            os_path=os_path,
            size=size,
            mtime=mtime,
            hidden=hidden,
            system=system,
            read_only=read_only,
            extension=extension_of(rel.rpartition("/")[2]),
            head=head,
            opened=opened_ok,
        )

    def _link_entry(
        self, os_path: str, rel: str, status: os.stat_result
    ) -> tuple[FileEntry, str | None]:
        """Build the entry for a link, and say which directory (if any) to descend into."""
        hidden, system, read_only = _attributes(rel, status, None)
        unfollowed = FileEntry(
            path=rel,
            os_path=os_path,
            size=status.st_size,
            mtime=status.st_mtime,
            is_symlink=True,
            hidden=hidden,
            system=system,
            read_only=read_only,
            extension=extension_of(rel.rpartition("/")[2]),
        )
        if not self._limits.follow_symlinks:
            return unfollowed, None
        try:
            real = os.path.realpath(os_path, strict=True)
            target = os.stat(real)
        except (OSError, ValueError):
            # Broken, looping, or not resolvable: there is nothing to follow.
            return unfollowed, None
        if not _is_within(real, self._root_real) or target.st_dev != self._root_dev:
            return unfollowed, None
        if stat.S_ISDIR(target.st_mode):
            followed = FileEntry(
                path=rel,
                os_path=real,
                mtime=target.st_mtime,
                is_dir=True,
                is_symlink=True,
                hidden=hidden,
                system=system,
                read_only=read_only,
            )
            return followed, real
        if stat.S_ISREG(target.st_mode):
            entry = self._file_entry(real, rel, target)
            if entry is not None:
                return _as_link(entry), None
        return unfollowed, None

    # -- DOS attributes on Linux ----------------------------------------------------

    def _probe_dos_attributes(self, root_os: str) -> bool:
        """True if the scanned filesystem answers the FAT attribute query (Linux only)."""
        return _IS_LINUX and self._dos_attributes_of_dir(root_os) is not None

    @staticmethod
    def _dos_attributes_of_dir(os_path: str) -> int | None:
        try:
            descriptor = os.open(os_path, _DIR_OPEN_FLAGS)
        except OSError:
            return None
        try:
            return _dos_attributes(descriptor)
        finally:
            os.close(descriptor)


def _as_link(entry: FileEntry) -> FileEntry:
    return FileEntry(
        path=entry.path,
        os_path=entry.os_path,
        size=entry.size,
        mtime=entry.mtime,
        is_symlink=True,
        hidden=entry.hidden,
        system=entry.system,
        read_only=entry.read_only,
        extension=entry.extension,
        head=entry.head,
        opened=entry.opened,
    )


def _dos_attributes(descriptor: int) -> int | None:
    """The DOS attribute byte of an open file on a FAT or exFAT volume, on Linux.

    Returns ``None`` anywhere else: on other platforms, and on filesystems that do not
    implement the query (they answer ``ENOTTY``).
    """
    if not _IS_LINUX:
        return None
    try:
        import fcntl
    except ImportError:
        return None
    buffer = bytearray(4)
    try:
        fcntl.ioctl(descriptor, _FAT_IOCTL_GET_ATTRIBUTES, buffer, True)
    except OSError:
        return None
    return int(struct.unpack("=I", buffer)[0])


def _attributes(
    rel: str, status: os.stat_result, dos: int | None
) -> tuple[bool | None, bool | None, bool | None]:
    """``(hidden, system, read_only)`` from whatever the platform exposes."""
    if _IS_WINDOWS:
        bits = getattr(status, "st_file_attributes", 0)
        return (
            bool(bits & stat.FILE_ATTRIBUTE_HIDDEN),
            bool(bits & stat.FILE_ATTRIBUTE_SYSTEM),
            bool(bits & stat.FILE_ATTRIBUTE_READONLY),
        )
    dotted = rel.rpartition("/")[2].startswith(".")
    if dos is None:
        return dotted, None, None
    return (
        dotted or bool(dos & _DOS_HIDDEN),
        bool(dos & _DOS_SYSTEM),
        bool(dos & _DOS_READ_ONLY),
    )


def walk(
    root: str | os.PathLike[str],
    limits: ScanLimits,
    *,
    cancel: threading.Event | None = None,
    clock: Clock | None = None,
) -> Walk:
    """Walk ``root`` breadth-first within ``limits``, yielding a :class:`FileEntry` each.

    Nothing is read until the result is iterated. Problems with individual files and
    directories never raise: they are recorded on the returned :class:`Walk`, which also
    reports whether a limit was hit and why. A root that cannot be read at all yields
    nothing and records an issue of kind ``failed``.

    Args:
        root: the directory to scan, typically a volume's mount point.
        limits: the bounds on the walk.
        cancel: set this event from another thread to stop the walk at the next entry.
        clock: time source for ``max_seconds``; the system clock if omitted.

    Returns:
        An iterator of entries that also exposes the walk's counters and issues.
    """
    return Walk(root, limits, cancel=cancel, clock=clock)
