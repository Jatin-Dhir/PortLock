"""The seams between PortLock's enforcement logic and the operating system.

Every privileged operating-system access the enforcers, the lockdown manager and
``portlock doctor`` make goes through one of the small interfaces defined here
(``docs/DESIGN.md`` section 6, ``docs/ARCHITECTURE.md`` section 2.2 E1):

==================  ======================================================================
``SysfsIO``         read and write sysfs attributes (Linux)
``BlockIO``         the ``BLKROGET`` / ``BLKROSET`` ioctls on a block device node (Linux)
``RuleFileIO``      the udev rules file PortLock generates (Linux)
``RegistryIO``      policy values under ``HKEY_LOCAL_MACHINE`` (Windows)
``CfgMgrAPI``       the Configuration Manager calls that disable, enable and eject (Windows)
``DiskIO``          the per-disk read-only attribute (Windows)
``CommandRunner``   run a program with an argument list and a timeout
``ExternalTimer``   a one-shot operating-system timer that outlives PortLock (14.16)
``DirPrivacy``      make and check a private directory (14.18)
==================  ======================================================================

Each interface has three kinds of implementation in this module:

* the **real** one, used when PortLock is installed. Real implementations import their
  platform modules (``fcntl``, ``winreg``, the Windows DLLs) only when first used, so
  this module imports on every platform. The test suite never calls a real
  implementation that changes anything; where one shells out, the command lines it
  builds and the output it parses are tested through :class:`FakeCommandRunner`;
* a **fake** (``Fake*``) that keeps the operating-system state in memory, records every
  call and can inject the failures the enforcement documents list. The enforcement logic
  runs unmodified against the fakes, on Windows and on Linux alike;
* the shared value types (:class:`CommandResult`, :class:`RegValue`,
  :class:`PrivacyReport`, :class:`MechanismStatus`) and :class:`ChangeRecorder`, the
  write-ahead helper both enforcers use.

Errors: real and fake seams report operating-system failures as :class:`OSError` with the
``errno`` the operating system would give (``ENOENT`` for a device that has gone,
``EACCES`` without privilege, ``EROFS`` for a read-only sysfs). The Configuration Manager
seam returns ``CONFIGRET`` codes instead, as the API does. Timer and directory-privacy
failures raise :class:`~portlock.core.errors.EnforcementError`.
"""

from __future__ import annotations

import contextlib
import csv
import ctypes
import errno
import io
import json
import os
import posixpath
import re
import stat
import struct
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from xml.sax.saxutils import escape as xml_escape

from portlock.core.errors import EnforcementError
from portlock.core.fsutil import atomic_write_bytes, atomic_write_text
from portlock.core.models import sanitize_device_text
from portlock.guard.base import JournalEntry

__all__ = [
    "MAX_COMMAND_TIMEOUT",
    "REG_DWORD",
    "REG_MULTI_SZ",
    "REG_SZ",
    "BlockIO",
    "CfgMgrAPI",
    "ChangeRecorder",
    "CommandResult",
    "CommandRunner",
    "DirPrivacy",
    "DiskIO",
    "ExternalTimer",
    "FakeBlockIO",
    "FakeCfgMgr",
    "FakeCommandRunner",
    "FakeDevNode",
    "FakeDirPrivacy",
    "FakeDisks",
    "FakeExternalTimer",
    "FakeRegistry",
    "FakeRuleFiles",
    "FakeSysfs",
    "IcaclsDirPrivacy",
    "JournalUnavailable",
    "MechanismStatus",
    "PosixDirPrivacy",
    "PrivacyReport",
    "RealBlockIO",
    "RealRuleFiles",
    "RealSysfs",
    "RegValue",
    "RegistryIO",
    "RuleFileIO",
    "ScheduledTaskTimer",
    "SubprocessRunner",
    "SysfsIO",
    "SystemdRunTimer",
    "TimerError",
    "WinCfgMgr",
    "WinDisks",
    "WinRegistry",
    "current_process_privileged",
    "encode_reg",
    "parse_icacls_output",
    "parse_schtasks_query",
    "scheduled_task_xml",
    "validate_timer_name",
]

# --------------------------------------------------------------------------------------
# Shared value types
# --------------------------------------------------------------------------------------

#: Registry value types PortLock reads and writes (winnt.h).
REG_SZ = 1
REG_DWORD = 4
REG_MULTI_SZ = 7
_REG_PREFIX = {REG_SZ: "sz", REG_DWORD: "dword", REG_MULTI_SZ: "multi_sz"}
_REG_TYPES = {prefix: kind for kind, prefix in _REG_PREFIX.items()}
_DWORD_MAX = 0xFFFFFFFF
_MAX_REG_TEXT = 1024

#: Output kept from a command, per stream. Enough for every command PortLock runs.
_MAX_OUTPUT_CHARS = 64 * 1024
#: Upper bound on any command's timeout (ARCHITECTURE 2.2 E8: no call blocks for long).
MAX_COMMAND_TIMEOUT = 10.0


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What a program run through a :class:`CommandRunner` did.

    Attributes:
        returncode: the exit status; ``-1`` if the program timed out or could not start.
        stdout / stderr: decoded output, capped at 64 KiB each.
        timed_out: True if the program was stopped because it ran past its timeout.
    """

    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True if the program ran to completion and exited with status 0."""
        return self.returncode == 0 and not self.timed_out

    def describe(self) -> str:
        """One line for an error message: the status and the first line of output."""
        if self.timed_out:
            return "timed out"
        text = (self.stderr or self.stdout).strip().splitlines()
        first = sanitize_device_text(text[0], limit=200) if text else None
        return f"exit status {self.returncode}" + (f": {first}" if first else "")


@dataclass(frozen=True, slots=True)
class RegValue:
    """One registry value: its type and its data.

    ``REG_DWORD`` data is an ``int`` from 0 to 0xFFFFFFFF, ``REG_SZ`` a ``str``,
    ``REG_MULTI_SZ`` a tuple of ``str``. Other types are not handled by PortLock.

    Raises:
        ValueError: if the type is not one of the three or the data does not fit it.
    """

    type: int
    data: int | str | tuple[str, ...]

    def __post_init__(self) -> None:
        if self.type == REG_DWORD:
            data = self.data
            if isinstance(data, bool) or not isinstance(data, int) or not 0 <= data <= _DWORD_MAX:
                raise ValueError(f"REG_DWORD data must be 0..0xFFFFFFFF, got {data!r}")
        elif self.type == REG_SZ:
            if not isinstance(self.data, str) or "\x00" in self.data:
                raise ValueError("REG_SZ data must be a string without NUL characters")
            if len(self.data) > _MAX_REG_TEXT:
                raise ValueError("REG_SZ data is longer than PortLock handles")
        elif self.type == REG_MULTI_SZ:
            if isinstance(self.data, str) or not isinstance(self.data, tuple | list):
                raise ValueError("REG_MULTI_SZ data must be a sequence of strings")
            items = tuple(self.data)
            for item in items:
                if not isinstance(item, str) or "\x00" in item or len(item) > _MAX_REG_TEXT:
                    raise ValueError("REG_MULTI_SZ items must be strings without NUL characters")
            object.__setattr__(self, "data", items)
        else:
            raise ValueError(f"unsupported registry value type {self.type!r}")

    @classmethod
    def dword(cls, value: int) -> RegValue:
        return cls(REG_DWORD, value)

    @classmethod
    def sz(cls, value: str) -> RegValue:
        return cls(REG_SZ, value)

    def encode(self) -> str:
        """The journal form: ``dword:1``, ``sz:<text>`` or ``multi_sz:<JSON list>``.

        Type and data are both kept, so restoring puts back exactly the value that was
        there, type included.
        """
        prefix = _REG_PREFIX[self.type]
        if self.type == REG_MULTI_SZ:
            return f"{prefix}:{json.dumps(list(self.data), ensure_ascii=True)}"
        return f"{prefix}:{self.data}"

    @classmethod
    def decode(cls, text: str) -> RegValue:
        """Parse :meth:`encode` output.

        Raises:
            ValueError: if ``text`` is not in that form.
        """
        if not isinstance(text, str):
            raise ValueError("an encoded registry value must be a string")
        prefix, colon, body = text.partition(":")
        if not colon or prefix not in _REG_TYPES:
            raise ValueError(f"not an encoded registry value: {text[:40]!r}")
        kind = _REG_TYPES[prefix]
        if kind == REG_DWORD:
            if not re.fullmatch(r"[0-9]{1,10}", body):
                raise ValueError(f"not a REG_DWORD value: {body[:40]!r}")
            return cls(REG_DWORD, int(body))
        if kind == REG_SZ:
            return cls(REG_SZ, body)
        try:
            items = json.loads(body)
        except ValueError as exc:
            raise ValueError("REG_MULTI_SZ value is not a JSON list") from exc
        if not isinstance(items, list):
            raise ValueError("REG_MULTI_SZ value is not a JSON list")
        return cls(REG_MULTI_SZ, tuple(items))


def encode_reg(value: RegValue | None) -> str | None:
    """:meth:`RegValue.encode`, with ``None`` (value absent) passed through."""
    return None if value is None else value.encode()


@dataclass(frozen=True, slots=True)
class PrivacyReport:
    """Whether a directory is private, and if not, why.

    Attributes:
        path: the directory that was checked.
        private: True only if every check passed.
        problems: one sentence per failed check; empty when ``private``.
    """

    path: str
    private: bool
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "private": self.private, "problems": list(self.problems)}


@dataclass(frozen=True, slots=True)
class MechanismStatus:
    """Whether one enforcement mechanism can be used on this machine right now.

    Attributes:
        role: what the mechanism does for PortLock: ``block``, ``eject``,
            ``default_deny``, ``read_only`` or ``baseline_read_only``.
        mechanism: its stable identifier (ARCHITECTURE 2.2 E13).
        available: True only if the mechanism exists *and* this process may use it.
        tier: what it really guarantees, in words (DESIGN 14.14).
        reason: why it is unavailable; empty when available.
    """

    role: str
    mechanism: str
    available: bool
    tier: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "mechanism": self.mechanism,
            "available": self.available,
            "tier": self.tier,
            "reason": self.reason,
        }


class JournalUnavailable(EnforcementError):
    """The write-ahead hook refused an entry, so the change it describes was not made."""

    code = "journal_unavailable"


class TimerError(EnforcementError):
    """A one-shot operating-system timer could not be armed, cancelled or queried."""

    code = "timer_error"


class ChangeRecorder:
    """Write-ahead journaling for one enforcement call (ARCHITECTURE 2.2 E2 and E3).

    :meth:`apply` hands the entry to the write-ahead hook *before* making the change and
    records it as undoable only once the change was made. If the hook raises, the change
    is not made and :class:`JournalUnavailable` is raised; if the change itself fails,
    its exception propagates and the entry is not recorded. :attr:`undo` therefore lists
    exactly the changes that happened, in the order made, also after a failure part way.
    """

    def __init__(self, write_ahead: Callable[[JournalEntry], None] | None) -> None:
        self._write_ahead = write_ahead
        self.undo: list[JournalEntry] = []

    def apply(self, entry: JournalEntry, change: Callable[[], None]) -> None:
        """Journal ``entry`` ahead, then make ``change``.

        Raises:
            JournalUnavailable: if the write-ahead hook raised; nothing was changed.
        """
        if self._write_ahead is not None:
            try:
                self._write_ahead(entry)
            except Exception as exc:
                raise JournalUnavailable(
                    f"journal unavailable: {type(exc).__name__}: {exc}"
                ) from exc
        change()
        self.undo.append(entry)


# --------------------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------------------


@runtime_checkable
class SysfsIO(Protocol):
    """Access to sysfs (and to other plain files the Linux enforcer only looks at).

    Paths are POSIX paths. ``write_text`` never creates a file: sysfs attributes exist
    or they do not.
    """

    def read_text(self, path: str) -> str:
        """The attribute's content, stripped. Raises ``OSError``."""
        ...

    def write_text(self, path: str, value: str) -> None:
        """Write ``value`` to an existing attribute. Raises ``OSError``."""
        ...

    def exists(self, path: str) -> bool:
        """True if something is at ``path`` (a dangling symbolic link counts)."""
        ...

    def listdir(self, path: str) -> list[str]:
        """The names in a directory, sorted. Raises ``OSError``."""
        ...

    def realpath(self, path: str) -> str:
        """``path`` with every symbolic link resolved, like ``os.path.realpath``."""
        ...

    def writable(self, path: str) -> bool:
        """True if this process may write ``path`` now (``access(W_OK)``)."""
        ...


@runtime_checkable
class BlockIO(Protocol):
    """The read-only flag of a block device node: ``BLKROGET`` and ``BLKROSET``."""

    @property
    def available(self) -> bool:
        """True if the ioctls exist on this platform."""
        ...

    def get_read_only(self, node: str) -> bool:
        """Raises ``OSError`` (``ENOENT`` when the node has gone)."""
        ...

    def set_read_only(self, node: str, read_only: bool) -> None:
        """Raises ``OSError``."""
        ...


@runtime_checkable
class RuleFileIO(Protocol):
    """The udev rules file PortLock writes."""

    def read(self, path: str) -> str | None:
        """The file's text, or ``None`` if it does not exist. Raises ``OSError``."""
        ...

    def write(self, path: str, text: str) -> None:
        """Replace the file atomically (mode 0644). Raises ``OSError``."""
        ...

    def remove(self, path: str) -> None:
        """Delete the file; an absent file is not an error. Raises ``OSError``."""
        ...

    def dir_writable(self, directory: str) -> bool:
        """True if ``directory`` exists and this process may create files in it."""
        ...


@runtime_checkable
class CommandRunner(Protocol):
    """Runs a program. Always an argument list, never a shell string (E8)."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        """Run ``argv`` and wait at most ``timeout`` seconds. Never raises for the
        program's own failure: that is in the result."""
        ...


@runtime_checkable
class RegistryIO(Protocol):
    """Values under ``HKEY_LOCAL_MACHINE``. Keys are given without the hive."""

    @property
    def available(self) -> bool: ...

    def get(self, key: str, name: str) -> RegValue | None:
        """The value, or ``None`` if the key or value is absent. Raises ``OSError``, and
        ``ValueError`` for a value of a type PortLock does not handle."""
        ...

    def set(self, key: str, name: str, value: RegValue) -> None:
        """Write the value, creating the key if needed. Raises ``OSError``."""
        ...

    def delete(self, key: str, name: str) -> None:
        """Remove the value; an absent value is not an error. Raises ``OSError``."""
        ...

    def values(self, key: str) -> dict[str, RegValue]:
        """Every value of ``key`` PortLock can read; empty if the key is absent."""
        ...


@runtime_checkable
class CfgMgrAPI(Protocol):
    """Configuration Manager calls. Every method returns a ``CONFIGRET`` first."""

    @property
    def available(self) -> bool: ...

    def locate(self, instance_id: str, *, phantom: bool) -> tuple[int, int]:
        """``CM_Locate_DevNodeW``: ``(cr, devinst)``. ``phantom`` finds a node whose
        device is not connected."""
        ...

    def status(self, devinst: int) -> tuple[int, int, int]:
        """``CM_Get_DevNode_Status``: ``(cr, status flags, problem code)``."""
        ...

    def disable(self, devinst: int, *, persist: bool) -> int:
        """``CM_Disable_DevNode`` with ``CM_DISABLE_UI_NOT_OK`` and, if ``persist``,
        ``CM_DISABLE_PERSIST``."""
        ...

    def enable(self, devinst: int) -> int:
        """``CM_Enable_DevNode``."""
        ...

    def request_eject(self, devinst: int) -> tuple[int, int, str]:
        """``CM_Request_Device_EjectW`` with a veto buffer: ``(cr, veto type, veto name)``."""
        ...

    def reenumerate(self, devinst: int) -> int:
        """``CM_Reenumerate_DevNode``, asynchronous."""
        ...


@runtime_checkable
class DiskIO(Protocol):
    """The per-disk read-only attribute of the disks a USB device exposes."""

    @property
    def available(self) -> bool: ...

    def disk_numbers(self, instance_id: str) -> list[int]:
        """The ``PhysicalDriveN`` numbers of the device's disks; empty if it has none
        right now (blocked, no medium, not storage). Raises ``OSError``."""
        ...

    def get_read_only(self, disk: int) -> bool:
        """Raises ``OSError`` (``ENOENT`` when the disk has gone)."""
        ...

    def set_read_only(self, disk: int, read_only: bool) -> None:
        """Set or clear the attribute, not persisted across restarts. Raises ``OSError``."""
        ...


@runtime_checkable
class ExternalTimer(Protocol):
    """A one-shot operating-system timer that runs a command at a set time (DESIGN 14.16).

    It outlives the PortLock process: it is armed when default-deny or lockdown is
    engaged, runs ``portlock recover`` at expiry, and is cancelled on lift or renewal.
    """

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        """Arm (or re-arm, replacing) timer ``name`` to run ``argv`` at ``at``.

        Raises:
            TimerError: if the operating system refused.
            ValueError: if the name, time or command is malformed.
        """
        ...

    def cancel(self, name: str) -> None:
        """Disarm timer ``name``; an unknown timer is not an error. Raises ``TimerError``."""
        ...

    def is_armed(self, name: str) -> bool:
        """True if timer ``name`` is armed. Raises ``TimerError``."""
        ...


@runtime_checkable
class DirPrivacy(Protocol):
    """Make a directory private to PortLock, and check that it is (DESIGN 14.18)."""

    def ensure_private(self, path: str | os.PathLike[str]) -> None:
        """Create ``path`` if missing and restrict it to the service's own account and
        administrators. Raises ``EnforcementError`` if it cannot be made private."""
        ...

    def check(self, path: str | os.PathLike[str]) -> PrivacyReport:
        """Report whether ``path`` is private. Never changes anything; never raises."""
        ...


# --------------------------------------------------------------------------------------
# Privilege
# --------------------------------------------------------------------------------------


def current_process_privileged() -> bool:
    """True if this process runs as root (POSIX) or as an administrator (Windows)."""
    if sys.platform == "win32":
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            return False
        try:
            shell32 = loader("shell32.dll", use_last_error=True, winmode=_SEARCH_SYSTEM32)
            return bool(shell32.IsUserAnAdmin())
        except (OSError, AttributeError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


# --------------------------------------------------------------------------------------
# Real implementations: Linux
# --------------------------------------------------------------------------------------

_MAX_ATTRIBUTE_BYTES = 4096
_MAX_RULE_FILE_BYTES = 64 * 1024
# linux/fs.h: _IO(0x12, 93) and _IO(0x12, 94).
_BLKROSET = 0x125D
_BLKROGET = 0x125E


class RealSysfs:
    """:class:`SysfsIO` on the real filesystem."""

    def read_text(self, path: str) -> str:
        with open(path, "rb") as stream:
            data = stream.read(_MAX_ATTRIBUTE_BYTES)
        return data.decode("ascii", errors="replace").strip()

    def write_text(self, path: str, value: str) -> None:
        # No O_CREAT: a sysfs attribute that does not exist must not be created as a
        # file (and outside sysfs nothing may be created at all). O_NOFOLLOW refuses a
        # symbolic link as the last component, so a path validated as canonical cannot
        # be swapped for a link between validation and write.
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            os.write(descriptor, value.encode("ascii"))
        finally:
            os.close(descriptor)

    def exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def listdir(self, path: str) -> list[str]:
        return sorted(os.listdir(path))

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def writable(self, path: str) -> bool:
        return os.access(path, os.W_OK)


class RealBlockIO:
    """:class:`BlockIO` through ``fcntl.ioctl`` (Linux only)."""

    @property
    def available(self) -> bool:
        return sys.platform.startswith("linux")

    def get_read_only(self, node: str) -> bool:
        import fcntl  # Linux only; imported here so this module imports everywhere

        descriptor = self._open(node)
        try:
            buffer = bytearray(struct.pack("i", 0))
            fcntl.ioctl(descriptor, _BLKROGET, buffer, True)
            return struct.unpack("i", bytes(buffer))[0] != 0
        finally:
            os.close(descriptor)

    def set_read_only(self, node: str, read_only: bool) -> None:
        import fcntl

        descriptor = self._open(node)
        try:
            fcntl.ioctl(descriptor, _BLKROSET, struct.pack("i", 1 if read_only else 0))
        finally:
            os.close(descriptor)

    @staticmethod
    def _open(node: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(node, flags)
        try:
            if not stat.S_ISBLK(os.fstat(descriptor).st_mode):
                raise OSError(errno.ENOTBLK, "not a block device", node)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor


class RealRuleFiles:
    """:class:`RuleFileIO` on the real filesystem."""

    def read(self, path: str) -> str | None:
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                return stream.read(_MAX_RULE_FILE_BYTES)
        except FileNotFoundError:
            return None

    def write(self, path: str, text: str) -> None:
        atomic_write_text(path, text, private=False)
        # udev reads rules as root; 0644 is the conventional mode for rules files.
        os.chmod(path, 0o644)

    def remove(self, path: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)

    def dir_writable(self, directory: str) -> bool:
        return os.path.isdir(directory) and os.access(directory, os.W_OK)


class SubprocessRunner:
    """:class:`CommandRunner` with :mod:`subprocess`: no shell, no console window, stdin
    closed, output captured and capped, the timeout capped at 10 seconds."""

    def __init__(self, *, env: Mapping[str, str] | None = None) -> None:
        self._env = dict(env) if env is not None else None

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        arguments = _check_argv(argv)
        limit = min(max(float(timeout), 0.1), MAX_COMMAND_TIMEOUT)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        try:
            completed = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=limit,
                check=False,
                shell=False,
                env=self._env,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(-1, _decode(exc.stdout), _decode(exc.stderr), timed_out=True)
        except OSError as exc:
            return CommandResult(-1, "", f"cannot run {arguments[0]}: {exc.strerror or exc}")
        return CommandResult(
            completed.returncode, _decode(completed.stdout), _decode(completed.stderr)
        )


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else raw.decode(_console_encoding(), errors="replace")
    return text[:_MAX_OUTPUT_CHARS]


def _console_encoding() -> str:
    # Windows console tools write their output in the OEM code page when it is piped.
    return "oem" if sys.platform == "win32" else "utf-8"


def _check_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, str | bytes):
        raise TypeError("argv must be a sequence of arguments, not a single string")
    arguments = list(argv)
    if not arguments:
        raise ValueError("argv must name a program")
    for argument in arguments:
        if not isinstance(argument, str) or "\x00" in argument:
            raise ValueError("every argument must be a string without NUL characters")
    return arguments


# --------------------------------------------------------------------------------------
# Real implementations: Windows (ctypes and winreg, loaded on first use)
# --------------------------------------------------------------------------------------

# Restrict the DLL search to System32: a privileged agent must not load a planted DLL.
_SEARCH_SYSTEM32 = 0x00000800
_HKLM_PREFIX = "HKLM\\"

# cfgmgr32.h
_CM_LOCATE_DEVNODE_NORMAL = 0x0
_CM_LOCATE_DEVNODE_PHANTOM = 0x1
_CM_DISABLE_UI_NOT_OK = 0x4
_CM_DISABLE_PERSIST = 0x8
_CM_REENUMERATE_NORMAL = 0x0
_VETO_NAME_CHARS = 260

# winioctl.h; values from the header, see docs/enforcement/windows.md section 9.
_IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x000700F0
_IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F4
_DISK_ATTRIBUTE_READ_ONLY = 0x2
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ_WRITE = 0x3
_OPEN_EXISTING = 3
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_ACCESS_DENIED = 5
# SET_DISK_ATTRIBUTES: DWORD Version; BOOLEAN Persist; BYTE Reserved1[3];
# DWORDLONG Attributes; DWORDLONG AttributesMask; DWORD Reserved2[4]  (40 bytes)
_SET_DISK_ATTRIBUTES = struct.Struct("<I?3xQQ16x")
# GET_DISK_ATTRIBUTES: DWORD Version; DWORD Reserved1; DWORDLONG Attributes  (16 bytes)
_GET_DISK_ATTRIBUTES = struct.Struct("<IIQ")


def _win_loader() -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    if sys.platform != "win32" or loader is None:
        raise OSError(errno.ENOSYS, "the Windows API is not available on this platform")
    return loader


class WinCfgMgr:
    """:class:`CfgMgrAPI` over ``cfgmgr32.dll``. Loads the DLL on first use."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._library: Any | None = None

    @property
    def available(self) -> bool:
        try:
            self._cfgmgr()
        except OSError:
            return False
        return True

    def _cfgmgr(self) -> Any:
        with self._lock:
            if self._library is None:
                library = _win_loader()(
                    "cfgmgr32.dll", use_last_error=True, winmode=_SEARCH_SYSTEM32
                )
                dword = ctypes.c_uint32
                pointer = ctypes.POINTER(dword)
                prototypes: dict[str, tuple[tuple[Any, ...], Any]] = {
                    "CM_Locate_DevNodeW": ((pointer, ctypes.c_wchar_p, dword), dword),
                    "CM_Get_DevNode_Status": ((pointer, pointer, dword, dword), dword),
                    "CM_Disable_DevNode": ((dword, dword), dword),
                    "CM_Enable_DevNode": ((dword, dword), dword),
                    "CM_Request_Device_EjectW": (
                        (dword, ctypes.POINTER(ctypes.c_int), ctypes.c_wchar_p, dword, dword),
                        dword,
                    ),
                    "CM_Reenumerate_DevNode": ((dword, dword), dword),
                }
                try:
                    for name, (argtypes, restype) in prototypes.items():
                        function = getattr(library, name)
                        function.argtypes = argtypes
                        function.restype = restype
                except AttributeError as exc:
                    raise OSError(errno.ENOSYS, f"cfgmgr32.dll lacks {exc}") from exc
                self._library = library
            return self._library

    def locate(self, instance_id: str, *, phantom: bool) -> tuple[int, int]:
        devinst = ctypes.c_uint32(0)
        flags = _CM_LOCATE_DEVNODE_PHANTOM if phantom else _CM_LOCATE_DEVNODE_NORMAL
        code = self._cfgmgr().CM_Locate_DevNodeW(ctypes.byref(devinst), instance_id, flags)
        return int(code), int(devinst.value)

    def status(self, devinst: int) -> tuple[int, int, int]:
        status_flags, problem = ctypes.c_uint32(0), ctypes.c_uint32(0)
        code = self._cfgmgr().CM_Get_DevNode_Status(
            ctypes.byref(status_flags), ctypes.byref(problem), devinst, 0
        )
        return int(code), int(status_flags.value), int(problem.value)

    def disable(self, devinst: int, *, persist: bool) -> int:
        flags = _CM_DISABLE_UI_NOT_OK | (_CM_DISABLE_PERSIST if persist else 0)
        return int(self._cfgmgr().CM_Disable_DevNode(devinst, flags))

    def enable(self, devinst: int) -> int:
        return int(self._cfgmgr().CM_Enable_DevNode(devinst, 0))

    def request_eject(self, devinst: int) -> tuple[int, int, str]:
        veto = ctypes.c_int(0)
        # A veto buffer must be passed: with NULL the PnP manager shows a dialog.
        name = ctypes.create_unicode_buffer(_VETO_NAME_CHARS)
        code = self._cfgmgr().CM_Request_Device_EjectW(
            devinst, ctypes.byref(veto), name, _VETO_NAME_CHARS, 0
        )
        return int(code), int(veto.value), name.value

    def reenumerate(self, devinst: int) -> int:
        return int(self._cfgmgr().CM_Reenumerate_DevNode(devinst, _CM_REENUMERATE_NORMAL))


class WinRegistry:
    """:class:`RegistryIO` over :mod:`winreg`, 64-bit view of ``HKEY_LOCAL_MACHINE``."""

    _MAX_VALUES = 4096

    @property
    def available(self) -> bool:
        return sys.platform == "win32"

    @staticmethod
    def _winreg() -> Any:
        if sys.platform != "win32":
            raise OSError(errno.ENOSYS, "the Windows registry is not available here")
        import winreg  # Windows only; imported here so this module imports everywhere

        return winreg

    def get(self, key: str, name: str) -> RegValue | None:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as handle:
                data, kind = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None
        return _from_winreg(kind, data)

    def set(self, key: str, name: str, value: RegValue) -> None:
        winreg = self._winreg()
        data: Any = list(value.data) if value.type == REG_MULTI_SZ else value.data
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        ) as handle:
            winreg.SetValueEx(handle, name, 0, value.type, data)

    def delete(self, key: str, name: str) -> None:
        winreg = self._winreg()
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
            ) as handle:
                winreg.DeleteValue(handle, name)
        except FileNotFoundError:
            return

    def values(self, key: str) -> dict[str, RegValue]:
        winreg = self._winreg()
        found: dict[str, RegValue] = {}
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as handle:
                for index in range(self._MAX_VALUES):
                    try:
                        name, data, kind = winreg.EnumValue(handle, index)
                    except OSError:
                        break
                    with contextlib.suppress(ValueError):
                        found[name] = _from_winreg(kind, data)
        except FileNotFoundError:
            return {}
        return found


def _from_winreg(kind: int, data: Any) -> RegValue:
    if kind == REG_MULTI_SZ:
        return RegValue(REG_MULTI_SZ, tuple(data or ()))
    return RegValue(kind, data)


class WinDisks:
    """:class:`DiskIO` with ``IOCTL_DISK_GET/SET_DISK_ATTRIBUTES``.

    Disks are found through the read-only device-tree walk of
    :func:`portlock.guard.windows.volumes.find_disks`. The attribute is set with
    ``Persist = FALSE``: it lasts until the disk goes away or the machine restarts, and
    nothing is written to the medium.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._kernel32: Any | None = None
        self._api: Any | None = None

    @property
    def available(self) -> bool:
        try:
            self._k32()
        except OSError:
            return False
        return True

    def _k32(self) -> Any:
        with self._lock:
            if self._kernel32 is None:
                library = _win_loader()(
                    "kernel32.dll", use_last_error=True, winmode=_SEARCH_SYSTEM32
                )
                dword = ctypes.c_uint32
                library.CreateFileW.argtypes = (
                    ctypes.c_wchar_p,
                    dword,
                    dword,
                    ctypes.c_void_p,
                    dword,
                    dword,
                    ctypes.c_void_p,
                )
                library.CreateFileW.restype = ctypes.c_void_p
                library.DeviceIoControl.argtypes = (
                    ctypes.c_void_p,
                    dword,
                    ctypes.c_void_p,
                    dword,
                    ctypes.c_void_p,
                    dword,
                    ctypes.POINTER(dword),
                    ctypes.c_void_p,
                )
                library.DeviceIoControl.restype = ctypes.c_int
                library.CloseHandle.argtypes = (ctypes.c_void_p,)
                library.CloseHandle.restype = ctypes.c_int
                self._kernel32 = library
            return self._kernel32

    def disk_numbers(self, instance_id: str) -> list[int]:
        from portlock.core.errors import BackendError
        from portlock.guard.windows.api import FILE_DEVICE_DISK, WinApi
        from portlock.guard.windows.volumes import find_disks

        with self._lock:
            if self._api is None:
                self._api = WinApi()
            api = self._api
        try:
            devinst = api.locate_devnode(instance_id)
            if devinst is None:
                return []
            disks = find_disks(api, devinst)
        except BackendError as exc:
            raise OSError(errno.EIO, f"cannot list the device's disks: {exc}") from exc
        return sorted(disk.device_number for disk in disks if disk.device_type == FILE_DEVICE_DISK)

    def get_read_only(self, disk: int) -> bool:
        output = ctypes.create_string_buffer(_GET_DISK_ATTRIBUTES.size)
        self._ioctl(disk, 0, _IOCTL_DISK_GET_DISK_ATTRIBUTES, None, output)
        _version, _reserved, attributes = _GET_DISK_ATTRIBUTES.unpack(output.raw)
        return bool(attributes & _DISK_ATTRIBUTE_READ_ONLY)

    def set_read_only(self, disk: int, read_only: bool) -> None:
        request = _SET_DISK_ATTRIBUTES.pack(
            _SET_DISK_ATTRIBUTES.size,
            False,
            _DISK_ATTRIBUTE_READ_ONLY if read_only else 0,
            _DISK_ATTRIBUTE_READ_ONLY,
        )
        self._ioctl(
            disk,
            _GENERIC_READ | _GENERIC_WRITE,
            _IOCTL_DISK_SET_DISK_ATTRIBUTES,
            ctypes.create_string_buffer(request, len(request)),
            None,
        )

    def _ioctl(self, disk: int, access: int, code: int, inbuf: Any, outbuf: Any) -> None:
        if isinstance(disk, bool) or not isinstance(disk, int) or not 0 <= disk < 1000:
            raise ValueError(f"not a disk number: {disk!r}")
        kernel32 = self._k32()
        path = f"\\\\.\\PhysicalDrive{disk}"
        handle = kernel32.CreateFileW(
            path, access, _FILE_SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None
        )
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise _win_os_error(int(ctypes.get_last_error()), path)  # type: ignore[attr-defined]
        try:
            returned = ctypes.c_uint32(0)
            ok = kernel32.DeviceIoControl(
                handle,
                code,
                inbuf,
                len(inbuf.raw) if inbuf is not None else 0,
                outbuf,
                len(outbuf.raw) if outbuf is not None else 0,
                ctypes.byref(returned),
                None,
            )
            if not ok:
                raise _win_os_error(int(ctypes.get_last_error()), path)  # type: ignore[attr-defined]
        finally:
            kernel32.CloseHandle(handle)


def _win_os_error(code: int, path: str) -> OSError:
    if code in (_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND):
        return FileNotFoundError(errno.ENOENT, "the disk has gone", path)
    if code == _ERROR_ACCESS_DENIED:
        return PermissionError(errno.EACCES, "access denied", path)
    return OSError(errno.EIO, f"Win32 error {code}", path)


# --------------------------------------------------------------------------------------
# Real implementations: external timers
# --------------------------------------------------------------------------------------

_TIMER_NAME = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_TIMER_TIMEOUT = 8.0
_SYSTEMCTL_NOT_LOADED = 5


def validate_timer_name(name: str) -> str:
    """Check a timer name: lowercase letters, digits and hyphens, at most 48 characters.

    Raises:
        ValueError: if it is anything else.
    """
    if not isinstance(name, str) or not _TIMER_NAME.match(name):
        raise ValueError(f"a timer name is lowercase letters, digits and hyphens: {name!r}")
    return name


def _aware_utc(at: datetime) -> datetime:
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("a timer needs a timezone-aware datetime")
    return at.astimezone(UTC).replace(microsecond=0)


class SystemdRunTimer:
    """:class:`ExternalTimer` as a transient systemd timer unit (``systemd-run``).

    The timer ``portlock-<name>.timer`` fires once at a wall-clock time given in UTC and
    starts ``portlock-<name>.service``, which runs the command and is collected after it
    exits. Transient units live in ``/run`` and vanish at reboot, as does everything the
    dead-man timer would undo except the udev rules file, which ``portlock recover``
    removes at the next start.
    """

    def __init__(
        self,
        runner: CommandRunner,
        *,
        systemd_run: str = "/usr/bin/systemd-run",
        systemctl: str = "/usr/bin/systemctl",
    ) -> None:
        self._runner = runner
        self._systemd_run = systemd_run
        self._systemctl = systemctl

    @staticmethod
    def unit(name: str) -> str:
        """The unit name stem for timer ``name``."""
        return f"portlock-{validate_timer_name(name)}"

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        unit = self.unit(name)
        when = _aware_utc(at).strftime("%Y-%m-%d %H:%M:%S UTC")
        command = _check_argv(argv)
        if not posixpath.isabs(command[0]):
            raise ValueError("the timer's program must be an absolute path")
        self.cancel(name)
        result = self._runner.run(
            [
                self._systemd_run,
                f"--unit={unit}",
                "--description=PortLock dead-man timer: restore journaled settings",
                f"--on-calendar={when}",
                "--timer-property=AccuracySec=1s",
                "--collect",
                "--quiet",
                "--",
                *command,
            ],
            timeout=_TIMER_TIMEOUT,
        )
        if not result.ok:
            raise TimerError(f"systemd-run could not arm {unit}.timer: {result.describe()}")

    def cancel(self, name: str) -> None:
        unit = self.unit(name)
        result = self._runner.run(
            [self._systemctl, "stop", f"{unit}.timer"], timeout=_TIMER_TIMEOUT
        )
        # Status 5 is "unit not loaded": there was no such timer, which is what we want.
        if not result.ok and not (
            result.returncode == _SYSTEMCTL_NOT_LOADED and not result.timed_out
        ):
            raise TimerError(f"systemctl could not stop {unit}.timer: {result.describe()}")

    def is_armed(self, name: str) -> bool:
        unit = self.unit(name)
        result = self._runner.run(
            [self._systemctl, "is-active", f"{unit}.timer"], timeout=_TIMER_TIMEOUT
        )
        if result.timed_out:
            raise TimerError(f"systemctl is-active {unit}.timer timed out")
        # is-active prints exactly one state word; it is not translated.
        return result.returncode == 0 and result.stdout.strip() == "active"


_TASK_FOLDER = "\\PortLock\\"
_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
#: The well-known SID of the LocalSystem account.
_SID_LOCAL_SYSTEM = "S-1-5-18"


def scheduled_task_xml(at: datetime, argv: Sequence[str], *, description: str) -> str:
    """The Task Scheduler definition of a one-shot task that runs ``argv`` at ``at``.

    The task runs as LocalSystem with the highest privileges, starts as soon as possible
    if the machine was asleep or off at the time (``StartWhenAvailable``), ignores
    battery state, and is stopped after ten minutes.
    """
    command = _check_argv(argv)
    start = _aware_utc(at).strftime("%Y-%m-%dT%H:%M:%SZ")
    arguments = subprocess.list2cmdline(command[1:])
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        f'<Task version="1.2" xmlns="{_TASK_NAMESPACE}">\n'
        f"  <RegistrationInfo><Description>{xml_escape(description)}</Description>"
        "</RegistrationInfo>\n"
        "  <Triggers><TimeTrigger>"
        f"<StartBoundary>{start}</StartBoundary><Enabled>true</Enabled>"
        "</TimeTrigger></Triggers>\n"
        '  <Principals><Principal id="Author">'
        f"<UserId>{_SID_LOCAL_SYSTEM}</UserId><RunLevel>HighestAvailable</RunLevel>"
        "</Principal></Principals>\n"
        "  <Settings>"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<StartWhenAvailable>true</StartWhenAvailable>"
        "<ExecutionTimeLimit>PT10M</ExecutionTimeLimit>"
        "<Enabled>true</Enabled>"
        "</Settings>\n"
        '  <Actions Context="Author"><Exec>'
        f"<Command>{xml_escape(command[0])}</Command>"
        f"<Arguments>{xml_escape(arguments)}</Arguments>"
        "</Exec></Actions>\n"
        "</Task>\n"
    )


def parse_schtasks_query(output: str, task_name: str) -> bool:
    """True if ``schtasks /Query /FO CSV /NH`` output lists ``task_name``.

    Only the first column (the task's full name) is used; the others are translated.
    """
    wanted = task_name.casefold()
    for row in csv.reader(io.StringIO(output)):
        if row and row[0].strip().casefold() == wanted:
            return True
    return False


class ScheduledTaskTimer:
    """:class:`ExternalTimer` as a one-shot Task Scheduler task (``schtasks``).

    The task ``\\PortLock\\<name>`` is registered from an XML definition
    (:func:`scheduled_task_xml`), which carries the start time as an ISO 8601 UTC
    timestamp; ``schtasks /SD`` and ``/ST`` would need the date in the machine's locale
    format. The XML file is written into ``work_dir`` (PortLock's private state
    directory) for the duration of the call and removed afterwards.
    """

    def __init__(
        self,
        runner: CommandRunner,
        work_dir: Path,
        *,
        schtasks: str = "C:\\Windows\\System32\\schtasks.exe",
    ) -> None:
        self._runner = runner
        self._work_dir = Path(work_dir)
        self._schtasks = schtasks

    @staticmethod
    def task_name(name: str) -> str:
        """The full Task Scheduler name of timer ``name``."""
        return _TASK_FOLDER + validate_timer_name(name)

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        task = self.task_name(name)
        definition = scheduled_task_xml(
            at, argv, description="PortLock dead-man timer: restore journaled settings"
        )
        path = self._work_dir / f"{validate_timer_name(name)}.task.xml"
        # Task Scheduler reads task XML as UTF-16 with a byte-order mark.
        atomic_write_bytes(path, b"\xff\xfe" + definition.encode("utf-16-le"), private=True)
        try:
            result = self._runner.run(
                [self._schtasks, "/Create", "/TN", task, "/XML", str(path), "/F"],
                timeout=_TIMER_TIMEOUT,
            )
        finally:
            with contextlib.suppress(OSError):
                path.unlink()
        if not result.ok:
            raise TimerError(f"schtasks could not create {task}: {result.describe()}")

    def cancel(self, name: str) -> None:
        task = self.task_name(name)
        # The "not found" message is translated, so ask first instead of parsing it.
        if not self.is_armed(name):
            return
        result = self._runner.run(
            [self._schtasks, "/Delete", "/TN", task, "/F"], timeout=_TIMER_TIMEOUT
        )
        if not result.ok:
            raise TimerError(f"schtasks could not delete {task}: {result.describe()}")

    def is_armed(self, name: str) -> bool:
        task = self.task_name(name)
        result = self._runner.run(
            [self._schtasks, "/Query", "/TN", task, "/FO", "CSV", "/NH"], timeout=_TIMER_TIMEOUT
        )
        if result.timed_out:
            raise TimerError(f"schtasks /Query {task} timed out")
        return result.returncode == 0 and parse_schtasks_query(result.stdout, task)


# --------------------------------------------------------------------------------------
# Real implementations: directory privacy
# --------------------------------------------------------------------------------------


class PosixDirPrivacy:
    """:class:`DirPrivacy` on POSIX: owner, mode 0700, and ancestors nobody else controls.

    A directory is private when it is a real directory (not a symbolic link), owned by
    this process's effective user or root, has no group or other permissions, and every
    ancestor of its resolved path is owned by this user or root and is not writable by
    others (unless sticky, like ``/tmp``): otherwise someone else could rename it away
    and put their own in its place.

    The operating-system functions are parameters so the logic is tested on any platform.
    """

    def __init__(
        self,
        *,
        lstat: Callable[[str], Any] = os.lstat,
        chmod: Callable[[str, int], None] = os.chmod,
        chown: Callable[[str, int, int], None] | None = None,
        makedirs: Callable[[str], None] | None = None,
        geteuid: Callable[[], int] | None = None,
        realpath: Callable[[str], str] = os.path.realpath,
    ) -> None:
        self._lstat = lstat
        self._chmod = chmod
        self._chown = chown
        self._makedirs = makedirs
        self._geteuid = geteuid
        self._realpath = realpath

    def _euid(self) -> int:
        if self._geteuid is not None:
            return self._geteuid()
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            raise EnforcementError("POSIX ownership is not available on this platform")
        return int(geteuid())

    def ensure_private(self, path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        if not posixpath.isabs(text):
            raise EnforcementError(f"{text} is not an absolute path", code="not_private")
        try:
            info = self._lstat(text)
        except FileNotFoundError:
            self._make(text)
            info = self._lstat(text)
        if stat.S_ISLNK(info.st_mode):
            raise EnforcementError(f"{text} is a symbolic link", code="not_private")
        euid = self._euid()
        if info.st_uid != euid and euid == 0:
            chown = self._chown if self._chown is not None else getattr(os, "chown", None)
            if chown is None:
                raise EnforcementError("cannot change ownership on this platform")
            chown(text, 0, 0)
        self._chmod(text, 0o700)
        report = self.check(path)
        if not report.private:
            raise EnforcementError(
                f"{text} could not be made private: {'; '.join(report.problems)}",
                code="not_private",
            )

    def _make(self, text: str) -> None:
        if self._makedirs is not None:
            self._makedirs(text)
        else:
            os.makedirs(text, mode=0o700, exist_ok=True)

    def check(self, path: str | os.PathLike[str]) -> PrivacyReport:
        text = os.fspath(path)
        problems: list[str] = []
        try:
            euid = self._euid()
            trusted = {0, euid}
            if not posixpath.isabs(text):
                problems.append("the path is not absolute")
            info = self._lstat(text)
            if stat.S_ISLNK(info.st_mode):
                problems.append("it is a symbolic link")
            elif not stat.S_ISDIR(info.st_mode):
                problems.append("it is not a directory")
            if info.st_uid not in trusted:
                problems.append(f"it is owned by uid {info.st_uid}, not by this service or root")
            if stat.S_IMODE(info.st_mode) & 0o077:
                problems.append(
                    f"its mode is {stat.S_IMODE(info.st_mode):04o}; other users can enter it"
                    " (it must be 0700)"
                )
            parent = posixpath.dirname(self._realpath(text))
            for _ in range(64):
                ancestor = self._lstat(parent)
                if ancestor.st_uid not in trusted:
                    problems.append(f"{parent} is owned by uid {ancestor.st_uid}")
                mode = stat.S_IMODE(ancestor.st_mode)
                if mode & 0o022 and not mode & stat.S_ISVTX:
                    problems.append(
                        f"{parent} is writable by other users, who could replace the directory"
                    )
                if parent == "/":
                    break
                parent = posixpath.dirname(parent)
        except FileNotFoundError:
            problems.append("it does not exist")
        except (OSError, EnforcementError) as exc:
            problems.append(f"it cannot be checked: {exc}")
        return PrivacyReport(path=text, private=not problems, problems=tuple(problems))


#: Principals allowed on a private directory, as ``icacls`` prints them on an English
#: Windows. Other display languages translate these names; there the check fails closed.
_ICACLS_ALLOWED = frozenset({"nt authority\\system", "builtin\\administrators"})
_ICACLS_GRANT = ("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
# Everyone, Authenticated Users, Users, CREATOR OWNER: removed explicitly as well, in
# case the directory was created with explicit entries for them.
_ICACLS_REMOVE = ("*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545", "*S-1-3-0")
_ICACLS_TIMEOUT = 8.0


def parse_icacls_output(output: str, path: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse ``icacls <path>`` output into ``(principal, rights)`` pairs.

    ``icacls`` prints the path followed by the first entry on one line, one further entry
    per indented line, a blank line, and a summary. Returns the entries and a list of
    lines that could not be understood.
    """
    entries: list[tuple[str, str]] = []
    unparsed: list[str] = []
    lines = output.replace("\r\n", "\n").split("\n")
    first = True
    for raw in lines:
        line = raw.strip()
        if not line:
            if not first:
                break
            continue
        if first:
            # The first line starts with the path itself.
            first = False
            if not line.casefold().startswith(path.casefold()):
                unparsed.append(line)
                continue
            line = line[len(path) :].strip()
        principal, separator, rights = line.partition(":(")
        if not separator or not principal:
            unparsed.append(line)
            continue
        entries.append((principal.strip(), "(" + rights))
    return entries, unparsed


class IcaclsDirPrivacy:
    """:class:`DirPrivacy` on Windows with ``icacls``.

    Private means: inheritance removed and access granted only to LocalSystem and the
    Administrators group (deny entries are allowed). The check reads the names
    ``icacls`` prints, which Windows translates; on a non-English system they are not
    recognised and the directory is reported as not private (fail closed).
    """

    def __init__(
        self,
        runner: CommandRunner,
        *,
        icacls: str = "C:\\Windows\\System32\\icacls.exe",
        makedirs: Callable[[str], None] | None = None,
    ) -> None:
        self._runner = runner
        self._icacls = icacls
        self._makedirs = makedirs

    def ensure_private(self, path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        if self._makedirs is not None:
            self._makedirs(text)
        else:
            os.makedirs(text, exist_ok=True)
        result = self._runner.run(
            [
                self._icacls,
                text,
                "/inheritance:r",
                "/grant:r",
                *_ICACLS_GRANT,
                "/remove:g",
                *_ICACLS_REMOVE,
            ],
            timeout=_ICACLS_TIMEOUT,
        )
        if not result.ok:
            raise EnforcementError(
                f"icacls could not restrict {text}: {result.describe()}", code="not_private"
            )
        report = self.check(path)
        if not report.private:
            raise EnforcementError(
                f"{text} could not be made private: {'; '.join(report.problems)}",
                code="not_private",
            )

    def check(self, path: str | os.PathLike[str]) -> PrivacyReport:
        text = os.fspath(path)
        result = self._runner.run([self._icacls, text], timeout=_ICACLS_TIMEOUT)
        if not result.ok:
            return PrivacyReport(
                text, False, (f"its access list cannot be read: {result.describe()}",)
            )
        entries, unparsed = parse_icacls_output(result.stdout, text)
        problems: list[str] = []
        if not entries:
            problems.append("no access entries could be read")
        for principal, rights in entries:
            if "(DENY)" in rights.upper():
                continue
            if principal.casefold() not in _ICACLS_ALLOWED:
                problems.append(f"it grants {rights} to {principal}")
            if "(I)" in rights.upper():
                problems.append(f"the entry for {principal} is inherited from the parent")
        for line in unparsed:
            problems.append(f"unrecognised access entry: {line[:120]}")
        return PrivacyReport(text, not problems, tuple(problems))


# --------------------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------------------


def _oserror(code: int, path: str) -> OSError:
    # OSError(errno, ...) returns the matching subclass (FileNotFoundError, ...).
    return OSError(code, os.strerror(code), path)


class FakeSysfs:
    """An in-memory sysfs: files, directories and symbolic links keyed by POSIX path.

    Linux sysfs names contain colons (``1-2:1.0``), which Windows file names cannot, so
    the tests use this instead of a directory tree. It behaves like the kernel where the
    enforcer depends on it: writes go to existing attributes only, links resolve like
    ``realpath``, an unprivileged writer gets ``EACCES``, a read-only sysfs ``EROFS``,
    and failures can be injected per path and operation.

    Attributes:
        writes: every successful write as ``(resolved path, value)``, oldest first.
        privileged: when False, every write fails with ``EACCES``.
        read_only_fs: when True, every write fails with ``EROFS``.
    """

    _MAX_LINKS = 40

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._files: dict[str, str] = {}
        self._dirs: set[str] = {"/"}
        self._links: dict[str, str] = {}
        self._locked: set[str] = set()
        self._failures: dict[tuple[str, str], int] = {}
        self._transforms: dict[str, Callable[[str], str]] = {}
        self.writes: list[tuple[str, str]] = []
        self.privileged = True
        self.read_only_fs = False

    # -- building the tree -------------------------------------------------------------

    @staticmethod
    def _norm(path: str) -> str:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"fake sysfs paths are absolute POSIX paths: {path!r}")
        return posixpath.normpath(path)

    def add_dir(self, path: str) -> None:
        with self._lock:
            current = "/"
            for part in self._norm(path).strip("/").split("/"):
                if not part:
                    continue
                current = posixpath.join(current, part)
                self._dirs.add(current)

    def add_file(self, path: str, value: str, *, writable: bool = True) -> None:
        """Create an attribute. ``writable=False`` models a mode-0444 attribute."""
        with self._lock:
            normal = self._norm(path)
            self.add_dir(posixpath.dirname(normal))
            self._files[normal] = value
            if writable:
                self._locked.discard(normal)
            else:
                self._locked.add(normal)

    def add_link(self, path: str, target: str) -> None:
        """Create a symbolic link; ``target`` may be relative, as in real sysfs."""
        with self._lock:
            normal = self._norm(path)
            self.add_dir(posixpath.dirname(normal))
            self._links[normal] = target

    def remove_tree(self, path: str) -> None:
        """Remove ``path`` and everything below it: the device was unplugged."""
        with self._lock:
            normal = self._norm(path)
            prefix = normal.rstrip("/") + "/"
            for store in (self._files, self._links):
                for key in [key for key in store if key == normal or key.startswith(prefix)]:
                    del store[key]
            self._dirs = {d for d in self._dirs if d != normal and not d.startswith(prefix)}

    def fail(self, operation: str, path: str, code: int) -> None:
        """Make ``operation`` (``read``, ``write``, ``listdir``) on ``path`` fail with ``code``."""
        if operation not in ("read", "write", "listdir"):
            raise ValueError(f"unknown operation {operation!r}")
        with self._lock:
            self._failures[(operation, self._norm(path))] = code

    def clear_failures(self) -> None:
        with self._lock:
            self._failures.clear()

    def on_write(self, path: str, transform: Callable[[str], str]) -> None:
        """Store ``transform(value)`` instead of the value written, like a kernel that
        accepts a write but keeps a different value."""
        with self._lock:
            self._transforms[self._norm(path)] = transform

    def value(self, path: str) -> str | None:
        """The stored value at ``path`` (links followed), or ``None``."""
        with self._lock:
            return self._files.get(self._resolve(self._norm(path)))

    # -- SysfsIO -----------------------------------------------------------------------

    def _resolve(self, path: str) -> str:
        """Resolve every link in ``path``; missing components are kept as they are."""
        parts = [part for part in path.split("/") if part]
        resolved = "/"
        hops = 0
        while parts:
            part = parts.pop(0)
            candidate = posixpath.normpath(posixpath.join(resolved, part))
            if candidate in self._links:
                hops += 1
                if hops > self._MAX_LINKS:
                    raise _oserror(errno.ELOOP, path)
                target = self._links[candidate]
                base = "/" if target.startswith("/") else resolved
                rest = [p for p in posixpath.normpath(posixpath.join(base, target)).split("/") if p]
                parts = rest + parts
                resolved = "/"
                continue
            resolved = candidate
        return resolved

    def _check_failure(self, operation: str, path: str, real: str) -> None:
        code = self._failures.get((operation, real), self._failures.get((operation, path)))
        if code is not None:
            raise _oserror(code, path)

    def read_text(self, path: str) -> str:
        with self._lock:
            normal = self._norm(path)
            real = self._resolve(normal)
            self._check_failure("read", normal, real)
            if real in self._files:
                return self._files[real].strip()
            if real in self._dirs:
                raise _oserror(errno.EISDIR, path)
            raise _oserror(errno.ENOENT, path)

    def write_text(self, path: str, value: str) -> None:
        with self._lock:
            normal = self._norm(path)
            real = self._resolve(normal)
            self._check_failure("write", normal, real)
            if real not in self._files:
                raise _oserror(errno.EISDIR if real in self._dirs else errno.ENOENT, path)
            if self.read_only_fs:
                raise _oserror(errno.EROFS, path)
            if not self.privileged or real in self._locked:
                raise _oserror(errno.EACCES, path)
            transform = self._transforms.get(real)
            self._files[real] = transform(value) if transform is not None else value
            self.writes.append((real, value))

    def exists(self, path: str) -> bool:
        with self._lock:
            normal = self._norm(path)
            if normal == "/":
                return True
            parent = self._resolve(posixpath.dirname(normal))
            last = posixpath.join(parent, posixpath.basename(normal))
            return last in self._files or last in self._dirs or last in self._links

    def listdir(self, path: str) -> list[str]:
        with self._lock:
            normal = self._norm(path)
            real = self._resolve(normal)
            self._check_failure("listdir", normal, real)
            if real not in self._dirs:
                raise _oserror(errno.ENOTDIR if real in self._files else errno.ENOENT, path)
            prefix = real.rstrip("/") + "/"
            names = {
                key[len(prefix) :]
                for store in (self._files, self._links, self._dirs)
                for key in store
                if key.startswith(prefix) and "/" not in key[len(prefix) :] and key != real
            }
            return sorted(names)

    def realpath(self, path: str) -> str:
        with self._lock:
            return self._resolve(self._norm(path))

    def writable(self, path: str) -> bool:
        with self._lock:
            real = self._resolve(self._norm(path))
            return (
                real in self._files
                and real not in self._locked
                and self.privileged
                and not self.read_only_fs
                and ("write", real) not in self._failures
            )


class FakeBlockIO:
    """In-memory read-only flags of block device nodes.

    Attributes:
        calls: ``(operation, node, value)`` for every call, oldest first.
        privileged: when False, ``set_read_only`` fails with ``EACCES``.
    """

    def __init__(self, *, available: bool = True) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, bool] = {}
        self._failures: dict[tuple[str, str], int] = {}
        self._available = available
        self.calls: list[tuple[str, str, bool | None]] = []
        self.privileged = True

    @property
    def available(self) -> bool:
        return self._available

    def add(self, node: str, *, read_only: bool = False) -> None:
        with self._lock:
            self._nodes[node] = read_only

    def remove(self, node: str) -> None:
        with self._lock:
            self._nodes.pop(node, None)

    def is_read_only(self, node: str) -> bool | None:
        with self._lock:
            return self._nodes.get(node)

    def fail(self, operation: str, node: str, code: int) -> None:
        """Make ``get`` or ``set`` on ``node`` fail with ``code``."""
        with self._lock:
            self._failures[(operation, node)] = code

    def get_read_only(self, node: str) -> bool:
        with self._lock:
            self.calls.append(("get", node, None))
            code = self._failures.get(("get", node))
            if code is not None:
                raise _oserror(code, node)
            if node not in self._nodes:
                raise _oserror(errno.ENOENT, node)
            return self._nodes[node]

    def set_read_only(self, node: str, read_only: bool) -> None:
        with self._lock:
            self.calls.append(("set", node, read_only))
            code = self._failures.get(("set", node))
            if code is not None:
                raise _oserror(code, node)
            if node not in self._nodes:
                raise _oserror(errno.ENOENT, node)
            if not self.privileged:
                raise _oserror(errno.EACCES, node)
            self._nodes[node] = read_only


class FakeRuleFiles:
    """In-memory rules files and directories.

    Attributes:
        privileged: when False, writes and removals fail with ``EACCES``.
        calls: ``(operation, path)`` for every write and removal.
    """

    def __init__(self, directories: Iterable[str] = ()) -> None:
        self._lock = threading.Lock()
        self._files: dict[str, str] = {}
        self._dirs: set[str] = set(directories)
        self._failures: dict[tuple[str, str], int] = {}
        self.calls: list[tuple[str, str]] = []
        self.privileged = True

    def add_dir(self, directory: str) -> None:
        with self._lock:
            self._dirs.add(directory)

    def put(self, path: str, text: str) -> None:
        """Place a file directly, as another program would."""
        with self._lock:
            self._files[path] = text

    def fail(self, operation: str, path: str, code: int) -> None:
        with self._lock:
            self._failures[(operation, path)] = code

    def files(self) -> dict[str, str]:
        with self._lock:
            return dict(self._files)

    def _check(self, operation: str, path: str) -> None:
        code = self._failures.get((operation, path))
        if code is not None:
            raise _oserror(code, path)

    def read(self, path: str) -> str | None:
        with self._lock:
            self._check("read", path)
            return self._files.get(path)

    def write(self, path: str, text: str) -> None:
        with self._lock:
            self._check("write", path)
            if posixpath.dirname(path) not in self._dirs:
                raise _oserror(errno.ENOENT, path)
            if not self.privileged:
                raise _oserror(errno.EACCES, path)
            self._files[path] = text
            self.calls.append(("write", path))

    def remove(self, path: str) -> None:
        with self._lock:
            self._check("remove", path)
            if not self.privileged:
                raise _oserror(errno.EACCES, path)
            self._files.pop(path, None)
            self.calls.append(("remove", path))

    def dir_writable(self, directory: str) -> bool:
        with self._lock:
            return directory in self._dirs and self.privileged


class FakeCommandRunner:
    """A :class:`CommandRunner` that answers from rules instead of running anything.

    A rule matches when the command starts with its prefix; the most recently added
    matching rule answers. Without a match the answer is ``default``.

    Attributes:
        calls: every ``(argv, timeout)``, oldest first.
    """

    def __init__(self, default: CommandResult | None = None) -> None:
        self._lock = threading.Lock()
        self._rules: list[tuple[tuple[str, ...], CommandResult, bool]] = []
        self._default = default if default is not None else CommandResult(0)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def respond(self, prefix: Sequence[str], result: CommandResult, *, once: bool = False) -> None:
        """Answer commands starting with ``prefix`` with ``result`` (once, if asked)."""
        with self._lock:
            self._rules.append((tuple(prefix), result, once))

    def commands(self) -> list[tuple[str, ...]]:
        """The argument lists run so far."""
        with self._lock:
            return [argv for argv, _timeout in self.calls]

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        arguments = tuple(_check_argv(argv))
        with self._lock:
            self.calls.append((arguments, float(timeout)))
            for index in range(len(self._rules) - 1, -1, -1):
                prefix, result, once = self._rules[index]
                if arguments[: len(prefix)] == prefix:
                    if once:
                        del self._rules[index]
                    return result
            return self._default


class FakeRegistry:
    """An in-memory ``HKEY_LOCAL_MACHINE``. Key and value names compare without case.

    Attributes:
        privileged: when False, writes and deletions fail with ``EACCES``.
        calls: ``(operation, key, name)`` for every write and deletion.
    """

    def __init__(self, *, available: bool = True) -> None:
        self._lock = threading.Lock()
        self._values: dict[tuple[str, str], tuple[str, RegValue]] = {}
        self._failures: dict[str, int] = {}
        self._available = available
        self.calls: list[tuple[str, str, str]] = []
        self.privileged = True

    @property
    def available(self) -> bool:
        return self._available

    def put(self, key: str, name: str, value: RegValue) -> None:
        """Place a value directly, as Group Policy or an administrator would."""
        with self._lock:
            self._values[(key.casefold(), name.casefold())] = (name, value)

    def fail(self, operation: str, code: int) -> None:
        """Make every ``get``, ``set``, ``delete`` or ``values`` call fail with ``code``."""
        with self._lock:
            self._failures[operation] = code

    def clear_failures(self) -> None:
        with self._lock:
            self._failures.clear()

    def snapshot(self) -> dict[tuple[str, str], RegValue]:
        """Every value as ``{(key casefolded, name casefolded): value}``."""
        with self._lock:
            return {key: value for key, (_name, value) in self._values.items()}

    def _check(self, operation: str, key: str) -> None:
        code = self._failures.get(operation)
        if code is not None:
            raise _oserror(code, key)

    def get(self, key: str, name: str) -> RegValue | None:
        with self._lock:
            self._check("get", key)
            item = self._values.get((key.casefold(), name.casefold()))
            return item[1] if item is not None else None

    def set(self, key: str, name: str, value: RegValue) -> None:
        if not isinstance(value, RegValue):
            raise TypeError("value must be a RegValue")
        with self._lock:
            self._check("set", key)
            if not self.privileged:
                raise _oserror(errno.EACCES, key)
            self._values[(key.casefold(), name.casefold())] = (name, value)
            self.calls.append(("set", key, name))

    def delete(self, key: str, name: str) -> None:
        with self._lock:
            self._check("delete", key)
            if not self.privileged:
                raise _oserror(errno.EACCES, key)
            self._values.pop((key.casefold(), name.casefold()), None)
            self.calls.append(("delete", key, name))

    def values(self, key: str) -> dict[str, RegValue]:
        with self._lock:
            self._check("values", key)
            folded = key.casefold()
            return {
                name: value
                for (item_key, _folded_name), (name, value) in self._values.items()
                if item_key == folded
            }


# CONFIGRET values the fake returns (cfgmgr32.h).
_CR_SUCCESS = 0x00
_CR_NO_SUCH_DEVNODE = 0x0D
_CR_REMOVE_VETOED = 0x17
_CR_NOT_DISABLEABLE = 0x28
_CR_ACCESS_DENIED = 0x33
# Status flags and problem codes (cfg.h).
_DN_DRIVER_LOADED = 0x00000002
_DN_STARTED = 0x00000008
_DN_HAS_PROBLEM = 0x00000400
_DN_DISABLEABLE = 0x00002000
_CM_PROB_FAILED_INSTALL = 0x1C
_CM_PROB_DISABLED = 0x16


@dataclass(slots=True)
class FakeDevNode:
    """One device node of :class:`FakeCfgMgr`.

    Attributes:
        present: the device is connected (a node that is not is a "phantom").
        installed: Windows installed a driver; False models a device an installation
            restriction kept out (problem code 28).
        disabled / persisted: disabled, and whether the disable survives a restart.
        disable_veto: ``CM_Disable_DevNode`` answers ``CR_REMOVE_VETOED``.
        eject_veto: ``(veto type, veto name)`` that refuses an eject, if any.
    """

    instance_id: str
    devinst: int
    present: bool = True
    installed: bool = True
    disableable: bool = True
    disabled: bool = False
    persisted: bool = False
    disable_veto: bool = False
    eject_veto: tuple[int, str] | None = None
    reenumerations: int = 0


class FakeCfgMgr:
    """An in-memory Plug and Play device tree for :class:`CfgMgrAPI`.

    Attributes:
        privileged: when False, state-changing calls answer ``CR_ACCESS_DENIED``.
        calls: ``(operation, instance id)`` for every call, oldest first.
    """

    def __init__(self, *, available: bool = True) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, FakeDevNode] = {}
        self._by_handle: dict[int, FakeDevNode] = {}
        self._failures: dict[str, int] = {}
        self._next = 0x1000
        self._available = available
        self.calls: list[tuple[str, str]] = []
        self.privileged = True

    @property
    def available(self) -> bool:
        return self._available

    def add(self, instance_id: str, **state: Any) -> FakeDevNode:
        """Add a device node. Keyword arguments set :class:`FakeDevNode` fields."""
        with self._lock:
            self._next += 1
            node = FakeDevNode(instance_id=instance_id, devinst=self._next, **state)
            self._nodes[instance_id.casefold()] = node
            self._by_handle[node.devinst] = node
            return node

    def node(self, instance_id: str) -> FakeDevNode:
        with self._lock:
            return self._nodes[instance_id.casefold()]

    def unplug(self, instance_id: str) -> None:
        """The device was disconnected: its node becomes a phantom."""
        with self._lock:
            self._nodes[instance_id.casefold()].present = False

    def uninstall(self, instance_id: str) -> None:
        """The node is removed from the system altogether."""
        with self._lock:
            node = self._nodes.pop(instance_id.casefold())
            self._by_handle.pop(node.devinst, None)

    def fail(self, operation: str, code: int) -> None:
        """Make ``locate``, ``status``, ``disable``, ``enable``, ``eject`` or
        ``reenumerate`` answer ``code``."""
        with self._lock:
            self._failures[operation] = code

    def clear_failures(self) -> None:
        with self._lock:
            self._failures.clear()

    def _call(self, operation: str, node: FakeDevNode | None, label: str = "") -> int | None:
        self.calls.append((operation, node.instance_id if node is not None else label))
        return self._failures.get(operation)

    def locate(self, instance_id: str, *, phantom: bool) -> tuple[int, int]:
        with self._lock:
            node = self._nodes.get(instance_id.casefold())
            failure = self._call("locate", node, instance_id)
            if failure is not None:
                return failure, 0
            if node is None or (not node.present and not phantom):
                return _CR_NO_SUCH_DEVNODE, 0
            return _CR_SUCCESS, node.devinst

    def status(self, devinst: int) -> tuple[int, int, int]:
        with self._lock:
            node = self._by_handle.get(devinst)
            failure = self._call("status", node, str(devinst))
            if failure is not None:
                return failure, 0, 0
            if node is None or not node.present:
                return _CR_NO_SUCH_DEVNODE, 0, 0
            flags = _DN_DISABLEABLE if node.disableable else 0
            if node.disabled:
                return _CR_SUCCESS, flags | _DN_HAS_PROBLEM, _CM_PROB_DISABLED
            if not node.installed:
                return _CR_SUCCESS, flags | _DN_HAS_PROBLEM, _CM_PROB_FAILED_INSTALL
            return _CR_SUCCESS, flags | _DN_STARTED | _DN_DRIVER_LOADED, 0

    def disable(self, devinst: int, *, persist: bool) -> int:
        with self._lock:
            node = self._by_handle.get(devinst)
            failure = self._call("disable", node, str(devinst))
            if failure is not None:
                return failure
            if node is None or not node.present:
                return _CR_NO_SUCH_DEVNODE
            if not self.privileged:
                return _CR_ACCESS_DENIED
            if not node.disableable:
                return _CR_NOT_DISABLEABLE
            if node.disable_veto:
                return _CR_REMOVE_VETOED
            node.disabled, node.persisted = True, persist
            return _CR_SUCCESS

    def enable(self, devinst: int) -> int:
        with self._lock:
            node = self._by_handle.get(devinst)
            failure = self._call("enable", node, str(devinst))
            if failure is not None:
                return failure
            if node is None:
                return _CR_NO_SUCH_DEVNODE
            if not self.privileged:
                return _CR_ACCESS_DENIED
            node.disabled = node.persisted = False
            return _CR_SUCCESS

    def request_eject(self, devinst: int) -> tuple[int, int, str]:
        with self._lock:
            node = self._by_handle.get(devinst)
            failure = self._call("eject", node, str(devinst))
            if failure is not None:
                return failure, 0, ""
            if node is None or not node.present:
                return _CR_NO_SUCH_DEVNODE, 0, ""
            if node.eject_veto is not None:
                veto_type, veto_name = node.eject_veto
                return _CR_REMOVE_VETOED, veto_type, veto_name
            node.present = False
            return _CR_SUCCESS, 0, ""

    def reenumerate(self, devinst: int) -> int:
        with self._lock:
            node = self._by_handle.get(devinst)
            failure = self._call("reenumerate", node, str(devinst))
            if failure is not None:
                return failure
            if node is None or not node.present:
                return _CR_NO_SUCH_DEVNODE
            if not self.privileged:
                return _CR_ACCESS_DENIED
            # Re-enumerating an allowed device lets Windows install it.
            node.reenumerations += 1
            node.installed = True
            return _CR_SUCCESS


class FakeDisks:
    """In-memory disks with a read-only attribute, keyed by ``PhysicalDriveN`` number.

    Attributes:
        privileged: when False, ``set_read_only`` fails with ``EACCES``.
        calls: ``(operation, disk, value)`` for every get and set.
    """

    def __init__(self, *, available: bool = True) -> None:
        self._lock = threading.Lock()
        self._owners: dict[str, list[int]] = {}
        self._read_only: dict[int, bool] = {}
        self._failures: dict[str, int] = {}
        self._available = available
        self.calls: list[tuple[str, int, bool | None]] = []
        self.privileged = True

    @property
    def available(self) -> bool:
        return self._available

    def attach(self, instance_id: str, *disks: int, read_only: bool = False) -> None:
        """Give device ``instance_id`` the disks ``disks``."""
        with self._lock:
            self._owners[instance_id.casefold()] = list(disks)
            for disk in disks:
                self._read_only[disk] = read_only

    def detach(self, instance_id: str) -> None:
        """The device's disks went away (unplugged, or the device was disabled)."""
        with self._lock:
            for disk in self._owners.pop(instance_id.casefold(), []):
                self._read_only.pop(disk, None)

    def is_read_only(self, disk: int) -> bool | None:
        with self._lock:
            return self._read_only.get(disk)

    def fail(self, operation: str, code: int) -> None:
        """Make ``list``, ``get`` or ``set`` fail with ``code``."""
        with self._lock:
            self._failures[operation] = code

    def disk_numbers(self, instance_id: str) -> list[int]:
        with self._lock:
            code = self._failures.get("list")
            if code is not None:
                raise _oserror(code, instance_id)
            return list(self._owners.get(instance_id.casefold(), []))

    def get_read_only(self, disk: int) -> bool:
        with self._lock:
            self.calls.append(("get", disk, None))
            code = self._failures.get("get")
            if code is not None:
                raise _oserror(code, str(disk))
            if disk not in self._read_only:
                raise _oserror(errno.ENOENT, str(disk))
            return self._read_only[disk]

    def set_read_only(self, disk: int, read_only: bool) -> None:
        with self._lock:
            self.calls.append(("set", disk, read_only))
            code = self._failures.get("set")
            if code is not None:
                raise _oserror(code, str(disk))
            if disk not in self._read_only:
                raise _oserror(errno.ENOENT, str(disk))
            if not self.privileged:
                raise _oserror(errno.EACCES, str(disk))
            self._read_only[disk] = read_only


class FakeExternalTimer:
    """An :class:`ExternalTimer` that only remembers what it was asked to do.

    Attributes:
        armed: ``{name: (time, argv)}`` of the timers currently armed.
        calls: ``(operation, name)`` for every call.
        failing: when True, every call raises :class:`TimerError`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.armed: dict[str, tuple[datetime, tuple[str, ...]]] = {}
        self.calls: list[tuple[str, str]] = []
        self.failing = False

    def _enter(self, operation: str, name: str) -> str:
        self.calls.append((operation, name))
        validate_timer_name(name)
        if self.failing:
            raise TimerError(f"simulated failure to {operation} timer {name}")
        return name

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        with self._lock:
            self._enter("arm", name)
            self.armed[name] = (_aware_utc(at), tuple(_check_argv(argv)))

    def cancel(self, name: str) -> None:
        with self._lock:
            self._enter("cancel", name)
            self.armed.pop(name, None)

    def is_armed(self, name: str) -> bool:
        with self._lock:
            self._enter("is_armed", name)
            return name in self.armed


class FakeDirPrivacy:
    """A :class:`DirPrivacy` that records which paths were made private.

    Attributes:
        private: paths reported as private.
        problems: per path, the problems :meth:`check` reports for a non-private path.
        refuse: paths that :meth:`ensure_private` cannot make private.
        calls: ``(operation, path)`` for every call.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.private: set[str] = set()
        self.problems: dict[str, tuple[str, ...]] = {}
        self.refuse: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    def ensure_private(self, path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        with self._lock:
            self.calls.append(("ensure", text))
            if text in self.refuse:
                raise EnforcementError(f"{text} could not be made private", code="not_private")
            self.private.add(text)
            self.problems.pop(text, None)

    def check(self, path: str | os.PathLike[str]) -> PrivacyReport:
        text = os.fspath(path)
        with self._lock:
            self.calls.append(("check", text))
            if text in self.private:
                return PrivacyReport(text, True)
            return PrivacyReport(
                text, False, self.problems.get(text, ("it has not been made private",))
            )
