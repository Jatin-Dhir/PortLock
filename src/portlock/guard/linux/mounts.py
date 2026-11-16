"""Mount points for USB volumes, from ``/proc/self/mountinfo``.

sysfs says which block devices a USB device exposes; it does not say where they are
mounted. The kernel's mount table does. This module parses it, attaches mount points and
filesystem types to :class:`~portlock.core.models.Volume` values, and can watch the
table for changes. It only reads.

The table is the one of the calling process's mount namespace. A service that runs in
its own namespace (most systemd sandboxing options create one) sees a mount made
elsewhere only if mount propagation carries it in.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import select
import socket
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from portlock.core.errors import BackendError
from portlock.core.models import UsbDevice, Volume

__all__ = [
    "MountEntry",
    "MountWatcher",
    "attach_mounts",
    "parse_mountinfo",
    "unescape_mount_field",
]

_log = logging.getLogger(__name__)

DEFAULT_MOUNTINFO = Path("/proc/self/mountinfo")

# The table of a busy container host runs to a few megabytes at most.
_MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
_OCTAL_ESCAPE = re.compile(rb"\\([0-3][0-7]{2})")
_DEV_NUMBER = re.compile(r"[0-9]{1,10}:[0-9]{1,10}")
_ID = re.compile(r"[0-9]{1,10}")


@dataclass(frozen=True, slots=True)
class MountEntry:
    """One line of ``mountinfo``: one mount.

    Attributes:
        mount_id / parent_id: the kernel's identifiers for this mount and its parent.
        device: ``major:minor`` of the mounted filesystem (``st_dev`` of its files).
        root: the directory inside the filesystem that this mount shows; ``/`` unless it
            is a bind mount of a subdirectory.
        mount_point: where it is mounted, relative to the process's root.
        options: per-mount options (``rw``, ``nosuid``, ...).
        fs_type: filesystem type, e.g. ``vfat`` or ``fuse.exfat``.
        source: the mount source, usually a device node.
        super_options: per-superblock options.
    """

    mount_id: int
    parent_id: int
    device: str
    root: str
    mount_point: str
    options: tuple[str, ...]
    fs_type: str
    source: str
    super_options: tuple[str, ...]

    @property
    def read_only(self) -> bool:
        """True if either the mount or the filesystem itself is mounted read-only."""
        return "ro" in self.options or "ro" in self.super_options


def unescape_mount_field(field: str | bytes) -> str:
    r"""Undo the kernel's escaping of one ``mountinfo`` field.

    Fields are separated by spaces, so the kernel writes a space inside a path as
    ``\040``, a tab as ``\011``, a newline as ``\012`` and a backslash as ``\134``. Each
    backslash followed by three octal digits is turned back into its byte. Bytes that are
    not UTF-8 become U+FFFD, so the result is always well-formed text.
    """
    raw = field.encode("utf-8", errors="surrogateescape") if isinstance(field, str) else field
    decoded = _OCTAL_ESCAPE.sub(lambda match: bytes([int(match.group(1), 8)]), raw)
    return decoded.decode("utf-8", errors="replace")


def parse_mountinfo(source: str | bytes | os.PathLike[str]) -> list[MountEntry]:
    """Parse a mount table.

    Args:
        source: the table itself as ``str`` or ``bytes``, or a path object
            (``pathlib.Path``) naming the file to read, normally ``/proc/self/mountinfo``.

    Returns:
        One entry per well-formed line, in file order. Lines that do not have the
        documented shape are skipped: an unparsable line must not hide the others.

    Raises:
        BackendError: if ``source`` is a path that cannot be read.
    """
    if isinstance(source, str):
        data = source.encode("utf-8", errors="surrogateescape")
    elif isinstance(source, bytes | bytearray | memoryview):
        data = bytes(source)
    else:
        try:
            with open(source, "rb") as stream:
                data = stream.read(_MAX_MOUNTINFO_BYTES)
        except OSError as exc:
            raise BackendError(
                f"cannot read mount table {os.fspath(source)}: {exc.strerror or exc}"
            ) from exc
    entries: list[MountEntry] = []
    for line in data.split(b"\n"):
        entry = _parse_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def attach_mounts(devices: Iterable[UsbDevice], mounts: Sequence[MountEntry]) -> list[UsbDevice]:
    """Fill in ``mount_point`` and ``fs_type`` on the volumes of ``devices``.

    A volume matches a mount by its ``major:minor`` number (which
    :func:`~portlock.guard.linux.sysfs.read_usb_devices` records in ``backend_data``) or
    by the mount source being its device node. The number is tried first because the
    source can be an alias such as ``/dev/disk/by-uuid/...``; the node covers filesystems
    like btrfs that report a number of their own.

    When a volume is mounted more than once, the mount of the whole filesystem is
    preferred over a bind mount of a subdirectory, and the oldest mount over later ones.
    ``read_only`` is left as read from the block device: a read-only *mount* can be
    remounted read-write by its owner, so it is not the same guarantee.

    Returns:
        New device objects, in the order given. Devices without volumes are returned
        unchanged.
    """
    by_number: dict[str, list[MountEntry]] = {}
    by_source: dict[str, list[MountEntry]] = {}
    for mount in mounts:
        by_number.setdefault(mount.device, []).append(mount)
        by_source.setdefault(mount.source, []).append(mount)

    result: list[UsbDevice] = []
    for device in devices:
        if not device.volumes:
            result.append(device)
            continue
        volumes: list[Volume] = []
        for volume in device.volumes:
            number = device.backend_data.get(f"blockdev:{volume.device_node}")
            candidates = by_number.get(number, []) if number is not None else []
            if not candidates:
                candidates = by_source.get(volume.device_node, [])
            if candidates:
                best = min(candidates, key=lambda mount: (mount.root != "/", mount.mount_id))
                volume = replace(volume, mount_point=best.mount_point, fs_type=best.fs_type)
            volumes.append(volume)
        result.append(replace(device, volumes=tuple(volumes)))
    return result


def _parse_line(line: bytes) -> MountEntry | None:
    # 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
    #  0  1    2     3     4          5  optional... -    +1        +2                 +3
    fields = line.rstrip(b"\r").split(b" ")
    if len(fields) < 9:
        return None
    try:
        separator = fields.index(b"-", 6)
    except ValueError:
        return None
    tail = fields[separator + 1 :]
    if len(tail) < 2:
        return None
    mount_id = fields[0].decode("ascii", errors="replace")
    parent_id = fields[1].decode("ascii", errors="replace")
    device = fields[2].decode("ascii", errors="replace")
    if not (_ID.fullmatch(mount_id) and _ID.fullmatch(parent_id) and _DEV_NUMBER.fullmatch(device)):
        return None
    mount_point = unescape_mount_field(fields[4])
    if not mount_point.startswith("/"):
        return None
    return MountEntry(
        mount_id=int(mount_id),
        parent_id=int(parent_id),
        device=device,
        root=unescape_mount_field(fields[3]),
        mount_point=mount_point,
        options=_split_options(fields[5]),
        fs_type=unescape_mount_field(tail[0]),
        source=unescape_mount_field(tail[1]),
        super_options=_split_options(tail[2]) if len(tail) > 2 else (),
    )


def _split_options(field: bytes) -> tuple[str, ...]:
    return tuple(unescape_mount_field(option) for option in field.split(b",") if option)


class MountWatcher:
    """Calls back whenever the mount table changes.

    Mounting a filesystem is not a device event, so no uevent announces it. The kernel
    does flag the open mount table as having "exceptional" data whenever a mount or
    unmount happens in the namespace, which ``poll`` reports as ``POLLPRI``. A thread
    waits for that and calls ``on_change``; the callback is expected to be cheap (it
    should schedule a re-read, not do one).

    Args:
        on_change: called from the watcher thread after each change. It carries no
            detail: the caller re-reads the table.
        path: the table to watch.
    """

    def __init__(self, on_change: Callable[[], None], path: Path = DEFAULT_MOUNTINFO) -> None:
        self._on_change = on_change
        self._path = Path(path)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._wake: socket.socket | None = None

    def start(self) -> None:
        """Open the table and start watching.

        Raises:
            BackendError: if this platform cannot poll files, the table cannot be
                opened, or the watcher is already running.
        """
        with self._lock:
            if self._thread is not None:
                raise BackendError("the mount watcher is already running")
            if not hasattr(select, "poll"):
                raise BackendError("this platform cannot watch the mount table")
            try:
                descriptor = os.open(self._path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            except OSError as exc:
                raise BackendError(
                    f"cannot open mount table {self._path}: {exc.strerror or exc}"
                ) from exc
            try:
                wake_reader, wake_writer = socket.socketpair()
            except OSError as exc:
                os.close(descriptor)
                raise BackendError(f"cannot create a wake-up channel: {exc}") from exc
            self._wake = wake_writer
            self._thread = threading.Thread(
                target=self._run,
                args=(descriptor, wake_reader),
                name="portlock-mounts",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        """Stop watching and release the file. Safe to call when not started."""
        with self._lock:
            thread, wake = self._thread, self._wake
            self._thread = self._wake = None
        if thread is None or wake is None:
            return
        with contextlib.suppress(OSError):
            wake.send(b"\0")
        if thread is not threading.current_thread():
            thread.join()
        wake.close()

    def _run(self, descriptor: int, wake_reader: socket.socket) -> None:
        try:
            poller = select.poll()
            poller.register(descriptor, select.POLLPRI | select.POLLERR)
            poller.register(wake_reader.fileno(), select.POLLIN)
            while True:
                try:
                    ready = poller.poll()
                except InterruptedError:
                    continue
                if any(fileno == wake_reader.fileno() for fileno, _events in ready):
                    return
                if ready:
                    self._notify()
        except OSError as exc:
            _log.warning("the mount watcher stopped: %s", exc)
        finally:
            os.close(descriptor)
            wake_reader.close()

    def _notify(self) -> None:
        try:
            self._on_change()
        except Exception:
            # A failing callback must not end the watch.
            _log.exception("mount change callback failed")
