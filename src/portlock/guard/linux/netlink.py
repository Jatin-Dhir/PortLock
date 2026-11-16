"""Device arrival and removal notifications from the kernel.

Whenever a device is added, removed or changed, the kernel broadcasts a *uevent* on a
netlink socket (protocol ``NETLINK_KOBJECT_UEVENT``, multicast group 1). Listening needs
no privilege. :class:`UeventMonitor` subscribes, checks where each message came from,
parses it and reports the ones that concern USB devices and their block devices.

A uevent is treated as a hint that something changed, never as a description of what did.
Its content is not used to identify a device: the caller re-reads sysfs. Three reasons:
the kernel announces a USB device before its interfaces exist; a full receive buffer
drops messages (``ENOBUFS``), and re-reading is the only way to recover; and inside a
container the root user of the container may inject uevents into its own network
namespace, which then arrive looking exactly like kernel messages.

Where the socket cannot be opened at all, :class:`PollingMonitor` gets the same result by
comparing snapshots.
"""

from __future__ import annotations

import contextlib
import enum
import errno
import logging
import re
import select
import socket
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import NamedTuple, Protocol

from portlock.core.errors import BackendError
from portlock.core.models import DeviceEventType, UsbDevice

__all__ = [
    "KERNEL_GROUP",
    "NETLINK_KOBJECT_UEVENT",
    "Datagram",
    "DeviceChange",
    "KernelUeventSocket",
    "MonitorStats",
    "PollingMonitor",
    "UeventKind",
    "UeventMonitor",
    "UeventTransport",
    "classify_uevent",
    "diff_devices",
    "open_kernel_uevent_socket",
    "parse_uevent",
]

_log = logging.getLogger(__name__)

#: Netlink protocol number of the kernel's uevent channel (``linux/netlink.h``). The
#: ``socket`` module does not export it.
NETLINK_KOBJECT_UEVENT = 15
#: Multicast group on which the kernel itself broadcasts. Group 2 carries the events that
#: udev re-broadcasts after running its rules; those come from a user-space process.
KERNEL_GROUP = 1

# The kernel builds a uevent in a 2048-byte buffer plus the "action@devpath" header.
_RECEIVE_BYTES = 16384
_MAX_UEVENT_BYTES = 8192
_RECEIVE_BUFFER_BYTES = 1024 * 1024

_ACTIONS = frozenset({"add", "remove", "change", "move", "online", "offline", "bind", "unbind"})
_LIBUDEV_PREFIX = b"libudev\0"
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_SEQNUM = re.compile(r"[0-9]{1,20}")
# Every device behind a USB host controller has the root hub's "usbN" in its path.
_BELOW_USB_ROOT_HUB = re.compile(r"/usb[0-9]+/")


class UeventKind(enum.StrEnum):
    """The kinds of uevent that can change what PortLock knows about a USB device."""

    USB_DEVICE = "usb_device"
    USB_INTERFACE = "usb_interface"
    #: A disk or partition that belongs to a USB device appeared, went or changed.
    BLOCK = "block"


def parse_uevent(data: bytes) -> dict[str, str] | None:
    """Parse one kernel uevent message.

    A kernel message is ``action@devpath``, a NUL, then ``KEY=VALUE`` pairs each
    terminated by a NUL::

        add@/devices/pci0000:00/.../usb1/1-2\\0ACTION=add\\0DEVPATH=/devices/...\\0SUBSYSTEM=usb\\0...

    Args:
        data: the datagram payload.

    Returns:
        The pairs as a dictionary (always containing ``ACTION``, ``DEVPATH`` and
        ``SUBSYSTEM``), or ``None`` if the message is not a well-formed kernel uevent.
        Messages in libudev's own format (they start with ``libudev``), messages whose
        header disagrees with their ``ACTION`` or ``DEVPATH``, unknown actions, pairs
        without ``=``, repeated keys and oversized messages are all rejected.
    """
    if not isinstance(data, bytes | bytearray | memoryview):
        return None
    raw = bytes(data)
    if not raw or len(raw) > _MAX_UEVENT_BYTES or raw.startswith(_LIBUDEV_PREFIX):
        return None
    header, separator, body = raw.partition(b"\0")
    if not separator:
        return None
    action_raw, at, devpath_raw = header.partition(b"@")
    if not at:
        return None
    try:
        action = action_raw.decode("ascii")
        devpath = devpath_raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if action not in _ACTIONS or not devpath.startswith("/"):
        return None

    fields: dict[str, str] = {}
    pairs = body.split(b"\0")
    if pairs and pairs[-1] == b"":
        pairs.pop()
    for pair in pairs:
        key_raw, equals, value_raw = pair.partition(b"=")
        if not equals:
            return None
        key = key_raw.decode("ascii", errors="replace")
        if not _KEY.fullmatch(key) or key in fields:
            return None
        # Values can carry device-supplied text; never let undecodable bytes raise.
        fields[key] = value_raw.decode("utf-8", errors="replace")

    if fields.get("ACTION") != action or fields.get("DEVPATH") != devpath:
        return None
    if not fields.get("SUBSYSTEM"):
        return None
    if "SEQNUM" in fields and not _SEQNUM.fullmatch(fields["SEQNUM"]):
        return None
    return fields


def classify_uevent(fields: Mapping[str, str]) -> UeventKind | None:
    """Say whether a parsed uevent concerns a USB device, and how.

    Returns:
        :attr:`UeventKind.USB_DEVICE` or :attr:`UeventKind.USB_INTERFACE` for the ``usb``
        subsystem, :attr:`UeventKind.BLOCK` for a block device that sits below a USB
        host controller, and ``None`` for everything else.
    """
    subsystem = fields.get("SUBSYSTEM")
    if subsystem == "usb":
        devtype = fields.get("DEVTYPE")
        if devtype == "usb_device":
            return UeventKind.USB_DEVICE
        if devtype == "usb_interface":
            return UeventKind.USB_INTERFACE
        return None
    if subsystem == "block" and _BELOW_USB_ROOT_HUB.search(fields.get("DEVPATH", "")):
        return UeventKind.BLOCK
    return None


@dataclass(frozen=True, slots=True)
class Datagram:
    """One received netlink message with what the kernel says about its origin.

    Attributes:
        data: the payload.
        sender_pid: netlink port id of the sender. ``0`` means the kernel.
        sender_groups: multicast group mask the message was sent to.
        truncated: the payload did not fit the receive buffer and was cut.
    """

    data: bytes
    sender_pid: int
    sender_groups: int
    truncated: bool = False


class UeventTransport(Protocol):
    """Where a :class:`UeventMonitor` gets its messages from."""

    def receive(self) -> Datagram | None:
        """Block until a message arrives. ``None`` means :meth:`interrupt` was called.

        Raises:
            OSError: on a socket error; ``ENOBUFS`` if messages were dropped.
        """
        ...

    def interrupt(self) -> None:
        """Make a blocked :meth:`receive` return ``None``. Callable from any thread."""
        ...

    def close(self) -> None:
        """Release the socket."""
        ...


class KernelUeventSocket:
    """A netlink socket subscribed to kernel uevents.

    Args:
        protocol: netlink protocol; the default is the uevent channel.
        groups: multicast group mask to join.
        receive_buffer: requested ``SO_RCVBUF``. The kernel caps it at
            ``net.core.rmem_max``; a burst that still overflows it surfaces as ``ENOBUFS``.

    Raises:
        BackendError: if the platform has no netlink, or the socket cannot be opened
            or bound (for example in a sandbox that filters address families).
    """

    def __init__(
        self,
        *,
        protocol: int = NETLINK_KOBJECT_UEVENT,
        groups: int = KERNEL_GROUP,
        receive_buffer: int = _RECEIVE_BUFFER_BYTES,
    ) -> None:
        family = getattr(socket, "AF_NETLINK", None)
        if family is None:
            raise BackendError("netlink sockets are not available on this platform")
        opened: list[socket.socket] = []
        try:
            sock = socket.socket(family, socket.SOCK_RAW | socket.SOCK_CLOEXEC, protocol)
            opened.append(sock)
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
            # Port id 0 lets the kernel pick a unique one for this socket.
            sock.bind((0, groups))
            sock.setblocking(False)
            wake_reader, wake_writer = socket.socketpair()
            opened += [wake_reader, wake_writer]
        except OSError as exc:
            for item in opened:
                item.close()
            raise BackendError(
                f"cannot open the kernel uevent socket: {exc.strerror or exc}"
            ) from exc
        self._socket = sock
        self._wake_reader = wake_reader
        self._wake_writer = wake_writer

    @property
    def port_id(self) -> int:
        """The netlink port id the kernel assigned to this socket."""
        return int(self._socket.getsockname()[0])

    def receive(self) -> Datagram | None:
        while True:
            readable, _, _ = select.select([self._socket, self._wake_reader], [], [])
            if self._wake_reader in readable:
                return None
            try:
                data, _ancillary, flags, address = self._socket.recvmsg(_RECEIVE_BYTES)
            except (BlockingIOError, InterruptedError):
                continue
            return Datagram(
                data=data,
                sender_pid=int(address[0]),
                sender_groups=int(address[1]),
                truncated=bool(flags & socket.MSG_TRUNC),
            )

    def interrupt(self) -> None:
        with contextlib.suppress(OSError):
            self._wake_writer.send(b"\0")

    def close(self) -> None:
        for item in (self._socket, self._wake_reader, self._wake_writer):
            with contextlib.suppress(OSError):
                item.close()


def open_kernel_uevent_socket() -> UeventTransport:
    """Open the kernel's uevent channel. The default transport of :class:`UeventMonitor`.

    Raises:
        BackendError: if it cannot be opened here.
    """
    return KernelUeventSocket()


@dataclass(frozen=True, slots=True)
class MonitorStats:
    """Counters of a :class:`UeventMonitor`, for ``portlock doctor`` and for tests.

    Attributes:
        received: messages read from the socket.
        accepted: messages passed on to the caller.
        ignored: well-formed kernel uevents about something other than USB.
        malformed: messages from the kernel that could not be parsed.
        foreign: messages dropped because they did not come from the kernel.
        overruns: times the kernel reported dropped messages (or one arrived truncated).
    """

    received: int = 0
    accepted: int = 0
    ignored: int = 0
    malformed: int = 0
    foreign: int = 0
    overruns: int = 0


UeventCallback = Callable[[UeventKind, Mapping[str, str]], None]


class UeventMonitor:
    """Receives kernel uevents on a background thread and reports the relevant ones.

    Args:
        on_event: called for each accepted uevent with its kind and its fields.
        on_overrun: called when messages were lost. The caller must assume that anything
            may have changed and re-enumerate.
        on_failure: called once if the socket fails for good; the monitor has stopped
            delivering by then, so the caller should switch to polling.
        transport_factory: opens the socket; replaceable for tests.

    All callbacks run on the monitor's thread and must not block for long: the socket is
    not read while one runs.
    """

    def __init__(
        self,
        on_event: UeventCallback,
        on_overrun: Callable[[], None],
        *,
        on_failure: Callable[[OSError], None] | None = None,
        transport_factory: Callable[[], UeventTransport] = open_kernel_uevent_socket,
    ) -> None:
        self._on_event = on_event
        self._on_overrun = on_overrun
        self._on_failure = on_failure
        self._transport_factory = transport_factory
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._transport: UeventTransport | None = None
        self._stop_requested = threading.Event()
        self._counters = dict.fromkeys(MonitorStats.__dataclass_fields__, 0)

    @property
    def stats(self) -> MonitorStats:
        """A consistent copy of the counters."""
        with self._lock:
            return MonitorStats(**self._counters)

    @property
    def running(self) -> bool:
        """True while the receive thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        """Open the socket and start receiving.

        Raises:
            BackendError: if the socket cannot be opened, or the monitor is running.
        """
        with self._lock:
            if self._thread is not None:
                raise BackendError("the uevent monitor is already running")
            transport = self._transport_factory()
            self._stop_requested = threading.Event()
            self._transport = transport
            self._thread = threading.Thread(
                target=self._run,
                args=(transport, self._stop_requested),
                name="portlock-uevent",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        """Stop receiving, wait for the thread to finish and close the socket.

        Safe to call when not started, more than once, and from a callback.
        """
        with self._lock:
            thread, transport = self._thread, self._transport
            stop_requested = self._stop_requested
            self._thread = self._transport = None
        if thread is None or transport is None:
            return
        stop_requested.set()
        transport.interrupt()
        if thread is not threading.current_thread():
            thread.join()
        transport.close()

    def _run(self, transport: UeventTransport, stop_requested: threading.Event) -> None:
        while not stop_requested.is_set():
            try:
                datagram = transport.receive()
            except OSError as exc:
                if stop_requested.is_set():
                    return
                if exc.errno == errno.ENOBUFS:
                    # The receive buffer filled up and the kernel threw messages away.
                    # Which ones is unknowable, so the only safe reaction is to tell the
                    # caller to look at everything again.
                    self._overrun("the kernel dropped uevents (receive buffer full)")
                    continue
                _log.error("the uevent socket failed: %s", exc)
                self._call(self._on_failure, exc)
                return
            if datagram is not None:
                self._handle(datagram)

    def _handle(self, datagram: Datagram) -> None:
        self._count("received")
        # Who sent this? Netlink is a datagram bus, not a pipe from the kernel: any
        # process the kernel allows can address a message to this socket, and it would
        # carry the same "add@/devices/..." text. Accepting such a message would let a
        # local process invent arrivals and removals, and an agent that believes them can
        # be made to re-evaluate, flood its audit log, or (if it ever trusted the
        # content) misjudge a device. udev had exactly this hole: CVE-2009-1185, local
        # root by sending it a forged uevent. Current kernels refuse unprivileged senders
        # on this protocol, but a process with CAP_NET_ADMIN is still allowed, and so was
        # everyone on kernels before that restriction. The kernel fills in the sender
        # address itself: port id 0 is the kernel and no user-space socket can have it.
        # So: only port id 0, and only the kernel's own broadcast group.
        if datagram.sender_pid != 0 or datagram.sender_groups != KERNEL_GROUP:
            total = self._count("foreign")
            if total == 1 or total % 1000 == 0:
                _log.warning(
                    "ignored %d netlink message(s) not sent by the kernel (latest from"
                    " port id %d, groups %#x)",
                    total,
                    datagram.sender_pid,
                    datagram.sender_groups,
                )
            return
        if datagram.truncated:
            # Part of an event is gone, which is no better than the whole event gone.
            self._overrun("a uevent was larger than the receive buffer")
            return
        fields = parse_uevent(datagram.data)
        if fields is None:
            self._count("malformed")
            return
        kind = classify_uevent(fields)
        if kind is None:
            self._count("ignored")
            return
        self._count("accepted")
        self._call(self._on_event, kind, fields)

    def _overrun(self, reason: str) -> None:
        self._count("overruns")
        _log.warning("%s; re-enumerating", reason)
        self._call(self._on_overrun)

    def _count(self, name: str) -> int:
        with self._lock:
            self._counters[name] += 1
            return self._counters[name]

    @staticmethod
    def _call(callback: Callable[..., None] | None, *arguments: object) -> None:
        if callback is None:
            return
        try:
            callback(*arguments)
        except Exception:
            # One failing callback must not end monitoring.
            _log.exception("uevent callback failed")


class DeviceChange(NamedTuple):
    """One difference between two snapshots."""

    type: DeviceEventType
    device: UsbDevice


def diff_devices(
    before: Mapping[str, UsbDevice], after: Mapping[str, UsbDevice]
) -> list[DeviceChange]:
    """Compare two snapshots keyed by ``instance_id``.

    * A key only in ``after`` is ``ARRIVED``; a key only in ``before`` is ``REMOVED``.
    * The same key with a different device behind it (other ids or serial, or another
      ``connection_id``, or failing that another ``devnum``, which the kernel assigns
      afresh on every connection) means the port was re-used between the snapshots:
      ``REMOVED`` for the old device, ``ARRIVED`` for the new one.
    * The same connection with different content, typically new volumes or a new mount
      point, is ``CHANGED``.

    Returns:
        Removals first (children before their hubs), then arrivals (hubs before their
        children), then changes.
    """
    removed: list[UsbDevice] = []
    arrived: list[UsbDevice] = []
    changed: list[UsbDevice] = []
    for key, old in before.items():
        new = after.get(key)
        if new is None:
            removed.append(old)
        elif not _same_connection(old, new):
            removed.append(old)
            arrived.append(new)
        elif new != old:
            changed.append(new)
    arrived.extend(device for key, device in after.items() if key not in before)

    removed.sort(key=_depth_key, reverse=True)
    arrived.sort(key=_depth_key)
    changed.sort(key=_depth_key)
    return (
        [DeviceChange(DeviceEventType.REMOVED, device) for device in removed]
        + [DeviceChange(DeviceEventType.ARRIVED, device) for device in arrived]
        + [DeviceChange(DeviceEventType.CHANGED, device) for device in changed]
    )


def _same_connection(old: UsbDevice, new: UsbDevice) -> bool:
    if (old.vendor_id, old.product_id, old.serial, old.bcd_device) != (
        new.vendor_id,
        new.product_id,
        new.serial,
        new.bcd_device,
    ):
        return False
    if old.connection_id is not None and new.connection_id is not None:
        return old.connection_id == new.connection_id
    old_number, new_number = old.backend_data.get("devnum"), new.backend_data.get("devnum")
    return old_number is None or new_number is None or old_number == new_number


def _depth_key(device: UsbDevice) -> tuple[int, str]:
    path = device.bus_path or ""
    return path.count(".") + (0 if path.startswith("usb") else 1), device.instance_id


class PollingMonitor:
    """The fallback when the uevent socket cannot be opened: compare snapshots.

    Every ``interval`` seconds it takes a snapshot and reports how it differs from the
    previous one. This sees everything a uevent would announce, later, with one gap that
    cannot be closed: a device plugged in and removed again between two polls is never
    seen.

    Args:
        snapshot: returns the devices present now; normally
            :func:`~portlock.guard.linux.sysfs.read_usb_devices` with mounts attached.
        on_changes: called from the polling thread with a non-empty list of differences.
        interval: seconds between polls; must be positive.
    """

    def __init__(
        self,
        snapshot: Callable[[], Iterable[UsbDevice]],
        on_changes: Callable[[list[DeviceChange]], None],
        *,
        interval: float = 2.0,
    ) -> None:
        if not interval > 0:
            raise ValueError("the polling interval must be greater than zero")
        self._snapshot = snapshot
        self._on_changes = on_changes
        self._interval = interval
        self._lock = threading.Lock()
        self._known: dict[str, UsbDevice] | None = None
        self._thread: threading.Thread | None = None
        self._stop_requested = threading.Event()

    def prime(self, baseline: Iterable[UsbDevice] | None = None) -> None:
        """Set the baseline: the devices in it will not be reported as arrivals.

        Args:
            baseline: the devices already reported by whoever was watching before. The
                first poll then reports everything that differs from it. ``None`` takes
                a snapshot now.

        Raises:
            BackendError: if the snapshot cannot be taken.
        """
        source = self._snapshot() if baseline is None else baseline
        current = {device.instance_id: device for device in source}
        with self._lock:
            self._known = current

    def poll_once(self) -> list[DeviceChange]:
        """Take a snapshot now and return how it differs from the previous one.

        The first call without :meth:`prime` only records the baseline. This is what the
        polling thread runs; it is public so that a caller can force a check.

        Raises:
            BackendError: if the snapshot cannot be taken. The previous snapshot is
                kept, so nothing is lost: the next successful poll reports the change.
        """
        current = {device.instance_id: device for device in self._snapshot()}
        with self._lock:
            previous, self._known = self._known, current
        return diff_devices(previous, current) if previous is not None else []

    def start(self) -> None:
        """Start polling. Takes the baseline first unless :meth:`prime` already did.

        Raises:
            BackendError: if the baseline snapshot fails, or polling is already running.
        """
        with self._lock:
            if self._thread is not None:
                raise BackendError("the polling monitor is already running")
            primed = self._known is not None
        if not primed:
            self.prime()
        with self._lock:
            if self._thread is not None:
                raise BackendError("the polling monitor is already running")
            self._stop_requested = threading.Event()
            self._thread = threading.Thread(
                target=self._run,
                args=(self._stop_requested,),
                name="portlock-poll",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        """Stop polling and wait for the thread. Safe to call when not started."""
        with self._lock:
            thread, stop_requested = self._thread, self._stop_requested
            self._thread = None
        if thread is None:
            return
        stop_requested.set()
        if thread is not threading.current_thread():
            thread.join()

    def _run(self, stop_requested: threading.Event) -> None:
        while not stop_requested.wait(self._interval):
            try:
                changes = self.poll_once()
            except BackendError as exc:
                _log.warning("polling for USB devices failed: %s", exc)
                continue
            except Exception:
                # The thread must outlive a bug in one read, or detection would stop
                # without anyone being told. The previous snapshot is kept.
                _log.exception("polling for USB devices failed unexpectedly")
                continue
            if changes and not stop_requested.is_set():
                try:
                    self._on_changes(changes)
                except Exception:
                    _log.exception("device change callback failed")
