"""The Linux device backend: enumeration from sysfs, notifications from the kernel.

:class:`LinuxBackend` observes and nothing more. It reads sysfs and the mount table,
listens for kernel uevents, and tells its caller when a USB device arrived, left or
changed. It needs no privilege and writes nothing; making the kernel refuse a device is
the enforcer's job (see ``docs/enforcement/linux.md``).

How a notification becomes an event:

1. A uevent (or a change of the mount table) arrives. It is only a hint.
2. :class:`ChangeTracker` waits until the hints have stopped for a moment. One plug-in
   produces a burst of them: the device, each of its interfaces, driver binding, and
   about a second later the disk and its partitions.
3. sysfs is read again and compared with the previous snapshot. A device that was not
   there is ``ARRIVED``, one that is gone is ``REMOVED``, and the same connection with
   new content (a volume appeared, a filesystem was mounted) is ``CHANGED``.

Because events are derived from state and not from the messages, a burst of uevents can
never produce two arrivals, lost uevents cost nothing but latency, and forged uevents
cannot invent a device. When the kernel reports that it dropped uevents (``ENOBUFS``),
sysfs is re-read at once and, after whatever that read found, a ``RESYNC`` event tells
the caller to enumerate again: a device that came and went while messages were being
dropped is invisible to any snapshot, and the caller must not rely on having seen every
connection.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import BackendError
from portlock.core.models import DeviceEvent, DeviceEventType, UsbDevice
from portlock.guard.base import BackendCapabilities, DeviceBackend, EventCallback
from portlock.guard.linux.mounts import (
    DEFAULT_MOUNTINFO,
    MountWatcher,
    attach_mounts,
    parse_mountinfo,
)
from portlock.guard.linux.netlink import (
    DeviceChange,
    PollingMonitor,
    UeventKind,
    UeventMonitor,
    UeventTransport,
    diff_devices,
    open_kernel_uevent_socket,
)
from portlock.guard.linux.sysfs import DEFAULT_BOOT_ID, read_boot_id, read_usb_devices

__all__ = ["ChangeTracker", "LinuxBackend"]

_log = logging.getLogger(__name__)

_MODE_EVENTS = "events"
_MODE_POLLING = "polling"
# Pause after a failed read of sysfs before trying again, so that a failure that does not
# go away cannot turn the worker into a busy loop.
_RETRY_SECONDS = 1.0


class _UeventUnavailable(BackendError):
    """The uevent socket could not be opened; polling is the way forward."""


class ChangeTracker:
    """Turns "something may have changed" hints into device events.

    The tracker is synchronous and driven by an injected clock, so its timing is tested
    without threads or sleeping. Whoever owns it calls :meth:`hint` when the operating
    system signals a change, asks :meth:`due_in` how long to wait, and calls
    :meth:`collect` when that time has passed.

    Args:
        snapshot: returns the devices present now.
        clock: source of monotonic time and of event timestamps.
        settle_seconds: how long the hints must have been quiet before sysfs is read.
            Reading in the middle of a burst is not wrong, only wasteful: each read is
            complete in itself.
        max_delay_seconds: upper bound on the wait, counted from the first hint, so that
            an endless stream of hints cannot postpone the read for ever.

    Raises:
        ValueError: unless ``0 <= settle_seconds <= max_delay_seconds``.

    All methods are safe to call from several threads.
    """

    def __init__(
        self,
        snapshot: Callable[[], Iterable[UsbDevice]],
        clock: Clock,
        *,
        settle_seconds: float = 0.25,
        max_delay_seconds: float = 2.0,
    ) -> None:
        if settle_seconds < 0 or max_delay_seconds < settle_seconds:
            raise ValueError("need 0 <= settle_seconds <= max_delay_seconds")
        self._snapshot = snapshot
        self._clock = clock
        self._settle = settle_seconds
        self._max_delay = max_delay_seconds
        self._lock = threading.Lock()
        # Held across "read sysfs, swap the snapshot" so two collectors cannot interleave
        # and report changes in the wrong order.
        self._collecting = threading.Lock()
        self._known: dict[str, UsbDevice] = {}
        self._first_hint: float | None = None
        self._last_hint: float | None = None
        self._urgent = False
        self._resync = False

    def prime(self) -> None:
        """Record the devices present now as the baseline; they are not reported.

        Hints received before this call are kept: a device that arrives while the
        baseline is being read must still be found by the next :meth:`collect`.

        Raises:
            BackendError: if the snapshot cannot be taken.
        """
        with self._collecting:
            current = {device.instance_id: device for device in self._snapshot()}
            with self._lock:
                self._known = current

    def known(self) -> list[UsbDevice]:
        """The devices as of the last read: what has been reported so far.

        Whoever takes over from this tracker (the polling fallback) starts from this list
        and not from a fresh read, so a change that happened during the hand-over is
        still reported.
        """
        with self._lock:
            return list(self._known.values())

    def hint(self, *, urgent: bool = False, resync: bool = False) -> None:
        """Note that the operating system signalled a change.

        Args:
            urgent: read on the next :meth:`collect` without waiting for quiet.
            resync: notifications were lost. Implies ``urgent`` (waiting cannot make the
                picture clearer), and the next successful :meth:`collect` ends with a
                ``RESYNC`` event.
        """
        now = self._clock.monotonic()
        with self._lock:
            if self._first_hint is None:
                self._first_hint = now
            self._last_hint = now
            self._urgent = self._urgent or urgent or resync
            self._resync = self._resync or resync

    def due_in(self) -> float | None:
        """Seconds until :meth:`collect` will read; ``0.0`` if now, ``None`` if idle."""
        now = self._clock.monotonic()
        with self._lock:
            return self._due_in(now)

    def collect(self) -> list[DeviceEvent]:
        """Read the device list if a read is due and report what changed.

        Returns:
            The events: removals, then arrivals, then changes, then ``RESYNC`` if
            notifications were lost since the last read. Empty if no read is due or
            nothing changed.

        Raises:
            BackendError: if the snapshot cannot be taken. The hints (and a pending
                ``RESYNC``) stay pending and the previous snapshot is kept, so the read is
                retried after another settle period and nothing is lost.
        """
        with self._collecting:
            now = self._clock.monotonic()
            with self._lock:
                due = self._due_in(now)
                if due is None or due > 0:
                    return []
                self._first_hint = self._last_hint = None
                self._urgent = False
                resync, self._resync = self._resync, False
            try:
                current = {device.instance_id: device for device in self._snapshot()}
            except Exception:
                # Any failure, expected or not, leaves the work pending.
                with self._lock:
                    self._resync = self._resync or resync
                # Not urgent: retrying a failed read at once would only fail again.
                self.hint()
                raise
            with self._lock:
                previous, self._known = self._known, current
        at = self._clock.now()
        events = [
            DeviceEvent(change.type, change.device, at)
            for change in diff_devices(previous, current)
        ]
        if resync:
            # Last, so that the caller's own enumeration starts from a tracker that is
            # already up to date: any later change produces a fresh hint and read.
            events.append(DeviceEvent(DeviceEventType.RESYNC, None, at))
        return events

    def _due_in(self, now: float) -> float | None:
        if self._first_hint is None or self._last_hint is None:
            return None
        if self._urgent:
            return 0.0
        quiet_at = self._last_hint + self._settle
        latest_at = self._first_hint + self._max_delay
        return max(0.0, min(quiet_at, latest_at) - now)


class LinuxBackend(DeviceBackend):
    """Observes USB devices on Linux. Read-only; needs no privilege.

    Notifications come from the kernel's uevent socket. Where that socket cannot be
    opened (a sandbox that filters netlink, a platform without it) the backend polls
    sysfs instead and says so in :meth:`capabilities`.

    Args:
        sysfs_root: where sysfs is mounted.
        mountinfo: the mount table used to fill in mount points, or ``None`` to leave
            volumes without them.
        clock: time source for event timestamps and for the settle delay.
        settle_seconds: quiet time after the last uevent before sysfs is re-read.
        max_delay_seconds: longest a re-read is postponed while uevents keep coming.
        poll_interval: seconds between snapshots when polling.
        transport_factory: opens the uevent socket; replaceable for tests.
        mount_watcher_factory: builds the mount table watcher from a callback and the
            table's path; replaceable for tests.
        boot_id_path: the kernel's boot id, which makes every device's
            ``connection_id`` unique across reboots. ``None``, or a file that cannot be
            read, leaves ``connection_id`` unset (``None``) on every device.

    Raises:
        ValueError: if a delay is negative, ``max_delay_seconds`` is smaller than
            ``settle_seconds``, or ``poll_interval`` is not positive.
    """

    def __init__(
        self,
        *,
        sysfs_root: Path = Path("/sys"),
        mountinfo: Path | None = DEFAULT_MOUNTINFO,
        clock: Clock | None = None,
        settle_seconds: float = 0.25,
        max_delay_seconds: float = 2.0,
        poll_interval: float = 2.0,
        transport_factory: Callable[[], UeventTransport] = open_kernel_uevent_socket,
        mount_watcher_factory: Callable[[Callable[[], None], Path], MountWatcher] = MountWatcher,
        boot_id_path: Path | None = DEFAULT_BOOT_ID,
    ) -> None:
        if settle_seconds < 0 or max_delay_seconds < settle_seconds:
            raise ValueError("need 0 <= settle_seconds <= max_delay_seconds")
        if not poll_interval > 0:
            raise ValueError("poll_interval must be greater than zero")
        self._sysfs_root = Path(sysfs_root)
        self._mountinfo = Path(mountinfo) if mountinfo is not None else None
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._settle_seconds = settle_seconds
        self._max_delay_seconds = max_delay_seconds
        self._poll_interval = poll_interval
        self._transport_factory = transport_factory
        self._mount_watcher_factory = mount_watcher_factory
        self._boot_id_path = Path(boot_id_path) if boot_id_path is not None else None
        # The boot id cannot change while this process runs, so a successful read is kept.
        # A failed one is retried by the next enumeration; the file is tiny.
        self._boot_id_lock = threading.Lock()
        self._boot_id: str | None = None

        # _lock guards every field below; _wake shares it and wakes the worker thread.
        self._lock = threading.Lock()
        self._wake = threading.Condition(self._lock)
        self._on_event: EventCallback | None = None
        # Counts calls to start(), so that work left over from an earlier run (a fallback
        # to polling that was still on its way) can tell that it is no longer wanted.
        self._generation = 0
        self._stopping = False
        self._mode: str | None = None
        self._fallback_reason: str | None = None
        self._mounts_watched = False
        self._worker: threading.Thread | None = None
        # Set to make the worker finish. Separate from _stopping: when the backend
        # switches to polling the worker must go, but what it has found is still delivered.
        self._worker_halt: threading.Event | None = None
        self._monitor: UeventMonitor | None = None
        self._poller: PollingMonitor | None = None
        self._mount_watcher: MountWatcher | None = None

    def capabilities(self) -> BackendCapabilities:
        """Report what this backend can do on this machine right now.

        While the backend is running, ``event_driven`` says how it is actually being
        notified. Before that, it says whether the uevent socket can be opened (it is
        opened and closed again to find out).
        """
        notes: list[str] = []
        devices_directory = self._sysfs_root / "bus" / "usb" / "devices"
        can_enumerate = devices_directory.is_dir()
        if not can_enumerate:
            notes.append(
                f"no USB bus under {self._sysfs_root}: this kernel exposes no USB devices"
                " (usual in WSL and in containers without the host's sysfs)"
            )
        with self._lock:
            mode, reason = self._mode, self._fallback_reason
            mounts_watched = self._mounts_watched
        if mode is None:
            reason = self._probe_uevent_socket()
            event_driven = reason is None
        else:
            event_driven = mode == _MODE_EVENTS
        if not event_driven:
            notes.append(
                f"kernel uevent socket unavailable ({reason}): polling every"
                f" {self._poll_interval:g} s; a device plugged in and removed between two"
                " polls is not seen"
            )
        if self._current_boot_id() is None:
            notes.append(
                "the kernel boot id cannot be read: devices are reported without a"
                " connection id, so a re-plug cannot be told from the same connection"
                " by that id"
            )
        if self._mountinfo is None:
            notes.append("no mount table configured: volumes are reported without mount points")
        elif mode == _MODE_EVENTS and not mounts_watched:
            notes.append(
                "the mount table cannot be watched: a mount is noticed only with the next"
                " device event"
            )
        return BackendCapabilities(
            name="linux",
            can_enumerate=can_enumerate,
            event_driven=event_driven,
            notes=tuple(notes),
        )

    def enumerate(self) -> list[UsbDevice]:
        """Return every USB device currently connected, with volumes and mount points.

        Each device carries a ``connection_id`` (boot id, bus number, device number)
        when the boot id can be read.

        Raises:
            BackendError: if sysfs cannot be read. An unreadable mount table is not an
                error: the volumes are then returned without mount points.
        """
        devices = read_usb_devices(self._sysfs_root, boot_id=self._current_boot_id())
        if self._mountinfo is None or not any(device.volumes for device in devices):
            return devices
        try:
            mounts = parse_mountinfo(self._mountinfo)
        except BackendError as exc:
            _log.debug("mount points unavailable: %s", exc)
            return devices
        return attach_mounts(devices, mounts)

    def start(self, on_event: EventCallback) -> None:
        """Begin reporting arrivals, removals and changes to ``on_event``.

        The callback runs on a backend thread, one call at a time. Listening begins
        before the baseline is read, and devices in the baseline are not reported. The
        caller calls ``start`` first and :meth:`enumerate` after it, so a device that
        arrives in between is seen by both (the caller's handling is idempotent per
        ``connection_id``) instead of by neither. If the kernel reports that uevents were
        dropped, the backend reports what a fresh read shows and then ``RESYNC``, after
        which the caller enumerates again.

        Raises:
            BackendError: if the backend is already started, or sysfs cannot be read.
        """
        with self._lock:
            if self._on_event is not None:
                raise BackendError("the Linux backend is already started")
            self._on_event = on_event
            self._stopping = False
            self._generation += 1
            generation = self._generation
        try:
            try:
                self._start_events(generation)
            except _UeventUnavailable as exc:
                _log.warning("%s; polling sysfs instead", exc)
                self._start_polling(str(exc), generation)
        except BackendError:
            self._stop_components()
            with self._lock:
                self._on_event = None
            raise

    def stop(self) -> None:
        """Stop reporting and release OS resources. Safe to call when not started.

        No event is delivered after this returns. It waits for the backend's threads to
        finish, except when it is called from the event callback itself: a thread cannot
        wait for itself, so that thread ends as soon as the callback returns.
        """
        self._stop_components()
        with self._lock:
            self._on_event = None

    # -- event-driven mode ------------------------------------------------------------

    def _start_events(self, generation: int) -> None:
        tracker = ChangeTracker(
            self.enumerate,
            self._clock,
            settle_seconds=self._settle_seconds,
            max_delay_seconds=self._max_delay_seconds,
        )

        def on_uevent(_kind: UeventKind, _fields: Mapping[str, str]) -> None:
            self._hint(tracker)

        def on_overrun() -> None:
            self._hint(tracker, resync=True)

        def on_mounts_changed() -> None:
            self._hint(tracker)

        def on_failure(error: OSError) -> None:
            self._on_monitor_failure(error, generation, tracker)

        monitor = UeventMonitor(
            on_uevent,
            on_overrun,
            on_failure=on_failure,
            transport_factory=self._transport_factory,
        )
        try:
            monitor.start()
        except BackendError as exc:
            raise _UeventUnavailable(str(exc)) from exc

        watcher: MountWatcher | None = None
        try:
            # Listening started before the baseline is read, so a device that arrives
            # during the read leaves a hint behind and is found by the first re-read.
            tracker.prime()
            if self._mountinfo is not None:
                watcher = self._mount_watcher_factory(on_mounts_changed, self._mountinfo)
                try:
                    watcher.start()
                except BackendError as exc:
                    _log.info("not watching the mount table: %s", exc)
                    watcher = None
        except BaseException:
            monitor.stop()
            raise

        halt = threading.Event()
        worker = threading.Thread(
            target=self._pump, args=(tracker, halt), name="portlock-linux-backend", daemon=True
        )
        with self._lock:
            wanted = self._generation == generation and not self._stopping
            if wanted:
                self._monitor = monitor
                self._mount_watcher = watcher
                self._mounts_watched = watcher is not None
                self._worker = worker
                self._worker_halt = halt
                self._mode = _MODE_EVENTS
                self._fallback_reason = None
                worker.start()
        if not wanted:
            # stop() ran while this was starting up.
            monitor.stop()
            if watcher is not None:
                watcher.stop()

    def _hint(self, tracker: ChangeTracker, *, resync: bool = False) -> None:
        tracker.hint(resync=resync)
        with self._wake:
            self._wake.notify_all()

    def _on_monitor_failure(self, error: OSError, generation: int, tracker: ChangeTracker) -> None:
        """The uevent socket died while running: carry on by polling.

        Runs on the monitor's own thread, which cannot stop itself and wait for itself,
        so the switch is handed to a thread of its own.
        """
        threading.Thread(
            target=self._switch_to_polling,
            args=(f"the uevent socket failed: {error.strerror or error}", generation, tracker),
            name="portlock-linux-fallback",
            daemon=True,
        ).start()

    def _switch_to_polling(self, reason: str, generation: int, tracker: ChangeTracker) -> None:
        with self._lock:
            if self._generation != generation or self._stopping or self._mode != _MODE_EVENTS:
                return
        # Not a final stop: the worker delivers what it has already found, then ends.
        self._stop_components(final=False)
        try:
            # Polling continues from what the tracker last reported, not from a fresh
            # read: a device that arrived during the switch is in neither, so it would
            # otherwise become part of the new baseline and never be announced.
            self._start_polling(reason, generation, baseline=tracker.known())
        except BackendError as exc:
            _log.error("cannot fall back to polling: %s", exc)

    def _pump(self, tracker: ChangeTracker, halt: threading.Event) -> None:
        while True:
            with self._wake:
                while not halt.is_set():
                    delay = tracker.due_in()
                    if delay is not None and delay <= 0:
                        break
                    self._wake.wait(delay)
                if halt.is_set():
                    return
            try:
                events = tracker.collect()
            except Exception as exc:
                # Whatever went wrong, this thread must not die: a dead worker would mean
                # detection stopped without anyone being told. The tracker kept its hints,
                # so the read is retried.
                if isinstance(exc, BackendError):
                    _log.warning("cannot read USB devices: %s", exc)
                else:
                    _log.exception("reading USB devices failed unexpectedly")
                with self._wake:
                    if not halt.is_set():
                        self._wake.wait(_RETRY_SECONDS)
                continue
            for event in events:
                self._deliver(event)

    # -- polling mode -----------------------------------------------------------------

    def _start_polling(
        self, reason: str, generation: int, baseline: list[UsbDevice] | None = None
    ) -> None:
        poller = PollingMonitor(self.enumerate, self._on_poll_changes, interval=self._poll_interval)
        poller.prime(baseline)
        with self._lock:
            if self._generation != generation or self._stopping:
                return
            self._poller = poller
            self._mode = _MODE_POLLING
            self._fallback_reason = reason
            self._mounts_watched = False
            # Started under the lock so that a concurrent stop() either sees the poller
            # and stops it, or has already made this method return above.
            poller.start()

    def _on_poll_changes(self, changes: list[DeviceChange]) -> None:
        at = self._clock.now()
        for change in changes:
            self._deliver(DeviceEvent(change.type, change.device, at))

    # -- shared -----------------------------------------------------------------------

    def _deliver(self, event: DeviceEvent) -> None:
        with self._lock:
            callback = None if self._stopping else self._on_event
        if callback is None:
            return
        try:
            callback(event)
        except Exception:
            # The pipeline failing on one event must not stop detection.
            where = event.device.bus_path if event.device is not None else None
            _log.exception("device event callback failed for %s (%s)", event.type.value, where)

    def _stop_components(self, *, final: bool = True) -> None:
        """Stop every thread and release the sockets.

        Args:
            final: the backend is being stopped, so nothing more may be delivered.
                ``False`` when only the way of being notified is being replaced.
        """
        with self._wake:
            if final:
                self._stopping = True
            monitor, self._monitor = self._monitor, None
            poller, self._poller = self._poller, None
            watcher, self._mount_watcher = self._mount_watcher, None
            worker, self._worker = self._worker, None
            halt, self._worker_halt = self._worker_halt, None
            if halt is not None:
                halt.set()
            self._mode = None
            self._mounts_watched = False
            self._wake.notify_all()
        if monitor is not None:
            monitor.stop()
        if watcher is not None:
            watcher.stop()
        if poller is not None:
            poller.stop()
        if worker is not None and worker is not threading.current_thread():
            worker.join()

    def _current_boot_id(self) -> str | None:
        if self._boot_id_path is None:
            return None
        with self._boot_id_lock:
            if self._boot_id is None:
                self._boot_id = read_boot_id(self._boot_id_path)
            return self._boot_id

    def _probe_uevent_socket(self) -> str | None:
        """Why the uevent socket cannot be opened, or ``None`` if it can."""
        try:
            transport = self._transport_factory()
        except BackendError as exc:
            return str(exc)
        transport.close()
        return None
