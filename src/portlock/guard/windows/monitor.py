"""Watch for USB devices arriving and leaving. Read-only.

Two sources of truth are combined, because neither is enough alone:

* **Notifications** say *when* to look. ``CM_Register_Notification`` calls back on an
  operating-system thread-pool thread for the USB device interface class, for volumes,
  and for every device instance (which is what reports a device that Windows enumerated
  but refused to install). The callback copies the payload into a queue and returns; it
  does nothing else.
* **Snapshots** say *what* changed. A worker thread takes the notifications off the
  queue, waits for the burst to end, enumerates, and compares the result with the
  previous snapshot. The difference becomes ``ARRIVED``, ``REMOVED`` and ``CHANGED``
  events.

Deriving events from snapshots rather than from individual notifications is what makes
them trustworthy: a composite device that produces a dozen notifications is one device
in the snapshot and therefore one ``ARRIVED``; a notification that was lost, duplicated
or arrived out of order cannot produce a wrong event, only a late one, and a periodic
re-check bounds how late. A re-plug between two snapshots is recognised by the device's
``connection_id`` changing, and becomes ``REMOVED`` followed by ``ARRIVED``.

``RESYNC`` tells the receiver to enumerate again because the monitor may have missed
something: the notification queue overflowed, the system resumed from sleep (reported by
``PowerRegisterSuspendResumeNotification``, or inferred when the worker wakes far later
than it asked to), or no baseline could be taken when monitoring started.

Where notifications are unavailable (Windows 7, or a registration failure) the same
machinery runs from a timer: the **polling fallback** compares snapshots every couple of
seconds.

:class:`ChangeTracker` holds all the timing logic and takes an injected clock, so it is
tested without threads and without sleeping. :class:`DeviceMonitor` adds the queue, the
worker thread and the registrations.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Final

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import BackendError
from portlock.core.models import DeviceEvent, DeviceEventType, UsbDevice
from portlock.guard.base import EventCallback
from portlock.guard.windows.api import (
    CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED,
    CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
    CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
    GUID_DEVINTERFACE_USB_DEVICE,
    GUID_DEVINTERFACE_VOLUME,
    PBT_APMRESUMEAUTOMATIC,
    PBT_APMRESUMESUSPEND,
    NotificationHandle,
    WinApi,
    decode_notify_event,
)
from portlock.guard.windows.enumerate import ConnectionTokens

__all__ = [
    "ChangeTracker",
    "DeviceMonitor",
    "SnapshotFunction",
    "classify_notification",
    "diff_snapshots",
    "removed_usb_instance",
]

_LOG = logging.getLogger(__name__)

#: Returns the devices present right now. Raises ``BackendError`` if it cannot tell.
SnapshotFunction = Callable[[], Iterable[UsbDevice]]

# Device instances whose arrival or removal can change what enumeration reports. Events
# for anything else (Bluetooth, audio endpoints, software devices) are ignored.
_USB_ENUMERATOR: Final = "USB"
_STORAGE_ENUMERATORS: Final = frozenset({"USBSTOR", "SCSI", "STORAGE"})
_RESUME_EVENTS: Final = frozenset({PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND})

_QUEUE_LIMIT: Final = 1024
_MAX_FOLLOW_UPS: Final = 3
_ERROR_RETRY_SECONDS: Final = 5.0
_JOIN_TIMEOUT_SECONDS: Final = 10.0
#: A worker that wakes this much later than it asked to was most likely suspended with
#: the rest of the system.
_DEFAULT_SLEEP_GAP_SECONDS: Final = 60.0


def classify_notification(payload: bytes) -> bool | None:
    """Decide what a notification payload means for the monitor.

    Returns:
        ``True`` for an event about a USB device itself, which extends the wait for the
        burst to end (more nodes of the same device are probably on their way);
        ``False`` for a storage event (a disk or volume appeared), which asks for a
        re-check without delaying one that is already due; ``None`` for an event about
        an unrelated device, which is ignored. A payload that cannot be decoded counts
        as ``True``: when in doubt, look.
    """
    event = decode_notify_event(payload)
    if event is None:
        return True
    if event.filter_type == CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE:
        return event.class_guid != GUID_DEVINTERFACE_VOLUME
    enumerator = event.name.partition("\\")[0].upper()
    if enumerator == _USB_ENUMERATOR:
        return True
    if enumerator in _STORAGE_ENUMERATORS:
        return False
    return None


def removed_usb_instance(action: int | None, payload: bytes) -> str | None:
    """Return the instance id a notification reports as removed, if it is a USB node."""
    if action != CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED:
        return None
    event = decode_notify_event(payload)
    if event is None or event.filter_type != CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
        return None
    if event.name.partition("\\")[0].upper() != _USB_ENUMERATOR:
        return None
    return event.name


def _key(device: UsbDevice) -> str:
    # Instance ids are case-insensitive.
    return device.instance_id.upper()


def _reconnected(before: UsbDevice, after: UsbDevice) -> bool:
    """True if the same instance id now belongs to a newer connection.

    The instance id survives a re-plug; the connection id does not. If it changed, the
    device was unplugged and plugged back in (or restarted) between two snapshots, even
    though it looks present in both.
    """
    first = before.connection_id
    second = after.connection_id
    return first is not None and second is not None and first != second


def diff_snapshots(
    old: Mapping[str, UsbDevice], new: Mapping[str, UsbDevice], at: datetime
) -> list[DeviceEvent]:
    """Turn two snapshots into events.

    Args:
        old: the previous snapshot, keyed by upper-cased instance id.
        new: the current snapshot, keyed the same way.
        at: the time to stamp the events with.

    Returns:
        ``REMOVED`` events (carrying the last known description), then ``ARRIVED``, then
        ``CHANGED``, each group in instance-id order. A device whose connection id
        changed between the snapshots yields ``REMOVED`` followed by ``ARRIVED``.
    """
    removed: list[DeviceEvent] = []
    arrived: list[DeviceEvent] = []
    changed: list[DeviceEvent] = []
    for key in sorted(old.keys() | new.keys()):
        before = old.get(key)
        after = new.get(key)
        if before is not None and after is None:
            removed.append(DeviceEvent(DeviceEventType.REMOVED, before, at))
        elif before is None and after is not None:
            arrived.append(DeviceEvent(DeviceEventType.ARRIVED, after, at))
        elif before is not None and after is not None:
            if _reconnected(before, after):
                removed.append(DeviceEvent(DeviceEventType.REMOVED, before, at))
                arrived.append(DeviceEvent(DeviceEventType.ARRIVED, after, at))
            elif before != after:
                changed.append(DeviceEvent(DeviceEventType.CHANGED, after, at))
    return removed + arrived + changed


def _differs(old: Mapping[str, UsbDevice], new: Mapping[str, UsbDevice]) -> bool:
    if old.keys() != new.keys():
        return True
    return any(old[key] != new[key] or _reconnected(old[key], new[key]) for key in old)


class ChangeTracker:
    """Decides when to enumerate and turns snapshot differences into events.

    The tracker is driven from one thread: call :meth:`trigger` when something may have
    changed, :meth:`next_wait` to learn how long to wait, and :meth:`step` to do
    whatever is due. All timing uses the injected clock's monotonic time.

    Three things can make a snapshot due:

    * a **trigger**. The snapshot is taken once ``settle_seconds`` have passed without a
      further *extending* trigger, and no later than ``max_settle_seconds`` after the
      first one. This is the debounce: the nodes of a composite device arrive as a
      burst, and the burst is answered once;
    * a **follow-up**, ``followup_seconds`` after a snapshot taken for a trigger, and
      again while follow-ups keep finding changes (a drive letter is assigned a little
      after its volume appears, and nothing announces it);
    * a **poll**, every ``poll_interval`` seconds. A poll does not report by itself: if
      the snapshot differs it raises a trigger, so a device that is half-way through
      arriving is still reported once, complete.

    :meth:`request_resync` makes the next successful snapshot end with a ``RESYNC``
    event. A tracker started with :meth:`start_unprimed` has no baseline; its first
    successful snapshot becomes the baseline and is reported as ``RESYNC`` alone.

    Args:
        snapshot: returns the devices present now.
        clock: time source.
        settle_seconds: quiet time required after the last extending trigger.
        max_settle_seconds: upper bound on the wait after the first trigger.
        followup_seconds: delay before each follow-up snapshot; 0 disables follow-ups.
        poll_interval: seconds between polls; ``None`` disables polling.
        tokens: connection tokens to end when a USB instance is reported removed.
        sleep_gap_seconds: waking this many seconds or more after the time
            :meth:`next_wait` asked for is treated as a resume from sleep; ``None``
            disables the check.

    Raises:
        ValueError: if a duration is negative, ``max_settle_seconds`` is smaller than
            ``settle_seconds``, or ``poll_interval`` or ``sleep_gap_seconds`` is not
            positive.
    """

    def __init__(
        self,
        snapshot: SnapshotFunction,
        clock: Clock,
        *,
        settle_seconds: float = 0.25,
        max_settle_seconds: float = 2.0,
        followup_seconds: float = 1.0,
        poll_interval: float | None = None,
        tokens: ConnectionTokens | None = None,
        sleep_gap_seconds: float | None = None,
    ) -> None:
        if settle_seconds < 0 or followup_seconds < 0:
            raise ValueError("durations must not be negative")
        if max_settle_seconds < settle_seconds:
            raise ValueError("max_settle_seconds must be at least settle_seconds")
        if poll_interval is not None and poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        if sleep_gap_seconds is not None and sleep_gap_seconds <= 0:
            raise ValueError("sleep_gap_seconds must be greater than zero")
        self._snapshot = snapshot
        self._clock = clock
        self._settle = float(settle_seconds)
        self._max_settle = float(max_settle_seconds)
        self._followup = float(followup_seconds)
        self._poll_interval = poll_interval
        self._tokens = tokens
        self._sleep_gap = sleep_gap_seconds
        self._baseline: dict[str, UsbDevice] = {}
        self._primed = False
        self._resync_pending = False
        self._first_trigger: float | None = None
        self._last_trigger: float | None = None
        self._followup_at: float | None = None
        self._followups_left = 0
        self._next_poll: float | None = None
        self._expected_wake: float | None = None
        self._last_error: str | None = None

    @property
    def known(self) -> tuple[UsbDevice, ...]:
        """The devices in the current baseline, in instance-id order."""
        return tuple(self._baseline[key] for key in sorted(self._baseline))

    @property
    def primed(self) -> bool:
        """True once a baseline has been taken."""
        return self._primed

    @property
    def last_error(self) -> str | None:
        """Why the most recent snapshot failed, or ``None`` if it succeeded."""
        return self._last_error

    def prime(self) -> None:
        """Take the baseline. Devices present now are never reported as arrivals.

        Raises:
            BackendError: if the devices cannot be enumerated.
        """
        self._baseline = self._take()
        self._primed = True
        self._resync_pending = False
        self._first_trigger = self._last_trigger = None
        self._followup_at = None
        self._followups_left = 0
        self._expected_wake = None
        self._last_error = None
        if self._poll_interval is not None:
            self._next_poll = self._clock.monotonic() + self._poll_interval

    def start_unprimed(self, reason: str) -> None:
        """Start without a baseline because the devices could not be listed.

        A snapshot is retried every few seconds. The first that succeeds becomes the
        baseline and is reported as ``RESYNC``, so the receiver enumerates instead of
        being told that every present device just arrived.
        """
        now = self._clock.monotonic()
        self._baseline = {}
        self._primed = False
        self._resync_pending = True
        self._first_trigger = self._last_trigger = None
        self._followups_left = 0
        self._followup_at = now + _ERROR_RETRY_SECONDS
        self._expected_wake = None
        self._last_error = reason
        if self._poll_interval is not None:
            self._next_poll = now + self._poll_interval

    def trigger(self, *, extend: bool = True) -> None:
        """Record that something may have changed.

        Args:
            extend: restart the quiet period. Pass False for an event that should cause
                a snapshot without delaying one that is already pending.
        """
        now = self._clock.monotonic()
        if self._first_trigger is None:
            self._first_trigger = self._last_trigger = now
        elif extend:
            self._last_trigger = now

    def request_resync(self) -> None:
        """Ask for a snapshot that ends with a ``RESYNC`` event.

        Used when notifications may have been missed. Requests made before the snapshot
        is taken are answered by one ``RESYNC``.
        """
        self._resync_pending = True
        self.trigger(extend=False)

    def notify(self, payload: bytes, action: int | None = None) -> bool:
        """Feed one operating-system notification to the tracker.

        The payload is classified with :func:`classify_notification`; one about an
        unrelated device is dropped without causing a snapshot. The removal of a USB
        device instance also ends its connection token, so that its next arrival gets a
        new connection id even where Windows records no arrival time.

        Returns:
            True if the notification raised a trigger, False if it was ignored.
        """
        if self._tokens is not None:
            removed = removed_usb_instance(action, payload)
            if removed is not None:
                self._tokens.forget(removed)
        extend = classify_notification(payload)
        if extend is None:
            return False
        self.trigger(extend=extend)
        return True

    def next_wait(self) -> float | None:
        """Seconds until something is due (0 if it is due now), or ``None`` if idle."""
        deadlines = [
            deadline
            for deadline in (self._trigger_deadline(), self._followup_at, self._next_poll)
            if deadline is not None
        ]
        if not deadlines:
            self._expected_wake = None
            return None
        self._expected_wake = min(deadlines)
        return max(0.0, self._expected_wake - self._clock.monotonic())

    def step(self) -> list[DeviceEvent]:
        """Do whatever is due now and return the events it produced, possibly none.

        Never raises for an enumeration failure: the failure is kept in
        :attr:`last_error`, the baseline is left alone, and another attempt is scheduled.
        """
        now = self._clock.monotonic()
        if (
            self._sleep_gap is not None
            and self._expected_wake is not None
            and now - self._expected_wake >= self._sleep_gap
        ):
            _LOG.info(
                "the device monitor woke %.0f s late; resynchronizing", now - self._expected_wake
            )
            self.request_resync()
        self._expected_wake = None
        events: list[DeviceEvent] = []
        deadline = self._trigger_deadline()
        if deadline is not None and now >= deadline:
            self._first_trigger = self._last_trigger = None
            self._followups_left = _MAX_FOLLOW_UPS
            events = self._rescan(now)
            # One follow-up always: what the trigger announced may not be visible yet.
            self._schedule_followup(now)
        elif self._followup_at is not None and now >= self._followup_at:
            self._followup_at = None
            events = self._rescan(now)
            if events:
                self._schedule_followup(now)
        if (
            self._next_poll is not None
            and self._poll_interval is not None
            and now >= self._next_poll
        ):
            self._next_poll = now + self._poll_interval
            if not events and self._first_trigger is None and self._poll_found_change():
                self.trigger()
        return events

    def _trigger_deadline(self) -> float | None:
        if self._first_trigger is None or self._last_trigger is None:
            return None
        return min(self._last_trigger + self._settle, self._first_trigger + self._max_settle)

    def _schedule_followup(self, now: float) -> None:
        if self._followup > 0 and self._followups_left > 0 and self._followup_at is None:
            self._followups_left -= 1
            self._followup_at = now + self._followup

    def _take(self) -> dict[str, UsbDevice]:
        return {_key(device): device for device in self._snapshot()}

    def _rescan(self, now: float) -> list[DeviceEvent]:
        try:
            current = self._take()
        except BackendError as exc:
            self._last_error = str(exc)
            _LOG.warning("device enumeration failed, will retry: %s", exc)
            self._followup_at = now + _ERROR_RETRY_SECONDS
            return []
        self._last_error = None
        at = self._clock.now()
        if not self._primed:
            self._baseline = current
            self._primed = True
            self._resync_pending = False
            return [DeviceEvent(DeviceEventType.RESYNC, None, at)]
        events = diff_snapshots(self._baseline, current, at)
        self._baseline = current
        if self._resync_pending:
            self._resync_pending = False
            events.append(DeviceEvent(DeviceEventType.RESYNC, None, at))
        return events

    def _poll_found_change(self) -> bool:
        try:
            current = self._take()
        except BackendError as exc:
            self._last_error = str(exc)
            _LOG.warning("device enumeration failed during a poll: %s", exc)
            return False
        self._last_error = None
        return not self._primed or _differs(self._baseline, current)


class _Signal:
    """A queue sentinel that is not a notification payload."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"_Signal({self.name})"


#: Wakes the worker so it can see the stop request.
_STOP: Final = _Signal("stop")
#: The system resumed from sleep.
_RESUME: Final = _Signal("resume")

_QueueItem = tuple[int, bytes] | _Signal


class DeviceMonitor:
    """Reports USB arrivals, removals and changes to a callback, from its own thread.

    ``start`` registers for notifications where the operating system supports them and
    falls back to polling where it does not; :attr:`event_driven` says which is in
    effect and :attr:`notes` says why. Events are delivered one at a time, in order,
    from a single worker thread. A callback that raises is logged and does not stop the
    monitor.

    The object is thread-safe: ``start``, ``stop`` and the properties may be called from
    any thread, and ``stop`` may be called from inside the callback.

    Args:
        api: the Windows API seam.
        snapshot: returns the devices present now (normally the backend's enumeration).
        clock: time source for event timestamps and debounce timing.
        settle_seconds / max_settle_seconds / followup_seconds: see
            :class:`ChangeTracker`.
        poll_interval: seconds between snapshots in the polling fallback.
        resync_interval: seconds between safety re-checks while notifications are
            active; ``None`` disables them.
        force_polling: never register for notifications.
        tokens: connection tokens shared with ``snapshot``, ended on removal
            notifications.
        sleep_gap_seconds: see :class:`ChangeTracker`; ``None`` disables the check.
    """

    def __init__(
        self,
        api: WinApi,
        snapshot: SnapshotFunction,
        clock: Clock | None = None,
        *,
        settle_seconds: float = 0.25,
        max_settle_seconds: float = 2.0,
        followup_seconds: float = 1.0,
        poll_interval: float = 2.0,
        resync_interval: float | None = 30.0,
        force_polling: bool = False,
        tokens: ConnectionTokens | None = None,
        sleep_gap_seconds: float | None = _DEFAULT_SLEEP_GAP_SECONDS,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        if resync_interval is not None and resync_interval <= 0:
            raise ValueError("resync_interval must be greater than zero")
        self._api = api
        self._snapshot = snapshot
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._settle = settle_seconds
        self._max_settle = max_settle_seconds
        self._followup = followup_seconds
        self._poll_interval = poll_interval
        self._resync_interval = resync_interval
        self._force_polling = force_polling
        self._tokens = tokens
        self._sleep_gap = sleep_gap_seconds
        # Validate the timing arguments now rather than at start().
        self._new_tracker(event_driven=False)

        self._lock = threading.Lock()
        self._state = "stopped"
        self._event_driven = False
        self._notes: tuple[str, ...] = ()
        self._handles: list[NotificationHandle] = []
        self._resume_handle: NotificationHandle | None = None
        self._queue: queue.Queue[_QueueItem] | None = None
        self._stop_requested: threading.Event | None = None
        self._thread: threading.Thread | None = None

    def _new_tracker(self, *, event_driven: bool) -> ChangeTracker:
        return ChangeTracker(
            self._snapshot,
            self._clock,
            settle_seconds=self._settle,
            max_settle_seconds=self._max_settle,
            followup_seconds=self._followup,
            poll_interval=self._resync_interval if event_driven else self._poll_interval,
            tokens=self._tokens,
            sleep_gap_seconds=self._sleep_gap,
        )

    # -- state -------------------------------------------------------------------------

    @property
    def running(self) -> bool:
        """True between a successful ``start`` and the matching ``stop``."""
        with self._lock:
            return self._state == "running"

    @property
    def event_driven(self) -> bool:
        """True if notifications drive the monitor, False if it polls.

        While stopped this is the mode ``start`` is expected to select.
        """
        with self._lock:
            if self._state == "stopped":
                return self._can_register()
            return self._event_driven

    @property
    def notes(self) -> tuple[str, ...]:
        """Human-readable lines describing the mode in effect and any shortfall."""
        with self._lock:
            if self._state != "stopped":
                return self._notes
            if self._can_register():
                return ("not started; will use CM_Register_Notification",)
            return (f"not started; will poll every {self._poll_interval:g} s",)

    def _can_register(self) -> bool:
        if self._force_polling:
            return False
        try:
            return self._api.supports_notifications()
        except BackendError:
            return False

    # -- lifecycle ---------------------------------------------------------------------

    def start(self, on_event: EventCallback) -> None:
        """Begin reporting to ``on_event``.

        Notifications are registered *before* the baseline snapshot is taken, and the
        caller enumerates *after* this returns, so a device that arrives in between is
        listed, reported, or both, but never lost. Devices in the baseline are not
        reported. If the baseline cannot be taken, monitoring starts anyway and a
        ``RESYNC`` is delivered once the devices can be listed.

        Raises:
            BackendError: if the monitor is already started or stopping
                (code ``already_started``), or the Windows device API is not available
                (code ``unsupported_platform``).
        """
        with self._lock:
            if self._state != "stopped":
                raise BackendError(
                    "the device monitor is already started (or is still stopping)",
                    code="already_started",
                )
            if not self._api.available:
                raise BackendError(
                    "the Windows device API is not available on this platform",
                    code="unsupported_platform",
                )
            events: queue.Queue[_QueueItem] = queue.Queue(maxsize=_QUEUE_LIMIT)
            overflow = threading.Event()
            handles, resume_handle, event_driven, notes = self._subscribe(events, overflow)
            tracker = self._new_tracker(event_driven=event_driven)
            try:
                tracker.prime()
            except BackendError as exc:
                _LOG.warning("no device baseline at start, will resynchronize: %s", exc)
                tracker.start_unprimed(str(exc))
            except BaseException:
                self._unsubscribe(handles, resume_handle)
                raise
            stop_requested = threading.Event()
            thread = threading.Thread(
                target=self._run,
                args=(tracker, events, overflow, stop_requested, on_event),
                name="portlock-win-monitor",
                daemon=True,
            )
            self._handles = handles
            self._resume_handle = resume_handle
            self._event_driven = event_driven
            self._notes = notes
            self._queue = events
            self._stop_requested = stop_requested
            self._thread = thread
            self._state = "running"
            thread.start()

    def stop(self) -> None:
        """Stop reporting and release the registrations. Safe when not started.

        Returns once the registrations are closed and the worker has finished, so no
        callback runs after ``stop`` returns. Called from inside the callback it returns
        without waiting for the worker, which ends as soon as the callback does.
        """
        with self._lock:
            if self._state != "running":
                return
            self._state = "stopping"
            handles = self._handles
            resume_handle = self._resume_handle
            events = self._queue
            stop_requested = self._stop_requested
            thread = self._thread
            self._handles = []
            self._resume_handle = None
        try:
            # Outside the lock: unregistering waits for callbacks in flight, and joining
            # waits for a callback that may itself be asking this object for its state.
            self._unsubscribe(handles, resume_handle)
            if stop_requested is not None:
                stop_requested.set()
            if events is not None:
                # If the queue is full the worker is about to wake anyway.
                with contextlib.suppress(queue.Full):
                    events.put_nowait(_STOP)
            if thread is not None and thread is not threading.current_thread():
                thread.join(_JOIN_TIMEOUT_SECONDS)
                if thread.is_alive():
                    _LOG.warning("the device monitor thread did not stop in time")
        finally:
            with self._lock:
                self._state = "stopped"
                self._queue = None
                self._stop_requested = None
                self._thread = None
                self._event_driven = False
                self._notes = ()

    # -- notifications -----------------------------------------------------------------

    def _subscribe(
        self, events: queue.Queue[_QueueItem], overflow: threading.Event
    ) -> tuple[list[NotificationHandle], NotificationHandle | None, bool, tuple[str, ...]]:
        """Register for notifications, or explain why the monitor will poll instead.

        Returns the device registrations, the resume registration (or ``None``), whether
        the monitor is event driven, and the notes describing it.
        """

        def put(item: _QueueItem) -> None:
            # Operating-system thread: hand over and return. A dropped item is not lost
            # information as long as the worker learns that something was dropped.
            try:
                events.put_nowait(item)
            except queue.Full:
                overflow.set()

        def sink(action: int, payload: bytes) -> None:
            put((action, payload))

        def power_sink(event_type: int) -> None:
            if event_type in _RESUME_EVENTS:
                put(_RESUME)

        polling = f"polling every {self._poll_interval:g} s"
        if self._force_polling:
            return [], None, False, (f"{polling}: notifications disabled by configuration",)
        resume_handle, resume_note = self._subscribe_resume(power_sink)
        if not self._can_register():
            return (
                [],
                resume_handle,
                False,
                (f"{polling}: CM_Register_Notification is not available", resume_note),
            )
        try:
            primary = self._api.register_interface_notification(GUID_DEVINTERFACE_USB_DEVICE, sink)
        except BackendError as exc:
            return [], resume_handle, False, (f"{polling}: {exc}", resume_note)
        handles = [primary]
        sources = ["USB device interface"]
        notes: list[str] = []
        optional: tuple[tuple[str, Callable[[], NotificationHandle]], ...] = (
            (
                "volume interface",
                lambda: self._api.register_interface_notification(GUID_DEVINTERFACE_VOLUME, sink),
            ),
            ("device instances", lambda: self._api.register_instance_notification(sink)),
        )
        for label, register in optional:
            try:
                handles.append(register())
                sources.append(label)
            except BackendError as exc:
                notes.append(f"no {label} notifications: {exc}")
        summary = "notifications: CM_Register_Notification (" + ", ".join(sources) + ")"
        if self._resync_interval is not None:
            summary += f", re-checked every {self._resync_interval:g} s"
        return handles, resume_handle, True, (summary, *notes, resume_note)

    def _subscribe_resume(
        self, power_sink: Callable[[int], None]
    ) -> tuple[NotificationHandle | None, str]:
        """Register for resume-from-sleep events; return the handle (or None) and a note."""
        fallback = (
            f"; waking {self._sleep_gap:g} s late is treated as a resume"
            if self._sleep_gap is not None
            else ""
        )
        try:
            if not self._api.supports_resume_notifications():
                return None, (
                    "no resume notifications: PowerRegisterSuspendResumeNotification "
                    f"is not available{fallback}"
                )
            handle = self._api.register_resume_notification(power_sink)
        except BackendError as exc:
            return None, f"no resume notifications: {exc}{fallback}"
        return handle, "resume from sleep: PowerRegisterSuspendResumeNotification"

    def _unsubscribe(
        self, handles: list[NotificationHandle], resume_handle: NotificationHandle | None
    ) -> None:
        for handle in handles:
            try:
                self._api.unregister_notification(handle)
            except BackendError as exc:
                _LOG.warning("could not unregister %r: %s", handle, exc)
        if resume_handle is not None:
            try:
                self._api.unregister_resume_notification(resume_handle)
            except BackendError as exc:
                _LOG.warning("could not unregister %r: %s", resume_handle, exc)

    # -- worker ------------------------------------------------------------------------

    def _run(
        self,
        tracker: ChangeTracker,
        events: queue.Queue[_QueueItem],
        overflow: threading.Event,
        stop_requested: threading.Event,
        on_event: EventCallback,
    ) -> None:
        while not stop_requested.is_set():
            wait = tracker.next_wait()
            try:
                item: _QueueItem | None = events.get(timeout=wait)
            except queue.Empty:
                item = None
            # Drain the burst so that it is classified, and answered, as one.
            while item is not None:
                if isinstance(item, _Signal):
                    if item is _STOP:
                        return
                    tracker.request_resync()
                else:
                    action, payload = item
                    tracker.notify(payload, action)
                try:
                    item = events.get_nowait()
                except queue.Empty:
                    item = None
            if overflow.is_set():
                # Cleared before resynchronizing, so a drop after this point is seen on
                # the next round.
                overflow.clear()
                _LOG.warning("device notifications were dropped; resynchronizing")
                tracker.request_resync()
            if stop_requested.is_set():
                return
            for event in tracker.step():
                if stop_requested.is_set():
                    return
                try:
                    on_event(event)
                except Exception:
                    _LOG.exception("the device event callback failed for a %s event", event.type)
