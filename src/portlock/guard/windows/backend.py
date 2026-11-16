"""The Windows device backend: enumeration and arrival/removal monitoring.

:class:`WindowsBackend` implements :class:`~portlock.guard.base.DeviceBackend` on top of
the three modules beside it. It observes and nothing more: it needs no privilege and
changes no device or system state. Enforcement on Windows is a separate component; the
mechanisms it may use are specified in ``docs/enforcement/windows.md``.
"""

from __future__ import annotations

from portlock.core.clock import Clock
from portlock.core.models import UsbDevice
from portlock.guard.base import BackendCapabilities, DeviceBackend, EventCallback
from portlock.guard.windows.api import WinApi
from portlock.guard.windows.enumerate import ConnectionTokens, enumerate_usb_devices
from portlock.guard.windows.monitor import DeviceMonitor

__all__ = ["WindowsBackend"]

_UNAVAILABLE_NOTE = "the Windows device API is not available on this platform"
_IDENTITY_NOTES = (
    "manufacturer is not reported: Windows only knows the installed driver's "
    "manufacturer string, which is not a property of the device",
    "interfaces are reported per function (one per usbccgp child node), and only once "
    "a composite device's generic parent driver has started",
    "connection ids combine the instance id with DEVPKEY_Device_LastArrivalDate; a "
    "device without that property gets a token that changes when its removal is seen",
    "removable is False only directly on a root-hub port that Windows reports as fixed",
)


class WindowsBackend(DeviceBackend):
    """Observes USB devices on Windows. Read-only; needs no privilege.

    Devices are read from the Plug and Play device tree. Arrivals and removals are
    pushed by ``CM_Register_Notification`` where it exists (Windows 8 and later) and
    found by polling where it does not; :meth:`capabilities` says which is in effect.

    Contract with the caller (see :meth:`DeviceBackend.start`): call :meth:`start`
    first and :meth:`enumerate` second. A device that arrives between the two is then
    listed, reported, or both, and when it is both, the listing and the ``ARRIVED``
    event carry the same ``connection_id``, so the caller can recognise the duplicate.
    ``RESYNC`` asks the caller to enumerate again.

    Args:
        api: the Windows API seam. Tests pass a fake; by default the real one is used.
        clock: time source for event timestamps and debounce timing.
        settle_seconds: quiet time after the last notification before devices are
            re-read. This is what turns the burst of a composite device into one event.
        max_settle_seconds: upper bound on that wait.
        followup_seconds: delay before re-reading once more after a change, to pick up
            what Windows adds late (drive letters).
        poll_interval: seconds between snapshots when polling.
        resync_interval: seconds between safety re-checks while notifications are
            active; ``None`` disables them.
        force_polling: use the polling fallback even where notifications exist.
        sleep_gap_seconds: a worker that wakes this much later than planned reports
            ``RESYNC`` (a backstop for resume notifications); ``None`` disables it.

    Raises:
        BackendError: if the Windows libraries are present but cannot be loaded.
        ValueError: if a timing argument is out of range.
    """

    def __init__(
        self,
        api: WinApi | None = None,
        clock: Clock | None = None,
        *,
        settle_seconds: float = 0.25,
        max_settle_seconds: float = 2.0,
        followup_seconds: float = 1.0,
        poll_interval: float = 2.0,
        resync_interval: float | None = 30.0,
        force_polling: bool = False,
        sleep_gap_seconds: float | None = 60.0,
    ) -> None:
        self._api = api if api is not None else WinApi()
        # Shared by every enumeration pass and the monitor, so that a device listed by
        # the caller and reported by the monitor has one connection id.
        self._tokens = ConnectionTokens()
        self._monitor = DeviceMonitor(
            self._api,
            self.enumerate,
            clock,
            settle_seconds=settle_seconds,
            max_settle_seconds=max_settle_seconds,
            followup_seconds=followup_seconds,
            poll_interval=poll_interval,
            resync_interval=resync_interval,
            force_polling=force_polling,
            tokens=self._tokens,
            sleep_gap_seconds=sleep_gap_seconds,
        )

    def capabilities(self) -> BackendCapabilities:
        """Report what this backend can do on this machine right now.

        ``event_driven`` is True while notifications are registered and False while the
        polling fallback is in use. Before :meth:`start` it is the mode ``start`` is
        expected to select. ``notes`` names the mechanism, the reason for a fallback,
        and the standing limits of what Windows reports about a device.
        """
        if not self._api.available:
            return BackendCapabilities(
                name="windows",
                can_enumerate=False,
                event_driven=False,
                notes=(_UNAVAILABLE_NOTE,),
            )
        return BackendCapabilities(
            name="windows",
            can_enumerate=True,
            event_driven=self._monitor.event_driven,
            notes=(*self._monitor.notes, *_IDENTITY_NOTES),
        )

    def enumerate(self) -> list[UsbDevice]:
        """Return every USB device currently connected, hubs and root hubs included.

        Every device carries a ``connection_id``. Safe to call from any thread, whether
        or not the backend is started.

        Raises:
            BackendError: if the operating system cannot be queried (always the case on
                a platform other than Windows unless a fake API was supplied).
        """
        return enumerate_usb_devices(self._api, tokens=self._tokens)

    def start(self, on_event: EventCallback) -> None:
        """Begin reporting arrivals, removals and changes to ``on_event``.

        The callback is invoked from the backend's worker thread, one event at a time.
        Devices present when ``start`` takes its baseline are not reported: enumerate
        after ``start`` returns to learn them. ``RESYNC`` is reported when notifications
        were dropped, after a resume from sleep, and once the baseline is taken if it
        could not be taken at start. An exception raised by the callback is logged and
        does not stop the backend.

        Raises:
            BackendError: if the backend is already started (code ``already_started``)
                or the Windows device API is unavailable (code ``unsupported_platform``).
        """
        self._monitor.start(on_event)

    def stop(self) -> None:
        """Stop reporting and release operating-system resources.

        Safe to call when not started, and more than once. No event is delivered after
        this returns, unless it is called from inside the callback itself.
        """
        self._monitor.stop()
