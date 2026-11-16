"""A simulated machine: the device backend and enforcer that touch nothing real.

:class:`FakeBackend` and :class:`FakeEnforcer` are the test double for the whole service
and what ``portlock simulate`` runs on. They keep the contracts in
:mod:`portlock.guard.base` exactly, so that code proven against them behaves the same
against the Windows and Linux backends:

* the backend reports nothing before ``start``, gives every connection its own
  ``connection_id``, treats a second ``start`` as an error, delivers events one at a
  time from a single thread, and can report ``RESYNC``;
* the enforcer is idempotent, returns expected failures instead of raising, describes
  every change with journal entries that :meth:`FakeEnforcer.restore` can undo (only
  where the value is still the one it applied), and never pretends to a capability it
  was configured without.

Neither class reads or changes anything on the machine it runs on.
"""

from __future__ import annotations

import dataclasses
import itertools
import logging
import secrets
import threading
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import BackendError, EnforcementError, NotPrivilegedError
from portlock.core.models import DeviceEvent, DeviceEventType, UsbDevice
from portlock.guard.base import (
    Action,
    BackendCapabilities,
    DeviceBackend,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    EventCallback,
    JournalEntry,
    JournalKind,
    Tier,
)

__all__ = [
    "AUTHORIZED_DEFAULT_TARGET",
    "AUTHORIZED_DEFAULT_VALUES",
    "JOURNAL_KIND",
    "DeviceListener",
    "EnforcerCall",
    "FakeBackend",
    "FakeEnforcer",
    "authorized_target",
    "read_only_target",
]

#: The ``JournalEntry.kind`` of every entry the fake enforcer writes, and the only kind
#: it can restore: simulated state must never be mistaken for real operating-system
#: state, nor real state be "restored" by the simulation.
JOURNAL_KIND = JournalKind.FAKE
#: Target of the machine-wide entry, modelled on Linux ``authorized_default``.
AUTHORIZED_DEFAULT_TARGET = "authorized_default"
#: Values the simulated ``authorized_default`` can hold, as on Linux: ``-1`` authorize
#: wired devices, ``0`` authorize nothing (default-deny), ``1`` authorize everything
#: (the starting value), ``2`` authorize internal devices only. PortLock writes only
#: ``0`` and ``1``; the others are what another program may set.
AUTHORIZED_DEFAULT_VALUES: tuple[str, ...] = ("-1", "0", "1", "2")

#: Told about every plug, unplug and update of a :class:`FakeBackend`, started or not.
DeviceListener = Callable[[DeviceEventType, UsbDevice], None]

_LOG = logging.getLogger(__name__)
_STOP_TIMEOUT_SECONDS = 5.0

_AUTHORIZED_SUFFIX = "/authorized"
_READ_ONLY_SUFFIX = "/ro"
# Values of the simulated ``authorized_default``: new devices are admitted, or kept out.
_ALLOW, _DENY = "1", "0"
# Simulated values of a device's ``authorized`` and ``ro`` attributes.
_ON, _OFF = "1", "0"


def authorized_target(instance_id: str) -> str:
    """The journal target of one device's simulated ``authorized`` attribute."""
    return instance_id + _AUTHORIZED_SUFFIX


def read_only_target(instance_id: str) -> str:
    """The journal target of one device's simulated read-only flag."""
    return instance_id + _READ_ONLY_SUFFIX


_MECHANISMS: dict[Action, str] = {
    Action.BLOCK: "fake:authorized",
    Action.UNBLOCK: "fake:authorized",
    Action.READ_ONLY: "fake:read_only",
    Action.READ_WRITE: "fake:read_only",
    Action.EJECT: "fake:eject",
    Action.DEFAULT_DENY_ON: "fake:default_deny",
    Action.DEFAULT_DENY_OFF: "fake:default_deny",
    Action.RESTORE: "fake:restore",
}


class FakeBackend(DeviceBackend):
    """A device backend whose devices are plugged in by the test (or the simulator).

    Events follow the real backends' rules (``DeviceBackend.start``). Nothing is
    reported before :meth:`start`; devices already present at ``start`` are never
    announced, because the caller starts the backend and *then* enumerates; removing or
    updating such a device afterwards *is* reported. A device plugged in between
    ``start`` and the caller's :meth:`enumerate` is therefore seen both ways, exactly
    the overlap the contract tells callers to expect. Events are delivered strictly one
    at a time, in the order the changes were made.

    Every connection gets a fresh ``connection_id`` (the device passed to :meth:`plug`
    is stored and reported with it); :meth:`update` keeps the connection's id, and
    plugging the same device in again gives it a new one. A change made with
    ``quiet=True`` is not reported, as when a real backend's notification queue
    overflows; :meth:`resync` then reports ``RESYNC`` so the caller enumerates again.

    Delivery has two modes:

    * **Threaded** (the default) is what real backends do: a backend thread calls the
      callback. :meth:`wait_idle` blocks until everything queued has been delivered,
      so tests need no sleeping. An exception from the callback is logged, kept in
      :attr:`callback_errors`, and does not stop later events.
    * **Synchronous** (``synchronous=True``) is for deterministic tests:
      :meth:`plug`, :meth:`unplug` and :meth:`update` return only after the callback
      has handled the event, and re-raise an exception the callback raised. A change
      made from *inside* the callback is delivered after the current callback returns,
      never nested within it, because no real backend re-enters its callback.

    All methods are thread-safe.

    Args:
        devices: devices that are already connected.
        clock: source of event timestamps; the system clock if omitted.
        synchronous: deliver on the calling thread, as described above.
        name: reported in :meth:`capabilities`.

    Raises:
        ValueError: if two of ``devices`` share an instance id.
    """

    def __init__(
        self,
        devices: Iterable[UsbDevice] = (),
        *,
        clock: Clock | None = None,
        synchronous: bool = False,
        name: str = "fake",
    ) -> None:
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._synchronous = bool(synchronous)
        self._name = name
        # One condition guards all state below. It is released while the callback runs.
        self._cond = threading.Condition(threading.RLock())
        self._devices: dict[str, UsbDevice] = {}
        self._listeners: list[DeviceListener] = []
        self._callback: EventCallback | None = None
        self._generation = 0
        self._queue: deque[tuple[int, int, DeviceEvent]] = deque()
        self._enqueued = 0
        self._settled = 0
        self._pumper: int | None = None
        self._worker: threading.Thread | None = None
        self._enumerate_error: str | None = None
        self._callback_errors: list[Exception] = []
        # Connection ids are unique within this backend (the counter) and across
        # backends and runs (the random prefix), as a "once" grant bound to one must
        # never match a later connection.
        self._connection_prefix = f"{name}-{secrets.token_hex(4)}"
        self._connection_counter = itertools.count(1)
        for device in devices:
            _require_device(device)
            if device.instance_id in self._devices:
                raise ValueError(f"duplicate instance id {device.instance_id!r}")
            self._devices[device.instance_id] = self._new_connection(device)

    # --- DeviceBackend ---------------------------------------------------------------

    def capabilities(self) -> BackendCapabilities:
        """Report the simulated backend (enumeration fails while an error is injected)."""
        with self._cond:
            failing = self._enumerate_error is not None
        notes = ["simulated devices: no hardware is read or changed"]
        if failing:
            notes.append("enumeration is set to fail")
        return BackendCapabilities(
            name=self._name, can_enumerate=not failing, event_driven=True, notes=tuple(notes)
        )

    def enumerate(self) -> list[UsbDevice]:
        """Return every connected device, in the order they were plugged in.

        Raises:
            BackendError: if a failure was injected with :meth:`fail_enumerate`.
        """
        with self._cond:
            if self._enumerate_error is not None:
                raise BackendError(self._enumerate_error)
            return list(self._devices.values())

    def start(self, on_event: EventCallback) -> None:
        """Begin reporting changes to ``on_event``.

        Raises:
            BackendError: if the backend is already started.
            TypeError: if ``on_event`` is not callable.
        """
        if not callable(on_event):
            raise TypeError(f"on_event must be callable, got {type(on_event).__name__}")
        with self._cond:
            if self._callback is not None:
                raise BackendError("the fake backend is already started; call stop() first")
            self._callback = on_event
            self._generation += 1
            if not self._synchronous:
                self._worker = threading.Thread(
                    target=self._run_worker,
                    args=(self._generation,),
                    name="portlock-fake-backend",
                    daemon=True,
                )
                self._worker.start()

    def stop(self) -> None:
        """Stop reporting. Safe to call when not started, and from inside the callback.

        Events not yet delivered are discarded. When ``stop`` returns, no callback is
        running (unless ``stop`` was called from the callback itself) and none will
        start. If a callback is stuck, ``stop`` gives up waiting for it after five
        seconds rather than hang.
        """
        me = threading.get_ident()
        with self._cond:
            self._callback = None
            self._generation += 1
            self._queue.clear()
            self._settled = self._enqueued
            worker, self._worker = self._worker, None
            self._cond.notify_all()
            self._cond.wait_for(
                lambda: self._pumper is None or self._pumper == me, timeout=_STOP_TIMEOUT_SECONDS
            )
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=_STOP_TIMEOUT_SECONDS)

    # --- the simulated world ---------------------------------------------------------

    @property
    def started(self) -> bool:
        """True between :meth:`start` and :meth:`stop`."""
        with self._cond:
            return self._callback is not None

    @property
    def synchronous(self) -> bool:
        """True if events are delivered on the thread that made the change."""
        return self._synchronous

    @property
    def callback_errors(self) -> tuple[Exception, ...]:
        """Every exception the event callback has raised, oldest first."""
        with self._cond:
            return tuple(self._callback_errors)

    def get(self, instance_id: str) -> UsbDevice | None:
        """The connected device with this instance id, or ``None``."""
        with self._cond:
            return self._devices.get(instance_id)

    def is_present(self, instance_id: str) -> bool:
        """True if a device with this instance id is connected."""
        with self._cond:
            return instance_id in self._devices

    def add_listener(self, listener: DeviceListener) -> list[UsbDevice]:
        """Be told of every plug, unplug and update, whether or not the backend is started.

        This is the "physical world" side of the simulation, used by
        :class:`FakeEnforcer` to keep per-connection state. The listener runs inside
        the call that made the change, before the event is queued, and must not call
        back into the backend.

        Returns:
            The devices connected at the moment the listener was added. Taken together
            with the notifications that follow, that is a gap-free view of what is
            connected.
        """
        if not callable(listener):
            raise TypeError(f"listener must be callable, got {type(listener).__name__}")
        with self._cond:
            self._listeners.append(listener)
            return list(self._devices.values())

    def plug(self, device: UsbDevice, *, quiet: bool = False) -> UsbDevice:
        """Connect a device. Reports ``ARRIVED`` if the backend is started.

        Args:
            device: the device; any ``connection_id`` it carries is replaced.
            quiet: make the change without reporting it (a missed notification).

        Returns:
            The device as connected, with its new ``connection_id``.

        Raises:
            ValueError: if a device with the same instance id is already connected.
            TypeError: if ``device`` is not a :class:`UsbDevice`.
        """
        _require_device(device)
        with self._cond:
            if device.instance_id in self._devices:
                raise ValueError(f"{device.instance_id!r} is already connected")
            connected = self._new_connection(device)
            self._devices[device.instance_id] = connected
            ticket = self._changed_locked(DeviceEventType.ARRIVED, connected, quiet=quiet)
        self._after_change(ticket)
        return connected

    def unplug(self, instance_id: str, *, quiet: bool = False) -> UsbDevice:
        """Disconnect a device. Reports ``REMOVED`` if the backend is started.

        Args:
            instance_id: the device to disconnect.
            quiet: make the change without reporting it (a missed notification).

        Returns:
            The device as it was last known.

        Raises:
            KeyError: if no device with that instance id is connected.
        """
        with self._cond:
            device = self._devices.pop(instance_id, None)
            if device is None:
                raise KeyError(f"{instance_id!r} is not connected")
            ticket = self._changed_locked(DeviceEventType.REMOVED, device, quiet=quiet)
        self._after_change(ticket)
        return device

    def update(self, device: UsbDevice, *, quiet: bool = False) -> UsbDevice:
        """Replace the description of a connected device (for example: a volume was
        mounted). Reports ``CHANGED`` if the backend is started.

        The connection is the same one, so it keeps its ``connection_id`` whatever
        ``device`` carries.

        Returns:
            The device as now described, with the connection's ``connection_id``.

        Raises:
            KeyError: if no device with the same instance id is connected.
            TypeError: if ``device`` is not a :class:`UsbDevice`.
        """
        _require_device(device)
        with self._cond:
            current = self._devices.get(device.instance_id)
            if current is None:
                raise KeyError(f"{device.instance_id!r} is not connected")
            updated = dataclasses.replace(device, connection_id=current.connection_id)
            self._devices[device.instance_id] = updated
            ticket = self._changed_locked(DeviceEventType.CHANGED, updated, quiet=quiet)
        self._after_change(ticket)
        return updated

    def resync(self) -> bool:
        """Report ``RESYNC``: the backend may have missed events, enumerate again.

        Returns:
            True if the event was reported, False if the backend is not started.
        """
        with self._cond:
            ticket = self._changed_locked(DeviceEventType.RESYNC, None)
        self._after_change(ticket)
        return ticket is not None

    def fail_enumerate(self, message: str | None = "simulated enumeration failure") -> None:
        """Make :meth:`enumerate` raise :class:`BackendError`; ``None`` clears it."""
        with self._cond:
            self._enumerate_error = message

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Block until every queued event has been delivered or discarded.

        Returns:
            True if the backend is idle, False if ``timeout`` seconds passed first.
            Must not be called from the event callback (it would wait for itself).
        """
        with self._cond:
            return self._cond.wait_for(lambda: self._settled >= self._enqueued, timeout=timeout)

    # --- delivery --------------------------------------------------------------------

    def _new_connection(self, device: UsbDevice) -> UsbDevice:
        connection_id = f"{self._connection_prefix}-{next(self._connection_counter)}"
        return dataclasses.replace(device, connection_id=connection_id)

    def _changed_locked(
        self, kind: DeviceEventType, device: UsbDevice | None, *, quiet: bool = False
    ) -> int | None:
        """Tell the listeners and queue the event. Returns its ticket, or ``None`` if
        nothing is to be reported (not started, or a quiet change)."""
        if device is not None:
            # The listeners model the physical world, which changes whether or not
            # anybody is told; RESYNC is not a change to it.
            for listener in tuple(self._listeners):
                listener(kind, device)
        if self._callback is None or quiet:
            return None
        self._enqueued += 1
        event = DeviceEvent(type=kind, device=device, at=self._clock.now())
        self._queue.append((self._enqueued, self._generation, event))
        self._cond.notify_all()
        return self._enqueued

    def _after_change(self, ticket: int | None) -> None:
        if ticket is None or not self._synchronous:
            return
        me = threading.get_ident()
        with self._cond:
            if self._pumper == me:
                # Called from inside the callback: the delivery loop further up this
                # thread's stack picks the event up when the current callback returns.
                return
            # Another thread may be delivering; it will deliver this event too.
            self._cond.wait_for(lambda: self._pumper is None or self._settled >= ticket)
            if self._settled >= ticket:
                return
            self._pumper = me
        errors: list[Exception] = []
        try:
            self._drain(errors)
        finally:
            with self._cond:
                self._pumper = None
                self._cond.notify_all()
        if errors:
            raise errors[0]

    def _run_worker(self, generation: int) -> None:
        me = threading.get_ident()
        while True:
            with self._cond:
                self._cond.wait_for(
                    lambda: (
                        self._generation != generation
                        or (bool(self._queue) and self._pumper is None)
                    )
                )
                if self._generation != generation:
                    return
                self._pumper = me
            try:
                self._drain([])
            finally:
                with self._cond:
                    self._pumper = None
                    self._cond.notify_all()

    def _drain(self, errors: list[Exception]) -> None:
        """Deliver queued events, oldest first, until none are left."""
        while True:
            with self._cond:
                if not self._queue:
                    return
                ticket, generation, event = self._queue.popleft()
                # An event queued before a stop() must not reach a later start()'s callback.
                callback = self._callback if generation == self._generation else None
            try:
                if callback is not None:
                    callback(event)
            except Exception as exc:
                _LOG.error("device event callback failed for %s", event.type.value, exc_info=exc)
                errors.append(exc)
                with self._cond:
                    self._callback_errors.append(exc)
            finally:
                with self._cond:
                    self._settled = max(self._settled, ticket)
                    self._cond.notify_all()


@dataclass(frozen=True, slots=True)
class EnforcerCall:
    """One call made to a :class:`FakeEnforcer`.

    Attributes:
        action: what was asked for.
        instance_id: the device it was asked for; ``None`` for calls about no one
            device (default-deny, restore).
        result: what the enforcer returned; ``None`` if an injected exception was
            raised instead.
        device: the device object passed in, when there was one.
    """

    action: Action
    instance_id: str | None
    result: EnforcementResult | None
    device: UsbDevice | None = None


@dataclass(slots=True)
class _Injection:
    error: str
    remaining: int | None
    raises: Exception | None


class FakeEnforcer(Enforcer):
    """An enforcer that keeps the "operating-system state" in memory.

    It models, per device instance id, whether the device is blocked and whether its
    storage is read-only, plus the machine-wide default-deny switch. Every call is
    recorded in :attr:`calls`.

    Faithfulness to the :class:`~portlock.guard.base.Enforcer` contract:

    * Asking for the state already in force succeeds with ``changed=False`` and an
      empty ``undo``. This holds even without the capability or the privilege, just as
      a real enforcer can see that there is nothing to do.
    * Every change returns journal entries of kind :data:`JOURNAL_KIND` holding the
      previous value; the targets are :func:`authorized_target`,
      :func:`read_only_target` and :data:`AUTHORIZED_DEFAULT_TARGET`. :meth:`restore`
      puts them back, newest first, but only where the simulated value still equals
      what was applied. The one change not journaled is admitting a device that
      default-deny had kept out: nothing PortLock did is being reversed.
    * The simulated ``authorized_default`` can be changed behind PortLock's back with
      :meth:`set_authorized_default_externally`, to exercise that restore rule.
    * With a ``write_ahead`` hook, each entry is handed to the hook *before* the change
      it describes. If the hook raises, the change is not made and the call returns
      ``ok=False`` with ``error`` starting ``journal unavailable``.
    * A capability the enforcer was configured without makes the call *return*
      ``ok=False``; nothing raises except a programming error (a wrong argument type)
      or an exception injected on purpose with :meth:`fail`.
    * Making a device read-only fails (``not a storage device``) if it has no storage.
    * A device may be made read-only while it is still blocked. Its storage was then
      never writable, so that call, and later calls that find it still read-only,
      report the *preventive* tier; read-only applied to a usable device is *reactive*.
    * Ejecting cannot be undone, so its ``undo`` is empty.

    Linking a :class:`FakeBackend` (``backend=``) makes the simulation follow the
    connection the way Linux does: state belongs to one connection and is dropped when
    the device is unplugged; a device that arrives while default-deny is on starts out
    blocked (and blocking it reports the *preventive* tier); calls about a device that
    is no longer connected fail; ejecting unplugs the device. Without a backend, state
    is simply kept per instance id until :meth:`forget` is called.

    All methods are thread-safe.

    Args:
        capabilities: what the enforcer can do; everything, by default. See also
            :meth:`unprivileged`.
        backend: the simulated machine to follow, if any.
        write_ahead: called with each journal entry just before the change it
            describes is made, with the enforcer's lock held; it must not call back
            into the enforcer.
    """

    def __init__(
        self,
        capabilities: EnforcerCapabilities | None = None,
        *,
        backend: FakeBackend | None = None,
        write_ahead: Callable[[JournalEntry], None] | None = None,
    ) -> None:
        if capabilities is not None and not isinstance(capabilities, EnforcerCapabilities):
            raise TypeError("capabilities must be an EnforcerCapabilities or None")
        if write_ahead is not None and not callable(write_ahead):
            raise TypeError("write_ahead must be callable or None")
        self._write_ahead = write_ahead
        self._capabilities = capabilities if capabilities is not None else _full_capabilities()
        self._backend = backend
        self._lock = threading.RLock()
        self._blocked: set[str] = set()
        self._preventive: set[str] = set()
        self._read_only: set[str] = set()
        # Read-only devices whose storage was never writable while usable: the flag was
        # set while the device was still blocked.
        self._read_only_early: set[str] = set()
        self._ejected: set[str] = set()
        self._authorized_default = _ALLOW
        self._calls: list[EnforcerCall] = []
        self._injections: dict[Action, _Injection] = {}
        # Instance ids connected to the linked backend, kept current by its
        # notifications; None when there is no backend and presence is not modelled.
        # The enforcer never calls into the backend while holding its own lock (the
        # backend notifies with *its* lock held, and the two must not cross), so it
        # keeps this mirror instead of asking.
        self._connected: set[str] | None = None
        if backend is not None:
            # The one exception to the rule above, and a safe one: until add_listener
            # has registered the callback nobody can be waiting for this lock, and
            # holding it makes the first notification wait until the mirror is seeded.
            with self._lock:
                present = backend.add_listener(self._on_backend_change)
                self._connected = {device.instance_id for device in present}

    @classmethod
    def unprivileged(cls, *, backend: FakeBackend | None = None) -> FakeEnforcer:
        """An enforcer running without administrator rights: it can change nothing."""
        return cls(
            EnforcerCapabilities(
                name="fake",
                privileged=False,
                block=False,
                read_only=False,
                eject=False,
                default_deny=False,
                notes=("simulated: not running with administrator rights",),
            ),
            backend=backend,
        )

    # --- inspection and control (not part of the Enforcer interface) ------------------

    @property
    def calls(self) -> tuple[EnforcerCall, ...]:
        """Every call made so far, oldest first."""
        with self._lock:
            return tuple(self._calls)

    def calls_for(self, *actions: Action) -> tuple[EnforcerCall, ...]:
        """The recorded calls whose action is one of ``actions``."""
        with self._lock:
            return tuple(call for call in self._calls if call.action in actions)

    def clear_calls(self) -> None:
        """Forget the recorded calls. State is unaffected."""
        with self._lock:
            self._calls.clear()

    @property
    def default_deny(self) -> bool:
        """True if PortLock's default-deny is in force (``authorized_default`` is 0)."""
        with self._lock:
            return self._authorized_default == _DENY

    @property
    def authorized_default(self) -> str:
        """The simulated ``authorized_default`` value; see :data:`AUTHORIZED_DEFAULT_VALUES`."""
        with self._lock:
            return self._authorized_default

    def set_authorized_default_externally(self, value: str) -> None:
        """Change ``authorized_default`` as another program would, unjournaled.

        Simulates an administrator or a configuration-management tool writing the
        setting behind PortLock's back, so that :meth:`restore` finds a value it did not
        apply. Not recorded in :attr:`calls`.

        Raises:
            ValueError: if ``value`` is not one of :data:`AUTHORIZED_DEFAULT_VALUES`.
        """
        if value not in AUTHORIZED_DEFAULT_VALUES:
            raise ValueError(
                f"authorized_default must be one of {AUTHORIZED_DEFAULT_VALUES}, got {value!r}"
            )
        with self._lock:
            self._authorized_default = value

    def is_blocked(self, device: UsbDevice | str) -> bool:
        """True if the device (or instance id) is currently blocked."""
        with self._lock:
            return _instance_id(device) in self._blocked

    def is_read_only(self, device: UsbDevice | str) -> bool:
        """True if the device's storage is currently read-only."""
        with self._lock:
            return _instance_id(device) in self._read_only

    def was_ejected(self, device: UsbDevice | str) -> bool:
        """True if the device was ejected (and, with a backend, not plugged in since)."""
        with self._lock:
            return _instance_id(device) in self._ejected

    def state(self) -> dict[str, object]:
        """A snapshot of everything the enforcer has changed, for display and assertions."""
        with self._lock:
            return {
                "default_deny": self._authorized_default == _DENY,
                "blocked": sorted(self._blocked),
                "read_only": sorted(self._read_only),
                "ejected": sorted(self._ejected),
            }

    def forget(self, device: UsbDevice | str) -> None:
        """Drop all state for one connection, as the OS does when a device goes away."""
        with self._lock:
            self._forget_locked(_instance_id(device))

    def set_capabilities(self, capabilities: EnforcerCapabilities) -> None:
        """Change what the enforcer can do from now on (for example: privilege was lost)."""
        if not isinstance(capabilities, EnforcerCapabilities):
            raise TypeError("capabilities must be an EnforcerCapabilities")
        with self._lock:
            self._capabilities = capabilities

    def fail(
        self,
        action: Action,
        error: str = "injected failure",
        *,
        times: int | None = 1,
        raises: Exception | None = None,
    ) -> None:
        """Make calls for ``action`` fail without changing any state.

        Args:
            action: which operation fails. ``set_read_only`` is ``READ_ONLY`` or
                ``READ_WRITE``; ``set_default_deny`` is ``DEFAULT_DENY_ON`` or
                ``DEFAULT_DENY_OFF``.
            error: the ``error`` of the ``ok=False`` result.
            times: how many calls fail; ``None`` means until :meth:`clear_failures`.
            raises: raise this exception instead of returning a result, to exercise a
                caller's handling of an enforcer that breaks its contract.

        Raises:
            ValueError: if ``times`` is not a positive integer or ``None``.
        """
        if not isinstance(action, Action):
            raise TypeError("action must be an Action")
        if times is not None and (
            isinstance(times, bool) or not isinstance(times, int) or times < 1
        ):
            raise ValueError(f"times must be a positive integer or None, got {times!r}")
        with self._lock:
            self._injections[action] = _Injection(error=error, remaining=times, raises=raises)

    def clear_failures(self) -> None:
        """Remove every injected failure."""
        with self._lock:
            self._injections.clear()

    # --- Enforcer --------------------------------------------------------------------

    def capabilities(self) -> EnforcerCapabilities:
        """Report the configured capabilities."""
        with self._lock:
            return self._capabilities

    def block(self, device: UsbDevice) -> EnforcementResult:
        """Stop the simulated OS from talking to ``device``."""
        return self._device_call(Action.BLOCK, device, self._block_locked)

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        """Reverse :meth:`block` (or authorize a device that default-deny held back)."""
        return self._device_call(Action.UNBLOCK, device, self._unblock_locked)

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        """Make the device's storage read-only, or writable again."""
        if not isinstance(read_only, bool):
            raise TypeError("read_only must be True or False")
        if read_only:
            return self._device_call(Action.READ_ONLY, device, self._read_only_locked)
        return self._device_call(Action.READ_WRITE, device, self._read_write_locked)

    def eject(self, device: UsbDevice) -> EnforcementResult:
        """Safely remove ``device``. With a linked backend the device is unplugged."""
        result = self._device_call(Action.EJECT, device, self._eject_locked)
        if result.ok and result.changed and self._backend is not None:
            # Outside the enforcer's lock: unplugging calls back into _on_backend_change.
            try:
                self._backend.unplug(device.instance_id)
            except KeyError:
                _LOG.debug("%s was unplugged before the eject completed", device.instance_id)
        return result

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        """Turn "refuse devices that have not been authorized" on or off."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.DEFAULT_DENY_ON if enabled else Action.DEFAULT_DENY_OFF
        with self._lock:
            return self._record(action, None, None, lambda: self._default_deny_locked(action))

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        """Put back the ``previous`` value of each journal entry, newest first.

        Entries are expected oldest first, as they were journaled. Every entry is
        validated before anything is written: only :data:`JOURNAL_KIND` entries with a
        target and values this enforcer could have written are usable; the others are
        reported in ``error`` and make the result ``ok=False``, while the usable ones
        are still restored, because a partial restore gives back more access than none.

        A usable entry is reverted only if the simulated value still equals its
        ``applied`` value. One that already holds ``previous`` needs nothing; one that
        holds anything else was changed by someone else since and is left alone, which
        ``detail`` reports. An entry for a device that is no longer connected (when a
        backend is linked) is skipped: its state went with the connection.
        """
        frozen = tuple(entries)
        with self._lock:
            return self._record(Action.RESTORE, None, None, lambda: self._restore_locked(frozen))

    # --- implementation --------------------------------------------------------------

    def _on_backend_change(self, kind: DeviceEventType, device: UsbDevice) -> None:
        with self._lock:
            instance_id = device.instance_id
            if kind is DeviceEventType.CHANGED:
                return
            if self._connected is not None:
                if kind is DeviceEventType.ARRIVED:
                    self._connected.add(instance_id)
                else:
                    self._connected.discard(instance_id)
            # Enforcement state belongs to one connection, so it goes when the device
            # does. That it was ejected stays on record until it is plugged in again.
            was_ejected = instance_id in self._ejected
            self._forget_locked(instance_id)
            if kind is DeviceEventType.REMOVED:
                if was_ejected:
                    self._ejected.add(instance_id)
            elif self._holds_back_locked(device):
                # Refused from the first instant: this is what "preventive" means.
                self._blocked.add(instance_id)
                self._preventive.add(instance_id)

    def _holds_back_locked(self, device: UsbDevice) -> bool:
        """Whether ``authorized_default`` keeps a newly connected device out.

        As on Linux: ``0`` keeps every device out, ``2`` every device that is not
        built in, and ``1`` and ``-1`` (all simulated devices are wired) none.
        """
        if self._authorized_default == _DENY:
            return True
        return self._authorized_default == "2" and device.removable is not False

    def _forget_locked(self, instance_id: str) -> None:
        self._blocked.discard(instance_id)
        self._preventive.discard(instance_id)
        self._read_only.discard(instance_id)
        self._read_only_early.discard(instance_id)
        self._ejected.discard(instance_id)

    def _is_present_locked(self, instance_id: str) -> bool:
        """Whether the device is connected. Always True when no backend is linked."""
        return self._connected is None or instance_id in self._connected

    def _device_call(
        self,
        action: Action,
        device: UsbDevice,
        operation: Callable[[UsbDevice], EnforcementResult],
    ) -> EnforcementResult:
        _require_device(device)

        def run() -> EnforcementResult:
            if self._is_present_locked(device.instance_id):
                return operation(device)
            if action is Action.EJECT:
                # Gone is exactly what an eject asks for.
                return self._no_change(action, f"{device.instance_id} is not connected")
            return self._failure(action, f"device {device.instance_id} is no longer connected")

        with self._lock:
            return self._record(action, device.instance_id, device, run)

    def _record(
        self,
        action: Action,
        instance_id: str | None,
        device: UsbDevice | None,
        run: Callable[[], EnforcementResult],
    ) -> EnforcementResult:
        """Apply an injected failure or run the operation, and record the call."""
        injection = self._injections.get(action)
        if injection is not None:
            if injection.remaining is not None:
                injection.remaining -= 1
                if injection.remaining == 0:
                    del self._injections[action]
            if injection.raises is not None:
                self._calls.append(EnforcerCall(action, instance_id, None, device))
                raise injection.raises
            result = self._failure(action, injection.error)
        else:
            result = run()
        self._calls.append(EnforcerCall(action, instance_id, result, device))
        return result

    def _failure(self, action: Action, error: str) -> EnforcementResult:
        return EnforcementResult(
            action=action,
            ok=False,
            mechanism=_MECHANISMS[action],
            detail=f"{action.value} failed: {error}",
            error=error,
        )

    def _no_change(self, action: Action, detail: str, tier: Tier = Tier.NONE) -> EnforcementResult:
        return EnforcementResult(
            action=action, ok=True, mechanism=_MECHANISMS[action], tier=tier, detail=detail
        )

    def _unavailable(self, action: Action, capability: str) -> EnforcementResult | None:
        """A failure result if the enforcer lacks ``capability``, else ``None``."""
        if getattr(self._capabilities, capability):
            return None
        if not self._capabilities.privileged:
            return self._failure(
                action,
                f"{NotPrivilegedError.code}: administrator rights are needed to {action.value}",
            )
        return self._failure(
            action,
            f"{EnforcementError.code}: this enforcer has no {capability} mechanism",
        )

    def _write_ahead_locked(self, action: Action, entry: JournalEntry) -> EnforcementResult | None:
        """Offer ``entry`` to the write-ahead hook before the change it describes.

        Returns a failure result if the hook refused, in which case the change must not
        be made; ``None`` if the change may go ahead.
        """
        if self._write_ahead is None:
            return None
        try:
            self._write_ahead(entry)
        except Exception as exc:
            return self._failure(action, f"journal unavailable: {type(exc).__name__}: {exc}")
        return None

    def _block_locked(self, device: UsbDevice) -> EnforcementResult:
        instance_id = device.instance_id
        if instance_id in self._blocked:
            tier = Tier.PREVENTIVE if instance_id in self._preventive else Tier.REACTIVE
            return self._no_change(Action.BLOCK, f"{instance_id} is already blocked", tier)
        unavailable = self._unavailable(Action.BLOCK, "block")
        if unavailable is not None:
            return unavailable
        entry = JournalEntry(JOURNAL_KIND, authorized_target(instance_id), _ON, _OFF)
        refused = self._write_ahead_locked(Action.BLOCK, entry)
        if refused is not None:
            return refused
        self._blocked.add(instance_id)
        return EnforcementResult(
            action=Action.BLOCK,
            ok=True,
            mechanism=_MECHANISMS[Action.BLOCK],
            tier=Tier.REACTIVE,
            changed=True,
            detail=f"blocked {instance_id}",
            undo=(entry,),
        )

    def _unblock_locked(self, device: UsbDevice) -> EnforcementResult:
        instance_id = device.instance_id
        if instance_id not in self._blocked:
            return self._no_change(Action.UNBLOCK, f"{instance_id} is not blocked")
        unavailable = self._unavailable(Action.UNBLOCK, "block")
        if unavailable is not None:
            return unavailable
        if instance_id in self._preventive:
            # Admitting a device that default-deny kept out. Nothing PortLock did is
            # being reversed, so there is nothing to journal: putting "the previous
            # value" back would lock the device out again.
            self._blocked.discard(instance_id)
            self._preventive.discard(instance_id)
            return EnforcementResult(
                action=Action.UNBLOCK,
                ok=True,
                mechanism=_MECHANISMS[Action.UNBLOCK],
                tier=Tier.REACTIVE,
                changed=True,
                detail=f"admitted {instance_id}, which default-deny had kept out",
            )
        entry = JournalEntry(JOURNAL_KIND, authorized_target(instance_id), _OFF, _ON)
        refused = self._write_ahead_locked(Action.UNBLOCK, entry)
        if refused is not None:
            return refused
        self._blocked.discard(instance_id)
        return EnforcementResult(
            action=Action.UNBLOCK,
            ok=True,
            mechanism=_MECHANISMS[Action.UNBLOCK],
            tier=Tier.REACTIVE,
            changed=True,
            detail=f"unblocked {instance_id}",
            undo=(entry,),
        )

    def _read_only_locked(self, device: UsbDevice) -> EnforcementResult:
        instance_id = device.instance_id
        if instance_id in self._read_only:
            early = instance_id in self._read_only_early
            return self._no_change(
                Action.READ_ONLY,
                f"{instance_id} is already read-only",
                Tier.PREVENTIVE if early else Tier.REACTIVE,
            )
        if not device.is_storage:
            return self._failure(Action.READ_ONLY, "not a storage device")
        unavailable = self._unavailable(Action.READ_ONLY, "read_only")
        if unavailable is not None:
            return unavailable
        entry = JournalEntry(JOURNAL_KIND, read_only_target(instance_id), _OFF, _ON)
        refused = self._write_ahead_locked(Action.READ_ONLY, entry)
        if refused is not None:
            return refused
        # Armed while the device is still blocked, the restriction is in place before
        # the device can be used at all: the race-free path a real enforcer gets from
        # arming read-only ahead of admitting the device.
        early = instance_id in self._blocked
        self._read_only.add(instance_id)
        if early:
            self._read_only_early.add(instance_id)
        return EnforcementResult(
            action=Action.READ_ONLY,
            ok=True,
            mechanism=_MECHANISMS[Action.READ_ONLY],
            tier=Tier.PREVENTIVE if early else Tier.REACTIVE,
            changed=True,
            detail=f"made {instance_id} read-only" + (" before it was admitted" if early else ""),
            undo=(entry,),
        )

    def _read_write_locked(self, device: UsbDevice) -> EnforcementResult:
        instance_id = device.instance_id
        if instance_id not in self._read_only:
            return self._no_change(Action.READ_WRITE, f"{instance_id} is already writable")
        unavailable = self._unavailable(Action.READ_WRITE, "read_only")
        if unavailable is not None:
            return unavailable
        entry = JournalEntry(JOURNAL_KIND, read_only_target(instance_id), _ON, _OFF)
        refused = self._write_ahead_locked(Action.READ_WRITE, entry)
        if refused is not None:
            return refused
        self._read_only.discard(instance_id)
        self._read_only_early.discard(instance_id)
        return EnforcementResult(
            action=Action.READ_WRITE,
            ok=True,
            mechanism=_MECHANISMS[Action.READ_WRITE],
            tier=Tier.REACTIVE,
            changed=True,
            detail=f"made {instance_id} writable",
            undo=(entry,),
        )

    def _eject_locked(self, device: UsbDevice) -> EnforcementResult:
        instance_id = device.instance_id
        if instance_id in self._ejected:
            return self._no_change(Action.EJECT, f"{instance_id} was already ejected")
        unavailable = self._unavailable(Action.EJECT, "eject")
        if unavailable is not None:
            return unavailable
        self._ejected.add(instance_id)
        return EnforcementResult(
            action=Action.EJECT,
            ok=True,
            mechanism=_MECHANISMS[Action.EJECT],
            tier=Tier.REACTIVE,
            changed=True,
            detail=f"ejected {instance_id}",
        )

    def _default_deny_locked(self, action: Action) -> EnforcementResult:
        enabled = action is Action.DEFAULT_DENY_ON
        # As on Linux, the stored value is "authorize new devices by default".
        wanted = _DENY if enabled else _ALLOW
        if self._authorized_default == wanted:
            return self._no_change(
                action,
                f"default-deny is already {'on' if enabled else 'off'}",
                Tier.PREVENTIVE if enabled else Tier.NONE,
            )
        unavailable = self._unavailable(action, "default_deny")
        if unavailable is not None:
            return unavailable
        entry = JournalEntry(
            JOURNAL_KIND, AUTHORIZED_DEFAULT_TARGET, self._authorized_default, wanted
        )
        refused = self._write_ahead_locked(action, entry)
        if refused is not None:
            return refused
        self._authorized_default = wanted
        return EnforcementResult(
            action=action,
            ok=True,
            mechanism=_MECHANISMS[action],
            tier=Tier.PREVENTIVE if enabled else Tier.NONE,
            changed=True,
            detail=f"turned default-deny {'on' if enabled else 'off'}",
            undo=(entry,),
        )

    def _restore_locked(self, entries: tuple[JournalEntry, ...]) -> EnforcementResult:
        if not entries:
            return self._no_change(Action.RESTORE, "nothing to restore")
        if not self._capabilities.privileged:
            return self._failure(
                Action.RESTORE,
                f"{NotPrivilegedError.code}: administrator rights are needed to restore",
            )
        # Validate everything before writing anything: a tampered journal must not get
        # a single write in before its first bad entry is noticed.
        usable: list[_Restoration] = []
        errors: list[str] = []
        for entry in entries:
            try:
                usable.append(_validate(entry))
            except ValueError as exc:
                errors.append(str(exc))
        restored = skipped = already = 0
        left_alone: list[str] = []
        for item in reversed(usable):
            if item.instance_id is not None and not self._is_present_locked(item.instance_id):
                # Per-device state is volatile: it went when the device did.
                skipped += 1
                continue
            current = self._current_value_locked(item)
            if current == item.previous:
                already += 1
            elif current == item.applied:
                self._write_value_locked(item, item.previous)
                restored += 1
            else:
                # Someone else changed it since PortLock did. Their value stands.
                left_alone.append(f"{item.target} (now {current!r})")
        detail = f"restored {restored} of {len(entries)} journal entries"
        if already:
            detail += f"; {already} already held their previous value"
        if left_alone:
            detail += (
                f"; {len(left_alone)} left alone because something else changed them since: "
                + ", ".join(left_alone)
            )
        if skipped:
            detail += f"; {skipped} skipped because the device is no longer connected"
        if errors:
            detail += f"; {len(errors)} could not be restored"
        return EnforcementResult(
            action=Action.RESTORE,
            ok=not errors,
            mechanism=_MECHANISMS[Action.RESTORE],
            changed=restored > 0,
            detail=detail,
            error="; ".join(errors) if errors else None,
        )

    def _current_value_locked(self, item: _Restoration) -> str:
        if item.instance_id is None:
            return self._authorized_default
        if item.read_only:
            return _ON if item.instance_id in self._read_only else _OFF
        return _OFF if item.instance_id in self._blocked else _ON

    def _write_value_locked(self, item: _Restoration, value: str) -> None:
        instance_id = item.instance_id
        if instance_id is None:
            self._authorized_default = value
        elif item.read_only:
            if value == _ON:
                self._read_only.add(instance_id)
            else:
                self._read_only.discard(instance_id)
                self._read_only_early.discard(instance_id)
        elif value == _OFF:
            self._blocked.add(instance_id)
        else:
            self._blocked.discard(instance_id)
            self._preventive.discard(instance_id)


def _full_capabilities() -> EnforcerCapabilities:
    return EnforcerCapabilities(
        name="fake",
        privileged=True,
        block=True,
        read_only=True,
        eject=True,
        default_deny=True,
        notes=("simulated: no operating-system state is changed",),
    )


@dataclass(frozen=True, slots=True)
class _Restoration:
    """A journal entry that passed validation, with its defaults filled in."""

    target: str
    #: The device the entry is about; ``None`` for ``authorized_default``.
    instance_id: str | None
    #: True for a read-only flag, False for ``authorized`` (or the machine-wide entry).
    read_only: bool
    previous: str
    applied: str


def _validate(entry: JournalEntry) -> _Restoration:
    """Check that ``entry`` is one this enforcer could have written.

    A missing ``previous`` means the setting did not exist, so the default applies:
    authorized, writable, and new devices authorized by default.

    Raises:
        ValueError: naming what is wrong with the entry.
    """
    if entry.kind != JOURNAL_KIND:
        raise ValueError(f"cannot restore a {entry.kind!r} journal entry ({entry.target})")
    target = entry.target
    instance_id: str | None = None
    read_only = False
    if target == AUTHORIZED_DEFAULT_TARGET:
        allowed: tuple[str, ...] = AUTHORIZED_DEFAULT_VALUES
        default = _ALLOW
    else:
        for suffix, flag, flag_default in (
            (_AUTHORIZED_SUFFIX, False, _ON),
            (_READ_ONLY_SUFFIX, True, _OFF),
        ):
            if target.endswith(suffix):
                instance_id = target[: -len(suffix)]
                read_only, default = flag, flag_default
                break
        else:
            raise ValueError(f"unknown journal target {target!r}")
        if not instance_id:
            raise ValueError(f"journal target {target!r} names no device")
        allowed = (_OFF, _ON)
    if entry.previous is not None and entry.previous not in allowed:
        raise ValueError(f"unusable previous value {entry.previous!r} for {target}")
    applied = entry.applied
    if applied is None or applied not in allowed:
        raise ValueError(f"unusable applied value {applied!r} for {target}")
    previous = entry.previous if entry.previous is not None else default
    return _Restoration(target, instance_id, read_only, previous, applied)


def _instance_id(device: UsbDevice | str) -> str:
    return device.instance_id if isinstance(device, UsbDevice) else device


def _require_device(device: object) -> None:
    if not isinstance(device, UsbDevice):
        raise TypeError(f"expected a UsbDevice, got {type(device).__name__}")
