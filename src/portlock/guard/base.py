"""Interfaces between PortLock and the operating system.

Two interfaces, deliberately separate:

* :class:`DeviceBackend` *observes*. It lists devices and reports arrivals and removals.
  It needs no privilege and changes nothing.
* :class:`Enforcer` *acts*. It makes the operating system refuse or restrict a device.
  It needs administrator or root rights, and it is the only part of PortLock that
  protects anything.

Nothing calls an :class:`Enforcer` directly. Calls go through
``portlock.guard.safety.SafeEnforcer``, which refuses to act on protected devices.

Every change an enforcer makes is described by :class:`JournalEntry` values that record
the previous state, so the change can be undone exactly, even by a later process.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from portlock.core.models import DeviceEvent, UsbDevice

__all__ = [
    "STAND_IN_MECHANISMS",
    "Action",
    "BackendCapabilities",
    "DeviceBackend",
    "EnforcementResult",
    "Enforcer",
    "EnforcerCapabilities",
    "EventCallback",
    "JournalEntry",
    "JournalKind",
    "Tier",
]

EventCallback = Callable[[DeviceEvent], None]

#: ``EnforcementResult.mechanism`` values of a result that stands in for a call that was
#: never made: ``dry-run`` (monitor mode's dry run, ``guard.safety``) and ``watch-only``
#: (``guard.watchonly``). Such a result says what *would* happen; it never proves that the
#: operating system is now in the requested state, even when ``ok`` is True.
STAND_IN_MECHANISMS = frozenset({"dry-run", "watch-only"})


class Tier(enum.StrEnum):
    """When, relative to the device becoming usable, a mechanism takes effect."""

    #: The OS refused the device from the first instant; it was never usable.
    PREVENTIVE = "preventive"
    #: PortLock acted after the device appeared; there was a short usable window.
    REACTIVE = "reactive"
    #: Nothing was enforced.
    NONE = "none"


class Action(enum.StrEnum):
    """The operations an enforcer can be asked to perform."""

    BLOCK = "block"
    UNBLOCK = "unblock"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    EJECT = "eject"
    DEFAULT_DENY_ON = "default_deny_on"
    DEFAULT_DENY_OFF = "default_deny_off"
    RESTORE = "restore"


class JournalKind(enum.StrEnum):
    """Every kind of operating-system state PortLock may change, and therefore restore.

    Restoring a journal is a privileged write. Keeping the kinds to a closed list, each
    with a validated target, stops a tampered journal from being used to write anywhere
    else.
    """

    #: ``authorized`` attribute of one USB device in sysfs. Target: the sysfs path.
    SYSFS_AUTHORIZED = "sysfs_authorized"
    #: ``authorized_default`` attribute of one USB host controller. Target: the sysfs path.
    SYSFS_AUTHORIZED_DEFAULT = "sysfs_authorized_default"
    #: Read-only flag of one block device. Target: the device node.
    BLOCK_READ_ONLY = "block_read_only"
    #: A udev rules file written by PortLock. Target: the file path.
    UDEV_RULE = "udev_rule"
    #: Enabled or disabled state of one Windows device node. Target: the instance id.
    WIN_DEVNODE = "win_devnode"
    #: Read-only attribute of one Windows disk. Target: the disk device path.
    WIN_DISK_READ_ONLY = "win_disk_read_only"
    #: One Windows policy registry value. Target: the key path and value name.
    WIN_POLICY_VALUE = "win_policy_value"
    #: State inside the in-memory fake enforcer. Target: free-form.
    FAKE = "fake"


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    """What a device backend can do on this machine right now."""

    name: str
    can_enumerate: bool
    #: True if arrivals are pushed by the OS; False if the backend polls.
    event_driven: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EnforcerCapabilities:
    """What an enforcer can do on this machine right now.

    A capability is True only if the mechanism is present *and* this process has the
    rights to use it. ``portlock doctor`` prints this, and the pipeline consults it so a
    decision that cannot be enforced is recorded as not enforced.
    """

    name: str
    privileged: bool
    block: bool
    read_only: bool
    eject: bool
    default_deny: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One reversible change to operating-system state.

    Attributes:
        kind: a :class:`JournalKind` value; anything else raises ``ValueError``.
        target: what was changed: a path, a registry value, a device instance id.
        previous: the value before the change, or ``None`` if there was none.
        applied: the value written, or ``None`` if the change was a removal.
    """

    kind: str
    target: str
    previous: str | None
    applied: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", JournalKind(self.kind).value)
        if not isinstance(self.target, str) or not self.target:
            raise ValueError("a journal entry needs a non-empty target")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "previous": self.previous,
            "applied": self.applied,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> JournalEntry:
        return cls(
            kind=str(data["kind"]),
            target=str(data["target"]),
            previous=data.get("previous"),
            applied=data.get("applied"),
        )


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """The outcome of one enforcement call.

    Attributes:
        action: what was asked for.
        ok: True if the OS is now in the requested state.
        mechanism: how it was done, e.g. ``sysfs:authorized``; ``dry-run`` in monitor
            mode; ``refused`` when the safety layer declined.
        tier: whether the mechanism is preventive or reactive.
        changed: False if the OS was already in the requested state.
        detail: one line for the audit log.
        undo: what to restore to reverse this call. Empty if nothing changed.
        error: why it failed, when ``ok`` is False.
    """

    action: Action
    ok: bool
    mechanism: str
    tier: Tier = Tier.NONE
    changed: bool = False
    detail: str = ""
    undo: tuple[JournalEntry, ...] = ()
    error: str | None = None

    @property
    def performed(self) -> bool:
        """True if the call succeeded *and* was really made to the operating system.

        A stand-in result (:data:`STAND_IN_MECHANISMS`) is never performed, whatever its
        ``ok`` says. Only a performed release may close a journal record or forget that
        PortLock holds a device back: closing one on a stand-in's word would forget a
        change that is still in place.
        """
        return self.ok and self.mechanism not in STAND_IN_MECHANISMS

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "ok": self.ok,
            "mechanism": self.mechanism,
            "tier": self.tier.value,
            "changed": self.changed,
            "detail": self.detail,
            "undo": [entry.to_dict() for entry in self.undo],
            "error": self.error,
        }


class DeviceBackend(ABC):
    """Observes USB devices. Read-only; needs no privilege."""

    @abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Report what this backend can do on this machine right now."""

    @abstractmethod
    def enumerate(self) -> list[UsbDevice]:
        """Return every USB device currently connected.

        Raises:
            BackendError: if the operating system cannot be queried.
        """

    @abstractmethod
    def start(self, on_event: EventCallback) -> None:
        """Begin reporting arrivals, removals and changes to ``on_event``.

        The callback is invoked from a backend thread. To leave no gap, the caller
        starts the backend first and enumerates afterwards, so a device that arrives in
        between may be reported both ways: handling an arrival must be idempotent per
        connection. A backend that may have missed events (a notification queue
        overflowed, the system resumed from sleep) reports ``RESYNC`` and the caller
        enumerates again. Calling ``start`` twice without ``stop`` is an error.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop reporting and release OS resources. Safe to call when not started."""


class Enforcer(ABC):
    """Makes the operating system restrict devices.

    Contract for every method:

    * It is idempotent: asking for the state the OS is already in succeeds with
      ``changed=False`` and an empty ``undo``.
    * Expected failures (missing privilege, device gone, mechanism unavailable) are
      *returned* as ``ok=False`` with ``error`` set, never raised, so the caller can
      audit them. Only programming errors raise.
    * It never formats, repartitions, wipes or deletes anything.
    """

    @abstractmethod
    def capabilities(self) -> EnforcerCapabilities:
        """Report what this enforcer can do on this machine right now."""

    @abstractmethod
    def block(self, device: UsbDevice) -> EnforcementResult:
        """Make the OS stop communicating with ``device``."""

    @abstractmethod
    def unblock(self, device: UsbDevice) -> EnforcementResult:
        """Reverse :meth:`block` for ``device``."""

    @abstractmethod
    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        """Make the storage exposed by ``device`` read-only, or writable again."""

    @abstractmethod
    def eject(self, device: UsbDevice) -> EnforcementResult:
        """Ask the OS to safely remove ``device``."""

    @abstractmethod
    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        """Turn the OS-level "refuse devices that have not been authorized" mode on or off."""

    @abstractmethod
    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        """Put back the ``previous`` value of each journal entry, newest first.

        An entry is reverted only if the current value still equals its ``applied``
        value. If someone else has changed it since (a group policy refresh, an
        administrator), it is left alone and reported in ``detail``. Every target is
        validated against what its :class:`JournalKind` allows before anything is written.
        """
