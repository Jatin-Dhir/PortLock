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
    "Action",
    "BackendCapabilities",
    "DeviceBackend",
    "EnforcementResult",
    "Enforcer",
    "EnforcerCapabilities",
    "EventCallback",
    "JournalEntry",
    "Tier",
]

EventCallback = Callable[[DeviceEvent], None]


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
        kind: the mechanism family, e.g. ``sysfs``, ``registry``, ``devnode``.
        target: what was changed: a path, a registry value, a device instance id.
        previous: the value before the change, or ``None`` if there was none.
        applied: the value written, or ``None`` if the change was a removal.
    """

    kind: str
    target: str
    previous: str | None
    applied: str | None

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

        The callback is invoked from a backend thread. It must not be called for devices
        that were already present at start; the caller enumerates those itself.
        Calling ``start`` twice without ``stop`` is an error.
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
        """Put back the ``previous`` value of each journal entry, newest first."""
