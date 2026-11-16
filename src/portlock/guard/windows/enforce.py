"""The Windows enforcer: device nodes, eject, installation and storage policies, disk attribute.

Mechanisms, as specified in ``docs/enforcement/windows.md`` and corrected by
``docs/DESIGN.md`` section 14.14:

=========================  ==================================================  ===========
What                       How                                                 Tier
=========================  ==================================================  ===========
block / unblock            ``CM_Disable_DevNode`` with ``CM_DISABLE_PERSIST``  reactive
                           / ``CM_Enable_DevNode``; under default-deny the
                           device's ``AllowInstanceIDs`` entry is added or
                           removed as well
default-deny               ``DenyRemovableDevices`` and ``AllowDenyLayered``   preventive
                           under the Device Installation ``Restrictions``      for never-
                           policy key                                          installed
                                                                               devices only
read-only, per device      the per-disk read-only attribute                    reactive,
                           (``IOCTL_DISK_SET_DISK_ATTRIBUTES``, not persisted) best effort
read-only baseline         Removable Storage Access ``Deny_Write`` for         standing,
                           removable disks and WPD devices (class-wide)        class-wide
eject                      ``CM_Request_Device_EjectW`` with a veto buffer     reactive
=========================  ==================================================  ===========

Device Installation Restrictions stop only devices that were never installed on this
machine, so disabling the device node on every unapproved arrival stays the backstop. The
per-disk attribute does not take away write access an existing mount already has. The
class-wide baseline cannot release one device: Windows has no per-device exception in
those values. Each of these limits is stated in the result it applies to.

Every operating-system access goes through the seams in :mod:`portlock.guard.seams`.
Importing this module on Linux works: nothing Windows-specific is loaded until a real
seam is used. No mechanism here has been run against a real device by the test suite.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from portlock.core.errors import BackendError, EnforcementError, NotPrivilegedError
from portlock.core.models import UsbDevice, sanitize_device_text
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
    JournalKind,
    Tier,
)
from portlock.guard.seams import (
    REG_DWORD,
    REG_SZ,
    CfgMgrAPI,
    ChangeRecorder,
    DiskIO,
    JournalUnavailable,
    MechanismStatus,
    RegistryIO,
    RegValue,
    WinCfgMgr,
    WinDisks,
    WinRegistry,
    current_process_privileged,
    encode_reg,
)
from portlock.guard.windows.api import config_ret_name
from portlock.guard.windows.enumerate import NodeKind, parse_instance_id

__all__ = [
    "ALLOW_INSTANCE_IDS_KEY",
    "DISK_CLASS_KEY",
    "MECHANISM_DENY_WRITE",
    "MECHANISM_DISABLE",
    "MECHANISM_DISK_READ_ONLY",
    "MECHANISM_EJECT",
    "MECHANISM_INSTALL_RESTRICTIONS",
    "MECHANISM_RESTORE",
    "REMOVABLE_STORAGE_KEY",
    "RESTRICTIONS_KEY",
    "WPD_CLASS_KEY",
    "WindowsEnforcer",
    "disk_target",
    "policy_target",
    "system_device_ids",
]

MECHANISM_DISABLE = "cfgmgr:disable-devnode"
MECHANISM_EJECT = "cfgmgr:request-eject"
MECHANISM_INSTALL_RESTRICTIONS = "policy:device-install-restrictions"
MECHANISM_DENY_WRITE = "policy:removable-storage-deny-write(class-wide)"
MECHANISM_DISK_READ_ONLY = "disk:read-only-attribute"
MECHANISM_RESTORE = "journal:restore"

RESTRICTIONS_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions"
ALLOW_INSTANCE_IDS_KEY = RESTRICTIONS_KEY + "\\AllowInstanceIDs"
REMOVABLE_STORAGE_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices"
#: Removable disks (``GUID_DEVINTERFACE_VOLUME`` class key of the policy).
DISK_CLASS_KEY = REMOVABLE_STORAGE_KEY + "\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
#: Windows Portable Devices: phones and cameras over MTP or PTP.
WPD_CLASS_KEY = REMOVABLE_STORAGE_KEY + "\\{6AC27878-A6FA-4155-BA85-F98F491D4F33}"

_DENY_REMOVABLE = "DenyRemovableDevices"
_ALLOW_DENY_LAYERED = "AllowDenyLayered"
_ALLOW_INSTANCE_IDS = "AllowInstanceIDs"
_DENY_WRITE = "Deny_Write"
_HKLM = "HKLM\\"
_ON = RegValue(REG_DWORD, 1)
_ON_TEXT = _ON.encode()
#: The only Restrictions values PortLock writes. Any other value there was put by an
#: administrator or a domain policy, and PortLock does not compete with it.
_OWNED_RESTRICTIONS = frozenset(
    name.casefold() for name in (_DENY_REMOVABLE, _ALLOW_DENY_LAYERED, _ALLOW_INSTANCE_IDS)
)
_ALLOW_ENTRY_NAME = re.compile(r"[1-9][0-9]{0,3}\Z")
_DISK_TARGET = re.compile(r"\\\\\.\\PhysicalDrive([0-9]{1,3})\Z")
_MAX_ALLOW_ENTRIES = 9999

# CONFIGRET (cfgmgr32.h). Names for the codes api.py's table does not carry.
CR_SUCCESS = 0x00
_CR_INVALID_DEVNODE = 0x05
_CR_NO_SUCH_DEVNODE = 0x0D
_CR_REMOVE_VETOED = 0x17
_CR_DEVICE_NOT_THERE = 0x24
_CR_NOT_DISABLEABLE = 0x28
_CR_ACCESS_DENIED = 0x33
_CR_NAMES = {
    _CR_REMOVE_VETOED: "CR_REMOVE_VETOED",
    _CR_DEVICE_NOT_THERE: "CR_DEVICE_NOT_THERE",
    _CR_NOT_DISABLEABLE: "CR_NOT_DISABLEABLE",
}
_GONE_CODES = frozenset({_CR_INVALID_DEVNODE, _CR_NO_SUCH_DEVNODE, _CR_DEVICE_NOT_THERE})

# Device node status (cfg.h).
_DN_STARTED = 0x00000008
_DN_HAS_PROBLEM = 0x00000400
_DN_DISABLEABLE = 0x00002000
_CM_PROB_DISABLED = 0x16
#: Problem 28, "drivers not installed": how a device an installation restriction kept
#: out appears (UNVERIFIED for every restriction and Windows build).
_CM_PROB_FAILED_INSTALL = 0x1C

# PNP_VETO_TYPE (cfg.h).
_VETO_NAMES = {
    0: "PNP_VetoTypeUnknown",
    1: "PNP_VetoLegacyDevice",
    2: "PNP_VetoPendingClose",
    3: "PNP_VetoWindowsApp",
    4: "PNP_VetoWindowsService",
    5: "PNP_VetoOutstandingOpen",
    6: "PNP_VetoDevice",
    7: "PNP_VetoDriver",
    8: "PNP_VetoIllegalDeviceRequest",
    9: "PNP_VetoInsufficientPower",
    10: "PNP_VetoNonDisableable",
    11: "PNP_VetoLegacyDriver",
    12: "PNP_VetoInsufficientRights",
    13: "PNP_VetoAlreadyRemoved",
}

_ENABLED, _DISABLED = "enabled", "disabled"
_DEFAULT_DENY_TIER = (
    "preventive for never-installed devices only: Windows keeps using a device it"
    " installed before, so disabling the device node on every unapproved arrival remains"
    " the backstop; Microsoft documents that the restriction may only take effect after a"
    " restart"
)
_BEST_EFFORT = (
    "best effort: the per-disk read-only attribute does not take away write access that a"
    " mounted file system or an open handle already has (DESIGN 14.14)"
)


def policy_target(key: str, name: str) -> str:
    """The journal target of one policy value: ``HKLM\\<key>\\<name>``."""
    return f"{_HKLM}{key}\\{name}"


def disk_target(disk: int) -> str:
    """The journal target of one disk's read-only attribute: ``\\\\.\\PhysicalDriveN``."""
    return f"\\\\.\\PhysicalDrive{disk}"


class _Failure(EnforcementError):
    """An expected failure inside one call; becomes an ``ok=False`` result."""


@dataclass(frozen=True, slots=True)
class _Outcome:
    detail: str
    tier: Tier = Tier.NONE
    ok: bool = True
    error: str | None = None
    changed: bool = False


@dataclass(frozen=True, slots=True)
class _Node:
    devinst: int
    status: int
    problem: int

    @property
    def disabled(self) -> bool:
        return bool(self.status & _DN_HAS_PROBLEM) and self.problem == _CM_PROB_DISABLED

    @property
    def started(self) -> bool:
        return bool(self.status & _DN_STARTED)

    @property
    def not_installed(self) -> bool:
        return bool(self.status & _DN_HAS_PROBLEM) and self.problem == _CM_PROB_FAILED_INSTALL


@dataclass(frozen=True, slots=True)
class _Plan:
    entry: JournalEntry
    volatile: bool
    run: Callable[[], str]


class WindowsEnforcer(Enforcer):
    """Makes Windows restrict USB devices (see the module docstring for the mechanisms).

    Contract (``guard/base.py`` and ARCHITECTURE 2.2): every method is idempotent,
    returns expected failures instead of raising, never formats, wipes or deletes, and
    describes each change with typed journal entries handed to ``write_ahead`` before the
    change is made. ``UsbDevice.instance_id`` must be a USB device instance id
    (``USB\\VID_xxxx&PID_xxxx\\...``); root hubs and interface nodes are refused.

    Calls are serialized by an internal lock.

    Args:
        cfgmgr: Configuration Manager calls.
        registry: ``HKEY_LOCAL_MACHINE`` policy values.
        disks: the per-disk read-only attribute.
        is_admin: whether this process runs with administrator rights.
        write_ahead: called with each journal entry just before its change is made.
    """

    def __init__(
        self,
        *,
        cfgmgr: CfgMgrAPI,
        registry: RegistryIO,
        disks: DiskIO,
        is_admin: Callable[[], bool],
        write_ahead: Callable[[JournalEntry], None] | None = None,
    ) -> None:
        if write_ahead is not None and not callable(write_ahead):
            raise TypeError("write_ahead must be callable or None")
        self._cfgmgr = cfgmgr
        self._registry = registry
        self._disks = disks
        self._is_admin = is_admin
        self._write_ahead = write_ahead
        self._lock = threading.RLock()

    @classmethod
    def system(
        cls, *, write_ahead: Callable[[JournalEntry], None] | None = None
    ) -> WindowsEnforcer:
        """The enforcer wired to the real operating system."""
        return cls(
            cfgmgr=WinCfgMgr(),
            registry=WinRegistry(),
            disks=WinDisks(),
            is_admin=current_process_privileged,
            write_ahead=write_ahead,
        )

    # --- capabilities -----------------------------------------------------------------

    def restriction_conflicts(self) -> tuple[str, ...]:
        """Device Installation Restriction values PortLock did not write (and never
        writes), such as ``AllowAdminInstall`` set by a domain policy."""
        try:
            values = self._registry.values(RESTRICTIONS_KEY)
        except (OSError, ValueError):
            return ()
        return tuple(sorted(name for name in values if name.casefold() not in _OWNED_RESTRICTIONS))

    def mechanisms(self) -> tuple[MechanismStatus, ...]:
        """Each mechanism's availability on this machine now, with the reason if not."""
        with self._lock:
            admin = self._is_admin()

            def status(
                role: str, mechanism: str, available: bool, why: str, tier: str
            ) -> MechanismStatus:
                if not admin:
                    return MechanismStatus(
                        role, mechanism, False, tier, "not running as an administrator"
                    )
                if not available:
                    return MechanismStatus(role, mechanism, False, tier, why)
                return MechanismStatus(role, mechanism, True, tier)

            cfgmgr = self._cfgmgr.available
            registry = self._registry.available
            no_cfgmgr = "the Configuration Manager API (cfgmgr32.dll) is not available here"
            no_registry = "the Windows registry is not available here"
            conflicts = self.restriction_conflicts() if registry else ()
            default_deny_reason = no_registry
            if registry and conflicts:
                default_deny_reason = (
                    "Device Installation Restriction values not written by PortLock are"
                    f" present ({', '.join(conflicts)}): a domain or local policy manages them"
                )
            return (
                status(
                    "block",
                    MECHANISM_DISABLE,
                    cfgmgr,
                    no_cfgmgr,
                    "reactive: the device was usable from enumeration until it was disabled",
                ),
                status("eject", MECHANISM_EJECT, cfgmgr, no_cfgmgr, "reactive; for clean removal"),
                status(
                    "default_deny",
                    MECHANISM_INSTALL_RESTRICTIONS,
                    registry and not conflicts,
                    default_deny_reason,
                    _DEFAULT_DENY_TIER,
                ),
                status(
                    "read_only",
                    MECHANISM_DISK_READ_ONLY,
                    self._disks.available,
                    "the disk attribute API is not available here",
                    "reactive, best effort: it does not revoke existing write access",
                ),
                status(
                    "baseline_read_only",
                    MECHANISM_DENY_WRITE,
                    registry,
                    no_registry,
                    "standing and class-wide: every removable disk and portable device is"
                    " write-denied; one device cannot be released; may need a restart",
                ),
            )

    def capabilities(self) -> EnforcerCapabilities:
        """What this enforcer can do now. Computed without side effects."""
        with self._lock:
            statuses = {status.role: status for status in self.mechanisms()}
            notes = [
                f"{status.mechanism} unavailable: {status.reason}"
                for status in statuses.values()
                if not status.available
            ]
            conflicts = self.restriction_conflicts() if self._registry.available else ()
            if conflicts:
                notes.append(
                    "conflict: Device Installation Restriction values not written by"
                    f" PortLock: {', '.join(conflicts)}"
                )
            notes.append(f"default-deny is {_DEFAULT_DENY_TIER}")
            notes.append(f"per-device read-only is {_BEST_EFFORT}")
            return EnforcerCapabilities(
                name="windows",
                privileged=bool(self._is_admin()),
                block=statuses["block"].available,
                read_only=statuses["read_only"].available,
                eject=statuses["eject"].available,
                default_deny=statuses["default_deny"].available,
                notes=tuple(notes),
            )

    def default_deny_active(self) -> bool:
        """True if ``DenyRemovableDevices`` is in force, whoever set it."""
        try:
            return self._registry.get(RESTRICTIONS_KEY, _DENY_REMOVABLE) == _ON
        except (OSError, ValueError):
            return False

    def baseline_active(self) -> bool:
        """True if the class-wide ``Deny_Write`` for removable disks is in force."""
        try:
            return self._registry.get(DISK_CLASS_KEY, _DENY_WRITE) == _ON
        except (OSError, ValueError):
            return False

    # --- Enforcer ---------------------------------------------------------------------

    def block(self, device: UsbDevice) -> EnforcementResult:
        """Disable the device node, persistently; under default-deny also withdraw its
        ``AllowInstanceIDs`` entry so a re-plug is not admitted."""
        _require_device(device)
        return self._run(Action.BLOCK, MECHANISM_DISABLE, lambda rec: self._block(device, rec))

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        """Enable the device node; under default-deny first allow its instance id and
        re-enumerate it so Windows installs it (that admission is not journaled, E4)."""
        _require_device(device)
        return self._run(Action.UNBLOCK, MECHANISM_DISABLE, lambda rec: self._unblock(device, rec))

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        """Set or clear the read-only attribute of each disk of ``device`` (best effort).

        Under the class-wide baseline a single device cannot be made writable: that is
        reported as a failure, after the per-disk attribute has been cleared.
        """
        _require_device(device)
        if not isinstance(read_only, bool):
            raise TypeError("read_only must be True or False")
        action = Action.READ_ONLY if read_only else Action.READ_WRITE
        return self._run(
            action, MECHANISM_DISK_READ_ONLY, lambda rec: self._read_only(device, read_only, rec)
        )

    def eject(self, device: UsbDevice) -> EnforcementResult:
        """Request safe removal. A veto is a failure that names who vetoed."""
        _require_device(device)
        return self._run(Action.EJECT, MECHANISM_EJECT, lambda _rec: self._eject(device))

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        """Set (or remove) ``AllowDenyLayered`` and ``DenyRemovableDevices``."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.DEFAULT_DENY_ON if enabled else Action.DEFAULT_DENY_OFF
        return self._run(
            action, MECHANISM_INSTALL_RESTRICTIONS, lambda rec: self._default_deny(enabled, rec)
        )

    def set_baseline_read_only(self, enabled: bool) -> EnforcementResult:
        """Set (or remove) ``Deny_Write`` for removable disks and portable devices.

        This is ``baseline_read_only`` on Windows (windows.md section 10): standing and
        class-wide. Microsoft documents that it may take effect only after a restart.
        """
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.READ_ONLY if enabled else Action.READ_WRITE
        return self._run(action, MECHANISM_DENY_WRITE, lambda rec: self._baseline(enabled, rec))

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        """Put back the ``previous`` value of each entry, newest first.

        Every entry is validated before anything is written: a device node target must
        be a USB device instance id, a policy target one of the named policy values
        (with a value of the type that policy holds), a disk target a ``PhysicalDriveN``
        path. Invalid entries are reported and skipped. A value is reverted only if it
        still equals what was applied; one someone else changed (a Group Policy refresh,
        an administrator) is left alone and named in ``detail``. A device node is located
        with the phantom flag, so a device that is not connected is re-enabled too.
        """
        frozen = tuple(entries)
        for entry in frozen:
            if not isinstance(entry, JournalEntry):
                raise TypeError(f"expected JournalEntry values, got {type(entry).__name__}")
        with self._lock:
            return self._restore(frozen)

    # --- implementation ---------------------------------------------------------------

    def _run(
        self, action: Action, mechanism: str, body: Callable[[ChangeRecorder], _Outcome]
    ) -> EnforcementResult:
        with self._lock:
            recorder = ChangeRecorder(self._write_ahead)
            try:
                outcome = body(recorder)
            except (_Failure, JournalUnavailable) as failure:
                message = str(failure)
                return EnforcementResult(
                    action=action,
                    ok=False,
                    mechanism=mechanism,
                    changed=bool(recorder.undo),
                    detail=f"{action.value} failed: {message}",
                    undo=tuple(recorder.undo),
                    error=message,
                )
            return EnforcementResult(
                action=action,
                ok=outcome.ok,
                mechanism=mechanism,
                tier=outcome.tier,
                changed=outcome.changed or bool(recorder.undo),
                detail=outcome.detail,
                undo=tuple(recorder.undo),
                error=outcome.error,
            )

    def _require_admin(self, what: str) -> None:
        if not self._is_admin():
            raise _Failure(f"{NotPrivilegedError.code}: administrator rights are needed to {what}")

    @staticmethod
    def _device_id(instance_id: str) -> str:
        try:
            parsed = parse_instance_id(instance_id)
        except ValueError as exc:
            raise _Failure(
                f"refused: {instance_id!r} is not a USB device instance id: {exc}"
            ) from exc
        if parsed.kind is not NodeKind.DEVICE:
            raise _Failure(
                f"refused: {instance_id} is a {parsed.kind.value} node, not a USB device"
            )
        return instance_id

    def _check(self, code: int, call: str, instance_id: str) -> None:
        if code == CR_SUCCESS:
            return
        name = _cr_name(code)
        if code in _GONE_CODES:
            raise _Failure(f"device is gone: {instance_id} ({call}: {name})")
        if code == _CR_ACCESS_DENIED:
            raise _Failure(f"{NotPrivilegedError.code}: {call} was refused ({name})")
        if code == _CR_REMOVE_VETOED:
            raise _Failure(
                f"{call} was vetoed ({name}): an open handle or a driver refused; nothing changed"
            )
        if code == _CR_NOT_DISABLEABLE:
            raise _Failure(f"refused: {instance_id} cannot be disabled ({name})")
        raise _Failure(f"{call} failed for {instance_id} ({name})")

    def _node(self, instance_id: str) -> _Node:
        code, devinst = self._cfgmgr.locate(instance_id, phantom=False)
        self._check(code, "CM_Locate_DevNodeW", instance_id)
        code, status, problem = self._cfgmgr.status(devinst)
        self._check(code, "CM_Get_DevNode_Status", instance_id)
        return _Node(devinst, status, problem)

    def _reg_get(self, key: str, name: str) -> RegValue | None:
        try:
            return self._registry.get(key, name)
        except ValueError as exc:
            raise _Failure(f"{policy_target(key, name)} holds an unexpected value: {exc}") from exc
        except OSError as exc:
            raise _Failure(_registry_error(exc, policy_target(key, name), "read")) from exc

    def _reg_values(self, key: str) -> dict[str, RegValue]:
        try:
            return self._registry.values(key)
        except OSError as exc:
            raise _Failure(_registry_error(exc, _HKLM + key, "read")) from exc

    def _reg_set(self, key: str, name: str, value: RegValue | None) -> None:
        try:
            if value is None:
                self._registry.delete(key, name)
            else:
                self._registry.set(key, name, value)
        except OSError as exc:
            raise _Failure(_registry_error(exc, policy_target(key, name), "write")) from exc

    def _put(
        self,
        recorder: ChangeRecorder,
        key: str,
        name: str,
        before: RegValue | None,
        after: RegValue | None,
    ) -> None:
        recorder.apply(
            JournalEntry(
                JournalKind.WIN_POLICY_VALUE,
                policy_target(key, name),
                encode_reg(before),
                encode_reg(after),
            ),
            lambda: self._reg_set(key, name, after),
        )

    def _allow_entries(self, instance_id: str) -> list[tuple[str, RegValue]]:
        folded = instance_id.casefold()
        return [
            (name, value)
            for name, value in self._reg_values(ALLOW_INSTANCE_IDS_KEY).items()
            if _ALLOW_ENTRY_NAME.match(name)
            and value.type == REG_SZ
            and isinstance(value.data, str)
            and value.data.casefold() == folded
        ]

    def _ensure_allowed(self, instance_id: str, recorder: ChangeRecorder) -> bool:
        """Put ``instance_id`` on the allow list. Returns True if anything changed."""
        changed = False
        flag = self._reg_get(RESTRICTIONS_KEY, _ALLOW_INSTANCE_IDS)
        if flag != _ON:
            self._put(recorder, RESTRICTIONS_KEY, _ALLOW_INSTANCE_IDS, flag, _ON)
            changed = True
        if self._allow_entries(instance_id):
            return changed
        taken = set(self._reg_values(ALLOW_INSTANCE_IDS_KEY))
        for number in range(1, _MAX_ALLOW_ENTRIES + 1):
            if str(number) not in taken:
                self._put(
                    recorder, ALLOW_INSTANCE_IDS_KEY, str(number), None, RegValue.sz(instance_id)
                )
                return True
        raise _Failure("the AllowInstanceIDs list is full")

    def _block(self, device: UsbDevice, recorder: ChangeRecorder) -> _Outcome:
        ident = self._device_id(device.instance_id)
        self._require_admin("disable a device")
        node = self._node(ident)
        default_deny = self.default_deny_active()
        notes: list[str] = []
        if node.disabled:
            notes.append(f"{ident} is already disabled")
        elif (
            default_deny
            and node.not_installed
            and not node.started
            and not self._allow_entries(ident)
        ):
            # E7: an installation restriction keeps it out; no second mechanism is added.
            return _Outcome(
                f"{ident} was never installed: the Device Installation Restrictions keep it"
                " out (preventive for never-installed devices)",
                Tier.PREVENTIVE,
            )
        else:
            if not node.status & _DN_DISABLEABLE:
                raise _Failure(
                    f"refused: {ident} cannot be disabled (DN_DISABLEABLE is clear); it is"
                    " not enforced"
                )
            recorder.apply(
                JournalEntry(JournalKind.WIN_DEVNODE, ident, _ENABLED, _DISABLED),
                lambda: self._check(
                    self._cfgmgr.disable(node.devinst, persist=True), "CM_Disable_DevNode", ident
                ),
            )
            notes.append(
                f"disabled {ident} with CM_DISABLE_PERSIST: it stays disabled across"
                " restarts until PortLock enables it; it was usable from enumeration until"
                " now (reactive)"
            )
        if default_deny:
            for name, value in self._allow_entries(ident):
                self._put(recorder, ALLOW_INSTANCE_IDS_KEY, name, value, None)
                notes.append(f"withdrew its AllowInstanceIDs entry {name}")
        return _Outcome("; ".join(notes), Tier.REACTIVE)

    def _unblock(self, device: UsbDevice, recorder: ChangeRecorder) -> _Outcome:
        ident = self._device_id(device.instance_id)
        self._require_admin("enable a device")
        default_deny = self.default_deny_active()
        notes: list[str] = []
        if default_deny and self._ensure_allowed(ident, recorder):
            notes.append(f"added {ident} to the AllowInstanceIDs list")
        node = self._node(ident)
        admitted = False
        if node.disabled:
            recorder.apply(
                JournalEntry(JournalKind.WIN_DEVNODE, ident, _DISABLED, _ENABLED),
                lambda: self._check(self._cfgmgr.enable(node.devinst), "CM_Enable_DevNode", ident),
            )
            notes.append(f"enabled {ident}")
        elif default_deny and not node.started:
            # Admission (E4): nothing PortLock did is reversed, so nothing is journaled.
            self._check(self._cfgmgr.reenumerate(node.devinst), "CM_Reenumerate_DevNode", ident)
            notes.append(f"re-enumerated {ident} so Windows installs it (admission, not journaled)")
            admitted = True
        if not notes:
            return _Outcome(f"{ident} is already enabled")
        return _Outcome("; ".join(notes), changed=admitted)

    def _eject(self, device: UsbDevice) -> _Outcome:
        ident = self._device_id(device.instance_id)
        self._require_admin("eject a device")
        code, devinst = self._cfgmgr.locate(ident, phantom=False)
        self._check(code, "CM_Locate_DevNodeW", ident)
        code, veto, vetoer = self._cfgmgr.request_eject(devinst)
        if code == CR_SUCCESS and veto == 0:
            return _Outcome(
                f"safe removal of {ident} requested; it returns when re-plugged (no undo)",
                Tier.REACTIVE,
                changed=True,
            )
        if code in _GONE_CODES:
            raise _Failure(f"device is gone: {ident} ({_cr_name(code)})")
        who = sanitize_device_text(vetoer, limit=120) or "unknown"
        raise _Failure(
            f"eject vetoed: {_VETO_NAMES.get(veto, f'veto type {veto}')} by {who!r}"
            f" ({_cr_name(code)}); nothing changed"
        )

    def _default_deny(self, enabled: bool, recorder: ChangeRecorder) -> _Outcome:
        if enabled:
            conflicts = self.restriction_conflicts()
            if conflicts:
                raise _Failure(
                    "refused: Device Installation Restriction values not written by PortLock"
                    f" are present ({', '.join(conflicts)}); a domain or local policy manages"
                    " them"
                )
            changed = 0
            # Layered evaluation first, so an AllowInstanceIDs entry can release an
            # approved device from DenyRemovableDevices from the moment that is set.
            for name in (_ALLOW_DENY_LAYERED, _DENY_REMOVABLE):
                current = self._reg_get(RESTRICTIONS_KEY, name)
                if current == _ON:
                    continue
                self._require_admin("change device installation policy")
                self._put(recorder, RESTRICTIONS_KEY, name, current, _ON)
                changed += 1
            prefix = "default-deny is on" if changed else "default-deny was already on"
            return _Outcome(f"{prefix}: {_DEFAULT_DENY_TIER}", Tier.PREVENTIVE)
        notes: list[str] = []
        for name in (_DENY_REMOVABLE, _ALLOW_DENY_LAYERED):
            current = self._reg_get(RESTRICTIONS_KEY, name)
            if current is None:
                continue
            if current != _ON:
                notes.append(
                    f"{name} holds {current.encode()}, which PortLock never writes; left alone"
                )
                continue
            self._require_admin("change device installation policy")
            self._put(recorder, RESTRICTIONS_KEY, name, current, None)
        detail = "default-deny is off: Windows installs new removable devices again"
        return _Outcome("; ".join([detail, *notes]))

    def _baseline(self, enabled: bool, recorder: ChangeRecorder) -> _Outcome:
        notes: list[str] = []
        for key in (DISK_CLASS_KEY, WPD_CLASS_KEY):
            current = self._reg_get(key, _DENY_WRITE)
            if enabled:
                if current == _ON:
                    continue
                self._require_admin("change removable storage policy")
                self._put(recorder, key, _DENY_WRITE, current, _ON)
            elif current is not None:
                if current != _ON:
                    notes.append(
                        f"{policy_target(key, _DENY_WRITE)} holds {current.encode()}; left alone"
                    )
                    continue
                self._require_admin("change removable storage policy")
                self._put(recorder, key, _DENY_WRITE, current, None)
        if enabled:
            detail = (
                "removable disks and portable devices are write-denied class-wide (standing"
                " baseline). Windows offers no per-device exception, so one approved device"
                " cannot be released; Microsoft documents that the setting may take effect"
                " only after a restart"
            )
            return _Outcome("; ".join([detail, *notes]), Tier.PREVENTIVE)
        return _Outcome("; ".join(["the class-wide write deny is lifted", *notes]))

    def _disk_numbers(self, ident: str) -> list[int]:
        try:
            return self._disks.disk_numbers(ident)
        except OSError as exc:
            raise _Failure(f"cannot list the disks of {ident}: {exc.strerror or exc}") from exc

    def _disk_get(self, disk: int) -> bool:
        try:
            return self._disks.get_read_only(disk)
        except OSError as exc:
            raise _Failure(_disk_error(exc, disk, "read")) from exc

    def _disk_set(self, disk: int, read_only: bool) -> None:
        try:
            self._disks.set_read_only(disk, read_only)
        except OSError as exc:
            raise _Failure(_disk_error(exc, disk, "set")) from exc

    def _read_only(self, device: UsbDevice, read_only: bool, recorder: ChangeRecorder) -> _Outcome:
        if read_only and not device.is_storage:
            raise _Failure("not a storage device")
        ident = self._device_id(device.instance_id)
        baseline = self.baseline_active()
        disks = self._disk_numbers(ident)
        if not disks:
            if not read_only:
                if baseline:
                    raise _Failure(
                        "baseline_read_only on Windows is a class-wide Deny_Write policy: one"
                        " device cannot be released from it"
                    )
                return _Outcome(f"{ident} has no disk; nothing to make writable")
            if baseline:
                return _Outcome(
                    f"{ident} has no disk now; the standing class-wide Deny_Write baseline"
                    " covers it when its volumes appear",
                    Tier.PREVENTIVE,
                )
            raise _Failure(
                "not enforced: the device has no disk now (it may be blocked, have no"
                " medium, or be a portable device without a disk); call again once it has one"
            )
        flipped = 0
        for disk in disks:
            if self._disk_get(disk) == read_only:
                continue
            self._require_admin("change a disk's read-only attribute")
            before, after = ("0", "1") if read_only else ("1", "0")
            recorder.apply(
                JournalEntry(JournalKind.WIN_DISK_READ_ONLY, disk_target(disk), before, after),
                lambda disk=disk: self._disk_set(disk, read_only),
            )
            flipped += 1
        if not read_only:
            detail = (
                f"cleared the read-only attribute on {flipped} of {len(disks)} disk(s) of {ident}"
            )
            if baseline:
                message = (
                    "baseline_read_only on Windows is a class-wide Deny_Write policy: one"
                    " device cannot be released from it"
                )
                return _Outcome(f"{detail}; {message}", ok=False, error=message)
            return _Outcome(detail)
        detail = (
            f"set the read-only attribute on {flipped} of {len(disks)} disk(s) of {ident}"
            f" ({len(disks) - flipped} already had it); {_BEST_EFFORT}"
        )
        if baseline:
            return _Outcome(
                detail + "; the standing class-wide Deny_Write baseline also covers it",
                Tier.PREVENTIVE,
            )
        return _Outcome(detail, Tier.REACTIVE)

    # -- restore -----------------------------------------------------------------------

    def _plan(self, entry: JournalEntry) -> _Plan:
        kind = entry.kind
        if kind == JournalKind.WIN_DEVNODE:
            ident = self._device_id(entry.target)
            values = {_ENABLED, _DISABLED}
            if (
                entry.previous not in values
                or entry.applied not in values
                or entry.previous == entry.applied
            ):
                raise _Failure(f"refused journal entry for {ident}: unusable device node states")
            return _Plan(entry, False, lambda: self._restore_devnode(ident, entry))
        if kind == JournalKind.WIN_POLICY_VALUE:
            key, name, previous, applied = _validate_policy_entry(entry)
            return _Plan(entry, False, lambda: self._restore_policy(key, name, previous, applied))
        if kind == JournalKind.WIN_DISK_READ_ONLY:
            match = _DISK_TARGET.match(entry.target)
            values = {"0", "1"}
            if (
                match is None
                or entry.previous not in values
                or entry.applied not in values
                or entry.previous == entry.applied
            ):
                raise _Failure(f"refused journal entry: {entry.target!r} is not a disk attribute")
            disk = int(match.group(1))
            # The attribute is set without Persist: it went away with the disk.
            return _Plan(entry, True, lambda: self._restore_disk(disk, entry))
        raise _Failure(f"cannot restore a {kind!r} journal entry on Windows ({entry.target})")

    def _restore_devnode(self, ident: str, entry: JournalEntry) -> str:
        code, devinst = self._cfgmgr.locate(ident, phantom=True)
        if code in _GONE_CODES:
            raise _Failure(f"{ident} no longer exists on this system ({_cr_name(code)})")
        self._check(code, "CM_Locate_DevNodeW", ident)
        code, status, problem = self._cfgmgr.status(devinst)
        if code == CR_SUCCESS:
            current = _DISABLED if _Node(devinst, status, problem).disabled else _ENABLED
        elif code in _GONE_CODES and entry.previous == _ENABLED:
            # Not connected: its state cannot be read. Enabling only lifts a disable, so
            # it is safe to do without seeing the current state.
            self._check(self._cfgmgr.enable(devinst), "CM_Enable_DevNode", ident)
            return "restored"
        else:
            raise _Failure(f"the state of {ident} cannot be read ({_cr_name(code)}); left alone")
        if current == entry.previous:
            return "already"
        if current != entry.applied:
            return f"left:{ident} (now {current})"
        if entry.previous == _ENABLED:
            self._check(self._cfgmgr.enable(devinst), "CM_Enable_DevNode", ident)
        else:
            if not status & _DN_DISABLEABLE:
                raise _Failure(f"refused: {ident} cannot be disabled (DN_DISABLEABLE is clear)")
            self._check(self._cfgmgr.disable(devinst, persist=True), "CM_Disable_DevNode", ident)
        return "restored"

    def _restore_policy(
        self, key: str, name: str, previous: RegValue | None, applied: RegValue | None
    ) -> str:
        current = self._reg_get(key, name)
        if current == previous:
            return "already"
        if current != applied:
            shown = current.encode() if current is not None else "absent"
            return f"left:{policy_target(key, name)} (now {_short(shown)})"
        self._reg_set(key, name, previous)
        return "restored"

    def _restore_disk(self, disk: int, entry: JournalEntry) -> str:
        try:
            current = "1" if self._disks.get_read_only(disk) else "0"
        except FileNotFoundError:
            return "gone"
        except OSError as exc:
            raise _Failure(_disk_error(exc, disk, "read")) from exc
        if current == entry.previous:
            return "already"
        if current != entry.applied:
            return f"left:{entry.target} (now {current})"
        self._disk_set(disk, entry.previous == "1")
        return "restored"

    def _restore(self, entries: tuple[JournalEntry, ...]) -> EnforcementResult:
        if not entries:
            return EnforcementResult(
                action=Action.RESTORE,
                ok=True,
                mechanism=MECHANISM_RESTORE,
                detail="nothing to restore",
            )
        plans: list[_Plan] = []
        errors: list[str] = []
        for entry in entries:
            try:
                plans.append(self._plan(entry))
            except _Failure as failure:
                errors.append(str(failure))
        restored = already = gone = 0
        left_alone: list[str] = []
        admin = self._is_admin()
        for plan in reversed(plans):
            if not admin:
                errors.append(
                    f"{NotPrivilegedError.code}: administrator rights are needed to restore"
                    f" {plan.entry.target}"
                )
                continue
            try:
                outcome = plan.run()
            except _Failure as failure:
                errors.append(str(failure))
                continue
            if outcome == "restored":
                restored += 1
            elif outcome == "already":
                already += 1
            elif outcome == "gone":
                gone += 1
            else:
                left_alone.append(outcome.removeprefix("left:"))
        detail = f"restored {restored} of {len(entries)} journal entries"
        if already:
            detail += f"; {already} already held their previous value"
        if gone:
            detail += f"; {gone} disappeared with their device (nothing to restore)"
        if left_alone:
            detail += (
                f"; {len(left_alone)} left alone because something else changed them since: "
                + ", ".join(left_alone)
            )
        if errors:
            detail += f"; {len(errors)} could not be restored"
        return EnforcementResult(
            action=Action.RESTORE,
            ok=not errors,
            mechanism=MECHANISM_RESTORE,
            changed=restored > 0,
            detail=detail,
            error="; ".join(errors) if errors else None,
        )


# --------------------------------------------------------------------------------------
# Journal target validation
# --------------------------------------------------------------------------------------

#: Every policy value PortLock may write, as (key, value name pattern, value type).
_POLICY_TARGETS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (RESTRICTIONS_KEY, re.compile(f"{_DENY_REMOVABLE}\\Z", re.IGNORECASE), REG_DWORD),
    (RESTRICTIONS_KEY, re.compile(f"{_ALLOW_DENY_LAYERED}\\Z", re.IGNORECASE), REG_DWORD),
    (RESTRICTIONS_KEY, re.compile(f"{_ALLOW_INSTANCE_IDS}\\Z", re.IGNORECASE), REG_DWORD),
    (ALLOW_INSTANCE_IDS_KEY, _ALLOW_ENTRY_NAME, REG_SZ),
    (DISK_CLASS_KEY, re.compile(f"{_DENY_WRITE}\\Z", re.IGNORECASE), REG_DWORD),
    (WPD_CLASS_KEY, re.compile(f"{_DENY_WRITE}\\Z", re.IGNORECASE), REG_DWORD),
)


def _validate_policy_entry(
    entry: JournalEntry,
) -> tuple[str, str, RegValue | None, RegValue | None]:
    target = entry.target
    if not target.upper().startswith(_HKLM):
        raise _Failure(f"refused journal entry: {target!r} is not under HKLM")
    key, _separator, name = target[len(_HKLM) :].rpartition("\\")
    match = next(
        (
            (allowed_key, kind)
            for allowed_key, pattern, kind in _POLICY_TARGETS
            if key.casefold() == allowed_key.casefold() and pattern.match(name)
        ),
        None,
    )
    if match is None:
        raise _Failure(f"refused journal entry: {target!r} is not a policy value PortLock writes")
    allowed_key, kind = match
    decoded: list[RegValue | None] = []
    for label, text in (("previous", entry.previous), ("applied", entry.applied)):
        if text is None:
            decoded.append(None)
            continue
        try:
            value = RegValue.decode(text)
        except ValueError as exc:
            raise _Failure(f"refused journal entry for {target}: {label} value: {exc}") from exc
        if value.type != kind:
            raise _Failure(f"refused journal entry for {target}: {label} value has the wrong type")
        if kind == REG_SZ:
            try:
                parsed = parse_instance_id(str(value.data))
            except ValueError as exc:
                raise _Failure(
                    f"refused journal entry for {target}: {label} is not a USB instance id"
                ) from exc
            if parsed.kind is not NodeKind.DEVICE:
                raise _Failure(f"refused journal entry for {target}: {label} is not a USB device")
        decoded.append(value)
    previous, applied = decoded
    if previous == applied:
        raise _Failure(f"refused journal entry for {target}: previous equals applied")
    if kind == REG_DWORD and applied not in (None, _ON):
        raise _Failure(f"refused journal entry for {target}: PortLock only ever writes 1")
    return allowed_key, name, previous, applied


# --------------------------------------------------------------------------------------
# System volume
# --------------------------------------------------------------------------------------


def system_device_ids(
    devices: Sequence[UsbDevice], *, env: Mapping[str, str] | None = None, api: object | None = None
) -> frozenset[str]:
    """The instance ids of the devices in ``devices`` that hold, or lead to, the disk of
    ``%SystemDrive%`` or ``%SystemRoot%``.

    Read-only: volumes are matched to disks with ``IOCTL_STORAGE_GET_DEVICE_NUMBER`` and
    disks to USB devices with the device-tree walk of
    :func:`portlock.guard.windows.volumes.find_disks`. A hub above such a device is
    included too.

    Args:
        devices: the connected devices.
        env: environment to read ``SystemDrive`` / ``SystemRoot`` from (default: this
            process's).
        api: a :class:`~portlock.guard.windows.api.WinApi` (a fake in tests).

    Raises:
        BackendError: if the system drive is unknown, no volume is mounted at it, or the
            device tree cannot be read.
    """
    from portlock.guard.windows.api import FILE_DEVICE_DISK, WinApi
    from portlock.guard.windows.volumes import find_disks, is_volume_guid_path

    source = os.environ if env is None else env
    roots: set[str] = set()
    for variable in ("SystemDrive", "SystemRoot"):
        value = source.get(variable) or source.get(variable.upper())
        if value and re.match(r"[A-Za-z]:", value):
            roots.add(value[0].upper() + ":\\")
    if not roots:
        raise BackendError("neither SystemDrive nor SystemRoot names a drive letter")
    winapi: WinApi = api if api is not None else WinApi()  # type: ignore[assignment]
    system_disks: set[int] = set()
    for name in winapi.volume_names():
        if not is_volume_guid_path(name):
            continue
        points = {point.upper() for point in winapi.volume_mount_points(name)}
        if not points & roots:
            continue
        number = winapi.storage_device_number(name[:-1])
        if number is not None and number.device_type == FILE_DEVICE_DISK:
            system_disks.add(number.device_number)
        else:
            system_disks.update(winapi.volume_disk_numbers(name[:-1]))
    if not system_disks:
        raise BackendError("no disk holds the system drive")
    by_id = {device.instance_id.casefold(): device.instance_id for device in devices}
    found: set[str] = set()
    for device in devices:
        devinst = winapi.locate_devnode(device.instance_id)
        if devinst is None:
            continue
        disks = find_disks(winapi, devinst)
        if not any(
            disk.device_type == FILE_DEVICE_DISK and disk.device_number in system_disks
            for disk in disks
        ):
            continue
        found.add(device.instance_id)
        parent = winapi.get_parent(devinst)
        for _ in range(32):
            if parent is None:
                break
            parent_id = winapi.get_device_id(parent)
            if parent_id and parent_id.casefold() in by_id:
                found.add(by_id[parent_id.casefold()])
            parent = winapi.get_parent(parent)
    return frozenset(found)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _require_device(device: object) -> None:
    if not isinstance(device, UsbDevice):
        raise TypeError(f"expected a UsbDevice, got {type(device).__name__}")


def _cr_name(code: int) -> str:
    return _CR_NAMES.get(code) or config_ret_name(code)


def _short(value: str) -> str:
    return value if len(value) <= 60 else value[:57] + "..."


def _registry_error(exc: OSError, target: str, doing: str) -> str:
    if isinstance(exc, PermissionError):
        return f"{NotPrivilegedError.code}: cannot {doing} {target}: access denied"
    return f"cannot {doing} {target}: {exc.strerror or exc}"


def _disk_error(exc: OSError, disk: int, doing: str) -> str:
    target = disk_target(disk)
    if isinstance(exc, PermissionError):
        return f"{NotPrivilegedError.code}: cannot {doing} the attribute of {target}: access denied"
    if isinstance(exc, FileNotFoundError):
        return f"device is gone: {target} no longer exists"
    return f"cannot {doing} the attribute of {target}: {exc.strerror or exc}"
