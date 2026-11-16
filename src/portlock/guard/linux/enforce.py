"""The Linux enforcer: sysfs authorization, ``BLKROSET`` and a read-only udev baseline.

Mechanisms, as specified in ``docs/enforcement/linux.md`` and corrected by
``docs/DESIGN.md`` sections 14.14 to 14.19:

======================  ===========================================  ====================
What                    How                                          Tier
======================  ===========================================  ====================
block / unblock         ``<device>/authorized`` = ``0`` / ``1``      reactive
default-deny            every ``usbN/authorized_default`` and        preventive for later
                        ``/sys/module/usbcore/parameters/``          arrivals only
                        ``authorized_default`` = ``0``
read-only, per device   ``BLKROSET`` on the device's disk and        reactive, best effort
                        partitions
read-only baseline      a generated udev rules file that sets        preventive (the
                        ``BLKROSET`` at ``add``, before automounters  dependable form)
eject                   ``<device>/remove`` = ``1``                  reactive
======================  ===========================================  ====================

Only ``usbcore.authorized_default=0`` on the kernel command line is preventive from boot
(14.19); :func:`parse_authorized_default_param` reads it for ``portlock doctor``.

Every operating-system access goes through the seams in :mod:`portlock.guard.seams`, so
everything here runs against in-memory fakes. Every write is journaled ahead
(:class:`~portlock.guard.seams.ChangeRecorder`), every journal target is validated before
:meth:`LinuxEnforcer.restore` writes it, and nothing is ever written outside the sysfs
attributes named here, block device nodes of USB disks and the one rules file.

No mechanism in this module has been run against a real device by the test suite.
"""

from __future__ import annotations

import errno
import posixpath
import re
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from portlock.core.errors import BackendError, EnforcementError, NotPrivilegedError
from portlock.core.models import UsbDevice
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
    JournalKind,
    Tier,
)
from portlock.guard.linux.mounts import parse_mountinfo
from portlock.guard.linux.sysfs import is_device_name, is_root_hub_name
from portlock.guard.seams import (
    BlockIO,
    ChangeRecorder,
    CommandRunner,
    JournalUnavailable,
    MechanismStatus,
    RealBlockIO,
    RealRuleFiles,
    RealSysfs,
    RuleFileIO,
    SubprocessRunner,
    SysfsIO,
    current_process_privileged,
)

__all__ = [
    "BASELINE_RULE_NAME",
    "DEFAULT_BLOCKDEV",
    "DEFAULT_RULES_DIR",
    "DEFAULT_UDEVADM",
    "MECHANISM_AUTHORIZED",
    "MECHANISM_AUTHORIZED_DEFAULT",
    "MECHANISM_BLKROSET",
    "MECHANISM_REMOVE",
    "MECHANISM_RESTORE",
    "MECHANISM_UDEV_BLKROSET",
    "MECHANISM_UDEV_RULE",
    "SYSTEM_MOUNT_POINTS",
    "USBGUARD_MARKERS",
    "LinuxEnforcer",
    "baseline_rule_text",
    "parse_authorized_default_param",
    "system_device_ids",
]

MECHANISM_AUTHORIZED = "sysfs:authorized"
MECHANISM_AUTHORIZED_DEFAULT = "sysfs:authorized_default"
MECHANISM_REMOVE = "sysfs:remove"
MECHANISM_BLKROSET = "blkroset"
MECHANISM_UDEV_BLKROSET = "udev-rule+blkroset"
MECHANISM_UDEV_RULE = "udev-rule"
MECHANISM_RESTORE = "journal:restore"

#: Name of the baseline rules file. It sorts after ``60-persistent-storage.rules``, which
#: sets ``ID_BUS`` (``docs/enforcement/linux.md`` section 5.3).
BASELINE_RULE_NAME = "60-portlock-readonly.rules"
DEFAULT_RULES_DIR = "/etc/udev/rules.d"
DEFAULT_UDEVADM = "/usr/bin/udevadm"
DEFAULT_BLOCKDEV = "/usr/sbin/blockdev"
#: Files whose presence means USBGuard is installed: it also writes ``authorized`` and
#: ``authorized_default`` and would contend with PortLock.
USBGUARD_MARKERS: tuple[str, ...] = ("/etc/usbguard/usbguard-daemon.conf",)
#: Mount points whose backing devices are "the system volume" (ARCHITECTURE 3.2).
SYSTEM_MOUNT_POINTS: tuple[str, ...] = ("/", "/boot", "/boot/efi", "/efi", "/usr", "/var", "/etc")

_MODULE_PARAMETER = "module/usbcore/parameters/authorized_default"
_AUTHORIZED_VALUES = frozenset({"0", "1"})
_AUTHORIZED_DEFAULT_VALUES = frozenset({"-1", "0", "1", "2"})
# authorized_default values under which a new device is not configured until authorized:
# 0 refuses every device, 2 every device not on an internal (hardwired) port.
_DEFAULT_DENY_VALUES = frozenset({"0", "2"})
_RO_VALUES = frozenset({"0", "1"})
_BLOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9!._+-]{0,63}")
_PARAMETER = re.compile(r"usbcore\.authorized_default=(\S{0,16})")
_COMMAND_TIMEOUT = 8.0
_MAX_SLAVE_DEPTH = 8
_GONE = frozenset({errno.ENOENT, errno.ENODEV, errno.ENXIO})
_DENIED = frozenset({errno.EACCES, errno.EPERM})

_BEST_EFFORT = (
    "best effort: a filesystem mounted read-write before the flag was set, and files"
    " already open for writing, keep write access until remounted (DESIGN 14.14)"
)


def baseline_rule_text(blockdev: str = DEFAULT_BLOCKDEV) -> str:
    """The udev rule that makes every USB disk and partition read-only at ``add``.

    The rule runs ``blockdev --setro`` from ``RUN``, which udev executes after all rules
    for the event; listeners such as udisks2 learn about the device afterwards
    (``docs/enforcement/linux.md`` 5.3, the ordering is UNVERIFIED in documentation).

    Raises:
        ValueError: if ``blockdev`` is not a plain absolute path.
    """
    if not re.fullmatch(r"/[A-Za-z0-9/._-]{1,200}", blockdev):
        raise ValueError(f"blockdev must be a plain absolute path, got {blockdev!r}")
    return (
        "# PortLock: USB disks and partitions start read-only; PortLock releases approved"
        " ones.\n"
        "# Written by PortLock and removed by its restore. An edited file is left alone.\n"
        'ACTION=="add|change", SUBSYSTEM=="block", ENV{ID_BUS}=="usb",'
        ' ENV{DEVTYPE}=="disk|partition",'
        f' RUN+="{blockdev} --setro $devnode"\n'
    )


def parse_authorized_default_param(cmdline: str) -> str | None:
    """The value of ``usbcore.authorized_default=`` on a kernel command line.

    The last occurrence wins, as in the kernel. Returns ``None`` if the parameter is
    absent. The value is returned as written (at most 16 characters); the kernel accepts
    ``-1``, ``0``, ``1`` and ``2``.
    """
    if not isinstance(cmdline, str):
        return None
    found: str | None = None
    for token in cmdline.split():
        match = _PARAMETER.fullmatch(token)
        if match is not None:
            found = match.group(1)
    return found


class _Failure(EnforcementError):
    """An expected failure inside one call; becomes an ``ok=False`` result."""


@dataclass(frozen=True, slots=True)
class _UsbDir:
    """A validated USB device directory: ``<root>/devices/.../usbN/N-P[.P...]``."""

    path: str
    name: str
    root_hub: str


@dataclass(frozen=True, slots=True)
class _Outcome:
    detail: str
    tier: Tier = Tier.NONE
    ok: bool = True
    error: str | None = None
    changed: bool = False
    mechanism: str | None = None


@dataclass(frozen=True, slots=True)
class _Plan:
    """One validated journal entry, with how to read and write its target."""

    entry: JournalEntry
    previous: str | None
    applied: str | None
    volatile: bool
    read: Callable[[], str | None]
    write: Callable[[str | None], None]


class LinuxEnforcer(Enforcer):
    """Makes Linux restrict USB devices (see the module docstring for the mechanisms).

    Contract (``guard/base.py`` and ARCHITECTURE 2.2): every method is idempotent,
    returns expected failures instead of raising, never formats, wipes or deletes, and
    describes each change with typed journal entries, handed to ``write_ahead`` before
    the change is made. ``UsbDevice.instance_id`` must be the device's resolved sysfs
    directory, as :class:`~portlock.guard.linux.backend.LinuxBackend` reports it; any
    other value is refused before anything is touched.

    Calls are serialized by an internal lock.

    Args:
        sysfs: sysfs access (and existence checks of other plain files).
        block: ``BLKROGET`` / ``BLKROSET``.
        rules: the udev rules file.
        runner: runs ``udevadm control --reload``.
        is_root: whether this process may write the attributes.
        sysfs_root: where sysfs is mounted.
        rules_dir: where the baseline rules file is written.
        write_ahead: called with each journal entry just before its change is made.
        udevadm / blockdev: absolute paths of the two programs involved.
        conflict_markers: files whose presence reveals another program (USBGuard) that
            manages the same attributes.

    Raises:
        ValueError: if a path argument is not a normalized absolute POSIX path.
    """

    def __init__(
        self,
        *,
        sysfs: SysfsIO,
        block: BlockIO,
        rules: RuleFileIO,
        runner: CommandRunner,
        is_root: Callable[[], bool],
        sysfs_root: str = "/sys",
        rules_dir: str = DEFAULT_RULES_DIR,
        write_ahead: Callable[[JournalEntry], None] | None = None,
        udevadm: str = DEFAULT_UDEVADM,
        blockdev: str = DEFAULT_BLOCKDEV,
        conflict_markers: Sequence[str] = USBGUARD_MARKERS,
    ) -> None:
        for name, value in (("sysfs_root", sysfs_root), ("rules_dir", rules_dir)):
            if not _is_clean_absolute(value) or value == "/":
                raise ValueError(f"{name} must be a normalized absolute path, got {value!r}")
        if not _is_clean_absolute(udevadm):
            raise ValueError("udevadm must be an absolute path")
        if write_ahead is not None and not callable(write_ahead):
            raise TypeError("write_ahead must be callable or None")
        self._sysfs = sysfs
        self._block = block
        self._rules = rules
        self._runner = runner
        self._is_root = is_root
        self._root = sysfs_root
        self._devices_prefix = sysfs_root + "/devices/"
        self._bus_dir = sysfs_root + "/bus/usb/devices"
        self._class_block = sysfs_root + "/class/block"
        self._module_parameter = posixpath.join(sysfs_root, _MODULE_PARAMETER)
        self._rules_dir = rules_dir
        self._rules_path = posixpath.join(rules_dir, BASELINE_RULE_NAME)
        self._rule_text = baseline_rule_text(blockdev)
        self._udevadm = udevadm
        self._write_ahead = write_ahead
        self._conflict_markers = tuple(conflict_markers)
        self._lock = threading.RLock()

    @classmethod
    def system(cls, *, write_ahead: Callable[[JournalEntry], None] | None = None) -> LinuxEnforcer:
        """The enforcer wired to the real operating system."""
        return cls(
            sysfs=RealSysfs(),
            block=RealBlockIO(),
            rules=RealRuleFiles(),
            runner=SubprocessRunner(env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}),
            is_root=current_process_privileged,
            write_ahead=write_ahead,
        )

    @property
    def rules_path(self) -> str:
        """Where the read-only baseline rule is written."""
        return self._rules_path

    # --- capabilities -----------------------------------------------------------------

    def mechanisms(self) -> tuple[MechanismStatus, ...]:
        """Each mechanism's availability on this machine now, with the reason if not.

        Side-effect free: reads directory listings and checks write permission.
        """
        with self._lock:
            root = self._is_root()
            hubs = self._root_hub_dirs()
            no_bus = (
                f"no USB host controller under {self._bus_dir} (WSL without an attached"
                " device, or a container without the host's sysfs)"
            )

            def attribute_status(
                role: str, mechanism: str, attribute: str, tier: str
            ) -> MechanismStatus:
                if not root:
                    return MechanismStatus(role, mechanism, False, tier, "not running as root")
                if not hubs:
                    return MechanismStatus(role, mechanism, False, tier, no_bus)
                paths = [posixpath.join(hub, attribute) for hub in hubs]
                if not any(self._sysfs.exists(path) for path in paths):
                    return MechanismStatus(
                        role, mechanism, False, tier, f"this kernel has no {attribute} attribute"
                    )
                if not any(self._sysfs.writable(path) for path in paths):
                    return MechanismStatus(
                        role,
                        mechanism,
                        False,
                        tier,
                        f"{attribute} is not writable here: sysfs is read-only (a container,"
                        " or ProtectKernelTunables=yes)",
                    )
                return MechanismStatus(role, mechanism, True, tier)

            statuses = [
                attribute_status(
                    "block",
                    MECHANISM_AUTHORIZED,
                    "authorized",
                    "reactive: the device was usable from enumeration until it was deauthorized",
                ),
                attribute_status(
                    "eject",
                    MECHANISM_REMOVE,
                    "remove",
                    "reactive; the port stays disabled until the device is unplugged",
                ),
                attribute_status(
                    "default_deny",
                    MECHANISM_AUTHORIZED_DEFAULT,
                    "authorized_default",
                    "preventive for devices that arrive afterwards; devices already"
                    " connected are not affected",
                ),
            ]
            read_only_tier = "reactive, best effort: it does not revoke existing write access"
            if not root:
                statuses.append(
                    MechanismStatus(
                        "read_only",
                        MECHANISM_BLKROSET,
                        False,
                        read_only_tier,
                        "not running as root",
                    )
                )
            elif not self._block.available:
                statuses.append(
                    MechanismStatus(
                        "read_only",
                        MECHANISM_BLKROSET,
                        False,
                        read_only_tier,
                        "the BLKROSET ioctl is not available on this platform",
                    )
                )
            else:
                statuses.append(
                    MechanismStatus("read_only", MECHANISM_BLKROSET, True, read_only_tier)
                )
            baseline_tier = (
                "preventive: USB disks are read-only from the moment they appear; the"
                " dependable form of read-only"
            )
            if not root:
                reason = "not running as root"
            elif not self._block.available:
                reason = "the BLKROSET ioctl is not available on this platform"
            elif not self._rules.dir_writable(self._rules_dir):
                reason = f"{self._rules_dir} does not exist or is not writable"
            else:
                reason = ""
            statuses.append(
                MechanismStatus(
                    "baseline_read_only", MECHANISM_UDEV_RULE, not reason, baseline_tier, reason
                )
            )
            return tuple(statuses)

    def capabilities(self) -> EnforcerCapabilities:
        """What this enforcer can do now. Computed without side effects."""
        with self._lock:
            statuses = {status.role: status for status in self.mechanisms()}
            notes = [
                f"{status.mechanism} unavailable: {status.reason}"
                for status in statuses.values()
                if not status.available
            ]
            if not self._sysfs.exists(self._module_parameter):
                notes.append(
                    "the usbcore authorized_default module parameter is missing: host"
                    " controllers that register after default-deny is turned on are not"
                    " covered until their arrival is handled"
                )
            notes.append(
                "only usbcore.authorized_default=0 on the kernel command line is preventive"
                " from boot; turning default-deny on at run time covers later arrivals only"
            )
            notes.extend(self._conflicts())
            return EnforcerCapabilities(
                name="linux",
                privileged=bool(self._is_root()),
                block=statuses["block"].available,
                read_only=statuses["read_only"].available,
                eject=statuses["eject"].available,
                default_deny=statuses["default_deny"].available,
                notes=tuple(notes),
            )

    def _conflicts(self) -> list[str]:
        return [
            f"conflict: USBGuard is installed ({marker}); if its daemon runs it also writes"
            " authorized and authorized_default and will contend with PortLock"
            for marker in self._conflict_markers
            if self._sysfs.exists(marker)
        ]

    # --- Enforcer ---------------------------------------------------------------------

    def block(self, device: UsbDevice) -> EnforcementResult:
        """Deauthorize ``device``: its drivers are released and it stays unconfigured."""
        _require_device(device)
        return self._run(
            Action.BLOCK, MECHANISM_AUTHORIZED, lambda rec: self._block_device(device, rec)
        )

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        """Authorize ``device`` again.

        Admitting a device that default-deny kept out is not journaled (ARCHITECTURE 2.2
        E4): restoring "the previous value" would lock it out again.
        """
        _require_device(device)
        return self._run(
            Action.UNBLOCK, MECHANISM_AUTHORIZED, lambda rec: self._unblock_device(device, rec)
        )

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        """Set or clear ``BLKROSET`` on every disk and partition of ``device``.

        Reactive read-only is best effort (DESIGN 14.14). Where the baseline rule is in
        place, a device's storage was read-only from the start and the result says
        ``preventive``; a device that has no block device yet (still blocked) can only be
        covered by the baseline (E12), otherwise the call fails and the caller repeats it
        once the device is unblocked.
        """
        _require_device(device)
        if not isinstance(read_only, bool):
            raise TypeError("read_only must be True or False")
        action = Action.READ_ONLY if read_only else Action.READ_WRITE
        return self._run(
            action, MECHANISM_BLKROSET, lambda rec: self._read_only(device, read_only, rec)
        )

    def eject(self, device: UsbDevice) -> EnforcementResult:
        """Write ``1`` to the device's ``remove`` attribute. Not journaled: there is no
        undo in software; the device returns when it is re-plugged."""
        _require_device(device)
        return self._run(Action.EJECT, MECHANISM_REMOVE, lambda _rec: self._eject(device))

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        """Write ``0`` (or ``1``) to every host controller's ``authorized_default`` and to
        the usbcore module parameter that controllers registering later inherit."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.DEFAULT_DENY_ON if enabled else Action.DEFAULT_DENY_OFF
        return self._run(
            action, MECHANISM_AUTHORIZED_DEFAULT, lambda rec: self._default_deny(enabled, rec)
        )

    def set_baseline_read_only(self, enabled: bool) -> EnforcementResult:
        """Install (or remove) the read-only baseline rules file and reload udev.

        This is ``baseline_read_only`` (DESIGN 14.14): from then on every USB disk and
        partition starts read-only, and :meth:`set_read_only` with ``False`` releases an
        approved device. Devices already present are not changed by the rule itself.
        A file of the same name that PortLock did not write is never touched.
        """
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.READ_ONLY if enabled else Action.READ_WRITE
        return self._run(action, MECHANISM_UDEV_RULE, lambda rec: self._baseline(enabled, rec))

    def baseline_active(self) -> bool:
        """True if PortLock's baseline rules file is in place, unmodified."""
        with self._lock:
            try:
                return self._rules.read(self._rules_path) == self._rule_text
            except OSError:
                return False

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        """Put back the ``previous`` value of each entry, newest first.

        Every entry is validated before anything is written: its kind must be a Linux
        kind, its target one of the named attributes inside sysfs (reached without a
        symbolic link), a block device node of a USB disk, or PortLock's own rules file,
        and its values ones that kind can hold. Invalid entries are reported and skipped.
        A value is reverted only if it still equals what was applied; a value someone
        else changed since is left alone and named in ``detail``. A per-device target
        that has disappeared with its device counts as restored.
        """
        frozen = tuple(entries)
        for entry in frozen:
            if not isinstance(entry, JournalEntry):
                raise TypeError(f"expected JournalEntry values, got {type(entry).__name__}")
        with self._lock:
            return self._restore(frozen)

    # --- implementation ---------------------------------------------------------------

    def _run(
        self,
        action: Action,
        mechanism: str,
        body: Callable[[ChangeRecorder], _Outcome],
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
                mechanism=outcome.mechanism or mechanism,
                tier=outcome.tier,
                changed=outcome.changed or bool(recorder.undo),
                detail=outcome.detail,
                undo=tuple(recorder.undo),
                error=outcome.error,
            )

    def _require_root(self, what: str) -> None:
        if not self._is_root():
            raise _Failure(f"{NotPrivilegedError.code}: root is needed to {what}")

    def _locate(self, instance_id: str) -> _UsbDir:
        """Validate that ``instance_id`` is a USB device directory inside sysfs."""
        path = instance_id
        if (
            not isinstance(path, str)
            or not _is_clean_absolute(path)
            or not path.startswith(self._devices_prefix)
        ):
            raise _Failure(
                f"refused: {path!r} is not a USB device directory under {self._root}/devices"
            )
        name = posixpath.basename(path)
        if is_root_hub_name(name):
            raise _Failure(
                f"refused: {path} is a root hub (a host controller); deauthorizing it would cut"
                " off every device on the bus"
            )
        if not is_device_name(name):
            raise _Failure(f"refused: {name!r} is not a USB device name")
        parts = path.split("/")
        hub_index = None
        for index in range(len(parts) - 2, -1, -1):
            if is_root_hub_name(parts[index]):
                hub_index = index
                break
        bus = name.split("-", 1)[0]
        if hub_index is None or parts[hub_index] != f"usb{bus}":
            raise _Failure(f"refused: {path} does not lie below the root hub of bus {bus}")
        for between in parts[hub_index + 1 : -1]:
            if not is_device_name(between) or between.split("-", 1)[0] != bus:
                raise _Failure(f"refused: {path} has an unexpected component {between!r}")
        if self._sysfs.realpath(path) != path:
            raise _Failure(f"refused: {path} leads out of place through a symbolic link")
        return _UsbDir(path, name, "/".join(parts[: hub_index + 1]))

    def _read(self, path: str, doing: str) -> str:
        try:
            return self._sysfs.read_text(path)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, path, doing)) from exc

    def _write(self, path: str, value: str, doing: str) -> None:
        try:
            self._sysfs.write_text(path, value)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, path, doing)) from exc

    def _default_deny_keeps_out(self, usb: _UsbDir) -> bool:
        try:
            value = self._sysfs.read_text(usb.root_hub + "/authorized_default")
        except OSError:
            return False
        return value in _DEFAULT_DENY_VALUES

    def _block_device(self, device: UsbDevice, recorder: ChangeRecorder) -> _Outcome:
        usb = self._locate(device.instance_id)
        attribute = usb.path + "/authorized"
        current = self._read(attribute, "read")
        if current == "0":
            if self._default_deny_keeps_out(usb):
                # E7: default-deny already keeps it out; no second mechanism is added.
                return _Outcome(
                    f"{usb.path} is not authorized: default-deny kept it out from the start",
                    Tier.PREVENTIVE,
                )
            return _Outcome(f"{usb.path} is already deauthorized", Tier.REACTIVE)
        if current != "1":
            raise _Failure(f"unexpected value {current!r} in {attribute}")
        self._require_root("deauthorize a device")
        recorder.apply(
            JournalEntry(JournalKind.SYSFS_AUTHORIZED, attribute, "1", "0"),
            lambda: self._write(attribute, "0", "deauthorize"),
        )
        return _Outcome(
            f"deauthorized {usb.path}: its drivers are unbound and it stays unconfigured;"
            " it was usable from enumeration until now (reactive)",
            Tier.REACTIVE,
        )

    def _unblock_device(self, device: UsbDevice, recorder: ChangeRecorder) -> _Outcome:
        usb = self._locate(device.instance_id)
        attribute = usb.path + "/authorized"
        current = self._read(attribute, "read")
        if current == "1":
            return _Outcome(f"{usb.path} is already authorized")
        if current != "0":
            raise _Failure(f"unexpected value {current!r} in {attribute}")
        self._require_root("authorize a device")
        if self._default_deny_keeps_out(usb):
            self._write(attribute, "1", "authorize")
            return _Outcome(
                f"admitted {usb.path}, which default-deny had kept out (not journaled:"
                " restoring would lock it out again)",
                changed=True,
            )
        recorder.apply(
            JournalEntry(JournalKind.SYSFS_AUTHORIZED, attribute, "0", "1"),
            lambda: self._write(attribute, "1", "authorize"),
        )
        return _Outcome(f"authorized {usb.path} again; its drivers probe")

    def _eject(self, device: UsbDevice) -> _Outcome:
        usb = self._locate(device.instance_id)
        if not self._sysfs.exists(usb.path):
            raise _Failure(f"device is gone: {usb.path} no longer exists")
        self._require_root("eject a device")
        self._write(usb.path + "/remove", "1", "eject")
        mounted = [volume.mount_point for volume in device.volumes if volume.mount_point]
        detail = (
            f"removed {usb.path}: its port stays disabled until the device is unplugged;"
            " there is no undo in software"
        )
        if mounted:
            detail += (
                f"; {len(mounted)} volume(s) were still mounted, and data not yet written"
                " back to them is lost"
            )
        return _Outcome(detail, Tier.REACTIVE, changed=True)

    # -- default-deny ------------------------------------------------------------------

    def _root_hub_dirs(self) -> list[str]:
        """Resolved directories of every root hub, validated to lie inside sysfs."""
        try:
            names = self._sysfs.listdir(self._bus_dir)
        except OSError:
            return []
        hubs: list[str] = []
        for name in names:
            if not is_root_hub_name(name):
                continue
            real = self._sysfs.realpath(posixpath.join(self._bus_dir, name))
            if (
                _is_clean_absolute(real)
                and real.startswith(self._devices_prefix)
                and posixpath.basename(real) == name
            ):
                hubs.append(real)
        return sorted(hubs)

    def _default_deny(self, enabled: bool, recorder: ChangeRecorder) -> _Outcome:
        wanted = "0" if enabled else "1"
        satisfied = {"0"} if enabled else {"1"}
        targets = [
            path
            for path in (hub + "/authorized_default" for hub in self._root_hub_dirs())
            if self._sysfs.exists(path)
        ]
        if not targets:
            raise _Failure(f"no USB host controller with authorized_default under {self._bus_dir}")
        errors: list[str] = []
        warnings: list[str] = []
        changed = 0
        pending = [(path, self._read(path, "read")) for path in targets]
        module_value: str | None = None
        if self._sysfs.exists(self._module_parameter):
            try:
                module_value = self._sysfs.read_text(self._module_parameter)
            except OSError as exc:
                warnings.append(_describe_os_error(exc, self._module_parameter, "read"))
        else:
            warnings.append(
                "the usbcore module parameter authorized_default does not exist here, so"
                " host controllers registered later are not covered"
            )
        module_satisfied = satisfied if enabled else {"1", "-1"}
        needs_module = module_value is not None and module_value not in module_satisfied
        if all(value in satisfied for _path, value in pending) and not needs_module:
            state = "on" if enabled else "off"
            detail = f"default-deny is already {state} on {len(targets)} host controller(s)"
            if warnings:
                detail += "; " + "; ".join(warnings)
            return _Outcome(detail, Tier.PREVENTIVE if enabled else Tier.NONE)
        self._require_root("change authorized_default")
        for path, value in pending:
            if value in satisfied:
                continue
            if value not in _AUTHORIZED_DEFAULT_VALUES:
                errors.append(f"unexpected value {value!r} in {path}; left alone")
                continue
            try:
                self._set_default(path, value, wanted, recorder)
                changed += 1
            except _Failure as failure:
                errors.append(str(failure))
        if needs_module and module_value is not None:
            if module_value in _AUTHORIZED_DEFAULT_VALUES:
                try:
                    self._set_default(self._module_parameter, module_value, wanted, recorder)
                except _Failure as failure:
                    # UNVERIFIED that every kernel lets root write it (linux.md 3.3):
                    # existing controllers are covered; later ones are reported.
                    warnings.append(f"{failure}; host controllers registered later are not covered")
            else:
                warnings.append(f"unexpected module parameter value {module_value!r}; left alone")
        if enabled:
            detail = (
                f"default-deny on for {len(targets)} host controller(s) ({changed} changed):"
                " devices that arrive from now on are not configured until PortLock"
                " authorizes them; devices already connected are not affected; only"
                " usbcore.authorized_default=0 on the kernel command line is preventive"
                " from boot"
            )
        else:
            detail = (
                f"default-deny off for {len(targets)} host controller(s) ({changed} changed):"
                " new devices are authorized by the kernel again"
            )
        if warnings:
            detail += "; " + "; ".join(warnings)
        if errors:
            return _Outcome(
                detail + "; failed: " + "; ".join(errors),
                Tier.PREVENTIVE if enabled and changed else Tier.NONE,
                ok=False,
                error="; ".join(errors),
            )
        return _Outcome(detail, Tier.PREVENTIVE if enabled else Tier.NONE)

    def _set_default(self, path: str, previous: str, wanted: str, recorder: ChangeRecorder) -> None:
        recorder.apply(
            JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, path, previous, wanted),
            lambda: self._write(path, wanted, "write authorized_default"),
        )
        # The write happened and is journaled; a kernel that keeps another value (for
        # example one that does not know the value) is reported as not enforced.
        back = self._read(path, "read back")
        if back != wanted:
            raise _Failure(f"{path}: wrote {wanted!r} but the kernel kept {back!r}")

    # -- read-only ---------------------------------------------------------------------

    def _block_nodes(self, usb: _UsbDir) -> list[str]:
        """Device nodes of every disk and partition below the device, found through
        ``<root>/class/block``, whose links resolve into the device's own directory."""
        try:
            names = self._sysfs.listdir(self._class_block)
        except OSError:
            return []
        prefix = usb.path + "/"
        nodes: list[str] = []
        for name in names:
            if not _BLOCK_NAME.fullmatch(name):
                continue
            real = self._sysfs.realpath(posixpath.join(self._class_block, name))
            # A link left dangling by a disk that is going away resolves all the same.
            if real.startswith(prefix) and self._sysfs.exists(real):
                # devtmpfs turns the "!" of names like cciss!c0d0 into a directory.
                nodes.append("/dev/" + name.replace("!", "/"))
        return sorted(nodes)

    def _get_ro(self, node: str) -> bool:
        try:
            return self._block.get_read_only(node)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, node, "read the read-only flag of")) from exc

    def _set_ro(self, node: str, read_only: bool) -> None:
        try:
            self._block.set_read_only(node, read_only)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, node, "set the read-only flag of")) from exc

    def _read_only(self, device: UsbDevice, read_only: bool, recorder: ChangeRecorder) -> _Outcome:
        if read_only and not device.is_storage:
            raise _Failure("not a storage device")
        usb = self._locate(device.instance_id)
        if not self._sysfs.exists(usb.path):
            raise _Failure(f"device is gone: {usb.path} no longer exists")
        nodes = self._block_nodes(usb)
        baseline = self.baseline_active()
        if not nodes:
            if not read_only:
                return _Outcome(f"{usb.path} has no block device; nothing to make writable")
            if baseline:
                return _Outcome(
                    f"{usb.path} has no block device yet; the read-only baseline rule makes"
                    " its disks and partitions read-only when they appear",
                    Tier.PREVENTIVE,
                    mechanism=MECHANISM_UDEV_BLKROSET,
                )
            raise _Failure(
                "not enforced: the device has no block device yet (it may still be blocked,"
                " or have no medium) and the read-only baseline is not installed; call again"
                " once it has one"
            )
        if not self._block.available:
            raise _Failure("the BLKROSET ioctl is not available on this platform")
        flipped: list[str] = []
        for node in nodes:
            if self._get_ro(node) == read_only:
                continue
            self._require_root("change the read-only flag of a block device")
            before, after = ("0", "1") if read_only else ("1", "0")
            recorder.apply(
                JournalEntry(JournalKind.BLOCK_READ_ONLY, node, before, after),
                lambda node=node: self._set_ro(node, read_only),
            )
            flipped.append(node)
        if not read_only:
            detail = f"{len(flipped)} of {len(nodes)} block device(s) of {usb.path} made writable"
            if baseline:
                detail += "; released from the read-only baseline (a re-plug starts read-only)"
            return _Outcome(detail)
        if not flipped and baseline:
            return _Outcome(
                f"all {len(nodes)} block device(s) of {usb.path} are read-only; the baseline"
                " rule made them read-only when they appeared",
                Tier.PREVENTIVE,
                mechanism=MECHANISM_UDEV_BLKROSET,
            )
        detail = (
            f"{len(flipped)} of {len(nodes)} block device(s) of {usb.path} made read-only"
            f" ({len(nodes) - len(flipped)} already were); {_BEST_EFFORT}"
        )
        writable_mounts = [
            volume.mount_point
            for volume in device.volumes
            if volume.mount_point and volume.read_only is not True
        ]
        if writable_mounts:
            detail += f"; {len(writable_mounts)} mounted volume(s) remain writable until remounted"
        return _Outcome(
            detail,
            Tier.REACTIVE,
            mechanism=MECHANISM_UDEV_BLKROSET if baseline else MECHANISM_BLKROSET,
        )

    def _reload_udev(self) -> str | None:
        """Ask udev to re-read its rules. Returns an error message, or ``None``."""
        result = self._runner.run([self._udevadm, "control", "--reload"], timeout=_COMMAND_TIMEOUT)
        if result.ok:
            return None
        return (
            f"udevadm control --reload failed ({result.describe()}): udev has not read the change"
        )

    def _rules_read(self) -> str | None:
        try:
            return self._rules.read(self._rules_path)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, self._rules_path, "read")) from exc

    def _rules_write(self, text: str | None) -> None:
        try:
            if text is None:
                self._rules.remove(self._rules_path)
            else:
                self._rules.write(self._rules_path, text)
        except OSError as exc:
            raise _Failure(_describe_os_error(exc, self._rules_path, "write")) from exc

    def _baseline(self, enabled: bool, recorder: ChangeRecorder) -> _Outcome:
        current = self._rules_read()
        if enabled and current == self._rule_text:
            return _Outcome("the read-only baseline rule is already installed", Tier.PREVENTIVE)
        if not enabled and current is None:
            return _Outcome("the read-only baseline rule is not installed")
        if current is not None and current != self._rule_text:
            raise _Failure(
                f"refused: {self._rules_path} exists and is not PortLock's rule; it is left alone"
            )
        self._require_root("change udev rules")
        previous, applied = (None, self._rule_text) if enabled else (self._rule_text, None)
        recorder.apply(
            JournalEntry(JournalKind.UDEV_RULE, self._rules_path, previous, applied),
            lambda: self._rules_write(applied),
        )
        failure = self._reload_udev()
        if enabled:
            detail = (
                f"installed {self._rules_path}: USB disks and partitions that appear from now"
                " on are read-only before automounters see them; approved devices are"
                " released one by one. Devices already present are not changed by the rule"
            )
        else:
            detail = f"removed {self._rules_path}: USB disks no longer start read-only"
        if failure is not None:
            return _Outcome(f"{detail}; {failure}", ok=False, error=failure)
        return _Outcome(detail, Tier.PREVENTIVE if enabled else Tier.NONE)

    # -- restore -----------------------------------------------------------------------

    def _plan(self, entry: JournalEntry) -> _Plan:
        kind = entry.kind
        target = entry.target
        if kind == JournalKind.SYSFS_AUTHORIZED:
            if posixpath.basename(target) != "authorized":
                raise _Failure(f"refused journal entry: {target!r} is not an authorized attribute")
            usb = self._locate(posixpath.dirname(target))
            attribute = usb.path + "/authorized"
            _check_values(entry, _AUTHORIZED_VALUES, allow_none=False)
            return _Plan(
                entry,
                entry.previous,
                entry.applied,
                True,
                lambda: self._sysfs.read_text(attribute),
                lambda value: self._sysfs.write_text(attribute, str(value)),
            )
        if kind == JournalKind.SYSFS_AUTHORIZED_DEFAULT:
            attribute = self._validate_default_target(target)
            _check_values(entry, _AUTHORIZED_DEFAULT_VALUES, allow_none=False)
            return _Plan(
                entry,
                entry.previous,
                entry.applied,
                False,
                lambda: self._sysfs.read_text(attribute),
                lambda value: self._sysfs.write_text(attribute, str(value)),
            )
        if kind == JournalKind.BLOCK_READ_ONLY:
            node = self._validate_node(target)
            _check_values(entry, _RO_VALUES, allow_none=False)
            return _Plan(
                entry,
                entry.previous,
                entry.applied,
                True,
                lambda: "1" if self._block.get_read_only(node) else "0",
                lambda value: self._block.set_read_only(node, value == "1"),
            )
        if kind == JournalKind.UDEV_RULE:
            if target != self._rules_path:
                raise _Failure(
                    f"refused journal entry: {target!r} is not PortLock's rules file"
                    f" ({self._rules_path})"
                )
            allowed = {None, self._rule_text}
            if (
                entry.previous not in allowed
                or entry.applied not in allowed
                or entry.previous == entry.applied
            ):
                raise _Failure(
                    f"refused journal entry for {target}: only PortLock's own rule text may"
                    " be written there"
                )
            return _Plan(
                entry,
                entry.previous,
                entry.applied,
                False,
                lambda: self._rules.read(self._rules_path),
                self._write_rule_for_restore,
            )
        raise _Failure(f"cannot restore a {kind!r} journal entry on Linux ({target})")

    def _write_rule_for_restore(self, value: str | None) -> None:
        if value is None:
            self._rules.remove(self._rules_path)
        else:
            self._rules.write(self._rules_path, value)

    def _validate_default_target(self, target: str) -> str:
        if target == self._module_parameter:
            if self._sysfs.realpath(target) != target:
                raise _Failure(f"refused journal entry: {target} is reached through a link")
            return target
        directory, name = posixpath.split(target)
        if (
            name != "authorized_default"
            or not _is_clean_absolute(target)
            or not directory.startswith(self._devices_prefix)
            or not is_root_hub_name(posixpath.basename(directory))
        ):
            raise _Failure(
                f"refused journal entry: {target!r} is not a host controller's authorized_default"
            )
        if self._sysfs.realpath(directory) != directory:
            raise _Failure(f"refused journal entry: {target} leaves sysfs through a link")
        return target

    def _validate_node(self, target: str) -> str:
        name = target[len("/dev/") :] if target.startswith("/dev/") else ""
        sysfs_name = name.replace("/", "!")
        if not _BLOCK_NAME.fullmatch(sysfs_name) or name.count("/") > 1:
            raise _Failure(f"refused journal entry: {target!r} is not a block device node")
        return target

    def _node_is_usb_disk(self, node: str) -> bool | None:
        """True if ``node`` is a disk or partition of a USB device; ``None`` if it has gone."""
        link = posixpath.join(self._class_block, node[len("/dev/") :].replace("/", "!"))
        if not self._sysfs.exists(link):
            return None
        real = self._sysfs.realpath(link)
        if not real.startswith(self._devices_prefix):
            return False
        return any(is_root_hub_name(part) for part in real.split("/"))

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
        rules_changed = False
        for plan in reversed(plans):
            target = plan.entry.target
            if plan.entry.kind == JournalKind.BLOCK_READ_ONLY:
                usb_disk = self._node_is_usb_disk(target)
                if usb_disk is None:
                    gone += 1
                    continue
                if not usb_disk:
                    errors.append(f"refused journal entry: {target} is not a USB disk")
                    continue
            try:
                current = plan.read()
            except OSError as exc:
                if exc.errno in _GONE and plan.volatile:
                    gone += 1
                    continue
                errors.append(_describe_os_error(exc, target, "read"))
                continue
            if current == plan.previous:
                already += 1
                continue
            if current != plan.applied:
                left_alone.append(f"{target} (now {_short(current)})")
                continue
            if not self._is_root():
                errors.append(f"{NotPrivilegedError.code}: root is needed to restore {target}")
                continue
            try:
                plan.write(plan.previous)
            except OSError as exc:
                if exc.errno in _GONE and plan.volatile:
                    gone += 1
                    continue
                errors.append(_describe_os_error(exc, target, "restore"))
                continue
            restored += 1
            rules_changed = rules_changed or plan.entry.kind == JournalKind.UDEV_RULE
        if rules_changed:
            failure = self._reload_udev()
            if failure is not None:
                errors.append(failure)
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
# System volume
# --------------------------------------------------------------------------------------


def system_device_ids(
    devices: Sequence[UsbDevice],
    *,
    sysfs: SysfsIO,
    mountinfo: str | bytes,
    sysfs_root: str = "/sys",
) -> frozenset[str]:
    """The instance ids of the devices in ``devices`` that back the system volume.

    The mounts of :data:`SYSTEM_MOUNT_POINTS` are taken from ``mountinfo``; each one's
    ``major:minor`` is resolved through ``<root>/dev/block`` (or, for a filesystem that
    reports an anonymous device number, its source node through ``<root>/class/block``),
    and ``slaves/`` is followed down device-mapper and RAID stacks to the physical disks.
    A device backs the system volume if such a disk lies below its sysfs directory.

    Raises:
        BackendError: if the mount table has no root filesystem, or the root filesystem
            names a block device that cannot be found in sysfs.
    """
    if not _is_clean_absolute(sysfs_root):
        raise ValueError("sysfs_root must be a normalized absolute path")
    try:
        entries = parse_mountinfo(mountinfo)
    except BackendError:
        raise
    except Exception as exc:
        raise BackendError(f"the mount table cannot be parsed: {exc}") from exc
    mounts = {}
    for entry in entries:
        if entry.mount_point in SYSTEM_MOUNT_POINTS:
            # A later mount at the same point hides the earlier one.
            mounts[entry.mount_point] = entry
    if "/" not in mounts:
        raise BackendError("the mount table has no root filesystem")
    physical: set[str] = set()
    for point, entry in mounts.items():
        block = _resolve_block(sysfs, sysfs_root, entry.device, entry.source)
        if block is None:
            if point == "/" and entry.source.startswith("/dev/"):
                raise BackendError(
                    f"the root filesystem's device ({entry.source}) cannot be found in sysfs"
                )
            continue
        physical.update(_physical_disks(sysfs, sysfs_root, block, 0))
    found = set()
    for device in devices:
        prefix = device.instance_id.rstrip("/") + "/"
        if any(path.startswith(prefix) for path in physical):
            found.add(device.instance_id)
    return frozenset(found)


def _resolve_block(sysfs: SysfsIO, root: str, number: str, source: str) -> str | None:
    if re.fullmatch(r"[1-9][0-9]{0,9}:[0-9]{1,10}", number):
        candidate = f"{root}/dev/block/{number}"
        if sysfs.exists(candidate):
            return sysfs.realpath(candidate)
    if source.startswith("/dev/"):
        name = posixpath.basename(sysfs.realpath(source)) if sysfs.exists(source) else ""
        for candidate_name in (name, posixpath.basename(source)):
            if candidate_name and _BLOCK_NAME.fullmatch(candidate_name):
                link = f"{root}/class/block/{candidate_name}"
                if sysfs.exists(link):
                    return sysfs.realpath(link)
    return None


def _physical_disks(sysfs: SysfsIO, root: str, path: str, depth: int) -> set[str]:
    if depth > _MAX_SLAVE_DEPTH:
        return {path}
    try:
        slaves = sysfs.listdir(path + "/slaves")
    except OSError:
        slaves = []
    names = [name for name in slaves if _BLOCK_NAME.fullmatch(name)]
    if not names:
        return {path}
    found: set[str] = set()
    for name in names:
        found.update(
            _physical_disks(sysfs, root, sysfs.realpath(f"{root}/class/block/{name}"), depth + 1)
        )
    return found


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _is_clean_absolute(path: object) -> bool:
    return (
        isinstance(path, str)
        and path.startswith("/")
        and "\x00" not in path
        and "\\" not in path
        and posixpath.normpath(path) == path
    )


def _require_device(device: object) -> None:
    if not isinstance(device, UsbDevice):
        raise TypeError(f"expected a UsbDevice, got {type(device).__name__}")


def _check_values(entry: JournalEntry, allowed: Iterable[str], *, allow_none: bool) -> None:
    permitted = set(allowed)
    for label, value in (("previous", entry.previous), ("applied", entry.applied)):
        if value is None and allow_none:
            continue
        if value not in permitted:
            raise _Failure(
                f"refused journal entry for {entry.target}: unusable {label} value {_short(value)}"
            )
    if entry.previous == entry.applied:
        raise _Failure(f"refused journal entry for {entry.target}: previous equals applied")


def _short(value: object) -> str:
    text = repr(value)
    return text if len(text) <= 40 else text[:37] + "..."


def _describe_os_error(exc: OSError, path: str, doing: str) -> str:
    code = exc.errno
    name = errno.errorcode.get(code, str(code)) if code is not None else "error"
    if code in _DENIED:
        return f"{NotPrivilegedError.code}: cannot {doing} {path}: permission denied ({name})"
    if code in _GONE:
        return f"device is gone: {path} ({name})"
    if code == errno.EROFS:
        return (
            f"cannot {doing} {path}: sysfs is read-only here ({name}; a container, or"
            " ProtectKernelTunables=yes): not enforced"
        )
    reason = exc.strerror or str(exc)
    return f"cannot {doing} {path}: {reason} ({name})"
