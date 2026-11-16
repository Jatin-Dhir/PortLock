"""Platform selection and the capability report behind ``portlock doctor``.

This is the only module that names the concrete platform classes. Each platform package
is imported only when that platform is selected, so importing this module on Linux does
not import the Windows package and the other way round.

* :func:`create_backend` / :func:`create_enforcer` build the raw platform objects.
* :func:`create_guard` builds both and wraps the enforcer in the two
  :class:`~portlock.guard.safety.SafeEnforcer` instances the service uses (ARCHITECTURE
  2.3): ``live`` (enforces; restores, unblocks and default-deny are never refused) and
  ``dry`` (monitor mode: records what would be done, changes nothing).
* :func:`create_external_timer` and :func:`create_dir_privacy` build the dead-man timer
  (DESIGN 14.16) and the directory-privacy seam (14.18) for the platform;
  :func:`dead_man_command` is the command the timer runs.
  :class:`SystemSeams` replaces individual seams those real objects are built on (tests).
  A watch-only process (``guard.watchonly``, DESIGN 14.28) never calls these: the
  composition root gives it inert stand-ins instead.
* :func:`doctor` reports, without changing anything, whether this process is privileged,
  which mechanisms are available (with the reason when not), whether
  ``usbcore.authorized_default=0`` is on the Linux kernel command line, and whether the
  state and configuration directories are private. For a watch-only process it builds
  no enforcer and no directory-privacy check, and runs no command.
"""

from __future__ import annotations

import dataclasses
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from portlock import __version__
from portlock.core.clock import Clock, utc_iso
from portlock.core.config import Config
from portlock.core.errors import BackendError
from portlock.core.models import UsbDevice
from portlock.guard.base import (
    BackendCapabilities,
    DeviceBackend,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
)
from portlock.guard.safety import RefusalCallback, SafeEnforcer, SafetyContext
from portlock.guard.seams import (
    BlockIO,
    CfgMgrAPI,
    CommandRunner,
    DirPrivacy,
    DiskIO,
    ExternalTimer,
    IcaclsDirPrivacy,
    MechanismStatus,
    PosixDirPrivacy,
    RegistryIO,
    RuleFileIO,
    ScheduledTaskTimer,
    SubprocessRunner,
    SysfsIO,
    SystemdRunTimer,
)
from portlock.guard.watchonly import NO_ANTIVIRUS_NOTE, Posture, WatchOnlyEnforcer

__all__ = [
    "DEAD_MAN_TIMER",
    "STATUS_FAIL",
    "STATUS_INFO",
    "STATUS_OK",
    "STATUS_WARN",
    "DoctorCheck",
    "DoctorReport",
    "Guard",
    "SystemSeams",
    "create_backend",
    "create_dir_privacy",
    "create_enforcer",
    "create_external_timer",
    "create_guard",
    "dead_man_command",
    "doctor",
    "platform_family",
    "system_instance_ids",
]

#: Name of the one-shot operating-system timer that runs ``portlock recover`` (14.16).
DEAD_MAN_TIMER = "deadman"

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"
_STATUSES = (STATUS_OK, STATUS_WARN, STATUS_FAIL, STATUS_INFO)

_WINDOWS = "windows"
_LINUX = "linux"
_PROC_CMDLINE = "/proc/cmdline"
_PRIVILEGE_WORD = {_WINDOWS: "administrator", _LINUX: "root"}
_ROLES = (
    ("guard.block", "block"),
    ("guard.read_only", "read_only"),
    ("guard.eject", "eject"),
    ("guard.default_deny", "default_deny"),
    ("guard.baseline_read_only", "baseline_read_only"),
)


def platform_family(platform: str | None = None) -> str:
    """``"windows"`` or ``"linux"`` for a ``sys.platform`` value.

    Raises:
        BackendError: (code ``unsupported_platform``) for anything else.
    """
    name = sys.platform if platform is None else platform
    if name == "win32":
        return _WINDOWS
    if isinstance(name, str) and name.startswith("linux"):
        return _LINUX
    raise BackendError(f"unsupported platform {name!r}", code="unsupported_platform")


def create_backend(config: Config, *, clock: Clock, platform: str | None = None) -> DeviceBackend:
    """The device backend for the platform. Never a fake: tests pass fakes themselves.

    Raises:
        BackendError: for an unsupported platform, or if the platform API cannot load.
    """
    family = platform_family(platform)
    if family == _WINDOWS:
        from portlock.guard.windows.backend import WindowsBackend

        return WindowsBackend(clock=clock, poll_interval=config.polling_interval_seconds)
    from portlock.guard.linux.backend import LinuxBackend

    return LinuxBackend(clock=clock, poll_interval=config.polling_interval_seconds)


@dataclass(frozen=True, slots=True)
class SystemSeams:
    """Replacements for the operating-system seams the real platform objects are built on.

    ``None`` fields mean the real seam. Tests pass seams that record or raise, so that the
    real composition (``service.daemon``) can be exercised while proving which seams it
    reaches: an enforcing process reaches them, a watch-only one none of them.

    Attributes:
        runner: runs ``icacls``, ``schtasks``, ``systemd-run``, ``udevadm``.
        registry / cfgmgr / disks: the Windows registry, device and disk calls.
        sysfs / block / rules: the Linux sysfs, block-device and udev-rule access.
        is_admin: whether the process may use the mechanisms.
    """

    runner: CommandRunner | None = None
    registry: RegistryIO | None = None
    cfgmgr: CfgMgrAPI | None = None
    disks: DiskIO | None = None
    sysfs: SysfsIO | None = None
    block: BlockIO | None = None
    rules: RuleFileIO | None = None
    is_admin: Callable[[], bool] | None = None


def create_enforcer(
    config: Config,
    *,
    platform: str | None = None,
    write_ahead: Callable[[JournalEntry], None] | None = None,
    seams: SystemSeams | None = None,
) -> Enforcer:
    """The **raw** enforcer for the platform, wired to the real operating system.

    Callers wrap it in :class:`~portlock.guard.safety.SafeEnforcer` before any call;
    :func:`create_guard` does that. ``seams`` replaces individual operating-system seams.

    Raises:
        BackendError: for an unsupported platform.
    """
    del config  # The enforcers take no configuration today; the parameter keeps the API.
    family = platform_family(platform)
    if family == _WINDOWS:
        from portlock.guard.windows.enforce import WindowsEnforcer

        if seams is None:
            return WindowsEnforcer.system(write_ahead=write_ahead)
        from portlock.guard.seams import (
            WinCfgMgr,
            WinDisks,
            WinRegistry,
            current_process_privileged,
        )

        return WindowsEnforcer(
            cfgmgr=seams.cfgmgr if seams.cfgmgr is not None else WinCfgMgr(),
            registry=seams.registry if seams.registry is not None else WinRegistry(),
            disks=seams.disks if seams.disks is not None else WinDisks(),
            is_admin=seams.is_admin if seams.is_admin is not None else current_process_privileged,
            write_ahead=write_ahead,
        )
    from portlock.guard.linux.enforce import LinuxEnforcer

    if seams is None:
        return LinuxEnforcer.system(write_ahead=write_ahead)
    from portlock.guard.seams import (
        RealBlockIO,
        RealRuleFiles,
        RealSysfs,
        current_process_privileged,
    )

    return LinuxEnforcer(
        sysfs=seams.sysfs if seams.sysfs is not None else RealSysfs(),
        block=seams.block if seams.block is not None else RealBlockIO(),
        rules=seams.rules if seams.rules is not None else RealRuleFiles(),
        runner=(
            seams.runner
            if seams.runner is not None
            else SubprocessRunner(env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        ),
        is_root=seams.is_admin if seams.is_admin is not None else current_process_privileged,
        write_ahead=write_ahead,
    )


@dataclass(frozen=True, slots=True)
class Guard:
    """The detection and enforcement objects of one PortLock process.

    Attributes:
        backend: observes devices.
        enforcer: the raw enforcer; never called directly except through the wrappers.
        live: ``SafeEnforcer(enforcer, dry_run=False)``: everything that enforces,
            releases, admits or restores goes through it.
        dry: ``SafeEnforcer(enforcer, dry_run=True)``: records what enforce mode would
            have done; reaches nothing.
    """

    backend: DeviceBackend
    enforcer: Enforcer
    live: SafeEnforcer
    dry: SafeEnforcer


def create_guard(
    config: Config,
    *,
    clock: Clock,
    context_provider: Callable[[], SafetyContext],
    on_refusal: RefusalCallback | None = None,
    platform: str | None = None,
    write_ahead: Callable[[JournalEntry], None] | None = None,
    backend: DeviceBackend | None = None,
    enforcer: Enforcer | None = None,
) -> Guard:
    """Choose the backend and enforcer for the platform and wrap the enforcer.

    ``backend`` and ``enforcer`` replace the platform objects (``portlock simulate``
    passes the fakes). Both wrappers share ``context_provider`` and ``on_refusal``.
    """
    chosen_backend = (
        backend if backend is not None else create_backend(config, clock=clock, platform=platform)
    )
    chosen_enforcer = (
        enforcer
        if enforcer is not None
        else create_enforcer(config, platform=platform, write_ahead=write_ahead)
    )
    return Guard(
        backend=chosen_backend,
        enforcer=chosen_enforcer,
        live=SafeEnforcer(chosen_enforcer, context_provider, dry_run=False, on_refusal=on_refusal),
        dry=SafeEnforcer(chosen_enforcer, context_provider, dry_run=True, on_refusal=on_refusal),
    )


def system_instance_ids(
    devices: Sequence[UsbDevice],
    *,
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
) -> frozenset[str]:
    """The instance ids of the devices backing the system volume, for ``SafetyContext``.

    Reads the real mount table and sysfs (Linux) or volume and device tree (Windows).

    Raises:
        BackendError: for an unsupported platform, or if the system volume cannot be
            traced.
    """
    family = platform_family(platform)
    if family == _WINDOWS:
        from portlock.guard.windows.enforce import system_device_ids as windows_ids

        return windows_ids(devices, env=env)
    from portlock.guard.linux.enforce import system_device_ids as linux_ids
    from portlock.guard.seams import RealSysfs

    try:
        with open("/proc/self/mountinfo", "rb") as stream:
            table = stream.read(16 * 1024 * 1024)
    except OSError as exc:
        raise BackendError(f"cannot read the mount table: {exc.strerror or exc}") from exc
    return linux_ids(devices, sysfs=RealSysfs(), mountinfo=table)


def create_external_timer(
    config: Config, *, platform: str | None = None, runner: CommandRunner | None = None
) -> ExternalTimer:
    """The dead-man timer for the platform: ``systemd-run`` or ``schtasks``.

    The Windows timer writes its task definition into the state directory for the
    duration of the call, so that directory must exist (and be private).

    Raises:
        BackendError: for an unsupported platform.
    """
    family = platform_family(platform)
    command_runner = runner if runner is not None else SubprocessRunner()
    if family == _WINDOWS:
        return ScheduledTaskTimer(command_runner, Path(config.paths.state_dir))
    return SystemdRunTimer(command_runner)


def create_dir_privacy(
    *, platform: str | None = None, runner: CommandRunner | None = None
) -> DirPrivacy:
    """The directory-privacy seam for the platform: POSIX modes, or ``icacls``.

    Raises:
        BackendError: for an unsupported platform.
    """
    if platform_family(platform) == _WINDOWS:
        return IcaclsDirPrivacy(runner if runner is not None else SubprocessRunner())
    return PosixDirPrivacy()


def dead_man_command(config: Config, *, python: str | None = None) -> tuple[str, ...]:
    """The command the dead-man timer runs: ``portlock recover --dead-man``.

    The interpreter is run isolated (``-I``) so that nothing in the working directory
    or the environment can change what a privileged recovery imports. ``--dead-man``
    tells ``recover`` that a timer, not an operator, started it: it then leaves a running
    service alone (the service ends its own lockdown) and never writes the kill-switch
    file, which would otherwise turn enforcement off for good.
    """
    interpreter = python if python is not None else sys.executable
    if not interpreter:
        raise BackendError("the Python interpreter's path is unknown")
    return (
        interpreter,
        "-I",
        "-m",
        "portlock",
        "recover",
        "--config",
        str(config.paths.config_file),
        "--dead-man",
    )


# --------------------------------------------------------------------------------------
# portlock doctor
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One line of ``portlock doctor``.

    Attributes:
        id: stable identifier, e.g. ``guard.block``.
        status: ``ok``, ``warn``, ``fail`` or ``info``.
        summary: one sentence.
        detail: more, when there is more to say.
    """

    id: str
    status: str
    summary: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in _STATUSES:
            raise ValueError(f"unknown doctor status {self.status!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """The guard half of ``portlock doctor``.

    Never contains a serial number, a product name or an instance id: device information
    appears only as counts.
    """

    generated_at: datetime
    platform: str
    version: str
    backend: BackendCapabilities | None
    enforcer: EnforcerCapabilities | None
    checks: tuple[DoctorCheck, ...]
    mechanisms: tuple[MechanismStatus, ...] = ()

    @property
    def worst(self) -> str:
        """``fail`` if any check failed, else ``warn`` if any warned, else ``ok``."""
        statuses = {check.status for check in self.checks}
        for status in (STATUS_FAIL, STATUS_WARN):
            if status in statuses:
                return status
        return STATUS_OK

    def check(self, check_id: str) -> DoctorCheck | None:
        """The check with this id, if the report has it."""
        return next((check for check in self.checks if check.id == check_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": utc_iso(self.generated_at),
            "platform": self.platform,
            "version": self.version,
            "worst": self.worst,
            "backend": _capabilities_dict(self.backend),
            "enforcer": _capabilities_dict(self.enforcer),
            "mechanisms": [status.to_dict() for status in self.mechanisms],
            "checks": [check.to_dict() for check in self.checks],
        }


def _capabilities_dict(
    capabilities: BackendCapabilities | EnforcerCapabilities | None,
) -> dict[str, Any] | None:
    if capabilities is None:
        return None
    data = dataclasses.asdict(capabilities)
    data["notes"] = list(capabilities.notes)
    return data


class _Scrubber:
    """Removes device-identifying strings (serials, names, instance ids) from text."""

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def learn(self, devices: Sequence[UsbDevice]) -> None:
        for device in devices:
            for value in (
                device.instance_id,
                device.serial,
                device.product,
                device.manufacturer,
                device.connection_id,
                *(volume.label for volume in device.volumes),
                *(volume.fs_uuid for volume in device.volumes),
            ):
                if value and len(value) >= 3:
                    self._secrets.append(value)
        # Longest first, so an instance id is replaced before the serial inside it.
        self._secrets.sort(key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, "<device>")
        return text

    def notes(self, capabilities: Any) -> Any:
        if capabilities is None:
            return None
        return dataclasses.replace(
            capabilities, notes=tuple(self(note) for note in capabilities.notes)
        )


def doctor(
    config: Config,
    *,
    clock: Clock,
    backend: DeviceBackend | None = None,
    enforcer: Enforcer | None = None,
    platform: str | None = None,
    dir_privacy: DirPrivacy | None = None,
    kernel_cmdline: Callable[[], str] | None = None,
    system_ids: Callable[[Sequence[UsbDevice]], frozenset[str]] | None = None,
    posture: Posture | None = None,
) -> DoctorReport:
    """Report what PortLock can do on this machine. Never raises; changes nothing.

    Missing ``backend`` / ``enforcer`` / ``dir_privacy`` are created for the platform and
    only queried (``capabilities()``, ``enumerate()``, ``mechanisms()``, ``check()``).
    ``kernel_cmdline`` defaults to reading ``/proc/cmdline`` on Linux. ``system_ids``
    defaults to :func:`system_instance_ids` only when the backend was created here: with
    an injected backend the system-volume check needs an injected probe.

    ``posture`` (``guard.watchonly``) adds two plain lines, ``guard.watch_only`` and
    ``guard.directories``. For a watch-only posture no enforcer and no directory-privacy
    seam is created: the enforcement mechanisms and the directory permissions are
    reported as not probed, and no command (``icacls``) is run. Any other posture is
    probed in full, as without one.

    Checks, in order: ``guard.watch_only`` and ``guard.directories`` (with a posture),
    ``guard.platform``, ``guard.privilege``, ``guard.backend``,
    ``guard.detect``, ``guard.enumerate``, ``guard.block``, ``guard.read_only``,
    ``guard.eject``, ``guard.default_deny``, ``guard.baseline_read_only``,
    ``guard.conflicts``, ``guard.system_volume``, ``guard.boot_default_deny`` (Linux
    only), ``guard.state_dir``, ``guard.config_dir``. A missing mechanism is ``warn``
    when the process is unprivileged and ``fail`` when it is privileged.
    """
    checks: list[DoctorCheck] = []
    scrub = _Scrubber()
    inert = posture is not None and posture.watch_only
    if posture is not None:
        checks.extend(_posture_checks(config, posture))
    name = sys.platform if platform is None else platform
    family: str | None
    try:
        family = platform_family(name)
        checks.append(DoctorCheck("guard.platform", STATUS_OK, f"platform {name} ({family})"))
    except BackendError as exc:
        family = None
        checks.append(DoctorCheck("guard.platform", STATUS_FAIL, str(exc)))

    created_backend = backend is None
    backend_caps: BackendCapabilities | None = None
    if backend is None and family is not None:
        try:
            backend = create_backend(config, clock=clock, platform=name)
        except Exception as exc:
            checks.append(_failure("guard.backend", "the device backend cannot be created", exc))
    if enforcer is None and posture is not None and inert:
        # Watch-only: the platform enforcer is never built, not even to be asked.
        enforcer = WatchOnlyEnforcer(elevated=posture.elevated)
    if enforcer is None and family is not None:
        try:
            enforcer = create_enforcer(config, platform=name)
        except Exception as exc:
            checks.append(_failure("guard.enforcer", "the enforcer cannot be created", exc))

    enforcer_caps: EnforcerCapabilities | None = None
    if enforcer is not None:
        try:
            enforcer_caps = enforcer.capabilities()
        except Exception as exc:
            checks.append(
                _failure("guard.enforcer", "the enforcer cannot report its capabilities", exc)
            )
    mechanisms: tuple[MechanismStatus, ...] = ()
    report_mechanisms = getattr(enforcer, "mechanisms", None)
    if callable(report_mechanisms):
        try:
            mechanisms = tuple(report_mechanisms())
        except Exception as exc:
            checks.append(_failure("guard.mechanisms", "the mechanisms cannot be listed", exc))

    privileged = enforcer_caps is not None and enforcer_caps.privileged
    word = _PRIVILEGE_WORD.get(family or "", "administrator or root")
    if enforcer_caps is None:
        checks.append(
            DoctorCheck("guard.privilege", STATUS_FAIL, "privilege unknown: no enforcer report")
        )
    elif privileged:
        checks.append(DoctorCheck("guard.privilege", STATUS_OK, f"running as {word}"))
    else:
        checks.append(
            DoctorCheck(
                "guard.privilege",
                STATUS_WARN,
                f"not running as {word}: PortLock can monitor but enforce nothing",
            )
        )

    devices: list[UsbDevice] = []
    if backend is not None:
        try:
            backend_caps = backend.capabilities()
            status = STATUS_OK if backend_caps.can_enumerate else STATUS_FAIL
            checks.append(
                DoctorCheck(
                    "guard.backend",
                    status,
                    f"backend {backend_caps.name}: "
                    + ("can list devices" if backend_caps.can_enumerate else "cannot list devices"),
                    "; ".join(backend_caps.notes),
                )
            )
            checks.append(
                DoctorCheck(
                    "guard.detect",
                    STATUS_OK if backend_caps.event_driven else STATUS_WARN,
                    "arrivals are pushed by the operating system"
                    if backend_caps.event_driven
                    else "arrivals are found by polling",
                )
            )
        except Exception as exc:
            checks.append(
                _failure("guard.backend", "the backend cannot report its capabilities", exc)
            )
        try:
            devices = list(backend.enumerate())
            scrub.learn(devices)
            checks.append(
                DoctorCheck("guard.enumerate", STATUS_OK, f"{len(devices)} USB device(s) connected")
            )
        except Exception as exc:
            checks.append(_failure("guard.enumerate", "devices cannot be listed", exc))

    by_role = {status.role: status for status in mechanisms}
    for check_id, role in _ROLES:
        if inert:
            checks.append(
                DoctorCheck(
                    check_id,
                    STATUS_INFO,
                    f"{role}: not probed (watch-only never touches enforcement mechanisms)",
                )
            )
            continue
        checks.append(
            _mechanism_check(check_id, role, by_role.get(role), enforcer_caps, privileged)
        )

    notes = enforcer_caps.notes if enforcer_caps is not None else ()
    conflicts = [note for note in notes if note.startswith("conflict")]
    checks.append(
        DoctorCheck(
            "guard.conflicts",
            STATUS_WARN if conflicts else STATUS_OK,
            f"{len(conflicts)} conflicting program(s) or polic(ies)"
            if conflicts
            else "no conflicting program or policy found",
            "; ".join(conflicts),
        )
    )

    checks.append(_system_volume_check(devices, system_ids, created_backend, name, backend))
    if family == _LINUX:
        checks.append(_boot_check(kernel_cmdline))
    privacy = dir_privacy
    if privacy is None and family is not None and not inert:
        try:
            privacy = create_dir_privacy(platform=name)
        except Exception as exc:
            checks.append(_failure("guard.state_dir", "directory privacy cannot be checked", exc))
    for check_id, label, path in (
        ("guard.state_dir", "state directory", config.paths.state_dir),
        ("guard.config_dir", "configuration directory", config.paths.config_dir),
    ):
        if inert:
            checks.append(
                DoctorCheck(
                    check_id,
                    STATUS_INFO,
                    f"the {label} was not checked for privacy: watch-only neither checks nor"
                    " changes directory permissions",
                )
            )
            continue
        checks.append(_privacy_check(check_id, label, Path(path), privacy))

    scrubbed = tuple(
        DoctorCheck(check.id, check.status, scrub(check.summary), scrub(check.detail))
        for check in checks
    )
    return DoctorReport(
        generated_at=clock.now(),
        platform=str(name),
        version=__version__,
        backend=scrub.notes(backend_caps),
        enforcer=scrub.notes(enforcer_caps),
        checks=scrubbed,
        mechanisms=tuple(
            dataclasses.replace(status, reason=scrub(status.reason)) for status in mechanisms
        ),
    )


def _posture_checks(config: Config, posture: Posture) -> list[DoctorCheck]:
    """The two plain lines a person reads first: watch-only or not, and where."""
    reason = posture.refusal()
    if reason is not None:
        mode = DoctorCheck(
            "guard.watch_only",
            STATUS_INFO,
            "watch-only: PortLock shows and records your USB devices and changes nothing on"
            " this computer outside its own folder; nothing is blocked, ejected or made"
            " read-only, and no command is run",
            f"{reason} {NO_ANTIVIRUS_NOTE[0].upper()}{NO_ANTIVIRUS_NOTE[1:]}.",
        )
    else:
        mode = DoctorCheck(
            "guard.watch_only",
            STATUS_INFO,
            "not watch-only: this process runs as administrator with system-wide directories,"
            " so it uses the enforcement mechanisms below (in monitor mode it blocks only an"
            " engaged lockdown)",
        )
    where = (
        "system-wide directories"
        if posture.system_wide
        else "directories that are not system-wide (this user's own, or not provably local)"
    )
    directories = DoctorCheck(
        "guard.directories",
        STATUS_INFO,
        f"{where}: state in {config.paths.state_dir}, configuration in {config.paths.config_dir}",
    )
    return [mode, directories]


def _failure(check_id: str, summary: str, exc: Exception) -> DoctorCheck:
    return DoctorCheck(check_id, STATUS_FAIL, summary, f"{type(exc).__name__}: {exc}")


def _mechanism_check(
    check_id: str,
    role: str,
    status: MechanismStatus | None,
    capabilities: EnforcerCapabilities | None,
    privileged: bool,
) -> DoctorCheck:
    missing = STATUS_FAIL if privileged else STATUS_WARN
    if status is not None:
        if status.available:
            return DoctorCheck(check_id, STATUS_OK, f"{status.mechanism}: available", status.tier)
        return DoctorCheck(
            check_id,
            missing,
            f"{status.mechanism}: unavailable ({status.reason})",
            status.tier,
        )
    if capabilities is None:
        return DoctorCheck(check_id, STATUS_FAIL, f"{role}: unknown (no enforcer report)")
    available = getattr(capabilities, role, None)
    if available is None:
        return DoctorCheck(check_id, STATUS_INFO, f"{role}: not reported by this enforcer")
    if available:
        return DoctorCheck(check_id, STATUS_OK, f"{role}: available")
    return DoctorCheck(check_id, missing, f"{role}: unavailable", "; ".join(capabilities.notes))


def _system_volume_check(
    devices: Sequence[UsbDevice],
    probe: Callable[[Sequence[UsbDevice]], frozenset[str]] | None,
    created_backend: bool,
    platform: str,
    backend: DeviceBackend | None,
) -> DoctorCheck:
    if backend is None:
        return DoctorCheck("guard.system_volume", STATUS_FAIL, "not checked: no device backend")
    if probe is None:
        if not created_backend:
            return DoctorCheck(
                "guard.system_volume",
                STATUS_INFO,
                "not checked: no system-volume probe was supplied with this backend",
            )

        def probe(found: Sequence[UsbDevice]) -> frozenset[str]:
            return system_instance_ids(found, platform=platform)

    try:
        backing = probe(devices)
    except Exception as exc:
        return _failure(
            "guard.system_volume",
            "the devices backing the system volume cannot be determined; none is protected"
            " for that reason",
            exc,
        )
    if backing:
        return DoctorCheck(
            "guard.system_volume",
            STATUS_INFO,
            f"{len(backing)} USB device(s) back the system volume and are protected",
        )
    return DoctorCheck("guard.system_volume", STATUS_OK, "no USB device backs the system volume")


def _boot_check(kernel_cmdline: Callable[[], str] | None) -> DoctorCheck:
    from portlock.guard.linux.enforce import parse_authorized_default_param

    reader = kernel_cmdline if kernel_cmdline is not None else _read_proc_cmdline
    try:
        value = parse_authorized_default_param(reader())
    except Exception as exc:
        return _failure("guard.boot_default_deny", "the kernel command line cannot be read", exc)
    if value == "0":
        return DoctorCheck(
            "guard.boot_default_deny",
            STATUS_OK,
            "usbcore.authorized_default=0 is set: USB devices are refused from boot",
        )
    if value == "2":
        return DoctorCheck(
            "guard.boot_default_deny",
            STATUS_OK,
            "usbcore.authorized_default=2 is set: only devices on internal ports are"
            " authorized from boot",
        )
    if value is None:
        return DoctorCheck(
            "guard.boot_default_deny",
            STATUS_WARN,
            "usbcore.authorized_default is not on the kernel command line: devices that"
            " enumerate before PortLock starts are authorized by the kernel",
            "only usbcore.authorized_default=0 on the kernel command line is preventive from"
            " boot (DESIGN 14.19); PortLock never edits the boot loader",
        )
    return DoctorCheck(
        "guard.boot_default_deny",
        STATUS_WARN,
        f"usbcore.authorized_default={value} is set: the kernel authorizes devices at boot",
    )


def _read_proc_cmdline() -> str:
    with open(_PROC_CMDLINE, encoding="ascii", errors="replace") as stream:
        return stream.read(64 * 1024)


def _privacy_check(
    check_id: str, label: str, path: Path, privacy: DirPrivacy | None
) -> DoctorCheck:
    if privacy is None:
        return DoctorCheck(check_id, STATUS_FAIL, f"the {label} cannot be checked")
    try:
        report = privacy.check(path)
    except Exception as exc:
        return _failure(check_id, f"the {label} cannot be checked", exc)
    if report.private:
        return DoctorCheck(check_id, STATUS_OK, f"the {label} is private")
    return DoctorCheck(
        check_id,
        STATUS_FAIL,
        f"the {label} is not private: enforce mode is refused until it is",
        "; ".join(report.problems),
    )
