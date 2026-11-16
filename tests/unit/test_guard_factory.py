"""Platform selection, the guard wrappers, and ``portlock doctor``.

The doctor is exercised with fakes only: no real backend enumerates, no real enforcer is
queried, no directory permission is read from this machine and ``/proc/cmdline`` is never
opened. Constructing a platform object is allowed (it touches nothing); calling it is not.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

import portlock
from factories import flash_drive, keyboard, make_device
from portlock.core.clock import FakeClock
from portlock.core.config import Config, PathsConfig
from portlock.core.errors import BackendError
from portlock.core.models import UsbDevice
from portlock.guard.base import EnforcerCapabilities
from portlock.guard.factory import (
    DEAD_MAN_TIMER,
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_OK,
    STATUS_WARN,
    DoctorCheck,
    DoctorReport,
    create_backend,
    create_dir_privacy,
    create_enforcer,
    create_external_timer,
    create_guard,
    dead_man_command,
    doctor,
    platform_family,
    system_instance_ids,
)
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.linux.enforce import LinuxEnforcer
from portlock.guard.safety import SafetyContext
from portlock.guard.seams import (
    FakeBlockIO,
    FakeCommandRunner,
    FakeDirPrivacy,
    FakeRuleFiles,
    FakeSysfs,
    IcaclsDirPrivacy,
    PosixDirPrivacy,
    ScheduledTaskTimer,
    SystemdRunTimer,
)

CHECK_ORDER = [
    "guard.platform",
    "guard.privilege",
    "guard.backend",
    "guard.detect",
    "guard.enumerate",
    "guard.block",
    "guard.read_only",
    "guard.eject",
    "guard.default_deny",
    "guard.baseline_read_only",
    "guard.conflicts",
    "guard.system_volume",
]
MARKER_SERIAL = "TESTMARKERSERIAL42"
MARKER_PRODUCT = "Marker Product Zeta"
MARKER_ID = "test/marker-instance-77"


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(paths=PathsConfig.under(tmp_path / "home"))


@pytest.fixture
def privacy(config: Config) -> FakeDirPrivacy:
    fake = FakeDirPrivacy()
    fake.ensure_private(config.paths.state_dir)
    fake.ensure_private(config.paths.config_dir)
    return fake


def marked_device() -> UsbDevice:
    return flash_drive(serial=MARKER_SERIAL, product=MARKER_PRODUCT, instance_id=MARKER_ID)


# --- platform selection -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "family"), [("win32", "windows"), ("linux", "linux"), ("linux2", "linux")]
)
def test_platform_family(platform: str, family: str) -> None:
    assert platform_family(platform) == family


def test_unsupported_platforms_are_refused(config: Config, clock: FakeClock) -> None:
    for call in (
        lambda: platform_family("darwin"),
        lambda: create_backend(config, clock=clock, platform="darwin"),
        lambda: create_enforcer(config, platform="darwin"),
        lambda: system_instance_ids([], platform="darwin"),
        lambda: create_external_timer(config, platform="freebsd13"),
        lambda: create_dir_privacy(platform="cygwin"),
    ):
        with pytest.raises(BackendError) as raised:
            call()
        assert raised.value.code == "unsupported_platform"


def test_the_linux_objects_are_built_without_touching_anything(
    config: Config, clock: FakeClock
) -> None:
    from portlock.guard.linux.backend import LinuxBackend

    assert isinstance(create_backend(config, clock=clock, platform="linux"), LinuxBackend)
    enforcer = create_enforcer(config, platform="linux", write_ahead=lambda entry: None)
    assert isinstance(enforcer, LinuxEnforcer)
    assert isinstance(create_dir_privacy(platform="linux"), PosixDirPrivacy)
    assert isinstance(create_external_timer(config, platform="linux"), SystemdRunTimer)


def test_the_windows_objects_are_chosen_for_win32(config: Config) -> None:
    from portlock.guard.windows.enforce import WindowsEnforcer

    assert isinstance(create_enforcer(config, platform="win32"), WindowsEnforcer)
    assert isinstance(create_dir_privacy(platform="win32"), IcaclsDirPrivacy)
    timer = create_external_timer(config, platform="win32", runner=FakeCommandRunner())
    assert isinstance(timer, ScheduledTaskTimer)


def test_importing_the_factory_imports_neither_platform_package() -> None:
    source = Path(portlock.__file__).resolve().parents[1]
    code = (
        "import sys, portlock.guard.factory as f; "
        "print(f.platform_family('linux'), "
        "'portlock.guard.windows' in sys.modules, 'portlock.guard.linux' in sys.modules)"
    )
    environment = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split() == ["linux", "False", "False"]


def test_the_dead_man_command_runs_recover_isolated(config: Config) -> None:
    command = dead_man_command(config, python="/usr/bin/python3")
    assert command == (
        "/usr/bin/python3",
        "-I",
        "-m",
        "portlock",
        "recover",
        "--config",
        str(config.paths.config_file),
        "--dead-man",
    )
    assert DEAD_MAN_TIMER == "deadman"
    with pytest.raises(BackendError):
        dead_man_command(config, python="")


# --- the guard wrappers -------------------------------------------------------------------


def test_create_guard_wraps_one_enforcer_twice(config: Config, clock: FakeClock) -> None:
    backend = FakeBackend([flash_drive()], clock=clock, synchronous=True)
    enforcer = FakeEnforcer(backend=backend)
    guard = create_guard(
        config,
        clock=clock,
        context_provider=SafetyContext,
        backend=backend,
        enforcer=enforcer,
    )
    assert guard.backend is backend and guard.enforcer is enforcer
    assert not guard.live.dry_run and guard.dry.dry_run
    dry = guard.dry.block(flash_drive())
    assert dry.ok and dry.mechanism == "dry-run" and enforcer.calls == ()
    live = guard.live.block(flash_drive())
    assert live.ok and enforcer.is_blocked(flash_drive())
    refused = guard.live.block(keyboard())
    assert not refused.ok and refused.mechanism == "refused"


# --- doctor -------------------------------------------------------------------------------


def run_doctor(
    config: Config,
    clock: FakeClock,
    privacy: FakeDirPrivacy,
    *,
    enforcer: object | None = None,
    devices: Sequence[UsbDevice] = (),
    platform: str = "linux",
    cmdline: str = "root=/dev/sda1 usbcore.authorized_default=0",
    system_ids: object = None,
) -> DoctorReport:
    backend = FakeBackend(devices, clock=clock, synchronous=True)
    return doctor(
        config,
        clock=clock,
        backend=backend,
        enforcer=enforcer if enforcer is not None else FakeEnforcer(),  # type: ignore[arg-type]
        platform=platform,
        dir_privacy=privacy,
        kernel_cmdline=lambda: cmdline,
        system_ids=system_ids if system_ids is not None else (lambda found: frozenset()),  # type: ignore[arg-type]
    )


def test_doctor_with_a_privileged_enforcer(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = run_doctor(config, clock, privacy, devices=[flash_drive()])
    ids = [check.id for check in report.checks]
    assert ids == [*CHECK_ORDER, "guard.boot_default_deny", "guard.state_dir", "guard.config_dir"]
    assert report.worst == STATUS_OK, [c for c in report.checks if c.status != STATUS_OK]
    assert report.check("guard.enumerate").summary == "1 USB device(s) connected"  # type: ignore[union-attr]
    assert report.version == portlock.__version__
    assert report.generated_at == clock.now()
    data = report.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["worst"] == "ok" and data["enforcer"]["privileged"] is True


def test_doctor_without_privilege_warns_for_each_mechanism(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = run_doctor(config, clock, privacy, enforcer=FakeEnforcer.unprivileged())
    assert report.check("guard.privilege").status == STATUS_WARN  # type: ignore[union-attr]
    for check_id in ("guard.block", "guard.read_only", "guard.eject", "guard.default_deny"):
        assert report.check(check_id).status == STATUS_WARN  # type: ignore[union-attr]
    # FakeEnforcer does not report a baseline mechanism.
    assert report.check("guard.baseline_read_only").status == STATUS_INFO  # type: ignore[union-attr]
    assert report.worst == STATUS_WARN


def test_doctor_fails_a_missing_mechanism_when_privileged(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    enforcer = FakeEnforcer(
        EnforcerCapabilities(
            name="partial",
            privileged=True,
            block=True,
            read_only=False,
            eject=True,
            default_deny=True,
            notes=("conflict: another agent manages devices",),
        )
    )
    report = run_doctor(config, clock, privacy, enforcer=enforcer)
    assert report.check("guard.read_only").status == STATUS_FAIL  # type: ignore[union-attr]
    conflicts = report.check("guard.conflicts")
    assert conflicts is not None and conflicts.status == STATUS_WARN
    assert "another agent" in conflicts.detail
    assert report.worst == STATUS_FAIL


def linux_rig(root: bool) -> LinuxEnforcer:
    sysfs = FakeSysfs()
    hub = "/sys/devices/pci0000:00/0000:00:14.0/usb1"
    for name in ("authorized", "authorized_default", "remove"):
        sysfs.add_file(f"{hub}/{name}", "1")
    sysfs.add_link("/sys/bus/usb/devices/usb1", "../../../devices/pci0000:00/0000:00:14.0/usb1")
    sysfs.read_only_fs = True
    return LinuxEnforcer(
        sysfs=sysfs,
        block=FakeBlockIO(),
        rules=FakeRuleFiles(["/etc/udev/rules.d"]),
        runner=FakeCommandRunner(),
        is_root=lambda: root,
    )


def test_doctor_gives_each_mechanism_s_reason(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = run_doctor(config, clock, privacy, enforcer=linux_rig(root=True))
    block = report.check("guard.block")
    assert block is not None and block.status == STATUS_FAIL
    assert "sysfs:authorized: unavailable" in block.summary and "read-only" in block.summary
    baseline = report.check("guard.baseline_read_only")
    assert baseline is not None and baseline.status == STATUS_OK and "preventive" in baseline.detail
    assert {status.role for status in report.mechanisms} >= {"block", "baseline_read_only"}
    unprivileged = run_doctor(config, clock, privacy, enforcer=linux_rig(root=False))
    assert unprivileged.check("guard.block").status == STATUS_WARN  # type: ignore[union-attr]
    assert "not running as root" in unprivileged.check("guard.block").summary  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("cmdline", "status", "text"),
    [
        ("quiet usbcore.authorized_default=0", STATUS_OK, "refused from boot"),
        ("usbcore.authorized_default=2", STATUS_OK, "internal ports"),
        ("quiet splash", STATUS_WARN, "not on the kernel command line"),
        ("usbcore.authorized_default=1", STATUS_WARN, "authorizes devices at boot"),
    ],
)
def test_doctor_reports_the_kernel_command_line(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy, cmdline: str, status: str, text: str
) -> None:
    check = run_doctor(config, clock, privacy, cmdline=cmdline).check("guard.boot_default_deny")
    assert check is not None and check.status == status and text in check.summary


def test_the_kernel_command_line_is_a_linux_check_only(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = run_doctor(config, clock, privacy, platform="win32")
    assert report.check("guard.boot_default_deny") is None
    assert report.check("guard.privilege").summary == "running as administrator"  # type: ignore[union-attr]


def test_doctor_reports_directories_that_are_not_private(config: Config, clock: FakeClock) -> None:
    privacy = FakeDirPrivacy()
    privacy.problems[str(config.paths.state_dir)] = ("its mode is 0755",)
    report = run_doctor(config, clock, privacy)
    state = report.check("guard.state_dir")
    assert state is not None and state.status == STATUS_FAIL and "0755" in state.detail
    assert report.check("guard.config_dir").status == STATUS_FAIL  # type: ignore[union-attr]
    assert privacy.calls and all(operation == "check" for operation, _path in privacy.calls)


def test_doctor_never_raises_and_turns_errors_into_failures(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    class Broken(FakeEnforcer):
        def capabilities(self) -> EnforcerCapabilities:
            raise RuntimeError("capabilities exploded")

    backend = FakeBackend([], clock=clock, synchronous=True)
    backend.fail_enumerate("bus unreadable")

    def boom() -> str:
        raise OSError("no /proc here")

    def probe(found: Sequence[UsbDevice]) -> frozenset[str]:
        raise BackendError("the mount table is gone")

    report = doctor(
        config,
        clock=clock,
        backend=backend,
        enforcer=Broken(),
        platform="linux",
        dir_privacy=privacy,
        kernel_cmdline=boom,
        system_ids=probe,
    )
    statuses = {check.id: check.status for check in report.checks}
    assert statuses["guard.enforcer"] == STATUS_FAIL
    assert statuses["guard.privilege"] == STATUS_FAIL
    assert statuses["guard.enumerate"] == STATUS_FAIL
    assert statuses["guard.system_volume"] == STATUS_FAIL
    assert statuses["guard.boot_default_deny"] == STATUS_FAIL
    assert report.enforcer is None


def test_doctor_on_an_unsupported_platform(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = doctor(config, clock=clock, platform="darwin", dir_privacy=privacy)
    assert report.check("guard.platform").status == STATUS_FAIL  # type: ignore[union-attr]
    assert report.worst == STATUS_FAIL


def test_doctor_without_a_probe_for_an_injected_backend(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    report = doctor(
        config,
        clock=clock,
        backend=FakeBackend([], clock=clock),
        enforcer=FakeEnforcer(),
        platform="linux",
        dir_privacy=privacy,
        kernel_cmdline=lambda: "",
    )
    check = report.check("guard.system_volume")
    assert check is not None and check.status == STATUS_INFO and "not checked" in check.summary


def test_doctor_counts_system_volume_devices(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    device = marked_device()
    report = run_doctor(
        config, clock, privacy, devices=[device], system_ids=lambda found: frozenset({MARKER_ID})
    )
    check = report.check("guard.system_volume")
    assert check is not None and check.status == STATUS_INFO
    assert check.summary.startswith("1 USB device(s) back the system volume")


def test_the_report_never_names_a_device(
    config: Config, clock: FakeClock, privacy: FakeDirPrivacy
) -> None:
    device = marked_device()
    other = make_device(instance_id="test/other-1", serial=None, product=None, manufacturer=None)
    enforcer = FakeEnforcer(
        EnforcerCapabilities(
            name="fake",
            privileged=True,
            block=False,
            read_only=True,
            eject=True,
            default_deny=True,
            notes=(f"block failed for {MARKER_ID} ({MARKER_PRODUCT})",),
        )
    )

    def probe(found: Sequence[UsbDevice]) -> frozenset[str]:
        raise BackendError(f"cannot trace {MARKER_ID} serial {MARKER_SERIAL}")

    report = run_doctor(
        config, clock, privacy, enforcer=enforcer, devices=[device, other], system_ids=probe
    )
    text = json.dumps(report.to_dict())
    for marker in (MARKER_SERIAL, MARKER_PRODUCT, MARKER_ID, "Example Corp"):
        assert marker not in text
    assert "<device>" in text


def test_doctor_checks_reject_unknown_statuses() -> None:
    with pytest.raises(ValueError):
        DoctorCheck("guard.x", "great", "summary")
