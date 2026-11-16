"""The seams: value types, the write-ahead helper, the fakes, and the command lines the
real implementations build and the output they parse.

No real implementation that changes anything is called. ``systemd-run``, ``systemctl``,
``schtasks`` and ``icacls`` are never run: their command lines are captured by a
:class:`FakeCommandRunner`. The only program actually started is this Python
interpreter, to test :class:`SubprocessRunner` itself.
"""

from __future__ import annotations

import errno
import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from portlock.core.errors import EnforcementError
from portlock.guard.base import JournalEntry, JournalKind
from portlock.guard.seams import (
    REG_DWORD,
    REG_MULTI_SZ,
    REG_SZ,
    ChangeRecorder,
    CommandResult,
    FakeBlockIO,
    FakeCfgMgr,
    FakeCommandRunner,
    FakeDirPrivacy,
    FakeDisks,
    FakeExternalTimer,
    FakeRegistry,
    FakeRuleFiles,
    FakeSysfs,
    IcaclsDirPrivacy,
    JournalUnavailable,
    PosixDirPrivacy,
    RealBlockIO,
    RegValue,
    ScheduledTaskTimer,
    SubprocessRunner,
    SystemdRunTimer,
    TimerError,
    current_process_privileged,
    encode_reg,
    parse_icacls_output,
    parse_schtasks_query,
    scheduled_task_xml,
    validate_timer_name,
)

AT = datetime(2026, 3, 1, 14, 30, 5, 123456, tzinfo=UTC)
RECOVER = (
    "/usr/bin/python3",
    "-I",
    "-m",
    "portlock",
    "recover",
    "--config",
    "/etc/portlock/portlock.toml",
)

# --- RegValue -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (RegValue(REG_DWORD, 1), "dword:1"),
        (RegValue(REG_DWORD, 0xFFFFFFFF), "dword:4294967295"),
        (
            RegValue(REG_SZ, "USB\\VID_1209&PID_0001\\TEST0001"),
            "sz:USB\\VID_1209&PID_0001\\TEST0001",
        ),
        (RegValue(REG_SZ, "a:b"), "sz:a:b"),
        (RegValue(REG_MULTI_SZ, ("one", "two")), 'multi_sz:["one", "two"]'),
    ],
)
def test_registry_values_round_trip_through_the_journal_form(value: RegValue, text: str) -> None:
    assert value.encode() == text
    assert RegValue.decode(text) == value
    assert encode_reg(value) == text


def test_encode_reg_keeps_absence() -> None:
    assert encode_reg(None) is None


@pytest.mark.parametrize(
    ("kind", "data"),
    [
        (REG_DWORD, -1),
        (REG_DWORD, 2**32),
        (REG_DWORD, True),
        (REG_DWORD, "1"),
        (REG_SZ, 1),
        (REG_SZ, "a\x00b"),
        (REG_SZ, "x" * 2000),
        (REG_MULTI_SZ, "not a list"),
        (REG_MULTI_SZ, ("ok", 3)),
        (3, b"binary"),
    ],
)
def test_registry_values_are_validated(kind: int, data: object) -> None:
    with pytest.raises(ValueError):
        RegValue(kind, data)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "text",
    ["", "dword", "dword:", "dword:-1", "dword:1e3", "qword:1", "multi_sz:{}", "multi_sz:[", 7],
)
def test_malformed_journal_values_are_rejected(text: object) -> None:
    with pytest.raises(ValueError):
        RegValue.decode(text)  # type: ignore[arg-type]


# --- ChangeRecorder -----------------------------------------------------------------------

ENTRY = JournalEntry(JournalKind.SYSFS_AUTHORIZED, "/sys/devices/x/usb1/1-1/authorized", "1", "0")


def test_the_recorder_journals_before_it_changes() -> None:
    order: list[str] = []
    recorder = ChangeRecorder(lambda entry: order.append("journal"))
    recorder.apply(ENTRY, lambda: order.append("change"))
    assert order == ["journal", "change"]
    assert recorder.undo == [ENTRY]


def test_a_refused_journal_entry_prevents_the_change() -> None:
    changed: list[bool] = []

    def refuse(entry: JournalEntry) -> None:
        raise PermissionError("journal is read-only")

    recorder = ChangeRecorder(refuse)
    with pytest.raises(JournalUnavailable, match="journal unavailable: PermissionError"):
        recorder.apply(ENTRY, lambda: changed.append(True))
    assert changed == [] and recorder.undo == []


def test_a_failed_change_is_not_recorded() -> None:
    def fail() -> None:
        raise OSError(errno.ENODEV, "gone")

    recorder = ChangeRecorder(None)
    with pytest.raises(OSError):
        recorder.apply(ENTRY, fail)
    assert recorder.undo == []


# --- FakeSysfs ----------------------------------------------------------------------------


def test_the_fake_sysfs_resolves_links_like_realpath() -> None:
    sysfs = FakeSysfs()
    sysfs.add_file("/sys/devices/pci0000:00/usb1/1-1/authorized", "1\n")
    sysfs.add_link("/sys/bus/usb/devices/1-1", "../../../devices/pci0000:00/usb1/1-1")
    sysfs.add_link("/sys/absolute", "/sys/devices/pci0000:00")
    assert sysfs.realpath("/sys/bus/usb/devices/1-1") == "/sys/devices/pci0000:00/usb1/1-1"
    assert sysfs.realpath("/sys/absolute/usb1") == "/sys/devices/pci0000:00/usb1"
    assert sysfs.realpath("/sys/missing/x") == "/sys/missing/x"
    assert sysfs.read_text("/sys/bus/usb/devices/1-1/authorized") == "1"
    assert sysfs.listdir("/sys/bus/usb/devices") == ["1-1"]
    assert sysfs.listdir("/sys/devices/pci0000:00/usb1/1-1") == ["authorized"]


def test_the_fake_sysfs_never_creates_a_file() -> None:
    sysfs = FakeSysfs()
    sysfs.add_dir("/sys/devices")
    with pytest.raises(FileNotFoundError):
        sysfs.write_text("/sys/devices/new", "1")
    with pytest.raises(IsADirectoryError):
        sysfs.write_text("/sys/devices", "1")
    assert not sysfs.exists("/sys/devices/new")


def test_the_fake_sysfs_models_privilege_read_only_mounts_and_failures() -> None:
    sysfs = FakeSysfs()
    sysfs.add_file("/sys/a", "1")
    sysfs.add_file("/sys/locked", "1", writable=False)
    with pytest.raises(PermissionError):
        sysfs.write_text("/sys/locked", "0")
    assert not sysfs.writable("/sys/locked") and sysfs.writable("/sys/a")
    sysfs.read_only_fs = True
    with pytest.raises(OSError) as raised:
        sysfs.write_text("/sys/a", "0")
    assert raised.value.errno == errno.EROFS
    sysfs.read_only_fs = False
    sysfs.privileged = False
    with pytest.raises(PermissionError):
        sysfs.write_text("/sys/a", "0")
    sysfs.privileged = True
    sysfs.fail("read", "/sys/a", errno.ENODEV)
    with pytest.raises(OSError) as raised:
        sysfs.read_text("/sys/a")
    assert raised.value.errno == errno.ENODEV
    sysfs.clear_failures()
    sysfs.on_write("/sys/a", lambda value: "kept")
    sysfs.write_text("/sys/a", "0")
    assert sysfs.read_text("/sys/a") == "kept"
    assert sysfs.writes == [("/sys/a", "0")]
    with pytest.raises(ValueError):
        sysfs.fail("chmod", "/sys/a", errno.EIO)


def test_the_fake_sysfs_detects_link_loops_and_dangling_links() -> None:
    sysfs = FakeSysfs()
    sysfs.add_link("/sys/a", "b")
    sysfs.add_link("/sys/b", "a")
    with pytest.raises(OSError) as raised:
        sysfs.read_text("/sys/a/x")
    assert raised.value.errno == errno.ELOOP
    sysfs.add_link("/sys/dangling", "nowhere")
    assert sysfs.exists("/sys/dangling")
    with pytest.raises(ValueError):
        sysfs.read_text("relative")


def test_removing_a_tree_takes_everything_below_it() -> None:
    sysfs = FakeSysfs()
    sysfs.add_file("/sys/d/1-1/authorized", "1")
    sysfs.add_link("/sys/d/1-1/port", "../port1")
    sysfs.add_file("/sys/d/1-10/authorized", "1")
    sysfs.remove_tree("/sys/d/1-1")
    assert not sysfs.exists("/sys/d/1-1") and not sysfs.exists("/sys/d/1-1/port")
    assert sysfs.exists("/sys/d/1-10/authorized")


# --- other fakes --------------------------------------------------------------------------


def test_fake_block_io_rule_files_disks_and_registry_model_privilege() -> None:
    block = FakeBlockIO()
    block.add("/dev/sdz")
    block.privileged = False
    with pytest.raises(PermissionError):
        block.set_read_only("/dev/sdz", True)
    with pytest.raises(FileNotFoundError):
        block.get_read_only("/dev/sdy")

    rules = FakeRuleFiles(["/etc/udev/rules.d"])
    with pytest.raises(FileNotFoundError):
        rules.write("/elsewhere/x.rules", "x")
    rules.privileged = False
    with pytest.raises(PermissionError):
        rules.write("/etc/udev/rules.d/x.rules", "x")
    assert not rules.dir_writable("/etc/udev/rules.d")

    disks = FakeDisks()
    disks.attach("USB\\VID_1209&PID_0001\\TEST", 4)
    assert disks.disk_numbers("usb\\vid_1209&pid_0001\\test") == [4]
    disks.privileged = False
    with pytest.raises(PermissionError):
        disks.set_read_only(4, True)

    registry = FakeRegistry()
    registry.put("SOFTWARE\\Key", "Name", RegValue.dword(1))
    assert registry.get("software\\key", "NAME") == RegValue.dword(1)
    assert registry.values("SOFTWARE\\KEY") == {"Name": RegValue.dword(1)}
    registry.privileged = False
    with pytest.raises(PermissionError):
        registry.delete("SOFTWARE\\Key", "Name")
    with pytest.raises(TypeError):
        registry.set("SOFTWARE\\Key", "Name", 1)  # type: ignore[arg-type]


def test_the_fake_device_tree_answers_like_cfgmgr() -> None:
    cfg = FakeCfgMgr()
    node = cfg.add("USB\\VID_1209&PID_0001\\TEST")
    code, devinst = cfg.locate("usb\\vid_1209&pid_0001\\test", phantom=False)
    assert code == 0 and devinst == node.devinst
    assert cfg.disable(devinst, persist=True) == 0 and node.disabled and node.persisted
    code, status, problem = cfg.status(devinst)
    assert code == 0 and status & 0x400 and problem == 0x16
    cfg.unplug(node.instance_id)
    assert cfg.locate(node.instance_id, phantom=False)[0] == 0x0D
    assert cfg.locate(node.instance_id, phantom=True)[0] == 0
    assert cfg.status(devinst)[0] == 0x0D
    assert cfg.enable(devinst) == 0 and not node.disabled
    cfg.privileged = False
    assert cfg.enable(devinst) == 0x33
    assert cfg.locate("USB\\VID_1209&PID_0002\\NONE", phantom=True)[0] == 0x0D


def test_the_fake_timer_and_privacy_seams() -> None:
    timer = FakeExternalTimer()
    timer.arm("deadman", AT, RECOVER)
    assert timer.is_armed("deadman") and timer.armed["deadman"][0] == AT.replace(microsecond=0)
    timer.cancel("deadman")
    assert not timer.is_armed("deadman")
    timer.failing = True
    with pytest.raises(TimerError):
        timer.arm("deadman", AT, RECOVER)
    with pytest.raises(ValueError):
        FakeExternalTimer().arm("Dead Man", AT, RECOVER)

    privacy = FakeDirPrivacy()
    assert not privacy.check(Path("/var/lib/portlock")).private
    privacy.ensure_private(Path("/var/lib/portlock"))
    assert privacy.check(Path("/var/lib/portlock")).private
    privacy.refuse.add(str(Path("/etc/portlock")))
    with pytest.raises(EnforcementError):
        privacy.ensure_private(Path("/etc/portlock"))


def test_the_fake_runner_answers_from_the_newest_matching_rule() -> None:
    runner = FakeCommandRunner()
    runner.respond(("a",), CommandResult(1))
    runner.respond(("a", "b"), CommandResult(2), once=True)
    assert runner.run(["a", "b", "c"], timeout=1).returncode == 2
    assert runner.run(["a", "b", "c"], timeout=1).returncode == 1
    assert runner.run(["z"], timeout=1).returncode == 0
    assert runner.commands() == [("a", "b", "c"), ("a", "b", "c"), ("z",)]


# --- SubprocessRunner and CommandResult ---------------------------------------------------


def test_the_subprocess_runner_runs_an_argument_list() -> None:
    result = SubprocessRunner().run([sys.executable, "-c", "print('seam ok')"], timeout=30)
    assert result.ok and result.stdout.strip() == "seam ok"


def test_the_subprocess_runner_reports_a_missing_program() -> None:
    missing = str(Path(sys.executable).parent / "no-such-program-portlock")
    result = SubprocessRunner().run([missing], timeout=5)
    assert not result.ok and result.returncode == -1 and "cannot run" in result.stderr


@pytest.mark.parametrize("argv", ["echo hi", [], ["a", 1], ["a\x00b"]])
def test_command_lines_are_validated(argv: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        SubprocessRunner().run(argv, timeout=1)  # type: ignore[arg-type]


def test_command_results_describe_themselves() -> None:
    assert CommandResult(0).ok
    assert not CommandResult(0, timed_out=True).ok
    assert CommandResult(-1, timed_out=True).describe() == "timed out"
    assert CommandResult(3, stderr="bad thing\nmore").describe() == "exit status 3: bad thing"
    assert CommandResult(4).describe() == "exit status 4"


# --- systemd-run --------------------------------------------------------------------------


def test_systemd_timer_arm_cancels_first_and_builds_the_unit() -> None:
    runner = FakeCommandRunner()
    SystemdRunTimer(runner).arm("deadman", AT.astimezone(timezone(timedelta(hours=2))), RECOVER)
    assert runner.commands() == [
        ("/usr/bin/systemctl", "stop", "portlock-deadman.timer"),
        (
            "/usr/bin/systemd-run",
            "--unit=portlock-deadman",
            "--description=PortLock dead-man timer: restore journaled settings",
            "--on-calendar=2026-03-01 14:30:05 UTC",
            "--timer-property=AccuracySec=1s",
            "--collect",
            "--quiet",
            "--",
            *RECOVER,
        ),
    ]
    assert all(timeout <= 10 for _argv, timeout in runner.calls)


def test_systemd_timer_failures_raise() -> None:
    runner = FakeCommandRunner()
    runner.respond(("/usr/bin/systemd-run",), CommandResult(1, stderr="Unit already exists"))
    with pytest.raises(TimerError, match="Unit already exists"):
        SystemdRunTimer(runner).arm("deadman", AT, RECOVER)
    runner.respond(("/usr/bin/systemctl", "stop"), CommandResult(1, stderr="Access denied"))
    with pytest.raises(TimerError, match="Access denied"):
        SystemdRunTimer(runner).cancel("deadman")


def test_systemd_timer_cancel_of_an_unknown_unit_is_fine() -> None:
    runner = FakeCommandRunner()
    runner.respond(("/usr/bin/systemctl", "stop"), CommandResult(5, stderr="Unit not loaded."))
    SystemdRunTimer(runner).cancel("deadman")


@pytest.mark.parametrize(
    ("result", "armed"),
    [
        (CommandResult(0, stdout="active\n"), True),
        (CommandResult(3, stdout="inactive\n"), False),
        (CommandResult(4, stdout="unknown\n"), False),
        (CommandResult(0, stdout="activating\n"), False),
    ],
)
def test_systemd_timer_is_armed_reads_is_active(result: CommandResult, armed: bool) -> None:
    runner = FakeCommandRunner()
    runner.respond(("/usr/bin/systemctl", "is-active"), result)
    assert SystemdRunTimer(runner).is_armed("deadman") is armed
    assert runner.commands() == [("/usr/bin/systemctl", "is-active", "portlock-deadman.timer")]


def test_systemd_timer_input_is_validated() -> None:
    runner = FakeCommandRunner()
    timer = SystemdRunTimer(runner)
    with pytest.raises(ValueError):
        timer.arm("deadman", datetime(2026, 1, 1), RECOVER)
    with pytest.raises(ValueError):
        timer.arm("deadman", AT, ("python3", "-m", "portlock"))
    with pytest.raises(ValueError):
        timer.arm("x;rm", AT, RECOVER)
    runner.respond(("/usr/bin/systemctl", "is-active"), CommandResult(-1, timed_out=True))
    with pytest.raises(TimerError):
        timer.is_armed("deadman")
    assert validate_timer_name("deadman-2") == "deadman-2"
    assert runner.commands() == [("/usr/bin/systemctl", "is-active", "portlock-deadman.timer")]


# --- schtasks -----------------------------------------------------------------------------

WIN_RECOVER = (
    "C:\\Program Files\\PortLock\\python.exe",
    "-I",
    "-m",
    "portlock",
    "recover",
    "--config",
    "C:\\ProgramData\\PortLock\\config\\portlock.toml",
)


def test_the_task_definition_runs_as_system_at_the_time_in_utc() -> None:
    xml = scheduled_task_xml(
        AT.astimezone(timezone(timedelta(hours=-5))), WIN_RECOVER, description="a & b <c>"
    )
    assert "<StartBoundary>2026-03-01T14:30:05Z</StartBoundary>" in xml
    assert "<UserId>S-1-5-18</UserId>" in xml and "<RunLevel>HighestAvailable</RunLevel>" in xml
    assert "<StartWhenAvailable>true</StartWhenAvailable>" in xml
    assert "<Command>C:\\Program Files\\PortLock\\python.exe</Command>" in xml
    assert (
        "<Arguments>-I -m portlock recover --config "
        "C:\\ProgramData\\PortLock\\config\\portlock.toml</Arguments>"
    ) in xml
    assert "<Description>a &amp; b &lt;c&gt;</Description>" in xml


def test_task_arguments_with_spaces_and_markup_are_quoted_and_escaped() -> None:
    xml = scheduled_task_xml(AT, ("C:\\p.exe", "--config", "C:\\A B\\x&y.toml"), description="d")
    assert '<Arguments>--config "C:\\A B\\x&amp;y.toml"</Arguments>' in xml


def test_scheduled_task_arm_registers_from_a_private_xml_file(tmp_path: Path) -> None:
    seen: dict[str, bytes] = {}

    class Recording(FakeCommandRunner):
        def run(self, argv, *, timeout):  # type: ignore[no-untyped-def]
            if "/Create" in argv:
                seen["xml"] = Path(argv[argv.index("/XML") + 1]).read_bytes()
            return super().run(argv, timeout=timeout)

    runner = Recording()
    timer = ScheduledTaskTimer(runner, tmp_path, schtasks="C:\\Windows\\System32\\schtasks.exe")
    timer.arm("deadman", AT, WIN_RECOVER)
    xml_path = str(tmp_path / "deadman.task.xml")
    assert runner.commands() == [
        (
            "C:\\Windows\\System32\\schtasks.exe",
            "/Create",
            "/TN",
            "\\PortLock\\deadman",
            "/XML",
            xml_path,
            "/F",
        )
    ]
    assert seen["xml"].startswith(b"\xff\xfe")
    assert "2026-03-01T14:30:05Z" in seen["xml"][2:].decode("utf-16-le")
    assert list(tmp_path.iterdir()) == []


def test_scheduled_task_failures_raise_and_clean_up(tmp_path: Path) -> None:
    runner = FakeCommandRunner()
    runner.respond(("schtasks.exe", "/Create"), CommandResult(1, stderr="ERROR: Access is denied."))
    timer = ScheduledTaskTimer(runner, tmp_path, schtasks="schtasks.exe")
    with pytest.raises(TimerError, match="Access is denied"):
        timer.arm("deadman", AT, WIN_RECOVER)
    assert list(tmp_path.iterdir()) == []


def test_scheduled_task_cancel_deletes_only_an_existing_task(tmp_path: Path) -> None:
    runner = FakeCommandRunner()
    runner.respond(("s.exe", "/Query"), CommandResult(1, stderr="ERROR: localized text"))
    timer = ScheduledTaskTimer(runner, tmp_path, schtasks="s.exe")
    timer.cancel("deadman")
    assert runner.commands() == [
        ("s.exe", "/Query", "/TN", "\\PortLock\\deadman", "/FO", "CSV", "/NH")
    ]
    runner.respond(
        ("s.exe", "/Query"),
        CommandResult(0, stdout='"\\PortLock\\deadman","1.3.2026 15:30:05","Bereit"\n'),
    )
    timer.cancel("deadman")
    assert runner.commands()[-1] == ("s.exe", "/Delete", "/TN", "\\PortLock\\deadman", "/F")


def test_parse_schtasks_query_uses_only_the_task_name() -> None:
    output = '"\\PortLock\\deadman","3/1/2026 2:30:05 PM","Ready"\r\n'
    assert parse_schtasks_query(output, "\\PortLock\\deadman")
    assert parse_schtasks_query(output.upper(), "\\PortLock\\deadman")
    assert not parse_schtasks_query(output, "\\PortLock\\other")
    assert not parse_schtasks_query("", "\\PortLock\\deadman")


# --- POSIX directory privacy --------------------------------------------------------------

DIR = stat.S_IFDIR


def stat_table(entries: dict[str, tuple[int, int]]):  # type: ignore[no-untyped-def]
    def lstat(path: str) -> SimpleNamespace:
        if path not in entries:
            raise FileNotFoundError(errno.ENOENT, "missing", path)
        mode, uid = entries[path]
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    return lstat


SAFE_TREE = {
    "/": (DIR | 0o755, 0),
    "/var": (DIR | 0o755, 0),
    "/var/lib": (DIR | 0o755, 0),
    "/var/lib/portlock": (DIR | 0o700, 0),
}


def posix(entries: dict[str, tuple[int, int]], euid: int = 0, **kwargs: object) -> PosixDirPrivacy:
    return PosixDirPrivacy(
        lstat=stat_table(entries),
        geteuid=lambda: euid,
        realpath=lambda path: path,
        **kwargs,  # type: ignore[arg-type]
    )


def test_a_private_posix_directory_passes() -> None:
    report = posix(SAFE_TREE).check(PurePosixPath("/var/lib/portlock"))
    assert report.private and report.problems == ()


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"/var/lib/portlock": (DIR | 0o755, 0)}, "mode is 0755"),
        ({"/var/lib/portlock": (DIR | 0o700, 1234)}, "owned by uid 1234"),
        ({"/var/lib/portlock": (stat.S_IFLNK | 0o777, 0)}, "symbolic link"),
        ({"/var/lib/portlock": (stat.S_IFREG | 0o600, 0)}, "not a directory"),
        ({"/var/lib": (DIR | 0o777, 0)}, "/var/lib is writable by other users"),
        ({"/var": (DIR | 0o755, 1000)}, "/var is owned by uid 1000"),
    ],
)
def test_posix_privacy_problems_are_named(
    change: dict[str, tuple[int, int]], expected: str
) -> None:
    report = posix({**SAFE_TREE, **change}).check(PurePosixPath("/var/lib/portlock"))
    assert not report.private
    assert any(expected in problem for problem in report.problems), report.problems


def test_a_sticky_world_writable_ancestor_is_acceptable() -> None:
    tree = {"/": (DIR | 0o755, 0), "/tmp": (DIR | 0o1777, 0), "/tmp/pl": (DIR | 0o700, 0)}
    assert posix(tree).check(PurePosixPath("/tmp/pl")).private


def test_a_missing_posix_directory_is_not_private() -> None:
    report = posix({"/": (DIR | 0o755, 0)}).check(PurePosixPath("/var/lib/portlock"))
    assert not report.private and report.problems == ("it does not exist",)


def test_ensure_private_creates_tightens_and_takes_ownership() -> None:
    entries = {k: v for k, v in SAFE_TREE.items() if k != "/var/lib/portlock"}
    calls: list[tuple[str, ...]] = []

    def makedirs(path: str) -> None:
        calls.append(("makedirs", path))
        entries[path] = (DIR | 0o755, 1000)

    def chmod(path: str, mode: int) -> None:
        calls.append(("chmod", path, oct(mode)))
        entries[path] = (DIR | mode, entries[path][1])

    def chown(path: str, uid: int, gid: int) -> None:
        calls.append(("chown", path, str(uid), str(gid)))
        entries[path] = (entries[path][0], uid)

    privacy = posix(entries, makedirs=makedirs, chmod=chmod, chown=chown)
    privacy.ensure_private(PurePosixPath("/var/lib/portlock"))
    assert calls == [
        ("makedirs", "/var/lib/portlock"),
        ("chown", "/var/lib/portlock", "0", "0"),
        ("chmod", "/var/lib/portlock", "0o700"),
    ]
    assert privacy.check(PurePosixPath("/var/lib/portlock")).private


def test_ensure_private_refuses_what_it_cannot_fix() -> None:
    tree = {**SAFE_TREE, "/var/lib": (DIR | 0o777, 0)}
    privacy = posix(tree, chmod=lambda path, mode: None)
    with pytest.raises(EnforcementError, match="could not be made private"):
        privacy.ensure_private(PurePosixPath("/var/lib/portlock"))
    link = {**SAFE_TREE, "/var/lib/portlock": (stat.S_IFLNK | 0o777, 0)}
    with pytest.raises(EnforcementError, match="symbolic link"):
        posix(link, chmod=lambda path, mode: None).ensure_private(
            PurePosixPath("/var/lib/portlock")
        )


# --- icacls -------------------------------------------------------------------------------

WIN_DIR = "C:\\ProgramData\\PortLock\\state"
PRIVATE_LISTING = (
    f"{WIN_DIR} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n"
    "                                BUILTIN\\Administrators:(OI)(CI)(F)\r\n"
    "\r\n"
    "Successfully processed 1 files; Failed processing 0 files\r\n"
)


def test_icacls_ensure_private_strips_inheritance_and_grants_system_and_admins() -> None:
    runner = FakeCommandRunner()
    runner.respond(("icacls.exe", WIN_DIR), CommandResult(0, stdout=PRIVATE_LISTING))
    made: list[str] = []
    privacy = IcaclsDirPrivacy(runner, icacls="icacls.exe", makedirs=made.append)
    privacy.ensure_private(Path(WIN_DIR))
    assert made == [WIN_DIR]
    assert runner.commands()[0] == (
        "icacls.exe",
        WIN_DIR,
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)F",
        "*S-1-5-32-544:(OI)(CI)F",
        "/remove:g",
        "*S-1-1-0",
        "*S-1-5-11",
        "*S-1-5-32-545",
        "*S-1-3-0",
    )
    assert runner.commands()[1] == ("icacls.exe", WIN_DIR)


def test_icacls_check_accepts_only_system_and_administrators() -> None:
    runner = FakeCommandRunner()
    runner.respond(("icacls.exe",), CommandResult(0, stdout=PRIVATE_LISTING))
    assert IcaclsDirPrivacy(runner, icacls="icacls.exe").check(Path(WIN_DIR)).private


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        (
            f"{WIN_DIR} BUILTIN\\Users:(OI)(CI)(RX)\n NT AUTHORITY\\SYSTEM:(F)\n\nok\n",
            "grants (OI)(CI)(RX) to BUILTIN\\Users",
        ),
        (
            f"{WIN_DIR} NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)\n\nok\n",
            "inherited",
        ),
        (
            f"{WIN_DIR} NT-AUTORITÄT\\SYSTEM:(OI)(CI)(F)\n\nok\n",
            "grants (OI)(CI)(F) to NT-AUTORITÄT\\SYSTEM",
        ),
        ("C:\\other NT AUTHORITY\\SYSTEM:(F)\n\nok\n", "unrecognised access entry"),
        ("\n", "no access entries"),
    ],
)
def test_icacls_check_names_what_is_wrong(listing: str, expected: str) -> None:
    runner = FakeCommandRunner()
    runner.respond(("icacls.exe",), CommandResult(0, stdout=listing))
    report = IcaclsDirPrivacy(runner, icacls="icacls.exe").check(Path(WIN_DIR))
    assert not report.private
    assert any(expected in problem for problem in report.problems), report.problems


def test_icacls_deny_entries_do_not_make_a_directory_public() -> None:
    listing = (
        f"{WIN_DIR} Everyone:(OI)(CI)(DENY)(W)\n NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
        " BUILTIN\\Administrators:(OI)(CI)(F)\n\nok\n"
    )
    runner = FakeCommandRunner()
    runner.respond(("icacls.exe",), CommandResult(0, stdout=listing))
    assert IcaclsDirPrivacy(runner, icacls="icacls.exe").check(Path(WIN_DIR)).private


def test_icacls_failures_fail_closed() -> None:
    runner = FakeCommandRunner()
    runner.respond(("icacls.exe",), CommandResult(5, stderr="Access is denied."))
    report = IcaclsDirPrivacy(runner, icacls="icacls.exe").check(Path(WIN_DIR))
    assert not report.private and "Access is denied" in report.problems[0]
    with pytest.raises(EnforcementError):
        IcaclsDirPrivacy(runner, icacls="icacls.exe", makedirs=lambda path: None).ensure_private(
            Path(WIN_DIR)
        )


def test_parse_icacls_output_splits_principal_and_rights() -> None:
    entries, unparsed = parse_icacls_output(PRIVATE_LISTING, WIN_DIR)
    assert entries == [
        ("NT AUTHORITY\\SYSTEM", "(OI)(CI)(F)"),
        ("BUILTIN\\Administrators", "(OI)(CI)(F)"),
    ]
    assert unparsed == []


# --- real seams: only facts that need no operating-system call ----------------------------


def test_real_seams_report_their_platform_without_touching_anything() -> None:
    assert RealBlockIO().available is sys.platform.startswith("linux")
    assert isinstance(current_process_privileged(), bool)
