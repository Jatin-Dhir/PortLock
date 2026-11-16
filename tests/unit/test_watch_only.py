"""Watch-only (DESIGN 14.28): a process that could never be trusted to enforce changes nothing.

The rule, decided once per process: a process is watch-only exactly when it is not
elevated, or its directories are not provably system-wide. The mode does not decide it.

The central tests run the *real* start-up path (``service.daemon.run`` and
``build_runtime``, the real factory, the real HTTP API) with every operating-system seam
replaced by a tripwire that records and raises the moment anything touches it: the
``CommandRunner`` (``icacls``, ``schtasks``, ``systemd-run``), the registry, the
Configuration Manager device API, disks, sysfs, block devices and udev rules. On top of
that the factories that build the real enforcer, timer and directory-privacy objects are
replaced by tripwires (a watch-only process must not even build them), and
``subprocess.Popen`` itself is replaced, so no program could start by another route. The
device backend is the in-memory fake: these are unit tests and read no real hardware.

An elevated process with system-wide directories is the other side of the rule: it is
composed with recording fakes and must reach them, in monitor mode too, as it did before
watch-only existed.
"""

from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import errno
import http.client
import io
import json
import os
import subprocess
import sys
import threading
import types
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive, keyboard, mounted_flash_drive
from portlock.audit import events as ev
from portlock.auth.accounts import Role
from portlock.console import cli as cli_module
from portlock.console.api import ApiServer
from portlock.console.cli import EXIT_AUTH, EXIT_FAILED, EXIT_OK, EXIT_UNREACHABLE, CliEnv, main
from portlock.core import privilege
from portlock.core import service as service_module
from portlock.core.clock import FakeClock
from portlock.core.config import (
    AuditConfig,
    Config,
    LockdownConfig,
    PathsConfig,
    ScanConfig,
    config_to_toml,
    default_config,
    load_config,
    paths_per_user,
)
from portlock.core.db import Database
from portlock.core.errors import ConfigError
from portlock.core.models import Mode
from portlock.core.service import ServiceError
from portlock.core.store import (
    JOURNAL_FILE_NAME,
    LockdownRecord,
    PendingChangeRecord,
    RecoveryJournal,
    StateStore,
)
from portlock.guard import factory
from portlock.guard.base import Action, EnforcementResult, JournalEntry
from portlock.guard.fake import FakeBackend
from portlock.guard.safety import MECHANISM_DRY_RUN, SafeEnforcer, SafetyContext
from portlock.guard.seams import (
    CommandResult,
    FakeCfgMgr,
    FakeCommandRunner,
    FakeDisks,
    FakeRegistry,
)
from portlock.guard.watchonly import (
    MECHANISM_WATCH_ONLY,
    NO_ANTIVIRUS_NOTE,
    WATCH_ONLY_NOTE,
    Posture,
    StandIns,
    WatchOnlyDirPrivacy,
    WatchOnlyEnforcer,
    WatchOnlyTimer,
    detect_posture,
)
from portlock.lockdown.manager import rollback
from portlock.service.daemon import (
    EXIT_ALREADY_RUNNING,
    EXIT_PORT,
    EXIT_STATE_UNUSABLE,
    LOCK_FILE_NAME,
    RUNTIME_FILE_NAME,
    STOP_REQUEST_NAME,
    InstanceLock,
    Runtime,
    build_runtime,
    run,
)
from portlock.service.daemon import EXIT_OK as DAEMON_OK

START = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)
ADMIN = "owner"
PASSWORD = "a throwaway passphrase for tests 42"
CHANNEL = "session-test"
PLATFORMS = ("win32", "linux")
NATIVE = "win32" if sys.platform == "win32" else "linux"
PROGRAM = "python -m portlock"
SRC = Path(__file__).resolve().parents[2] / "src"
ALL_ENGINES = ("heuristics", "hashset", "clamav", "defender")
# How an elevated process names a profile that HOME or USERPROFILE gives it. On POSIX it
# is "the home folder of the account that runs it" only for the home the account database
# gives that account (fourth pass, D7), never for a HOME under tmp_path.
OWN_WORDS = "own folders"


# --- tripwires ------------------------------------------------------------------------------


class Tripwire:
    """Every operating-system seam handed to the real composition reports here."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        self._lock = threading.Lock()

    def hit(self, what: str) -> None:
        with self._lock:
            self.hits.append(what)
        raise AssertionError(f"watch-only reached the operating system: {what}")


class Wired:
    """A seam whose every attribute is a tripwire: touching it at all is recorded."""

    def __init__(self, trip: Tripwire, label: str) -> None:
        object.__setattr__(self, "_trip", trip)
        object.__setattr__(self, "_label", label)

    def __getattr__(self, name: str) -> Any:
        self._trip.hit(f"{self._label}.{name}")


def tripwire_seams(trip: Tripwire) -> factory.SystemSeams:
    def is_admin() -> bool:
        trip.hit("is_admin")
        return False

    return factory.SystemSeams(
        runner=Wired(trip, "runner"),  # type: ignore[arg-type]
        registry=Wired(trip, "registry"),  # type: ignore[arg-type]
        cfgmgr=Wired(trip, "cfgmgr"),  # type: ignore[arg-type]
        disks=Wired(trip, "disks"),  # type: ignore[arg-type]
        sysfs=Wired(trip, "sysfs"),  # type: ignore[arg-type]
        block=Wired(trip, "block"),  # type: ignore[arg-type]
        rules=Wired(trip, "rules"),  # type: ignore[arg-type]
        is_admin=is_admin,
    )


@pytest.fixture
def no_commands(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Replace process creation itself: any program at all is recorded and refused."""
    started: list[Any] = []

    class NoPopen:
        def __init__(self, args: Any, *rest: Any, **kwargs: Any) -> None:
            started.append(args)
            raise AssertionError(f"a program was started: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", NoPopen)
    monkeypatch.setattr(os, "system", lambda command: started.append(command) or 1)
    return started


@pytest.fixture
def no_real_objects(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """A watch-only process must not even *build* the real enforcer, timer or privacy check."""
    built: list[str] = []

    def forbidden(name: str) -> Callable[..., Any]:
        def build(*args: Any, **kwargs: Any) -> Any:
            built.append(name)
            raise AssertionError(f"watch-only built the real {name}")

        return build

    for name in ("create_enforcer", "create_external_timer", "create_dir_privacy", "create_guard"):
        monkeypatch.setattr(factory, name, forbidden(name))
    return built


def make_config(home: Path, mode: Mode = Mode.MONITOR, *, scan: ScanConfig | None = None) -> Config:
    return Config(
        paths=PathsConfig.under(home),
        mode=mode,
        scan=scan if scan is not None else ScanConfig(enabled=False),
        lockdown=LockdownConfig(default_minutes=30, max_minutes=240),
    )


def profile_env(profile: Path) -> dict[str, str]:
    """An environment in which ``profile`` is this user's own profile on both systems."""
    return {
        "USERPROFILE": str(profile),
        "LOCALAPPDATA": str(profile / "AppData" / "Local"),
        "HOME": str(profile),
    }


def audit_types(runtime: Runtime) -> list[str]:
    return [record.event_type for record in runtime.audit_log.iterate()]


@contextlib.contextmanager
def instance_lock(state: Path) -> Iterator[None]:
    """Hold the instance lock the way a running service does."""
    state.mkdir(parents=True, exist_ok=True)
    lock = InstanceLock(state / LOCK_FILE_NAME)
    assert lock.acquire()
    try:
        yield
    finally:
        lock.release()


# --- the real start-up path ------------------------------------------------------------------


def run_daemon(
    config: Config,
    platform: str,
    trip: Tripwire,
    *,
    elevated: bool,
    env: dict[str, str],
    check: Callable[[Runtime, int], None],
    devices: tuple[Any, ...] | None = None,
    api: bool = False,
    tick_seconds: float = 0.01,
) -> int:
    """``daemon.run`` with tripwire seams; ``check`` runs inside the started process."""
    clock = FakeClock(START)
    backend = FakeBackend(
        list(devices) if devices is not None else [flash_drive(), keyboard()],
        clock=clock,
        synchronous=True,
    )
    stop = threading.Event()
    failures: list[BaseException] = []
    announced: list[tuple[str, int]] = []

    def on_started(runtime: Runtime) -> None:
        try:
            check(runtime, announced[0][1])
        except BaseException as exc:
            failures.append(exc)
        finally:
            stop.set()

    code = run(
        config,
        install_signal_handlers=False,
        api_factory=(lambda runtime: ApiServer(runtime, port=0)) if api else None,
        tick_seconds=tick_seconds,
        stop_event=stop,
        clock=clock,
        backend=backend,
        platform=platform,
        system_ids=lambda devices: frozenset(),
        seams=tripwire_seams(trip),
        elevated=elevated,
        env=env,
        on_started=on_started,
        announce=lambda runtime, host, port: announced.append((host, port)),
        program=PROGRAM,
    )
    if failures:
        raise failures[0]
    assert len(announced) == 1
    return code


@pytest.mark.parametrize("platform", PLATFORMS)
def test_an_ordinary_users_start_doctor_and_shutdown_reach_no_seam(
    tmp_path: Path, platform: str, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    trip = Tripwire()
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        service = runtime.service
        assert runtime.watch_only and runtime.stand_ins is not None
        mode = service.get_mode()
        assert mode.effective_mode is Mode.MONITOR and mode.watch_only is True
        assert mode.can_enforce is False
        assert mode.watch_only_reason is not None
        assert "it is not running as administrator" in mode.watch_only_reason
        assert mode.to_dict()["watch_only_reason"] == mode.watch_only_reason
        status = service.status().to_dict()
        assert status["mode"]["watch_only"] is True
        enforcer = status["enforcer"]
        assert enforcer["name"] == "watch-only"
        assert not (
            enforcer["block"]
            or enforcer["read_only"]
            or enforcer["eject"]
            or enforcer["default_deny"]
        )
        assert status["counts"]["connected"] == 2
        assert NO_ANTIVIRUS_NOTE in status["mode"]["notes"]
        service.tick()
        report = service.doctor().to_dict()
        by_id = {item["id"]: item for item in report["checks"]}
        assert by_id["guard.watch_only"]["summary"].startswith("watch-only")
        assert "outside its own folder" in by_id["guard.watch_only"]["summary"]
        assert by_id["guard.block"]["status"] == "info"
        assert "not probed" in by_id["guard.block"]["summary"]
        assert by_id["guard.state_dir"]["status"] == "info"
        # DESIGN 14.28 / item 14: nothing was checked, so nothing may say "private".
        assert by_id["service.privacy"]["status"] == "info"
        assert "not checked" in by_id["service.privacy"]["summary"]
        assert (
            "Antivirus engines are not used in watch-only"
            in (by_id["service.scan_engines"]["detail"])
        )
        seen["types"] = audit_types(runtime)
        assert runtime.stand_ins is not None
        seen["would"] = runtime.stand_ins.would

    code = run_daemon(
        make_config(tmp_path / "home"),
        platform,
        trip,
        elevated=False,
        env=profile_env(tmp_path),
        check=check,
    )
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []
    assert ev.SERVICE_STARTED in seen["types"]
    assert ev.ENFORCEMENT_APPLIED not in seen["types"]
    assert ev.MODE_CHANGED not in seen["types"]
    # The pending flash drive is what PortLock *would* block; nothing was.
    assert ev.ENFORCEMENT_WOULD_APPLY in seen["types"]
    assert not (tmp_path / "home" / "state" / RUNTIME_FILE_NAME).exists()


@pytest.mark.parametrize("platform", PLATFORMS)
def test_a_kill_switch_file_in_watch_only_is_left_alone_and_reaches_no_seam(
    tmp_path: Path, platform: str, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    # Before the database and at every tick a kill-switch file makes PortLock ask whether
    # its directory is private. Watch-only must ask only its inert stand-in, and must not
    # build the real privacy check (icacls on Windows) to answer.
    config = make_config(tmp_path / "home")
    Path(config.paths.config_dir).mkdir(parents=True)
    Path(config.paths.kill_switch_file).write_bytes(b"test\n")
    trip = Tripwire()

    def check(runtime: Runtime, port: int) -> None:
        runtime.service.tick()
        runtime.service.tick()
        runtime.service.doctor()
        assert runtime.service.get_mode().killswitch is False

    code = run_daemon(config, platform, trip, elevated=False, env={}, check=check)
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []
    assert Path(config.paths.kill_switch_file).exists()


@pytest.mark.parametrize("platform", PLATFORMS)
def test_the_three_refusals_leave_nothing_behind(
    tmp_path: Path, platform: str, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    trip = Tripwire()

    def check(runtime: Runtime, port: int) -> None:
        service = runtime.service
        runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
        reason = service.get_mode().watch_only_reason
        assert reason is not None
        before = audit_types(runtime)
        attempts: list[Callable[[], Any]] = [
            lambda: service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL),
            lambda: service.lockdown_engage(
                minutes=30, reason="practice", actor=ADMIN, channel=CHANNEL
            ),
            lambda: service.set_default_deny(True, actor=ADMIN, channel=CHANNEL),
        ]
        for attempt in attempts:
            with pytest.raises(ServiceError) as refused:
                attempt()
            assert refused.value.code == "watch_only"
            assert refused.value.message == reason
        # Turning things off, and monitor mode, stay allowed.
        assert service.set_default_deny(False, actor=ADMIN, channel=CHANNEL).value is False
        service.set_mode(Mode.MONITOR, actor=ADMIN, channel=CHANNEL)
        assert service.pending_changes() == []
        lockdown = service.lockdown_status()
        assert lockdown.state.value == "idle" and lockdown.active is False
        assert runtime.store.get_lockdown().state == "idle"
        settings = service.get_settings().to_dict()
        assert settings["runtime"]["default_deny"] is False
        assert runtime.store.get_setting("default_deny") in (None, False)
        mode = service.get_mode()
        assert (mode.mode, mode.effective_mode) == (Mode.MONITOR, Mode.MONITOR)
        new = audit_types(runtime)[len(before) :]
        assert not [kind for kind in new if kind.startswith(("lockdown.", "change.", "mode."))]
        assert runtime.journal.open_records() == []
        # A change an enforcing run left in the store cannot be confirmed here either.
        runtime.store.add_pending_change(
            PendingChangeRecord(
                id="0123456789abcdef",
                kind="enforce_mode",
                status="awaiting",
                actor=ADMIN,
                channel="0" * 64,
                params={"previous": None},
                preview=(),
                result=None,
                created_at=START,
                deadline_at=START + timedelta(minutes=1),
                timeout_seconds=60,
            )
        )
        for confirm in (service.confirm_change, service.lockdown_confirm):
            with pytest.raises(ServiceError) as refused:
                confirm("0123456789abcdef", actor=ADMIN, channel=CHANNEL)
            assert refused.value.code == "watch_only"
        assert service.get_mode().mode is Mode.MONITOR

    code = run_daemon(
        make_config(tmp_path / "home"),
        platform,
        trip,
        elevated=False,
        env=profile_env(tmp_path),
        check=check,
    )
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []


class Http:
    """The service's API on the loopback address, as the console calls it."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.token: str | None = None

    def __call__(self, method: str, path: str, body: object = None) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            headers: dict[str, str] = {}
            payload: bytes | None = None
            if body is not None:
                payload = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            if self.token is not None:
                headers["Authorization"] = f"Bearer {self.token}"
            connection.request(method, "/api/v1" + path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
        finally:
            connection.close()


def cli_env(home: Path, *, stdin: str = "", **overrides: Any) -> tuple[CliEnv, io.StringIO]:
    out = io.StringIO()
    settings: dict[str, Any] = {
        "environ": {"PORTLOCK_HOME": str(home)},
        "stdin": io.StringIO(stdin),
        "stdout": out,
        "stderr": out,
        "clock": FakeClock(START),
        "is_tty": lambda: False,
        "is_elevated": lambda: False,
        "program": PROGRAM,
    }
    settings.update(overrides)
    return CliEnv(**settings), out


def test_the_console_contract_of_a_watch_only_service(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    trip = Tripwire()
    volume = tmp_path / "volume"
    volume.mkdir()
    (volume / "notes.txt").write_text("nothing to see\n", encoding="utf-8")
    home = tmp_path / "home"
    drive = mounted_flash_drive(str(volume), instance_id="test/1-9", bus_path="1-9")
    config = make_config(home, scan=ScanConfig(enabled=True, engines=ALL_ENGINES))
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        call = Http(port)
        # Before init: the command line names the program the user started.
        env, out = cli_env(home)
        assert main(["status"], env=env) == EXIT_OK
        assert f"no administrator exists yet: run '{PROGRAM} init'" in out.getvalue()

        runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
        status, data = call("POST", "/auth/login", {"username": ADMIN, "password": PASSWORD})
        assert status == 200
        call.token = str(data["token"])

        status, mode = call("GET", "/mode")
        assert status == 200
        reason = mode["watch_only_reason"]
        assert mode["watch_only"] is True and mode["can_enforce"] is False
        assert isinstance(reason, str) and reason.startswith("PortLock cannot change")

        for method, path, body in (
            ("PUT", "/mode", {"mode": "enforce"}),
            ("POST", "/lockdown/engage", {"minutes": 30}),
            ("PUT", "/default-deny", {"enabled": True}),
        ):
            status, data = call(method, path, body)
            assert status == 409, (path, data)
            assert data["error"]["code"] == "watch_only"
            assert data["error"]["message"] == reason
        assert call("PUT", "/default-deny", {"enabled": False})[0] == 200
        status, lockdown = call("GET", "/lockdown")
        assert (lockdown["state"], lockdown["active"]) == ("idle", False)
        assert call("GET", "/changes")[1]["changes"] == []

        status, info = call("GET", "/status")
        assert info["mode"]["watch_only_reason"] == reason
        enforcer = info["enforcer"]
        assert enforcer["name"] == "watch-only"
        assert not any(enforcer[key] for key in ("block", "read_only", "eject", "default_deny"))

        status, listing = call("GET", "/devices")
        outcomes = {item["enforcement"]["outcome"] for item in listing["devices"]}
        assert outcomes <= {"not_needed", "would_apply"} and "would_apply" in outcomes
        assert {item["enforcement"]["os_state"] for item in listing["devices"]} == {"open"}

        # A scan request starts no program: the antivirus engines are not even built.
        assert runtime.service._scanner is not None
        assert runtime.service._scanner.engines == ()  # type: ignore[attr-defined]
        connection = next(
            item["connection_id"] for item in listing["devices"] if item["device"]["volumes"]
        )
        status, data = call("POST", "/scans", {"connection_id": connection})
        assert status == 202, data
        runtime.service.run_scans()

        # status --detail says watch-only, with the reason (item 18).
        env, out = cli_env(home, stdin=PASSWORD + "\n", environ={"PORTLOCK_HOME": str(home)})
        code = main(["--user", ADMIN, "--password-stdin", "status", "--detail"], env=env)
        seen["status"] = (code, out.getvalue())

    code = run_daemon(
        config,
        NATIVE,
        trip,
        elevated=False,
        env=profile_env(tmp_path),
        check=check,
        devices=(flash_drive(), keyboard(), drive),
        api=True,
    )
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []
    status_code, text = seen["status"]
    assert status_code == EXIT_OK, text
    assert "WATCH-ONLY" in text and "why: PortLock cannot change this computer" in text
    assert PASSWORD not in text


def test_enforce_in_the_configuration_file_still_starts_watch_only(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    trip = Tripwire()

    def check(runtime: Runtime, port: int) -> None:
        mode = runtime.service.get_mode()
        assert mode.mode is Mode.ENFORCE and mode.effective_mode is Mode.MONITOR
        assert mode.watch_only and not mode.can_enforce
        connections = runtime.service.list_connections()
        assert {view.to_dict()["enforcement"]["outcome"] for view in connections} <= {
            "not_needed",
            "would_apply",
        }

    code = run_daemon(
        make_config(tmp_path / "home", mode=Mode.ENFORCE),
        NATIVE,
        trip,
        elevated=False,
        env={},
        check=check,
    )
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []


def test_an_elevated_process_with_a_per_user_home_is_watch_only(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    trip = Tripwire()

    def check(runtime: Runtime, port: int) -> None:
        assert runtime.posture is not None and runtime.posture.elevated
        assert runtime.watch_only
        reason = runtime.service.get_mode().watch_only_reason
        # An elevated process in its own profile: on POSIX that is root's own home (C3).
        assert reason is not None and OWN_WORDS in reason
        assert "administrator" not in reason
        assert runtime.service.status().to_dict()["enforcer"]["privileged"] is True

    code = run_daemon(
        make_config(tmp_path / "profile" / "pl"),
        NATIVE,
        trip,
        elevated=True,
        env=profile_env(tmp_path / "profile"),
        check=check,
    )
    assert code == DAEMON_OK
    assert trip.hits == [] and no_commands == [] and no_real_objects == []


def windows_seams() -> tuple[factory.SystemSeams, FakeCommandRunner, FakeRegistry]:
    runner = FakeCommandRunner(CommandResult(0, "", ""))
    registry = FakeRegistry()
    seams = factory.SystemSeams(
        runner=runner,
        registry=registry,
        cfgmgr=FakeCfgMgr(),
        disks=FakeDisks(),
        is_admin=lambda: True,
    )
    return seams, runner, registry


def programs(runner: FakeCommandRunner) -> list[str]:
    return [Path(argv[0].replace("\\", "/")).name.lower() for argv in runner.commands()]


def test_an_elevated_system_wide_process_in_monitor_mode_enforces_as_before(
    tmp_path: Path, no_commands: list[Any]
) -> None:
    # The composition of commit d781c2a: the real Windows objects on recording fakes.
    seams, runner, registry = windows_seams()
    clock = FakeClock(START)
    runtime = build_runtime(
        make_config(tmp_path / "home"),
        clock=clock,
        backend=FakeBackend([keyboard()], clock=clock, synchronous=True),
        platform="win32",
        system_ids=lambda devices: frozenset(),
        seams=seams,
        posture=Posture(elevated=True, system_wide=True),
    )
    try:
        assert runtime.posture is not None and not runtime.watch_only
        assert runtime.stand_ins is None
        assert type(runtime.enforcer).__name__ == "WindowsEnforcer"
        runtime.service.start(threads=False)
        # DESIGN 14.18: the directories are made private at every start, monitor or not.
        assert "icacls.exe" in programs(runner)
        mode = runtime.service.get_mode()
        assert mode.effective_mode is Mode.MONITOR
        assert mode.watch_only is False and mode.watch_only_reason is None
        assert mode.to_dict()["watch_only_reason"] is None

        # Announced as monitor mode, never as WATCH-ONLY (item 9).
        out = io.StringIO()
        cli_module._Cli(CliEnv(stdout=out, program=PROGRAM))._announce(runtime, "127.0.0.1", 0)
        assert "monitor mode" in out.getvalue() and "WATCH-ONLY" not in out.getvalue()
        report = runtime.service.doctor().to_dict()
        by_id = {item["id"]: item for item in report["checks"]}
        assert by_id["guard.watch_only"]["summary"].startswith("not watch-only")
        assert "not probed" not in by_id["guard.block"]["summary"]

        # DESIGN 11: an engaged lockdown blocks for real in monitor mode, with its timer.
        runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
        assert registry.snapshot() == {}
        engaged = runtime.service.lockdown_engage(
            minutes=30, reason="practice", actor=ADMIN, channel=CHANNEL
        )
        runtime.service.lockdown_confirm(engaged.value.change.id, actor=ADMIN, channel=CHANNEL)
        assert runtime.service.lockdown_status().active is True
        assert registry.snapshot() != {}  # default-deny reached the registry seam
        assert "schtasks.exe" in programs(runner)  # the dead-man timer was armed
        types_ = audit_types(runtime)
        assert ev.ENFORCEMENT_APPLIED in types_
    finally:
        runtime.service.stop()
        runtime.close()
    assert no_commands == []


def test_the_banner_says_watch_only_only_when_it_is() -> None:
    out = io.StringIO()
    announcer = cli_module._Cli(CliEnv(stdout=out, program=PROGRAM))._announce

    class Accounts:
        def __init__(self, users: bool) -> None:
            self.users = users

        def has_users(self) -> bool:
            return self.users

    def runtime(watch_only: bool, users: bool) -> Any:
        mode = types.SimpleNamespace(effective_mode=Mode.MONITOR)
        service = types.SimpleNamespace(get_mode=lambda: mode)
        return types.SimpleNamespace(
            watch_only=watch_only, service=service, accounts=Accounts(users)
        )

    announcer(runtime(True, True), "127.0.0.1", 47613)
    text = out.getvalue()
    assert "WATCH-ONLY" in text and "outside its own folder" in text
    assert "http://127.0.0.1:47613/" in text and f"{PROGRAM} stop" in text
    assert "Sign in with the administrator name" in text
    out.truncate(0)
    out.seek(0)
    announcer(runtime(False, True), "::1", 47613)
    text = out.getvalue()
    assert "WATCH-ONLY" not in text and "running in monitor mode" in text
    assert "http://[::1]:47613/" in text
    out.truncate(0)
    out.seek(0)
    # Item 15: without an administrator account the next step is init, not "sign in".
    announcer(runtime(True, False), "127.0.0.1", 47613)
    text = out.getvalue()
    assert f"run '{PROGRAM} init'" in text and "you chose at init" not in text


# --- the posture -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("elevated", "system_wide", "watch_only"),
    [(False, False, True), (False, True, True), (True, False, True), (True, True, False)],
)
def test_the_posture_rule(elevated: bool, system_wide: bool, watch_only: bool) -> None:
    posture = Posture(elevated=elevated, system_wide=system_wide)
    assert posture.watch_only is watch_only
    assert (posture.refusal() is None) is (not watch_only)
    assert posture.to_dict()["watch_only"] is watch_only


def test_the_reason_says_what_portlock_cannot_do_and_why() -> None:
    both = Posture(elevated=False, system_wide=False).refusal()
    assert both == (
        "PortLock cannot change this computer: it is not running as administrator, and its "
        "files are in this user's own folders, which every program this user runs could "
        "change. It stays watch-only: it shows and records, and blocks nothing."
    )
    only = Posture(elevated=True, system_wide=False).refusal()
    assert only is not None and "administrator" not in only and "own folders" in only
    assert "enforce mode" not in both
    assert "outside its own folder" in WATCH_ONLY_NOTE


def test_the_posture_ignores_the_mode(tmp_path: Path) -> None:
    for mode in Mode:
        config = make_config(tmp_path / "home", mode=mode)
        system = detect_posture(config, elevated=True, env={}, platform=NATIVE)
        assert system.system_wide and not system.watch_only
        ordinary = detect_posture(config, elevated=False, env={}, platform=NATIVE)
        assert ordinary.watch_only


def test_process_elevated_asks_the_operating_system(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(privilege, "sys", types.SimpleNamespace(platform="linux"))
    monkeypatch.setattr(privilege, "os", types.SimpleNamespace(geteuid=lambda: 1000))
    assert privilege.process_elevated() is False
    monkeypatch.setattr(privilege, "os", types.SimpleNamespace(geteuid=lambda: 0))
    assert privilege.process_elevated() is True
    monkeypatch.setattr(privilege, "os", types.SimpleNamespace())
    assert privilege.process_elevated() is False

    answers: list[int] = []

    class Shell32:
        def IsUserAnAdmin(self) -> int:
            return answers[-1]

    def loader(name: str, **kwargs: Any) -> Shell32:
        assert name == "shell32.dll"
        return Shell32()

    monkeypatch.setattr(privilege, "sys", types.SimpleNamespace(platform="win32"))
    monkeypatch.setattr(privilege, "ctypes", types.SimpleNamespace(WinDLL=loader))
    answers.append(0)
    assert privilege.process_elevated() is False
    answers.append(1)
    assert privilege.process_elevated() is True

    def broken(name: str, **kwargs: Any) -> Any:
        raise OSError("no shell32 here")

    monkeypatch.setattr(privilege, "ctypes", types.SimpleNamespace(WinDLL=broken))
    assert privilege.process_elevated() is False


# --- scanning in watch-only --------------------------------------------------------------------


def test_the_scanner_has_no_antivirus_engine_in_watch_only(
    tmp_path: Path, no_commands: list[Any]
) -> None:
    clock = FakeClock(START)
    config = make_config(tmp_path / "home", scan=ScanConfig(enabled=True, engines=ALL_ENGINES))
    runtime = build_runtime(
        config,
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        posture=Posture(elevated=False, system_wide=True),
    )
    try:
        scanner = runtime.service._scanner
        assert scanner is not None and scanner.engines == ()  # type: ignore[attr-defined]
    finally:
        runtime.close()
    # Only the antivirus engines go: with them alone there is no scanner at all.
    only_av = make_config(
        tmp_path / "home2", scan=ScanConfig(enabled=True, engines=("clamav", "defender"))
    )
    runtime = build_runtime(
        only_av,
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        posture=Posture(elevated=False, system_wide=False),
    )
    try:
        assert runtime.service._scanner is None
    finally:
        runtime.close()
    # An enforcing process keeps the engines it was configured with.
    seams, _runner, _registry = windows_seams()
    runtime = build_runtime(
        make_config(tmp_path / "home3", scan=ScanConfig(enabled=True, engines=ALL_ENGINES)),
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        platform="win32",
        system_ids=lambda devices: frozenset(),
        seams=seams,
        posture=Posture(elevated=True, system_wide=True),
    )
    try:
        engines = runtime.service._scanner.engines  # type: ignore[union-attr]
        assert {engine.name for engine in engines} == {"clamav", "defender"}
    finally:
        runtime.close()
    assert no_commands == []


def test_the_antivirus_note_is_the_same_in_the_service_and_the_guard() -> None:
    assert service_module._NO_ANTIVIRUS_NOTE == NO_ANTIVIRUS_NOTE


# --- leftovers of an enforcing run ---------------------------------------------------------------


def leftover_hold(config: Config) -> bytes:
    state = Path(config.paths.state_dir)
    state.mkdir(parents=True)
    journal = RecoveryJournal(state / JOURNAL_FILE_NAME, clock=FakeClock(START))
    journal.add_hold(scope="USB\\VID_1209&PID_0001\\TEST0001", fingerprint=None)
    return (state / JOURNAL_FILE_NAME).read_bytes()


def leftover_lockdown(config: Config) -> bytes:
    Path(config.paths.state_dir).mkdir(parents=True)
    db = Database(config.paths.database_file)
    try:
        StateStore(db, clock=FakeClock(START)).save_lockdown(
            LockdownRecord(
                state="active",
                engaged_at=START,
                engaged_by=ADMIN,
                reason="left by an enforcing run",
                minutes=30,
                expires_at=START + timedelta(minutes=30),
                remaining_seconds=1800,
                checkpoint_at=START,
            )
        )
    finally:
        db.close()
    journal = Path(config.paths.state_dir) / JOURNAL_FILE_NAME
    return journal.read_bytes() if journal.exists() else b""


@pytest.mark.parametrize("leave", [leftover_hold, leftover_lockdown])
def test_a_watch_only_start_refuses_what_an_enforcing_run_left(
    tmp_path: Path,
    leave: Callable[[Config], bytes],
    capsys: pytest.CaptureFixture[str],
    no_commands: list[Any],
    no_real_objects: list[str],
) -> None:
    config = make_config(tmp_path / "home")
    journal_before = leave(config)
    trip = Tripwire()

    def check(runtime: Runtime, port: int) -> None:
        raise AssertionError("a watch-only service started over real leftovers")

    code = run(
        config,
        install_signal_handlers=False,
        clock=FakeClock(START),
        backend=FakeBackend([flash_drive()], clock=FakeClock(START), synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        seams=tripwire_seams(trip),
        elevated=False,
        env={},
        on_started=lambda runtime: check(runtime, 0),
        program=PROGRAM,
    )
    assert code == EXIT_STATE_UNUSABLE
    err = capsys.readouterr().err
    assert str(config.paths.state_dir) in err
    assert "enforcing PortLock left in place" in err and "neither enforce nor undo" in err
    assert f"run '{PROGRAM} recover' as administrator" in err
    journal = Path(config.paths.state_dir) / JOURNAL_FILE_NAME
    assert (journal.read_bytes() if journal.exists() else b"") == journal_before
    assert trip.hits == [] and no_commands == [] and no_real_objects == []


def test_a_per_user_home_with_leftovers_never_invites_recover(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_real_objects: list[str]
) -> None:
    config = make_config(tmp_path / "home")
    before = leftover_hold(config)
    code = run(
        config,
        install_signal_handlers=False,
        clock=FakeClock(START),
        backend=FakeBackend([], clock=FakeClock(START), synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        seams=tripwire_seams(Tripwire()),
        elevated=False,
        env=profile_env(tmp_path),
        program=PROGRAM,
    )
    assert code == EXIT_STATE_UNUSABLE
    err = capsys.readouterr().err
    assert "recover' as administrator" not in err and f"{PROGRAM} recover" not in err
    assert "move the folder aside" in err
    assert (Path(config.paths.state_dir) / JOURNAL_FILE_NAME).read_bytes() == before


# --- a stand-in never closes or forgets a real change --------------------------------------------


def test_a_stand_in_result_is_never_performed() -> None:
    assert EnforcementResult(Action.UNBLOCK, ok=True, mechanism="cfgmgr").performed
    assert not EnforcementResult(Action.UNBLOCK, ok=False, mechanism="cfgmgr").performed
    assert not EnforcementResult(Action.UNBLOCK, ok=True, mechanism=MECHANISM_DRY_RUN).performed
    assert not EnforcementResult(Action.RESTORE, ok=True, mechanism=MECHANISM_WATCH_ONLY).performed


def test_the_service_never_closes_a_hold_on_a_stand_ins_word(tmp_path: Path) -> None:
    config = make_config(tmp_path / "home")
    device = flash_drive()
    state = Path(config.paths.state_dir)
    state.mkdir(parents=True)
    clock = FakeClock(START)
    RecoveryJournal(state / JOURNAL_FILE_NAME, clock=clock).add_hold(
        scope=device.instance_id, fingerprint=None
    )
    stand_ins = StandIns.create(elevated=False)
    runtime = build_runtime(
        config,
        clock=clock,
        backend=FakeBackend([device], clock=clock, synchronous=True),
        enforcer=stand_ins.enforcer,
        timer=stand_ins.timer,
        dir_privacy=stand_ins.dir_privacy,
        system_ids=lambda devices: frozenset(),
    )
    try:
        runtime.service.start(threads=False)
        runtime.service.reconcile("test")
        # The stand-in was asked to unblock (it would), but the device stays held.
        assert any(item.startswith("would unblock") for item in stand_ins.would)
        holds = runtime.journal.open_records(scope=device.instance_id)
        assert len(holds) == 1 and holds[0].is_hold
    finally:
        runtime.service.stop()
        runtime.close()
    assert len(RecoveryJournal(state / JOURNAL_FILE_NAME, clock=clock).open_records()) == 1


@pytest.mark.parametrize("dry_run", [False, True])
def test_rollback_closes_no_record_on_a_stand_ins_word(tmp_path: Path, dry_run: bool) -> None:
    clock = FakeClock(START)
    journal = RecoveryJournal(tmp_path / JOURNAL_FILE_NAME, clock=clock)
    device = flash_drive()
    journal.add_hold(scope=device.instance_id, fingerprint=None)
    entry = JournalEntry("win_devnode", "USB\\VID_1209&PID_0001\\TEST", "enabled", "disabled")
    with journal.recording(scope="global", action=Action.BLOCK, fingerprint=None):
        journal.write_ahead(entry)
        journal.record(
            EnforcementResult(
                Action.BLOCK, ok=True, mechanism="cfgmgr", changed=True, undo=(entry,)
            )
        )
    assert len(journal.open_records()) == 2
    live = SafeEnforcer(WatchOnlyEnforcer(elevated=True), lambda: SafetyContext(), dry_run=dry_run)
    report = rollback(journal, live, [device], reason="test")
    assert report.restored == 0 and report.released == 0
    assert len(report.failed) == 2 and report.remaining == 2
    assert len(RecoveryJournal(tmp_path / JOURNAL_FILE_NAME, clock=clock).open_records()) == 2


# --- the stand-ins ------------------------------------------------------------------------


def test_the_watch_only_enforcer_records_would_and_never_claims_a_restore() -> None:
    enforcer = WatchOnlyEnforcer(elevated=False)
    device = flash_drive()
    for result in (
        enforcer.block(device),
        enforcer.unblock(device),
        enforcer.eject(device),
        enforcer.set_read_only(device, True),
        enforcer.set_read_only(device, False),
        enforcer.set_default_deny(True),
        enforcer.set_baseline_read_only(True),
        enforcer.restore([]),
    ):
        assert result.ok and result.mechanism == MECHANISM_DRY_RUN and not result.changed
        assert not result.performed
        assert result.detail.startswith("watch-only: would")
    entry = JournalEntry("win_devnode", "USB\\VID_1209&PID_0001\\TEST", "enabled", "disabled")
    restored = enforcer.restore([entry])
    assert restored.action is Action.RESTORE and restored.ok is False
    assert restored.mechanism == MECHANISM_WATCH_ONLY
    # No stand-in invites an elevated recover: for a per-user home it would be refused.
    assert "recover" not in str(restored.error) and "recover" not in restored.detail
    caps = enforcer.capabilities()
    assert not (caps.block or caps.read_only or caps.eject or caps.default_deny)
    assert caps.privileged is False and enforcer.mechanisms() == ()
    assert enforcer.log.total == 9


def test_the_timer_and_privacy_stand_ins_change_no_permission(tmp_path: Path) -> None:
    timer = WatchOnlyTimer()
    assert timer.inert is True
    timer.arm("deadman", START + timedelta(minutes=5), ["portlock", "recover"])
    timer.cancel("deadman")
    assert timer.is_armed("deadman") is False
    with pytest.raises(ValueError):
        timer.arm("Bad Name", START, ["x"])
    privacy = WatchOnlyDirPrivacy()
    target = tmp_path / "new" / "state"
    privacy.ensure_private(target)
    assert target.is_dir()
    report = privacy.check(target)
    assert report.private is False and "not checked" in report.problems[0]


def test_stand_ins_share_one_log() -> None:
    stand_ins = StandIns.create(elevated=True)
    stand_ins.enforcer.block(flash_drive())
    stand_ins.timer.arm("deadman", START, ["portlock"])
    stand_ins.dir_privacy.check(".")
    assert len(stand_ins.would) == 2 and stand_ins.enforcer.capabilities().privileged


# --- system-wide or not: other spellings of the profile -------------------------------------------


WIN_PROFILE = {
    "USERPROFILE": "C:\\Users\\Alice",
    "LOCALAPPDATA": "C:\\Users\\Alice\\AppData\\Local",
}


def win_paths(state: str, config: str | None = None) -> PathsConfig:
    return PathsConfig(state_dir=Path(state), config_dir=Path(config or state))


@pytest.mark.parametrize(
    "state",
    [
        "C:\\Users\\Alice\\pl",
        "c:\\USERS\\alice\\pl",
        "C:/Users/Alice/pl",
        "C:\\ProgramData\\..\\Users\\Alice\\pl",
        "\\\\?\\C:\\ProgramData\\PortLock",
        "\\\\.\\C:\\ProgramData\\PortLock",
        "\\\\localhost\\C$\\ProgramData\\PortLock",
        "//server/share/PortLock",
        "ProgramData\\PortLock",
        "C:ProgramData\\PortLock",
    ],
)
def test_another_spelling_of_the_profile_is_not_system_wide_on_windows(state: str) -> None:
    assert paths_per_user(win_paths(state), platform="win32", env=WIN_PROFILE)


def test_a_system_wide_location_is_recognised_on_windows() -> None:
    paths = win_paths("C:\\ProgramData\\PortLock")
    assert not paths_per_user(paths, platform="win32", env=WIN_PROFILE)
    # With nothing in the environment only the registry (Windows itself; a fixed fake in
    # the unit tests) says where the profiles are; elsewhere nothing does, which fails
    # closed (fourth pass, D2).
    assert paths_per_user(paths, platform="win32", env={}) is (sys.platform != "win32")
    assert not paths_per_user(paths, platform="win32", env={"SystemDrive": "C:"})
    # The configuration directory counts as much as the state directory.
    mixed = win_paths("C:\\ProgramData\\PortLock", "C:\\Users\\Alice\\cfg")
    assert paths_per_user(mixed, platform="win32", env=WIN_PROFILE)


@pytest.mark.parametrize(
    "env",
    [
        {"USERPROFILE": ""},
        {"USERPROFILE": "   "},
        {"USERPROFILE": "Users\\Alice"},
        # A UNC path to this computer is another spelling of a local folder (C1).
        {"APPDATA": "\\\\localhost\\C$\\Users\\Alice"},
        {"userprofile": "relative"},
    ],
)
def test_a_broken_profile_variable_fails_closed_on_windows(env: dict[str, str]) -> None:
    assert paths_per_user(win_paths("C:\\ProgramData\\PortLock"), platform="win32", env=env)


def test_posix_spellings_and_failures() -> None:
    def per_user(state: str, env: dict[str, str]) -> bool:
        paths = PathsConfig(state_dir=Path(state), config_dir=Path("/etc/portlock"))
        return paths_per_user(paths, platform="linux", env=env)

    home = {"HOME": "/home/alice"}
    assert per_user("/home/alice/.local/state/portlock", home)
    assert per_user("/var/lib/../../home/alice/pl", home)
    assert per_user("/home/alice", home)
    assert not per_user("/var/lib/portlock", home)
    # Another user's home is not system-wide either (C2).
    assert per_user("/home/alice2/pl", home)
    assert not per_user("/var/lib/portlock", {})
    assert not per_user("/var/lib/portlock", {"HOME": "/"})
    assert per_user("/var/lib/portlock", {"HOME": ""})
    assert per_user("/var/lib/portlock", {"HOME": "alice"})
    assert per_user("relative/state", {})


def _short_name(path: Path) -> str | None:
    """The 8.3 short name of an existing path, or ``None`` if the volume makes none."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None
    buffer = ctypes.create_unicode_buffer(1024)
    length = windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    if not length or buffer.value.lower() == str(path).lower():
        return None
    return str(buffer.value)


def _link(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))  # type: ignore[attr-defined]
    else:
        os.symlink(target, link, target_is_directory=True)


def test_links_and_aliases_on_this_system_resolve_to_the_profile(tmp_path: Path) -> None:
    # The profile lies in a profiles root of its own: everything under the parent of
    # USERPROFILE is some user's profile (C2), so "system" must be outside it.
    profile = tmp_path / "Users" / "Profile Of A Person"
    (profile / "pl").mkdir(parents=True)
    system = tmp_path / "system"
    system.mkdir()
    env = {"HOME": str(profile), "USERPROFILE": str(profile)}

    def per_user(state: Path | str) -> bool:
        paths = PathsConfig(state_dir=Path(state), config_dir=system)
        return paths_per_user(paths, platform=NATIVE, env=env)

    assert not per_user(system / "state")
    assert per_user(profile / "pl")
    assert per_user(f"{system}{os.sep}..{os.sep}Users{os.sep}{profile.name}{os.sep}pl")
    # A junction (Windows) or symbolic link (POSIX) from a system-looking place.
    _link(system / "looks-system-wide", profile)
    assert per_user(system / "looks-system-wide" / "pl")
    # The profile variable itself spelled through the link resolves too.
    env["HOME"] = env["USERPROFILE"] = str(system / "looks-system-wide")
    assert per_user(profile / "pl")
    env["HOME"] = env["USERPROFILE"] = str(profile)
    short = _short_name(profile)
    if short is not None:
        assert per_user(Path(short) / "pl")
        env["USERPROFILE"] = short
        assert per_user(profile / "pl")


# --- per-user default directories ----------------------------------------------------------------


def test_an_ordinary_user_on_windows_gets_localappdata() -> None:
    env = {"LOCALAPPDATA": "C:\\Users\\someone\\AppData\\Local", "USERPROFILE": "C:\\Users\\x"}
    paths = default_config("win32", env, elevated=False).paths
    state = str(paths.state_dir).replace("/", "\\").lower()
    assert state.endswith("appdata\\local\\portlock\\state")
    config = str(paths.config_dir).replace("/", "\\").lower()
    assert config.endswith("appdata\\local\\portlock\\config")


def test_windows_falls_back_to_the_profile_and_refuses_without_one() -> None:
    paths = default_config("win32", {"USERPROFILE": "C:\\Users\\x"}, elevated=False).paths
    assert "appdata" in str(paths.state_dir).lower()
    with pytest.raises(ConfigError, match="PORTLOCK_HOME"):
        default_config("win32", {}, elevated=False)


def test_an_ordinary_user_on_linux_gets_the_xdg_directories() -> None:
    paths = default_config("linux", {"HOME": "/home/someone"}, elevated=False).paths
    assert paths.state_dir.as_posix() == "/home/someone/.local/state/portlock"
    assert paths.config_dir.as_posix() == "/home/someone/.config/portlock"
    assert paths_per_user(paths, platform="linux", env={"HOME": "/home/someone"})
    custom = default_config(
        "linux",
        {"HOME": "/home/someone", "XDG_STATE_HOME": "/srv/s", "XDG_CONFIG_HOME": "relative"},
        elevated=False,
    ).paths
    assert custom.state_dir.as_posix() == "/srv/s/portlock"
    # A relative XDG directory is invalid by the specification and ignored.
    assert custom.config_dir.as_posix() == "/home/someone/.config/portlock"
    with pytest.raises(ConfigError):
        default_config("linux", {}, elevated=False)


def test_portlock_home_and_an_elevated_process_keep_their_directories() -> None:
    home = default_config("linux", {"PORTLOCK_HOME": "/opt/pl", "HOME": "/h"}, elevated=False)
    assert home.paths.state_dir.as_posix() == "/opt/pl/state"
    system = default_config("linux", {"HOME": "/home/someone"}, elevated=True)
    assert system.paths.state_dir.as_posix() == "/var/lib/portlock"
    assert not paths_per_user(system.paths, platform="linux", env={"HOME": "/home/someone"})


def test_loading_a_config_file_uses_the_per_user_defaults_for_what_it_omits(
    tmp_path: Path,
) -> None:
    source = tmp_path / "portlock.toml"
    source.write_text('mode = "monitor"\n', encoding="utf-8")
    loaded = load_config(source, env={"HOME": "/home/someone"}, platform="linux", elevated=False)
    assert loaded.paths.state_dir.as_posix() == "/home/someone/.local/state/portlock"


# --- the command line ----------------------------------------------------------------------------


def cli(
    tmp_path: Path, *argv: str, stdin: str = "", home: bool = True, **env: Any
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    environ = dict(profile_env(tmp_path))
    if home:
        environ["PORTLOCK_HOME"] = str(tmp_path / "home")
    environ.update(env.pop("extra_environ", {}))
    settings: dict[str, Any] = {
        "environ": environ,
        "stdin": io.StringIO(stdin),
        "stdout": out,
        "stderr": err,
        "clock": FakeClock(START),
        "is_tty": lambda: False,
        "is_elevated": lambda: False,
        "program": PROGRAM,
    }
    settings.update(env)
    code = main(list(argv), env=CliEnv(**settings))
    return code, out.getvalue(), err.getvalue()


def init(tmp_path: Path, password: str = PASSWORD, **env: Any) -> tuple[int, str, str]:
    return cli(
        tmp_path, "init", "--username", ADMIN, "--password-stdin", stdin=password + "\n", **env
    )


def test_init_for_an_ordinary_user_says_watch_only_and_how_to_start(tmp_path: Path) -> None:
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "watch-only" in out and "outside its own folder" in out
    assert f"{PROGRAM} run" in out and "enroll" not in out
    assert f"Later: {PROGRAM} audit verify" in out
    assert PASSWORD not in out and PASSWORD not in err


def test_the_command_line_uses_per_user_defaults_without_portlock_home(tmp_path: Path) -> None:
    # No PORTLOCK_HOME: an ordinary user's init must land in the per-user directories.
    code, out, err = init(tmp_path, home=False)
    assert code == EXIT_OK, err
    if sys.platform == "win32":
        state = tmp_path / "AppData" / "Local" / "PortLock" / "state"
    else:
        state = tmp_path / ".local" / "state" / "portlock"
    assert (state / "portlock.db").is_file()
    assert f"State: {state}" in out


def test_a_refused_password_creates_nothing_and_says_what_to_do(tmp_path: Path) -> None:
    code, _out, err = init(tmp_path, password="short")
    assert code == EXIT_FAILED
    assert "nothing was changed" in err and f"Run '{PROGRAM} init' again" in err
    assert not (tmp_path / "home").exists()
    # Three refused tries at a terminal end the same way.
    answers = iter(["short", "also short", "again short"])
    code, _out, err = cli(
        tmp_path, "init", "--username", ADMIN, is_tty=lambda: True, getpass=lambda p: next(answers)
    )
    assert code == EXIT_FAILED and "no acceptable password was given" in err
    assert f"Run '{PROGRAM} init' again" in err
    assert not (tmp_path / "home").exists()
    # The next init is a first init: the audit key is shown.
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "Audit verification key" in out and "No audit verification key" not in out


def run_before_init(home: Path) -> Path:
    """``run`` before ``init``: a configuration naming a key store, and a service that made
    it (its initial key went nowhere) and wrote records with it. Returns the key path."""
    key = home / "state" / "audit.key"
    config = dataclasses.replace(make_config(home), audit=AuditConfig(hmac_key_file=key, sinks=()))
    Path(config.paths.config_dir).mkdir(parents=True)
    config.paths.config_file.write_text(config_to_toml(config), encoding="utf-8")
    clock = FakeClock(START)
    stand_ins = StandIns.create(elevated=False)
    runtime = build_runtime(
        config,
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        enforcer=stand_ins.enforcer,
        timer=stand_ins.timer,
        dir_privacy=stand_ins.dir_privacy,
        system_ids=lambda devices: frozenset(),
    )
    try:
        runtime.service.start(threads=False)
        runtime.service.stop()
    finally:
        runtime.close()
    assert key.is_file()
    return key


def shown_key(out: str) -> str:
    lines = out.splitlines()
    return lines[lines.index("Audit verification key. Keep it offline: it is shown only now.") + 1]


def test_a_key_store_nobody_was_shown_is_set_aside_and_replaced(tmp_path: Path) -> None:
    key = run_before_init(tmp_path / "home")
    old_key = key.read_bytes()
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "Audit verification key" in out and "was moved to" in out
    state = key.parent
    aside = [path for path in state.iterdir() if path.name.startswith("audit.key.unused-")]
    assert len(aside) == 1 and aside[0].read_bytes() == old_key
    assert key.read_bytes() != old_key
    # The replacement is audited, and the key that was shown verifies the log offline.
    db = Database(state / "portlock.db")
    try:
        rows = db.query("SELECT data FROM audit_log WHERE event_type = 'config.changed'")
    finally:
        db.close()
    assert any(json.loads(row["data"])["key"] == "audit.key_store" for row in rows)
    key_file = tmp_path / "shown.key"
    key_file.write_text(shown_key(out), encoding="utf-8")
    code, out, err = cli(tmp_path, "audit", "verify", "--offline", "--key-file", str(key_file))
    assert code == EXIT_OK, out + err


def test_init_will_not_replace_a_key_store_a_running_service_holds(tmp_path: Path) -> None:
    assert init(tmp_path)[0] == EXIT_OK
    state = tmp_path / "home" / "state"
    db = Database(state / "portlock.db")
    try:
        db.execute("DELETE FROM auth_users")
    finally:
        db.close()
    asked: list[str] = []
    with instance_lock(state):
        code, _out, err = cli(
            tmp_path,
            "init",
            "--username",
            ADMIN,
            is_tty=lambda: True,
            getpass=lambda prompt: asked.append(prompt) or PASSWORD,
        )
    assert code == EXIT_FAILED and f"'{PROGRAM} stop'" in err
    assert asked == []  # refused before asking for anything


def system_wide_elsewhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> PathsConfig:
    """A system-wide installation that exists, wherever the test runs."""
    system = PathsConfig.under(tmp_path / "system-wide")
    Path(system.state_dir).mkdir(parents=True)
    original = cli_module.default_config

    def fake_default(platform: str | None = None, env: Any = None, *, elevated: bool = True) -> Any:
        if elevated:
            return Config(paths=system)
        return original(platform, env, elevated=elevated)

    monkeypatch.setattr(cli_module, "default_config", fake_default)
    return system


def test_an_ordinary_user_is_told_about_a_system_wide_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = system_wide_elsewhere(monkeypatch, tmp_path)
    asked: list[str] = []

    def getpass(prompt: str) -> str:
        asked.append(prompt)
        return PASSWORD

    out = io.StringIO()
    settings: dict[str, Any] = {
        "environ": {"PORTLOCK_HOME": str(tmp_path / "home")},
        "stdout": out,
        "stderr": io.StringIO(),
        "clock": FakeClock(START),
        "is_tty": lambda: True,
        "getpass": getpass,
        "is_elevated": lambda: False,
        "program": PROGRAM,
    }

    def on_getpass(prompt: str) -> str:
        # The notice was printed before anything was asked.
        assert "system-wide PortLock installation" in out.getvalue()
        return getpass(prompt)

    settings["getpass"] = on_getpass
    code = main(["init", "--username", ADMIN], env=CliEnv(**settings))
    assert code == EXIT_OK and asked
    assert str(system.state_dir) in out.getvalue()
    for command in ("status", "stop"):
        code, _out, err = cli(tmp_path, command)
        assert code == EXIT_UNREACHABLE
        assert "not running" in err and "system-wide installation exists" in err


def test_an_elevated_window_says_it_is_the_system_wide_installation(tmp_path: Path) -> None:
    code, out, err = init(
        tmp_path, extra_environ={"USERPROFILE": "", "HOME": ""}, is_elevated=lambda: True
    )
    # USERPROFILE and HOME set but empty make the location fail closed: watch-only.
    assert code == EXIT_OK, err
    assert "stays watch-only" in out
    code, out, err = cli(
        tmp_path / "other",
        "init",
        "--username",
        ADMIN,
        "--password-stdin",
        stdin=PASSWORD + "\n",
        is_elevated=lambda: True,
        environ={"PORTLOCK_HOME": str(tmp_path / "other" / "home")},
    )
    assert code == EXIT_OK, err
    assert "system-wide PortLock installation" in out and "can block USB devices" in out
    assert "only watches" in out
    seen: dict[str, Any] = {}

    def fake_run(config: Any, **kwargs: Any) -> int:
        seen.update(kwargs)
        return 0

    code, out, _err = cli(
        tmp_path / "other",
        "run",
        is_elevated=lambda: True,
        run_service=fake_run,
        environ={"PORTLOCK_HOME": str(tmp_path / "other" / "home")},
    )
    assert code == EXIT_OK and "can block USB devices" in out
    assert seen["elevated"] is True and seen["program"] == PROGRAM


def test_run_hands_the_posture_inputs_and_the_messages_to_the_daemon(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_run(config: Any, **kwargs: Any) -> int:
        seen.update(kwargs)
        return 0

    code, _out, _err = cli(tmp_path, "run", run_service=fake_run)
    assert code == 0
    assert seen["elevated"] is False and seen["env"]["PORTLOCK_HOME"] == str(tmp_path / "home")
    assert callable(seen["announce"]) and seen["program"] == PROGRAM
    assert seen["config_file"] == tmp_path / "home" / "config" / "portlock.toml"


def test_messages_name_the_program_the_user_started(tmp_path: Path) -> None:
    code, _out, err = cli(tmp_path, "user", "reset-password", ADMIN, "--local", "--password-stdin")
    assert code == EXIT_FAILED and f"run '{PROGRAM} init'" in err
    code, _out, err = cli(tmp_path, "--no-such-option")
    assert f"Run '{PROGRAM} --help'" in err
    code, _out, err = cli(
        tmp_path,
        "recover",
        is_elevated=lambda: True,
        extra_environ={"USERPROFILE": "", "HOME": ""},
    )
    # An empty profile variable fails closed: the home counts as per-user, refused.
    assert code == EXIT_FAILED and "recover does not act on" in err


def test_recover_refuses_a_per_user_home_before_writing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[str] = []

    def create_enforcer(config: Any, hook: Any) -> Any:
        built.append("enforcer")
        raise AssertionError("recover built an enforcer for a per-user home")

    home = tmp_path / "home"
    code, _out, err = cli(
        tmp_path, "recover", is_elevated=lambda: True, create_enforcer=create_enforcer
    )
    assert code == EXIT_FAILED and "recover does not act on" in err
    assert OWN_WORDS in err and "Nothing was changed" in err
    assert built == [] and not (home / "config" / "DISABLE_ENFORCEMENT").exists()
    # The same home outside any profile is system-wide: recover goes on to its own checks.
    code, _out, err = cli(
        tmp_path,
        "recover",
        is_elevated=lambda: True,
        environ={"PORTLOCK_HOME": str(home)},
        create_enforcer=lambda config, hook: WatchOnlyEnforcer(elevated=False),
    )
    assert code == EXIT_AUTH and f"'{PROGRAM} recover' needs administrator" in err


def test_offline_doctor_for_an_ordinary_user_probes_no_mechanism(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_commands: list[Any],
    no_real_objects: list[str],
) -> None:
    monkeypatch.setattr(
        factory,
        "create_backend",
        lambda config, *, clock, platform=None: FakeBackend([flash_drive()], clock=clock),
    )
    monkeypatch.setattr(factory, "system_instance_ids", lambda devices, **kw: frozenset())
    code, out, err = cli(tmp_path, "doctor", "--offline")
    assert code == EXIT_OK, out + err
    assert "guard.watch_only: watch-only" in out
    assert "not system-wide" in out
    assert "not running as administrator" in out
    assert no_commands == [] and no_real_objects == []


# --- the process: stale files, ports, a second start ----------------------------------------------


def test_files_a_killed_service_left_do_not_end_the_next_start(
    tmp_path: Path, no_real_objects: list[str]
) -> None:
    config = make_config(tmp_path / "home")
    state = Path(config.paths.state_dir)
    state.mkdir(parents=True)
    (state / STOP_REQUEST_NAME).write_bytes(b"stop\n")
    (state / RUNTIME_FILE_NAME).write_text("{}", encoding="utf-8")
    seen: dict[str, bool] = {}

    def check(runtime: Runtime, port: int) -> None:
        # The ticker never ran (an hour apart): only the start can have removed it.
        seen["request"] = (state / STOP_REQUEST_NAME).exists()
        seen["runtime"] = json.loads((state / RUNTIME_FILE_NAME).read_text()) != {}

    code = run_daemon(
        config, NATIVE, Tripwire(), elevated=False, env={}, check=check, tick_seconds=3600
    )
    assert code == DAEMON_OK
    assert seen == {"request": False, "runtime": True}


def test_a_busy_port_names_the_setting_to_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], no_real_objects: list[str]
) -> None:
    class Busy:
        host, port = "127.0.0.1", 47600

        def start(self) -> None:
            raise OSError(errno.EADDRINUSE, "Only one usage of each socket address")

        def stop(self) -> None:
            raise AssertionError("never started")

    config = make_config(tmp_path / "home")
    source = tmp_path / "chosen.toml"
    code = run(
        config,
        install_signal_handlers=False,
        api_factory=lambda runtime: Busy(),
        clock=FakeClock(START),
        backend=FakeBackend([], clock=FakeClock(START), synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        seams=tripwire_seams(Tripwire()),
        elevated=False,
        env={},
        config_file=source,
    )
    assert code == EXIT_PORT
    err = capsys.readouterr().err
    assert "another program is already using that port" in err
    assert "[api]" in err and "port = <number>" in err and str(source) in err
    assert "WinError" not in err and "Errno" not in err


def test_a_second_start_says_where_the_first_one_is(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = make_config(tmp_path / "home")
    state = Path(config.paths.state_dir)
    with instance_lock(state):
        (state / RUNTIME_FILE_NAME).write_text(
            json.dumps(
                {
                    "v": 1,
                    "pid": 4242,
                    "host": "127.0.0.1",
                    "port": 47613,
                    "run_id": "0123456789abcdef",
                    "started_at": "2026-01-01T00:00:00.000000Z",
                    "version": "0",
                    "secret": "s" * 20,
                }
            ),
            encoding="utf-8",
        )
        code = run(config, install_signal_handlers=False, program=PROGRAM, elevated=False, env={})
    assert code == EXIT_ALREADY_RUNNING
    err = capsys.readouterr().err
    assert "already running" in err and "http://127.0.0.1:47613/" in err
    assert f"'{PROGRAM} stop'" in err
    assert (state / RUNTIME_FILE_NAME).exists()  # the running service's file is untouched


def test_python_dash_m_portlock_works_from_the_source_folder(tmp_path: Path) -> None:
    # No installation: the package is found because the working directory is ``src``.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PORTLOCK_", "PYTHON"))
    }
    env.update({"PORTLOCK_HOME": str(tmp_path / "home"), "PYTHONDONTWRITEBYTECODE": "1"})
    result = subprocess.run(
        [sys.executable, "-m", "portlock", "init", "--username", ADMIN, "--password-stdin"],
        cwd=SRC,
        input=PASSWORD + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "PortLock is set up." in result.stdout
    assert "python -m portlock run" in result.stdout
    assert (tmp_path / "home" / "state" / "portlock.db").is_file()


def test_the_runtime_reports_the_posture_it_was_built_with(tmp_path: Path) -> None:
    clock = FakeClock(START)
    for index, posture in enumerate(
        (Posture(elevated=False, system_wide=True), Posture(elevated=True, system_wide=False))
    ):
        runtime = build_runtime(
            make_config(tmp_path / f"home{index}"),
            clock=clock,
            backend=FakeBackend([], clock=clock, synchronous=True),
            platform=NATIVE,
            system_ids=lambda devices: frozenset(),
            posture=posture,
        )
        try:
            assert runtime.posture == posture and runtime.watch_only
            assert isinstance(runtime.enforcer, WatchOnlyEnforcer)
        finally:
            runtime.close()
    with pytest.raises(ValueError, match="stand-ins"):
        build_runtime(
            make_config(tmp_path / "injected"),
            clock=clock,
            backend=FakeBackend([], clock=clock, synchronous=True),
            platform=NATIVE,
            timer=WatchOnlyTimer(),
            system_ids=lambda devices: frozenset(),
            posture=Posture(elevated=False, system_wide=True),
        )
