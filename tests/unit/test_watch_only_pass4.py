"""Watch-only, fourth pass (DESIGN 14.28): what the third review found.

Each test names the item of the fourth-pass specification it holds (D1 to D10). The
helpers of ``test_watch_only`` are reused. Nothing here reaches a real device, the
registry, a permission or the network: the registry and name resolution are fakes
(``tests/unit/conftest.py`` and the tests below), and every operating-system seam of a
service is a tripwire or a recording fake.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from test_watch_only import (
    ADMIN,
    CHANNEL,
    NATIVE,
    PASSWORD,
    PROGRAM,
    START,
    Tripwire,
    cli,
    init,
    instance_lock,
    make_config,
    run_before_init,
    run_daemon,
    shown_key,
    windows_seams,
)

from portlock.audit import events as ev
from portlock.auth.accounts import Role
from portlock.console import cli as cli_module
from portlock.console.cli import EXIT_FAILED, EXIT_OK, EXIT_UNREACHABLE
from portlock.core import config as config_module
from portlock.core import service as service_module
from portlock.core.canonical import canonicalize
from portlock.core.clock import FakeClock, utc_iso
from portlock.core.config import (
    LOCATION_OTHER_USER,
    LOCATION_OWN,
    LOCATION_SHARED,
    LOCATION_UNCONFIRMED,
    AuditConfig,
    Config,
    PathsConfig,
    config_to_toml,
    per_user_cause,
)
from portlock.core.db import Database
from portlock.core.models import Mode
from portlock.core.store import JOURNAL_FILE_NAME, RecoveryJournal
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.guard.watchonly import CAUSE_ACCOUNT_HOME, Posture, StandIns, detect_posture
from portlock.service.daemon import EXIT_OK as DAEMON_OK
from portlock.service.daemon import LOCK_FILE_NAME, RUNTIME_FILE_NAME, Runtime, build_runtime

B = chr(92)  # a backslash, spelled so that no escape sequence is ever written
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the account database is POSIX")


def win(text: str) -> str:
    return text.replace("/", B)


def win_dirs(state: str) -> PathsConfig:
    return PathsConfig(state_dir=Path(win(state)), config_dir=Path(win(state)))


# --- D1: what init decided on changed while it waited ---------------------------------------


CHANGED = "PortLock's files changed while init was waiting. Nothing was changed"


def init_waiting(tmp_path: Path, name: str, meanwhile: Callable[[], None]) -> tuple[int, str, str]:
    """``init`` at a terminal; ``meanwhile`` runs while it waits for the password."""
    asked: list[str] = []

    def getpass(prompt: str) -> str:
        if not asked:
            meanwhile()
        asked.append(prompt)
        return PASSWORD

    return cli(tmp_path, "init", "--username", name, is_tty=lambda: True, getpass=getpass)


def users(home: Path) -> list[str]:
    db = Database(home / "state" / "portlock.db")
    try:
        return [str(row["username"]) for row in db.query("SELECT username FROM auth_users")]
    finally:
        db.close()


def verifies(tmp_path: Path, out: str) -> bool:
    key_file = tmp_path / "shown.key"
    key_file.write_text(shown_key(out), encoding="utf-8")
    code, _out, _err = cli(tmp_path, "audit", "verify", "--offline", "--key-file", str(key_file))
    return code == EXIT_OK


def snapshot_of(home: Path) -> dict[str, bytes]:
    """Every file under ``home`` except the database (which reading opens) and the lock."""
    return {
        str(path.relative_to(home)): path.read_bytes()
        for path in sorted(home.rglob("*"))
        if path.is_file() and not path.name.startswith(("portlock.db", LOCK_FILE_NAME))
    }


def test_d1_a_second_init_that_finished_meanwhile_stops_the_first(tmp_path: Path) -> None:
    # A stale key store (run before init): both inits would set it aside and make a key.
    home = tmp_path / "home"
    run_before_init(home)
    second: dict[str, Any] = {}

    def meanwhile() -> None:
        second["result"] = init(tmp_path)
        second["files"] = snapshot_of(home)

    code, out, err = init_waiting(tmp_path, ADMIN, meanwhile)
    assert code == EXIT_FAILED, out + err
    assert CHANGED in err and f"run '{PROGRAM} init' again" in err
    assert "Audit verification key" not in out
    # Nothing was changed: the second init's files are as it left them, with one
    # administrator, one key store set aside, and the key it showed verifies the log.
    b_code, b_out, b_err = second["result"]
    assert b_code == EXIT_OK, b_err
    assert snapshot_of(home) == second["files"]
    assert users(home) == [ADMIN]
    assert len([p for p in (home / "state").iterdir() if ".unused-" in p.name]) == 1
    assert verifies(tmp_path, b_out)


def test_d1_a_second_administrator_is_never_created(tmp_path: Path) -> None:
    home = tmp_path / "home"
    second: dict[str, Any] = {}

    def meanwhile() -> None:
        second["result"] = init(tmp_path)

    code, _out, err = init_waiting(tmp_path, "second", meanwhile)
    assert code == EXIT_FAILED and CHANGED in err
    assert second["result"][0] == EXIT_OK
    assert users(home) == [ADMIN]
    assert verifies(tmp_path, second["result"][1])


def test_d1_a_service_that_came_and_went_meanwhile_stops_init(tmp_path: Path) -> None:
    # The configuration names a key store that does not exist yet; a service started and
    # stopped while init waited creates the database and the key store.
    home = tmp_path / "home"
    key = home / "state" / "audit.key"
    config = Config(
        paths=make_config(home).paths,
        mode=Mode.MONITOR,
        audit=AuditConfig(hmac_key_file=key, sinks=()),
    )
    Path(config.paths.config_dir).mkdir(parents=True)
    config.paths.config_file.write_text(config_to_toml(config), encoding="utf-8")

    def meanwhile() -> None:
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

    code, out, err = init_waiting(tmp_path, ADMIN, meanwhile)
    assert code == EXIT_FAILED and CHANGED in err
    assert "Audit verification key" not in out
    assert users(home) == []
    # The next init sees what is there now, shows a key, and that key verifies the log.
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert verifies(tmp_path, out)


def test_d1_init_still_succeeds_when_nothing_changed(tmp_path: Path) -> None:
    code, out, err = init_waiting(tmp_path, ADMIN, lambda: None)
    assert code == EXIT_OK, err
    assert verifies(tmp_path, out)


# --- D2: the folder that holds the profiles, whoever runs PortLock -----------------------


def service_env(profile: str) -> dict[str, str]:
    """What SYSTEM or LocalService sees: its own profile is not under C:/Users."""
    return {
        "USERPROFILE": win(profile),
        "LOCALAPPDATA": win(profile + "/AppData/Local"),
        "APPDATA": win(profile + "/AppData/Roaming"),
        "PUBLIC": win("C:/Users/Public"),
        "SystemDrive": "C:",
        "COMPUTERNAME": "PC1",
    }


@pytest.mark.parametrize(
    "env",
    [
        service_env("C:/Windows/System32/config/systemprofile"),
        service_env("C:/Windows/ServiceProfiles/LocalService"),
        {"SystemDrive": "C:"},
        {"PUBLIC": win("C:/Users/Public")},
    ],
    ids=["system", "local-service", "system-drive-only", "public-only"],
)
def test_d2_another_users_profile_is_per_user_under_any_account(env: dict[str, str]) -> None:
    assert per_user_cause(win_dirs("C:/Users/Alice/pl"), platform="win32", env=env) == (
        LOCATION_OTHER_USER
    )
    assert per_user_cause(win_dirs("C:/ProgramData/PortLock"), platform="win32", env=env) is None
    if "PUBLIC" in env:
        assert per_user_cause(win_dirs("C:/Users/Public/pl"), platform="win32", env=env) == (
            LOCATION_SHARED
        )


def test_d2_profiles_on_another_drive_are_found_by_system_drive_and_public() -> None:
    env = {"SystemDrive": "D:", "PUBLIC": win("E:/Profiles/Public")}
    for state in ("D:/Users/Alice/pl", "E:/Profiles/Bob/pl"):
        assert per_user_cause(win_dirs(state), platform="win32", env=env) == LOCATION_OTHER_USER


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"PUBLIC": B + B + "fileserver" + B + "public"},
        {"COMPUTERNAME": "PC1"},
    ],
    ids=["empty", "public-on-a-file-server", "nothing-about-profiles"],
)
def test_d2_no_known_profiles_folder_fails_closed(env: dict[str, str]) -> None:
    # Off Windows the registry is not asked: nothing tells where the profiles are.
    if sys.platform == "win32":
        pytest.skip("on Windows the registry names the profiles folder")
    paths = win_dirs("C:/ProgramData/PortLock")
    assert per_user_cause(paths, platform="win32", env=env) == LOCATION_UNCONFIRMED


@pytest.mark.parametrize("drive", ["C", "C:" + B, "", "CC:"])
def test_d2_an_unusable_system_drive_fails_closed(drive: str) -> None:
    env = {"SystemDrive": drive, "USERPROFILE": win("C:/Users/Alice")}
    paths = win_dirs("C:/ProgramData/PortLock")
    assert per_user_cause(paths, platform="win32", env=env) == LOCATION_UNCONFIRMED


@pytest.mark.skipif(sys.platform != "win32", reason="the registry is asked only on Windows")
def test_d2_the_registry_names_the_profiles_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = win_dirs("C:/Users/Alice/pl")
    monkeypatch.setattr(config_module, "_registry_profiles_directory", lambda: win("C:/Users"))
    assert per_user_cause(paths, platform="win32", env={}) == LOCATION_OTHER_USER
    monkeypatch.setattr(config_module, "_registry_profiles_directory", lambda: None)
    assert per_user_cause(paths, platform="win32", env={}) == LOCATION_UNCONFIRMED


class FakeWinreg:
    """The few ``winreg`` names the lookup uses; anything that writes is absent."""

    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self, value: Any, kind: int, *, missing: bool = False) -> None:
        self.value, self.kind, self.missing = value, kind, missing
        self.opened: list[tuple[Any, str, int, int]] = []

    def OpenKey(self, root: Any, path: str, reserved: int, access: int) -> Any:
        self.opened.append((root, path, reserved, access))
        if self.missing:
            raise FileNotFoundError(errno.ENOENT, "not found")
        owner = self

        class Key:
            def __enter__(self) -> Any:
                return owner

            def __exit__(self, *exc: object) -> None:
                return None

        return Key()

    def QueryValueEx(self, key: Any, name: str) -> tuple[Any, int]:
        assert name == "ProfilesDirectory"
        return self.value, self.kind

    def ExpandEnvironmentStrings(self, text: str) -> str:
        return text.replace("%SystemDrive%", "C:")


def test_d2_the_registry_lookup_only_reads() -> None:
    registry = FakeWinreg("%SystemDrive%" + B + "Users", FakeWinreg.REG_EXPAND_SZ)
    assert config_module._read_profiles_directory(registry) == "C:" + B + "Users"
    [(root, path, _reserved, access)] = registry.opened
    assert root is FakeWinreg.HKEY_LOCAL_MACHINE and path.endswith("ProfileList")
    assert access == FakeWinreg.KEY_READ | FakeWinreg.KEY_WOW64_64KEY
    assert config_module._read_profiles_directory(FakeWinreg("", FakeWinreg.REG_SZ)) is None
    assert config_module._read_profiles_directory(FakeWinreg(7, FakeWinreg.REG_SZ)) is None
    missing = FakeWinreg(None, FakeWinreg.REG_SZ, missing=True)
    assert config_module._read_profiles_directory(missing) is None


# --- D3: a lock that cannot be looked at is not "free" ------------------------------------


@pytest.fixture
def unsearchable_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A state directory this user cannot search, as Python 3.11 to 3.14 all see it.

    ``os.stat`` of anything inside it is denied, and ``Path.is_file`` answers as it does
    from Python 3.13 on (False instead of raising), so the test holds on every version.
    The runtime file cannot be read either.
    """
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    (state / LOCK_FILE_NAME).write_bytes(b"")
    runtime = state / RUNTIME_FILE_NAME
    runtime.write_text("{}", encoding="utf-8")
    prefix = os.path.normcase(str(state)) + os.sep
    real_stat = os.stat

    def denied(path: Any) -> bool:
        try:
            return os.path.normcase(os.fspath(path)).startswith(prefix)
        except TypeError:
            return False

    def stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if denied(path):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_stat(path, *args, **kwargs)

    def is_file(self: Path) -> bool:
        try:
            return bool(self.stat().st_mode & 0o100000)
        except OSError:
            return False

    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(Path, "is_file", is_file)
    monkeypatch.setattr(cli_module, "read_runtime_file", lambda state_dir: None)
    return state


@pytest.mark.parametrize("command", ["stop", "status"])
def test_d3_an_unsearchable_state_directory_is_cannot_tell(
    unsearchable_state: Path, tmp_path: Path, command: str
) -> None:
    code, out, err = cli(tmp_path, command)
    assert code == EXIT_UNREACHABLE, out + err
    assert "cannot tell whether the service is running" in err
    assert "Permission denied" in err
    assert "the service is not running" not in err
    # A running service's runtime file is never removed on a guess.
    assert os.path.lexists(unsearchable_state / RUNTIME_FILE_NAME)


def test_d3_init_refuses_when_it_cannot_tell(unsearchable_state: Path, tmp_path: Path) -> None:
    code, _out, err = init(tmp_path)
    assert code == EXIT_FAILED and "cannot tell whether a PortLock service is running" in err


def test_d3_a_missing_lock_or_state_directory_is_free(tmp_path: Path) -> None:
    lock_state = cli_module._Cli(cli_module.CliEnv())._lock_state
    assert lock_state(tmp_path / "nowhere") == (False, "")
    (tmp_path / "a-file").write_bytes(b"")
    assert lock_state(tmp_path / "a-file") == (False, "")  # NotADirectoryError
    with instance_lock(tmp_path / "held"):
        assert lock_state(tmp_path / "held") == (True, "")


# --- D4: default-deny stored but not in force -------------------------------------------------


@pytest.fixture
def elevated_monitor(tmp_path: Path) -> Iterator[Runtime]:
    """An elevated, system-wide process in monitor mode on recording Windows fakes, with
    default-deny stored on by an earlier run."""
    seams, _runner, _registry = windows_seams()
    clock = FakeClock(START)
    runtime = build_runtime(
        make_config(tmp_path / "home"),
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        platform="win32",
        system_ids=lambda devices: frozenset(),
        seams=seams,
        posture=Posture(elevated=True, system_wide=True),
    )
    runtime.store.set_setting("default_deny", True, by="earlier")
    runtime.service.start(threads=False)
    runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
    try:
        yield runtime
    finally:
        runtime.service.stop()
        runtime.close()


def test_d4_monitor_mode_reports_default_deny_stored_but_not_in_force(
    elevated_monitor: Runtime,
) -> None:
    service = elevated_monitor.service
    assert not elevated_monitor.watch_only
    view = service.get_default_deny()
    assert (view.enabled, view.stored) == (False, True)
    assert view.note is not None
    assert view.note.startswith("Default-deny is stored on but not in force")
    assert "monitor mode" in view.note
    settings = service.get_settings().to_dict()
    assert settings["effective"]["default_deny"] is False
    assert settings["runtime"]["default_deny"] is False
    assert settings["notes"] == [view.note]
    # Nothing was asked of the operating system.
    assert not elevated_monitor.journal.open_records()


def test_d4_effective_default_deny_follows_what_is_asked_of_the_system(
    elevated_monitor: Runtime,
) -> None:
    service = elevated_monitor.service
    engaged = service.lockdown_engage(minutes=30, reason="practice", actor=ADMIN, channel=CHANNEL)
    service.lockdown_confirm(engaged.value.change.id, actor=ADMIN, channel=CHANNEL)
    assert service.lockdown_status().active is True
    # A lockdown denies new devices whatever is stored; the stored choice is still not in
    # force, because that needs enforce mode.
    settings = service.get_settings().to_dict()
    assert settings["effective"]["default_deny"] is True
    assert service.get_default_deny().enabled is False


def test_d4_the_kill_switch_takes_default_deny_out_of_force(elevated_monitor: Runtime) -> None:
    service = elevated_monitor.service
    service._activate_killswitch()
    view = service.get_default_deny()
    assert (view.enabled, view.stored) == (False, True)
    assert view.note is not None and "kill switch" in view.note
    assert service.get_settings().to_dict()["effective"]["default_deny"] is False


def test_d4_enforce_mode_puts_it_in_force(tmp_path: Path) -> None:
    # The recording Windows fakes cannot make directories private, which refuses enforce
    # mode (DESIGN 14.18); a process composed with the plain fakes can switch.
    clock = FakeClock(START)
    runtime = build_runtime(
        make_config(tmp_path / "home"),
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        enforcer=FakeEnforcer(),
        timer=FakeExternalTimer(),
        dir_privacy=FakeDirPrivacy(),
        system_ids=lambda devices: frozenset(),
    )
    try:
        runtime.store.set_setting("default_deny", True, by="earlier")
        runtime.service.start(threads=False)
        runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
        service = runtime.service
        assert service.get_default_deny().enabled is False
        applied = service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
        service.confirm_change(applied.extra["change"]["id"], actor=ADMIN, channel=CHANNEL)
        view = service.get_default_deny()
        assert (view.enabled, view.stored, view.note) == (True, True, None)
        assert service.get_settings().to_dict()["effective"]["default_deny"] is True
    finally:
        runtime.service.stop()
        runtime.close()


# --- D5 and D7: homes from the account database ------------------------------------------


@pytest.fixture
def accounts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    """root runs PortLock; login accounts live in unusual places (all under tmp_path)."""
    places = {
        "root": tmp_path / "root",
        "bob": tmp_path / "export" / "home" / "bob",
        "carol": tmp_path / "var" / "home" / "carol",
        "service": tmp_path / "srv" / "daemon",
        "ghost": tmp_path / "srv" / "users" / "ghost",  # no such directory
    }
    for name, place in places.items():
        if name != "ghost":
            place.mkdir(parents=True)
    table = [
        (0, str(places["root"])),
        (1001, str(places["bob"])),
        (60001, str(places["carol"])),
        (999, str(places["service"])),
        (1002, str(places["ghost"])),
        (65534, "/"),
    ]
    login_defs = tmp_path / "login.defs"
    login_defs.write_text("# comment\nUID_MIN\t\t\t 1000\nUID_MAX 60000\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "_accounts", lambda: table)
    monkeypatch.setattr(config_module, "_LOGIN_DEFS", login_defs)
    monkeypatch.setattr(config_module, "_effective_uid", lambda: 0)
    monkeypatch.setattr(
        config_module,
        "_account_home",
        lambda account, *, by_uid: (0, str(places["root"])) if account == "0" else None,
    )
    monkeypatch.setattr(config_module, "_running_under_wsl", lambda: False)
    return places


def posix_paths(directory: Path) -> PathsConfig:
    return PathsConfig(state_dir=directory, config_dir=directory)


@POSIX_ONLY
def test_d5_homes_outside_home_are_another_users(accounts: dict[str, Path]) -> None:
    env = {"HOME": str(accounts["root"])}
    for name in ("bob", "carol"):
        paths = posix_paths(accounts[name] / "pl")
        assert per_user_cause(paths, platform="linux", env=env) == LOCATION_OTHER_USER, name
        posture = detect_posture(Config(paths=paths), elevated=True, env=env, platform="linux")
        assert posture.watch_only and posture.cause == LOCATION_OTHER_USER
    # A system account (uid below UID_MIN) and a home that is no directory are not.
    for directory in (accounts["service"], accounts["ghost"]):
        assert per_user_cause(posix_paths(directory / "pl"), platform="linux", env=env) is None


@POSIX_ONLY
def test_d5_uid_min_comes_from_login_defs(
    accounts: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert config_module._uid_min() == 1000
    (tmp_path / "login.defs").write_text("UID_MIN 500\n", encoding="utf-8")
    assert config_module._uid_min() == 500
    service = posix_paths(accounts["service"] / "pl")
    assert per_user_cause(service, platform="linux", env={}) == LOCATION_OTHER_USER
    monkeypatch.setattr(config_module, "_LOGIN_DEFS", tmp_path / "absent")
    assert config_module._uid_min() == 1000
    (tmp_path / "login.defs").write_text("UID_MIN not-a-number\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "_LOGIN_DEFS", tmp_path / "login.defs")
    assert config_module._uid_min() == 1000


@POSIX_ONLY
def test_d5_windows_profiles_under_wsl_are_per_user(
    accounts: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mounts = tmp_path / "mnt"
    for name in ("c", "d", "wsl", "wslg"):
        (mounts / name).mkdir(parents=True)
    monkeypatch.setattr(config_module, "_WSL_MOUNTS", str(mounts))
    paths = posix_paths(mounts / "d" / "Users" / "Alice" / "pl")
    assert per_user_cause(paths, platform="linux", env={}) is None
    monkeypatch.setattr(config_module, "_running_under_wsl", lambda: True)
    assert per_user_cause(paths, platform="linux", env={}) == LOCATION_OTHER_USER
    assert config_module._wsl_windows_profiles() == [
        str(mounts / "c" / "Users"),
        str(mounts / "d" / "Users"),
    ]
    elsewhere = posix_paths(mounts / "c" / "ProgramData" / "PortLock")
    assert per_user_cause(elsewhere, platform="linux", env={}) is None


@POSIX_ONLY
@pytest.mark.parametrize("home", [None, "/"])
def test_d7_roots_own_home_counts_without_home(accounts: dict[str, Path], home: str | None) -> None:
    env = {} if home is None else {"HOME": home}
    paths = posix_paths(accounts["root"] / "pl")
    assert per_user_cause(paths, platform="linux", env=env) == LOCATION_OWN
    posture = detect_posture(Config(paths=paths), elevated=True, env=env, platform="linux")
    assert posture.watch_only and posture.cause == CAUSE_ACCOUNT_HOME
    assert "a root installation must not live there" in str(posture.refusal())


@POSIX_ONLY
def test_d7_another_users_home_left_in_home_is_another_users(accounts: dict[str, Path]) -> None:
    # su without "-": root's HOME still names bob's home.
    env = {"HOME": str(accounts["bob"])}
    paths = posix_paths(accounts["bob"] / "pl")
    posture = detect_posture(Config(paths=paths), elevated=True, env=env, platform="linux")
    assert posture.cause == LOCATION_OTHER_USER
    assert "another user's folders" in str(posture.refusal())
    assert "root installation" not in str(posture.refusal())


@POSIX_ONLY
def test_d7_a_home_that_is_nobodys_account_is_not_roots(
    accounts: dict[str, Path], tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env = {"HOME": str(elsewhere)}
    paths = posix_paths(elsewhere / "pl")
    posture = detect_posture(Config(paths=paths), elevated=True, env=env, platform="linux")
    assert posture.watch_only and posture.cause == LOCATION_OWN


def test_d7_foreign_names_still_use_home() -> None:
    # Tests of another platform have no account database: HOME is all there is.
    if sys.platform != "win32":
        pytest.skip("only a foreign platform compares names alone")
    config = Config(paths=PathsConfig(state_dir=Path("/root/pl"), config_dir=Path("/root/pl")))
    posture = detect_posture(config, elevated=True, env={"HOME": "/root"}, platform="linux")
    assert posture.cause == CAUSE_ACCOUNT_HOME


# --- D6: names for this computer ------------------------------------------------------------


OWN_V4 = "192.0.2.7"
OWN_V6 = "2001:db8::7"


@pytest.fixture
def resolver(monkeypatch: pytest.MonkeyPatch) -> dict[str, frozenset[Any]]:
    """Name resolution as a table: this computer is ``pc1`` at two addresses."""
    import ipaddress

    def table(*addresses: str) -> frozenset[Any]:
        return frozenset(ipaddress.ip_address(text) for text in addresses)

    answers = {
        "pc1": table(OWN_V4, OWN_V6),
        "pc1-alias.example.test": table(OWN_V4),
        "loop-alias.example.test": table("::1"),
        "v6-only.example.test": table(OWN_V6),
        "fileserver.example.test": table("198.51.100.4", "2001:db8::44"),
    }
    monkeypatch.setattr(config_module, "_lookup", lambda name: answers.get(name, frozenset()))
    monkeypatch.setattr(config_module, "_host_name", lambda: "pc1")
    monkeypatch.setattr(config_module.socket, "gethostbyname_ex", fail_lookup)
    return answers


def fail_lookup(name: str) -> Any:
    raise socket.gaierror(socket.EAI_NONAME, "not found")


@pytest.mark.parametrize(
    "server",
    [
        "127.0.0.1.",
        "localhost.",
        "LOCALHOST..",
        "pc1.",
        OWN_V4,
        OWN_V4 + ".",
        "2001-db8--7.ipv6-literal.net",
        "[" + OWN_V6 + "]",
        "pc1-alias.example.test",
        "pc1-alias.example.test.",
        "loop-alias.example.test",
        "v6-only.example.test",
    ],
)
def test_d6_every_name_for_this_computer_is_local(resolver: dict[str, Any], server: str) -> None:
    assert config_module._remote_server(server, {}, native=True) is False


@pytest.mark.parametrize(
    "server", ["fileserver.example.test", "198.51.100.4", "offline-server.example.test"]
)
def test_d6_other_computers_stay_remote(resolver: dict[str, Any], server: str) -> None:
    # A name that does not resolve is taken for a server that cannot be reached now.
    assert config_module._remote_server(server, {}, native=True) is True


@pytest.mark.skipif(sys.platform != "win32", reason="a UNC path is resolved only on Windows")
@pytest.mark.parametrize(
    "server", [OWN_V4, OWN_V4 + ".", "2001-db8--7.ipv6-literal.net", "pc1-alias.example.test"]
)
def test_d6_a_unc_path_to_this_computers_own_address_fails_closed(
    resolver: dict[str, Any], server: str
) -> None:
    profile = win("C:/Users/Alice")
    env = {
        "USERPROFILE": profile,
        "LOCALAPPDATA": profile + B + "AppData" + B + "Local",
        "APPDATA": B + B + server + B + "profiles" + B + "Alice",
    }
    paths = win_dirs("C:/ProgramData/PortLock")
    assert per_user_cause(paths, platform="win32", env=env) == LOCATION_UNCONFIRMED
    env["APPDATA"] = B + B + "fileserver.example.test" + B + "profiles" + B + "Alice"
    assert per_user_cause(paths, platform="win32", env=env) is None


# --- D8: what init says about a key store it sets aside ------------------------------------


def test_d8_init_says_what_is_true_about_the_key_store_it_sets_aside(tmp_path: Path) -> None:
    run_before_init(tmp_path / "home")
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "an audit key store that no administrator was set up with was moved to" in out
    assert "never shown" not in out
    db = Database(tmp_path / "home" / "state" / "portlock.db")
    try:
        rows = db.query("SELECT data FROM audit_log WHERE event_type = ?", (ev.CONFIG_CHANGED,))
    finally:
        db.close()
    reasons = [json.loads(row["data"]).get("reason") for row in rows]
    assert "no administrator was set up with it" in reasons
    assert "its initial key was never shown" not in reasons


# --- D9: each watch-only journal guard on its own -------------------------------------------


def closed_hold(path: Path) -> bytes:
    """A journal with one hold that an enforcing run closed but did not compact away."""
    journal = RecoveryJournal(path, clock=FakeClock(START))
    record = journal.add_hold(scope=win("USB/VID_1209&PID_0001/T1"), fingerprint=None)
    line = {"op": "close", "id": record.id, "ts": utc_iso(START), "reason": "test"}
    with path.open("ab") as stream:
        stream.write(canonicalize(line).encode("utf-8") + b"\n")
    return path.read_bytes()


def test_d9_compact_leaves_a_read_only_journal_as_it_is(tmp_path: Path) -> None:
    path = tmp_path / JOURNAL_FILE_NAME
    before = closed_hold(path)
    journal = RecoveryJournal(path, clock=FakeClock(START), read_only=True)
    assert journal.open_records() == []
    journal.compact()
    assert path.read_bytes() == before
    # The same journal, writable, is compacted: the guard is what kept it.
    RecoveryJournal(path, clock=FakeClock(START)).compact()
    assert path.read_bytes() != before


def test_d9_a_watch_only_stop_never_calls_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = service_module.rollback

    def recording(*args: Any, **kwargs: Any) -> Any:
        calls.append(str(kwargs.get("reason")))
        return real(*args, **kwargs)

    monkeypatch.setattr(service_module, "rollback", recording)
    config = make_config(tmp_path / "home")
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        seen["watch_only"] = runtime.watch_only

    code = run_daemon(config, NATIVE, Tripwire(), elevated=False, env={}, check=check)
    assert code == DAEMON_OK and seen["watch_only"] is True
    assert calls == []
    # An enforcing process does roll back at its stop: the patch is where the service
    # looks for it.
    seams, _runner, _registry = windows_seams()
    clock = FakeClock(START)
    runtime = build_runtime(
        make_config(tmp_path / "elevated"),
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        platform="win32",
        system_ids=lambda devices: frozenset(),
        seams=seams,
        posture=Posture(elevated=True, system_wide=True),
    )
    try:
        runtime.service.start(threads=False)
        runtime.service.stop()
    finally:
        runtime.close()
    assert calls == ["service_stop"]


# --- D10: a runtime file whose service does not answer ---------------------------------------


class UnopenableLock:
    """An instance lock whose file this user cannot open for writing."""

    def __init__(self, path: Any) -> None:
        self.path = path

    def acquire(self) -> bool:
        raise PermissionError(errno.EACCES, "Permission denied", str(self.path))

    def release(self) -> None:
        return None


def closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_d10_stop_says_a_service_that_does_not_answer_is_probably_not_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    (state / LOCK_FILE_NAME).write_bytes(b"")
    port = closed_port()
    (state / RUNTIME_FILE_NAME).write_text(
        json.dumps(
            {
                "v": 1,
                "pid": 4242,
                "host": "127.0.0.1",
                "port": port,
                "run_id": "0123456789abcdef",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "version": "0",
                "secret": "s" * 20,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_module, "InstanceLock", UnopenableLock)
    code, _out, err = cli(tmp_path, "--timeout", "2", "stop")
    assert code == EXIT_UNREACHABLE
    assert "probably not running" in err and f"127.0.0.1:{port}" in err
    assert "does not answer" in err and "Permission denied" in err
    assert "cannot be read" not in err
    # It changed nothing: the runtime file is where it was, and no stop request was made.
    assert (state / RUNTIME_FILE_NAME).exists()
    assert sorted(path.name for path in state.iterdir()) == [LOCK_FILE_NAME, RUNTIME_FILE_NAME]


def test_d10_an_unreadable_runtime_file_still_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    (state / LOCK_FILE_NAME).write_bytes(b"")
    monkeypatch.setattr(cli_module, "InstanceLock", UnopenableLock)
    code, _out, err = cli(tmp_path, "stop")
    assert code == EXIT_UNREACHABLE
    assert "cannot tell whether the service is running" in err and "cannot be read" in err
