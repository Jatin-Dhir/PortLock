"""Watch-only, third pass (DESIGN 14.28): what the second review found.

Each test names the item of the third-pass specification it holds (C1 to C12). The
helpers of ``test_watch_only`` are reused: the real start-up path (``daemon.run``) runs
with every operating-system seam replaced by a tripwire, and ``subprocess.Popen`` itself
is refused. Nothing here reaches a real device, the registry or a permission.
"""

from __future__ import annotations

import errno
import io
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_watch_only import (
    ADMIN,
    NATIVE,
    PASSWORD,
    PROGRAM,
    START,
    Http,
    Tripwire,
    cli,
    init,
    instance_lock,
    leftover_hold,
    leftover_lockdown,
    make_config,
    run_before_init,
    run_daemon,
    shown_key,
    system_wide_elsewhere,
    tripwire_seams,
)

from portlock.audit.log import AuditKeyStore
from portlock.auth.accounts import Role
from portlock.console import cli as cli_module
from portlock.console.cli import (
    EXIT_AUTH,
    EXIT_FAILED,
    EXIT_OK,
    EXIT_UNREACHABLE,
    CliEnv,
)
from portlock.core import config as config_module
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
    load_config,
    per_user_cause,
)
from portlock.core.db import Database
from portlock.core.errors import StoreError
from portlock.core.models import Mode
from portlock.core.service import _sentence
from portlock.core.store import JOURNAL_FILE_NAME, RecoveryJournal, StateStore
from portlock.guard import factory
from portlock.guard.base import Action
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.guard.watchonly import (
    CAUSE_ACCOUNT_HOME,
    NO_ANTIVIRUS_NOTE,
    WATCH_ONLY_NOTE,
    Posture,
    WatchOnlyEnforcer,
    detect_posture,
    location_clause,
)
from portlock.service import daemon
from portlock.service.daemon import EXIT_OK as DAEMON_OK
from portlock.service.daemon import (
    EXIT_STATE_UNUSABLE,
    LOCK_FILE_NAME,
    InstanceLock,
    Runtime,
    build_runtime,
    run,
)

B = chr(92)  # a backslash, spelled so that no escape sequence is ever written


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


def win(text: str) -> str:
    """A Windows path written with forward slashes, turned into backslashes."""
    return text.replace("/", B)


SYSTEM = PathsConfig(
    state_dir=Path(win("C:/ProgramData/PortLock")), config_dir=Path(win("C:/ProgramData/PortLock"))
)
ALICE = {
    "USERPROFILE": win("C:/Users/Alice"),
    "LOCALAPPDATA": win("C:/Users/Alice/AppData/Local"),
    "COMPUTERNAME": "ALICE-PC",
}


def win_dirs(state: str) -> PathsConfig:
    return PathsConfig(state_dir=Path(win(state)), config_dir=Path(win(state)))


def posix_dirs(state: str) -> PathsConfig:
    return PathsConfig(state_dir=Path(state), config_dir=Path("/etc/portlock"))


# --- C1: a redirected AppData ---------------------------------------------------------------


@pytest.mark.parametrize(
    "appdata",
    [
        "//fileserver/profiles$/alice/AppData/Roaming",
        "//fileserver.corp.example/profiles$/alice",
        "//192.0.2.10/profiles$/alice",
    ],
)
def test_c1_a_redirected_appdata_on_a_file_server_is_skipped(appdata: str) -> None:
    env = dict(ALICE, APPDATA=win(appdata))
    assert per_user_cause(SYSTEM, platform="win32", env=env) is None
    # An elevated administrator's system-wide installation is not watch-only.
    posture = detect_posture(Config(paths=SYSTEM), elevated=True, env=env, platform="win32")
    assert not posture.watch_only and posture.refusal() is None
    # The profile itself still counts: a folder inside it stays per-user.
    assert per_user_cause(win_dirs("C:/Users/Alice/pl"), platform="win32", env=env) == (
        LOCATION_OWN
    )


@pytest.mark.parametrize(
    "env",
    [
        # A UNC path to this computer is another spelling of a local folder.
        dict(ALICE, APPDATA=win("//localhost/C$/Users/Alice/AppData/Roaming")),
        dict(ALICE, APPDATA=win("//LOCALHOST.localdomain/C$/Users/Alice")),
        dict(ALICE, APPDATA=win("//127.0.0.7/C$/Users/Alice")),
        dict(ALICE, APPDATA=win("//[::1]/C$/Users/Alice")),
        dict(ALICE, APPDATA=win("//0--1.ipv6-literal.net/C$/Users/Alice")),
        dict(ALICE, APPDATA=win("//alice-pc/C$/Users/Alice")),
        dict(ALICE, APPDATA=win("//ALICE-PC.corp.example/C$/Users/Alice")),
        # Device namespaces, a UNC path without a share, empty and relative values.
        dict(ALICE, APPDATA=win("//?/C:/Users/Alice/AppData/Roaming")),
        dict(ALICE, APPDATA=win("//?/UNC/fileserver/profiles$/alice")),
        dict(ALICE, APPDATA=win("//./C:/Users/Alice")),
        dict(ALICE, APPDATA=win("//fileserver")),
        dict(ALICE, APPDATA=""),
        dict(ALICE, APPDATA="AppData"),
        # USERPROFILE and LOCALAPPDATA are never skipped, even on a file server.
        dict(ALICE, USERPROFILE=win("//fileserver/profiles$/alice")),
        dict(ALICE, LOCALAPPDATA=win("//fileserver/profiles$/alice/Local")),
        dict(ALICE, PUBLIC=win("//localhost/C$/Users/Public")),
    ],
)
def test_c1_everything_else_still_fails_closed(env: dict[str, str]) -> None:
    assert per_user_cause(SYSTEM, platform="win32", env=env) == LOCATION_UNCONFIRMED
    posture = detect_posture(Config(paths=SYSTEM), elevated=True, env=env, platform="win32")
    assert posture.watch_only


@pytest.mark.parametrize(
    "state", ["//fileserver/share/PortLock", "//?/C:/ProgramData/PortLock", "//./C:/x"]
)
def test_c1_a_unc_or_device_candidate_fails_closed(state: str) -> None:
    env = dict(ALICE, APPDATA=win("//fileserver/profiles$/alice"))
    assert per_user_cause(win_dirs(state), platform="win32", env=env) == LOCATION_UNCONFIRMED


def test_c1_recover_acts_on_a_system_wide_home_despite_a_redirected_appdata(
    tmp_path: Path,
) -> None:
    # The reviewer's probe: an elevated recover of the real system-wide installation was
    # refused as "this user's own folders" when APPDATA was on a file server. Here it
    # gets past the location check to its own administrator check.
    home = tmp_path / "ProgramData" / "PortLock"
    environ = {
        "PORTLOCK_HOME": str(home),
        "USERPROFILE": str(tmp_path / "Users" / "alice"),
        "LOCALAPPDATA": str(tmp_path / "Users" / "alice" / "AppData" / "Local"),
        "APPDATA": win("//fileserver/profiles$/alice/AppData/Roaming"),
        "HOME": str(tmp_path / "Users" / "alice"),
    }
    code, _out, err = cli(
        tmp_path,
        "recover",
        environ=environ,
        is_elevated=lambda: True,
        create_enforcer=lambda config, hook: WatchOnlyEnforcer(elevated=False),
    )
    assert "recover does not act on" not in err
    assert code == EXIT_AUTH and "needs administrator" in err


# --- C2: another account's profile ----------------------------------------------------------


def test_c2_another_users_profile_and_the_public_folder_are_not_system_wide() -> None:
    assert per_user_cause(win_dirs("C:/Users/Bob/pl"), platform="win32", env=ALICE) == (
        LOCATION_OTHER_USER
    )
    assert per_user_cause(win_dirs("c:/users/BOB/pl"), platform="win32", env=ALICE) == (
        LOCATION_OTHER_USER
    )
    public = dict(ALICE, PUBLIC=win("C:/Users/Public"))
    assert per_user_cause(win_dirs("C:/Users/Public/pl"), platform="win32", env=public) == (
        LOCATION_SHARED
    )
    assert per_user_cause(win_dirs("C:/Users/Alice/pl"), platform="win32", env=public) == (
        LOCATION_OWN
    )
    assert per_user_cause(SYSTEM, platform="win32", env=public) is None
    # An elevated window opened with another administrator's credentials.
    admin = {"USERPROFILE": win("C:/Users/Admin2")}
    posture = detect_posture(
        Config(paths=win_dirs("C:/Users/Alice/pl")), elevated=True, env=admin, platform="win32"
    )
    assert posture.watch_only and posture.cause == LOCATION_OTHER_USER


def test_c2_home_directories_on_posix_are_not_system_wide() -> None:
    root = {"HOME": "/root"}
    assert per_user_cause(posix_dirs("/home/alice/pl"), platform="linux", env=root) == (
        LOCATION_OTHER_USER
    )
    assert per_user_cause(posix_dirs("/Users/bob/pl"), platform="darwin", env=root) == (
        LOCATION_OTHER_USER
    )
    assert per_user_cause(posix_dirs("/var/lib/../../home/x"), platform="linux", env=root) == (
        LOCATION_OTHER_USER
    )
    assert per_user_cause(posix_dirs("/var/lib/portlock"), platform="linux", env=root) is None
    # sudo PORTLOCK_HOME=/home/alice/pl portlock run: HOME is /root.
    posture = detect_posture(
        Config(paths=posix_dirs("/home/alice/pl")), elevated=True, env=root, platform="linux"
    )
    assert posture.watch_only and posture.cause == LOCATION_OTHER_USER


@pytest.mark.skipif(sys.platform == "win32", reason="sudo, doas and pkexec are POSIX")
def test_c2_the_account_that_started_sudo_owns_its_home(monkeypatch: pytest.MonkeyPatch) -> None:
    homes = {"alice": (1000, "/srv/people/alice"), "1000": (1000, "/srv/people/alice")}

    def account_home(account: str, *, by_uid: bool) -> tuple[int, str] | None:
        return homes.get(account)

    monkeypatch.setattr(config_module, "_account_home", account_home)
    monkeypatch.setattr(config_module, "_effective_uid", lambda: 0)
    paths = posix_dirs("/srv/people/alice/pl")
    assert per_user_cause(paths, platform="linux", env={"HOME": "/root"}) is None
    for name, value in (("SUDO_USER", "alice"), ("DOAS_USER", "alice"), ("PKEXEC_UID", "1000")):
        env = {"HOME": "/root", name: value}
        assert per_user_cause(paths, platform="linux", env=env) == LOCATION_OTHER_USER
        # Fail closed when that account cannot be found.
        env[name] = "nobody-with-this-name" if name != "PKEXEC_UID" else "not-a-number"
        assert per_user_cause(paths, platform="linux", env=env) == LOCATION_UNCONFIRMED
    # A sudo that keeps HOME: alice's home is still alice's, not root's own.
    kept = {"HOME": "/srv/people/alice", "SUDO_USER": "alice"}
    assert per_user_cause(paths, platform="linux", env=kept) == LOCATION_OTHER_USER
    # root running sudo names itself: its home is decided by HOME alone.
    homes["root"] = (0, "/root")
    env = {"HOME": "/root", "SUDO_USER": "root"}
    assert per_user_cause(posix_dirs("/var/lib/portlock"), platform="linux", env=env) is None


@pytest.mark.skipif(sys.platform == "win32", reason="the account database is POSIX")
def test_c2_the_real_account_database_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    import pwd

    me = pwd.getpwuid(os.geteuid())
    monkeypatch.setattr(config_module, "_effective_uid", lambda: -1)
    paths = posix_dirs(str(Path(me.pw_dir) / "pl"))
    env = {"HOME": "/root", "SUDO_USER": me.pw_name}
    assert per_user_cause(paths, platform="linux", env=env) == LOCATION_OTHER_USER
    env["SUDO_USER"] = "portlock-test-no-such-account"
    assert per_user_cause(paths, platform="linux", env=env) == LOCATION_UNCONFIRMED


@pytest.mark.skipif(sys.platform != "win32", reason="the profiles root is a Windows notion")
def test_c2_an_elevated_recover_refuses_another_users_folder(tmp_path: Path) -> None:
    # An elevated window opened with another administrator's credentials. recover refuses
    # the folder before it builds anything or writes anything. (Every path is under
    # tmp_path, so that a regression could never write anywhere else.)
    users = tmp_path / "Users"
    built: list[str] = []

    def create_enforcer(config: Any, hook: Any) -> Any:
        built.append("enforcer")
        raise AssertionError("recover built an enforcer for another user's folder")

    environ = {
        "PORTLOCK_HOME": str(users / "alice" / "pl"),
        "USERPROFILE": str(users / "admin2"),
    }
    code, _out, err = cli(
        tmp_path,
        "recover",
        environ=environ,
        is_elevated=lambda: True,
        create_enforcer=create_enforcer,
    )
    assert code == EXIT_FAILED and "another user's folders" in err
    assert "this user's own folders" not in err and built == []
    assert not (users / "alice").exists()


# --- C3: the reason is true for the case at hand ----------------------------------------------


def test_c3_every_cause_has_its_own_true_reason() -> None:
    texts = {
        cause: Posture(elevated=True, system_wide=False, cause=cause).refusal()
        for cause in (
            LOCATION_OWN,
            LOCATION_OTHER_USER,
            LOCATION_SHARED,
            CAUSE_ACCOUNT_HOME,
            LOCATION_UNCONFIRMED,
        )
    }
    assert len(set(texts.values())) == 5
    own = "this user's own folders"
    assert own in str(texts[LOCATION_OWN])
    assert "another user's folders" in str(texts[LOCATION_OTHER_USER])
    assert "all users of this computer share" in str(texts[LOCATION_SHARED])
    assert "a root installation must not live there" in str(texts[CAUSE_ACCOUNT_HOME])
    assert "network or device path" in str(texts[LOCATION_UNCONFIRMED])
    for cause, text in texts.items():
        assert text is not None and text.startswith("PortLock cannot change this computer: ")
        assert text.endswith("It stays watch-only: it shows and records, and blocks nothing.")
        if cause != LOCATION_OWN:
            assert own not in text
    # Without a cause (a posture built by hand) it reads as the ordinary user's case.
    assert location_clause(None) == location_clause(LOCATION_OWN)


def test_c3_roots_own_home_says_a_root_installation_must_not_live_there() -> None:
    config = Config(paths=PathsConfig(state_dir=Path("/root/pl"), config_dir=Path("/root/pl")))
    posture = detect_posture(config, elevated=True, env={"HOME": "/root"}, platform="linux")
    assert posture.cause == CAUSE_ACCOUNT_HOME
    assert "a root installation must not live there" in str(posture.refusal())
    # The same folder for an ordinary user is simply that user's own.
    user = detect_posture(config, elevated=False, env={"HOME": "/root"}, platform="linux")
    assert user.cause == LOCATION_OWN
    # On Windows an administrator's own profile is that user's own folders.
    windows = detect_posture(
        Config(paths=win_dirs("C:/Users/Alice/pl")), elevated=True, env=ALICE, platform="win32"
    )
    assert windows.cause == LOCATION_OWN


def test_c3_the_command_line_words_each_message_from_the_cause(tmp_path: Path) -> None:
    # An unreadable profile variable: the location cannot be confirmed. Neither the init
    # notice nor recover may claim the files are in this user's own folders.
    unreadable = {"PORTLOCK_HOME": str(tmp_path / "home"), "USERPROFILE": "", "HOME": ""}
    code, out, err = init(tmp_path, environ=unreadable, is_elevated=lambda: True)
    assert code == EXIT_OK, err
    assert "stays watch-only" in out and "own folders" not in out
    assert "cannot confirm" in out
    code, _out, err = cli(tmp_path, "recover", environ=unreadable, is_elevated=lambda: True)
    assert code == EXIT_FAILED and "recover does not act on" in err
    assert "cannot confirm" in err and "own folders" not in err
    if NATIVE == "linux":
        # root's own home: say that a root installation must not live there. (Under
        # tmp_path, so that a regression could never write anywhere else.)
        root_home = tmp_path / "root-home"
        root = {"PORTLOCK_HOME": str(root_home / "pl"), "HOME": str(root_home)}
        code, _out, err = cli(tmp_path, "recover", environ=root, is_elevated=lambda: True)
        assert code == EXIT_FAILED and "a root installation must not live there" in err
        assert not root_home.exists()


@pytest.mark.parametrize(
    ("cause", "words"),
    [
        (LOCATION_OWN, "this user's own folders"),
        (LOCATION_OTHER_USER, "another user's folders"),
        (LOCATION_UNCONFIRMED, "cannot confirm"),
    ],
)
def test_c3_the_leftovers_message_says_why_the_folder_is_not_trusted(
    tmp_path: Path, cause: str, words: str
) -> None:
    posture = Posture(elevated=True, system_wide=False, cause=cause)
    text = daemon._leftovers_message(posture, tmp_path, ["1 open record(s)"], PROGRAM)
    assert words in text and "move the folder aside" in text
    assert "recover" not in text
    for other in ("this user's own folders", "another user's folders", "cannot confirm"):
        if other != words:
            assert other not in text


# --- C4: init beside a running service --------------------------------------------------------


def test_c4_init_refuses_beside_a_running_service_before_creating_anything(
    tmp_path: Path,
) -> None:
    state = tmp_path / "home" / "state"
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
    assert code == EXIT_FAILED
    assert "Ctrl+C" in err and f"'{PROGRAM} stop'" in err and "Nothing was changed" in err
    assert asked == []
    assert sorted(path.name for path in state.iterdir()) == [LOCK_FILE_NAME]
    assert not (tmp_path / "home" / "config").exists()


def test_c4_init_holds_no_lock_while_it_waits_for_a_password(tmp_path: Path) -> None:
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    free: list[bool] = []

    def getpass(prompt: str) -> str:
        # A service started now must get the lock: init is only asking a person.
        probe = InstanceLock(state / LOCK_FILE_NAME)
        free.append(probe.acquire())
        probe.release()
        return PASSWORD

    code, _out, err = cli(
        tmp_path, "init", "--username", ADMIN, is_tty=lambda: True, getpass=getpass
    )
    assert code == EXIT_OK, err
    assert free and all(free)


def test_c4_a_service_started_while_init_waits_makes_it_refuse(tmp_path: Path) -> None:
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    service_lock = InstanceLock(state / LOCK_FILE_NAME)

    def getpass(prompt: str) -> str:
        if not service_lock.held:
            assert service_lock.acquire()  # a service starts while init waits
        return PASSWORD

    try:
        code, _out, err = cli(
            tmp_path, "init", "--username", ADMIN, is_tty=lambda: True, getpass=getpass
        )
    finally:
        service_lock.release()
    assert code == EXIT_FAILED and "Ctrl+C" in err and "Nothing was changed" in err
    assert not (state / "portlock.db").exists()
    assert not (tmp_path / "home" / "config" / "portlock.toml").exists()


def test_c4_init_is_refused_by_a_real_running_service(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    home = tmp_path / "home"
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        seen["init"] = init(tmp_path, environ={"PORTLOCK_HOME": str(home)})
        seen["db_users"] = runtime.accounts.has_users()

    code = run_daemon(make_config(home), NATIVE, Tripwire(), elevated=False, env={}, check=check)
    assert code == DAEMON_OK
    init_code, _out, err = seen["init"]
    assert init_code == EXIT_FAILED and "Ctrl+C" in err and seen["db_users"] is False
    # Once the service is stopped, init works, and the key it shows verifies the log
    # the service wrote before and the records written after.
    code, out, err = init(tmp_path, environ={"PORTLOCK_HOME": str(home)})
    assert code == EXIT_OK, err
    key_file = tmp_path / "shown.key"
    key_file.write_text(shown_key(out), encoding="utf-8")
    written = load_config(
        home / "config" / "portlock.toml", env={"PORTLOCK_HOME": str(home)}, elevated=False
    )
    assert written.audit.hmac_key_file is not None
    code = run_daemon(written, NATIVE, Tripwire(), elevated=False, env={}, check=lambda r, p: None)
    assert code == DAEMON_OK
    code, out, err = cli(
        tmp_path,
        "audit",
        "verify",
        "--offline",
        "--key-file",
        str(key_file),
        environ={"PORTLOCK_HOME": str(home)},
    )
    assert code == EXIT_OK, out + err


def test_c4_the_banner_without_an_administrator_says_stop_init_start() -> None:
    out = io.StringIO()
    announcer = cli_module._Cli(CliEnv(stdout=out, program=PROGRAM))._announce

    class Accounts:
        def has_users(self) -> bool:
            return False

    class Service:
        def get_mode(self) -> Any:
            return None

    class FakeRuntime:
        watch_only = True
        service = Service()
        accounts = Accounts()

    announcer(FakeRuntime(), "127.0.0.1", 47613)
    text = out.getvalue()
    assert "Stop this service (press Ctrl+C here)" in text
    assert f"run '{PROGRAM} init'" in text and f"'{PROGRAM} run'" in text
    assert "in another window first" not in text


# --- C5: init keeps a key store whose key was shown -------------------------------------------


def test_c5_init_keeps_the_key_store_once_an_administrator_was_created(tmp_path: Path) -> None:
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    key_file = tmp_path / "shown.key"
    key_file.write_text(shown_key(out), encoding="utf-8")
    state = tmp_path / "home" / "state"
    # The users table is empty afterwards (a restore, a hand edit): an administrator was
    # still created, and its key was shown then.
    db = Database(state / "portlock.db")
    try:
        db.execute("DELETE FROM auth_users")
    finally:
        db.close()
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "was moved to" not in out and "No audit verification key was shown" in out
    assert not [path for path in state.iterdir() if path.name.startswith("audit.key.unused-")]
    code, out, err = cli(tmp_path, "audit", "verify", "--offline", "--key-file", str(key_file))
    assert code == EXIT_OK, out + err


def test_c5_a_key_store_without_a_database_is_stale(tmp_path: Path) -> None:
    home = tmp_path / "home"
    key = home / "state" / "audit.key"
    key.parent.mkdir(parents=True)
    AuditKeyStore.create(key, anchor_seq=0)
    config = Config(paths=PathsConfig.under(home), audit=AuditConfig(hmac_key_file=key, sinks=()))
    Path(config.paths.config_dir).mkdir(parents=True)
    config.paths.config_file.write_text(config_to_toml(config), encoding="utf-8")
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "was moved to" in out and "Audit verification key" in out


def test_c5_a_service_that_ran_before_init_still_hands_over_a_new_key(tmp_path: Path) -> None:
    run_before_init(tmp_path / "home")
    code, out, _err = init(tmp_path)
    assert code == EXIT_OK and "was moved to" in out and "Audit verification key" in out


# --- C6: leftovers a watch-only start did not see ---------------------------------------------


def unknown_action(path: Path) -> None:
    RecoveryJournal(path, clock=FakeClock(START)).add_hold(
        scope=win("USB/VID_1209&PID_0001/T1"), fingerprint=None
    )
    path.write_bytes(path.read_bytes().replace(b'"action":"block"', b'"action":"block_v2"'))


def damaged_middle(path: Path) -> None:
    journal = RecoveryJournal(path, clock=FakeClock(START))
    journal.add_hold(scope=win("USB/VID_1209&PID_0001/T1"), fingerprint=None)
    record = journal.add_hold(scope=win("USB/VID_1209&PID_0001/T2"), fingerprint=None)
    journal.close([record.id], reason="test")
    lines = path.read_bytes().splitlines(keepends=True)
    lines[0] = lines[0][:20] + b"#garbled#" + lines[0][29:]
    path.write_bytes(b"".join(lines))


def a_directory(path: Path) -> None:
    path.mkdir()


def watch_only_start(config: Config, trip: Tripwire) -> int:
    return run(
        config,
        install_signal_handlers=False,
        clock=FakeClock(START),
        backend=FakeBackend([], clock=FakeClock(START), synchronous=True),
        platform=NATIVE,
        system_ids=lambda devices: frozenset(),
        seams=tripwire_seams(trip),
        elevated=False,
        env={},
        on_started=lambda runtime: pytest.fail("a watch-only service started over leftovers"),
        program=PROGRAM,
    )


@pytest.mark.parametrize("damage", [unknown_action, damaged_middle, a_directory])
def test_c6_journal_lines_it_cannot_read_are_leftovers(
    tmp_path: Path,
    damage: Any,
    capsys: pytest.CaptureFixture[str],
    no_commands: list[Any],
    no_real_objects: list[str],
) -> None:
    config = make_config(tmp_path / "home")
    state = Path(config.paths.state_dir)
    state.mkdir(parents=True)
    journal = state / JOURNAL_FILE_NAME
    damage(journal)
    before = journal.read_bytes() if journal.is_file() else None
    trip = Tripwire()
    assert watch_only_start(config, trip) == EXIT_STATE_UNUSABLE
    err = capsys.readouterr().err
    assert "cannot read" in err and "neither enforce nor undo" in err
    assert (journal.read_bytes() if journal.is_file() else None) == before
    assert journal.exists()
    assert trip.hits == [] and no_commands == [] and no_real_objects == []


def test_c6_a_watch_only_process_never_compacts_or_rewrites_the_journal(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    config = make_config(tmp_path / "home")
    state = Path(config.paths.state_dir)
    state.mkdir(parents=True)
    path = state / JOURNAL_FILE_NAME
    journal = RecoveryJournal(path, clock=FakeClock(START))
    record = journal.add_hold(scope=win("USB/VID_1209&PID_0001/T1"), fingerprint=None)
    # Closed by an enforcing run, but not yet compacted away: nothing is open.
    line = {"op": "close", "id": record.id, "ts": utc_iso(START), "reason": "test"}
    with path.open("ab") as stream:
        stream.write(canonicalize(line).encode("utf-8") + b"\n")
    assert RecoveryJournal(path, clock=FakeClock(START)).open_records() == []
    before = path.read_bytes()
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        seen["read_only"] = runtime.journal.read_only
        runtime.service.tick()

    code = run_daemon(config, NATIVE, Tripwire(), elevated=False, env={}, check=check)
    assert code == DAEMON_OK and seen["read_only"] is True
    assert path.read_bytes() == before


def test_c6_a_read_only_journal_refuses_writes_and_never_compacts(tmp_path: Path) -> None:
    path = tmp_path / JOURNAL_FILE_NAME
    RecoveryJournal(path, clock=FakeClock(START)).add_hold(
        scope=win("USB/VID_1209&PID_0001/T1"), fingerprint=None
    )
    before = path.read_bytes()
    journal = RecoveryJournal(path, clock=FakeClock(START), read_only=True)
    assert journal.read_only and len(journal.open_records()) == 1
    with pytest.raises(StoreError, match="read-only"):
        journal.add_hold(scope=win("USB/VID_1209&PID_0001/T2"), fingerprint=None)
    with pytest.raises(StoreError, match="read-only"):
        journal.close([journal.open_records()[0].id], reason="test")
    journal.compact()
    with journal.recording(scope="global", action=Action.UNBLOCK, fingerprint=None):
        pass
    assert path.read_bytes() == before


# --- C7: a stored default-deny in watch-only ---------------------------------------------------


def test_c7_a_stored_default_deny_is_reported_off_with_a_note(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    home = tmp_path / "home"
    config = make_config(home)
    Path(config.paths.state_dir).mkdir(parents=True)
    db = Database(config.paths.database_file)
    try:
        StateStore(db, clock=FakeClock(START)).set_setting("default_deny", True, by="earlier")
    finally:
        db.close()
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        service = runtime.service
        view = service.get_default_deny()
        assert (view.enabled, view.stored) == (False, True)
        assert view.note is not None and view.note.startswith("A default-deny setting stored")
        settings = service.get_settings().to_dict()
        assert settings["runtime"]["default_deny"] is False
        assert settings["effective"]["default_deny"] is False
        assert settings["notes"] == [view.note]
        runtime.accounts.create_user(ADMIN, PASSWORD, Role.ADMIN, actor="test")
        call = Http(port)
        status, data = call("POST", "/auth/login", {"username": ADMIN, "password": PASSWORD})
        call.token = str(data["token"])
        status, data = call("GET", "/default-deny")
        assert status == 200 and data == {"enabled": False, "stored": True, "note": view.note}
        status, data = call("GET", "/settings")
        assert data["runtime"]["default_deny"] is False and data["notes"] == [view.note]
        seen["cli"] = cli(
            tmp_path,
            "--user",
            ADMIN,
            "--password-stdin",
            "default-deny",
            stdin=PASSWORD + "\n",
            environ={"PORTLOCK_HOME": str(home)},
        )
        # Turning it off stays allowed and clears what is stored.
        assert service.set_default_deny(False, actor=ADMIN, channel="session-test").value is False
        assert service.get_default_deny() == type(view)(False, False, None)

    code = run_daemon(config, NATIVE, Tripwire(), elevated=False, env={}, check=check, api=True)
    assert code == DAEMON_OK
    cli_code, out, err = seen["cli"]
    assert cli_code == EXIT_OK, err
    assert "default-deny is off" in out and "is ignored" in out


def test_c7_an_enforcing_process_reports_what_is_stored(tmp_path: Path) -> None:
    clock = FakeClock(START)
    config = make_config(tmp_path / "home")
    runtime = build_runtime(
        config,
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        enforcer=FakeEnforcer(),
        timer=FakeExternalTimer(),
        dir_privacy=FakeDirPrivacy(),
        system_ids=lambda devices: frozenset(),
    )
    try:
        runtime.store.set_setting("default_deny", True, by="test")
        runtime.service.start(threads=False)
        view = runtime.service.get_default_deny()
        assert (view.enabled, view.stored, view.note) == (True, True, None)
        assert runtime.service.get_settings().to_dict()["notes"] == []
    finally:
        runtime.service.stop()
        runtime.close()


# --- C8: the kill switch with an injected privacy check ---------------------------------------


def test_c8_a_watch_only_run_never_honours_the_kill_switch_with_a_real_enforcer(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    config = make_config(tmp_path / "home")
    Path(config.paths.config_dir).mkdir(parents=True)
    Path(config.paths.state_dir).mkdir(parents=True)
    Path(config.paths.kill_switch_file).write_bytes(b"test\n")
    privacy = FakeDirPrivacy()
    for directory in (config.paths.state_dir, config.paths.config_dir):
        privacy.ensure_private(directory)
    trip = Tripwire()
    with pytest.raises(ValueError, match="stand-ins"):
        run(
            config,
            install_signal_handlers=False,
            clock=FakeClock(START),
            backend=FakeBackend([], clock=FakeClock(START), synchronous=True),
            platform=NATIVE,
            system_ids=lambda devices: frozenset(),
            seams=tripwire_seams(trip),
            dir_privacy=privacy,
            elevated=False,
            env={},
            program=PROGRAM,
        )
    assert no_real_objects == [] and trip.hits == [] and no_commands == []
    assert Path(config.paths.kill_switch_file).exists()
    # The lock was given back.
    probe = InstanceLock(Path(config.paths.state_dir) / LOCK_FILE_NAME)
    assert probe.acquire()
    probe.release()


# --- C9: stop and status when the lock file cannot be opened ----------------------------------


class UnopenableLock:
    """An instance lock whose file this user cannot open for writing."""

    def __init__(self, path: Any) -> None:
        self.path = path

    def acquire(self) -> bool:
        raise PermissionError(errno.EACCES, "Permission denied", str(self.path))

    def release(self) -> None:
        return None


@pytest.mark.parametrize("command", ["stop", "status"])
def test_c9_stop_and_status_say_plainly_that_they_cannot_tell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    state = tmp_path / "home" / "state"
    state.mkdir(parents=True)
    (state / LOCK_FILE_NAME).write_bytes(b"")
    monkeypatch.setattr(cli_module, "InstanceLock", UnopenableLock)
    code, out, err = cli(tmp_path, command)
    assert code == EXIT_UNREACHABLE, out + err
    assert "cannot tell whether the service is running" in err
    assert "Permission denied" in err and "PermissionError" not in err
    # init says so too, before it asks for anything.
    code, _out, err = init(tmp_path)
    assert code == EXIT_FAILED and "cannot tell whether a PortLock service is running" in err


def test_c9_status_falls_back_to_the_runtime_file_and_a_ping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_real_objects: list[str]
) -> None:
    home = tmp_path / "home"
    seen: dict[str, Any] = {}

    def check(runtime: Runtime, port: int) -> None:
        with monkeypatch.context() as patch:
            patch.setattr(cli_module, "InstanceLock", UnopenableLock)
            seen["status"] = cli(tmp_path, "status", environ={"PORTLOCK_HOME": str(home)})

    code = run_daemon(
        make_config(home), NATIVE, Tripwire(), elevated=False, env={}, check=check, api=True
    )
    assert code == DAEMON_OK
    status_code, out, err = seen["status"]
    assert status_code == EXIT_OK, out + err
    assert "is running" in out


def test_c9_a_stop_request_that_cannot_be_written_is_explained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "home" / "state"
    seen: list[str] = []

    def refuse(state_dir: Any) -> None:
        seen.append(str(state_dir))
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(cli_module, "request_stop", refuse)
    with instance_lock(state):
        (state / "runtime.json").write_text(
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
        code, _out, err = cli(tmp_path, "stop")
    assert seen and code == EXIT_FAILED
    assert "the stop request cannot be written" in err and "Ctrl+C" in err


# --- C10: the notice knows only the default location ------------------------------------------


def test_c10_no_notice_for_a_configuration_chosen_by_hand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_wide_elsewhere(monkeypatch, tmp_path)
    code, out, err = init(tmp_path)
    assert code == EXIT_OK, err
    assert "system-wide PortLock installation in the default location" in out
    chosen = tmp_path / "chosen.toml"
    chosen.write_text(
        config_to_toml(Config(paths=PathsConfig.under(tmp_path / "chosen-home"))),
        encoding="utf-8",
    )
    code, out, err = cli(
        tmp_path / "a",
        "--config",
        str(chosen),
        "init",
        "--username",
        ADMIN,
        "--password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert code == EXIT_OK, err
    assert "system-wide" not in out
    code, _out, err = cli(
        tmp_path / "b", "stop", extra_environ={"PORTLOCK_CONFIG": str(chosen)}, home=False
    )
    assert code == EXIT_UNREACHABLE and "system-wide" not in err
    code, _out, err = cli(tmp_path, "stop")
    assert code == EXIT_UNREACHABLE and "in the default location" in err


# --- C11: a refused start creates nothing -----------------------------------------------------


def files_under(root: Path) -> set[str]:
    return {str(path.relative_to(root)) for path in root.rglob("*")}


@pytest.mark.parametrize("leave", [leftover_hold, leftover_lockdown])
def test_c11_a_refused_start_creates_no_key_store_and_no_database(
    tmp_path: Path, leave: Any, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    home = tmp_path / "home"
    config = make_config(home)
    key = Path(config.paths.state_dir) / "audit.key"
    config = Config(
        paths=config.paths,
        mode=config.mode,
        scan=config.scan,
        lockdown=config.lockdown,
        audit=AuditConfig(hmac_key_file=key, sinks=()),
    )
    leave(config)
    before = files_under(home)
    assert watch_only_start(config, Tripwire()) == EXIT_STATE_UNUSABLE
    assert not key.exists()
    # Every start takes the instance lock first; nothing else may be new.
    assert files_under(home) - {str(Path("state") / LOCK_FILE_NAME)} == before


# --- C12: notes the console shows as sentences of their own -----------------------------------


def test_c12_notes_start_with_a_capital_letter(
    tmp_path: Path, no_commands: list[Any], no_real_objects: list[str]
) -> None:
    assert NO_ANTIVIRUS_NOTE.startswith("Antivirus engines are not used in watch-only: ")
    assert WATCH_ONLY_NOTE.startswith("Watch-only: ")
    assert _sentence("the kill switch disabled enforcement") == (
        "The kill switch disabled enforcement."
    )
    assert _sentence("Done already.") == "Done already."

    def check(runtime: Runtime, port: int) -> None:
        mode = runtime.service.get_mode()
        assert mode.notes and all(note[0].isupper() for note in mode.notes)
        assert NO_ANTIVIRUS_NOTE in mode.notes
        notes = runtime.service.status().to_dict()["enforcer"]["notes"]
        assert notes and all(note[0].isupper() for note in notes)

    code = run_daemon(
        make_config(tmp_path / "home"), NATIVE, Tripwire(), elevated=False, env={}, check=check
    )
    assert code == DAEMON_OK
    # An enforcer's own notes reach the console as sentences too.
    clock = FakeClock(START)
    runtime = build_runtime(
        make_config(tmp_path / "other"),
        clock=clock,
        backend=FakeBackend([], clock=clock, synchronous=True),
        enforcer=FakeEnforcer.unprivileged(),
        timer=FakeExternalTimer(),
        dir_privacy=FakeDirPrivacy(),
        system_ids=lambda devices: frozenset(),
    )
    try:
        runtime.service.start(threads=False)
        notes = runtime.service.get_mode().notes
        assert "Simulated: not running with administrator rights." in notes
        assert runtime.service.get_mode().mode is Mode.MONITOR
    finally:
        runtime.service.stop()
        runtime.close()


def test_c12_the_doctor_reason_is_not_doubled(tmp_path: Path) -> None:
    checks = factory._posture_checks(
        make_config(tmp_path / "home"), Posture(elevated=False, system_wide=False)
    )
    detail = checks[0].detail
    assert detail.endswith(NO_ANTIVIRUS_NOTE) and ".." not in detail
    assert "this user's own folders" in checks[1].summary
