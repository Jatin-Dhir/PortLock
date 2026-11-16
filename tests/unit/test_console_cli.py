"""The command line: parsing, exit codes, and every command that works without the service
(``docs/ARCHITECTURE.md`` 4.2). The commands that talk to the service are exercised end to
end in ``tests/integration/test_cli_*.py``."""

from __future__ import annotations

import contextlib
import io
import json
import re
import sqlite3
import tempfile
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive
from portlock.audit.log import AuditKey
from portlock.auth.accounts import AccountStore, AuthPolicy, Channel
from portlock.console import cli as cli_module
from portlock.console.cli import (
    EXIT_AUTH,
    EXIT_CHECK,
    EXIT_FAILED,
    EXIT_OK,
    EXIT_UNREACHABLE,
    EXIT_USAGE,
    CliEnv,
    main,
)
from portlock.core.clock import FakeClock
from portlock.core.config import load_config
from portlock.core.db import Database
from portlock.core.store import JOURNAL_FILE_NAME, RecoveryJournal
from portlock.guard.base import Action, EnforcerCapabilities, JournalEntry
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeExternalTimer
from portlock.service.daemon import (
    LOCK_FILE_NAME,
    RUNTIME_FILE_NAME,
    STOP_REQUEST_NAME,
    InstanceLock,
)

START = datetime(2026, 6, 1, 8, 0, tzinfo=UTC)
NOWHERE = Path(tempfile.gettempdir()) / "portlock-cli-unit-tests-nowhere"
PASSWORD = "an administrator passphrase 2026"


@dataclass
class Result:
    code: int
    out: str
    err: str


def run(
    home: Path | None,
    *argv: str,
    stdin: str = "",
    tty: bool = False,
    secrets: Sequence[str] = (),
    environ: dict[str, str] | None = None,
    nowhere: bool = True,
    **env: Any,
) -> Result:
    """Run ``portlock argv`` with the streams captured and the prompts answered."""
    out, err = io.StringIO(), io.StringIO()
    answers = list(secrets)
    prompts: list[str] = []

    def getpass(prompt: str) -> str:
        prompts.append(prompt)
        return answers.pop(0)

    # Commands that need no home still get one that does not exist, so that nothing can
    # reach the real default directories.
    variables = {"PORTLOCK_HOME": str(home if home is not None else NOWHERE)} if nowhere else {}
    variables.update(environ or {})
    # The same answers on every machine, whoever runs the suite: an administrator who
    # started the installed ``portlock`` command. Per-user runs are tested separately.
    env.setdefault("is_elevated", lambda: True)
    env.setdefault("program", "portlock")
    environment = CliEnv(
        environ=variables,
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
        getpass=getpass,
        clock=FakeClock(START),
        is_tty=lambda: tty,
        **env,
    )
    code = main(list(argv), env=environment)
    result = Result(code, out.getvalue(), err.getvalue())
    result.prompts = prompts  # type: ignore[attr-defined]
    return result


@pytest.fixture(scope="module")
def initialized(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Result]]:
    home = tmp_path_factory.mktemp("cli-home")
    result = run(
        home, "init", "--username", "Root-Admin", "--password-stdin", stdin=PASSWORD + "\n"
    )
    assert result.code == EXIT_OK, result.err
    yield home, result


# --- parsing and usage --------------------------------------------------------------------

COMMANDS = [
    "init",
    "run",
    "stop",
    "status",
    "doctor",
    "devices",
    "approve",
    "deny",
    "trust",
    "grant",
    "revoke",
    "enroll",
    "release-port",
    "policy",
    "audit",
    "scan",
    "lockdown",
    "mode",
    "scope",
    "default-deny",
    "changes",
    "confirm",
    "cancel",
    "recover",
    "simulate",
    "service",
    "user",
]
NESTED = {
    "policy": ["init", "validate", "show", "set", "test"],
    "audit": ["tail", "query", "verify", "export"],
    "lockdown": ["engage", "confirm", "renew", "lift", "status"],
    "service": ["print-unit", "print-task"],
    "user": [
        "list",
        "add",
        "role",
        "disable",
        "enable",
        "delete",
        "unlock",
        "recovery-codes",
        "reset-password",
    ],
}


def test_the_help_lists_every_command_and_the_exit_codes() -> None:
    result = run(None, "--help")
    assert result.code == EXIT_OK and result.err == ""
    for command in COMMANDS:
        assert re.search(rf"\b{re.escape(command)}\b", result.out), command
    assert "Exit codes" in result.out or "exit codes" in result.out
    assert run(None, "--version").out.startswith("portlock 0.")


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_has_help(command: str) -> None:
    result = run(None, command, "--help")
    assert result.code == EXIT_OK and result.out.startswith("usage: portlock " + command)
    for option in ("--config", "--url", "--user", "--password-stdin", "--json", "--timeout"):
        assert option in result.out, (command, option)


@pytest.mark.parametrize(("command", "actions"), sorted(NESTED.items()))
def test_every_subcommand_has_help(command: str, actions: list[str]) -> None:
    for action in actions:
        result = run(None, command, action, "--help")
        assert result.code == EXIT_OK and f"usage: portlock {command} {action}" in result.out


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["frobnicate"],
        ["approve"],
        ["approve", "notanumber"],
        ["trust", "--kind", "forever"],
        ["policy"],
        ["audit", "export", "--since-seq", "x"],
        ["lockdown", "engage", "--minutes", "x"],
        ["user", "add", "bob"],
        ["user", "add", "bob", "--role", "root"],
        ["status", "--unknown"],
        ["mode", "sideways"],
        ["scope", "everything"],
        ["devices", "--limit"],
        ["grant", "FP"],
        ["--timeout", "soon", "status"],
    ],
)
def test_bad_arguments_are_a_usage_error(argv: list[str]) -> None:
    result = run(None, *argv)
    assert result.code == EXIT_USAGE
    assert result.err or result.out  # something said what is wrong


def test_a_password_is_never_accepted_as_an_argument_or_read_from_the_environment(
    tmp_path: Path,
) -> None:
    refused = run(tmp_path, "--password", "hunter2hunter2", "status")
    assert refused.code == EXIT_USAGE and "hunter2" not in refused.out
    refused = run(tmp_path, "devices", "--password=hunter2hunter2")
    assert refused.code == EXIT_USAGE
    # PORTLOCK_PASSWORD is not a thing: with no terminal and no --password-stdin there is no way in.
    (tmp_path / "state").mkdir()
    runtime = tmp_path / "state" / RUNTIME_FILE_NAME
    runtime.write_text(
        json.dumps(
            {
                "v": 1,
                "pid": 1,
                "host": "127.0.0.1",
                "port": 9,
                "run_id": "0" * 16,
                "started_at": "2026-01-01T00:00:00.000000Z",
                "version": "0",
                "secret": "s",
            }
        )
    )
    result = run(
        tmp_path, "--user", "admin", "devices", environ={"PORTLOCK_PASSWORD": "hunter2hunter2"}
    )
    assert result.code in (EXIT_UNREACHABLE, EXIT_USAGE)


def test_global_options_work_before_or_after_the_command(tmp_path: Path) -> None:
    for argv in (
        ["--json", "status"],
        ["status", "--json"],
        ["--url", "http://127.0.0.1:1", "status"],
        ["status", "--url", "http://127.0.0.1:1", "--timeout", "1"],
    ):
        result = run(tmp_path, *argv)
        assert result.code == EXIT_UNREACHABLE, (argv, result.err)
    # The command's own value is not overwritten by the default of the top-level parser.
    result = run(tmp_path, "--json", "status", "--timeout", "1", "--url", "ftp://127.0.0.1:1")
    assert result.code == EXIT_USAGE and "--url must look like" in result.err


# --- finding the service ------------------------------------------------------------------


def test_a_service_command_without_a_running_service_says_so_and_exits_4(tmp_path: Path) -> None:
    result = run(tmp_path, "devices", "--user", "admin", "--password-stdin", stdin="x\n")
    assert result.code == EXIT_UNREACHABLE
    assert "the service is not running" in result.err and RUNTIME_FILE_NAME in result.err
    assert result.out == ""


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://example.com:47600", EXIT_USAGE),
        ("http://192.0.2.1:47600", EXIT_USAGE),
        ("https://127.0.0.1:47600", EXIT_USAGE),
        ("127.0.0.1:47600", EXIT_USAGE),
        ("http://127.0.0.1", EXIT_USAGE),
        ("http://127.0.0.1:1", EXIT_UNREACHABLE),
        ("http://localhost:1", EXIT_UNREACHABLE),
        ("http://[::1]:1", EXIT_UNREACHABLE),
    ],
)
def test_the_url_must_be_loopback_http_with_a_port(tmp_path: Path, url: str, code: int) -> None:
    result = run(tmp_path, "--url", url, "--timeout", "2", "status")
    assert result.code == code, result.err


def test_the_url_may_come_from_the_environment(tmp_path: Path) -> None:
    result = run(
        tmp_path, "--timeout", "2", "status", environ={"PORTLOCK_URL": "http://127.0.0.1:1"}
    )
    assert result.code == EXIT_UNREACHABLE and "did not answer" in result.err


def test_a_corrupt_runtime_file_is_the_same_as_no_service(tmp_path: Path) -> None:
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / RUNTIME_FILE_NAME).write_text("{not json")
    assert run(tmp_path, "status").code == EXIT_UNREACHABLE
    (tmp_path / "state" / RUNTIME_FILE_NAME).write_text(json.dumps({"v": 1}))
    assert run(tmp_path, "status").code == EXIT_UNREACHABLE


def test_a_configuration_problem_is_reported_with_its_path(tmp_path: Path) -> None:
    config = tmp_path / "bad.toml"
    config.write_text('mode = "sometimes"\n[api]\nport = 99999\n', encoding="utf-8")
    result = run(tmp_path, "--config", str(config), "status")
    assert result.code == EXIT_FAILED and "configuration" in result.err and "mode" in result.err


def test_a_missing_named_configuration_file_is_an_error(tmp_path: Path) -> None:
    result = run(tmp_path, "--config", str(tmp_path / "nope.toml"), "status")
    assert result.code == EXIT_FAILED and "configuration" in result.err


# --- init ---------------------------------------------------------------------------------


def test_init_shows_the_key_and_the_recovery_codes_once(initialized: tuple[Path, Result]) -> None:
    home, result = initialized
    text = result.out
    assert "PortLock is set up." in text and "Administrator: root-admin" in text
    key = re.search(r"Audit verification key.*\n\s+(\S+)", text).group(1)  # type: ignore[union-attr]
    codes = re.findall(r"^\s{2}([0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){7})$", text, re.MULTILINE)
    assert len(codes) == 8 and len(set(codes)) == 8
    assert AuditKey.parse(key).anchor_seq == 0
    assert PASSWORD not in text and PASSWORD not in result.err
    config = load_config(home / "config" / "portlock.toml", env={})
    assert config.audit.hmac_key_file is not None and Path(config.audit.hmac_key_file).is_file()
    for path in home.rglob("*"):
        if path.is_file() and path.suffix != ".db":
            data = path.read_bytes()
            assert key.encode() not in data, path
            assert not any(code.encode() in data for code in codes), path
    db = sqlite3.connect(home / "state" / "portlock.db")
    try:
        raw = b"".join(
            bytes(str(row), "utf-8") for row in db.execute("SELECT * FROM auth_recovery_codes")
        )
    finally:
        db.close()
    assert not any(code.replace("-", "").encode().lower() in raw.lower() for code in codes)
    assert "portlock run" in text and "portlock enroll" in text and "print-unit" in text


def test_the_recovery_codes_init_printed_work(initialized: tuple[Path, Result]) -> None:
    home, result = initialized
    codes = re.findall(r"^\s{2}([0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){7})$", result.out, re.MULTILINE)
    config = load_config(home / "config" / "portlock.toml", env={})
    db = Database(config.paths.database_file)
    try:
        accounts = AccountStore(db, clock=FakeClock(START), policy=AuthPolicy())
        user = accounts.get_user("root-admin")
        assert user is not None and user.role.value == "admin"
        assert accounts.authenticate("root-admin", PASSWORD, channel=Channel.LOCAL).ok
        assert accounts.use_recovery_code("root-admin", codes[0], channel=Channel.LOCAL)
        assert not accounts.use_recovery_code("root-admin", codes[0], channel=Channel.LOCAL)
        assert accounts.remaining_recovery_codes("root-admin") == 7
    finally:
        db.close()


def test_init_refuses_to_run_twice(initialized: tuple[Path, Result]) -> None:
    home, _ = initialized
    result = run(home, "init", "--username", "second", "--password-stdin", stdin=PASSWORD + "x\n")
    assert result.code == EXIT_FAILED and "already set up" in result.err
    assert "recovery" not in result.out.lower()


def test_init_refuses_a_weak_password_and_creates_nothing(tmp_path: Path) -> None:
    result = run(tmp_path, "init", "--password-stdin", stdin="short\n")
    assert result.code == EXIT_FAILED and "not acceptable" in result.err
    assert "recovery" not in result.out.lower()
    for word in ("portlock123", "password1234"):
        assert run(tmp_path, "init", "--password-stdin", stdin=word + "\n").code == EXIT_FAILED


def test_init_asks_twice_at_a_terminal_and_rejects_a_mismatch(tmp_path: Path) -> None:
    result = run(
        tmp_path, "init", tty=True, stdin="\n", secrets=[PASSWORD, "something else entirely 1"] * 3
    )
    assert result.code == EXIT_FAILED and "differ" in result.err
    ok = run(tmp_path / "ok", "init", tty=True, stdin="boss\n", secrets=[PASSWORD, PASSWORD])
    assert ok.code == EXIT_OK and "Administrator: boss" in ok.out
    assert ok.prompts == ["New administrator password: ", "Repeat it: "]  # type: ignore[attr-defined]


def test_init_with_no_terminal_and_no_stdin_flag_cannot_ask(tmp_path: Path) -> None:
    result = run(tmp_path, "init")
    assert result.code == EXIT_USAGE and "--password-stdin" in result.err


def test_init_does_not_rewrite_an_operators_configuration(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    own = config_dir / "portlock.toml"
    own.write_text('host_label = "lab"\n', encoding="utf-8")
    result = run(tmp_path, "init", "--username", "boss", "--password-stdin", stdin=PASSWORD + "\n")
    assert result.code == EXIT_OK and own.read_text(encoding="utf-8") == 'host_label = "lab"\n'
    assert "hmac_key_file" in result.out and "No audit verification key was shown" in result.out


# --- local account commands, offline audit verification -----------------------------------


def test_a_lost_password_is_reset_on_the_machine(initialized: tuple[Path, Result]) -> None:
    home, _ = initialized
    new = "the replacement passphrase 77"
    result = run(
        home,
        "user",
        "reset-password",
        "root-admin",
        "--local",
        "--password-stdin",
        stdin=new + "\n",
    )
    assert result.code == EXIT_OK and "every session ended" in result.out
    config = load_config(home / "config" / "portlock.toml", env={})
    db = Database(config.paths.database_file)
    try:
        accounts = AccountStore(db, clock=FakeClock(START), policy=AuthPolicy())
        assert accounts.authenticate("root-admin", new, channel=Channel.LOCAL).ok
        assert not accounts.authenticate("root-admin", PASSWORD, channel=Channel.LOCAL).ok
        for _ in range(6):
            accounts.authenticate("root-admin", "wrong wrong wrong 1", channel=Channel.NETWORK)
        assert accounts.lockout_remaining("root-admin") > 0
    finally:
        db.close()
    assert run(home, "user", "unlock", "root-admin", "--local").code == EXIT_OK
    db = Database(config.paths.database_file)
    try:
        assert (
            AccountStore(db, clock=FakeClock(START), policy=AuthPolicy()).lockout_remaining(
                "root-admin"
            )
            == 0
        )
    finally:
        db.close()
    assert run(home, "user", "unlock", "nobody", "--local").code == EXIT_FAILED
    weak = run(
        home, "user", "reset-password", "root-admin", "--local", "--password-stdin", stdin="weak\n"
    )
    assert weak.code == EXIT_FAILED
    entries = (home / "state" / "audit.head").exists()
    assert entries


def test_the_offline_verification_walks_the_chain_with_the_key_and_notices_tampering(
    initialized: tuple[Path, Result], tmp_path: Path
) -> None:
    home, result = initialized
    key = re.search(r"Audit verification key.*\n\s+(\S+)", result.out).group(1)  # type: ignore[union-attr]
    key_file = tmp_path / "initial.key"
    key_file.write_text(key + "\n", encoding="utf-8")
    plain = run(home, "audit", "verify", "--offline")
    assert plain.code == EXIT_OK and "verifies" in plain.out and "no MACs were checked" in plain.out
    keyed = run(home, "audit", "verify", "--offline", "--key-file", str(key_file))
    assert keyed.code == EXIT_OK and "verifies" in keyed.out and "no MACs" not in keyed.out
    wrong = tmp_path / "wrong.key"
    wrong.write_text(AuditKey(0, b"\x01" * 32).encode(), encoding="utf-8")
    assert run(home, "audit", "verify", "--offline", "--key-file", str(wrong)).code == EXIT_CHECK
    assert (
        run(home, "audit", "verify", "--offline", "--key-file", str(tmp_path / "nope")).code
        == EXIT_FAILED
    )
    db = sqlite3.connect(home / "state" / "portlock.db")
    try:
        db.execute("DROP TRIGGER audit_log_no_update")  # what an attacker with the file would do
        db.execute("UPDATE audit_log SET data = '{\"forged\":true}' WHERE seq = 2")
        db.commit()
    finally:
        db.close()
    broken = run(home, "audit", "verify", "--offline")
    assert broken.code == EXIT_CHECK and "DOES NOT verify at record 2" in broken.out


def test_offline_verification_without_a_database_says_to_run_init(tmp_path: Path) -> None:
    result = run(tmp_path, "audit", "verify", "--offline")
    assert result.code == EXIT_FAILED and "portlock init" in result.err


# --- policy files -------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "policies"


def test_a_policy_file_is_validated_without_the_service() -> None:
    good = run(None, "policy", "validate", str(FIXTURES / "office.json"))
    assert good.code == EXIT_OK and re.match(
        r"valid: .+, \d+ rule\(s\), hash [0-9a-f]{64}", good.out
    )
    toml = run(None, "policy", "validate", str(FIXTURES / "office.toml"))
    assert toml.code == EXIT_OK
    bad = run(None, "policy", "validate", str(FIXTURES / "broken.json"))
    assert bad.code == EXIT_CHECK and bad.out.startswith("not valid:") and "rules[" in bad.out
    assert run(None, "policy", "validate", str(FIXTURES / "dupkey.json")).code == EXIT_CHECK
    assert run(None, "policy", "validate", str(FIXTURES / "missing.json")).code == EXIT_CHECK


def test_a_policy_is_created_and_never_overwritten_by_accident(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    made = run(None, "policy", "init", "--output", str(target))
    assert made.code == EXIT_OK and json.loads(target.read_text(encoding="utf-8"))["version"] == 1
    assert run(None, "policy", "validate", str(target)).code == EXIT_OK
    assert run(None, "policy", "init", "--output", str(target)).code == EXIT_FAILED
    assert run(None, "policy", "init", "--output", str(target), "--force").code == EXIT_OK
    printed = run(None, "policy", "init")
    assert json.loads(printed.out)["name"] == "PortLock default policy"
    example = run(None, "policy", "init", "--example")
    assert example.code == EXIT_OK and json.loads(example.out)["rules"]
    assert run(None, "policy", "validate", str(tmp_path / "x.json")).code == EXIT_CHECK


def test_a_policy_can_be_tried_on_a_device_without_the_service(tmp_path: Path) -> None:
    device = json.dumps(
        {
            "vendor_id": 4617,
            "product_id": 5,
            "serial": "TEST0005BAD1",
            "interfaces": [
                {"cls": 8, "subcls": 6, "protocol": 80},
                {"cls": 3, "subcls": 1, "protocol": 1},
            ],
        }
    )
    default = tmp_path / "default.json"
    run(None, "policy", "init", "--output", str(default))
    result = run(None, "policy", "test", "--local", "--policy", str(default), "--device", device)
    assert result.code == EXIT_OK and result.out.startswith("deny: rule deny-input-with-other")
    stick = json.dumps(
        {
            "vendor_id": 4617,
            "product_id": 1,
            "serial": "TEST0001A7C3",
            "interfaces": [{"cls": 8, "subcls": 6, "protocol": 80}],
        }
    )
    assert (
        "(the policy default)"
        in run(None, "policy", "test", "--local", "--policy", str(default), "--device", stick).out
    )
    from_file = tmp_path / "device.json"
    from_file.write_text(stick, encoding="utf-8")
    assert (
        run(
            None, "policy", "test", "--local", "--policy", str(default), "--device", f"@{from_file}"
        ).code
        == EXIT_OK
    )
    assert run(None, "policy", "test", "--local").code == EXIT_USAGE
    assert (
        run(None, "policy", "test", "--local", "--policy", str(default), "--device", "{nope").code
        == EXIT_USAGE
    )
    assert (
        run(None, "policy", "test", "--local", "--policy", str(default), "--device", "[1]").code
        == EXIT_USAGE
    )
    assert (
        run(
            None,
            "policy",
            "test",
            "--local",
            "--policy",
            str(default),
            "--device",
            '{"vendor_id": 99999, "product_id": 1}',
        ).code
        == EXIT_USAGE
    )


# --- service definitions ------------------------------------------------------------------


def test_the_unit_is_printed_for_review_and_the_instructions_go_to_stderr(tmp_path: Path) -> None:
    result = run(
        None,
        "service",
        "print-unit",
        "--executable",
        "/usr/local/bin/portlock",
        host_platform="linux",
        nowhere=False,
    )
    assert result.code == EXIT_OK
    assert (
        result.out.startswith("# PortLock service unit")
        and "ExecStart=/usr/local/bin/portlock run" in result.out
    )
    assert "systemctl enable --now portlock" in result.err and "yourself" in result.err
    target = tmp_path / "portlock.service"
    written = run(
        None,
        "service",
        "print-unit",
        "--executable",
        "/usr/local/bin/portlock",
        "--output",
        str(target),
        host_platform="linux",
        nowhere=False,
    )
    assert written.code == EXIT_OK and "Nothing was installed." in written.out
    assert target.read_text(encoding="utf-8").startswith("# PortLock service unit")
    again = run(
        None,
        "service",
        "print-unit",
        "--executable",
        "/usr/local/bin/portlock",
        "--output",
        str(target),
        host_platform="linux",
        nowhere=False,
    )
    assert again.code == EXIT_FAILED and "--force" in again.err
    assert (
        run(
            None,
            "service",
            "print-unit",
            "--executable",
            "/usr/local/bin/portlock",
            "--output",
            str(target),
            "--force",
            host_platform="linux",
            nowhere=False,
        ).code
        == EXIT_OK
    )


def test_a_unit_for_another_system_needs_the_executable_and_says_what_it_assumed() -> None:
    result = run(None, "service", "print-unit", host_platform="win32", nowhere=False)
    assert result.code == EXIT_USAGE and "--executable is required" in result.err
    other = run(
        None,
        "service",
        "print-unit",
        "--executable",
        "/opt/portlock/bin/portlock",
        host_platform="win32",
        nowhere=False,
    )
    assert other.code == EXIT_OK and "Linux default directories" in other.err
    assert "ReadWritePaths=/var/lib/portlock /etc/portlock /etc/udev/rules.d" in other.out


def test_the_task_is_written_as_utf_16_with_a_byte_order_mark(tmp_path: Path) -> None:
    target = tmp_path / "task.xml"
    result = run(
        None,
        "service",
        "print-task",
        "--executable",
        "C:\\PortLock\\python.exe",
        "--output",
        str(target),
        "--config",
        "C:\\ProgramData\\PortLock\\portlock.toml",
        host_platform="win32",
        nowhere=False,
    )
    assert result.code == EXIT_OK, result.err
    raw = target.read_bytes()
    assert raw.startswith(b"\xff\xfe")
    text = raw[2:].decode("utf-16-le")
    assert "<UserId>S-1-5-18</UserId>" in text and "C:\\PortLock\\python.exe" in text
    assert 'schtasks /Create /TN "\\PortLock\\Service"' in result.err


def test_a_hostile_executable_is_refused_by_the_command() -> None:
    result = run(
        None,
        "service",
        "print-unit",
        "--executable",
        "relative/portlock",
        host_platform="linux",
        nowhere=False,
    )
    assert result.code == EXIT_FAILED and "absolute" in result.err


# --- stop and run -------------------------------------------------------------------------


def write_runtime(state: Path) -> Path:
    state.mkdir(parents=True, exist_ok=True)
    path = state / RUNTIME_FILE_NAME
    path.write_text(
        json.dumps(
            {
                "v": 1,
                "pid": 4242,
                "host": "127.0.0.1",
                "port": 47600,
                "run_id": "0123456789abcdef",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "version": "0.2.0",
                "secret": "s" * 20,
            }
        )
    )
    return path


@contextlib.contextmanager
def service_lock(state: Path) -> Iterator[None]:
    """Hold the instance lock the way a running service does."""
    lock = InstanceLock(state / LOCK_FILE_NAME)
    assert lock.acquire()
    try:
        yield
    finally:
        lock.release()


def test_stop_asks_politely_and_waits_for_the_service_to_go(tmp_path: Path) -> None:
    assert run(tmp_path, "stop").code == EXIT_UNREACHABLE
    runtime = write_runtime(tmp_path / "state")
    ticks: list[float] = []

    def sleep(seconds: float) -> None:
        ticks.append(seconds)
        if len(ticks) == 3:
            runtime.unlink()  # the service shut down

    with service_lock(tmp_path / "state"):
        result = run(tmp_path, "stop", sleep=sleep)
    assert result.code == EXIT_OK and "The service stopped." in result.out
    assert (tmp_path / "state" / STOP_REQUEST_NAME).read_bytes() == b"stop\n"
    assert len(ticks) == 3


def test_stop_gives_up_after_fifteen_seconds(tmp_path: Path) -> None:
    write_runtime(tmp_path / "state")
    clock = [0.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    with service_lock(tmp_path / "state"):
        result = run(tmp_path, "stop", sleep=sleep, monotonic=lambda: clock[0])
    assert result.code == EXIT_FAILED and "did not stop within 15 seconds" in result.err
    assert 15.0 <= clock[0] < 16.0


def test_stop_after_a_killed_service_says_not_running_at_once(tmp_path: Path) -> None:
    # A killed service leaves runtime.json behind, but nobody holds the instance lock.
    runtime = write_runtime(tmp_path / "state")
    (tmp_path / "state" / LOCK_FILE_NAME).write_bytes(b"")

    def sleep(seconds: float) -> None:
        raise AssertionError("stop waited for a service that is not there")

    result = run(tmp_path, "stop", sleep=sleep)
    assert result.code == EXIT_UNREACHABLE and "the service is not running" in result.err
    assert not runtime.exists()
    assert not (tmp_path / "state" / STOP_REQUEST_NAME).exists()
    status = run(tmp_path, "status")
    assert status.code == EXIT_UNREACHABLE and "not running" in status.err
    assert "Error" not in status.err


def test_run_hands_the_configuration_and_the_api_to_the_daemon(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_run(config: Any, **kwargs: Any) -> int:
        seen.update(kwargs, config=config)
        return 5

    result = run(tmp_path, "run", run_service=fake_run, run_options={"tick_seconds": 0.5})
    assert result.code == 5  # the daemon's own exit code is passed through
    assert seen["config"].paths.state_dir == tmp_path / "state"
    assert seen["api_factory"] is cli_module.api_factory and seen["tick_seconds"] == 0.5


@pytest.mark.parametrize(
    ("raised", "code", "fragment"),
    [
        (OSError("disk on fire"), EXIT_FAILED, "OSError: disk on fire"),
        (ValueError("bad value"), EXIT_FAILED, "ValueError"),
        (KeyboardInterrupt(), 130, "interrupted"),
    ],
)
def test_an_unexpected_failure_is_one_line_and_a_nonzero_exit(
    tmp_path: Path, raised: BaseException, code: int, fragment: str
) -> None:
    def boom(config: Any, **kwargs: Any) -> int:
        raise raised

    result = run(tmp_path, "run", run_service=boom)
    assert result.code == code and fragment in result.err and "Traceback" not in result.err
    debug = run(tmp_path, "run", run_service=boom, environ={"PORTLOCK_DEBUG": "1"})
    assert debug.code == code and (code == 130 or "Traceback" in debug.err)


def test_a_portlock_error_is_one_escaped_line(tmp_path: Path) -> None:
    from portlock.core.errors import StoreError

    def boom(config: Any, **kwargs: Any) -> int:
        raise StoreError("the database \x1b[31mis damaged\x1b[0m")

    result = run(tmp_path, "run", run_service=boom)
    assert result.code == EXIT_FAILED and "\x1b" not in result.err and "\\x1b" in result.err


# --- doctor, simulate ----------------------------------------------------------------------


class FakeReport:
    def __init__(self, *statuses: str) -> None:
        self.statuses = statuses

    def to_dict(self) -> dict[str, Any]:
        return {
            "checks": [
                {
                    "id": f"guard.c{n}",
                    "status": status,
                    "summary": f"check {n} \x1b[1m",
                    "detail": "d",
                }
                for n, status in enumerate(self.statuses)
            ],
            "worst": "x",
        }


def test_doctor_checks_this_machine_directly_when_there_is_no_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli_module.factory, "doctor", lambda config, clock, **_: FakeReport("ok", "warn", "info")
    )
    result = run(tmp_path, "doctor", "--offline")
    assert (
        result.code == EXIT_OK
        and "[ok  ] guard.c0" in result.out
        and "[warn] guard.c1" in result.out
    )
    assert "\x1b" not in result.out and "\\x1b" in result.out
    fallback = run(tmp_path, "doctor")
    assert fallback.code == EXIT_OK and "checking this machine directly" in fallback.err
    monkeypatch.setattr(
        cli_module.factory, "doctor", lambda config, clock, **_: FakeReport("ok", "fail")
    )
    assert run(tmp_path, "doctor", "--offline").code == EXIT_CHECK
    as_json = run(tmp_path, "doctor", "--offline", "--json")
    assert json.loads(as_json.out)["checks"][1]["status"] == "fail" and as_json.code == EXIT_CHECK


def test_simulate_passes_its_options_to_the_simulator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake(args: Any, **kwargs: Any) -> int:
        captured.update(vars(args), **kwargs)
        return 0

    monkeypatch.setattr(cli_module, "run_simulation", fake)
    assert (
        run(tmp_path, "simulate", "--port", "5", "--no-serve", "--scenario", "none").code == EXIT_OK
    )
    assert captured["port"] == 5 and captured["serve"] is False and captured["scenario"] == "none"
    assert run(tmp_path, "simulate").code == EXIT_OK
    assert captured["serve"] is True and captured["scenario"] == "tour" and captured["port"] == 0
    # No option can select a real enforcer.
    helptext = run(None, "simulate", "--help").out
    assert "enforcer" not in helptext and "backend" not in helptext and "--config" in helptext


# --- recover ------------------------------------------------------------------------------


class Machine:
    """A simulated operating system with something PortLock changed, and the journal of it."""

    def __init__(self, home: Path, *, privileged: bool = True) -> None:
        self.state = home / "state"
        self.state.mkdir(parents=True)
        self.hook: Callable[[JournalEntry], None] | None = None
        self.backend = FakeBackend(synchronous=True)
        caps = (
            None
            if privileged
            else EnforcerCapabilities(
                name="fake",
                privileged=False,
                block=False,
                read_only=False,
                eject=False,
                default_deny=False,
            )
        )
        self.enforcer = FakeEnforcer(backend=self.backend, write_ahead=self._ahead)
        self.timer = FakeExternalTimer()
        self.backend.start(lambda event: None)
        self.device = self.backend.plug(flash_drive("TEST0001A7C3"))
        journal = RecoveryJournal(self.state / JOURNAL_FILE_NAME, clock=FakeClock(START))
        self.hook = journal.write_ahead
        with journal.recording(
            scope=self.device.instance_id, action=Action.BLOCK, fingerprint=None
        ):
            assert self.enforcer.block(self.device).ok
        if caps is not None:
            self.enforcer.set_capabilities(caps)  # the enforcer later runs without rights

    def _ahead(self, entry: JournalEntry) -> None:
        assert self.hook is not None
        self.hook(entry)

    def factories(self) -> dict[str, Any]:
        def create_enforcer(config: Any, hook: Callable[[JournalEntry], None]) -> FakeEnforcer:
            self.hook = hook
            return self.enforcer

        return {
            "create_enforcer": create_enforcer,
            "create_backend": lambda config, clock: self.backend,
            "create_timer": lambda config: self.timer,
        }


def open_records(state: Path) -> int:
    return len(RecoveryJournal(state / JOURNAL_FILE_NAME, clock=FakeClock(START)).open_records())


def test_recover_lists_what_it_would_restore_and_changes_nothing(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    assert machine.enforcer.is_blocked(machine.device)
    result = run(tmp_path, "recover", "--dry-run", **machine.factories())
    assert (
        result.code == EXIT_OK
        and "1 open journal record(s)" in result.out
        and "nothing was changed" in result.out
    )
    assert "block" in result.out
    assert machine.enforcer.is_blocked(machine.device) and open_records(machine.state) == 1
    assert not (tmp_path / "config" / "DISABLE_ENFORCEMENT").exists()


def test_recover_puts_every_journaled_setting_back_with_no_database_and_no_login(
    tmp_path: Path,
) -> None:
    machine = Machine(tmp_path)
    assert not (machine.state / "portlock.db").exists()  # no database anywhere
    result = run(tmp_path, "recover", **machine.factories())
    assert result.code == EXIT_OK, result.err
    assert "1 setting(s) restored" in result.out and "0 failed" in result.out
    assert not machine.enforcer.is_blocked(machine.device) and open_records(machine.state) == 0
    kill_switch = tmp_path / "config" / "DISABLE_ENFORCEMENT"
    assert kill_switch.is_file() and "delete that file" in result.out
    assert (machine.state / "last-recover.json").is_file()  # for the next start to audit
    again = run(tmp_path, "recover", **machine.factories())
    assert again.code == EXIT_OK and "0 setting(s) restored" in again.out


def test_recover_needs_administrator_rights(tmp_path: Path) -> None:
    machine = Machine(tmp_path, privileged=False)
    result = run(tmp_path, "recover", **machine.factories())
    assert result.code == EXIT_AUTH and "administrator" in result.err
    assert open_records(machine.state) == 1
    # A refused attempt must not leave the kill switch behind: creating that file is
    # what switches enforcement off.
    assert not (tmp_path / "config" / "DISABLE_ENFORCEMENT").exists()
    assert machine.enforcer.is_blocked(machine.device)


def test_recover_works_with_the_config_argument_the_dead_man_timer_passes(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    config = tmp_path / "config" / "portlock.toml"
    config.parent.mkdir()
    config.write_text('host_label = "box"\n', encoding="utf-8")
    result = run(
        None,
        "recover",
        "--config",
        str(config),
        environ={"PORTLOCK_HOME": str(tmp_path)},
        **machine.factories(),
    )
    assert result.code == EXIT_OK and open_records(machine.state) == 0


def test_recover_keeps_going_when_devices_or_the_timer_cannot_be_reached(tmp_path: Path) -> None:
    from portlock.core.errors import BackendError

    machine = Machine(tmp_path)
    factories = machine.factories()

    def broken_backend(config: Any, clock: Any) -> Any:
        raise BackendError("no device API here")

    def broken_timer(config: Any) -> Any:
        raise BackendError("no scheduler here")

    result = run(
        tmp_path,
        "recover",
        **{**factories, "create_backend": broken_backend, "create_timer": broken_timer},
    )
    assert result.code == EXIT_OK
    assert (
        "devices could not be listed" in result.err
        and "dead-man timer could not be reached" in result.err
    )
    assert open_records(machine.state) == 0


def test_recover_beside_a_running_service_creates_the_kill_switch_and_waits_for_it(
    tmp_path: Path,
) -> None:
    machine = Machine(tmp_path)
    service = InstanceLock(machine.state / LOCK_FILE_NAME)
    assert service.acquire()  # the service is running
    try:
        clock = [0.0]
        journal_path = machine.state / JOURNAL_FILE_NAME

        def sleep(seconds: float) -> None:
            clock[0] += seconds
            if clock[0] >= 1.0:
                journal_path.write_text("")  # the service honoured the file and restored

        result = run(
            tmp_path, "recover", sleep=sleep, monotonic=lambda: clock[0], **machine.factories()
        )
        assert result.code == EXIT_OK and "The journal is empty" in result.out
        assert (tmp_path / "config" / "DISABLE_ENFORCEMENT").is_file()
        assert machine.enforcer.is_blocked(machine.device)  # not touched by the command itself
    finally:
        service.release()


def test_recover_beside_a_service_that_does_not_restore_says_to_stop_it(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    service = InstanceLock(machine.state / LOCK_FILE_NAME)
    assert service.acquire()
    try:
        clock = [0.0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        result = run(
            tmp_path, "recover", sleep=sleep, monotonic=lambda: clock[0], **machine.factories()
        )
        assert result.code == EXIT_FAILED and "stop the PortLock process" in result.err
    finally:
        service.release()


def test_the_dead_man_recover_restores_without_the_kill_switch(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    result = run(tmp_path, "recover", "--dead-man", **machine.factories())
    assert result.code == EXIT_OK, result.err
    assert "1 setting(s) restored" in result.out
    assert not machine.enforcer.is_blocked(machine.device) and open_records(machine.state) == 0
    # The timer must never switch enforcement off for good: the next start sees the marker,
    # ends the lockdown it describes as recovered and carries on enforcing.
    assert not (tmp_path / "config" / "DISABLE_ENFORCEMENT").exists()
    assert (machine.state / "last-recover.json").is_file()
    assert "not disabled" in result.out and "delete that file" not in result.out


def test_the_dead_man_recover_leaves_a_running_service_alone(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    service = InstanceLock(machine.state / LOCK_FILE_NAME)
    assert service.acquire()  # the service is running and ends its own lockdown
    try:
        result = run(tmp_path, "recover", "--dead-man", **machine.factories())
        assert result.code == EXIT_OK and "Nothing was changed" in result.out
        assert not (tmp_path / "config" / "DISABLE_ENFORCEMENT").exists()
        assert machine.enforcer.is_blocked(machine.device) and open_records(machine.state) == 1
        assert not (machine.state / "last-recover.json").exists()
    finally:
        service.release()


def test_an_unprivileged_dead_man_recover_changes_nothing(tmp_path: Path) -> None:
    machine = Machine(tmp_path, privileged=False)
    result = run(tmp_path, "recover", "--dead-man", **machine.factories())
    assert result.code == EXIT_AUTH
    assert not (tmp_path / "config" / "DISABLE_ENFORCEMENT").exists()
    assert machine.enforcer.is_blocked(machine.device)


def test_the_command_line_holds_no_lock_after_recover(tmp_path: Path) -> None:
    machine = Machine(tmp_path)
    assert run(tmp_path, "recover", **machine.factories()).code == EXIT_OK
    lock = InstanceLock(machine.state / LOCK_FILE_NAME)
    assert lock.acquire()
    lock.release()


def test_threads_started_by_a_command_do_not_leak(tmp_path: Path) -> None:
    before = {thread.name for thread in threading.enumerate()}
    run(None, "policy", "init")
    assert {thread.name for thread in threading.enumerate()} == before
