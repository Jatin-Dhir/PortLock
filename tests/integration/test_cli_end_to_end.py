"""The ``portlock`` command line against a running simulated service.

A :class:`~portlock.console.simulate.Simulation` (the whole service on the fake backend and
enforcer, with the real API on a loopback port and a ``runtime.json``) is started in a
temporary directory, and every command is run through ``main`` exactly as the console script
runs it: it finds the service through ``runtime.json``, proves it is talking to the service,
logs in with the password it is given, makes its calls and logs out. Nothing here touches a
real device, enforcer or system setting."""

from __future__ import annotations

import http.server
import io
import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

from portlock.console.cli import (
    EXIT_AUTH,
    EXIT_CHECK,
    EXIT_FAILED,
    EXIT_OK,
    EXIT_UNREACHABLE,
    CliEnv,
    main,
)
from portlock.console.simulate import DEVICES, Simulation
from portlock.core.canonical import parse_canonical
from portlock.core.clock import FakeClock
from portlock.policy import DEFAULT_POLICY, policy_to_dict
from portlock.service.daemon import RUNTIME_FILE_NAME, read_runtime_file

START = datetime(2026, 7, 1, 9, 0, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "policies"


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def json(self) -> Any:
        return json.loads(self.out)


class Rig:
    def __init__(self, sim: Simulation, password: str) -> None:
        self.sim = sim
        self.password = password

    def cli(
        self,
        *argv: str,
        user: str = "admin",
        password: str | None = None,
        stdin: str | None = None,
        tty: bool = False,
        env: dict[str, str] | None = None,
        no_login_args: bool = False,
    ) -> Result:
        out, err = io.StringIO(), io.StringIO()
        secret = self.password if password is None else password
        answers = [secret]
        variables = {"PORTLOCK_HOME": str(self.sim.home)}
        variables.update(env or {})
        text = stdin if stdin is not None else secret + "\n"
        environment = CliEnv(
            environ=variables,
            stdin=io.StringIO(text),
            stdout=out,
            stderr=err,
            getpass=lambda prompt: answers.pop(0),
            clock=FakeClock(START),
            is_tty=lambda: tty,
        )
        arguments = (
            list(argv)
            if no_login_args
            else ["--user", user, *([] if tty else ["--password-stdin"]), *argv]
        )
        code = main(arguments, env=environment)
        return Result(code, out.getvalue(), err.getvalue())

    def plug(self, name: str) -> Any:
        return self.sim.plug(name)

    def view(self, name: str) -> Any:
        return self.sim.connection(name)


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Rig]:
    sim = Simulation(home=tmp_path_factory.mktemp("cli-sim"), clock=FakeClock(START))
    sim.start()
    password = sim.create_admin()
    sim.serve()
    machine = Rig(sim, password)
    try:
        yield machine
    finally:
        sim.close()


@pytest.fixture(autouse=True)
def tidy(rig: Rig) -> Iterator[None]:
    """Each test starts with no devices, grants, lockdown or waiting change, default policy."""
    yield
    service = rig.sim.service
    for change in service.pending_changes():
        service.cancel_change(change.id, actor="admin")
    status = service.lockdown_status()
    if status.active:
        rig.sim.lift_lockdown()
    for view in service.list_connections(open_only=True):
        if rig.sim.backend.is_present(view.device.instance_id):
            rig.sim.backend.unplug(view.device.instance_id)
    for grant in service.list_grants():
        service.revoke_grant(grant.id, actor="admin")
    rig.sim.pump()
    for view in service.list_connections(open_only=True):
        if rig.sim.backend.is_present(view.device.instance_id):
            rig.sim.backend.unplug(view.device.instance_id)
    service.replace_policy(policy_to_dict(DEFAULT_POLICY), actor="admin")
    rig.sim.pump()
    rig.sim.clock.advance(61)  # type: ignore[attr-defined]
    rig.sim.pump()


def table_rows(text: str) -> list[list[str]]:
    lines = [line for line in text.splitlines() if line.strip()]
    return [re.split(r"\s{2,}", line.strip()) for line in lines[1:]]


# --- status, devices, approving ----------------------------------------------------------


def test_status_needs_no_login_and_says_it_is_a_simulation(rig: Rig) -> None:
    result = rig.cli("status", no_login_args=True)
    assert result.code == EXIT_OK and result.err == ""
    assert "PortLock 0." in result.out and "SIMULATION" in result.out
    data = rig.cli("status", "--json", no_login_args=True).json
    assert data["simulation"] is True and data["setup_required"] is False and "proof" not in data
    detail = rig.cli("status", "--detail")
    assert detail.code == EXIT_OK and "mode: enforce" in detail.out and "devices:" in detail.out


def test_a_waiting_device_is_listed_approved_and_remembered(rig: Rig) -> None:
    rig.plug("unknown-stick")
    listed = rig.cli("devices")
    assert (
        listed.code == EXIT_OK
        and "pending" in listed.out
        and "waiting for a decision" in listed.out
    )
    cid = rig.view("unknown-stick").connection_id
    approved = rig.cli(
        "approve",
        str(cid),
        "--kind",
        "temporary",
        "--for",
        "2h",
        "--read-only",
        "--note",
        "from the cli",
    )
    assert approved.code == EXIT_OK, approved.err
    assert (
        "temporary grant" in approved.out
        and "(read-only)" in approved.out
        and "is now read_only" in approved.out
    )
    assert rig.view("unknown-stick").state.value == "read_only"
    known = rig.cli("devices", "--known", "--text", "Flash Drive 32GB")
    assert known.code == EXIT_OK and "Simulated Flash Drive 32GB" in known.out
    history = rig.cli("devices", "--history", "--limit", "5")
    assert history.code == EXIT_OK and "read_only" in history.out
    as_json = rig.cli("devices", "--json").json
    assert as_json["devices"][0]["state"] == "read_only"
    assert (
        rig.cli("approve", str(cid), "--kind", "temporary", "--for", "2h").code == EXIT_FAILED
    )  # not pending any more


def test_a_device_can_be_denied_and_the_reason_is_recorded(rig: Rig) -> None:
    rig.plug("second-stick")
    cid = rig.view("second-stick").connection_id
    result = rig.cli("deny", str(cid), "--note", "not ours")
    assert result.code == EXIT_OK and f"device {cid} is denied" in result.out
    assert rig.view("second-stick").resolution["note"] == "not ours"  # type: ignore[index]
    again = rig.cli("deny", str(cid))
    assert again.code == EXIT_FAILED and "not_pending" in again.err
    missing = rig.cli("deny", "999999")
    assert missing.code == EXIT_FAILED and "not_connected" in missing.err


def test_bad_arguments_to_a_service_command_are_reported_by_the_service(rig: Rig) -> None:
    rig.plug("unknown-stick")
    cid = str(rig.view("unknown-stick").connection_id)
    assert rig.cli("approve", cid, "--kind", "trust", "--for", "2h").code == EXIT_FAILED
    assert rig.cli("approve", cid, "--kind", "temporary").code == EXIT_FAILED
    result = rig.cli("approve", cid, "--kind", "temporary", "--for", "soon")
    assert (
        result.code == EXIT_FAILED
        and "invalid_request" in result.err
        and "expires_in" in result.err
    )


def test_trust_grants_and_revocation(rig: Rig) -> None:
    rig.plug("trusted-stick")
    fingerprint = rig.view("trusted-stick").fingerprint
    trusted = rig.cli("trust", fingerprint, "--read-only", "--note", "backup")
    assert trusted.code == EXIT_OK and "trust grant" in trusted.out and "(read-only)" in trusted.out
    assert rig.view("trusted-stick").state.value == "read_only"
    listing = rig.cli("trust", "--list")
    assert fingerprint in listing.out and "read-only" in listing.out and "backup" in listing.out
    grant_id = re.search(r"([0-9a-f]{32})", listing.out).group(1)  # type: ignore[union-attr]
    revoked = rig.cli("revoke", grant_id)
    assert revoked.code == EXIT_OK and "revoked trust grant" in revoked.out
    # Taking away access to a mounted volume asks for a clean eject first (DESIGN 14.11),
    # and the simulated eject unplugs the stick.
    assert not rig.sim.backend.is_present(DEVICES["trusted-stick"]().instance_id)
    assert rig.cli("revoke", grant_id).code == EXIT_FAILED
    assert "no trusted devices" in rig.cli("trust", "--list").out
    unknown = rig.cli("trust", "plk1:" + "a" * 32)
    assert unknown.code == EXIT_FAILED and "unknown_device" in unknown.err
    once = rig.cli("grant", fingerprint, "--kind", "once", "--note", "one-off")
    assert once.code == EXIT_OK and "once grant" in once.out
    short = rig.cli("grant", fingerprint, "--kind", "temporary", "--for", "30m")
    assert short.code == EXIT_OK and "temporary grant" in short.out


def test_a_device_without_a_serial_can_be_granted_only_by_port_and_never_trusted(rig: Rig) -> None:
    rig.plug("blank-stick")
    fingerprint = rig.view("blank-stick").fingerprint
    refused = rig.cli("trust", fingerprint)
    assert refused.code == EXIT_FAILED and "low_confidence" in refused.err
    plain = rig.cli("grant", fingerprint, "--kind", "temporary", "--for", "1h")
    assert plain.code == EXIT_FAILED and "low_confidence" in plain.err
    limited = rig.cli(
        "grant", fingerprint, "--kind", "temporary", "--for", "1h", "--allow-low-confidence"
    )
    assert limited.code == EXIT_OK


def test_an_input_device_is_enrolled_listed_and_released(rig: Rig) -> None:
    rig.plug("keyboard")
    cid = rig.view("keyboard").connection_id
    enrolled = rig.cli("enroll", str(cid), "--label", "my keyboard")
    assert enrolled.code == EXIT_OK and "stays protected there" in enrolled.out
    listing = rig.cli("enroll")
    assert "my keyboard" in listing.out and "FINGERPRINT" in listing.out
    fingerprint = rig.view("keyboard").fingerprint
    assert rig.cli("enroll", "--remove", fingerprint).code == EXIT_OK
    assert "no enrolments" in rig.cli("enroll").out
    assert rig.cli("enroll", "--remove", fingerprint).code == EXIT_FAILED
    assert rig.cli("release-port", "1-1").code == EXIT_FAILED  # nothing is held


# --- policy ------------------------------------------------------------------------------


def test_a_policy_is_shown_set_tested_and_restored(rig: Rig, tmp_path: Path) -> None:
    shown = rig.cli("policy", "show")
    assert (
        shown.code == EXIT_OK
        and "PortLock default policy" in shown.out
        and "deny-input-with-other: deny" in shown.out
    )
    raw = rig.cli("policy", "show", "--raw")
    original = json.loads(raw.out)
    current_hash = re.search(r"hash ([0-9a-f]{64})", shown.out).group(1)  # type: ignore[union-attr]
    office = rig.cli(
        "policy", "set", str(FIXTURES / "office.json"), "--expected-hash", current_hash
    )
    assert office.code == EXIT_OK and "is active" in office.out
    stale = rig.cli("policy", "set", str(FIXTURES / "office.json"), "--expected-hash", current_hash)
    assert stale.code == EXIT_FAILED and "policy_conflict" in stale.err
    bad = rig.cli("policy", "set", str(FIXTURES / "broken.json"))
    assert bad.code == EXIT_CHECK and "not valid" in bad.err
    rig.plug("unknown-stick")
    cid = rig.view("unknown-stick").connection_id
    tested = rig.cli("policy", "test", "--connection", str(cid))
    assert tested.code == EXIT_OK and "fingerprint plk1:" in tested.out
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
    hidden = rig.cli("policy", "test", "--device", device)
    assert "deny" in hidden.out and "deny-badusb" in hidden.out  # the office policy is active
    original_file = tmp_path / "original.json"
    original_file.write_text(json.dumps(original), encoding="utf-8")
    restored = rig.cli("policy", "set", str(original_file))
    assert restored.code == EXIT_OK
    assert "PortLock default policy" in rig.cli("policy", "show").out


# --- audit -------------------------------------------------------------------------------


def test_the_audit_log_is_read_verified_and_exported(rig: Rig, tmp_path: Path) -> None:
    rig.plug("unknown-stick")
    fingerprint = rig.view("unknown-stick").fingerprint
    tail = rig.cli("audit", "tail", "-n", "5")
    assert tail.code == EXIT_OK and len(tail.out.strip().splitlines()) == 5
    query = rig.cli("audit", "query", "--type", "device.*", "--device", fingerprint)
    assert query.code == EXIT_OK and "device.connected" in query.out and fingerprint in query.out
    assert (
        "no audit records match" in rig.cli("audit", "query", "--actor", "nobody-by-this-name").out
    )
    verified = rig.cli("audit", "verify")
    assert verified.code == EXIT_OK and "the audit log verifies" in verified.out
    head = rig.cli("audit", "tail", "-n", "1", "--json").json["head"]
    ok = rig.cli("audit", "verify", "--expected-head", f"{head['seq']}:{head['hash']}")
    assert ok.code == EXIT_OK
    forged = rig.cli("audit", "verify", "--expected-head", f"{head['seq']}:{'0' * 64}")
    assert forged.code == EXIT_CHECK and "DOES NOT verify" in forged.out
    assert rig.cli("audit", "verify", "--expected-head", "garbage").code == 2
    target = tmp_path / "audit.jsonl"
    exported = rig.cli("audit", "export", "--output", str(target))
    assert exported.code == EXIT_OK
    records = [parse_canonical(line) for line in target.read_bytes().splitlines()]
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    assert all(records[i]["prev_hash"] == records[i - 1]["hash"] for i in range(1, len(records)))
    assert (
        rig.cli("audit", "export", "--output", str(target)).code == EXIT_FAILED
    )  # not overwritten
    assert rig.cli("audit", "export", "--output", str(target), "--force").code == EXIT_OK
    printed = rig.cli("audit", "export", "--since-seq", str(len(records)))
    assert printed.code == EXIT_OK and len(printed.out.strip().splitlines()) >= 1
    # A verification that fails is an alarm that stays until one succeeds.
    assert "chain broken" in json.dumps(rig.cli("doctor", "--json").json["checks"])
    assert rig.cli("audit", "verify").code == EXIT_OK


def test_a_scan_is_requested_and_reported(rig: Rig) -> None:
    rig.plug("badusb")
    cid = rig.view("badusb").connection_id
    queued = rig.cli("scan", str(cid))
    assert queued.code == EXIT_OK and "queued" in queued.out and "/simulated/badusb" in queued.out
    rig.sim.pump()
    listing = rig.cli("scan", "--list")
    assert "done" in listing.out and "suspicious" in listing.out
    scan_id = re.search(r"^\s*(\d+)\s", listing.out.splitlines()[1]).group(1)  # type: ignore[union-attr]
    report = rig.cli("scan", "--show", scan_id)
    assert (
        report.code == EXIT_OK
        and "verdict suspicious" in report.out
        and "autorun.inf" in report.out
    )
    assert rig.cli("scan", "999999").code == EXIT_FAILED  # not connected


# --- lockdown, commit-confirm ------------------------------------------------------------


def test_lockdown_engaged_and_confirmed_in_one_command_then_renewed_and_lifted(rig: Rig) -> None:
    rig.plug("trusted-stick")
    rig.sim.approve("trusted-stick", kind="trust")
    engaged = rig.cli(
        "lockdown", "engage", "--minutes", "5", "--reason", "from the cli", "--confirm"
    )
    assert engaged.code == EXIT_OK, engaged.err
    assert (
        "LOCKDOWN" in engaged.out
        and "would block: Simulated Corp Simulated Flash Drive 16GB" in engaged.out
    )
    assert "Confirmed: the change is kept." in engaged.out
    status = rig.cli("lockdown", "status")
    assert "LOCKDOWN active" in status.out and "from the cli" in status.out
    # The lockdown blocks removable storage: the mounted stick is asked to leave.
    assert not rig.sim.backend.is_present(DEVICES["trusted-stick"]().instance_id)
    renewed = rig.cli("lockdown", "renew", "--minutes", "10")
    assert renewed.code == EXIT_OK and "renewed 1 time(s)" in renewed.out
    lifted = rig.cli("lockdown", "lift")
    assert lifted.code == EXIT_OK and "The lockdown is lifted." in lifted.out
    assert "no lockdown" in rig.cli("lockdown", "status").out
    assert rig.cli("lockdown", "lift").code == EXIT_FAILED  # nothing to lift


def test_the_cli_lifts_a_lockdown_while_the_network_is_locked_out_of_that_account(
    rig: Rig,
) -> None:
    import http.client

    assert rig.cli("lockdown", "engage", "--minutes", "5", "--confirm").code == EXIT_OK
    runtime = read_runtime_file(rig.sim.config.paths.state_dir)
    assert runtime is not None
    # Any local program, no credentials: failed logins for the administrator's name keep
    # the network lockout alive (DESIGN 14.21 says it must never block the elevated CLI).
    for _ in range(6):
        connection = http.client.HTTPConnection(runtime["host"], runtime["port"], timeout=10)
        try:
            body = json.dumps({"username": "admin", "password": "a wrong passphrase 123"})
            connection.request(
                "POST", "/api/v1/auth/login", body, {"Content-Type": "application/json"}
            )
            reply = connection.getresponse()
            reply.read()
        finally:
            connection.close()
    assert reply.status == 429
    lifted = rig.cli("lockdown", "lift")
    assert lifted.code == EXIT_OK, lifted.err
    assert "The lockdown is lifted." in lifted.out
    assert "no lockdown" in rig.cli("lockdown", "status").out


def test_a_lockdown_is_confirmed_by_a_separate_command_over_the_same_channel(rig: Rig) -> None:
    engaged = rig.cli("lockdown", "engage")
    assert engaged.code == EXIT_OK and "Confirm with: portlock confirm" in engaged.out
    change_id = re.search(r"portlock confirm ([0-9a-f]{16})", engaged.out).group(1)  # type: ignore[union-attr]
    waiting = rig.cli("changes")
    assert change_id in waiting.out and "lockdown" in waiting.out
    confirmed = rig.cli("confirm")  # no id: the only change waiting
    assert confirmed.code == EXIT_OK and "confirmed lockdown" in confirmed.out
    assert "nothing is waiting" in rig.cli("changes").out
    assert rig.sim.service.lockdown_status().active is True


def test_an_unconfirmed_lockdown_rolls_back_and_a_cancelled_one_does_too(rig: Rig) -> None:
    engaged = rig.cli("lockdown", "engage", "--minutes", "5")
    change_id = re.search(r"portlock confirm ([0-9a-f]{16})", engaged.out).group(1)  # type: ignore[union-attr]
    rig.sim.advance(61)
    assert "no lockdown" in rig.cli("lockdown", "status").out
    late = rig.cli("confirm", change_id)
    assert late.code == EXIT_FAILED and "no_pending_change" in late.err
    again = rig.cli("lockdown", "engage")
    second = re.search(r"portlock confirm ([0-9a-f]{16})", again.out).group(1)  # type: ignore[union-attr]
    cancelled = rig.cli("cancel", second)
    assert cancelled.code == EXIT_OK and "rolled back" in cancelled.out
    assert rig.cli("cancel", second).code == EXIT_FAILED
    assert rig.cli("confirm").code == EXIT_FAILED and "0 change(s)" in rig.cli("confirm").err


def test_at_a_terminal_the_operator_is_asked_whether_to_keep_the_lockdown(rig: Rig) -> None:
    kept = rig.cli("lockdown", "engage", tty=True, stdin="yes\n")
    assert (
        kept.code == EXIT_OK
        and "Keep it? Type yes to confirm" in kept.err
        and "Confirmed" in kept.out
    )
    assert rig.sim.service.lockdown_status().active is True
    rig.sim.lift_lockdown()
    declined = rig.cli("lockdown", "engage", tty=True, stdin="no\n")
    assert declined.code == EXIT_OK and "Not confirmed" in declined.out
    rig.sim.advance(61)
    assert rig.sim.service.lockdown_status().active is False


def test_mode_scope_and_default_deny_use_the_same_commit_confirm(rig: Rig) -> None:
    assert "mode enforce" in rig.cli("mode").out
    assert rig.cli("mode", "monitor").code == EXIT_OK and "mode monitor" in rig.cli("mode").out
    back = rig.cli("mode", "enforce", "--confirm")
    assert back.code == EXIT_OK and "Confirmed: the change is kept." in back.out
    assert "mode enforce" in rig.cli("mode").out
    assert rig.cli("scope").out.strip() == "scope storage"
    assert rig.cli("scope", "storage_and_unknown", "--confirm").code == EXIT_OK
    assert rig.cli("scope").out.strip() == "scope storage_and_unknown"
    assert (
        rig.cli("scope", "storage").code == EXIT_OK
        and rig.cli("scope").out.strip() == "scope storage"
    )
    assert "default-deny is off" in rig.cli("default-deny").out
    assert rig.cli("default-deny", "on", "--confirm").code == EXIT_OK
    assert "default-deny is on" in rig.cli("default-deny").out
    assert (
        rig.cli("default-deny", "off").code == EXIT_OK
        and "default-deny is off" in rig.cli("default-deny").out
    )


# --- users and roles ---------------------------------------------------------------------


def test_accounts_are_created_used_demoted_and_removed_from_the_command_line(rig: Rig) -> None:
    created = rig.cli(
        "user",
        "add",
        "olivia",
        "--role",
        "operator",
        stdin=rig.password + "\nan operator passphrase 55\n",
    )
    assert created.code == EXIT_OK and "olivia: operator" in created.out
    listing = rig.cli("user", "list")
    assert "olivia" in listing.out and "operator" in listing.out and "admin" in listing.out
    rig.plug("unknown-stick")
    cid = str(rig.view("unknown-stick").connection_id)
    as_operator = rig.cli("approve", cid, user="olivia", password="an operator passphrase 55")
    assert as_operator.code == EXIT_OK
    forbidden = rig.cli(
        "policy",
        "set",
        str(FIXTURES / "office.json"),
        user="olivia",
        password="an operator passphrase 55",
    )
    assert forbidden.code == EXIT_AUTH and "forbidden" in forbidden.err
    assert (
        rig.cli("user", "list", user="olivia", password="an operator passphrase 55").code
        == EXIT_AUTH
    )
    assert rig.cli("user", "role", "olivia", "auditor").code == EXIT_OK
    assert rig.cli("devices", user="olivia", password="an operator passphrase 55").code == EXIT_OK
    assert (
        rig.cli("approve", "1", user="olivia", password="an operator passphrase 55").code
        == EXIT_AUTH
    )
    codes = rig.cli("user", "recovery-codes", "olivia")
    assert (
        codes.code == EXIT_OK
        and len(re.findall(r"[0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){7}", codes.out)) == 8
    )
    assert rig.cli("user", "disable", "olivia").code == EXIT_OK
    disabled = rig.cli("status", "--detail", user="olivia", password="an operator passphrase 55")
    assert disabled.code == EXIT_AUTH and "account_disabled" in disabled.err
    assert rig.cli("user", "delete", "olivia").code == EXIT_OK
    assert rig.cli("user", "delete", "olivia").code == EXIT_FAILED
    assert rig.cli("user", "delete", "admin").code == EXIT_FAILED  # the last administrator


def test_a_wrong_password_is_exit_3_and_never_echoed(rig: Rig) -> None:
    result = rig.cli("devices", password="definitely not the password 1")
    assert result.code == EXIT_AUTH and "invalid_credentials" in result.err
    assert "definitely not the password" not in result.err + result.out
    assert rig.cli("devices", user="nobody").code == EXIT_AUTH


def test_the_command_line_cannot_be_locked_out_by_guessing_at_the_api(rig: Rig) -> None:
    runtime = read_runtime_file(rig.sim.config.paths.state_dir)
    assert runtime is not None
    url = f"http://127.0.0.1:{runtime['port']}"
    # Without the runtime file's secret a login is a network login and is locked out.
    for _ in range(5):
        wrong = rig.cli(
            "--url", url, "devices", password="guess guess guess 1", no_login_args=False
        )
        assert wrong.code == EXIT_AUTH
    locked = rig.cli("--url", url, "devices")
    assert locked.code == EXIT_AUTH and "locked_out" in locked.err
    # The command line, which holds the secret, is on the local channel and gets in.
    assert rig.cli("devices").code == EXIT_OK
    rig.sim.runtime.accounts.clear_lockout("admin", actor="test")


def test_the_password_comes_from_a_hidden_prompt_at_a_terminal(rig: Rig) -> None:
    prompts: list[str] = []
    out, err = io.StringIO(), io.StringIO()
    environment = CliEnv(
        environ={"PORTLOCK_HOME": str(rig.sim.home)},
        stdin=io.StringIO(""),
        stdout=out,
        stderr=err,
        getpass=lambda prompt: prompts.append(prompt) or rig.password,
        is_tty=lambda: True,
    )
    assert main(["--user", "admin", "devices"], env=environment) == EXIT_OK
    assert prompts == ["Password for admin: "]
    assert rig.password not in out.getvalue() + err.getvalue()
    tty_user = CliEnv(
        environ={"PORTLOCK_HOME": str(rig.sim.home)},
        stdin=io.StringIO("admin\n"),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        getpass=lambda prompt: rig.password,
        is_tty=lambda: True,
    )
    assert main(["devices"], env=tty_user) == EXIT_OK
    assert "User name: " in tty_user.stderr.getvalue()  # type: ignore[union-attr]


# --- the service is who it says it is ------------------------------------------------------


class Impostor(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        Impostor.seen.append(f"{self.command} {self.path} {body.decode('latin-1')}")
        payload = json.dumps(
            {
                "service": "portlock",
                "api": 1,
                "version": "0.2.0",
                "run_id": "0123456789abcdef",
                "setup_required": False,
                "simulation": False,
                "proof": "0" * 64,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _answer

    def log_message(self, format: str, *args: Any) -> None:
        return


def test_a_program_squatting_on_the_port_never_sees_a_password(rig: Rig, tmp_path: Path) -> None:
    Impostor.seen = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Impostor)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    home = tmp_path / "home"
    state = home / "state"
    state.mkdir(parents=True)
    (state / RUNTIME_FILE_NAME).write_text(
        json.dumps(
            {
                "v": 1,
                "pid": 1,
                "host": "127.0.0.1",
                "port": server.server_address[1],
                "run_id": "0123456789abcdef",
                "started_at": "2026-01-01T00:00:00.000000Z",
                "version": "0.2.0",
                "secret": "the-real-secret-the-squatter-does-not-know",
            }
        )
    )
    try:
        result = rig.cli(
            "devices", env={"PORTLOCK_HOME": str(home)}, password="my real admin password 1"
        )
        assert result.code == EXIT_UNREACHABLE
        assert "did not prove" in result.err and "no credentials were sent" in result.err
        assert len(Impostor.seen) == 1 and Impostor.seen[0].startswith("GET /api/v1/ping")
        assert not any("password" in entry or "my real admin" in entry for entry in Impostor.seen)
        assert (
            rig.cli("status", env={"PORTLOCK_HOME": str(home)}, no_login_args=True).code
            == EXIT_UNREACHABLE
        )
    finally:
        server.shutdown()
        server.server_close()


def test_a_stale_runtime_file_does_not_authenticate_the_real_service(
    rig: Rig, tmp_path: Path
) -> None:
    runtime = read_runtime_file(rig.sim.config.paths.state_dir)
    assert runtime is not None
    home = tmp_path / "stale"
    (home / "state").mkdir(parents=True)
    (home / "state" / RUNTIME_FILE_NAME).write_text(
        json.dumps({**runtime, "secret": "a-secret-from-an-earlier-run"})
    )
    result = rig.cli("devices", env={"PORTLOCK_HOME": str(home)})
    assert result.code == EXIT_UNREACHABLE and "no credentials were sent" in result.err
    wrong_run = home / "state" / RUNTIME_FILE_NAME
    wrong_run.write_text(json.dumps({**runtime, "run_id": "ffffffffffffffff"}))
    assert rig.cli("devices", env={"PORTLOCK_HOME": str(home)}).code == EXIT_UNREACHABLE


def test_a_stopped_service_is_exit_4(rig: Rig, tmp_path: Path) -> None:
    result = rig.cli("devices", env={"PORTLOCK_HOME": str(tmp_path / "nothing")})
    assert result.code == EXIT_UNREACHABLE and "the service is not running" in result.err


# --- output -------------------------------------------------------------------------------


def test_json_output_is_the_apis_answer_unchanged(rig: Rig) -> None:
    rig.plug("keyboard")
    for argv, key in (
        (("devices", "--json"), "devices"),
        (("policy", "show", "--json"), "policy"),
        (("lockdown", "status", "--json"), "state"),
        (("trust", "--list", "--json"), "trust"),
    ):
        result = rig.cli(*argv)
        assert result.code == EXIT_OK and key in result.json
    doctor = rig.cli("doctor", "--json")
    failed = [c for c in doctor.json["checks"] if c["status"] == "fail"]
    assert doctor.code == EXIT_OK and doctor.json["checks"], failed
    assert doctor.json["worst"] in ("ok", "warn")
    text = rig.cli("doctor")
    assert "[ok  ] guard.platform" in text.out and "service.audit" in text.out


def test_nothing_that_came_from_outside_reaches_the_terminal_unescaped(rig: Rig) -> None:
    # Control characters are refused at the door; what slips through (a right-to-left
    # override in a note, which reorders the text after it) is written out by the command line.
    rtl = chr(0x202E)
    rig.plug("trusted-stick")
    fingerprint = rig.view("trusted-stick").fingerprint
    trusted = rig.cli("trust", fingerprint, "--note", "invoice" + rtl + "fdp.exe")
    assert trusted.code == EXIT_OK
    outputs = [
        rig.cli("trust", "--list").out,
        rig.cli("devices", "--known").out,
        rig.cli("audit", "tail", "-n", "40").out,
    ]
    for output in outputs:
        assert rtl not in output and chr(27) not in output and chr(7) not in output
    assert "invoice" + chr(92) + "u202efdp.exe" in outputs[0]
    refused = rig.cli("trust", fingerprint, "--note", "bell" + chr(7))
    assert refused.code == EXIT_FAILED and chr(7) not in refused.err + refused.out


def test_every_command_ends_with_a_clean_logout(rig: Rig) -> None:
    before = len(rig.sim.runtime.sessions.list_sessions("admin"))
    for _ in range(3):
        assert rig.cli("devices").code == EXIT_OK
    assert len(rig.sim.runtime.sessions.list_sessions("admin")) == before
    logouts = [r for r in rig.sim.runtime.audit_log.iterate() if r.event_type == "auth.logout"]
    assert len(logouts) >= 3 and all(r.actor == "admin" for r in logouts[-3:])
    logins = [r for r in rig.sim.runtime.audit_log.iterate() if r.event_type == "auth.login"]
    assert all(r.data["channel"] == "local" for r in logins[-3:])  # the command line's own channel
    assert rig.password not in json.dumps(
        [r.to_dict() for r in rig.sim.runtime.audit_log.iterate()]
    )
