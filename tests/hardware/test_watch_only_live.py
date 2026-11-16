"""The real service, watch-only, on this machine. Read-only; opt-in with ``--run-hardware``.

Every other test of watch-only uses fakes. This one starts the real command line
(``init``, then ``run``) as an ordinary process with a throwaway home directory, looks at
it through its own HTTP API, asks it for the three things that would change the machine
(enforce mode, a lockdown, default-deny), and stops it with a signal, the way a person
presses Ctrl+C.

The process runs under ``flight_recorder.py``, which refuses and records every attempt to
start a program, write the registry or call a mutating operating-system seam, and records
every file written and socket opened. The test passes only if nothing was refused, nothing
was reached, and nothing outside the home directory was written.

It runs only where the process could not enforce anyway (not elevated, or a per-user home):
an elevated process with a system-wide home is skipped, because there PortLock is entitled
to use the real mechanisms. As in the other live tests, only counts and category names are
printed, never a device name, serial number or identifier.
"""

from __future__ import annotations

import collections
import contextlib
import http.client
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from portlock.core.config import PathsConfig, paths_per_user
from portlock.core.privilege import process_elevated
from portlock.service.daemon import EXIT_PORT, RUNTIME_FILE_NAME

pytestmark = [pytest.mark.hardware]

SRC = Path(__file__).resolve().parents[2] / "src"
RECORDER = Path(__file__).resolve().with_name("flight_recorder.py")
_START_SECONDS = 60.0
_STOP_SECONDS = 30.0
_BOUND_ALLOWED = frozenset({"AF_INET 127.0.0.1", "AF_INET6 ::1", "AF_NETLINK"})
_CONNECTED_ALLOWED = frozenset({"AF_INET 127.0.0.1", "AF_INET6 ::1"})
# What an enforcement record may say while nothing is enforced.
_UNTOUCHED_OUTCOMES = frozenset({None, "undetermined", "not_needed", "would_apply"})


@dataclass
class Live:
    """A running watch-only service and how to reach it.

    The secrets and the environment are kept out of the representation, because pytest
    prints the representation of a fixture in a failure report.
    """

    home: Path
    port: int
    token: str = field(repr=False)
    password: str = field(repr=False)
    process: subprocess.Popen[str] = field(repr=False)
    init_report: Path
    run_report: Path
    environment: dict[str, str] = field(repr=False)


def call(
    port: int, method: str, path: str, *, token: str | None = None, body: object = None
) -> tuple[int, Any]:
    """One request to the service's API on the loopback address."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=40)
    try:
        headers: dict[str, str] = {}
        payload: bytes | None = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        connection.request(method, "/api/v1" + path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, (json.loads(raw) if raw else None)
    finally:
        connection.close()


def error_code(data: Any) -> str | None:
    error = data.get("error") if isinstance(data, dict) else None
    return str(error.get("code")) if isinstance(error, dict) else None


def launch(
    arguments: list[str], environment: dict[str, str], report: Path, **options: Any
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-B", str(RECORDER), *arguments],
        env={**environment, "PORTLOCK_FLIGHT_REPORT": str(report)},
        text=True,
        **options,
    )


def free_port() -> int:
    """A port nothing listens on now. ``PORTLOCK_LIVE_PORTS=LOW-HIGH`` keeps the choice in
    that range (so that a run beside a real installation never comes near its port);
    otherwise the operating system picks one."""
    wanted = os.environ.get("PORTLOCK_LIVE_PORTS", "").strip()
    if wanted:
        low, _, high = wanted.partition("-")
        candidates = list(range(int(low), int(high) + 1))
        secrets.SystemRandom().shuffle(candidates)
    else:
        candidates = [0]
    for candidate in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return int(probe.getsockname()[1])
    pytest.fail(f"no free port in PORTLOCK_LIVE_PORTS={wanted}")


def problems_in(report: Path) -> list[str]:
    """Everything in a flight report that breaks the watch-only promise, as plain lines."""
    data = json.loads(report.read_text(encoding="utf-8"))
    found: list[str] = []
    for name in data["missing"]:
        found.append(f"no tripwire could be armed on {name} (was it renamed?)")
    for item in data["blocked"]:
        found.append(f"refused: {json.dumps(item, sort_keys=True)}")
    for item in data["seam_calls"]:
        found.append(f"a mutating seam was reached: {json.dumps(item, sort_keys=True)}")
    for table in ("writes_outside_home", "fs_changes_outside_home", "databases_outside_home"):
        for key, count in data[table].items():
            found.append(f"{table}: {count} x {key}")
    for key in data["sockets_bound"]:
        if key not in _BOUND_ALLOWED:
            found.append(f"a socket was bound outside the loopback address: {key}")
    for key in data["sockets_connected"]:
        if key not in _CONNECTED_ALLOWED:
            found.append(f"a connection was made to another machine: {key}")
    return found


def stop(live: Live) -> str:
    """Stop the service the way a person does and say how it was done."""
    process = live.process
    if process.poll() is not None:
        return "it had already stopped"
    how = "a console break" if sys.platform == "win32" else "SIGINT"
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
    except OSError:
        # No console to send a break through: ask it to stop the other documented way.
        how = "the stop command"
        stopper = launch(
            ["stop"],
            live.environment,
            live.home / "stop-report.json",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stopper.wait(timeout=_STOP_SECONDS)
    try:
        process.wait(timeout=_STOP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        pytest.fail(f"the service did not stop within {int(_STOP_SECONDS)} s of {how}")
    return how


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Live]:
    home = tmp_path_factory.mktemp("portlock-home")
    if process_elevated() and not paths_per_user(PathsConfig.under(home)):
        pytest.skip(
            "this process is elevated and its temporary directory is system-wide, so "
            "PortLock could enforce here; the live watch-only test runs only where it cannot"
        )
    reports = tmp_path_factory.mktemp("portlock-reports")
    environment = {
        name: value for name, value in os.environ.items() if name.upper() != "PORTLOCK_CONFIG"
    }
    environment.update(
        PORTLOCK_HOME=str(home),
        PYTHONPATH=os.pathsep.join(
            part for part in (str(SRC), environment.get("PYTHONPATH", "")) if part
        ),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
    )
    password = secrets.token_urlsafe(24) + "aA1!"

    init_report = reports / "init.json"
    init = launch(
        ["init", "--username", "admin", "--password-stdin"],
        environment,
        init_report,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # The output holds the audit key and recovery codes of the throwaway home: not shown.
    _, errors = init.communicate(password + "\n", timeout=180)
    assert init.returncode == 0, f"init failed: {errors[-600:]}"

    run_report = reports / "run.json"
    log = (reports / "run.log").open("w", encoding="utf-8")
    try:
        process, port = start_service(home, environment, run_report, log=log)
    except BaseException:
        log.close()
        raise
    result = Live(home, port, "", password, process, init_report, run_report, environment)
    try:
        status, data = call(
            port, "POST", "/auth/login", body={"username": "admin", "password": password}
        )
        assert status == 200, f"login answered {status} {error_code(data)}"
        result.token = str(data["token"])
        yield result
    finally:
        if process.poll() is None:
            with contextlib.suppress(Exception):
                stop(result)
        if process.poll() is None:
            process.kill()
            process.wait()
        log.close()


def test_init_changed_nothing_outside_its_home(live: Live) -> None:
    assert problems_in(live.init_report) == []


def test_the_service_says_it_is_watch_only(live: Live) -> None:
    status, mode = call(live.port, "GET", "/mode", token=live.token)
    assert status == 200
    assert mode["watch_only"] is True
    assert mode["effective_mode"] == "monitor"
    assert mode["can_enforce"] is False
    assert isinstance(mode["watch_only_reason"], str) and mode["watch_only_reason"]

    status, info = call(live.port, "GET", "/status", token=live.token)
    assert status == 200
    assert info["simulation"] is False
    assert info["enforcer"]["name"] == "watch-only"
    assert info["enforcer"]["block"] is False


def test_real_devices_are_listed_and_none_is_touched(
    live: Live, capsys: pytest.CaptureFixture[str]
) -> None:
    status, data = call(live.port, "GET", "/devices", token=live.token)
    assert status == 200
    connections = data["devices"]
    categories: collections.Counter[str] = collections.Counter()
    touched: list[str] = []
    for position, connection in enumerate(connections):
        categories["+".join(connection["device"]["categories"]) or "(none)"] += 1
        enforcement = connection.get("enforcement") or {}
        if enforcement.get("outcome") not in _UNTOUCHED_OUTCOMES:
            touched.append(f"device {position}: outcome {enforcement.get('outcome')}")
        if enforcement.get("os_state") not in (None, "open"):
            touched.append(f"device {position}: os_state {enforcement.get('os_state')}")
    line = ", ".join(f"{name}={count}" for name, count in sorted(categories.items()))
    with capsys.disabled():
        print(f"\n[portlock live] watch-only service: devices={len(connections)}; {line}")
    assert touched == []


def test_doctor_reports_no_failure(live: Live) -> None:
    status, report = call(live.port, "GET", "/doctor", token=live.token)
    assert status == 200
    failed = {check["id"] for check in report["checks"] if check["status"] == "fail"}
    if sys.platform.startswith("linux") and not Path("/sys/bus/usb/devices").is_dir():
        # A kernel that exposes no USB bus (WSL, most containers): the doctor is right to
        # say that it cannot list devices, and nothing else may fail.
        failed.discard("guard.backend")
    assert failed == set()
    assert "guard.watch_only" in [check["id"] for check in report["checks"]]


def test_the_audit_chain_verifies(live: Live) -> None:
    status, result = call(live.port, "POST", "/audit/verify", token=live.token, body={})
    assert status == 200
    assert result["ok"] is True
    assert result["checked"] > 0


def test_enforce_lockdown_and_default_deny_are_refused(live: Live) -> None:
    status, data = call(live.port, "PUT", "/mode", token=live.token, body={"mode": "enforce"})
    assert (status, error_code(data)) == (409, "watch_only")

    status, data = call(
        live.port, "POST", "/lockdown/engage", token=live.token, body={"minutes": 1}
    )
    assert (status, error_code(data)) == (409, "watch_only")

    status, data = call(live.port, "PUT", "/default-deny", token=live.token, body={"enabled": True})
    assert (status, error_code(data)) == (409, "watch_only")

    status, lockdown = call(live.port, "GET", "/lockdown", token=live.token)
    assert status == 200
    assert (lockdown["state"], lockdown["active"]) == ("idle", False)
    status, mode = call(live.port, "GET", "/mode", token=live.token)
    assert (mode["mode"], mode["effective_mode"]) == ("monitor", "monitor")
    status, changes = call(live.port, "GET", "/changes", token=live.token)
    assert changes["changes"] == []


def test_a_scan_request_starts_no_program(live: Live, capsys: pytest.CaptureFixture[str]) -> None:
    # The flight recorder refuses and records any program start; the last test reads it.
    status, report = call(live.port, "GET", "/doctor", token=live.token)
    assert status == 200
    engines = next(check for check in report["checks"] if check["id"] == "service.scan_engines")
    assert "Antivirus engines are not used in watch-only" in engines["detail"]
    status, data = call(live.port, "GET", "/devices", token=live.token)
    assert status == 200
    requested = 0
    for connection in data["devices"]:
        if not connection["device"]["volumes"]:
            continue
        status, answer = call(
            live.port,
            "POST",
            "/scans",
            token=live.token,
            body={"connection_id": connection["connection_id"]},
        )
        assert (status, error_code(answer)) in (
            (202, None),
            (409, "no_mounted_volume"),
            (409, "scan_unavailable"),
        ), (status, error_code(answer))
        if status == 202:
            requested += 1
    deadline = time.monotonic() + 120.0
    while requested and time.monotonic() < deadline:
        status, scans = call(live.port, "GET", "/scans", token=live.token)
        if all(scan.get("finished_at") for scan in scans["scans"]):
            break
        time.sleep(0.5)
    with capsys.disabled():
        print(f"\n[portlock live] watch-only service: scans requested={requested}")


def test_a_signal_stops_it_cleanly_and_nothing_was_changed(
    live: Live, capsys: pytest.CaptureFixture[str]
) -> None:
    how = stop(live)
    with capsys.disabled():
        print(f"\n[portlock live] watch-only service: stopped by {how}")
    assert live.process.returncode == 0
    assert not (live.home / "state" / "runtime.json").exists()
    assert problems_in(live.run_report) == []


def wait_until_up(process: subprocess.Popen[str], port: int, home: Path) -> bool:
    """Wait until the service answers its ping and has written its runtime file.

    Returns False when it exited because its port was taken (``EXIT_PORT``): another
    program took the free port between :func:`free_port` and the service binding it.
    That is no fault of PortLock's, and the caller starts it once more on a new port.
    """
    runtime_file = home / "state" / RUNTIME_FILE_NAME
    deadline = time.monotonic() + _START_SECONDS
    while time.monotonic() < deadline and process.poll() is None:
        with contextlib.suppress(OSError):
            if call(port, "GET", "/ping")[0] == 200 and runtime_file.exists():
                return True
        time.sleep(0.25)
    if process.poll() == EXIT_PORT:
        return False
    pytest.fail(f"the service did not answer (exit code {process.poll()})")


def start_service(
    home: Path, environment: dict[str, str], report: Path, *, log: Any = None
) -> tuple[subprocess.Popen[str], int]:
    """``run`` on a free port, answering and with its runtime file written; once more on a
    new port if that one was taken meanwhile. ``log`` receives its output (else it is
    dropped). Its own process group, so that a break reaches it and not the tests."""
    for _attempt in range(2):
        port = free_port()
        use_port(home, port)
        process = launch(
            ["run"],
            environment,
            report,
            stdin=subprocess.DEVNULL,
            stdout=log if log is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if log is not None else subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        try:
            up = wait_until_up(process, port, home)
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise
        if up:
            return process, port
    pytest.fail("the service found its port taken twice in a row")


def report_writes(report: Path) -> int:
    """How many times the flight recorder has written ``report`` (0 before the first)."""
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    writes = data.get("writes") if isinstance(data, dict) else None
    return writes if isinstance(writes, int) else 0


def wait_for_a_report_after_now(process: subprocess.Popen[str], report: Path) -> None:
    """Wait until the recorder has written ``report`` again, so that what the process did
    up to now is in it, before the process is killed and can write nothing more.

    The recorder rewrites its report once a second. On a fast machine (a GitHub runner)
    the service answers well within that second, and a kill right then left no report.
    """
    seen = report_writes(report)
    deadline = time.monotonic() + _START_SECONDS
    while time.monotonic() < deadline and process.poll() is None:
        if report_writes(report) > seen:
            return
        time.sleep(0.1)
    pytest.fail(f"the flight recorder wrote no report (exit code {process.poll()})")


def use_port(home: Path, port: int) -> None:
    config_file = home / "config" / "portlock.toml"
    text, replaced = re.subn(
        r"(?m)^port\s*=\s*\d+", f"port = {port}", config_file.read_text(encoding="utf-8")
    )
    assert replaced == 1, "the configuration file init wrote has no port line to change"
    config_file.write_text(text, encoding="utf-8")


def test_a_killed_service_leaves_nothing_that_blocks_the_next_start(
    live: Live, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert live.process.poll() is not None, "the first service is still running"
    runtime_file = live.home / "state" / "runtime.json"
    reports = tmp_path

    # A service that is killed (the window closed) leaves its runtime file behind. It is
    # killed only once it answers and has written that file.
    killed, _port = start_service(live.home, live.environment, reports / "killed.json")
    try:
        wait_for_a_report_after_now(killed, reports / "killed.json")
    finally:
        killed.kill()
        killed.wait()
    assert runtime_file.exists()

    # "stop" says at once that nothing runs, and clears the stale file.
    began = time.monotonic()
    stopper = launch(
        ["stop"],
        live.environment,
        reports / "stop.json",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _out, err = stopper.communicate(timeout=60)
    elapsed = time.monotonic() - began
    # "At once" is what it says, not how long a whole new process (interpreter, flight
    # recorder, imports) takes on a busy machine: a stop that waited for the service
    # ends with "did not stop within" and another exit code.
    assert stopper.returncode == 4, err[-400:]
    assert "the service is not running" in err
    assert "did not stop within" not in err
    assert not runtime_file.exists()

    # The next start keeps running: no stale stop request ends it at its first tick.
    again, port = start_service(live.home, live.environment, reports / "again.json")
    second = Live(
        live.home,
        port,
        "",
        live.password,
        again,
        live.init_report,
        reports / "again.json",
        live.environment,
    )
    try:
        time.sleep(3.0)  # several ticks of the real service, which reads stop.request
        assert again.poll() is None, "the second start ended by itself"
        assert call(port, "GET", "/ping")[0] == 200
        how = stop(second)
    finally:
        if again.poll() is None:
            again.kill()
            again.wait()
    with capsys.disabled():
        print(f"\n[portlock live] killed, stopped at once ({elapsed:.1f} s), restarted, {how}")
    assert again.returncode == 0
    for report in ("killed.json", "stop.json", "again.json"):
        assert problems_in(reports / report) == [], report
