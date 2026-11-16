"""The process: composition, single-instance lock, runtime file, run loop and exit codes."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive
from integration.harness import ADMIN, ADMIN_PASSWORD, RECOVER_ARGV, Harness
from portlock.core.config import AuditConfig
from portlock.core.db import Database
from portlock.core.models import Mode
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.lockdown.manager import Credential
from portlock.service.daemon import (
    EXIT_ALREADY_RUNNING,
    EXIT_OK,
    EXIT_PORT,
    EXIT_STATE_UNUSABLE,
    RUNTIME_FILE_NAME,
    AccountCredentials,
    InstanceLock,
    Runtime,
    build_runtime,
    read_runtime_file,
    request_stop,
    run,
    verify_cli_secret,
)

SRC = Path(__file__).resolve().parents[2] / "src"


def _run_kwargs(harness: Harness) -> dict[str, Any]:
    return {
        "install_signal_handlers": False,
        "tick_seconds": 0.02,
        "clock": harness.clock,
        "backend": harness.backend,
        "enforcer_factory": harness._factory,
        "timer": harness.timer,
        "dir_privacy": harness.privacy,
        "system_ids": lambda devices: frozenset(),
        "recover_argv": RECOVER_ARGV,
    }


def test_the_instance_lock_refuses_a_second_holder_here_and_in_another_process(
    tmp_path: Path,
) -> None:
    path = tmp_path / "portlock.lock"
    first, second = InstanceLock(path), InstanceLock(path)
    assert first.acquire() and first.held
    assert not second.acquire() and not first.acquire()
    probe = (
        "import sys; from portlock.service.daemon import InstanceLock; "
        "print(InstanceLock(sys.argv[1]).acquire())"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1", "SYSTEMROOT": "C:\\Windows"},
        check=True,
    )
    assert result.stdout.strip() == "False"
    first.release()
    assert second.acquire()
    second.release()
    second.release()  # harmless when not held


def test_the_runtime_file_reader_refuses_anything_unexpected(tmp_path: Path) -> None:
    assert read_runtime_file(tmp_path) is None
    target = tmp_path / RUNTIME_FILE_NAME
    good = {
        "v": 1,
        "pid": 1,
        "host": "127.0.0.1",
        "port": 0,
        "run_id": "0" * 16,
        "started_at": "2026-01-01T00:00:00.000000Z",
        "version": "0.2.0",
        "secret": "s",
    }
    target.write_text(json.dumps(good), encoding="utf-8")
    assert read_runtime_file(tmp_path) == good
    for broken in ({**good, "extra": 1}, {**good, "v": 2}, {**good, "port": "1"}, [1]):
        target.write_text(json.dumps(broken), encoding="utf-8")
        assert read_runtime_file(tmp_path) is None
    target.write_bytes(b"\xff" * 10)
    assert read_runtime_file(tmp_path) is None
    assert not verify_cli_secret("abc", "abd") and verify_cli_secret("abc", "abc")
    assert not verify_cli_secret("abc", None) and not verify_cli_secret("", "")


def test_run_writes_the_runtime_file_and_stops_on_a_stop_request(tmp_path: Path) -> None:
    harness = Harness(tmp_path, devices=[flash_drive()])
    started: list[Runtime] = []
    ready = threading.Event()
    codes: list[int] = []

    def on_started(runtime: Runtime) -> None:
        started.append(runtime)
        ready.set()

    thread = threading.Thread(
        target=lambda: codes.append(
            run(harness.config, on_started=on_started, **_run_kwargs(harness))
        )
    )
    thread.start()
    try:
        assert ready.wait(30)
        runtime = started[0]
        data = read_runtime_file(harness.config.paths.state_dir)
        assert data is not None
        assert data["run_id"] == runtime.service.run_id and data["port"] == 0
        assert runtime.verify_cli_secret(data["secret"])
        assert len(data["secret"]) >= 40
        assert [v.device.instance_id for v in runtime.service.list_connections()] == ["test/1-1"]
        held = InstanceLock(harness.config.paths.state_dir / "portlock.lock")
        assert not held.acquire()
    finally:
        request_stop(harness.config.paths.state_dir)
        thread.join(30)
    assert codes == [EXIT_OK]
    assert not (harness.config.paths.state_dir / RUNTIME_FILE_NAME).exists()
    assert not (harness.config.paths.state_dir / "stop.request").exists()
    assert InstanceLock(harness.config.paths.state_dir / "portlock.lock").acquire()


def test_run_refuses_to_start_twice(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.config.paths.state_dir.mkdir(parents=True)
    lock = InstanceLock(harness.config.paths.state_dir / "portlock.lock")
    assert lock.acquire()
    try:
        assert run(harness.config, **_run_kwargs(harness)) == EXIT_ALREADY_RUNNING
    finally:
        lock.release()


def test_an_api_that_cannot_listen_stops_cleanly_with_exit_5(tmp_path: Path) -> None:
    harness = Harness(tmp_path)

    class Taken:
        host, port = "127.0.0.1", 47600

        def start(self) -> None:
            raise OSError("address already in use")

        def stop(self) -> None:
            raise AssertionError("never started")

    code = run(harness.config, api_factory=lambda runtime: Taken(), **_run_kwargs(harness))
    assert code == EXIT_PORT
    db = Database(harness.config.paths.database_file)
    try:
        types = [row["event_type"] for row in db.query("SELECT event_type FROM audit_log")]
    finally:
        db.close()
    assert types[-1] == "service.stopped"


def _newer_schema(harness: Harness) -> None:
    db = Database(harness.config.paths.database_file)
    try:
        db.execute(
            "INSERT INTO schema_migrations (component, version, applied_at)"
            " VALUES ('store', 999, 'x')"
        )
    finally:
        db.close()


@pytest.mark.parametrize("fail_closed", [False, True])
def test_unusable_state_exits_3_after_restoring_unless_fail_closed(
    tmp_path: Path, fail_closed: bool
) -> None:
    harness = Harness(tmp_path, mode=Mode.ENFORCE, fail_closed=fail_closed)
    harness.boot()
    harness.plug(flash_drive())
    assert harness.enforcer.is_blocked("test/1-1")
    harness.crash()
    _newer_schema(harness)
    code = run(harness.config, **_run_kwargs(harness))
    assert code == EXIT_STATE_UNUSABLE
    assert harness.enforcer.is_blocked("test/1-1") is fail_closed
    assert harness.config.paths.database_file.exists()  # never deleted


def test_the_kill_switch_is_honoured_before_a_broken_database_is_opened(tmp_path: Path) -> None:
    harness = Harness(tmp_path, mode=Mode.ENFORCE, fail_closed=True)
    harness.boot()
    harness.plug(flash_drive())
    harness.crash()
    _newer_schema(harness)
    harness.config.paths.kill_switch_file.write_text("", encoding="utf-8")
    assert run(harness.config, **_run_kwargs(harness)) == EXIT_STATE_UNUSABLE
    assert not harness.enforcer.is_blocked("test/1-1")


def test_an_injected_enforcer_needs_its_seams(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    with pytest.raises(ValueError, match="timer"):
        build_runtime(harness.config, enforcer=FakeEnforcer(), backend=FakeBackend())


def test_a_configured_key_store_is_created_once_and_records_carry_macs(tmp_path: Path) -> None:
    key_file = tmp_path / "keys" / "audit.key"
    harness = Harness(tmp_path, audit=AuditConfig(hmac_key_file=key_file))
    harness.boot()
    initial = harness.rt.initial_key
    assert initial is not None and key_file.exists()
    harness.plug(flash_drive())
    assert harness.rt.audit_log.verify(initial_key=initial).ok
    assert harness.rt.audit_log.verify(initial_key=initial).macs_checked >= 3
    harness.crash()
    harness.boot()
    assert harness.rt.initial_key is None and harness.rt.audit_log.keyed
    assert harness.rt.audit_log.verify(initial_key=initial).ok


def test_lifting_credentials_accept_only_an_administrator(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.boot()
    accounts = harness.rt.accounts
    harness.add_admin()
    accounts.create_user("oscar", "operator password 12345", "operator", actor=ADMIN)
    codes = accounts.generate_recovery_codes(ADMIN, actor=ADMIN)
    check = AccountCredentials(accounts)
    assert check.verify(ADMIN, Credential("password", ADMIN_PASSWORD))
    assert not check.verify(ADMIN, Credential("password", "wrong password 123"))
    assert not check.verify("oscar", Credential("password", "operator password 12345"))
    assert not check.verify("nobody", Credential("password", ADMIN_PASSWORD))
    assert check.verify(ADMIN, Credential("recovery_code", codes[0]))
    assert not check.verify(ADMIN, Credential("recovery_code", codes[0]))  # spent
    harness.crash()
