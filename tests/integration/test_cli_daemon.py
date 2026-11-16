"""``portlock run`` and ``portlock stop`` against the real daemon loop.

The process is the real ``service.daemon.run`` (single-instance lock, runtime file, ticker,
the API from ``console.api.api_factory``) on the fake backend, the fake enforcer and the
in-memory timer and directory check, in a temporary home. The command line is driven
through ``main`` exactly as the console script is."""

from __future__ import annotations

import io
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from portlock.console.cli import CliEnv, main
from portlock.core.config import ApiConfig, Config, PathsConfig
from portlock.core.models import Mode
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.service.daemon import RUNTIME_FILE_NAME, Runtime, read_runtime_file, run

PASSWORD = "an administrator passphrase 2026"
WAIT = 20.0


class Daemon:
    """The service running in a thread of this process."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.config = Config(
            paths=PathsConfig.under(home),
            mode=Mode.MONITOR,
            api=ApiConfig(host="127.0.0.1", port=0),
        )
        self.backend = FakeBackend()
        self.enforcer_hook: Callable[[Any], None] | None = None
        self.enforcer = FakeEnforcer(backend=self.backend, write_ahead=self._ahead)
        self.started = threading.Event()
        self.runtime: Runtime | None = None
        self.code: int | None = None
        self.thread = threading.Thread(target=self._run, name="test-daemon", daemon=True)

    def _ahead(self, entry: Any) -> None:
        assert self.enforcer_hook is not None
        self.enforcer_hook(entry)

    def _factory(self, hook: Callable[[Any], None]) -> FakeEnforcer:
        self.enforcer_hook = hook
        return self.enforcer

    def _on_started(self, runtime: Runtime) -> None:
        self.runtime = runtime
        runtime.accounts.create_user("operator-one", PASSWORD, "admin", actor="test")
        self.started.set()

    def _run(self) -> None:
        from portlock.console.api import api_factory

        self.code = run(
            self.config,
            install_signal_handlers=False,
            api_factory=api_factory,
            tick_seconds=0.05,
            backend=self.backend,
            enforcer_factory=self._factory,
            simulation=True,
            timer=FakeExternalTimer(),
            dir_privacy=FakeDirPrivacy(),
            system_ids=lambda devices: frozenset(),
            recover_argv=("portlock", "recover"),
            on_started=self._on_started,
        )


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[Daemon]:
    running = Daemon(tmp_path / "home")
    running.thread.start()
    assert running.started.wait(WAIT), "the daemon did not start"
    try:
        yield running
    finally:
        if running.thread.is_alive():
            state = Path(running.config.paths.state_dir)
            (state / "stop.request").write_bytes(b"stop\n")
            running.thread.join(WAIT)


def cli(home: Path, *argv: str, stdin: str = PASSWORD + "\n") -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    environment = CliEnv(
        environ={"PORTLOCK_HOME": str(home)},
        stdin=io.StringIO(stdin),
        stdout=out,
        stderr=err,
        is_tty=lambda: False,
    )
    code = main(["--user", "operator-one", "--password-stdin", *argv], env=environment)
    return code, out.getvalue(), err.getvalue()


def test_the_daemon_serves_the_api_and_the_command_line_finds_it(daemon: Daemon) -> None:
    runtime_file = read_runtime_file(daemon.config.paths.state_dir)
    assert runtime_file is not None and runtime_file["port"] != 0
    assert runtime_file["run_id"] == daemon.runtime.service.run_id  # type: ignore[union-attr]
    code, out, err = cli(daemon.home, "status", stdin="")
    assert code == 0 and "is running" in out and "SIMULATION" in out
    code, out, err = cli(daemon.home, "status", "--detail")
    assert code == 0 and "mode: monitor" in out, err
    code, out, err = cli(daemon.home, "devices")
    assert code == 0 and "no devices" in out


def test_a_device_plugged_into_the_daemon_is_decided_and_listed(daemon: Daemon) -> None:
    from factories import flash_drive

    daemon.backend.plug(flash_drive("TEST0101DAEM"))
    deadline = 200
    while deadline:
        code, out, err = cli(daemon.home, "devices", "--json")
        if code == 0 and '"state": "pending"' in out:
            break
        deadline -= 1
        threading.Event().wait(0.05)
    assert deadline, out + err
    code, out, err = cli(daemon.home, "devices")
    assert code == 0 and "pending" in out and "Example Corp Example Flash 16GB" in out


def test_stop_ends_the_daemon_cleanly_and_removes_the_runtime_file(daemon: Daemon) -> None:
    state = Path(daemon.config.paths.state_dir)
    assert (state / RUNTIME_FILE_NAME).is_file()
    out, err = io.StringIO(), io.StringIO()
    environment = CliEnv(
        environ={"PORTLOCK_HOME": str(daemon.home)}, stdin=io.StringIO(""), stdout=out, stderr=err
    )
    assert main(["stop"], env=environment) == 0, err.getvalue()
    assert "The service stopped." in out.getvalue()
    daemon.thread.join(WAIT)
    assert not daemon.thread.is_alive() and daemon.code == 0
    assert not (state / RUNTIME_FILE_NAME).exists()
    assert main(["stop"], env=environment) == 4  # nothing is running now
    code, _out, err_text = cli(daemon.home, "devices")
    assert code == 4 and "not running" in err_text


def test_a_second_daemon_is_refused_and_the_first_keeps_serving(
    daemon: Daemon, capsys: Any
) -> None:
    second = run(
        daemon.config,
        install_signal_handlers=False,
        backend=FakeBackend(),
        enforcer=FakeEnforcer(),
        simulation=True,
        timer=FakeExternalTimer(),
        dir_privacy=FakeDirPrivacy(),
    )
    assert second == 2 and "already running" in capsys.readouterr().err
    code, out, _err = cli(daemon.home, "status", stdin="")
    assert code == 0 and "is running" in out
