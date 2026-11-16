"""Signals stop the service while its main thread only waits.

On Windows before Python 3.13 a lock wait cannot be interrupted, so a signal handler never
ran while the main thread sat in an untimed ``Event.wait()``: Ctrl+C and Ctrl+Break did
nothing and the service could only be stopped from another window. The wait is now cut
into short pieces. These tests hold that: one checks the wait itself on every platform,
the other sends a real signal to a real process.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from portlock.service import daemon

SRC = Path(__file__).resolve().parents[2] / "src"

# The child installs the service's own handlers and waits the way the service waits.
_CHILD = textwrap.dedent(
    """
    import threading

    from portlock.service import daemon

    stopping = threading.Event()
    daemon._install_signals(stopping, [])
    print("ready", flush=True)
    daemon._wait_until_stopped(stopping)
    print("stopped", flush=True)
    """
)

# CTRL_C_EVENT cannot be sent to one child only; CTRL_BREAK_EVENT can, and it takes the
# same path through the interpreter (a handler that must run on the main thread).
_SIGNALS = ["CTRL_BREAK_EVENT"] if sys.platform == "win32" else ["SIGINT", "SIGTERM"]


class _RecordingEvent(threading.Event):
    """An event that notes every timeout it is waited on with and sets itself later."""

    def __init__(self, set_after: int) -> None:
        super().__init__()
        self.timeouts: list[float | None] = []
        self._set_after = set_after

    def wait(self, timeout: float | None = None) -> bool:
        self.timeouts.append(timeout)
        if len(self.timeouts) >= self._set_after:
            self.set()
        return super().wait(0)


def test_the_wait_is_never_untimed() -> None:
    event = _RecordingEvent(set_after=3)

    daemon._wait_until_stopped(event)

    assert len(event.timeouts) == 3
    assert all(timeout is not None and 0 < timeout <= 1.0 for timeout in event.timeouts)


def test_the_wait_returns_at_once_when_already_stopped() -> None:
    event = _RecordingEvent(set_after=99)
    event.set()

    daemon._wait_until_stopped(event)

    assert len(event.timeouts) == 1


@pytest.mark.parametrize("name", _SIGNALS)
def test_a_signal_ends_the_wait_of_a_real_process(name: str) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(SRC), environment.get("PYTHONPATH", "")) if part
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.Popen(
        [sys.executable, "-c", _CHILD],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        # Its own process group, so that the break reaches the child and not the tests.
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    try:
        assert process.stdout is not None
        first = process.stdout.readline().strip()
        if first != "ready":
            process.kill()
            _, errors = process.communicate()
            pytest.fail(f"the child did not start: {first!r} {errors[-800:]}")
        try:
            process.send_signal(getattr(signal, name))
        except OSError as exc:  # no console to send a break through
            pytest.skip(f"{name} cannot be sent here: {exc}")
        try:
            output, errors = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            pytest.fail(f"{name} did not end the wait within 20 seconds")
        assert output.strip() == "stopped", errors[-800:]
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
