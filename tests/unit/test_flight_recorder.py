"""The flight recorder of the live tests (``tests/hardware/flight_recorder.py``).

C13 of the third watch-only pass: on a fast machine (a GitHub runner) the live test killed
a service within its first second, before the recorder had written any report, and the
test failed reading it. The recorder now writes a report as soon as its tripwires are
armed, and counts its writes, so a test can wait for one that covers what happened.

The recorder runs in a child process: it installs an audit hook and arms tripwires on
PortLock's seams, which must not reach this test process. PortLock's own command is
replaced there by a stand-in, so nothing of PortLock runs at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARDWARE = ROOT / "tests" / "hardware"

_CHILD = """
import os
import sys

sys.path.insert(0, sys.argv[1])
import flight_recorder
import portlock.console.cli as cli

def stand_in(argv):
    # Exit 0 only if a report was already on disk when the command began.
    return 0 if os.path.exists(os.environ["PORTLOCK_FLIGHT_REPORT"]) else 7

cli.main = stand_in
raise SystemExit(flight_recorder.main())
"""


def test_the_report_exists_before_the_command_runs_and_counts_its_writes(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(("PORTLOCK_", "PYTHON"))
    }
    environment.update(
        PORTLOCK_HOME=str(tmp_path / "home"),
        PORTLOCK_FLIGHT_REPORT=str(report),
        PYTHONPATH=str(ROOT / "src"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", _CHILD, str(HARDWARE)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(report.read_text(encoding="utf-8"))
    # Once when armed, once at exit (and once a second in between, if it took that long).
    assert data["writes"] >= 2
    assert data["exit"] == 0
