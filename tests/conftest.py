"""Shared pytest configuration.

Safety rules for this suite (see docs/DESIGN.md, "Testing rules"):

* no test calls a real enforcement mechanism or changes any system setting;
* fixtures are synthetic: no real serial numbers, host names or user names;
* time is injected through ``FakeClock``; tests do not sleep to make things expire.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from portlock.core.clock import FakeClock
from portlock.core.db import Database

FIXTURES = Path(__file__).parent / "fixtures"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-hardware",
        action="store_true",
        default=False,
        help="run tests that read real device information from this machine (read-only)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_hardware = config.getoption("--run-hardware")
    for item in items:
        if "hardware" in item.keywords and not run_hardware:
            item.add_marker(pytest.mark.skip(reason="reads real hardware; pass --run-hardware"))
        if "linux_only" in item.keywords and not sys.platform.startswith("linux"):
            item.add_marker(pytest.mark.skip(reason="needs a Linux kernel"))
        if "windows_only" in item.keywords and sys.platform != "win32":
            item.add_marker(pytest.mark.skip(reason="needs Windows"))


@pytest.fixture
def fixtures_dir() -> Path:
    """Directory holding static test fixtures."""
    return FIXTURES


@pytest.fixture
def clock() -> FakeClock:
    """A clock that starts at 2026-01-01T00:00:00Z and only moves when advanced."""
    return FakeClock()


@pytest.fixture
def db() -> Iterator[Database]:
    """A private in-memory database."""
    database = Database()
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """An empty directory standing in for PortLock's state directory."""
    directory = tmp_path / "state"
    directory.mkdir()
    return directory
