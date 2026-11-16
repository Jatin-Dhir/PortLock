"""Fixtures for the integration tests: a whole PortLock process on a simulated machine.

Every test builds the runtime with ``service.daemon.build_runtime`` on ``tmp_path``
(real SQLite stores, journal file and audit log) with ``FakeBackend``, ``FakeEnforcer``
and ``FakeClock``. Nothing touches a real device, timer or system setting.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from integration.harness import Harness


@pytest.fixture
def machine(tmp_path: Path) -> Iterator[Callable[..., Harness]]:
    """Build (and boot) harnesses; each is stopped at the end if still running."""
    built: list[Harness] = []

    def make(*, boot: bool = True, **options: Any) -> Harness:
        harness = Harness(tmp_path / f"m{len(built)}", **options)
        built.append(harness)
        if boot:
            harness.boot()
        return harness

    yield make
    for harness in built:
        if harness.runtime is not None:
            harness.crash()
