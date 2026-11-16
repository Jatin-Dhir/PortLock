"""Unit tests read nothing about this machine that would make their answer depend on it.

``core.config`` asks two machine-wide sources when it decides whether a directory is
system-wide: the registry's ``ProfilesDirectory`` (Windows) and name resolution (a UNC
server that might be this computer). Both are replaced here for every unit test:

* the registry lookup answers a fixed folder that holds no test directory, so that a
  ``tmp_path`` (which on Windows lies inside the real profile of whoever runs the tests)
  is classed only by what each test puts in the environment;
* no name resolves, so no unit test sends a DNS query.

Tests of those two sources replace them again with their own fakes. The live tests under
``tests/hardware`` keep the real ones.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from portlock.core import config as config_module

#: What the registry's ProfilesDirectory reads as in unit tests: never above a tmp_path.
TEST_PROFILES_DIRECTORY = "C:" + chr(92) + "PortLock-test-profiles"


@pytest.fixture(autouse=True, scope="session")
def _machine_sources_replaced() -> Iterator[None]:
    # Session-wide, so that module-scoped fixtures (which run before any function-scoped
    # one) see the replacements too.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            config_module, "_registry_profiles_directory", lambda: TEST_PROFILES_DIRECTORY
        )
        patch.setattr(config_module, "_lookup", lambda name: frozenset())
        yield
