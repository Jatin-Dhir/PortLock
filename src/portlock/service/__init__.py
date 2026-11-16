"""The PortLock process: composition root, single-instance lock, run loop and shutdown.

See :mod:`portlock.service.daemon` and ``docs/ARCHITECTURE.md`` section 3.7.
"""

from __future__ import annotations

from portlock.service.daemon import (
    EXIT_ALREADY_RUNNING,
    EXIT_CONFIG,
    EXIT_ERROR,
    EXIT_OK,
    EXIT_PORT,
    EXIT_STATE_UNUSABLE,
    InstanceLock,
    Runtime,
    StoreRecovery,
    build_runtime,
    read_runtime_file,
    request_stop,
    run,
)

__all__ = [
    "EXIT_ALREADY_RUNNING",
    "EXIT_CONFIG",
    "EXIT_ERROR",
    "EXIT_OK",
    "EXIT_PORT",
    "EXIT_STATE_UNUSABLE",
    "InstanceLock",
    "Runtime",
    "StoreRecovery",
    "build_runtime",
    "read_runtime_file",
    "request_stop",
    "run",
]
