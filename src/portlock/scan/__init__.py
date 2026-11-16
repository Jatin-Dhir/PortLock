"""PortLock Scan: bounded read-only file inspection, hashing, heuristics and antivirus adapters.

* :mod:`portlock.scan.report` - findings, the scan report and the verdict rules.
* :mod:`portlock.scan.inspector` - the bounded, read-only walk and file hashing.
* :mod:`portlock.scan.heuristics` - rules for the file shapes removable-media malware uses.
* :mod:`portlock.scan.hashdb` - known-bad and known-good SHA-256 lists.
* :mod:`portlock.scan.av` - adapters for ClamAV and Microsoft Defender.
* :mod:`portlock.scan.scanner` - :class:`Scanner`, which runs all of the above.

Scanning only ever reads. Nothing in this package deletes, moves, renames, quarantines
or modifies a file on the scanned volume, and the antivirus tools are run with options
that report and nothing else. Nothing here imports ``portlock.guard``.
``docs/SCANNING.md`` is the reference: the limits, each heuristic and why it has the
severity it has, and what has and has not been checked against the real tools.
"""

from __future__ import annotations

from portlock.scan.av import (
    ClamAvEngine,
    CommandResult,
    CommandRunner,
    DefenderEngine,
    Engine,
    EngineCancelledError,
    EngineError,
    EngineTimeoutError,
    EngineUnavailableError,
    SubprocessRunner,
)
from portlock.scan.hashdb import (
    EICAR_SHA256,
    HashConflictError,
    HashEntry,
    HashKind,
    HashListError,
    HashSet,
    ImportResult,
    InvalidHashError,
    classify,
)
from portlock.scan.heuristics import HeuristicEngine, Rule
from portlock.scan.inspector import FileEntry, ScanLimits, Walk, hash_file, walk
from portlock.scan.report import (
    EngineStatus,
    Finding,
    FindingSeverity,
    IssueKind,
    ScanIssue,
    ScanReport,
    Verdict,
    safe_text,
)
from portlock.scan.scanner import (
    ENGINE_NAMES,
    ProgressCallback,
    Scanner,
    ScanProgress,
    build_scanner,
)

__all__ = [
    "EICAR_SHA256",
    "ENGINE_NAMES",
    "ClamAvEngine",
    "CommandResult",
    "CommandRunner",
    "DefenderEngine",
    "Engine",
    "EngineCancelledError",
    "EngineError",
    "EngineStatus",
    "EngineTimeoutError",
    "EngineUnavailableError",
    "FileEntry",
    "Finding",
    "FindingSeverity",
    "HashConflictError",
    "HashEntry",
    "HashKind",
    "HashListError",
    "HashSet",
    "HeuristicEngine",
    "ImportResult",
    "InvalidHashError",
    "IssueKind",
    "ProgressCallback",
    "Rule",
    "ScanIssue",
    "ScanLimits",
    "ScanProgress",
    "ScanReport",
    "Scanner",
    "SubprocessRunner",
    "Verdict",
    "Walk",
    "build_scanner",
    "classify",
    "hash_file",
    "safe_text",
    "walk",
]
