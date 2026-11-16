"""The scan pipeline: walk, hash, heuristics, hash lists and antivirus engines.

:class:`Scanner` ties the pieces of this package together and produces one
:class:`~portlock.scan.report.ScanReport`:

1. the antivirus engines that are available start scanning the volume, each on its own
   thread, so their (slow) work overlaps the walk instead of following it;
2. the volume is walked within the configured limits; every file is hashed, checked
   against the hash lists, and shown to the heuristics;
3. the engines are collected. One that failed, timed out or misbehaved is recorded and
   cannot affect the others or the walk.

Everything is read-only. Nothing on the scanned volume is deleted, moved, renamed,
quarantined or modified, by this code or by the tools it runs.

A scan is bounded by ``ScanLimits.max_seconds`` overall: the walk stops reading when
the budget is spent and each engine is given the same allowance as its timeout. A
``threading.Event`` cancels both. Whatever cut a scan short is named in the report, and
such a report is never ``clean``. Neither is one in which no engine took part.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import ConfigError, PortLockError, ScanError
from portlock.scan.av import (
    ClamAvEngine,
    CommandRunner,
    DefenderEngine,
    Engine,
    EngineCancelledError,
    EngineError,
    EngineTimeoutError,
    EngineUnavailableError,
)
from portlock.scan.hashdb import HashEntry, HashKind, HashSet, classify
from portlock.scan.heuristics import ENGINE_NAME as HEURISTICS_ENGINE
from portlock.scan.heuristics import HeuristicEngine, HeuristicSession
from portlock.scan.inspector import (
    HEAD_BYTES,
    FileEntry,
    FileTooLargeError,
    NotRegularFileError,
    ScanInterrupted,
    ScanLimits,
    Walk,
    digest_file,
    extension_of,
    read_prefix,
    walk,
)
from portlock.scan.report import (
    MAX_PATH_CHARS,
    EngineStatus,
    Finding,
    FindingSeverity,
    IssueKind,
    ScanIssue,
    ScanReport,
    safe_text,
)

__all__ = [
    "ENGINE_NAMES",
    "HASHSET_ENGINE",
    "MEMORY_ROOT",
    "ProgressCallback",
    "ScanProgress",
    "Scanner",
    "build_scanner",
]

#: The engine name on findings that come from the hash lists.
HASHSET_ENGINE = "hashset"
#: The ``root`` of a report produced by :meth:`Scanner.scan_bytes`.
MEMORY_ROOT = "<memory>"
#: Every engine :func:`build_scanner` knows, in the order the configuration lists them.
ENGINE_NAMES: tuple[str, ...] = (HEURISTICS_ENGINE, HASHSET_ENGINE, "clamav", "defender")

# How long, in real seconds beyond the time budget, an engine thread is waited for
# before it is given up on. An engine honours its own timeout; this only bounds one
# that does not.
_DEFAULT_ENGINE_GRACE = 10.0
_JOIN_SLICE = 0.1


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """A snapshot handed to the progress callback before each file is examined.

    ``current_path`` is a name chosen by whoever wrote the volume. Like every string in a
    :class:`~portlock.scan.report.ScanReport`, it passes through
    :func:`~portlock.scan.report.safe_text` here, at the type, so a progress display can
    print it as it is.
    """

    files_seen: int
    files_hashed: int
    bytes_hashed: int
    current_path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "current_path", safe_text(str(self.current_path), MAX_PATH_CHARS))


ProgressCallback = Callable[[ScanProgress], None]


class _Findings:
    """A bounded list of findings.

    Once ``limit`` findings are held, further ones are dropped, except malicious ones,
    which have an allowance of their own. A volume built to produce a hundred thousand
    suspicious findings can therefore neither exhaust memory nor push the one malicious
    finding out of the report.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._malicious = 0
        self.items: list[Finding] = []
        self.dropped = 0

    def add(self, finding: Finding) -> None:
        if finding.severity is FindingSeverity.MALICIOUS:
            if self._malicious < self._limit:
                self._malicious += 1
                self.items.append(finding)
                return
        elif len(self.items) - self._malicious < self._limit:
            self.items.append(finding)
            return
        self.dropped += 1

    def extend(self, findings: Sequence[Finding]) -> None:
        for finding in findings:
            self.add(finding)


@dataclass(slots=True)
class _State:
    """Everything one scan accumulates. Created per scan, so scans never share state."""

    session: HeuristicSession
    hash_findings: _Findings
    heuristic_findings: _Findings
    engine_findings: _Findings
    issues: list[ScanIssue] = field(default_factory=list)
    truncations: list[str] = field(default_factory=list)
    files_hashed: int = 0
    bytes_hashed: int = 0
    hash_lists_failed: bool = False
    internal_failures: int = 0

    def truncate(self, reason: str) -> None:
        if reason not in self.truncations:
            self.truncations.append(reason)

    def internal_failure(self, path: str, exc: Exception) -> None:
        """Record that examining ``path`` raised. The first is listed, the rest counted."""
        self.internal_failures += 1
        if self.internal_failures == 1:
            self.issues.append(
                ScanIssue(
                    "scan",
                    path,
                    f"could not be examined: unexpected {type(exc).__name__}",
                    IssueKind.FAILED,
                )
            )


@dataclass(slots=True)
class _EngineRun:
    """One engine's part in a scan. Written by its thread, read after the thread ends.

    ``started`` is real monotonic time, for bounding how long the thread is waited for.
    """

    engine: Engine
    name: str
    status_index: int
    started: float
    findings: list[Finding] = field(default_factory=list)
    failure: str | None = None
    timed_out: bool = False
    cancelled: bool = False
    unavailable: bool = False


def _engine_name(engine: object) -> str:
    name = getattr(engine, "name", None)
    return name if isinstance(name, str) and name else type(engine).__name__.lower()


class Scanner:
    """Scans a mounted volume, or bytes held in memory, and reports what it found.

    A scanner holds configuration only; each call builds its own working state, so one
    scanner may run several scans at once from different threads.

    Args:
        engines: antivirus engines to consult (see :mod:`portlock.scan.av`). An engine
            that is not available on this machine is listed in the report and skipped.
        hashsets: known-bad and known-good lists. The built-in digests (the EICAR test
            file) are recognised even with no list configured.
        limits: bounds on the scan; the defaults of :class:`ScanLimits` if omitted.
        clock: time source for the report's timestamps and for ``max_seconds``.
        heuristics: the heuristic rule set; the default rules if omitted.
        use_heuristics: apply the heuristics. When False they are neither run nor
            listed among the report's engines.
        use_hashsets: consult the hash lists, the built-in digests included. When False
            files are still hashed (findings carry the digest) but nothing is looked up.
        engine_grace: real seconds an engine thread is given beyond the time budget
            before it is abandoned and reported as failed.

    Raises:
        ConfigError: if ``engine_grace`` is not a non-negative number.
    """

    def __init__(
        self,
        engines: Sequence[Engine] = (),
        hashsets: Sequence[HashSet] = (),
        limits: ScanLimits | None = None,
        clock: Clock | None = None,
        *,
        heuristics: HeuristicEngine | None = None,
        use_heuristics: bool = True,
        use_hashsets: bool = True,
        engine_grace: float = _DEFAULT_ENGINE_GRACE,
    ) -> None:
        if isinstance(engine_grace, bool) or not isinstance(engine_grace, int | float):
            raise ConfigError(f"engine_grace must be a number, got {engine_grace!r}")
        # Written so that NaN fails it.
        if not 0 <= engine_grace < float("inf"):
            raise ConfigError(f"engine_grace must be zero or more seconds, got {engine_grace!r}")
        self._engines = tuple(engines)
        self._hashsets = tuple(hashsets)
        self._limits = limits if limits is not None else ScanLimits()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._use_heuristics = bool(use_heuristics)
        self._use_hashsets = bool(use_hashsets)
        if not self._use_heuristics:
            # An engine with no rules asks for no content and reports nothing.
            self._heuristics = HeuristicEngine((), folder_rule=False)
        else:
            self._heuristics = heuristics if heuristics is not None else HeuristicEngine()
        self._engine_grace = float(engine_grace)

    @property
    def limits(self) -> ScanLimits:
        """The bounds every scan by this scanner runs under."""
        return self._limits

    @property
    def engines(self) -> tuple[Engine, ...]:
        """The antivirus engines this scanner consults, in order."""
        return self._engines

    # -- public API ------------------------------------------------------------------

    def scan(
        self,
        root: str | os.PathLike[str],
        *,
        cancel: threading.Event | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanReport:
        """Scan the directory tree under ``root``.

        Never raises for anything found on the volume or for an engine that fails: all
        of that is in the report. See :mod:`portlock.scan.report` for how the verdict
        follows from it.

        Args:
            root: the directory to scan, typically a volume's mount point.
            cancel: set this event from another thread to stop the scan. The report then
                says ``cancelled`` and is ``incomplete`` unless something worse was
                already found.
            progress: called from the scanning thread before each file is examined. A
                callback that raises is not called again; the scan carries on.

        Returns:
            The report. Its ``errors`` list files that could not be read and engines
            that failed; its ``truncated_reason`` names any limit that was hit.

        Raises:
            TypeError: if ``root`` is not a path.
        """
        started_at = self._clock.now()
        root_text = os.fsdecode(root)
        state = self._new_state()
        statuses = self._builtin_statuses()

        usable: list[tuple[Engine, int]] = []
        for engine in self._engines:
            status, available = self._engine_status(engine, state)
            statuses.append(status)
            if available:
                usable.append((engine, len(statuses) - 1))
        if not (self._use_heuristics or self._use_hashsets or usable):
            # Walking and hashing a volume that nothing then judges would end in a
            # report that looks like a clean bill of health. Say what really happened.
            state.issues.append(self._nothing_took_part())
            return self._report(root_text, started_at, 0, state, statuses, [])

        walker = walk(root_text, self._limits, cancel=cancel, clock=self._clock)
        runs: list[tuple[_EngineRun, threading.Thread]] = []
        if self._is_directory(root_text):
            # Otherwise the walk reports the unusable root, once, for everybody.
            for engine, index in usable:
                run = _EngineRun(engine, statuses[index].name, index, time.monotonic())
                runs.append((run, self._start_engine(run, root_text, cancel)))

        files_seen = 0
        try:
            for entry in walker:
                try:
                    if entry.is_dir:
                        state.heuristic_findings.extend(state.session.inspect(entry))
                        continue
                    files_seen += 1
                    if progress is not None:
                        progress = self._report_progress(progress, state, files_seen, entry)
                    self._examine_file(walker, entry, state)
                except Exception as exc:
                    # A defect in handling one file must cost that file, not the scan,
                    # and must never pass for "nothing found".
                    state.internal_failure(entry.display_path, exc)
        except Exception as exc:
            state.issues.append(
                ScanIssue(
                    "walk",
                    "",
                    f"the walk stopped on an unexpected {type(exc).__name__}",
                    IssueKind.FAILED,
                )
            )
        finally:
            walker.close()
        state.heuristic_findings.extend(state.session.finish())

        for run, thread in runs:
            self._collect_engine(run, thread, state, statuses, cancel)

        state.issues[:0] = walker.issues
        if walker.issues_dropped:
            state.issues.append(
                ScanIssue(
                    "walk",
                    "",
                    f"{walker.issues_dropped} further unreadable entries are not listed",
                )
            )
        truncations = list(walker.truncation_reasons)
        truncations += [reason for reason in state.truncations if reason not in truncations]
        return self._report(root_text, started_at, files_seen, state, statuses, truncations)

    def scan_bytes(self, name: str, data: bytes | bytearray | memoryview) -> ScanReport:
        """Examine content held in memory as if it were a file called ``name``.

        The heuristics and the hash lists are applied; antivirus engines are not (they
        scan paths), and the report's engine list says so by leaving them out. Nothing
        is written to disk, which makes this the way to exercise detection, the EICAR
        test content included, without tripping the machine's own antivirus.

        Args:
            name: the file name to judge the content under. A ``/``-separated relative
                path places the file below the root (a bare name is *at* the root, where
                the root-only rules apply).
            data: the complete content.

        Returns:
            A report whose root is ``<memory>``.

        Raises:
            ScanError: if ``name`` is not a string, or is empty, absolute, contains a
                NUL character or a ``..`` component.
            TypeError: if ``data`` is not bytes-like.
        """
        if not isinstance(name, str):
            raise ScanError("the name of in-memory content must be a string")
        relative = name.replace("\\", "/")
        parts = [part for part in relative.split("/") if part]
        if not parts or relative.startswith("/") or "\x00" in name or ".." in parts:
            raise ScanError("in-memory content needs a relative file name")
        content = bytes(data)
        started_at = self._clock.now()
        state = self._new_state()
        statuses = self._builtin_statuses()
        if not statuses:
            state.issues.append(self._nothing_took_part())
            return self._report(MEMORY_ROOT, started_at, 0, state, statuses, [])
        entry = FileEntry(
            path="/".join(parts),
            os_path="",
            size=len(content),
            extension=extension_of(parts[-1]),
            head=content[:HEAD_BYTES],
            opened=True,
        )
        digest = hashlib.sha256(content).hexdigest()
        state.files_hashed, state.bytes_hashed = 1, len(content)
        wanted = self._heuristics.content_wanted(entry)
        self._judge(entry, content[:wanted] if wanted else None, digest, state)
        state.heuristic_findings.extend(state.session.finish())
        return self._report(MEMORY_ROOT, started_at, 1, state, statuses, [])

    # -- one file --------------------------------------------------------------------

    def _examine_file(self, walker: Walk, entry: FileEntry, state: _State) -> None:
        content: bytes | None = None
        digest: str | None = None
        if entry.opened:
            wanted = min(self._heuristics.content_wanted(entry), walker.remaining_bytes)
            whole = False
            if len(entry.head) < HEAD_BYTES:
                # The walk hit the end of the file while reading its head, so the head
                # is the whole file: no need to open a small file a second time.
                content, whole = (entry.head if wanted > 0 else None), True
            elif wanted > 0:
                content = self._read_content(walker, entry, wanted)
                whole = content is not None and len(content) < wanted
            if whole:
                complete = entry.head if content is None else content
                digest = hashlib.sha256(complete).hexdigest()
                state.files_hashed += 1
                state.bytes_hashed += len(complete)
            else:
                digest = self._hash(walker, entry, state)
        self._judge(entry, content, digest, state)

    @staticmethod
    def _read_content(walker: Walk, entry: FileEntry, wanted: int) -> bytes | None:
        if walker.stop_reason() is not None:
            # The walk reports the reason itself at its next step.
            return None
        try:
            content = read_prefix(entry.os_path, wanted)
        except (OSError, NotRegularFileError) as exc:
            # Recorded through the walk, whose issue list is bounded by max_errors.
            walker.record_issue(HEURISTICS_ENGINE, entry.path, f"could not be read: {_reason(exc)}")
            return None
        walker.charge(len(content))
        return content

    def _hash(self, walker: Walk, entry: FileEntry, state: _State) -> str | None:
        """Hash one file within the budget. ``None`` if it was not hashed (and why is noted)."""
        reason = walker.stop_reason()
        if reason is not None:
            state.truncate(reason)
            return None
        per_file = self._limits.max_file_bytes
        if per_file is not None and entry.size > per_file:
            walker.record_issue(
                "hash",
                entry.path,
                f"{entry.size} bytes is over the per-file limit of {per_file}; not hashed",
            )
            return None
        allowance = walker.remaining_bytes
        if per_file is not None:
            allowance = min(allowance, per_file)
        if entry.size > allowance:
            state.truncate("max_bytes")
            return None
        try:
            digest = digest_file(entry.os_path, max_bytes=allowance, should_stop=walker.stop_reason)
        except ScanInterrupted as exc:
            state.truncate(exc.reason)
            return None
        except FileTooLargeError:
            # It grew after it was listed, past what is left of the budget.
            state.truncate("max_bytes")
            return None
        except (OSError, NotRegularFileError) as exc:
            walker.record_issue("hash", entry.path, f"could not be read: {_reason(exc)}")
            return None
        walker.charge(digest.size)
        state.files_hashed += 1
        state.bytes_hashed += digest.size
        return digest.sha256

    def _judge(
        self, entry: FileEntry, content: bytes | None, digest: str | None, state: _State
    ) -> None:
        """Apply the hash lists and the heuristics to one file."""
        match: HashEntry | None = None
        if digest is not None and self._use_hashsets:
            match = self._classify(digest, state)
        if match is not None and match.kind is HashKind.KNOWN_BAD:
            state.hash_findings.add(
                Finding(
                    path=entry.display_path,
                    engine=HASHSET_ENGINE,
                    rule=match.label or "known-bad",
                    severity=FindingSeverity.MALICIOUS,
                    detail=f"SHA-256 is on the known-bad list '{match.source}'",
                    sha256=digest,
                )
            )
        trusted_by: str | None = None
        if match is not None and match.kind is HashKind.KNOWN_GOOD:
            # A known-good digest vouches for this exact file against PortLock's own
            # guesses. The session records the suppression instead of the findings.
            label = f" as {safe_text(match.label, 80)}" if match.label else ""
            trusted_by = f"on the known-good list '{match.source}'{label}"
        state.heuristic_findings.extend(
            state.session.inspect(entry, content, digest, trusted_by=trusted_by)
        )

    def _classify(self, digest: str, state: _State) -> HashEntry | None:
        try:
            return classify(digest, self._hashsets)
        except PortLockError as exc:
            # A broken list must not read as "no match": say so, once, as a failure.
            if not state.hash_lists_failed:
                state.hash_lists_failed = True
                state.issues.append(
                    ScanIssue(
                        HASHSET_ENGINE,
                        "",
                        f"the hash lists could not be consulted: {exc.message}",
                        IssueKind.FAILED,
                    )
                )
            return None

    @staticmethod
    def _report_progress(
        progress: ProgressCallback, state: _State, files_seen: int, entry: FileEntry
    ) -> ProgressCallback | None:
        """Call the progress callback; returns it, or ``None`` once it has raised."""
        try:
            progress(
                ScanProgress(files_seen, state.files_hashed, state.bytes_hashed, entry.display_path)
            )
        except Exception:
            # The callback belongs to the caller's user interface. Its failure is not a
            # reason to abandon a security scan half way; stop calling it and go on.
            return None
        return progress

    # -- engines ---------------------------------------------------------------------

    def _builtin_statuses(self) -> list[EngineStatus]:
        statuses: list[EngineStatus] = []
        if self._use_heuristics:
            statuses.append(EngineStatus(HEURISTICS_ENGINE, True, self._heuristics.version()))
        if self._use_hashsets:
            statuses.append(EngineStatus(HASHSET_ENGINE, True, None))
        return statuses

    @staticmethod
    def _nothing_took_part() -> ScanIssue:
        return ScanIssue(
            "scan",
            "",
            "no scan engine is enabled and available; nothing was examined",
            IssueKind.FAILED,
        )

    @staticmethod
    def _is_directory(root: str) -> bool:
        try:
            return os.path.isdir(root)
        except (OSError, ValueError):
            return False

    @staticmethod
    def _engine_status(engine: Engine, state: _State) -> tuple[EngineStatus, bool]:
        """Ask an engine whether it can take part; a faulty engine counts as failed."""
        name = _engine_name(engine)
        try:
            available = bool(engine.available())
        except Exception as exc:
            state.issues.append(
                ScanIssue(
                    name, "", f"availability check failed: {type(exc).__name__}", IssueKind.FAILED
                )
            )
            return EngineStatus(name, False, None), False
        version: str | None = None
        if available:
            try:
                reported = engine.version()
            except Exception:
                reported = None
            version = reported if isinstance(reported, str) else None
        return EngineStatus(name, available, version), available

    def _start_engine(
        self, run: _EngineRun, root: str, cancel: threading.Event | None
    ) -> threading.Thread:
        # A daemon thread: an engine that never returns must not keep the process alive.
        thread = threading.Thread(
            target=self._run_engine,
            args=(run, root, self._limits.max_seconds, cancel),
            name=f"portlock-scan-{run.name}",
            daemon=True,
        )
        thread.start()
        return thread

    @staticmethod
    def _run_engine(
        run: _EngineRun, root: str, timeout: float, cancel: threading.Event | None
    ) -> None:
        """Thread body: run one engine and record how it went. Never raises."""
        try:
            produced = run.engine.scan_path(root, timeout=timeout, cancel=cancel)
            if not isinstance(produced, list | tuple) or not all(
                isinstance(item, Finding) for item in produced
            ):
                run.failure = "returned something other than a list of findings"
                return
            run.findings = list(produced)
        except EngineCancelledError as exc:
            run.findings = list(exc.findings)
            run.cancelled = True
        except EngineTimeoutError as exc:
            run.findings = list(exc.findings)
            run.timed_out = True
            run.failure = exc.message
        except EngineUnavailableError as exc:
            run.unavailable = True
            run.failure = exc.message
        except EngineError as exc:
            run.findings = list(exc.findings)
            run.failure = exc.message
        except Exception as exc:
            # Isolation: whatever an engine does wrong stays that engine's failure.
            run.failure = f"unexpected failure: {type(exc).__name__}"

    def _collect_engine(
        self,
        run: _EngineRun,
        thread: threading.Thread,
        state: _State,
        statuses: list[EngineStatus],
        cancel: threading.Event | None,
    ) -> None:
        """Wait for one engine, within its allowance, and fold its result into the scan."""
        # Real time, not the injected clock: this bounds how long a real thread is
        # waited for, and a thread does not run on a clock a test can move.
        deadline = run.started + self._limits.max_seconds + self._engine_grace
        cancel_seen = False
        while thread.is_alive():
            now = time.monotonic()
            if not cancel_seen and cancel is not None and cancel.is_set():
                # A cancelled engine is expected to stop at once, not at its timeout.
                cancel_seen = True
                deadline = min(deadline, now + self._engine_grace)
            if now >= deadline:
                break
            thread.join(min(_JOIN_SLICE, deadline - now))
        if thread.is_alive():
            # It ignored its timeout. The daemon thread is abandoned, not waited for,
            # and whatever it might still produce is not read.
            state.issues.append(
                ScanIssue(run.name, "", "did not stop when its time was up", IssueKind.FAILED)
            )
            return
        state.engine_findings.extend(run.findings)
        if run.cancelled:
            state.truncate("cancelled")
        elif run.timed_out:
            state.truncate("max_seconds")
            state.issues.append(ScanIssue(run.name, "", run.failure or "timed out"))
        elif run.failure is not None:
            if run.unavailable:
                # The tool is installed but cannot scan (service stopped, disabled by
                # policy). The engine list says so; the verdict still cannot be clean,
                # because an engine the operator configured did not look at the volume.
                status = statuses[run.status_index]
                statuses[run.status_index] = EngineStatus(status.name, False, status.version)
            state.issues.append(ScanIssue(run.name, "", run.failure, IssueKind.FAILED))

    # -- assembling the report -------------------------------------------------------

    def _new_state(self) -> _State:
        limit = self._limits.max_findings
        return _State(
            session=self._heuristics.session(),
            hash_findings=_Findings(limit),
            heuristic_findings=_Findings(limit),
            engine_findings=_Findings(limit),
        )

    def _report(
        self,
        root: str,
        started_at: datetime,
        files_seen: int,
        state: _State,
        statuses: list[EngineStatus],
        truncations: list[str],
    ) -> ScanReport:
        issues = list(state.issues)
        if state.internal_failures > 1:
            issues.append(
                ScanIssue(
                    "scan",
                    "",
                    f"{state.internal_failures - 1} further files could not be examined",
                    IssueKind.FAILED,
                )
            )
        for rule_id, path, message in state.session.errors:
            issues.append(
                ScanIssue(
                    HEURISTICS_ENGINE, path, f"rule {rule_id} failed: {message}", IssueKind.FAILED
                )
            )
        if state.session.errors_dropped:
            issues.append(
                ScanIssue(
                    HEURISTICS_ENGINE,
                    "",
                    f"{state.session.errors_dropped} further rule failures are not listed",
                    IssueKind.FAILED,
                )
            )
        findings = [
            *state.hash_findings.items,
            *state.heuristic_findings.items,
            *state.engine_findings.items,
        ]
        dropped = (
            state.hash_findings.dropped
            + state.heuristic_findings.dropped
            + state.engine_findings.dropped
        )
        if dropped:
            truncations = [*truncations, "max_findings"]
        return ScanReport(
            root=root,
            started_at=started_at,
            finished_at=self._clock.now(),
            files_seen=files_seen,
            files_hashed=state.files_hashed,
            bytes_hashed=state.bytes_hashed,
            findings=tuple(findings),
            truncated=bool(truncations),
            truncated_reason=", ".join(truncations) if truncations else None,
            errors=tuple(issues),
            engines=tuple(statuses),
        )


def build_scanner(
    engine_names: Iterable[str],
    *,
    hashsets: Sequence[HashSet] = (),
    limits: ScanLimits | None = None,
    clock: Clock | None = None,
    runner: CommandRunner | None = None,
) -> Scanner:
    """Build a :class:`Scanner` from the engine names used in the configuration.

    ``heuristics`` and ``hashset`` switch the two built-in engines on; ``clamav`` and
    ``defender`` add the adapters for those products, which report themselves as
    unavailable where the product is not installed. Repeated names count once.

    Args:
        engine_names: names from :data:`ENGINE_NAMES`, e.g. ``config.scan.engines``.
        hashsets: the hash lists to consult when ``hashset`` is named.
        limits: bounds on each scan.
        clock: time source for the scanner and the adapters.
        runner: how the adapters run their tools; real subprocesses if omitted.

    Raises:
        ConfigError: if a name is unknown, or no engine is named at all.
    """
    names = list(dict.fromkeys(engine_names))
    unknown = [name for name in names if name not in ENGINE_NAMES]
    if unknown:
        raise ConfigError(
            f"unknown scan engine(s) {', '.join(repr(name) for name in unknown)}: "
            f"expected any of {', '.join(ENGINE_NAMES)}"
        )
    if not names:
        raise ConfigError("at least one scan engine must be named")
    engines: list[Engine] = []
    if "clamav" in names:
        engines.append(ClamAvEngine(runner, clock=clock))
    if "defender" in names:
        engines.append(DefenderEngine(runner))
    return Scanner(
        engines,
        hashsets,
        limits,
        clock,
        use_heuristics=HEURISTICS_ENGINE in names,
        use_hashsets=HASHSET_ENGINE in names,
    )


def _reason(exc: Exception) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or type(exc).__name__
    return str(exc)
