"""Adapters for antivirus products that may already be installed on the machine.

PortLock ships no signatures of its own. Where ClamAV or Microsoft Defender is present,
these adapters ask it to scan a mounted volume and translate what it prints into
:class:`~portlock.scan.report.Finding` values.

Rules every adapter follows:

* **Read-only.** The tools are run with options that report and nothing else. ClamAV is
  never given ``--remove`` or ``--move``; Defender is always given
  ``-DisableRemediation``, which stops it from quarantining what it detects.
* **No trust in PATH.** A tool is looked up by absolute path in the system directories
  where its installer puts it. A program of the same name elsewhere is ignored.
* **No shell.** Commands are argument lists passed to an injectable
  :class:`CommandRunner`, with a timeout, bounded output capture and a kill on cancel.
* **Failure is never "clean".** A tool that is missing is reported as unavailable. A
  tool that runs and fails (service stopped, disabled by policy, database missing,
  output that cannot be understood, timeout) raises :class:`EngineError`; the scanner
  records it and the verdict cannot be ``clean``.

Tests drive the adapters through a fake runner and recorded tool output; see
``docs/SCANNING.md`` for what has been confirmed against the real tools.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol, runtime_checkable

from portlock.core.clock import Clock, SystemClock
from portlock.core.errors import ScanError
from portlock.scan.report import Finding, FindingSeverity, safe_text

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "ClamAvEngine",
    "CommandResult",
    "CommandRunner",
    "DefenderEngine",
    "Engine",
    "EngineCancelledError",
    "EngineError",
    "EngineTimeoutError",
    "EngineUnavailableError",
    "SubprocessRunner",
    "find_tool",
    "is_trusted_program",
    "parse_clam_output",
    "parse_defender_output",
    "relative_to_root",
]

#: Output kept from one command. A volume full of detections prints one line per file;
#: anything beyond this is discarded and the run is treated as failed.
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024

_IS_WINDOWS = sys.platform == "win32"
_PROBE_TIMEOUT = 10.0
_POLL_SECONDS = 0.05
_KILL_WAIT_SECONDS = 5.0
_READER_JOIN_SECONDS = 2.0
_MESSAGE_CLIP = 300


class EngineError(ScanError):
    """An antivirus engine ran and failed, or its result cannot be trusted.

    Attributes:
        findings: detections that were read from the output before the failure. They
            stand; the failure only means the engine's answer is not complete.
    """

    code = "engine_error"

    def __init__(self, message: str, *, findings: Sequence[Finding] = ()) -> None:
        super().__init__(message)
        self.findings: tuple[Finding, ...] = tuple(findings)


class EngineUnavailableError(EngineError):
    """The engine cannot be used here: not installed, service stopped, or disabled."""

    code = "engine_unavailable"


class EngineTimeoutError(EngineError):
    """The engine did not finish within its time allowance and was stopped."""

    code = "engine_timeout"


class EngineCancelledError(EngineError):
    """The engine was stopped because the scan was cancelled."""

    code = "engine_cancelled"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What running one command produced.

    Attributes:
        returncode: the exit code, or ``None`` if the process had to be killed.
        stdout / stderr: captured output, each cut at the runner's ``max_output``.
        timed_out: the process outlived its timeout and was killed.
        cancelled: the process was killed because the cancel event was set.
        truncated: output beyond ``max_output`` was discarded.
    """

    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False


class CommandRunner(Protocol):
    """Runs one external command. The seam that keeps real processes out of tests."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> CommandResult:
        """Run ``argv`` (a program path and its arguments) to completion.

        Never raises for a non-zero exit, a timeout or a cancellation: those are
        reported in the result.

        Raises:
            EngineError: if the program cannot be started.
        """
        ...


class _Capture:
    """Drains one pipe on a thread, keeping at most ``limit`` bytes.

    Reading continues past the limit and the excess is thrown away, so a tool that
    prints without end can neither fill memory nor stall on a full pipe.
    """

    def __init__(self, stream: IO[bytes] | None, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._lock = threading.Lock()
        self._chunks: list[bytes] = []
        self._size = 0
        self.truncated = False
        self._thread = threading.Thread(target=self._drain, name="portlock-av-pipe", daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        if self._stream is None:
            return
        # read1 returns as soon as the pipe has anything, so output is collected as it
        # is produced. A pipe closed under us (the process was killed) ends the loop.
        read = getattr(self._stream, "read1", self._stream.read)
        with contextlib.suppress(OSError, ValueError):
            while True:
                chunk = read(65536)
                if not chunk:
                    break
                with self._lock:
                    room = self._limit - self._size
                    if room > 0:
                        self._chunks.append(chunk[:room])
                        self._size += min(len(chunk), room)
                    if len(chunk) > room:
                        self.truncated = True

    def finish(self, wait: float) -> bytes:
        self._thread.join(wait)
        with self._lock:
            return b"".join(self._chunks)


class SubprocessRunner:
    """The real :class:`CommandRunner`.

    The program must be given by absolute path, so a look-alike earlier on ``PATH`` can
    never be started. Standard input is closed, no shell is involved, and no console
    window is opened on Windows. Timeouts are measured in real time: a child process
    does not run on an injected clock.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> CommandResult:
        """Run ``argv`` and capture its output. See :meth:`CommandRunner.run`.

        Raises:
            ValueError: if ``argv`` is empty, holds anything but strings, does not start
                with an absolute path, or the timeout or output limit is not positive.
            EngineError: if the program cannot be started.
        """
        arguments = list(argv)
        if not arguments or not all(isinstance(item, str) for item in arguments):
            raise ValueError("argv must be a non-empty list of strings")
        if not os.path.isabs(arguments[0]):
            raise ValueError("refusing to run a program that is not given by absolute path")
        if not timeout > 0 or max_output <= 0:
            raise ValueError("timeout and max_output must be positive")
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, ValueError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
            raise EngineError(f"cannot start {os.path.basename(arguments[0])}: {reason}") from exc
        out = _Capture(process.stdout, max_output)
        err = _Capture(process.stderr, max_output)
        deadline = time.monotonic() + timeout
        timed_out = cancelled = False
        try:
            while True:
                try:
                    process.wait(_POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if cancel is not None and cancel.is_set():
                    cancelled = True
                elif time.monotonic() >= deadline:
                    timed_out = True
                else:
                    continue
                # Only ever the process started above.
                process.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(_KILL_WAIT_SECONDS)
                break
        finally:
            if process.poll() is None:
                process.kill()
            stdout = out.finish(_READER_JOIN_SECONDS)
            stderr = err.finish(_READER_JOIN_SECONDS)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
        killed = timed_out or cancelled
        return CommandResult(
            returncode=None if killed else process.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=out.truncated or err.truncated,
        )


@runtime_checkable
class Engine(Protocol):
    """An antivirus engine the scanner can ask to examine a directory tree."""

    name: str

    def available(self) -> bool:
        """True if the engine is installed and can be asked to scan."""
        ...

    def version(self) -> str | None:
        """The engine's version, or ``None`` if it cannot be determined."""
        ...

    def scan_path(
        self,
        root: str | os.PathLike[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
    ) -> list[Finding]:
        """Scan everything under ``root`` and return the detections.

        An empty list means the engine examined the tree and found nothing.

        Raises:
            EngineUnavailableError: if the engine cannot be used here.
            EngineTimeoutError: if it did not finish within ``timeout`` seconds.
            EngineCancelledError: if ``cancel`` was set.
            EngineError: for any other failure. ``findings`` on the exception holds
                whatever detections were read before it.
        """
        ...


# -- locating tools ------------------------------------------------------------------


def is_trusted_program(path: Path) -> bool:
    """True if ``path`` is a program that only the system administrator could have put there.

    On POSIX the file and the directory holding it must be owned by root and writable by
    nobody else (links are resolved first, so a distribution's alternatives links work).
    On Windows the check is only that the path is an existing file: the directories
    searched there are writable by administrators alone under the default ACLs, and
    PortLock does not inspect ACLs.
    """
    try:
        resolved = path.resolve(strict=True)
        status = resolved.stat()
        if not stat.S_ISREG(status.st_mode):
            return False
        if _IS_WINDOWS:
            return True
        parent = resolved.parent.stat()
    except (OSError, RuntimeError):
        return False
    writable_by_others = stat.S_IWGRP | stat.S_IWOTH
    return (
        status.st_uid == 0
        and parent.st_uid == 0
        and not status.st_mode & writable_by_others
        and not parent.st_mode & writable_by_others
    )


def find_tool(
    names: Sequence[str],
    directories: Iterable[str | os.PathLike[str]],
    *,
    trusted: bool = True,
) -> Path | None:
    """Find the first of ``names`` in the first of ``directories`` that holds it.

    ``PATH`` is never consulted.

    Args:
        names: file names to look for, in order of preference.
        directories: absolute directories to look in, in order of preference. Relative
            ones are skipped.
        trusted: require :func:`is_trusted_program` to accept the file. Only tests,
            which search a temporary directory, turn this off.

    Returns:
        The absolute path of the program, or ``None``.
    """
    for directory in directories:
        base = Path(directory)
        if not base.is_absolute():
            continue
        for name in names:
            candidate = base / name
            try:
                present = candidate.is_file()
            except OSError:
                present = False
            if present and (not trusted or is_trusted_program(candidate)):
                return candidate
    return None


_PROGRAM_FILES = "C:\\Program Files"


def _windows_directory(variable: str, default: str) -> str:
    """A well-known Windows directory from the environment, or its standard location."""
    value = os.environ.get(variable, "")
    return value if value and os.path.isabs(value) else default


def _clamav_directories() -> tuple[str, ...]:
    if _IS_WINDOWS:
        roots = (
            _windows_directory("ProgramW6432", _PROGRAM_FILES),
            _windows_directory("ProgramFiles", _PROGRAM_FILES),
        )
        return tuple(dict.fromkeys(os.path.join(root, "ClamAV") for root in roots))
    return ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/clamav/bin")


# -- parsing helpers -----------------------------------------------------------------

_DRIVE = re.compile(r"[A-Za-z]:")
_EXTENDED_PREFIXES = ("//?/UNC/", "//?/", "//./")


def relative_to_root(path: str, root: str) -> str:
    """Express a path printed by a tool relative to the scan root, ``/``-separated.

    Works on the text alone, so Windows output can be interpreted on any platform. A
    path that is not under the root is returned as printed (with ``/`` separators for a
    Windows path), never dropped: the finding it belongs to still stands.
    """
    windows = "\\" in root or bool(_DRIVE.match(root))

    def normalise(text: str) -> str:
        if not windows:
            return text
        text = text.replace("\\", "/")
        for prefix in _EXTENDED_PREFIXES:
            if text.upper().startswith(prefix.upper()):
                return ("//" if prefix.endswith("UNC/") else "") + text[len(prefix) :]
        return text

    candidate = normalise(path)
    base = normalise(root).rstrip("/")
    left, right = (candidate.casefold(), base.casefold()) if windows else (candidate, base)
    if left == right or left == right + "/":
        return ""
    if left.startswith(right + "/"):
        return candidate[len(base) + 1 :]
    return candidate


def _decode_output(data: bytes) -> str:
    """Decode tool output without ever failing.

    UTF-16 is recognised by its byte-order mark or its pattern of zero bytes. Anything
    else is read as UTF-8, with undecodable bytes carried through so that a path in
    another encoding is still shown (escaped) rather than lost.
    """
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace")
    sample = data[1:512:2]
    if len(sample) >= 4 and sample.count(0) * 5 >= len(sample) * 4:
        return data.decode("utf-16-le", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", "surrogateescape")


def _clip(text: str) -> str:
    return safe_text(text, _MESSAGE_CLIP)


def _absolute_root(root: str | os.PathLike[str]) -> str:
    """The scan root as an absolute path, the form the tools echo back in their output."""
    text = os.fsdecode(root)
    if text.startswith(("/", "\\\\")) or _DRIVE.match(text):
        # Already absolute in POSIX or Windows terms; keep the caller's spelling.
        return text
    return os.path.abspath(text)


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    return list(dict.fromkeys(findings))


def _check_stopped(result: CommandResult, tool: str, timeout: float) -> None:
    if result.cancelled:
        raise EngineCancelledError(f"{tool} was stopped because the scan was cancelled")
    if result.timed_out:
        raise EngineTimeoutError(f"{tool} did not finish within {timeout:.0f} s and was stopped")


# -- ClamAV --------------------------------------------------------------------------

_CLAM_FOUND = re.compile(r"(?P<path>.+): (?P<name>\S+) FOUND\Z")
_CLAM_FILE_ERROR = re.compile(r"(?P<path>.+): (?P<message>.+) ERROR\Z")
_CLAM_ERROR_PREFIXES = ("ERROR:", "LibClamAV Error:")
# The one kind of warning that means a file went unscanned.
_CLAM_UNREAD_WARNING = "WARNING: Can't "
# Detection names that are ClamAV's own heuristics or "potentially unwanted" class,
# not a signature for a known piece of malware.
_CLAM_SOFT_PREFIXES = ("PUA.", "Heuristics.")
_MAX_ERROR_LINES = 20


def parse_clam_output(text: str, root: str) -> tuple[list[Finding], list[str]]:
    """Read the output of ``clamscan`` or ``clamdscan`` run with ``--no-summary``.

    Detections are lines of the form ``<path>: <signature> FOUND``. The path is whatever
    precedes the last ``": "`` before the signature, so colons and spaces inside a path
    are handled. Errors are ``<path>: <message> ERROR`` lines and lines starting with
    ``ERROR:`` or ``LibClamAV Error:``, plus ``WARNING: Can't ...`` lines, which are how
    an unreadable file is announced. Other warnings (an old database, say) are ignored.

    Args:
        text: standard output and standard error, decoded.
        root: the directory that was scanned, for making paths relative.

    Returns:
        The detections and the error messages (at most twenty are kept).
    """
    findings: list[Finding] = []
    errors: list[str] = []
    error_count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        found = _CLAM_FOUND.match(line)
        if found is not None:
            name = found.group("name")
            soft = name.startswith(_CLAM_SOFT_PREFIXES)
            findings.append(
                Finding(
                    path=relative_to_root(found.group("path"), root),
                    engine=ClamAvEngine.name,
                    rule=name,
                    severity=FindingSeverity.SUSPICIOUS if soft else FindingSeverity.MALICIOUS,
                    detail=f"ClamAV reports {name}",
                )
            )
            continue
        failed = _CLAM_FILE_ERROR.match(line)
        if failed is not None:
            where = relative_to_root(failed.group("path"), root) or "."
            message = f"{where}: {failed.group('message')}"
        elif line.startswith(_CLAM_ERROR_PREFIXES) or line.startswith(_CLAM_UNREAD_WARNING):
            message = line
        else:
            continue
        error_count += 1
        if len(errors) < _MAX_ERROR_LINES:
            errors.append(_clip(message))
    if error_count > len(errors):
        errors.append(f"and {error_count - len(errors)} more error(s)")
    return _deduplicate(findings), errors


class ClamAvEngine:
    """ClamAV, through ``clamdscan`` when a daemon answers and ``clamscan`` otherwise.

    The daemon keeps the signature database in memory, so asking it is far faster than
    loading the database afresh in ``clamscan``. If the daemon does not answer, or its
    scan fails (it often runs as a user that cannot read a freshly mounted volume),
    ``clamscan`` is run instead with whatever time is left.

    Args:
        runner: runs the commands; a real subprocess runner if omitted.
        directories: where to look for the tools instead of the system defaults.
        trusted: require root-owned, non-writable tools on POSIX. Tests searching a
            temporary directory turn this off.
        clock: used to share one timeout between the commands of a scan.
    """

    name = "clamav"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        directories: Sequence[str | os.PathLike[str]] | None = None,
        trusted: bool = True,
        clock: Clock | None = None,
    ) -> None:
        self._runner: CommandRunner = runner if runner is not None else SubprocessRunner()
        self._directories = tuple(directories) if directories is not None else None
        self._trusted = trusted
        self._clock: Clock = clock if clock is not None else SystemClock()

    def _find(self, tool: str) -> str | None:
        names = (f"{tool}.exe", tool) if _IS_WINDOWS else (tool,)
        directories = self._directories if self._directories is not None else _clamav_directories()
        found = find_tool(names, directories, trusted=self._trusted)
        return str(found) if found is not None else None

    def available(self) -> bool:
        """True if ``clamscan`` or ``clamdscan`` is installed in a system directory."""
        return self._find("clamscan") is not None or self._find("clamdscan") is not None

    def version(self) -> str | None:
        """The ``ClamAV <version>/<database>/<date>`` line the tool prints, or ``None``."""
        tool = self._find("clamscan") or self._find("clamdscan")
        if tool is None:
            return None
        try:
            result = self._runner.run([tool, "--version"], timeout=_PROBE_TIMEOUT)
        except EngineError:
            return None
        if result.returncode != 0:
            return None
        lines = _decode_output(result.stdout).strip().splitlines()
        first = lines[0].strip() if lines else ""
        return safe_text(first, 120) if first.startswith("ClamAV") else None

    def _daemon_answers(
        self, clamdscan: str, timeout: float, cancel: threading.Event | None
    ) -> bool:
        try:
            result = self._runner.run([clamdscan, "--ping", "1"], timeout=timeout, cancel=cancel)
        except EngineError:
            return False
        # Releases before 0.103 do not know --ping and exit with 2, which sends the scan
        # to clamscan: slower, but correct.
        return result.returncode == 0 and not result.timed_out and not result.cancelled

    def _run(
        self, tool: str, root: str, timeout: float, cancel: threading.Event | None
    ) -> tuple[list[Finding], list[str]]:
        """Run one of the two tools; returns its detections and its error messages."""
        # The tool's name as its documentation spells it, on every platform: messages
        # say "clamscan", not "clamscan.exe".
        label = Path(tool).stem
        # clamdscan accepts clamscan's options and ignores those the daemon decides
        # itself, -r among them (the daemon always recurses).
        result = self._runner.run(
            [tool, "--no-summary", "--infected", "-r", root], timeout=timeout, cancel=cancel
        )
        _check_stopped(result, label, timeout)
        output = _decode_output(result.stdout) + "\n" + _decode_output(result.stderr)
        findings, errors = parse_clam_output(output, root)
        if result.truncated:
            errors.append(f"{label} printed more than could be captured")
        code = result.returncode
        if code == 1 and not findings:
            errors.append(f"{label} reported a detection that could not be read from its output")
        elif code == 2 and not errors:
            errors.append(f"{label} reported an error (exit code 2)")
        elif code not in (0, 1, 2):
            errors.append(f"{label} ended with unexpected exit code {code}")
        return findings, errors

    def scan_path(
        self,
        root: str | os.PathLike[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
    ) -> list[Finding]:
        """Scan ``root`` recursively with ClamAV. See :meth:`Engine.scan_path`.

        Exit code 0 is a clean result, 1 a detection, 2 an error. A detection is
        reported even when the run also had errors; the errors are then raised with the
        detections attached, so neither is lost.
        """
        target = _absolute_root(root)
        clamdscan, clamscan = self._find("clamdscan"), self._find("clamscan")
        if clamdscan is None and clamscan is None:
            raise EngineUnavailableError("ClamAV is not installed (no clamscan or clamdscan)")
        started = self._clock.monotonic()

        def remaining() -> float:
            left = timeout - (self._clock.monotonic() - started)
            if left <= 0:
                raise EngineTimeoutError(f"ClamAV did not finish within {timeout:.0f} s")
            return left

        findings: list[Finding] = []
        errors: list[str] = []
        daemon_used = False
        if clamdscan is not None and self._daemon_answers(
            clamdscan, min(remaining(), _PROBE_TIMEOUT), cancel
        ):
            daemon_used = True
            findings, errors = self._run(clamdscan, target, remaining(), cancel)
            if not errors:
                return findings
        if clamscan is not None:
            try:
                more, errors = self._run(clamscan, target, remaining(), cancel)
            except EngineError as exc:
                # Keep what the daemon already found when the fallback is cut short.
                exc.findings = tuple(_deduplicate([*findings, *exc.findings]))
                raise
            findings = _deduplicate([*findings, *more])
            if not errors:
                return findings
        elif not daemon_used:
            raise EngineUnavailableError(
                "the ClamAV daemon does not answer and clamscan is not installed"
            )
        raise EngineError("ClamAV: " + "; ".join(errors), findings=findings)


# -- Microsoft Defender --------------------------------------------------------------

_DEFENDER_VERSION_DIR = re.compile(r"\d+(?:\.\d+)+(?:-\d+)?\Z")
_DEFENDER_FAILED = re.compile(r"Failed with hr\s*=\s*0x([0-9A-Fa-f]{1,8})")
_DEFENDER_NO_THREATS = re.compile(r"found no threats", re.IGNORECASE)
_DEFENDER_THREAT_COUNT = re.compile(r"found (\d+) threats?", re.IGNORECASE)
_DEFENDER_THREAT = re.compile(r"\s*Threat\s*:\s*(?P<name>\S.*)\Z")
_DEFENDER_RESOURCE = re.compile(r"\s+(?P<kind>[A-Za-z]+)\s*:\s(?P<value>\S.*)\Z")
_DEFENDER_RULE_LINE = re.compile(r"-{20,}")
# HRESULTs that mean "Defender cannot scan on this machine", as opposed to "this scan
# went wrong".
_DEFENDER_UNAVAILABLE = {
    0x800106BA: "the Microsoft Defender service is not running "
    "(another antivirus product may have taken its place)",
    0x800704EC: "Microsoft Defender is turned off by policy",
}
_DEFENDER_KNOWN_FAILURES = {
    0x80070005: "access denied",
    0x80070002: "the path to scan was not found",
}
_DEFENDER_SOFT_PREFIXES = ("PUA:", "PUAAdvertising:", "PUADlManager:")


def parse_defender_output(text: str, root: str) -> tuple[list[Finding], bool]:
    """Read the console output of ``MpCmdRun.exe -Scan ... -DisableRemediation``.

    A clean scan prints ``Scanning <path> found no threats.`` A scan with detections
    prints ``found N threats.`` followed by one block per threat::

        Threat                  : <name>
        Resources               : 1 total
            file                : <path>

    One finding is produced for each resource of each threat (the part of a resource
    before ``->`` is the file; what follows names a member of an archive). A threat
    with no file resource yields a finding against the scan root.

    Args:
        text: standard output and standard error, decoded.
        root: the directory that was scanned, for making paths relative.

    Returns:
        The detections, and whether the tool said in so many words that it found none.

    Raises:
        EngineUnavailableError: if the output says the Defender service is not running
            or that Defender is disabled by policy.
        EngineError: if the output reports any other failure, or announces threats that
            cannot be read from it.
    """
    failed = _DEFENDER_FAILED.search(text)
    if failed is not None:
        code = int(failed.group(1), 16)
        if code in _DEFENDER_UNAVAILABLE:
            raise EngineUnavailableError(f"{_DEFENDER_UNAVAILABLE[code]} (hr = 0x{code:08X})")
        reason = _DEFENDER_KNOWN_FAILURES.get(code, "the scan failed")
        raise EngineError(f"Microsoft Defender: {reason} (hr = 0x{code:08X})")

    findings: list[Finding] = []
    threat: str | None = None
    resources = 0

    def close_threat() -> None:
        if threat is not None and resources == 0:
            findings.append(_defender_finding(threat, "", ""))

    for raw in text.splitlines():
        line = raw.rstrip()
        started = _DEFENDER_THREAT.match(line)
        if started is not None:
            close_threat()
            threat, resources = started.group("name").strip(), 0
            continue
        if threat is None:
            continue
        if _DEFENDER_RULE_LINE.search(line):
            # The dashed line that ends a threat block.
            close_threat()
            threat = None
            continue
        resource = _DEFENDER_RESOURCE.match(line)
        if resource is None or resource.group("kind").lower() == "resources":
            continue
        value = resource.group("value").strip()
        file_part, _, member = value.partition("->")
        findings.append(_defender_finding(threat, relative_to_root(file_part, root), member))
        resources += 1
    close_threat()

    announced = _DEFENDER_THREAT_COUNT.search(text)
    if announced is not None and int(announced.group(1)) > 0 and not findings:
        raise EngineError(
            f"Microsoft Defender reported {announced.group(1)} threat(s) "
            "but the list could not be read from its output"
        )
    return _deduplicate(findings), bool(_DEFENDER_NO_THREATS.search(text))


def _defender_finding(threat: str, path: str, member: str) -> Finding:
    soft = threat.startswith(_DEFENDER_SOFT_PREFIXES)
    detail = f"Microsoft Defender reports {threat}"
    if member:
        detail += f" in archive member {member}"
    return Finding(
        path=path,
        engine=DefenderEngine.name,
        rule=threat,
        severity=FindingSeverity.SUSPICIOUS if soft else FindingSeverity.MALICIOUS,
        detail=detail,
    )


def _version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


class DefenderEngine:
    """Microsoft Defender Antivirus, through its command-line tool ``MpCmdRun.exe``.

    The tool is taken from the newest versioned directory under
    ``%ProgramData%\\Microsoft\\Windows Defender\\Platform`` (where platform updates
    install it), falling back to ``%ProgramFiles%\\Windows Defender``. It is run as::

        MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation

    a custom scan of one path that reports detections and removes nothing.

    Args:
        runner: runs the command; a real subprocess runner if omitted.
        executable: use this ``MpCmdRun.exe`` instead of searching. Tests pass one.
        program_data / program_files: search under these instead of the system's
            directories. Tests pass temporary ones.
    """

    name = "defender"

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        executable: str | os.PathLike[str] | None = None,
        program_data: str | os.PathLike[str] | None = None,
        program_files: str | os.PathLike[str] | None = None,
    ) -> None:
        self._runner: CommandRunner = runner if runner is not None else SubprocessRunner()
        self._executable = Path(executable) if executable is not None else None
        self._program_data = Path(program_data) if program_data is not None else None
        self._program_files = Path(program_files) if program_files is not None else None

    def locate(self) -> Path | None:
        """The ``MpCmdRun.exe`` that would be run, or ``None`` if there is none.

        Without explicit directories the search only happens on Windows.
        """
        if self._executable is not None:
            usable = self._executable.is_absolute() and self._executable.is_file()
            return self._executable if usable else None
        if self._program_data is None and self._program_files is None and not _IS_WINDOWS:
            return None
        program_data = self._program_data or Path(
            _windows_directory("ProgramData", "C:\\ProgramData")
        )
        program_files = self._program_files or Path(
            _windows_directory("ProgramW6432", _windows_directory("ProgramFiles", _PROGRAM_FILES))
        )
        platform = program_data / "Microsoft" / "Windows Defender" / "Platform"
        try:
            versions = sorted(
                (
                    item.name
                    for item in os.scandir(platform)
                    if _DEFENDER_VERSION_DIR.match(item.name) and item.is_dir()
                ),
                key=_version_key,
                reverse=True,
            )
        except OSError:
            versions = []
        directories = [platform / version for version in versions]
        directories.append(program_files / "Windows Defender")
        return find_tool(("MpCmdRun.exe",), directories, trusted=False)

    def available(self) -> bool:
        """True if ``MpCmdRun.exe`` is present.

        That the Defender *service* is running can only be learned by scanning; a
        stopped or policy-disabled service surfaces as :class:`EngineUnavailableError`
        from :meth:`scan_path`, never as a clean result.
        """
        return self.locate() is not None

    def version(self) -> str | None:
        """The platform version, taken from the versioned directory the tool is in."""
        tool = self.locate()
        if tool is None:
            return None
        name = tool.parent.name
        return name if _DEFENDER_VERSION_DIR.match(name) else None

    def scan_path(
        self,
        root: str | os.PathLike[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
    ) -> list[Finding]:
        """Run a custom Defender scan of ``root``. See :meth:`Engine.scan_path`.

        The result is ``clean`` only if the tool exits with 0 *and* prints that it found
        no threats. Exit code 2 means either detections or a failure; the output decides
        which, and output that settles neither is an error.
        """
        tool = self.locate()
        if tool is None:
            raise EngineUnavailableError("Microsoft Defender's MpCmdRun.exe was not found")
        target = _absolute_root(root)
        result = self._runner.run(
            [str(tool), "-Scan", "-ScanType", "3", "-File", target, "-DisableRemediation"],
            timeout=timeout,
            cancel=cancel,
        )
        _check_stopped(result, "MpCmdRun.exe", timeout)
        output = _decode_output(result.stdout) + "\n" + _decode_output(result.stderr)
        findings, said_clean = parse_defender_output(output, target)
        if result.truncated:
            raise EngineError(
                "Microsoft Defender printed more than could be captured", findings=findings
            )
        if findings:
            return findings
        if result.returncode == 0 and said_clean:
            return []
        raise EngineError(
            f"Microsoft Defender gave no usable result (exit code {result.returncode})"
        )
