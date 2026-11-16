"""The scan pipeline: walk, hashing, hash lists, heuristics and engines, put together.

Volumes are directories under ``tmp_path`` holding harmless synthetic files. Antivirus
engines are stand-ins; nothing here runs ClamAV or Defender, and nothing writes the EICAR
string or any other malware sample: known-bad content is ordinary bytes whose digest a
test puts on a known-bad list.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from portlock.core.clock import FakeClock
from portlock.core.errors import ConfigError, ScanError, StoreError
from portlock.scan.av import (
    ClamAvEngine,
    DefenderEngine,
    EngineCancelledError,
    EngineError,
    EngineTimeoutError,
    EngineUnavailableError,
)
from portlock.scan.hashdb import HashEntry, HashKind, HashSet
from portlock.scan.inspector import ScanLimits
from portlock.scan.report import Finding, FindingSeverity, IssueKind, ScanReport, Verdict
from portlock.scan.scanner import (
    ENGINE_NAMES,
    HASHSET_ENGINE,
    MEMORY_ROOT,
    Scanner,
    ScanProgress,
    build_scanner,
)

#: The start of a PE file: enough for the heuristics to call it a Windows program.
PE_HEAD = b"MZ" + b"\x00" * 62
RLO = chr(0x202E)


class FakeEngine:
    """An antivirus engine stand-in that answers from a script and records its calls."""

    def __init__(
        self,
        name: str = "fakeav",
        *,
        available: bool | Exception = True,
        version: str | None = "9.9",
        findings: Any = (),
        error: Exception | None = None,
        block: threading.Event | None = None,
    ) -> None:
        self.name = name
        self._available = available
        self._version = version
        self._findings = findings
        self._error = error
        self._block = block
        self.calls: list[tuple[str, float, threading.Event | None]] = []

    def available(self) -> bool:
        if isinstance(self._available, Exception):
            raise self._available
        return self._available

    def version(self) -> str | None:
        return self._version

    def scan_path(
        self, root: str | os.PathLike[str], *, timeout: float, cancel: threading.Event | None = None
    ) -> Any:
        self.calls.append((os.fspath(root), timeout, cancel))
        if self._block is not None:
            # Ignores its timeout on purpose; the test releases it afterwards.
            self._block.wait(10)
        if self._error is not None:
            raise self._error
        return list(self._findings) if isinstance(self._findings, tuple) else self._findings


class BrokenHashSet(HashSet):
    """A hash list whose storage has failed."""

    def lookup(self, sha256: str) -> HashEntry | None:
        raise StoreError("database error: disk I/O error")


def volume(root: Path, files: dict[str, bytes]) -> Path:
    """Write ``files`` (relative ``/``-separated names) under ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def summary(report: ScanReport) -> list[tuple[str, str, str, str]]:
    return sorted(
        (finding.path, finding.engine, finding.rule, finding.severity.value)
        for finding in report.findings
    )


def known_bad(content: bytes, label: str = "Test.Bad-1") -> HashSet:
    hashset = HashSet(name="local")
    hashset.add(hashlib.sha256(content).hexdigest(), HashKind.KNOWN_BAD, label)
    return hashset


CLEAN_FILES = {
    "notes.txt": b"meeting at ten\n",
    "photos/beach.jpg": b"\xff\xd8\xff\xe0 not really a jpeg",
    "docs/report.pdf": b"%PDF-1.7 synthetic",
}


@pytest.fixture
def clean_volume(tmp_path: Path) -> Path:
    return volume(tmp_path / "vol", CLEAN_FILES)


# --- verdicts -------------------------------------------------------------------------


def test_a_clean_volume_is_clean_and_untouched(clean_volume: Path, clock: FakeClock) -> None:
    before = snapshot(clean_volume)

    report = Scanner(clock=clock).scan(clean_volume)

    assert report.verdict is Verdict.CLEAN and report.complete
    assert report.files_seen == 3 and report.files_hashed == 3
    assert report.bytes_hashed == sum(len(content) for content in CLEAN_FILES.values())
    assert report.findings == () and report.errors == ()
    assert [(engine.name, engine.available) for engine in report.engines] == [
        ("heuristics", True),
        (HASHSET_ENGINE, True),
    ]
    assert report.started_at == clock.now() and report.finished_at == clock.now()
    # Scanning only reads: every byte and every modification time is as it was.
    assert snapshot(clean_volume) == before


def test_an_executable_at_the_root_is_suspicious(tmp_path: Path, clock: FakeClock) -> None:
    root = volume(tmp_path / "vol", {"setup.exe": PE_HEAD, **CLEAN_FILES})

    report = Scanner(clock=clock).scan(root)

    assert report.verdict is Verdict.SUSPICIOUS
    assert ("setup.exe", "heuristics", "root.executable", "suspicious") in summary(report)
    finding = next(item for item in report.findings if item.rule == "root.executable")
    assert finding.sha256 == hashlib.sha256(PE_HEAD).hexdigest()


def test_a_known_bad_digest_is_malicious_wherever_the_file_is(
    tmp_path: Path, clock: FakeClock
) -> None:
    payload = b"synthetic payload, harmless bytes"
    root = volume(tmp_path / "vol", {"deep/er/still/data.bin": payload, **CLEAN_FILES})

    report = Scanner(hashsets=[known_bad(payload)], clock=clock).scan(root)

    assert report.verdict is Verdict.MALICIOUS
    (finding,) = report.findings
    assert (finding.path, finding.engine, finding.rule, finding.severity) == (
        "deep/er/still/data.bin",
        HASHSET_ENGINE,
        "Test.Bad-1",
        FindingSeverity.MALICIOUS,
    )
    assert finding.sha256 == hashlib.sha256(payload).hexdigest()
    assert finding.detail == "SHA-256 is on the known-bad list 'local'"


def test_a_known_good_digest_silences_the_heuristics_for_that_file(
    tmp_path: Path, clock: FakeClock
) -> None:
    root = volume(tmp_path / "vol", {"setup.exe": PE_HEAD})
    vouched = HashSet(name="vendor")
    vouched.add(hashlib.sha256(PE_HEAD).hexdigest(), HashKind.KNOWN_GOOD, "Example installer")

    report = Scanner(hashsets=[vouched], clock=clock).scan(root)

    assert not any(item.severity is not FindingSeverity.INFO for item in report.findings)
    assert report.verdict is Verdict.CLEAN


def test_with_hash_lists_switched_off_files_are_still_hashed_but_not_judged(
    tmp_path: Path, clock: FakeClock
) -> None:
    payload = b"would be bad"
    root = volume(tmp_path / "vol", {"data.bin": payload})

    report = Scanner(hashsets=[known_bad(payload)], clock=clock, use_hashsets=False).scan(root)

    assert report.verdict is Verdict.CLEAN and report.files_hashed == 1
    assert [engine.name for engine in report.engines] == ["heuristics"]


def test_a_broken_hash_list_is_a_failure_reported_once(tmp_path: Path, clock: FakeClock) -> None:
    root = volume(tmp_path / "vol", CLEAN_FILES)

    report = Scanner(hashsets=[BrokenHashSet(name="local")], clock=clock).scan(root)

    assert report.verdict is Verdict.ERROR
    failures = [issue for issue in report.errors if issue.source == HASHSET_ENGINE]
    assert len(failures) == 1 and failures[0].kind is IssueKind.FAILED
    assert "the hash lists could not be consulted" in failures[0].message


# --- device text ----------------------------------------------------------------------


def test_hostile_names_reach_the_report_escaped(tmp_path: Path, clock: FakeClock) -> None:
    disguised = f"photo{RLO}gpj.exe"
    root = volume(
        tmp_path / "vol",
        {
            disguised: PE_HEAD,
            "autorun.inf": f"[autorun]\r\nopen=run{RLO}me.exe\r\nlabel=FREE{RLO}STUFF\r\n".encode(),
        },
    )
    seen: list[ScanProgress] = []

    report = Scanner(clock=clock).scan(root, progress=seen.append)

    assert report.verdict is Verdict.MALICIOUS
    paths = {finding.path for finding in report.findings}
    assert "photo\\u202egpj.exe" in paths
    launch = next(item for item in report.findings if item.rule == "autorun.launch")
    assert "run\\u202eme.exe" in launch.detail
    # No raw control or format character anywhere in what leaves the scanner.
    encoded = json.dumps(report.to_dict(), ensure_ascii=False)
    assert RLO not in encoded
    assert all(item.current_path.isprintable() for item in seen)
    assert any(item.current_path == "photo\\u202egpj.exe" for item in seen)


def test_progress_text_is_escaped_at_the_type() -> None:
    progress = ScanProgress(1, 0, 0, f"a{RLO}b\x1b[2J")
    assert progress.current_path == "a\\u202eb\\x1b[2J"


# --- limits, time and cancellation ----------------------------------------------------


def test_a_file_limit_makes_the_scan_incomplete_not_clean(tmp_path: Path, clock: FakeClock) -> None:
    root = volume(tmp_path / "vol", {f"file{index}.txt": b"x" for index in range(6)})

    report = Scanner(limits=ScanLimits(max_files=2), clock=clock).scan(root)

    assert report.verdict is Verdict.INCOMPLETE and not report.complete
    assert report.truncated and report.truncated_reason is not None
    assert "max_files" in report.truncated_reason


def test_the_time_budget_is_measured_on_the_injected_clock(
    tmp_path: Path, clock: FakeClock
) -> None:
    root = volume(tmp_path / "vol", {f"file{index}.txt": b"x" for index in range(5)})

    def slow_progress(_progress: ScanProgress) -> None:
        clock.advance(40)

    report = Scanner(limits=ScanLimits(max_seconds=100), clock=clock).scan(
        root, progress=slow_progress
    )

    assert report.verdict is Verdict.INCOMPLETE
    assert report.truncated_reason is not None and "max_seconds" in report.truncated_reason
    assert report.files_seen < 5


def test_a_cancelled_scan_says_so(clean_volume: Path, clock: FakeClock) -> None:
    cancel = threading.Event()
    cancel.set()
    engine = FakeEngine(error=EngineCancelledError("stopped because the scan was cancelled"))

    report = Scanner([engine], clock=clock).scan(clean_volume, cancel=cancel)

    assert report.verdict is Verdict.INCOMPLETE
    assert report.truncated_reason is not None and "cancelled" in report.truncated_reason
    assert engine.calls and engine.calls[0][2] is cancel


def test_a_progress_callback_that_raises_is_dropped_and_the_scan_goes_on(
    clean_volume: Path, clock: FakeClock
) -> None:
    calls: list[str] = []

    def broken(progress: ScanProgress) -> None:
        calls.append(progress.current_path)
        raise RuntimeError("display went away")

    report = Scanner(clock=clock).scan(clean_volume, progress=broken)

    assert len(calls) == 1
    assert report.verdict is Verdict.CLEAN and report.files_seen == 3


def test_findings_are_bounded_but_malicious_ones_are_never_crowded_out(
    tmp_path: Path, clock: FakeClock
) -> None:
    payload = b"the one that matters"
    files = {f"tool{index}.exe": PE_HEAD + bytes([index]) for index in range(8)}
    root = volume(tmp_path / "vol", {**files, "zz/payload.bin": payload})

    report = Scanner(
        hashsets=[known_bad(payload)], limits=ScanLimits(max_findings=3), clock=clock
    ).scan(root)

    assert report.verdict is Verdict.MALICIOUS
    assert report.truncated_reason is not None and "max_findings" in report.truncated_reason
    assert any(finding.path == "zz/payload.bin" for finding in report.findings)
    suspicious = [f for f in report.findings if f.severity is FindingSeverity.SUSPICIOUS]
    assert len(suspicious) <= 3


def test_a_root_that_is_not_a_directory_is_a_failure(tmp_path: Path, clock: FakeClock) -> None:
    engine = FakeEngine()

    report = Scanner([engine], clock=clock).scan(tmp_path / "missing")

    assert report.verdict in (Verdict.ERROR, Verdict.INCOMPLETE)
    assert report.verdict is not Verdict.CLEAN and report.errors
    # The engines are not sent to scan something that is not there.
    assert engine.calls == []


# --- antivirus engines ----------------------------------------------------------------


def test_engine_findings_are_merged_and_the_engine_is_listed(
    clean_volume: Path, clock: FakeClock
) -> None:
    detection = Finding("docs/report.pdf", "fakeav", "Test.Sig-1", FindingSeverity.MALICIOUS)
    engine = FakeEngine(findings=(detection,))

    report = Scanner([engine], limits=ScanLimits(max_seconds=120), clock=clock).scan(clean_volume)

    assert report.verdict is Verdict.MALICIOUS and detection in report.findings
    assert [(e.name, e.available, e.version) for e in report.engines][-1] == ("fakeav", True, "9.9")
    ((root, timeout, cancel),) = engine.calls
    assert root == os.fspath(clean_volume) and timeout == 120 and cancel is None


@pytest.mark.parametrize(
    ("engine", "verdict", "available", "message", "truncated"),
    [
        (
            FakeEngine(error=EngineError("ClamAV: ERROR: out of memory")),
            Verdict.ERROR,
            True,
            "ClamAV: ERROR: out of memory",
            None,
        ),
        (
            FakeEngine(error=EngineUnavailableError("the service is not running")),
            Verdict.ERROR,
            False,
            "the service is not running",
            None,
        ),
        (
            FakeEngine(error=EngineTimeoutError("did not finish within 300 s")),
            Verdict.INCOMPLETE,
            True,
            "did not finish within 300 s",
            "max_seconds",
        ),
        (
            FakeEngine(error=RuntimeError("bug in the adapter")),
            Verdict.ERROR,
            True,
            "unexpected failure: RuntimeError",
            None,
        ),
        (
            FakeEngine(findings="not a list"),
            Verdict.ERROR,
            True,
            "returned something other than a list of findings",
            None,
        ),
        (
            FakeEngine(available=OSError("probe crashed")),
            Verdict.ERROR,
            False,
            "availability check failed: OSError",
            None,
        ),
    ],
)
def test_an_engine_that_fails_never_leaves_a_clean_verdict(
    clean_volume: Path,
    clock: FakeClock,
    engine: FakeEngine,
    verdict: Verdict,
    available: bool,
    message: str,
    truncated: str | None,
) -> None:
    report = Scanner([engine], clock=clock).scan(clean_volume)

    assert report.verdict is verdict
    status = report.engines[-1]
    assert (status.name, status.available) == ("fakeav", available)
    assert any(issue.source == "fakeav" and issue.message == message for issue in report.errors)
    if truncated is not None:
        assert report.truncated_reason is not None and truncated in report.truncated_reason


def test_detections_read_before_an_engine_failed_still_count(
    clean_volume: Path, clock: FakeClock
) -> None:
    found = Finding("notes.txt", "fakeav", "Test.Sig-2", FindingSeverity.MALICIOUS)
    engine = FakeEngine(error=EngineError("ClamAV: partly failed", findings=[found]))

    report = Scanner([engine], clock=clock).scan(clean_volume)

    assert report.verdict is Verdict.MALICIOUS and found in report.findings
    assert any(issue.kind is IssueKind.FAILED for issue in report.errors)


def test_an_engine_that_is_not_installed_is_listed_and_skipped(
    clean_volume: Path, clock: FakeClock
) -> None:
    engine = FakeEngine(available=False)

    report = Scanner([engine], clock=clock).scan(clean_volume)

    assert report.verdict is Verdict.CLEAN and engine.calls == []
    assert (report.engines[-1].name, report.engines[-1].available) == ("fakeav", False)


def test_an_engine_that_ignores_its_timeout_is_abandoned(
    clean_volume: Path, clock: FakeClock
) -> None:
    release = threading.Event()
    engine = FakeEngine(block=release)
    try:
        # A tiny budget and no grace: the scanner waits about 50 ms of real time for the
        # thread, then gives up on it. The engine itself is still blocked at that point.
        report = Scanner(
            [engine], limits=ScanLimits(max_seconds=0.05), clock=clock, engine_grace=0
        ).scan(clean_volume)
    finally:
        release.set()

    assert report.verdict is Verdict.ERROR
    assert any(
        issue.source == "fakeav" and issue.message == "did not stop when its time was up"
        for issue in report.errors
    )


def test_with_nothing_to_judge_the_scan_says_so(clean_volume: Path, clock: FakeClock) -> None:
    report = Scanner(clock=clock, use_heuristics=False, use_hashsets=False).scan(clean_volume)

    assert report.verdict is Verdict.ERROR and report.files_seen == 0
    (issue,) = report.errors
    assert issue.message == "no scan engine is enabled and available; nothing was examined"


def test_heuristics_switched_off_are_not_listed(tmp_path: Path, clock: FakeClock) -> None:
    root = volume(tmp_path / "vol", {"setup.exe": PE_HEAD})

    report = Scanner(clock=clock, use_heuristics=False).scan(root)

    assert report.verdict is Verdict.CLEAN
    assert [engine.name for engine in report.engines] == [HASHSET_ENGINE]


@pytest.mark.parametrize("grace", [-1, float("nan"), float("inf"), "10", True])
def test_the_engine_grace_is_validated(grace: Any) -> None:
    with pytest.raises(ConfigError):
        Scanner(engine_grace=grace)


# --- content held in memory -----------------------------------------------------------


def test_bytes_in_memory_are_judged_like_a_file(clock: FakeClock) -> None:
    payload = b"in memory only"
    scanner = Scanner([FakeEngine()], hashsets=[known_bad(payload)], clock=clock)

    report = scanner.scan_bytes("sub/dir/blob.bin", payload)

    assert report.root == MEMORY_ROOT and report.verdict is Verdict.MALICIOUS
    assert [(f.path, f.engine) for f in report.findings] == [("sub/dir/blob.bin", HASHSET_ENGINE)]
    # Antivirus engines scan paths; they take no part and are not listed.
    assert [engine.name for engine in report.engines] == ["heuristics", HASHSET_ENGINE]
    assert (report.files_seen, report.files_hashed, report.bytes_hashed) == (1, 1, len(payload))


def test_a_bare_name_in_memory_is_at_the_root(clock: FakeClock) -> None:
    at_root = Scanner(clock=clock).scan_bytes("setup.exe", PE_HEAD)
    below = Scanner(clock=clock).scan_bytes("tools/setup.exe", PE_HEAD)

    assert any(finding.rule == "root.executable" for finding in at_root.findings)
    assert not any(finding.rule == "root.executable" for finding in below.findings)


@pytest.mark.parametrize("name", ["", "/", "/etc/passwd", "a/../b", "nul\x00byte", "..", 7])
def test_in_memory_names_must_be_relative_and_plain(name: Any, clock: FakeClock) -> None:
    with pytest.raises(ScanError):
        Scanner(clock=clock).scan_bytes(name, b"data")


def test_in_memory_with_nothing_to_judge_is_an_error(clock: FakeClock) -> None:
    report = Scanner(clock=clock, use_heuristics=False, use_hashsets=False).scan_bytes(
        "a.bin", b"data"
    )
    assert report.verdict is Verdict.ERROR


# --- building from configuration ------------------------------------------------------


def test_build_scanner_maps_names_to_engines(clock: FakeClock) -> None:
    scanner = build_scanner(["heuristics", "hashset", "clamav", "defender", "clamav"], clock=clock)
    kinds: Sequence[type] = [type(engine) for engine in scanner.engines]
    assert kinds == [ClamAvEngine, DefenderEngine]
    assert ENGINE_NAMES == ("heuristics", "hashset", "clamav", "defender")

    only_heuristics = build_scanner(["heuristics"], clock=clock)
    assert only_heuristics.engines == ()
    report = only_heuristics.scan_bytes("a.txt", b"text")
    assert [engine.name for engine in report.engines] == ["heuristics"]


@pytest.mark.parametrize(
    ("names", "message"),
    [([], "at least one scan engine"), (["heuristics", "sophos"], "unknown scan engine")],
)
def test_build_scanner_refuses_bad_names(names: list[str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        build_scanner(names)


def test_the_scanner_keeps_its_configuration(clock: FakeClock) -> None:
    limits = ScanLimits(max_files=10)
    engine = FakeEngine()
    scanner = Scanner([engine], limits=limits, clock=clock)
    assert scanner.limits is limits and scanner.engines == (engine,)
