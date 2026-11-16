"""Antivirus adapters, driven through a fake command runner and recorded tool output.

Nothing here runs ClamAV, and only one opt-in ``hardware`` test runs Microsoft Defender.
The fixtures under ``tests/fixtures/av`` are written by hand in the tools' output
formats, with made-up paths and detection names.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from portlock.core.clock import FakeClock
from portlock.core.errors import ScanError
from portlock.scan import av
from portlock.scan.av import (
    DEFAULT_MAX_OUTPUT,
    ClamAvEngine,
    CommandResult,
    DefenderEngine,
    Engine,
    EngineCancelledError,
    EngineError,
    EngineTimeoutError,
    EngineUnavailableError,
    SubprocessRunner,
    find_tool,
    is_trusted_program,
    parse_clam_output,
    parse_defender_output,
    relative_to_root,
)
from portlock.scan.report import Finding, FindingSeverity

IS_WINDOWS = sys.platform == "win32"
CLAM_ROOT = "/media/test/EXAMPLE DRIVE"
DEFENDER_ROOT = "F:\\usb volume"
I_ACUTE = "\N{LATIN SMALL LETTER I WITH ACUTE}"
N_TILDE = "\N{LATIN SMALL LETTER N WITH TILDE}"
O_ACUTE = "\N{LATIN SMALL LETTER O WITH ACUTE}"

Responder = Callable[[list[str]], CommandResult]


class FakeRunner:
    """A :class:`CommandRunner` that records what it was asked to run and answers from a script."""

    def __init__(self, respond: Responder) -> None:
        self._respond = respond
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []
        self.cancels: list[threading.Event | None] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout: float,
        cancel: threading.Event | None = None,
        max_output: int = DEFAULT_MAX_OUTPUT,
    ) -> CommandResult:
        assert all(isinstance(item, str) for item in argv), "argv must be a list of strings"
        assert os.path.isabs(argv[0]), "the program must be given by absolute path"
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        self.cancels.append(cancel)
        return self._respond(list(argv))

    @property
    def programs(self) -> list[str]:
        """The base name of each program run, without a Windows ``.exe``."""
        return [Path(call[0]).name.removesuffix(".exe") for call in self.calls]


def fixture_bytes(fixtures_dir: Path, name: str) -> bytes:
    return (fixtures_dir / "av" / name).read_bytes()


def install(directory: Path, *tools: str) -> Path:
    """Create empty stand-ins for the named tools, as this platform would name them."""
    directory.mkdir(parents=True, exist_ok=True)
    for tool in tools:
        (directory / (f"{tool}.exe" if IS_WINDOWS else tool)).write_bytes(b"")
    return directory


def clam(runner: FakeRunner, directory: Path, **kwargs: object) -> ClamAvEngine:
    # An injected clock unless a test brings its own: with the real one, the time left for
    # the second command of a scan depends on how fast this machine ran the first, and
    # the timeouts passed to the runner could not be compared exactly.
    kwargs.setdefault("clock", FakeClock())
    return ClamAvEngine(runner, directories=[directory], trusted=False, **kwargs)  # type: ignore[arg-type]


def summary(findings: list[Finding] | tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    return [(finding.path, finding.rule, finding.severity.value) for finding in findings]


def by_tool(**answers: CommandResult | Responder) -> Responder:
    """A responder keyed by tool name; ``ping`` answers ``clamdscan --ping``."""

    def respond(argv: list[str]) -> CommandResult:
        tool = Path(argv[0]).name.removesuffix(".exe")
        key = "ping" if "--ping" in argv else "version" if "--version" in argv else tool
        answer = answers[key]
        return answer(argv) if callable(answer) else answer

    return respond


OK = CommandResult(0)
DAEMON_DOWN = CommandResult(2, stderr=b"ERROR: Could not connect to clamd on LocalSocket\n")


# -- paths printed by the tools -----------------------------------------------------


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("/media/usb/a/b.txt", "/media/usb", "a/b.txt"),
        ("/media/usb", "/media/usb/", ""),
        ("/media/usb/", "/media/usb", ""),
        ("/media/usbx/a", "/media/usb", "/media/usbx/a"),
        ("/other/x", "/media/usb", "/other/x"),
        ("/a", "/", "a"),
        ("/media/usb/back\\slash", "/media/usb", "back\\slash"),
        ("/media/USB/a", "/media/usb", "/media/USB/a"),
        ("F:\\usb volume\\Dir\\x.exe", "F:\\usb volume", "Dir/x.exe"),
        ("f:\\USB VOLUME\\x.exe", "F:\\usb volume\\", "x.exe"),
        ("E:\\x.exe", "E:\\", "x.exe"),
        ("E:/x.exe", "E:", "x.exe"),
        ("\\\\?\\E:\\dir\\x.exe", "E:\\", "dir/x.exe"),
        ("G:\\other\\x.exe", "F:\\usb volume", "G:/other/x.exe"),
        ("\\\\server\\share\\dir\\x", "\\\\server\\share", "dir/x"),
        ("\\\\?\\UNC\\server\\share\\dir\\x", "\\\\server\\share", "dir/x"),
    ],
)
def test_tool_paths_are_made_relative_to_the_scan_root(path: str, root: str, expected: str) -> None:
    assert relative_to_root(path, root) == expected


# -- ClamAV output ------------------------------------------------------------------


def test_clam_detections_are_parsed_with_awkward_paths(fixtures_dir: Path) -> None:
    text = fixture_bytes(fixtures_dir, "clam_found.txt").decode("utf-8")

    findings, errors = parse_clam_output(text, CLAM_ROOT)

    assert errors == []
    assert summary(findings) == [
        ("setup.exe", "Win.Test.EICAR_HDB-1", "malicious"),
        ("My Files/report 2026: final.pdf.exe", "Win.Trojan.Agent-1234567", "malicious"),
        (f"Fotos/d{I_ACUTE}a de playa/se{N_TILDE}al.scr", "Win.Worm.Example-99", "malicious"),
        ("tools/packed.bin", "PUA.Win.Packer.Example-7", "suspicious"),
        ("archive/locked.zip", "Heuristics.Encrypted.Zip", "suspicious"),
    ]
    assert all(finding.engine == "clamav" and finding.sha256 is None for finding in findings)
    assert findings[0].detail == "ClamAV reports Win.Test.EICAR_HDB-1"


def test_clam_errors_are_separated_from_detections_and_warnings(fixtures_dir: Path) -> None:
    text = fixture_bytes(fixtures_dir, "clam_errors.txt").decode("utf-8")

    findings, errors = parse_clam_output(text, CLAM_ROOT)

    assert summary(findings) == [("payload.dll", "Win.Trojan.Example-42", "malicious")]
    assert errors == [
        "private/notes.txt: Access denied.",
        "gone.tmp: lstat() failed: No such file or directory.",
        "WARNING: Can't open file /media/test/EXAMPLE DRIVE/locked.db: Permission denied",
        "ERROR: Can't open /var/lib/clamav/daily.cld",
    ]


def test_clam_output_with_windows_line_endings_and_blank_lines() -> None:
    text = (
        "\r\n\r\nE:\\Mis documentos\\a b.exe: Win.Test-1 FOUND\r\n"
        "   \r\nE:\\: Access denied. ERROR\r\n"
    )

    findings, errors = parse_clam_output(text, "E:\\")

    assert summary(findings) == [("Mis documentos/a b.exe", "Win.Test-1", "malicious")]
    assert errors == [".: Access denied."]


def test_clam_error_lines_are_bounded() -> None:
    text = "".join(f"/r/f{index}: Access denied. ERROR\n" for index in range(500))
    text += "/r/x.exe: Win.Test-1 FOUND\n" * 3

    findings, errors = parse_clam_output(text, "/r")

    assert len(errors) == 21 and errors[-1] == "and 480 more error(s)"
    assert summary(findings) == [("x.exe", "Win.Test-1", "malicious")]


def test_a_file_name_cannot_talk_its_way_out_of_a_detection() -> None:
    """A newline in a name splits the line; the detection still ends in FOUND."""
    text = "/r/innocent.txt\n/r/still infected.exe: Win.Test-1 FOUND\nOK\n/r/x: y OK\n"

    findings, errors = parse_clam_output(text, "/r")

    assert summary(findings) == [("still infected.exe", "Win.Test-1", "malicious")]
    assert errors == []


def test_a_hostile_file_name_in_tool_output_is_escaped_in_the_finding() -> None:
    rlo, escape = chr(0x202E), chr(0x1B)
    text = f"/r/photo{rlo}gpj.exe: Win.Test-1 FOUND\n/r/{escape}[2Jx: Access denied. ERROR\n"

    findings, errors = parse_clam_output(text, "/r")

    assert summary(findings) == [("photo\\u202egpj.exe", "Win.Test-1", "malicious")]
    assert errors == ["\\x1b[2Jx: Access denied."]
    assert all(finding.path.isprintable() for finding in findings)


# -- the ClamAV engine --------------------------------------------------------------


def test_the_daemon_is_preferred_when_it_answers(tmp_path: Path, fixtures_dir: Path) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    found = CommandResult(1, stdout=fixture_bytes(fixtures_dir, "clam_found.txt"))
    runner = FakeRunner(by_tool(ping=OK, clamdscan=found))
    engine = clam(runner, tools)

    findings = engine.scan_path(CLAM_ROOT, timeout=120)

    assert len(findings) == 5 and findings[0].path == "setup.exe"
    assert runner.programs == ["clamdscan", "clamdscan"]
    assert runner.calls[0][1:] == ["--ping", "1"]
    assert runner.calls[1][1:] == ["--no-summary", "--infected", "-r", CLAM_ROOT]
    assert runner.timeouts == [10.0, 120.0]
    assert isinstance(engine, Engine) and engine.name == "clamav" and engine.available()


def test_a_clean_tree_is_an_empty_result(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    runner = FakeRunner(by_tool(ping=OK, clamdscan=OK))

    assert clam(runner, tools).scan_path(CLAM_ROOT, timeout=60) == []
    assert runner.programs == ["clamdscan", "clamdscan"]


def test_clamscan_is_used_when_the_daemon_does_not_answer(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    found = CommandResult(1, stdout=fixture_bytes(fixtures_dir, "clam_found.txt"))
    runner = FakeRunner(by_tool(ping=DAEMON_DOWN, clamscan=found))

    findings = clam(runner, tools).scan_path(CLAM_ROOT, timeout=60)

    assert len(findings) == 5
    assert runner.programs == ["clamdscan", "clamscan"]
    assert runner.calls[1][1:] == ["--no-summary", "--infected", "-r", CLAM_ROOT]


def test_clamscan_alone_is_enough(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    runner = FakeRunner(by_tool(clamscan=OK))

    assert clam(runner, tools).scan_path(CLAM_ROOT, timeout=60) == []
    assert runner.programs == ["clamscan"]


def test_a_daemon_that_cannot_read_the_volume_falls_back_to_clamscan(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    denied = CommandResult(2, stdout=fixture_bytes(fixtures_dir, "clam_errors.txt"))
    later = CommandResult(1, stdout=b"/media/test/EXAMPLE DRIVE/other.exe: Win.Test-2 FOUND\n")
    runner = FakeRunner(by_tool(ping=OK, clamdscan=denied, clamscan=later))

    findings = clam(runner, tools).scan_path(CLAM_ROOT, timeout=60)

    assert runner.programs == ["clamdscan", "clamdscan", "clamscan"]
    assert summary(findings) == [
        ("payload.dll", "Win.Trojan.Example-42", "malicious"),
        ("other.exe", "Win.Test-2", "malicious"),
    ]


def test_errors_from_both_tools_are_an_engine_error_that_keeps_the_detections(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    denied = CommandResult(2, stdout=fixture_bytes(fixtures_dir, "clam_errors.txt"))
    runner = FakeRunner(by_tool(ping=OK, clamdscan=denied, clamscan=denied))

    with pytest.raises(EngineError) as caught:
        clam(runner, tools).scan_path(CLAM_ROOT, timeout=60)

    assert type(caught.value) is EngineError and caught.value.code == "engine_error"
    assert isinstance(caught.value, ScanError)
    assert summary(caught.value.findings) == [("payload.dll", "Win.Trojan.Example-42", "malicious")]
    assert caught.value.message.startswith("ClamAV: private/notes.txt: Access denied.; ")
    assert "ERROR: Can't open /var/lib/clamav/daily.cld" in caught.value.message


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            CommandResult(1, stdout=b"something was found, apparently\n"),
            "clamscan reported a detection that could not be read from its output",
        ),
        (CommandResult(2), "clamscan reported an error (exit code 2)"),
        (CommandResult(50, stderr=b"some database problem\n"), "unexpected exit code 50"),
        (CommandResult(-9), "unexpected exit code -9"),
        (CommandResult(None), "unexpected exit code None"),
        (
            # The tool echoes the scanned root back; the error is reported relative to it.
            CommandResult(0, stdout=b"/r/a: Access denied. ERROR\n"),
            "ClamAV: a: Access denied.",
        ),
        (CommandResult(0, truncated=True), "clamscan printed more than could be captured"),
        (
            CommandResult(1, stdout=b"/r/a.exe: Win.Test-1 FOUND\nERROR: out of memory\n"),
            "ClamAV: ERROR: out of memory",
        ),
    ],
)
def test_anything_short_of_a_clear_answer_is_an_error_never_clean(
    tmp_path: Path, result: CommandResult, message: str
) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    engine = clam(FakeRunner(by_tool(clamscan=result)), tools)

    with pytest.raises(EngineError) as caught:
        engine.scan_path("/r", timeout=60)

    assert message in caught.value.message
    if b"FOUND" in result.stdout:
        assert summary(caught.value.findings) == [("a.exe", "Win.Test-1", "malicious")]


def test_exit_code_zero_with_a_detection_line_still_reports_it(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    odd = CommandResult(0, stdout=b"/r/a.exe: Win.Test-1 FOUND\n")

    findings = clam(FakeRunner(by_tool(clamscan=odd)), tools).scan_path("/r", timeout=60)

    assert summary(findings) == [("a.exe", "Win.Test-1", "malicious")]


def test_a_timeout_and_a_cancellation_are_reported_as_such(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    cancel = threading.Event()
    slow = FakeRunner(by_tool(clamscan=CommandResult(None, timed_out=True)))
    stopped = FakeRunner(by_tool(clamscan=CommandResult(None, cancelled=True)))

    with pytest.raises(EngineTimeoutError) as timed_out:
        clam(slow, tools).scan_path("/r", timeout=45)
    with pytest.raises(EngineCancelledError) as cancelled:
        clam(stopped, tools).scan_path("/r", timeout=45, cancel=cancel)

    assert timed_out.value.code == "engine_timeout"
    assert timed_out.value.message == "clamscan did not finish within 45 s and was stopped"
    assert cancelled.value.code == "engine_cancelled"
    assert stopped.cancels == [cancel]


def test_one_timeout_covers_every_command_of_a_scan(tmp_path: Path, clock: FakeClock) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")
    denied = CommandResult(2, stdout=b"/r/a: Access denied. ERROR\n/r/b.exe: Win.Test-1 FOUND\n")

    def slow_daemon(_argv: list[str]) -> CommandResult:
        clock.advance(40)
        return denied

    def quick_ping(_argv: list[str]) -> CommandResult:
        clock.advance(5)
        return OK

    runner = FakeRunner(by_tool(ping=quick_ping, clamdscan=slow_daemon, clamscan=OK))
    engine = clam(runner, tools, clock=clock)

    assert engine.scan_path("/r", timeout=60)[0].path == "b.exe"
    assert runner.timeouts == [10.0, 55.0, 15.0]

    runner = FakeRunner(by_tool(ping=quick_ping, clamdscan=slow_daemon, clamscan=OK))
    with pytest.raises(EngineTimeoutError) as caught:
        clam(runner, tools, clock=clock).scan_path("/r", timeout=45)
    # The daemon's detection survives the fallback that never got to run.
    assert summary(caught.value.findings) == [("b.exe", "Win.Test-1", "malicious")]
    assert runner.programs == ["clamdscan", "clamdscan"]


def test_clamav_that_is_not_installed_is_unavailable(tmp_path: Path) -> None:
    empty = tmp_path / "bin"
    empty.mkdir()
    runner = FakeRunner(by_tool())
    engine = clam(runner, empty)

    assert engine.available() is False and engine.version() is None
    with pytest.raises(EngineUnavailableError) as caught:
        engine.scan_path("/r", timeout=60)
    assert caught.value.code == "engine_unavailable" and runner.calls == []


def test_a_silent_daemon_without_clamscan_is_unavailable_not_clean(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamdscan")
    runner = FakeRunner(by_tool(ping=DAEMON_DOWN))
    engine = clam(runner, tools)

    assert engine.available() is True
    with pytest.raises(EngineUnavailableError, match="daemon does not answer"):
        engine.scan_path("/r", timeout=60)
    assert runner.programs == ["clamdscan"]


def test_a_runner_that_cannot_start_the_daemon_client_falls_back(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamdscan", "clamscan")

    def respond(argv: list[str]) -> CommandResult:
        if "--ping" in argv:
            raise EngineError("cannot start clamdscan: Exec format error")
        return OK

    runner = FakeRunner(respond)

    assert clam(runner, tools).scan_path("/r", timeout=60) == []
    assert runner.programs == ["clamdscan", "clamscan"]


def test_the_clamav_version_is_the_line_the_tool_prints(tmp_path: Path, fixtures_dir: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    printed = CommandResult(0, stdout=fixture_bytes(fixtures_dir, "clam_version.txt"))
    runner = FakeRunner(by_tool(version=printed))

    assert clam(runner, tools).version() == "ClamAV 1.4.1/27480/Mon Dec  2 09:39:37 2024"
    assert runner.calls[0][1:] == ["--version"] and runner.timeouts == [10.0]


@pytest.mark.parametrize(
    "result",
    [
        CommandResult(2, stdout=b"ClamAV 1.4.1\n"),
        CommandResult(0, stdout=b""),
        CommandResult(0, stdout=b"something else entirely\n"),
        CommandResult(None, timed_out=True),
    ],
)
def test_an_unreadable_version_is_none(tmp_path: Path, result: CommandResult) -> None:
    tools = install(tmp_path / "bin", "clamscan")

    assert clam(FakeRunner(by_tool(version=result)), tools).version() is None


def test_output_in_another_encoding_keeps_its_detections(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    latin = CommandResult(1, stdout=b"/r/caf\xe9/men\xfa.exe: Win.Test-1 FOUND\n")

    (finding,) = clam(FakeRunner(by_tool(clamscan=latin)), tools).scan_path("/r", timeout=60)

    assert finding.path == "caf\\xe9/men\\xfa.exe"
    assert finding.rule == "Win.Test-1"


def test_a_relative_root_is_made_absolute_before_the_tool_sees_it(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")
    runner = FakeRunner(by_tool(clamscan=OK))

    clam(runner, tools).scan_path(Path("some") / "relative dir", timeout=60)

    target = runner.calls[0][-1]
    assert os.path.isabs(target) and target.endswith("relative dir")
    assert not target.startswith("-")


# -- finding tools ------------------------------------------------------------------


def test_tools_are_looked_up_in_the_given_directories_only(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for directory in (first, second):
        directory.mkdir()
    (second / "tool").write_bytes(b"")
    (second / "other").write_bytes(b"")
    (first / "tool").mkdir()

    assert find_tool(["tool"], [first, second], trusted=False) == second / "tool"
    assert find_tool(["missing", "other", "tool"], [first, second], trusted=False) == (
        second / "other"
    )
    assert find_tool(["tool"], [first], trusted=False) is None
    assert find_tool(["tool"], ["relative/dir", "second"], trusted=False) is None
    assert find_tool(["tool"], [], trusted=False) is None
    assert find_tool([], [second], trusted=False) is None


def test_a_bare_program_name_is_never_trusted_to_the_search_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A look-alike earlier on PATH must not be picked up."""
    planted = install(tmp_path / "planted", "clamscan", "clamdscan")
    monkeypatch.setenv("PATH", str(planted) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(planted)
    empty = tmp_path / "system"
    empty.mkdir()

    assert clam(FakeRunner(by_tool()), empty).available() is False


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX ownership and permission bits")
def test_a_tool_must_be_root_owned_and_not_writable_by_others(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("everything the test creates would be root-owned")
    tools = install(tmp_path / "bin", "clamscan")

    assert is_trusted_program(tools / "clamscan") is False
    assert find_tool(["clamscan"], [tools]) is None
    assert ClamAvEngine(FakeRunner(by_tool()), directories=[tools]).available() is False
    assert is_trusted_program(Path("/bin/sh")) is True
    assert is_trusted_program(tmp_path / "absent") is False
    assert is_trusted_program(tmp_path) is False


@pytest.mark.windows_only
def test_on_windows_a_trusted_program_is_an_existing_file(tmp_path: Path) -> None:
    tools = install(tmp_path / "bin", "clamscan")

    assert is_trusted_program(tools / "clamscan.exe") is True
    assert is_trusted_program(tools / "absent.exe") is False
    assert is_trusted_program(tools) is False


# -- Microsoft Defender output ------------------------------------------------------


def test_a_clean_defender_scan_says_so_in_words(fixtures_dir: Path) -> None:
    text = fixture_bytes(fixtures_dir, "mp_clean.txt").decode("utf-8")

    assert parse_defender_output(text, DEFENDER_ROOT) == ([], True)
    assert parse_defender_output(text.replace("\n", "\r\n"), DEFENDER_ROOT) == ([], True)
    assert parse_defender_output("", DEFENDER_ROOT) == ([], False)


def test_defender_threats_are_parsed_resource_by_resource(fixtures_dir: Path) -> None:
    text = fixture_bytes(fixtures_dir, "mp_threats.txt").decode("utf-8")

    findings, said_clean = parse_defender_output(text, DEFENDER_ROOT)

    assert said_clean is False
    assert summary(findings) == [
        ("tools/test file.com", "Virus:DOS/EICAR_Test_File", "malicious"),
        ("backups/old archive.zip", "Virus:DOS/EICAR_Test_File", "malicious"),
        ("backups/old archive.zip", "Virus:DOS/EICAR_Test_File", "malicious"),
        (f"Descargas/instalaci{O_ACUTE}n.exe", "PUA:Win32/ExampleBundler", "suspicious"),
    ]
    assert [finding.detail for finding in findings[1:3]] == [
        "Microsoft Defender reports Virus:DOS/EICAR_Test_File",
        "Microsoft Defender reports Virus:DOS/EICAR_Test_File in archive member inner/test.com",
    ]
    assert all(finding.engine == "defender" for finding in findings)


def test_a_threat_without_a_file_resource_is_reported_against_the_root() -> None:
    text = (
        "Scanning F:\\usb volume found 1 threats.\r\n"
        "----------------------------- Threat information ------------------------------\r\n"
        "Threat                  : Trojan:Win32/Example.A\r\n"
        "Resources               : 0 total\r\n"
        "-------------------------------------------------------------------------------\r\n"
    )

    findings, _said_clean = parse_defender_output(text, DEFENDER_ROOT)

    assert summary(findings) == [("", "Trojan:Win32/Example.A", "malicious")]


@pytest.mark.parametrize(
    ("fixture", "error", "phrase"),
    [
        ("mp_service.txt", EngineUnavailableError, "service is not running"),
        ("mp_policy.txt", EngineUnavailableError, "turned off by policy"),
    ],
)
def test_a_stopped_or_disabled_defender_is_unavailable(
    fixtures_dir: Path, fixture: str, error: type[EngineError], phrase: str
) -> None:
    text = fixture_bytes(fixtures_dir, fixture).decode("utf-8")

    with pytest.raises(error) as caught:
        parse_defender_output(text, DEFENDER_ROOT)

    assert phrase in caught.value.message and "hr = 0x800" in caught.value.message
    assert caught.value.code == "engine_unavailable"
    # The log path the tool mentions belongs to the machine it ran on; it is not repeated.
    assert "Users" not in caught.value.message


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "CmdTool: Failed with hr = 0x80070005. Check the log",
            "Microsoft Defender: access denied (hr = 0x80070005)",
        ),
        (
            "CmdTool: Failed with hr = 0x80508023. Check the log",
            "Microsoft Defender: the scan failed (hr = 0x80508023)",
        ),
        (
            "Scan starting...\nScan finished.\nScanning F:\\usb volume found 3 threats.\n",
            "Microsoft Defender reported 3 threat(s) but the list could not be read",
        ),
    ],
)
def test_defender_failures_are_engine_errors(text: str, message: str) -> None:
    with pytest.raises(EngineError) as caught:
        parse_defender_output(text, DEFENDER_ROOT)

    assert type(caught.value) is EngineError
    assert message in caught.value.message


# -- the Defender engine ------------------------------------------------------------


def defender_install(tmp_path: Path, *versions: str, legacy: bool = False) -> tuple[Path, Path]:
    """A stand-in for ProgramData and Program Files holding the given platform versions."""
    program_data, program_files = tmp_path / "ProgramData", tmp_path / "Program Files"
    platform = program_data / "Microsoft" / "Windows Defender" / "Platform"
    platform.mkdir(parents=True)
    for version in versions:
        (platform / version).mkdir()
        (platform / version / "MpCmdRun.exe").write_bytes(b"")
    (program_files / "Windows Defender").mkdir(parents=True)
    if legacy:
        (program_files / "Windows Defender" / "MpCmdRun.exe").write_bytes(b"")
    return program_data, program_files


def defender(runner: FakeRunner, tmp_path: Path, *versions: str) -> DefenderEngine:
    program_data, program_files = defender_install(tmp_path, *(versions or ("4.18.24090.11-0",)))
    return DefenderEngine(runner, program_data=program_data, program_files=program_files)


def test_the_newest_platform_version_of_the_tool_is_used(tmp_path: Path) -> None:
    program_data, program_files = defender_install(
        tmp_path, "4.18.2-0", "4.18.24090.11-0", "4.18.1909.6-0", "4.18.24090.9-1", legacy=True
    )
    platform = program_data / "Microsoft" / "Windows Defender" / "Platform"
    (platform / "CurrentVersion").mkdir()
    (platform / "CurrentVersion" / "MpCmdRun.exe").write_bytes(b"")
    (platform / "9.99.0-bogus").mkdir()
    (platform / "9.99.0-bogus" / "MpCmdRun.exe").write_bytes(b"")
    (platform / "5.0.0.0-0").mkdir()
    (platform / "4.99.1.1-0").write_bytes(b"a file, not a directory")
    engine = DefenderEngine(
        FakeRunner(by_tool()), program_data=program_data, program_files=program_files
    )

    assert engine.locate() == platform / "4.18.24090.11-0" / "MpCmdRun.exe"
    assert engine.version() == "4.18.24090.11-0"
    assert engine.available() is True and engine.name == "defender"
    assert isinstance(engine, Engine)


def test_the_program_files_copy_is_the_fallback(tmp_path: Path) -> None:
    program_data, program_files = defender_install(tmp_path, legacy=True)
    engine = DefenderEngine(
        FakeRunner(by_tool()), program_data=program_data, program_files=program_files
    )

    assert engine.locate() == program_files / "Windows Defender" / "MpCmdRun.exe"
    assert engine.available() is True and engine.version() is None


def test_defender_that_is_not_installed_is_unavailable(tmp_path: Path) -> None:
    program_data, program_files = defender_install(tmp_path)
    runner = FakeRunner(by_tool())
    missing = DefenderEngine(runner, program_data=program_data, program_files=program_files)
    named = DefenderEngine(runner, executable=tmp_path / "nowhere" / "MpCmdRun.exe")
    relative = DefenderEngine(runner, executable="MpCmdRun.exe")

    for engine in (missing, named, relative):
        assert engine.available() is False and engine.version() is None
        with pytest.raises(EngineUnavailableError, match=r"MpCmdRun\.exe was not found"):
            engine.scan_path(DEFENDER_ROOT, timeout=60)
    assert runner.calls == []


@pytest.mark.skipif(IS_WINDOWS, reason="on Windows the real tool may be installed")
def test_defender_is_not_looked_for_off_windows() -> None:
    engine = DefenderEngine(FakeRunner(by_tool()))

    assert engine.locate() is None and engine.available() is False


def test_defender_is_run_as_a_custom_scan_that_removes_nothing(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    clean = CommandResult(0, stdout=fixture_bytes(fixtures_dir, "mp_clean.txt"))
    runner = FakeRunner(by_tool(MpCmdRun=clean))
    cancel = threading.Event()
    engine = defender(runner, tmp_path)

    assert engine.scan_path(DEFENDER_ROOT, timeout=90, cancel=cancel) == []
    assert runner.calls == [
        [
            str(engine.locate()),
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            DEFENDER_ROOT,
            "-DisableRemediation",
        ]
    ]
    assert runner.timeouts == [90] and runner.cancels == [cancel]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_defender_detections_are_returned_whatever_the_console_encoding(
    tmp_path: Path, fixtures_dir: Path, encoding: str, newline: str
) -> None:
    text = fixture_bytes(fixtures_dir, "mp_threats.txt").decode("utf-8").replace("\n", newline)
    runner = FakeRunner(by_tool(MpCmdRun=CommandResult(2, stdout=text.encode(encoding))))

    findings = defender(runner, tmp_path).scan_path(DEFENDER_ROOT, timeout=60)

    assert [finding.path for finding in findings] == [
        "tools/test file.com",
        "backups/old archive.zip",
        "backups/old archive.zip",
        f"Descargas/instalaci{O_ACUTE}n.exe",
    ]


def test_detections_are_believed_even_with_exit_code_zero(
    tmp_path: Path, fixtures_dir: Path
) -> None:
    threats = CommandResult(0, stdout=fixture_bytes(fixtures_dir, "mp_threats.txt"))

    findings = defender(FakeRunner(by_tool(MpCmdRun=threats)), tmp_path).scan_path(
        DEFENDER_ROOT, timeout=60
    )

    assert len(findings) == 4


@pytest.mark.parametrize(
    ("result", "error", "phrase"),
    [
        (CommandResult(0), EngineError, "no usable result (exit code 0)"),
        (CommandResult(2), EngineError, "no usable result (exit code 2)"),
        (
            CommandResult(
                2, stdout=b"Scan starting...\nScan finished.\nScanning X found no threats.\n"
            ),
            EngineError,
            "no usable result (exit code 2)",
        ),
        (
            CommandResult(0, stdout=b"Der Scan wurde gestartet...\nKeine Bedrohungen.\n"),
            EngineError,
            "no usable result (exit code 0)",
        ),
        (
            CommandResult(2, stdout=b"CmdTool: Failed with hr = 0x800106ba. Check the log\n"),
            EngineUnavailableError,
            "service is not running",
        ),
        (
            CommandResult(2, stderr=b"CmdTool: Failed with hr = 0x800704EC.\n"),
            EngineUnavailableError,
            "turned off by policy",
        ),
        (CommandResult(None, timed_out=True), EngineTimeoutError, "did not finish within 60 s"),
        (CommandResult(None, cancelled=True), EngineCancelledError, "cancelled"),
        (
            CommandResult(0, stdout=b"Scanning X found no threats.\n", truncated=True),
            EngineError,
            "printed more than could be captured",
        ),
    ],
)
def test_defender_is_clean_only_on_exit_zero_and_the_words_no_threats(
    tmp_path: Path, result: CommandResult, error: type[EngineError], phrase: str
) -> None:
    engine = defender(FakeRunner(by_tool(MpCmdRun=result)), tmp_path)

    with pytest.raises(error) as caught:
        engine.scan_path(DEFENDER_ROOT, timeout=60)

    assert type(caught.value) is error
    assert phrase in caught.value.message


@pytest.mark.hardware
@pytest.mark.windows_only
def test_the_real_defender_reports_a_directory_of_text_files_as_clean(tmp_path: Path) -> None:
    """Runs the installed MpCmdRun.exe, read-only, on three harmless files it is given."""
    engine = DefenderEngine()
    if not engine.available():
        pytest.skip("MpCmdRun.exe is not installed")
    (tmp_path / "notes.txt").write_text("plain text\n", encoding="utf-8")
    (tmp_path / "with spaces.txt").write_text("more plain text\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "data.csv").write_text("a,b\n1,2\n", encoding="utf-8")

    assert engine.scan_path(tmp_path, timeout=300) == []
    assert sorted(path.name for path in tmp_path.rglob("*")) == [
        "data.csv",
        "notes.txt",
        "sub",
        "with spaces.txt",
    ]


# -- the real command runner --------------------------------------------------------


def python(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_the_runner_captures_output_and_the_exit_code() -> None:
    result = SubprocessRunner().run(
        python("import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"), timeout=30
    )

    assert result.returncode == 3
    assert result.stdout.split() == [b"out"] and result.stderr.split() == [b"err"]
    assert (result.timed_out, result.cancelled, result.truncated) == (False, False, False)


def test_the_runner_gives_the_child_no_input_and_no_shell() -> None:
    code = "import sys; print(repr(sys.stdin.read())); print(sys.argv[1])"

    result = SubprocessRunner().run([*python(code), "$HOME; echo injected & whoami"], timeout=30)

    assert result.returncode == 0
    assert result.stdout.split(b"\n")[0].strip() == b"''"
    assert result.stdout.split(b"\n")[1].strip() == b"$HOME; echo injected & whoami"


def test_the_runner_kills_a_command_that_outlives_its_timeout() -> None:
    result = SubprocessRunner().run(
        python("import time; print('started', flush=True); time.sleep(60)"), timeout=0.5
    )

    assert result.timed_out is True and result.cancelled is False
    assert result.returncode is None
    assert result.stdout.split() == [b"started"]


def test_the_runner_kills_a_command_when_cancelled() -> None:
    cancel = threading.Event()
    timer = threading.Timer(0.3, cancel.set)
    timer.start()
    try:
        result = SubprocessRunner().run(
            python("import time; time.sleep(60)"), timeout=30, cancel=cancel
        )
    finally:
        timer.cancel()

    assert result.cancelled is True and result.timed_out is False and result.returncode is None


def test_the_runner_bounds_what_it_keeps_of_the_output() -> None:
    code = "import sys; sys.stdout.write('x' * 400000); sys.stderr.write('y' * 10)"

    result = SubprocessRunner().run(python(code), timeout=30, max_output=1000)

    assert result.returncode == 0
    assert result.stdout == b"x" * 1000 and result.stderr == b"y" * 10
    assert result.truncated is True


@pytest.mark.parametrize(
    ("argv", "timeout", "max_output"),
    [
        ([], 5, 100),
        (["python", "-c", "pass"], 5, 100),
        ([sys.executable, 3], 5, 100),
        ([sys.executable], 0, 100),
        ([sys.executable], float("nan"), 100),
        ([sys.executable], 5, 0),
    ],
)
def test_the_runner_refuses_bad_requests(argv: list[str], timeout: float, max_output: int) -> None:
    with pytest.raises(ValueError):
        SubprocessRunner().run(argv, timeout=timeout, max_output=max_output)


def test_a_program_that_cannot_be_started_is_an_engine_error(tmp_path: Path) -> None:
    missing = tmp_path / "absent" / "tool"

    with pytest.raises(EngineError) as caught:
        SubprocessRunner().run([str(missing)], timeout=5)

    assert caught.value.message.startswith("cannot start tool: ")
    assert str(tmp_path) not in caught.value.message


def test_output_decoding_never_fails() -> None:
    assert av._decode_output("caf\N{LATIN SMALL LETTER E WITH ACUTE}".encode("utf-16")) == (
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    )
    assert av._decode_output("plain text".encode("utf-16-le")) == "plain text"
    assert av._decode_output(b"\xef\xbb\xbfwith bom") == "with bom"
    assert av._decode_output(b"caf\xe9").encode("utf-8", "surrogateescape") == b"caf\xe9"
    assert av._decode_output(b"") == ""
    assert FindingSeverity.MALICIOUS.value == "malicious"
