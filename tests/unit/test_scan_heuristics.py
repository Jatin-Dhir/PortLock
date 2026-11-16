"""Heuristic rules, one at a time, on hand-built entries and hand-built file content."""

from __future__ import annotations

import random
import struct
from typing import Any

import pytest

from portlock.scan.heuristics import (
    AUTORUN_READ_BYTES,
    DEFAULT_RULES,
    EXECUTABLE_EXTENSIONS,
    INI_READ_BYTES,
    SHORTCUT_READ_BYTES,
    AutorunCommand,
    FolderMasquerade,
    HeuristicEngine,
    Rule,
    ShellLink,
    executable_format,
    is_executable,
    parse_autorun_inf,
    parse_shell_link,
    rule_autorun_inf,
    rule_deceptive_name,
    rule_desktop_ini,
    rule_hidden_executable,
    rule_root_executable,
    rule_shortcut,
    rule_type_mismatch,
)
from portlock.scan.inspector import FileEntry, extension_of
from portlock.scan.report import Finding, FindingSeverity

RLO = chr(0x202E)
NBSP = chr(0xA0)
SHA = "ab" * 32

PE_HEAD = b"MZ" + bytes(58) + struct.pack("<I", 0x80) + bytes(64) + b"PE\x00\x00" + bytes(64)
DOS_HEAD = b"MZ\x90\x00\x03" + bytes(59) + b"This program cannot be run in DOS mode" + bytes(32)
ELF_HEAD = b"\x7fELF\x02\x01\x01" + bytes(57)
MACHO_HEAD = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + bytes(56)
JPEG_HEAD = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(53)


def entry(path: str, head: bytes = b"", **fields: Any) -> FileEntry:
    """An entry as the walk would produce it for ``path`` (``/``-separated, from the root)."""
    values: dict[str, Any] = {
        "path": path,
        "os_path": "",
        "size": len(head),
        "extension": "" if fields.get("is_dir") else extension_of(path.rpartition("/")[2]),
        "head": head,
        "opened": not fields.get("is_dir", False),
    }
    values.update(fields)
    return FileEntry(**values)


def rules_of(findings: list[Finding]) -> list[tuple[str, str]]:
    return [(finding.rule, finding.severity.value) for finding in findings]


# -- a Shell Link builder, following [MS-SHLLINK] ------------------------------------

LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
MY_COMPUTER = bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")


def build_lnk(
    *,
    local_path: str | None = None,
    arguments: str | None = None,
    id_path: tuple[str, ...] | None = None,
    env_target: str | None = None,
    relative_path: str | None = None,
    working_dir: str | None = None,
    description: str | None = None,
    icon: str | None = None,
    unicode: bool = True,
    wide_link_info: bool = False,
    show: int = 1,
) -> bytes:
    """Build the bytes of a Windows shortcut with the given parts.

    ``id_path`` is a drive followed by directory names and a final file name, for
    example ``("C:\\\\", "Windows", "System32", "cmd.exe")``.
    """
    flags = 0x80 if unicode else 0
    body = b""
    if id_path is not None:
        flags |= 0x01
        root = bytes([0x1F, 0x50]) + MY_COMPUTER
        items = struct.pack("<H", len(root) + 2) + root
        volume = bytes([0x2F]) + id_path[0].encode("ascii").ljust(22, b"\x00")
        items += struct.pack("<H", len(volume) + 2) + volume
        for position, name in enumerate(id_path[1:]):
            is_file = position == len(id_path) - 2
            item = bytes([0x32 if is_file else 0x31, 0x00]) + struct.pack(
                "<IHHH", 0, 0, 0, 0x20 if is_file else 0x10
            )
            item += name.encode("ascii") + b"\x00"
            item += b"\x00" * (len(item) % 2)
            items += struct.pack("<H", len(item) + 2) + item
        items += b"\x00\x00"
        body += struct.pack("<H", len(items)) + items
    if local_path is not None:
        flags |= 0x02
        header_size = 0x24 if wide_link_info else 0x1C
        volume_id = struct.pack("<IIII", 0x11, 3, 0x1234ABCD, 0x10) + b"\x00"
        base = local_path.encode("cp1252", "replace") + b"\x00"
        suffix = b"\x00"
        volume_offset = header_size
        base_offset = volume_offset + len(volume_id)
        suffix_offset = base_offset + len(base)
        tail = volume_id + base + suffix
        header = struct.pack(
            "<IIIIII", header_size, 0x1, volume_offset, base_offset, 0, suffix_offset
        )
        if wide_link_info:
            wide_base = local_path.encode("utf-16-le") + b"\x00\x00"
            wide_base_offset = header_size + len(tail)
            wide_suffix_offset = wide_base_offset + len(wide_base)
            header += struct.pack("<II", wide_base_offset, wide_suffix_offset)
            tail += wide_base + b"\x00\x00"
        body += struct.pack("<I", 4 + len(header) + len(tail)) + header + tail
    for bit, value in (
        (0x04, description),
        (0x08, relative_path),
        (0x10, working_dir),
        (0x20, arguments),
        (0x40, icon),
    ):
        if value is None:
            continue
        flags |= bit
        encoded = value.encode("utf-16-le") if unicode else value.encode("cp1252", "replace")
        body += struct.pack("<H", len(value)) + encoded
    if env_target is not None:
        flags |= 0x200
        ansi = env_target.encode("cp1252", "replace").ljust(260, b"\x00")
        wide = env_target.encode("utf-16-le").ljust(520, b"\x00")
        body += struct.pack("<II", 0x314, 0xA0000001) + ansi + wide
    body += struct.pack("<I", 0)
    header = (
        struct.pack("<I", 0x4C)
        + LNK_CLSID
        + struct.pack("<II", flags, 0x20)
        + bytes(24)
        + struct.pack("<IiI", 0, 0, show)
        + bytes(12)
    )
    assert len(header) == 0x4C
    return header + body


CMD = "C:\\Windows\\System32\\cmd.exe"


# -- recognising executable content -------------------------------------------------


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (PE_HEAD, "PE"),
        (b"MZ" + bytes(58) + struct.pack("<I", 0x400) + bytes(448), "PE"),
        (DOS_HEAD, "DOS executable"),
        (ELF_HEAD, "ELF"),
        (MACHO_HEAD, "Mach-O"),
        (b"\xfe\xed\xfa\xce" + bytes(60), "Mach-O"),
        (b"\xfe\xed\xfa\xcf" + bytes(60), "Mach-O"),
        (b"\xce\xfa\xed\xfe" + bytes(60), "Mach-O"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(56), "Mach-O"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(56), None),
        (b"\xca\xfe\xba\xbe", None),
        (b"MZ is how this plain text file happens to start, and it goes on for a while.", None),
        (b"MZ", None),
        (JPEG_HEAD, None),
        (b"#!/bin/sh\necho hello\n", None),
        (b"", None),
    ],
)
def test_executable_formats_are_recognised_by_content(head: bytes, expected: str | None) -> None:
    assert executable_format(head) == expected


def test_is_executable_goes_by_extension_or_content() -> None:
    assert is_executable(entry("tool.EXE"))
    assert is_executable(entry("holiday.jpg", PE_HEAD))
    assert not is_executable(entry("holiday.jpg", JPEG_HEAD))
    assert not is_executable(entry("tools.exe", is_dir=True))


# -- executables at the root --------------------------------------------------------


@pytest.mark.parametrize("extension", sorted(EXECUTABLE_EXTENSIONS))
def test_every_launchable_type_at_the_root_is_flagged(extension: str) -> None:
    findings = rule_root_executable(entry(f"Open Me{extension.upper()}"), None)

    assert rules_of(findings) == [("root.executable", "suspicious")]
    assert findings[0].path == f"Open Me{extension.upper()}" and findings[0].engine == "heuristics"
    assert f"{extension} file at the volume root" in findings[0].detail


def test_the_listed_extensions_are_exactly_the_documented_ones() -> None:
    documented = (
        "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
        "hta", "lnk", "msi", "jar", "dll",
    )  # fmt: skip

    assert frozenset(f".{name}" for name in documented) == EXECUTABLE_EXTENSIONS
    assert len(documented) == 18


@pytest.mark.parametrize(
    ("name", "head", "phrase"),
    [
        ("readme", ELF_HEAD, "ELF program under the name of a plain file"),
        ("notes.dat", PE_HEAD, "PE program under the name of a .dat file"),
        ("update.bin", MACHO_HEAD, "Mach-O program under the name of a .bin file"),
        ("setup.exe", PE_HEAD, ".exe file (PE) at the volume root"),
    ],
)
def test_native_programs_at_the_root_are_flagged_whatever_their_name(
    name: str, head: bytes, phrase: str
) -> None:
    findings = rule_root_executable(entry(name, head), None)

    assert rules_of(findings) == [("root.executable", "suspicious")]
    assert phrase in findings[0].detail


@pytest.mark.parametrize(
    "candidate",
    [
        entry("docs/setup.exe", PE_HEAD),
        entry("notes.txt", b"just text"),
        entry("holiday.jpg", JPEG_HEAD),
        entry("tools.exe", is_dir=True),
    ],
)
def test_the_root_rule_leaves_everything_else_alone(candidate: FileEntry) -> None:
    assert rule_root_executable(candidate, None) == []


# -- deceptive names ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("invoice.pdf.exe", [("name.double_extension", "suspicious")]),
        ("Holiday.JPG.scr", [("name.double_extension", "suspicious")]),
        ("docs/photo.jpg.lnk", [("name.double_extension", "suspicious")]),
        ("report.docx.js", [("name.double_extension", "suspicious")]),
        ("invoice.pdf.exe .", [("name.double_extension", "suspicious")]),
        ("setup.x64.exe", []),
        ("jquery.min.js", []),
        ("template.html.js", []),
        ("archive.tar.gz", []),
        ("invoice.pdf", []),
        ("plain.exe", []),
        (
            "invoice.pdf" + " " * 40 + ".exe",
            [("name.double_extension", "suspicious"), ("name.padded_extension", "suspicious")],
        ),
        (
            "invoice.pdf" + NBSP * 12 + ".exe",
            [("name.double_extension", "suspicious"), ("name.padded_extension", "suspicious")],
        ),
        ("my     notes.cmd", [("name.padded_extension", "suspicious")]),
        ("four    spaces.exe", []),
        ("many      spaces.txt", []),
    ],
)
def test_decoy_and_padded_extensions(name: str, expected: list[tuple[str, str]]) -> None:
    assert rules_of(rule_deceptive_name(entry(name), None)) == expected


def test_a_double_extension_finding_names_both_extensions() -> None:
    (finding,) = rule_deceptive_name(entry("invoice.pdf.exe"), None)

    assert finding.detail == ".exe file presented as a .pdf file"


def test_a_right_to_left_override_on_an_executable_is_malicious() -> None:
    name = f"photo{RLO}gpj.exe"

    (finding,) = rule_deceptive_name(entry(name, PE_HEAD), None)

    assert (finding.rule, finding.severity) == ("name.bidi_override", FindingSeverity.MALICIOUS)
    assert finding.path == "photo\\u202egpj.exe"
    assert RLO not in finding.path and RLO not in finding.detail


def test_a_right_to_left_override_hiding_executable_content_is_malicious() -> None:
    (finding,) = rule_deceptive_name(entry(f"annual{RLO}fdp.dat", PE_HEAD), None)

    assert finding.severity is FindingSeverity.MALICIOUS and "by content" not in finding.detail
    assert ".dat" in finding.detail


@pytest.mark.parametrize("code", [0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068])
def test_every_bidirectional_control_is_noticed(code: int) -> None:
    findings = rule_deceptive_name(entry(f"a{chr(code)}b.scr"), None)

    assert rules_of(findings) == [("name.bidi_override", "malicious")]


def test_a_right_to_left_override_on_a_harmless_file_is_only_noted() -> None:
    findings = rule_deceptive_name(entry(f"notes{RLO}txt.md", b"# notes"), None)

    assert rules_of(findings) == [("name.bidi_override", "info")]
    assert rule_deceptive_name(entry(f"folder{RLO}exe", is_dir=True), None) == []


# -- content that does not match the name -------------------------------------------


@pytest.mark.parametrize(
    ("name", "head", "kind"),
    [
        ("holiday.jpg", PE_HEAD, "PE"),
        ("deep/down/Report.PDF", ELF_HEAD, "ELF"),
        ("song.mp3", MACHO_HEAD, "Mach-O"),
        ("backup.zip", DOS_HEAD, "DOS executable"),
    ],
)
def test_a_program_under_a_document_extension_is_flagged(name: str, head: bytes, kind: str) -> None:
    (finding,) = rule_type_mismatch(entry(name, head), None)

    assert (finding.rule, finding.severity) == ("type.mismatch", FindingSeverity.SUSPICIOUS)
    assert finding.detail == f"content is a {kind} program but the name says {extension_of(name)}"


@pytest.mark.parametrize(
    "candidate",
    [
        entry("holiday.jpg", JPEG_HEAD),
        entry("plugin.dat", PE_HEAD),
        entry("library.dll", PE_HEAD),
        entry("noextension", ELF_HEAD),
        entry("empty.jpg"),
        entry("folder.jpg", is_dir=True),
    ],
)
def test_the_mismatch_rule_stays_clear_of_ordinary_files(candidate: FileEntry) -> None:
    assert rule_type_mismatch(candidate, None) == []


# -- hidden executables -------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "detail"),
    [
        ({"hidden": True}, ".exe file marked hidden"),
        ({"system": True, "hidden": False}, ".exe file marked system"),
        ({"hidden": True, "system": True}, ".exe file marked hidden and system"),
    ],
)
def test_a_hidden_or_system_executable_is_flagged(fields: dict[str, Any], detail: str) -> None:
    (finding,) = rule_hidden_executable(entry("data/svchost.exe", **fields), None)

    assert (finding.rule, finding.severity) == ("hidden.executable", FindingSeverity.SUSPICIOUS)
    assert finding.detail == detail


def test_a_hidden_program_is_flagged_whatever_its_extension() -> None:
    (finding,) = rule_hidden_executable(entry("cache.dat", PE_HEAD, hidden=True), None)

    assert finding.detail == "PE program marked hidden"


@pytest.mark.parametrize(
    "candidate",
    [
        entry("visible.exe", hidden=False, system=False),
        entry("unknown.exe", hidden=None, system=None),
        entry("hidden.txt", hidden=True),
        entry("hidden.exe", is_dir=True, hidden=True),
    ],
)
def test_the_hidden_rule_needs_both_hidden_and_executable(candidate: FileEntry) -> None:
    assert rule_hidden_executable(candidate, None) == []


# -- autorun.inf --------------------------------------------------------------------


def test_autorun_launch_entries_are_reported_with_their_targets() -> None:
    content = (
        b"; a comment\r\n"
        b"[AutoRun]\r\n"
        b"Open = RECYCLER\\payload.exe /quiet\r\n"
        b"ShellExecute=readme.html\r\n"
        b"shell\\Explore\\Command = wscript.exe run.vbs\r\n"
        b"shell\\Explore = Explore\r\n"
        b"icon=shell32.dll,4\r\n"
        b"action=Open folder to view files\r\n"
        b"label=EXAMPLE\r\n"
    )

    assert parse_autorun_inf(content) == (
        AutorunCommand("open", "RECYCLER\\payload.exe /quiet"),
        AutorunCommand("shellexecute", "readme.html"),
        AutorunCommand("shell\\explore\\command", "wscript.exe run.vbs"),
    )
    findings = rule_autorun_inf(entry("AUTORUN.INF", content[:512]), content)
    assert rules_of(findings) == [("autorun.launch", "suspicious")] * 3
    assert [finding.detail for finding in findings] == [
        "autorun.inf open= runs RECYCLER\\payload.exe /quiet",
        "autorun.inf shellexecute= runs readme.html",
        "autorun.inf shell\\explore\\command= runs wscript.exe run.vbs",
    ]


@pytest.mark.parametrize(
    "content",
    [
        "[autorun]\nopen=a.exe\n".encode("utf-16"),
        "[autorun]\nopen=a.exe\n".encode("utf-16-le"),
        b"\xef\xbb\xbf[autorun]\nopen=a.exe\n",
        b"[autorun.amd64]\nopen=a.exe\n",
        b"  [ AUTORUN ]  \n\topen\t=\ta.exe  \n",
        b"[autorun]\x00\nopen=a.exe\x00\x00\n",
        b"[autorun]\ropen=a.exe\r",
    ],
)
def test_autorun_is_read_in_whatever_encoding_and_spacing(content: bytes) -> None:
    assert parse_autorun_inf(content) == (AutorunCommand("open", "a.exe"),)


def test_autorun_padded_with_binary_junk_is_still_read() -> None:
    """Conficker hid its entries between lines of random bytes."""
    noise = random.Random(7)
    junk = [
        bytes(noise.randrange(1, 256) for _ in range(60)).replace(b"\n", b"?") for _ in range(40)
    ]
    lines = [*junk[:20], b"[AUTorUN", *junk[20:25], b"[AUTorUN]", *junk[25:30]]
    lines += [b"shelLExECUte=rUNdLl32.EXE .\\RECYCLER\\jwgkvsq.vmx,ahaezedrn", *junk[30:]]
    content = b"\r\n".join(lines)

    commands = parse_autorun_inf(content)

    assert AutorunCommand("shellexecute", "rUNdLl32.EXE .\\RECYCLER\\jwgkvsq.vmx,ahaezedrn") in (
        commands
    )
    findings = rule_autorun_inf(entry("autorun.inf", content[:512]), content)
    assert findings and all(finding.severity is FindingSeverity.SUSPICIOUS for finding in findings)
    assert all(
        finding.path == "autorun.inf" and finding.detail.isprintable() for finding in findings
    )


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"[autorun]\nicon=drive.ico\nlabel=EXAMPLE\n",
        b"[other]\nopen=a.exe\n",
        b"open=a.exe\n",
        bytes(range(256)) * 64,
        b"\xff\xfe" + bytes(range(256)) * 16,
        b"\x00" * 4096,
        b"[" * 5000,
        b"=" * 5000 + b"\n[autorun\nopen",
    ],
)
def test_an_autorun_file_without_launch_entries_is_only_noted(content: bytes) -> None:
    findings = rule_autorun_inf(entry("autorun.inf", content[:512]), content)

    assert rules_of(findings) == [("autorun.present", "info")]
    assert findings[0].detail == "autorun.inf at the volume root with no launch entries"


def test_an_unread_autorun_file_is_still_noted() -> None:
    findings = rule_autorun_inf(entry("autorun.inf", opened=False), None)

    assert rules_of(findings) == [("autorun.present", "info")]
    assert "was not read" in findings[0].detail


@pytest.mark.parametrize(
    "candidate",
    [
        entry("backup/autorun.inf"),
        entry("autorun.inf", is_dir=True),
        entry("autorun.inf.txt"),
        entry("notautorun.inf"),
    ],
)
def test_only_the_root_autorun_file_counts(candidate: FileEntry) -> None:
    assert rule_autorun_inf(candidate, b"[autorun]\nopen=a.exe\n") == []


def test_hostile_autorun_values_are_bounded_and_escaped() -> None:
    target = "evil" + RLO + "\x07\x1b[2J" + "A" * 300
    content = b"[autorun]\n" + b"".join(f"open={target}{index}\n".encode() for index in range(200))

    findings = rule_autorun_inf(entry("autorun.inf"), content[:AUTORUN_READ_BYTES])

    assert len(findings) == 16
    for finding in findings:
        assert len(finding.detail) < 300 and finding.detail.isprintable()
        assert "\\u202e\\x07\\x1b[2J" in finding.detail


# -- shortcuts ----------------------------------------------------------------------


def test_a_shortcut_parses_into_its_parts() -> None:
    data = build_lnk(
        local_path=CMD,
        arguments="/c start payload.vbs",
        id_path=("C:\\", "Windows", "System32", "cmd.exe"),
        relative_path="..\\..\\Windows\\System32\\cmd.exe",
        working_dir="C:\\Windows",
        description="Photos",
        icon="%SystemRoot%\\System32\\shell32.dll",
        show=7,
    )

    link = parse_shell_link(data)

    assert link == ShellLink(
        target=CMD,
        arguments="/c start payload.vbs",
        working_dir="C:\\Windows",
        relative_path="..\\..\\Windows\\System32\\cmd.exe",
        icon_location="%SystemRoot%\\System32\\shell32.dll",
        description="Photos",
        environment_target=None,
        id_list_path="C:\\Windows\\System32\\cmd.exe",
        evidence=link.evidence if link else (),
        show_command=7,
        complete=True,
    )
    assert "cmd.exe" in link.evidence and "System32" in link.evidence
    # The item list spells out the same path as LinkInfo, so it appears once; the bare
    # program name from the item list comes last, and bare folder names not at all.
    assert link.target_candidates == (CMD, "..\\..\\Windows\\System32\\cmd.exe", "cmd.exe")


def test_ansi_strings_and_wide_link_info_are_both_understood() -> None:
    ansi = parse_shell_link(build_lnk(local_path=CMD, arguments="/k echo", unicode=False))
    wide = parse_shell_link(build_lnk(local_path=CMD, arguments="/k echo", wide_link_info=True))

    assert ansi is not None and wide is not None
    assert (ansi.target, ansi.arguments, ansi.complete) == (CMD, "/k echo", True)
    assert (wide.target, wide.arguments, wide.complete) == (CMD, "/k echo", True)


@pytest.mark.parametrize(
    "interpreter",
    ["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"],
)
def test_a_shortcut_to_each_interpreter_is_flagged(interpreter: str) -> None:
    data = build_lnk(local_path=f"C:\\Windows\\System32\\{interpreter.upper()}.EXE", arguments="x")

    (finding,) = rule_shortcut(entry("docs/Photos.lnk", data[:512]), data)

    assert (finding.rule, finding.severity) == ("shortcut.interpreter", FindingSeverity.SUSPICIOUS)
    assert finding.detail.startswith(f"shortcut launches {interpreter}: target=C:\\Windows")
    assert finding.detail.endswith("arguments=x")


@pytest.mark.parametrize(
    "parts",
    [
        {"id_path": ("C:\\", "Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe")},
        {"env_target": "%ComSpec%"},
        {"env_target": "%windir%\\system32\\mshta.exe"},
        {"relative_path": "..\\..\\..\\Windows\\System32\\wscript.exe"},
        {"local_path": '"C:\\Windows\\System32\\cmd.exe"  '},
        {"local_path": "C:/Windows/System32/cmd.exe"},
        {
            "local_path": "C:\\Windows\\explorer.exe",
            "arguments": "/c powershell -w hidden -enc AAAA",
        },
        {
            "local_path": "C:\\Tools\\launcher.exe",
            "arguments": "C:\\Windows\\System32\\cmd.exe /c x",
        },
        {"local_path": "C:\\Tools\\launcher.exe", "arguments": "%COMSPEC% /c x"},
        {"local_path": CMD, "unicode": False, "arguments": "/c x"},
    ],
)
def test_the_interpreter_is_found_wherever_the_format_can_hold_it(parts: dict[str, Any]) -> None:
    data = build_lnk(**parts)

    findings = rule_shortcut(entry("Documents.lnk", data[:512]), data)

    assert rules_of(findings) == [("shortcut.interpreter", "suspicious")]


@pytest.mark.parametrize(
    "parts",
    [
        {"local_path": "C:\\Windows\\notepad.exe", "arguments": "readme.txt"},
        {"local_path": "E:\\Documents"},
        {"local_path": "C:\\Windows\\notepad.exe", "arguments": "build.cmd"},
        {"local_path": "C:\\Tools\\git.exe", "arguments": "--cmd status -cmd=1"},
        {"id_path": ("C:\\", "tools", "cmd", "readme.txt")},
        {"local_path": "C:\\Program Files\\Example\\cmdline-tool.exe"},
        {"local_path": "C:\\Program Files\\Example\\mycmd.exe"},
        {"description": "Start cmd for me"},
    ],
)
def test_ordinary_shortcuts_are_left_alone(parts: dict[str, Any]) -> None:
    data = build_lnk(**parts)

    assert parse_shell_link(data) is not None
    assert rule_shortcut(entry("Documents.lnk", data[:512]), data) == []


def test_padded_arguments_are_called_out_and_shown_collapsed() -> None:
    data = build_lnk(local_path=CMD, arguments="/c" + " " * 300 + "start hidden\\payload.exe")

    (finding,) = rule_shortcut(entry("Photos.lnk", data[:512]), data)

    assert "arguments=/c start hidden\\payload.exe" in finding.detail
    assert finding.detail.endswith("(arguments padded with blanks to hide the command)")


def test_long_hostile_arguments_are_bounded_and_escaped() -> None:
    data = build_lnk(local_path=CMD, arguments="/c " + RLO + "\x00\x07" + "A" * 30000)

    (finding,) = rule_shortcut(entry("Photos.lnk", data[:512]), data)

    assert len(finding.detail) < 500 and finding.detail.isprintable()


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"garbage",
        bytes(range(256)) * 4,
        b"\x4c\x00\x00\x00" + bytes(200),
        LNK_CLSID * 20,
        b"L" * 100_000,
    ],
)
def test_a_lnk_file_that_is_not_a_shortcut_is_noted_not_fatal(content: bytes) -> None:
    assert parse_shell_link(content) is None
    findings = rule_shortcut(entry("docs/broken.lnk", content[:512]), content)

    assert rules_of(findings) == [("shortcut.malformed", "info")]


def test_a_header_that_promises_more_than_the_file_holds() -> None:
    header = build_lnk()[:0x4C]
    everything = header[:20] + struct.pack("<I", 0xFFFFFFFF) + header[24:]

    link = parse_shell_link(everything)

    assert link is not None and link.complete is False and link.target is None
    assert rules_of(rule_shortcut(entry("x.lnk"), everything)) == [("shortcut.malformed", "info")]


def test_a_shortcut_cut_short_still_gives_up_what_was_read() -> None:
    data = build_lnk(local_path=CMD, arguments="/c start payload.exe", description="Photos")
    cut = data[: data.index("payload".encode("utf-16-le"))]

    link = parse_shell_link(cut)

    assert link is not None and link.complete is False
    assert link.target == CMD and link.arguments is None
    assert rules_of(rule_shortcut(entry("Photos.lnk"), cut)) == [
        ("shortcut.interpreter", "suspicious")
    ]


def test_no_prefix_of_a_shortcut_can_crash_the_parser() -> None:
    data = build_lnk(
        local_path=CMD,
        arguments="/c start x",
        id_path=("C:\\", "Windows", "System32", "cmd.exe"),
        env_target="%ComSpec%",
        relative_path="..\\cmd.exe",
        working_dir="C:\\",
        description="d",
        icon="i",
        wide_link_info=True,
    )
    target = entry("p.lnk")

    for length in range(len(data) + 1):
        link = parse_shell_link(data[:length])
        assert link is None or isinstance(link, ShellLink)
        for finding in rule_shortcut(target, data[:length]):
            assert finding.rule in ("shortcut.interpreter", "shortcut.malformed")
    assert parse_shell_link(data) is not None and parse_shell_link(data).complete


def test_random_damage_to_a_shortcut_cannot_crash_the_parser() -> None:
    data = bytearray(
        build_lnk(
            local_path=CMD,
            arguments="/c start x",
            id_path=("C:\\", "Windows", "System32", "cmd.exe"),
            env_target="%ComSpec%",
            relative_path="..\\cmd.exe",
        )
    )
    noise = random.Random(20261116)
    target = entry("p.lnk")
    parsed = 0

    for _ in range(1500):
        damaged = bytearray(data)
        for _ in range(noise.randrange(1, 12)):
            # Leave the 20-byte signature alone so the damage reaches the parser proper.
            damaged[noise.randrange(20, len(damaged))] = noise.randrange(256)
        link = parse_shell_link(bytes(damaged))
        parsed += link is not None
        for finding in rule_shortcut(target, bytes(damaged)):
            assert finding.detail.isprintable() and len(finding.detail) <= 1024

    assert parsed == 1500


def test_the_shortcut_rule_only_reads_lnk_files_it_was_given() -> None:
    data = build_lnk(local_path=CMD)

    assert rule_shortcut(entry("Photos.lnk", data[:512]), None) == []
    assert rule_shortcut(entry("Photos.txt", data[:512]), data) == []
    assert rule_shortcut(entry("Photos.lnk", is_dir=True), data) == []


# -- desktop.ini --------------------------------------------------------------------

FOLDER_SHORTCUT = "{0AFACED1-E828-11D1-9187-B532F1E9575D}"
RECYCLE_BIN = "{645FF040-5081-101B-9F08-00AA002F954E}"


@pytest.mark.parametrize(
    ("line", "detail"),
    [
        (
            f"CLSID2={FOLDER_SHORTCUT}",
            f"desktop.ini redirects its folder with CLSID2={FOLDER_SHORTCUT.lower()} "
            "(Folder Shortcut)",
        ),
        (
            f"clsid = {RECYCLE_BIN}",
            f"desktop.ini redirects its folder with CLSID={RECYCLE_BIN.lower()} (Recycle Bin)",
        ),
        (
            "UICLSID={12345678-1234-1234-1234-1234567890AB}",
            "desktop.ini redirects its folder with UICLSID={12345678-1234-1234-1234-1234567890ab}",
        ),
    ],
)
def test_a_desktop_ini_with_a_class_id_is_flagged(line: str, detail: str) -> None:
    content = f"[.ShellClassInfo]\r\n{line}\r\nIconResource=shell32.dll,3\r\n".encode()

    (finding,) = rule_desktop_ini(entry("Photos/desktop.ini", content), content)

    assert (finding.rule, finding.severity) == ("desktopini.clsid", FindingSeverity.SUSPICIOUS)
    assert finding.detail == detail


@pytest.mark.parametrize(
    "path",
    [
        "$RECYCLE.BIN/S-1-5-21-1000000000-2000000000-3000000000-1001/desktop.ini",
        "RECYCLER/S-1-5-21-1000000000-2000000000-3000000000-1001/Desktop.ini",
        "Recycled/desktop.ini",
    ],
)
def test_the_recycle_bins_own_desktop_ini_is_expected(path: str) -> None:
    content = f"[.ShellClassInfo]\r\nCLSID={RECYCLE_BIN}\r\n".encode("utf-16")

    assert rule_desktop_ini(entry(path, content), content) == []
    # The same class id anywhere else, or another class id inside a recycle bin, is not.
    assert len(rule_desktop_ini(entry("Photos/desktop.ini"), content)) == 1
    other = f"[.ShellClassInfo]\r\nCLSID2={FOLDER_SHORTCUT}\r\n".encode()
    assert len(rule_desktop_ini(entry(path), other)) == 1


@pytest.mark.parametrize(
    "content",
    [
        b"[.ShellClassInfo]\r\nIconResource=C:\\Windows\\System32\\shell32.dll,3\r\n",
        b"[.ShellClassInfo]\r\nCLSID=not-a-guid\r\n",
        b"[ViewState]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\n",
        b"",
        bytes(range(256)) * 32,
    ],
)
def test_an_ordinary_or_broken_desktop_ini_is_left_alone(content: bytes) -> None:
    assert rule_desktop_ini(entry("Photos/desktop.ini", content[:512]), content) == []


def test_the_desktop_ini_rule_only_reads_desktop_ini() -> None:
    content = f"[.ShellClassInfo]\r\nCLSID2={FOLDER_SHORTCUT}\r\n".encode()

    assert rule_desktop_ini(entry("Photos/settings.ini"), content) == []
    assert rule_desktop_ini(entry("Photos/desktop.ini"), None) == []
    assert rule_desktop_ini(entry("desktop.ini", is_dir=True), content) == []
    many = "[.ShellClassInfo]\n" + f"CLSID2={FOLDER_SHORTCUT}\n" * 500
    assert len(rule_desktop_ini(entry("desktop.ini"), many.encode())) == 16


# -- a folder and its same-named twin -----------------------------------------------


def observe_all(rule: FolderMasquerade, entries: list[FileEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for item in entries:
        findings += rule.observe(item)
    return findings + rule.finish()


@pytest.mark.parametrize(
    ("twin", "folder_fields", "severity", "detail"),
    [
        ("Photos.lnk", {}, "suspicious", ".lnk file with the same name as a folder beside it"),
        ("photos.EXE", {}, "suspicious", ".exe file with the same name as a folder beside it"),
        (
            "Photos.lnk",
            {"hidden": True},
            "malicious",
            ".lnk file with the same name as a hidden folder beside it",
        ),
        (
            "Photos.scr",
            {"system": True},
            "malicious",
            ".scr file with the same name as a hidden folder beside it",
        ),
    ],
)
def test_a_launcher_named_like_the_folder_beside_it(
    twin: str, folder_fields: dict[str, Any], severity: str, detail: str
) -> None:
    folder = entry("Photos", is_dir=True, **folder_fields)

    for order in ([folder, entry(twin)], [entry(twin), folder]):
        (finding,) = observe_all(FolderMasquerade(), order)
        assert (finding.rule, finding.severity.value) == ("folder.masquerade", severity)
        assert (finding.path, finding.detail) == (twin, detail)


def test_the_folder_rule_only_compares_neighbours() -> None:
    entries = [
        entry("Photos", is_dir=True),
        entry("Music", is_dir=True),
        entry("Photos.dll"),
        entry("Photos.txt"),
        entry("Photos2.lnk"),
        entry("Music.jar"),
        entry("Music/Photos.lnk"),
        entry("Music/Videos", is_dir=True),
        entry("Other/Videos.exe"),
    ]

    assert observe_all(FolderMasquerade(), entries) == []


def test_the_folder_rule_reports_each_directory_as_the_walk_leaves_it() -> None:
    rule = FolderMasquerade()

    assert rule.observe(entry("a/Docs", is_dir=True)) == []
    assert rule.observe(entry("a/Docs.lnk"), SHA) == []
    left = rule.observe(entry("b/Docs.lnk"))
    assert [(finding.path, finding.sha256) for finding in left] == [("a/Docs.lnk", SHA)]
    assert rule.finish() == [] and rule.finish() == []


def test_a_vouched_for_twin_is_only_noted() -> None:
    rule = FolderMasquerade()
    rule.observe(entry("Tool", is_dir=True, hidden=True))
    rule.observe(entry("Tool.exe"), SHA, "on the known-good list 'local'")

    (finding,) = rule.finish()

    assert finding.severity is FindingSeverity.INFO
    assert finding.detail.endswith("because the file is on the known-good list 'local'")


# -- the engine and its sessions ----------------------------------------------------


def test_the_engine_asks_for_content_only_where_a_rule_needs_it() -> None:
    engine = HeuristicEngine()

    assert engine.content_wanted(entry("autorun.inf")) == AUTORUN_READ_BYTES
    assert engine.content_wanted(entry("sub/autorun.inf")) == 0
    assert engine.content_wanted(entry("a/b/Photos.LNK")) == SHORTCUT_READ_BYTES
    assert engine.content_wanted(entry("a/Desktop.ini")) == INI_READ_BYTES
    assert engine.content_wanted(entry("setup.exe")) == 0
    assert engine.content_wanted(entry("Photos.lnk", is_dir=True)) == 0
    assert engine.name == "heuristics" and engine.version() == "1"
    assert len(DEFAULT_RULES) == 7 and len({rule.rule_id for rule in DEFAULT_RULES}) == 7


def test_a_session_runs_every_rule_and_attaches_the_digest() -> None:
    session = HeuristicEngine().session()
    hidden_dropper = entry("invoice.pdf.exe", PE_HEAD, hidden=True)

    findings = session.inspect(hidden_dropper, None, SHA)

    assert sorted(rules_of(findings)) == [
        ("hidden.executable", "suspicious"),
        ("name.double_extension", "suspicious"),
        ("root.executable", "suspicious"),
    ]
    assert {finding.sha256 for finding in findings} == {SHA}
    assert session.finish() == [] and session.errors == []


def test_a_session_applies_the_folder_rule_across_entries() -> None:
    session = HeuristicEngine().session()

    first = session.inspect(entry("Photos", is_dir=True, hidden=True))
    second = session.inspect(entry("Photos.lnk", b"junk"), b"junk")
    last = session.finish()

    assert first == []
    assert sorted(rules_of(second)) == [
        ("root.executable", "suspicious"),
        ("shortcut.malformed", "info"),
    ]
    assert rules_of(last) == [("folder.masquerade", "malicious")]


def test_a_known_good_file_has_its_findings_replaced_by_a_record_of_that() -> None:
    session = HeuristicEngine().session()

    findings = session.inspect(
        entry("setup.pdf.exe", PE_HEAD), None, SHA, trusted_by="on the known-good list 'vendor'"
    )

    (finding,) = findings
    assert (finding.rule, finding.severity) == ("suppressed.known_good", FindingSeverity.INFO)
    assert finding.sha256 == SHA
    assert finding.detail == (
        "2 heuristic finding(s) suppressed (name.double_extension, root.executable): "
        "the file is on the known-good list 'vendor'"
    )
    assert session.inspect(entry("notes.txt"), trusted_by="on the known-good list 'vendor'") == []


def test_a_rule_that_raises_is_contained_and_reported() -> None:
    def broken(_entry: FileEntry, _content: bytes | None) -> list[Finding]:
        raise RuntimeError("secret detail that must not leak into a report")

    def greedy(_entry: FileEntry) -> int:
        raise ZeroDivisionError

    engine = HeuristicEngine([Rule("broken", broken, greedy), *DEFAULT_RULES], folder_rule=False)
    session = engine.session()

    findings = session.inspect(entry("setup.exe"))

    assert rules_of(findings) == [("root.executable", "suspicious")]
    assert session.errors == [("broken", "setup.exe", "RuntimeError")]
    assert engine.content_wanted(entry("autorun.inf")) == AUTORUN_READ_BYTES
    assert session.finish() == []


def test_an_engine_can_be_given_no_rules_at_all() -> None:
    session = HeuristicEngine([], folder_rule=False).session()

    assert session.inspect(entry("Photos", is_dir=True, hidden=True)) == []
    assert session.inspect(entry("Photos.exe", PE_HEAD, hidden=True)) == []
    assert session.finish() == []
