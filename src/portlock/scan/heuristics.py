"""Heuristic rules: file shapes that removable-media malware keeps reusing.

Each rule is a small function that looks at one :class:`FileEntry` (and, where it needs
them, the leading bytes of the file's content) and returns findings. Rules never touch
the filesystem, so each can be tested on its own with a hand-built entry.

A heuristic recognises a *shape*, not malice. Every rule here reports ``suspicious``
("a person should look") unless the evidence is strong enough that no ordinary volume
would show it; the two cases that report ``malicious`` say why. A file whose hash is on
the known-good list has its heuristic findings suppressed by the scanner, which is the
intended way to silence a false positive. ``docs/SCANNING.md`` justifies each severity.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from portlock.scan.inspector import FileEntry, extension_of
from portlock.scan.report import Finding, FindingSeverity, safe_text

__all__ = [
    "AUTORUN_READ_BYTES",
    "DEFAULT_RULES",
    "ENGINE_NAME",
    "EXECUTABLE_EXTENSIONS",
    "INI_READ_BYTES",
    "RULESET_VERSION",
    "SHORTCUT_READ_BYTES",
    "AutorunCommand",
    "FolderMasquerade",
    "HeuristicEngine",
    "HeuristicSession",
    "Rule",
    "ShellLink",
    "executable_format",
    "is_executable",
    "parse_autorun_inf",
    "parse_shell_link",
    "rule_autorun_inf",
    "rule_deceptive_name",
    "rule_desktop_ini",
    "rule_hidden_executable",
    "rule_root_executable",
    "rule_shortcut",
    "rule_type_mismatch",
]

ENGINE_NAME = "heuristics"
#: Bumped whenever a rule is added, removed or changes what it matches.
RULESET_VERSION = "1"

#: Leading bytes of ``autorun.inf``, ``desktop.ini`` and ``.lnk`` files given to rules.
AUTORUN_READ_BYTES = 64 * 1024
INI_READ_BYTES = 64 * 1024
SHORTCUT_READ_BYTES = 256 * 1024

#: Extensions Windows runs, or hands to an interpreter, on a double-click.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".msi", ".jar", ".dll",
    }
)  # fmt: skip

# Extensions a person expects to be inert. A decoy first extension (invoice.pdf.exe) is
# drawn from the short list; the longer list is what executable content should never be
# found under.
_DECOY_EXTENSIONS = frozenset(
    {
        ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rtf",
        ".txt", ".odt", ".ods", ".odp", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".tif", ".tiff", ".mp3", ".wav", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".zip",
        ".rar", ".7z",
    }
)  # fmt: skip
_DATA_EXTENSIONS = _DECOY_EXTENSIONS | frozenset(
    {
        ".htm", ".html", ".xml", ".json", ".ini", ".log", ".ico", ".svg", ".webp", ".flac",
        ".ogg", ".m4a", ".epub", ".md",
    }
)  # fmt: skip

# What a same-named twin of a folder has to be for the folder-replacement trick to work:
# something a double-click launches. A library is not.
_LAUNCHABLE_EXTENSIONS = EXECUTABLE_EXTENSIONS - {".dll", ".jar"}

# Programs that run whatever their command line tells them to.
_INTERPRETERS = frozenset(
    {"cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"}
)
_INTERPRETER_IN_TEXT = re.compile(
    r"(?<![a-z0-9_.\-])(" + "|".join(sorted(_INTERPRETERS)) + r")(?:\.exe)?(?![a-z0-9_.\-])",
    re.IGNORECASE,
)
_COMSPEC = "%comspec%"

# Bidirectional embedding, override and isolate controls (U+202A..U+202E and
# U+2066..U+2069). U+202E, right-to-left override, is the one used in practice.
_BIDI_CONTROLS = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
# Characters that render as blank space: space, tab, no-break space and the Unicode
# spaces, plus the braille blank and the Hangul filler, both of which display as nothing.
_BLANKS = "".join(
    chr(code)
    for code in (
        0x09, 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x202F, 0x205F, 0x2800, 0x3000,
        0x3164,
    )
)  # fmt: skip
_PADDING_RUN = 5
_PADDING = re.compile("[" + re.escape(_BLANKS) + "]{" + str(_PADDING_RUN) + ",}")

_GUID = re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I)
_RECYCLE_BIN_CLSID = "{645ff040-5081-101b-9f08-00aa002f954e}"
_RECYCLE_BIN_FOLDERS = frozenset({"$recycle.bin", "recycler", "recycled"})
_KNOWN_CLSIDS = {
    _RECYCLE_BIN_CLSID: "Recycle Bin",
    "{0afaced1-e828-11d1-9187-b532f1e9575d}": "Folder Shortcut",
    "{21ec2020-3aea-1069-a2dd-08002b30309d}": "Control Panel",
    "{20d04fe0-3aea-1069-a2d8-08002b30309d}": "This PC",
    "{2227a280-3aea-1069-a2de-08002b30309d}": "Printers",
}

_DETAIL_CLIP = 200
_MAX_INI_LINES = 20_000
_MAX_INI_LINE_CHARS = 4096
_MAX_FINDINGS_PER_FILE = 16
# How many folders and how many launchers of one directory the folder rule remembers.
_MAX_TRACKED_NEIGHBOURS = 10_000
_MAX_RULE_ERRORS = 100


def _clip(text: str) -> str:
    return safe_text(text, _DETAIL_CLIP)


def _finding(
    entry: FileEntry, rule: str, severity: FindingSeverity, detail: str, sha256: str | None = None
) -> Finding:
    return Finding(entry.display_path, ENGINE_NAME, rule, severity, detail, sha256)


# -- content recognition ------------------------------------------------------------


def executable_format(head: bytes) -> str | None:
    """Name the native executable format that ``head`` starts with, if any.

    Recognises PE (and bare DOS ``MZ`` programs), ELF and Mach-O, including fat Mach-O
    binaries, which share their magic number with Java class files and are told apart
    by the architecture count that follows.

    Returns:
        ``"PE"``, ``"DOS executable"``, ``"ELF"`` or ``"Mach-O"``, or ``None``.
    """
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    ):  # fmt: skip
        return "Mach-O"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(head) >= 8:
        # A Java class file carries its version here (45 or more); a fat binary carries
        # the number of architectures (a handful).
        if 1 <= int.from_bytes(head[4:8], "big") <= 30:
            return "Mach-O"
        return None
    if head[:2] == b"MZ" and len(head) >= 64:
        pe_offset = int.from_bytes(head[60:64], "little")
        if pe_offset + 4 <= len(head):
            if head[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                return "PE"
        elif 64 <= pe_offset <= 0x1000:
            # The PE header lies past the bytes we hold; a stub of this size is normal.
            return "PE"
        # No PE header in sight. Plain text can start with "MZ"; a DOS header cannot be
        # free of zero bytes.
        if b"\x00" in head[2:64]:
            return "DOS executable"
    return None


def _stem(entry: FileEntry) -> str:
    """The entry's name without its extension, and without trailing dots and spaces."""
    trimmed = entry.name.rstrip(" .")
    if entry.extension and trimmed.lower().endswith(entry.extension):
        return trimmed[: len(trimmed) - len(entry.extension)]
    return trimmed


def is_executable(entry: FileEntry) -> bool:
    """True if the entry would run: by its extension, or by what its content is."""
    if entry.is_dir:
        return False
    return entry.extension in EXECUTABLE_EXTENSIONS or executable_format(entry.head) is not None


def _decode_text(data: bytes) -> str:
    """Decode configuration-file bytes the way Windows would, without ever failing."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", "replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    sample = data[1:512:2]
    if len(sample) >= 4 and sample.count(0) * 5 >= len(sample) * 4:
        # UTF-16 without a byte-order mark: every other byte is zero.
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Latin-1 maps every byte, so garbage padded around real lines still decodes.
        return data.decode("latin-1")


def _ini_entries(text: str) -> list[tuple[str, str, str]]:
    """``(section, key, value)`` for every ``key=value`` line; names are lowercased.

    Deliberately forgiving: worms pad these files with binary junk between the real
    lines, so anything that is not a section header or an assignment is skipped.
    """
    entries: list[tuple[str, str, str]] = []
    section = ""
    for number, raw in enumerate(text.splitlines()):
        if number >= _MAX_INI_LINES:
            break
        line = raw[:_MAX_INI_LINE_CHARS].replace("\x00", "").strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("["):
            end = line.find("]")
            if end > 0:
                section = line[1:end].strip().lower()
            continue
        key, separator, value = line.partition("=")
        if separator:
            entries.append((section, key.strip().lower(), value.strip()))
    return entries


@dataclass(frozen=True, slots=True)
class AutorunCommand:
    """One entry of an ``autorun.inf`` that names something to run.

    Attributes:
        key: the entry, lowercased: ``open``, ``shellexecute`` or ``shell\\<verb>\\command``.
        target: the command line or document the entry points at.
    """

    key: str
    target: str


_SHELL_COMMAND_KEY = re.compile(r"shell\\[^\\]+\\command\Z")


def parse_autorun_inf(data: bytes) -> tuple[AutorunCommand, ...]:
    """Extract the launch entries from the bytes of an ``autorun.inf``.

    Reads the ``[autorun]`` section and its architecture-specific variants. Tolerates
    binary padding, missing byte-order marks and any encoding; returns an empty tuple
    for input that holds no launch entry at all.
    """
    commands: list[AutorunCommand] = []
    for section, key, value in _ini_entries(_decode_text(data)):
        if section != "autorun" and not section.startswith("autorun."):
            continue
        if key in ("open", "shellexecute") or _SHELL_COMMAND_KEY.match(key):
            commands.append(AutorunCommand(key, value))
    return tuple(commands)


# -- the Shell Link (.lnk) binary format --------------------------------------------

_LNK_HEADER_SIZE = 0x4C
# CLSID 00021401-0000-0000-C000-000000000046, as stored on disk.
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_LNK_HAS_ID_LIST = 0x00000001
_LNK_HAS_LINK_INFO = 0x00000002
_LNK_IS_UNICODE = 0x00000080
# StringData fields in their on-disk order, with the LinkFlags bit that announces each.
_LNK_STRINGS = (
    (0x00000004, "description"),
    (0x00000008, "relative_path"),
    (0x00000010, "working_dir"),
    (0x00000020, "arguments"),
    (0x00000040, "icon_location"),
)
_LNK_ENVIRONMENT_BLOCK = 0xA0000001
_LNK_MAX_ID_ITEMS = 256
_LNK_MAX_EXTRA_BLOCKS = 64
_LNK_MAX_EVIDENCE = 512
_PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e]{3,260}")
_PRINTABLE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){3,260}")


class _Truncated(Exception):
    """The shortcut's structure runs past the bytes available."""


@dataclass(frozen=True, slots=True)
class ShellLink:
    """What a Windows shortcut says it will launch.

    Attributes:
        target: the best available path of the program or document, or ``None``.
        arguments: the command-line arguments, or ``None`` if the link has none.
        working_dir / relative_path / icon_location / description: the other strings.
        environment_target: the target as an environment-variable path, if present.
        id_list_path: the target as spelled out by the link's shell item list.
        evidence: every printable string found in the item list (short names, long
            names), kept for matching program names the structured fields miss.
        show_command: the window state requested (7 is "minimised, not activated").
        complete: False if the structure was cut off or inconsistent, in which case the
            fields hold whatever was parsed before that point.
    """

    target: str | None = None
    arguments: str | None = None
    working_dir: str | None = None
    relative_path: str | None = None
    icon_location: str | None = None
    description: str | None = None
    environment_target: str | None = None
    id_list_path: str | None = None
    evidence: tuple[str, ...] = ()
    show_command: int = 0
    complete: bool = True

    @property
    def target_candidates(self) -> tuple[str, ...]:
        """Every string that names the target, most trustworthy first."""
        # A bare string from the item list counts only if it names a program, so that a
        # folder which happens to be called "cmd" somewhere along the path does not.
        programs = (text for text in self.evidence if text.lower().endswith(".exe"))
        candidates = (
            self.target,
            self.environment_target,
            self.id_list_path,
            self.relative_path,
            *programs,
        )
        return tuple(dict.fromkeys(value for value in candidates if value))


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise _Truncated
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise _Truncated
    return int.from_bytes(data[offset : offset + 4], "little")


def _take(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise _Truncated
    return data[offset : offset + size]


def _c_string(data: bytes, offset: int, *, wide: bool) -> str | None:
    """A NUL-terminated string at ``offset``; ``None`` if the offset is out of range."""
    if offset <= 0 or offset >= len(data):
        return None
    if wide:
        end = offset
        while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", offset)
    return data[offset : end if end >= 0 else len(data)].decode("cp1252", "replace")


def _id_list(blob: bytes) -> tuple[str | None, tuple[str, ...]]:
    """The path spelled out by a shell item list, and every printable string in it."""
    names: list[str] = []
    position = 0
    for _ in range(_LNK_MAX_ID_ITEMS):
        if position + 2 > len(blob):
            break
        size = int.from_bytes(blob[position : position + 2], "little")
        if size < 3 or position + size > len(blob):
            # Zero is the terminator; anything else this small or this large is damage.
            break
        item = blob[position + 2 : position + size]
        position += size
        kind = item[0] & 0x70
        if kind == 0x20:
            # A volume item: "C:\" as an ANSI string.
            name = item[1:].split(b"\x00", 1)[0].decode("cp1252", "replace").rstrip("\\")
        elif kind == 0x30 and len(item) > 12:
            # A file or directory item: the name follows twelve bytes of size, date,
            # time and attributes, as UTF-16 when the low type bits say so.
            if item[0] & 0x04:
                name = _c_string(item, 12, wide=True) or ""
            else:
                name = item[12:].split(b"\x00", 1)[0].decode("cp1252", "replace")
        else:
            continue
        if name:
            names.append(name)
    strings = [match.decode("ascii") for match in _PRINTABLE_ASCII.findall(blob)]
    strings += [match.decode("utf-16-le") for match in _PRINTABLE_UTF16.findall(blob)]
    evidence = tuple(dict.fromkeys(strings))[:_LNK_MAX_EVIDENCE]
    return ("\\".join(names) if names else None), evidence


def _link_info_path(info: bytes) -> str | None:
    """The target path recorded in a LinkInfo structure, local or on a network share."""
    header_size = _u32(info, 4)
    flags = _u32(info, 8)
    wide = header_size >= 0x24
    suffix = (_c_string(info, _u32(info, 32), wide=True) if wide else None) or _c_string(
        info, _u32(info, 24), wide=False
    )
    base: str | None = None
    if flags & 0x1:
        base = (_c_string(info, _u32(info, 28), wide=True) if wide else None) or _c_string(
            info, _u32(info, 16), wide=False
        )
    elif flags & 0x2:
        network_offset = _u32(info, 20)
        if 0 < network_offset < len(info):
            network = info[network_offset:]
            base = _c_string(network, _u32(network, 8), wide=False)
            if base and suffix:
                base += "\\"
    if base is None:
        return None
    return base + (suffix or "")


def parse_shell_link(data: bytes) -> ShellLink | None:
    """Parse the leading bytes of a ``.lnk`` file far enough to see what it launches.

    Follows the Shell Link binary format ([MS-SHLLINK]): the header, the optional item
    list and LinkInfo, the string data, and the environment-variable block of the extra
    data. Every offset and size comes from the file and is checked against the bytes
    actually present; a link that is cut short or inconsistent yields what was parsed up
    to that point with ``complete`` set to False. Nothing in a file can make this raise.

    Returns:
        The parsed link, or ``None`` if the data does not begin with a Shell Link header.
    """
    if (
        len(data) < _LNK_HEADER_SIZE
        or int.from_bytes(data[:4], "little") != _LNK_HEADER_SIZE
        or data[4:20] != _LNK_CLSID
    ):
        return None
    flags = int.from_bytes(data[20:24], "little")
    fields: dict[str, str | None] = {}
    evidence: tuple[str, ...] = ()
    complete = True
    position = _LNK_HEADER_SIZE
    try:
        if flags & _LNK_HAS_ID_LIST:
            size = _u16(data, position)
            fields["id_list_path"], evidence = _id_list(_take(data, position + 2, size))
            position += 2 + size
        if flags & _LNK_HAS_LINK_INFO:
            size = _u32(data, position)
            if size < 4:
                raise _Truncated
            info = _take(data, position, size)
            position += size
            try:
                fields["target"] = _link_info_path(info)
            except _Truncated:
                # The LinkInfo block is damaged inside, but its declared size was
                # honoured, so the strings after it can still be read.
                complete = False
        wide = bool(flags & _LNK_IS_UNICODE)
        for bit, name in _LNK_STRINGS:
            if not flags & bit:
                continue
            count = _u16(data, position)
            raw = _take(data, position + 2, count * 2 if wide else count)
            position += 2 + len(raw)
            fields[name] = raw.decode("utf-16-le" if wide else "cp1252", "replace")
        for _ in range(_LNK_MAX_EXTRA_BLOCKS):
            if position + 4 > len(data):
                break
            size = _u32(data, position)
            if size < 4:
                break
            block = _take(data, position, size)
            position += size
            if size >= 8 + 260 and _u32(block, 4) == _LNK_ENVIRONMENT_BLOCK:
                ansi = _c_string(block, 8, wide=False)
                unicode_target = _c_string(block, 8 + 260, wide=True) if size >= 788 else None
                fields["environment_target"] = unicode_target or ansi
    except _Truncated:
        complete = False
    return ShellLink(
        target=fields.get("target") or fields.get("environment_target"),
        arguments=fields.get("arguments"),
        working_dir=fields.get("working_dir"),
        relative_path=fields.get("relative_path"),
        icon_location=fields.get("icon_location"),
        description=fields.get("description"),
        environment_target=fields.get("environment_target"),
        id_list_path=fields.get("id_list_path"),
        evidence=evidence,
        show_command=int.from_bytes(data[60:64], "little"),
        complete=complete,
    )


def _interpreter_named_by(path: str) -> str | None:
    """The interpreter a target path names (``cmd`` for ``C:\\...\\cmd.exe``), if any."""
    cleaned = path.strip().strip('"').strip()
    if _COMSPEC in cleaned.lower():
        return "cmd"
    base = re.split(r"[\\/]", cleaned)[-1].rstrip(" .").lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base if base in _INTERPRETERS else None


# -- rules that look at one entry ---------------------------------------------------


def rule_autorun_inf(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """``autorun.inf`` at the volume root.

    Technique: AutoRun/AutoPlay abuse (MITRE ATT&CK T1091, replication through removable
    media). Windows reads this file when a volume is mounted; its ``open=``,
    ``shellexecute=`` and ``shell\\verb\\command=`` entries name a program to run, or to
    offer in the AutoPlay dialog under a label the file also supplies. Conficker and
    most USB worms before it spread this way. Each launch entry is reported with its
    target. The file's mere presence is reported as ``info``: a label and an icon are
    harmless, and since Windows 7 the launch entries are ignored for USB storage.
    """
    if entry.is_dir or entry.depth != 0 or entry.name.lower() != "autorun.inf":
        return []
    if content is None:
        return [
            _finding(
                entry,
                "autorun.present",
                FindingSeverity.INFO,
                "autorun.inf at the volume root; its content was not read",
            )
        ]
    commands = parse_autorun_inf(content)
    if not commands:
        return [
            _finding(
                entry,
                "autorun.present",
                FindingSeverity.INFO,
                "autorun.inf at the volume root with no launch entries",
            )
        ]
    return [
        _finding(
            entry,
            "autorun.launch",
            FindingSeverity.SUSPICIOUS,
            f"autorun.inf {_clip(command.key)}= runs {_clip(command.target) or '(nothing)'}",
        )
        for command in commands[:_MAX_FINDINGS_PER_FILE]
    ]


def rule_root_executable(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """An executable or script sitting at the volume root.

    Technique: user execution of a planted file (T1204.002) and removable-media
    replication (T1091). The root is what a person sees first on opening a drive, so
    that is where worms and "found USB stick" lures put their payload. Matched by the
    extensions Windows runs on a double-click, and by PE, ELF and Mach-O content
    whatever the name says. Installers and portable tools legitimately live here too,
    hence ``suspicious`` and no more.
    """
    if entry.is_dir or entry.depth != 0:
        return []
    kind = executable_format(entry.head)
    if entry.extension in EXECUTABLE_EXTENSIONS:
        what = f"{entry.extension} file" + (f" ({kind})" if kind else "")
    elif kind is not None:
        what = f"{kind} program under the name of a {entry.extension or 'plain'} file"
    else:
        return []
    return [
        _finding(entry, "root.executable", FindingSeverity.SUSPICIOUS, f"{what} at the volume root")
    ]


def rule_deceptive_name(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """A file name built to hide that the file is executable.

    Technique: masquerading (T1036). Three variants, each reported separately:

    * a decoy extension before the real one, ``invoice.pdf.exe`` (T1036.007); Windows
      hides known extensions by default, so the user sees ``invoice.pdf``;
    * a long run of blanks before the real extension, pushing it out of the visible
      part of the name;
    * a right-to-left override or another bidirectional control (T1036.002), which makes
      ``photo<RLO>gpj.exe`` display as ``photoexe.jpg``. No legitimate program is named
      with one, so on an executable this is reported as ``malicious``; on any other file
      it is noted as ``info``.
    """
    if entry.is_dir:
        return []
    name = entry.name
    executable = is_executable(entry)
    findings: list[Finding] = []
    if any(char in _BIDI_CONTROLS for char in name):
        if executable:
            findings.append(
                _finding(
                    entry,
                    "name.bidi_override",
                    FindingSeverity.MALICIOUS,
                    "executable whose name uses a right-to-left override to disguise "
                    f"its extension ({entry.extension or 'by content'})",
                )
            )
        else:
            findings.append(
                _finding(
                    entry,
                    "name.bidi_override",
                    FindingSeverity.INFO,
                    "name contains a bidirectional control character",
                )
            )
    if entry.extension not in EXECUTABLE_EXTENSIONS:
        return findings
    decoy = extension_of(_stem(entry).rstrip(_BLANKS + "."))
    if decoy in _DECOY_EXTENSIONS:
        findings.append(
            _finding(
                entry,
                "name.double_extension",
                FindingSeverity.SUSPICIOUS,
                f"{entry.extension} file presented as a {decoy} file",
            )
        )
    if _PADDING.search(name):
        findings.append(
            _finding(
                entry,
                "name.padded_extension",
                FindingSeverity.SUSPICIOUS,
                f"name is padded with blanks that push the {entry.extension} extension out of view",
            )
        )
    return findings


def rule_type_mismatch(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """Executable content under a document, picture, media or archive extension.

    Technique: masquerading the file type (T1036.008). A PE, ELF or Mach-O file named
    ``.jpg`` will not run on a double-click; it is a payload parked where a loader
    (typically a shortcut running ``rundll32`` or a script) will find it and where a
    person, or a filter keyed on extensions, will not look. Only extensions that are
    never legitimately executable are matched, to stay clear of the many odd
    extensions software uses for its own libraries.
    """
    if entry.is_dir or entry.extension not in _DATA_EXTENSIONS:
        return []
    kind = executable_format(entry.head)
    if kind is None:
        return []
    return [
        _finding(
            entry,
            "type.mismatch",
            FindingSeverity.SUSPICIOUS,
            f"content is a {kind} program but the name says {entry.extension}",
        )
    ]


def rule_hidden_executable(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """An executable carrying the hidden or system attribute.

    Technique: hidden files and directories (T1564.001). A worm marks its copy hidden
    and system so that Explorer, with default settings, does not show it, while the
    shortcut or autorun entry that launches it stays visible. Software distributed on
    removable media has no reason to hide its programs.
    """
    if entry.is_dir or not (entry.hidden or entry.system) or not is_executable(entry):
        return []
    marks = " and ".join(
        label for label, value in (("hidden", entry.hidden), ("system", entry.system)) if value
    )
    kind = entry.extension if entry.extension in EXECUTABLE_EXTENSIONS else None
    what = f"{kind} file" if kind else f"{executable_format(entry.head)} program"
    return [
        _finding(entry, "hidden.executable", FindingSeverity.SUSPICIOUS, f"{what} marked {marks}")
    ]


def rule_shortcut(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """A Windows shortcut that launches a command interpreter or script host.

    Technique: shortcut abuse (T1204.002 user execution through a malicious link, with
    T1059 command and scripting interpreters and T1218 signed-binary proxy execution).
    USB worms replace the user's folders with shortcuts whose target is ``cmd.exe``,
    ``powershell``, ``wscript``, ``cscript``, ``mshta``, ``rundll32`` or ``regsvr32``,
    with arguments that start the hidden payload and then open the real folder. The
    target is read from every place the format can hold it (LinkInfo, the item list, the
    environment-variable block, the relative path) and the arguments are searched too.
    A ``.lnk`` that cannot be parsed is noted as ``info``.
    """
    if entry.is_dir or entry.extension != ".lnk" or content is None:
        return []
    link = parse_shell_link(content)
    if link is None:
        return [
            _finding(
                entry,
                "shortcut.malformed",
                FindingSeverity.INFO,
                ".lnk file that is not a valid Windows shortcut",
            )
        ]
    interpreter: str | None = None
    target = next(iter(link.target_candidates), "(none)")
    for candidate in link.target_candidates:
        interpreter = _interpreter_named_by(candidate)
        if interpreter:
            target = candidate
            break
    arguments = link.arguments or ""
    in_arguments = _INTERPRETER_IN_TEXT.search(arguments)
    if interpreter is None and in_arguments is None and _COMSPEC not in arguments.lower():
        if link.complete:
            return []
        return [
            _finding(
                entry,
                "shortcut.malformed",
                FindingSeverity.INFO,
                "shortcut is cut short or inconsistent; its target could not be fully read",
            )
        ]
    launched = interpreter or (in_arguments.group(1).lower() if in_arguments else "cmd")
    detail = f"shortcut launches {launched}: target={_clip(target)}"
    if arguments:
        detail += f" arguments={_clip(' '.join(arguments.split()))}"
        if _PADDING.search(arguments):
            detail += " (arguments padded with blanks to hide the command)"
    return [_finding(entry, "shortcut.interpreter", FindingSeverity.SUSPICIOUS, detail)]


def rule_desktop_ini(entry: FileEntry, content: bytes | None) -> list[Finding]:
    """``desktop.ini`` that turns its folder into a shell object through a CLSID.

    Technique: hiding artifacts (T1564) and masquerading. A ``CLSID``, ``CLSID2`` or
    ``UICLSID`` entry under ``[.ShellClassInfo]`` makes Explorer present the folder as
    the shell object with that class id: a "Folder Shortcut" that opens somewhere else,
    or the Recycle Bin or Control Panel, so that what is really inside (usually the
    payload) cannot be browsed. The one expected case, the Recycle Bin's own class id
    inside a recycle-bin folder, is not reported.
    """
    if entry.is_dir or content is None or entry.name.lower() != "desktop.ini":
        return []
    findings: list[Finding] = []
    top_folder = entry.path.split("/", 1)[0].lower()
    for section, key, value in _ini_entries(_decode_text(content)):
        if section != ".shellclassinfo" or key not in ("clsid", "clsid2", "uiclsid"):
            continue
        match = _GUID.search(value)
        if match is None:
            continue
        clsid = match.group(0).lower()
        if clsid == _RECYCLE_BIN_CLSID and entry.depth > 0 and top_folder in _RECYCLE_BIN_FOLDERS:
            continue
        label = _KNOWN_CLSIDS.get(clsid)
        findings.append(
            _finding(
                entry,
                "desktopini.clsid",
                FindingSeverity.SUSPICIOUS,
                f"desktop.ini redirects its folder with {key.upper()}={clsid}"
                + (f" ({label})" if label else ""),
            )
        )
        if len(findings) >= _MAX_FINDINGS_PER_FILE:
            break
    return findings


# -- the rule that compares neighbours ----------------------------------------------


class FolderMasquerade:
    """A folder with a same-named shortcut or program beside it.

    Technique: the folder-replacement trick of USB worms (T1091 with T1036 and
    T1564.001). The worm hides each of the user's folders and drops, next to it, a
    ``.lnk`` or an ``.exe`` with a folder icon and the folder's name. The user opens
    "their folder", runs the worm, and the worm opens the real folder so nothing seems
    wrong.

    A same-named launcher beside a visible folder is ``suspicious``: a program next to
    its own data folder looks the same. Beside a folder that is hidden or marked system
    the two signs corroborate each other, which an ordinary volume does not show, so
    that is reported as ``malicious``.

    The rule sees entries one at a time and relies on the walk yielding a directory's
    entries together (it does: the walk is breadth-first, one directory at a time).
    It therefore holds one directory's folders and launchers in memory, no more, and at
    most ten thousand of each: in a directory larger than that, built to exhaust
    memory, the entries beyond the first ten thousand are not compared.
    """

    rule_id = "folder.masquerade"

    def __init__(self) -> None:
        self._parent: str | None = None
        self._folders: dict[str, bool] = {}
        self._launchers: list[tuple[str, str, str, str | None, str | None]] = []

    def observe(
        self, entry: FileEntry, sha256: str | None = None, trusted_by: str | None = None
    ) -> list[Finding]:
        """Take the next entry; returns findings for the directory just completed.

        Args:
            entry: the entry, as the walk produced it.
            sha256: the file's digest, if known; attached to a finding about it.
            trusted_by: if the file is vouched for (it is on a known-good list), a few
                words saying by what. A match is then noted as ``info`` only.
        """
        findings: list[Finding] = []
        if entry.parent != self._parent:
            findings = self.finish()
            self._parent = entry.parent
        if entry.is_dir:
            if len(self._folders) < _MAX_TRACKED_NEIGHBOURS:
                self._folders[entry.name.casefold()] = bool(entry.hidden or entry.system)
        elif (
            entry.extension in _LAUNCHABLE_EXTENSIONS
            and len(self._launchers) < _MAX_TRACKED_NEIGHBOURS
        ):
            stem = _stem(entry).rstrip().casefold()
            self._launchers.append((stem, entry.display_path, entry.extension, sha256, trusted_by))
        return findings

    def finish(self) -> list[Finding]:
        """Report on the current directory and forget it."""
        findings: list[Finding] = []
        for stem, path, extension, sha256, trusted_by in self._launchers:
            concealed = self._folders.get(stem)
            if concealed is None:
                continue
            detail = (
                f"{extension} file with the same name as a "
                f"{'hidden ' if concealed else ''}folder beside it"
            )
            if trusted_by is not None:
                severity = FindingSeverity.INFO
                detail += f"; not counted against the volume because the file is {trusted_by}"
            elif concealed:
                severity = FindingSeverity.MALICIOUS
            else:
                severity = FindingSeverity.SUSPICIOUS
            findings.append(Finding(path, ENGINE_NAME, self.rule_id, severity, detail, sha256))
        self._folders = {}
        self._launchers = []
        return findings


# -- the engine ---------------------------------------------------------------------


def _wants_autorun(entry: FileEntry) -> int:
    at_root = entry.depth == 0 and not entry.is_dir
    return AUTORUN_READ_BYTES if at_root and entry.name.lower() == "autorun.inf" else 0


def _wants_shortcut(entry: FileEntry) -> int:
    return SHORTCUT_READ_BYTES if not entry.is_dir and entry.extension == ".lnk" else 0


def _wants_desktop_ini(entry: FileEntry) -> int:
    return INI_READ_BYTES if not entry.is_dir and entry.name.lower() == "desktop.ini" else 0


def _wants_nothing(entry: FileEntry) -> int:
    return 0


@dataclass(frozen=True, slots=True)
class Rule:
    """One heuristic.

    Attributes:
        rule_id: a stable identifier; the rule's findings use it or a refinement of it.
        check: the rule: ``(entry, content) -> findings``. ``content`` is ``None`` when
            the rule asked for none or the file could not be read.
        wants: how many leading bytes of the file the rule needs for this entry.
    """

    rule_id: str
    check: Callable[[FileEntry, bytes | None], list[Finding]]
    wants: Callable[[FileEntry], int] = field(default=_wants_nothing)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("autorun", rule_autorun_inf, _wants_autorun),
    Rule("root.executable", rule_root_executable),
    Rule("name", rule_deceptive_name),
    Rule("type.mismatch", rule_type_mismatch),
    Rule("hidden.executable", rule_hidden_executable),
    Rule("shortcut", rule_shortcut, _wants_shortcut),
    Rule("desktopini", rule_desktop_ini, _wants_desktop_ini),
)


class HeuristicSession:
    """The heuristics applied to one scan. Not shared between scans or threads.

    Attributes:
        errors: ``(rule id, display path, message)`` for each time a rule raised (the
            first hundred). A rule is not supposed to, whatever the input; if one does,
            the other rules and the rest of the scan are unaffected and the failure is
            reported here.
        errors_dropped: how many further rule failures were counted but not stored.
    """

    def __init__(self, rules: Sequence[Rule], folder_rule: bool) -> None:
        self._rules = tuple(rules)
        self._folders = FolderMasquerade() if folder_rule else None
        self.errors: list[tuple[str, str, str]] = []
        self.errors_dropped = 0

    def inspect(
        self,
        entry: FileEntry,
        content: bytes | None = None,
        sha256: str | None = None,
        *,
        trusted_by: str | None = None,
    ) -> list[Finding]:
        """Run every rule on one entry.

        Args:
            entry: the entry, as the walk produced it.
            content: the leading bytes of the file, at least as many as
                :meth:`HeuristicEngine.content_wanted` asked for, or ``None``.
            sha256: the file's digest, if known; attached to the findings.
            trusted_by: if this exact file is vouched for (its digest is on a
                known-good list), a few words saying by what. The rules still run, but
                what they would have reported is replaced by a single ``info`` finding
                that says how many findings were suppressed and why, so the suppression
                is itself on the record.

        Returns:
            Findings about this entry, plus any the folder rule had pending for the
            directory that the walk has just left.
        """
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                produced = rule.check(entry, content)
            except Exception as exc:  # one faulty rule must not cost the whole scan
                if len(self.errors) < _MAX_RULE_ERRORS:
                    self.errors.append((rule.rule_id, entry.display_path, type(exc).__name__))
                else:
                    self.errors_dropped += 1
                continue
            findings.extend(_with_digest(produced, sha256))
        if trusted_by is not None and findings:
            findings = [
                Finding(
                    entry.display_path,
                    ENGINE_NAME,
                    "suppressed.known_good",
                    FindingSeverity.INFO,
                    f"{len(findings)} heuristic finding(s) suppressed "
                    f"({', '.join(sorted({item.rule for item in findings}))}): "
                    f"the file is {trusted_by}",
                    sha256,
                )
            ]
        if self._folders is not None:
            findings.extend(self._folders.observe(entry, sha256, trusted_by))
        return findings

    def finish(self) -> list[Finding]:
        """Flush what the folder rule still holds. Call once, after the last entry."""
        return self._folders.finish() if self._folders is not None else []


def _with_digest(findings: Iterable[Finding], sha256: str | None) -> list[Finding]:
    if sha256 is None:
        return list(findings)
    return [
        Finding(item.path, item.engine, item.rule, item.severity, item.detail, sha256)
        for item in findings
    ]


class HeuristicEngine:
    """The configured set of heuristic rules.

    Args:
        rules: the per-entry rules to apply; :data:`DEFAULT_RULES` if omitted.
        folder_rule: whether to apply :class:`FolderMasquerade` as well.
    """

    name = ENGINE_NAME

    def __init__(self, rules: Sequence[Rule] | None = None, *, folder_rule: bool = True) -> None:
        self._rules = tuple(DEFAULT_RULES if rules is None else rules)
        self._folder_rule = folder_rule

    def version(self) -> str:
        """The rule-set version, reported alongside the engine in every scan report."""
        return RULESET_VERSION

    def content_wanted(self, entry: FileEntry) -> int:
        """How many leading bytes of ``entry`` the rules need (0 for most files)."""
        wanted = 0
        for rule in self._rules:
            try:
                wanted = max(wanted, rule.wants(entry))
            except Exception:  # noqa: S112 - a faulty rule simply gets no content
                continue
        return wanted

    def session(self) -> HeuristicSession:
        """Start the heuristics for one scan."""
        return HeuristicSession(self._rules, self._folder_rule)
