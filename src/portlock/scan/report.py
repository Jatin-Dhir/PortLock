"""What a scan found, and the one-word verdict derived from it.

A :class:`ScanReport` is an immutable record of one scan: what was looked at, what was
found, what could not be looked at, and which engines took part. The verdict is *derived*
from that content rather than stored, so a report can never claim "clean" while also
listing a detection or an unread file.

Verdict rules, in order (the first that applies wins):

1. ``malicious`` if any finding is malicious.
2. ``suspicious`` if any finding is suspicious.
3. ``error`` if an engine failed or the scan itself could not run
   (an issue of kind ``failed``).
4. ``incomplete`` if a limit, a cancellation or an unreadable file meant that part of the
   volume was not examined (``truncated`` is set, or an issue of kind ``unread`` exists).
5. ``clean`` otherwise.

A scan that did not look at everything is therefore never reported as ``clean``, and an
engine that failed never turns into ``clean`` either. ``info`` findings are observations
and do not change the verdict.

The verdict names the worst thing *found*; it does not say whether the scan was
thorough. A report can be ``suspicious`` and also truncated, or ``malicious`` with an
engine that failed. :attr:`ScanReport.complete` answers that second question on its own,
for callers that treat an unfinished scan more strictly than a finished one.

**Device text.** Everything on a scanned volume was chosen by whoever wrote it: file
names, the label and launch targets in an ``autorun.inf``, shortcut targets, folder
settings, and the antivirus output that quotes them. That text is untrusted in the same
way as a device's descriptor strings (docs/DESIGN.md, section 14.7). It is made safe in
one place: :func:`safe_text`, applied by the constructors of :class:`Finding`,
:class:`ScanIssue`, :class:`EngineStatus` and :class:`ScanReport` (and of
``scanner.ScanProgress``), so no engine can put a raw hostile string into a report by
forgetting to escape it. :func:`safe_text` does for display what
``portlock.core.models.sanitize_device_text`` does for descriptor strings, except that it
shows an unsafe character as a visible escape instead of replacing it, because the
operator may need to see exactly how a file name was disguised. A report is therefore
always safe to print, log and encode as JSON.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from portlock.core.clock import parse_utc_iso, utc_iso

__all__ = [
    "MAX_DETAIL_CHARS",
    "MAX_PATH_CHARS",
    "EngineStatus",
    "Finding",
    "FindingSeverity",
    "IssueKind",
    "ScanIssue",
    "ScanReport",
    "Verdict",
    "decide_verdict",
    "safe_text",
]

#: Longest path and detail text a finding or issue keeps. Hostile names and tool output
#: are cut to these lengths so one finding cannot bloat a report.
MAX_PATH_CHARS = 2048
MAX_DETAIL_CHARS = 1024

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.\-]{0,63}\Z")

_SURROGATE_ESCAPE_FIRST = 0xDC80
_SURROGATE_ESCAPE_LAST = 0xDCFF
_ELLIPSIS = "..."


def safe_text(text: str, limit: int | None = None) -> str:
    """Return ``text`` with every character that could corrupt or spoof a display escaped.

    Everything Unicode does not class as printable is replaced by a visible ASCII
    escape: control characters, format characters (this is where right-to-left overrides
    and zero-width characters live), line separators, every space other than the plain
    one, private-use and unassigned code points, and lone surrogates. A byte that could
    not be decoded (carried by Python as a ``surrogateescape`` code point) is shown as
    the byte it was. Letters of any script pass through.

    The result is well-formed Unicode, ``str.isprintable()`` is true of it, and applying
    the function twice changes nothing.

    Args:
        text: any string, including one holding lone surrogates.
        limit: if given, the result is cut to at most this many characters, ending in
            ``...`` when something was removed.
    """
    if text.isprintable():
        escaped = text
    else:
        parts: list[str] = []
        for char in text:
            code = ord(char)
            if char.isprintable():
                parts.append(char)
            elif _SURROGATE_ESCAPE_FIRST <= code <= _SURROGATE_ESCAPE_LAST:
                parts.append(f"\\x{code - 0xDC00:02x}")
            elif code < 0x100:
                parts.append(f"\\x{code:02x}")
            elif code < 0x10000:
                parts.append(f"\\u{code:04x}")
            else:
                parts.append(f"\\U{code:08x}")
        escaped = "".join(parts)
    if limit is not None and len(escaped) > limit:
        keep = max(0, limit - len(_ELLIPSIS))
        return escaped[:keep] + _ELLIPSIS[: limit - keep]
    return escaped


class FindingSeverity(enum.StrEnum):
    """How serious one finding is."""

    #: An observation worth recording that does not, by itself, call for action.
    INFO = "info"
    #: A person should look at this. Heuristics report at this level unless the
    #: evidence is strong.
    SUSPICIOUS = "suspicious"
    #: A known-bad hash, an antivirus detection, or a heuristic with strong evidence.
    MALICIOUS = "malicious"


class Verdict(enum.StrEnum):
    """The outcome of a scan in one word. See the module docstring for the rules."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class IssueKind(enum.StrEnum):
    """Why something is listed under a report's ``errors``."""

    #: Part of the volume could not be examined (permission denied, a file vanished, a
    #: read failed). The scan carried on; the verdict cannot be ``clean``.
    UNREAD = "unread"
    #: An engine failed, or the scan as a whole could not run.
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing an engine noticed about one file.

    Attributes:
        path: the file, relative to the scan root, with ``/`` separators. Empty when the
            finding is about the root itself.
        engine: which engine reported it, e.g. ``heuristics``, ``hashset``, ``clamav``.
        rule: the engine's own identifier for what matched (a heuristic rule id, a hash
            list label, an antivirus signature name).
        severity: see :class:`FindingSeverity`.
        detail: one line for a person.
        sha256: the file's SHA-256 in lowercase hex, when it was computed.

    Raises:
        ValueError: if the severity is unknown, the engine name is not a short lowercase
            identifier, or ``sha256`` is not 64 lowercase hex digits.
    """

    path: str
    engine: str
    rule: str
    severity: FindingSeverity
    detail: str = ""
    sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.engine, str) or not _NAME_PATTERN.match(self.engine):
            raise ValueError(f"invalid engine name: {self.engine!r}")
        if self.sha256 is not None and (
            not isinstance(self.sha256, str) or not _SHA256_PATTERN.match(self.sha256)
        ):
            raise ValueError("sha256 must be 64 lowercase hex digits")
        object.__setattr__(self, "severity", FindingSeverity(self.severity))
        # Sanitised here, at the type boundary, so no engine can put a raw hostile name
        # or raw tool output into a report by forgetting to escape it.
        object.__setattr__(self, "path", safe_text(str(self.path), MAX_PATH_CHARS))
        object.__setattr__(self, "rule", safe_text(str(self.rule), MAX_DETAIL_CHARS))
        object.__setattr__(self, "detail", safe_text(str(self.detail), MAX_DETAIL_CHARS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "engine": self.engine,
            "rule": self.rule,
            "severity": self.severity.value,
            "detail": self.detail,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        """Rebuild a finding from :meth:`to_dict` output.

        Raises:
            KeyError, ValueError: if a field is missing or invalid.
        """
        return cls(
            path=str(data["path"]),
            engine=str(data["engine"]),
            rule=str(data["rule"]),
            severity=FindingSeverity(data["severity"]),
            detail=str(data.get("detail", "")),
            sha256=data.get("sha256"),
        )


@dataclass(frozen=True, slots=True)
class ScanIssue:
    """Something that kept the scan from examining part of the volume, or from running.

    Attributes:
        source: who reports it: ``walk``, ``hash``, ``heuristics``, ``scan`` or an
            engine name.
        path: the file or directory concerned, relative to the scan root; empty when the
            issue is not about one path.
        message: what went wrong, for the operator.
        kind: see :class:`IssueKind`.
    """

    source: str
    path: str
    message: str
    kind: IssueKind = IssueKind.UNREAD

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", IssueKind(self.kind))
        object.__setattr__(self, "source", safe_text(str(self.source), 64))
        object.__setattr__(self, "path", safe_text(str(self.path), MAX_PATH_CHARS))
        object.__setattr__(self, "message", safe_text(str(self.message), MAX_DETAIL_CHARS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "path": self.path,
            "message": self.message,
            "kind": self.kind.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanIssue:
        return cls(
            source=str(data["source"]),
            path=str(data.get("path", "")),
            message=str(data["message"]),
            kind=IssueKind(data.get("kind", IssueKind.UNREAD.value)),
        )


@dataclass(frozen=True, slots=True)
class EngineStatus:
    """Whether one engine took part in a scan.

    Attributes:
        name: the engine's name.
        available: False if the engine is not installed or cannot be used here. An
            unavailable engine contributes nothing; it is listed so the reader knows
            which engines the verdict rests on.
        version: the engine's own version string, when it could be determined.
    """

    name: str
    available: bool
    version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", safe_text(str(self.name), 64))
        object.__setattr__(self, "available", bool(self.available))
        if self.version is not None:
            object.__setattr__(self, "version", safe_text(str(self.version), 200))

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "available": self.available, "version": self.version}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EngineStatus:
        return cls(str(data["name"]), bool(data["available"]), data.get("version"))


def decide_verdict(
    findings: Iterable[Finding], truncated: bool, errors: Iterable[ScanIssue]
) -> Verdict:
    """Apply the verdict rules from the module docstring.

    Args:
        findings: everything the engines reported.
        truncated: True if a limit or a cancellation cut the scan short.
        errors: everything that could not be examined or that failed.
    """
    severities = {finding.severity for finding in findings}
    if FindingSeverity.MALICIOUS in severities:
        return Verdict.MALICIOUS
    if FindingSeverity.SUSPICIOUS in severities:
        return Verdict.SUSPICIOUS
    kinds = {issue.kind for issue in errors}
    if IssueKind.FAILED in kinds:
        return Verdict.ERROR
    if truncated or IssueKind.UNREAD in kinds:
        return Verdict.INCOMPLETE
    return Verdict.CLEAN


@dataclass(frozen=True, slots=True)
class ScanReport:
    """The complete result of one scan.

    Attributes:
        root: what was scanned, as given by the caller (escaped for display).
        started_at / finished_at: timezone-aware UTC times from the injected clock.
        files_seen: files and links met during the walk (directories are not counted).
        files_hashed: files whose SHA-256 was computed in full.
        bytes_hashed: bytes read for those hashes.
        findings: what the engines reported.
        truncated: True if a limit or a cancellation stopped the scan before it had
            examined everything.
        truncated_reason: which limits, e.g. ``max_files`` or ``max_depth, max_seconds``;
            ``None`` when not truncated.
        errors: files that could not be read, and engines that failed.
        engines: every engine that was configured, with availability and version.

    Raises:
        ValueError: if a time is not a timezone-aware datetime, a counter is negative,
            or ``truncated`` and ``truncated_reason`` disagree.
    """

    root: str
    started_at: datetime
    finished_at: datetime
    files_seen: int = 0
    files_hashed: int = 0
    bytes_hashed: int = 0
    findings: tuple[Finding, ...] = ()
    truncated: bool = False
    truncated_reason: str | None = None
    errors: tuple[ScanIssue, ...] = ()
    engines: tuple[EngineStatus, ...] = ()

    def __post_init__(self) -> None:
        for name in ("started_at", "finished_at"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime) or moment.utcoffset() is None:
                raise ValueError(f"{name} must be a timezone-aware datetime, got {moment!r}")
        for name in ("files_seen", "files_hashed", "bytes_hashed"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
        if bool(self.truncated) != (self.truncated_reason is not None):
            raise ValueError("truncated and truncated_reason must be given together")
        object.__setattr__(self, "root", safe_text(str(self.root), MAX_PATH_CHARS))
        object.__setattr__(self, "truncated", bool(self.truncated))
        if self.truncated_reason is not None:
            object.__setattr__(self, "truncated_reason", safe_text(self.truncated_reason, 200))
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "errors", tuple(self.errors))
        object.__setattr__(self, "engines", tuple(self.engines))

    @property
    def verdict(self) -> Verdict:
        """The outcome in one word, derived from the findings, truncation and errors."""
        return decide_verdict(self.findings, self.truncated, self.errors)

    @property
    def complete(self) -> bool:
        """True if nothing was skipped: no limit hit, no unread file, no failed engine."""
        return not self.truncated and not self.errors

    @property
    def worst_severity(self) -> FindingSeverity | None:
        """The most serious severity among the findings, or ``None`` if there are none."""
        order = (FindingSeverity.MALICIOUS, FindingSeverity.SUSPICIOUS, FindingSeverity.INFO)
        present = {finding.severity for finding in self.findings}
        return next((severity for severity in order if severity in present), None)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable form (for the API, the audit log and the state store)."""
        return {
            "root": self.root,
            "started_at": utc_iso(self.started_at),
            "finished_at": utc_iso(self.finished_at),
            "files_seen": self.files_seen,
            "files_hashed": self.files_hashed,
            "bytes_hashed": self.bytes_hashed,
            "findings": [finding.to_dict() for finding in self.findings],
            "truncated": self.truncated,
            "truncated_reason": self.truncated_reason,
            "errors": [issue.to_dict() for issue in self.errors],
            "engines": [engine.to_dict() for engine in self.engines],
            "verdict": self.verdict.value,
            "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanReport:
        """Rebuild a report from :meth:`to_dict` output.

        The stored ``verdict`` is checked against the one derived from the content, so a
        record edited to say ``clean`` while still listing a detection is rejected. The
        stored ``complete`` is ignored: it is always derived.

        Raises:
            KeyError, ValueError: if a field is missing or invalid, or the stored
                verdict does not match the content.
        """
        report = cls(
            root=str(data["root"]),
            started_at=parse_utc_iso(data["started_at"]),
            finished_at=parse_utc_iso(data["finished_at"]),
            files_seen=data["files_seen"],
            files_hashed=data["files_hashed"],
            bytes_hashed=data["bytes_hashed"],
            findings=tuple(Finding.from_dict(item) for item in data.get("findings", ())),
            truncated=bool(data.get("truncated", False)),
            truncated_reason=data.get("truncated_reason"),
            errors=tuple(ScanIssue.from_dict(item) for item in data.get("errors", ())),
            engines=tuple(EngineStatus.from_dict(item) for item in data.get("engines", ())),
        )
        stored = data.get("verdict")
        if stored is not None and stored != report.verdict.value:
            raise ValueError(
                f"stored verdict {stored!r} does not match the report content "
                f"({report.verdict.value!r})"
            )
        return report
