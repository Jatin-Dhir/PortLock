"""Known-bad and known-good SHA-256 lists.

A :class:`HashSet` is a named list of digests, each marked *known bad* or *known good*
and optionally labelled. It lives in the PortLock database (table ``scan_hashes``, owned
by the ``scan`` component) or, when no database is given, in memory. Lists are exchanged
as plain text files: one digest per line, an optional label after it, ``#`` comments.

How the scanner uses a match:

* **known bad** - a ``malicious`` finding carrying the entry's label;
* **known good** - the heuristic findings for that exact file are suppressed. Antivirus
  detections are not: a known-good entry vouches against PortLock's own guesses, it does
  not overrule another engine.

When lists disagree about a digest, *bad wins*, everywhere: a known-bad entry cannot be
overwritten by a known-good one (it has to be removed first), an import of known-good
digests skips those already known bad, and :func:`classify` prefers a bad match in any
list over a good match in another.

The EICAR antivirus test file is recognised by its published SHA-256, which is built in
and cannot be overridden. Only the digest is stored here, never the file's content, so
the detection pipeline can be demonstrated end to end without a detectable byte ever
being written to disk.
"""

from __future__ import annotations

import enum
import os
import re
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from portlock.core.clock import Clock, SystemClock, utc_iso
from portlock.core.db import Database
from portlock.core.errors import ScanError

__all__ = [
    "BUILTIN_KNOWN_BAD",
    "EICAR_LABEL",
    "EICAR_SHA256",
    "MAX_IMPORT_BYTES",
    "MIGRATIONS",
    "HashConflictError",
    "HashEntry",
    "HashKind",
    "HashListError",
    "HashSet",
    "ImportResult",
    "InvalidHashError",
    "classify",
    "normalize_sha256",
]

#: SHA-256 of the 68-byte EICAR Standard Anti-Virus Test File. A harmless, published
#: constant that every antivirus product detects on purpose.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_LABEL = "EICAR-Test-File"

#: Digests that are always known bad, whatever the configured lists say.
BUILTIN_KNOWN_BAD: Mapping[str, str] = MappingProxyType({EICAR_SHA256: EICAR_LABEL})

#: The largest list file :meth:`HashSet.import_file` reads.
MAX_IMPORT_BYTES = 64 * 1024 * 1024

#: Schema of the ``scan`` component. Append only; never edit a published migration.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE scan_hashes (
        set_name TEXT NOT NULL,
        sha256   TEXT NOT NULL CHECK (length(sha256) = 64),
        kind     TEXT NOT NULL CHECK (kind IN ('known_bad', 'known_good')),
        label    TEXT,
        added_at TEXT NOT NULL,
        PRIMARY KEY (set_name, sha256)
    ) WITHOUT ROWID;
    """,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SET_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.\-]{0,63}\Z")
_MAX_LABEL_CHARS = 200
_MAX_LINE_BYTES = 1024
_MAX_PROBLEMS = 20


class InvalidHashError(ScanError):
    """A value is not a SHA-256 digest, a list kind, a label or a list name."""

    code = "invalid_hash"


class HashConflictError(ScanError):
    """A digest that is known bad was offered as known good."""

    code = "hash_conflict"


class HashListError(ScanError):
    """A hash list file was rejected. ``problems`` names each bad line.

    Nothing from a rejected file is imported.
    """

    code = "hash_list_invalid"

    def __init__(self, message: str, *, problems: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.problems = problems


class HashKind(enum.StrEnum):
    """What a list entry asserts about the file with that digest."""

    KNOWN_BAD = "known_bad"
    KNOWN_GOOD = "known_good"


@dataclass(frozen=True, slots=True)
class HashEntry:
    """One digest on a list.

    Attributes:
        sha256: lowercase hex.
        kind: known bad or known good.
        label: what the file is (a malware family, a product name), if recorded.
        source: the name of the list the entry came from; ``builtin`` for the digests
            compiled into PortLock.
    """

    sha256: str
    kind: HashKind
    label: str | None = None
    source: str = "local"


@dataclass(frozen=True, slots=True)
class ImportResult:
    """What :meth:`HashSet.import_file` did.

    Attributes:
        added: digests that were not on the list before.
        updated: digests whose kind or label changed.
        unchanged: digests already present exactly as given (including repeats within
            the file).
        conflicts: known-good lines skipped because the digest is known bad.
    """

    added: int = 0
    updated: int = 0
    unchanged: int = 0
    conflicts: int = 0

    @property
    def total(self) -> int:
        """How many digest lines the file held."""
        return self.added + self.updated + self.unchanged + self.conflicts


def normalize_sha256(value: str) -> str:
    """Return a SHA-256 digest in canonical form: 64 lowercase hex digits.

    Raises:
        InvalidHashError: if ``value`` is not a SHA-256 digest in hex.
    """
    if not isinstance(value, str):
        raise InvalidHashError("a SHA-256 digest must be given as a hex string")
    digest = value.strip().lower()
    if not _SHA256_PATTERN.match(digest):
        raise InvalidHashError("not a SHA-256 digest: expected 64 hex digits")
    return digest


def _normalize_kind(kind: HashKind | str) -> HashKind:
    try:
        return HashKind(kind)
    except ValueError:
        raise InvalidHashError(
            f"unknown hash list kind {kind!r}: expected known_bad or known_good"
        ) from None


def _normalize_label(label: str | None) -> str | None:
    if label is None:
        return None
    if not isinstance(label, str):
        raise InvalidHashError("a label must be text")
    cleaned = label.strip()
    if not cleaned:
        return None
    if len(cleaned) > _MAX_LABEL_CHARS:
        raise InvalidHashError(f"label is longer than {_MAX_LABEL_CHARS} characters")
    if not cleaned.isprintable():
        raise InvalidHashError("label contains control or unprintable characters")
    return cleaned


def _parse_list(data: bytes) -> list[tuple[str, str | None]]:
    """Parse the bytes of a hash list file into ``(digest, label)`` pairs.

    Raises:
        HashListError: listing the first problems found, by line number.
    """
    entries: list[tuple[str, str | None]] = []
    problems: list[str] = []
    problem_count = 0
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for number, raw in enumerate(data.split(b"\n"), start=1):
        problem: str | None = None
        line = raw.rstrip(b"\r")
        if len(line) > _MAX_LINE_BYTES:
            problem = f"longer than {_MAX_LINE_BYTES} bytes"
        else:
            try:
                text = line.decode("utf-8").strip()
            except UnicodeDecodeError:
                problem = "not valid UTF-8"
            else:
                if not text or text.startswith("#"):
                    continue
                digest_text, _, rest = text.replace("\t", " ").partition(" ")
                rest = rest.strip()
                # sha256sum marks binary mode with an asterisk glued to the file name.
                if rest.startswith("*") and len(rest) > 1 and not rest[1].isspace():
                    rest = rest[1:]
                try:
                    entries.append((normalize_sha256(digest_text), _normalize_label(rest)))
                except InvalidHashError as exc:
                    problem = exc.message
        if problem is not None:
            problem_count += 1
            if len(problems) < _MAX_PROBLEMS:
                problems.append(f"line {number}: {problem}")
    if problem_count:
        raise HashListError(
            f"hash list rejected: {problem_count} invalid line(s); nothing was imported",
            problems=tuple(problems),
        )
    return entries


class HashSet:
    """A named list of known-bad and known-good SHA-256 digests.

    Safe to use from several threads. Two ``HashSet`` objects with the same name on the
    same database are the same list.

    Args:
        db: where the list is stored. ``None`` keeps it in memory only, which suits
            lists loaded from text files at start-up and tests.
        name: the list's name; distinguishes several lists in one database and is
            reported as the source of a match.
        clock: time source for the ``added_at`` column.

    Raises:
        InvalidHashError: if ``name`` is not a short lowercase identifier.
        StoreError: if the database cannot be migrated.
    """

    def __init__(
        self, db: Database | None = None, *, name: str = "local", clock: Clock | None = None
    ) -> None:
        if not isinstance(name, str) or not _SET_NAME_PATTERN.match(name) or name == "builtin":
            raise InvalidHashError(f"invalid hash list name: {name!r}")
        self._db = db
        self._name = name
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.RLock()
        self._memory: dict[str, tuple[HashKind, str | None]] = {}
        if db is not None:
            db.migrate("scan", MIGRATIONS)

    @property
    def name(self) -> str:
        return self._name

    # -- storage primitives (callers hold the lock or a transaction) -----------------

    def _get(self, digest: str) -> tuple[HashKind, str | None] | None:
        if self._db is None:
            return self._memory.get(digest)
        row = self._db.query_one(
            "SELECT kind, label FROM scan_hashes WHERE set_name = ? AND sha256 = ?",
            (self._name, digest),
        )
        return (HashKind(row["kind"]), row["label"]) if row is not None else None

    def _put(self, digest: str, kind: HashKind, label: str | None) -> None:
        if self._db is None:
            self._memory[digest] = (kind, label)
            return
        self._db.execute(
            "INSERT INTO scan_hashes (set_name, sha256, kind, label, added_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT (set_name, sha256) DO UPDATE SET"
            " kind = excluded.kind, label = excluded.label, added_at = excluded.added_at",
            (self._name, digest, kind.value, label, utc_iso(self._clock.now())),
        )

    def _store(self, digest: str, kind: HashKind, label: str | None) -> str:
        """Apply one entry under the "bad wins" rule; says what happened to it."""
        existing = self._get(digest)
        blocked = digest in BUILTIN_KNOWN_BAD or (
            existing is not None and existing[0] is HashKind.KNOWN_BAD
        )
        if kind is HashKind.KNOWN_GOOD and blocked:
            return "conflict"
        if existing == (kind, label):
            return "unchanged"
        self._put(digest, kind, label)
        return "added" if existing is None else "updated"

    # -- public API ------------------------------------------------------------------

    def add(self, sha256: str, kind: HashKind | str, label: str | None = None) -> bool:
        """Put a digest on the list, or change its kind or label.

        Args:
            sha256: the digest in hex, any case.
            kind: ``known_bad`` or ``known_good``.
            label: what the file is; printable text of at most 200 characters.

        Returns:
            True if the list changed, False if the entry was already there as given.

        Raises:
            InvalidHashError: if the digest, kind or label is malformed.
            HashConflictError: if a known-bad digest (on this list or built in) is
                offered as known good. Remove it first if that is really intended.
            StoreError: if the database write fails.
        """
        digest = normalize_sha256(sha256)
        wanted = _normalize_kind(kind)
        cleaned = _normalize_label(label)
        with self._lock:
            if self._db is None:
                outcome = self._store(digest, wanted, cleaned)
            else:
                with self._db.transaction():
                    outcome = self._store(digest, wanted, cleaned)
        if outcome == "conflict":
            raise HashConflictError(
                f"{digest} is known bad and cannot be listed as known good; "
                "remove the known-bad entry first"
            )
        return outcome != "unchanged"

    def remove(self, sha256: str) -> bool:
        """Take a digest off the list. Built-in digests are unaffected.

        Returns:
            True if the digest was on the list.

        Raises:
            InvalidHashError: if ``sha256`` is not a SHA-256 digest.
            StoreError: if the database write fails.
        """
        digest = normalize_sha256(sha256)
        with self._lock:
            if self._db is None:
                return self._memory.pop(digest, None) is not None
            cursor = self._db.execute(
                "DELETE FROM scan_hashes WHERE set_name = ? AND sha256 = ?",
                (self._name, digest),
            )
            return cursor.rowcount > 0

    def lookup(self, sha256: str) -> HashEntry | None:
        """Return this list's entry for a digest, or ``None``.

        Raises:
            InvalidHashError: if ``sha256`` is not a SHA-256 digest.
        """
        digest = normalize_sha256(sha256)
        with self._lock:
            found = self._get(digest)
        if found is None:
            return None
        return HashEntry(digest, found[0], found[1], self._name)

    def contains(self, sha256: str, kind: HashKind | str | None = None) -> bool:
        """True if the digest is on this list (as ``kind``, when a kind is given).

        Raises:
            InvalidHashError: if the digest or the kind is malformed.
        """
        wanted = _normalize_kind(kind) if kind is not None else None
        entry = self.lookup(sha256)
        return entry is not None and (wanted is None or entry.kind is wanted)

    def count(self, kind: HashKind | str | None = None) -> int:
        """How many digests are on this list, optionally of one kind."""
        wanted = _normalize_kind(kind) if kind is not None else None
        with self._lock:
            if self._db is None:
                return sum(1 for held, _ in self._memory.values() if wanted in (None, held))
            if wanted is None:
                row = self._db.query_one(
                    "SELECT COUNT(*) AS n FROM scan_hashes WHERE set_name = ?", (self._name,)
                )
            else:
                row = self._db.query_one(
                    "SELECT COUNT(*) AS n FROM scan_hashes WHERE set_name = ? AND kind = ?",
                    (self._name, wanted.value),
                )
        return int(row["n"]) if row is not None else 0

    def entries(self, kind: HashKind | str | None = None) -> Iterator[HashEntry]:
        """Every entry on this list in digest order, optionally of one kind."""
        wanted = _normalize_kind(kind) if kind is not None else None
        with self._lock:
            if self._db is None:
                rows = sorted(
                    (digest, held, label) for digest, (held, label) in self._memory.items()
                )
            else:
                rows = [
                    (row["sha256"], HashKind(row["kind"]), row["label"])
                    for row in self._db.query(
                        "SELECT sha256, kind, label FROM scan_hashes WHERE set_name = ?"
                        " ORDER BY sha256",
                        (self._name,),
                    )
                ]
        for digest, held, label in rows:
            if wanted is None or held is wanted:
                yield HashEntry(digest, held, label, self._name)

    def import_file(self, path: str | os.PathLike[str], kind: HashKind | str) -> ImportResult:
        """Import a text file of digests, all as ``kind``.

        Format: one entry per line, ``<64 hex digits>`` optionally followed by blanks
        and a label; blank lines and lines starting with ``#`` are ignored. The output
        of ``sha256sum`` is accepted as it is (the file name becomes the label). The
        file must be UTF-8.

        Every line is validated before anything is stored, and the import is one
        transaction: a file with a single bad line changes nothing.

        Returns:
            Counts of what was added, updated, left unchanged and skipped.

        Raises:
            InvalidHashError: if ``kind`` is not a list kind.
            HashListError: if the file cannot be read, is larger than
                :data:`MAX_IMPORT_BYTES`, or contains an invalid line. ``problems``
                lists up to twenty of them by line number.
            StoreError: if the database write fails.
        """
        wanted = _normalize_kind(kind)
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_IMPORT_BYTES + 1)
        except OSError as exc:
            raise HashListError(
                f"cannot read the hash list: {exc.strerror or type(exc).__name__}"
            ) from exc
        if len(data) > MAX_IMPORT_BYTES:
            raise HashListError(f"hash list is larger than {MAX_IMPORT_BYTES} bytes")
        entries = _parse_list(data)
        with self._lock:
            if self._db is None:
                return self._import(entries, wanted)
            with self._db.transaction():
                return self._import(entries, wanted)

    def _import(self, entries: Iterable[tuple[str, str | None]], kind: HashKind) -> ImportResult:
        counts = {"added": 0, "updated": 0, "unchanged": 0, "conflict": 0}
        for digest, label in entries:
            counts[self._store(digest, kind, label)] += 1
        return ImportResult(
            added=counts["added"],
            updated=counts["updated"],
            unchanged=counts["unchanged"],
            conflicts=counts["conflict"],
        )


def classify(sha256: str, hashsets: Iterable[HashSet]) -> HashEntry | None:
    """Decide what the configured lists, taken together, say about a digest.

    The built-in known-bad digests are consulted first. After that a known-bad entry in
    any list wins over a known-good entry in another.

    Returns:
        The deciding entry, or ``None`` if no list knows the digest.

    Raises:
        InvalidHashError: if ``sha256`` is not a SHA-256 digest.
        StoreError: if a list's database cannot be read.
    """
    digest = normalize_sha256(sha256)
    builtin = BUILTIN_KNOWN_BAD.get(digest)
    if builtin is not None:
        return HashEntry(digest, HashKind.KNOWN_BAD, builtin, "builtin")
    good: HashEntry | None = None
    for hashset in hashsets:
        entry = hashset.lookup(digest)
        if entry is None:
            continue
        if entry.kind is HashKind.KNOWN_BAD:
            return entry
        if good is None:
            good = entry
    return good
