"""Known-bad and known-good hash lists: storage, text import and precedence."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from portlock.core.clock import FakeClock, utc_iso
from portlock.core.db import Database
from portlock.core.errors import ScanError, StoreError
from portlock.scan import hashdb
from portlock.scan.hashdb import (
    BUILTIN_KNOWN_BAD,
    EICAR_LABEL,
    EICAR_SHA256,
    HashConflictError,
    HashEntry,
    HashKind,
    HashListError,
    HashSet,
    ImportResult,
    InvalidHashError,
    classify,
    normalize_sha256,
)


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


A, B, C, D = (digest_of(letter) for letter in "abcd")


@pytest.fixture(params=["memory", "database"])
def hashes(request: pytest.FixtureRequest, clock: FakeClock) -> Iterator[HashSet]:
    """A hash list on each backend; every behavioural test runs against both."""
    if request.param == "memory":
        yield HashSet(clock=clock)
        return
    database = Database()
    try:
        yield HashSet(database, clock=clock)
    finally:
        database.close()


# -- digests ------------------------------------------------------------------------


def test_digests_are_normalised_to_lowercase_hex() -> None:
    assert normalize_sha256(f"  {A.upper()}\n") == A


@pytest.mark.parametrize(
    "value",
    [
        "",
        A[:-1],
        A + "0",
        "g" * 64,
        A[:32] + " " + A[33:],
        "0x" + A[2:],
        A.encode(),
        None,
        int(A, 16),
    ],
)
def test_anything_that_is_not_a_sha256_digest_is_rejected(value: object) -> None:
    with pytest.raises(InvalidHashError) as caught:
        normalize_sha256(value)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_hash"
    assert isinstance(caught.value, ScanError)


def test_the_eicar_digest_is_built_in() -> None:
    assert EICAR_SHA256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert dict(BUILTIN_KNOWN_BAD) == {EICAR_SHA256: EICAR_LABEL}
    with pytest.raises(TypeError):
        BUILTIN_KNOWN_BAD["0" * 64] = "x"  # type: ignore[index]


# -- add, contains, remove ----------------------------------------------------------


def test_an_empty_list_knows_nothing(hashes: HashSet) -> None:
    assert not hashes.contains(A)
    assert hashes.lookup(A) is None
    assert hashes.count() == 0 and list(hashes.entries()) == []
    assert hashes.remove(A) is False


def test_added_digests_are_found_by_kind(hashes: HashSet) -> None:
    assert hashes.add(A.upper(), HashKind.KNOWN_BAD, "  Worm.Example  ") is True
    assert hashes.add(B, "known_good") is True

    assert hashes.contains(A) and hashes.contains(A, "known_bad")
    assert not hashes.contains(A, HashKind.KNOWN_GOOD)
    assert hashes.contains(B, "known_good") and not hashes.contains(B, "known_bad")
    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Worm.Example", "local")
    assert hashes.lookup(B.upper()) == HashEntry(B, HashKind.KNOWN_GOOD, None, "local")
    assert (hashes.count(), hashes.count("known_bad"), hashes.count("known_good")) == (2, 1, 1)


def test_adding_the_same_entry_again_changes_nothing(hashes: HashSet) -> None:
    assert hashes.add(A, "known_bad", "Worm.Example") is True
    assert hashes.add(A, "known_bad", "Worm.Example") is False
    assert hashes.add(A, "known_bad", "Worm.Renamed") is True

    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Worm.Renamed", "local")
    assert hashes.count() == 1


def test_removal_takes_a_digest_off_the_list(hashes: HashSet) -> None:
    hashes.add(A, "known_bad")
    hashes.add(B, "known_good")

    assert hashes.remove(A.upper()) is True
    assert hashes.remove(A) is False
    assert not hashes.contains(A) and hashes.contains(B)
    assert hashes.count() == 1


def test_entries_are_listed_in_digest_order(hashes: HashSet) -> None:
    hashes.add(C, "known_good", "three")
    hashes.add(A, "known_bad", "one")
    hashes.add(B, "known_good")

    ordered = sorted([A, B, C])
    assert [entry.sha256 for entry in hashes.entries()] == ordered
    assert [entry.sha256 for entry in hashes.entries("known_good")] == sorted([B, C])
    assert next(iter(hashes.entries("known_bad"))) == HashEntry(
        A, HashKind.KNOWN_BAD, "one", "local"
    )


@pytest.mark.parametrize(
    ("kind", "label"),
    [
        ("bad", None),
        ("", None),
        ("KNOWN_BAD", None),
        (None, None),
        ("known_bad", "x" * 201),
        ("known_bad", "line\nbreak"),
        ("known_bad", "bell\x07"),
        ("known_bad", "override" + chr(0x202E)),
        ("known_bad", 42),
    ],
)
def test_bad_kinds_and_labels_are_rejected(hashes: HashSet, kind: object, label: object) -> None:
    with pytest.raises(InvalidHashError):
        hashes.add(A, kind, label)  # type: ignore[arg-type]
    assert hashes.count() == 0


def test_a_label_is_stored_verbatim_however_it_reads(hashes: HashSet) -> None:
    label = "Robert'); DROP TABLE scan_hashes;-- \N{SNOWMAN}"

    hashes.add(A, "known_bad", label)
    hashes.add(B, "known_good", "   ")

    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, label, "local")
    assert hashes.lookup(B) == HashEntry(B, HashKind.KNOWN_GOOD, None, "local")
    assert hashes.count() == 2


@pytest.mark.parametrize("name", ["", "Local", "has space", "builtin", "x" * 65, "-lead", 7])
def test_list_names_are_short_lowercase_identifiers(name: object) -> None:
    with pytest.raises(InvalidHashError):
        HashSet(name=name)  # type: ignore[arg-type]


# -- bad wins -----------------------------------------------------------------------


def test_a_known_bad_digest_cannot_be_made_known_good(hashes: HashSet) -> None:
    hashes.add(A, "known_bad", "Worm.Example")

    with pytest.raises(HashConflictError) as caught:
        hashes.add(A, "known_good", "trust me")

    assert caught.value.code == "hash_conflict"
    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Worm.Example", "local")
    # Deliberate removal first is the only way.
    hashes.remove(A)
    assert hashes.add(A, "known_good", "reviewed") is True


def test_a_known_good_digest_can_be_reclassified_as_bad(hashes: HashSet) -> None:
    hashes.add(A, "known_good", "installer")

    assert hashes.add(A, "known_bad", "Trojan.Example") is True
    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Trojan.Example", "local")


def test_the_built_in_digest_cannot_be_overridden(hashes: HashSet) -> None:
    with pytest.raises(HashConflictError):
        hashes.add(EICAR_SHA256, "known_good", "harmless really")

    assert not hashes.contains(EICAR_SHA256)
    assert classify(EICAR_SHA256, [hashes]) == HashEntry(
        EICAR_SHA256, HashKind.KNOWN_BAD, EICAR_LABEL, "builtin"
    )
    assert classify(EICAR_SHA256.upper(), []) is not None


def test_classify_prefers_bad_in_any_list_over_good_in_another(clock: FakeClock) -> None:
    vendor = HashSet(name="vendor", clock=clock)
    threats = HashSet(name="threats", clock=clock)
    vendor.add(A, "known_good", "installer")
    vendor.add(B, "known_good", "driver")
    threats.add(A, "known_bad", "Trojan.Example")

    assert classify(A, [vendor, threats]) == HashEntry(
        A, HashKind.KNOWN_BAD, "Trojan.Example", "threats"
    )
    assert classify(A, [threats, vendor]) == classify(A, [vendor, threats])
    assert classify(B, [vendor, threats]) == HashEntry(B, HashKind.KNOWN_GOOD, "driver", "vendor")
    assert classify(C, [vendor, threats]) is None
    assert classify(A, []) is None
    with pytest.raises(InvalidHashError):
        classify("not a digest", [vendor])


# -- the database backend -----------------------------------------------------------


def test_the_list_lives_in_the_scan_component_of_the_database(
    db: Database, clock: FakeClock
) -> None:
    hashes = HashSet(db, clock=clock)
    hashes.add(A, "known_bad", "Worm.Example")

    assert db.schema_version("scan") == len(hashdb.MIGRATIONS) == 1
    rows = db.query("SELECT set_name, sha256, kind, label, added_at FROM scan_hashes")
    assert [tuple(row) for row in rows] == [
        ("local", A, "known_bad", "Worm.Example", utc_iso(clock.now()))
    ]
    # Opening the list again must not try to recreate the table.
    assert HashSet(db, clock=clock).contains(A)


def test_lists_in_one_database_are_separate_by_name(db: Database, clock: FakeClock) -> None:
    first = HashSet(db, name="first", clock=clock)
    second = HashSet(db, name="second", clock=clock)
    first.add(A, "known_bad")
    second.add(A, "known_good")
    second.add(B, "known_good")

    assert first.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, None, "first")
    assert second.lookup(A) == HashEntry(A, HashKind.KNOWN_GOOD, None, "second")
    assert (first.count(), second.count()) == (1, 2)
    assert first.remove(B) is False
    assert HashSet(db, name="first", clock=clock).count() == 1


def test_the_list_survives_reopening_the_database(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "state.db"
    with Database(path) as database:
        HashSet(database, clock=clock).add(A, "known_bad", "Worm.Example")

    with Database(path) as database:
        reopened = HashSet(database, clock=clock)
        assert reopened.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Worm.Example", "local")


def test_the_database_refuses_rows_the_api_would_never_write(
    db: Database, clock: FakeClock
) -> None:
    HashSet(db, clock=clock)

    for values in (("local", "abc", "known_bad"), ("local", A, "maybe")):
        with pytest.raises(StoreError):
            db.execute(
                "INSERT INTO scan_hashes (set_name, sha256, kind, added_at) VALUES (?, ?, ?, 'x')",
                values,
            )


def test_a_failed_store_surfaces_as_a_store_error(clock: FakeClock) -> None:
    database = Database()
    hashes = HashSet(database, clock=clock)
    database.close()

    with pytest.raises(StoreError):
        hashes.add(A, "known_bad")
    with pytest.raises(StoreError):
        classify(A, [hashes])


def test_concurrent_writers_do_not_lose_entries(hashes: HashSet) -> None:
    failures: list[BaseException] = []

    def writer(worker: int) -> None:
        try:
            for index in range(40):
                hashes.add(digest_of(f"{worker}-{index}"), "known_bad", f"w{worker}")
                hashes.add(digest_of(f"shared-{index}"), "known_good")
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=writer, args=(worker,)) for worker in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    assert failures == []
    assert hashes.count("known_bad") == 320 and hashes.count("known_good") == 40


# -- importing text files -----------------------------------------------------------


def write_list(tmp_path: Path, content: bytes | str) -> Path:
    path = tmp_path / "hashes.txt"
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return path


def test_a_text_list_is_imported_with_labels_and_comments(tmp_path: Path, hashes: HashSet) -> None:
    path = write_list(
        tmp_path,
        chr(0xFEFF) + "# known-bad hashes, one per line\r\n"
        "\r\n"
        f"{A}\r\n"
        f"{B.upper()}   Worm.Example variant 2\r\n"
        f"   {C}\tTrojan.\N{LATIN SMALL LETTER E WITH ACUTE}xample   \r\n"
        "   # an indented comment\r\n"
        f"{D}  *payload file.exe\n",
    )

    result = hashes.import_file(path, "known_bad")

    assert result == ImportResult(added=4, updated=0, unchanged=0, conflicts=0)
    assert result.total == 4
    assert list(hashes.entries()) == sorted(
        [
            HashEntry(A, HashKind.KNOWN_BAD, None, "local"),
            HashEntry(B, HashKind.KNOWN_BAD, "Worm.Example variant 2", "local"),
            HashEntry(
                C, HashKind.KNOWN_BAD, "Trojan.\N{LATIN SMALL LETTER E WITH ACUTE}xample", "local"
            ),
            HashEntry(D, HashKind.KNOWN_BAD, "payload file.exe", "local"),
        ],
        key=lambda entry: entry.sha256,
    )


def test_sha256sum_output_is_accepted_as_it_is(tmp_path: Path, hashes: HashSet) -> None:
    path = write_list(tmp_path, f"{A}  tools/setup.exe\n{B} *tools/driver.sys\n")

    hashes.import_file(path, HashKind.KNOWN_GOOD)

    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_GOOD, "tools/setup.exe", "local")
    assert hashes.lookup(B) == HashEntry(B, HashKind.KNOWN_GOOD, "tools/driver.sys", "local")


def test_importing_again_reports_what_changed(tmp_path: Path, hashes: HashSet) -> None:
    hashes.import_file(write_list(tmp_path, f"{A} first\n{B} second\n"), "known_bad")

    result = hashes.import_file(
        write_list(tmp_path, f"{A} first\n{B} renamed\n{C}\n{C}\n{A} first\n"), "known_bad"
    )

    assert result == ImportResult(added=1, updated=1, unchanged=3, conflicts=0)
    assert hashes.count() == 3
    assert hashes.lookup(B) == HashEntry(B, HashKind.KNOWN_BAD, "renamed", "local")


def test_a_known_good_import_never_overrides_known_bad(tmp_path: Path, hashes: HashSet) -> None:
    hashes.add(A, "known_bad", "Worm.Example")
    path = write_list(tmp_path, f"{A} trust me\n{B} fine\n{EICAR_SHA256} also fine\n")

    result = hashes.import_file(path, "known_good")

    assert result == ImportResult(added=1, updated=0, unchanged=0, conflicts=2)
    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Worm.Example", "local")
    assert hashes.lookup(B) == HashEntry(B, HashKind.KNOWN_GOOD, "fine", "local")
    assert not hashes.contains(EICAR_SHA256)


def test_a_known_bad_import_reclassifies_known_good(tmp_path: Path, hashes: HashSet) -> None:
    hashes.add(A, "known_good", "installer")

    result = hashes.import_file(write_list(tmp_path, f"{A} Trojan.Example\n"), "known_bad")

    assert result == ImportResult(added=0, updated=1, unchanged=0, conflicts=0)
    assert hashes.lookup(A) == HashEntry(A, HashKind.KNOWN_BAD, "Trojan.Example", "local")


@pytest.mark.parametrize(
    ("bad_line", "problem"),
    [
        (b"not-a-hash label", "line 2: not a SHA-256 digest: expected 64 hex digits"),
        (A[:63].encode(), "line 2: not a SHA-256 digest: expected 64 hex digits"),
        ((A + "ff").encode(), "line 2: not a SHA-256 digest: expected 64 hex digits"),
        (
            b"d41d8cd98f00b204e9800998ecf8427e",
            "line 2: not a SHA-256 digest: expected 64 hex digits",
        ),
        (A.encode() + b" bad \xff\xfe label", "line 2: not valid UTF-8"),
        (A.encode() + b" bell\x07", "line 2: label contains control or unprintable characters"),
        (A.encode() + b" " + b"x" * 201, "line 2: label is longer than 200 characters"),
        (A.encode() + b" " + b"x" * 2000, "line 2: longer than 1024 bytes"),
        (b"\x00" * 64, "line 2: not a SHA-256 digest: expected 64 hex digits"),
    ],
)
def test_one_bad_line_rejects_the_whole_file(
    tmp_path: Path, hashes: HashSet, bad_line: bytes, problem: str
) -> None:
    hashes.add(D, "known_good", "already here")
    path = write_list(
        tmp_path, B.encode() + b" good line\n" + bad_line + b"\n" + C.encode() + b"\n"
    )

    with pytest.raises(HashListError) as caught:
        hashes.import_file(path, "known_bad")

    assert caught.value.code == "hash_list_invalid"
    assert caught.value.problems == (problem,)
    assert "1 invalid line(s); nothing was imported" in caught.value.message
    assert [entry.sha256 for entry in hashes.entries()] == [D]


def test_many_bad_lines_are_counted_and_the_first_twenty_named(
    tmp_path: Path, hashes: HashSet
) -> None:
    path = write_list(tmp_path, "".join(f"bogus {index}\n" for index in range(35)))

    with pytest.raises(HashListError) as caught:
        hashes.import_file(path, "known_bad")

    assert len(caught.value.problems) == 20
    assert caught.value.problems[0].startswith("line 1: ")
    assert caught.value.problems[-1].startswith("line 20: ")
    assert "35 invalid line(s)" in caught.value.message
    assert hashes.count() == 0


def test_an_empty_or_comment_only_file_imports_nothing(tmp_path: Path, hashes: HashSet) -> None:
    assert hashes.import_file(write_list(tmp_path, b""), "known_bad") == ImportResult()
    assert hashes.import_file(write_list(tmp_path, "# nothing\n\n   \n"), "known_bad").total == 0
    assert hashes.count() == 0


def test_a_missing_or_oversized_file_is_rejected(
    tmp_path: Path, hashes: HashSet, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(HashListError, match="cannot read the hash list") as caught:
        hashes.import_file(tmp_path / "absent.txt", "known_bad")
    assert str(tmp_path) not in caught.value.message

    with pytest.raises(HashListError, match="cannot read the hash list"):
        hashes.import_file(tmp_path, "known_bad")

    monkeypatch.setattr(hashdb, "MAX_IMPORT_BYTES", 100)
    path = write_list(tmp_path, f"{A}\n{B}\n")
    with pytest.raises(HashListError, match="larger than 100 bytes"):
        hashes.import_file(path, "known_bad")
    assert hashes.count() == 0


def test_the_kind_is_checked_before_the_file_is_read(tmp_path: Path, hashes: HashSet) -> None:
    with pytest.raises(InvalidHashError):
        hashes.import_file(tmp_path / "absent.txt", "known_ugly")


def test_a_database_import_is_one_transaction(tmp_path: Path, clock: FakeClock) -> None:
    database = Database()
    hashes = HashSet(database, clock=clock)
    hashes.add(D, "known_good")
    path = write_list(tmp_path, f"{A}\n{B}\n{C}\n")
    real_execute = database.execute
    calls = 0

    def failing_execute(sql: str, params: object = ()) -> object:
        nonlocal calls
        if sql.startswith("INSERT INTO scan_hashes"):
            calls += 1
            if calls == 3:
                raise StoreError("database error: disk full")
        return real_execute(sql, params)  # type: ignore[arg-type]

    database.execute = failing_execute  # type: ignore[method-assign]
    with pytest.raises(StoreError):
        hashes.import_file(path, "known_bad")
    database.execute = real_execute  # type: ignore[method-assign]

    assert calls == 3
    assert [entry.sha256 for entry in hashes.entries()] == [D]
    database.close()
