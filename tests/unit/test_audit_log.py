"""The audit log: chaining, validation, queries, verification and concurrency."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import portlock
from portlock.audit import log as log_module
from portlock.audit.events import REGISTRY, EventRegistry
from portlock.audit.log import (
    DEFAULT_SECRET_KEYS,
    GENESIS_HASH,
    MAC_KEY_BYTES,
    MAX_DATA_BYTES,
    MAX_QUERY_LIMIT,
    RATCHET_DOMAIN,
    AuditError,
    AuditKey,
    AuditKeyStore,
    AuditLog,
    AuditRecord,
    VerifyResult,
    ratchet_key,
    read_head_file,
    record_hash,
    record_mac,
    redact,
)
from portlock.core.canonical import parse_canonical
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import PortLockError, StoreError
from portlock.core.models import Severity

KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))
FP = "plk1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
FP2 = "plk1:765432ZYXWVUTSRQPONMLKJIHGFEDCBA"
SELECT = (
    "SELECT seq, ts, event_type, severity, actor, device_fp, data, prev_hash, hash, mac"
    " FROM audit_log"
)


@pytest.fixture
def log(db: Database, clock: FakeClock) -> AuditLog:
    return AuditLog(db, clock=clock)


@pytest.fixture
def key_path(state_dir: Path) -> Path:
    return state_dir / "audit.key"


@pytest.fixture
def created(key_path: Path) -> tuple[AuditKeyStore, AuditKey]:
    return AuditKeyStore.create(key_path)


@pytest.fixture
def initial_key(created: tuple[AuditKeyStore, AuditKey]) -> AuditKey:
    return created[1]


@pytest.fixture
def keyed(db: Database, clock: FakeClock, created: tuple[AuditKeyStore, AuditKey]) -> AuditLog:
    return AuditLog(db, clock=clock, key_store=created[0])


def independent_hash(prev_hash: str, body: dict[str, Any]) -> str:
    """The chain hash computed without any PortLock code (valid for ASCII-keyed bodies)."""
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(bytes.fromhex(prev_hash) + encoded.encode("utf-8")).hexdigest()


def independent_key(initial: bytes, steps: int) -> bytes:
    """``k_steps`` from ``k_0`` with nothing but hashlib, as the design states it."""
    key = initial
    for _ in range(steps):
        key = hashlib.sha256(b"portlock-audit-ratchet" + key).digest()
    return key


def stored_key(path: Path) -> tuple[int, bytes]:
    """What an intruder who reads the key store file learns: (next seq, key)."""
    state = json.loads(path.read_bytes())
    return state["seq"], bytes.fromhex(state["key"])


def remac(db: Database, seq: int, key: bytes) -> None:
    """Give record ``seq`` a MAC made with ``key``, as a forger holding ``key`` can."""
    row = db.query_one("SELECT hash FROM audit_log WHERE seq = ?", (seq,))
    assert row is not None
    db.execute("UPDATE audit_log SET mac = ? WHERE seq = ?", (record_mac(key, row["hash"]), seq))


def fill(log: AuditLog, clock: FakeClock, count: int = 6) -> list[AuditRecord]:
    records = []
    for index in range(count):
        clock.advance(1)
        records.append(log.append("device.connected", device_fp=FP, data={"n": index}))
    return records


def unprotect(db: Database) -> None:
    """Do what an attacker with write access does first: drop the append-only triggers."""
    for name in ("audit_log_no_update", "audit_log_no_delete", "audit_log_next_seq_only"):
        db.execute(f"DROP TRIGGER {name}")


def tamper(db: Database, column: str, sql_value: str, params: tuple[Any, ...] = ()) -> None:
    """Overwrite one column of record 3 with a SQL expression (test-chosen, never input)."""
    db.execute(f"UPDATE audit_log SET {column} = {sql_value} WHERE seq = 3", params)  # noqa: S608


def rechain(db: Database, from_seq: int, *, mac: str | None = "keep") -> None:
    """Rebuild every hash from ``from_seq`` on, as a forger without the HMAC key would."""
    rows = db.query(SELECT + " WHERE seq >= ? ORDER BY seq", (from_seq - 1,))
    prev_hash = GENESIS_HASH
    for row in rows:
        if row["seq"] < from_seq:
            prev_hash = row["hash"]
            continue
        digest = record_hash(
            prev_hash,
            seq=row["seq"],
            ts=row["ts"],
            event_type=row["event_type"],
            severity=row["severity"],
            actor=row["actor"],
            device_fp=row["device_fp"],
            data=json.loads(row["data"]),
        )
        new_mac = row["mac"] if mac == "keep" else mac
        db.execute(
            "UPDATE audit_log SET prev_hash = ?, hash = ?, mac = ? WHERE seq = ?",
            (prev_hash, digest, new_mac, row["seq"]),
        )
        prev_hash = digest


# --- appending -----------------------------------------------------------------------


def test_genesis_hash_is_the_documented_constant() -> None:
    assert hashlib.sha256(b"portlock-audit-v1").hexdigest() == GENESIS_HASH
    assert GENESIS_HASH == "66733296c9268618439464e304e8b8fbbec7ba390d114a728e3cc7e6f97c2849"


def test_first_record_chains_from_genesis(log: AuditLog, clock: FakeClock) -> None:
    record = log.append(
        "device.connected", actor="system", device_fp=FP, data={"vendor_id": 0x1209, "ok": True}
    )
    assert record.seq == 1
    assert record.ts == "2026-01-01T00:00:00.000000Z"
    assert record.timestamp == clock.now()
    assert record.event_type == "device.connected"
    assert record.severity is Severity.INFO
    assert record.actor == "system" and record.device_fp == FP
    assert record.data == {"vendor_id": 0x1209, "ok": True}
    assert record.prev_hash == GENESIS_HASH
    assert record.mac is None
    assert record.hash == independent_hash(
        GENESIS_HASH,
        {
            "seq": 1,
            "ts": "2026-01-01T00:00:00.000000Z",
            "event_type": "device.connected",
            "severity": "info",
            "actor": "system",
            "device_fp": FP,
            "data": {"vendor_id": 0x1209, "ok": True},
        },
    )


def test_each_record_links_to_the_one_before(log: AuditLog, clock: FakeClock) -> None:
    first = log.append("service.started")
    clock.advance(timedelta(microseconds=1))
    second = log.append("device.removed", data={"why": "unplugged"})
    assert (second.seq, second.prev_hash) == (2, first.hash)
    assert second.ts == "2026-01-01T00:00:00.000001Z"
    assert second.hash == independent_hash(
        first.hash,
        {
            "seq": 2,
            "ts": second.ts,
            "event_type": "device.removed",
            "severity": "info",
            "actor": None,
            "device_fp": None,
            "data": {"why": "unplugged"},
        },
    )
    assert second.hash != first.hash
    assert log.head() == (2, second.hash)


def test_non_ascii_text_is_hashed_as_utf8(log: AuditLog) -> None:
    name = "Zo" + chr(0xEB) + " " + chr(0x1F512)
    record = log.append("auth.login", actor=name, data={"note": name})
    body = (
        '{"actor":"' + name + '","data":{"note":"' + name + '"},"device_fp":null,'
        '"event_type":"auth.login","seq":1,"severity":"info",'
        '"ts":"2026-01-01T00:00:00.000000Z"}'
    )
    expected = hashlib.sha256(bytes.fromhex(GENESIS_HASH) + body.encode("utf-8")).hexdigest()
    assert record.hash == expected
    assert log.get(1) == record


def test_a_keyed_log_macs_each_record_under_its_own_ratcheted_key(
    keyed: AuditLog, initial_key: AuditKey
) -> None:
    first = keyed.append("service.started")
    second = keyed.append("service.stopped")
    assert keyed.keyed and initial_key.anchor_seq == 0
    k1 = independent_key(initial_key.key, 1)
    k2 = independent_key(initial_key.key, 2)
    assert first.mac == hmac.new(k1, bytes.fromhex(first.hash), hashlib.sha256).hexdigest()
    assert second.mac == hmac.new(k2, bytes.fromhex(second.hash), hashlib.sha256).hexdigest()
    assert first.mac == record_mac(initial_key.key_for(1), first.hash)
    assert len({first.mac, second.mac, first.hash, second.hash}) == 4


def test_the_ratchet_is_sha256_over_the_domain_and_the_key() -> None:
    assert RATCHET_DOMAIN == b"portlock-audit-ratchet" and MAC_KEY_BYTES == 32
    assert ratchet_key(KEY) == hashlib.sha256(b"portlock-audit-ratchet" + KEY).digest()
    assert ratchet_key(KEY, 0) == KEY
    assert ratchet_key(KEY, 5) == independent_key(KEY, 5)
    assert ratchet_key(bytearray(KEY), 2) == ratchet_key(ratchet_key(KEY))
    for bad_key in (b"", bytes(31), bytes(33), "k" * 32, None):
        with pytest.raises(AuditError, match="exactly 32 bytes"):
            ratchet_key(bad_key)  # type: ignore[arg-type]
    for bad_steps in (-1, 1.0, True, "2"):
        with pytest.raises(AuditError, match="steps"):
            ratchet_key(KEY, bad_steps)  # type: ignore[arg-type]


def test_the_stored_row_holds_canonical_json(log: AuditLog, db: Database) -> None:
    log.append("device.connected", data={"b": [1, {"z": None, "a": True}], "a": "x"})
    row = db.query_one(SELECT + " WHERE seq = 1")
    assert row is not None
    assert row["data"] == '{"a":"x","b":[1,{"a":true,"z":null}]}'
    assert row["severity"] == "info" and row["actor"] is None and row["mac"] is None
    assert db.schema_version("audit") == 1


def test_missing_data_is_stored_as_an_empty_object(log: AuditLog, db: Database) -> None:
    record = log.append("service.stopped")
    assert record.data == {}
    assert db.query_one("SELECT data FROM audit_log")["data"] == "{}"  # type: ignore[index]


def test_severity_defaults_to_the_catalogue_and_can_be_overridden(log: AuditLog) -> None:
    assert log.append("enforcement.failed").severity is Severity.ERROR
    assert log.append("enforcement.failed", Severity.CRITICAL).severity is Severity.CRITICAL
    assert log.append("enforcement.failed", "warning").severity is Severity.WARNING
    with pytest.raises(AuditError, match="unknown severity"):
        log.append("enforcement.failed", "fatal")
    with pytest.raises(AuditError, match="unknown severity"):
        log.append("enforcement.failed", 3)  # type: ignore[arg-type]
    assert log.count() == 3


def test_unknown_event_types_are_refused_in_strict_mode(log: AuditLog) -> None:
    with pytest.raises(AuditError, match=r"unknown event type 'device.conected'") as caught:
        log.append("device.conected")
    assert caught.value.code == "unknown_event_type"
    assert isinstance(caught.value, PortLockError)
    assert log.count() == 0


def test_a_lenient_registry_accepts_new_types_with_an_explicit_severity(
    db: Database, clock: FakeClock
) -> None:
    log = AuditLog(db, clock=clock, registry=EventRegistry(REGISTRY, strict=False))
    record = log.append("plugin.loaded", "notice")
    assert (record.event_type, record.severity) == ("plugin.loaded", Severity.NOTICE)
    with pytest.raises(AuditError, match="no default severity"):
        log.append("plugin.loaded")
    assert log.verify() == VerifyResult(True, 1, None, None, 0, (1, record.hash))


@pytest.mark.parametrize(
    "event_type",
    [
        "",
        "device",
        "Device.Connected",
        "device..connected",
        "device.connected ",
        "a.b" * 30,
        7,
        None,
    ],
)
def test_malformed_event_types_are_refused(log: AuditLog, event_type: Any) -> None:
    with pytest.raises(AuditError, match="invalid event type"):
        log.append(event_type)
    assert log.count() == 0


def _self_referencing() -> dict[str, Any]:
    data: dict[str, Any] = {}
    data["self"] = data
    return data


def _too_deep() -> dict[str, Any]:
    data: dict[str, Any] = {}
    for _ in range(40):
        data = {"d": data}
    return data


@pytest.mark.parametrize(
    "data",
    [
        {"ratio": 0.5},
        {"nested": [1, {"x": 1.0}]},
        {"nan": float("nan")},
        {"big": 2**53},
        {"small": -(2**53)},
        {1: "integer key"},
        {"caf" + chr(0xE9): "non-ASCII key"},
        {"blob": b"bytes"},
        {"when": datetime(2026, 1, 1, tzinfo=UTC)},
        {"set": {1, 2}},
        {"lone": chr(0xD800)},
        _self_referencing(),
        _too_deep(),
        ["a", "list"],
        "a string",
        42,
    ],
    ids=[
        "float",
        "nested-float",
        "nan",
        "unsafe-int",
        "unsafe-negative",
        "int-key",
        "non-ascii-key",
        "bytes",
        "datetime",
        "set",
        "lone-surrogate",
        "self-reference",
        "too-deep",
        "list",
        "string",
        "int",
    ],
)
def test_data_that_is_not_canonical_json_is_refused(log: AuditLog, data: Any) -> None:
    with pytest.raises(AuditError, match="data "):
        log.append("device.connected", data=data)
    assert log.count() == 0
    assert log.head() == (0, GENESIS_HASH)


def test_floats_are_refused_with_an_explanation(log: AuditLog) -> None:
    with pytest.raises(AuditError, match="no floats"):
        log.append("scan.finished", data={"seconds": 1.25})


def test_data_is_limited_to_64_kib_once_encoded(log: AuditLog) -> None:
    assert MAX_DATA_BYTES == 64 * 1024
    overhead = len('{"k":""}')
    fits = log.append("scan.finished", data={"k": "x" * (MAX_DATA_BYTES - overhead)})
    assert len(fits.data["k"]) == MAX_DATA_BYTES - overhead
    with pytest.raises(AuditError, match="65537 bytes once encoded; the limit is 65536"):
        log.append("scan.finished", data={"k": "x" * (MAX_DATA_BYTES - overhead + 1)})
    # Size is measured in UTF-8 bytes, not characters.
    with pytest.raises(AuditError, match="the limit is 65536"):
        log.append("scan.finished", data={"k": chr(0x6771) * 30000})
    assert log.count() == 1


@pytest.mark.parametrize("field", ["actor", "device_fp"])
@pytest.mark.parametrize("value", ["", "x" * 257, "line\nbreak", "nul\x00", "esc\x1b[31m", 5, b"b"])
def test_labels_are_validated(log: AuditLog, field: str, value: Any) -> None:
    with pytest.raises(AuditError, match=field):
        log.append("auth.login", **{field: value})
    assert log.count() == 0


def test_labels_may_be_long_and_non_ascii(log: AuditLog) -> None:
    actor = chr(0x6771) * 256
    assert log.append("auth.login", actor=actor).actor == actor


def test_secret_bearing_keys_are_redacted_before_storage(log: AuditLog, db: Database) -> None:
    record = log.append(
        "auth.failure",
        actor="alice",
        data={
            "user": "alice",
            "password": "hunter2-do-not-store",
            "Session_Token": "tok-1234",
            "attempt": {"recovery_code": "AAAA-BBBB", "n": 3},
            "history": [{"token": "tok-5678", "at": 1}],
            "key": "mode",
        },
    )
    assert record.data == {
        "user": "alice",
        "password": "[redacted]",
        "Session_Token": "[redacted]",
        "attempt": {"recovery_code": "[redacted]", "n": 3},
        "history": [{"token": "[redacted]", "at": 1}],
        "key": "mode",
    }
    stored = db.query_one("SELECT data FROM audit_log")["data"]  # type: ignore[index]
    for secret in ("hunter2", "tok-1234", "AAAA-BBBB", "tok-5678"):
        assert secret not in stored
    assert log.verify().ok


def test_redact_helper() -> None:
    original = {"a": {"pin": "1234", "PIN": "5678", "keep": (1, {"pin": "9"})}, "password": "p"}
    cleaned = redact(original, ["pin"])
    assert cleaned == {
        "a": {"pin": "[redacted]", "PIN": "[redacted]", "keep": [1, {"pin": "[redacted]"}]},
        "password": "p",
    }
    assert original["a"]["pin"] == "1234"  # the input is not modified
    assert redact({"password": None, "x": 1}) == {"password": "[redacted]", "x": 1}
    assert redact({"pin": 1, "p": 2}, "pin") == {"pin": "[redacted]", "p": 2}  # not p, i, n
    assert redact("just a string") == "just a string"
    assert {"password", "token", "recovery_code", "private_key"} <= DEFAULT_SECRET_KEYS
    assert "key" not in DEFAULT_SECRET_KEYS
    with pytest.raises(AuditError, match="must be strings"):
        redact({}, [1])  # type: ignore[list-item]
    with pytest.raises(AuditError, match="nested deeper"):
        redact(_self_referencing())


def test_records_do_not_share_state_with_the_caller(log: AuditLog) -> None:
    data = {"list": [1, 2], "inner": {"a": 1}}
    record = log.append("device.changed", data=data)
    data["list"].append(3)
    data["inner"]["a"] = 2
    assert record.data == {"list": [1, 2], "inner": {"a": 1}}
    with pytest.raises(TypeError):
        record.data["new"] = 1  # type: ignore[index]
    exported = record.to_dict()
    exported["data"]["list"].append(99)
    assert record.data["list"] == [1, 2]
    assert log.get(1) == record
    assert len({record, log.get(1)}) == 1


def test_a_failed_append_leaves_nothing_behind(db: Database) -> None:
    class FailingClock(FakeClock):
        fail = True

        def now(self) -> datetime:
            if self.fail:
                raise RuntimeError("clock unavailable")
            return super().now()

    clock = FailingClock()
    log = AuditLog(db, clock=clock)
    with pytest.raises(RuntimeError, match="clock unavailable"):
        log.append("service.started")
    assert log.count() == 0
    clock.fail = False
    assert log.append("service.started").seq == 1
    assert log.verify().ok


@pytest.mark.parametrize("store", [b"k" * 32, "audit.key", 12345, AuditKey(0, KEY)])
def test_a_key_store_must_be_a_key_store(db: Database, clock: FakeClock, store: Any) -> None:
    with pytest.raises(AuditError, match="key_store must be an AuditKeyStore"):
        AuditLog(db, clock=clock, key_store=store)


@pytest.mark.parametrize(
    ("anchor", "key", "message"),
    [
        (-1, KEY, "anchor_seq"),
        (2**63 - 1, KEY, "anchor_seq"),
        (True, KEY, "anchor_seq"),
        ("0", KEY, "anchor_seq"),
        (0, b"", "exactly 32 bytes"),
        (0, bytes(16), "exactly 32 bytes"),
        (0, bytes(33), "exactly 32 bytes"),
        (0, "k" * 32, "exactly 32 bytes"),
    ],
)
def test_malformed_initial_keys_are_refused(anchor: Any, key: Any, message: str) -> None:
    with pytest.raises(AuditError, match=message):
        AuditKey(anchor, key)


def test_an_initial_key_never_shows_itself_and_round_trips_as_text() -> None:
    key = AuditKey(7, bytearray(KEY))
    assert isinstance(key.key, bytes)
    assert KEY.hex() not in repr(key) and "7" in repr(key)
    text = key.encode()
    assert text == "plak1-7-" + KEY.hex()
    assert AuditKey.parse(text) == key
    assert AuditKey.parse("  " + text + "\n") == key
    assert key.key_for(8) == independent_key(KEY, 1)
    assert key.key_for(10) == independent_key(KEY, 3)
    for not_after in (7, 1):
        with pytest.raises(AuditError, match="not after the key's anchor"):
            key.key_for(not_after)
    for garbage in (
        "",
        "plak1-7-" + KEY.hex()[:-1],
        "plak1--" + KEY.hex(),
        "plak2-7-" + KEY.hex(),
        "plak1-07-" + KEY.hex(),
        "plak1-7-" + KEY.hex().upper(),
        None,
        7,
    ):
        with pytest.raises(AuditError, match="not an audit key"):
            AuditKey.parse(garbage)  # type: ignore[arg-type]


def test_a_second_log_on_the_same_database_continues_the_chain(
    db: Database, clock: FakeClock
) -> None:
    first = AuditLog(db, clock=clock)
    one = first.append("service.started")
    second = AuditLog(db, clock=clock)
    two = second.append("service.stopped")
    assert (two.seq, two.prev_hash) == (2, one.hash)
    assert first.verify().checked == 2


# --- the append-only triggers --------------------------------------------------------


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2", "UPDATE refused"),
        ("UPDATE audit_log SET seq = 99 WHERE seq = 2", "UPDATE refused"),
        ("DELETE FROM audit_log WHERE seq = 2", "DELETE refused"),
        ("DELETE FROM audit_log", "DELETE refused"),
        (
            "INSERT OR REPLACE INTO audit_log SELECT 2, ts, event_type, severity, 'mallory',"
            " device_fp, data, prev_hash, hash, mac FROM audit_log WHERE seq = 2",
            "INSERT out of sequence refused",
        ),
        (
            "INSERT INTO audit_log SELECT 9, ts, event_type, severity, actor,"
            " device_fp, data, prev_hash, hash, mac FROM audit_log WHERE seq = 2",
            "INSERT out of sequence refused",
        ),
        (
            "INSERT INTO audit_log (ts, event_type, severity, data, prev_hash, hash)"
            " SELECT ts, event_type, severity, data, prev_hash, hash FROM audit_log WHERE seq = 2",
            "INSERT out of sequence refused",
        ),
    ],
)
def test_triggers_refuse_everything_but_appending(
    log: AuditLog, db: Database, clock: FakeClock, statement: str, message: str
) -> None:
    records = fill(log, clock, 3)
    with pytest.raises(StoreError, match=message):
        db.execute(statement)
    assert log.query(descending=False) == records
    assert log.verify().ok
    assert log.append("service.stopped").seq == 4  # the real path still works


# --- reading -------------------------------------------------------------------------


def test_get_count_head_and_tail(log: AuditLog, clock: FakeClock) -> None:
    assert log.count() == 0
    assert log.head() == (0, GENESIS_HASH)
    assert log.get(1) is None
    assert log.tail(5) == []
    records = fill(log, clock, 5)
    assert log.count() == 5
    assert log.head() == (5, records[-1].hash)
    assert log.get(3) == records[2]
    assert log.get(6) is None and log.get(0) is None and log.get(-1) is None
    assert log.get(2**63 - 1) is None and log.get(2**63) is None and log.get(2**200) is None
    assert log.tail(2) == records[3:]
    assert [record.seq for record in log.tail(50)] == [1, 2, 3, 4, 5]
    assert [record.seq for record in log.iterate(since_seq=4)] == [4, 5]
    for bad in ("3", 3.0, True, None):
        with pytest.raises(AuditError):
            log.get(bad)  # type: ignore[arg-type]
    with pytest.raises(AuditError):
        log.tail(0)
    with pytest.raises(AuditError):
        list(log.iterate(since_seq=0))


@pytest.fixture
def varied(log: AuditLog, clock: FakeClock) -> AuditLog:
    """Eight records, one second apart, starting at 00:00:01."""
    entries: list[tuple[str, dict[str, Any]]] = [
        ("service.started", {"actor": "system"}),
        ("device.connected", {"device_fp": FP, "data": {"product": "Example Flash 16GB"}}),
        ("decision.made", {"device_fp": FP, "data": {"access": "deny", "note": "100%_sure"}}),
        ("enforcement.failed", {"device_fp": FP, "data": {"path": "C:\\dev\\x", "q": 'say "no"'}}),
        ("auth.failure", {"actor": "alice", "data": {"reason": "bad credentials"}}),
        ("auth.lockout", {"actor": "alice"}),
        ("device.connected", {"device_fp": FP2, "data": {"product": "Caf" + chr(0xE9) + " Drive"}}),
        ("killswitch.activated", {"actor": "system", "data": {"lines": "a\nb"}}),
    ]
    for event_type, fields in entries:
        clock.advance(1)
        log.append(event_type, **fields)
    return log


def seqs(records: list[AuditRecord]) -> list[int]:
    return [record.seq for record in records]


def test_query_defaults_to_newest_first(varied: AuditLog) -> None:
    assert seqs(varied.query()) == [8, 7, 6, 5, 4, 3, 2, 1]
    assert seqs(varied.query(descending=False)) == [1, 2, 3, 4, 5, 6, 7, 8]
    assert seqs(varied.query(limit=3)) == [8, 7, 6]
    assert seqs(varied.query(limit=3, descending=False)) == [1, 2, 3]


def test_query_by_sequence_bounds_is_inclusive(varied: AuditLog) -> None:
    assert seqs(varied.query(since_seq=6)) == [8, 7, 6]
    assert seqs(varied.query(until_seq=2)) == [2, 1]
    assert seqs(varied.query(since_seq=3, until_seq=5, descending=False)) == [3, 4, 5]
    assert varied.query(since_seq=9) == []
    assert varied.query(since_seq=5, until_seq=4) == []


def test_query_by_time_is_inclusive_then_exclusive(varied: AuditLog) -> None:
    third = datetime(2026, 1, 1, 0, 0, 3, tzinfo=UTC)
    fifth = datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
    assert seqs(varied.query(since=third, until=fifth, descending=False)) == [3, 4]
    assert seqs(varied.query(since="2026-01-01T00:00:07Z")) == [8, 7]
    assert seqs(varied.query(until="2026-01-01T00:00:02.000000Z")) == [1]
    with pytest.raises(AuditError, match="since"):
        varied.query(since=datetime(2026, 1, 1, 0, 0, 3))  # naive: refused, not guessed at
    with pytest.raises(AuditError, match="until"):
        varied.query(until="yesterday")
    with pytest.raises(AuditError, match="since"):
        varied.query(since=1767225600)  # type: ignore[arg-type]


def test_query_converts_other_time_zones(varied: AuditLog) -> None:
    east = timezone(timedelta(hours=5, minutes=30))
    since = datetime(2026, 1, 1, 5, 30, 7, tzinfo=east)  # 00:00:07 UTC
    assert seqs(varied.query(since=since)) == [8, 7]


def test_query_by_event_type(varied: AuditLog) -> None:
    assert seqs(varied.query(event_types=["device.connected"])) == [7, 2]
    assert seqs(varied.query(event_types="auth.failure")) == [5]
    assert seqs(varied.query(event_types=["auth.*"])) == [6, 5]
    assert seqs(varied.query(event_types=("auth.*", "service.started", "nothing.here"))) == [
        6,
        5,
        1,
    ]
    assert seqs(varied.query(event_types={"device.*"})) == [7, 2]
    # A prefix matches whole segments only: "auth.*" must not match "authx.y".
    assert varied.query(event_types=["aut.*"]) == []
    assert varied.query(event_types=[]) == []
    for bad in (["Device.*"], ["*"], ["auth.%"], ["a b"], [5], ["x" * 80]):
        with pytest.raises(AuditError, match="invalid event type filter"):
            varied.query(event_types=bad)  # type: ignore[arg-type]
    with pytest.raises(AuditError, match="at most 64"):
        varied.query(event_types=[f"a.b{n}" for n in range(65)])


def test_query_by_minimum_severity(varied: AuditLog) -> None:
    assert seqs(varied.query(min_severity="critical")) == [8]
    assert seqs(varied.query(min_severity=Severity.ERROR)) == [8, 4]
    assert seqs(varied.query(min_severity="warning")) == [8, 6, 5, 4]
    assert len(varied.query(min_severity="debug")) == 8
    with pytest.raises(AuditError, match="unknown severity"):
        varied.query(min_severity="severe")


def test_query_by_device_and_actor(varied: AuditLog) -> None:
    assert seqs(varied.query(device_fp=FP)) == [4, 3, 2]
    assert seqs(varied.query(device_fp=FP2)) == [7]
    assert seqs(varied.query(actor="alice")) == [6, 5]
    assert varied.query(actor="Alice") == []  # exact match
    assert seqs(varied.query(actor="alice", event_types=["auth.lockout"], min_severity="info")) == [
        6
    ]
    assert varied.query(actor="alice", device_fp=FP) == []


def test_query_by_text(varied: AuditLog) -> None:
    assert seqs(varied.query(text="flash")) == [2]  # ASCII case is ignored
    assert seqs(varied.query(text="ALICE")) == [6, 5]  # matches the actor column
    assert seqs(varied.query(text="lockout")) == [6]  # matches the event type
    assert seqs(varied.query(text=FP2[-8:])) == [7]  # matches the fingerprint
    assert seqs(varied.query(text="Caf" + chr(0xE9))) == [7]
    assert varied.query(text="no such thing") == []
    # LIKE wildcards in the needle are literal.
    assert seqs(varied.query(text="100%_sure")) == [3]
    assert varied.query(text="100%sure") == []
    assert varied.query(text="_") == containing(varied, "_")
    assert seqs(varied.query(text="_")) == [3]  # only "100%_sure"; a wildcard would match all
    assert seqs(varied.query(text="%")) == [3]
    # Characters that JSON escapes are found as the user typed them.
    assert seqs(varied.query(text="C:\\dev")) == [4]
    assert seqs(varied.query(text='say "no"')) == [4]
    assert seqs(varied.query(text="a\nb")) == [8]
    for bad in ("", "x" * 257, 5, chr(0xDC00)):
        with pytest.raises(AuditError, match="text"):
            varied.query(text=bad)  # type: ignore[arg-type]


def containing(log: AuditLog, text: str) -> list[AuditRecord]:
    """Records whose stored columns really contain ``text`` (the oracle for LIKE tests)."""

    def strings(value: Any) -> Iterator[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                yield key
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)
        elif isinstance(value, str):
            yield value
        else:
            yield json.dumps(value)

    return [
        record
        for record in log.query()
        if any(
            text.lower() in candidate.lower()
            for candidate in (
                record.event_type,
                record.actor or "",
                record.device_fp or "",
                *strings(dict(record.data)),
            )
        )
    ]


@pytest.mark.parametrize(
    "hostile",
    ["' OR '1'='1", "'; DROP TABLE audit_log; --", '" OR 1=1 --', "\\", "x' UNION SELECT 1 --"],
)
def test_filters_are_bound_not_spliced(varied: AuditLog, hostile: str) -> None:
    # A lone backslash is the one hostile string that really occurs (in the Windows path).
    assert seqs(varied.query(text=hostile)) == ([4] if hostile == chr(92) else [])
    assert varied.query(text=hostile) == containing(varied, hostile)
    assert varied.query(actor=hostile) == []
    assert varied.query(device_fp=hostile) == []
    with pytest.raises(AuditError):
        varied.query(event_types=[hostile])
    assert varied.count() == 8
    assert varied.verify().ok


@pytest.mark.parametrize("limit", [0, -1, "10", 2.5, True, None])
def test_query_limit_must_be_a_positive_integer(varied: AuditLog, limit: Any) -> None:
    with pytest.raises(AuditError, match="limit"):
        varied.query(limit=limit)


@pytest.mark.parametrize("name", ["since_seq", "until_seq"])
@pytest.mark.parametrize("value", [-1, "1", 1.5, True])
def test_query_sequence_bounds_are_validated(varied: AuditLog, name: str, value: Any) -> None:
    with pytest.raises(AuditError, match=name):
        varied.query(**{name: value})


def test_query_limit_is_capped(log: AuditLog) -> None:
    for index in range(MAX_QUERY_LIMIT + 5):
        log.append("device.connected", data={"n": index})
    newest = log.query(limit=10**9)
    assert len(newest) == MAX_QUERY_LIMIT
    assert (newest[0].seq, newest[-1].seq) == (MAX_QUERY_LIMIT + 5, 6)
    assert len(log.tail(10**9)) == MAX_QUERY_LIMIT
    assert len(log.query()) == 100  # the default


# --- verification --------------------------------------------------------------------


def test_an_empty_log_verifies(log: AuditLog) -> None:
    assert log.verify() == VerifyResult(True, 0, None, None, 0, None)
    assert log.verify(expected_head=(0, GENESIS_HASH)).ok


def test_an_intact_log_verifies(log: AuditLog, clock: FakeClock) -> None:
    records = fill(log, clock, 6)
    result = log.verify()
    assert result == VerifyResult(True, 6, None, None, 0, (6, records[-1].hash))
    assert log.verify(expected_head=log.head()).ok
    assert log.verify(expected_head=(3, records[2].hash)).ok
    assert log.verify(expected_head=(0, GENESIS_HASH)).ok


def test_an_intact_keyed_log_verifies_every_mac_with_the_initial_key(
    keyed: AuditLog, clock: FakeClock, initial_key: AuditKey
) -> None:
    records = fill(keyed, clock, 4)
    head = (4, records[-1].hash)
    assert keyed.verify(initial_key=initial_key) == VerifyResult(True, 4, None, None, 4, head)
    # The running log only holds the next key, so on its own it checks the chain only.
    assert keyed.verify() == VerifyResult(True, 4, None, None, 0, head)
    # The key can be written down as text and read back.
    restored = AuditKey.parse(initial_key.encode())
    assert keyed.verify(initial_key=restored).macs_checked == 4
    later = keyed.verify(start_seq=3, initial_key=initial_key)
    assert (later.ok, later.checked, later.macs_checked) == (True, 2, 2)


def test_verify_refuses_an_initial_key_of_the_wrong_type(keyed: AuditLog) -> None:
    for wrong in (KEY, KEY.hex(), (0, KEY)):
        with pytest.raises(AuditError, match="initial_key must be an AuditKey"):
            keyed.verify(initial_key=wrong)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("column", "value", "reason"),
    [
        ("ts", "2026-01-01T00:00:03.000001Z", "was altered"),
        ("event_type", "device.removed", "was altered"),
        ("severity", "debug", "was altered"),
        ("actor", "mallory", "was altered"),
        ("device_fp", FP2, "was altered"),
        ("device_fp", None, "was altered"),
        ("data", '{"n":7}', "was altered"),
        ("data", "{}", "was altered"),
        ("hash", "ab" * 32, "was altered"),
        ("prev_hash", "cd" * 32, "does not link"),
    ],
)
def test_a_modified_field_is_detected(
    log: AuditLog, db: Database, clock: FakeClock, column: str, value: Any, reason: str
) -> None:
    records = fill(log, clock, 6)
    unprotect(db)
    tamper(db, column, "?", (value,))
    result = log.verify()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.checked == 2
    assert result.head == (2, records[1].hash)
    assert result.reason is not None and reason in result.reason and "record 3" in result.reason


def test_changing_a_hash_breaks_the_next_link(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 4)
    unprotect(db)
    # Forge record 2 completely, with a hash that matches its new contents.
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    row = db.query_one(SELECT + " WHERE seq = 2")
    assert row is not None
    forged = record_hash(
        row["prev_hash"],
        seq=2,
        ts=row["ts"],
        event_type=row["event_type"],
        severity=row["severity"],
        actor="mallory",
        device_fp=row["device_fp"],
        data=json.loads(row["data"]),
    )
    db.execute("UPDATE audit_log SET hash = ? WHERE seq = 2", (forged,))
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 3, 2)
    assert result.reason is not None and "does not link to record 2" in result.reason


@pytest.mark.parametrize("deleted", [1, 3, 5])
def test_a_deleted_record_is_detected(
    log: AuditLog, db: Database, clock: FakeClock, deleted: int
) -> None:
    fill(log, clock, 6)
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq = ?", (deleted,))
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, deleted, deleted - 1)
    assert result.reason == (
        f"record {deleted} is missing (the next record present is {deleted + 1})"
    )


def test_a_deleted_record_hidden_by_renumbering_is_detected(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 6)
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq = 3")
    db.execute("UPDATE audit_log SET seq = seq - 1 WHERE seq > 3")
    assert log.count() == 5
    result = log.verify()
    assert (result.ok, result.first_bad_seq) == (False, 3)
    assert result.reason is not None and "does not link to record 2" in result.reason


def test_reordered_records_are_detected(log: AuditLog, db: Database, clock: FakeClock) -> None:
    fill(log, clock, 6)
    unprotect(db)
    db.execute("UPDATE audit_log SET seq = 1000 WHERE seq = 3")
    db.execute("UPDATE audit_log SET seq = 3 WHERE seq = 4")
    db.execute("UPDATE audit_log SET seq = 4 WHERE seq = 1000")
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 3, 2)
    assert result.reason is not None and "reordered" in result.reason


def test_an_inserted_record_is_detected(log: AuditLog, db: Database, clock: FakeClock) -> None:
    records = fill(log, clock, 3)
    unprotect(db)
    forged = record_hash(
        "ee" * 32,
        seq=4,
        ts="2026-01-01T00:00:09.000000Z",
        event_type="trust.added",
        severity="notice",
        actor="mallory",
        device_fp=FP2,
        data={},
    )
    db.execute(
        "INSERT INTO audit_log VALUES (4, '2026-01-01T00:00:09.000000Z',"
        " 'trust.added', 'notice', 'mallory', ?, '{}', ?, ?, NULL)",
        (FP2, "ee" * 32, forged),
    )
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.head) == (False, 4, (3, records[2].hash))


def test_truncation_is_detected_only_with_an_expected_head(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 6)
    saved = log.head()
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq > 4")
    # The honest limit of a hash chain: a shorter chain is still a valid chain.
    assert log.verify().ok
    result = log.verify(expected_head=saved)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 5, 4)
    assert result.reason == (
        "the log ends at record 4 but record 6 was expected: the tail was truncated"
    )


def test_a_truncated_and_regrown_log_is_detected(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 6)
    saved = log.head()
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq > 4")
    fill(log, clock, 4)  # different timestamps, so different hashes at 5 and 6
    assert log.verify().ok
    result = log.verify(expected_head=saved)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 6, 5)
    assert result.reason is not None and "expected hash" in result.reason


def test_emptying_the_log_is_detected_with_an_expected_head(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 2)
    saved = log.head()
    unprotect(db)
    db.execute("DELETE FROM audit_log")
    assert log.verify().ok
    result = log.verify(expected_head=saved)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 1, 0)


def test_a_rechained_forgery_passes_without_a_key_but_not_against_a_saved_head(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 6)
    saved = log.head()
    unprotect(db)
    db.execute("UPDATE audit_log SET data = ? WHERE seq = 2", ('{"n":"forged"}',))
    rechain(db, 2)
    # Stated plainly in the design: a consistent rebuilt chain verifies on its own.
    assert log.verify() == VerifyResult(True, 6, None, None, 0, log.head())
    assert log.get(2).data == {"n": "forged"}  # type: ignore[union-attr]
    result = log.verify(expected_head=saved)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 6, 5)
    assert result.reason is not None and "rewritten" in result.reason


@pytest.mark.parametrize("mac", ["keep", None, "ab" * 32])
def test_a_rechained_forgery_is_detected_with_the_initial_key(
    keyed: AuditLog, db: Database, clock: FakeClock, initial_key: AuditKey, mac: str | None
) -> None:
    records = fill(keyed, clock, 6)
    unprotect(db)
    db.execute("UPDATE audit_log SET data = ? WHERE seq = 2", ('{"n":"forged"}',))
    rechain(db, 2, mac=mac)
    result = keyed.verify(initial_key=initial_key)
    assert (result.ok, result.first_bad_seq, result.checked, result.macs_checked) == (
        False,
        2,
        1,
        1,
    )
    assert result.head == (1, records[0].hash)
    assert result.reason is not None
    assert ("no MAC" if mac is None else "MAC that does not match") in result.reason
    # The same database read without the key shows why the key matters.
    assert keyed.verify().ok


def test_the_wrong_initial_key_does_not_verify(
    keyed: AuditLog, clock: FakeClock, initial_key: AuditKey
) -> None:
    fill(keyed, clock, 3)
    for wrong in (AuditKey(0, OTHER_KEY), AuditKey(1, initial_key.key)):
        result = keyed.verify(initial_key=wrong)
        assert (result.ok, result.macs_checked) == (False, 0)
        assert result.reason is not None and "wrong initial key" in result.reason


def test_a_log_that_gained_its_key_later_checks_macs_after_the_anchor(
    db: Database, clock: FakeClock, key_path: Path
) -> None:
    fill(AuditLog(db, clock=clock), clock, 2)
    store, initial = AuditKeyStore.create(key_path, anchor_seq=2)
    assert initial.anchor_seq == 2 and stored_key(key_path) == (3, initial.key_for(3))
    keyed = AuditLog(db, clock=clock, key_store=store)
    records = fill(keyed, clock, 3)
    assert [record.mac is None for record in keyed.iterate()] == [True, True, False, False, False]
    assert records[0].mac == record_mac(independent_key(initial.key, 1), records[0].hash)
    result = keyed.verify(initial_key=initial)
    assert (result.ok, result.checked, result.macs_checked) == (True, 5, 3)
    # Anchored at 0 instead, the same key demands MACs the first records never had.
    wrong = keyed.verify(initial_key=AuditKey(0, initial.key))
    assert (wrong.ok, wrong.first_bad_seq) == (False, 1)
    assert wrong.reason == "record 1 has no MAC although the log is keyed from 1"
    # Without the key the hashes still verify, and the result says no MAC was checked.
    unkeyed = AuditLog(db, clock=clock).verify()
    assert (unkeyed.ok, unkeyed.checked, unkeyed.macs_checked) == (True, 5, 0)


# --- forward security ----------------------------------------------------------------


def test_the_key_store_only_ever_holds_the_next_key(
    keyed: AuditLog, clock: FakeClock, key_path: Path, initial_key: AuditKey, state_dir: Path
) -> None:
    # k_0 is handed out once and never written: the file starts at k_1.
    assert stored_key(key_path) == (1, independent_key(initial_key.key, 1))
    for count in range(1, 6):
        keyed.append("device.connected", data={"n": count})
        assert stored_key(key_path) == (count + 1, independent_key(initial_key.key, count + 1))
    # No earlier key, in any spelling, survives anywhere in the state directory.
    leftovers = b"".join(path.read_bytes() for path in state_dir.iterdir())
    assert sorted(path.name for path in state_dir.iterdir()) == ["audit.key"]
    for step in range(6):
        old = independent_key(initial_key.key, step)
        assert old not in leftovers and old.hex().encode() not in leftovers
    assert keyed.verify(initial_key=initial_key).macs_checked == 5


@pytest.mark.parametrize("target", [1, 4, 8])
def test_the_current_key_cannot_produce_a_valid_mac_for_any_earlier_record(
    keyed: AuditLog,
    db: Database,
    clock: FakeClock,
    key_path: Path,
    initial_key: AuditKey,
    target: int,
) -> None:
    records = fill(keyed, clock, 8)
    # The intruder takes over now and reads everything PortLock has: the key store.
    position, current = stored_key(key_path)
    assert position == 9
    reachable = {ratchet_key(current, steps) for steps in range(64)}
    earlier = {independent_key(initial_key.key, seq) for seq in range(9)}
    assert reachable.isdisjoint(earlier), "no earlier key can be computed from the current one"

    # They rewrite one earlier record, rebuild the chain after it, and MAC every record
    # they touched with the best keys they have.
    unprotect(db)
    tamper_seq = target
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = ?", (tamper_seq,))
    rechain(db, tamper_seq)
    for seq in range(tamper_seq, 9):
        remac(db, seq, current)
    assert keyed.verify().ok, "the chain alone cannot tell"
    result = keyed.verify(initial_key=initial_key)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, target, target - 1)
    assert result.reason is not None and "MAC that does not match" in result.reason
    assert result.head == ((target - 1, records[target - 2].hash) if target > 1 else None)

    # Any key they can derive gives the same answer.
    for steps in (1, 2, 30):
        remac(db, tamper_seq, ratchet_key(current, steps))
        assert keyed.verify(initial_key=initial_key).first_bad_seq == target


def test_what_the_current_key_can_still_do_is_append(
    keyed: AuditLog, db: Database, clock: FakeClock, key_path: Path, initial_key: AuditKey
) -> None:
    """The documented limit: a forged record *after* the takeover verifies."""
    fill(keyed, clock, 3)
    _, current = stored_key(key_path)
    forged = AuditLog(db, clock=clock)
    record = forged.append("trust.added", actor="mallory")
    unprotect(db)
    remac(db, record.seq, current)
    assert keyed.verify(initial_key=initial_key).ok


@pytest.mark.parametrize("damage", ["modified", "deleted", "reordered"])
def test_verification_with_the_initial_key_pinpoints_the_damaged_record(
    keyed: AuditLog,
    db: Database,
    clock: FakeClock,
    key_path: Path,
    initial_key: AuditKey,
    damage: str,
) -> None:
    fill(keyed, clock, 7)
    _, current = stored_key(key_path)
    unprotect(db)
    if damage == "modified":
        db.execute("UPDATE audit_log SET data = '{\"n\":99}' WHERE seq = 4")
    elif damage == "deleted":
        db.execute("DELETE FROM audit_log WHERE seq = 4")
        db.execute("UPDATE audit_log SET seq = seq - 1 WHERE seq > 4")
    else:
        db.execute("UPDATE audit_log SET seq = 1000 WHERE seq = 4")
        db.execute("UPDATE audit_log SET seq = 4 WHERE seq = 5")
        db.execute("UPDATE audit_log SET seq = 5 WHERE seq = 1000")
    # The forger repairs the chain and MACs with the only key they have.
    rechain(db, 4)
    for seq in range(4, keyed.count() + 1):
        remac(db, seq, current)
    result = keyed.verify(initial_key=initial_key)
    assert (result.ok, result.first_bad_seq, result.checked, result.macs_checked) == (
        False,
        4,
        3,
        3,
    )
    assert result.reason == (
        "record 4 has a MAC that does not match: it was altered or re-chained by someone "
        "without its key, or the wrong initial key was given"
    )


def test_an_untouched_log_verifies_with_the_initial_key_after_a_restart(
    tmp_path: Path, clock: FakeClock, key_path: Path
) -> None:
    path = tmp_path / "audit.db"
    _, initial = AuditKeyStore.create(key_path)
    for _ in range(3):
        with Database(path) as db:
            fill(AuditLog(db, clock=clock, key_store=AuditKeyStore(key_path)), clock, 4)
    with Database(path) as db:
        result = AuditLog(db, clock=clock).verify(initial_key=initial)
        assert (result.ok, result.checked, result.macs_checked) == (True, 12, 12)


# --- the key store file --------------------------------------------------------------


def test_creating_a_key_store_never_replaces_one(key_path: Path, created: Any) -> None:
    before = key_path.read_bytes()
    with pytest.raises(AuditError, match="already exists"):
        AuditKeyStore.create(key_path)
    assert key_path.read_bytes() == before
    assert sorted(os.listdir(key_path.parent)) == ["audit.key"]  # no staging file left


def test_a_key_store_is_created_in_a_new_private_directory(tmp_path: Path) -> None:
    path = tmp_path / "new" / "keys" / "audit.key"
    store, initial = AuditKeyStore.create(path, anchor_seq=41)
    assert store.path == path and store.position == 42
    assert stored_key(path) == (42, independent_key(initial.key, 1))
    assert repr(store) == f"AuditKeyStore({str(path)!r})"
    assert initial.key.hex() not in repr(store)


def test_creating_a_key_store_without_hard_links_still_refuses_to_replace(
    key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_links(_source: Any, _target: Any) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(log_module.os, "link", no_links)
    store, initial = AuditKeyStore.create(key_path)
    assert store.position == 1
    with pytest.raises(AuditError, match="already exists"):
        AuditKeyStore.create(key_path)
    assert stored_key(key_path) == (1, initial.key_for(1))
    assert sorted(os.listdir(key_path.parent)) == ["audit.key"]


def test_a_key_store_that_cannot_be_created_is_reported(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"")
    with pytest.raises(AuditError, match="cannot create the audit MAC key store"):
        AuditKeyStore.create(blocker / "audit.key")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "does not exist"),
        (b"", "not in the stored format"),
        (b"{}", "not in the stored format"),
        (b'{"key":"' + b"ab" * 32 + b'","seq":1}', "not in the stored format"),
        (b'{"key":"' + b"ab" * 32 + b'","seq":1,"v":2}', "not in the stored format"),
        (b'{"key":"' + b"ab" * 31 + b'","seq":1,"v":1}', "not in the stored format"),
        (b'{"key":"' + b"AB" * 32 + b'","seq":1,"v":1}', "not in the stored format"),
        (b'{"key":"' + b"ab" * 32 + b'","seq":0,"v":1}', "not in the stored format"),
        (b'{"key":"' + b"ab" * 32 + b'","seq":"1","v":1}', "not in the stored format"),
        (b'{"key":"' + b"ab" * 32 + b'","seq":1,"v":1} ', "not in the stored format"),
        (b"x" * 5000, "too large"),
    ],
)
def test_a_damaged_key_store_is_refused(
    key_path: Path, content: bytes | None, message: str
) -> None:
    if content is not None:
        key_path.write_bytes(content)
        if sys.platform != "win32":
            key_path.chmod(0o600)
    with pytest.raises(AuditError, match=message):
        AuditKeyStore(key_path)


def test_a_key_store_path_that_is_a_directory_is_refused(key_path: Path) -> None:
    key_path.mkdir()
    with pytest.raises(AuditError, match="not a regular file"):
        AuditKeyStore(key_path)


@pytest.mark.linux_only
def test_key_store_files_are_owner_only(tmp_path: Path, db: Database, clock: FakeClock) -> None:
    path = tmp_path / "keys" / "audit.key"
    store, _ = AuditKeyStore.create(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.stat().st_nlink == 1  # the staging name is gone
    AuditLog(db, clock=clock, key_store=store).append("service.started")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600  # the ratcheted file too


@pytest.mark.linux_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644])
def test_a_key_store_other_users_can_read_is_refused(
    key_path: Path, created: Any, mode: int
) -> None:
    key_path.chmod(mode)
    with pytest.raises(AuditError, match="accessible to other users"):
        AuditKeyStore(key_path)


@pytest.mark.linux_only
def test_a_key_store_that_is_a_symlink_is_refused(key_path: Path, created: Any) -> None:
    link = key_path.with_name("link.key")
    link.symlink_to(key_path)
    with pytest.raises(AuditError, match="not a regular file"):
        AuditKeyStore(link)


def test_a_key_store_left_behind_by_a_crash_catches_up(
    keyed: AuditLog, clock: FakeClock, key_path: Path, initial_key: AuditKey
) -> None:
    fill(keyed, clock, 2)
    stale = key_path.read_bytes()
    fill(keyed, clock, 3)
    # The process died after committing records 3 to 5, before replacing the key file.
    key_path.write_bytes(stale)
    assert keyed.verify(initial_key=initial_key).ok
    fill(keyed, clock, 2)
    assert stored_key(key_path) == (8, independent_key(initial_key.key, 8))
    assert keyed.verify(initial_key=initial_key).macs_checked == 7


def test_a_key_store_ahead_of_the_log_refuses_to_append(
    keyed: AuditLog, db: Database, clock: FakeClock, key_path: Path
) -> None:
    fill(keyed, clock, 4)
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq > 2")
    with pytest.raises(AuditError) as caught:
        keyed.append("service.started")
    assert caught.value.code == "audit_key_ahead"
    assert "records were removed" in str(caught.value)
    assert keyed.count() == 2
    result = keyed.verify()
    assert (result.ok, result.first_bad_seq) == (False, 3)
    assert result.reason == (
        "the MAC key store has moved on to record 5 but the log ends at record 2: records "
        "were removed, or the database was replaced"
    )


def test_a_key_store_implausibly_far_behind_is_refused(
    keyed: AuditLog, db: Database, clock: FakeClock, key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(log_module, "_MAX_RATCHET_STEPS", 3)
    fill(keyed, clock, 3)
    stale = key_path.read_bytes()
    fill(keyed, clock, 1)
    key_path.write_bytes(stale)  # at record 4; record 5 is one step on: fine
    fill(keyed, clock, 1)
    key_path.write_bytes(b'{"key":"' + b"ab" * 32 + b'","seq":1,"v":1}')
    with pytest.raises(AuditError) as caught:
        keyed.append("service.started")
    assert caught.value.code == "audit_key_behind"
    assert keyed.count() == 5


def test_a_key_store_that_cannot_be_updated_is_counted_not_fatal(
    keyed: AuditLog,
    clock: FakeClock,
    key_path: Path,
    initial_key: AuditKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fill(keyed, clock, 1)

    def disk_full(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(log_module, "atomic_write_bytes", disk_full)
    record = keyed.append("service.started")
    assert record.seq == 2 and keyed.count() == 2
    assert keyed.state_failures == 1
    assert stored_key(key_path)[0] == 2, "the key of record 2 is still on disk"
    monkeypatch.undo()
    fill(keyed, clock, 1)
    assert stored_key(key_path)[0] == 4
    assert keyed.verify(initial_key=initial_key).macs_checked == 3


def test_a_writer_never_moves_the_key_store_backwards(
    created: tuple[AuditKeyStore, AuditKey], key_path: Path
) -> None:
    store, initial = created
    store.advance_past(5, initial.key_for(5))
    assert stored_key(key_path) == (6, initial.key_for(6))
    store.advance_past(3, initial.key_for(3))  # a slower writer, late
    assert stored_key(key_path) == (6, initial.key_for(6))
    assert store.key_for(9) == initial.key_for(9)
    with pytest.raises(AuditError) as caught:
        store.key_for(5)
    assert caught.value.code == "audit_key_ahead"


# --- the head file -------------------------------------------------------------------


@pytest.fixture
def head_path(state_dir: Path) -> Path:
    return state_dir / "audit.head"


@pytest.fixture
def headed(db: Database, clock: FakeClock, head_path: Path) -> AuditLog:
    return AuditLog(db, clock=clock, head_path=head_path)


def test_the_head_file_follows_every_append(
    headed: AuditLog, clock: FakeClock, head_path: Path
) -> None:
    assert headed.head_path == head_path
    assert read_head_file(head_path) is None
    assert headed.verify() == VerifyResult(True, 0, None, None, 0, None, False)
    for _ in range(3):
        (record,) = fill(headed, clock, 1)
        assert read_head_file(head_path) == (record.seq, record.hash)
    assert json.loads(head_path.read_bytes()) == {"hash": headed.head()[1], "seq": 3, "v": 1}
    result = headed.verify()
    assert result == VerifyResult(True, 3, None, None, 0, headed.head(), True)


def test_the_head_file_detects_a_truncated_log(
    headed: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(headed, clock, 6)
    unprotect(db)
    db.execute("DELETE FROM audit_log WHERE seq > 4")
    result = headed.verify()
    assert (result.ok, result.first_bad_seq, result.checked, result.head_checked) == (
        False,
        5,
        4,
        False,
    )
    assert result.reason == (
        "the log ends at record 4 but the head file names record 6: records were removed, "
        "or the database was replaced by an older copy"
    )


def test_the_head_file_detects_a_replaced_database(
    tmp_path: Path, clock: FakeClock, head_path: Path
) -> None:
    with Database(tmp_path / "real.db") as real:
        fill(AuditLog(real, clock=clock, head_path=head_path), clock, 5)
    # Someone substitutes a database built elsewhere, of the same length.
    with Database(tmp_path / "substitute.db") as substitute:
        clock.advance(100)
        fill(AuditLog(substitute, clock=clock), clock, 5)
        result = AuditLog(substitute, clock=clock, head_path=head_path).verify()
        assert (result.ok, result.first_bad_seq) == (False, 5)
        assert result.reason == (
            "record 5 does not match the head file: the log was rewritten or replaced"
        )


def test_a_rechained_forgery_is_caught_by_the_head_file_without_any_key(
    headed: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(headed, clock, 5)
    unprotect(db)
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2")
    rechain(db, 2)
    result = headed.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 5, 5)


def test_a_missing_or_damaged_head_file_fails_verification(
    headed: AuditLog, clock: FakeClock, head_path: Path
) -> None:
    fill(headed, clock, 2)
    head_path.unlink()
    result = headed.verify()
    assert (result.ok, result.first_bad_seq) == (False, None)
    assert result.reason == (
        "the head file is missing although the log has records: it was deleted, or the "
        "database was replaced"
    )
    head_path.write_bytes(b"not json")
    result = headed.verify()
    assert result.ok is False and result.reason is not None
    assert result.reason.startswith("the head file cannot be used:")
    # A damaged head file is left for verification to report, and the failure counted.
    fill(headed, clock, 1)
    assert head_path.read_bytes() == b"not json"
    assert headed.state_failures == 1


@pytest.mark.parametrize(
    "content",
    [
        b'{"hash":"' + b"ab" * 32 + b'","seq":1}',
        b'{"hash":"' + b"ab" * 31 + b'","seq":1,"v":1}',
        b'{"hash":"' + b"ab" * 32 + b'","seq":0,"v":1}',
        b'{"hash":"' + b"ab" * 32 + b'","seq":true,"v":1}',
        b'{"hash":7,"seq":1,"v":1}',
        b"[]",
    ],
)
def test_read_head_file_refuses_anything_it_did_not_write(head_path: Path, content: bytes) -> None:
    head_path.write_bytes(content)
    with pytest.raises(AuditError, match="audit head file is not in the stored format"):
        read_head_file(head_path)


def test_the_head_file_never_moves_backwards(
    db: Database, clock: FakeClock, head_path: Path
) -> None:
    first = AuditLog(db, clock=clock, head_path=head_path)
    records = fill(first, clock, 3)
    # A slower writer that committed record 2 earlier writes its head late.
    first._after_commit(2, records[1].hash, None)
    assert read_head_file(head_path) == (3, records[2].hash)
    assert first.verify().ok


@pytest.mark.linux_only
def test_a_head_file_others_can_write_is_refused(
    headed: AuditLog, clock: FakeClock, head_path: Path
) -> None:
    fill(headed, clock, 1)
    assert stat.S_IMODE(head_path.stat().st_mode) == 0o600
    head_path.chmod(0o622)
    with pytest.raises(AuditError, match="accessible to other users"):
        read_head_file(head_path)
    head_path.chmod(0o644)  # readable by others is fine: it holds no secret
    assert read_head_file(head_path) is not None


# --- starting again after damage -----------------------------------------------------


def damaged_database(tmp_path: Path, clock: FakeClock, head_path: Path, key_path: Path) -> Path:
    """A database with five records whose file was then moved aside, as 14.23 says."""
    original = tmp_path / "portlock.db"
    with Database(original) as old:
        store, _ = AuditKeyStore.create(key_path)
        fill(AuditLog(old, clock=clock, key_store=store, head_path=head_path), clock, 5)
    aside = tmp_path / "portlock.db.damaged"
    original.rename(aside)
    return aside


def test_a_fresh_log_names_the_damaged_database_and_its_last_head(
    tmp_path: Path, clock: FakeClock, head_path: Path, key_path: Path
) -> None:
    aside = damaged_database(tmp_path, clock, head_path, key_path)
    old_head = read_head_file(head_path)
    assert old_head is not None and old_head[0] == 5
    old_key = key_path.read_bytes()
    with Database(tmp_path / "portlock.db") as db:
        fresh = AuditLog.start_fresh(
            db,
            clock=clock,
            damaged_path=aside,
            key_store_path=key_path,
            head_path=head_path,
            reason="integrity_check failed",
        )
        record = fresh.record
        assert (record.seq, record.event_type, record.severity) == (
            1,
            "store.recovered",
            Severity.CRITICAL,
        )
        assert record.actor == "system"
        assert dict(record.data) == {
            "damaged_file": "portlock.db.damaged",
            "damaged_sha256": hashlib.sha256(aside.read_bytes()).hexdigest(),
            "damaged_bytes": aside.stat().st_size,
            "last_known_head": {"seq": 5, "hash": old_head[1]},
            "head_source": "head_file",
            "reason": "integrity_check failed",
        }
        # A new key store with a new k_0, and the head file now follows the new log.
        assert fresh.initial_key is not None and fresh.initial_key.anchor_seq == 0
        assert key_path.read_bytes() != old_key
        assert read_head_file(head_path) == (1, record.hash)
        fresh.log.append("service.started")
        result = fresh.log.verify(initial_key=fresh.initial_key)
        assert (result.ok, result.checked, result.macs_checked, result.head_checked) == (
            True,
            2,
            2,
            True,
        )
    assert aside.exists(), "the damaged file is never deleted"


def test_a_fresh_log_can_take_the_head_from_the_caller_or_go_without(
    tmp_path: Path, clock: FakeClock, head_path: Path, key_path: Path
) -> None:
    aside = damaged_database(tmp_path, clock, head_path, key_path)
    with Database(tmp_path / "one.db") as db:
        fresh = AuditLog.start_fresh(
            db, clock=clock, damaged_path=aside, last_known_head=(9, "cd" * 32)
        )
        assert fresh.record.data["last_known_head"] == {"seq": 9, "hash": "cd" * 32}
        assert fresh.record.data["head_source"] == "caller"
        assert fresh.initial_key is None and fresh.record.mac is None
    with Database(tmp_path / "two.db") as db:
        fresh = AuditLog.start_fresh(db, clock=clock, damaged_path=aside)
        assert fresh.record.data["last_known_head"] is None
        assert fresh.record.data["head_source"] == "none"
        assert "reason" not in fresh.record.data
    head_path.write_bytes(b"garbage")
    with Database(tmp_path / "three.db") as db:
        fresh = AuditLog.start_fresh(db, clock=clock, damaged_path=aside, head_path=head_path)
        assert fresh.record.data["head_source"] == "head_file_unreadable"
        assert read_head_file(head_path) == (1, fresh.record.hash)


def test_a_fresh_log_refuses_a_used_database_or_bad_input(
    tmp_path: Path, db: Database, clock: FakeClock, head_path: Path, key_path: Path
) -> None:
    aside = damaged_database(tmp_path, clock, head_path, key_path)
    AuditLog(db, clock=clock).append("service.started")
    with pytest.raises(AuditError, match="empty database"):
        AuditLog.start_fresh(db, clock=clock, damaged_path=aside, key_store_path=key_path)
    assert key_path.exists(), "nothing is touched when the request is refused"
    with Database() as empty:
        with pytest.raises(AuditError, match="cannot read"):
            AuditLog.start_fresh(empty, clock=clock, damaged_path=tmp_path / "absent.db")
        with pytest.raises(AuditError, match="not a regular file"):
            AuditLog.start_fresh(empty, clock=clock, damaged_path=tmp_path)
        for head in ((0, "ab" * 32), (1, "AB" * 32), [1, "ab" * 32], (1,)):
            with pytest.raises(AuditError, match="last_known_head"):
                AuditLog.start_fresh(
                    empty,
                    clock=clock,
                    damaged_path=aside,
                    last_known_head=head,  # type: ignore[arg-type]
                )
        with pytest.raises(AuditError, match="reason"):
            AuditLog.start_fresh(empty, clock=clock, damaged_path=aside, reason="line\nbreak")
        assert AuditLog(empty, clock=clock).count() == 0


def test_verify_from_a_later_record(log: AuditLog, db: Database, clock: FakeClock) -> None:
    records = fill(log, clock, 6)
    assert log.verify(start_seq=4) == VerifyResult(True, 3, None, None, 0, (6, records[5].hash))
    assert log.verify(start_seq=7) == VerifyResult(True, 0, None, None, 0, None)
    beyond = log.verify(start_seq=9)
    assert (beyond.ok, beyond.first_bad_seq, beyond.reason) == (False, 8, "record 8 is missing")
    # An expected head that lies before the starting point is still compared.
    assert log.verify(start_seq=4, expected_head=(2, records[1].hash)).ok
    stale = log.verify(start_seq=4, expected_head=(2, "ab" * 32))
    assert (stale.ok, stale.first_bad_seq) == (False, 2)

    unprotect(db)
    db.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 5")
    result = log.verify(start_seq=4)
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 5, 1)
    db.execute("DELETE FROM audit_log WHERE seq = 3")
    missing_anchor = log.verify(start_seq=4)
    assert (missing_anchor.ok, missing_anchor.first_bad_seq) == (False, 3)


@pytest.mark.parametrize(
    ("column", "sql_value", "fragment"),
    [
        ("hash", "'" + "zz" * 32 + "'", "hash is not in the stored format"),
        ("hash", "'" + "AB" * 32 + "'", "hash is not in the stored format"),
        ("prev_hash", "x'" + "00" * 64 + "'", "prev_hash is not in the stored format"),
        ("ts", "'last tuesday'", "ts is not in the stored format"),
        ("ts", "20260101", "ts is not in the stored format"),
        ("data", "'not json'", "not valid JSON"),
        ("data", "'[1,2]'", "data is not an object"),
        ("data", "'{\"n\": 2}'", "not in canonical form"),
        ("data", "'{\"n\":2.5}'", "integers"),
        ("data", "x'7b7d'", "data is not text"),
        ("mac", "'" + "zz" * 32 + "'", "mac is not in the stored format"),
        ("event_type", "x'6162'", "event_type is not text"),
        ("actor", "x'6162'", "actor is not text"),
    ],
)
def test_malformed_stored_values_are_reported_not_raised(
    log: AuditLog, db: Database, clock: FakeClock, column: str, sql_value: str, fragment: str
) -> None:
    fill(log, clock, 4)
    unprotect(db)
    tamper(db, column, sql_value)
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 3, 2)
    assert result.reason is not None and fragment in result.reason


def test_undecodable_text_is_reported_at_the_right_record(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    records = fill(log, clock, 5)
    unprotect(db)
    db.execute("UPDATE audit_log SET actor = CAST(x'ff' AS TEXT) WHERE seq = 4")
    result = log.verify()
    assert (result.ok, result.first_bad_seq, result.checked) == (False, 4, 3)
    assert result.head == (3, records[2].hash)
    assert result.reason is not None and "record 4 cannot be read" in result.reason


def test_an_unreadable_database_is_reported_not_raised(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 2)
    db.execute("DROP TABLE audit_log")
    result = log.verify()
    assert (result.ok, result.checked) == (False, 0)
    assert result.first_bad_seq is None
    assert result.reason is not None and "could not be read" in result.reason
    assert "no such table" in result.reason


@pytest.mark.parametrize(
    "expected_head",
    [
        (1,),
        (1, "abc"),
        ("1", "ab" * 32),
        (-1, "ab" * 32),
        (True, "ab" * 32),
        (2**63, "ab" * 32),
        (1, "AB" * 32),
        (1, "ab" * 32, 2),
        [1, "ab" * 32],
        5,
    ],
)
def test_verify_rejects_malformed_arguments(log: AuditLog, expected_head: Any) -> None:
    with pytest.raises(AuditError, match="expected_head"):
        log.verify(expected_head=expected_head)


@pytest.mark.parametrize("start_seq", [0, -3, "1", 1.0, True, None, 2**63, 2**200])
def test_verify_rejects_a_malformed_start(log: AuditLog, start_seq: Any) -> None:
    with pytest.raises(AuditError, match="start_seq"):
        log.verify(start_seq=start_seq)


def test_sequence_numbers_sqlite_cannot_hold_are_refused_cleanly(
    log: AuditLog, clock: FakeClock
) -> None:
    """A number past 2**63 - 1 must be an AuditError, never an OverflowError from SQLite."""
    records = fill(log, clock, 3)
    largest, too_large = 2**63 - 1, 2**63
    for call in (
        lambda: log.verify(start_seq=too_large),
        lambda: log.verify(expected_head=(too_large, "ab" * 32)),
        lambda: log.verify(start_seq=3, expected_head=(too_large, "ab" * 32)),
        lambda: list(log.iterate(since_seq=too_large)),
        lambda: log.export_jsonl(io.BytesIO(), since_seq=too_large),
        lambda: log.query(since_seq=too_large),
        lambda: log.query(until_seq=too_large),
    ):
        with pytest.raises(AuditError, match=f"integer from [01] to {largest}|expected_head"):
            call()

    # The largest number SQLite can hold is a legitimate argument everywhere.
    beyond = log.verify(start_seq=largest)
    assert (beyond.ok, beyond.first_bad_seq, beyond.checked) == (False, largest - 1, 0)
    truncated = log.verify(expected_head=(largest, "ab" * 32))
    assert (truncated.ok, truncated.first_bad_seq, truncated.checked) == (False, 4, 3)
    assert truncated.reason is not None and "truncated" in truncated.reason
    assert truncated.head == (3, records[2].hash)
    assert list(log.iterate(since_seq=largest)) == []
    assert log.export_jsonl(io.BytesIO(), since_seq=largest) == 0
    assert log.query(since_seq=largest) == []
    assert seqs(log.query(until_seq=largest)) == [3, 2, 1]
    assert log.verify().ok and log.count() == 3


def test_an_expected_head_of_zero_must_be_the_genesis_hash(log: AuditLog, clock: FakeClock) -> None:
    fill(log, clock, 2)
    result = log.verify(expected_head=(0, "ab" * 32))
    assert (result.ok, result.first_bad_seq, result.checked) == (False, None, 0)
    assert result.reason is not None and "genesis" in result.reason


def test_verify_streams_in_bounded_batches(
    log: AuditLog, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    total = 1203
    for index in range(total):
        log.append("device.connected", data={"n": index})
    sizes: list[int] = []
    real_query = db.query

    def counting_query(sql: str, params: Any = ()) -> list[Any]:
        rows = real_query(sql, params)
        sizes.append(len(rows))
        return rows

    monkeypatch.setattr(db, "query", counting_query)
    result = log.verify()
    assert (result.ok, result.checked) == (True, total)
    assert max(sizes) == 500 and sum(sizes) == total
    assert len(sizes) >= 4  # 500 + 500 + 203 + the empty batch that ends the walk


def test_appending_to_a_corrupt_tail_is_refused(
    log: AuditLog, db: Database, clock: FakeClock
) -> None:
    fill(log, clock, 2)
    unprotect(db)
    db.execute("UPDATE audit_log SET hash = ? WHERE seq = 2", ("zz" * 32,))
    with pytest.raises(AuditError, match="record 2 has a malformed hash") as caught:
        log.append("service.stopped")
    assert caught.value.code == "audit_corrupt"
    assert log.count() == 2
    with pytest.raises(AuditError, match="record 2 has a malformed hash"):
        log.head()
    with pytest.raises(AuditError, match="record 2 has a malformed hash"):
        log.checkpoint()


def test_reading_a_corrupt_record_is_refused(log: AuditLog, db: Database, clock: FakeClock) -> None:
    fill(log, clock, 3)
    unprotect(db)
    db.execute("UPDATE audit_log SET data = 'garbage' WHERE seq = 2")
    db.execute("UPDATE audit_log SET severity = 'apocalyptic' WHERE seq = 3")
    assert log.get(1) is not None
    for call in (
        lambda: log.get(2),
        lambda: log.get(3),
        lambda: log.query(),
        lambda: log.tail(1),
        lambda: list(log.iterate()),
        lambda: log.export_jsonl(io.BytesIO()),
    ):
        with pytest.raises(AuditError, match="is corrupt") as caught:
            call()
        assert caught.value.code == "audit_corrupt"


# --- concurrency ---------------------------------------------------------------------


def run_threads(targets: list[Any]) -> None:
    errors: list[BaseException] = []

    def guarded(target: Any) -> None:
        try:
            target()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=guarded, args=(target,)) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []


def test_concurrent_threads_cannot_fork_the_chain(
    keyed: AuditLog, initial_key: AuditKey, key_path: Path
) -> None:
    workers, each = 8, 50
    barrier = threading.Barrier(workers)

    def work(worker: int) -> None:
        barrier.wait(10)
        for index in range(each):
            keyed.append("device.connected", actor=f"worker-{worker}", data={"i": index})

    run_threads([lambda worker=worker: work(worker) for worker in range(workers)])
    total = workers * each
    assert keyed.count() == total
    result = keyed.verify(initial_key=initial_key)
    assert (result.ok, result.checked, result.macs_checked) == (True, total, total)
    assert stored_key(key_path) == (total + 1, initial_key.key_for(total + 1))
    assert keyed.state_failures == 0
    records = list(keyed.iterate())
    assert [record.seq for record in records] == list(range(1, total + 1))
    assert len({record.hash for record in records}) == total
    # Every worker's records are all there, in the order that worker wrote them.
    for worker in range(workers):
        mine = [record.data["i"] for record in records if record.actor == f"worker-{worker}"]
        assert mine == list(range(each))


def test_two_database_handles_on_one_file_cannot_fork_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    key_path, head_path = tmp_path / "audit.key", tmp_path / "audit.head"
    _, initial = AuditKeyStore.create(key_path)
    clock = FakeClock()
    handles = [Database(path), Database(path)]
    try:
        logs = [
            AuditLog(handle, clock=clock, key_store=AuditKeyStore(key_path), head_path=head_path)
            for handle in handles
        ]
        workers_per_handle, each = 2, 20
        barrier = threading.Barrier(len(logs) * workers_per_handle)

        def work(log: AuditLog, name: str) -> None:
            barrier.wait(10)
            for index in range(each):
                log.append("device.connected", actor=name, data={"i": index})

        run_threads(
            [
                lambda log=log, name=f"h{number}-w{worker}": work(log, name)
                for number, log in enumerate(logs)
                for worker in range(workers_per_handle)
            ]
        )
        total = len(logs) * workers_per_handle * each
        for log in logs:
            result = log.verify(initial_key=initial)
            assert (result.ok, result.checked, result.macs_checked) == (True, total, total)
            assert result.head_checked
        assert logs[0].head() == logs[1].head()
        assert read_head_file(head_path) == logs[0].head()
        assert stored_key(key_path) == (total + 1, initial.key_for(total + 1))
        with Database(path) as third:
            fresh = AuditLog(third, clock=clock)
            records = list(fresh.iterate())
            assert [record.seq for record in records] == list(range(1, total + 1))
            assert {record.actor for record in records} == {"h0-w0", "h0-w1", "h1-w0", "h1-w1"}
            assert fresh.verify(expected_head=logs[0].head()).ok
    finally:
        for handle in handles:
            handle.close()


# What the CLI does beside a running service: its own process, its own handle, one file.
_APPENDER = """
import sys

sys.path.insert(0, sys.argv[1])

from portlock.audit.log import AuditKeyStore, AuditLog
from portlock.core.clock import FakeClock
from portlock.core.db import Database

with Database(sys.argv[2]) as db:
    store = AuditKeyStore(sys.argv[4])
    log = AuditLog(db, clock=FakeClock(), key_store=store, head_path=sys.argv[5])
    for index in range(int(sys.argv[3])):
        log.append("device.connected", actor="cli", data={"i": index})
        if index == 0:
            print("appending", flush=True)
"""


def test_a_separate_process_on_the_same_file_cannot_fork_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    key_path, head_path = tmp_path / "audit.key", tmp_path / "audit.head"
    _, initial = AuditKeyStore.create(key_path)
    source_root = str(Path(portlock.__file__).resolve().parents[1])
    each = 40
    with Database(path) as db:
        log = AuditLog(
            db, clock=FakeClock(), key_store=AuditKeyStore(key_path), head_path=head_path
        )
        child = subprocess.Popen(
            # -B: the child must not write bytecode into the source tree.
            [
                sys.executable,
                "-B",
                "-c",
                _APPENDER,
                source_root,
                str(path),
                str(each),
                str(key_path),
                str(head_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert child.stdout is not None and child.stderr is not None
            # Start only once the child is writing, so the two really do overlap. (A
            # child that failed to start has exited, so reading its stderr returns.)
            assert child.stdout.readline().strip() == "appending", child.stderr.read()
            for index in range(each):
                log.append("device.connected", actor="service", data={"i": index})
            _, errors = child.communicate(timeout=30)
            assert child.returncode == 0, errors
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()

        result = log.verify(initial_key=initial)
        assert (result.ok, result.checked, result.macs_checked) == (True, 2 * each, 2 * each)
        assert result.head_checked
        records = list(log.iterate())
        assert [record.seq for record in records] == list(range(1, 2 * each + 1))
        assert len({record.hash for record in records}) == 2 * each
        for name in ("cli", "service"):
            mine = [record.data["i"] for record in records if record.actor == name]
            assert mine == list(range(each))


def test_a_read_only_handle_can_verify_but_not_append(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "audit.db"
    with Database(path) as writable:
        records = fill(AuditLog(writable, clock=clock), clock, 3)
        with Database(path, read_only=True) as read_only:
            log = AuditLog(read_only, clock=clock)
            assert log.verify() == VerifyResult(True, 3, None, None, 0, (3, records[2].hash))
            assert log.tail(1) == [records[2]]
            with pytest.raises(StoreError):
                log.append("service.stopped")
        assert AuditLog(writable, clock=clock).count() == 3


# --- sinks ---------------------------------------------------------------------------


class Collector:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def emit(self, record: AuditRecord) -> None:
        self.records.append(record)


def test_committed_records_reach_the_sink(db: Database, clock: FakeClock) -> None:
    sink = Collector()
    log = AuditLog(db, clock=clock, sink=sink)
    first = log.append("service.started")
    second = log.append("device.connected", device_fp=FP)
    assert sink.records == [first, second]
    with pytest.raises(AuditError):
        log.append("no.such_event")
    with pytest.raises(AuditError):
        log.append("device.connected", data={"x": 1.5})
    assert sink.records == [first, second]


def test_a_failing_sink_never_breaks_auditing(db: Database, clock: FakeClock) -> None:
    class Broken:
        def emit(self, record: AuditRecord) -> None:
            raise OSError("disk full")

    log = AuditLog(db, clock=clock, sink=Broken())
    assert log.append("service.started").seq == 1
    assert log.append("service.stopped").seq == 2
    assert log.sink_failures == 2
    assert log.verify().checked == 2


def test_the_sink_sees_records_in_sequence_order_under_concurrency(
    db: Database, clock: FakeClock
) -> None:
    sink = Collector()
    log = AuditLog(db, clock=clock, sink=sink)
    workers, each = 6, 40
    barrier = threading.Barrier(workers)

    def work() -> None:
        barrier.wait(10)
        for _ in range(each):
            log.append("device.connected")

    run_threads([work] * workers)
    assert [record.seq for record in sink.records] == list(range(1, workers * each + 1))
    assert log.sink_failures == 0


def test_a_sink_may_read_the_log_it_is_attached_to(db: Database, clock: FakeClock) -> None:
    seen: list[tuple[int, int]] = []

    class Reader:
        log: AuditLog

        def emit(self, record: AuditRecord) -> None:
            seen.append((record.seq, self.log.count()))

    reader = Reader()
    reader.log = AuditLog(db, clock=clock, sink=reader)
    barrier = threading.Barrier(4)

    def work() -> None:
        barrier.wait(10)
        for _ in range(25):
            reader.log.append("device.connected")

    run_threads([work] * 4)
    assert [seq for seq, _ in seen] == list(range(1, 101))
    assert all(count >= seq for seq, count in seen)  # the record was committed first


def test_a_record_is_not_emitted_when_its_transaction_fails(db: Database) -> None:
    sink = Collector()

    class FailingClock(FakeClock):
        def now(self) -> datetime:
            raise RuntimeError("clock unavailable")

    log = AuditLog(db, clock=FailingClock(), sink=sink)
    with pytest.raises(RuntimeError):
        log.append("service.started")
    assert sink.records == [] and log.sink_failures == 0


# --- checkpoint and export -----------------------------------------------------------


def test_checkpoint(log: AuditLog, clock: FakeClock) -> None:
    assert log.checkpoint() == {
        "seq": 0,
        "hash": GENESIS_HASH,
        "ts": "2026-01-01T00:00:00.000000Z",
        "count": 0,
    }
    records = fill(log, clock, 3)
    clock.advance(60)
    checkpoint = log.checkpoint()
    assert checkpoint == {
        "seq": 3,
        "hash": records[2].hash,
        "ts": "2026-01-01T00:01:03.000000Z",
        "count": 3,
    }
    # Suitable for export and signing: canonical JSON round-trips it exactly.
    encoded = json.dumps(checkpoint, sort_keys=True, separators=(",", ":"))
    assert parse_canonical(encoded) == checkpoint
    assert log.verify(expected_head=(checkpoint["seq"], checkpoint["hash"])).ok
    assert log.count() == 3  # taking a checkpoint records nothing


def lines_of(stream: io.BytesIO) -> Iterator[dict[str, Any]]:
    for line in stream.getvalue().split(b"\n")[:-1]:
        yield parse_canonical(line)


def test_export_jsonl_writes_one_canonical_object_per_line(
    keyed: AuditLog, clock: FakeClock
) -> None:
    fill(keyed, clock, 3)
    keyed.append("auth.login", actor="Zo" + chr(0xEB), data={"note": "line\nbreak " + chr(0x2028)})
    binary = io.BytesIO()
    assert keyed.export_jsonl(binary) == 4
    raw = binary.getvalue()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 4
    exported = list(lines_of(binary))
    assert exported == [record.to_dict() for record in keyed.iterate()]
    assert list(exported[0]) == sorted(exported[0])
    assert set(exported[0]) == {
        "seq",
        "ts",
        "event_type",
        "severity",
        "actor",
        "device_fp",
        "data",
        "prev_hash",
        "hash",
        "mac",
    }

    text = io.StringIO()
    assert keyed.export_jsonl(text) == 4
    assert text.getvalue().encode("utf-8") == raw

    tail = io.BytesIO()
    assert keyed.export_jsonl(tail, since_seq=3) == 2
    assert [entry["seq"] for entry in lines_of(tail)] == [3, 4]
    assert keyed.export_jsonl(io.BytesIO(), since_seq=5) == 0
    with pytest.raises(AuditError, match="since_seq"):
        keyed.export_jsonl(io.BytesIO(), since_seq=0)


def test_an_export_can_be_verified_without_portlock(
    keyed: AuditLog, clock: FakeClock, initial_key: AuditKey
) -> None:
    fill(keyed, clock, 5)
    stream = io.BytesIO()
    keyed.export_jsonl(stream)
    prev_hash = GENESIS_HASH
    key = initial_key.key
    for number, line in enumerate(stream.getvalue().splitlines(), start=1):
        entry = json.loads(line)
        body = {
            name: entry[name]
            for name in ("seq", "ts", "event_type", "severity", "actor", "device_fp", "data")
        }
        assert entry["seq"] == number
        assert entry["prev_hash"] == prev_hash
        assert entry["hash"] == independent_hash(prev_hash, body)
        key = hashlib.sha256(b"portlock-audit-ratchet" + key).digest()
        assert entry["mac"] == hmac.new(key, bytes.fromhex(entry["hash"]), "sha256").hexdigest()
        prev_hash = entry["hash"]
    assert prev_hash == keyed.head()[1]
