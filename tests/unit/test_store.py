"""The state store and the enforcement journal (core/store.py)."""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from factories import flash_drive, keyboard
from portlock.core.canonical import canonicalize
from portlock.core.clock import FakeClock
from portlock.core.config import SCOPES
from portlock.core.db import Database
from portlock.core.errors import StoreError
from portlock.core.fingerprint import fingerprint
from portlock.core.models import (
    Access,
    Decision,
    DecisionSource,
    Mode,
    ScanRequirement,
    UsbDevice,
)
from portlock.core.store import (
    _SCOPES,
    GLOBAL_SCOPE,
    ConnectionState,
    LockdownRecord,
    Outcome,
    PendingChangeRecord,
    RecoveryJournal,
    ScanState,
    StateStore,
    check_journal_entry,
)
from portlock.guard.base import Action, EnforcementResult, JournalEntry, Tier
from portlock.guard.fake import FakeEnforcer, authorized_target

RUN = "0123456789abcdef"
T0 = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def store(db: Database, clock: FakeClock) -> StateStore:
    return StateStore(db, clock=clock)


def _open(store: StateStore, device: UsbDevice, *, at: datetime = T0) -> int:
    record = store.open_connection(
        device, fingerprint(device), run_id=RUN, present_at_start=False, connected_at=at
    )
    return record.id


# --- schema and settings -----------------------------------------------------------------


def test_the_schema_is_one_migration_and_reopening_changes_nothing(
    db: Database, clock: FakeClock
) -> None:
    StateStore(db, clock=clock)
    StateStore(db, clock=clock)
    assert db.schema_version("store") == 1
    tables = {row["name"] for row in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "devices",
        "connections",
        "decisions",
        "scans",
        "settings",
        "enrolments",
        "lockdown_state",
        "lockdown_history",
        "pending_changes",
    } <= tables


def test_the_store_knows_the_same_scopes_as_the_configuration() -> None:
    assert _SCOPES == SCOPES


def test_settings_are_a_closed_validated_set(store: StateStore) -> None:
    assert store.get_setting("mode") is None
    assert store.get_setting("mode", "monitor") == "monitor"
    store.set_setting("mode", "enforce", by="alice")
    store.set_setting("scan.enabled", False, by="alice")
    store.set_setting("lockdown.default_minutes", 30, by="alice")
    store.set_setting("scope", "all_except_protected", by="alice")
    store.set_setting("service.run", {"run_id": RUN, "started_at": "2026-01-01T00:00:00Z"}, by="s")
    assert store.settings() == {
        "mode": "enforce",
        "scan.enabled": False,
        "lockdown.default_minutes": 30,
        "scope": "all_except_protected",
        "service.run": {"run_id": RUN, "started_at": "2026-01-01T00:00:00Z"},
    }
    for key, value in [
        ("mode", "off"),
        ("scan.enabled", 1),
        ("lockdown.default_minutes", 0),
        ("lockdown.default_minutes", True),
        ("scope", "everything"),
        ("protected_fingerprints", ["not-a-fingerprint"]),
        ("service.run", {"run_id": "XYZ", "started_at": "2026-01-01T00:00:00Z"}),
        ("policy.last_good", {"hash": "", "policy": {}}),
    ]:
        with pytest.raises(StoreError):
            store.set_setting(key, value, by="alice")
    with pytest.raises(StoreError, match="unknown setting"):
        store.set_setting("lockdown.max_minutes", 5, by="alice")
    with pytest.raises(StoreError):
        store.get_setting("nope")
    store.delete_setting("mode")
    assert store.get_setting("mode") is None


def test_a_damaged_setting_is_reported_by_get_and_skipped_by_settings(store: StateStore) -> None:
    store.set_setting("mode", "monitor", by="alice")
    store.set_setting("scan.enabled", True, by="alice")
    store.db.execute("UPDATE settings SET value = '\"sideways\"' WHERE key = 'mode'")
    with pytest.raises(StoreError, match="unusable"):
        store.get_setting("mode")
    assert store.settings() == {"scan.enabled": True}


# --- devices and connections -------------------------------------------------------------


def test_an_arrival_records_the_device_and_opens_a_connection(store: StateStore) -> None:
    device = flash_drive(connection_id="c-1")
    record = store.open_connection(
        device,
        fingerprint(device),
        run_id=RUN,
        present_at_start=True,
        connected_at=T0,
        storage_identity="disk-1",
    )
    assert record.state is ConnectionState.NEW and record.scan_state is ScanState.NONE
    assert record.device == device and record.connection_token == "c-1"
    assert record.instance_id == "test/1-1" and record.bus_path == "1-1"
    assert record.present_at_start and record.is_open and record.connected_at == T0
    assert record.fingerprint == fingerprint(device)
    seen = store.get_device(fingerprint(device).value)
    assert seen is not None and seen.connection_count == 1 and seen.storage_identity == "disk-1"
    # A CHANGED event refreshes the row without counting a connection.
    store.record_sighting(device, fingerprint(device), storage_identity=None)
    seen = store.get_device(fingerprint(device).value)
    assert seen is not None and seen.connection_count == 1 and seen.storage_identity == "disk-1"


def test_arrivals_are_idempotent_per_backend_connection(store: StateStore) -> None:
    first = flash_drive(connection_id="c-1")
    one = _open(store, first)
    # The same arrival reported twice (start-up enumeration racing the monitor).
    assert _open(store, first) == one
    assert len(store.open_connections()) == 1
    # Same instance id, new token: a re-plug whose removal was missed.
    two = _open(store, flash_drive(connection_id="c-2"), at=T0 + timedelta(seconds=5))
    assert two != one
    old = store.get_connection(one)
    assert old is not None and old.close_reason == "resync" and not old.is_open
    assert [c.id for c in store.open_connections()] == [two]
    found = store.find_open_connection("test/1-1", "c-2")
    assert found is not None and found.id == two
    assert store.find_open_connection("test/1-1", "c-1") is None
    assert store.find_open_connection("test/9-9") is None
    assert store.get_device(fingerprint(first).value).connection_count == 2  # type: ignore[union-attr]


def test_update_connection_accepts_only_known_keys_and_values(store: StateStore) -> None:
    cid = _open(store, flash_drive())
    moved = flash_drive(bus_path="2-1")
    record = store.update_connection(
        cid,
        state=ConnectionState.DENIED,
        provisional=True,
        resolution={"action": "deny", "by": "alice"},
        scan_state="queued",
        last_scan_id=7,
        device=moved,
    )
    assert record.state is ConnectionState.DENIED and record.provisional
    assert record.resolution == {"action": "deny", "by": "alice"}
    assert record.scan_state is ScanState.QUEUED and record.last_scan_id == 7
    assert record.bus_path == "2-1" and record.device == moved
    with pytest.raises(StoreError, match="does not accept"):
        store.update_connection(cid, removed_at=T0)
    with pytest.raises(StoreError):
        store.update_connection(cid, state="exploded")
    with pytest.raises(StoreError):
        store.update_connection(cid, provisional="yes")
    with pytest.raises(StoreError, match="unknown connection"):
        store.update_connection(999, state="allowed")


def test_closing_connections(store: StateStore) -> None:
    one = _open(store, flash_drive())
    _open(store, keyboard())
    closed = store.close_connection(one, removed_at=T0 + timedelta(minutes=1), reason="removed")
    assert closed.removed_at == T0 + timedelta(minutes=1) and closed.close_reason == "removed"
    # Closing again keeps the first removal.
    again = store.close_connection(one, removed_at=T0 + timedelta(minutes=9), reason="resync")
    assert again.removed_at == closed.removed_at and again.close_reason == "removed"
    with pytest.raises(StoreError):
        store.close_connection(one, removed_at=T0, reason="vanished")
    assert store.close_open_connections(removed_at=T0, reason="service_restart") == 1
    assert store.open_connections() == []


def test_connections_page_newest_first(store: StateStore) -> None:
    devices = [
        flash_drive(instance_id=f"test/p-{index}", connection_id=str(index))
        for index in range(1200)
    ]
    for device in devices:
        _open(store, device)
    seen: list[int] = []
    before: int | None = None
    while True:
        page = store.list_connections(before_id=before, limit=10_000)
        if not page:
            break
        assert len(page) <= 500
        seen.extend(record.id for record in page)
        before = page[-1].id
    assert len(seen) == 1200 and seen == sorted(seen, reverse=True)
    assert len(store.list_connections(limit=0)) == 1
    only = store.list_connections(fingerprint=fingerprint(devices[0]).value, limit=3)
    assert len(only) == 3


def test_decisions_are_recorded_with_the_connection_atomically(store: StateStore) -> None:
    cid = _open(store, flash_drive())
    decision = Decision(
        access=Access.READ_ONLY,
        source=DecisionSource.POLICY,
        reasons=("rule r1",),
        rule_id="r1",
        scan=ScanRequirement.REQUIRED,
        alert=True,
        expires_at=T0 + timedelta(hours=1),
    )
    record = store.add_decision(
        cid, decision, trigger="arrival", policy_hash="h1", mode=Mode.ENFORCE, decided_at=T0
    )
    assert record.decision == decision and record.outcome is Outcome.UNDETERMINED
    assert record.tier is Tier.NONE and record.mode is Mode.ENFORCE
    assert store.get_connection(cid).decision_id == record.id  # type: ignore[union-attr]
    store.set_outcome(
        record.id,
        outcome=Outcome.APPLIED,
        mechanism="fake:read_only",
        tier=Tier.REACTIVE,
        detail="made read-only",
        error=None,
        enforced_at=T0,
    )
    stored = store.get_decision(record.id)
    assert stored is not None and stored.outcome is Outcome.APPLIED and stored.enforced_at == T0
    deny = Decision(access=Access.DENY, source=DecisionSource.LOCKDOWN)
    store.add_decision(
        cid, deny, trigger="lockdown.engaged", policy_hash="h1", mode=Mode.MONITOR, decided_at=T0
    )
    assert [d.decision.access for d in store.list_decisions(connection_id=cid)] == [
        Access.DENY,
        Access.READ_ONLY,
    ]
    assert len(store.list_decisions(access=Access.DENY)) == 1
    # A decision for an unknown connection writes nothing at all.
    with pytest.raises(StoreError):
        store.add_decision(
            999, deny, trigger="x", policy_hash="h", mode=Mode.MONITOR, decided_at=T0
        )
    assert len(store.list_decisions()) == 2
    with pytest.raises(StoreError):
        store.set_outcome(
            999,
            outcome=Outcome.FAILED,
            mechanism=None,
            tier=Tier.NONE,
            detail=None,
            error="x",
            enforced_at=T0,
        )


def test_scans_round_trip(store: StateStore) -> None:
    cid = _open(store, flash_drive())
    fp = fingerprint(flash_drive()).value
    scan = store.add_scan(
        cid, fp, "/media/test", trigger="policy", requested_by="system", queued_at=T0
    )
    assert scan.state == "queued" and scan.report is None
    done = store.update_scan(
        scan.id, state="done", started_at=T0, finished_at=T0, verdict="clean", report={"files": 3}
    )
    assert done.verdict == "clean" and done.report == {"files": 3} and done.finished_at == T0
    with pytest.raises(StoreError):
        store.update_scan(scan.id, mount_point="/elsewhere")
    with pytest.raises(StoreError):
        store.add_scan(cid, fp, "/m", trigger="cron", requested_by="system", queued_at=T0)
    assert [s.id for s in store.list_scans(connection_id=cid)] == [scan.id]


def test_device_search_escapes_wildcards_and_pages(store: StateStore, clock: FakeClock) -> None:
    for index, product in enumerate(["Disk 100%", "Disk_A", "Disk B"]):
        device = flash_drive(
            instance_id=f"test/s-{index}", product=product, serial=f"TESTSERIAL{index:04d}"
        )
        _open(store, device, at=T0 + timedelta(minutes=index))
    assert [d.device.product for d in store.list_devices(text="100%")] == ["Disk 100%"]
    assert [d.device.product for d in store.list_devices(text="_")] == ["Disk_A"]
    everything = store.list_devices()
    assert [d.device.product for d in everything] == ["Disk B", "Disk_A", "Disk 100%"]
    rest = store.list_devices(before=everything[0].fingerprint.value)
    assert [d.device.product for d in rest] == ["Disk_A", "Disk 100%"]


def test_a_damaged_row_is_skipped_by_lists_and_reported_by_get(store: StateStore) -> None:
    good = _open(store, flash_drive())
    bad = _open(store, keyboard())
    store.db.execute("UPDATE connections SET description = '{broken' WHERE id = ?", (bad,))
    assert [c.id for c in store.list_connections()] == [good]
    assert [c.id for c in store.open_connections()] == [good]
    with pytest.raises(StoreError, match="cannot be read"):
        store.get_connection(bad)


def test_two_handles_on_one_file_share_the_state(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "portlock.db"
    with Database(path) as first, Database(path) as second:
        one, two = StateStore(first, clock=clock), StateStore(second, clock=clock)
        cid = _open(one, flash_drive())
        two.set_setting("mode", "enforce", by="alice")
        assert two.get_connection(cid) is not None
        assert one.get_setting("mode") == "enforce"


# --- enrolments, lockdown rows, pending changes ------------------------------------------


def test_enrolments_bind_a_fingerprint_to_a_port(store: StateStore) -> None:
    value = fingerprint(keyboard()).value
    first = store.add_enrolment(value, "1-2", by="alice", label="desk keyboard")
    again = store.add_enrolment(value, "1-2", by="bob")
    assert again == first and first.enrolled_by == "alice"
    store.add_enrolment(value, "3-1", by="alice")
    assert store.enrolled_pairs() == frozenset({(value, "1-2"), (value, "3-1")})
    for bad in [("plk1:short", "1-2"), (value, ""), (value, "x" * 200)]:
        with pytest.raises(StoreError):
            store.add_enrolment(*bad, by="alice")
    assert store.remove_enrolment(value, "3-1") == 1
    assert store.remove_enrolment(value) == 1
    assert store.list_enrolments() == []


def test_lockdown_changes_are_compare_and_set_and_atomic(
    store: StateStore, clock: FakeClock
) -> None:
    assert store.get_lockdown().state == "idle"
    pending = store.add_pending_change(_pending("aaaaaaaaaaaaaaaa"))
    active = LockdownRecord(
        state="active",
        engaged_at=T0,
        engaged_by="alice",
        reason="test",
        minutes=5,
        expires_at=T0 + timedelta(minutes=5),
        remaining_seconds=300,
        checkpoint_at=T0,
        change_id=pending.id,
        timer_armed=True,
    )
    stored = store.save_lockdown(active, expect={"idle"})
    assert stored.state == "active" and stored.timer_armed and stored.change_id == pending.id
    # The expectation fails: nothing is written, not even the history row.
    with pytest.raises(StoreError) as caught:
        store.save_lockdown(LockdownRecord(), expect={"idle"}, history_end=(T0, "bob", "lifted"))
    assert caught.value.code == "lockdown_conflict"
    assert store.lockdown_history() == [] and store.get_lockdown().state == "active"
    # One transaction: idle, a history row, and the pending change gone.
    store.save_lockdown(
        LockdownRecord(),
        expect={"active"},
        history_end=(T0, "bob", "lifted"),
        delete_change=pending.id,
    )
    history = store.lockdown_history()
    assert [(h.engaged_by, h.ended_by, h.end_reason) for h in history] == [
        ("alice", "bob", "lifted")
    ]
    assert store.get_pending_change(pending.id) is None
    with pytest.raises(StoreError):
        store.save_lockdown(LockdownRecord(state="frozen"))
    with pytest.raises(StoreError):
        store.save_lockdown(LockdownRecord(), history_end=(T0, "bob", "bored"))


def test_pending_changes_round_trip(store: StateStore) -> None:
    record = store.add_pending_change(_pending("bbbbbbbbbbbbbbbb"))
    assert record.status == "applying" and record.preview == ({"outcome": "block"},)
    moved = store.set_pending_status(record.id, "awaiting", result={"summary": {"blocked": 1}})
    assert moved.status == "awaiting" and moved.result == {"summary": {"blocked": 1}}
    assert [p.id for p in store.pending_changes(kind="lockdown")] == [record.id]
    assert store.pending_changes(kind="enforce_mode") == []
    with pytest.raises(StoreError):
        store.add_pending_change(_pending("not-hex"))
    with pytest.raises(StoreError):
        store.set_pending_status(record.id, "confirmed")
    assert store.delete_pending_change(record.id) and not store.delete_pending_change(record.id)


def _pending(change_id: str) -> PendingChangeRecord:
    return PendingChangeRecord(
        id=change_id,
        kind="lockdown",
        status="applying",
        actor="alice",
        channel="c" * 64,
        params={"minutes": 5},
        preview=({"outcome": "block"},),
        result=None,
        created_at=T0,
        deadline_at=T0 + timedelta(seconds=60),
        timeout_seconds=60,
    )


# --- the recovery journal ----------------------------------------------------------------


@pytest.fixture
def journal_path(tmp_path: Path) -> Path:
    return tmp_path / "journal.jsonl"


@pytest.fixture
def journal(journal_path: Path, clock: FakeClock) -> RecoveryJournal:
    return RecoveryJournal(journal_path, clock=clock)


def _lines(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _journaled(
    journal: RecoveryJournal, fake: FakeEnforcer, action: Action, device: UsbDevice
) -> EnforcementResult:
    with journal.recording(
        scope=device.instance_id, action=action, fingerprint=fingerprint(device).value
    ):
        if action is Action.BLOCK:
            result = fake.block(device)
        elif action is Action.UNBLOCK:
            result = fake.unblock(device)
        elif action is Action.READ_ONLY:
            result = fake.set_read_only(device, True)
        else:
            result = fake.set_read_only(device, False)
        journal.record(result)
    return result


def test_write_ahead_outside_a_recording_is_refused(journal: RecoveryJournal) -> None:
    entry = JournalEntry("fake", "test/1-1/authorized", "1", "0")
    with pytest.raises(StoreError, match="inside recording"):
        journal.write_ahead(entry)
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    result = fake.block(flash_drive())
    # The enforcer refuses to write when the journal cannot record the change first.
    assert not result.ok and result.error is not None and "journal unavailable" in result.error
    assert not fake.is_blocked(flash_drive())


def test_block_then_unblock_returns_to_baseline(
    journal: RecoveryJournal, journal_path: Path
) -> None:
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    device = flash_drive()
    _journaled(journal, fake, Action.BLOCK, device)
    [record] = journal.open_records()
    assert record.entry == JournalEntry("fake", authorized_target("test/1-1"), "1", "0")
    assert record.scope == "test/1-1" and record.action is Action.BLOCK
    assert record.fingerprint == fingerprint(device).value
    # Blocking again changes nothing and keeps the one baseline.
    _journaled(journal, fake, Action.BLOCK, device)
    assert len(journal.open_records()) == 1
    _journaled(journal, fake, Action.UNBLOCK, device)
    assert journal.open_records() == []
    # The last open record closed, so the file was compacted to nothing.
    assert journal_path.read_bytes() == b""


def test_a_releasing_call_over_an_existing_value_opens_nothing(journal: RecoveryJournal) -> None:
    device = flash_drive()
    elsewhere = FakeEnforcer()
    elsewhere.block(device)
    # The device was blocked by someone else; unblocking it must not record "blocked"
    # as a baseline, because restoring that baseline would block it again.
    with journal.recording(scope=device.instance_id, action=Action.UNBLOCK, fingerprint=None):
        journal.write_ahead(JournalEntry("fake", authorized_target(device.instance_id), "0", "1"))
        result = elsewhere.unblock(device)
        journal.record(result)
    assert result.ok and result.undo
    assert journal.open_records() == []


def test_written_ahead_but_not_applied_is_closed(
    journal: RecoveryJournal, journal_path: Path
) -> None:
    # Another open record keeps the file from being compacted, so the close is visible.
    journal.add_hold(scope="test/other", fingerprint=None)
    entry = JournalEntry("fake", "test/1-1/authorized", "1", "0")
    with journal.recording(scope="test/1-1", action=Action.BLOCK, fingerprint=None):
        journal.write_ahead(entry)
        assert len(journal.open_records()) == 2
        journal.record(EnforcementResult(Action.BLOCK, ok=False, mechanism="x", error="busy"))
    assert [r.scope for r in journal.open_records()] == ["test/other"]
    closes = [line for line in _lines(journal_path) if line.get("op") == "close"]
    assert [line["reason"] for line in closes] == ["not applied"]


def test_the_first_baseline_is_kept_and_global_kinds_are_global(journal: RecoveryJournal) -> None:
    first = JournalEntry(
        "sysfs_authorized_default", "/sys/bus/usb/devices/usb1/authorized_default", "1", "0"
    )
    second = JournalEntry("sysfs_authorized_default", first.target, "2", "0")
    with journal.recording(scope="test/1-1", action=Action.DEFAULT_DENY_ON, fingerprint=None):
        journal.write_ahead(first)
        journal.write_ahead(second)
        journal.record(
            EnforcementResult(Action.DEFAULT_DENY_ON, ok=True, mechanism="x", undo=(first,))
        )
    [record] = journal.open_records()
    assert record.entry == first and record.scope == GLOBAL_SCOPE and record.fingerprint is None


def test_record_opens_baselines_for_an_enforcer_without_the_hook(journal: RecoveryJournal) -> None:
    fake = FakeEnforcer()
    device = flash_drive()
    _journaled(journal, fake, Action.BLOCK, device)
    _journaled(journal, fake, Action.READ_ONLY, device)
    assert sorted(r.entry.target for r in journal.open_records() if r.entry) == [
        "test/1-1/authorized",
        "test/1-1/ro",
    ]
    with pytest.raises(StoreError, match="inside recording"):
        journal.record(EnforcementResult(Action.BLOCK, ok=True, mechanism="x"))


def test_a_recording_cannot_nest(journal: RecoveryJournal) -> None:
    with (
        journal.recording(scope="a", action=Action.BLOCK, fingerprint=None),
        pytest.raises(StoreError, match="already active"),
        journal.recording(scope="b", action=Action.BLOCK, fingerprint=None),
    ):
        pass
    # The failed attempt did not leave a recording behind.
    with journal.recording(scope="b", action=Action.BLOCK, fingerprint=None):
        journal.add_hold(scope="b", fingerprint=None)
    assert len(journal.open_records()) == 1


def test_reopening_gives_the_same_open_set(
    journal: RecoveryJournal, journal_path: Path, clock: FakeClock
) -> None:
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    for index in range(3):
        _journaled(journal, fake, Action.BLOCK, flash_drive(instance_id=f"test/r-{index}"))
    hold = journal.add_hold(scope="test/held", fingerprint=None)
    assert journal.add_hold(scope="test/held", fingerprint=None) == hold
    _journaled(journal, fake, Action.UNBLOCK, flash_drive(instance_id="test/r-1"))
    again = RecoveryJournal(journal_path, clock=clock)
    assert again.open_records() == journal.open_records()
    assert again.corrupt_lines == 0
    assert [r.scope for r in again.open_records()] == ["test/held", "test/r-2", "test/r-0"]


def test_compaction_keeps_exactly_the_open_records(
    journal: RecoveryJournal, journal_path: Path, clock: FakeClock
) -> None:
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    keep = flash_drive(instance_id="test/keep")
    _journaled(journal, fake, Action.BLOCK, keep)
    for index in range(5):
        device = flash_drive(instance_id=f"test/c-{index}")
        _journaled(journal, fake, Action.BLOCK, device)
        _journaled(journal, fake, Action.UNBLOCK, device)
    assert len(_lines(journal_path)) == 11
    journal.compact()
    lines = _lines(journal_path)
    assert len(lines) == 1 and lines[0]["scope"] == "test/keep"
    assert RecoveryJournal(journal_path, clock=clock).open_records() == journal.open_records()


def test_discard_volatile_closes_only_that_device_s_volatile_records(
    journal: RecoveryJournal,
) -> None:
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    _journaled(journal, fake, Action.BLOCK, flash_drive())
    journal.add_hold(scope="test/1-1", fingerprint=None)
    _journaled(journal, fake, Action.BLOCK, flash_drive(instance_id="test/other"))
    devnode = JournalEntry("win_devnode", "USB\\VID_1209&PID_0001\\TEST0001", "enabled", "disabled")
    with journal.recording(scope="test/1-1", action=Action.BLOCK, fingerprint=None):
        journal.write_ahead(devnode)
        journal.record(EnforcementResult(Action.BLOCK, ok=True, mechanism="x", undo=(devnode,)))
    discarded = journal.discard_volatile("test/1-1", reason="device left")
    assert len(discarded) == 2
    left = journal.open_records()
    assert {(r.scope, r.entry.kind if r.entry else None) for r in left} == {
        ("test/1-1", "win_devnode"),
        ("test/other", "fake"),
    }


def test_a_torn_last_line_and_garbage_lines_are_skipped_and_counted(
    journal_path: Path, clock: FakeClock
) -> None:
    journal = RecoveryJournal(journal_path, clock=clock)
    fake = FakeEnforcer(write_ahead=journal.write_ahead)
    _journaled(journal, fake, Action.BLOCK, flash_drive())
    with journal_path.open("ab") as stream:
        stream.write(b"not json at all\n")
        stream.write(b"\xff\xfe\n")
        stream.write(b"[1,2,3]\n")
        stream.write(b'{"op":"open","id":"0011')  # torn: the write never finished
    reloaded = RecoveryJournal(journal_path, clock=clock)
    assert reloaded.corrupt_lines == 4
    assert len(reloaded.open_records()) == 1
    # The next record starts on a fresh line, so it is readable after another reload.
    reloaded.add_hold(scope="test/held", fingerprint=None)
    third = RecoveryJournal(journal_path, clock=clock)
    assert len(third.open_records()) == 2 and third.corrupt_lines == 4


def _record_line(**overrides: object) -> bytes:
    record: dict[str, object] = {
        "op": "open",
        "id": "00112233445566ff",
        "ts": "2026-01-01T00:00:00.000000Z",
        "scope": "test/1-1",
        "action": "block",
        "fp": None,
        "entry": {"kind": "fake", "target": "test/1-1/authorized", "previous": "1", "applied": "0"},
    }
    record.update(overrides)
    return canonicalize(record).encode("utf-8") + b"\n"


@pytest.mark.parametrize(
    "line",
    [
        # A target outside sysfs: a tampered journal steering a restore at a system file.
        _record_line(
            entry={
                "kind": "sysfs_authorized",
                "target": "/etc/shadow",
                "previous": "1",
                "applied": "0",
            }
        ),
        _record_line(
            entry={
                "kind": "sysfs_authorized",
                "target": "/sys/../etc/shadow",
                "previous": "1",
                "applied": "0",
            }
        ),
        _record_line(
            entry={
                "kind": "udev_rule",
                "target": "/etc/udev/rules.d/../../cron.d/x",
                "previous": None,
                "applied": "x",
            }
        ),
        _record_line(
            entry={
                "kind": "win_policy_value",
                "target": "HKLM\\SOFTWARE\\Run\\evil",
                "previous": None,
                "applied": "1",
            }
        ),
        _record_line(
            entry={
                "kind": "win_devnode",
                "target": "PCI\\VEN_8086",
                "previous": "1",
                "applied": "0",
            }
        ),
        _record_line(entry={"kind": "shell", "target": "x", "previous": None, "applied": "rm"}),
        _record_line(entry={"kind": "fake", "target": "t", "previous": 1, "applied": "0"}),
        _record_line(action="restore"),
        _record_line(action="eject"),
        _record_line(id="XYZ"),
        _record_line(fp="plk1:nope"),
        _record_line(scope=""),
        _record_line(ts="yesterday"),
        _record_line(extra=1),
        _record_line(op="delete"),
        _record_line(op="hold", entry=None),
        # Global kinds are only valid with the global scope.
        _record_line(
            entry={
                "kind": "sysfs_authorized_default",
                "target": "/sys/bus/usb/devices/usb1/authorized_default",
                "previous": "1",
                "applied": "0",
            }
        ),
        # Not canonical: whitespace and unsorted keys.
        b'{"op": "close", "id": "00112233445566ff", "ts": "2026-01-01T00:00:00Z", "reason": "x"}\n',
    ],
)
def test_tampered_records_are_refused_on_replay(
    journal_path: Path, clock: FakeClock, line: bytes
) -> None:
    good = _record_line(
        id="aaaaaaaaaaaaaaaa",
        scope="test/2-2",
        entry={"kind": "fake", "target": "test/2-2/authorized", "previous": "1", "applied": "0"},
    )
    journal_path.write_bytes(good + line)
    journal = RecoveryJournal(journal_path, clock=clock)
    assert journal.corrupt_lines == 1
    assert [r.id for r in journal.open_records()] == ["aaaaaaaaaaaaaaaa"]


def test_duplicate_ids_and_second_baselines_are_refused_on_replay(
    journal_path: Path, clock: FakeClock
) -> None:
    first = _record_line(id="aaaaaaaaaaaaaaaa")
    same_id = _record_line(
        id="aaaaaaaaaaaaaaaa",
        scope="test/2-2",
        entry={"kind": "fake", "target": "test/2-2/authorized", "previous": "1", "applied": "0"},
    )
    second_baseline = _record_line(
        id="bbbbbbbbbbbbbbbb",
        entry={"kind": "fake", "target": "test/1-1/authorized", "previous": "0", "applied": "1"},
    )
    close_unknown = (
        canonicalize(
            {"op": "close", "id": "cccccccccccccccc", "ts": "2026-01-01T00:00:00Z", "reason": "x"}
        ).encode()
        + b"\n"
    )
    journal_path.write_bytes(first + same_id + second_baseline + close_unknown)
    journal = RecoveryJournal(journal_path, clock=clock)
    assert journal.corrupt_lines == 2
    [record] = journal.open_records()
    assert record.id == "aaaaaaaaaaaaaaaa" and record.entry is not None
    assert record.entry.previous == "1"


def test_an_over_long_line_is_skipped(journal_path: Path, clock: FakeClock) -> None:
    journal_path.write_bytes(b"x" * 40_000 + b"\n" + _record_line())
    journal = RecoveryJournal(journal_path, clock=clock)
    assert journal.corrupt_lines == 1 and len(journal.open_records()) == 1


@pytest.mark.parametrize(
    ("entry", "ok"),
    [
        (JournalEntry("sysfs_authorized", "/sys/bus/usb/devices/1-2/authorized", "1", "0"), True),
        (JournalEntry("sysfs_authorized", "sys/bus/usb/devices/1-2/authorized", "1", "0"), False),
        (JournalEntry("block_read_only", "/dev/sdb", "0", "1"), True),
        (JournalEntry("block_read_only", "/sys/block/sdb", "0", "1"), False),
        (
            JournalEntry("udev_rule", "/etc/udev/rules.d/60-portlock-readonly.rules", None, "x"),
            True,
        ),
        (JournalEntry("udev_rule", "/etc/udev/rules.d/60-portlock.conf", None, "x"), False),
        (JournalEntry("win_devnode", "USB\\VID_1209&PID_0001\\TEST0001", "1", "0"), True),
        (JournalEntry("win_disk_read_only", "\\\\.\\PhysicalDrive3", "0", "1"), True),
        (JournalEntry("win_disk_read_only", "disk" + chr(7), "0", "1"), False),
        (
            JournalEntry(
                "win_policy_value",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\Deny_Write",
                None,
                "1",
            ),
            True,
        ),
        (JournalEntry("fake", "anything/authorized", "1", "0"), True),
        (JournalEntry("fake", "t", "1", "0" * 5000), False),
    ],
)
def test_journal_entry_targets_are_checked_per_kind(entry: JournalEntry, ok: bool) -> None:
    if ok:
        check_journal_entry(entry)
    else:
        with pytest.raises(ValueError):
            check_journal_entry(entry)


def test_write_ahead_refuses_an_entry_it_could_never_restore(journal: RecoveryJournal) -> None:
    with (
        journal.recording(scope="test/1-1", action=Action.BLOCK, fingerprint=None),
        pytest.raises(StoreError, match="invalid entry"),
    ):
        journal.write_ahead(JournalEntry("sysfs_authorized", "/etc/passwd", "1", "0"))
    assert journal.open_records() == []


def test_concurrent_appends_lose_nothing(
    journal: RecoveryJournal, journal_path: Path, clock: FakeClock
) -> None:
    def worker(index: int) -> None:
        for item in range(25):
            journal.add_hold(scope=f"test/t{index}-{item}", fingerprint=None)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    reloaded = RecoveryJournal(journal_path, clock=clock)
    assert len(reloaded.open_records()) == 200 and reloaded.corrupt_lines == 0


def test_an_unwritable_journal_raises_store_error(tmp_path: Path, clock: FakeClock) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    journal = RecoveryJournal(blocker / "journal.jsonl", clock=clock)
    with pytest.raises(StoreError, match="cannot write"):
        journal.add_hold(scope="test/1-1", fingerprint=None)
    assert journal.open_records() == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_journal_file_is_owner_only(journal: RecoveryJournal, journal_path: Path) -> None:
    journal.add_hold(scope="test/1-1", fingerprint=None)
    assert journal_path.stat().st_mode & 0o077 == 0
