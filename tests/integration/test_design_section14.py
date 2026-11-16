"""The behaviours DESIGN.md section 14 added, end to end."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from factories import BOOT_KEYBOARD, CDC_ACM, flash_drive, keyboard, make_device
from integration.harness import ADMIN, START, Harness, StubScanner, with_volume
from portlock.auth.grants import GrantKind, GrantStore
from portlock.core.clock import FakeClock
from portlock.core.config import SCOPE_ALL_EXCEPT_PROTECTED
from portlock.core.db import Database
from portlock.core.errors import StoreError
from portlock.core.fingerprint import fingerprint
from portlock.core.models import Mode, UsbInterface
from portlock.core.store import ConnectionState, Outcome
from portlock.guard.base import Action

NETWORK = UsbInterface(0x02, 0x06, 0x00)  # CDC ECM


def _hid_enforcing(machine: Callable[..., Harness], **options: object) -> Harness:
    harness = machine(
        hid_enforcement=True,
        acknowledge_lockout_risk=True,
        scope=SCOPE_ALL_EXCEPT_PROTECTED,
        **options,
    )
    harness.set_mode(Mode.ENFORCE)
    return harness


# --- 14.1 enrolment and clones --------------------------------------------------------------


def test_an_enrolled_keyboard_is_protected_on_its_port_only(
    machine: Callable[..., Harness],
) -> None:
    harness = _hid_enforcing(machine)
    harness.plug(keyboard())
    # With HID enforcement on, a keyboard that is not enrolled is an unknown device.
    assert harness.view("test/1-2").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-2")
    enrolled = harness.service.enroll(harness.connection_id("test/1-2"), actor=ADMIN).value
    assert enrolled.bus_path == "1-2"
    view = harness.view("test/1-2")
    assert view.state is ConnectionState.PROTECTED and view.protection_codes == ("enrolled",)
    assert not harness.enforcer.is_blocked("test/1-2")
    assert harness.records("enroll.added")[-1].data["bus_path"] == "1-2"
    # The same keyboard on another port is not protected by that enrolment.
    harness.unplug("test/1-2")
    harness.plug(keyboard(instance_id="test/7-7", bus_path="7-7"))
    assert harness.view("test/7-7").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/7-7")


def test_a_second_device_presenting_an_enrolled_fingerprint_is_denied_with_an_alert(
    machine: Callable[..., Harness],
) -> None:
    harness = _hid_enforcing(machine)
    harness.plug(keyboard())
    harness.service.enroll(harness.connection_id("test/1-2"), actor=ADMIN)
    harness.plug(keyboard(instance_id="test/8-1", bus_path="8-1"))

    clone = harness.view("test/8-1")
    assert clone.fingerprint == harness.view("test/1-2").fingerprint
    assert clone.state is ConnectionState.DENIED
    assert harness.enforcer.is_blocked("test/8-1")
    assert harness.view("test/1-2").state is ConnectionState.PROTECTED
    assert not harness.enforcer.is_blocked("test/1-2")
    detected = harness.records("safety.clone_detected")[-1]
    assert detected.severity.value == "critical"
    assert detected.data["denied"] == [clone.connection_id]
    assert detected.data["code"] == "enrolled_fingerprint_clone"


def test_being_connected_at_start_confers_no_protection(machine: Callable[..., Harness]) -> None:
    harness = _hid_enforcing(machine, devices=[keyboard()])
    view = harness.view("test/1-2")
    assert view.present_at_start and not view.protected
    assert harness.enforcer.is_blocked("test/1-2")


# --- 14.2 and 14.5: input beside another function ------------------------------------------


def test_a_keyboard_that_is_also_a_network_adapter_is_denied_by_default(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    implant = make_device(
        instance_id="test/9-1",
        bus_path="9-1",
        product_id=0x0009,
        serial="TEST00090001",
        interfaces=(BOOT_KEYBOARD, NETWORK),
    )
    harness.plug(implant)
    view = harness.view("test/9-1")
    assert view.state is ConnectionState.DENIED and not view.protected
    assert view.decision is not None and view.decision.decision.rule_id == "deny-input-with-other"
    assert harness.enforcer.is_blocked("test/9-1")
    assert harness.records("safety.suspicious_device")[-1].data["reason"] == "input_with_other"


def test_a_device_outside_the_scope_is_reported_as_not_enforced_never_as_protected(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    serial = make_device(
        instance_id="test/9-2", bus_path="9-2", product_id=0x000A, interfaces=(CDC_ACM,)
    )
    harness.plug(serial)
    view = harness.view("test/9-2")
    assert view.state is ConnectionState.PENDING and not view.protected
    assert view.enforcement is not None
    assert view.enforcement.outcome is Outcome.UNSUPPORTED
    assert view.enforcement.mechanism == "out-of-scope"
    assert not harness.enforcer.is_blocked("test/9-2")
    assert harness.enforcer.calls_for(Action.BLOCK) == ()
    failed = harness.records("enforcement.failed")[-1]
    assert failed.data["error"].startswith("out_of_scope")
    assert harness.service.status().counts["not_enforced"] == 1


# --- 14.6 port hold-down -------------------------------------------------------------------


def test_a_port_that_keeps_re_enumerating_is_held_and_its_audit_coalesced(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {"id": "allow", "match": {"category": ["storage"]}, "action": {"access": "allow"}}
            ],
        },
        actor=ADMIN,
    )
    for _ in range(5):
        harness.plug(flash_drive())
        harness.unplug("test/1-1")
    harness.plug(flash_drive())  # the sixth arrival in the window starts the hold
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.DENIED
    assert harness.enforcer.is_blocked("test/1-1")
    held = harness.records("safety.port_held")
    assert len(held) == 1 and held[0].data["port"] == "1-1" and held[0].data["arrivals"] == 6
    connected_before = len(harness.records("device.connected"))
    harness.unplug("test/1-1")
    harness.plug(flash_drive())  # during the hold: still blocked, no record of its own
    assert harness.enforcer.is_blocked("test/1-1")
    assert len(harness.records("device.connected")) == connected_before
    harness.tick(120)
    released = harness.records("safety.port_held")[-1]
    assert released.data["released"] is True and released.data["coalesced"] == 1
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert not harness.enforcer.is_blocked("test/1-1")


# --- 14.9 required scans --------------------------------------------------------------------


def _scanning(machine: Callable[..., Harness], verdicts: dict[str, str]) -> Harness:
    clock = FakeClock(START)
    harness = machine(clock=clock, scanner=StubScanner(clock, verdicts))
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "scan-first",
                    "match": {"category": ["storage"]},
                    "action": {"access": "allow", "scan": "required"},
                }
            ],
        },
        actor=ADMIN,
    )
    harness.set_mode(Mode.ENFORCE)
    return harness


def test_a_required_scan_admits_read_only_and_applies_the_access_only_when_clean(
    machine: Callable[..., Harness],
) -> None:
    harness = _scanning(machine, {})
    harness.plug(with_volume(flash_drive()))
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.ALLOWED and view.provisional
    assert view.enforcement is not None and view.enforcement.os_state == "read_only"
    assert harness.enforcer.is_read_only("test/1-1") and not harness.enforcer.is_blocked("test/1-1")
    assert harness.run_scans() == 1
    after = harness.view("test/1-1")
    assert not after.provisional and after.scan_state.value == "clean"
    assert not harness.enforcer.is_read_only("test/1-1")
    finished = harness.records("scan.finished")[-1]
    assert finished.data["verdict"] == "clean"


def test_an_incomplete_required_scan_leaves_the_device_read_only_with_an_alert(
    machine: Callable[..., Harness],
) -> None:
    harness = _scanning(machine, {"/media/stick": "incomplete"})
    harness.plug(with_volume(flash_drive()))
    harness.run_scans()
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.READ_ONLY
    assert view.decision is not None and view.decision.decision.alert
    assert view.decision.decision.source.value == "scan"
    assert harness.enforcer.is_read_only("test/1-1")


def test_a_malicious_finding_revokes_cleanly_read_only_then_eject(
    machine: Callable[..., Harness],
) -> None:
    clock = FakeClock(START)
    harness = machine(clock=clock, scanner=StubScanner(clock, {"/media/stick": "malicious"}))
    harness.set_mode(Mode.ENFORCE)
    harness.plug(with_volume(flash_drive()))
    harness.service.approve(
        harness.connection_id("test/1-1"), kind="trust", actor=ADMIN, role="admin"
    )
    assert not harness.enforcer.is_blocked("test/1-1")
    harness.run_scans()
    detection = harness.records("scan.detection")[-1]
    assert detection.data["severity"] == "malicious" and detection.data["engine"] == "hashset"
    revoked = [r for r in harness.records("enforcement.applied") if "revocation" in r.data]
    assert revoked and revoked[-1].data["action"] == "eject"
    assert revoked[-1].data["revocation"] == {
        "read_only": "applied",
        "eject": "clean",
        "clean": True,
        "mechanism": "fake:eject",
    }
    assert harness.records("decision.made")[-1].data["revocation"]["clean"] is True
    calls = [call.action for call in harness.enforcer.calls]
    assert calls.index(Action.READ_ONLY) < calls.index(Action.EJECT)
    assert harness.enforcer.was_ejected("test/1-1")
    assert harness.service.list_connections() == []  # the clean eject removed it


# --- 14.10 failures -------------------------------------------------------------------------


def test_an_enforcement_failure_is_recorded_as_not_enforced_and_retried(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.enforcer.fail(Action.BLOCK, "device busy", times=2)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.enforcement is not None and view.enforcement.outcome is Outcome.FAILED
    assert view.enforcement.os_state == "open" and view.enforcement.error == "device busy"
    assert not harness.enforcer.is_blocked("test/1-1")
    assert harness.service.status().counts["not_enforced"] == 1
    harness.tick(30)  # first retry fails the same way: audited once only
    assert len(harness.records("enforcement.failed")) == 1
    harness.tick(30)
    assert harness.view("test/1-1").enforcement.outcome is Outcome.APPLIED  # type: ignore[union-attr]
    assert harness.enforcer.is_blocked("test/1-1")


def test_a_device_that_cannot_be_evaluated_is_pending_and_blocked_in_enforce_mode(
    machine: Callable[..., Harness], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    engine = harness.service._loaded.engine

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("corrupt rule")

    monkeypatch.setattr(engine, "evaluate", broken)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    assert view.decision is not None and "evaluation failed" in view.decision.decision.reasons[0]
    failed = [r for r in harness.records("enforcement.failed") if r.data["action"] == "evaluate"]
    assert failed and "corrupt rule" in failed[0].data["error"]


# --- 14.23 a damaged database ---------------------------------------------------------------


def test_a_damaged_database_is_moved_aside_and_a_new_log_names_it(
    machine: Callable[..., Harness],
) -> None:
    harness = machine(mode=Mode.ENFORCE)  # the mode setting is lost with the database
    harness.plug(flash_drive())
    harness.crash()
    database = harness.config.paths.database_file
    for suffix in ("-wal", "-shm"):
        companion = database.with_name(database.name + suffix)
        if companion.exists():
            companion.unlink()
    garbage = b"this is not a database" * 64
    database.write_bytes(garbage)

    harness.boot()

    assert harness.rt.store_recovery is not None
    aside = harness.rt.store_recovery.damaged_path
    assert aside.read_bytes() == garbage and aside.parent == database.parent
    first = harness.records()[0]
    assert first.event_type == "store.recovered"
    assert first.data["damaged_file"] == aside.name
    assert first.data["last_known_head"] is not None
    assert harness.rt.audit_log.verify().ok
    # The journal survived (it is a file): the stick is still blocked, and evaluated afresh.
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.view("test/1-1").state is ConnectionState.PENDING


# --- changes underneath the service ---------------------------------------------------------


def test_the_policy_file_changing_underneath_is_reloaded_and_reconciled(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    assert harness.enforcer.is_blocked("test/1-1")
    path: Path = harness.config.paths.config_dir / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {"id": "ok", "match": {"category": ["storage"]}, "action": {"access": "allow"}}
                ],
            }
        ),
        encoding="utf-8",
    )
    harness.tick(5)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert not harness.enforcer.is_blocked("test/1-1")
    assert harness.records("policy.changed")[-1].data["source"] == "file"
    path.write_text("{ not json", encoding="utf-8")
    harness.tick(5)
    assert harness.records("policy.invalid")[-1].data["source"] == "file"
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED  # the last good stays


def test_a_grant_written_by_another_process_is_acted_on(machine: Callable[..., Harness]) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    stick = harness.plug(flash_drive())
    other = Database(harness.config.paths.database_file)
    try:
        GrantStore(other, clock=harness.clock).create(
            fingerprint(stick), GrantKind.TRUST, granted_by="cli"
        )
    finally:
        other.close()
    harness.tick(5)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert not harness.enforcer.is_blocked("test/1-1")


def test_a_failing_store_never_stops_enforcement(
    machine: Callable[..., Harness], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)

    def failing(*args: object, **kwargs: object) -> None:
        raise StoreError("disk I/O error")

    monkeypatch.setattr(harness.rt.store, "open_connection", failing)
    harness.plug(flash_drive())
    assert harness.enforcer.is_blocked("test/1-1")
    status = harness.service.status()
    assert "store" in status.degraded and status.counts["pending"] == 1
    assert harness.records("enforcement.applied")[-1].data["connection_id"] is None
