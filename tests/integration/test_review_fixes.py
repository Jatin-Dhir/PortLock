"""Regression tests for the code review of the service, lockdown manager, API and CLI.

Each test reproduces a defect two independent reviewers found (``docs/REVIEW.md`` lists
them) and fails without its fix. Everything runs on the simulated machine: fake backend,
fake enforcer, fake clock and fake timer. Nothing touches a real device.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

from factories import (
    CDC_ACM,
    flash_drive,
    hub,
    internal_webcam,
    keyboard,
    make_device,
    mounted_flash_drive,
)
from integration.harness import ADMIN, START, Harness, StubScanner
from portlock.core.clock import FakeClock
from portlock.core.models import Mode, UsbDevice, Volume
from portlock.core.store import ConnectionState
from portlock.guard.base import Action
from portlock.lockdown.manager import LOCKDOWN_TIMER, recover

Machine = Callable[..., Harness]

_ALLOW_UNTIL = "allow-until"


def _modem() -> UsbDevice:
    return make_device(
        instance_id="test/1-6",
        product_id=0x0006,
        serial="TEST0006",
        product="Example Modem",
        interfaces=(CDC_ACM,),
        bus_path="1-6",
    )


def _scan_policy(harness: Harness, scan: str) -> None:
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "allow-scanned",
                    "match": {"vendor_id": ["0x1209"]},
                    "action": {"access": "allow", "scan": scan},
                }
            ],
        },
        actor=ADMIN,
    )


def _os_state(harness: Harness, instance_id: str) -> str | None:
    enforcement = harness.view(instance_id).enforcement
    return enforcement.os_state if enforcement is not None else None


# --- default-deny convergence only admits what PortLock holds back -----------------------


def test_a_lockdown_does_not_re_enable_a_device_someone_else_disabled(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.plug(internal_webcam())
    harness.enforcer._blocked.add("test/1-7")  # disabled outside PortLock
    harness.tick(1)
    harness.engage(30)
    assert harness.enforcer.is_blocked("test/1-7")
    harness.lift()
    assert harness.enforcer.is_blocked("test/1-7")
    unblocks = [
        r for r in harness.records("enforcement.applied") if r.data.get("action") == "unblock"
    ]
    assert not [r for r in unblocks if r.data.get("connection_id") is not None]


def test_standing_default_deny_does_not_re_enable_a_device_someone_else_disabled(
    machine: Machine,
) -> None:
    harness = machine()
    harness.add_admin()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(internal_webcam())
    harness.enforcer._blocked.add("test/1-7")
    applied = harness.service.set_default_deny(True, actor=ADMIN, channel="session-0001")
    harness.service.confirm_change(
        applied.extra["change"]["id"], actor=ADMIN, channel="session-0001"
    )
    harness.tick(120)
    assert harness.enforcer.default_deny
    harness.restart()  # every device is converged again at start
    assert harness.enforcer.default_deny
    assert harness.enforcer.is_blocked("test/1-7")


def test_a_clean_stop_does_not_re_enable_a_device_someone_else_disabled(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.plug(_modem())
    harness.enforcer._blocked.add("test/1-6")  # an administrator deauthorized it
    harness.engage(30)
    assert harness.enforcer.is_blocked("test/1-6")
    harness.stop()
    assert harness.enforcer.is_blocked("test/1-6")


def test_a_device_that_arrives_under_default_deny_is_still_admitted(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.engage(30)
    assert harness.enforcer.default_deny
    harness.plug(keyboard())  # protected: it must never be locked out
    assert not harness.enforcer.is_blocked("test/1-2")
    harness.lift()
    assert not harness.enforcer.default_deny


def test_a_device_default_deny_still_holds_back_is_admitted_on_stop(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.engage(30)
    harness.enforcer.fail(Action.UNBLOCK, times=1)  # its admission at arrival fails
    harness.plug(keyboard())
    assert harness.enforcer.is_blocked("test/1-2")  # unauthorized, and no record of its own
    harness.stop()
    assert not harness.enforcer.is_blocked("test/1-2")


# --- recover readmits hubs ---------------------------------------------------------------


def test_recover_readmits_a_hub_and_the_keyboard_behind_it(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.engage(30)
    harness.crash()
    harness.backend.plug(hub(instance_id="test/1-4", bus_path="1-4"))
    harness.backend.plug(keyboard(instance_id="test/1-2", bus_path="1-2"))
    assert harness.enforcer.is_blocked("test/1-4") and harness.enforcer.is_blocked("test/1-2")
    report = recover(
        harness.config.paths.state_dir,
        harness.enforcer,
        harness.backend.enumerate(),
        clock=harness.clock,
        is_admin=lambda: True,
        timer=harness.timer,
    )
    assert report.readmitted == 2 and not report.failed
    assert harness.enforcer.state()["blocked"] == []


# --- the dead-man timer fires after the service had its chance ---------------------------


def test_the_lockdown_timer_is_armed_after_the_expiry_by_a_grace_period(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.engage(30)
    expires = harness.service.lockdown_status().expires_at
    armed_at, argv = harness.timer.armed[LOCKDOWN_TIMER]
    assert armed_at == expires + timedelta(seconds=30)
    assert argv[-1] == "test"  # the harness's recover command, passed on unchanged


def test_a_restart_re_arms_the_lockdown_timer_with_the_grace_period(machine: Machine) -> None:
    harness = machine()
    harness.add_admin()
    harness.engage(30)
    harness.tick(60)
    harness.restart()
    status = harness.service.lockdown_status()
    armed_at, _argv = harness.timer.armed[LOCKDOWN_TIMER]
    assert status.active and armed_at == status.expires_at + timedelta(seconds=30)


def test_the_service_ends_an_expiring_lockdown_before_its_timer_could_fire(
    machine: Machine,
) -> None:
    harness = machine()
    harness.add_admin()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    harness.engage(30)
    armed_at, _argv = harness.timer.armed[LOCKDOWN_TIMER]
    harness.clock.advance(1800)
    harness.service.tick()
    assert harness.clock.now() < armed_at  # the OS timer has not fired yet
    assert not harness.service.lockdown_status().active
    assert LOCKDOWN_TIMER not in harness.timer.armed
    assert "lockdown.expired" in harness.event_types()
    assert harness.service.get_mode().effective_mode is Mode.ENFORCE
    assert not harness.service.get_mode().killswitch


# --- the audit high-water mark survives a restart ----------------------------------------


def test_a_rolled_back_clock_does_not_revive_an_expired_rule_after_a_restart(
    machine: Machine,
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    ends = START + timedelta(hours=1)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": _ALLOW_UNTIL,
                    "expires": ends.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "match": {"vendor_id": ["0x1209"]},
                    "action": {"access": "allow"},
                }
            ],
        },
        actor=ADMIN,
    )
    harness.plug(flash_drive())
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    harness.tick(7200)
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    newest = harness.rt.audit.newest_timestamp
    harness.clock.set(START)  # two hours back
    harness.tick()
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    harness.restart()
    assert harness.rt.audit.newest_timestamp is not None
    assert harness.rt.audit.newest_timestamp >= newest
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")


def test_a_time_window_stays_closed_after_a_clock_rollback_within_one_run(
    machine: Machine,
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    ends = START + timedelta(minutes=5)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": _ALLOW_UNTIL,
                    "expires": ends.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "match": {"vendor_id": ["0x1209"]},
                    "action": {"access": "allow"},
                }
            ],
        },
        actor=ADMIN,
    )
    harness.plug(flash_drive())
    harness.tick(300)
    harness.clock.set(START)
    harness.tick(60)
    assert harness.view("test/1-1").state is ConnectionState.PENDING


# --- scans -------------------------------------------------------------------------------


def test_a_manual_rescan_keeps_the_device_read_only_until_it_finishes(tmp_path: Path) -> None:
    clock = FakeClock(START)
    scanner = StubScanner(clock, {"/media/test": "suspicious"})
    harness = Harness(tmp_path / "m", clock=clock, scanner=scanner)
    harness.boot()
    try:
        harness.set_mode(Mode.ENFORCE)
        _scan_policy(harness, "on_mount")
        harness.plug(mounted_flash_drive())
        harness.run_scans()
        assert harness.enforcer.is_read_only("test/1-1")
        harness.service.request_scan(harness.connection_id("test/1-1"), actor=ADMIN)
        harness.tick(60)  # the periodic re-evaluation runs while the rescan waits
        assert harness.enforcer.is_read_only("test/1-1")
        assert _os_state(harness, "test/1-1") == "read_only"
        scanner.verdicts["/media/test"] = "clean"
        harness.run_scans()
        assert not harness.enforcer.is_read_only("test/1-1")
    finally:
        harness.crash()


def test_a_volume_mounted_after_a_clean_scan_is_read_only_until_it_is_scanned(
    tmp_path: Path,
) -> None:
    clock = FakeClock(START)
    scanner = StubScanner(clock, {"/media/test": "clean", "/media/second": "malicious"})
    harness = Harness(tmp_path / "m", clock=clock, scanner=scanner)
    harness.boot()
    try:
        harness.set_mode(Mode.ENFORCE)
        _scan_policy(harness, "required")
        device = harness.plug(mounted_flash_drive())
        harness.run_scans()
        assert _os_state(harness, "test/1-1") == "open"
        second = Volume(device_node="/dev/sdz2", mount_point="/media/second", fs_type="vfat")
        harness.update(dataclasses.replace(device, volumes=(*device.volumes, second)))
        assert _os_state(harness, "test/1-1") == "read_only"
        assert harness.enforcer.is_read_only("test/1-1")
        harness.run_scans()  # the second volume is malicious: the device is revoked
        present = {v.device.instance_id for v in harness.service.list_connections(open_only=True)}
        assert "test/1-1" not in present or harness.enforcer.is_blocked("test/1-1")
    finally:
        harness.crash()


# --- lockdown exemptions survive a restart -----------------------------------------------


def test_a_device_exempt_from_a_lockdown_stays_exempt_after_a_restart(machine: Machine) -> None:
    harness = machine(scope="all_except_protected")
    harness.set_mode(Mode.ENFORCE)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "trusted-adapter",
                    "match": {"vendor_id": ["0x1209"], "product_id": ["0x0002"]},
                    "action": {"access": "allow"},
                }
            ],
        },
        actor=ADMIN,
    )
    adapter = make_device(
        instance_id="test/2-1",
        bus_path="2-1",
        product_id=0x0002,
        serial="TEST0002B8D4",
        product="Example Serial Adapter",
        interfaces=(CDC_ACM,),
    )
    harness.plug(adapter)
    harness.tick(5)
    harness.engage(minutes=60)
    assert not harness.enforcer.is_blocked("test/2-1")
    harness.tick(30)
    harness.restart()
    assert harness.service.lockdown_status().active
    assert not harness.enforcer.is_blocked("test/2-1")


def test_a_device_plugged_in_while_the_service_was_down_is_not_exempt(machine: Machine) -> None:
    harness = machine(scope="all_except_protected")
    harness.set_mode(Mode.ENFORCE)
    harness.engage(minutes=60)
    harness.crash()
    newcomer = make_device(
        instance_id="test/2-2",
        bus_path="2-2",
        product_id=0x0003,
        serial="TEST0003C9E5",
        product="Example Serial Adapter",
        interfaces=(CDC_ACM,),
    )
    harness.backend.plug(newcomer)
    harness.boot()
    assert harness.service.lockdown_status().active
    assert harness.enforcer.is_blocked("test/2-2")


# --- an unconfirmed scope widening cannot undo a later narrowing -------------------------


def test_narrowing_the_scope_cancels_a_pending_widening(machine: Machine) -> None:
    harness = machine(scope="storage_and_unknown")
    channel = "session-0001"
    widened = harness.service.set_scope("all_except_protected", actor=ADMIN, channel=channel)
    assert widened.extra["change"]["kind"] == "widen_scope"
    harness.service.set_scope("storage", actor=ADMIN, channel=channel)
    assert not harness.service.pending_changes()
    assert harness.service.get_settings().runtime["scope"] == "storage"
    harness.tick(120)  # past the confirmation deadline: nothing is left to roll back
    assert harness.service.get_settings().runtime["scope"] == "storage"


def test_narrowing_to_a_scope_wider_than_the_previous_one_still_needs_confirmation(
    machine: Machine,
) -> None:
    harness = machine(scope="storage")
    channel = "session-0001"
    harness.service.set_scope("all_except_protected", actor=ADMIN, channel=channel)
    result = harness.service.set_scope("storage_and_unknown", actor=ADMIN, channel=channel)
    change = result.extra["change"]
    assert change["kind"] == "widen_scope"
    assert [item.id for item in harness.service.pending_changes()] == [change["id"]]
    harness.tick(120)  # never confirmed: back to what it was
    assert harness.service.get_settings().runtime["scope"] == "storage"
