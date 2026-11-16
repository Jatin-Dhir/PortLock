"""Service restart: state, grants, the journal and an active lockdown survive; an expired
lockdown is lifted; an unconfirmed change is rolled back."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from factories import flash_drive, keyboard
from integration.harness import ADMIN, CHANNEL, Harness
from portlock.core.models import Mode
from portlock.core.store import ConnectionState
from portlock.lockdown.manager import LOCKDOWN_TIMER, LockdownState


def _enforcing(machine: Callable[..., Harness], **options: object) -> Harness:
    harness = machine(**options)
    harness.set_mode(Mode.ENFORCE)
    return harness


def test_trust_mode_and_the_pending_queue_survive_a_clean_restart(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.plug(flash_drive(instance_id="test/3-1", bus_path="3-1", serial="TEST00030001"))
    harness.service.approve(
        harness.connection_id("test/3-1"), kind="trust", actor=ADMIN, role="admin"
    )
    pending_before = harness.connection_id("test/1-1")

    report = harness.service.stop()
    assert report is not None and report.failed == ()
    # A clean stop puts back everything PortLock changed.
    assert harness.enforcer.state()["blocked"] == []
    assert harness.rt.journal.open_records() == []
    stopped = harness.records("service.stopped")[-1]
    assert stopped.data["clean"] is True
    harness.rt.close()
    harness.runtime = None
    harness.backend.stop()

    harness.boot()
    assert harness.service.get_mode().effective_mode is Mode.ENFORCE
    pending = harness.view("test/1-1")
    assert pending.state is ConnectionState.PENDING and pending.present_at_start
    assert pending.connection_id != pending_before
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.view("test/3-1").state is ConnectionState.ALLOWED
    started = harness.records("service.started")[-1]
    assert started.data["previous_shutdown"] == "clean"
    closed = harness.service.list_connections(open_only=False)
    assert {view.close_reason for view in closed if view.removed_at} == {"service_stop"}


def test_a_crash_keeps_blocked_devices_blocked_and_is_recovered_and_audited(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    record = harness.rt.journal.open_records()[0]

    harness.crash()
    # Between the crash and the next start the device stays blocked: the journal says so.
    assert harness.enforcer.is_blocked("test/1-1")
    harness.boot()

    assert harness.enforcer.is_blocked("test/1-1")
    assert [r.id for r in harness.rt.journal.open_records()] == [record.id]
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING and view.present_at_start
    recovered = harness.records("service.recovered")[-1]
    assert recovered.data["connections_closed"] == 1
    assert recovered.data["journal_records_found"] == 1
    assert recovered.data["journal_records_discarded"] == 0
    assert harness.records("service.started")[-1].data["previous_shutdown"] == "unclean"
    old = harness.service.list_connections(open_only=False)[-1]
    assert old.close_reason == "service_restart"


def test_a_volatile_record_of_a_device_removed_while_down_is_discarded(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.crash()
    harness.backend.unplug("test/1-1")
    harness.boot()
    assert harness.rt.journal.open_records() == []
    assert harness.records("service.recovered")[-1].data["journal_records_discarded"] == 1


def test_a_once_grant_survives_a_restart_only_while_its_device_stays(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.plug(flash_drive(instance_id="test/3-1", bus_path="3-1", serial="TEST00030001"))
    kept = harness.service.approve(harness.connection_id("test/1-1"), kind="once", actor=ADMIN)
    spent = harness.service.approve(harness.connection_id("test/3-1"), kind="once", actor=ADMIN)
    harness.crash()
    harness.backend.unplug("test/3-1")
    harness.boot()
    active = {grant.id for grant in harness.service.list_grants()}
    assert active == {kept.value.id}
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    expired = harness.records("grant.expired")[-1]
    assert expired.data["grant_id"] == spent.value.id
    assert expired.data["reason"] == "service_restart"


def test_an_active_lockdown_survives_a_restart(machine: Callable[..., Harness]) -> None:
    harness = machine(devices=[keyboard()])
    harness.plug(flash_drive())
    harness.engage(30)
    harness.clock.advance(600)
    harness.tick()
    harness.crash()
    harness.clock.advance(60)
    harness.boot()

    status = harness.service.lockdown_status()
    assert status.state is LockdownState.ACTIVE and status.active
    assert status.remaining_seconds is not None and 1000 <= status.remaining_seconds <= 1140
    assert harness.enforcer.default_deny
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.view("test/1-1").state is ConnectionState.DENIED
    assert not harness.enforcer.is_blocked("test/1-2")
    assert LOCKDOWN_TIMER in harness.timer.armed
    assert harness.records("service.recovered")[-1].data["lockdown"] == "resumed"


def test_a_lockdown_that_expired_while_the_service_was_down_is_lifted_at_start(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.plug(flash_drive())
    harness.engage(10)
    assert harness.enforcer.is_blocked("test/1-1")
    harness.crash()
    harness.clock.advance(timedelta(minutes=11))
    harness.boot()

    assert harness.service.lockdown_status().state is LockdownState.IDLE
    assert not harness.enforcer.default_deny
    # Monitor mode: nothing remains restricted once the lockdown is gone.
    assert harness.enforcer.state()["blocked"] == []
    assert harness.rt.journal.open_records() == []
    expired = harness.records("lockdown.expired")[-1]
    assert expired.data["found_at_start"] is True and expired.data["end_reason"] == "expired"
    assert LOCKDOWN_TIMER not in harness.timer.armed


def test_an_unconfirmed_switch_to_enforce_is_rolled_back_at_restart(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.plug(flash_drive())
    applied = harness.service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
    assert applied.extra["change"]["kind"] == "enforce_mode"
    assert harness.enforcer.is_blocked("test/1-1")
    harness.crash()
    harness.boot()
    assert harness.service.get_mode().effective_mode is Mode.MONITOR
    assert not harness.enforcer.is_blocked("test/1-1")
    rolled = harness.records("change.rolled_back")[-1]
    assert rolled.data["kind"] == "enforce_mode" and rolled.data["found_at_start"] is True


def test_fail_closed_keeps_restrictions_across_a_clean_stop(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine, fail_closed=True)
    harness.plug(flash_drive())
    assert harness.service.stop() is None
    assert harness.enforcer.is_blocked("test/1-1")
    assert len(harness.rt.journal.open_records()) == 1
    harness.rt.close()
    harness.runtime = None
    harness.backend.stop()
    harness.boot()
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.view("test/1-1").state is ConnectionState.PENDING
