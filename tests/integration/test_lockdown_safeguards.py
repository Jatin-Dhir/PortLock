"""Lockdown safeguards: protected devices untouched, the dead-man timer, commit-confirm
rollback, re-authentication to lift, the kill switch and recovery without the database."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

from factories import flash_drive, hub, keyboard, mouse
from integration.harness import ADMIN, ADMIN_PASSWORD, CHANNEL, RECOVER_ARGV, Harness
from portlock.core.errors import AuthError
from portlock.core.models import Mode
from portlock.core.service import ServiceError
from portlock.core.store import ConnectionState
from portlock.guard.base import Action
from portlock.lockdown.manager import (
    LOCKDOWN_TIMER,
    ConfirmationError,
    Credential,
    LockdownState,
    recover,
)

RESTRICTING = (Action.BLOCK, Action.READ_ONLY, Action.EJECT)


def _with_devices(machine: Callable[..., Harness], **options: object) -> Harness:
    harness = machine(devices=[keyboard(), mouse(), hub()], **options)
    harness.plug(flash_drive())
    return harness


def test_lockdown_blocks_storage_and_holds_new_devices_but_never_touches_protected_ones(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    harness.enforcer.clear_calls()
    harness.engage(30)

    assert harness.enforcer.default_deny
    assert harness.enforcer.is_blocked("test/1-1")
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.DENIED
    assert view.decision is not None and view.decision.decision.source.value == "lockdown"
    restricted = {call.instance_id for call in harness.enforcer.calls_for(*RESTRICTING)}
    assert restricted == {"test/1-1"}
    for protected in ("test/1-2", "test/1-3", "test/1-4"):
        assert harness.view(protected).state is ConnectionState.PROTECTED
    armed_at, argv = harness.timer.armed[LOCKDOWN_TIMER]
    assert argv == RECOVER_ARGV
    assert armed_at == harness.clock.now() + timedelta(minutes=30)
    # A new stick is refused from the first instant; a new keyboard is admitted.
    harness.plug(flash_drive(instance_id="test/5-1", bus_path="5-1", serial="TEST00050001"))
    assert harness.enforcer.is_blocked("test/5-1")
    assert harness.view("test/5-1").enforcement.tier.value == "preventive"  # type: ignore[union-attr]
    harness.plug(keyboard(instance_id="test/5-2", bus_path="5-2"))
    assert not harness.enforcer.is_blocked("test/5-2")
    assert harness.view("test/5-2").state is ConnectionState.PROTECTED


def test_the_dead_man_timer_lifts_the_lockdown_and_releases_everything(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    harness.engage(20)
    harness.tick(20 * 60 - 1)
    assert harness.service.lockdown_status().active
    harness.tick(1)
    assert harness.service.lockdown_status().state is LockdownState.IDLE
    assert not harness.enforcer.default_deny
    assert harness.enforcer.state()["blocked"] == []
    assert harness.view("test/1-1").state is ConnectionState.PENDING  # monitor mode again
    assert LOCKDOWN_TIMER not in harness.timer.armed
    expired = harness.records("lockdown.expired")[-1]
    assert expired.data["end_reason"] == "expired" and expired.data["found_at_start"] is False
    assert harness.rt.journal.open_records() == []


def test_an_unconfirmed_lockdown_is_rolled_back(machine: Callable[..., Harness]) -> None:
    harness = _with_devices(machine)
    change_id = harness.engage(30, confirm=False)
    assert harness.enforcer.is_blocked("test/1-1")
    with pytest.raises(ConfirmationError) as wrong:
        harness.service.lockdown_confirm(change_id, actor=ADMIN, channel="another-session")
    assert wrong.value.code == "wrong_channel"
    harness.tick(60)
    assert harness.service.lockdown_status().state is LockdownState.IDLE
    assert not harness.enforcer.is_blocked("test/1-1")
    assert not harness.enforcer.default_deny
    rolled = harness.records("change.rolled_back")[-1]
    assert rolled.data["kind"] == "lockdown" and rolled.data["change_id"] == change_id


def test_an_unconfirmed_switch_to_enforce_mode_is_rolled_back(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    applied = harness.service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
    preview = {item["instance_id"]: item["outcome"] for item in applied.extra["change"]["preview"]}
    assert preview["test/1-1"] == "block" and preview["test/1-2"] == "protected"
    assert harness.enforcer.is_blocked("test/1-1")
    harness.tick(59)
    assert harness.service.get_mode().effective_mode is Mode.ENFORCE
    harness.tick(1)
    assert harness.service.get_mode().effective_mode is Mode.MONITOR
    assert not harness.enforcer.is_blocked("test/1-1")


def test_lifting_needs_an_administrator_credential(machine: Callable[..., Harness]) -> None:
    harness = _with_devices(machine)
    harness.add_admin()
    harness.rt.accounts.create_user("oscar", "operator password 12345", "operator", actor=ADMIN)
    harness.engage(30)
    with pytest.raises(AuthError) as wrong:
        harness.service.lockdown_lift(actor=ADMIN, credential=Credential("password", "nope"))
    assert wrong.value.code == "reauthentication_failed"
    with pytest.raises(AuthError):
        harness.service.lockdown_lift(
            actor="oscar", credential=Credential("password", "operator password 12345")
        )
    assert harness.service.lockdown_status().active
    lifted = harness.service.lockdown_lift(
        actor=ADMIN, credential=Credential("password", ADMIN_PASSWORD)
    )
    assert lifted.value.status.state is LockdownState.IDLE
    assert not harness.enforcer.default_deny and harness.enforcer.state()["blocked"] == []
    assert harness.records("lockdown.lifted")[-1].actor == ADMIN


def test_lockdown_acts_in_monitor_mode_and_is_refused_without_the_means_to_block(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    assert harness.service.get_mode().effective_mode is Mode.MONITOR
    harness.engage(10)
    assert harness.enforcer.is_blocked("test/1-1")

    from portlock.guard.fake import FakeEnforcer

    weak = machine(capabilities=FakeEnforcer.unprivileged().capabilities())
    with pytest.raises(ServiceError) as refused:
        weak.service.lockdown_engage(minutes=10, actor=ADMIN, channel=CHANNEL)
    assert refused.value.code == "enforcement_unavailable"


def test_the_kill_switch_restores_everything_and_blocks_re_engage(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    harness.set_mode(Mode.ENFORCE)
    harness.engage(30)
    assert harness.enforcer.default_deny
    harness.config.paths.kill_switch_file.write_text("", encoding="utf-8")
    harness.tick()

    assert harness.service.lockdown_status().state is LockdownState.IDLE
    assert not harness.enforcer.default_deny
    assert harness.enforcer.state()["blocked"] == []
    mode = harness.service.get_mode()
    assert mode.killswitch and mode.effective_mode is Mode.MONITOR and mode.source == "killswitch"
    activated = harness.records("killswitch.activated")[-1]
    assert activated.data["lockdown_was_active"] is True
    assert activated.severity.value == "critical"
    assert harness.records("recovery.restored")[-1].data["reason"] == "killswitch"
    with pytest.raises(ServiceError) as refused:
        harness.service.lockdown_engage(minutes=5, actor=ADMIN, channel=CHANNEL)
    assert refused.value.code == "killswitch_active"
    # Removing the file does not silently re-enable enforcement.
    harness.config.paths.kill_switch_file.unlink()
    harness.tick()
    assert harness.service.get_mode().effective_mode is Mode.MONITOR


def test_a_kill_switch_in_a_directory_that_is_not_private_is_ignored(
    machine: Callable[..., Harness],
) -> None:
    harness = machine(boot=False)
    harness.privacy.refuse.add(str(harness.config.paths.config_dir))
    harness.boot()
    harness.plug(flash_drive())
    harness.engage(10)
    harness.config.paths.kill_switch_file.write_text("", encoding="utf-8")
    harness.tick()
    assert harness.service.lockdown_status().active
    assert harness.enforcer.is_blocked("test/1-1")
    # And enforce mode is refused while the directory is not private (DESIGN 14.18).
    with pytest.raises(ServiceError) as refused:
        harness.service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
    assert refused.value.code == "not_private"


def test_recover_works_without_the_database_and_the_next_start_ends_the_lockdown(
    machine: Callable[..., Harness],
) -> None:
    harness = _with_devices(machine)
    harness.engage(30)
    harness.crash()
    database = harness.config.paths.database_file
    moved = database.with_name("elsewhere.db")
    database.rename(moved)
    devices = harness.backend.enumerate()
    report = recover(
        harness.config.paths.state_dir,
        harness.enforcer,
        devices,
        clock=harness.clock,
        is_admin=lambda: True,
        timer=harness.timer,
    )
    assert report.failed == () and report.remaining == 0
    assert not harness.enforcer.default_deny
    assert harness.enforcer.state()["blocked"] == []
    moved.rename(database)
    harness.clock.advance(5)
    harness.boot()
    assert harness.service.lockdown_status().state is LockdownState.IDLE
    restored = [r for r in harness.records("recovery.restored") if r.actor == "local-console"]
    assert restored and restored[-1].data["reason"] == "recover"
    assert harness.records("lockdown.lifted")[-1].data["end_reason"] == "recovered"
