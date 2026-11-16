"""Unauthorized device handling: blocked in enforce mode, reported in monitor mode."""

from __future__ import annotations

from collections.abc import Callable

from factories import flash_drive, storage_with_keyboard
from integration.harness import ADMIN, Harness
from portlock.core.models import Access, Mode
from portlock.core.store import ConnectionState, Outcome
from portlock.guard.base import Action


def test_an_unknown_device_is_blocked_in_enforce_mode(machine: Callable[..., Harness]) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert view.enforcement is not None
    assert view.enforcement.outcome is Outcome.APPLIED
    assert view.enforcement.mechanism == "fake:authorized"
    assert view.enforcement.tier.value == "reactive"
    assert harness.enforcer.is_blocked("test/1-1")
    applied = harness.records("enforcement.applied")[-1]
    assert applied.data["action"] == "block" and applied.data["cause"] == "default"
    assert harness.journal_open() == 1


def test_an_unknown_device_is_only_reported_in_monitor_mode(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert view.enforcement is not None
    assert view.enforcement.outcome is Outcome.WOULD_APPLY
    assert view.enforcement.would == "blocked" and view.enforcement.os_state == "open"
    assert harness.enforcer.calls == ()
    assert harness.records("enforcement.would_apply")[-1].data["mechanism"] == "dry-run"


def test_storage_with_a_keyboard_is_denied_with_an_alert(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    alerts: list[dict[str, object]] = []
    harness.service.bus.subscribe("alert", lambda event: alerts.append(dict(event.payload)))
    harness.plug(storage_with_keyboard())
    view = harness.view("test/1-5")
    assert view.state is ConnectionState.DENIED and not view.protected
    assert view.decision is not None
    assert view.decision.decision.access is Access.DENY
    assert view.decision.decision.rule_id == "deny-input-with-other"
    assert view.decision.decision.alert is True
    assert harness.enforcer.is_blocked("test/1-5")
    suspicious = harness.records("safety.suspicious_device")[-1]
    assert suspicious.data["reason"] == "storage_with_input"
    assert suspicious.severity.value == "warning"
    assert harness.records("decision.made")[-1].severity.value == "warning"
    assert alerts and alerts[0]["fingerprint"] == view.fingerprint


def test_an_operator_can_deny_and_eject_a_pending_device(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    applied = harness.service.deny(cid, eject=True, note="unknown stick", actor=ADMIN)
    ejected = applied.extra["eject"]
    assert ejected is not None and ejected.ok and ejected.changed
    assert harness.enforcer.calls_for(Action.EJECT)
    harness.service.drain_events()
    assert harness.service.list_connections() == []  # the eject unplugged it
    assert harness.records("device.removed")[-1].data["connection_id"] == cid
