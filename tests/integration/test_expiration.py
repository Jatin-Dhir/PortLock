"""Policy expiration: a grant, a rule and a time window ending while the device is connected."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from factories import flash_drive
from integration.harness import ADMIN, START, Harness
from portlock.core.models import Mode
from portlock.core.store import ConnectionState


def _enforcing(machine: Callable[..., Harness]) -> Harness:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    return harness


def test_a_temporary_grant_expiring_blocks_the_connected_device_within_one_tick(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    events: list[tuple[str, Any]] = []
    harness.service.bus.subscribe("*", lambda event: events.append((event.topic, event.payload)))
    expires = harness.clock.now() + timedelta(minutes=10)
    harness.service.approve(
        harness.connection_id("test/1-1"), kind="temporary", expires_at=expires, actor=ADMIN
    )
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    decision = harness.view("test/1-1").decision
    assert decision is not None and decision.decision.expires_at == expires

    harness.tick(599)
    assert not harness.enforcer.is_blocked("test/1-1")
    events.clear()
    harness.tick(1)

    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    topics = [topic for topic, _ in events]
    assert "grant.changed" in topics and "decision.made" in topics
    change = next(payload for topic, payload in events if topic == "grant.changed")
    assert change["change"] == "expired"
    assert harness.records("grant.expired")[-1].data["reason"] == "expired"


def test_a_rule_expiring_while_connected_is_reevaluated_and_enforced(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    ends = START + timedelta(hours=1)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "allow-until",
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
    harness.tick(3599)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    harness.tick(1)
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert view.decision is not None and view.decision.trigger == "expiry"
    assert harness.enforcer.is_blocked("test/1-1")


def test_a_time_window_closing_is_enforced(machine: Callable[..., Harness]) -> None:
    harness = _enforcing(machine)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "office-hours",
                    "match": {
                        "vendor_id": ["0x1209"],
                        "time": {"days": ["mon"], "start": "09:00", "end": "10:00"},
                    },
                    "action": {"access": "allow"},
                }
            ],
        },
        actor=ADMIN,
    )
    harness.plug(flash_drive())  # Monday 09:00 UTC
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    harness.tick(3600)
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")


def test_setting_the_clock_back_does_not_revive_an_expired_grant(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    expires = harness.clock.now() + timedelta(minutes=5)
    harness.service.approve(
        harness.connection_id("test/1-1"), kind="temporary", expires_at=expires, actor=ADMIN
    )
    harness.tick(300)
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    harness.clock.set(START)  # back to before the expiry
    harness.tick()
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    rollback = harness.records("clock.rollback_detected")
    assert len(rollback) == 1 and rollback[0].data["behind_seconds"] >= 299
    harness.tick()  # audited once per rollback, not on every tick
    assert len(harness.records("clock.rollback_detected")) == 1
