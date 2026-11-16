"""Permission enforcement: allow, read-only and deny reach the OS; monitor mode changes nothing."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from factories import flash_drive, keyboard, phone
from integration.harness import ADMIN, CHANNEL, Harness
from portlock.core.models import Mode
from portlock.core.store import ConnectionState, Outcome

POLICY: dict[str, Any] = {
    "version": 1,
    "name": "three verdicts",
    "rules": [
        {
            "id": "allow-1",
            "match": {"vendor_id": ["0x1209"], "product_id": ["0x0001"]},
            "action": {"access": "allow"},
        },
        {
            "id": "ro-6",
            "match": {"vendor_id": ["0x1209"], "product_id": ["0x0006"]},
            "action": {"access": "read_only"},
        },
        {
            "id": "deny-7",
            "match": {"vendor_id": ["0x1209"], "product_id": ["0x0007"]},
            "action": {"access": "deny"},
        },
    ],
}


def _three(machine: Callable[..., Harness], mode: Mode) -> Harness:
    harness = machine()
    harness.service.replace_policy(POLICY, actor=ADMIN)
    if mode is Mode.ENFORCE:
        harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    harness.plug(
        flash_drive(
            instance_id="test/2-1", bus_path="2-1", serial="TEST00020001", product_id=0x0007
        )
    )
    harness.plug(phone())
    return harness


def test_allow_read_only_and_deny_are_enforced(machine: Callable[..., Harness]) -> None:
    harness = _three(machine, Mode.ENFORCE)
    fake = harness.enforcer
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert not fake.is_blocked("test/1-1") and not fake.is_read_only("test/1-1")
    # A phone is an imaging device: in scope, but it has no mass storage interface, so
    # read-only cannot be enforced on it and that is recorded as not enforced.
    phone_view = harness.view("test/1-6")
    assert phone_view.state is ConnectionState.READ_ONLY
    assert phone_view.enforcement is not None
    assert phone_view.enforcement.outcome is Outcome.UNSUPPORTED
    assert phone_view.enforcement.os_state == "open"
    assert harness.view("test/2-1").state is ConnectionState.DENIED
    assert fake.is_blocked("test/2-1")
    assert harness.service.status().counts["not_enforced"] == 1


def test_read_only_storage_is_made_read_only(machine: Callable[..., Harness]) -> None:
    harness = machine()
    policy = dict(POLICY)
    policy["rules"] = [
        {
            "id": "ro-storage",
            "match": {"category": ["storage"]},
            "action": {"access": "read_only"},
        }
    ]
    harness.service.replace_policy(policy, actor=ADMIN)
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.READ_ONLY
    assert view.enforcement is not None and view.enforcement.outcome is Outcome.APPLIED
    assert harness.enforcer.is_read_only("test/1-1")
    assert not harness.enforcer.is_blocked("test/1-1")


def test_monitor_mode_changes_nothing_on_the_operating_system(
    machine: Callable[..., Harness],
) -> None:
    harness = _three(machine, Mode.MONITOR)
    harness.plug(keyboard())
    assert harness.enforcer.calls == ()
    assert harness.journal_open() == 0
    outcomes = {
        view.device.instance_id: view.enforcement.outcome if view.enforcement else None
        for view in harness.service.list_connections()
    }
    assert outcomes["test/2-1"] is Outcome.WOULD_APPLY
    assert outcomes["test/1-6"] is Outcome.WOULD_APPLY
    assert outcomes["test/1-1"] is Outcome.NOT_NEEDED
    assert outcomes["test/1-2"] is Outcome.NOT_NEEDED


def test_returning_to_monitor_mode_releases_everything_portlock_restricted(
    machine: Callable[..., Harness],
) -> None:
    harness = _three(machine, Mode.ENFORCE)
    assert harness.enforcer.is_blocked("test/2-1")
    applied = harness.service.set_mode(Mode.MONITOR, actor=ADMIN, channel=CHANNEL)
    assert applied.value.effective_mode is Mode.MONITOR
    assert applied.summary is not None and applied.summary.released >= 1
    assert harness.enforcer.state()["blocked"] == []
    assert harness.journal_open() == 0
    assert harness.records("mode.changed")[-1].data["new"] == "monitor"
