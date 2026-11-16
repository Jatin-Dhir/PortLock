"""Reconnection: a new connection, the same fingerprint, the decision recomputed."""

from __future__ import annotations

from collections.abc import Callable

from factories import flash_drive
from integration.harness import ADMIN, Harness
from portlock.core.models import Mode
from portlock.core.store import ConnectionState


def _enforcing(machine: Callable[..., Harness]) -> Harness:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    return harness


def test_a_reconnected_device_gets_a_new_connection_and_the_same_fingerprint(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    first = harness.plug(flash_drive())
    before = harness.view("test/1-1")
    harness.unplug("test/1-1")
    second = harness.plug(flash_drive())
    after = harness.view("test/1-1")
    assert second.connection_id != first.connection_id
    assert after.connection_id != before.connection_id
    assert after.fingerprint == before.fingerprint
    assert after.connection_count == 2
    assert after.state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")


def test_a_once_approved_device_reconnects_pending(machine: Callable[..., Harness]) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.service.approve(harness.connection_id("test/1-1"), kind="once", actor=ADMIN)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    harness.unplug("test/1-1")
    harness.plug(flash_drive())
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")


def test_a_denied_device_reconnects_denied_and_a_trusted_one_allowed(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.plug(flash_drive(instance_id="test/3-1", bus_path="3-1", serial="TEST00030001"))
    harness.service.approve(
        harness.connection_id("test/3-1"), kind="trust", actor=ADMIN, role="admin"
    )
    harness.service.deny(harness.connection_id("test/1-1"), actor=ADMIN)
    for instance_id in ("test/1-1", "test/3-1"):
        harness.unplug(instance_id)
    harness.plug(flash_drive())
    harness.plug(flash_drive(instance_id="test/3-1", bus_path="3-1", serial="TEST00030001"))
    # An operator's denial was for that connection only; the device is pending again,
    # and blocked either way.
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.view("test/3-1").state is ConnectionState.ALLOWED
    assert not harness.enforcer.is_blocked("test/3-1")


def test_a_re_plug_on_the_same_port_before_the_removal_is_seen_is_a_new_connection(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    harness.service.approve(harness.connection_id("test/1-1"), kind="once", actor=ADMIN)
    old = harness.connection_id("test/1-1")
    # The removal and the new arrival happen while nobody is listening.
    harness.backend.unplug("test/1-1", quiet=True)
    harness.backend.plug(flash_drive(), quiet=True)
    harness.tick(30)
    view = harness.view("test/1-1")
    assert view.connection_id != old
    # The once grant belonged to the old connection: the new one is pending.
    assert view.state is ConnectionState.PENDING
