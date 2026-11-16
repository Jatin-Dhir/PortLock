"""Device removal: the connection closes, one-time grants are spent, nothing is enforced."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from factories import flash_drive
from integration.harness import ADMIN, START, Harness, StubScanner, with_volume
from portlock.core.clock import FakeClock
from portlock.core.models import Mode


def test_removal_closes_the_connection_and_is_streamed_and_audited(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    removed: list[Any] = []
    harness.service.bus.subscribe("device.removed", lambda event: removed.append(event.payload))
    harness.enforcer.clear_calls()
    harness.clock.advance(42)

    harness.unplug("test/1-1")

    assert harness.enforcer.calls == ()  # the device is gone: no enforcer call
    assert harness.service.list_connections() == []
    history = harness.service.list_connections(open_only=False)
    assert history[0].connection_id == cid and history[0].close_reason == "removed"
    assert history[0].removed_at == harness.clock.now()
    record = harness.records("device.removed")[-1]
    assert record.data["duration_seconds"] == 42 and record.data["state"] == "pending"
    assert removed and removed[0]["connection_id"] == cid
    assert removed[0]["close_reason"] == "removed"
    # The fake's per-connection state went with the device; so did the volatile record.
    assert harness.journal_open() == 0


def test_removal_spends_a_one_time_grant(machine: Callable[..., Harness]) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    grant = harness.service.approve(
        harness.connection_id("test/1-1"), kind="once", actor=ADMIN
    ).value
    harness.unplug("test/1-1")
    expired = harness.records("grant.expired")[-1]
    assert expired.data == {"grant_id": grant.id, "kind": "once", "reason": "consumed"}
    assert harness.service.list_grants() == []


def test_removal_cancels_a_queued_scan(machine: Callable[..., Harness]) -> None:
    clock = FakeClock(START)
    scanner = StubScanner(clock)
    harness = machine(clock=clock, scanner=scanner)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "scan-all",
                    "match": {"category": ["storage"]},
                    "action": {"access": "allow", "scan": "on_mount"},
                }
            ],
        },
        actor=ADMIN,
    )
    harness.plug(with_volume(flash_drive()))
    scans = harness.service.list_scans()
    assert [scan.record.state for scan in scans] == ["queued"]
    harness.unplug("test/1-1")
    harness.run_scans()
    assert scanner.calls == []
    assert harness.service.get_scan(scans[0].record.id).record.state == "cancelled"
