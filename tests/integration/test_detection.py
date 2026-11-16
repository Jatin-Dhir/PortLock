"""USB detection: arrivals, devices present at start, the start gap and resync."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from factories import flash_drive, keyboard, phone
from integration.harness import START, Harness
from portlock.core.models import DeviceEvent, DeviceEventType
from portlock.core.store import ConnectionState


def test_a_plugged_device_is_listed_and_streamed_without_polling(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    events: list[tuple[str, Any]] = []
    harness.service.bus.subscribe("*", lambda event: events.append((event.topic, event.payload)))

    plugged = harness.plug(flash_drive())

    view = harness.view("test/1-1")
    assert view.device.connection_id == plugged.connection_id
    assert view.present_at_start is False and view.state is ConnectionState.PENDING
    topics = [topic for topic, _ in events if topic != "audit.appended"]
    assert topics[0] == "device.connected"
    assert "decision.made" in topics
    connected = next(payload for topic, payload in events if topic == "device.connected")
    assert connected["connection"]["fingerprint"] == view.fingerprint
    assert connected["connection"]["state"] == "new"
    audited = harness.records("device.connected")
    assert audited[-1].data["connection_id"] == view.connection_id
    assert audited[-1].data["device"]["product"] == "Example Flash 16GB"


def test_devices_present_at_start_get_connections_marked_present_at_start(
    machine: Callable[..., Harness],
) -> None:
    harness = machine(devices=[keyboard(), phone()])
    views = {view.device.instance_id: view for view in harness.service.list_connections()}
    assert set(views) == {"test/1-2", "test/1-6"}
    assert all(view.present_at_start for view in views.values())
    # Being connected at start confers nothing: the phone is pending, the keyboard is
    # protected by its category, not by its presence.
    assert views["test/1-6"].state is ConnectionState.PENDING
    assert views["test/1-2"].protection_codes == ("input_device",)


def test_an_arrival_in_the_start_gap_is_handled_once(machine: Callable[..., Harness]) -> None:
    harness = machine(boot=False)
    runtime = harness.build()
    service = runtime.service
    original = harness.backend.enumerate

    def enumerate_then_plug() -> list[Any]:
        # The device arrives after the backend started but is also listed: seen twice.
        devices = original()
        if not harness.backend.is_present("test/1-1"):
            harness.backend.plug(flash_drive())
            devices = original()
        return devices

    harness.backend.enumerate = enumerate_then_plug  # type: ignore[method-assign]
    service.start(threads=False)
    service.drain_events()
    harness.backend.enumerate = original  # type: ignore[method-assign]
    open_views = service.list_connections()
    assert [view.device.instance_id for view in open_views] == ["test/1-1"]
    assert len(harness.records("device.connected")) == 1


def test_a_missed_arrival_and_removal_are_found_by_the_periodic_resync(
    machine: Callable[..., Harness],
) -> None:
    harness = machine(devices=[phone()])
    harness.backend.plug(flash_drive(), quiet=True)
    harness.backend.unplug("test/1-6", quiet=True)
    harness.tick(29)
    assert {v.device.instance_id for v in harness.service.list_connections()} == {"test/1-6"}
    harness.tick(1)
    assert {v.device.instance_id for v in harness.service.list_connections()} == {"test/1-1"}
    connected = harness.records("device.connected")[-1]
    removed = harness.records("device.removed")[-1]
    assert connected.data["synthesized"] is True and removed.data["synthesized"] is True
    assert removed.data["reason"] == "resync"


def test_a_resync_event_from_the_backend_enumerates_again(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.backend.plug(flash_drive(), quiet=True)
    assert harness.service.list_connections() == []
    assert harness.backend.resync() is True
    harness.service.drain_events()
    assert [v.device.instance_id for v in harness.service.list_connections()] == ["test/1-1"]


def test_backend_failure_is_degraded_then_recovered_and_audited(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    harness.backend.fail_enumerate("simulated outage")
    harness.backend.resync()
    harness.service.drain_events()
    status = harness.service.status()
    assert "backend" in status.degraded and status.backend["healthy"] is False
    harness.backend.fail_enumerate(None)
    harness.tick(30)
    assert "backend" not in harness.service.status().degraded
    recovered = harness.records("service.recovered")[-1]
    assert recovered.data["component"] == "backend"
    assert recovered.data["outage_seconds"] == 30


def test_an_event_storm_that_overflows_the_queue_is_recovered_by_resync(
    machine: Callable[..., Harness],
) -> None:
    harness = machine()
    service = harness.service
    ghost = DeviceEvent(DeviceEventType.REMOVED, flash_drive(instance_id="test/9-9"), START)
    for _ in range(1000):
        service.on_backend_event(ghost)  # fills the queue; each is a no-op when handled
    harness.backend.plug(flash_drive())  # this arrival does not fit and is dropped
    assert service.drain_events() == 1000
    assert service.list_connections() == []
    harness.tick()  # a dropped event forces a resync at the next tick
    assert [v.device.instance_id for v in service.list_connections()] == ["test/1-1"]
