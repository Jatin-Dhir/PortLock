"""The fake backend and fake enforcer: they must keep the contracts of guard/base.py."""

from __future__ import annotations

import itertools
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from factories import (
    flash_drive,
    internal_webcam,
    keyboard,
    mounted_flash_drive,
    phone,
    storage_with_keyboard,
)
from portlock.core.clock import FakeClock
from portlock.core.errors import BackendError, PortLockError
from portlock.core.models import DeviceEvent, DeviceEventType, UsbDevice
from portlock.guard.base import (
    Action,
    DeviceBackend,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
    JournalKind,
    Tier,
)
from portlock.guard.fake import (
    AUTHORIZED_DEFAULT_TARGET,
    AUTHORIZED_DEFAULT_VALUES,
    JOURNAL_KIND,
    EnforcerCall,
    FakeBackend,
    FakeEnforcer,
    authorized_target,
    read_only_target,
)

ARRIVED, REMOVED, CHANGED, RESYNC = (
    DeviceEventType.ARRIVED,
    DeviceEventType.REMOVED,
    DeviceEventType.CHANGED,
    DeviceEventType.RESYNC,
)
CLEAN_STATE = {"default_deny": False, "blocked": [], "read_only": [], "ejected": []}


def _numbered(index: int) -> UsbDevice:
    return flash_drive(serial=f"TEST{index:04d}A7C3", instance_id=f"test/9-{index}")


def _wait_until(condition: Callable[[], bool], timeout: float = 10.0) -> None:
    """Wait for another thread to reach a state that offers nothing to block on."""
    deadline = time.monotonic() + timeout
    pause = threading.Event()
    while not condition():
        assert time.monotonic() < deadline, "the awaited state was never reached"
        pause.wait(0.001)


def _summary(events: list[DeviceEvent]) -> list[tuple[str, str]]:
    return [
        (event.type.value, event.device.instance_id if event.device is not None else "")
        for event in events
    ]


@pytest.fixture
def sync_backend(clock: FakeClock) -> FakeBackend:
    return FakeBackend(clock=clock, synchronous=True)


# === FakeBackend =======================================================================


def test_backend_is_a_device_backend_and_reports_itself() -> None:
    backend = FakeBackend()
    assert isinstance(backend, DeviceBackend)
    capabilities = backend.capabilities()
    assert capabilities.name == "fake"
    assert capabilities.can_enumerate is True
    assert capabilities.event_driven is True
    assert any("simulated" in note for note in capabilities.notes)
    assert FakeBackend(name="simulator").capabilities().name == "simulator"


def test_enumerate_lists_connected_devices_in_plug_order(sync_backend: FakeBackend) -> None:
    initial = FakeBackend([keyboard(), flash_drive()])
    assert initial.enumerate() == [keyboard(), flash_drive()]

    assert sync_backend.enumerate() == []
    sync_backend.plug(flash_drive())
    sync_backend.plug(keyboard())
    sync_backend.plug(phone())
    sync_backend.unplug(keyboard().instance_id)
    assert sync_backend.enumerate() == [flash_drive(), phone()]
    assert sync_backend.get("test/1-1") == flash_drive()
    assert sync_backend.get("test/1-2") is None
    assert sync_backend.is_present("test/1-6") and not sync_backend.is_present("test/1-2")


def test_enumerate_returns_a_copy(sync_backend: FakeBackend) -> None:
    sync_backend.plug(flash_drive())
    listing = sync_backend.enumerate()
    listing.clear()
    assert sync_backend.enumerate() == [flash_drive()]


def test_nothing_is_reported_before_start(sync_backend: FakeBackend) -> None:
    events: list[DeviceEvent] = []
    sync_backend.plug(flash_drive())
    sync_backend.update(mounted_flash_drive())
    sync_backend.unplug("test/1-1")
    sync_backend.plug(keyboard())
    assert sync_backend.started is False
    sync_backend.start(events.append)
    assert sync_backend.started is True
    # Neither the earlier changes nor the device already present are announced.
    assert events == []
    assert sync_backend.enumerate() == [keyboard()]


def test_arrivals_removals_and_changes_are_reported_after_start(
    sync_backend: FakeBackend, clock: FakeClock
) -> None:
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)

    sync_backend.plug(flash_drive())
    clock.advance(5)
    sync_backend.update(mounted_flash_drive())
    clock.advance(5)
    sync_backend.unplug("test/1-1")

    assert _summary(events) == [
        ("arrived", "test/1-1"),
        ("changed", "test/1-1"),
        ("removed", "test/1-1"),
    ]
    assert events[0].device == flash_drive()
    assert events[1].device == mounted_flash_drive() and events[1].device.volumes
    # A removal carries the device as it was last known.
    assert events[2].device == mounted_flash_drive()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert [event.at for event in events] == [
        start,
        start + timedelta(seconds=5),
        start + timedelta(seconds=10),
    ]


def test_a_device_present_at_start_is_not_announced_but_its_later_changes_are(
    clock: FakeClock,
) -> None:
    backend = FakeBackend([flash_drive(), keyboard()], clock=clock, synchronous=True)
    events: list[DeviceEvent] = []
    backend.start(events.append)
    assert events == []
    backend.update(mounted_flash_drive())
    backend.unplug("test/1-2")
    assert _summary(events) == [("changed", "test/1-1"), ("removed", "test/1-2")]


def test_starting_twice_is_an_error(sync_backend: FakeBackend) -> None:
    first: list[DeviceEvent] = []
    second: list[DeviceEvent] = []
    sync_backend.start(first.append)
    with pytest.raises(BackendError) as caught:
        sync_backend.start(second.append)
    assert isinstance(caught.value, PortLockError) and caught.value.code == "backend_error"
    # The failed second start changed nothing: the first callback still receives events.
    sync_backend.plug(flash_drive())
    assert len(first) == 1 and second == []


def test_start_requires_a_callable(sync_backend: FakeBackend) -> None:
    with pytest.raises(TypeError):
        sync_backend.start(None)  # type: ignore[arg-type]
    assert sync_backend.started is False


def test_stop_is_safe_when_not_started_and_can_be_repeated(sync_backend: FakeBackend) -> None:
    sync_backend.stop()
    sync_backend.stop()
    sync_backend.start(lambda _event: None)
    sync_backend.stop()
    sync_backend.stop()
    assert sync_backend.started is False


def test_nothing_is_reported_after_stop_and_a_restart_starts_clean(
    sync_backend: FakeBackend,
) -> None:
    first: list[DeviceEvent] = []
    second: list[DeviceEvent] = []
    sync_backend.start(first.append)
    sync_backend.plug(flash_drive())
    sync_backend.stop()

    sync_backend.plug(keyboard())
    sync_backend.unplug("test/1-1")
    assert _summary(first) == [("arrived", "test/1-1")]

    sync_backend.start(second.append)
    assert second == []
    sync_backend.plug(phone())
    assert _summary(second) == [("arrived", "test/1-6")]
    assert _summary(first) == [("arrived", "test/1-1")]


def test_plugging_the_same_instance_twice_is_rejected(sync_backend: FakeBackend) -> None:
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    sync_backend.plug(flash_drive())
    with pytest.raises(ValueError, match="already connected"):
        sync_backend.plug(flash_drive(serial="TEST0002B8D4"))
    assert len(events) == 1
    assert sync_backend.enumerate() == [flash_drive()]
    with pytest.raises(ValueError, match="duplicate"):
        FakeBackend([flash_drive(), flash_drive()])


def test_unplugging_or_updating_an_unknown_device_is_rejected(sync_backend: FakeBackend) -> None:
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    with pytest.raises(KeyError):
        sync_backend.unplug("test/1-1")
    with pytest.raises(KeyError):
        sync_backend.update(flash_drive())
    assert events == [] and sync_backend.enumerate() == []


@pytest.mark.parametrize("bogus", [None, "test/1-1", {"instance_id": "test/1-1"}, 7])
def test_only_devices_can_be_plugged(sync_backend: FakeBackend, bogus: object) -> None:
    with pytest.raises(TypeError):
        sync_backend.plug(bogus)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sync_backend.update(bogus)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FakeBackend([bogus])  # type: ignore[list-item]


def test_enumeration_failure_can_be_injected(sync_backend: FakeBackend) -> None:
    sync_backend.plug(flash_drive())
    sync_backend.fail_enumerate("the device tree could not be read")
    with pytest.raises(BackendError, match="device tree could not be read"):
        sync_backend.enumerate()
    assert sync_backend.capabilities().can_enumerate is False
    sync_backend.fail_enumerate(None)
    assert sync_backend.enumerate() == [flash_drive()]
    assert sync_backend.capabilities().can_enumerate is True


def test_listeners_see_every_change_started_or_not(sync_backend: FakeBackend) -> None:
    seen: list[tuple[DeviceEventType, str]] = []
    sync_backend.add_listener(lambda kind, device: seen.append((kind, device.instance_id)))
    sync_backend.plug(flash_drive())
    sync_backend.start(lambda _event: None)
    sync_backend.update(mounted_flash_drive())
    sync_backend.unplug("test/1-1")
    assert seen == [(ARRIVED, "test/1-1"), (CHANGED, "test/1-1"), (REMOVED, "test/1-1")]
    with pytest.raises(TypeError):
        sync_backend.add_listener("not callable")  # type: ignore[arg-type]


# --- connections and resynchronization ---------------------------------------------------


def test_every_plug_is_a_new_connection_with_its_own_id(sync_backend: FakeBackend) -> None:
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    first = sync_backend.plug(flash_drive(connection_id="chosen-by-the-test"))
    # The backend supplies the id; whatever the device carried is replaced.
    assert first.connection_id is not None and first.connection_id != "chosen-by-the-test"
    assert sync_backend.get("test/1-1").connection_id == first.connection_id  # type: ignore[union-attr]
    assert events[0].device is not None and events[0].device.connection_id == first.connection_id

    # A volume appearing is the same connection: the id is kept.
    updated = sync_backend.update(mounted_flash_drive())
    assert updated.connection_id == first.connection_id
    assert events[1].device is not None and events[1].device.connection_id == first.connection_id

    # Unplugged and plugged in again, on the same port with the same instance id: a new
    # connection, which is exactly what a "once" grant must be able to tell apart.
    removed = sync_backend.unplug("test/1-1")
    assert removed.connection_id == first.connection_id
    second = sync_backend.plug(flash_drive())
    assert second.instance_id == first.instance_id
    assert second.connection_id not in (None, first.connection_id)
    # The device description is otherwise unchanged (connection ids are not compared).
    assert second == first


def test_connection_ids_are_unique_across_backends_and_initial_devices() -> None:
    seen: set[str] = set()
    for _ in range(3):
        backend = FakeBackend([keyboard(), flash_drive()], synchronous=True)
        ids = [device.connection_id for device in backend.enumerate()]
        ids.append(backend.plug(phone()).connection_id)
        assert None not in ids
        seen.update(str(value) for value in ids)
    assert len(seen) == 9


def test_resync_is_reported_without_a_device(sync_backend: FakeBackend, clock: FakeClock) -> None:
    listened: list[DeviceEventType] = []
    sync_backend.add_listener(lambda kind, _device: listened.append(kind))
    assert sync_backend.resync() is False  # not started: nobody to tell
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    clock.advance(3)
    assert sync_backend.resync() is True
    assert len(events) == 1
    assert events[0].type is RESYNC and events[0].device is None
    assert events[0].at == datetime(2026, 1, 1, 0, 0, 3, tzinfo=UTC)
    # The simulated machine did not change, so its listeners hear nothing.
    assert listened == []


def test_a_missed_change_is_recovered_by_resync_and_enumeration(
    sync_backend: FakeBackend,
) -> None:
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    sync_backend.plug(flash_drive())
    # The notification queue overflows: these changes happen but are not reported.
    sync_backend.plug(keyboard(), quiet=True)
    sync_backend.update(mounted_flash_drive(), quiet=True)
    sync_backend.unplug("test/1-1", quiet=True)
    assert _summary(events) == [("arrived", "test/1-1")]

    sync_backend.resync()
    assert _summary(events)[-1] == ("resync", "")
    # What the caller does on RESYNC: enumerate again, and find the truth.
    assert sync_backend.enumerate() == [keyboard()]


def test_a_quiet_change_still_reaches_a_linked_enforcer(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    device = sync_backend.plug(flash_drive())
    assert enforcer.block(device).changed
    # The OS forgets the device whether or not anybody was told it left.
    sync_backend.unplug(device.instance_id, quiet=True)
    assert enforcer.state() == CLEAN_STATE


def test_starting_then_enumerating_can_see_a_device_both_ways(sync_backend: FakeBackend) -> None:
    # The contract: start first, enumerate afterwards, so nothing falls in the gap.
    # A device arriving in between is reported AND listed, and the caller must treat
    # the second sighting of one connection as the same connection.
    events: list[DeviceEvent] = []
    sync_backend.plug(keyboard())
    sync_backend.start(events.append)
    arrived = sync_backend.plug(flash_drive())
    listed = sync_backend.enumerate()
    assert _summary(events) == [("arrived", "test/1-1")]
    assert listed == [keyboard(), flash_drive()]
    assert listed[1].connection_id == arrived.connection_id


# --- synchronous delivery ---------------------------------------------------------------


def test_synchronous_delivery_runs_the_callback_on_the_calling_thread(
    sync_backend: FakeBackend,
) -> None:
    threads: list[int] = []
    sync_backend.start(lambda _event: threads.append(threading.get_ident()))
    assert sync_backend.synchronous is True
    sync_backend.plug(flash_drive())
    assert threads == [threading.get_ident()]
    assert sync_backend.wait_idle(timeout=0) is True


def test_synchronous_delivery_raises_what_the_callback_raised(sync_backend: FakeBackend) -> None:
    def broken(event: DeviceEvent) -> None:
        if event.device.instance_id == "test/1-1":
            raise RuntimeError("the pipeline failed")

    sync_backend.start(broken)
    with pytest.raises(RuntimeError, match="the pipeline failed"):
        sync_backend.plug(flash_drive())
    # The device is connected all the same, and the backend keeps working.
    assert sync_backend.enumerate() == [flash_drive()]
    assert len(sync_backend.callback_errors) == 1
    sync_backend.plug(keyboard())
    assert sync_backend.enumerate() == [flash_drive(), keyboard()]


def test_a_change_made_inside_the_callback_is_delivered_after_it_returns(
    sync_backend: FakeBackend,
) -> None:
    log: list[str] = []

    def callback(event: DeviceEvent) -> None:
        log.append(f"begin {event.type.value}")
        if event.type is ARRIVED:
            sync_backend.unplug(event.device.instance_id)
            log.append("unplug returned")
        log.append(f"end {event.type.value}")

    sync_backend.start(callback)
    sync_backend.plug(flash_drive())
    # Never nested: a real backend does not re-enter its callback.
    assert log == [
        "begin arrived",
        "unplug returned",
        "end arrived",
        "begin removed",
        "end removed",
    ]
    assert sync_backend.enumerate() == []


def test_stop_from_inside_the_callback_does_not_deadlock(sync_backend: FakeBackend) -> None:
    events: list[DeviceEvent] = []

    def callback(event: DeviceEvent) -> None:
        events.append(event)
        sync_backend.stop()

    sync_backend.start(callback)
    sync_backend.plug(flash_drive())
    sync_backend.plug(keyboard())
    assert _summary(events) == [("arrived", "test/1-1")]
    assert sync_backend.started is False


def test_synchronous_delivery_from_many_threads_is_serialized(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock, synchronous=True)
    threads_count, per_thread = 6, 40
    delivered: list[str] = []
    active = [0]
    overlaps = [0]
    guard = threading.Lock()

    def callback(event: DeviceEvent) -> None:
        with guard:
            active[0] += 1
            if active[0] > 1:
                overlaps[0] += 1
        delivered.append(f"{event.type.value} {event.device.instance_id}")
        with guard:
            active[0] -= 1

    backend.start(callback)
    start = threading.Barrier(threads_count)
    failures: list[BaseException] = []

    def worker(base: int) -> None:
        try:
            start.wait(timeout=10)
            for offset in range(per_thread):
                device = _numbered(base * 1000 + offset)
                backend.plug(device)
                # Synchronous: by now the arrival has been delivered.
                assert f"arrived {device.instance_id}" in delivered
                backend.unplug(device.instance_id)
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(threads_count)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in workers)
    assert failures == []
    assert overlaps[0] == 0
    assert len(delivered) == len(set(delivered)) == threads_count * per_thread * 2
    assert backend.enumerate() == []
    for base in range(threads_count):
        for offset in range(per_thread):
            instance_id = _numbered(base * 1000 + offset).instance_id
            assert delivered.index(f"arrived {instance_id}") < delivered.index(
                f"removed {instance_id}"
            )


# --- threaded delivery ------------------------------------------------------------------


def test_threaded_delivery_uses_a_backend_thread(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    assert backend.synchronous is False
    seen: list[tuple[int, str]] = []
    backend.start(lambda event: seen.append((threading.get_ident(), event.type.value)))
    try:
        backend.plug(flash_drive())
        backend.update(mounted_flash_drive())
        backend.unplug("test/1-1")
        assert backend.wait_idle() is True
    finally:
        backend.stop()
    assert [kind for _, kind in seen] == ["arrived", "changed", "removed"]
    thread_ids = {ident for ident, _ in seen}
    assert len(thread_ids) == 1 and threading.get_ident() not in thread_ids


def test_threaded_delivery_survives_a_failing_callback(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    seen: list[str] = []

    def callback(event: DeviceEvent) -> None:
        seen.append(event.device.instance_id)
        if event.device.instance_id == "test/1-1":
            raise RuntimeError("the pipeline failed")

    backend.start(callback)
    try:
        backend.plug(flash_drive())  # does not raise: the failure is on the backend thread
        backend.plug(keyboard())
        assert backend.wait_idle() is True
    finally:
        backend.stop()
    assert seen == ["test/1-1", "test/1-2"]
    assert [str(error) for error in backend.callback_errors] == ["the pipeline failed"]


def test_threaded_stop_waits_for_the_callback_and_then_stays_silent(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    entered = threading.Event()
    release = threading.Event()
    finished: list[str] = []

    def callback(event: DeviceEvent) -> None:
        entered.set()
        release.wait(timeout=10)
        finished.append(event.device.instance_id)

    backend.start(callback)
    backend.plug(flash_drive())
    assert entered.wait(timeout=10)
    backend.plug(keyboard())  # queued behind the callback that is still running

    stopper = threading.Thread(target=backend.stop)
    stopper.start()
    # stop() has taken effect once the backend no longer reports itself started; it
    # must then still be waiting, because the callback has not been released yet.
    _wait_until(lambda: not backend.started)
    assert stopper.is_alive()
    assert finished == []
    release.set()
    stopper.join(timeout=10)
    assert not stopper.is_alive()
    # stop() returned only after the running callback finished, and the queued event
    # was discarded rather than delivered late.
    assert finished == ["test/1-1"]
    backend.plug(phone())
    assert backend.wait_idle() is True
    assert finished == ["test/1-1"]
    assert backend.enumerate() == [flash_drive(), keyboard(), phone()]


def test_threaded_stop_from_inside_the_callback_does_not_deadlock(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    stopped = threading.Event()

    def callback(_event: DeviceEvent) -> None:
        backend.stop()
        stopped.set()

    backend.start(callback)
    backend.plug(flash_drive())
    assert stopped.wait(timeout=10)
    assert backend.started is False
    # It can be started again afterwards.
    events: list[DeviceEvent] = []
    backend.start(events.append)
    try:
        backend.plug(keyboard())
        assert backend.wait_idle() is True
    finally:
        backend.stop()
    assert _summary(events) == [("arrived", "test/1-2")]


def test_threaded_delivery_from_many_threads_loses_and_duplicates_nothing(
    clock: FakeClock,
) -> None:
    backend = FakeBackend(clock=clock)
    threads_count, per_thread = 8, 50
    delivered: list[tuple[str, str]] = []
    active = [0]
    overlaps = [0]

    def callback(event: DeviceEvent) -> None:
        active[0] += 1
        if active[0] > 1:
            overlaps[0] += 1
        delivered.append((event.type.value, event.device.instance_id))
        active[0] -= 1

    backend.start(callback)
    start = threading.Barrier(threads_count)
    failures: list[BaseException] = []

    def worker(base: int) -> None:
        try:
            start.wait(timeout=10)
            for offset in range(per_thread):
                device = _numbered(base * 1000 + offset)
                backend.plug(device)
                if offset % 2:
                    backend.unplug(device.instance_id)
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(threads_count)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=30)
    try:
        assert backend.wait_idle(timeout=30) is True
    finally:
        backend.stop()

    assert failures == []
    assert overlaps[0] == 0
    total = threads_count * per_thread
    arrivals = [instance for kind, instance in delivered if kind == "arrived"]
    removals = [instance for kind, instance in delivered if kind == "removed"]
    assert len(arrivals) == len(set(arrivals)) == total
    assert len(removals) == len(set(removals)) == total // 2
    assert len(backend.enumerate()) == total // 2
    assert {device.instance_id for device in backend.enumerate()} == set(arrivals) - set(removals)
    for instance in removals:
        assert delivered.index(("arrived", instance)) < delivered.index(("removed", instance))


def test_wait_idle_reports_a_timeout(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    release = threading.Event()
    backend.start(lambda _event: release.wait(timeout=10))
    try:
        backend.plug(flash_drive())
        assert backend.wait_idle(timeout=0.01) is False
        release.set()
        assert backend.wait_idle() is True
    finally:
        release.set()
        backend.stop()


# === FakeEnforcer ======================================================================


def test_enforcer_is_an_enforcer_with_full_capabilities_by_default() -> None:
    enforcer = FakeEnforcer()
    assert isinstance(enforcer, Enforcer)
    assert enforcer.capabilities() == EnforcerCapabilities(
        name="fake",
        privileged=True,
        block=True,
        read_only=True,
        eject=True,
        default_deny=True,
        notes=("simulated: no operating-system state is changed",),
    )
    assert enforcer.state() == CLEAN_STATE
    assert enforcer.calls == ()


def test_block_and_unblock_change_state_and_journal_it() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()

    blocked = enforcer.block(device)
    assert blocked == EnforcementResult(
        action=Action.BLOCK,
        ok=True,
        mechanism="fake:authorized",
        tier=Tier.REACTIVE,
        changed=True,
        detail="blocked test/1-1",
        undo=(JournalEntry("fake", "test/1-1/authorized", "1", "0"),),
        error=None,
    )
    assert enforcer.is_blocked(device) and enforcer.is_blocked("test/1-1")
    assert not enforcer.is_blocked(keyboard())

    unblocked = enforcer.unblock(device)
    assert unblocked.ok and unblocked.changed and unblocked.action is Action.UNBLOCK
    assert unblocked.undo == (JournalEntry(JOURNAL_KIND, "test/1-1/authorized", "0", "1"),)
    assert not enforcer.is_blocked(device)
    assert enforcer.state() == CLEAN_STATE


def test_read_only_changes_state_and_journals_it() -> None:
    enforcer = FakeEnforcer()
    device = mounted_flash_drive()

    result = enforcer.set_read_only(device, True)
    assert result.ok and result.changed and result.action is Action.READ_ONLY
    assert result.mechanism == "fake:read_only" and result.tier is Tier.REACTIVE
    assert result.undo == (JournalEntry("fake", "test/1-1/ro", "0", "1"),)
    assert enforcer.is_read_only(device)
    assert not enforcer.is_blocked(device)

    back = enforcer.set_read_only(device, False)
    assert back.ok and back.changed and back.action is Action.READ_WRITE
    assert back.undo == (JournalEntry(JOURNAL_KIND, "test/1-1/ro", "1", "0"),)
    assert not enforcer.is_read_only(device)


def test_read_only_fails_for_a_device_without_storage() -> None:
    enforcer = FakeEnforcer()
    result = enforcer.set_read_only(keyboard(), True)
    assert result.ok is False and result.changed is False and result.undo == ()
    assert result.error == "not a storage device"
    assert not enforcer.is_read_only(keyboard())
    # Asking for it to be writable is asking for what is already so.
    assert enforcer.set_read_only(keyboard(), False).ok is True
    # Storage paired with a keyboard does have storage.
    assert enforcer.set_read_only(storage_with_keyboard(), True).ok is True


def test_read_only_armed_while_the_device_is_blocked_is_preventive() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    assert enforcer.block(device).ok

    armed = enforcer.set_read_only(device, True)
    assert armed.ok and armed.changed
    assert armed.tier is Tier.PREVENTIVE
    assert armed.detail == "made test/1-1 read-only before it was admitted"
    assert armed.undo == (JournalEntry("fake", "test/1-1/ro", "0", "1"),)

    # Admitting the device does not lift the restriction or change how it came about.
    assert enforcer.unblock(device).ok
    assert enforcer.is_read_only(device) and not enforcer.is_blocked(device)
    again = enforcer.set_read_only(device, True)
    assert again.ok and not again.changed and again.undo == ()
    assert again.tier is Tier.PREVENTIVE

    # Once it has been writable while usable, the next read-only is after the fact.
    assert enforcer.set_read_only(device, False).changed
    late = enforcer.set_read_only(device, True)
    assert late.changed and late.tier is Tier.REACTIVE
    assert late.detail == "made test/1-1 read-only"
    assert enforcer.set_read_only(device, True).tier is Tier.REACTIVE


def test_the_preventive_read_only_tier_does_not_outlive_its_restriction(
    sync_backend: FakeBackend,
) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    device = flash_drive()
    enforcer.set_default_deny(True)
    sync_backend.plug(device)

    # Held back by default-deny: read-only armed now is in place before first use.
    armed = enforcer.set_read_only(device, True)
    assert armed.changed and armed.tier is Tier.PREVENTIVE
    assert enforcer.unblock(device).changed

    # Restoring the journal entry lifts it; arming it again on the usable device is late.
    assert enforcer.restore(armed.undo).changed
    assert not enforcer.is_read_only(device)
    assert enforcer.set_read_only(device, True).tier is Tier.REACTIVE

    # A new connection starts from nothing, here held back once more.
    sync_backend.unplug(device.instance_id)
    sync_backend.plug(device)
    assert not enforcer.is_read_only(device)
    assert enforcer.set_read_only(device, True).tier is Tier.PREVENTIVE

    # forget() drops the memory too.
    enforcer.forget(device)
    assert enforcer.set_read_only(device, True).tier is Tier.REACTIVE


def test_every_journal_entry_is_of_the_fake_kind() -> None:
    # Simulated state must never be mistaken for, or restored over, real OS state.
    assert JOURNAL_KIND is JournalKind.FAKE
    assert AUTHORIZED_DEFAULT_TARGET == "authorized_default"
    assert (authorized_target("test/1-1"), read_only_target("test/1-1")) == (
        "test/1-1/authorized",
        "test/1-1/ro",
    )
    enforcer = FakeEnforcer()
    produced = [
        *enforcer.block(flash_drive()).undo,
        *enforcer.set_read_only(flash_drive(), True).undo,
        *enforcer.set_default_deny(True).undo,
        *enforcer.unblock(flash_drive()).undo,
        *enforcer.set_read_only(flash_drive(), False).undo,
        *enforcer.set_default_deny(False).undo,
    ]
    assert len(produced) == 6
    assert {entry.kind for entry in produced} == {"fake"}
    assert [entry.target for entry in produced] == [
        "test/1-1/authorized",
        "test/1-1/ro",
        "authorized_default",
        "test/1-1/authorized",
        "test/1-1/ro",
        "authorized_default",
    ]
    # Each entry records the move from `previous` to `applied`, and they differ.
    assert all({entry.previous, entry.applied} == {"0", "1"} for entry in produced)
    # The entries survive the trip through storage with their kind intact.
    assert [JournalEntry.from_dict(entry.to_dict()) for entry in produced] == produced


def test_eject_cannot_be_undone() -> None:
    enforcer = FakeEnforcer()
    result = enforcer.eject(flash_drive())
    assert result.ok and result.changed and result.action is Action.EJECT
    assert result.mechanism == "fake:eject"
    assert result.undo == ()
    assert enforcer.was_ejected(flash_drive())
    assert enforcer.state()["ejected"] == ["test/1-1"]


def test_default_deny_changes_state_and_journals_it() -> None:
    enforcer = FakeEnforcer()
    on = enforcer.set_default_deny(True)
    assert on.ok and on.changed and on.action is Action.DEFAULT_DENY_ON
    assert on.mechanism == "fake:default_deny" and on.tier is Tier.PREVENTIVE
    # As on Linux, what is stored is whether new devices are authorized by default.
    assert on.undo == (JournalEntry("fake", "authorized_default", "1", "0"),)
    assert enforcer.default_deny is True

    off = enforcer.set_default_deny(False)
    assert off.ok and off.changed and off.action is Action.DEFAULT_DENY_OFF
    assert off.undo == (JournalEntry(JOURNAL_KIND, "authorized_default", "0", "1"),)
    assert enforcer.default_deny is False


@pytest.mark.parametrize(
    "operation",
    [
        lambda enforcer: enforcer.block(flash_drive()),
        lambda enforcer: enforcer.set_read_only(flash_drive(), True),
        lambda enforcer: enforcer.eject(flash_drive()),
        lambda enforcer: enforcer.set_default_deny(True),
    ],
    ids=["block", "read_only", "eject", "default_deny"],
)
def test_every_operation_is_idempotent(operation) -> None:  # type: ignore[no-untyped-def]
    enforcer = FakeEnforcer()
    first = operation(enforcer)
    state = enforcer.state()
    assert first.ok and first.changed

    for _ in range(3):
        again = operation(enforcer)
        assert again.ok is True
        assert again.changed is False
        assert again.undo == ()
        assert again.error is None
        assert again.action is first.action and again.mechanism == first.mechanism
    assert enforcer.state() == state


@pytest.mark.parametrize(
    "operation",
    [
        lambda enforcer: enforcer.unblock(flash_drive()),
        lambda enforcer: enforcer.set_read_only(flash_drive(), False),
        lambda enforcer: enforcer.set_default_deny(False),
        lambda enforcer: enforcer.restore([]),
    ],
    ids=["unblock", "read_write", "default_deny_off", "restore_nothing"],
)
def test_asking_for_the_initial_state_changes_nothing(operation) -> None:  # type: ignore[no-untyped-def]
    for enforcer in (FakeEnforcer(), FakeEnforcer.unprivileged()):
        result = operation(enforcer)
        assert result.ok is True and result.changed is False and result.undo == ()
        assert enforcer.state() == CLEAN_STATE


# --- restore ----------------------------------------------------------------------------


def test_restore_undoes_everything_that_was_journaled() -> None:
    enforcer = FakeEnforcer()
    stick, other = flash_drive(), _numbered(2)
    journal: list[JournalEntry] = []
    journal += enforcer.set_default_deny(True).undo
    journal += enforcer.block(stick).undo
    journal += enforcer.set_read_only(other, True).undo
    journal += enforcer.block(other).undo
    assert len(journal) == 4
    assert enforcer.state() == {
        "default_deny": True,
        "blocked": ["test/1-1", "test/9-2"],
        "read_only": ["test/9-2"],
        "ejected": [],
    }

    result = enforcer.restore(journal)
    assert result.ok is True and result.changed is True
    assert result.action is Action.RESTORE and result.mechanism == "fake:restore"
    assert result.detail == "restored 4 of 4 journal entries"
    assert result.undo == () and result.error is None
    assert enforcer.state() == CLEAN_STATE

    # Restoring again finds everything already in place.
    again = enforcer.restore(journal)
    assert again.ok is True and again.changed is False
    assert enforcer.state() == CLEAN_STATE


def test_restore_works_from_entries_that_were_stored_and_reloaded() -> None:
    enforcer = FakeEnforcer()
    stored = [entry.to_dict() for entry in enforcer.block(flash_drive()).undo]
    reloaded = [JournalEntry.from_dict(item) for item in stored]
    # A later process: a new enforcer object looking at the same (simulated) machine.
    assert enforcer.restore(reloaded).changed is True
    assert not enforcer.is_blocked(flash_drive())


def test_restore_applies_entries_newest_first() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    # block, then unblock: the journal ends with "it was blocked before this change".
    journal = [*enforcer.block(device).undo, *enforcer.unblock(device).undo]
    assert [entry.previous for entry in journal] == ["1", "0"]
    assert not enforcer.is_blocked(device)

    enforcer.restore(journal)
    # Newest first ends on the oldest entry's previous value: authorized. Oldest first
    # would leave the device blocked.
    assert not enforcer.is_blocked(device)

    reversed_journal = [*enforcer.block(device).undo, *enforcer.unblock(device).undo][::-1]
    enforcer.restore(reversed_journal)
    assert enforcer.is_blocked(device)


def test_restore_reinstates_a_restriction_that_was_previously_in_force() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    enforcer.block(device)
    enforcer.set_read_only(device, True)
    enforcer.set_default_deny(True)
    undo = [
        *enforcer.unblock(device).undo,
        *enforcer.set_read_only(device, False).undo,
        *enforcer.set_default_deny(False).undo,
    ]
    assert enforcer.state() == CLEAN_STATE
    assert enforcer.restore(undo).changed is True
    assert enforcer.state() == {
        "default_deny": True,
        "blocked": ["test/1-1"],
        "read_only": ["test/1-1"],
        "ejected": [],
    }


def test_restore_treats_a_missing_previous_value_as_the_os_default() -> None:
    enforcer = FakeEnforcer()
    enforcer.block(flash_drive())
    enforcer.set_read_only(flash_drive(), True)
    enforcer.set_default_deny(True)
    result = enforcer.restore(
        [
            JournalEntry("fake", "authorized_default", None, "0"),
            JournalEntry("fake", "test/1-1/authorized", None, "0"),
            JournalEntry("fake", "test/1-1/ro", None, "1"),
        ]
    )
    assert result.ok and result.changed
    assert enforcer.state() == CLEAN_STATE


def test_restore_reports_entries_it_cannot_use_but_restores_the_rest() -> None:
    enforcer = FakeEnforcer()
    good = enforcer.block(flash_drive()).undo
    bad = [
        JournalEntry("win_policy_value", "HKLM/Software/Policies/Example/DenyAll", "0", "1"),
        JournalEntry("sysfs_authorized", "/sys/bus/usb/devices/1-1/authorized", "1", "0"),
        JournalEntry("fake", "test/1-1/authorized", "maybe", "0"),
        JournalEntry("fake", "test/1-1/ro", "0", None),
        JournalEntry("fake", "test/1-1/speed", "1", "0"),
        JournalEntry("fake", "/ro", "1", "0"),
        JournalEntry("fake", "authorized_sometimes", "1", "0"),
        JournalEntry("fake", "authorized_default", "3", "0"),
    ]
    result = enforcer.restore([*bad, *good])
    assert result.ok is False
    assert result.changed is True
    assert result.detail == "restored 1 of 9 journal entries; 8 could not be restored"
    assert result.error is not None
    assert "cannot restore a 'win_policy_value' journal entry" in result.error
    assert "cannot restore a 'sysfs_authorized' journal entry" in result.error
    assert "unusable previous value 'maybe'" in result.error
    assert "unusable applied value None for test/1-1/ro" in result.error
    assert "unknown journal target 'test/1-1/speed'" in result.error
    assert "'/ro' names no device" in result.error
    assert "unknown journal target 'authorized_sometimes'" in result.error
    assert "unusable previous value '3'" in result.error
    # The usable entry was still applied: partial access is better than none.
    assert not enforcer.is_blocked(flash_drive())


def test_a_rejected_entry_writes_nothing_even_where_its_target_exists() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    journal = [*enforcer.block(device).undo, *enforcer.set_default_deny(True).undo]
    # Newest in the journal, so first in restore order; its previous value is not one
    # the enforcer could have read, so the read-only flag it names is never touched.
    tampered = [*journal, JournalEntry("fake", "test/1-1/ro", "on", "0")]
    result = enforcer.restore(tampered)
    assert result.ok is False and result.changed is True
    assert result.error == "unusable previous value 'on' for test/1-1/ro"
    assert result.detail == "restored 2 of 3 journal entries; 1 could not be restored"
    assert enforcer.state() == CLEAN_STATE


def test_restore_reverts_only_values_that_are_still_what_was_applied() -> None:
    enforcer = FakeEnforcer()
    on = enforcer.set_default_deny(True)
    assert on.undo == (JournalEntry("fake", "authorized_default", "1", "0"),)

    # Another program changes the setting behind PortLock's back.
    enforcer.set_authorized_default_externally("2")
    result = enforcer.restore(on.undo)
    assert result.ok is True and result.changed is False
    assert result.detail == (
        "restored 0 of 1 journal entries; 1 left alone because something else changed "
        "them since: authorized_default (now '2')"
    )
    # Their value stands: restoring must not undo somebody else's decision.
    assert enforcer.authorized_default == "2"
    assert enforcer.default_deny is False


def test_restore_counts_values_already_back_where_they_were() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    undo = enforcer.block(device).undo
    # An administrator unblocked it by hand: the value is the previous one again.
    enforcer.forget(device)
    result = enforcer.restore(undo)
    assert result.ok is True and result.changed is False
    assert result.detail == "restored 0 of 1 journal entries; 1 already held their previous value"


def test_an_external_authorized_default_is_journaled_as_the_previous_value() -> None:
    enforcer = FakeEnforcer()
    enforcer.set_authorized_default_externally("-1")
    on = enforcer.set_default_deny(True)
    assert on.undo == (JournalEntry("fake", "authorized_default", "-1", "0"),)
    assert enforcer.default_deny is True
    assert enforcer.restore(on.undo).changed is True
    assert enforcer.authorized_default == "-1"
    with pytest.raises(ValueError):
        enforcer.set_authorized_default_externally("3")
    assert AUTHORIZED_DEFAULT_VALUES == ("-1", "0", "1", "2")
    # Not an enforcer call, so it is not in the record.
    assert [call.action for call in enforcer.calls] == [Action.DEFAULT_DENY_ON, Action.RESTORE]


def test_restore_needs_privilege() -> None:
    enforcer = FakeEnforcer()
    undo = enforcer.block(flash_drive()).undo
    enforcer.set_capabilities(FakeEnforcer.unprivileged().capabilities())
    result = enforcer.restore(undo)
    assert result.ok is False and result.changed is False
    assert result.error is not None and result.error.startswith("not_privileged")
    assert enforcer.is_blocked(flash_drive())


# --- write-ahead journaling -------------------------------------------------------------


def test_the_write_ahead_hook_sees_every_entry_that_a_call_then_returns() -> None:
    seen: list[JournalEntry] = []
    enforcer = FakeEnforcer(write_ahead=seen.append)
    device = flash_drive()
    returned: list[JournalEntry] = []
    for result in (
        enforcer.set_default_deny(True),
        enforcer.block(device),
        enforcer.set_read_only(device, True),
        enforcer.unblock(device),
        enforcer.set_read_only(device, False),
        enforcer.set_default_deny(False),
    ):
        assert result.ok and result.changed and len(result.undo) == 1
        returned += result.undo
    assert seen == returned
    assert len(seen) == 6


def test_the_write_ahead_hook_is_not_called_when_nothing_is_written() -> None:
    seen: list[JournalEntry] = []
    enforcer = FakeEnforcer(write_ahead=seen.append)
    device = flash_drive()
    enforcer.unblock(device)  # already unblocked
    enforcer.set_read_only(device, False)  # already writable
    enforcer.set_default_deny(False)  # already off
    enforcer.set_read_only(keyboard(), True)  # not a storage device
    enforcer.eject(device)  # cannot be undone, so nothing to journal
    enforcer.fail(Action.BLOCK)
    enforcer.block(device)  # injected failure
    enforcer.restore([JournalEntry("fake", "test/1-1/authorized", "1", "0")])
    assert seen == []

    unprivileged = FakeEnforcer(FakeEnforcer.unprivileged().capabilities(), write_ahead=seen.append)
    assert unprivileged.block(device).ok is False
    assert seen == []


@pytest.mark.parametrize(
    "operation",
    [
        lambda enforcer: enforcer.block(flash_drive()),
        lambda enforcer: enforcer.set_read_only(flash_drive(), True),
        lambda enforcer: enforcer.set_default_deny(True),
    ],
    ids=["block", "read_only", "default_deny"],
)
def test_a_change_is_not_made_if_it_cannot_be_journaled_first(operation) -> None:  # type: ignore[no-untyped-def]
    def journal_is_down(_entry: JournalEntry) -> None:
        raise OSError("disk full")

    enforcer = FakeEnforcer(write_ahead=journal_is_down)
    result = operation(enforcer)
    assert result.ok is False and result.changed is False and result.undo == ()
    assert result.error == "journal unavailable: OSError: disk full"
    assert enforcer.state() == CLEAN_STATE


def test_releasing_is_journaled_first_too() -> None:
    journal_up = [True]

    def write_ahead(_entry: JournalEntry) -> None:
        if not journal_up[0]:
            raise OSError("disk full")

    enforcer = FakeEnforcer(write_ahead=write_ahead)
    device = flash_drive()
    enforcer.block(device)
    enforcer.set_read_only(device, True)
    journal_up[0] = False
    assert enforcer.unblock(device).error == "journal unavailable: OSError: disk full"
    assert enforcer.set_read_only(device, False).ok is False
    assert enforcer.is_blocked(device) and enforcer.is_read_only(device)
    with pytest.raises(TypeError):
        FakeEnforcer(write_ahead="journal.jsonl")  # type: ignore[arg-type]


def test_admitting_a_held_back_device_needs_no_journal(sync_backend: FakeBackend) -> None:
    journal_up = [True]

    def write_ahead(_entry: JournalEntry) -> None:
        if not journal_up[0]:
            raise OSError("disk full")

    enforcer = FakeEnforcer(backend=sync_backend, write_ahead=write_ahead)
    enforcer.set_default_deny(True)
    board = sync_backend.plug(keyboard())
    assert enforcer.is_blocked(board)

    # Letting a keyboard in must not depend on the journal: nothing is being undone.
    journal_up[0] = False
    admitted = enforcer.unblock(board)
    assert admitted.ok is True and admitted.changed is True and admitted.undo == ()
    assert not enforcer.is_blocked(board)


# --- recorded calls ---------------------------------------------------------------------


def test_every_call_is_recorded_in_order_with_its_result() -> None:
    enforcer = FakeEnforcer()
    stick, board = flash_drive(), keyboard()
    results = [
        enforcer.block(stick),
        enforcer.block(stick),
        enforcer.set_read_only(board, True),
        enforcer.set_read_only(stick, False),
        enforcer.unblock(stick),
        enforcer.eject(stick),
        enforcer.set_default_deny(True),
        enforcer.set_default_deny(False),
        enforcer.restore([]),
    ]
    assert list(enforcer.calls) == [
        EnforcerCall(Action.BLOCK, "test/1-1", results[0], stick),
        EnforcerCall(Action.BLOCK, "test/1-1", results[1], stick),
        EnforcerCall(Action.READ_ONLY, "test/1-2", results[2], board),
        EnforcerCall(Action.READ_WRITE, "test/1-1", results[3], stick),
        EnforcerCall(Action.UNBLOCK, "test/1-1", results[4], stick),
        EnforcerCall(Action.EJECT, "test/1-1", results[5], stick),
        EnforcerCall(Action.DEFAULT_DENY_ON, None, results[6], None),
        EnforcerCall(Action.DEFAULT_DENY_OFF, None, results[7], None),
        EnforcerCall(Action.RESTORE, None, results[8], None),
    ]
    pairs = zip(enforcer.calls, results, strict=True)
    assert all(call.result is result for call, result in pairs)
    assert len(enforcer.calls_for(Action.BLOCK)) == 2
    assert len(enforcer.calls_for(Action.BLOCK, Action.UNBLOCK)) == 3
    assert enforcer.calls_for(Action.READ_ONLY)[0].result.ok is False  # type: ignore[union-attr]

    enforcer.clear_calls()
    assert enforcer.calls == ()
    # Clearing the record does not touch the simulated state.
    assert enforcer.was_ejected(stick)


def test_forget_drops_the_state_of_one_connection() -> None:
    enforcer = FakeEnforcer()
    stick, other = flash_drive(), _numbered(2)
    for device in (stick, other):
        enforcer.block(device)
        enforcer.set_read_only(device, True)
    enforcer.eject(stick)
    enforcer.forget(stick)
    assert enforcer.state() == {
        "default_deny": False,
        "blocked": ["test/9-2"],
        "read_only": ["test/9-2"],
        "ejected": [],
    }


@pytest.mark.parametrize("bogus", [None, "test/1-1", 5, {"instance_id": "test/1-1"}])
def test_wrong_argument_types_are_programming_errors(bogus: object) -> None:
    enforcer = FakeEnforcer()
    for call in (enforcer.block, enforcer.unblock, enforcer.eject):
        with pytest.raises(TypeError):
            call(bogus)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        enforcer.set_read_only(bogus, True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        enforcer.set_read_only(flash_drive(), "yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        enforcer.set_default_deny(1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FakeEnforcer(capabilities="all")  # type: ignore[arg-type]
    assert enforcer.calls == () and enforcer.state() == CLEAN_STATE


# --- failure injection ------------------------------------------------------------------


def test_an_injected_failure_is_returned_once_and_changes_nothing() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    enforcer.fail(Action.BLOCK, "the OS said no")

    failed = enforcer.block(device)
    assert failed == EnforcementResult(
        action=Action.BLOCK,
        ok=False,
        mechanism="fake:authorized",
        tier=Tier.NONE,
        changed=False,
        detail="block failed: the OS said no",
        undo=(),
        error="the OS said no",
    )
    assert not enforcer.is_blocked(device)
    # Other actions are unaffected, and the next block succeeds.
    assert enforcer.set_read_only(device, True).ok is True
    assert enforcer.block(device).changed is True
    assert [call.result.ok for call in enforcer.calls] == [False, True, True]  # type: ignore[union-attr]


def test_injected_failures_can_repeat_or_persist() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    enforcer.fail(Action.EJECT, times=2)
    assert [enforcer.eject(device).ok for _ in range(3)] == [False, False, True]

    enforcer.fail(Action.DEFAULT_DENY_ON, "policy store is read-only", times=None)
    assert [enforcer.set_default_deny(True).ok for _ in range(5)] == [False] * 5
    assert enforcer.default_deny is False
    # Turning it off is a different action and is not affected.
    assert enforcer.set_default_deny(False).ok is True
    enforcer.clear_failures()
    assert enforcer.set_default_deny(True).changed is True


@pytest.mark.parametrize(
    ("action", "operation"),
    [
        (Action.BLOCK, lambda enforcer: enforcer.block(flash_drive())),
        (Action.UNBLOCK, lambda enforcer: enforcer.unblock(flash_drive())),
        (Action.READ_ONLY, lambda enforcer: enforcer.set_read_only(flash_drive(), True)),
        (Action.READ_WRITE, lambda enforcer: enforcer.set_read_only(flash_drive(), False)),
        (Action.EJECT, lambda enforcer: enforcer.eject(flash_drive())),
        (Action.DEFAULT_DENY_ON, lambda enforcer: enforcer.set_default_deny(True)),
        (Action.DEFAULT_DENY_OFF, lambda enforcer: enforcer.set_default_deny(False)),
        (Action.RESTORE, lambda enforcer: enforcer.restore([])),
    ],
    ids=[
        "block",
        "unblock",
        "read_only",
        "read_write",
        "eject",
        "default_deny_on",
        "default_deny_off",
        "restore",
    ],
)
def test_failures_can_be_injected_for_every_action(action: Action, operation) -> None:  # type: ignore[no-untyped-def]
    enforcer = FakeEnforcer()
    enforcer.fail(action, "injected")
    result = operation(enforcer)
    assert result.ok is False and result.error == "injected" and result.action is action
    assert enforcer.state() == CLEAN_STATE

    enforcer.fail(action, raises=OSError("contract broken"))
    with pytest.raises(OSError, match="contract broken"):
        operation(enforcer)
    assert enforcer.calls[-1] == EnforcerCall(
        action, enforcer.calls[0].instance_id, None, enforcer.calls[0].device
    )
    assert enforcer.state() == CLEAN_STATE
    # The injection was used up: the operation works again.
    assert operation(enforcer).ok is True


@pytest.mark.parametrize("times", [0, -1, 1.5, True, "2"])
def test_invalid_injections_are_rejected(times: object) -> None:
    enforcer = FakeEnforcer()
    with pytest.raises(ValueError):
        enforcer.fail(Action.BLOCK, times=times)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        enforcer.fail("block")  # type: ignore[arg-type]
    assert enforcer.block(flash_drive()).ok is True


# --- capabilities -----------------------------------------------------------------------


def test_the_unprivileged_enforcer_can_change_nothing_and_says_why() -> None:
    enforcer = FakeEnforcer.unprivileged()
    capabilities = enforcer.capabilities()
    assert capabilities.privileged is False
    assert (capabilities.block, capabilities.read_only) == (False, False)
    assert (capabilities.eject, capabilities.default_deny) == (False, False)

    device = flash_drive()
    results = [
        enforcer.block(device),
        enforcer.set_read_only(device, True),
        enforcer.eject(device),
        enforcer.set_default_deny(True),
    ]
    for result in results:
        assert result.ok is False and result.changed is False and result.undo == ()
        assert result.error is not None and result.error.startswith("not_privileged: ")
        assert result.mechanism.startswith("fake:")
    assert enforcer.state() == CLEAN_STATE
    assert len(enforcer.calls) == 4


@pytest.mark.parametrize(
    ("missing", "operation"),
    [
        ("block", lambda enforcer: enforcer.block(flash_drive())),
        ("read_only", lambda enforcer: enforcer.set_read_only(flash_drive(), True)),
        ("eject", lambda enforcer: enforcer.eject(flash_drive())),
        ("default_deny", lambda enforcer: enforcer.set_default_deny(True)),
    ],
    ids=["block", "read_only", "eject", "default_deny"],
)
def test_a_missing_mechanism_fails_only_its_own_operations(missing: str, operation) -> None:  # type: ignore[no-untyped-def]
    flags = {"block": True, "read_only": True, "eject": True, "default_deny": True}
    flags[missing] = False
    capabilities = EnforcerCapabilities(name="partial", privileged=True, **flags)
    enforcer = FakeEnforcer(capabilities)
    assert enforcer.capabilities() is capabilities

    result = operation(enforcer)
    assert result.ok is False and result.changed is False
    assert result.error == f"enforcement_error: this enforcer has no {missing} mechanism"
    assert enforcer.state() == CLEAN_STATE

    # Everything else still works.
    others = {
        "block": lambda: enforcer.block(_numbered(5)),
        "read_only": lambda: enforcer.set_read_only(_numbered(6), True),
        "eject": lambda: enforcer.eject(_numbered(7)),
        "default_deny": lambda: enforcer.set_default_deny(True),
    }
    del others[missing]
    assert all(other().changed for other in others.values())


def test_losing_a_capability_does_not_strand_existing_restrictions_silently() -> None:
    enforcer = FakeEnforcer()
    device = flash_drive()
    enforcer.block(device)
    enforcer.set_capabilities(FakeEnforcer.unprivileged().capabilities())
    # The device IS blocked, so unblocking is a real change and needs the privilege:
    # the failure is reported, not disguised as "nothing to do".
    result = enforcer.unblock(device)
    assert result.ok is False and result.error is not None
    assert enforcer.is_blocked(device)
    with pytest.raises(TypeError):
        enforcer.set_capabilities("root")  # type: ignore[arg-type]


# --- linked to a backend ----------------------------------------------------------------


def test_linked_enforcer_fails_for_a_device_that_is_gone(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    device = sync_backend.plug(flash_drive())
    assert enforcer.block(device).changed is True
    sync_backend.unplug(device.instance_id)

    for result in (
        enforcer.block(device),
        enforcer.unblock(device),
        enforcer.set_read_only(device, True),
        enforcer.set_read_only(device, False),
    ):
        assert result.ok is False
        assert result.error == "device test/1-1 is no longer connected"
    # Its state went with the connection.
    assert enforcer.state() == CLEAN_STATE
    # Ejecting something that is already gone is already done.
    gone = enforcer.eject(device)
    assert gone.ok is True and gone.changed is False


def test_linked_enforcer_state_belongs_to_one_connection(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    device = sync_backend.plug(mounted_flash_drive())
    enforcer.block(device)
    enforcer.set_read_only(device, True)
    sync_backend.unplug(device.instance_id)
    sync_backend.plug(device)
    # A freshly connected device is authorized and writable again.
    assert not enforcer.is_blocked(device) and not enforcer.is_read_only(device)
    assert enforcer.block(device).changed is True
    # An update (a volume appearing) is the same connection: state is kept.
    sync_backend.update(flash_drive())
    assert enforcer.is_blocked(device)


def test_linked_eject_unplugs_the_device(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    events: list[DeviceEvent] = []
    sync_backend.start(events.append)
    device = sync_backend.plug(flash_drive())

    result = enforcer.eject(device)
    assert result.ok and result.changed
    assert sync_backend.enumerate() == []
    assert _summary(events) == [("arrived", "test/1-1"), ("removed", "test/1-1")]
    assert enforcer.was_ejected(device)

    again = enforcer.eject(device)
    assert again.ok is True and again.changed is False
    assert len(events) == 2
    # Plugged in again, it is a new connection.
    sync_backend.plug(device)
    assert not enforcer.was_ejected(device)


def test_a_failed_eject_does_not_unplug(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    device = sync_backend.plug(flash_drive())
    enforcer.fail(Action.EJECT, "device is busy")
    assert enforcer.eject(device).ok is False
    assert sync_backend.enumerate() == [device]


def test_default_deny_blocks_new_arrivals_from_the_first_instant(
    sync_backend: FakeBackend,
) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    already_here = sync_backend.plug(keyboard())
    enforcer.set_default_deny(True)
    # Devices connected before default-deny was turned on are untouched.
    assert not enforcer.is_blocked(already_here)

    newcomer = sync_backend.plug(flash_drive())
    assert enforcer.is_blocked(newcomer)
    blocked = enforcer.block(newcomer)
    assert blocked.ok is True and blocked.changed is False
    assert blocked.tier is Tier.PREVENTIVE
    assert blocked.undo == ()

    # Admitting it is a real change, but not one to journal: PortLock is not reversing
    # anything it did, and "restoring" the previous value would lock the device out.
    allowed = enforcer.unblock(newcomer)
    assert allowed.ok is True and allowed.changed is True
    assert allowed.undo == ()
    assert "admitted" in allowed.detail
    assert not enforcer.is_blocked(newcomer)
    # Blocked again by hand, it is the reactive tier.
    assert enforcer.block(newcomer).tier is Tier.REACTIVE


def test_lifting_default_deny_does_not_authorize_devices_it_held_back(
    sync_backend: FakeBackend,
) -> None:
    # This is how Linux behaves, and a lockdown that forgets it leaves devices dead.
    enforcer = FakeEnforcer(backend=sync_backend)
    enforcer.set_default_deny(True)
    held_back = sync_backend.plug(flash_drive())
    enforcer.set_default_deny(False)
    assert enforcer.is_blocked(held_back)
    # A device that arrives now is fine.
    assert not enforcer.is_blocked(sync_backend.plug(keyboard()))
    assert enforcer.unblock(held_back).changed is True


def test_an_externally_set_internal_only_default_holds_back_removable_devices(
    sync_backend: FakeBackend,
) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    enforcer.set_authorized_default_externally("2")
    assert enforcer.default_deny is False  # not PortLock's default-deny
    removable = sync_backend.plug(flash_drive())
    built_in = sync_backend.plug(internal_webcam())
    assert enforcer.is_blocked(removable)
    assert not enforcer.is_blocked(built_in)
    enforcer.set_authorized_default_externally("-1")
    assert not enforcer.is_blocked(sync_backend.plug(phone()))


def test_linked_restore_skips_devices_that_are_gone(sync_backend: FakeBackend) -> None:
    enforcer = FakeEnforcer(backend=sync_backend)
    stays = sync_backend.plug(flash_drive())
    leaves = sync_backend.plug(_numbered(2))
    journal = [
        *enforcer.set_default_deny(True).undo,
        *enforcer.block(stays).undo,
        *enforcer.block(leaves).undo,
    ]
    sync_backend.unplug(leaves.instance_id)

    result = enforcer.restore(journal)
    assert result.ok is True and result.changed is True
    assert result.detail == (
        "restored 2 of 3 journal entries; 1 skipped because the device is no longer connected"
    )
    assert enforcer.state() == CLEAN_STATE


# --- thread-safety ----------------------------------------------------------------------


def test_concurrent_enforcement_keeps_state_and_the_call_record_consistent() -> None:
    enforcer = FakeEnforcer()
    threads_count, devices_per_thread, rounds = 8, 10, 10
    start = threading.Barrier(threads_count)
    failures: list[BaseException] = []
    shared = flash_drive()

    def worker(base: int) -> None:
        try:
            own = [_numbered(base * 100 + offset) for offset in range(devices_per_thread)]
            start.wait(timeout=10)
            for _ in range(rounds):
                for device in own:
                    assert enforcer.block(device).changed is True
                    assert enforcer.set_read_only(device, True).changed is True
                    assert enforcer.unblock(device).changed is True
                    # Everybody also fights over one shared device.
                    enforcer.block(shared)
                    enforcer.unblock(shared)
                    assert enforcer.set_read_only(device, False).changed is True
            for device in own[::2]:
                assert enforcer.block(device).changed is True
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(threads_count)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in workers)
    assert failures == []

    expected_blocked = sorted(
        _numbered(base * 100 + offset).instance_id
        for base in range(threads_count)
        for offset in range(0, devices_per_thread, 2)
    )
    state = enforcer.state()
    assert [item for item in state["blocked"] if item != shared.instance_id] == expected_blocked  # type: ignore[union-attr]
    assert state["read_only"] == []
    per_thread_calls = rounds * devices_per_thread * 6 + devices_per_thread // 2
    assert len(enforcer.calls) == threads_count * per_thread_calls
    # The shared device: every change was a real toggle, so they alternate exactly.
    toggles = [
        call.action
        for call in enforcer.calls
        if call.instance_id == shared.instance_id
        and call.result is not None
        and call.result.changed
    ]
    assert all(first != second for first, second in itertools.pairwise(toggles))
    assert enforcer.is_blocked(shared) is (bool(toggles) and toggles[-1] is Action.BLOCK)


def test_linked_enforcer_and_backend_do_not_deadlock_under_concurrency(clock: FakeClock) -> None:
    backend = FakeBackend(clock=clock)
    enforcer = FakeEnforcer(backend=backend)
    seen: list[str] = []

    def callback(event: DeviceEvent) -> None:
        # What the service does: act on arrivals from the backend thread.
        if event.type is ARRIVED:
            enforcer.block(event.device)
        seen.append(event.type.value)

    backend.start(callback)
    start = threading.Barrier(4)
    failures: list[BaseException] = []

    def worker(base: int) -> None:
        try:
            start.wait(timeout=10)
            for offset in range(40):
                device = backend.plug(_numbered(base * 100 + offset))
                enforcer.set_read_only(device, True)
                enforcer.eject(device)  # unplugs it, calling back into the enforcer
        except BaseException as exc:
            failures.append(exc)

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=30)
    alive = [thread for thread in workers if thread.is_alive()]
    try:
        assert alive == []
        assert backend.wait_idle(timeout=30) is True
    finally:
        backend.stop()
    assert failures == []
    assert backend.enumerate() == []
    assert seen.count("arrived") == seen.count("removed") == 160
    state = enforcer.state()
    assert state["blocked"] == [] and state["read_only"] == []
