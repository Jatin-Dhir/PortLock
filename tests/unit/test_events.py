"""The event bus: ordering, isolation of failing handlers, history and thread-safety."""

from __future__ import annotations

import threading
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from portlock.core.clock import FakeClock
from portlock.core.events import (
    DEFAULT_HISTORY,
    HANDLER_ERROR_TOPIC,
    WILDCARD,
    Event,
    EventBus,
)


@pytest.fixture
def bus(clock: FakeClock) -> EventBus:
    return EventBus(clock)


def _seqs(events: list[Event]) -> list[int]:
    return [event.seq for event in events]


# --- publishing ------------------------------------------------------------------------


def test_publish_returns_the_event_with_sequence_time_topic_and_payload(
    bus: EventBus, clock: FakeClock
) -> None:
    first = bus.publish("device.connected", {"fingerprint": "plk1:example", "port": 3})
    clock.advance(90)
    second = bus.publish("device.removed")

    assert first.seq == 1 and second.seq == 2
    assert first.ts == datetime(2026, 1, 1, tzinfo=UTC)
    assert second.ts - first.ts == timedelta(seconds=90)
    assert first.topic == "device.connected"
    assert dict(first.payload) == {"fingerprint": "plk1:example", "port": 3}
    assert dict(second.payload) == {}
    assert bus.last_seq == 2


def test_events_are_immutable_and_detached_from_the_published_mapping(bus: EventBus) -> None:
    source = {"state": "before"}
    event = bus.publish("grant.created", source)
    source["state"] = "after"
    source["extra"] = "added later"
    assert dict(event.payload) == {"state": "before"}
    with pytest.raises(TypeError):
        event.payload["state"] = "tampered"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        event.seq = 99  # type: ignore[misc]


def test_event_to_dict(bus: EventBus) -> None:
    event = bus.publish("lockdown.engaged", {"minutes": 60})
    assert event.to_dict() == {
        "seq": 1,
        "ts": "2026-01-01T00:00:00.000000Z",
        "topic": "lockdown.engaged",
        "payload": {"minutes": 60},
    }


@pytest.mark.parametrize(
    "topic", ["", "*", " device", "device connected", "a" * 129, ".leading", "tab\tbed", None, 5]
)
def test_invalid_topics_are_rejected(bus: EventBus, topic: object) -> None:
    with pytest.raises(ValueError):
        bus.publish(topic)  # type: ignore[arg-type]
    assert bus.last_seq == 0
    assert bus.recent() == []


@pytest.mark.parametrize("payload", [["a", "b"], "text", 5, {1: "numeric key"}])
def test_invalid_payloads_are_rejected(bus: EventBus, payload: object) -> None:
    with pytest.raises(TypeError):
        bus.publish("device.connected", payload)  # type: ignore[arg-type]
    assert bus.last_seq == 0


# --- subscribing -----------------------------------------------------------------------


def test_handlers_receive_only_their_topic_and_wildcard_receives_everything(
    bus: EventBus,
) -> None:
    connected: list[Event] = []
    everything: list[Event] = []
    bus.subscribe("device.connected", connected.append)
    bus.subscribe(WILDCARD, everything.append)

    first = bus.publish("device.connected")
    second = bus.publish("device.removed")
    bus.publish("device.connected.extra")

    assert connected == [first]
    assert everything[:2] == [first, second]
    assert [event.topic for event in everything] == [
        "device.connected",
        "device.removed",
        "device.connected.extra",
    ]


def test_handlers_run_in_subscription_order_on_the_publishing_thread(bus: EventBus) -> None:
    order: list[str] = []
    threads: set[int] = set()

    def handler(name: str):  # type: ignore[no-untyped-def]
        def handle(_event: Event) -> None:
            order.append(name)
            threads.add(threading.get_ident())

        return handle

    bus.subscribe("x", handler("exact-1"))
    bus.subscribe(WILDCARD, handler("wild-1"))
    bus.subscribe("x", handler("exact-2"))
    bus.subscribe("y", handler("other"))
    bus.subscribe(WILDCARD, handler("wild-2"))

    bus.publish("x")
    assert order == ["exact-1", "wild-1", "exact-2", "wild-2"]
    assert threads == {threading.get_ident()}


def test_publish_returns_only_after_the_handlers_have_run(bus: EventBus) -> None:
    seen: list[int] = []
    bus.subscribe("x", lambda event: seen.append(event.seq))
    event = bus.publish("x")
    assert seen == [event.seq]


def test_unsubscribe_stops_delivery_and_is_idempotent(bus: EventBus) -> None:
    seen: list[Event] = []
    unsubscribe = bus.subscribe("x", seen.append)
    bus.publish("x")
    unsubscribe()
    unsubscribe()
    bus.publish("x")
    assert _seqs(seen) == [1]


def test_the_same_handler_can_subscribe_twice_and_unsubscribe_separately(bus: EventBus) -> None:
    seen: list[Event] = []
    first = bus.subscribe("x", seen.append)
    bus.subscribe("x", seen.append)
    bus.publish("x")
    assert _seqs(seen) == [1, 1]
    first()
    bus.publish("x")
    assert _seqs(seen) == [1, 1, 2]


def test_a_handler_unsubscribed_by_an_earlier_handler_is_skipped(bus: EventBus) -> None:
    seen: list[str] = []
    cancel: list = []  # type: ignore[type-arg]

    def first(_event: Event) -> None:
        seen.append("first")
        cancel[0]()

    bus.subscribe("x", first)
    cancel.append(bus.subscribe("x", lambda _event: seen.append("second")))
    bus.publish("x")
    assert seen == ["first"]


def test_a_handler_subscribed_during_delivery_starts_with_the_next_event(bus: EventBus) -> None:
    late: list[int] = []

    def subscriber(event: Event) -> None:
        if event.seq == 1:
            bus.subscribe("x", lambda inner: late.append(inner.seq))

    bus.subscribe("x", subscriber)
    bus.publish("x")
    assert late == []
    bus.publish("x")
    assert late == [2]


def test_a_handler_may_publish(bus: EventBus) -> None:
    log: list[tuple[str, int]] = []

    def on_arrival(event: Event) -> None:
        log.append(("arrival-start", event.seq))
        follow_up = bus.publish("device.decided", {"about": event.seq})
        log.append(("arrival-end", follow_up.seq))

    bus.subscribe("device.connected", on_arrival)
    bus.subscribe("device.decided", lambda event: log.append(("decided", event.seq)))
    bus.subscribe("device.connected", lambda event: log.append(("late-subscriber", event.seq)))

    bus.publish("device.connected")
    # The nested event is delivered at once, before the outer one reaches later handlers.
    assert log == [
        ("arrival-start", 1),
        ("decided", 2),
        ("arrival-end", 2),
        ("late-subscriber", 1),
    ]
    assert _seqs(bus.recent()) == [1, 2]


def test_invalid_subscriptions_are_rejected(bus: EventBus) -> None:
    with pytest.raises(TypeError):
        bus.subscribe("x", "not callable")  # type: ignore[arg-type]
    for topic in ("", "two words", "**", None):
        with pytest.raises(ValueError):
            bus.subscribe(topic, print)  # type: ignore[arg-type]


# --- failing handlers ------------------------------------------------------------------


def test_a_failing_handler_does_not_stop_the_others(bus: EventBus) -> None:
    seen: list[str] = []

    def broken(_event: Event) -> None:
        seen.append("broken")
        raise RuntimeError("handler exploded")

    bus.subscribe("x", lambda _event: seen.append("before"))
    bus.subscribe("x", broken)
    bus.subscribe("x", lambda _event: seen.append("after"))

    event = bus.publish("x")
    assert event.seq == 1
    assert seen == ["before", "broken", "after"]


def test_a_failure_is_published_on_the_error_topic(bus: EventBus) -> None:
    errors: list[Event] = []

    def broken(_event: Event) -> None:
        raise ValueError("bad value 42")

    bus.subscribe("device.connected", broken)
    bus.subscribe(HANDLER_ERROR_TOPIC, errors.append)

    original = bus.publish("device.connected")
    assert len(errors) == 1
    error = errors[0]
    assert error.topic == "internal.handler_error"
    assert error.seq == original.seq + 1
    assert error.payload["topic"] == "device.connected"
    assert error.payload["seq"] == original.seq
    assert error.payload["error_type"] == "ValueError"
    assert error.payload["error"] == "bad value 42"
    assert error.payload["handler"].endswith("broken")
    assert _seqs(bus.recent(topics=[HANDLER_ERROR_TOPIC])) == [2]


def test_each_failing_handler_is_reported_separately(bus: EventBus) -> None:
    errors: list[Event] = []

    def first(_event: Event) -> None:
        raise RuntimeError("one")

    def second(_event: Event) -> None:
        raise KeyError("two")

    bus.subscribe("x", first)
    bus.subscribe("x", second)
    bus.subscribe(HANDLER_ERROR_TOPIC, errors.append)
    bus.publish("x")
    assert [event.payload["error_type"] for event in errors] == ["RuntimeError", "KeyError"]


def test_a_failing_error_handler_does_not_recurse(bus: EventBus) -> None:
    calls: list[str] = []

    def broken(_event: Event) -> None:
        raise RuntimeError("original failure")

    def broken_error_handler(event: Event) -> None:
        calls.append(event.payload["error"])
        raise RuntimeError("the error handler is broken too")

    survivors: list[Event] = []
    bus.subscribe("x", broken)
    bus.subscribe(HANDLER_ERROR_TOPIC, broken_error_handler)
    bus.subscribe(HANDLER_ERROR_TOPIC, survivors.append)

    bus.publish("x")
    # One error event for the original failure; the failure while delivering it is
    # not published again.
    assert calls == ["original failure"]
    assert len(survivors) == 1
    assert [event.topic for event in bus.recent()] == ["x", HANDLER_ERROR_TOPIC]


def test_a_wildcard_handler_that_always_fails_is_called_a_bounded_number_of_times(
    bus: EventBus,
) -> None:
    calls: list[str] = []

    def always_fails(event: Event) -> None:
        calls.append(event.topic)
        raise RuntimeError("always")

    bus.subscribe(WILDCARD, always_fails)
    bus.publish("x")
    assert calls == ["x", HANDLER_ERROR_TOPIC]
    assert bus.last_seq == 2


def test_publishing_keeps_working_after_failures(bus: EventBus) -> None:
    seen: list[int] = []

    def flaky(event: Event) -> None:
        if event.seq == 1:
            raise RuntimeError("first time only")
        seen.append(event.seq)

    bus.subscribe("x", flaky)
    bus.publish("x")
    later = bus.publish("x")
    assert seen == [later.seq]


def test_exceptions_that_are_not_errors_are_not_swallowed(bus: EventBus) -> None:
    def interrupted(_event: Event) -> None:
        raise KeyboardInterrupt

    bus.subscribe("x", interrupted)
    with pytest.raises(KeyboardInterrupt):
        bus.publish("x")


# --- history ---------------------------------------------------------------------------


def test_history_defaults_to_a_thousand_events(clock: FakeClock) -> None:
    bus = EventBus(clock)
    assert DEFAULT_HISTORY == 1000
    assert bus.history_size == 1000
    for _ in range(1005):
        bus.publish("tick")
    kept = bus.recent()
    assert len(kept) == 1000
    assert kept[0].seq == 6 and kept[-1].seq == 1005
    assert bus.last_seq == 1005


def test_history_is_bounded_and_sequence_numbers_keep_counting(clock: FakeClock) -> None:
    bus = EventBus(clock, history=3)
    for index in range(10):
        bus.publish("tick", {"index": index})
    assert _seqs(bus.recent()) == [8, 9, 10]
    assert [event.payload["index"] for event in bus.recent()] == [7, 8, 9]


def test_a_bus_without_history_still_delivers(clock: FakeClock) -> None:
    bus = EventBus(clock, history=0)
    seen: list[Event] = []
    bus.subscribe("x", seen.append)
    bus.publish("x")
    assert len(seen) == 1
    assert bus.recent() == []
    assert bus.history_size == 0


@pytest.mark.parametrize("history", [-1, 1.5, "10", True, None])
def test_invalid_history_sizes_are_rejected(history: object) -> None:
    with pytest.raises(ValueError):
        EventBus(history=history)  # type: ignore[arg-type]


def test_recent_without_arguments_returns_everything_oldest_first(bus: EventBus) -> None:
    assert bus.recent() == []
    events = [bus.publish("a"), bus.publish("b"), bus.publish("a")]
    assert bus.recent() == events


def test_recent_with_only_a_limit_returns_the_newest(bus: EventBus) -> None:
    for _ in range(6):
        bus.publish("tick")
    assert _seqs(bus.recent(limit=2)) == [5, 6]
    assert _seqs(bus.recent(limit=100)) == [1, 2, 3, 4, 5, 6]
    assert bus.recent(limit=0) == []


def test_recent_since_a_sequence_number_pages_forward_without_gaps(bus: EventBus) -> None:
    for _ in range(7):
        bus.publish("tick")
    collected: list[int] = []
    cursor = 0
    while True:
        page = bus.recent(since_seq=cursor, limit=3)
        if not page:
            break
        collected += _seqs(page)
        cursor = page[-1].seq
    assert collected == [1, 2, 3, 4, 5, 6, 7]
    assert _seqs(bus.recent(since_seq=5)) == [6, 7]
    assert bus.recent(since_seq=7) == []
    assert bus.recent(since_seq=999) == []
    assert _seqs(bus.recent(since_seq=0, limit=2)) == [1, 2]


def test_recent_filters_by_topic(bus: EventBus) -> None:
    bus.publish("a")
    bus.publish("b")
    bus.publish("c")
    bus.publish("a")
    assert _seqs(bus.recent(topics=["a"])) == [1, 4]
    assert _seqs(bus.recent(topics={"a", "c"})) == [1, 3, 4]
    assert _seqs(bus.recent(topics="b")) == [2]
    assert bus.recent(topics=[]) == []
    assert bus.recent(topics=["never.published"]) == []
    assert _seqs(bus.recent(since_seq=1, limit=1, topics=["a", "c"])) == [3]
    assert _seqs(bus.recent(limit=1, topics=["a", "b"])) == [4]


def test_recent_returns_a_copy(bus: EventBus) -> None:
    bus.publish("a")
    snapshot = bus.recent()
    snapshot.clear()
    assert len(bus.recent()) == 1


@pytest.mark.parametrize(
    "arguments",
    [
        {"since_seq": -1},
        {"limit": -1},
        {"since_seq": 1.5},
        {"limit": "5"},
        {"limit": True},
        {"topics": ["bad topic"]},
        {"topics": ["*"]},
    ],
)
def test_recent_rejects_invalid_arguments(bus: EventBus, arguments: dict[str, object]) -> None:
    bus.publish("a")
    with pytest.raises(ValueError):
        bus.recent(**arguments)  # type: ignore[arg-type]


def test_the_system_clock_is_used_when_none_is_given() -> None:
    event = EventBus().publish("x")
    assert event.ts.tzinfo is not None
    assert event.ts.utcoffset() == timedelta(0)


# --- thread-safety ---------------------------------------------------------------------


def test_concurrent_publishers_get_unique_ordered_sequence_numbers(clock: FakeClock) -> None:
    publishers, per_thread = 8, 400
    total = publishers * per_thread
    bus = EventBus(clock, history=total)

    received: list[Event] = []
    received_lock = threading.Lock()
    wildcard_count = [0]

    def collect(event: Event) -> None:
        with received_lock:
            received.append(event)

    def count(_event: Event) -> None:
        with received_lock:
            wildcard_count[0] += 1

    bus.subscribe("load", collect)
    bus.subscribe(WILDCARD, count)

    start = threading.Barrier(publishers + 1)
    returned: list[list[Event]] = [[] for _ in range(publishers)]
    failures: list[BaseException] = []

    def publisher(index: int) -> None:
        try:
            start.wait(timeout=10)
            for number in range(per_thread):
                returned[index].append(bus.publish("load", {"thread": index, "n": number}))
        except BaseException as exc:
            failures.append(exc)

    def churn() -> None:
        # Subscribing and unsubscribing while others publish must not disturb them.
        try:
            start.wait(timeout=10)
            for _ in range(300):
                bus.subscribe("load", lambda _event: None)()
                bus.recent(limit=5)
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=publisher, args=(index,)) for index in range(publishers)]
    threads.append(threading.Thread(target=churn))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)
    assert failures == []

    # Every publish got its own sequence number, with none skipped.
    all_returned = [event for events in returned for event in events]
    assert sorted(_seqs(all_returned)) == list(range(1, total + 1))
    assert bus.last_seq == total
    # The history is complete and in sequence order.
    assert _seqs(bus.recent()) == list(range(1, total + 1))
    # Each handler ran exactly once per event.
    assert sorted(_seqs(received)) == list(range(1, total + 1))
    assert wildcard_count[0] == total
    # Events from one thread were numbered, and delivered, in the order it published.
    for index in range(publishers):
        own_returned = _seqs(returned[index])
        assert own_returned == sorted(own_returned)
        assert [event.payload["n"] for event in returned[index]] == list(range(per_thread))
        own_received = [event for event in received if event.payload["thread"] == index]
        assert [event.payload["n"] for event in own_received] == list(range(per_thread))


def test_concurrent_handler_failures_are_all_reported(clock: FakeClock) -> None:
    publishers, per_thread = 4, 100
    bus = EventBus(clock, history=publishers * per_thread * 2)
    errors: list[Event] = []
    lock = threading.Lock()

    def broken(_event: Event) -> None:
        raise RuntimeError("concurrent failure")

    def collect(event: Event) -> None:
        with lock:
            errors.append(event)

    bus.subscribe("load", broken)
    bus.subscribe(HANDLER_ERROR_TOPIC, collect)

    def publisher() -> None:
        for _ in range(per_thread):
            bus.publish("load")

    threads = [threading.Thread(target=publisher) for _ in range(publishers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert len(errors) == publishers * per_thread
    reported = sorted(event.payload["seq"] for event in errors)
    originals = _seqs(bus.recent(topics=["load"]))
    assert reported == originals
    assert bus.last_seq == publishers * per_thread * 2
