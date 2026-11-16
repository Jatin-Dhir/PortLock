"""The in-process event bus.

Components inside the service tell each other what happened ("a device arrived", "a
grant expired", "lockdown engaged") through one :class:`EventBus`, so that the audit
log, the web console's live view and the pipeline do not need to know about each other.

The bus is deliberately simple and synchronous:

* :meth:`EventBus.publish` runs every matching handler on the publishing thread, in the
  order the handlers subscribed, and returns once they have all run.
* A handler that raises does not stop the others. Its failure is logged and published
  as an :data:`HANDLER_ERROR_TOPIC` event; a failure *while delivering that* event is
  only logged, so a broken error handler cannot make the bus recurse.
* The last :data:`DEFAULT_HISTORY` events are kept in a ring, so a late consumer (a web
  console that has just connected) can catch up with :meth:`EventBus.recent`.

Threading. Every method may be called from any thread. Sequence numbers are unique and
increasing, and the history is in sequence order. Events published by *one* thread are
delivered in order; two threads publishing at the same time each run the handlers on
their own thread, so a handler can be running for two events at once and must be
thread-safe. No lock is held while a handler runs: a handler may publish, subscribe or
unsubscribe freely. An event published from inside a handler is delivered immediately,
before the outer event reaches the remaining handlers.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from portlock.core.clock import Clock, SystemClock, utc_iso

__all__ = [
    "DEFAULT_HISTORY",
    "HANDLER_ERROR_TOPIC",
    "WILDCARD",
    "Event",
    "EventBus",
    "Handler",
]

#: Subscribing to this topic receives every event.
WILDCARD = "*"
#: Topic of the event published when a handler raises.
HANDLER_ERROR_TOPIC = "internal.handler_error"
#: How many events the history ring keeps unless told otherwise.
DEFAULT_HISTORY = 1000

_LOG = logging.getLogger(__name__)
_TOPIC_PATTERN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z")
_EMPTY_PAYLOAD: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Event:
    """One thing that happened.

    Attributes:
        seq: position in this bus's stream; starts at 1 and never repeats.
        ts: when it was published (timezone-aware UTC, from the injected clock).
        topic: what happened, dotted lower-case by convention: ``device.connected``.
        payload: the details. Read-only; the bus keeps a shallow copy of what was
            published, so nested values should be treated as immutable.
    """

    seq: int
    ts: datetime
    topic: str
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """A plain description (JSON-serializable if the payload is)."""
        return {
            "seq": self.seq,
            "ts": utc_iso(self.ts),
            "topic": self.topic,
            "payload": dict(self.payload),
        }


Handler = Callable[[Event], None]


class _Subscription:
    __slots__ = ("active", "handler", "topic")

    def __init__(self, topic: str, handler: Handler) -> None:
        self.topic = topic
        self.handler = handler
        self.active = True


class EventBus:
    """Thread-safe, synchronous publish/subscribe with a bounded history.

    Args:
        clock: source of event timestamps; the system clock if omitted.
        history: how many of the most recent events :meth:`recent` can return.

    Raises:
        ValueError: if ``history`` is not a non-negative integer.
    """

    def __init__(self, clock: Clock | None = None, *, history: int = DEFAULT_HISTORY) -> None:
        if isinstance(history, bool) or not isinstance(history, int) or history < 0:
            raise ValueError(f"history must be a non-negative integer, got {history!r}")
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.Lock()
        self._seq = 0
        self._next_subscription = 0
        # Insertion-ordered, so iterating it is iterating in subscription order.
        self._subscriptions: dict[int, _Subscription] = {}
        self._history: deque[Event] = deque(maxlen=history)

    @property
    def last_seq(self) -> int:
        """Sequence number of the most recently published event (0 if none yet)."""
        with self._lock:
            return self._seq

    @property
    def oldest_seq(self) -> int | None:
        """Sequence number of the oldest event still in the history, or ``None`` if the
        history is empty.

        A consumer resuming after sequence number ``n`` has missed nothing exactly when
        ``n == last_seq``, or ``oldest_seq`` is not ``None`` and ``oldest_seq <= n + 1``.
        """
        with self._lock:
            return self._history[0].seq if self._history else None

    @property
    def history_size(self) -> int:
        """How many events the history ring can hold."""
        return self._history.maxlen or 0

    def subscribe(self, topic: str, handler: Handler) -> Callable[[], None]:
        """Call ``handler`` for every event on ``topic`` published from now on.

        Args:
            topic: an exact topic name, or ``"*"`` for every event.
            handler: called with the :class:`Event`, on the publishing thread.

        Returns:
            A function that cancels the subscription. Calling it more than once is
            harmless. Once it has returned, the handler is not started again; a call
            already in progress on another thread is not interrupted.

        Raises:
            ValueError: if ``topic`` is not a valid topic name or ``"*"``.
            TypeError: if ``handler`` is not callable.
        """
        if topic != WILDCARD:
            _check_topic(topic)
        if not callable(handler):
            raise TypeError(f"handler must be callable, got {type(handler).__name__}")
        subscription = _Subscription(topic, handler)
        with self._lock:
            self._next_subscription += 1
            key = self._next_subscription
            self._subscriptions[key] = subscription

        def unsubscribe() -> None:
            with self._lock:
                subscription.active = False
                self._subscriptions.pop(key, None)

        return unsubscribe

    def publish(self, topic: str, payload: Mapping[str, Any] | None = None) -> Event:
        """Record an event and run its handlers before returning.

        Args:
            topic: an exact topic name (not ``"*"``).
            payload: the details; a mapping with string keys. Copied shallowly.

        Returns:
            The event, with its sequence number and timestamp.

        Raises:
            ValueError: if ``topic`` is not a valid topic name.
            TypeError: if ``payload`` is not a mapping with string keys.

        A handler that raises does not make ``publish`` raise; see the module docstring.
        """
        _check_topic(topic)
        frozen = _freeze(payload)
        with self._lock:
            # Stamped under the lock so that timestamps never run against the order of
            # the sequence numbers.
            stamp = self._clock.now()
            self._seq += 1
            event = Event(self._seq, stamp, topic, frozen)
            self._history.append(event)
            targets = [
                subscription
                for subscription in self._subscriptions.values()
                if subscription.topic == topic or subscription.topic == WILDCARD
            ]
        for subscription in targets:
            # Honour an unsubscribe that happened after the snapshot was taken, for
            # instance by an earlier handler of this very event.
            if not subscription.active:
                continue
            try:
                subscription.handler(event)
            except Exception as exc:
                self._handler_failed(event, subscription.handler, exc)
        return event

    def recent(
        self,
        since_seq: int | None = None,
        limit: int | None = None,
        topics: Iterable[str] | None = None,
    ) -> list[Event]:
        """Return events from the history ring, oldest first.

        Args:
            since_seq: ``None`` asks for the *latest* events: with ``limit`` it returns
                the newest ``limit`` of them. A number asks for the events *after* that
                sequence number: with ``limit`` it returns the oldest ``limit`` of
                them, so a consumer can page forward by passing the last sequence
                number it saw and never skip one that is still in the ring.
            limit: the most events to return; ``None`` for no limit.
            topics: only events on exactly these topics; ``None`` for all.

        Raises:
            ValueError: if ``since_seq`` or ``limit`` is negative, or not an integer.
        """
        if since_seq is not None:
            _check_count("since_seq", since_seq)
        if limit is not None:
            _check_count("limit", limit)
        wanted = None if topics is None else frozenset(_as_topics(topics))
        with self._lock:
            snapshot = list(self._history)
        floor = since_seq if since_seq is not None else 0
        matches = [
            event
            for event in snapshot
            if event.seq > floor and (wanted is None or event.topic in wanted)
        ]
        if limit is None:
            return matches
        if limit == 0:
            return []
        return matches[-limit:] if since_seq is None else matches[:limit]

    def _handler_failed(self, event: Event, handler: Handler, exc: Exception) -> None:
        name = _handler_name(handler)
        _LOG.error(
            "event handler %s failed for %s (seq %d)", name, event.topic, event.seq, exc_info=exc
        )
        if event.topic == HANDLER_ERROR_TOPIC:
            # The failure happened while reporting a failure. Logging it is all that is
            # safe to do: publishing again could loop for ever.
            return
        self.publish(
            HANDLER_ERROR_TOPIC,
            {
                "topic": event.topic,
                "seq": event.seq,
                "handler": name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )


def _check_topic(topic: object) -> None:
    if not isinstance(topic, str) or not _TOPIC_PATTERN.match(topic):
        raise ValueError(
            "a topic is 1 to 128 letters, digits, '_', '.', ':' or '-', starting with a "
            f"letter, digit or '_'; got {topic!r}"
        )


def _as_topics(topics: Iterable[str]) -> list[str]:
    if isinstance(topics, str):
        # A bare string is iterable, one character at a time; that is never intended.
        topics = [topics]
    result = list(topics)
    for topic in result:
        _check_topic(topic)
    return result


def _check_count(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")


def _freeze(payload: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if payload is None:
        return _EMPTY_PAYLOAD
    if not isinstance(payload, Mapping):
        raise TypeError(f"payload must be a mapping, got {type(payload).__name__}")
    copy = dict(payload)
    for key in copy:
        if not isinstance(key, str):
            raise TypeError(f"payload keys must be strings, got {type(key).__name__}")
    return MappingProxyType(copy)


def _handler_name(handler: Handler) -> str:
    name = getattr(handler, "__qualname__", None)
    if not isinstance(name, str):
        name = type(handler).__qualname__
    module = getattr(handler, "__module__", None)
    return f"{module}.{name}" if isinstance(module, str) else name
