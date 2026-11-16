"""AuditWriter: never raises into the pipeline, keeps a bounded backlog, flushes in order."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

from portlock.audit.events import AuditError
from portlock.audit.log import AuditLog
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import StoreError
from portlock.core.events import EventBus
from portlock.core.models import Severity
from portlock.core.service import AuditWriter


@pytest.fixture
def log(db: Database, clock: FakeClock) -> AuditLog:
    return AuditLog(db, clock=clock)


@pytest.fixture
def bus(clock: FakeClock) -> EventBus:
    return EventBus(clock)


class Flaky:
    """Make ``log.append`` fail on demand."""

    def __init__(self, log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> None:
        self.real = log.append
        self.error: Exception | None = None
        monkeypatch.setattr(log, "append", self)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.error is not None:
            raise self.error
        return self.real(*args, **kwargs)


@pytest.fixture
def flaky(log: AuditLog, monkeypatch: pytest.MonkeyPatch) -> Iterator[Flaky]:
    yield Flaky(log, monkeypatch)


def test_an_append_is_written_and_published(log: AuditLog, bus: EventBus, clock: FakeClock) -> None:
    seen: list[dict[str, Any]] = []
    bus.subscribe("audit.appended", lambda event: seen.append(dict(event.payload)))
    writer = AuditWriter(log, bus=bus, clock=clock)
    record = writer("service.started", actor="system", data={"run_id": "0" * 16})
    assert record is not None and record.seq == 1
    assert seen == [
        {
            "seq": 1,
            "ts": record.ts,
            "event_type": "service.started",
            "severity": "info",
            "actor": "system",
            "device_fp": None,
        }
    ]
    assert writer.newest_timestamp == clock.now() and not writer.degraded


def test_a_failed_append_is_backlogged_and_flushed_in_order_marked_delayed(
    log: AuditLog, bus: EventBus, clock: FakeClock, flaky: Flaky
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock)
    flaky.error = StoreError("database is locked")
    assert writer("device.connected", data={"n": 1}) is None
    clock.advance(5)
    flaky.error = None
    # Nothing new overtakes the backlog, even once the log works again.
    assert writer("device.removed", data={"n": 2}) is None
    assert writer.degraded and writer.backlog == 2
    assert writer.flush_backlog() == 2
    records = list(log.iterate())
    assert [r.event_type for r in records] == ["device.connected", "device.removed"]
    assert all(r.data["delayed"] is True for r in records)
    assert records[0].data["occurred_at"] == "2026-01-01T00:00:00.000000Z"
    assert records[1].data["occurred_at"] == "2026-01-01T00:00:05.000000Z"
    assert not writer.degraded


def test_the_backlog_is_bounded_and_drops_the_oldest(
    log: AuditLog, bus: EventBus, clock: FakeClock, flaky: Flaky
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock, max_backlog=3)
    flaky.error = OSError("disk full")
    for index in range(5):
        writer("device.connected", data={"n": index})
    assert writer.backlog == 3 and writer.dropped == 2
    flaky.error = None
    writer.flush_backlog()
    assert [r.data["n"] for r in log.iterate()] == [2, 3, 4]


def test_a_flush_stops_at_the_first_failure_and_keeps_the_rest(
    log: AuditLog, bus: EventBus, clock: FakeClock, flaky: Flaky
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock)
    flaky.error = AuditError("key store ahead", code="audit_key_ahead")
    writer("device.connected", data={"n": 1})
    writer("device.connected", data={"n": 2})
    assert writer.flush_backlog() == 0 and writer.backlog == 2


def test_unknown_events_and_malformed_data_are_dropped_not_retried(
    log: AuditLog, bus: EventBus, clock: FakeClock
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock)
    assert writer("device.exploded") is None
    assert writer("device.connected", data={"bad": 1.5}) is None  # floats are refused
    assert writer.backlog == 0 and writer.dropped == 2
    assert log.count() == 0


def test_auth_events_take_their_actor_from_the_data(
    log: AuditLog, bus: EventBus, clock: FakeClock
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock)
    writer.auth_hook("auth.failure", Severity.WARNING, {"username": "mallory", "reason": "x"})
    writer.auth_hook("auth.user_created", Severity.NOTICE, {"username": "bob", "actor": "alice"})
    first, second = log.iterate()
    assert (first.actor, first.severity) == ("mallory", Severity.WARNING)
    assert second.actor == "alice"


def test_the_newest_timestamp_survives_a_clock_set_back(
    log: AuditLog, bus: EventBus, clock: FakeClock
) -> None:
    writer = AuditWriter(log, bus=bus, clock=clock)
    clock.advance(timedelta(hours=2))
    writer("service.started")
    late = clock.now()
    clock.set(late - timedelta(hours=1))
    writer("service.stopped")
    assert writer.newest_timestamp == late
    # A new writer on the same log learns it from the tail.
    assert AuditWriter(log, bus=bus, clock=clock).newest_timestamp == late - timedelta(hours=1)
