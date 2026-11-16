"""The server-sent event stream (``docs/API.md`` section 7): framing, ordering, resuming,
heartbeats, the end of a session, the stream limit and a client that cannot keep up."""

from __future__ import annotations

import json
import socket
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from test_console_support import WAIT, ApiClient, ApiRig

import portlock.console.api as api_module
from factories import flash_drive
from portlock.auth.accounts import Permission
from portlock.console.api import ApiServer


class EventStream:
    """A reader of ``GET /events`` on a raw socket."""

    def __init__(
        self,
        port: int,
        token: str | None,
        *,
        headers: dict[str, str] | None = None,
        target: str = "/api/v1/events",
    ) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=WAIT)
        lines = [f"GET {target} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
        if token is not None:
            lines.append(f"Authorization: Bearer {token}")
        lines += [f"{name}: {value}" for name, value in (headers or {}).items()]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        self.file = self.sock.makefile("rb")
        self.status = int(self.file.readline().split()[1])
        self.headers: dict[str, str] = {}
        while (line := self.file.readline().rstrip(b"\r\n")) != b"":
            name, _, value = line.decode("latin-1").partition(":")
            self.headers[name.lower()] = value.strip()
        self.error_body = b""
        if self.status != 200:
            length = int(self.headers.get("content-length", "0"))
            self.error_body = self.file.read(length)

    def frame(self, timeout: float = WAIT) -> dict[str, Any] | None:
        """The next frame (``{"event", "id", "data"}``, or ``{"comment"}``); ``None`` at the end."""
        self.sock.settimeout(timeout)
        fields: dict[str, Any] = {}
        while True:
            raw = self.file.readline()
            if not raw:
                return None
            line = raw.rstrip(b"\n").decode("utf-8")
            if line == "":
                if fields and set(fields) != {"retry"}:
                    if "data" in fields:
                        fields["data"] = json.loads(fields["data"])
                    return fields
                fields = {}
                continue
            if line.startswith(":"):
                return {"comment": line[1:].strip()}
            name, _, value = line.partition(":")
            fields[name] = value.strip()

    def until(self, event: str, *, limit: int = 100) -> dict[str, Any]:
        for _ in range(limit):
            frame = self.frame()
            assert frame is not None, f"the stream ended before {event}"
            if frame.get("event") == event:
                return frame
        raise AssertionError(f"no {event} in {limit} frames")

    def events(self, count: int) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        while len(found) < count:
            frame = self.frame()
            assert frame is not None
            if "event" in frame:
                found.append(frame)
        return found

    def ended(self) -> bool:
        """True if the server closes the stream within the time allowed."""
        self.sock.settimeout(WAIT)
        try:
            while self.file.readline():
                pass
        except OSError:
            return False
        return True

    def close(self) -> None:
        self.file.close()
        self.sock.close()


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path_factory.mktemp("events"))
    try:
        yield machine
    finally:
        machine.close()


@pytest.fixture
def open_stream(rig: ApiRig) -> Iterator[Callable[..., EventStream]]:
    opened: list[EventStream] = []

    def make(role: str | None = "admin", **kwargs: Any) -> EventStream:
        token = rig.token(role) if role is not None else None
        stream = EventStream(kwargs.pop("port", rig.port), token, **kwargs)
        opened.append(stream)
        return stream

    yield make
    for stream in opened:
        stream.close()


def seq_of(frame: dict[str, Any]) -> int:
    run_id, _, number = frame["id"].partition("-")
    assert len(run_id) == 16
    return int(number)


# --- framing -----------------------------------------------------------------------------


def test_the_stream_starts_with_a_retry_hint_and_a_hello(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    stream = open_stream()
    assert stream.status == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert stream.headers["cache-control"] == "no-store" and "content-length" not in stream.headers
    assert stream.headers["connection"] == "close"
    assert stream.file.readline() == b"retry: 3000\n" and stream.file.readline() == b"\n"
    hello = stream.frame()
    assert hello is not None and hello["event"] == "hello" and "id" not in hello
    data = hello["data"]
    assert data["run_id"] == rig.runtime.service.run_id
    assert data["resumed"] is False and data["seq"] == rig.runtime.bus.last_seq
    assert data["server_time"].endswith("Z")


def test_the_stream_needs_a_session_and_the_view_permission(rig: ApiRig) -> None:
    assert ApiClient(rig.port).get("/events").status == 401
    for role in ("admin", "operator", "auditor"):
        stream = EventStream(rig.port, rig.token(role))
        assert stream.status == 200
        stream.close()


def test_a_device_arriving_is_seen_with_no_request_made(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    stream = open_stream()
    stream.until("hello")
    stick = flash_drive("TEST0601STRM", instance_id="test/6-1", bus_path="6-1")
    rig.harness.plug(stick)
    try:
        arrived = stream.until("device.connected")
        assert arrived["data"]["connection"]["device"]["serial"] == "TEST0601STRM"
        assert arrived["data"]["connection"]["state"] == "new"
        decided = stream.until("decision.made")
        view = decided["data"]["connection"]
        assert view["state"] == "pending" and view["decision"]["access"] == "pending"
        assert view["connection_id"] == arrived["data"]["connection"]["connection_id"]
        assert seq_of(arrived) < seq_of(decided)
        status = stream.until("status.changed")
        assert status["data"]["counts"]["pending"] >= 1 and status["data"]["degraded"] == []
        rig.client().post(f"/connections/{view['connection_id']}/approve", {})
        granted = stream.until("grant.changed")
        assert granted["data"]["change"] == "created" and granted["data"]["grant"]["kind"] == "once"
        allowed = stream.until("decision.made")
        assert allowed["data"]["connection"]["state"] == "allowed"
    finally:
        rig.harness.unplug(stick.instance_id)
    removed = stream.until("device.removed")
    assert (
        removed["data"]["fingerprint"].startswith("plk1:")
        and removed["data"]["close_reason"] == "removed"
    )


def test_event_ids_increase_and_every_frame_is_one_line_of_json(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    stream = open_stream()
    stream.until("hello")
    hostile = flash_drive(
        "TEST0602LINE", instance_id="test/6-2", bus_path="6-2", product="line one\r\nline two <b>"
    )
    rig.harness.plug(hostile)
    try:
        frames = stream.events(4)
        ids = [seq_of(frame) for frame in frames]
        assert ids == sorted(ids) and len(set(ids)) == len(ids)
        connected = next(frame for frame in frames if frame["event"] == "device.connected")
        # The device model replaces control characters, so the text cannot break a frame.
        replaced = "line one" + chr(0xFFFD) * 2 + "line two <b>"
        assert connected["data"]["connection"]["device"]["product"] == replaced
    finally:
        rig.harness.unplug(hostile.instance_id)


def test_audit_records_are_announced_only_to_sessions_that_may_read_the_audit_log(
    rig: ApiRig, open_stream: Callable[..., EventStream], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = api_module.can
    monkeypatch.setattr(
        api_module,
        "can",
        lambda role, permission: permission is not Permission.VIEW_AUDIT and real(role, permission),
    )
    blind = open_stream("operator")
    blind.until("hello")
    monkeypatch.setattr(api_module, "can", real)
    sighted = open_stream("operator")
    sighted.until("hello")
    rig.runtime.audit("config.changed", actor="test", data={"key": "x"})
    rig.runtime.bus.publish("test.marker", {"after": True})
    seen = []
    while True:
        frame = blind.frame()
        assert frame is not None
        seen.append(frame.get("event"))
        if frame.get("event") == "test.marker":
            break
    assert "audit.appended" not in seen
    appended = sighted.until("audit.appended")
    assert (
        appended["data"]["event_type"] == "config.changed" and appended["data"]["actor"] == "test"
    )
    assert set(appended["data"]) == {"seq", "ts", "event_type", "severity", "actor", "device_fp"}


def test_internal_events_and_unencodable_payloads_do_not_reach_the_client(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    stream = open_stream()
    stream.until("hello")
    bus = rig.runtime.bus
    bus.publish("internal.handler_error", {"error": "secret"})
    bus.publish("test.bad", {"x": object()})
    bus.publish("test.good", {"ok": 1})
    seen: list[str] = []
    while True:
        frame = stream.frame()
        assert frame is not None
        if "event" in frame:
            seen.append(frame["event"])
        if frame.get("event") == "test.good":
            assert frame["data"] == {"ok": 1}
            break
    assert "test.bad" not in seen and not any(name.startswith("internal.") for name in seen)


def test_html_characters_in_event_data_are_json_escaped(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    stream = open_stream()
    stream.until("hello")
    rig.runtime.bus.publish("test.html", {"name": "<img src=x onerror=alert(1)> & more"})
    stream.sock.settimeout(WAIT)
    raw = b""
    while b"test.html" not in raw:
        raw += stream.file.readline()
    data_line = stream.file.readline()
    assert b"<" not in data_line and b">" not in data_line and b"&" not in data_line
    assert (
        json.loads(data_line.decode().split(":", 1)[1])["name"]
        == "<img src=x onerror=alert(1)> & more"
    )


# --- resuming ----------------------------------------------------------------------------


def run_id(rig: ApiRig) -> str:
    return rig.runtime.service.run_id


def test_a_client_that_reconnects_gets_exactly_what_it_missed(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    first = open_stream()
    first.until("hello")
    rig.runtime.bus.publish("test.one", {"n": 1})
    last = first.until("test.one")
    first.close()
    rig.runtime.bus.publish("test.two", {"n": 2})
    rig.runtime.bus.publish("test.three", {"n": 3})
    second = open_stream(headers={"Last-Event-ID": last["id"]})
    hello = second.frame()
    assert hello is not None and hello["data"]["resumed"] is True
    replay = second.events(2)
    assert [frame["event"] for frame in replay] == ["test.two", "test.three"]
    assert seq_of(replay[0]) == seq_of(last) + 1
    rig.runtime.bus.publish("test.four", {"n": 4})
    live = second.until("test.four")
    assert seq_of(live) == seq_of(replay[1]) + 1  # nothing lost, nothing repeated


def test_the_resume_point_may_be_a_query_parameter(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    marker = rig.runtime.bus.publish("test.marker", {"n": 0})
    rig.runtime.bus.publish("test.after", {"n": 1})
    stream = open_stream(target=f"/api/v1/events?since={run_id(rig)}-{marker.seq}")
    assert stream.until("hello")["data"]["resumed"] is True
    assert stream.until("test.after")["data"] == {"n": 1}


def test_an_unknown_run_or_a_future_position_means_start_again(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    restarted = open_stream(headers={"Last-Event-ID": "0123456789abcdef-5"})
    hello = restarted.frame()
    assert hello is not None and hello["data"]["resumed"] is False
    reset = restarted.frame()
    assert (
        reset is not None and reset["event"] == "reset" and reset["data"] == {"reason": "restart"}
    )
    future = open_stream(headers={"Last-Event-ID": f"{run_id(rig)}-999999999"})
    assert future.frame()["data"]["resumed"] is False  # type: ignore[index]
    assert future.frame()["data"] == {"reason": "gap"}  # type: ignore[index]


def test_a_gap_older_than_the_history_means_start_again(
    rig: ApiRig, open_stream: Callable[..., EventStream]
) -> None:
    bus = rig.runtime.bus
    for n in range(bus.history_size + 50):
        bus.publish("test.noise", {"n": n})
    assert bus.oldest_seq is not None and bus.oldest_seq > 2
    stream = open_stream(headers={"Last-Event-ID": f"{run_id(rig)}-1"})
    assert stream.frame()["data"]["resumed"] is False  # type: ignore[index]
    reset = stream.frame()
    assert reset is not None and reset["data"] == {"reason": "gap"}
    nothing = open_stream(headers={"Last-Event-ID": f"{run_id(rig)}-{bus.last_seq}"})
    assert nothing.frame()["data"]["resumed"] is True  # type: ignore[index]


@pytest.mark.parametrize(
    "marker",
    ["", "nonsense", "0123456789abcdef", "0123456789abcdef-", "XYZ-1", "0123456789abcdef-1x"],
)
def test_a_malformed_resume_point_is_refused(
    rig: ApiRig, open_stream: Callable[..., EventStream], marker: str
) -> None:
    by_header = open_stream(headers={"Last-Event-ID": marker}) if marker else None
    if by_header is not None:
        assert by_header.status == 400
    by_query = open_stream(target=f"/api/v1/events?since={marker or 'x'}")
    assert by_query.status == 400
    assert json.loads(by_query.error_body)["error"]["code"] == "invalid_request"


# --- keep-alive, the end of a session, shutdown ------------------------------------------


@pytest.fixture
def quick(rig: ApiRig) -> Iterator[ApiServer]:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, keepalive_seconds=0.2, max_streams=3)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_silence_is_broken_by_a_comment(rig: ApiRig, quick: ApiServer) -> None:
    stream = EventStream(quick.port, rig.token("admin"))
    try:
        stream.until("hello")
        frame = stream.frame(WAIT)
        assert frame == {"comment": "keep-alive"}
    finally:
        stream.close()


def test_the_stream_ends_when_the_session_idles_out_and_it_does_not_keep_it_alive(
    rig: ApiRig, quick: ApiServer
) -> None:
    stream = EventStream(quick.port, rig.token("admin"))
    try:
        stream.until("hello")
        rig.runtime.clock.advance(10 * 60)
        assert stream.frame(WAIT) is not None  # a keep-alive or an event: still open
        rig.runtime.clock.advance(10 * 60)  # 20 minutes without a real request
        ended = stream.until("session.ended")
        assert ended["data"] == {"reason": "expired"}
        assert stream.ended()
    finally:
        stream.close()


def test_the_stream_ends_when_the_session_is_revoked(rig: ApiRig, quick: ApiServer) -> None:
    token = rig.token("operator")
    stream = EventStream(quick.port, token)
    try:
        stream.until("hello")
        assert rig.runtime.sessions.revoke(token)
        assert stream.until("session.ended")["data"] == {"reason": "revoked"}
        assert stream.ended()
    finally:
        stream.close()


def test_stopping_the_server_closes_the_streams(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, keepalive_seconds=0.2)
    server.start()
    stream = EventStream(server.port, rig.token("admin"))
    try:
        stream.until("hello")
        started = time.monotonic()
        server.stop()
        assert stream.ended() and time.monotonic() - started < WAIT
    finally:
        stream.close()


def test_there_is_a_limit_on_open_streams_and_a_place_is_freed_when_one_closes(
    rig: ApiRig, quick: ApiServer
) -> None:
    streams = [EventStream(quick.port, rig.token("admin")) for _ in range(3)]
    try:
        for stream in streams:
            assert stream.status == 200
        refused = EventStream(quick.port, rig.token("admin"))
        assert refused.status == 503
        assert json.loads(refused.error_body)["error"]["code"] == "too_many_streams"
        refused.close()
        streams.pop().close()
        deadline = time.monotonic() + WAIT
        while True:
            retry = EventStream(quick.port, rig.token("admin"))
            if retry.status == 200:
                streams.append(retry)
                break
            retry.close()
            assert time.monotonic() < deadline, "the place was never freed"
            time.sleep(0.1)
    finally:
        for stream in streams:
            stream.close()


def test_a_client_that_cannot_keep_up_is_disconnected(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, stream_queue=2, write_timeout=30.0)
    server.start()
    stream = EventStream(server.port, rig.token("admin"))
    try:
        stream.until("hello")
        blob = "x" * 200_000
        sent = 0
        for _ in range(120):  # far more than the socket buffers hold: the writer blocks
            rig.runtime.bus.publish("test.big", {"blob": blob})
            sent += 1
        received = 0
        stream.sock.settimeout(WAIT)
        while (frame := stream.frame()) is not None:
            if frame.get("event") == "test.big":
                received += 1
        assert received < sent  # it was cut off, not served everything
        assert stream.frame() is None  # and the connection really is closed
    finally:
        stream.close()
        server.stop()
