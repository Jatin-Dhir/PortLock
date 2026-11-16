"""Audit sinks: the JSONL file, syslog, callbacks and the fan-out."""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from portlock.audit import sinks as sinks_module
from portlock.audit.events import AuditError
from portlock.audit.log import AuditKeyStore, AuditLog, AuditRecord
from portlock.audit.sinks import (
    CallbackSink,
    ClawNetSink,
    FanOut,
    JsonlFileSink,
    MinSeveritySink,
    SinkStats,
    SyslogSink,
    format_rfc5424,
)
from portlock.core.canonical import parse_canonical
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.models import Severity

FP = "plk1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
WAIT = 10.0  # generous upper bound for cross-thread hand-offs; never slept through


def make_record(seq: int = 1, **overrides: Any) -> AuditRecord:
    fields: dict[str, Any] = {
        "seq": seq,
        "ts": f"2026-01-01T00:00:{seq % 60:02d}.000000Z",
        "event_type": "device.connected",
        "severity": Severity.INFO,
        "actor": None,
        "device_fp": FP,
        "data": {"n": seq},
        "prev_hash": f"{seq - 1:064x}",
        "hash": f"{seq:064x}",
        "mac": None,
    }
    fields.update(overrides)
    return AuditRecord(**fields)


def read_lines(path: Path) -> list[dict[str, Any]]:
    return [parse_canonical(line) for line in path.read_bytes().split(b"\n")[:-1]]


def line_of(record: AuditRecord) -> bytes:
    """The line a record becomes, computed independently so tests can pick exact sizes."""
    text = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8") + b"\n"


# --- JsonlFileSink -------------------------------------------------------------------


def test_file_sink_writes_one_canonical_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "export" / "audit.jsonl"
    sink = JsonlFileSink(path, 1_000_000)
    assert not path.parent.exists()  # nothing is touched until a record arrives
    records = [make_record(1), make_record(2, actor="Zo" + chr(0xEB), data={"note": "a\nb"})]
    for record in records:
        sink.emit(record)
    raw = path.read_bytes()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 2
    assert b"\r" not in raw
    assert read_lines(path) == [record.to_dict() for record in records]
    assert raw == line_of(records[0]) + line_of(records[1])
    assert ("Zo" + chr(0xEB)).encode("utf-8") in raw  # raw UTF-8, not an ASCII escape
    assert sink.rotations == 0 and sink.path == path
    sink.close()


def test_file_sink_appends_to_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = JsonlFileSink(path, 1_000_000)
    first.emit(make_record(1))
    first.close()
    second = JsonlFileSink(path, 1_000_000)
    second.emit(make_record(2))
    second.close()
    assert [entry["seq"] for entry in read_lines(path)] == [1, 2]


def test_file_sink_rotates_by_size_and_keeps_every_record_within_backups(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    line = len(line_of(make_record(1)))
    sink = JsonlFileSink(path, line * 3, backups=3)  # exactly three records per file
    for seq in range(1, 11):
        sink.emit(make_record(seq))
    sink.close()
    assert sink.rotations == 3 and sink.rotation_failures == 0
    assert sorted(item.name for item in tmp_path.iterdir()) == [
        "audit.jsonl",
        "audit.jsonl.1",
        "audit.jsonl.2",
        "audit.jsonl.3",
    ]
    assert [entry["seq"] for entry in read_lines(path)] == [10]
    assert [entry["seq"] for entry in read_lines(tmp_path / "audit.jsonl.1")] == [7, 8, 9]
    assert [entry["seq"] for entry in read_lines(tmp_path / "audit.jsonl.2")] == [4, 5, 6]
    assert [entry["seq"] for entry in read_lines(tmp_path / "audit.jsonl.3")] == [1, 2, 3]
    for item in tmp_path.iterdir():
        assert item.stat().st_size <= line * 3


def test_file_sink_replaces_the_oldest_backup(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    line = len(line_of(make_record(1)))
    sink = JsonlFileSink(path, line, backups=2)  # one record per file
    for seq in range(1, 6):
        sink.emit(make_record(seq))
    sink.close()
    assert sorted(item.name for item in tmp_path.iterdir()) == [
        "audit.jsonl",
        "audit.jsonl.1",
        "audit.jsonl.2",
    ]
    assert [read_lines(tmp_path / name)[0]["seq"] for name in sorted(os.listdir(tmp_path))] == [
        5,
        4,
        3,
    ]
    assert sink.rotations == 4


def test_file_sink_gives_an_oversized_record_a_file_of_its_own(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(path, 400, backups=5)
    big = make_record(2, data={"blob": "x" * 2000})
    for record in (make_record(1), big, make_record(3)):
        sink.emit(record)
    sink.close()
    assert read_lines(path) == [make_record(3).to_dict()]
    assert read_lines(tmp_path / "audit.jsonl.1") == [big.to_dict()]
    assert read_lines(tmp_path / "audit.jsonl.2") == [make_record(1).to_dict()]


def test_file_sink_counts_existing_content_towards_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    line = len(line_of(make_record(1)))
    path.write_bytes(line_of(make_record(1)) + line_of(make_record(2)))
    sink = JsonlFileSink(path, line * 2)
    sink.emit(make_record(3))
    sink.close()
    assert [entry["seq"] for entry in read_lines(path)] == [3]
    assert [entry["seq"] for entry in read_lines(tmp_path / "audit.jsonl.1")] == [1, 2]


def test_file_sink_keeps_the_record_when_rotation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    line = len(line_of(make_record(1)))
    sink = JsonlFileSink(path, line)

    def refuse(_source: Any, _target: Any) -> None:
        raise PermissionError("the file is in use by another process")

    sink.emit(make_record(1))
    monkeypatch.setattr(sinks_module.os, "replace", refuse)
    sink.emit(make_record(2))
    sink.emit(make_record(3))
    monkeypatch.undo()
    assert sink.rotation_failures == 2 and sink.rotations == 0
    assert [entry["seq"] for entry in read_lines(path)] == [1, 2, 3]  # oversized, nothing lost
    sink.emit(make_record(4))  # rotation works again
    sink.close()
    assert sink.rotations == 1
    assert [entry["seq"] for entry in read_lines(path)] == [4]
    assert [entry["seq"] for entry in read_lines(tmp_path / "audit.jsonl.1")] == [1, 2, 3]


def test_file_sink_reports_write_failures_as_sink_errors(tmp_path: Path) -> None:
    directory = tmp_path / "is-a-directory"
    directory.mkdir()
    sink = JsonlFileSink(directory, 1000)
    with pytest.raises(AuditError, match="cannot write is-a-directory") as caught:
        sink.emit(make_record(1))
    assert caught.value.code == "sink_error"
    assert isinstance(caught.value.__cause__, OSError)


def test_file_sink_serializer(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    sink = JsonlFileSink(path, 10_000, serializer=lambda record: {"seq": record.seq, "z": [1, 2]})
    sink.emit(make_record(7))
    assert path.read_bytes() == b'{"seq":7,"z":[1,2]}\n'
    bad = JsonlFileSink(tmp_path / "bad.jsonl", 10_000, serializer=lambda record: {"ratio": 0.5})
    with pytest.raises(AuditError, match="not canonical JSON"):
        bad.emit(make_record(1))
    assert not (tmp_path / "bad.jsonl").exists()
    sink.close()


def test_file_sink_refuses_records_after_close(tmp_path: Path) -> None:
    sink = JsonlFileSink(tmp_path / "audit.jsonl", 1000)
    sink.emit(make_record(1))
    sink.close()
    sink.close()
    with pytest.raises(AuditError, match="closed") as caught:
        sink.emit(make_record(2))
    assert caught.value.code == "sink_error"
    assert len(read_lines(tmp_path / "audit.jsonl")) == 1


@pytest.mark.parametrize(
    "arguments",
    [
        {"max_bytes": 0},
        {"max_bytes": -5},
        {"max_bytes": "1000"},
        {"max_bytes": True},
        {"max_bytes": 1000, "backups": 0},
        {"max_bytes": 1000, "backups": 1.5},
        {"max_bytes": 1000, "serializer": "not callable"},
    ],
)
def test_file_sink_validates_its_arguments(tmp_path: Path, arguments: dict[str, Any]) -> None:
    with pytest.raises(AuditError):
        JsonlFileSink(tmp_path / "audit.jsonl", **arguments)


def test_file_sink_is_thread_safe(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(path, 6000, backups=100)
    workers, each = 8, 25
    barrier = threading.Barrier(workers)

    def work(worker: int) -> None:
        barrier.wait(WAIT)
        for index in range(each):
            sink.emit(make_record(worker * 1000 + index + 1))

    threads = [threading.Thread(target=work, args=(worker,)) for worker in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WAIT)
    sink.close()
    entries = [entry for item in tmp_path.iterdir() for entry in read_lines(item)]
    assert len(entries) == workers * each  # every line is complete and parses
    assert {entry["seq"] for entry in entries} == {
        worker * 1000 + index + 1 for worker in range(workers) for index in range(each)
    }
    assert sink.rotations > 0 and sink.rotation_failures == 0


@pytest.mark.linux_only
def test_file_sink_files_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "export" / "audit.jsonl"
    line = len(line_of(make_record(1)))
    sink = JsonlFileSink(path, line)
    sink.emit(make_record(1))
    sink.emit(make_record(2))
    sink.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "export" / "audit.jsonl.1").stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.linux_only
def test_file_sink_tightens_an_existing_file_and_does_not_follow_symlinks(tmp_path: Path) -> None:
    loose = tmp_path / "loose.jsonl"
    loose.write_bytes(b"")
    loose.chmod(0o644)
    sink = JsonlFileSink(loose, 1000)
    sink.emit(make_record(1))
    sink.close()
    assert stat.S_IMODE(loose.stat().st_mode) == 0o600

    target = tmp_path / "elsewhere.txt"
    target.write_bytes(b"untouched")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    with pytest.raises(AuditError, match=r"cannot write link\.jsonl"):
        JsonlFileSink(link, 1000).emit(make_record(1))
    assert target.read_bytes() == b"untouched"


# --- RFC 5424 formatting -------------------------------------------------------------


def split_message(message: bytes) -> tuple[list[str], str, dict[str, Any]]:
    """Split a formatted message into header fields, structured data and the JSON body."""
    fields = message.decode("utf-8").split(" ", 6)
    header, rest = fields[:6], fields[6]
    if rest.startswith("- "):
        return header, "-", json.loads(rest[2:])
    # One SD-ELEMENT: it ends at the first "]" that is not escaped by a backslash.
    assert rest.startswith("[")
    index = 1
    while rest[index] != "]":
        index += 2 if rest[index] == chr(92) else 1
    assert rest[index + 1] == " "
    return header, rest[: index + 1], json.loads(rest[index + 2 :])


def test_rfc5424_layout_is_exact() -> None:
    record = make_record(5, event_type="auth.failure", severity=Severity.WARNING, actor="alice")
    message = format_rfc5424(record, hostname="lab-1")
    body = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))
    assert message == (
        b"<108>1 2026-01-01T00:00:05.000000Z lab-1 portlock - auth.failure - " + body.encode()
    )
    assert split_message(message) == (
        ["<108>1", "2026-01-01T00:00:05.000000Z", "lab-1", "portlock", "-", "auth.failure"],
        "-",
        record.to_dict(),
    )


def test_rfc5424_fields_default_to_the_nil_value() -> None:
    fields, structured, body = split_message(format_rfc5424(make_record(1)))
    assert fields == [
        "<110>1",
        "2026-01-01T00:00:01.000000Z",
        "-",
        "portlock",
        "-",
        "device.connected",
    ]
    assert structured == "-"
    assert body == make_record(1).to_dict()


@pytest.mark.parametrize(
    ("severity", "code"),
    [
        (Severity.DEBUG, 7),
        (Severity.INFO, 6),
        (Severity.NOTICE, 5),
        (Severity.WARNING, 4),
        (Severity.ERROR, 3),
        (Severity.CRITICAL, 2),
    ],
)
def test_rfc5424_priority_is_facility_times_eight_plus_severity(
    severity: Severity, code: int
) -> None:
    record = make_record(1, severity=severity)
    assert format_rfc5424(record).startswith(f"<{13 * 8 + code}>1 ".encode())
    assert format_rfc5424(record, facility=4).startswith(f"<{4 * 8 + code}>1 ".encode())
    assert format_rfc5424(record, facility=0).startswith(f"<{code}>1 ".encode())
    assert format_rfc5424(record, facility=23).startswith(f"<{23 * 8 + code}>1 ".encode())


def test_rfc5424_header_options() -> None:
    message = format_rfc5424(
        make_record(1), hostname="gw.example.test", app_name="portlock-svc", procid="4242"
    )
    assert message.startswith(
        b"<110>1 2026-01-01T00:00:01.000000Z gw.example.test portlock-svc 4242 device.connected - {"
    )


def test_rfc5424_message_is_ascii_json_that_parses_to_the_record() -> None:
    name = "Zo" + chr(0xEB) + " " + chr(0x1F512)
    record = make_record(3, actor=name, data={"note": name, "tab": "a\tb"})
    message = format_rfc5424(record)
    assert message.isascii()  # valid without a byte-order mark, safe through 7-bit relays
    assert b"\n" not in message and b"\t" not in message
    _, _, body = split_message(message)
    assert body == record.to_dict()
    assert body["actor"] == name


def test_rfc5424_structured_data_needs_an_enterprise_number() -> None:
    record = make_record(
        9, severity=Severity.ERROR, actor='eve "the]bracket" \\ ' + chr(0xE9) + "\x07", device_fp=FP
    )
    message = format_rfc5424(record, enterprise_id=32473).decode("utf-8")
    expected = (
        '[portlock@32473 seq="9" severity="error" hash="' + record.hash + '"'
        ' actor="eve \\"the\\]bracket\\" \\\\ ' + chr(0xE9) + '" device_fp="' + FP + '"]'
    )
    assert f" device.connected {expected} {{" in message
    # Without labels the element still carries what identifies the record.
    plain = format_rfc5424(make_record(2, device_fp=None), enterprise_id=1).decode("utf-8")
    assert f'[portlock@1 seq="2" severity="info" hash="{make_record(2).hash}"] {{' in plain


def test_rfc5424_drops_data_when_the_message_would_be_too_long() -> None:
    record = make_record(4, data={"blob": "x" * 5000})
    message = format_rfc5424(record, max_message_bytes=2048, enterprise_id=7)
    assert len(message) <= 2048
    _, structured, body = split_message(message)
    assert body["data"] is None
    assert body["data_omitted_bytes"] == len('{"blob":""}') + 5000
    assert (body["seq"], body["hash"], body["prev_hash"]) == (4, record.hash, record.prev_hash)
    assert 'seq="4"' in structured
    # The same record fits when the limit allows.
    roomy = format_rfc5424(record, max_message_bytes=8192)
    assert split_message(roomy)[2] == record.to_dict()


def test_rfc5424_never_exceeds_the_limit_even_at_the_extremes() -> None:
    record = make_record(
        2**53 - 1,
        event_type="audit.verification_failed",
        severity=Severity.CRITICAL,
        actor=chr(0x1F512) * 256,
        device_fp=chr(0x6771) * 256,
        data={"blob": chr(0x6771) * 20000},
        mac="f" * 64,
    )
    message = format_rfc5424(
        record,
        hostname="h" * 255,
        app_name="a" * 48,
        procid="p" * 128,
        enterprise_id=2**31 - 1,
        max_message_bytes=1024,
    )
    assert len(message) <= 1024
    _, structured, body = split_message(message)
    assert body == {
        "seq": 2**53 - 1,
        "ts": record.ts,
        "event_type": "audit.verification_failed",
        "severity": "critical",
        "hash": record.hash,
        "truncated": True,
    }
    assert "actor=" not in structured and f'hash="{record.hash}"' in structured


def test_rfc5424_cannot_be_used_to_inject_header_fields() -> None:
    hostile = make_record(1, event_type="x y\n<0>1 fake", ts="not a time\n<0>")
    message = format_rfc5424(hostile)
    assert message.startswith(b"<110>1 - - portlock - x_y_<0>1_fake - {")
    assert b"\n" not in message


@pytest.mark.parametrize(
    "options",
    [
        {"hostname": "two words"},
        {"hostname": ""},
        {"hostname": "x" * 256},
        {"hostname": "caf" + chr(0xE9)},
        {"hostname": "line\nbreak"},
        {"app_name": "a" * 49},
        {"app_name": ""},
        {"procid": "p q"},
        {"procid": "p" * 129},
        {"facility": 24},
        {"facility": -1},
        {"facility": "13"},
        {"facility": True},
        {"enterprise_id": 0},
        {"enterprise_id": "32473"},
        {"enterprise_id": 2**31},
        {"max_message_bytes": 1023},
        {"max_message_bytes": 65508},
        {"max_message_bytes": 2048.0},
    ],
)
def test_rfc5424_options_are_validated(options: dict[str, Any]) -> None:
    with pytest.raises(AuditError):
        format_rfc5424(make_record(1), **options)
    with pytest.raises(AuditError):
        SyslogSink(("127.0.0.1", 514), **options)  # refused at construction, not on first use


# --- SyslogSink ----------------------------------------------------------------------


@pytest.fixture
def udp_receiver() -> Iterator[socket.socket]:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))  # loopback only, ephemeral port
    receiver.settimeout(WAIT)
    try:
        yield receiver
    finally:
        receiver.close()


def test_syslog_sink_sends_rfc5424_over_udp(udp_receiver: socket.socket) -> None:
    port = udp_receiver.getsockname()[1]
    sink = SyslogSink(("127.0.0.1", port), hostname="lab-1", enterprise_id=32473)
    records = [
        make_record(1, event_type="service.started", device_fp=None),
        make_record(2, severity=Severity.CRITICAL, actor="Zo" + chr(0xEB), data={"n": 2}),
    ]
    for record in records:
        sink.emit(record)
    received = [udp_receiver.recvfrom(65535)[0] for _ in records]
    sink.close()
    assert received == [sink.format(record) for record in records]
    assert received[0].startswith(
        b"<110>1 2026-01-01T00:00:01.000000Z lab-1 portlock - service.started [portlock@32473 "
    )
    assert received[1].startswith(b"<106>1 ")
    assert split_message(received[1])[2] == records[1].to_dict()


def test_syslog_sink_has_no_default_target_and_opens_nothing_until_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TypeError):
        SyslogSink()  # type: ignore[call-arg]
    created: list[Any] = []
    real_socket = socket.socket

    def tracking_socket(*args: Any, **kwargs: Any) -> socket.socket:
        created.append(args)
        return real_socket(*args, **kwargs)

    monkeypatch.setattr(sinks_module.socket, "socket", tracking_socket)
    sink = SyslogSink(("127.0.0.1", 9))
    sink.format(make_record(1))
    assert created == []  # constructing and formatting never touch the network
    sink.close()
    assert created == []


@pytest.mark.parametrize(
    "target",
    [
        ("localhost", 514),
        ("syslog.example.test", 514),
        ("127.0.0.1", 0),
        ("127.0.0.1", 65536),
        ("127.0.0.1", "514"),
        ("127.0.0.1", True),
        ("127.0.0.1",),
        (514, "127.0.0.1"),
        None,
        514,
        b"/dev/log",
    ],
)
def test_syslog_sink_refuses_invalid_targets(target: Any) -> None:
    with pytest.raises(AuditError):
        SyslogSink(target)


def test_syslog_sink_accepts_ip_literals_only() -> None:
    assert SyslogSink(("::1", 6514)).format(make_record(1)).startswith(b"<110>1 ")
    with pytest.raises(AuditError, match="literal IP address, not a host name"):
        SyslogSink(("localhost", 514))


@pytest.mark.parametrize("timeout", [0, -1, "1", None, True])
def test_syslog_sink_validates_its_timeout(timeout: Any) -> None:
    with pytest.raises(AuditError, match="timeout"):
        SyslogSink(("127.0.0.1", 514), timeout=timeout)


def test_syslog_sink_reports_send_failures_and_reconnects(
    monkeypatch: pytest.MonkeyPatch, udp_receiver: socket.socket
) -> None:
    port = udp_receiver.getsockname()[1]
    real_socket = socket.socket
    failing = {"on": True}
    opened: list[int] = []

    class FlakySocket(real_socket):  # type: ignore[misc, valid-type]
        def sendto(self, *args: Any) -> int:
            if failing["on"]:
                raise OSError(101, "Network is unreachable")
            return super().sendto(*args)

    def factory(*args: Any, **kwargs: Any) -> socket.socket:
        opened.append(1)
        return FlakySocket(*args, **kwargs)

    monkeypatch.setattr(sinks_module.socket, "socket", factory)
    sink = SyslogSink(("127.0.0.1", port))
    with pytest.raises(AuditError, match="cannot send to syslog") as caught:
        sink.emit(make_record(1))
    assert caught.value.code == "sink_error"
    failing["on"] = False
    sink.emit(make_record(2))
    assert udp_receiver.recvfrom(65535)[0] == sink.format(make_record(2))
    assert len(opened) == 2  # the failed socket was dropped and a new one opened
    sink.close()


def test_syslog_sink_refuses_records_after_close(udp_receiver: socket.socket) -> None:
    sink = SyslogSink(("127.0.0.1", udp_receiver.getsockname()[1]))
    sink.emit(make_record(1))
    assert udp_receiver.recvfrom(65535)[0] == sink.format(make_record(1))
    sink.close()
    sink.close()
    with pytest.raises(AuditError, match="closed"):
        sink.emit(make_record(2))


@pytest.mark.windows_only
def test_syslog_sink_refuses_unix_sockets_on_windows() -> None:
    with pytest.raises(AuditError, match="not available on this platform"):
        SyslogSink("/dev/log")


@pytest.mark.linux_only
def test_syslog_sink_sends_to_a_unix_datagram_socket(tmp_path: Path) -> None:
    path = tmp_path / "log.sock"
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        receiver.bind(str(path))
        receiver.settimeout(WAIT)
        sink = SyslogSink(path, hostname="lab-1")
        sink.emit(make_record(1))
        sink.emit(make_record(2))
        assert receiver.recv(65535) == sink.format(make_record(1))
        assert receiver.recv(65535) == sink.format(make_record(2))
        sink.close()
    finally:
        receiver.close()


@pytest.mark.linux_only
def test_syslog_sink_falls_back_to_a_unix_stream_socket(tmp_path: Path) -> None:
    path = tmp_path / "log.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(WAIT)
        sink = SyslogSink(str(path))
        sink.emit(make_record(1))
        sink.emit(make_record(2))
        connection, _ = listener.accept()
        connection.settimeout(WAIT)
        expected = sink.format(make_record(1)) + b"\n" + sink.format(make_record(2)) + b"\n"
        received = b""
        while len(received) < len(expected):
            chunk = connection.recv(65535)
            assert chunk, "the sink closed the stream early"
            received += chunk
        connection.close()
        sink.close()
        assert received == expected
    finally:
        listener.close()


@pytest.mark.linux_only
def test_syslog_sink_reports_a_missing_unix_socket(tmp_path: Path) -> None:
    sink = SyslogSink(tmp_path / "absent.sock")
    with pytest.raises(AuditError, match="cannot send to syslog") as caught:
        sink.emit(make_record(1))
    assert caught.value.code == "sink_error"


# --- CallbackSink --------------------------------------------------------------------


def test_callback_sink_passes_records_through() -> None:
    seen: list[AuditRecord] = []
    sink = CallbackSink(seen.append)
    sink.emit(make_record(1))
    sink.emit(make_record(2))
    assert seen == [make_record(1), make_record(2)]
    with pytest.raises(AuditError, match="callable"):
        CallbackSink("not callable")  # type: ignore[arg-type]

    def explode(_record: AuditRecord) -> None:
        raise ValueError("subscriber bug")

    with pytest.raises(ValueError, match="subscriber bug"):
        CallbackSink(explode).emit(make_record(3))


# --- FanOut --------------------------------------------------------------------------


class Collector:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []
        self.closed = 0

    def emit(self, record: AuditRecord) -> None:
        self.records.append(record)

    def close(self) -> None:
        self.closed += 1


class Broken:
    def emit(self, record: AuditRecord) -> None:
        raise OSError(f"disk full at record {record.seq}")


class Gate:
    """A sink that blocks inside ``emit`` until released, to stand in for a stalled target."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.records: list[AuditRecord] = []

    def emit(self, record: AuditRecord) -> None:
        self.entered.set()
        if not self.release.wait(WAIT):
            raise TimeoutError("the test never released the gate")
        self.records.append(record)


def test_fan_out_delivers_to_every_sink_in_order() -> None:
    first, second = Collector(), Collector()
    fan = FanOut([first, second])
    records = [make_record(seq) for seq in range(1, 6)]
    for record in records:
        fan.emit(record)
    assert first.records == records and second.records == records
    assert not fan.background
    assert fan.stats() == [
        SinkStats("Collector-0", 5, 0, 0, 0, None),
        SinkStats("Collector-1", 5, 0, 0, 0, None),
    ]
    assert fan.failures == 0 and fan.dropped == 0
    assert fan.flush() is True


def test_fan_out_isolates_a_failing_sink() -> None:
    before, after = Collector(), Collector()
    fan = FanOut({"before": before, "broken": Broken(), "after": after})
    for seq in (1, 2, 3):
        fan.emit(make_record(seq))  # must not raise
    assert [record.seq for record in before.records] == [1, 2, 3]
    assert [record.seq for record in after.records] == [1, 2, 3]
    assert fan.stats() == [
        SinkStats("before", 3, 0, 0, 0, None),
        SinkStats("broken", 0, 3, 0, 0, "OSError: disk full at record 3"),
        SinkStats("after", 3, 0, 0, 0, None),
    ]
    assert fan.failures == 3 and fan.dropped == 0


def test_fan_out_survives_any_exception_type() -> None:
    def explode(record: AuditRecord) -> None:
        raise ZeroDivisionError("bug in a subscriber")

    good = Collector()
    fan = FanOut([CallbackSink(explode), good])
    fan.emit(make_record(1))
    assert good.records == [make_record(1)]
    assert fan.stats()[0].last_error == "ZeroDivisionError: bug in a subscriber"


@pytest.mark.parametrize("queue_size", [0, -1, "8", 2.0, True])
def test_fan_out_validates_its_queue_size(queue_size: Any) -> None:
    with pytest.raises(AuditError, match="queue_size"):
        FanOut([Collector()], background=True, queue_size=queue_size)


def test_fan_out_refuses_things_that_are_not_sinks() -> None:
    with pytest.raises(AuditError, match="no emit"):
        FanOut([Collector(), object()])  # type: ignore[list-item]
    with pytest.raises(AuditError, match="'log' has no emit"):
        FanOut({"log": "audit.jsonl"})  # type: ignore[dict-item]


def test_background_fan_out_delivers_everything_in_order() -> None:
    first, second = Collector(), Collector()
    fan = FanOut({"first": first, "second": second}, background=True, queue_size=500)
    records = [make_record(seq) for seq in range(1, 301)]
    for record in records:
        fan.emit(record)
    assert fan.flush(WAIT) is True
    assert first.records == records and second.records == records
    assert fan.stats() == [
        SinkStats("first", 300, 0, 0, 0, None),
        SinkStats("second", 300, 0, 0, 0, None),
    ]
    assert fan.close(WAIT) is True
    assert first.closed == 1 and second.closed == 1


def test_background_fan_out_runs_sinks_off_the_callers_thread() -> None:
    threads: list[str] = []
    fan = FanOut(
        {"cb": CallbackSink(lambda record: threads.append(threading.current_thread().name))},
        background=True,
    )
    fan.emit(make_record(1))
    assert fan.flush(WAIT)
    assert threads == ["portlock-audit-sink-cb"]
    assert fan.close(WAIT)


def test_a_stalled_sink_blocks_nobody_and_its_overflow_is_counted() -> None:
    gate, healthy = Gate(), Collector()
    handled = threading.Semaphore(0)
    total = 20

    def collect(record: AuditRecord) -> None:
        healthy.emit(record)
        handled.release()

    fan = FanOut({"stalled": gate, "healthy": CallbackSink(collect)}, background=True, queue_size=2)
    fan.emit(make_record(1))
    assert gate.entered.wait(WAIT)  # the worker is now stuck inside the stalled sink
    assert handled.acquire(timeout=WAIT)
    for seq in range(2, total + 1):
        fan.emit(make_record(seq))  # returns at once although the other sink is stalled
        # Pace on the healthy sink only, so its own two-slot queue never overflows.
        assert handled.acquire(timeout=WAIT)
    assert [record.seq for record in healthy.records] == list(range(1, total + 1))

    stalled = fan.stats()[0]
    # One record is inside the sink, two are queued, the other seventeen were dropped.
    assert (stalled.delivered, stalled.failed, stalled.queued, stalled.dropped) == (0, 0, 2, 17)
    assert fan.dropped == 17
    assert fan.flush(0.05) is False  # still stalled: flush gives up instead of hanging

    gate.release.set()
    assert fan.flush(WAIT) is True
    assert [record.seq for record in gate.records] == [1, 2, 3]
    assert fan.stats()[0] == SinkStats("stalled", 3, 0, 17, 0, None)
    assert fan.stats()[1] == SinkStats("healthy", 20, 0, 0, 0, None)
    assert fan.close(WAIT) is True


def test_a_background_worker_survives_a_failing_sink() -> None:
    calls: list[int] = []

    def sometimes(record: AuditRecord) -> None:
        calls.append(record.seq)
        if record.seq % 2:
            raise RuntimeError(f"odd record {record.seq}")

    fan = FanOut({"flaky": CallbackSink(sometimes)}, background=True)
    for seq in range(1, 7):
        fan.emit(make_record(seq))
    assert fan.flush(WAIT)
    assert calls == [1, 2, 3, 4, 5, 6]
    assert fan.stats() == [SinkStats("flaky", 3, 3, 0, 0, "RuntimeError: odd record 5")]
    assert fan.failures == 3
    assert fan.close(WAIT)


def test_close_delivers_what_is_queued_then_drops_and_counts_later_records() -> None:
    sink = Collector()
    fan = FanOut({"sink": sink}, background=True, queue_size=100)
    for seq in range(1, 51):
        fan.emit(make_record(seq))
    assert fan.close(WAIT) is True
    assert [record.seq for record in sink.records] == list(range(1, 51))
    assert sink.closed == 1
    fan.emit(make_record(51))
    fan.emit(make_record(52))
    assert fan.close(WAIT) is True  # closing twice is harmless
    assert sink.closed == 1
    assert len(sink.records) == 50
    assert fan.stats() == [SinkStats("sink", 50, 0, 2, 0, None)]


def test_close_gives_up_on_a_stuck_sink_and_says_so() -> None:
    gate = Gate()
    fan = FanOut({"stuck": gate}, background=True, queue_size=4)
    fan.emit(make_record(1))
    assert gate.entered.wait(WAIT)
    assert fan.close(0.05) is False
    gate.release.set()  # let the abandoned worker finish so the test leaves nothing behind
    assert fan.flush(WAIT)


def test_closing_a_synchronous_fan_out_closes_its_sinks(tmp_path: Path) -> None:
    file_sink = JsonlFileSink(tmp_path / "audit.jsonl", 10_000)
    collector = Collector()
    fan = FanOut([file_sink, collector, CallbackSink(lambda record: None)])
    fan.emit(make_record(1))
    assert fan.close() is True
    assert collector.closed == 1
    with pytest.raises(AuditError, match="closed"):
        file_sink.emit(make_record(2))
    fan.emit(make_record(3))
    assert [stats.dropped for stats in fan.stats()] == [1, 1, 1]
    assert len(collector.records) == 1


# --- wired to the audit log ----------------------------------------------------------


def test_the_audit_log_feeds_a_fan_out(tmp_path: Path, db: Database, clock: FakeClock) -> None:
    path = tmp_path / "audit.jsonl"
    seen: list[int] = []
    fan = FanOut(
        {
            "file": JsonlFileSink(path, 1_000_000),
            "broken": Broken(),
            "callback": CallbackSink(lambda record: seen.append(record.seq)),
        }
    )
    key_store, initial_key = AuditKeyStore.create(tmp_path / "audit.key")
    log = AuditLog(db, clock=clock, key_store=key_store, sink=fan)
    log.append("service.started", actor="system")
    clock.advance(1)
    log.append("device.connected", device_fp=FP, data={"password": "never-written"})
    assert fan.close() is True
    assert read_lines(path) == [record.to_dict() for record in log.iterate()]
    assert all(line["mac"] is not None for line in read_lines(path))
    assert b"never-written" not in path.read_bytes()
    assert seen == [1, 2]
    assert log.sink_failures == 0  # the fan-out absorbed the broken sink
    assert fan.failures == 2
    assert log.verify(initial_key=initial_key).macs_checked == 2


def test_background_delivery_from_concurrent_appenders_keeps_sequence_order(
    db: Database, clock: FakeClock
) -> None:
    sink = Collector()
    fan = FanOut({"sink": sink}, background=True, queue_size=1000)
    log = AuditLog(db, clock=clock, sink=fan)
    workers, each = 4, 50
    barrier = threading.Barrier(workers)

    def work() -> None:
        barrier.wait(WAIT)
        for _ in range(each):
            log.append("device.connected")

    threads = [threading.Thread(target=work) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WAIT)
    assert fan.close(WAIT) is True
    assert [record.seq for record in sink.records] == list(range(1, workers * each + 1))
    assert fan.dropped == 0 and fan.failures == 0


# --- ClawNet ---------------------------------------------------------------------------

TOKEN = "tkn-0123456789abcdef"
LABEL = "lab-host"


class StubSigner:
    """Marks an envelope as signed without needing the optional ``cryptography`` package."""

    def sign_event(self, event: Any) -> dict[str, Any]:
        signed = dict(event)
        signed["sig"] = {"alg": "stub", "key": "k", "value": "v"}
        return signed


class RaisingSigner:
    def sign_event(self, event: Any) -> dict[str, Any]:
        raise RuntimeError("the signing key is gone")


class Node:
    """A ClawNet node's local API on 127.0.0.1 with an ephemeral port, as far as the sink
    can tell: it records what it was sent and answers as it is told to."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = 202
        self.gate: threading.Event | None = None
        self.arrived = threading.Event()
        node = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                node.requests.append(
                    {"path": self.path, "headers": dict(self.headers.items()), "body": body}
                )
                node.arrived.set()
                if node.gate is not None:
                    node.gate.wait(WAIT)
                self.send_response(node.status)
                self.send_header("Content-Length", "0")
                if node.status in (301, 302):
                    self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self) -> None:
        if self.gate is not None:
            self.gate.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(WAIT)


@pytest.fixture
def node() -> Iterator[Node]:
    running = Node()
    try:
        yield running
    finally:
        running.stop()


@pytest.fixture
def token_file(tmp_path: Path) -> Path:
    path = tmp_path / "clawnet.token"
    path.write_text(TOKEN + "\n", encoding="ascii")
    return path


def clawnet(node: Node, token_file: Path, **options: Any) -> ClawNetSink:
    arguments: dict[str, Any] = {"host": LABEL, "signer": StubSigner(), "timeout": 5.0}
    arguments.update(options)
    return ClawNetSink(node.base_url, "ops.audit", token_file, **arguments)


def test_clawnet_publishes_each_record_as_a_signed_event(node: Node, token_file: Path) -> None:
    sink = clawnet(node, token_file)
    try:
        record = make_record(7, event_type="device.denied", severity=Severity.WARNING)
        sink.emit(record)
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    assert len(node.requests) == 1
    request = node.requests[0]
    assert request["path"] == "/api/v1/channels/ops.audit/publish"
    headers = {name.lower(): value for name, value in request["headers"].items()}
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["content-type"] == "application/json"
    event = parse_canonical(request["body"])
    assert event["type"] == "device.denied" and event["severity"] == "warning"
    assert event["source"]["host"] == LABEL and event["source"]["product"] == "portlock"
    assert event["chain"] == {"seq": 7, "hash": record.hash}
    assert event["subject"] == {"device_fp": FP}
    assert event["sig"] == {"alg": "stub", "key": "k", "value": "v"}
    stats = sink.stats()
    assert (stats.delivered, stats.failed, stats.dropped, stats.queued) == (1, 0, 0, 0)
    assert stats.last_error is None
    assert sink.url == f"{node.base_url}/api/v1/channels/ops.audit/publish"


def test_clawnet_events_verify_under_the_real_signer(node: Node, token_file: Path) -> None:
    from portlock.audit import signing

    if not signing.has_signing_support():
        pytest.skip("the optional cryptography package is not usable here")
    signer = signing.EventSigner.generate()
    sink = clawnet(node, token_file, signer=signer)
    try:
        sink.emit(make_record(3))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    posted = parse_canonical(node.requests[0]["body"])
    outcome = signing.verify_event(posted, trusted_keys=[signer.public_key])
    assert outcome.ok, outcome.reason


def test_clawnet_does_nothing_until_it_is_used(node: Node, token_file: Path) -> None:
    before = {thread.name for thread in threading.enumerate()}
    sink = clawnet(node, token_file)
    assert {thread.name for thread in threading.enumerate()} == before
    assert node.requests == []
    stats = sink.stats()
    assert (stats.name, stats.delivered, stats.failed, stats.dropped) == ("clawnet", 0, 0, 0)
    sink.close(WAIT)  # closing a sink that never ran is fine
    sink.close(WAIT)


def test_clawnet_reads_the_token_again_for_every_request(node: Node, token_file: Path) -> None:
    sink = clawnet(node, token_file)
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
        token_file.write_text("  rotated-token-2 \r\n", encoding="ascii")
        sink.emit(make_record(2))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    sent = [request["headers"]["Authorization"] for request in node.requests]
    assert sent == [f"Bearer {TOKEN}", "Bearer rotated-token-2"]


@pytest.mark.parametrize("status", [301, 302, 401, 403, 429, 500])
def test_clawnet_counts_a_refusal_and_never_leaks_the_token(
    node: Node, token_file: Path, status: int
) -> None:
    node.status = status
    sink = clawnet(node, token_file)
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.failed) == (0, 1)
    assert stats.last_error == f"AuditError: the ClawNet node refused the event (HTTP {status})"
    assert TOKEN not in (stats.last_error or "")
    assert len(node.requests) == 1  # a refused record is not retried, a redirect not followed


@pytest.mark.parametrize(
    "content",
    [None, b"", b"   \n", b"two words", b"caf\xc3\xa9", b"x" * 5000, b"bad\x00token"],
    ids=["missing", "empty", "blank", "space", "non-ascii", "too-long", "nul"],
)
def test_clawnet_sends_nothing_without_a_usable_token(
    node: Node, token_file: Path, content: bytes | None
) -> None:
    if content is None:
        token_file.unlink()
    else:
        token_file.write_bytes(content)
    sink = clawnet(node, token_file)
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.failed) == (0, 1)
    assert "token file" in (stats.last_error or "")
    assert node.requests == []
    assert str(token_file) not in (stats.last_error or "")


def test_clawnet_survives_a_node_that_is_down(node: Node, token_file: Path) -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listens here now
    sink = ClawNetSink(
        f"http://127.0.0.1:{port}", "ops", token_file, host=LABEL, signer=StubSigner(), timeout=5.0
    )
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.failed) == (0, 1)
    assert (stats.last_error or "").startswith("AuditError: cannot reach the ClawNet node")
    assert TOKEN not in (stats.last_error or "")


def test_clawnet_survives_a_broken_signer(node: Node, token_file: Path) -> None:
    sink = clawnet(node, token_file, signer=RaisingSigner())
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    assert sink.stats().failed == 1 and "RuntimeError" in (sink.stats().last_error or "")
    assert node.requests == []


def test_clawnet_gives_up_on_a_node_that_does_not_answer(node: Node, token_file: Path) -> None:
    node.gate = threading.Event()
    sink = clawnet(node, token_file, timeout=0.3)
    try:
        sink.emit(make_record(1))
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.failed) == (0, 1)
    assert "cannot reach the ClawNet node: TimeoutError" in (stats.last_error or "")


def test_clawnet_emit_never_waits_for_the_node(node: Node, token_file: Path) -> None:
    node.gate = threading.Event()
    sink = clawnet(node, token_file, queue_size=2)
    try:
        sink.emit(make_record(1))
        assert node.arrived.wait(WAIT)  # the worker is now stuck inside the request
        sink.emit(make_record(2))
        sink.emit(make_record(3))
        sink.emit(make_record(4))  # the queue is full: dropped, counted, not waited for
        mid = sink.stats()
        assert (mid.queued, mid.dropped, mid.delivered) == (2, 1, 0)
        node.gate.set()
        assert sink.flush(WAIT)
    finally:
        sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.failed, stats.dropped, stats.queued) == (3, 0, 1, 0)
    sent = [parse_canonical(request["body"])["chain"]["seq"] for request in node.requests]
    assert sent == [1, 2, 3]


def test_clawnet_close_delivers_what_is_queued_and_then_drops(node: Node, token_file: Path) -> None:
    sink = clawnet(node, token_file)
    for seq in (1, 2, 3):
        sink.emit(make_record(seq))
    sink.close(WAIT)
    assert sink.stats().delivered == 3
    sink.emit(make_record(4))  # after close: counted, never sent
    sink.close(WAIT)
    stats = sink.stats()
    assert (stats.delivered, stats.dropped) == (3, 1)
    assert len(node.requests) == 3


def test_clawnet_works_behind_the_audit_log_and_a_severity_filter(
    node: Node, token_file: Path, db: Database, clock: FakeClock
) -> None:
    sink = clawnet(node, token_file)
    fan = FanOut({"clawnet": MinSeveritySink(sink, "warning")}, background=True)
    log = AuditLog(db, clock=clock, sink=fan)
    log.append("service.started", actor="system")  # info: filtered out
    warning = log.append("auth.failure", actor="alice", device_fp=FP)
    assert fan.close(WAIT) is True
    assert sink.stats().delivered == 1
    posted = parse_canonical(node.requests[0]["body"])
    assert posted["chain"] == {"seq": warning.seq, "hash": warning.hash}
    assert log.sink_failures == 0


@pytest.mark.parametrize(
    "arguments",
    [
        {"base_url": "http://192.0.2.10:47600"},
        {"base_url": "http://node.example:47600"},
        {"base_url": "ftp://127.0.0.1:47600"},
        {"base_url": "127.0.0.1:47600"},
        {"base_url": ""},
        {"base_url": None},
        {"base_url": "http://user:pw@127.0.0.1:47600"},
        {"base_url": "http://127.0.0.1:47600?x=1"},
        {"base_url": "http://127.0.0.1:47600#frag"},
        {"base_url": "http://127.0.0.1:99999"},
        {"channel": "Ops"},
        {"channel": "ops/../admin"},
        {"channel": ""},
        {"channel": "a" * 65},
        {"channel": None},
        {"host": ""},
        {"host": None},
        {"signer": object()},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": True},
        {"timeout": "2"},
        {"queue_size": 0},
        {"queue_size": True},
    ],
)
def test_clawnet_refuses_invalid_configuration(token_file: Path, arguments: dict[str, Any]) -> None:
    options: dict[str, Any] = {
        "base_url": "http://127.0.0.1:47600",
        "channel": "ops",
        "host": LABEL,
        "signer": StubSigner(),
    }
    options.update(arguments)
    base_url = options.pop("base_url")
    channel = options.pop("channel")
    with pytest.raises(AuditError):
        ClawNetSink(base_url, channel, token_file, **options)


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("http://127.0.0.1:47600", "http://127.0.0.1:47600/api/v1/channels/ops/publish"),
        ("http://127.0.0.1:47600/", "http://127.0.0.1:47600/api/v1/channels/ops/publish"),
        ("http://localhost", "http://localhost:80/api/v1/channels/ops/publish"),
        ("http://[::1]:8080/node", "http://[::1]:8080/node/api/v1/channels/ops/publish"),
        ("https://node.example", "https://node.example:443/api/v1/channels/ops/publish"),
        ("https://node.example:8443/x/", "https://node.example:8443/x/api/v1/channels/ops/publish"),
    ],
)
def test_clawnet_builds_the_publish_url(token_file: Path, base_url: str, expected: str) -> None:
    sink = ClawNetSink(base_url, "ops", token_file, host=LABEL, signer=StubSigner())
    assert sink.url == expected
    sink.close()
