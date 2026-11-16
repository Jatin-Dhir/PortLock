"""Where audit records go besides the database.

The database is the record of truth; sinks carry copies to places the local
administrator cannot quietly rewrite. Each sink implements :class:`AuditSink`, and
:class:`FanOut` delivers one record to several of them while keeping their failures
apart from auditing itself.

* :class:`JsonlFileSink` appends one canonical JSON object per line to a file that only
  its owner can read, and rotates it by atomic rename.
* :class:`SyslogSink` sends RFC 5424 messages to a UDP address or a Unix socket.
* :class:`CallbackSink` hands each record to a function, which is how another component
  (a ClawNet channel, the console's live view) subscribes.
* :class:`MinSeveritySink` wraps any of them with a severity threshold.

**No sink sends anything anywhere unless it is explicitly configured.** There are no
default targets: no sink is created by importing this module, a :class:`SyslogSink` has
no default address and never resolves a host name, and nothing here reads the machine's
host name; the name in a syslog header is the label the operator supplied, or ``-``.

Sinks receive records that the audit log has already redacted. They add nothing secret.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from portlock.audit.events import AuditError, coerce_severity
from portlock.audit.log import AuditRecord
from portlock.core.canonical import canonicalize
from portlock.core.errors import CanonicalError
from portlock.core.fsutil import ensure_private_dir, restrict_to_owner
from portlock.core.models import Severity

__all__ = [
    "AuditSink",
    "CallbackSink",
    "FanOut",
    "JsonlFileSink",
    "MinSeveritySink",
    "SinkStats",
    "SyslogSink",
    "format_rfc5424",
]


class AuditSink(Protocol):
    """Anything that accepts audit records.

    ``emit`` may raise; :class:`FanOut` and the audit log both contain the failure. A
    sink that holds resources may also offer ``close()``, which :meth:`FanOut.close`
    calls.
    """

    def emit(self, record: AuditRecord) -> None:
        """Deliver one record."""
        ...


def _sink_error(message: str, cause: BaseException) -> AuditError:
    return AuditError(f"{message}: {cause}", code="sink_error")


# --- file ----------------------------------------------------------------------------


class JsonlFileSink:
    """Append records to a JSON Lines file, rotating it when it grows too large.

    Each record is one line of canonical JSON (:meth:`AuditRecord.to_dict` unless a
    ``serializer`` is given) followed by ``\\n``. The file is created readable and
    writable by its owner only. When a record would take the file past ``max_bytes`` the
    file is renamed to ``<name>.1`` (older files shift to ``.2`` and so on) and a new
    file is started; renames are atomic, so a reader sees a complete old file or a
    complete new one. The rotated file numbered ``backups`` is replaced by the next
    rotation: the database, not this file, is the complete record.

    If rotation fails (on Windows, another program holding the file open is enough) the
    record is still appended to the current file and :attr:`rotation_failures` goes up:
    losing a record is worse than an oversized file.

    Thread-safe. The final path component is not followed if it is a symbolic link.

    Args:
        path: the file to append to. A missing parent directory is created private.
        max_bytes: rotate before the file would exceed this size. A single record larger
            than this is written to a file of its own.
        backups: how many rotated files to keep, at least 1.
        serializer: turns a record into the JSON object to write, for example a signed
            security-event envelope. It must return canonical-JSON-safe data.
        sync: flush each record to stable storage before returning (slower).

    Raises:
        AuditError: if an argument is out of range.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        max_bytes: int,
        *,
        backups: int = 5,
        serializer: Callable[[AuditRecord], Mapping[str, Any]] | None = None,
        sync: bool = False,
    ) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise AuditError("max_bytes must be a positive integer")
        if isinstance(backups, bool) or not isinstance(backups, int) or backups < 1:
            raise AuditError("backups must be a positive integer")
        if serializer is not None and not callable(serializer):
            raise AuditError("serializer must be callable")
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._backups = backups
        self._serializer = serializer
        self._sync = bool(sync)
        self._lock = threading.Lock()
        self._fd: int | None = None
        self._size = 0
        self._closed = False
        self._rotations = 0
        self._rotation_failures = 0

    @property
    def path(self) -> Path:
        """The file currently being appended to."""
        return self._path

    @property
    def rotations(self) -> int:
        """How many times the file has been rotated."""
        return self._rotations

    @property
    def rotation_failures(self) -> int:
        """How many rotations failed and were skipped."""
        return self._rotation_failures

    def emit(self, record: AuditRecord) -> None:
        """Append one record.

        Raises:
            AuditError: if the sink is closed, the serializer's output is not
                canonical-JSON-safe, or the file cannot be written
                (``code == "sink_error"``).
        """
        payload = record.to_dict() if self._serializer is None else dict(self._serializer(record))
        try:
            line = (canonicalize(payload) + "\n").encode("utf-8")
        except CanonicalError as exc:
            raise AuditError(f"the serializer's output is not canonical JSON: {exc}") from exc
        with self._lock:
            if self._closed:
                raise AuditError("the file sink is closed", code="sink_error")
            try:
                fd = self._fd if self._fd is not None else self._open()
                if self._size > 0 and self._size + len(line) > self._max_bytes:
                    fd = self._rotate()
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view) :]
                self._size += len(line)
                if self._sync:
                    os.fsync(fd)
            except OSError as exc:
                self._release()
                raise _sink_error(f"cannot write {self._path.name}", exc) from exc

    def close(self) -> None:
        """Close the file. Further ``emit`` calls are refused. Safe to call twice."""
        with self._lock:
            self._closed = True
            self._release()

    def _open(self) -> int:
        if not self._path.parent.exists():
            ensure_private_dir(self._path.parent)
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        fd = os.open(self._path, flags, 0o600)
        self._fd = fd
        # Also tightens a file that already existed with looser permissions.
        restrict_to_owner(self._path)
        self._size = os.fstat(fd).st_size
        return fd

    def _release(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None

    def _rotated(self, index: int) -> Path:
        return self._path.with_name(f"{self._path.name}.{index}")

    def _rotate(self) -> int:
        """Move the current file aside and start a new one; returns the open descriptor."""
        # The file must be closed first: Windows cannot rename an open file.
        self._release()
        try:
            for index in range(self._backups - 1, 0, -1):
                older = self._rotated(index)
                if older.exists():
                    os.replace(older, self._rotated(index + 1))
            os.replace(self._path, self._rotated(1))
            self._rotations += 1
        except OSError:
            self._rotation_failures += 1
        return self._open()


# --- syslog --------------------------------------------------------------------------

# RFC 5424 section 6.2.1: numerical severity codes.
_SYSLOG_SEVERITY: Mapping[Severity, int] = {
    Severity.DEBUG: 7,
    Severity.INFO: 6,
    Severity.NOTICE: 5,
    Severity.WARNING: 4,
    Severity.ERROR: 3,
    Severity.CRITICAL: 2,
}

#: Facility 13, "log audit" (RFC 5424 table 1).
FACILITY_LOG_AUDIT = 13

_NILVALUE = "-"
_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_MIN_MESSAGE_BYTES = 1024
_MAX_UDP_PAYLOAD = 65507
_LINUX_SYSLOG = "/dev/log"
_MACOS_SYSLOG = "/var/run/syslog"
# "192.0.2.10:514" or "[2001:db8::10]:514". Whether the address is a real IP literal is
# checked by the constructor; this only separates the address from the port.
_UDP_TARGET_PATTERN = re.compile(
    r"(?:\[(?P<v6>[0-9A-Fa-f:.]+)\]|(?P<v4>[^\[\]:/\s]+)):(?P<port>[0-9]{1,5})\Z"
)


def _header_field(name: str, value: str | None, limit: int) -> str:
    """Validate one RFC 5424 header field: 1..limit characters of PRINTUSASCII."""
    if value is None:
        return _NILVALUE
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= limit
        or any(not 33 <= ord(char) <= 126 for char in value)
    ):
        raise AuditError(
            f"syslog {name} must be 1 to {limit} printable ASCII characters without spaces"
        )
    return value


def _sd_value(value: object) -> str:
    """Escape an SD-PARAM value (RFC 5424 section 6.3.3) and drop control characters."""
    text = "".join(char for char in str(value) if ord(char) >= 32 and ord(char) != 127)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _ascii_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def format_rfc5424(
    record: AuditRecord,
    *,
    hostname: str | None = None,
    app_name: str = "portlock",
    procid: str | None = None,
    facility: int = FACILITY_LOG_AUDIT,
    enterprise_id: int | None = None,
    max_message_bytes: int = 2048,
) -> bytes:
    """Render one record as an RFC 5424 syslog message.

    Layout: ``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG``.

    * ``PRI`` is ``facility * 8 + severity``, with PortLock severities mapped to syslog
      debug(7) .. critical(2).
    * ``TIMESTAMP`` is the record's own time, UTC with microseconds.
    * ``MSGID`` is the event type.
    * ``STRUCTURED-DATA`` is ``-`` unless ``enterprise_id`` is given, in which case one
      element ``[portlock@<enterprise_id> seq=".." severity=".." hash=".." ...]`` is
      written. RFC 5424 requires a registered private enterprise number in that name;
      PortLock has none of its own, so the operator supplies theirs or goes without.
    * ``MSG`` is the record as a JSON object written in ASCII only (other characters as
      ``\\uXXXX`` escapes), so the message is valid without a byte-order mark and
      survives relays that are not 8-bit clean. It parses to the same value as the
      canonical form, so the receiver can recompute the record hash.

    The message never exceeds ``max_message_bytes``. If the full record does not fit,
    ``data`` is replaced by ``null`` with ``data_omitted_bytes`` saying how much was
    left out; if that still does not fit, only ``seq``, ``ts``, ``event_type``,
    ``severity`` and ``hash`` are sent with ``"truncated": true``. The sequence number
    and hash always arrive, so the receiver can fetch or cross-check the full record.

    Args:
        record: the record to render.
        hostname: the operator's label for this machine; ``-`` if omitted.
        app_name: the APP-NAME field.
        procid: the PROCID field; ``-`` if omitted.
        facility: syslog facility, 0 to 23.
        enterprise_id: the operator's IANA private enterprise number, or ``None``.
        max_message_bytes: the size limit, at least 1024.

    Raises:
        AuditError: if a header field is not valid RFC 5424 or a number is out of range.
    """
    if isinstance(facility, bool) or not isinstance(facility, int) or not 0 <= facility <= 23:
        raise AuditError("syslog facility must be an integer from 0 to 23")
    if (
        isinstance(max_message_bytes, bool)
        or not isinstance(max_message_bytes, int)
        or not _MIN_MESSAGE_BYTES <= max_message_bytes <= _MAX_UDP_PAYLOAD
    ):
        raise AuditError(
            f"max_message_bytes must be from {_MIN_MESSAGE_BYTES} to {_MAX_UDP_PAYLOAD}"
        )
    if enterprise_id is not None and (
        isinstance(enterprise_id, bool)
        or not isinstance(enterprise_id, int)
        or not 1 <= enterprise_id <= 2**31 - 1
    ):
        raise AuditError("enterprise_id must be a positive integer")

    priority = facility * 8 + _SYSLOG_SEVERITY[record.severity]
    # Records from the audit log always have a well-formed time and event type; a record
    # built by hand must still not be able to inject header fields.
    msgid = "".join(char if 33 <= ord(char) <= 126 else "_" for char in record.event_type[:32])
    header = " ".join(
        (
            f"<{priority}>1",
            record.ts if _TIMESTAMP_PATTERN.match(record.ts) else _NILVALUE,
            _header_field("hostname", hostname, 255),
            _header_field("app-name", app_name, 48),
            _header_field("procid", procid, 128),
            msgid or _NILVALUE,
        )
    )

    def structured(*, labels: bool) -> str:
        if enterprise_id is None:
            return _NILVALUE
        params: list[tuple[str, object]] = [
            ("seq", record.seq),
            ("severity", record.severity.value),
            ("hash", record.hash),
        ]
        if labels:
            params.extend(
                (name, value)
                for name, value in (("actor", record.actor), ("device_fp", record.device_fp))
                if value is not None
            )
        body = " ".join(f'{name}="{_sd_value(value)}"' for name, value in params)
        return f"[portlock@{enterprise_id} {body}]"

    full = record.to_dict()
    without_data = dict(full)
    without_data["data"] = None
    without_data["data_omitted_bytes"] = len(canonicalize(full["data"]).encode("utf-8"))
    minimal = {
        "seq": record.seq,
        "ts": record.ts,
        "event_type": record.event_type,
        "severity": record.severity.value,
        "hash": record.hash,
        "truncated": True,
    }
    for payload, labels in ((full, True), (without_data, True), (minimal, False)):
        message = " ".join((header, structured(labels=labels), _ascii_json(payload))).encode(
            "utf-8"
        )
        if len(message) <= max_message_bytes:
            return message
    # Unreachable for records produced by the audit log, whose fields are all bounded;
    # a hand-built record with an enormous event type or timestamp ends up here.
    raise AuditError("the record does not fit in a syslog message even without its data")


class SyslogSink:
    """Send each record as an RFC 5424 message to one explicitly configured target.

    The target is either a UDP address, given as ``(ip_address, port)`` with a literal
    IPv4 or IPv6 address (host names are refused, so emitting never performs a DNS
    lookup), or the path of a Unix-domain syslog socket such as ``/dev/log`` (POSIX
    only). Unix datagram sockets are tried first, then stream sockets, where each
    message is terminated by a newline.

    UDP gives no delivery guarantee: a message can be lost without any error here.
    Treat syslog as a convenience copy; signed checkpoints are the evidence.

    Thread-safe. See :func:`format_rfc5424` for the message layout and its options.

    Args:
        target: ``(ip_address, port)`` or a socket path. There is no default.
        hostname, app_name, procid, facility, enterprise_id, max_message_bytes: passed
            to :func:`format_rfc5424`.
        timeout: seconds a send may block before it counts as failed.

    Raises:
        AuditError: if the target or any option is invalid, or Unix sockets are
            requested on a platform without them.
    """

    def __init__(
        self,
        target: tuple[str, int] | str | os.PathLike[str],
        *,
        hostname: str | None = None,
        app_name: str = "portlock",
        procid: str | None = None,
        facility: int = FACILITY_LOG_AUDIT,
        enterprise_id: int | None = None,
        max_message_bytes: int = 2048,
        timeout: float = 1.0,
    ) -> None:
        self._udp: tuple[str, int] | None = None
        self._unix: str | None = None
        self._family = socket.AF_INET
        if isinstance(target, tuple):
            if len(target) != 2 or not isinstance(target[0], str):
                raise AuditError("a UDP syslog target is (ip_address, port)")
            try:
                address = ipaddress.ip_address(target[0])
            except ValueError as exc:
                raise AuditError(
                    "a UDP syslog target needs a literal IP address, not a host name"
                ) from exc
            port = target[1]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise AuditError("a UDP syslog port must be from 1 to 65535")
            self._udp = (str(address), port)
            self._family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        elif isinstance(target, str | os.PathLike):
            if sys.platform == "win32" or not hasattr(socket, "AF_UNIX"):
                raise AuditError("Unix-domain syslog sockets are not available on this platform")
            self._unix = os.fspath(target)
            if not self._unix:
                raise AuditError("a Unix syslog target is a socket path")
        else:
            raise AuditError("a syslog target is (ip_address, port) or a Unix socket path")
        if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not timeout > 0:
            raise AuditError("timeout must be a positive number of seconds")
        self._timeout = float(timeout)
        self._options: dict[str, Any] = {
            "hostname": hostname,
            "app_name": app_name,
            "procid": procid,
            "facility": facility,
            "enterprise_id": enterprise_id,
            "max_message_bytes": max_message_bytes,
        }
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._stream = False
        self._closed = False
        self._check_options()

    @classmethod
    def from_target(cls, target: str, **options: Any) -> SyslogSink:
        """Build a sink from the target text used in the configuration file.

        Accepted forms:

        * ``"local"``: the machine's own syslog socket (``/dev/log``; ``/var/run/syslog``
          on macOS). Not available on Windows, which has no local syslog daemon.
        * an absolute socket path, e.g. ``/run/systemd/journal/syslog``;
        * ``ip:port`` for UDP, with IPv6 addresses in brackets: ``192.0.2.10:514``,
          ``[2001:db8::10]:514``. Host names are refused (see the class docstring).

        Args:
            target: the configured target.
            **options: the keyword arguments of the constructor.

        Raises:
            AuditError: if the text is none of those forms, or the form is not usable
                on this platform.
        """
        if not isinstance(target, str) or not target:
            raise AuditError("a syslog target must be 'local', a socket path or ip:port")
        if target == "local":
            if sys.platform == "win32":
                raise AuditError(
                    "there is no local syslog socket on Windows; give the syslog target as ip:port"
                )
            return cls(_MACOS_SYSLOG if sys.platform == "darwin" else _LINUX_SYSLOG, **options)
        if target.startswith("/"):
            return cls(target, **options)
        match = _UDP_TARGET_PATTERN.match(target)
        if match is None:
            raise AuditError(
                f"syslog target {target!r} is not 'local', an absolute socket path, "
                "ip:port or [ipv6]:port"
            )
        return cls((match.group("v6") or match.group("v4"), int(match.group("port"))), **options)

    @property
    def target(self) -> tuple[str, int] | str:
        """Where messages go: ``(ip_address, port)`` or a Unix socket path."""
        if self._udp is not None:
            return self._udp
        return self._unix if self._unix is not None else ""

    def _check_options(self) -> None:
        """Format a throwaway record so invalid options fail here, not on the first event."""
        probe = AuditRecord(
            seq=1,
            ts="1970-01-01T00:00:00.000000Z",
            event_type="service.started",
            severity=Severity.INFO,
            actor=None,
            device_fp=None,
            data={},
            prev_hash="0" * 64,
            hash="0" * 64,
        )
        format_rfc5424(probe, **self._options)

    def format(self, record: AuditRecord) -> bytes:
        """The exact bytes :meth:`emit` sends for ``record`` (without stream framing)."""
        return format_rfc5424(record, **self._options)

    def emit(self, record: AuditRecord) -> None:
        """Send one record.

        Raises:
            AuditError: if the sink is closed or the message cannot be sent
                (``code == "sink_error"``).
        """
        message = self.format(record)
        with self._lock:
            if self._closed:
                raise AuditError("the syslog sink is closed", code="sink_error")
            try:
                sock = self._sock if self._sock is not None else self._connect()
                if self._udp is not None:
                    sock.sendto(message, self._udp)
                elif self._stream:
                    sock.sendall(message + b"\n")
                else:
                    sock.send(message)
            except OSError as exc:
                # Drop the socket so the next record reconnects (the daemon may restart).
                self._release()
                raise _sink_error("cannot send to syslog", exc) from exc

    def close(self) -> None:
        """Close the socket. Further ``emit`` calls are refused. Safe to call twice."""
        with self._lock:
            self._closed = True
            self._release()

    def _release(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None

    def _connect(self) -> socket.socket:
        if self._udp is not None:
            sock = socket.socket(self._family, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            self._sock = sock
            return sock
        path = self._unix if self._unix is not None else ""
        family = socket.AF_UNIX
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout)
            sock.connect(path)
            self._stream = False
        except OSError as exc:
            sock.close()
            if exc.errno != errno.EPROTOTYPE:
                raise
            # The daemon listens on a stream socket instead.
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.settimeout(self._timeout)
                sock.connect(path)
            except OSError:
                sock.close()
                raise
            self._stream = True
        self._sock = sock
        return sock


# --- callback ------------------------------------------------------------------------


class CallbackSink:
    """Hand each record to a function.

    The function runs on whichever thread delivers the record (the appender's, or a
    :class:`FanOut` worker), so it should return quickly and must be thread-safe.

    Raises:
        AuditError: if ``callback`` is not callable.
    """

    def __init__(self, callback: Callable[[AuditRecord], None]) -> None:
        if not callable(callback):
            raise AuditError("callback must be callable")
        self._callback = callback

    def emit(self, record: AuditRecord) -> None:
        """Call the function with ``record``; whatever it raises propagates."""
        self._callback(record)


# --- severity filter -----------------------------------------------------------------


class MinSeveritySink:
    """Pass on only records at or above a severity; the rest are silently skipped.

    Wraps any sink, so each configured sink can have its own threshold (a pager wants
    ``warning`` and up, the archive file wants everything). The database always keeps
    every record whatever the sinks are given.

    Args:
        sink: the sink to forward to.
        min_severity: the least severity that is forwarded.

    Raises:
        AuditError: if ``sink`` has no ``emit`` method or the severity is unknown.
    """

    def __init__(self, sink: AuditSink, min_severity: Severity | str) -> None:
        if not callable(getattr(sink, "emit", None)):
            raise AuditError("the wrapped sink has no emit() method")
        self._sink = sink
        self._floor = coerce_severity(min_severity)

    @property
    def min_severity(self) -> Severity:
        """The least severity that is forwarded."""
        return self._floor

    def emit(self, record: AuditRecord) -> None:
        """Forward ``record`` if it is severe enough; whatever the sink raises propagates."""
        if record.severity.rank >= self._floor.rank:
            self._sink.emit(record)

    def close(self) -> None:
        """Close the wrapped sink, if it can be closed."""
        closer = getattr(self._sink, "close", None)
        if callable(closer):
            closer()


# --- fan-out -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SinkStats:
    """Delivery counters for one sink behind a :class:`FanOut`.

    Attributes:
        name: the sink's name.
        delivered: records the sink accepted.
        failed: records the sink raised on. They are not retried.
        dropped: records never offered to the sink because its queue was full, or the
            fan-out was already closed.
        queued: records waiting in the background queue right now.
        last_error: the most recent failure, as ``ExceptionType: message``.
    """

    name: str
    delivered: int
    failed: int
    dropped: int
    queued: int
    last_error: str | None


class _Outlet:
    """One sink with its counters and, in background mode, its queue and worker."""

    _STOP = object()

    def __init__(self, name: str, sink: AuditSink, queue_size: int | None) -> None:
        self.name = name
        self.sink = sink
        self._lock = threading.Lock()
        self._delivered = 0
        self._failed = 0
        self._dropped = 0
        self._last_error: str | None = None
        self._queue: queue.Queue[Any] | None = None
        self._thread: threading.Thread | None = None
        if queue_size is not None:
            self._queue = queue.Queue(maxsize=queue_size)
            self._thread = threading.Thread(
                target=self._run,
                args=(self._queue,),
                name=f"portlock-audit-sink-{name}",
                daemon=True,
            )
            self._thread.start()

    def offer(self, record: AuditRecord) -> None:
        if self._queue is None:
            self._deliver(record)
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self.drop()

    def drop(self) -> None:
        with self._lock:
            self._dropped += 1

    def _deliver(self, record: AuditRecord) -> None:
        try:
            self.sink.emit(record)
        except Exception as exc:
            # Isolation is the whole point: count it, remember it, carry on.
            with self._lock:
                self._failed += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
        else:
            with self._lock:
                self._delivered += 1

    def _run(self, pending: queue.Queue[Any]) -> None:
        while True:
            item = pending.get()
            try:
                if item is self._STOP:
                    return
                self._deliver(item)
            finally:
                pending.task_done()

    def wait_idle(self, deadline: float) -> bool:
        """Wait until everything queued has been delivered or the deadline passes."""
        if self._queue is None:
            return True
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def stop(self, deadline: float) -> bool:
        """Ask the worker to finish what is queued and exit; True if it did in time."""
        if self._queue is None or self._thread is None:
            return True
        try:
            self._queue.put(self._STOP, timeout=max(0.0, deadline - time.monotonic()))
        except queue.Full:
            return False
        self._thread.join(max(0.0, deadline - time.monotonic()))
        return not self._thread.is_alive()

    def stats(self) -> SinkStats:
        queued = self._queue.qsize() if self._queue is not None else 0
        with self._lock:
            return SinkStats(
                self.name, self._delivered, self._failed, self._dropped, queued, self._last_error
            )


class FanOut:
    """Deliver each record to several sinks, keeping their failures to themselves.

    A sink that raises is counted and skipped; the other sinks still get the record and
    the caller never sees the exception. Nothing is retried: the database holds every
    record, and a sink that missed some can be refilled from
    :meth:`portlock.audit.log.AuditLog.export_jsonl`.

    In the default synchronous mode ``emit`` calls each sink in turn on the caller's
    thread, so a slow sink slows the caller. With ``background=True`` every sink gets
    its own bounded queue and worker thread: ``emit`` only enqueues and returns at once,
    a stalled sink delays nobody else, and when a queue is full the record is *dropped
    for that sink* and counted, never blocking. Call :meth:`close` on shutdown, or
    records still queued are lost when the process exits.

    Failures and drops are surfaced through :meth:`stats`, :attr:`failures` and
    :attr:`dropped`; the service reports them in its health output.

    Thread-safe. A ``FanOut`` is itself an :class:`AuditSink`.

    Args:
        sinks: the sinks, as a sequence or as a mapping from a name (used in statistics
            and thread names) to a sink.
        background: deliver on worker threads instead of the caller's thread.
        queue_size: the capacity of each background queue.

    Raises:
        AuditError: if a sink has no ``emit`` method or ``queue_size`` is out of range.
    """

    def __init__(
        self,
        sinks: Sequence[AuditSink] | Mapping[str, AuditSink],
        *,
        background: bool = False,
        queue_size: int = 1024,
    ) -> None:
        if isinstance(queue_size, bool) or not isinstance(queue_size, int) or queue_size < 1:
            raise AuditError("queue_size must be a positive integer")
        if isinstance(sinks, Mapping):
            named = [(str(name), sink) for name, sink in sinks.items()]
        else:
            named = [(f"{type(sink).__name__}-{index}", sink) for index, sink in enumerate(sinks)]
        for name, sink in named:
            if not callable(getattr(sink, "emit", None)):
                raise AuditError(f"sink {name!r} has no emit() method")
        self._background = bool(background)
        self._lock = threading.Lock()
        self._closed = False
        self._outlets = [
            _Outlet(name, sink, queue_size if self._background else None) for name, sink in named
        ]

    @property
    def background(self) -> bool:
        """True if records are delivered on worker threads."""
        return self._background

    def emit(self, record: AuditRecord) -> None:
        """Offer ``record`` to every sink. Never raises and, in background mode, never
        waits for a sink."""
        if self._background:
            # Enqueueing never blocks, and holding the lock keeps a record from slipping
            # into a queue behind the stop marker that close() puts there.
            with self._lock:
                for outlet in self._outlets:
                    if self._closed:
                        outlet.drop()
                    else:
                        outlet.offer(record)
            return
        with self._lock:
            closed = self._closed
        # Synchronous delivery runs outside the lock so appenders do not queue up behind
        # one another's sinks; each sink does its own locking.
        for outlet in self._outlets:
            if closed:
                outlet.drop()
            else:
                outlet.offer(record)

    def stats(self) -> list[SinkStats]:
        """Per-sink delivery counters, in the order the sinks were given."""
        return [outlet.stats() for outlet in self._outlets]

    @property
    def failures(self) -> int:
        """Total records that any sink raised on."""
        return sum(item.failed for item in self.stats())

    @property
    def dropped(self) -> int:
        """Total records dropped because a queue was full or the fan-out was closed."""
        return sum(item.dropped for item in self.stats())

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued record has been delivered or has failed.

        Returns:
            True if all queues emptied within ``timeout`` seconds. Always True in
            synchronous mode.
        """
        deadline = time.monotonic() + timeout
        return all(outlet.wait_idle(deadline) for outlet in self._outlets)

    def close(self, timeout: float = 5.0) -> bool:
        """Stop accepting records, deliver what is queued, stop the workers, close sinks.

        A sink's own ``close()`` is called if it has one and its worker has stopped.

        Returns:
            True if every worker finished within ``timeout`` seconds. A worker stuck
            inside a sink is abandoned (it is a daemon thread) and reported as False.
        """
        with self._lock:
            if self._closed:
                return True
            self._closed = True
        deadline = time.monotonic() + timeout
        clean = True
        for outlet in self._outlets:
            if not outlet.stop(deadline):
                clean = False
                continue
            closer = getattr(outlet.sink, "close", None)
            if callable(closer):
                with contextlib.suppress(Exception):
                    closer()
        return clean
