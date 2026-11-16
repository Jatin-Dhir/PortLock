"""The local HTTP API (``docs/API.md``, ``docs/ARCHITECTURE.md`` 4.1, amended by
``docs/DESIGN.md`` 12 and 14.20).

This module serves the API and the web console's static files on a loopback address. It
holds no device logic: every device operation is one call on
:class:`~portlock.core.service.PortLockService`. It is the only place where sessions are
looked at and roles are applied.

How a request is handled, each step failing fast with the error ``docs/API.md`` names:

1. **Admission.** At most 32 requests are in flight; the 33rd is answered ``503`` by the
   accept thread without a thread being spawned and without its body being read.
2. **Parse.** A small strict HTTP/1.1 parser (request line and headers at most 16 KiB,
   30 seconds to send them, no chunked bodies, no folded or duplicated security headers).
3. **Host** allowlist (DNS rebinding), then **Origin** and ``Sec-Fetch-Site``.
4. **Route** and **method**.
5. **Authentication.** ``Authorization: Bearer <token>`` on every request except the few
   public ones. There are no cookies, so there is nothing for another local web page to
   make the browser send, and therefore no CSRF token (DESIGN 14.20).
6. **Permission**, in :func:`_authorize` and nowhere else: the route's permission before
   the body is read, the permissions that depend on what was asked (the kind of grant,
   the kind of pending change, whose account) after it is parsed.
7. **Body**: size, content type, strict JSON (no floats, no duplicate keys), unknown
   fields refused.
8. The handler. Anything it raises is mapped to the error table in ``docs/API.md``; an
   unexpected exception becomes ``500`` with a request id and is logged, never returned.

Device-supplied text is returned as JSON strings, with ``<``, ``>`` and ``&`` written as
JSON escapes, so even a client that pastes a response into HTML does not turn a device's
name into markup. Static files are loaded into memory when the server starts and served
from there: a request never touches the file system, so there is no path to traverse.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import importlib.resources
import ipaddress
import json
import logging
import math
import queue
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import formatdate
from importlib.resources.abc import Traversable
from typing import Any, Protocol

from portlock import __version__
from portlock.audit.events import AuditError
from portlock.audit.log import AuditLog
from portlock.auth.accounts import (
    AccountStore,
    AuthenticationError,
    AuthFailure,
    Channel,
    InvalidUsernameError,
    LastAdminError,
    Permission,
    Role,
    UnknownUserError,
    User,
    UserExistsError,
    can,
    normalize_username,
)
from portlock.auth.grants import Grant, GrantError
from portlock.auth.passwords import PasswordPolicyError, check_password_policy
from portlock.auth.sessions import Session, SessionStore
from portlock.core.clock import Clock, parse_duration, parse_utc_iso, utc_iso
from portlock.core.config import SCOPES, Config
from portlock.core.errors import AuthError, PolicyError, PortLockError, StoreError
from portlock.core.events import Event, EventBus
from portlock.core.models import UsbDevice
from portlock.core.service import AuditWriter, PortLockService, ServiceError
from portlock.lockdown.manager import (
    CHANGE_DEFAULT_DENY,
    CHANGE_ENFORCE_MODE,
    CHANGE_LOCKDOWN,
    CHANGE_WIDEN_SCOPE,
    ConfirmationError,
    Credential,
    LockdownError,
)

__all__ = [
    "API_VERSION",
    "CHALLENGE_HEADER",
    "CLI_SECRET_HEADER",
    "CONTENT_SECURITY_POLICY",
    "ROUTES",
    "ApiError",
    "ApiServer",
    "Request",
    "Response",
    "Route",
    "RuntimeLike",
    "api_factory",
    "ping_proof",
]

_LOG = logging.getLogger(__name__)

API_VERSION = 1
BASE_PATH = "/api/v1"
#: Sent by the command line with the secret from the private runtime file. A login that
#: carries it is checked on the local channel, which the network lockout never blocks.
CLI_SECRET_HEADER = "X-PortLock-CLI-Secret"  # noqa: S105 - a header name, not a secret
#: Sent by the command line to ``GET /ping`` so that the service can prove it holds the
#: secret in the runtime file before any credential is sent to it.
CHALLENGE_HEADER = "X-PortLock-Challenge"

MAX_IN_FLIGHT = 32
MAX_STREAMS = 8
MAX_HEAD_BYTES = 16 * 1024
MAX_BODY_BYTES = 2 * 1024 * 1024
REQUEST_SECONDS = 30.0
WRITE_SECONDS = 10.0
KEEPALIVE_SECONDS = 15.0
STREAM_QUEUE = 256
LOGIN_BUDGET = 30
LOGIN_WINDOW_SECONDS = 60.0
HOUSEKEEPING_SECONDS = 60.0
_DRAIN_BYTES = 4 * 1024 * 1024
_DRAIN_SECONDS = 2.0
_MAX_STATIC_FILE = 2 * 1024 * 1024
_MAX_STATIC_FILES = 256
_MAX_QUERY_FIELDS = 32
_MAX_JSON_DEPTH = 32

#: ``docs/API.md`` section 2: what the static console files are served with.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_REASONS = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    421: "Misdirected Request",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
_SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Connection", "close"),
    ("Server", "PortLock"),
)
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".woff2": "font/woff2",
}
_TOKEN_CHARS = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_METHOD = re.compile(r"[A-Z]{1,16}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{16,128}\Z")
_FINGERPRINT = re.compile(r"plk1:[a-z2-7]{32}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_EVENT_ID = re.compile(r"([0-9a-f]{16})-([0-9]{1,18})\Z")
_DIGITS = re.compile(r"[0-9]{1,18}\Z")
_CONNECTION_STATES = ("new", "protected", "allowed", "read_only", "pending", "denied")
_ACCESS_VALUES = ("allow", "read_only", "deny", "pending")
_SEVERITIES = ("debug", "info", "notice", "warning", "error", "critical")
#: Headers that must not appear twice: two of them is how requests are smuggled.
_SINGLETON_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "authorization",
        "origin",
        "sec-fetch-site",
        "expect",
        "last-event-id",
        CLI_SECRET_HEADER.lower(),
        CHALLENGE_HEADER.lower(),
    }
)
_PRIVATE_TOPIC_PREFIX = "internal."
_AUDIT_TOPIC = "audit.appended"
_HTML_ESCAPES = str.maketrans(
    {"<": chr(92) + "u003c", ">": chr(92) + "u003e", "&": chr(92) + "u0026"}
)


# --- errors, requests, responses -------------------------------------------------------


class ApiError(PortLockError):
    """An error the API answers with, in the body ``docs/API.md`` section 3 describes.

    Attributes:
        status: the HTTP status.
        code: the stable error code clients branch on.
        details: code-specific data, or ``None``.
        headers: extra response headers (``Retry-After``, ``Allow``, ...).
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message, code=code)
        self.status = status
        self.details = dict(details) if details is not None else None
        self.headers = dict(headers) if headers is not None else {}


def _bad(path: str, message: str) -> ApiError:
    return ApiError(
        400,
        "invalid_request",
        f"{path}: {message}" if path else message,
        details={"problems": [{"path": path, "message": message}]},
    )


def _json_bytes(value: Any) -> bytes:
    """Compact JSON, ASCII only, with the three characters HTML cares about escaped."""
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return text.translate(_HTML_ESCAPES).encode("ascii")


@dataclass(slots=True)
class Response:
    """What a handler returns.

    Attributes:
        status: the HTTP status.
        body: a JSON-serializable value (``None`` for no body).
        headers: extra headers.
        raw: a pre-encoded body (static files), with ``content_type``.
        stream: for the event stream and the audit export: called with the connection
            once the headers are sent; the response ends when it returns.
        cleanup: called once the response is finished, whether or not it was sent (the
            event stream releases its place and its subscription here).
    """

    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes | None = None
    content_type: str = "application/json; charset=utf-8"
    stream: Callable[[_Conn], None] | None = None
    cleanup: Callable[[], None] | None = None


@dataclass(slots=True)
class Request:
    """One parsed request, as handlers see it.

    Attributes:
        method: upper-case method.
        path: the path as sent (not decoded).
        query: parsed query string, every name mapped to its values.
        headers: header names in lower case.
        body: the raw body (empty when there is none).
        params: the route's path parameters, decoded and validated.
        session: the authenticated session, ``None`` on a public route.
        token: the bearer token it was authenticated with.
        request_id: 16 hex characters, also in ``X-Request-Id``.
        json: the parsed body: ``None`` when there is none.
        cli: True if the request carried the correct command-line secret.
    """

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes
    request_id: str
    params: dict[str, str] = field(default_factory=dict)
    session: Session | None = None
    token: str | None = None
    json: dict[str, Any] | None = None
    cli: bool = False

    def fields(self) -> _Fields:
        """The members of the JSON body, to be read and then checked with ``finish()``."""
        return _Fields(self.json or {}, text=False)

    def query_fields(self) -> _Fields:
        """The query string, to be read and then checked with ``finish()``."""
        singles: dict[str, Any] = {}
        for name, values in self.query.items():
            singles[name] = values[0] if len(values) == 1 else values
        return _Fields(singles, text=True)

    def int_param(self, name: str) -> int:
        return int(self.params[name])

    @property
    def user(self) -> str:
        """The authenticated user name (only on routes that need a session)."""
        if self.session is None:
            raise ApiError(401, "unauthenticated", "this request needs a session")
        return self.session.username


class _Fields:
    """Reads and validates the members of a JSON object or a query string.

    Problems are collected, not raised one by one, so a client sees everything wrong with
    a request at once; :meth:`finish` raises ``invalid_request`` with each of them, and
    also reports members nobody asked for (an unknown field is always an error).
    """

    def __init__(self, data: Mapping[str, Any], *, text: bool) -> None:
        self._data = data
        self._text = text
        self._seen: set[str] = set()
        self._problems: list[dict[str, str]] = []

    def problem(self, path: str, message: str) -> None:
        self._problems.append({"path": path, "message": message})

    def _get(self, name: str, required: bool) -> tuple[bool, Any]:
        self._seen.add(name)
        if name in self._data and self._data[name] is not None:
            return True, self._data[name]
        if required:
            self.problem(name, "is required")
        return False, None

    def string(
        self,
        name: str,
        *,
        required: bool = False,
        default: str | None = None,
        max_length: int = 1024,
        min_length: int = 0,
        choices: Sequence[str] | None = None,
        pattern: re.Pattern[str] | None = None,
        printable: bool = False,
    ) -> str | None:
        found, value = self._get(name, required)
        if not found:
            return default
        if not isinstance(value, str):
            self.problem(name, "must be a string")
            return default
        if not min_length <= len(value) <= max_length:
            self.problem(name, f"must be {min_length} to {max_length} characters")
            return default
        if printable and any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            self.problem(name, "must not contain control characters")
            return default
        if choices is not None and value not in choices:
            self.problem(name, "must be one of " + ", ".join(choices))
            return default
        if pattern is not None and not pattern.match(value):
            self.problem(name, "is not in the expected form")
            return default
        return value

    def integer(
        self,
        name: str,
        *,
        required: bool = False,
        default: int | None = None,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int | None:
        found, value = self._get(name, required)
        if not found:
            return default
        if self._text and isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,18}", value):
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            self.problem(name, "must be an integer")
            return default
        if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
            low = "" if minimum is None else str(minimum)
            high = "" if maximum is None else str(maximum)
            self.problem(name, f"must be {low} to {high}".replace("  ", " ").strip())
            return default
        return value

    def boolean(self, name: str, *, default: bool | None = None) -> bool | None:
        found, value = self._get(name, False)
        if not found:
            return default
        if self._text and value in ("true", "false"):
            return value == "true"
        if not isinstance(value, bool):
            self.problem(name, "must be true or false")
            return default
        return value

    def time(self, name: str) -> datetime | None:
        found, value = self._get(name, False)
        if not found:
            return None
        if isinstance(value, str):
            with contextlib.suppress(ValueError):
                return parse_utc_iso(value)
        self.problem(name, "must be a UTC time like 2026-01-01T09:00:00Z")
        return None

    def mapping(self, name: str, *, required: bool = False) -> dict[str, Any] | None:
        found, value = self._get(name, required)
        if not found:
            return None
        if not isinstance(value, dict):
            self.problem(name, "must be an object")
            return None
        return value

    def strings(self, name: str, *, max_items: int = 64, max_length: int = 256) -> list[str] | None:
        """A list of strings; in a query string a repeated name."""
        found, value = self._get(name, False)
        if not found:
            return None
        items = value if isinstance(value, list) else [value] if self._text else None
        if (
            items is None
            or len(items) > max_items
            or not all(isinstance(item, str) and 0 < len(item) <= max_length for item in items)
        ):
            self.problem(name, f"must be a list of at most {max_items} short strings")
            return None
        return list(items)

    def has(self, name: str) -> bool:
        """True if ``name`` was sent (and is not null)."""
        return self._data.get(name) is not None

    def finish(self) -> None:
        """Raise ``invalid_request`` for every problem and every member nobody read."""
        for name in self._data:
            if name not in self._seen:
                self.problem(str(name)[:64], "is not a known field")
        if self._problems:
            first = self._problems[0]
            where = f"{first['path']}: " if first["path"] else ""
            raise ApiError(
                400,
                "invalid_request",
                f"the request is not valid ({where}{first['message']})",
                details={"problems": self._problems},
            )


def _reject_float(literal: str) -> Any:
    raise ValueError("floating-point numbers are not accepted")


def _reject_constant(literal: str) -> Any:
    raise ValueError(f"{literal} is not valid JSON")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member names are not accepted")
        result[key] = value
    return result


def _parse_json_object(body: bytes) -> dict[str, Any]:
    """Strict JSON for a request body. The top level must be an object."""
    try:
        text = body.decode("utf-8")
        value = json.loads(
            text,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_pairs,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ApiError(
            400, "invalid_request", f"the body is not valid JSON: {_short(exc)}"
        ) from None
    if not isinstance(value, dict):
        raise ApiError(400, "invalid_request", "the body must be a JSON object")
    if _depth(value) > _MAX_JSON_DEPTH:
        raise ApiError(400, "invalid_request", "the body is nested too deeply")
    return value


def _depth(value: Any) -> int:
    depth = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, dict | list):
            depth = max(depth, level)
            if level > _MAX_JSON_DEPTH:
                return level
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, level + 1) for child in children)
    return depth


def _short(exc: BaseException) -> str:
    return str(exc).splitlines()[0][:120] if str(exc) else type(exc).__name__


# --- static files ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _StaticFile:
    body: bytes
    content_type: str
    etag: str


def _load_static(root: Traversable | None) -> dict[str, _StaticFile]:
    """Every file of the console into memory, once. Missing console: no files."""
    try:
        base = (
            root if root is not None else importlib.resources.files("portlock.console") / "static"
        )
        if not base.is_dir():
            return {}
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return {}
    found: dict[str, _StaticFile] = {}

    def walk(node: Traversable, prefix: str, depth: int) -> None:
        for child in sorted(node.iterdir(), key=lambda item: item.name):
            name = child.name
            if name.startswith(".") or not name.isascii() or len(found) >= _MAX_STATIC_FILES:
                continue
            if child.is_dir():
                if depth < 4:
                    walk(child, f"{prefix}{name}/", depth + 1)
                continue
            suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            kind = _STATIC_TYPES.get(suffix)
            if kind is None or not child.is_file():
                continue
            data = child.read_bytes()
            if len(data) > _MAX_STATIC_FILE:
                continue
            etag = '"' + hashlib.sha256(data).hexdigest()[:16] + '"'
            found[prefix + name] = _StaticFile(data, kind, etag)

    walk(base, "", 0)
    return found


# --- limits ----------------------------------------------------------------------------


class _Budget:
    """At most ``limit`` credential checks in any ``window`` seconds, across all names.

    Every client of a loopback API has the same address, so there is no per-client limit
    to apply; this bounds what a flood of logins can cost (``docs/API.md`` 5.6).
    """

    def __init__(self, clock: Clock, limit: int = LOGIN_BUDGET, window: float = 60.0) -> None:
        self._clock = clock
        self._limit = limit
        self._window = window
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def charge(self) -> int:
        """0 if the check may go ahead (and is counted), else seconds until it may."""
        now = self._clock.monotonic()
        with self._lock:
            while self._times and now - self._times[0] >= self._window:
                self._times.popleft()
            if len(self._times) >= self._limit:
                return max(1, math.ceil(self._window - (now - self._times[0])))
            self._times.append(now)
            return 0


def ping_proof(secret: str, challenge: str) -> str:
    """What a service holding ``secret`` answers to ``challenge`` in ``GET /ping``.

    The command line sends a random challenge, checks this value and only then sends a
    credential, so a program that merely grabbed the port cannot collect passwords.
    """
    message = b"portlock/ping/1\x00" + challenge.encode("ascii")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


# --- the server ------------------------------------------------------------------------


class RuntimeLike(Protocol):
    """What the API needs of ``service.daemon.Runtime`` (named here so that this module
    does not import the daemon, which imports it)."""

    config: Config
    clock: Clock
    service: PortLockService
    accounts: AccountStore
    sessions: SessionStore
    audit: AuditWriter
    bus: EventBus
    cli_secret: str

    def verify_cli_secret(self, candidate: str) -> bool:
        """True if ``candidate`` is this process's command-line secret."""
        ...


class _Dropped(Exception):
    """The peer went away or was too slow; nothing can be answered."""


class _Conn:
    """The client's socket, written to with a time limit on every write."""

    def __init__(self, sock: socket.socket, write_timeout: float) -> None:
        self._sock = sock
        self._write_timeout = write_timeout

    def send(self, data: bytes) -> None:
        """Send all of ``data``; ``OSError`` (including a timeout) if the client is gone."""
        self._sock.settimeout(self._write_timeout)
        self._sock.sendall(data)


@dataclass(slots=True)
class _Exchange:
    """The state of one request/response on one connection."""

    sock: socket.socket
    request_id: str
    deadline: float
    method: str = ""
    declared: int = 0
    consumed: int = 0


class _Server:
    """The listener: one accept thread, one thread per connection, bounded."""

    def __init__(self, api: ApiServer, family: int) -> None:
        self.api = api
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self._counter = 0
        self._stopped = False

    def bind(self, address: tuple[str, int]) -> None:
        # Refuse address reuse (DESIGN 14.20), so no other process can share the port.
        # Windows: SO_EXCLUSIVEADDRUSE, and no SO_REUSEADDR (which there lets a second
        # process bind a port that is in use). POSIX: SO_REUSEADDR only lets a restart
        # bind a port that has connections in TIME_WAIT; it never allows a second listener.
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        self.socket.listen(64)
        self.socket.settimeout(0.2)

    def serve_forever(self) -> None:
        while not self._stopped:
            try:
                client, _address = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stopped:
                    return
                continue
            self._admit(client)

    def _admit(self, client: socket.socket) -> None:
        if not self.api._acquire_slot():
            self.api._reject_busy(client)
            return
        self._counter += 1
        thread = threading.Thread(
            target=self._run,
            args=(client,),
            name=f"portlock-api-{self._counter}",
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError:
            self.api._release_slot()
            self.api._reject_busy(client)

    def _run(self, client: socket.socket) -> None:
        try:
            self.api._serve(client)
        except Exception as exc:
            _LOG.error("an API connection failed unexpectedly", exc_info=exc)
        finally:
            with contextlib.suppress(OSError):
                client.shutdown(socket.SHUT_WR)
            with contextlib.suppress(OSError):
                client.close()
            self.api._release_slot()

    def close(self) -> None:
        self._stopped = True
        with contextlib.suppress(OSError):
            self.socket.close()


class ApiServer:
    """The local HTTP API and the static console, on a loopback address.

    Matches ``service.daemon.ApiServerLike``: ``start()`` binds and starts the accept
    thread (``OSError`` if the port is taken), ``stop()`` ends it, and ``host`` and
    ``port`` are the bound address once started (port ``0`` resolves then).

    Args:
        runtime: the service and its stores (``service.daemon.Runtime``).
        static_root: where the console's files are (default: ``static/`` in this package).
        host / port: override ``config.api``.
        request_timeout: seconds to receive a whole request (30).
        write_timeout: seconds one write may block, on a stream too (10).
        keepalive_seconds: silence after which a stream sends a comment (15).
        max_in_flight / max_streams: concurrent requests (32) and event streams (8).
        stream_queue: events a stream may lag behind before it is closed (256).
    """

    def __init__(
        self,
        runtime: RuntimeLike,
        *,
        static_root: Traversable | None = None,
        host: str | None = None,
        port: int | None = None,
        request_timeout: float = REQUEST_SECONDS,
        write_timeout: float = WRITE_SECONDS,
        keepalive_seconds: float = KEEPALIVE_SECONDS,
        max_in_flight: int = MAX_IN_FLIGHT,
        max_streams: int = MAX_STREAMS,
        stream_queue: int = STREAM_QUEUE,
    ) -> None:
        self.runtime = runtime
        self.host = host if host is not None else runtime.config.api.host
        self.port = port if port is not None else runtime.config.api.port
        try:
            self._family = (
                socket.AF_INET6 if ipaddress.ip_address(self.host).version == 6 else socket.AF_INET
            )
        except ValueError as exc:
            raise ValueError(f"the API host must be an IP address, not {self.host!r}") from exc
        if not ipaddress.ip_address(self.host).is_loopback:
            raise ValueError("the API listens on a loopback address only")
        self._static_root = static_root
        self.request_timeout = request_timeout
        self.write_timeout = write_timeout
        self.keepalive_seconds = keepalive_seconds
        self.max_in_flight = max_in_flight
        self.max_streams = max_streams
        self.stream_queue = stream_queue
        self._static: dict[str, _StaticFile] = {}
        self._allowed_hosts: frozenset[str] = frozenset()
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._in_flight = 0
        self._streams = 0
        self.stopping = threading.Event()
        self._budget = _Budget(runtime.clock, LOGIN_BUDGET, LOGIN_WINDOW_SECONDS)
        self._last_purge = 0.0
        self.endpoints = _Endpoints(self)

    @property
    def address(self) -> tuple[str, int]:
        """The bound host and port."""
        return self.host, self.port

    def start(self) -> None:
        """Bind and start accepting.

        Raises:
            OSError: if the address cannot be bound (in use, or not allowed).
        """
        if self._server is not None:
            raise RuntimeError("the API server is already started")
        self._static = _load_static(self._static_root)
        server = _Server(self, self._family)
        try:
            server.bind((self.host, self.port))
        except OSError:
            server.close()
            raise
        self.port = int(server.socket.getsockname()[1])
        self._allowed_hosts = self._host_values()
        self._server = server
        self.stopping.clear()
        self._thread = threading.Thread(
            target=server.serve_forever, name="portlock-api", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop accepting, tell every event stream to end, and wait for the accept thread."""
        server, self._server = self._server, None
        if server is None:
            return
        self.stopping.set()
        server.close()
        if self._thread is not None:
            self._thread.join(timeout)
        deadline = time.monotonic() + timeout
        while self._in_flight and time.monotonic() < deadline:
            time.sleep(0.01)

    # --- limits ----------------------------------------------------------------------

    def _acquire_slot(self) -> bool:
        with self._lock:
            if self._in_flight >= self.max_in_flight:
                return False
            self._in_flight += 1
            return True

    def _release_slot(self) -> None:
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)

    def acquire_stream(self) -> bool:
        """Take one of the event-stream places; False if all are in use."""
        with self._lock:
            if self._streams >= self.max_streams:
                return False
            self._streams += 1
            return True

    def release_stream(self) -> None:
        with self._lock:
            self._streams = max(0, self._streams - 1)

    def charge_login(self) -> int:
        """Count one credential check against the global budget; seconds to wait if over."""
        return self._budget.charge()

    def housekeeping(self) -> None:
        """Purge expired sessions, at most once a minute."""
        now = self.runtime.clock.monotonic()
        with self._lock:
            if self._last_purge and now - self._last_purge < HOUSEKEEPING_SECONDS:
                return
            self._last_purge = now
        with contextlib.suppress(PortLockError, OSError):
            self.runtime.sessions.purge_expired()

    def _reject_busy(self, client: socket.socket) -> None:
        """Answer 503 from the accept thread: no body is read and no thread is spawned."""
        error = ApiError(503, "server_busy", "too many requests are in flight; retry shortly")
        try:
            client.settimeout(0.5)
            client.sendall(self._render(self._error_response(error, secrets.token_hex(8)), None))
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                client.close()

    def _host_values(self) -> frozenset[str]:
        port = self.port
        names = {f"localhost:{port}"}
        if ":" in self.host:
            names.add(f"[{self.host}]:{port}")
            names.add(f"[{ipaddress.ip_address(self.host)}]:{port}")
        else:
            names.add(f"{self.host}:{port}")
        if port == 80:
            names |= {"localhost", self.host if ":" not in self.host else f"[{self.host}]"}
        return frozenset(name.lower() for name in names)

    # --- one connection --------------------------------------------------------------

    def _serve(self, sock: socket.socket) -> None:
        exchange = _Exchange(sock, secrets.token_hex(8), time.monotonic() + self.request_timeout)
        conn = _Conn(sock, self.write_timeout)
        try:
            response = self._process(exchange)
        except ApiError as exc:
            response = self._error_response(exc, exchange.request_id)
        except _Dropped:
            return
        except Exception as exc:
            _LOG.error("request %s failed unexpectedly", exchange.request_id, exc_info=exc)
            response = self._error_response(
                ApiError(500, "internal_error", "the request could not be handled"),
                exchange.request_id,
            )
        try:
            head_only = exchange.method == "HEAD"
            response.headers.setdefault("X-Request-Id", exchange.request_id)
            conn.send(self._render(response, response.stream, head_only=head_only))
            if response.stream is not None and not head_only:
                response.stream(conn)
        except OSError:
            return
        finally:
            if response.cleanup is not None:
                with contextlib.suppress(Exception):
                    response.cleanup()
        self._drain(exchange)

    def _drain(self, exchange: _Exchange) -> None:
        """Read what the client is still sending, so that closing does not reset the
        connection before it has read the answer (it would otherwise lose the error)."""
        remaining = exchange.declared - exchange.consumed
        if remaining <= 0:
            return
        sock = exchange.sock
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        end = time.monotonic() + _DRAIN_SECONDS
        budget = min(remaining, _DRAIN_BYTES)
        while budget > 0 and time.monotonic() < end:
            try:
                sock.settimeout(max(0.05, end - time.monotonic()))
                chunk = sock.recv(min(65536, budget))
            except OSError:
                return
            if not chunk:
                return
            budget -= len(chunk)

    def _recv(self, exchange: _Exchange, limit: int) -> bytes:
        remaining = exchange.deadline - time.monotonic()
        if remaining <= 0:
            raise _Dropped
        try:
            exchange.sock.settimeout(remaining)
            chunk = exchange.sock.recv(limit)
        except OSError:
            raise _Dropped from None
        if not chunk:
            raise _Dropped
        return chunk

    def _read_head(self, exchange: _Exchange) -> tuple[bytes, bytes]:
        buffer = bytearray()
        while True:
            end = buffer.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > MAX_HEAD_BYTES:
                    break
                return bytes(buffer[:end]), bytes(buffer[end + 4 :])
            if len(buffer) > MAX_HEAD_BYTES:
                break
            buffer += self._recv(exchange, 4096)
        raise ApiError(431, "invalid_request", "the request line and headers are too large")

    def _process(self, exchange: _Exchange) -> Response:
        head, prefix = self._read_head(exchange)
        method, target, headers = _parse_head(head)
        exchange.method = method
        self._check_host(headers)
        self._check_origin(headers)
        path, _, raw_query = target.partition("?")
        query = _parse_query(raw_query)
        length = _content_length(headers)
        exchange.declared = length
        request = Request(
            method=method,
            path=path,
            query=query,
            headers=headers,
            body=b"",
            request_id=exchange.request_id,
        )
        static = self._static_response(request)
        if static is not None:
            return static
        route, params = self._route(request)
        request.params = params
        unknown = sorted(set(query) - route.query)
        if unknown:
            raise ApiError(
                400,
                "invalid_request",
                f"the request is not valid ({unknown[0]}: is not a known field)",
                details={
                    "problems": [
                        {"path": name[:64], "message": "is not a known field"} for name in unknown
                    ]
                },
            )
        self._authenticate(request, route)
        _authorize(self.endpoints, route, request, stage="route")
        if length and method in ("GET", "HEAD", "DELETE"):
            raise ApiError(400, "invalid_request", "this request takes no body")
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "body_too_large", "the body is larger than 2 MiB")
        if length:
            _check_content_type(headers)
            if headers.get("expect", "").lower() == "100-continue":
                with contextlib.suppress(OSError):
                    exchange.sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            elif "expect" in headers:
                raise ApiError(400, "invalid_request", "the Expect header is not supported")
            body = bytearray(prefix[:length])
            exchange.consumed = len(prefix)
            while len(body) < length:
                chunk = self._recv(exchange, min(65536, length - len(body)))
                body += chunk
                exchange.consumed += len(chunk)
            request.body = bytes(body)
            request.json = _parse_json_object(request.body)
        _authorize(self.endpoints, route, request, stage="request")
        try:
            return route.handler(self.endpoints, request)
        except Exception as exc:
            mapped = self.endpoints.map_error(exc)
            if mapped is None:
                raise
            raise mapped from None

    def _check_host(self, headers: Mapping[str, str]) -> None:
        host = headers.get("host")
        if host is None or host.lower() not in self._allowed_hosts:
            raise ApiError(421, "host_not_allowed", "this host name is not served here")

    def _check_origin(self, headers: Mapping[str, str]) -> None:
        origin = headers.get("origin")
        if origin is not None and origin.lower() not in {
            f"http://{name}" for name in self._allowed_hosts
        }:
            raise ApiError(403, "origin_not_allowed", "this origin is not allowed")
        site = headers.get("sec-fetch-site")
        if site is not None and site.lower() not in ("same-origin", "none"):
            raise ApiError(403, "origin_not_allowed", "this origin is not allowed")

    def _static_response(self, request: Request) -> Response | None:
        path = request.path
        if path == BASE_PATH or path.startswith(BASE_PATH + "/"):
            return None
        if path == "/":
            name = "index.html"
        elif path.startswith("/static/"):
            name = path[len("/static/") :]
        else:
            name = path[1:]
        item = self._static.get(name)
        if item is None:
            raise ApiError(404, "not_found", "no such file or route")
        if request.method not in ("GET", "HEAD"):
            raise ApiError(
                405,
                "method_not_allowed",
                "static files are read-only",
                headers={"Allow": "GET, HEAD"},
            )
        headers = {
            "ETag": item.etag,
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Cache-Control": "no-cache",
        }
        if request.headers.get("if-none-match") == item.etag:
            return Response(304, headers=headers)
        return Response(200, headers=headers, raw=item.body, content_type=item.content_type)

    def _route(self, request: Request) -> tuple[Route, dict[str, str]]:
        path = request.path
        if request.method in ("OPTIONS", "TRACE", "CONNECT"):
            # No CORS preflight is ever answered: no other origin may read a response.
            raise ApiError(
                405,
                "method_not_allowed",
                f"{request.method} is not supported",
                headers={"Allow": "GET, POST, PUT, PATCH, DELETE"},
            )
        if not path.startswith(BASE_PATH + "/"):
            raise ApiError(404, "not_found", "no such route")
        segments = path[len(BASE_PATH) + 1 :].split("/")
        allowed: list[str] = []
        for route in ROUTES:
            params = route.match(segments)
            if params is None:
                continue
            if route.method == request.method:
                return route, params
            allowed.append(route.method)
        if allowed:
            raise ApiError(
                405,
                "method_not_allowed",
                f"{request.method} is not allowed here",
                headers={"Allow": ", ".join(sorted(set(allowed)))},
            )
        raise ApiError(404, "not_found", "no such route")

    def _authenticate(self, request: Request, route: Route) -> None:
        header = request.headers.get("authorization")
        if route.public:
            return
        token = None
        if header is not None:
            scheme, _, value = header.partition(" ")
            if scheme.lower() == "bearer" and value.strip() and " " not in value.strip():
                token = value.strip()
        session = None
        if token is not None:
            try:
                session = self.runtime.sessions.validate(token)
            except StoreError as exc:
                raise ApiError(
                    503, "store_unavailable", "the session store is unavailable"
                ) from exc
        if session is None:
            raise ApiError(
                401,
                "unauthenticated",
                "a valid bearer token is required",
                headers={"WWW-Authenticate": 'Bearer realm="portlock"'},
            )
        request.session = session
        request.token = token

    # --- responses -------------------------------------------------------------------

    def _error_response(self, error: ApiError, request_id: str) -> Response:
        headers = dict(error.headers)
        if error.status == 429 and "Retry-After" not in headers:
            retry = (error.details or {}).get("retry_after_seconds")
            if isinstance(retry, int):
                headers["Retry-After"] = str(max(1, retry))
        body = {
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
                "request_id": request_id,
            }
        }
        response = Response(error.status, body, headers)
        response.headers["X-Request-Id"] = request_id
        return response

    def _render(
        self,
        response: Response,
        stream: Callable[[_Conn], None] | None,
        *,
        head_only: bool = False,
    ) -> bytes:
        """The status line, headers and (unless streaming) body of a response."""
        status = response.status
        body = b""
        if response.raw is not None:
            body = response.raw
        elif response.body is not None:
            body = _json_bytes(response.body)
        lines = [f"HTTP/1.1 {status} {_REASONS.get(status, 'Status')}"]
        headers: dict[str, str] = dict(_SECURITY_HEADERS)
        headers["Date"] = formatdate(usegmt=True)
        if status not in (204, 304):
            headers["Content-Type"] = response.content_type
            if stream is None:
                headers["Content-Length"] = str(len(body))
        headers.update(response.headers)
        lines.extend(f"{name}: {value}" for name, value in headers.items())
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        return head if (head_only or stream is not None or status in (204, 304)) else head + body


def _parse_query(raw: str) -> dict[str, list[str]]:
    if not raw:
        return {}
    try:
        pairs = urllib.parse.parse_qsl(
            raw,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_QUERY_FIELDS,
        )
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "invalid_request", "the query string is not valid") from None
    result: dict[str, list[str]] = {}
    for name, value in pairs:
        result.setdefault(name, []).append(value)
    return result


def _content_length(headers: Mapping[str, str]) -> int:
    if "transfer-encoding" in headers:
        raise ApiError(
            400, "invalid_request", "chunked and other transfer encodings are not supported"
        )
    raw = headers.get("content-length")
    if raw is None:
        return 0
    if not re.fullmatch(r"[0-9]{1,12}", raw):
        raise ApiError(400, "invalid_request", "Content-Length is not valid")
    return int(raw)


def _check_content_type(headers: Mapping[str, str]) -> None:
    value = headers.get("content-type", "")
    media, _, parameters = value.partition(";")
    if media.strip().lower() != "application/json":
        raise ApiError(415, "unsupported_media_type", "a body must be sent as application/json")
    extra = parameters.strip().lower().replace(" ", "")
    if extra and extra not in ("charset=utf-8", 'charset="utf-8"'):
        raise ApiError(415, "unsupported_media_type", "the body must be UTF-8 JSON")


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    """The request line and headers, strictly. Raises ``ApiError(400)`` for anything odd."""
    try:
        text = head.decode("latin-1")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 decodes every byte
        raise ApiError(400, "invalid_request", "the request is not valid") from None
    lines = text.split("\r\n")
    if any(("\n" in line or "\r" in line or "\x00" in line) for line in lines):
        raise ApiError(400, "invalid_request", "the request contains control characters")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise ApiError(400, "invalid_request", "the request line is not valid")
    method, target = parts[0], parts[1]
    if not _METHOD.match(method):
        raise ApiError(400, "invalid_request", "the request method is not valid")
    if not target.startswith("/") or not target.isascii() or "#" in target:
        raise ApiError(400, "invalid_request", "the request target is not valid")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not _TOKEN_CHARS.match(name):
            raise ApiError(400, "invalid_request", "a header line is not valid")
        key = name.lower()
        if key in headers and key in _SINGLETON_HEADERS:
            raise ApiError(400, "invalid_request", f"the {name} header was sent twice")
        headers[key] = value.strip(" \t")
    return method, target, headers


# --- routes ----------------------------------------------------------------------------

_PARAM_CHECKS: dict[str, Callable[[str], str | None]] = {}


def _check_digits(value: str) -> str | None:
    return value if _DIGITS.match(value) else None


def _check_fingerprint(value: str) -> str | None:
    lowered = value.lower()
    return lowered if _FINGERPRINT.match(lowered) else None


def _check_hex32(value: str) -> str | None:
    return value if _HEX32.match(value) else None


def _check_hex16(value: str) -> str | None:
    return value if _HEX16.match(value) else None


def _check_username(value: str) -> str | None:
    try:
        return normalize_username(value)
    except InvalidUsernameError:
        return None


_PARAM_CHECKS.update(
    {
        "connection_id": _check_digits,
        "scan_id": _check_digits,
        "fingerprint": _check_fingerprint,
        "grant_id": _check_hex32,
        "change_id": _check_hex16,
        "username": _check_username,
    }
)

Handler = Callable[["_Endpoints", Request], Response]
Refine = Callable[["_Endpoints", Request], Iterable[Permission]]


@dataclass(frozen=True, slots=True)
class Route:
    """One endpoint of ``docs/API.md``.

    Attributes:
        method / pattern: ``GET`` and ``/devices/{fingerprint}``; ``{name}`` segments are
            validated by name (an id is digits, a fingerprint is ``plk1:`` and 32 base32
            characters, a grant id is 32 hex characters, a user name is normalized).
        permission: what the role must have, checked before the body is read. ``None``
            on a public route (``public=True``) and on a route any session may call.
        handler: the endpoint, a method of :class:`_Endpoints`.
        public: no session needed.
        query: the query-string members the route accepts; any other is an error.
        refine: permissions that depend on what was asked, checked after the body is
            parsed, by the same function as ``permission`` (the kind of grant, the kind
            of pending change, whose account).
    """

    method: str
    pattern: str
    permission: Permission | None
    handler: Handler
    public: bool = False
    query: frozenset[str] = frozenset()
    refine: Refine | None = None
    segments: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        object.__setattr__(self, "segments", tuple(self.pattern.strip("/").split("/")))

    def match(self, segments: Sequence[str]) -> dict[str, str] | None:
        """The path parameters if ``segments`` is this route's path, else ``None``."""
        if len(segments) != len(self.segments):
            return None
        params: dict[str, str] = {}
        for expected, actual in zip(self.segments, segments, strict=True):
            try:
                decoded = urllib.parse.unquote(actual, errors="strict")
            except UnicodeDecodeError:
                return None
            if expected.startswith("{"):
                name = expected[1:-1]
                checked = _PARAM_CHECKS[name](decoded)
                if checked is None:
                    return None
                params[name] = checked
            elif decoded != expected or "%" in actual:
                return None
        return params


def _require(session: Session, permission: Permission) -> None:
    """The one place a role is compared with a permission."""
    if not can(session.role, permission):
        raise ApiError(
            403,
            "forbidden",
            "your role does not allow this",
            details={"permission": permission.value},
        )


def _authorize(api: _Endpoints, route: Route, request: Request, *, stage: str) -> None:
    """Enforce the role a route needs. ``route`` stage runs before the body is read,
    ``request`` stage after it is parsed, for what depends on its content."""
    if route.public or request.session is None:
        return
    if stage == "route":
        if route.permission is not None:
            _require(request.session, route.permission)
    elif route.refine is not None:
        for permission in route.refine(api, request):
            _require(request.session, permission)


_CHANGE_PERMISSION = {
    CHANGE_LOCKDOWN: Permission.ENGAGE_LOCKDOWN,
    CHANGE_ENFORCE_MODE: Permission.CHANGE_MODE,
    CHANGE_WIDEN_SCOPE: Permission.CHANGE_MODE,
    CHANGE_DEFAULT_DENY: Permission.CHANGE_MODE,
}
_SERVICE_STATUS = {
    "not_found": 404,
    "invalid_request": 400,
    "not_connected": 409,
    "not_pending": 409,
    "unknown_device": 409,
    "low_confidence": 409,
    "policy_invalid": 400,
    "policy_conflict": 409,
    "killswitch_active": 409,
    "enforcement_unavailable": 409,
    "not_private": 409,
    "no_mounted_volume": 409,
    "scan_unavailable": 409,
    "scan_queue_full": 409,
    "store_unavailable": 503,
}
_LOCKDOWN_STATUS = {
    "lockdown_active": 409,
    "lockdown_not_active": 409,
    "invalid_duration": 409,
    "invalid_reason": 400,
    "killswitch_active": 409,
    "not_lifting": 409,
}
_CONFIRMATION_STATUS = {
    "no_pending_change": 404,
    "not_ready": 409,
    "wrong_channel": 409,
    "confirmation_expired": 409,
    "change_pending": 409,
    "timer_unavailable": 409,
}
_GRANT_ERRORS = {
    "grant_invalid": (409, "grant_invalid"),
    "grant_low_confidence": (409, "low_confidence"),
    "grant_not_found": (404, "not_found"),
    "grant_not_active": (404, "not_found"),
    "grant_bound_elsewhere": (409, "grant_invalid"),
}
_DEVICE_FIELDS = frozenset(
    {
        "instance_id",
        "vendor_id",
        "product_id",
        "serial",
        "manufacturer",
        "product",
        "bcd_device",
        "device_class",
        "interfaces",
        "bus_path",
        "removable",
        "volumes",
    }
)


class _SocketWriter:
    """A binary file object that writes to the client (the audit export)."""

    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    def write(self, data: bytes) -> int:
        self._conn.send(data)
        return len(data)


class _Endpoints:
    """Every endpoint of ``docs/API.md``: validation, one service call, the answer."""

    def __init__(self, server: ApiServer) -> None:
        self.server = server
        self.rt = server.runtime
        self.svc = server.runtime.service
        self.accounts = server.runtime.accounts
        self.sessions = server.runtime.sessions
        self.config = server.runtime.config
        self.clock = server.runtime.clock

    # --- errors ----------------------------------------------------------------------

    def map_error(self, exc: BaseException) -> ApiError | None:
        """The API error for an exception a handler let through; ``None`` for a bug."""
        if isinstance(exc, ApiError):
            return exc
        if isinstance(exc, ServiceError):
            status = _SERVICE_STATUS.get(exc.code)
            if status is None:
                return None
            details: dict[str, Any] | None = None
            if exc.code == "policy_invalid":
                details = {"problems": list(exc.problems)}
            elif exc.code == "policy_conflict":
                details = {"hash": self.svc.get_policy().hash}
            return ApiError(status, exc.code, exc.message, details=details)
        if isinstance(exc, LockdownError):
            status = _LOCKDOWN_STATUS.get(exc.code)
            if status is None:
                return None
            code = "invalid_request" if exc.code == "invalid_reason" else exc.code
            details = (
                {"max_minutes": self.config.lockdown.max_minutes}
                if exc.code == "invalid_duration"
                else None
            )
            return ApiError(status, code, exc.message, details=details)
        if isinstance(exc, ConfirmationError):
            status = _CONFIRMATION_STATUS.get(exc.code)
            return None if status is None else ApiError(status, exc.code, exc.message)
        if isinstance(exc, GrantError):
            mapped = _GRANT_ERRORS.get(exc.code)
            return None if mapped is None else ApiError(mapped[0], mapped[1], exc.message)
        if isinstance(exc, AuthenticationError):
            return self._auth_failure(exc.reason, exc.retry_after_seconds, reauth=True)
        if isinstance(exc, PasswordPolicyError):
            return ApiError(
                400,
                "password_policy",
                "the password is not acceptable",
                details={"problems": list(exc.problems)},
            )
        if isinstance(exc, UserExistsError):
            return ApiError(409, "user_exists", exc.message)
        if isinstance(exc, LastAdminError):
            return ApiError(409, "last_admin", exc.message)
        if isinstance(exc, UnknownUserError):
            return ApiError(404, "not_found", "no such user")
        if isinstance(exc, InvalidUsernameError):
            return _bad("username", exc.message)
        if isinstance(exc, AuthError):
            if exc.code == "reauthentication_failed":
                return ApiError(401, "reauthentication_failed", exc.message)
            if exc.code in ("invalid_role", "first_user_must_be_admin"):
                return _bad("role", exc.message)
            return None
        if isinstance(exc, PolicyError):
            return ApiError(
                400,
                "policy_invalid",
                "the policy is invalid",
                details={"problems": list(exc.problems)},
            )
        if isinstance(exc, AuditError):
            if exc.code in ("audit_corrupt", "audit_key_ahead", "audit_key_behind"):
                return ApiError(503, "store_unavailable", "the audit log cannot be read")
            return ApiError(400, "invalid_request", exc.message)
        if isinstance(exc, StoreError):
            return ApiError(503, "store_unavailable", "the database cannot be read or written")
        return None

    def _auth_failure(self, reason: AuthFailure, retry: int, *, reauth: bool = False) -> ApiError:
        details = {"retry_after_seconds": max(1, retry)} if retry else None
        if reason is AuthFailure.LOCKED_OUT:
            return ApiError(
                429,
                "locked_out",
                "too many failed attempts; try again later",
                details=details or {"retry_after_seconds": 1},
            )
        if reason is AuthFailure.BUSY:
            return ApiError(
                429,
                "busy",
                "too many sign-ins are being checked; retry in a moment",
                details={"retry_after_seconds": max(1, retry)},
            )
        if reason is AuthFailure.ACCOUNT_DISABLED:
            return ApiError(403, "account_disabled", "this account is disabled")
        if reauth:
            return ApiError(401, "reauthentication_failed", "the password was not accepted")
        return ApiError(401, "invalid_credentials", "the user name or password is not correct")

    # --- small helpers ---------------------------------------------------------------

    def _channel(self, request: Request) -> str:
        """The identity commit-confirm compares: stable for the command line, per session
        for everything else."""
        session = request.session
        if session is None:
            raise ApiError(401, "unauthenticated", "this request needs a session")
        if session.client == "cli":
            return f"cli:{session.username}"
        return f"session:{session.session_id}"

    def _page(self, items: Sequence[Any], limit: int, cursor: Callable[[Any], Any]) -> Any:
        return cursor(items[-1]) if items and len(items) >= limit else None

    def _credential_channel(self, request: Request) -> Channel:
        """Which channel a credential check runs on; counts it against the global budget."""
        secret = request.headers.get(CLI_SECRET_HEADER.lower())
        if secret is not None and self.rt.verify_cli_secret(secret):
            request.cli = True
            return Channel.LOCAL
        wait = self.server.charge_login()
        if wait:
            raise ApiError(
                429,
                "rate_limited",
                "too many sign-in attempts; retry shortly",
                details={"retry_after_seconds": wait},
            )
        return Channel.NETWORK

    def _new_session(self, user: User, request: Request) -> Response:
        self.server.housekeeping()
        label = "cli" if request.cli else "console" if "origin" in request.headers else "api"
        token, session = self.sessions.create(user.username, user.role, client=label)
        return Response(200, {"user": user.to_dict(), "session": session.to_dict(), "token": token})

    def _user(self, username: str) -> User:
        user = self.accounts.get_user(username)
        if user is None:
            raise ApiError(404, "not_found", "no such user")
        return user

    def _grant(self, grant_id: str) -> Grant:
        for grant in self.svc.list_grants(include_inactive=True):
            if grant.id == grant_id:
                return grant
        raise ApiError(404, "not_found", "no such grant")

    def _change(self, change: Any) -> dict[str, Any]:
        remaining = (change.deadline_at - self.clock.now()).total_seconds()
        return {
            "id": change.id,
            "kind": change.kind,
            "status": change.status,
            "actor": change.actor,
            "created_at": utc_iso(change.created_at),
            "deadline_at": utc_iso(change.deadline_at),
            "timeout_seconds": change.timeout_seconds,
            "remaining_seconds": max(0, math.ceil(remaining)),
            "preview": [dict(item) for item in change.preview],
        }

    def _expiry(
        self, kind: str, fields: _Fields, expires_in: str | None, expires_at: datetime | None
    ) -> datetime | None:
        if expires_in is not None and expires_at is not None:
            fields.problem("expires_in", "give expires_in or expires_at, not both")
        if kind == "trust" and (expires_in is not None or expires_at is not None):
            fields.problem("expires_in", "trust has no expiry")
        if kind == "temporary" and expires_in is None and expires_at is None:
            fields.problem("expires_in", "a temporary grant needs expires_in or expires_at")
        if expires_in is not None:
            try:
                return self.clock.now() + parse_duration(expires_in)
            except ValueError as exc:
                fields.problem("expires_in", str(exc).split(":")[0] + " (like 30m, 2h, 7d)")
        return expires_at

    # --- liveness, session, status ---------------------------------------------------

    def ping(self, request: Request) -> Response:
        try:
            simulation = self.svc.status().simulation
        except ServiceError:
            simulation = False
        body: dict[str, Any] = {
            "service": "portlock",
            "api": API_VERSION,
            "version": __version__,
            "run_id": self.svc.run_id,
            "setup_required": not self.accounts.has_users(),
            "simulation": simulation,
        }
        challenge = request.headers.get(CHALLENGE_HEADER.lower())
        if challenge is not None:
            if not _CHALLENGE.match(challenge):
                raise _bad(CHALLENGE_HEADER, "must be 16 to 128 lower-case hex characters")
            body["proof"] = ping_proof(self.rt.cli_secret, challenge)
        request.query_fields().finish()
        return Response(200, body)

    def login(self, request: Request) -> Response:
        fields = request.fields()
        username = fields.string("username", required=True, min_length=1, max_length=128)
        password = fields.string("password", required=True, min_length=1, max_length=4096)
        fields.finish()
        channel = self._credential_channel(request)
        result = self.accounts.authenticate(username or "", password or "", channel=channel)
        if not result.ok or result.user is None:
            raise self._auth_failure(
                result.reason or AuthFailure.INVALID_CREDENTIALS, result.retry_after_seconds
            )
        return self._new_session(result.user, request)

    def recovery(self, request: Request) -> Response:
        fields = request.fields()
        username = fields.string("username", required=True, min_length=1, max_length=128)
        code = fields.string("recovery_code", required=True, min_length=1, max_length=128)
        new_password = fields.string("new_password", required=True, min_length=1, max_length=4096)
        fields.finish()
        channel = self._credential_channel(request)
        try:
            name = normalize_username(username)
        except InvalidUsernameError:
            raise ApiError(
                401, "invalid_credentials", "the user name or recovery code is not correct"
            ) from None
        # A weak password is refused before the single-use code is spent.
        problems = check_password_policy(
            new_password or "", min_length=self.accounts.policy.min_password_length, username=name
        )
        if problems:
            raise ApiError(
                400,
                "password_policy",
                "the password is not acceptable",
                details={"problems": problems},
            )
        if not self.accounts.use_recovery_code(name, code or "", channel=channel):
            raise ApiError(
                401, "invalid_credentials", "the user name or recovery code is not correct"
            )
        self.accounts.set_password(name, new_password or "", actor=name)
        return self._new_session(self._user(name), request)

    def logout(self, request: Request) -> Response:
        request.fields().finish()
        session = request.session
        if session is not None and request.token is not None:
            self.sessions.revoke(request.token)
            self.rt.audit(
                "auth.logout",
                actor=session.username,
                data={"username": session.username, "session_id": session.session_id},
            )
        return Response(204)

    def session(self, request: Request) -> Response:
        session = request.session
        if session is None:
            raise ApiError(401, "unauthenticated", "this request needs a session")
        permissions = sorted(item.value for item in Permission if can(session.role, item))
        return Response(
            200,
            {
                "user": self._user(session.username).to_dict(),
                "session": session.to_dict(),
                "permissions": permissions,
            },
        )

    def change_own_password(self, request: Request) -> Response:
        fields = request.fields()
        current = fields.string("current_password", required=True, min_length=1, max_length=4096)
        new = fields.string("new_password", required=True, min_length=1, max_length=4096)
        fields.finish()
        channel = self._credential_channel(request)
        self.accounts.change_password(request.user, current or "", new or "", channel=channel)
        return self._new_session(self._user(request.user), request)

    def status(self, request: Request) -> Response:
        return Response(200, self.svc.status().to_dict())

    def doctor(self, request: Request) -> Response:
        return Response(200, self.svc.doctor().to_dict())

    # --- devices, connections, decisions ---------------------------------------------

    def devices(self, request: Request) -> Response:
        query = request.query_fields()
        state = query.string("state", choices=_CONNECTION_STATES)
        query.finish()
        views = self.svc.list_connections(open_only=True, state=state, limit=500)
        views.sort(key=lambda view: view.connection_id or 0)
        return Response(200, {"devices": [view.to_dict() for view in views]})

    def history(self, request: Request) -> Response:
        query = request.query_fields()
        limit = query.integer("limit", default=100, minimum=1, maximum=500) or 100
        before = query.integer("before_id", minimum=1)
        fingerprint = query.string("fingerprint", pattern=_FINGERPRINT)
        opened = query.boolean("open")
        query.finish()
        views = self.svc.list_connections(
            open_only=opened is True, fingerprint=fingerprint, before_id=before, limit=limit
        )
        next_id = self._page(views, limit, lambda view: view.connection_id)
        if opened is False:
            views = [view for view in views if view.removed_at is not None]
        return Response(200, {"connections": [view.to_dict() for view in views], "next": next_id})

    def known(self, request: Request) -> Response:
        query = request.query_fields()
        limit = query.integer("limit", default=100, minimum=1, maximum=500) or 100
        before = query.string("before", pattern=_FINGERPRINT)
        text = query.string("text", min_length=1, max_length=128)
        query.finish()
        devices = self.svc.list_devices(limit=limit, before=before, text=text)
        next_fp = self._page(devices, limit, lambda view: view.record.fingerprint.value)
        return Response(200, {"devices": [view.to_dict() for view in devices], "next": next_fp})

    def device(self, request: Request) -> Response:
        return Response(200, self.svc.get_device(request.params["fingerprint"]).to_dict())

    def connection(self, request: Request) -> Response:
        cid = request.int_param("connection_id")
        view = self.svc.get_connection(cid)
        decisions = self.svc.list_decisions(connection_id=cid, limit=100)
        scans = self.svc.list_scans(connection_id=cid, limit=100)
        return Response(
            200,
            {
                "connection": view.to_dict(),
                "decisions": [item.to_dict() for item in decisions],
                "scans": [item.to_dict() for item in scans],
            },
        )

    def decisions(self, request: Request) -> Response:
        query = request.query_fields()
        limit = query.integer("limit", default=100, minimum=1, maximum=500) or 100
        before = query.integer("before_id", minimum=1)
        connection_id = query.integer("connection_id", minimum=1)
        fingerprint = query.string("fingerprint", pattern=_FINGERPRINT)
        access = query.string("access", choices=_ACCESS_VALUES)
        query.finish()
        filters: dict[str, Any] = {"limit": limit}
        for name, value in (
            ("before_id", before),
            ("connection_id", connection_id),
            ("fingerprint", fingerprint),
        ):
            if value is not None:
                filters[name] = value
        if access is not None:
            from portlock.core.models import Access

            filters["access"] = Access(access)
        items = self.svc.list_decisions(**filters)
        return Response(
            200,
            {
                "decisions": [item.to_dict() for item in items],
                "next": self._page(items, limit, lambda item: item.id),
            },
        )

    # --- approving, denying, trust and grants ----------------------------------------

    def refine_approve(self, request: Request) -> Sequence[Permission]:
        kind = (request.json or {}).get("kind", "once")
        if kind == "trust":
            return (Permission.MANAGE_TRUST,)
        if kind == "temporary":
            return (Permission.ISSUE_TEMPORARY_GRANT,)
        return ()

    def approve(self, request: Request) -> Response:
        cid = request.int_param("connection_id")
        fields = request.fields()
        kind = fields.string("kind", default="once", choices=("once", "temporary", "trust"))
        read_only = fields.boolean("read_only", default=False)
        expires_in = fields.string("expires_in", max_length=32)
        expires_at = fields.time("expires_at")
        note = fields.string("note", default="", max_length=512, printable=True)
        expiry = self._expiry(kind or "once", fields, expires_in, expires_at)
        fields.finish()
        role = request.session.role.value if request.session is not None else "operator"
        applied = self.svc.approve(
            cid,
            kind=kind or "once",
            read_only=bool(read_only),
            expires_at=expiry,
            note=note or "",
            role=role,
            actor=request.user,
        )
        return Response(
            200,
            {
                "grant": applied.value.to_dict(),
                "connection": applied.extra["connection"].to_dict(),
                "reevaluated": list(applied.reevaluated),
            },
        )

    def deny(self, request: Request) -> Response:
        cid = request.int_param("connection_id")
        fields = request.fields()
        eject = fields.boolean("eject", default=False)
        note = fields.string("note", default="", max_length=512, printable=True)
        fields.finish()
        applied = self.svc.deny(cid, eject=bool(eject), note=note or "", actor=request.user)
        ejected = applied.extra.get("eject")
        return Response(
            200,
            {
                "connection": applied.value.to_dict(),
                "eject": None
                if ejected is None
                else {"ok": bool(ejected.ok), "error": ejected.error},
            },
        )

    def trust_list(self, request: Request) -> Response:
        grants = sorted(
            self.svc.list_grants(kind="trust"),
            key=lambda grant: (grant.created_at, grant.id),
            reverse=True,
        )
        return Response(200, {"trust": [grant.to_dict() for grant in grants]})

    def trust_add(self, request: Request) -> Response:
        fields = request.fields()
        fingerprint = fields.string("fingerprint", required=True, pattern=_FINGERPRINT)
        read_only = fields.boolean("read_only", default=False)
        note = fields.string("note", default="", max_length=512, printable=True)
        fields.finish()
        role = request.session.role.value if request.session is not None else "admin"
        # A low-confidence fingerprint can never be trusted (DESIGN 14.13): the grant store
        # says so, and says what to use instead, which is more useful than a flag that
        # could not help here.
        applied = self.svc.create_grant(
            fingerprint or "",
            "trust",
            read_only=bool(read_only),
            note=note or "",
            allow_low_confidence=True,
            role=role,
            actor=request.user,
        )
        return Response(
            201, {"grant": applied.value.to_dict(), "reevaluated": list(applied.reevaluated)}
        )

    def trust_remove(self, request: Request) -> Response:
        grant = self._grant(request.params["grant_id"])
        if grant.kind.value != "trust" or grant.ended_at is not None:
            raise ApiError(404, "not_found", "no such trust grant")
        applied = self.svc.revoke_grant(grant.id, actor=request.user)
        return Response(
            200, {"grant": applied.value.to_dict(), "reevaluated": list(applied.reevaluated)}
        )

    def grants_list(self, request: Request) -> Response:
        query = request.query_fields()
        inactive = query.boolean("include_inactive", default=False)
        kind = query.string("kind", choices=("trust", "temporary", "once"))
        fingerprint = query.string("fingerprint", pattern=_FINGERPRINT)
        query.finish()
        grants = self.svc.list_grants(include_inactive=bool(inactive), kind=kind)
        grants = [g for g in grants if fingerprint is None or g.fingerprint == fingerprint]
        grants.sort(key=lambda grant: (grant.created_at, grant.id), reverse=True)
        return Response(200, {"grants": [grant.to_dict() for grant in grants]})

    def grants_add(self, request: Request) -> Response:
        fields = request.fields()
        fingerprint = fields.string("fingerprint", required=True, pattern=_FINGERPRINT)
        kind = fields.string("kind", required=True, choices=("temporary", "once"))
        read_only = fields.boolean("read_only", default=False)
        expires_in = fields.string("expires_in", max_length=32)
        expires_at = fields.time("expires_at")
        note = fields.string("note", default="", max_length=512, printable=True)
        allow_low = fields.boolean("allow_low_confidence", default=False)
        expiry = self._expiry(kind or "once", fields, expires_in, expires_at)
        fields.finish()
        role = request.session.role.value if request.session is not None else "operator"
        applied = self.svc.create_grant(
            fingerprint or "",
            kind or "once",
            read_only=bool(read_only),
            expires_at=expiry,
            note=note or "",
            allow_low_confidence=bool(allow_low),
            role=role,
            actor=request.user,
        )
        return Response(
            201, {"grant": applied.value.to_dict(), "reevaluated": list(applied.reevaluated)}
        )

    def refine_grant_removal(self, request: Request) -> Sequence[Permission]:
        grant = self._grant(request.params["grant_id"])
        return (Permission.MANAGE_TRUST,) if grant.kind.value == "trust" else ()

    def grants_remove(self, request: Request) -> Response:
        grant = self._grant(request.params["grant_id"])
        if grant.ended_at is not None:
            raise ApiError(404, "not_found", "no such active grant")
        applied = self.svc.revoke_grant(grant.id, actor=request.user)
        return Response(
            200, {"grant": applied.value.to_dict(), "reevaluated": list(applied.reevaluated)}
        )

    # --- enrolments, held ports ------------------------------------------------------

    def enrolments_list(self, request: Request) -> Response:
        items = [
            {
                "fingerprint": item.fingerprint,
                "bus_path": item.bus_path,
                "label": item.label,
                "enrolled_at": utc_iso(item.enrolled_at),
                "enrolled_by": item.enrolled_by,
            }
            for item in self.svc.list_enrolments()
        ]
        return Response(200, {"enrolments": items})

    def enrolments_add(self, request: Request) -> Response:
        fields = request.fields()
        cid = fields.integer("connection_id", required=True, minimum=1)
        label = fields.string("label", max_length=128, printable=True)
        fields.finish()
        applied = self.svc.enroll(cid or 0, actor=request.user, label=label)
        record = applied.value
        return Response(
            201,
            {
                "enrolment": {
                    "fingerprint": record.fingerprint,
                    "bus_path": record.bus_path,
                    "label": record.label,
                    "enrolled_at": utc_iso(record.enrolled_at),
                    "enrolled_by": record.enrolled_by,
                },
                "reevaluated": list(applied.reevaluated),
            },
        )

    def enrolments_remove(self, request: Request) -> Response:
        query = request.query_fields()
        bus_path = query.string("bus_path", min_length=1, max_length=128, printable=True)
        query.finish()
        applied = self.svc.unenroll(
            request.params["fingerprint"], bus_path=bus_path, actor=request.user
        )
        if not applied.value:
            raise ApiError(404, "not_found", "no such enrolment")
        return Response(
            200,
            {
                "removed": applied.value,
                "summary": applied.summary.to_dict() if applied.summary else None,
            },
        )

    def release_port(self, request: Request) -> Response:
        fields = request.fields()
        port = fields.string("port", required=True, min_length=1, max_length=128, printable=True)
        fields.finish()
        applied = self.svc.release_port(port or "", actor=request.user)
        if not applied.value:
            raise ApiError(404, "not_found", "that port is not held")
        return Response(200, {"released": True, "reevaluated": list(applied.reevaluated)})

    # --- policy ----------------------------------------------------------------------

    def policy_get(self, request: Request) -> Response:
        return Response(200, self.svc.get_policy().to_dict())

    def policy_validate(self, request: Request) -> Response:
        fields = request.fields()
        policy = fields.mapping("policy", required=True)
        fields.finish()
        digest, problems = self.svc.validate_policy(policy or {})
        return Response(
            200, {"valid": digest is not None, "problems": list(problems), "hash": digest}
        )

    def policy_put(self, request: Request) -> Response:
        fields = request.fields()
        policy = fields.mapping("policy", required=True)
        expected = fields.string(
            "expected_hash", max_length=64, pattern=re.compile(r"[0-9a-f]{64}\Z")
        )
        fields.finish()
        applied = self.svc.replace_policy(policy or {}, expected_hash=expected, actor=request.user)
        body = applied.value.to_dict()
        body["previous_hash"] = applied.extra.get("previous_hash")
        body["summary"] = applied.summary.to_dict() if applied.summary else None
        return Response(200, body)

    def policy_test(self, request: Request) -> Response:
        fields = request.fields()
        cid = fields.integer("connection_id", minimum=1)
        fingerprint = fields.string("fingerprint", pattern=_FINGERPRINT)
        raw_device = fields.mapping("device")
        draft = fields.mapping("policy")
        at = fields.time("at")
        given = [
            name
            for name, value in (
                ("connection_id", cid),
                ("fingerprint", fingerprint),
                ("device", raw_device),
            )
            if value is not None
        ]
        if len(given) != 1:
            fields.problem("device", "give exactly one of connection_id, fingerprint and device")
        fields.finish()
        if cid is not None:
            device = self.svc.get_connection(cid).device
        elif fingerprint is not None:
            device = self.svc.get_device(fingerprint).device.record.device
        else:
            device = _device_from_json(raw_device or {})
        result = self.svc.test_policy(device=device, policy=draft, at=at)
        return Response(200, result.to_dict())

    # --- audit -----------------------------------------------------------------------

    def audit_list(self, request: Request) -> Response:
        query = request.query_fields()
        since_seq = query.integer("since_seq", minimum=1)
        until_seq = query.integer("until_seq", minimum=1)
        since = query.time("since")
        until = query.time("until")
        types = query.strings("type", max_items=32, max_length=64)
        min_severity = query.string("min_severity", choices=_SEVERITIES)
        device_fp = query.string("device_fp", pattern=_FINGERPRINT)
        actor = query.string("actor", min_length=1, max_length=128, printable=True)
        text = query.string("text", min_length=1, max_length=256)
        limit = query.integer("limit", default=100, minimum=1, maximum=500) or 100
        order = query.string("order", default="desc", choices=("desc", "asc"))
        query.finish()
        log = self.svc.audit_log
        records = log.query(
            since_seq=since_seq,
            until_seq=until_seq,
            since=since,
            until=until,
            event_types=types,
            min_severity=min_severity,
            device_fp=device_fp,
            actor=actor,
            text=text,
            limit=limit,
            descending=order != "asc",
        )
        next_seq: int | None = None
        if len(records) >= limit and records:
            last = records[-1].seq
            next_seq = (last - 1 if order != "asc" else last + 1) or None
            if order != "asc" and last <= 1:
                next_seq = None
        seq, digest = log.head()
        return Response(
            200,
            {
                "records": [record.to_dict() for record in records],
                "head": {"seq": seq, "hash": digest},
                "next": next_seq,
            },
        )

    def audit_verify(self, request: Request) -> Response:
        fields = request.fields()
        start = fields.integer("start_seq", default=1, minimum=1)
        head = fields.mapping("expected_head")
        expected: tuple[int, str] | None = None
        if head is not None:
            inner = _Fields(head, text=False)
            seq = inner.integer("seq", required=True, minimum=0)
            digest = inner.string("hash", required=True, pattern=re.compile(r"[0-9a-f]{64}\Z"))
            try:
                inner.finish()
            except ApiError as exc:
                for item in (exc.details or {}).get("problems", []):
                    fields.problem("expected_head." + item["path"], item["message"])
            else:
                expected = (seq or 0, digest or "")
        fields.finish()
        result = self.svc.verify_audit(
            start_seq=start or 1, expected_head=expected, actor=request.user
        )
        return Response(
            200,
            {
                "ok": result.ok,
                "checked": result.checked,
                "first_bad_seq": result.first_bad_seq,
                "reason": result.reason,
                "macs_checked": result.macs_checked,
                "head": None
                if result.head is None
                else {"seq": result.head[0], "hash": result.head[1]},
                "head_checked": result.head_checked,
                "keyed": self.svc.audit_log.keyed,
            },
        )

    def audit_export(self, request: Request) -> Response:
        query = request.query_fields()
        since = query.integer("since_seq", default=1, minimum=1) or 1
        query.finish()
        log: AuditLog = self.svc.audit_log

        def run(conn: _Conn) -> None:
            try:
                log.export_jsonl(_SocketWriter(conn), since_seq=since)
            except (AuditError, StoreError) as exc:
                # The headers are gone: all that can be done is to end the body early, so
                # that a client sees a truncated export instead of a complete-looking one.
                _LOG.error("the audit export stopped: %s", exc)

        return Response(
            200,
            headers={"Content-Disposition": 'attachment; filename="portlock-audit.jsonl"'},
            content_type="application/x-ndjson",
            stream=run,
        )

    def audit_checkpoint(self, request: Request) -> Response:
        log = self.svc.audit_log
        checkpoint = log.checkpoint()
        return Response(
            200, {"checkpoint": checkpoint, "signed_event": self._signed_checkpoint(checkpoint)}
        )

    def _signed_checkpoint(self, checkpoint: Mapping[str, Any]) -> dict[str, Any] | None:
        """The head record as a signed security event, or ``None`` without signing support."""
        from pathlib import Path

        from portlock.audit.events import security_event_from_record
        from portlock.audit.signing import has_signing_support, load_or_create_key

        seq = checkpoint.get("seq")
        if not has_signing_support() or not isinstance(seq, int) or seq < 1:
            return None
        try:
            record = self.svc.audit_log.get(seq)
            if record is None:
                return None
            signer = load_or_create_key(Path(self.config.paths.state_dir) / "event-signing.key")
            event = security_event_from_record(record, host=self.config.host_label)
            return signer.sign_event(event)
        except (AuditError, OSError) as exc:
            _LOG.error("the checkpoint could not be signed: %s", exc)
            return None

    # --- scans -----------------------------------------------------------------------

    def scans_request(self, request: Request) -> Response:
        fields = request.fields()
        cid = fields.integer("connection_id", required=True, minimum=1)
        mount = fields.string("mount_point", max_length=1024, printable=True)
        fields.finish()
        views = self.svc.request_scan(cid or 0, mount_point=mount, actor=request.user)
        return Response(202, {"scans": [view.to_dict() for view in views]})

    def scans_list(self, request: Request) -> Response:
        query = request.query_fields()
        limit = query.integer("limit", default=100, minimum=1, maximum=500) or 100
        before = query.integer("before_id", minimum=1)
        cid = query.integer("connection_id", minimum=1)
        fingerprint = query.string("fingerprint", pattern=_FINGERPRINT)
        query.finish()
        filters: dict[str, Any] = {"limit": limit}
        for name, value in (
            ("before_id", before),
            ("connection_id", cid),
            ("fingerprint", fingerprint),
        ):
            if value is not None:
                filters[name] = value
        views = self.svc.list_scans(**filters)
        return Response(
            200,
            {
                "scans": [view.to_dict() for view in views],
                "next": self._page(views, limit, lambda view: view.record.id),
            },
        )

    def scans_get(self, request: Request) -> Response:
        return Response(200, {"scan": self.svc.get_scan(request.int_param("scan_id")).to_dict()})

    # --- lockdown, pending changes, mode, scope, settings ----------------------------

    def lockdown_get(self, request: Request) -> Response:
        return Response(200, self.svc.lockdown_status().to_dict())

    def lockdown_engage(self, request: Request) -> Response:
        fields = request.fields()
        minutes = fields.integer("minutes")
        reason = fields.string("reason", default="", max_length=256, printable=True)
        fields.finish()
        applied = self.svc.lockdown_engage(
            minutes=minutes, reason=reason or "", actor=request.user, channel=self._channel(request)
        )
        result = applied.value
        return Response(
            200,
            {
                "lockdown": result.status.to_dict(),
                "summary": result.summary.to_dict(),
                "change": self._change(result.change),
            },
        )

    def lockdown_renew(self, request: Request) -> Response:
        fields = request.fields()
        minutes = fields.integer("minutes")
        fields.finish()
        applied = self.svc.lockdown_renew(minutes=minutes, actor=request.user)
        return Response(200, {"lockdown": applied.value.to_dict()})

    def lockdown_lift(self, request: Request) -> Response:
        fields = request.fields()
        password = fields.string("password", min_length=1, max_length=4096)
        code = fields.string("recovery_code", min_length=1, max_length=256)
        if (password is None) == (code is None):
            fields.problem("password", "give exactly one of password and recovery_code")
        fields.finish()
        wait = self.accounts.lockout_remaining(request.user)
        if password is not None and wait:
            raise ApiError(
                429,
                "locked_out",
                "too many failed attempts; try again later",
                details={"retry_after_seconds": wait},
            )
        credential = (
            Credential("password", password)
            if password is not None
            else Credential("recovery_code", code or "")
        )
        applied = self.svc.lockdown_lift(actor=request.user, credential=credential)
        result = applied.value
        return Response(
            200,
            {
                "lockdown": result.status.to_dict(),
                "summary": result.summary.to_dict() if result.summary is not None else None,
            },
        )

    def changes_list(self, request: Request) -> Response:
        return Response(
            200, {"changes": [self._change(item) for item in self.svc.pending_changes()]}
        )

    def refine_change(self, request: Request) -> Sequence[Permission]:
        for change in self.svc.pending_changes():
            if change.id == request.params["change_id"]:
                return (_CHANGE_PERMISSION.get(change.kind, Permission.CHANGE_MODE),)
        raise ApiError(404, "no_pending_change", "there is no such change waiting for confirmation")

    def change_confirm(self, request: Request) -> Response:
        request.fields().finish()
        record = self.svc.confirm_change(
            request.params["change_id"], actor=request.user, channel=self._channel(request)
        )
        return Response(200, {"change": self._change(record), "confirmed": True})

    def change_cancel(self, request: Request) -> Response:
        request.fields().finish()
        record = next(
            (item for item in self.svc.pending_changes() if item.id == request.params["change_id"]),
            None,
        )
        if record is None or not self.svc.cancel_change(record.id, actor=request.user):
            raise ApiError(404, "no_pending_change", "there is no such change to cancel")
        return Response(200, {"change": self._change(record), "cancelled": True})

    def mode_get(self, request: Request) -> Response:
        return Response(200, self.svc.get_mode().to_dict())

    def mode_put(self, request: Request) -> Response:
        fields = request.fields()
        mode = fields.string("mode", required=True, choices=("monitor", "enforce"))
        fields.finish()
        applied = self.svc.set_mode(
            mode or "monitor", actor=request.user, channel=self._channel(request)
        )
        return Response(
            200,
            {
                "mode": applied.value.to_dict(),
                "summary": applied.summary.to_dict() if applied.summary else None,
                "change": applied.extra.get("change"),
            },
        )

    def scope_get(self, request: Request) -> Response:
        scope = self.svc.get_settings().runtime["scope"]
        return Response(200, {"scope": scope, "scopes": list(SCOPES)})

    def scope_put(self, request: Request) -> Response:
        fields = request.fields()
        scope = fields.string("scope", required=True, choices=SCOPES)
        fields.finish()
        applied = self.svc.set_scope(
            scope or "", actor=request.user, channel=self._channel(request)
        )
        return Response(
            200,
            {
                "scope": applied.value,
                "summary": applied.summary.to_dict() if applied.summary else None,
                "change": applied.extra.get("change"),
            },
        )

    def default_deny_get(self, request: Request) -> Response:
        return Response(
            200, {"enabled": bool(self.svc.get_settings().runtime.get("default_deny", False))}
        )

    def default_deny_put(self, request: Request) -> Response:
        fields = request.fields()
        enabled = fields.boolean("enabled")
        if enabled is None:
            fields.problem("enabled", "is required")
        fields.finish()
        applied = self.svc.set_default_deny(
            bool(enabled), actor=request.user, channel=self._channel(request)
        )
        return Response(
            200,
            {
                "enabled": bool(applied.value),
                "summary": applied.summary.to_dict() if applied.summary else None,
                "change": applied.extra.get("change"),
            },
        )

    def settings_get(self, request: Request) -> Response:
        return Response(200, self.svc.get_settings().to_dict())

    def settings_patch(self, request: Request) -> Response:
        fields = request.fields()
        fingerprints = fields.strings("protected_fingerprints", max_items=256, max_length=64)
        scanning = fields.boolean("scan.enabled")
        minutes = fields.integer("lockdown.default_minutes", minimum=1)
        changes: dict[str, Any] = {}
        if fingerprints is not None:
            if not all(_FINGERPRINT.match(item) for item in fingerprints):
                fields.problem("protected_fingerprints", "each entry must be a fingerprint")
            changes["protected_fingerprints"] = fingerprints
        if scanning is not None:
            changes["scan.enabled"] = scanning
        if minutes is not None:
            changes["lockdown.default_minutes"] = minutes
        if not changes and not fields.has("protected_fingerprints"):
            fields.problem("", "give at least one setting to change")
        fields.finish()
        applied = self.svc.update_settings(changes, actor=request.user)
        body = applied.value.to_dict()
        body["summary"] = applied.summary.to_dict() if applied.summary else None
        return Response(200, body)

    # --- users -----------------------------------------------------------------------

    def users_list(self, request: Request) -> Response:
        users = []
        for user in self.accounts.list_users():
            entry = user.to_dict()
            entry["recovery_codes_remaining"] = self.accounts.remaining_recovery_codes(
                user.username
            )
            entry["locked_out_seconds"] = self.accounts.lockout_remaining(user.username)
            users.append(entry)
        return Response(200, {"users": users})

    def users_add(self, request: Request) -> Response:
        fields = request.fields()
        username = fields.string("username", required=True, min_length=1, max_length=64)
        password = fields.string("password", required=True, min_length=1, max_length=4096)
        role = fields.string("role", required=True, choices=tuple(item.value for item in Role))
        fields.finish()
        user = self.accounts.create_user(
            username or "", password or "", role or "auditor", actor=request.user
        )
        return Response(201, {"user": user.to_dict()})

    def users_role(self, request: Request) -> Response:
        fields = request.fields()
        role = fields.string("role", required=True, choices=tuple(item.value for item in Role))
        fields.finish()
        user = self.accounts.set_role(
            request.params["username"], role or "auditor", actor=request.user
        )
        return Response(200, {"user": user.to_dict()})

    def users_disable(self, request: Request) -> Response:
        request.fields().finish()
        user = self.accounts.disable_user(request.params["username"], actor=request.user)
        return Response(200, {"user": user.to_dict()})

    def users_enable(self, request: Request) -> Response:
        request.fields().finish()
        user = self.accounts.enable_user(request.params["username"], actor=request.user)
        return Response(200, {"user": user.to_dict()})

    def users_password(self, request: Request) -> Response:
        fields = request.fields()
        new = fields.string("new_password", required=True, min_length=1, max_length=4096)
        fields.finish()
        name = request.params["username"]
        self.accounts.set_password(name, new or "", actor=request.user)
        self.accounts.clear_lockout(name, actor=request.user)
        return Response(200, {"user": self._user(name).to_dict()})

    def refine_recovery_codes(self, request: Request) -> Sequence[Permission]:
        own = request.session is not None and request.params["username"] == request.session.username
        return () if own else (Permission.MANAGE_USERS,)

    def users_recovery_codes(self, request: Request) -> Response:
        request.fields().finish()
        name = request.params["username"]
        codes = self.accounts.generate_recovery_codes(name, actor=request.user)
        return Response(
            200, {"username": name, "codes": codes, "issued_at": utc_iso(self.clock.now())}
        )

    def users_unlock(self, request: Request) -> Response:
        request.fields().finish()
        name = request.params["username"]
        self.accounts.clear_lockout(name, actor=request.user)
        return Response(200, {"user": self._user(name).to_dict()})

    def users_delete(self, request: Request) -> Response:
        self.accounts.delete_user(request.params["username"], actor=request.user)
        return Response(204)

    # --- the event stream ------------------------------------------------------------

    def events(self, request: Request) -> Response:
        query = request.query_fields()
        since = query.string("since", max_length=64)
        query.finish()
        marker = request.headers.get("last-event-id") or since
        resume: tuple[str, int] | None = None
        if marker:
            found = _EVENT_ID.match(marker)
            if found is None:
                raise _bad(
                    "last-event-id" if request.headers.get("last-event-id") else "since",
                    "must look like <run_id>-<number>",
                )
            resume = (found.group(1), int(found.group(2)))
        session = request.session
        if session is None:
            raise ApiError(401, "unauthenticated", "this request needs a session")
        if not self.server.acquire_stream():
            raise ApiError(503, "too_many_streams", "too many event streams are open")
        bus = self.rt.bus
        mailbox: queue.Queue[Event] = queue.Queue(maxsize=self.server.stream_queue)
        lagged = threading.Event()
        wants_audit = can(session.role, Permission.VIEW_AUDIT)

        def visible(event: Event) -> bool:
            if event.topic.startswith(_PRIVATE_TOPIC_PREFIX):
                return False
            return wants_audit or event.topic != _AUDIT_TOPIC

        def deliver(event: Event) -> None:
            # Runs on whichever thread published, usually holding the service lock: it may
            # only enqueue.
            if not visible(event):
                return
            try:
                mailbox.put_nowait(event)
            except queue.Full:
                lagged.set()

        unsubscribe = bus.subscribe("*", deliver)
        latest = bus.last_seq
        oldest = bus.oldest_seq
        resumed = False
        reset: str | None = None
        floor = latest
        if resume is not None:
            run_id, number = resume
            if run_id != self.svc.run_id:
                reset = "restart"
            elif number > latest or not (
                number == latest or (oldest is not None and oldest <= number + 1)
            ):
                reset = "gap"
            else:
                resumed, floor = True, number

        def run(conn: _Conn) -> None:
            self._stream(conn, session, mailbox, lagged, visible, resumed, reset, floor, latest)

        def cleanup() -> None:
            unsubscribe()
            self.server.release_stream()

        return Response(
            200,
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
            content_type="text/event-stream; charset=utf-8",
            stream=run,
            cleanup=cleanup,
        )

    def _session_alive(self, known: Session) -> Session | None:
        """The session if it is still live. Does not count as activity: it only lists."""
        try:
            for item in self.sessions.list_sessions(known.username):
                if item.session_id == known.session_id:
                    return item
        except StoreError:
            return known
        return None

    def _stream(
        self,
        conn: _Conn,
        session: Session,
        mailbox: queue.Queue[Event],
        lagged: threading.Event,
        visible: Callable[[Event], bool],
        resumed: bool,
        reset: str | None,
        floor: int,
        latest: int,
    ) -> None:
        bus = self.rt.bus
        run_id = self.svc.run_id
        server = self.server

        def frame(name: str, data: Mapping[str, Any], event_id: str | None = None) -> bytes:
            head = f"id: {event_id}\n" if event_id else ""
            return (
                f"{head}event: {name}\ndata: ".encode("ascii") + _json_bytes(dict(data)) + b"\n\n"
            )

        def event_frame(event: Event) -> bytes | None:
            try:
                return frame(event.topic, event.payload, f"{run_id}-{event.seq}")
            except (TypeError, ValueError) as exc:
                _LOG.error("the event %s could not be encoded: %s", event.topic, exc)
                return None

        conn.send(b"retry: 3000\n\n")
        conn.send(
            frame(
                "hello",
                {
                    "run_id": run_id,
                    "seq": latest,
                    "resumed": resumed,
                    "server_time": utc_iso(self.clock.now()),
                },
            )
        )
        last_sent = floor
        if reset is not None:
            conn.send(frame("reset", {"reason": reset}))
            last_sent = latest
        elif resumed:
            for event in bus.recent(since_seq=floor):
                if visible(event):
                    data = event_frame(event)
                    if data is not None:
                        conn.send(data)
                last_sent = max(last_sent, event.seq)
        interval = server.keepalive_seconds
        beat = time.monotonic()
        checked = beat
        known = session
        while not server.stopping.is_set():
            if lagged.is_set():
                return
            try:
                event: Event | None = mailbox.get(timeout=min(0.2, interval))
            except queue.Empty:
                event = None
            now = time.monotonic()
            if event is not None and event.seq > last_sent:
                data = event_frame(event)
                if data is not None:
                    conn.send(data)
                last_sent = event.seq
                beat = now
            if now - checked >= interval:
                checked = now
                alive = self._session_alive(known)
                if alive is None:
                    gone = self.clock.now()
                    reason = (
                        "expired"
                        if gone >= known.idle_expires_at or gone >= known.expires_at
                        else "revoked"
                    )
                    conn.send(frame("session.ended", {"reason": reason}))
                    return
                known = alive
            if now - beat >= interval:
                beat = now
                conn.send(b": keep-alive\n\n")


def _device_from_json(raw: Mapping[str, Any]) -> UsbDevice:
    """A device a client describes for ``POST /policy/test``, checked field by field."""
    unknown = sorted(set(raw) - _DEVICE_FIELDS)
    if unknown:
        raise _bad(f"device.{unknown[0][:64]}", "is not a known field")
    data = dict(raw)
    data.setdefault("instance_id", "api-test/0")
    for required in ("vendor_id", "product_id"):
        if required not in data:
            raise _bad(f"device.{required}", "is required")
    try:
        return UsbDevice.from_dict(data)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise _bad("device", f"is not a valid device ({_short(exc)})") from None


R = Route
E = _Endpoints
P = Permission

#: The whole of ``docs/API.md``, one entry per endpoint. The endpoint tests walk it: every
#: route is in the document and every route says who may call it.
ROUTES: tuple[Route, ...] = (
    R("GET", "/ping", None, E.ping, public=True),
    R("POST", "/auth/login", None, E.login, public=True),
    R("POST", "/auth/recovery", None, E.recovery, public=True),
    R("POST", "/auth/logout", None, E.logout),
    R("GET", "/auth/session", None, E.session),
    R("POST", "/auth/password", None, E.change_own_password),
    R("GET", "/status", P.VIEW, E.status),
    R("GET", "/devices", P.VIEW, E.devices, query=frozenset({"state"})),
    R(
        "GET",
        "/devices/history",
        P.VIEW,
        E.history,
        query=frozenset({"limit", "before_id", "fingerprint", "open"}),
    ),
    R("GET", "/devices/known", P.VIEW, E.known, query=frozenset({"limit", "before", "text"})),
    R("GET", "/devices/{fingerprint}", P.VIEW, E.device),
    R("GET", "/connections/{connection_id}", P.VIEW, E.connection),
    R(
        "GET",
        "/decisions",
        P.VIEW,
        E.decisions,
        query=frozenset({"limit", "before_id", "connection_id", "fingerprint", "access"}),
    ),
    R(
        "POST",
        "/connections/{connection_id}/approve",
        P.APPROVE_DEVICE,
        E.approve,
        refine=E.refine_approve,
    ),
    R("POST", "/connections/{connection_id}/deny", P.APPROVE_DEVICE, E.deny),
    R("GET", "/trust", P.VIEW, E.trust_list),
    R("POST", "/trust", P.MANAGE_TRUST, E.trust_add),
    R("DELETE", "/trust/{grant_id}", P.MANAGE_TRUST, E.trust_remove),
    R(
        "GET",
        "/grants",
        P.VIEW,
        E.grants_list,
        query=frozenset({"include_inactive", "kind", "fingerprint"}),
    ),
    R("POST", "/grants", P.ISSUE_TEMPORARY_GRANT, E.grants_add),
    R(
        "DELETE",
        "/grants/{grant_id}",
        P.ISSUE_TEMPORARY_GRANT,
        E.grants_remove,
        refine=E.refine_grant_removal,
    ),
    R("GET", "/enrolments", P.VIEW, E.enrolments_list),
    R("POST", "/enrolments", P.MANAGE_TRUST, E.enrolments_add),
    R(
        "DELETE",
        "/enrolments/{fingerprint}",
        P.MANAGE_TRUST,
        E.enrolments_remove,
        query=frozenset({"bus_path"}),
    ),
    R("POST", "/ports/release", P.MANAGE_TRUST, E.release_port),
    R("GET", "/policy", P.VIEW, E.policy_get),
    R("POST", "/policy/validate", P.VIEW, E.policy_validate),
    R("PUT", "/policy", P.EDIT_POLICY, E.policy_put),
    R("POST", "/policy/test", P.VIEW, E.policy_test),
    R(
        "GET",
        "/audit",
        P.VIEW_AUDIT,
        E.audit_list,
        query=frozenset(
            {
                "since_seq",
                "until_seq",
                "since",
                "until",
                "type",
                "min_severity",
                "device_fp",
                "actor",
                "text",
                "limit",
                "order",
            }
        ),
    ),
    R("POST", "/audit/verify", P.VIEW_AUDIT, E.audit_verify),
    R("GET", "/audit/export", P.EXPORT_AUDIT, E.audit_export, query=frozenset({"since_seq"})),
    R("GET", "/audit/checkpoint", P.EXPORT_AUDIT, E.audit_checkpoint),
    R("POST", "/scans", P.RUN_SCAN, E.scans_request),
    R(
        "GET",
        "/scans",
        P.VIEW,
        E.scans_list,
        query=frozenset({"limit", "before_id", "connection_id", "fingerprint"}),
    ),
    R("GET", "/scans/{scan_id}", P.VIEW, E.scans_get),
    R("GET", "/lockdown", P.VIEW, E.lockdown_get),
    R("POST", "/lockdown/engage", P.ENGAGE_LOCKDOWN, E.lockdown_engage),
    R("POST", "/lockdown/renew", P.ENGAGE_LOCKDOWN, E.lockdown_renew),
    R("POST", "/lockdown/lift", P.LIFT_LOCKDOWN, E.lockdown_lift),
    R("GET", "/changes", P.VIEW, E.changes_list),
    R("POST", "/changes/{change_id}/confirm", P.VIEW, E.change_confirm, refine=E.refine_change),
    R("POST", "/changes/{change_id}/cancel", P.VIEW, E.change_cancel, refine=E.refine_change),
    R("GET", "/mode", P.VIEW, E.mode_get),
    R("PUT", "/mode", P.CHANGE_MODE, E.mode_put),
    R("GET", "/scope", P.VIEW, E.scope_get),
    R("PUT", "/scope", P.CHANGE_MODE, E.scope_put),
    R("GET", "/default-deny", P.VIEW, E.default_deny_get),
    R("PUT", "/default-deny", P.CHANGE_MODE, E.default_deny_put),
    R("GET", "/doctor", P.VIEW, E.doctor),
    R("GET", "/settings", P.VIEW, E.settings_get),
    R("PATCH", "/settings", P.EDIT_POLICY, E.settings_patch),
    R("GET", "/users", P.MANAGE_USERS, E.users_list),
    R("POST", "/users", P.MANAGE_USERS, E.users_add),
    R("PUT", "/users/{username}/role", P.MANAGE_USERS, E.users_role),
    R("POST", "/users/{username}/disable", P.MANAGE_USERS, E.users_disable),
    R("POST", "/users/{username}/enable", P.MANAGE_USERS, E.users_enable),
    R("POST", "/users/{username}/password", P.MANAGE_USERS, E.users_password),
    R(
        "POST",
        "/users/{username}/recovery-codes",
        None,
        E.users_recovery_codes,
        refine=E.refine_recovery_codes,
    ),
    R("POST", "/users/{username}/unlock", P.MANAGE_USERS, E.users_unlock),
    R("DELETE", "/users/{username}", P.MANAGE_USERS, E.users_delete),
    R("GET", "/events", P.VIEW, E.events, query=frozenset({"since"})),
)
del R, E, P


def api_factory(runtime: RuntimeLike) -> ApiServer:
    """``service.daemon.run``'s ``api_factory``: the API server for a runtime."""
    return ApiServer(runtime)
