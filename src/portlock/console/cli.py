"""``portlock``: the command line (``docs/ARCHITECTURE.md`` 4.2).

Two kinds of command:

* A **service command** is an HTTP client of the local API (``docs/API.md``). It finds the
  running service (``--url`` or ``PORTLOCK_URL``, else ``runtime.json`` in the state
  directory), **proves it is talking to the service** before it sends any credential
  (the service must answer a random challenge with a value only the holder of the secret
  in ``runtime.json`` can compute), logs in with a prompted password, makes its calls and
  logs out. Nothing is stored on disk. A privileged command always authenticates.
* A **local command** (``init``, ``run``, ``stop``, ``recover``, ``policy validate``,
  ``audit verify --offline``, ``doctor --offline``, ``service print-unit``, ``simulate``,
  ``user ... --local``) works on files with the operating system's rights and never needs
  the service. ``recover`` needs nothing but the journal file.

Passwords come from a hidden prompt or from standard input (``--password-stdin``); never
from an argument or the environment, where other users' tools could read them. Everything
a device said about itself is printed through
:func:`~portlock.console.escape_control`. ``--json`` prints the API's answer unchanged.

Exit codes: 0 success; 1 the operation failed; 2 usage; 3 not authenticated or not
permitted; 4 the service is not running, not reachable, or did not prove who it is;
5 a check failed (``audit verify``, ``policy validate``, ``doctor`` with a failure).
``run`` passes the daemon's own codes through (2 already running, 3 state unusable,
4 configuration rejected, 5 the API could not listen).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import getpass
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import sys
import time
import traceback
import urllib.parse
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, NoReturn

from portlock import __version__
from portlock.audit.log import AuditKeyStore, AuditLog
from portlock.auth.accounts import AccountStore, AuthPolicy, Role
from portlock.auth.passwords import ScryptParams, check_password_policy
from portlock.auth.sessions import SessionStore
from portlock.console import escape_control
from portlock.console.api import (
    CHALLENGE_HEADER,
    CLI_SECRET_HEADER,
    api_factory,
    ping_proof,
)
from portlock.console.simulate import SCENARIOS, run_simulation
from portlock.core.clock import Clock, SystemClock
from portlock.core.config import (
    HOME_ENV,
    AuditConfig,
    Config,
    config_to_toml,
    default_config,
    load_config,
    paths_per_user,
)
from portlock.core.db import Database
from portlock.core.errors import ConfigError, PortLockError
from portlock.core.events import EventBus
from portlock.core.fsutil import atomic_write_bytes, atomic_write_text, ensure_private_dir
from portlock.core.privilege import process_elevated
from portlock.core.service import AuditWriter
from portlock.core.store import JOURNAL_FILE_NAME, RecoveryJournal
from portlock.guard import factory
from portlock.guard.base import DeviceBackend, Enforcer
from portlock.guard.safety import SafeEnforcer, SafetyContext
from portlock.guard.watchonly import Posture, detect_posture
from portlock.lockdown.manager import ExternalTimer, recover
from portlock.policy import (
    DEFAULT_POLICY,
    EXAMPLE_POLICY,
    PolicyEngine,
    dump_policy_json,
    load_policy_file,
    policy_hash,
    policy_to_dict,
)
from portlock.service import install
from portlock.service.daemon import (
    HEAD_FILE_NAME,
    LOCK_FILE_NAME,
    RUNTIME_FILE_NAME,
    InstanceLock,
    read_runtime_file,
    request_stop,
    run,
)

__all__ = [
    "EXIT_AUTH",
    "EXIT_CHECK",
    "EXIT_FAILED",
    "EXIT_OK",
    "EXIT_UNREACHABLE",
    "EXIT_USAGE",
    "CliEnv",
    "main",
]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_UNREACHABLE = 4
EXIT_CHECK = 5

_MAX_RESPONSE = 32 * 1024 * 1024
_STOP_WAIT_SECONDS = 15.0
_RECOVER_WAIT_SECONDS = 10.0
_LOOPBACK_NAMES = frozenset({"localhost"})


# --- the environment the command line reaches outside itself ----------------------------


def _default_program() -> str:
    """``python -m portlock`` when started that way (no installation), else ``portlock``."""
    started = Path(sys.argv[0]) if sys.argv and sys.argv[0] else Path()
    by_module = started.name == "__main__.py" and started.parent.name == "portlock"
    return "python -m portlock" if by_module else "portlock"


@dataclass(slots=True)
class CliEnv:
    """Everything ``main`` touches outside its own arguments, replaceable in tests.

    The defaults are the real process: the real streams, the system clock, a hidden
    password prompt, ``service.daemon.run``, and the platform enforcer, backend and
    timer for ``recover``.
    """

    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    stdin: IO[str] | None = None
    stdout: IO[str] | None = None
    stderr: IO[str] | None = None
    getpass: Callable[[str], str] = getpass.getpass
    clock: Clock = field(default_factory=SystemClock)
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    is_tty: Callable[[], bool] = lambda: bool(sys.stdin and sys.stdin.isatty())
    run_service: Callable[..., int] = run
    run_options: Mapping[str, Any] = field(default_factory=dict)
    create_enforcer: Callable[[Config, Any], Enforcer] = lambda config, hook: (
        factory.create_enforcer(config, write_ahead=hook)
    )
    create_backend: Callable[[Config, Clock], DeviceBackend] = lambda config, clock: (
        factory.create_backend(config, clock=clock)
    )
    create_timer: Callable[[Config], ExternalTimer] = factory.create_external_timer
    host_platform: str = sys.platform
    executable: tuple[str, ...] = ()
    #: Whether this process is an administrator (root): decides between the system-wide
    #: and the per-user default directories, and whether enforce mode is possible.
    is_elevated: Callable[[], bool] = process_elevated
    #: How the user started this program, for the commands it suggests.
    program: str = field(default_factory=lambda: _default_program())

    def out(self) -> IO[str]:
        return self.stdout if self.stdout is not None else sys.stdout

    def err(self) -> IO[str]:
        return self.stderr if self.stderr is not None else sys.stderr

    def inp(self) -> IO[str]:
        return self.stdin if self.stdin is not None else sys.stdin


class _UsageError(Exception):
    """Bad command-line arguments (exit 2)."""


class _Exit(Exception):
    """``--help`` and friends: leave with this code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class _Failure(Exception):
    """A command failed; ``code`` is the exit status and ``message`` what to say."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _ApiFailure(_Failure):
    """The API answered with an error."""

    def __init__(self, status: int, code: str, message: str, details: Any) -> None:
        exit_code = EXIT_AUTH if status in (401, 403, 429) else EXIT_FAILED
        super().__init__(exit_code, f"{message} ({code})")
        self.status = status
        self.api_code = code
        self.details = details


class _Parser(argparse.ArgumentParser):
    """``argparse`` that reports through the environment and never exits the process."""

    env: CliEnv

    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self._print_message(message, self.env.err())
        raise _Exit(status)

    def _print_message(self, message: str, file: IO[str] | None = None) -> None:
        if message:
            target = self.env.out() if file is sys.stdout else self.env.err()
            target.write(message)


# --- output helpers ---------------------------------------------------------------------


def _text(value: object) -> str:
    return escape_control("" if value is None else value)


def _when(value: object) -> str:
    """A UTC timestamp as ``YYYY-MM-DD HH:MM:SS`` (anything else, escaped as it is)."""
    text = str(value) if value is not None else ""
    return text[:10] + " " + text[11:19] if len(text) >= 19 and text[10] == "T" else _text(text)


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    cells = [[_text(cell) for cell in row] for row in rows]
    widths = [
        max([len(header)] + [len(row[index]) for row in cells])
        for index, header in enumerate(headers)
    ]
    lines = ["  ".join(header.ljust(width) for header, width in zip(headers, widths, strict=True))]
    lines += [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in cells
    ]
    return "\n".join(line.rstrip() for line in lines)


def _connection_row(view: Mapping[str, Any]) -> list[object]:
    decision = view.get("decision") or {}
    enforcement = view.get("enforcement") or {}
    return [
        view.get("connection_id"),
        view.get("state"),
        decision.get("access", "-"),
        enforcement.get("os_state", "-"),
        view.get("display_name"),
        view.get("fingerprint"),
    ]


_CONNECTION_HEADERS = ("ID", "STATE", "ACCESS", "OS", "DEVICE", "FINGERPRINT")


def _audit_line(record: Mapping[str, Any]) -> str:
    data = record.get("data") or {}
    summary = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(summary) > 110:
        summary = summary[:107] + "..."
    fingerprint = record.get("device_fp")
    where = f" [{fingerprint}]" if fingerprint else ""
    return _text(
        f"{record.get('seq'):>6}  {_when(record.get('ts'))}  {record.get('severity')!s:<8} "
        f"{record.get('event_type')}  {record.get('actor') or '-'}{where}  {summary}"
    )


def _aside(path: Path, clock: Clock) -> Path:
    """A free name beside ``path`` to move it to; nothing is ever deleted."""
    stamp = clock.now().strftime("%Y%m%dT%H%M%SZ")
    candidate = path.with_name(f"{path.name}.unused-{stamp}")
    counter = 1
    while candidate.exists():
        counter += 1
        candidate = path.with_name(f"{path.name}.unused-{stamp}-{counter}")
    return candidate


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# --- talking to the service -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Endpoint:
    host: str
    port: int
    secret: str | None
    run_id: str | None


class _Http:
    """One HTTP request at a time to the local API: no cookies, no state, no redirects."""

    def __init__(self, endpoint: _Endpoint, timeout: float) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        query: Mapping[str, Any] | None = None,
        token: str | None = None,
        headers: Mapping[str, str] | None = None,
        sink: Callable[[bytes], None] | None = None,
    ) -> tuple[int, Any]:
        """``(status, parsed JSON or None)``. With ``sink`` a 2xx body is streamed to it."""
        target = "/api/v1" + path
        if query:
            pairs = [
                (name, item)
                for name, value in query.items()
                if value is not None
                for item in (value if isinstance(value, list | tuple) else [value])
            ]
            target += "?" + urllib.parse.urlencode(
                [
                    (name, str(item).lower() if isinstance(item, bool) else item)
                    for name, item in pairs
                ]
            )
        send: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": f"portlock-cli/{__version__}",
        }
        if token is not None:
            send["Authorization"] = f"Bearer {token}"
        payload: bytes | None = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            send["Content-Type"] = "application/json"
        send.update(headers or {})
        connection = http.client.HTTPConnection(
            self.endpoint.host, self.endpoint.port, timeout=self.timeout
        )
        try:
            connection.request(method, target, body=payload, headers=send)
            response = connection.getresponse()
            if sink is not None and 200 <= response.status < 300:
                while chunk := response.read(65536):
                    sink(chunk)
                return response.status, None
            raw = response.read(_MAX_RESPONSE)
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            raise _Failure(
                EXIT_UNREACHABLE,
                f"the service at {self.endpoint.host}:{self.endpoint.port} did not answer "
                f"({type(exc).__name__})",
            ) from None
        finally:
            connection.close()
        if not raw:
            return status, None
        try:
            return status, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _Failure(
                EXIT_UNREACHABLE, "the service answered with something that is not JSON"
            ) from None


class _Service:
    """A verified, logged-in connection to the service."""

    def __init__(
        self,
        http_client: _Http,
        token: str | None,
        password: str | None,
        secret: str | None = None,
    ) -> None:
        self.http = http_client
        self.token = token
        self.password = password
        # The runtime file's secret: a request that carries it is the elevated local
        # command line, whose credential checks the network lockout never refuses.
        self.secret = secret
        self.ping: dict[str, Any] = {}

    def call(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        query: Mapping[str, Any] | None = None,
        local: bool = False,
    ) -> Any:
        """One call. ``local`` also presents the secret, for a call that checks a credential."""
        headers = {CLI_SECRET_HEADER: self.secret} if local and self.secret else None
        status, data = self.http.request(
            method, path, body=body, query=query, token=self.token, headers=headers
        )
        if 200 <= status < 300:
            return data
        error = (data or {}).get("error") if isinstance(data, dict) else None
        if not isinstance(error, dict):
            raise _Failure(EXIT_FAILED, f"the service answered HTTP {status}")
        raise _ApiFailure(
            status, str(error.get("code")), str(error.get("message")), error.get("details")
        )

    def download(self, path: str, query: Mapping[str, Any], sink: Callable[[bytes], None]) -> None:
        status, data = self.http.request("GET", path, query=query, token=self.token, sink=sink)
        if not 200 <= status < 300:
            error = (data or {}).get("error") if isinstance(data, dict) else None
            code = str(error.get("code")) if isinstance(error, dict) else "error"
            message = str(error.get("message")) if isinstance(error, dict) else f"HTTP {status}"
            raise _ApiFailure(status, code, message, None)


# --- the commands -----------------------------------------------------------------------


def _auth_policy(config: Config) -> AuthPolicy:
    """The account policy the daemon builds from ``config.auth`` (kept in step with it)."""
    from datetime import timedelta

    auth = config.auth
    return AuthPolicy(
        scrypt=ScryptParams(n=auth.scrypt_n),
        min_password_length=auth.min_password_length,
        lockout_threshold=auth.lockout_threshold,
        lockout_base=timedelta(seconds=auth.lockout_base_seconds),
        lockout_max=timedelta(seconds=auth.lockout_max_seconds),
        max_network_verifications=auth.max_concurrent_verifications,
    )


@dataclass(slots=True)
class _Local:
    """The database and the stores a local command works on (no service involved)."""

    db: Database
    audit_log: AuditLog
    writer: AuditWriter
    accounts: AccountStore
    initial_key: str | None = None


class _Cli:
    """The commands. One instance per ``main`` call; ``self.env`` is everything outside."""

    def __init__(self, env: CliEnv) -> None:
        self.env = env

    # --- output ----------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        self.env.out().write(text + "\n")

    def warn(self, text: str) -> None:
        self.env.err().write(_text(text) + "\n")

    def emit(self, args: argparse.Namespace, data: Any, render: Callable[[Any], None]) -> None:
        """``--json``: the API's answer unchanged; otherwise ``render`` it."""
        if args.json:
            self.say(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True))
        else:
            render(data)

    # --- configuration, service, login -----------------------------------------------

    def config(self, args: argparse.Namespace) -> Config:
        path = args.config or self.env.environ.get("PORTLOCK_CONFIG")
        try:
            return load_config(
                path,
                env=self.env.environ,
                platform=self.env.host_platform,
                elevated=self.env.is_elevated(),
            )
        except ConfigError as exc:
            raise _Failure(EXIT_FAILED, f"configuration: {exc.message}") from None

    def _endpoint(self, args: argparse.Namespace, config: Config) -> _Endpoint:
        url = args.url or self.env.environ.get("PORTLOCK_URL")
        if url:
            parts = urllib.parse.urlsplit(url)
            try:
                port = parts.port
            except ValueError:
                port = None
            if parts.scheme != "http" or not parts.hostname or port is None:
                raise _Failure(EXIT_USAGE, "--url must look like http://127.0.0.1:47600")
            if not _is_loopback(parts.hostname):
                raise _Failure(
                    EXIT_USAGE,
                    "refusing to send credentials in clear text to a non-loopback address",
                )
            return _Endpoint(parts.hostname, port, None, None)
        data = read_runtime_file(config.paths.state_dir)
        if data is None:
            raise _Failure(
                EXIT_UNREACHABLE,
                f"the service is not running (no {RUNTIME_FILE_NAME} in {config.paths.state_dir})",
            )
        if not _is_loopback(data["host"]) or not 0 < data["port"] < 65536:
            raise _Failure(
                EXIT_UNREACHABLE, f"{RUNTIME_FILE_NAME} does not name a loopback address"
            )
        return _Endpoint(data["host"], data["port"], data["secret"], data["run_id"])

    def _verify(self, http_client: _Http, endpoint: _Endpoint) -> dict[str, Any]:
        """Check that the listener is the PortLock service before anything secret is sent."""
        if endpoint.secret is None:
            status, data = http_client.request("GET", "/ping")
            if status != 200 or not isinstance(data, dict) or data.get("service") != "portlock":
                raise _Failure(EXIT_UNREACHABLE, "the address does not answer as PortLock")
            self.warn(
                f"note: {endpoint.host}:{endpoint.port} was named with --url, so its identity "
                "cannot be checked"
            )
            return data
        challenge = secrets.token_hex(16)
        status, data = http_client.request("GET", "/ping", headers={CHALLENGE_HEADER: challenge})
        proof = data.get("proof") if isinstance(data, dict) else None
        expected = ping_proof(endpoint.secret, challenge)
        if (
            status != 200
            or not isinstance(data, dict)
            or data.get("run_id") != endpoint.run_id
            or not isinstance(proof, str)
            or not hmac.compare_digest(proof, expected)
        ):
            raise _Failure(
                EXIT_UNREACHABLE,
                "the program listening on the service's port did not prove that it is this "
                "installation's PortLock service; no credentials were sent",
            )
        # The proof answered one random challenge; it is not part of what the service reports.
        return {name: value for name, value in data.items() if name != "proof"}

    def _secret(self, args: argparse.Namespace, prompt: str) -> str:
        """A password or code: one line of standard input with ``--password-stdin``, else
        a hidden prompt. Never an argument or the environment."""
        if args.password_stdin:
            line = self.env.inp().readline()
            if not line:
                raise _Failure(EXIT_USAGE, "no secret was given on standard input")
            return line.rstrip("\r\n")
        if not self.env.is_tty():
            raise _Failure(EXIT_USAGE, "there is no terminal to ask on; use --password-stdin")
        return self.env.getpass(prompt)

    def _ask(self, prompt: str) -> str:
        err = self.env.err()
        err.write(prompt)
        err.flush()
        return self.env.inp().readline().strip()

    def _username(self, args: argparse.Namespace) -> str:
        name = args.user or self.env.environ.get("PORTLOCK_USER")
        if name:
            return name
        if not self.env.is_tty():
            raise _Failure(EXIT_USAGE, "give the user name with --user or PORTLOCK_USER")
        name = self._ask("User name: ")
        if not name:
            raise _Failure(EXIT_USAGE, "no user name was given")
        return name

    @contextmanager
    def service(self, args: argparse.Namespace, *, login: bool = True) -> Iterator[_Service]:
        """A verified connection, logged in unless ``login`` is False, logged out after."""
        config = self.config(args)
        endpoint = self._endpoint(args, config)
        http_client = _Http(endpoint, args.timeout)
        ping = self._verify(http_client, endpoint)
        if not login:
            svc = _Service(http_client, None, None)
            svc.ping = ping
            yield svc
            return
        name = self._username(args)
        password = self._secret(args, f"Password for {_text(name)}: ")
        headers = {CLI_SECRET_HEADER: endpoint.secret} if endpoint.secret else None
        status, data = http_client.request(
            "POST", "/auth/login", body={"username": name, "password": password}, headers=headers
        )
        if status != 200 or not isinstance(data, dict):
            error = (data or {}).get("error") if isinstance(data, dict) else None
            if isinstance(error, dict):
                raise _ApiFailure(
                    status, str(error.get("code")), str(error.get("message")), error.get("details")
                )
            raise _Failure(EXIT_AUTH, f"the login was refused (HTTP {status})")
        token = str(data["token"])
        svc = _Service(http_client, token, password, endpoint.secret)
        svc.ping = ping
        try:
            yield svc
        finally:
            with contextlib.suppress(_Failure):
                http_client.request("POST", "/auth/logout", token=token)

    # --- local stores ----------------------------------------------------------------

    def _open_local(
        self, config: Config, *, initial: Path | None = None, create: bool = False
    ) -> _Local:
        """Open the database and the stores without the service (``actor`` local-console)."""
        from datetime import timedelta

        clock = self.env.clock
        state_dir = Path(config.paths.state_dir)
        db_path = Path(config.paths.database_file)
        if not db_path.exists() and not create:
            raise _Failure(
                EXIT_FAILED, f"there is no database at {db_path}; run '{self.env.program} init'"
            )
        db = Database(db_path)
        try:
            initial_key: str | None = None
            key_store: AuditKeyStore | None = None
            key_path = initial if initial is not None else config.audit.hmac_key_file
            head_path = state_dir / HEAD_FILE_NAME
            if key_path is not None:
                if Path(key_path).exists():
                    key_store = AuditKeyStore(key_path)
                elif initial is not None:
                    head_seq = AuditLog(db, clock=clock).head()[0]
                    key_store, key = AuditKeyStore.create(initial, anchor_seq=head_seq)
                    initial_key = key.encode()
            log = AuditLog(db, clock=clock, key_store=key_store, head_path=head_path)
            writer = AuditWriter(log, bus=EventBus(clock), clock=clock)
            sessions = SessionStore(
                db,
                clock=clock,
                idle_timeout=timedelta(minutes=config.api.session_idle_minutes),
                absolute_timeout=timedelta(hours=config.api.session_max_hours),
            )
            accounts = AccountStore(
                db,
                clock=clock,
                audit=writer.auth_hook,
                policy=_auth_policy(config),
                sessions=sessions,
            )
        except BaseException:
            db.close()
            raise
        return _Local(db, log, writer, accounts, initial_key)

    # --- init, run, stop, recover ----------------------------------------------------

    def cmd_init(self, args: argparse.Namespace) -> int:
        """Set PortLock up: the first administrator, recovery codes, the audit key.

        Nothing is created until an acceptable password is in hand, so a mistyped or
        refused password leaves nothing behind that would cost the next ``init`` its
        audit verification key.
        """
        config = self.config(args)
        prog = self.env.program
        posture = self._posture(config)
        for notice in self._installation_notices(config, posture):
            self.say(notice)
        state_dir, config_dir = Path(config.paths.state_dir), Path(config.paths.config_dir)
        key_path = config.audit.hmac_key_file
        target = Path(args.config) if args.config else Path(config.paths.config_file)
        lock = InstanceLock(state_dir / LOCK_FILE_NAME)
        held = state_dir.is_dir() and lock.acquire()
        try:
            if Path(config.paths.database_file).exists():
                existing = self._open_local(config)
                try:
                    set_up = existing.accounts.has_users()
                finally:
                    existing.db.close()
                if set_up:
                    raise _Failure(
                        EXIT_FAILED,
                        "PortLock is already set up; init only creates the first administrator "
                        f"(use '{prog} user reset-password NAME --local' for a lost password)",
                    )
            # A key store with no administrator was never handed over: its initial key was
            # not shown (a failed init of an older PortLock, or `run` before `init`). It is
            # set aside, never deleted, and a new one is made whose key is shown below.
            stale_key = key_path is not None and Path(key_path).exists()
            if stale_key and not held:
                raise _Failure(
                    EXIT_FAILED,
                    f"a PortLock service is running in {state_dir} without an administrator; "
                    f"stop it first ('{prog} stop'), then run '{prog} init' again",
                )
            name = (
                args.username
                or (self._ask("Administrator user name [admin]: ") if self.env.is_tty() else "")
                or "admin"
            )
            password = self._new_password(args, config, name, again=f"{prog} init")
            # From here on there is an acceptable password: create everything.
            ensure_private_dir(state_dir)
            ensure_private_dir(config_dir)
            notes: list[str] = []
            if key_path is None:
                if target.exists():
                    notes.append(
                        f"{target} sets no audit.hmac_key_file, so the audit log is chained but "
                        f"carries no MACs. Add [audit] hmac_key_file = <path> and run '{prog} "
                        "init' on a new state directory to get a verification key."
                    )
                else:
                    key_path = state_dir / "audit.key"
                    config = dataclasses.replace(
                        config, audit=AuditConfig(hmac_key_file=key_path, sinks=config.audit.sinks)
                    )
                    atomic_write_text(target, config_to_toml(config), private=False)
                    notes.append(f"wrote {target}")
            elif stale_key:
                aside = _aside(Path(key_path), self.env.clock)
                os.replace(key_path, aside)
                notes.append(f"an audit key store whose key was never shown was moved to {aside}")
            local = self._open_local(
                config, initial=Path(key_path) if key_path else None, create=True
            )
            try:
                user = local.accounts.create_user(name, password, Role.ADMIN, actor="local-console")
                codes = local.accounts.generate_recovery_codes(user.username, actor="local-console")
                initial_key = local.initial_key
            finally:
                local.db.close()
        finally:
            if held:
                lock.release()
        self.say("PortLock is set up.")
        for note in notes:
            self.say(f"  {note}")
        self.say(f"Administrator: {_text(user.username)}")
        if initial_key is not None:
            self.say("")
            self.say("Audit verification key. Keep it offline: it is shown only now.")
            self.say(f"  {initial_key}")
            self.say(f"  Later: {prog} audit verify --offline --key-file FILE (the key in FILE)")
        else:
            self.say("No audit verification key was shown (no new key store was created).")
        self.say("")
        self.say("Recovery codes. Each works once; they are shown only now. Store them offline.")
        for code in codes:
            self.say(f"  {code}")
        self.say("")
        self.say(f"State: {config.paths.state_dir}")
        self.say(f"Configuration: {config.paths.config_dir}")
        if posture.watch_only:
            self.say(
                "This PortLock is watch-only: it will show and record your USB devices and "
                "change nothing on this computer outside its own folder."
            )
        self.say("")
        self.say("Next:")
        self.say(f"  {prog} run      start PortLock and print the console address")
        self.say(f"  {prog} doctor   what this machine can and cannot enforce")
        self.say(f"  {prog} stop     stop it again (or press Ctrl+C where it runs)")
        if not posture.watch_only:
            self.say(f"  {prog} enroll CONNECTION_ID   protect your own keyboard and mouse")
            self.say(f"  {prog} service print-unit     a hardened service definition to review")
        return EXIT_OK

    def _posture(self, config: Config) -> Posture:
        """The watch-only posture of a service started with ``config`` by this user."""
        return detect_posture(
            config,
            elevated=self.env.is_elevated(),
            env=self.env.environ,
            platform=self.env.host_platform,
        )

    def _installation_notices(self, config: Config, posture: Posture) -> list[str]:
        """Plain words about which installation this window uses, before anything else."""
        notices: list[str] = []
        other = self._system_wide_elsewhere(config)
        if other is not None:
            notices.append(
                f"Note: this computer also has a system-wide PortLock installation ({other}). "
                "This window is not run as administrator, so this command uses a separate, "
                f"per-user installation that only watches ({config.paths.state_dir}). To use "
                "the system-wide one, open a window as administrator."
            )
        if self.env.is_elevated():
            if posture.watch_only:
                notices.append(
                    "This window runs as administrator, but PortLock's files are in this "
                    "user's own folders, so it stays watch-only and blocks nothing."
                )
            else:
                notices.append(
                    "This window runs as administrator, so this is the system-wide PortLock "
                    f"installation ({config.paths.state_dir}), which can block USB devices. A "
                    "window that is not run as administrator uses a separate, per-user "
                    "installation that only watches."
                )
        return notices

    def _system_wide_elsewhere(self, config: Config) -> Path | None:
        """The system-wide installation an ordinary user is not using, if one exists."""
        if self.env.is_elevated():
            return None
        environ = {
            name: value for name, value in self.env.environ.items() if name.upper() != HOME_ENV
        }
        try:
            system = default_config(platform=self.env.host_platform, env=environ, elevated=True)
        except ConfigError:
            return None
        if Path(system.paths.state_dir) == Path(config.paths.state_dir):
            return None
        for candidate in (Path(system.paths.config_file), Path(system.paths.state_dir)):
            with contextlib.suppress(OSError):
                if candidate.exists():
                    return candidate
        return None

    def _running(self, state_dir: Path) -> bool:
        """True if a service holds this state directory's instance lock right now."""
        lock_path = state_dir / LOCK_FILE_NAME
        if not lock_path.is_file():
            return False
        probe = InstanceLock(lock_path)
        if probe.acquire():
            probe.release()
            return False
        return True

    def _not_running(self, config: Config) -> _Failure:
        message = "the service is not running"
        other = self._system_wide_elsewhere(config)
        if other is not None:
            message += (
                f" (in this user's installation, {config.paths.state_dir}). A system-wide "
                f"installation exists in {other}: open a window as administrator to reach it"
            )
        return _Failure(EXIT_UNREACHABLE, message)

    def _announce(self, runtime: Any, host: str, port: int) -> None:
        """Print, once the service is up, what it is doing and where its console is."""
        prog = self.env.program
        if runtime.watch_only:
            self.say(
                "PortLock is running in WATCH-ONLY mode: it shows and records your USB "
                "devices and changes nothing on this computer outside its own folder."
            )
        else:
            mode = runtime.service.get_mode().effective_mode.value
            self.say(f"PortLock is running in {mode} mode.")
        has_users = True
        with contextlib.suppress(PortLockError):
            has_users = bool(runtime.accounts.has_users())
        if port:
            shown = f"[{host}]" if ":" in host else host
            self.say("")
            self.say(f"  Open the console in your web browser:  http://{shown}:{port}/")
            self.say("")
            if has_users:
                self.say("  Sign in with the administrator name and password you chose at init.")
        else:
            self.say("  No console is listening.")
        if not has_users:
            self.say(
                f"  No administrator exists yet: run '{prog} init' in another window first, "
                "then sign in with the name and password you choose there."
            )
        self.say(f"  To stop it: press Ctrl+C here, or run '{prog} stop' in another window.")
        with contextlib.suppress(OSError, ValueError):
            self.env.out().flush()

    def _new_password(
        self, args: argparse.Namespace, config: Config, name: str, *, again: str
    ) -> str:
        """A new password that satisfies the policy, asked for (twice) at a terminal.

        ``again`` is the command that tries once more; every refusal names it.
        """
        minimum = config.auth.min_password_length
        advice = (
            f"nothing was changed. Run '{again}' again and choose a password of at least "
            f"{minimum} characters that is not easy to guess (a few unrelated words work well)"
        )
        for _attempt in range(3):
            password = self._secret(args, "New administrator password: ")
            problems = check_password_policy(password, min_length=minimum, username=name)
            if problems:
                if args.password_stdin or not self.env.is_tty():
                    raise _Failure(
                        EXIT_FAILED,
                        "the password is not acceptable: " + "; ".join(problems) + "; " + advice,
                    )
                self.warn("That password is not acceptable: " + "; ".join(problems))
                continue
            if not args.password_stdin and self.env.getpass("Repeat it: ") != password:
                self.warn("The two entries differ.")
                continue
            return password
        raise _Failure(EXIT_FAILED, "no acceptable password was given; " + advice)

    def cmd_run(self, args: argparse.Namespace) -> int:
        config = self.config(args)
        posture = self._posture(config)
        for notice in self._installation_notices(config, posture):
            self.say(notice)
        options = dict(self.env.run_options)
        options.setdefault("announce", self._announce)
        options.setdefault("elevated", self.env.is_elevated())
        options.setdefault("env", self.env.environ)
        options.setdefault("program", self.env.program)
        options.setdefault("config_file", self._config_source(args, config))
        return int(self.env.run_service(config, api_factory=api_factory, **options))

    def _config_source(self, args: argparse.Namespace, config: Config) -> Path:
        """The configuration file this command reads (or would read)."""
        named = args.config or self.env.environ.get("PORTLOCK_CONFIG")
        return Path(named) if named else Path(config.paths.config_file)

    def cmd_stop(self, args: argparse.Namespace) -> int:
        config = self.config(args)
        state_dir = Path(config.paths.state_dir)
        if not self._running(state_dir):
            # Nobody holds the instance lock: a runtime file is what a killed service left.
            with contextlib.suppress(OSError):
                (state_dir / RUNTIME_FILE_NAME).unlink()
            raise self._not_running(config)
        if read_runtime_file(state_dir) is None:
            raise _Failure(EXIT_UNREACHABLE, "the service is still starting; try again in a moment")
        request_stop(state_dir)
        deadline = self.env.monotonic() + _STOP_WAIT_SECONDS
        while read_runtime_file(state_dir) is not None:
            if self.env.monotonic() >= deadline:
                raise _Failure(
                    EXIT_FAILED,
                    f"the service did not stop within {int(_STOP_WAIT_SECONDS)} seconds",
                )
            self.env.sleep(0.2)
        self.say("The service stopped.")
        return EXIT_OK

    def cmd_recover(self, args: argparse.Namespace) -> int:
        """Restore every journaled operating-system setting. Needs no service, no
        database and no PortLock login: only the journal file and administrator rights."""
        config = self.config(args)
        state_dir = Path(config.paths.state_dir)
        clock = self.env.clock
        journal_path = state_dir / JOURNAL_FILE_NAME
        if args.dry_run:
            journal = RecoveryJournal(journal_path, clock=clock)
            records = journal.open_records()
            self.say(
                f"{len(records)} open journal record(s) in {journal_path}; nothing was changed."
            )
            for record in records:
                entry = record.entry
                what = "hold" if entry is None else f"{entry.kind} {entry.target}"
                self.say(f"  {record.id}  {record.action.value:<16} {_text(what)}")
            return EXIT_OK
        if paths_per_user(config.paths, platform=self.env.host_platform, env=self.env.environ):
            # DESIGN 14.28: any program this user runs can write a per-user journal, and an
            # elevated recover would apply it with the real enforcer. A per-user PortLock
            # is watch-only and never changed anything, so there is nothing to recover.
            raise _Failure(
                EXIT_FAILED,
                f"recover does not act on {state_dir}: it is in this user's own folders (or "
                "not provably a system-wide location), which any program this user runs "
                "could change, so its journal cannot be trusted with administrator rights. "
                "A PortLock kept there is watch-only and never changed this computer. "
                "Nothing was changed.",
            )
        kill_switch = Path(config.paths.kill_switch_file)
        lock = InstanceLock(state_dir / LOCK_FILE_NAME)
        running = not lock.acquire()
        if args.dead_man and running:
            # The timer is the backstop for a service that died. This one is alive and ends
            # its own lockdown (and its commit-confirm windows) on its next tick; writing
            # the kill-switch file now would switch enforcement off for good.
            self.say("The service is running: it ends the lockdown itself. Nothing was changed.")
            return EXIT_OK
        try:
            journal = RecoveryJournal(journal_path, clock=clock)
            enforcer = self.env.create_enforcer(config, journal.write_ahead)
            # Administrator rights are checked before anything is written. Creating the
            # kill-switch file is itself what switches enforcement off, so a caller who
            # is about to be refused must not get as far as creating it.
            if not enforcer.capabilities().privileged:
                raise _Failure(
                    EXIT_AUTH,
                    f"'{self.env.program} recover' needs administrator (root) rights: run it "
                    "in a window opened as administrator. Nothing was changed.",
                )
            if not args.dead_man:
                ensure_private_dir(kill_switch.parent)
                atomic_write_bytes(kill_switch, b"created by 'portlock recover'\n", private=True)
            if running:
                return self._recover_through_service(journal_path, kill_switch)
            live = SafeEnforcer(enforcer, lambda: SafetyContext(), dry_run=False)
            try:
                devices = self.env.create_backend(config, clock).enumerate()
            except PortLockError as exc:
                self.warn(f"devices could not be listed ({exc.message}); recovering anyway")
                devices = []
            timer: ExternalTimer | None
            try:
                timer = self.env.create_timer(config)
            except PortLockError as exc:
                self.warn(f"the dead-man timer could not be reached ({exc.message})")
                timer = None
            report = recover(
                state_dir,
                live,
                devices,
                clock=clock,
                is_admin=lambda: bool(enforcer.capabilities().privileged),
                timer=timer,
                reason="recover",
            )
        except PortLockError as exc:
            raise _Failure(
                EXIT_AUTH if exc.code == "not_privileged" else EXIT_FAILED, exc.message
            ) from None
        finally:
            lock.release()
        self.say(
            f"Recovered: {report.restored} setting(s) restored, {report.released} hold(s) "
            f"released, {report.readmitted} device(s) readmitted, {len(report.failed)} failed."
        )
        for target, reason in report.failed:
            self.say(f"  could not restore {_text(target)}: {_text(reason)}")
        if args.dead_man:
            # No kill switch: the next start finds the marker, ends the lockdown it
            # describes as recovered and enforces again.
            self.say("Enforcement is not disabled; the service resumes it when it starts.")
        else:
            self._after_recover(kill_switch)
        return EXIT_FAILED if report.failed else EXIT_OK

    def _recover_through_service(self, journal_path: Path, kill_switch: Path) -> int:
        """A running service honours the kill-switch file within a tick and restores itself."""
        self.say("The service is running: the kill-switch file was created and it will restore.")
        deadline = self.env.monotonic() + _RECOVER_WAIT_SECONDS
        while True:
            if not RecoveryJournal(journal_path, clock=self.env.clock).open_records():
                self.say("The journal is empty: every setting was restored.")
                self._after_recover(kill_switch)
                return EXIT_OK
            if self.env.monotonic() >= deadline:
                break
            self.env.sleep(0.2)
        self.warn(
            "the service did not empty the journal in time: stop the PortLock process, then "
            f"run '{self.env.program} recover' again"
        )
        return EXIT_FAILED

    def _after_recover(self, kill_switch: Path) -> None:
        self.say(f"Enforcement stays disabled while {kill_switch} exists. To enforce again:")
        self.say(f"  delete that file, then restart the service ({_text(kill_switch)}).")

    # --- simulate, service definitions -----------------------------------------------

    def cmd_simulate(self, args: argparse.Namespace) -> int:
        return int(run_simulation(args, stdin=self.env.inp(), out=self.env.out()))

    def cmd_service(self, args: argparse.Namespace) -> int:
        unit = args.service_command == "print-unit"
        target = "linux" if unit else "win32"
        host = self.env.host_platform
        on_target = host.startswith("linux") if unit else host == "win32"
        if args.config and Path(args.config).is_file():
            config = self.config(args)
        elif on_target:
            # --config only says where the file will be: it need not exist yet.
            config = default_config(platform=target, env=self.env.environ)
        else:
            config = default_config(platform=target, env={})
            self.warn(
                f"note: this is not a {'Linux' if unit else 'Windows'} machine, so the "
                f"definition uses the {'Linux' if unit else 'Windows'} default directories"
            )
        if args.executable:
            argv: tuple[str, ...] = (args.executable,)
        elif on_target:
            argv = self.env.executable or (sys.executable, "-I", "-m", "portlock")
        else:
            raise _Failure(EXIT_USAGE, "--executable is required when printing for another system")
        try:
            if unit:
                text = install.systemd_unit(config, executable=argv, config_file=args.config)
            else:
                text = install.windows_task_xml(config, executable=argv, config_file=args.config)
        except ConfigError as exc:
            raise _Failure(EXIT_FAILED, exc.message) from None
        if args.output:
            path = Path(args.output)
            if path.exists() and not args.force:
                raise _Failure(EXIT_FAILED, f"{path} exists; use --force to replace it")
            data = text.encode("utf-8") if unit else b"\xff\xfe" + text.encode("utf-16-le")
            path.write_bytes(data)
            self.say(f"Wrote {path}. Nothing was installed.")
            self.warn(install.install_instructions(target))
        else:
            self.env.out().write(text)
            self.warn(install.install_instructions(target))
        return EXIT_OK

    # --- status, doctor ----------------------------------------------------------------

    def cmd_status(self, args: argparse.Namespace) -> int:
        if not (args.url or self.env.environ.get("PORTLOCK_URL")):
            config = self.config(args)
            if not self._running(Path(config.paths.state_dir)):
                # No service holds the lock: a runtime file is a killed service's leftover.
                raise self._not_running(config)
        with self.service(args, login=args.detail) as svc:
            ping = svc.ping
            detail = svc.call("GET", "/status") if args.detail else None

        def render(data: Any) -> None:
            self.say(
                f"PortLock {_text(ping.get('version'))} is running "
                f"(run {_text(ping.get('run_id'))})"
            )
            if ping.get("simulation"):
                self.say("  SIMULATION: this is a simulated machine, not a real one")
            if ping.get("setup_required"):
                self.say(f"  no administrator exists yet: run '{self.env.program} init'")
            if data:
                mode, lock, counts = data["mode"], data["lockdown"], data["counts"]
                if mode.get("watch_only"):
                    self.say(
                        "  WATCH-ONLY: it shows and records, and changes nothing on this "
                        "computer outside its own folder"
                    )
                    if mode.get("watch_only_reason"):
                        self.say(f"  why: {_text(mode['watch_only_reason'])}")
                self.say(
                    f"  mode: {mode['effective_mode']} (chosen {mode['mode']}, {mode['source']})"
                )
                if lock and lock.get("active"):
                    self.say(
                        f"  LOCKDOWN active until {_when(lock.get('expires_at'))} "
                        f"({lock.get('remaining_seconds')} s left)"
                    )
                self.say(
                    "  devices: "
                    + ", ".join(f"{count} {name}" for name, count in counts.items() if count)
                    or "  devices: none"
                )
                if data.get("degraded"):
                    self.say("  DEGRADED: " + ", ".join(data["degraded"]))

        self.emit(args, detail if detail is not None else ping, lambda _data: render(detail))
        return EXIT_OK

    def cmd_doctor(self, args: argparse.Namespace) -> int:
        report: dict[str, Any] | None = None
        if not args.offline:
            try:
                with self.service(args) as svc:
                    report = svc.call("GET", "/doctor")
            except _Failure as exc:
                if exc.code != EXIT_UNREACHABLE:
                    raise
                self.warn(f"{exc.message}; checking this machine directly")
        if report is None:
            config = self.config(args)
            # A watch-only process has nothing to learn from probing the enforcement
            # mechanisms, and probing on Windows runs icacls: the doctor skips it.
            report = factory.doctor(
                config, clock=self.env.clock, posture=self._posture(config)
            ).to_dict()

        def render(data: Any) -> None:
            for check in data["checks"]:
                self.say(f"[{check['status']:<4}] {check['id']}: {_text(check['summary'])}")
                if check.get("detail"):
                    self.say(f"         {_text(check['detail'])}")

        self.emit(args, report, render)
        return EXIT_CHECK if any(c["status"] == "fail" for c in report["checks"]) else EXIT_OK

    # --- devices, approvals, trust, grants ---------------------------------------------

    def cmd_devices(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            if args.known:
                data = svc.call(
                    "GET", "/devices/known", query={"limit": args.limit, "text": args.text}
                )
                key = "devices"
            elif args.history:
                data = svc.call("GET", "/devices/history", query={"limit": args.limit})
                key = "connections"
            else:
                data = svc.call("GET", "/devices", query={"state": args.state})
                key = "devices"

        def render(payload: Any) -> None:
            items = payload[key]
            if not items:
                self.say("no devices")
                return
            if args.known:
                rows = [
                    [
                        item["fingerprint"],
                        item["confidence"],
                        item.get("trust") or "-",
                        "yes" if item["connected"] else "no",
                        item["display_name"],
                    ]
                    for item in items
                ]
                self.say(_table(("FINGERPRINT", "CONF", "TRUST", "HERE", "DEVICE"), rows))
            else:
                self.say(_table(_CONNECTION_HEADERS, [_connection_row(item) for item in items]))
                waiting = [i["connection_id"] for i in items if i.get("state") == "pending"]
                if waiting:
                    self.say(
                        f"{chr(10)}{len(waiting)} waiting for a decision: "
                        f"{self.env.program} approve ID | {self.env.program} deny ID"
                    )

        self.emit(args, data, render)
        return EXIT_OK

    def _show_grant(self, data: Mapping[str, Any]) -> None:
        grant = data["grant"]
        until = f" until {_when(grant['expires_at'])}" if grant.get("expires_at") else ""
        self.say(
            f"{grant['kind']} grant {grant['id']}{until}"
            f"{' (read-only)' if grant['read_only'] else ''} for {grant['fingerprint']}"
        )
        if data.get("connection"):
            view = data["connection"]
            self.say(f"  device {view['connection_id']} is now {view['state']}")
            for reason in (view.get("decision") or {}).get("reasons", [])[:2]:
                self.say(f"    {_text(reason)}")

    def cmd_approve(self, args: argparse.Namespace) -> int:
        body: dict[str, Any] = {"kind": args.kind, "read_only": args.read_only, "note": args.note}
        if args.duration:
            body["expires_in"] = args.duration
        with self.service(args) as svc:
            data = svc.call("POST", f"/connections/{args.connection_id}/approve", body=body)
        self.emit(args, data, self._show_grant)
        return EXIT_OK

    def cmd_deny(self, args: argparse.Namespace) -> int:
        body = {"eject": args.eject, "note": args.note}
        with self.service(args) as svc:
            data = svc.call("POST", f"/connections/{args.connection_id}/deny", body=body)

        def render(payload: Any) -> None:
            view = payload["connection"]
            self.say(
                f"device {view['connection_id']} is {view['state']}: {_text(view['display_name'])}"
            )
            if payload.get("eject") and not payload["eject"]["ok"]:
                self.say(f"  it could not be ejected: {_text(payload['eject']['error'])}")

        self.emit(args, data, render)
        return EXIT_OK

    def cmd_trust(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            if args.list or not args.fingerprint:
                data = svc.call("GET", "/trust")

                def render_list(payload: Any) -> None:
                    rows = [
                        [
                            g["id"],
                            g["fingerprint"],
                            "read-only" if g["read_only"] else "full",
                            g["note"],
                        ]
                        for g in payload["trust"]
                    ]
                    self.say(
                        _table(("GRANT", "FINGERPRINT", "ACCESS", "NOTE"), rows)
                        if rows
                        else "no trusted devices"
                    )

                self.emit(args, data, render_list)
                return EXIT_OK
            body = {
                "fingerprint": args.fingerprint,
                "read_only": args.read_only,
                "note": args.note,
            }
            data = svc.call("POST", "/trust", body=body)
        self.emit(args, data, self._show_grant)
        return EXIT_OK

    def cmd_grant(self, args: argparse.Namespace) -> int:
        body: dict[str, Any] = {
            "fingerprint": args.fingerprint,
            "kind": args.kind,
            "read_only": args.read_only,
            "note": args.note,
        }
        if args.duration:
            body["expires_in"] = args.duration
        if args.allow_low_confidence:
            body["allow_low_confidence"] = True
        with self.service(args) as svc:
            data = svc.call("POST", "/grants", body=body)
        self.emit(args, data, self._show_grant)
        return EXIT_OK

    def cmd_revoke(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            data = svc.call("DELETE", f"/grants/{args.grant_id}")
        self.emit(
            args, data, lambda d: self.say(f"revoked {d['grant']['kind']} grant {d['grant']['id']}")
        )
        return EXIT_OK

    def cmd_enroll(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            if args.remove:
                query = {"bus_path": args.port}
                data = svc.call("DELETE", f"/enrolments/{args.remove}", query=query)
                self.emit(args, data, lambda d: self.say(f"removed {d['removed']} enrolment(s)"))
            elif args.connection_id is not None:
                body: dict[str, Any] = {"connection_id": args.connection_id}
                if args.label:
                    body["label"] = args.label
                data = svc.call("POST", "/enrolments", body=body)
                self.emit(
                    args,
                    data,
                    lambda d: self.say(
                        f"enrolled {d['enrolment']['fingerprint']} on port "
                        f"{_text(d['enrolment']['bus_path'])}: it stays protected there"
                    ),
                )
            else:
                data = svc.call("GET", "/enrolments")

                def render(payload: Any) -> None:
                    rows = [
                        [
                            e["fingerprint"],
                            e["bus_path"],
                            e.get("label") or "-",
                            _when(e["enrolled_at"]),
                        ]
                        for e in payload["enrolments"]
                    ]
                    self.say(
                        _table(("FINGERPRINT", "PORT", "LABEL", "ENROLLED"), rows)
                        if rows
                        else "no enrolments"
                    )

                self.emit(args, data, render)
        return EXIT_OK

    def cmd_release_port(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            data = svc.call("POST", "/ports/release", body={"port": args.port})
        self.emit(args, data, lambda d: self.say(f"port {_text(args.port)} released"))
        return EXIT_OK

    # --- policy ------------------------------------------------------------------------

    def cmd_policy(self, args: argparse.Namespace) -> int:
        action = args.policy_command
        if action == "init":
            return self._policy_init(args)
        if action == "validate":
            return self._policy_validate(args)
        if action == "test" and args.local:
            return self._policy_test_local(args)
        with self.service(args) as svc:
            if action == "show":
                data = svc.call("GET", "/policy")
                if args.raw:
                    self.say(json.dumps(data["policy"], indent=2, sort_keys=True))
                    return EXIT_OK

                def render(payload: Any) -> None:
                    self.say(
                        f"{_text(payload['name'])}: {payload['rules']} rule(s), source "
                        f"{payload['source']}, hash {payload['hash']}"
                    )
                    for rule in payload["policy"]["rules"]:
                        action_ = rule["action"]
                        self.say(
                            f"  {_text(rule['id'])}: {action_['access']} "
                            f"(scan {action_['scan']}{', alert' if action_['alert'] else ''})"
                            f"{'' if rule['enabled'] else ' [disabled]'}"
                        )
                    default = payload["policy"]["default"]
                    self.say(f"  default: {default['access']}")

                self.emit(args, data, render)
            elif action == "set":
                document = self._load_policy(args.file)
                body: dict[str, Any] = {"policy": document}
                if args.expected_hash:
                    body["expected_hash"] = args.expected_hash
                data = svc.call("PUT", "/policy", body=body)
                self.emit(
                    args,
                    data,
                    lambda d: self.say(
                        f"policy {_text(d['name'])} is active: {d['rules']} rule(s), "
                        f"hash {d['hash']}"
                    ),
                )
            else:
                body = {}
                if args.connection is not None:
                    body["connection_id"] = args.connection
                if args.fingerprint:
                    body["fingerprint"] = args.fingerprint
                if args.device:
                    body["device"] = self._json_argument(args.device)
                if args.file:
                    body["policy"] = self._load_policy(args.file)
                data = svc.call("POST", "/policy/test", body=body)
                self.emit(args, data, self._show_policy_test)
        return EXIT_OK

    def _load_policy(self, path: str) -> dict[str, Any]:
        try:
            return policy_to_dict(load_policy_file(path))
        except PortLockError as exc:
            problems = getattr(exc, "problems", ()) or (exc.message,)
            raise _Failure(
                EXIT_CHECK, "the policy is not valid:\n  " + "\n  ".join(map(_text, problems))
            ) from None

    def _json_argument(self, text: str) -> dict[str, Any]:
        """JSON given inline, or ``@file`` to read it from a file."""
        try:
            raw = Path(text[1:]).read_text(encoding="utf-8") if text.startswith("@") else text
            value = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise _Failure(EXIT_USAGE, f"that is not JSON: {exc}") from None
        if not isinstance(value, dict):
            raise _Failure(EXIT_USAGE, "expected a JSON object")
        return value

    def _policy_init(self, args: argparse.Namespace) -> int:
        text = dump_policy_json(EXAMPLE_POLICY if args.example else DEFAULT_POLICY)
        if args.output:
            path = Path(args.output)
            if path.exists() and not args.force:
                raise _Failure(EXIT_FAILED, f"{path} exists; use --force to replace it")
            path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
            self.say(f"wrote {path}")
        else:
            self.env.out().write(text if text.endswith("\n") else text + "\n")
        return EXIT_OK

    def _policy_validate(self, args: argparse.Namespace) -> int:
        try:
            policy = load_policy_file(args.file)
        except PortLockError as exc:
            problems = getattr(exc, "problems", ()) or (exc.message,)
            self.say("not valid:")
            for problem in problems:
                self.say(f"  {_text(problem)}")
            return EXIT_CHECK
        self.say(
            f"valid: {_text(policy.name)}, {len(policy.rules)} rule(s), hash {policy_hash(policy)}"
        )
        return EXIT_OK

    def _policy_test_local(self, args: argparse.Namespace) -> int:
        """Evaluate a device against a policy file alone (no service, no grants)."""
        from portlock.core.fingerprint import fingerprint as compute_fingerprint
        from portlock.core.models import UsbDevice

        if not args.file or not args.device:
            raise _Failure(EXIT_USAGE, "--local needs --policy FILE and --device JSON")
        policy = load_policy_file(args.file)
        data = self._json_argument(args.device)
        data.setdefault("instance_id", "cli-test/0")
        try:
            device = UsbDevice.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise _Failure(EXIT_USAGE, f"that device is not valid: {exc}") from None
        fingerprint = compute_fingerprint(device)
        result = PolicyEngine(policy).evaluate(device, fingerprint, now=self.env.clock.now())
        rule = result.rule.id if result.rule is not None else "(the policy default)"
        self.say(
            f"{result.action.access.value}: rule {_text(rule)}, scan {result.action.scan.value}"
        )
        return EXIT_OK

    def _show_policy_test(self, data: Mapping[str, Any]) -> None:
        decision = data["decision"]
        self.say(
            f"{decision['access']} (source {decision['source']}), fingerprint {data['fingerprint']}"
        )
        for reason in decision.get("reasons", []):
            self.say(f"  {_text(reason)}")
        for trace in data.get("explain", []):
            self.say(f"  rule {_text(trace['rule_id'])}: {trace['outcome']}")

    # --- audit -------------------------------------------------------------------------

    def cmd_audit(self, args: argparse.Namespace) -> int:
        action = args.audit_command
        if action == "verify" and args.offline:
            return self._audit_verify_offline(args)
        with self.service(args) as svc:
            if action in ("tail", "query"):
                query: dict[str, Any] = {"limit": args.limit}
                if action == "query":
                    query.update(
                        {
                            "type": args.type,
                            "min_severity": args.min_severity,
                            "actor": args.actor,
                            "device_fp": args.device,
                            "since": args.since,
                            "until": args.until,
                            "text": args.text,
                        }
                    )
                data = svc.call("GET", "/audit", query=query)

                def render(payload: Any) -> None:
                    for record in reversed(payload["records"]):
                        self.say(_audit_line(record))
                    if not payload["records"]:
                        self.say("no audit records match")

                self.emit(args, data, render)
            elif action == "verify":
                body: dict[str, Any] = {}
                if args.expected_head:
                    seq, _, digest = args.expected_head.partition(":")
                    if not seq.isdigit() or not digest:
                        raise _Failure(EXIT_USAGE, "--expected-head is SEQ:HASH")
                    body["expected_head"] = {"seq": int(seq), "hash": digest}
                data = svc.call("POST", "/audit/verify", body=body)
                self.emit(args, data, self._show_verify)
                return EXIT_OK if data["ok"] else EXIT_CHECK
            else:
                return self._audit_export(args, svc)
        return EXIT_OK

    def _show_verify(self, data: Mapping[str, Any]) -> None:
        if data["ok"]:
            self.say(f"the audit log verifies: {data['checked']} record(s) checked")
            if not data.get("macs_checked"):
                self.say("  no MACs were checked: a fully rebuilt chain would not be noticed")
        else:
            self.say(
                f"the audit log DOES NOT verify at record {data['first_bad_seq']}: "
                f"{_text(data['reason'])}"
            )

    def _audit_verify_offline(self, args: argparse.Namespace) -> int:
        config = self.config(args)
        local = self._open_local(config)
        try:
            initial = None
            if args.key_file:
                from portlock.audit.log import AuditKey

                try:
                    initial = AuditKey.parse(
                        Path(args.key_file).read_text(encoding="utf-8").strip()
                    )
                except (OSError, PortLockError) as exc:
                    raise _Failure(EXIT_FAILED, f"the key file cannot be used: {exc}") from None
            result = local.audit_log.verify(initial_key=initial)
        finally:
            local.db.close()
        self._show_verify(
            {
                "ok": result.ok,
                "checked": result.checked,
                "first_bad_seq": result.first_bad_seq,
                "reason": result.reason,
                "macs_checked": result.macs_checked,
            }
        )
        return EXIT_OK if result.ok else EXIT_CHECK

    def _audit_export(self, args: argparse.Namespace, svc: _Service) -> int:
        query = {"since_seq": args.since_seq}
        if args.output:
            path = Path(args.output)
            if path.exists() and not args.force:
                raise _Failure(EXIT_FAILED, f"{path} exists; use --force to replace it")
            with path.open("wb") as handle:
                svc.download("/audit/export", query, handle.write)
            self.say(f"wrote {path}")
            return EXIT_OK
        pending = bytearray()

        def to_stdout(chunk: bytes) -> None:
            pending.extend(chunk)
            while (newline := pending.find(b"\n")) >= 0:
                line = bytes(pending[:newline]).decode("utf-8", errors="replace")
                del pending[: newline + 1]
                self.say(_text(line))

        svc.download("/audit/export", query, to_stdout)
        return EXIT_OK

    # --- scans, lockdown, changes, mode, scope -----------------------------------------

    def cmd_scan(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            if args.show is not None:
                data = svc.call("GET", f"/scans/{args.show}")
                self.emit(args, data, self._show_scan_report)
            elif args.list or args.connection_id is None:
                data = svc.call("GET", "/scans", query={"limit": args.limit})
                self.emit(args, data, lambda d: self._show_scans(d["scans"]))
            else:
                body: dict[str, Any] = {"connection_id": args.connection_id}
                if args.mount:
                    body["mount_point"] = args.mount
                data = svc.call("POST", "/scans", body=body)
                self.emit(args, data, lambda d: self._show_scans(d["scans"]))
        return EXIT_OK

    def _show_scans(self, scans: Sequence[Mapping[str, Any]]) -> None:
        if not scans:
            self.say("no scans")
            return
        rows = [
            [s["id"], s["connection_id"], s["state"], s["verdict"] or "-", s["mount_point"]]
            for s in scans
        ]
        self.say(_table(("ID", "DEVICE", "STATE", "VERDICT", "VOLUME"), rows))

    def _show_scan_report(self, data: Mapping[str, Any]) -> None:
        scan = data["scan"]
        self.say(f"scan {scan['id']}: {scan['state']}, verdict {scan['verdict'] or '-'}")
        report = scan.get("report") or {}
        for finding in report.get("findings", []):
            self.say(
                f"  {finding['severity']}: {_text(finding['path'])} "
                f"({finding['engine']}/{_text(finding['rule'])}) {_text(finding.get('detail'))}"
            )

    def _confirm_flow(self, svc: _Service, change: Mapping[str, Any] | None, auto: bool) -> None:
        """A change applied under commit-confirm: keep it, or let it roll back."""
        if not change:
            return
        self.say("")
        self.say(
            f"This change is in force but not yet kept. Confirm within "
            f"{change['timeout_seconds']} seconds, or it is rolled back."
        )
        blocked = [p for p in change.get("preview", []) if p.get("outcome") == "block"]
        for item in blocked[:10]:
            self.say(f"  would block: {_text(item.get('name'))} {_text(item.get('vid_pid'))}")
        if auto:
            answer = "yes"
        elif self.env.is_tty():
            answer = self._ask("Keep it? Type yes to confirm: ").lower()
        else:
            self.say(
                f"Confirm with: {self.env.program} confirm {change['id']}   "
                f"(or: {self.env.program} cancel {change['id']})"
            )
            return
        if answer in ("yes", "y"):
            svc.call("POST", f"/changes/{change['id']}/confirm")
            self.say("Confirmed: the change is kept.")
        else:
            self.say(
                "Not confirmed: it rolls back by itself "
                f"(or: {self.env.program} cancel {change['id']})."
            )

    def cmd_lockdown(self, args: argparse.Namespace) -> int:
        action = args.lockdown_command
        with self.service(args) as svc:
            if action == "status":
                data = svc.call("GET", "/lockdown")
                self.emit(args, data, self._show_lockdown)
            elif action == "engage":
                body: dict[str, Any] = {"reason": args.reason}
                if args.minutes is not None:
                    body["minutes"] = args.minutes
                data = svc.call("POST", "/lockdown/engage", body=body)
                self.emit(args, data, lambda d: self._show_lockdown(d["lockdown"]))
                if not args.json:
                    self._confirm_flow(svc, data["change"], args.confirm)
            elif action == "confirm":
                change_id = args.change_id or self._only_change(svc, "lockdown")
                data = svc.call("POST", f"/changes/{change_id}/confirm")
                self.emit(args, data, lambda d: self.say("Confirmed: the lockdown is kept."))
            elif action == "renew":
                body = {} if args.minutes is None else {"minutes": args.minutes}
                data = svc.call("POST", "/lockdown/renew", body=body)
                self.emit(args, data, lambda d: self._show_lockdown(d["lockdown"]))
            else:
                if args.recovery_code:
                    body = {"recovery_code": self._secret(args, "Recovery code: ")}
                else:
                    body = {"password": svc.password}
                data = svc.call("POST", "/lockdown/lift", body=body, local=True)
                self.emit(args, data, lambda d: self.say("The lockdown is lifted."))
        return EXIT_OK

    def _show_lockdown(self, data: Mapping[str, Any]) -> None:
        if not data.get("active"):
            self.say(f"no lockdown ({data['state']})")
            return
        self.say(
            f"LOCKDOWN {data['state']}: engaged by {_text(data['engaged_by'])} at "
            f"{_when(data['engaged_at'])}, ends {_when(data['expires_at'])} "
            f"({data['remaining_seconds']} s left), renewed {data['renew_count']} time(s)"
        )
        if data.get("reason"):
            self.say(f"  reason: {_text(data['reason'])}")

    def _only_change(self, svc: _Service, kind: str | None) -> str:
        changes = [
            c for c in svc.call("GET", "/changes")["changes"] if kind is None or c["kind"] == kind
        ]
        if len(changes) != 1:
            raise _Failure(
                EXIT_FAILED,
                f"{len(changes)} change(s) are waiting; name one "
                f"({self.env.program} changes lists them)",
            )
        return str(changes[0]["id"])

    def cmd_changes(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            data = svc.call("GET", "/changes")

        def render(payload: Any) -> None:
            rows = [
                [c["id"], c["kind"], c["actor"], f"{c['remaining_seconds']} s"]
                for c in payload["changes"]
            ]
            self.say(
                _table(("ID", "KIND", "BY", "TIME LEFT"), rows) if rows else "nothing is waiting"
            )

        self.emit(args, data, render)
        return EXIT_OK

    def cmd_confirm(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            change_id = args.change_id or self._only_change(svc, None)
            data = svc.call("POST", f"/changes/{change_id}/confirm")
        self.emit(args, data, lambda d: self.say(f"confirmed {d['change']['kind']}: it is kept"))
        return EXIT_OK

    def cmd_cancel(self, args: argparse.Namespace) -> int:
        with self.service(args) as svc:
            data = svc.call("POST", f"/changes/{args.change_id}/cancel")
        self.emit(args, data, lambda d: self.say(f"cancelled {d['change']['kind']}: rolled back"))
        return EXIT_OK

    def _setting(
        self,
        args: argparse.Namespace,
        path: str,
        value: Any,
        field_name: str,
        show: Callable[[Any], None],
    ) -> int:
        with self.service(args) as svc:
            if value is None:
                data = svc.call("GET", path)
                self.emit(args, data, show)
            else:
                data = svc.call("PUT", path, body={field_name: value})
                self.emit(args, data, show)
                if not args.json:
                    self._confirm_flow(svc, data.get("change"), args.confirm)
        return EXIT_OK

    def cmd_mode(self, args: argparse.Namespace) -> int:
        def show(data: Any) -> None:
            mode = data["mode"] if "mode" in data and isinstance(data["mode"], dict) else data
            self.say(
                f"mode {mode['effective_mode']} (chosen {mode['mode']}, source {mode['source']})"
            )
            for note in mode.get("notes", []):
                self.say(f"  {_text(note)}")

        return self._setting(args, "/mode", args.value, "mode", show)

    def cmd_scope(self, args: argparse.Namespace) -> int:
        return self._setting(
            args, "/scope", args.value, "scope", lambda d: self.say(f"scope {d['scope']}")
        )

    def cmd_default_deny(self, args: argparse.Namespace) -> int:
        value = None if args.value is None else args.value == "on"
        return self._setting(
            args,
            "/default-deny",
            value,
            "enabled",
            lambda d: self.say(f"default-deny is {'on' if d['enabled'] else 'off'}"),
        )

    # --- users -------------------------------------------------------------------------

    def cmd_user(self, args: argparse.Namespace) -> int:
        action = args.user_command
        if action in ("unlock", "reset-password") and args.local:
            return self._user_local(args)
        with self.service(args) as svc:
            name = getattr(args, "name", None)
            if action == "list":
                data = svc.call("GET", "/users")

                def render(payload: Any) -> None:
                    rows = [
                        [
                            u["username"],
                            u["role"],
                            "yes" if u["enabled"] else "NO",
                            _when(u["last_login_at"]) if u["last_login_at"] else "-",
                            u["recovery_codes_remaining"],
                            u["locked_out_seconds"] or "-",
                        ]
                        for u in payload["users"]
                    ]
                    self.say(
                        _table(("USER", "ROLE", "ENABLED", "LAST LOGIN", "CODES", "LOCKED"), rows)
                    )

                self.emit(args, data, render)
                return EXIT_OK
            if action == "add":
                password = self._secret(args, f"Password for the new user {_text(name)}: ")
                data = svc.call(
                    "POST",
                    "/users",
                    body={"username": name, "password": password, "role": args.role},
                )
            elif action == "role":
                data = svc.call("PUT", f"/users/{name}/role", body={"role": args.role})
            elif action in ("disable", "enable", "unlock"):
                data = svc.call("POST", f"/users/{name}/{action}")
            elif action == "reset-password":
                password = self._secret(args, f"New password for {_text(name)}: ")
                data = svc.call("POST", f"/users/{name}/password", body={"new_password": password})
            elif action == "recovery-codes":
                data = svc.call(
                    "POST",
                    f"/users/{name}/recovery-codes",
                    body={"current_password": svc.password},
                    local=True,
                )
                self.emit(args, data, self._show_codes)
                return EXIT_OK
            else:
                svc.call("DELETE", f"/users/{name}")
                self.say(f"deleted {_text(name)}")
                return EXIT_OK
        self.emit(
            args,
            data,
            lambda d: self.say(
                f"{_text(d['user']['username'])}: {d['user']['role']}"
                f"{'' if d['user']['enabled'] else ' (disabled)'}"
            ),
        )
        return EXIT_OK

    def _show_codes(self, data: Mapping[str, Any]) -> None:
        self.say("Recovery codes. Each works once; they are shown only now. Store them offline.")
        for code in data["codes"]:
            self.say(f"  {code}")

    def _user_local(self, args: argparse.Namespace) -> int:
        """Reset a password or clear a lockout directly on the database (OS rights only)."""
        config = self.config(args)
        local = self._open_local(config)
        try:
            if args.user_command == "unlock":
                local.accounts.clear_lockout(args.name, actor="local-console")
                self.say(f"unlocked {_text(args.name)}")
            else:
                password = self._new_password(
                    args,
                    config,
                    args.name,
                    again=f"{self.env.program} user reset-password {args.name} --local",
                )
                local.accounts.set_password(args.name, password, actor="local-console")
                self.say(f"the password of {_text(args.name)} was changed; every session ended")
        except PortLockError as exc:
            raise _Failure(EXIT_FAILED, exc.message) from None
        finally:
            local.db.close()
        return EXIT_OK


# --- the command line -------------------------------------------------------------------

_DURATION_HELP = "how long, like 30m, 2h or 7d"
_EPILOG = (
    "Service commands log in (a hidden password prompt, or --password-stdin) and talk to "
    "the running service. init, run, stop, recover, simulate, service, policy validate and "
    "audit verify --offline work on files and do not need it. Exit codes: 0 ok, 1 failed, "
    "2 usage, 3 not authenticated or not permitted, 4 service not running or not "
    "verified, 5 a check failed."
)


def _common(parser: _Parser, *, top: bool) -> None:
    """The options every command accepts. Only the top-level parser carries real defaults:
    a sub-command's would overwrite a value given before the command name."""
    default: Any = (lambda real: real) if top else (lambda real: argparse.SUPPRESS)
    parser.add_argument(
        "--config", metavar="FILE", default=default(None), help="the configuration file"
    )
    parser.add_argument(
        "--url",
        metavar="URL",
        default=default(None),
        help="the service, e.g. http://127.0.0.1:47600",
    )
    parser.add_argument(
        "--user", metavar="NAME", default=default(None), help="the user to log in as"
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        default=default(False),
        help="read the password from one line of standard input",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=default(False),
        help="print the API's answer unchanged",
    )
    parser.add_argument(
        "--timeout", type=float, metavar="SECONDS", default=default(15.0), help="request timeout"
    )


def _add(sub: Any, env: CliEnv, name: str, handler: Callable[..., int], help_text: str) -> _Parser:
    parser: _Parser = sub.add_parser(name, help=help_text, description=help_text, add_help=True)
    parser.env = env
    _common(parser, top=False)
    parser.set_defaults(func=handler)
    return parser


def _confirm_option(parser: _Parser) -> None:
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="confirm the change at once instead of asking (it is still rolled back "
        "unless confirmed)",
    )


def _build_parser(env: CliEnv, cli: _Cli) -> _Parser:
    root = _Parser(
        prog="portlock",
        description="PortLock: decide what a USB device may do, enforce it, keep a record.",
        epilog=_EPILOG,
    )
    root.env = env
    root.add_argument("--version", action="version", version=f"portlock {__version__}")
    _common(root, top=True)
    sub = root.add_subparsers(dest="command", metavar="COMMAND")

    p = _add(sub, env, "init", cli.cmd_init, "create the first administrator (once)")
    p.add_argument("--username", metavar="NAME", help="the administrator's user name")
    _add(sub, env, "run", cli.cmd_run, "run the service in the foreground")
    _add(sub, env, "stop", cli.cmd_stop, "stop the running service")
    p = _add(sub, env, "status", cli.cmd_status, "is the service running?")
    p.add_argument("--detail", action="store_true", help="log in and show mode, lockdown, counts")
    p = _add(sub, env, "doctor", cli.cmd_doctor, "what this machine can and cannot enforce")
    p.add_argument("--offline", action="store_true", help="check this machine directly")

    p = _add(sub, env, "devices", cli.cmd_devices, "list devices")
    p.add_argument("--known", action="store_true", help="every device ever seen")
    p.add_argument("--history", action="store_true", help="past and present connections")
    p.add_argument("--limit", type=int, default=100, metavar="N")
    p.add_argument("--state", metavar="STATE", help="only devices in this state")
    p.add_argument("--text", metavar="TEXT", help="with --known: match name, serial, fingerprint")
    p = _add(sub, env, "approve", cli.cmd_approve, "approve a device that is waiting")
    p.add_argument("connection_id", type=int)
    p.add_argument("--kind", choices=("once", "temporary", "trust"), default="once")
    p.add_argument("--for", dest="duration", metavar="DURATION", help=_DURATION_HELP)
    p.add_argument("--read-only", action="store_true")
    p.add_argument("--note", default="", metavar="TEXT")
    p = _add(sub, env, "deny", cli.cmd_deny, "refuse a device that is waiting")
    p.add_argument("connection_id", type=int)
    p.add_argument("--eject", action="store_true", help="also ask the system to eject it")
    p.add_argument("--note", default="", metavar="TEXT")
    p = _add(sub, env, "trust", cli.cmd_trust, "trust a device by fingerprint, or list trust")
    p.add_argument("fingerprint", nargs="?")
    p.add_argument("--list", action="store_true")
    p.add_argument("--read-only", action="store_true")
    p.add_argument("--note", default="", metavar="TEXT")
    p = _add(sub, env, "grant", cli.cmd_grant, "give a device temporary or one-time access")
    p.add_argument("fingerprint")
    p.add_argument("--kind", choices=("temporary", "once"), required=True)
    p.add_argument("--for", dest="duration", metavar="DURATION", help=_DURATION_HELP)
    p.add_argument("--read-only", action="store_true")
    p.add_argument("--note", default="", metavar="TEXT")
    p.add_argument("--allow-low-confidence", action="store_true")
    p = _add(sub, env, "revoke", cli.cmd_revoke, "withdraw a grant or trust")
    p.add_argument("grant_id")
    p = _add(
        sub,
        env,
        "enroll",
        cli.cmd_enroll,
        "protect an input device on its port (list, add, remove)",
    )
    p.add_argument("connection_id", type=int, nargs="?", help="the connection to enrol")
    p.add_argument("--label", metavar="TEXT")
    p.add_argument("--remove", metavar="FINGERPRINT", help="remove an enrolment")
    p.add_argument("--port", metavar="PATH", help="with --remove: only this port")
    p = _add(sub, env, "release-port", cli.cmd_release_port, "end a port hold-down early")
    p.add_argument("port")

    p = _add(sub, env, "policy", cli.cmd_policy, "show, validate, set, test or create a policy")
    policy = p.add_subparsers(dest="policy_command", metavar="ACTION", required=True)
    q = _add(policy, env, "init", cli.cmd_policy, "print (or write) the default policy")
    q.add_argument("--example", action="store_true", help="the annotated example instead")
    q.add_argument("--output", metavar="FILE")
    q.add_argument("--force", action="store_true")
    q = _add(policy, env, "validate", cli.cmd_policy, "check a policy file (no service)")
    q.add_argument("file")
    q = _add(policy, env, "show", cli.cmd_policy, "the active policy")
    q.add_argument("--raw", action="store_true", help="the policy document itself")
    q = _add(policy, env, "set", cli.cmd_policy, "make a policy file the active policy")
    q.add_argument("file")
    q.add_argument("--expected-hash", metavar="HASH", help="refuse if the active policy changed")
    q = _add(policy, env, "test", cli.cmd_policy, "what would the policy do with a device?")
    q.add_argument("--device", metavar="JSON|@FILE")
    q.add_argument("--connection", type=int, metavar="ID")
    q.add_argument("--fingerprint", metavar="FP")
    q.add_argument("--policy", dest="file", metavar="FILE", help="a draft policy to test instead")
    q.add_argument("--local", action="store_true", help="evaluate the file alone, no service")

    p = _add(sub, env, "audit", cli.cmd_audit, "read, verify and export the audit log")
    audit = p.add_subparsers(dest="audit_command", metavar="ACTION", required=True)
    q = _add(audit, env, "tail", cli.cmd_audit, "the newest records")
    q.add_argument("-n", "--limit", type=int, default=20, metavar="N")
    q = _add(audit, env, "query", cli.cmd_audit, "search the log")
    q.add_argument("--type", action="append", metavar="EVENT", help="repeatable; 'auth.*' works")
    q.add_argument("--min-severity", metavar="LEVEL")
    q.add_argument("--actor", metavar="NAME")
    q.add_argument("--device", metavar="FINGERPRINT")
    q.add_argument("--since", metavar="TIME", help="like 2026-01-01T00:00:00Z")
    q.add_argument("--until", metavar="TIME")
    q.add_argument("--text", metavar="TEXT")
    q.add_argument("-n", "--limit", type=int, default=50, metavar="N")
    q = _add(audit, env, "verify", cli.cmd_audit, "walk the hash chain")
    q.add_argument("--offline", action="store_true", help="read the database directly")
    q.add_argument("--key-file", metavar="FILE", help="offline: a file holding the initial key")
    q.add_argument("--expected-head", metavar="SEQ:HASH", help="a head saved earlier")
    q = _add(audit, env, "export", cli.cmd_audit, "the records as JSON lines")
    q.add_argument("--since-seq", type=int, default=1, metavar="N")
    q.add_argument("--output", metavar="FILE")
    q.add_argument("--force", action="store_true")

    p = _add(sub, env, "scan", cli.cmd_scan, "scan a connected device's volume, or list scans")
    p.add_argument("connection_id", type=int, nargs="?")
    p.add_argument("--mount", metavar="PATH")
    p.add_argument("--list", action="store_true")
    p.add_argument("--show", type=int, metavar="ID", help="one scan with its findings")
    p.add_argument("--limit", type=int, default=50, metavar="N")

    p = _add(sub, env, "lockdown", cli.cmd_lockdown, "emergency lockdown")
    lockdown = p.add_subparsers(dest="lockdown_command", metavar="ACTION", required=True)
    q = _add(lockdown, env, "engage", cli.cmd_lockdown, "block all removable storage now")
    q.add_argument("--minutes", type=int, metavar="N")
    q.add_argument("--reason", default="", metavar="TEXT")
    _confirm_option(q)
    q = _add(lockdown, env, "confirm", cli.cmd_lockdown, "keep an engaged lockdown")
    q.add_argument("change_id", nargs="?")
    q = _add(lockdown, env, "renew", cli.cmd_lockdown, "restart the dead-man timer")
    q.add_argument("--minutes", type=int, metavar="N")
    q = _add(lockdown, env, "lift", cli.cmd_lockdown, "lift the lockdown")
    q.add_argument("--recovery-code", action="store_true", help="prove it with a recovery code")
    _add(lockdown, env, "status", cli.cmd_lockdown, "is a lockdown active?")

    p = _add(sub, env, "mode", cli.cmd_mode, "show or change the mode (monitor or enforce)")
    p.add_argument("value", nargs="?", choices=("monitor", "enforce"))
    _confirm_option(p)
    p = _add(sub, env, "scope", cli.cmd_scope, "show or change what can be enforced against")
    p.add_argument(
        "value", nargs="?", choices=("storage", "storage_and_unknown", "all_except_protected")
    )
    _confirm_option(p)
    p = _add(sub, env, "default-deny", cli.cmd_default_deny, "show or change default-deny")
    p.add_argument("value", nargs="?", choices=("on", "off"))
    _confirm_option(p)
    _add(sub, env, "changes", cli.cmd_changes, "changes waiting for confirmation")
    p = _add(sub, env, "confirm", cli.cmd_confirm, "keep a change waiting for confirmation")
    p.add_argument("change_id", nargs="?")
    p = _add(sub, env, "cancel", cli.cmd_cancel, "roll a waiting change back now")
    p.add_argument("change_id")

    p = _add(sub, env, "recover", cli.cmd_recover, "restore every journaled setting (no service)")
    p.add_argument("--dry-run", action="store_true", help="list what would be restored")
    p.add_argument(
        "--dead-man",
        action="store_true",
        help="as run by the dead-man timer: leave a running service alone and never "
        "disable enforcement",
    )
    p = _add(sub, env, "simulate", cli.cmd_simulate, "explore PortLock on a simulated machine")
    p.add_argument("--scenario", choices=sorted(SCENARIOS), default="tour")
    p.add_argument(
        "--port", type=int, default=0, metavar="N", help="API port (default: any free one)"
    )
    p.add_argument(
        "--no-serve", dest="serve", action="store_false", help="print the timeline and exit"
    )
    p.set_defaults(serve=True)

    p = _add(sub, env, "service", cli.cmd_service, "print a service definition to review")
    service = p.add_subparsers(dest="service_command", metavar="ACTION", required=True)
    for name, text in (
        ("print-unit", "a hardened systemd unit"),
        ("print-task", "a Task Scheduler definition"),
    ):
        q = _add(service, env, name, cli.cmd_service, text)
        q.add_argument("--executable", metavar="PATH", help="the portlock program to run")
        q.add_argument(
            "--output", metavar="FILE", help="write the definition instead of printing it"
        )
        q.add_argument("--force", action="store_true")

    p = _add(sub, env, "user", cli.cmd_user, "manage accounts")
    users = p.add_subparsers(dest="user_command", metavar="ACTION", required=True)
    _add(users, env, "list", cli.cmd_user, "accounts and their state")
    q = _add(users, env, "add", cli.cmd_user, "create an account")
    q.add_argument("name")
    q.add_argument("--role", choices=[role.value for role in Role], required=True)
    q = _add(users, env, "role", cli.cmd_user, "change an account's role")
    q.add_argument("name")
    q.add_argument("role", choices=[role.value for role in Role])
    for name, text in (
        ("disable", "stop an account from logging in"),
        ("enable", "let an account log in again"),
        ("delete", "delete an account"),
        ("recovery-codes", "issue a fresh set of recovery codes"),
    ):
        q = _add(users, env, name, cli.cmd_user, text)
        q.add_argument("name")
    for name, text in (("unlock", "clear a lockout"), ("reset-password", "set a new password")):
        q = _add(users, env, name, cli.cmd_user, text)
        q.add_argument("name")
        q.add_argument(
            "--local", action="store_true", help="act on the database directly (no service)"
        )
    return root


def main(argv: Sequence[str] | None = None, *, env: CliEnv | None = None) -> int:
    """Run ``portlock``. Returns the exit status (see the module docstring)."""
    environment = env if env is not None else CliEnv()
    cli = _Cli(environment)
    parser = _build_parser(environment, cli)
    err = environment.err()
    try:
        args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    except _UsageError as exc:
        err.write(f"portlock: {_text(exc)}\n")
        err.write(f"Run '{environment.program} --help' for the commands.\n")
        return EXIT_USAGE
    except _Exit as exc:
        return exc.code
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help(environment.out())
        return EXIT_USAGE
    debug = environment.environ.get("PORTLOCK_DEBUG") == "1"
    try:
        return int(handler(args))
    except _Failure as exc:
        err.write(f"portlock: {_text(exc.message)}\n")
        return exc.code
    except PortLockError as exc:
        err.write(f"portlock: {_text(exc.message)}\n")
        if debug:
            err.write(traceback.format_exc())
        return EXIT_FAILED
    except KeyboardInterrupt:
        err.write("\nportlock: interrupted\n")
        return 130
    except (OSError, ValueError) as exc:
        err.write(f"portlock: {_text(type(exc).__name__)}: {_text(exc)}\n")
        if debug:
            err.write(traceback.format_exc())
        return EXIT_FAILED
