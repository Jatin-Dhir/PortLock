"""The PortLock process (``docs/ARCHITECTURE.md`` 3.7, amended by ``docs/DESIGN.md`` 14).

* :func:`build_runtime` is the single composition root: it checks the database (a
  damaged file is renamed aside and a new log is started, DESIGN 14.23), opens the
  stores and the audit log, and wires the backend, the enforcer (with the journal's
  write-ahead hook), the dead-man timer, the directory-privacy check and the
  :class:`~portlock.core.service.PortLockService`.
* :func:`run` is the process: single-instance lock, the kill switch honoured *before*
  the database is opened, start, the runtime file with the secret the command line
  authenticates with (14.20), the ticker, signals and a clean shutdown that restores
  journaled state unless ``fail_closed`` is set.

Nothing here contains pipeline logic.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import os
import secrets
import signal
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import IO, Any, Protocol

from portlock import __version__
from portlock.audit.events import AuditError
from portlock.audit.log import AuditKey, AuditKeyStore, AuditLog
from portlock.audit.sinks import AuditSink, FanOut, JsonlFileSink, MinSeveritySink, SyslogSink
from portlock.auth.accounts import AccountStore, AuthPolicy, Channel, Role
from portlock.auth.grants import GrantStore
from portlock.auth.passwords import ScryptParams
from portlock.auth.sessions import SessionStore
from portlock.core.clock import Clock, SystemClock, utc_iso
from portlock.core.config import Config, ConfigError
from portlock.core.db import Database
from portlock.core.errors import BackendError, PortLockError, StoreError
from portlock.core.events import EventBus
from portlock.core.fsutil import atomic_write_bytes, ensure_private_dir
from portlock.core.models import UsbDevice
from portlock.core.service import (
    AuditWriter,
    DirPrivacyLike,
    DoctorLike,
    PortLockService,
    ScannerLike,
    ServiceCheck,
)
from portlock.core.store import JOURNAL_FILE_NAME, RecoveryJournal, StateStore
from portlock.guard import factory
from portlock.guard.base import DeviceBackend, Enforcer, JournalEntry
from portlock.guard.fake import FakeBackend
from portlock.guard.safety import SafeEnforcer, SafetyContext
from portlock.guard.seams import ExternalTimer, FakeExternalTimer
from portlock.lockdown.manager import Credential, KillSwitch, RollbackReport, rollback
from portlock.scan.inspector import ScanLimits
from portlock.scan.scanner import build_scanner

__all__ = [
    "EXIT_ALREADY_RUNNING",
    "EXIT_CONFIG",
    "EXIT_ERROR",
    "EXIT_OK",
    "EXIT_PORT",
    "EXIT_STATE_UNUSABLE",
    "HEAD_FILE_NAME",
    "LOCK_FILE_NAME",
    "POLICY_FILE_NAME",
    "RUNTIME_FILE_NAME",
    "STOP_REQUEST_NAME",
    "AccountCredentials",
    "ApiServerLike",
    "InstanceLock",
    "Runtime",
    "StoreRecovery",
    "build_runtime",
    "read_runtime_file",
    "request_stop",
    "run",
    "verify_cli_secret",
]

_LOG = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ALREADY_RUNNING = 2
EXIT_STATE_UNUSABLE = 3
EXIT_CONFIG = 4
EXIT_PORT = 5

#: Single-instance lock, in the state directory.
LOCK_FILE_NAME = "portlock.lock"
#: How the command line finds and authenticates to the running service.
RUNTIME_FILE_NAME = "runtime.json"
#: Written by ``portlock stop``; the ticker sees it and stops the service.
STOP_REQUEST_NAME = "stop.request"
#: The audit log's head file (``audit.log``), beside the database.
HEAD_FILE_NAME = "audit.head"
#: The active policy, in the configuration directory.
POLICY_FILE_NAME = "policy.json"

_RUNTIME_VERSION = 1
_MAX_RUNTIME_BYTES = 4096
_FILE_SINK_BYTES = 64 * 1024 * 1024
_SECOND_SIGNAL_GRACE = 10.0
_SINK_CLOSE_SECONDS = 5.0
_SECRET_BYTES = 32


class ApiServerLike(Protocol):
    """What :func:`run` needs of ``console.api``'s server: start, stop and an address."""

    host: str
    port: int

    def start(self) -> None: ...

    def stop(self) -> None: ...


@dataclass(frozen=True, slots=True)
class StoreRecovery:
    """A damaged database that was renamed aside at start (DESIGN 14.23).

    Attributes:
        damaged_path: where the damaged file now is; it is never deleted.
        problems: what the integrity check reported.
    """

    damaged_path: Path
    problems: tuple[str, ...]


@dataclass(slots=True)
class Runtime:
    """Everything one PortLock process is made of.

    Attributes:
        cli_secret: the secret written to the private runtime file; the HTTP API
            accepts it from the command line (DESIGN 14.20). Never logged.
        initial_key: the initial key of an audit MAC key store created by this start
            (the operator keeps it offline), or ``None``.
        store_recovery: set when a damaged database was moved aside.
    """

    config: Config
    clock: Clock
    db: Database
    journal: RecoveryJournal
    audit_log: AuditLog
    audit: AuditWriter
    sinks: FanOut | None
    bus: EventBus
    accounts: AccountStore
    sessions: SessionStore
    grants: GrantStore
    store: StateStore
    service: PortLockService
    backend: DeviceBackend
    enforcer: Enforcer
    cli_secret: str
    initial_key: AuditKey | None = None
    store_recovery: StoreRecovery | None = None

    def close(self) -> None:
        """Flush the audit sinks (at most 5 s) and close the database. Safe twice."""
        if self.sinks is not None:
            with contextlib.suppress(Exception):
                self.sinks.close(_SINK_CLOSE_SECONDS)
        self.db.close()

    def verify_cli_secret(self, candidate: str) -> bool:
        """True if ``candidate`` is this process's command-line secret."""
        return verify_cli_secret(self.cli_secret, candidate)


def verify_cli_secret(expected: str, candidate: object) -> bool:
    """Constant-time comparison of a presented command-line secret."""
    if not isinstance(candidate, str) or not candidate or not expected:
        return False
    return secrets.compare_digest(expected.encode("utf-8"), candidate.encode("utf-8"))


class AccountCredentials:
    """``lockdown.manager.CredentialCheck`` on the account store: administrators only.

    A password is checked on the network channel (the API is the network path) unless
    the credential came over the elevated local command line; a recovery code is spent.
    Any failure says no.
    """

    def __init__(self, accounts: AccountStore) -> None:
        self._accounts = accounts

    def verify(self, actor: str, credential: Credential) -> bool:
        user = self._accounts.get_user(actor)
        if user is None or not user.enabled or user.role is not Role.ADMIN:
            return False
        if credential.kind == "password":
            channel = Channel.LOCAL if credential.local else Channel.NETWORK
            result = self._accounts.authenticate(actor, credential.secret, channel=channel)
            return bool(result.ok)
        if credential.kind == "recovery_code":
            return self._accounts.use_recovery_code(
                actor, credential.secret, channel=Channel.NETWORK
            )
        return False


# --- composition -------------------------------------------------------------------------


def build_runtime(
    config: Config,
    *,
    clock: Clock | None = None,
    backend: DeviceBackend | None = None,
    enforcer: Enforcer | None = None,
    enforcer_factory: Callable[[Callable[[JournalEntry], None]], Enforcer] | None = None,
    scanner: ScannerLike | None = None,
    platform: str | None = None,
    simulation: bool = False,
    timer: ExternalTimer | None = None,
    dir_privacy: DirPrivacyLike | None = None,
    system_ids: Callable[[Sequence[UsbDevice]], frozenset[str]] | None = None,
    recover_argv: Sequence[str] | None = None,
) -> Runtime:
    """Compose every component from a configuration. Nothing is started.

    Real platform objects are created for whatever is not given. ``enforcer_factory``
    receives the journal's write-ahead hook (the way every real enforcer is wired);
    ``enforcer`` is used as it is. With ``simulation`` the backend defaults to a
    :class:`~portlock.guard.fake.FakeBackend`, the timer to an in-memory one and the
    system-volume probe to "none". An injected enforcer outside simulation must come with
    an injected timer and directory-privacy check, so that a test can never reach the
    real operating-system timer or ``icacls`` by omission.

    Raises:
        StoreError: the database cannot be opened, or is from a newer PortLock.
        ConfigError: a component rejects the configuration.
        ValueError: an injected enforcer without its seams.
    """
    real_clock: Clock = clock if clock is not None else SystemClock()
    injected = enforcer is not None or enforcer_factory is not None
    if injected and not simulation and (timer is None or dir_privacy is None):
        raise ValueError("an injected enforcer needs an injected timer and dir_privacy")
    state_dir = Path(config.paths.state_dir)
    ensure_private_dir(state_dir)
    ensure_private_dir(config.paths.config_dir)

    journal = RecoveryJournal(state_dir / JOURNAL_FILE_NAME, clock=real_clock)
    recovery = _check_database(config.paths.database_file, real_clock)
    db = Database(config.paths.database_file)
    try:
        bus = EventBus(real_clock)
        sinks = _build_sinks(config)
        audit_log, initial_key = _open_audit_log(config, db, real_clock, sinks, recovery)
        writer = AuditWriter(audit_log, bus=bus, clock=real_clock)
        accounts: AccountStore | None = None

        def account_lookup(name: str) -> Any:
            return accounts.get_user(name) if accounts is not None else None

        sessions = SessionStore(
            db,
            clock=real_clock,
            idle_timeout=timedelta(minutes=config.api.session_idle_minutes),
            absolute_timeout=timedelta(hours=config.api.session_max_hours),
            account_lookup=account_lookup,
        )
        accounts = AccountStore(
            db,
            clock=real_clock,
            audit=writer.auth_hook,
            policy=_auth_policy(config),
            sessions=sessions,
        )
        grants = GrantStore(db, clock=real_clock)
        store = StateStore(db, clock=real_clock)

        chosen_backend = backend
        if chosen_backend is None:
            chosen_backend = (
                FakeBackend(clock=real_clock)
                if simulation
                else factory.create_backend(config, clock=real_clock, platform=platform)
            )
        if enforcer is not None:
            chosen_enforcer = enforcer
        elif enforcer_factory is not None:
            chosen_enforcer = enforcer_factory(journal.write_ahead)
        else:
            chosen_enforcer = factory.create_enforcer(
                config, platform=platform, write_ahead=journal.write_ahead
            )
        chosen_timer = timer
        if chosen_timer is None:
            chosen_timer = (
                FakeExternalTimer()
                if simulation
                else factory.create_external_timer(config, platform=platform)
            )
        privacy: DirPrivacyLike = (
            dir_privacy
            if dir_privacy is not None
            else factory.create_dir_privacy(platform=platform)
        )
        probe = system_ids
        if probe is None:
            probe = (
                (lambda devices: frozenset())
                if simulation
                else (lambda devices: factory.system_instance_ids(devices, platform=platform))
            )
        argv = tuple(recover_argv) if recover_argv is not None else factory.dead_man_command(config)
        chosen_scanner = scanner if scanner is not None else _build_scanner(config, real_clock)

        def guard_doctor(checks: Sequence[ServiceCheck]) -> DoctorLike:
            report = factory.doctor(
                config,
                clock=real_clock,
                backend=chosen_backend,
                enforcer=chosen_enforcer,
                platform=platform,
                dir_privacy=privacy,
                system_ids=probe,
            )
            extra = tuple(
                factory.DoctorCheck(check.id, check.status, check.summary, check.detail)
                for check in checks
            )
            return dataclasses.replace(report, checks=report.checks + extra)

        service = PortLockService(
            config=config,
            clock=real_clock,
            store=store,
            journal=journal,
            audit=writer,
            bus=bus,
            backend=chosen_backend,
            enforcer=chosen_enforcer,
            grants=grants,
            scanner=chosen_scanner,
            policy_path=Path(config.paths.config_dir) / POLICY_FILE_NAME,
            system_ids=probe,
            timer=chosen_timer,
            recover_argv=argv,
            dir_privacy=privacy,
            credentials=AccountCredentials(accounts),
            guard_doctor=guard_doctor,
            has_users=accounts.has_users,
            simulation=simulation,
            platform=platform,
        )
    except BaseException:
        db.close()
        raise
    return Runtime(
        config=config,
        clock=real_clock,
        db=db,
        journal=journal,
        audit_log=audit_log,
        audit=writer,
        sinks=sinks,
        bus=bus,
        accounts=accounts,
        sessions=sessions,
        grants=grants,
        store=store,
        service=service,
        backend=chosen_backend,
        enforcer=chosen_enforcer,
        cli_secret=secrets.token_urlsafe(_SECRET_BYTES),
        initial_key=initial_key,
        store_recovery=recovery,
    )


def _check_database(path: Path, clock: Clock) -> StoreRecovery | None:
    """DESIGN 14.23: a damaged database is renamed aside, never deleted or repaired."""
    if not path.is_file():
        return None
    problems = Database.check_file(path)
    if not problems:
        return None
    stamp = clock.now().strftime("%Y%m%dT%H%M%SZ")
    aside = path.with_name(f"{path.name}.damaged-{stamp}")
    counter = 1
    while aside.exists():
        counter += 1
        aside = path.with_name(f"{path.name}.damaged-{stamp}-{counter}")
    try:
        os.replace(path, aside)
        for suffix in ("-wal", "-shm"):
            companion = path.with_name(path.name + suffix)
            if companion.exists():
                os.replace(companion, aside.with_name(aside.name + suffix))
    except OSError as exc:
        raise StoreError(f"the damaged database could not be moved aside: {exc}") from exc
    _LOG.error("the database was damaged (%s); it was moved to %s", problems[0], aside.name)
    return StoreRecovery(aside, tuple(problems))


def _open_audit_log(
    config: Config,
    db: Database,
    clock: Clock,
    sinks: FanOut | None,
    recovery: StoreRecovery | None,
) -> tuple[AuditLog, AuditKey | None]:
    head_path = Path(config.paths.state_dir) / HEAD_FILE_NAME
    key_path = config.audit.hmac_key_file
    if recovery is not None:
        fresh = AuditLog.start_fresh(
            db,
            clock=clock,
            damaged_path=recovery.damaged_path,
            key_store_path=key_path,
            head_path=head_path,
            reason=recovery.problems[0][:200] if recovery.problems else None,
            sink=sinks,
        )
        return fresh.log, fresh.initial_key
    initial: AuditKey | None = None
    key_store: AuditKeyStore | None = None
    if key_path is not None:
        try:
            if Path(key_path).exists():
                key_store = AuditKeyStore(key_path)
            else:
                head_seq, _ = AuditLog(db, clock=clock).head()
                key_store, initial = AuditKeyStore.create(key_path, anchor_seq=head_seq)
        except (AuditError, OSError) as exc:
            # The chain and the head file still protect the log; doctor says MACs are off.
            _LOG.error("the audit MAC key store is unusable; records carry no MAC: %s", exc)
            key_store = None
    return AuditLog(db, clock=clock, key_store=key_store, head_path=head_path, sink=sinks), initial


def _build_sinks(config: Config) -> FanOut | None:
    sinks: dict[str, AuditSink] = {}
    for index, item in enumerate(config.audit.sinks):
        sink: AuditSink
        try:
            if item.type == "file":
                sink = JsonlFileSink(item.target, _FILE_SINK_BYTES)
            elif item.type == "syslog":
                sink = SyslogSink.from_target(item.target)
            else:
                _LOG.warning("audit sink type %r is not available in this process", item.type)
                continue
        except (AuditError, OSError, ValueError) as exc:
            _LOG.error("audit sink %d (%s) cannot be used: %s", index, item.type, exc)
            continue
        sinks[f"{item.type}-{index}"] = MinSeveritySink(sink, item.min_severity)
    if not sinks:
        return None
    return FanOut(sinks, background=True)


def _auth_policy(config: Config) -> AuthPolicy:
    auth = config.auth
    return AuthPolicy(
        scrypt=ScryptParams(n=auth.scrypt_n),
        min_password_length=auth.min_password_length,
        lockout_threshold=auth.lockout_threshold,
        lockout_base=timedelta(seconds=auth.lockout_base_seconds),
        lockout_max=timedelta(seconds=auth.lockout_max_seconds),
        max_network_verifications=auth.max_concurrent_verifications,
    )


def _build_scanner(config: Config, clock: Clock) -> ScannerLike | None:
    if not config.scan.enabled:
        return None
    limits = ScanLimits(
        max_files=config.scan.max_files,
        max_bytes=config.scan.max_bytes,
        max_seconds=float(config.scan.max_seconds),
        follow_symlinks=config.scan.follow_symlinks,
    )
    try:
        return build_scanner(config.scan.engines, limits=limits, clock=clock)
    except ConfigError as exc:
        _LOG.error("scanning is unavailable: %s", exc)
        return None


# --- single instance and the runtime file ------------------------------------------------


class InstanceLock:
    """A non-blocking operating-system lock on one byte of ``portlock.lock``.

    The lock dies with the process, so a crash never leaves it held. A second holder in
    the same process or another process is refused.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._handle: IO[bytes] | None = None
        self._guard = threading.Lock()

    @property
    def held(self) -> bool:
        return self._handle is not None

    def acquire(self) -> bool:
        """Take the lock. False if another holder has it."""
        with self._guard:
            if self._handle is not None:
                return False
            self._path.parent.mkdir(parents=True, exist_ok=True)
            handle = open(self._path, "a+b")  # noqa: SIM115 - held for the process lifetime
            try:
                _lock_byte(handle)
            except OSError:
                handle.close()
                return False
            self._handle = handle
            return True

    def release(self) -> None:
        """Give the lock up. Safe when not held."""
        with self._guard:
            handle, self._handle = self._handle, None
            if handle is None:
                return
            with contextlib.suppress(OSError):
                _unlock_byte(handle)
            handle.close()


if sys.platform == "win32":
    import msvcrt

    def _lock_byte(handle: IO[bytes]) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock_byte(handle: IO[bytes]) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock_byte(handle: IO[bytes]) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_byte(handle: IO[bytes]) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_runtime_file(state_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Read ``runtime.json``. ``None`` if it is absent or not what the service writes."""
    target = Path(state_dir) / RUNTIME_FILE_NAME
    try:
        raw = target.read_bytes()
    except OSError:
        return None
    if len(raw) > _MAX_RUNTIME_BYTES:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    required = {"v", "pid", "host", "port", "run_id", "started_at", "version", "secret"}
    if not isinstance(data, dict) or set(data) != required or data["v"] != _RUNTIME_VERSION:
        return None
    if not all(
        isinstance(data[key], int) and not isinstance(data[key], bool) for key in ("pid", "port")
    ):
        return None
    if not all(
        isinstance(data[key], str) for key in ("host", "run_id", "started_at", "version", "secret")
    ):
        return None
    return data


def _write_runtime_file(
    state_dir: Path, *, host: str, port: int, run_id: str, started_at: datetime, secret: str
) -> None:
    data = {
        "v": _RUNTIME_VERSION,
        "pid": os.getpid(),
        "host": host,
        "port": port,
        "run_id": run_id,
        "started_at": utc_iso(started_at),
        "version": __version__,
        "secret": secret,
    }
    atomic_write_bytes(
        state_dir / RUNTIME_FILE_NAME,
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        private=True,
    )


def request_stop(state_dir: str | os.PathLike[str]) -> None:
    """Ask the running service to stop (``portlock stop``), atomically."""
    atomic_write_bytes(Path(state_dir) / STOP_REQUEST_NAME, b"stop\n", private=True)


# --- the process -------------------------------------------------------------------------


def _pre_database_rollback(
    config: Config,
    *,
    reason: str,
    enforcer: Callable[[RecoveryJournal], Enforcer],
    backend: DeviceBackend,
    clock: Clock,
) -> RollbackReport:
    """Restore every journaled setting from the journal file alone (no database).

    ``enforcer`` builds (or returns) the raw enforcer, wired to this journal.
    """
    journal = RecoveryJournal(Path(config.paths.state_dir) / JOURNAL_FILE_NAME, clock=clock)
    try:
        devices = backend.enumerate()
    except BackendError as exc:
        _LOG.error("devices could not be listed for the rollback: %s", exc)
        devices = []
    # Releasing calls are never refused, so the empty context is enough here.
    live = SafeEnforcer(enforcer(journal), lambda: SafetyContext(), dry_run=False)
    report = rollback(journal, live, devices, reason=reason)
    _LOG.warning(
        "rollback (%s): %d restored, %d released, %d readmitted, %d failed",
        reason,
        report.restored,
        report.released,
        report.readmitted,
        len(report.failed),
    )
    return report


def run(
    config: Config,
    *,
    install_signal_handlers: bool = True,
    api_factory: Callable[[Runtime], ApiServerLike] | None = None,
    tick_seconds: float = 1.0,
    stop_event: threading.Event | None = None,
    clock: Clock | None = None,
    backend: DeviceBackend | None = None,
    enforcer: Enforcer | None = None,
    enforcer_factory: Callable[[Callable[[JournalEntry], None]], Enforcer] | None = None,
    scanner: ScannerLike | None = None,
    platform: str | None = None,
    simulation: bool = False,
    timer: ExternalTimer | None = None,
    dir_privacy: DirPrivacyLike | None = None,
    system_ids: Callable[[Sequence[UsbDevice]], frozenset[str]] | None = None,
    recover_argv: Sequence[str] | None = None,
    on_started: Callable[[Runtime], None] | None = None,
) -> int:
    """Run the service until a stop signal or ``stop.request``. Returns an exit code.

    Exit codes: 0 clean stop; 1 unexpected failure; 2 already running; 3 state unusable
    (after restoring journaled state, unless ``fail_closed``); 4 configuration rejected;
    5 the API could not listen.

    ``api_factory`` builds the HTTP API from the runtime (``console.api``); without one
    the service runs without a listener and ``runtime.json`` names port 0.
    ``on_started`` is called once everything is up (tests use it to reach the runtime).
    """
    real_clock: Clock = clock if clock is not None else SystemClock()
    state_dir = Path(config.paths.state_dir)
    try:
        ensure_private_dir(state_dir)
    except OSError as exc:
        _LOG.error("the state directory cannot be created: %s", exc)
        return EXIT_STATE_UNUSABLE
    lock = InstanceLock(state_dir / LOCK_FILE_NAME)
    if not lock.acquire():
        sys.stderr.write("portlock is already running\n")
        return EXIT_ALREADY_RUNNING
    stopping = stop_event if stop_event is not None else threading.Event()
    try:
        injected = enforcer is not None or enforcer_factory is not None
        if injected and not simulation and (timer is None or dir_privacy is None):
            raise ValueError("an injected enforcer needs an injected timer and dir_privacy")
        privacy = (
            dir_privacy
            if dir_privacy is not None
            else factory.create_dir_privacy(platform=platform)
        )
        early_backend = backend

        def raw_enforcer(journal: RecoveryJournal) -> Enforcer:
            if enforcer is not None:
                return enforcer
            if enforcer_factory is not None:
                return enforcer_factory(journal.write_ahead)
            return factory.create_enforcer(
                config, platform=platform, write_ahead=journal.write_ahead
            )

        def raw_backend() -> DeviceBackend:
            nonlocal early_backend
            if early_backend is None:
                early_backend = (
                    FakeBackend(clock=real_clock)
                    if simulation
                    else factory.create_backend(config, clock=real_clock, platform=platform)
                )
            return early_backend

        # DESIGN 11 and 14.18: a broken database must not stand between the operator and
        # the kill switch, so it is honoured from the journal file before anything else.
        if KillSwitch(config.paths.kill_switch_file, privacy).is_set():
            _pre_database_rollback(
                config,
                reason="killswitch",
                enforcer=raw_enforcer,
                backend=raw_backend(),
                clock=real_clock,
            )
        try:
            runtime = build_runtime(
                config,
                clock=real_clock,
                backend=backend,
                enforcer=enforcer,
                enforcer_factory=enforcer_factory,
                scanner=scanner,
                platform=platform,
                simulation=simulation,
                timer=timer,
                dir_privacy=privacy,
                system_ids=system_ids,
                recover_argv=recover_argv,
            )
        except (StoreError, AuditError) as exc:
            if not config.fail_closed:
                _pre_database_rollback(
                    config,
                    reason="state_unusable",
                    enforcer=raw_enforcer,
                    backend=raw_backend(),
                    clock=real_clock,
                )
            sys.stderr.write(
                f"portlock cannot use its state ({exc}). Nothing was deleted. Restore the "
                "database from a backup or move it aside, then start again; "
                "'portlock recover' restores journaled settings meanwhile.\n"
            )
            return EXIT_STATE_UNUSABLE
        except ConfigError as exc:
            sys.stderr.write(f"portlock: invalid configuration: {exc}\n")
            return EXIT_CONFIG
        return _serve(
            runtime,
            install_signal_handlers=install_signal_handlers,
            api_factory=api_factory,
            tick_seconds=tick_seconds,
            stopping=stopping,
            on_started=on_started,
        )
    finally:
        lock.release()


def _serve(
    runtime: Runtime,
    *,
    install_signal_handlers: bool,
    api_factory: Callable[[Runtime], ApiServerLike] | None,
    tick_seconds: float,
    stopping: threading.Event,
    on_started: Callable[[Runtime], None] | None,
) -> int:
    state_dir = Path(runtime.config.paths.state_dir)
    service = runtime.service
    api: ApiServerLike | None = None
    ticker: threading.Thread | None = None
    previous_handlers: dict[int, Any] = {}
    shutdown_started: list[float] = []
    code = EXIT_OK
    try:
        try:
            service.start(threads=True)
        except StoreError as exc:
            sys.stderr.write(f"portlock cannot write its state ({exc}).\n")
            return EXIT_STATE_UNUSABLE
        _show_initial_key(runtime)
        host, port = runtime.config.api.host, 0
        if api_factory is not None:
            try:
                api = api_factory(runtime)
                api.start()
                host, port = api.host, api.port
            except OSError as exc:
                sys.stderr.write(f"portlock: the API cannot listen ({exc}).\n")
                api = None
                return EXIT_PORT
        _write_runtime_file(
            state_dir,
            host=host,
            port=port,
            run_id=service.run_id,
            started_at=runtime.clock.now(),
            secret=runtime.cli_secret,
        )
        if install_signal_handlers:
            previous_handlers = _install_signals(stopping, shutdown_started)
        ticker = threading.Thread(
            target=_tick_loop,
            args=(service, state_dir, stopping, tick_seconds),
            name="portlock-ticker",
            daemon=True,
        )
        ticker.start()
        if on_started is not None:
            on_started(runtime)
        stopping.wait()
    except Exception as exc:
        _LOG.error("portlock stopped on an unexpected error", exc_info=exc)
        code = EXIT_ERROR
    finally:
        shutdown_started.append(time.monotonic())
        stopping.set()
        if ticker is not None:
            ticker.join(timeout=max(5.0, tick_seconds * 2))
        if api is not None:
            with contextlib.suppress(Exception):
                api.stop()
        try:
            service.stop()
        except PortLockError as exc:
            _LOG.error("stopping the service failed: %s", exc)
            code = EXIT_ERROR
        with contextlib.suppress(OSError):
            (state_dir / RUNTIME_FILE_NAME).unlink()
        runtime.close()
        for number, handler in previous_handlers.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(number, handler)
    return code


def _tick_loop(
    service: PortLockService, state_dir: Path, stopping: threading.Event, interval: float
) -> None:
    request = state_dir / STOP_REQUEST_NAME
    while not stopping.wait(interval):
        service.tick()
        if request.exists():
            with contextlib.suppress(OSError):
                request.unlink()
            stopping.set()


def _install_signals(stopping: threading.Event, shutdown_started: list[float]) -> dict[int, Any]:
    """SIGINT, SIGTERM (and SIGBREAK on Windows) stop the service.

    A second signal during shutdown is ignored for 10 seconds; after that it ends the
    process with exit code 1, for a shutdown that hangs.
    """

    def handler(number: int, frame: Any) -> None:
        if stopping.is_set() and shutdown_started:
            if time.monotonic() - shutdown_started[0] >= _SECOND_SIGNAL_GRACE:
                os._exit(EXIT_ERROR)
            return
        stopping.set()

    names = ["SIGINT", "SIGTERM", "SIGBREAK"]
    previous: dict[int, Any] = {}
    for name in names:
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            previous[number] = signal.signal(number, handler)
        except (ValueError, OSError):
            continue  # Not the main thread, or not supported here.
    return previous


def _show_initial_key(runtime: Runtime) -> None:
    """Show a newly created audit key once, and only to a person at a terminal."""
    key = runtime.initial_key
    if key is None:
        return
    stream = sys.stderr
    if stream is not None and stream.isatty():
        stream.write(
            "A new audit MAC key store was created. Keep this initial key offline; it is "
            f"shown only now:\n  {key.encode()}\n"
        )
    else:
        _LOG.warning(
            "a new audit MAC key store was created, but its initial key could not be shown "
            "(no terminal); create a new key store with 'portlock init' to obtain one"
        )
