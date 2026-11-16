"""Configuration: the model, its defaults, strict loading and a commented default file.

A :class:`Config` is an immutable value composed of immutable sections. It is validated
when it is built, however it is built, so a ``Config`` object that exists is one PortLock
may act on. In particular the two-setting rule for input devices (``docs/DESIGN.md``
section 2) cannot be bypassed by constructing the object in code instead of loading a
file.

Loading is strict and fails closed. An unknown key, a wrong type or an out-of-range value
is an error, never a warning, because a misspelt key in the configuration of a security
agent means a protection the operator believes is on and is not. Every problem in a file
is reported at once, each with its exact dotted path, so a broken file is fixed in one
pass.

Nothing in this module creates a directory, writes a file or asks the machine for its
host name. ``host_label`` is whatever the operator chose.

Where the directories come from, highest precedence first:

1. ``paths.state_dir`` / ``paths.config_dir`` set in the configuration file;
2. the ``PORTLOCK_HOME`` environment variable: ``<home>/state`` and ``<home>/config``;
3. for an elevated process (administrator or root; the caller says which), the
   system-wide default: ``%ProgramData%/PortLock`` on Windows (both directories),
   ``/var/lib/portlock`` and ``/etc/portlock`` elsewhere;
4. for an ordinary user, a per-user default: ``%LOCALAPPDATA%/PortLock/state`` and
   ``.../config`` on Windows, ``$XDG_STATE_HOME/portlock`` and ``$XDG_CONFIG_HOME/portlock``
   (``~/.local/state`` and ``~/.config`` when unset) elsewhere. A per-user installation
   is watch-only: :func:`paths_per_user` tells the guard layer so.
"""

from __future__ import annotations

import contextlib
import difflib
import ipaddress
import math
import ntpath
import os
import posixpath
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any

from portlock.core.errors import ConfigError
from portlock.core.models import Mode, Severity

__all__ = [
    "AUDIT_SINK_TYPES",
    "CONFIG_FILE_NAME",
    "DATABASE_FILE_NAME",
    "HOME_ENV",
    "KILL_SWITCH_FILE_NAME",
    "MAX_CONFIG_BYTES",
    "SCAN_ENGINES",
    "SCOPES",
    "SCOPE_ALL_EXCEPT_PROTECTED",
    "SCOPE_STORAGE",
    "SCOPE_STORAGE_AND_UNKNOWN",
    "ApiConfig",
    "AuditConfig",
    "AuditSinkConfig",
    "AuthConfig",
    "Config",
    "FlapGuardConfig",
    "GrantsConfig",
    "InvalidConfigError",
    "LockdownConfig",
    "PathsConfig",
    "ScanConfig",
    "config_to_toml",
    "default_config",
    "load_config",
    "paths_per_user",
]

#: Environment variable that relocates both directories under one home.
HOME_ENV = "PORTLOCK_HOME"
#: Name of the configuration file inside the configuration directory.
CONFIG_FILE_NAME = "portlock.toml"
#: Name of the state database inside the state directory.
DATABASE_FILE_NAME = "portlock.db"
#: Name of the kill-switch file inside the configuration directory (DESIGN section 11).
KILL_SWITCH_FILE_NAME = "DISABLE_ENFORCEMENT"
#: A configuration file larger than this is refused unread.
MAX_CONFIG_BYTES = 1024 * 1024

#: Only storage-like devices can be enforced against: mass storage, and imaging devices
#: (phones and cameras in MTP or PTP mode), which move files in both directions just the
#: same (DESIGN section 14.4). The default.
SCOPE_STORAGE = "storage"
#: Storage-like devices, plus devices that declare nothing recognisable (only "other" or
#: "vendor").
SCOPE_STORAGE_AND_UNKNOWN = "storage_and_unknown"
#: Everything that the safety layer does not protect.
SCOPE_ALL_EXCEPT_PROTECTED = "all_except_protected"
#: Every enforcement scope, narrowest first.
SCOPES: tuple[str, ...] = (SCOPE_STORAGE, SCOPE_STORAGE_AND_UNKNOWN, SCOPE_ALL_EXCEPT_PROTECTED)

#: Names accepted in ``scan.engines``.
SCAN_ENGINES: tuple[str, ...] = ("heuristics", "hashset", "clamav", "defender")
#: Values accepted for the ``type`` of an audit sink.
AUDIT_SINK_TYPES: tuple[str, ...] = ("file", "syslog", "clawnet")

_GIB = 1024**3
# scrypt cost: DESIGN section 8 fixes 2**17 as the floor; the ceiling keeps the memory of
# two concurrent verifications (128 * r * N bytes each, r = 8) at 1 GiB.
_SCRYPT_N_MIN = 2**17
_SCRYPT_N_MAX = 2**19
# DESIGN section 14.13: an operator's temporary grant, and any temporary grant to a
# low-confidence fingerprint, lasts at most 24 hours; the administrator's ceiling is a
# setting (30 days by default) bounded here to a year.
_OPERATOR_GRANT_CEILING_HOURS = 24
_LOW_CONFIDENCE_CEILING_HOURS = 24
_ADMIN_GRANT_CEILING_HOURS = 8760
_HOST_LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
_MAX_TEXT_LENGTH = 1024
_MAX_SINKS = 16
# The syslog target that means "this machine's own syslog socket".
_SYSLOG_LOCAL_TARGET = "local"
_WINDOWS_PROGRAM_DATA_FALLBACK = "C:\\ProgramData"

_LOCKOUT_RISK = (
    "enforcing against input devices can disable the only keyboard and mouse on this "
    "machine and leave nobody able to undo it; set acknowledge_lockout_risk = true only "
    "once there is another way in (a remote shell, or creating the DISABLE_ENFORCEMENT "
    "kill-switch file from another system)"
)


class InvalidConfigError(ConfigError):
    """A configuration failed validation.

    Attributes:
        problems: every fault found, each as ``"<dotted.path>: <what is wrong>"``.
        source: the file the configuration came from, or ``None`` if it was built in code.
    """

    def __init__(self, problems: Sequence[str], *, source: str | None = None) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        self.source = source
        where = f" ({source})" if source else ""
        count = len(self.problems)
        noun = "problem" if count == 1 else "problems"
        lines = "".join(f"\n  - {problem}" for problem in self.problems)
        super().__init__(f"invalid configuration{where}: {count} {noun}{lines}")


@dataclass(frozen=True, slots=True, kw_only=True)
class PathsConfig:
    """Where PortLock keeps its files. Both directories must be absolute.

    Attributes:
        state_dir: the database, the enforcement journal and key material.
        config_dir: the configuration file, the policy and the kill-switch file.
    """

    state_dir: Path
    config_dir: Path

    def __post_init__(self) -> None:
        for name in ("state_dir", "config_dir"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, Path(value))

    @classmethod
    def under(cls, home: str | os.PathLike[str]) -> PathsConfig:
        """The layout ``PORTLOCK_HOME`` gives: ``<home>/state`` and ``<home>/config``."""
        base = Path(home)
        return cls(state_dir=base / "state", config_dir=base / "config")

    @property
    def config_file(self) -> Path:
        """The configuration file :func:`load_config` reads when given no path."""
        return self.config_dir / CONFIG_FILE_NAME

    @property
    def database_file(self) -> Path:
        """The SQLite database holding audit records, accounts and grants."""
        return self.state_dir / DATABASE_FILE_NAME

    @property
    def kill_switch_file(self) -> Path:
        """If this file exists, PortLock restores every setting and only monitors."""
        return self.config_dir / KILL_SWITCH_FILE_NAME

    def to_dict(self) -> dict[str, Any]:
        return {"state_dir": _path_text(self.state_dir), "config_dir": _path_text(self.config_dir)}


@dataclass(frozen=True, slots=True, kw_only=True)
class ApiConfig:
    """The local HTTP API and web console.

    Attributes:
        host: a loopback IP address; anything else is refused.
        port: TCP port. ``0`` lets the operating system pick one (tests, simulation).
        session_idle_minutes: a session unused for this long is closed.
        session_max_hours: a session is closed after this long however busy it is.
    """

    host: str = "127.0.0.1"
    port: int = 47600
    session_idle_minutes: int = 15
    session_max_hours: int = 8

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "session_idle_minutes": self.session_idle_minutes,
            "session_max_hours": self.session_max_hours,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanConfig:
    """Limits and engines for scanning the volumes of a device that was granted access.

    Attributes:
        enabled: scan at all.
        max_files / max_bytes / max_seconds: a scan stops at whichever limit comes first.
        follow_symlinks: follow symbolic links that stay on the scanned volume.
        engines: which engines run, in order; names from :data:`SCAN_ENGINES`.
    """

    enabled: bool = True
    max_files: int = 20_000
    max_bytes: int = 2 * _GIB
    max_seconds: int = 120
    follow_symlinks: bool = False
    engines: tuple[str, ...] = SCAN_ENGINES

    def __post_init__(self) -> None:
        if isinstance(self.engines, list):
            object.__setattr__(self, "engines", tuple(self.engines))

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_files": self.max_files,
            "max_bytes": self.max_bytes,
            "max_seconds": self.max_seconds,
            "follow_symlinks": self.follow_symlinks,
            "engines": _as_list(self.engines),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class LockdownConfig:
    """Emergency lockdown and its dead-man timer.

    Attributes:
        default_minutes: how long a lockdown lasts when no duration is given.
        max_minutes: the longest a lockdown may be set or renewed for.
        allow_new_input_devices: keep accepting newly connected keyboards and mice
            during a lockdown, so the operator can still reach the machine.
    """

    default_minutes: int = 60
    max_minutes: int = 1440
    allow_new_input_devices: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_minutes": self.default_minutes,
            "max_minutes": self.max_minutes,
            "allow_new_input_devices": self.allow_new_input_devices,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthConfig:
    """Password and lockout rules for administrator accounts.

    Attributes:
        min_password_length: shortest password accepted; never below 12.
        lockout_threshold: consecutive failures before a delay is imposed.
        lockout_base_seconds: the first delay; it doubles with each further failure.
        lockout_max_seconds: the delay stops growing here.
        scrypt_n: the scrypt cost parameter N for new password hashes; a power of two
            from 2**17 (the design's value) to 2**19. Raising it re-hashes each
            password transparently at its next successful login.
        max_concurrent_verifications: at most this many password verifications run at
            once on the network path, so a flood of login attempts cannot exhaust
            memory (DESIGN section 14.21).
    """

    min_password_length: int = 12
    lockout_threshold: int = 5
    lockout_base_seconds: int = 30
    lockout_max_seconds: int = 900
    scrypt_n: int = _SCRYPT_N_MIN
    max_concurrent_verifications: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_password_length": self.min_password_length,
            "lockout_threshold": self.lockout_threshold,
            "lockout_base_seconds": self.lockout_base_seconds,
            "lockout_max_seconds": self.lockout_max_seconds,
            "scrypt_n": self.scrypt_n,
            "max_concurrent_verifications": self.max_concurrent_verifications,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class GrantsConfig:
    """Ceilings on temporary device grants (DESIGN section 14.13).

    Attributes:
        max_temporary_hours_operator: the longest temporary grant an operator may issue;
            at most 24.
        max_temporary_hours_admin: the longest temporary grant an administrator may
            issue; 720 (30 days) by default.
        low_confidence_max_hours: the longest temporary grant to a device whose
            fingerprint has low confidence (no unique-looking serial); at most 24. Such a
            grant is also bound to the port.
    """

    max_temporary_hours_operator: int = _OPERATOR_GRANT_CEILING_HOURS
    max_temporary_hours_admin: int = 720
    low_confidence_max_hours: int = _LOW_CONFIDENCE_CEILING_HOURS

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_temporary_hours_operator": self.max_temporary_hours_operator,
            "max_temporary_hours_admin": self.max_temporary_hours_admin,
            "low_confidence_max_hours": self.low_confidence_max_hours,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class FlapGuardConfig:
    """Port hold-down (DESIGN section 14.6; ``portlock.guard.safety.PortFlapGuard``).

    Attributes:
        max_arrivals: arrivals tolerated on one port within the window; one more holds
            the port blocked.
        window_seconds: length of the sliding window.
        cooldown_seconds: a held port is released after this long without an arrival.
    """

    max_arrivals: int = 5
    window_seconds: int = 30
    cooldown_seconds: int = 120

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_arrivals": self.max_arrivals,
            "window_seconds": self.window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditSinkConfig:
    """One place outside the local database that audit events are copied to.

    Attributes:
        type: one of :data:`AUDIT_SINK_TYPES`.
        target: where the copies go; always required, because nothing is sent anywhere
            unless the operator said where. For ``file`` an absolute path. For ``syslog``
            one of ``"local"`` (this machine's own syslog socket), the absolute path of
            a Unix-domain syslog socket (``/dev/log``), or a literal IP address and UDP
            port (``192.0.2.10:514``, ``[2001:db8::1]:514``). Host names are refused so
            that emitting an event never performs a DNS lookup, and on Windows only the
            address form is accepted because Windows has no local syslog socket. These
            are the forms ``portlock.audit.sinks.SyslogSink.from_target`` takes. For
            ``clawnet`` a channel name.
        min_severity: events below this severity are not sent to the sink.
    """

    type: str
    target: str
    min_severity: Severity = Severity.INFO

    def __post_init__(self) -> None:
        if isinstance(self.min_severity, str) and not isinstance(self.min_severity, Severity):
            # Accept the plain string a caller would naturally write; an unknown value
            # is left as it is and reported, with its path, when the Config is built.
            with contextlib.suppress(ValueError):
                object.__setattr__(self, "min_severity", Severity(self.min_severity))

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "target": self.target,
            "min_severity": _enum_value(self.min_severity),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditConfig:
    """Hardening of the audit log beyond its hash chain.

    Attributes:
        hmac_key_file: absolute path of a key file readable only by the service; when
            set, every record's hash is also authenticated under that key.
        sinks: external copies of the event stream.
    """

    hmac_key_file: Path | None = None
    sinks: tuple[AuditSinkConfig, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.hmac_key_file, str):
            object.__setattr__(self, "hmac_key_file", Path(self.hmac_key_file))
        if isinstance(self.sinks, list):
            object.__setattr__(self, "sinks", tuple(self.sinks))

    def to_dict(self) -> dict[str, Any]:
        sinks = self.sinks
        return {
            "hmac_key_file": _path_text(self.hmac_key_file),
            "sinks": [_section(sink, AuditSinkConfig) for sink in sinks]
            if isinstance(sinks, tuple)
            else sinks,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """The complete PortLock configuration.

    Attributes:
        paths: where state and configuration live.
        mode: ``monitor`` (the default: change nothing) or ``enforce``.
        scope: which devices may be enforced against; one of :data:`SCOPES`. The
            default, ``storage``, covers mass storage and imaging devices.
        hid_enforcement: allow enforcement against input devices. Needs
            ``acknowledge_lockout_risk`` and ``scope = "all_except_protected"``.
        acknowledge_lockout_risk: the operator's statement that they understand HID
            enforcement can disable their own keyboard and mouse.
        fail_closed: when a device cannot be evaluated, deny it instead of leaving it
            alone. Protected devices are never affected.
        commit_confirm_seconds: switching to enforce, widening the scope, turning on
            default-deny and engaging lockdown are rolled back unless confirmed within
            this many seconds over the same channel (DESIGN section 14.15).
        baseline_read_only: keep removable storage read-only as a standing baseline and
            release approved devices from it, the only dependable form of read-only
            (DESIGN section 14.14).
        api / scan / lockdown / auth / grants / flap_guard / audit: see the section
            classes. The API authenticates with bearer tokens only, so there are no
            cookie or CSRF settings.
        polling_interval_seconds: how often a backend without OS notifications looks
            for changes.
        host_label: an operator-chosen name for this machine, used in exported events.
            Never filled in from the real host name.

    Raises:
        InvalidConfigError: on construction, if any value is invalid. All problems are
            listed together.
    """

    paths: PathsConfig
    mode: Mode = Mode.MONITOR
    scope: str = SCOPE_STORAGE
    hid_enforcement: bool = False
    acknowledge_lockout_risk: bool = False
    fail_closed: bool = False
    commit_confirm_seconds: int = 60
    baseline_read_only: bool = False
    api: ApiConfig = field(default_factory=ApiConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    lockdown: LockdownConfig = field(default_factory=LockdownConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    grants: GrantsConfig = field(default_factory=GrantsConfig)
    flap_guard: FlapGuardConfig = field(default_factory=FlapGuardConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    polling_interval_seconds: float = 2.0
    host_label: str = "unnamed-host"

    def __post_init__(self) -> None:
        problems = _Problems()
        data = self.to_dict()
        # Every setting is present, so the defaults are never consulted; and the platform
        # the paths are meant for is not known here, so either path syntax is accepted.
        _check(data, data, None, problems)
        if problems:
            raise InvalidConfigError(problems.messages)
        # The values are known to be valid here; settle their types so that a Config
        # built from plain strings and integers equals one loaded from a file.
        object.__setattr__(self, "mode", Mode(self.mode))
        object.__setattr__(self, "polling_interval_seconds", float(self.polling_interval_seconds))

    @property
    def hid_enforcement_enabled(self) -> bool:
        """True only if both settings that HID enforcement requires are on.

        This, not ``hid_enforcement`` alone, is what the safety layer must be given.
        """
        return self.hid_enforcement is True and self.acknowledge_lockout_risk is True

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable description, in the same shape as the TOML file.

        ``audit.hmac_key_file`` is ``None`` when unset (the file simply omits it).
        """
        return {
            "mode": _enum_value(self.mode),
            "scope": self.scope,
            "hid_enforcement": self.hid_enforcement,
            "acknowledge_lockout_risk": self.acknowledge_lockout_risk,
            "fail_closed": self.fail_closed,
            "commit_confirm_seconds": self.commit_confirm_seconds,
            "baseline_read_only": self.baseline_read_only,
            "polling_interval_seconds": self.polling_interval_seconds,
            "host_label": self.host_label,
            "paths": _section(self.paths, PathsConfig),
            "api": _section(self.api, ApiConfig),
            "scan": _section(self.scan, ScanConfig),
            "lockdown": _section(self.lockdown, LockdownConfig),
            "auth": _section(self.auth, AuthConfig),
            "grants": _section(self.grants, GrantsConfig),
            "flap_guard": _section(self.flap_guard, FlapGuardConfig),
            "audit": _section(self.audit, AuditConfig),
        }


def default_config(
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    *,
    elevated: bool = True,
) -> Config:
    """The configuration PortLock runs with when there is no configuration file.

    Args:
        platform: a ``sys.platform`` value; ``"win32"`` selects the Windows layout and
            anything else the POSIX one. Defaults to the running platform.
        env: environment variables to consult (``PORTLOCK_HOME``, ``ProgramData``,
            ``LOCALAPPDATA``, ``USERPROFILE``, ``HOME``, ``XDG_STATE_HOME``,
            ``XDG_CONFIG_HOME``). Defaults to the process environment.
        elevated: whether the process that will use the directories is an administrator
            (root). ``True`` gives the system-wide directories, ``False`` the per-user
            ones. This module never asks the machine; the command line does
            (``core.privilege``) and passes the answer.

    Raises:
        ConfigError: if ``PORTLOCK_HOME`` (or another variable consulted) is a relative
            path, or no per-user directory can be found.
    """
    resolved_platform = sys.platform if platform is None else platform
    resolved_env = os.environ if env is None else env
    return Config(paths=_default_paths(resolved_platform, resolved_env, elevated=elevated))


def load_config(
    path: str | os.PathLike[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    elevated: bool = True,
) -> Config:
    """Read and validate a TOML configuration file.

    Settings the file does not mention keep their defaults (see :func:`default_config`).
    Loading never creates a directory or a file.

    Args:
        path: the file to read. ``None`` means ``portlock.toml`` in the default
            configuration directory, and in that case a missing file is not an error:
            the defaults are returned.
        env: environment variables to consult; defaults to the process environment.
        platform: a ``sys.platform`` value; defaults to the running platform.
        elevated: system-wide (``True``) or per-user (``False``) default directories;
            see :func:`default_config`.

    Raises:
        InvalidConfigError: if the file parses but its content is invalid. Unknown keys,
            wrong types and out-of-range values are each listed with their dotted path,
            all together.
        ConfigError: if the file cannot be read, is too large, is not UTF-8 or is not
            valid TOML, or if an explicitly named file does not exist.
    """
    resolved_platform = sys.platform if platform is None else platform
    resolved_env = os.environ if env is None else env
    defaults = default_config(resolved_platform, resolved_env, elevated=elevated)

    explicit = path is not None
    source = Path(path) if path is not None else defaults.paths.config_file
    text = _read_text(source, missing_ok=not explicit)
    if text is None:
        return defaults
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source} is not valid TOML: {exc}") from exc
    except RecursionError as exc:
        raise ConfigError(f"{source} is not valid TOML: nesting is too deep") from exc

    problems = _Problems()
    values = _check(document, defaults.to_dict(), resolved_platform, problems)
    if problems:
        raise InvalidConfigError(problems.messages, source=str(source))
    return _build(values)


def config_to_toml(config: Config) -> str:
    """Render a configuration as a commented TOML file.

    Every setting is written with its current value and a comment saying what it does,
    so ``config_to_toml(default_config())`` is the file an installer writes. Loading the
    result gives back an equal :class:`Config`.
    """
    data = config.to_dict()
    api, scan, lockdown = data["api"], data["scan"], data["lockdown"]
    auth, audit, paths = data["auth"], data["audit"], data["paths"]
    grants, flap_guard = data["grants"], data["flap_guard"]
    lines = [
        "# PortLock configuration.",
        "#",
        "# Loading is strict: an unknown key, a wrong type or an out-of-range value stops",
        "# PortLock from starting, and every problem is reported with its exact path.",
        "# A setting that is left out keeps its default.",
        "",
        '# "monitor" records what would have been done and changes nothing.',
        '# "enforce" has the operating system act on decisions.',
        f"mode = {_toml_string(data['mode'])}",
        "",
        "# Which devices may be enforced against. Anything outside the scope is left",
        "# alone and reported as not enforced (which is not the same as protected).",
        '#   "storage"               mass storage and imaging devices (phones and cameras',
        "#                           in MTP or PTP mode)",
        '#   "storage_and_unknown"   those, plus devices that declare nothing recognisable',
        '#   "all_except_protected"  everything the safety layer does not protect',
        f"scope = {_toml_string(data['scope'])}",
        "",
        "# Enforcing against keyboards, mice and other input-only devices. Off unless BOTH",
        "# of these are true, because it can disable the only keyboard on the machine and",
        '# leave nobody able to undo it. It also needs scope = "all_except_protected".',
        '# Input devices enrolled with "portlock enroll" stay protected on their port',
        "# regardless; merely being connected when the service starts protects nothing.",
        f"hid_enforcement = {_toml_bool(data['hid_enforcement'])}",
        f"acknowledge_lockout_risk = {_toml_bool(data['acknowledge_lockout_risk'])}",
        "",
        "# true: a device that cannot be evaluated is denied instead of left alone.",
        "# Protected devices are never affected.",
        f"fail_closed = {_toml_bool(data['fail_closed'])}",
        "",
        "# Switching to enforce, widening the scope, turning on default-deny and engaging",
        "# a lockdown are rolled back automatically unless confirmed within this many",
        "# seconds over the same channel (10 to 600).",
        f"commit_confirm_seconds = {data['commit_confirm_seconds']}",
        "",
        "# true: removable storage stays read-only as a standing baseline and approved",
        "# devices are released from it. Making a device read-only after it has mounted",
        "# does not take away write access the mount already has, so this is the only",
        "# dependable form of read-only.",
        f"baseline_read_only = {_toml_bool(data['baseline_read_only'])}",
        "",
        "# How often to look for device changes when the operating system cannot notify",
        "# PortLock of them (seconds, 0.1 to 3600).",
        f"polling_interval_seconds = {_toml_float(data['polling_interval_seconds'])}",
        "",
        "# A name you choose for this machine; it appears in exported events. PortLock",
        "# never fills this in from the real host name. Letters, digits, '.', '_', '-'.",
        f"host_label = {_toml_string(data['host_label'])}",
        "",
        "[paths]",
        "# Absolute directories. Set here, they win over the PORTLOCK_HOME environment",
        "# variable; delete them to use <PORTLOCK_HOME>/state and <PORTLOCK_HOME>/config,",
        "# or the operating-system default. PortLock never creates them while loading.",
        f"state_dir = {_toml_string(paths['state_dir'])}",
        f"config_dir = {_toml_string(paths['config_dir'])}",
        "",
        "[api]",
        "# The local HTTP API and web console. Only loopback IP addresses are accepted.",
        f"host = {_toml_string(api['host'])}",
        "# 0 lets the operating system pick a free port (tests and simulation).",
        f"port = {api['port']}",
        "# A session is closed after this long unused, and after this long regardless.",
        f"session_idle_minutes = {api['session_idle_minutes']}",
        f"session_max_hours = {api['session_max_hours']}",
        "",
        "[scan]",
        "# Scanning reads files; it never deletes or changes one.",
        f"enabled = {_toml_bool(scan['enabled'])}",
        "# A scan stops at whichever limit is reached first.",
        f"max_files = {scan['max_files']}",
        f"max_bytes = {scan['max_bytes']}",
        f"max_seconds = {scan['max_seconds']}",
        "# Symbolic links that leave the scanned volume are never followed.",
        f"follow_symlinks = {_toml_bool(scan['follow_symlinks'])}",
        '# Any of "heuristics", "hashset", "clamav", "defender". The antivirus adapters',
        "# are skipped when the product is not installed.",
        f"engines = {_toml_string_array(scan['engines'])}",
        "",
        "[lockdown]",
        "# The dead-man timer: a lockdown lifts itself after default_minutes unless it is",
        "# renewed, and can never be set for longer than max_minutes.",
        f"default_minutes = {lockdown['default_minutes']}",
        f"max_minutes = {lockdown['max_minutes']}",
        "# Keep accepting newly connected keyboards and mice during a lockdown, so the",
        "# operator can still reach the machine.",
        f"allow_new_input_devices = {_toml_bool(lockdown['allow_new_input_devices'])}",
        "",
        "[auth]",
        "# Shortest administrator password accepted (12 or more).",
        f"min_password_length = {auth['min_password_length']}",
        "# After this many consecutive failures a delay is imposed. It starts at",
        "# lockout_base_seconds and doubles up to lockout_max_seconds.",
        f"lockout_threshold = {auth['lockout_threshold']}",
        f"lockout_base_seconds = {auth['lockout_base_seconds']}",
        f"lockout_max_seconds = {auth['lockout_max_seconds']}",
        "# scrypt cost N for password hashes: a power of two from 131072 (2^17) to",
        "# 524288 (2^19). Raising it re-hashes each password at its next login.",
        f"scrypt_n = {auth['scrypt_n']}",
        "# At most this many password checks run at once on the network path (1 to 8).",
        f"max_concurrent_verifications = {auth['max_concurrent_verifications']}",
        "",
        "[grants]",
        "# The longest temporary device grant, in hours: an operator may grant at most",
        "# 24; an administrator at most max_temporary_hours_admin (up to 8760).",
        f"max_temporary_hours_operator = {grants['max_temporary_hours_operator']}",
        f"max_temporary_hours_admin = {grants['max_temporary_hours_admin']}",
        "# A device without a unique-looking serial number may only get a one-time grant",
        "# or a temporary grant of at most this many hours (1 to 24), bound to its port.",
        f"low_confidence_max_hours = {grants['low_confidence_max_hours']}",
        "",
        "[flap_guard]",
        "# A port that sees more than max_arrivals arrivals within window_seconds is held",
        "# blocked until cooldown_seconds pass without another arrival, so a device cannot",
        "# keep re-enumerating to reopen the moment before it is blocked.",
        f"max_arrivals = {flap_guard['max_arrivals']}",
        f"window_seconds = {flap_guard['window_seconds']}",
        f"cooldown_seconds = {flap_guard['cooldown_seconds']}",
        "",
        "[audit]",
        "# Absolute path of a key file readable only by the service. When set, every",
        "# audit record is also authenticated under that key.",
    ]
    if audit["hmac_key_file"] is None:
        lines.append('# hmac_key_file = "/absolute/path/to/audit-hmac.key"')
    else:
        lines.append(f"hmac_key_file = {_toml_string(audit['hmac_key_file'])}")
    lines += [
        "",
        "# Copies of the event stream kept where the local administrator cannot rewrite",
        '# them. type is "file", "syslog" or "clawnet"; min_severity is one of',
        f"# {', '.join(severity.value for severity in Severity)}.",
        '#   file     target = an absolute path, e.g. "/var/log/portlock/events.jsonl"',
        '#   syslog   target = "local" (the syslog socket of this machine), a socket path',
        '#            ("/dev/log"), or a literal IP address and UDP port',
        '#            ("192.0.2.10:514", "[2001:db8::1]:514"); host names are not',
        "#            resolved, and on Windows only the address form is available",
        "#   clawnet  target = a channel name",
    ]
    if not audit["sinks"]:
        lines += [
            "# [[audit.sinks]]",
            '# type = "file"',
            '# target = "/absolute/path/to/portlock-events.jsonl"',
            '# min_severity = "info"',
        ]
    for sink in audit["sinks"]:
        lines += [
            "",
            "[[audit.sinks]]",
            f"type = {_toml_string(sink['type'])}",
            f"target = {_toml_string(sink['target'])}",
            f"min_severity = {_toml_string(sink['min_severity'])}",
        ]
    return "\n".join(lines) + "\n"


# --- defaults --------------------------------------------------------------------------


def _is_windows(platform: str) -> bool:
    return platform == "win32"


def _flavour(platform: str) -> type[PurePath]:
    return PureWindowsPath if _is_windows(platform) else PurePosixPath


def _default_paths(platform: str, env: Mapping[str, str], *, elevated: bool) -> PathsConfig:
    flavour = _flavour(platform)
    home = env.get(HOME_ENV, "")
    if home.strip():
        # A relative home would put the database of a privileged service wherever the
        # process happened to be started from, so it is refused rather than resolved.
        if not flavour(home).is_absolute():
            raise ConfigError(f"{HOME_ENV} must be an absolute path, got {home!r}")
        base = flavour(home)
        return PathsConfig(
            state_dir=Path(str(base / "state")), config_dir=Path(str(base / "config"))
        )
    if not elevated:
        return _per_user_paths(platform, env)
    if _is_windows(platform):
        root = flavour(_program_data(env)) / "PortLock"
        return PathsConfig(state_dir=Path(str(root)), config_dir=Path(str(root)))
    return PathsConfig(state_dir=Path("/var/lib/portlock"), config_dir=Path("/etc/portlock"))


def _per_user_paths(platform: str, env: Mapping[str, str]) -> PathsConfig:
    """The directories an ordinary user's PortLock uses (watch-only)."""
    if _is_windows(platform):
        local = _env_path(env, "LOCALAPPDATA", PureWindowsPath)
        if local is None:
            profile = _env_path(env, "USERPROFILE", PureWindowsPath)
            if profile is None:
                raise ConfigError(
                    "no per-user directory was found (LOCALAPPDATA and USERPROFILE are unset);"
                    f" set {HOME_ENV} to an absolute directory"
                )
            local = profile / "AppData" / "Local"
        root = local / "PortLock"
        return PathsConfig(
            state_dir=Path(str(root / "state")), config_dir=Path(str(root / "config"))
        )
    user_home = _env_path(env, "HOME", PurePosixPath)
    # XDG base directories that are not absolute are invalid and ignored (the XDG Base
    # Directory specification says so), so the documented fallbacks apply.
    state_home = _env_path(env, "XDG_STATE_HOME", PurePosixPath)
    config_home = _env_path(env, "XDG_CONFIG_HOME", PurePosixPath)
    if state_home is None or config_home is None:
        if user_home is None:
            raise ConfigError(
                f"no per-user directory was found (HOME is unset); set {HOME_ENV} to an"
                " absolute directory"
            )
        state_home = state_home or user_home / ".local" / "state"
        config_home = config_home or user_home / ".config"
    return PathsConfig(
        state_dir=Path(str(state_home / "portlock")), config_dir=Path(str(config_home / "portlock"))
    )


def _env_path(env: Mapping[str, str], name: str, flavour: type[PurePath]) -> PurePath | None:
    """An absolute path from the environment, ``None`` when unset or not absolute.

    The name is matched without case, because ``os.environ`` is case-insensitive on
    Windows but a plain dict copy of it is not.
    """
    wanted = name.upper()
    for key, value in env.items():
        if key.upper() == wanted and value.strip():
            candidate = flavour(value)
            return candidate if candidate.is_absolute() else None
    return None


def paths_per_user(
    paths: PathsConfig, *, platform: str | None = None, env: Mapping[str, str] | None = None
) -> bool:
    """True unless both directories are provably system-wide locations.

    A directory is per-user when it lies inside the current user's own profile: on
    Windows ``USERPROFILE``, ``LOCALAPPDATA`` and ``APPDATA`` (a profile whose application
    data was redirected), elsewhere ``HOME`` unless it is ``/``. Such a directory belongs
    to the user, and every program the user runs can change it, so it cannot hold the
    state of an enforcing service: a process using it is watch-only (``guard.watchonly``).

    Another spelling of the profile must not pass for a system-wide location. When
    ``platform`` is the running system, both sides are resolved with
    :func:`os.path.realpath` (8.3 short names, ``..``, junctions, symbolic links and
    ``subst`` drives all resolve to the real profile). For a foreign ``platform`` (tests)
    only the names are compared, after normalisation. It fails closed: a UNC or
    device-namespace path (``\\\\server\\share``, ``\\\\?\\C:\\...``, ``\\\\.\\...``),
    a relative path, or a profile variable that is set but empty, relative or
    unresolvable makes the answer True.
    """
    resolved_platform = sys.platform if platform is None else platform
    resolved_env = os.environ if env is None else env
    windows = _is_windows(resolved_platform)
    native = windows == (sys.platform == "win32")
    roots: list[str] = []
    for name in ("USERPROFILE", "LOCALAPPDATA", "APPDATA") if windows else ("HOME",):
        value = _env_value(resolved_env, name, windows=windows)
        if value is None:
            continue
        root = _comparable(value, windows=windows, native=native)
        if root is None:
            return True
        if not windows and root == "/":
            # Root's home is "/" on many systems: that is the whole disk, not a profile.
            continue
        roots.append(root)
    for directory in (paths.state_dir, paths.config_dir):
        # A POSIX path held in a Windows ``Path`` (tests on Windows) prints with
        # backslashes; ``as_posix`` gives back the name as written.
        text = str(directory) if windows else PurePath(directory).as_posix()
        candidate = _comparable(text, windows=windows, native=native)
        if candidate is None:
            return True
        if any(_within(candidate, root, windows=windows) for root in roots):
            return True
    return False


def _env_value(env: Mapping[str, str], name: str, *, windows: bool) -> str | None:
    """The raw value of an environment variable, ``None`` when it is not set at all.

    On Windows the name is matched without case, because ``os.environ`` is
    case-insensitive there but a plain dict copy of it is not.
    """
    if not windows:
        return env.get(name)
    wanted = name.upper()
    for key, value in env.items():
        if key.upper() == wanted:
            return value
    return None


def _comparable(text: str, *, windows: bool, native: bool) -> str | None:
    """``text`` as an absolute, normalised path string to compare, or ``None`` (fail closed)."""
    if not text.strip() or "\x00" in text:
        return None
    if windows:
        # UNC (\\server\share, also \\localhost\C$) and device namespaces (\\?\, \\.\)
        # name the same disk in ways a prefix comparison cannot follow.
        if text.replace("/", "\\").startswith("\\\\"):
            return None
        if not PureWindowsPath(text).is_absolute():
            return None
    elif not PurePosixPath(text).is_absolute():
        return None
    if native:
        try:
            resolved = os.path.realpath(text)
        except (OSError, ValueError):
            return None
    else:
        resolved = ntpath.normpath(text) if windows else posixpath.normpath(text)
    if windows:
        # realpath turns a mapped network drive into a UNC path: not provably local.
        if resolved.replace("/", "\\").startswith("\\\\"):
            return None
        return ntpath.normcase(ntpath.normpath(resolved))
    return posixpath.normpath(resolved)


def _within(candidate: str, root: str, *, windows: bool) -> bool:
    separator = "\\" if windows else "/"
    return candidate == root or candidate.startswith(root.rstrip(separator) + separator)


def _program_data(env: Mapping[str, str]) -> str:
    # os.environ is case-insensitive on Windows, but a plain dict copy of it is not.
    for name, value in env.items():
        if name.upper() == "PROGRAMDATA" and value.strip():
            if not PureWindowsPath(value).is_absolute():
                raise ConfigError(f"ProgramData must be an absolute path, got {value!r}")
            return value
    return _WINDOWS_PROGRAM_DATA_FALLBACK


def _read_text(source: Path, *, missing_ok: bool) -> str | None:
    try:
        with open(source, "rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ConfigError(f"configuration file not found: {source}") from None
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file {source}: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"configuration file {source} is larger than {MAX_CONFIG_BYTES} bytes; refusing it"
        )
    try:
        # Editors on Windows like to add a byte-order mark; tomllib would reject it.
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"configuration file {source} is not valid UTF-8") from exc


# --- validation ------------------------------------------------------------------------

_MISSING: Any = object()


class _Problems:
    """Collects validation problems, remembering which paths they were about."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self._paths: set[str] = set()

    def add(self, path: str, message: str) -> None:
        self.messages.append(f"{path}: {message}")
        self._paths.add(path)

    def clean(self, *paths: str) -> bool:
        """True if none of ``paths`` has a problem (so a cross-check on them is fair)."""
        return self._paths.isdisjoint(paths)

    def __bool__(self) -> bool:
        return bool(self.messages)


class _Table:
    """Reads the keys of one table, reporting each fault with its dotted path.

    A key that is absent yields its default. A key that is present but invalid is
    reported and yields a harmless filler, so that one bad value never hides the
    problems after it; a filler is never used to build a :class:`Config`, because by
    then there is a problem on record.
    """

    def __init__(
        self, data: Any, defaults: Any, prefix: str, problems: _Problems, *, quiet: bool = False
    ) -> None:
        self._data: Mapping[str, Any] = data if isinstance(data, Mapping) else {}
        self._defaults: Mapping[str, Any] = defaults if isinstance(defaults, Mapping) else {}
        self._prefix = prefix
        self._problems = problems
        # Set for a table whose own value was faulty: that fault is already on record,
        # and complaining about each setting "missing" from it would only bury it.
        self._quiet = quiet
        self._known: list[str] = []

    def path(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def _take(self, key: str) -> Any:
        self._known.append(key)
        return self._data.get(key, _MISSING)

    def _fail(self, key: str, message: str) -> None:
        if not self._quiet:
            self._problems.add(self.path(key), message)

    def boolean(self, key: str) -> bool:
        value = self._take(key)
        if value is _MISSING:
            return self._defaults.get(key) is True
        if not isinstance(value, bool):
            self._fail(key, f"expected true or false, got {_describe(value)}")
            return False
        return value

    def integer(self, key: str, minimum: int, maximum: int) -> int:
        value = self._take(key)
        if value is _MISSING:
            value = self._defaults.get(key, minimum)
        if isinstance(value, bool) or not isinstance(value, int):
            self._fail(key, f"expected an integer, got {_describe(value)}")
            return minimum
        if not minimum <= value <= maximum:
            self._fail(key, f"must be between {minimum} and {maximum}, got {value}")
            return minimum
        return value

    def number(self, key: str, minimum: float, maximum: float) -> float:
        value = self._take(key)
        if value is _MISSING:
            value = self._defaults.get(key, minimum)
        if isinstance(value, bool) or not isinstance(value, int | float):
            self._fail(key, f"expected a number, got {_describe(value)}")
            return minimum
        # Written so that NaN, which TOML can express, fails the comparison.
        if not (math.isfinite(value) and minimum <= value <= maximum):
            self._fail(key, f"must be between {minimum} and {maximum}, got {value}")
            return minimum
        return float(value)

    def string(self, key: str, *, optional: bool = False, required: bool = False) -> str | None:
        """A non-empty, single-line string.

        ``optional`` lets the setting be unset (``None``); ``required`` makes its absence
        a problem instead of falling back to a default.
        """
        value = self._take(key)
        if value is _MISSING:
            if required:
                self._fail(key, "is required")
                return None
            value = self._defaults.get(key)
        if value is None and optional:
            return None
        if not isinstance(value, str):
            self._fail(key, f"expected a string, got {_describe(value)}")
            return None
        if not value.strip():
            self._fail(key, "must not be empty")
            return None
        if len(value) > _MAX_TEXT_LENGTH:
            self._fail(key, f"must not be longer than {_MAX_TEXT_LENGTH} characters")
            return None
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            self._fail(key, "must not contain control characters")
            return None
        return value

    def absolute_path(
        self,
        key: str,
        platform: str | None,
        *,
        optional: bool = False,
        required: bool = False,
    ) -> str | None:
        """A :meth:`string` that must also be an absolute path for ``platform``."""
        value = self.string(key, optional=optional, required=required)
        if value is not None and not _is_absolute(value, platform):
            self._fail(key, f"must be an absolute path, got {_describe(value)}")
            return None
        return value

    def choice(self, key: str, choices: Sequence[str], *, required: bool = False) -> str:
        value = self._take(key)
        if value is _MISSING:
            if required:
                self._fail(key, f"is required: one of {_quoted(choices)}")
                return choices[0]
            value = self._defaults.get(key)
        if not isinstance(value, str) or value not in choices:
            self._fail(key, f"must be one of {_quoted(choices)}, got {_describe(value)}")
            return choices[0]
        return value

    def array(self, key: str) -> list[Any] | None:
        """The array under ``key`` (its default if absent), or ``None`` if it is not one."""
        value = self._take(key)
        if value is _MISSING:
            value = self._defaults.get(key, [])
        if not isinstance(value, list | tuple):
            self._fail(key, f"expected an array, got {_describe(value)}")
            return None
        return list(value)

    def table(self, key: str) -> _Table:
        """The sub-table under ``key``.

        If the value is not a table, that is the one problem reported; its settings then
        read as their defaults and add no further noise.
        """
        value = self._take(key)
        broken = value is not _MISSING and not isinstance(value, Mapping)
        if broken:
            self._fail(key, f"expected a table, got {_describe(value)}")
        return _Table(
            value,
            self._defaults.get(key),
            f"{self.path(key)}.",
            self._problems,
            quiet=broken or self._quiet,
        )

    def finish(self) -> None:
        """Report every key that nothing asked for."""
        for key in self._data:
            if key in self._known:
                continue
            hint = difflib.get_close_matches(str(key), self._known, n=1)
            suffix = f" (did you mean {hint[0]!r}?)" if hint else ""
            self._fail(str(key), f"unknown key{suffix}")


def _check(
    data: Mapping[str, Any],
    defaults: Mapping[str, Any],
    platform: str | None,
    problems: _Problems,
) -> dict[str, Any]:
    """Validate a configuration in plain-data form and return the settled values.

    Args:
        data: the configuration as nested tables (a parsed TOML document, or
            :meth:`Config.to_dict` output).
        defaults: the value of every setting ``data`` may leave out, in the same shape.
        platform: selects which path syntax counts as absolute; ``None`` accepts either.
        problems: receives every fault found.
    """
    root = _Table(data, defaults, "", problems)
    values: dict[str, Any] = {
        "mode": root.choice("mode", [mode.value for mode in Mode]),
        "scope": root.choice("scope", SCOPES),
        "hid_enforcement": root.boolean("hid_enforcement"),
        "acknowledge_lockout_risk": root.boolean("acknowledge_lockout_risk"),
        "fail_closed": root.boolean("fail_closed"),
        "commit_confirm_seconds": root.integer("commit_confirm_seconds", 10, 600),
        "baseline_read_only": root.boolean("baseline_read_only"),
        "polling_interval_seconds": root.number("polling_interval_seconds", 0.1, 3600.0),
        "host_label": root.string("host_label"),
    }
    label = values["host_label"]
    if label is not None and not _HOST_LABEL_PATTERN.match(label):
        problems.add(
            "host_label",
            "must be 1 to 63 characters, start with a letter or digit and contain only "
            f"letters, digits, '.', '_' and '-'; got {_describe(label)}",
        )

    paths = root.table("paths")
    values["paths"] = {
        "state_dir": paths.absolute_path("state_dir", platform),
        "config_dir": paths.absolute_path("config_dir", platform),
    }
    paths.finish()

    api = root.table("api")
    values["api"] = {
        "host": api.string("host"),
        "port": api.integer("port", 0, 65535),
        "session_idle_minutes": api.integer("session_idle_minutes", 1, 1440),
        "session_max_hours": api.integer("session_max_hours", 1, 168),
    }
    api.finish()
    _check_loopback(values["api"]["host"], problems)
    _check_not_above(
        problems,
        "api.session_idle_minutes",
        values["api"]["session_idle_minutes"],
        "api.session_max_hours",
        values["api"]["session_max_hours"] * 60,
        unit="minutes",
    )

    scan = root.table("scan")
    values["scan"] = {
        "enabled": scan.boolean("enabled"),
        "max_files": scan.integer("max_files", 1, 10_000_000),
        "max_bytes": scan.integer("max_bytes", 1, 1024 * _GIB),
        "max_seconds": scan.integer("max_seconds", 1, 86_400),
        "follow_symlinks": scan.boolean("follow_symlinks"),
        "engines": _check_engines(scan, problems),
    }
    scan.finish()

    lockdown = root.table("lockdown")
    values["lockdown"] = {
        "default_minutes": lockdown.integer("default_minutes", 1, 10_080),
        "max_minutes": lockdown.integer("max_minutes", 1, 10_080),
        "allow_new_input_devices": lockdown.boolean("allow_new_input_devices"),
    }
    lockdown.finish()
    _check_not_above(
        problems,
        "lockdown.default_minutes",
        values["lockdown"]["default_minutes"],
        "lockdown.max_minutes",
        values["lockdown"]["max_minutes"],
        unit="minutes",
    )

    auth = root.table("auth")
    values["auth"] = {
        "min_password_length": auth.integer("min_password_length", 12, 128),
        "lockout_threshold": auth.integer("lockout_threshold", 1, 100),
        "lockout_base_seconds": auth.integer("lockout_base_seconds", 1, 3600),
        "lockout_max_seconds": auth.integer("lockout_max_seconds", 1, 86_400),
        "scrypt_n": auth.integer("scrypt_n", _SCRYPT_N_MIN, _SCRYPT_N_MAX),
        "max_concurrent_verifications": auth.integer("max_concurrent_verifications", 1, 8),
    }
    auth.finish()
    scrypt_n = values["auth"]["scrypt_n"]
    if problems.clean("auth.scrypt_n") and scrypt_n & (scrypt_n - 1):
        problems.add("auth.scrypt_n", f"must be a power of two, got {scrypt_n}")
    _check_not_above(
        problems,
        "auth.lockout_base_seconds",
        values["auth"]["lockout_base_seconds"],
        "auth.lockout_max_seconds",
        values["auth"]["lockout_max_seconds"],
        unit="seconds",
    )

    grants = root.table("grants")
    values["grants"] = {
        "max_temporary_hours_operator": grants.integer(
            "max_temporary_hours_operator", 1, _OPERATOR_GRANT_CEILING_HOURS
        ),
        "max_temporary_hours_admin": grants.integer(
            "max_temporary_hours_admin", 1, _ADMIN_GRANT_CEILING_HOURS
        ),
        "low_confidence_max_hours": grants.integer(
            "low_confidence_max_hours", 1, _LOW_CONFIDENCE_CEILING_HOURS
        ),
    }
    grants.finish()
    _check_not_above(
        problems,
        "grants.max_temporary_hours_operator",
        values["grants"]["max_temporary_hours_operator"],
        "grants.max_temporary_hours_admin",
        values["grants"]["max_temporary_hours_admin"],
        unit="hours",
    )

    flap_guard = root.table("flap_guard")
    values["flap_guard"] = {
        "max_arrivals": flap_guard.integer("max_arrivals", 2, 100),
        "window_seconds": flap_guard.integer("window_seconds", 1, 3600),
        "cooldown_seconds": flap_guard.integer("cooldown_seconds", 1, 86_400),
    }
    flap_guard.finish()

    audit = root.table("audit")
    values["audit"] = {
        "hmac_key_file": audit.absolute_path("hmac_key_file", platform, optional=True),
        "sinks": _check_sinks(audit, platform, problems),
    }
    audit.finish()
    root.finish()

    if problems.clean("hid_enforcement", "acknowledge_lockout_risk", "scope"):
        _check_hid_rules(values, problems)
    return values


def _check_not_above(
    problems: _Problems, path: str, value: int, limit_path: str, limit: int, *, unit: str
) -> None:
    """Cross-check two settings, but only if each was valid on its own."""
    if problems.clean(path, limit_path) and value > limit:
        problems.add(path, f"must not exceed {limit_path} ({limit} {unit}), got {value}")


def _check_hid_rules(values: Mapping[str, Any], problems: _Problems) -> None:
    if not values["hid_enforcement"]:
        return
    if not values["acknowledge_lockout_risk"]:
        problems.add(
            "hid_enforcement", f"requires acknowledge_lockout_risk = true: {_LOCKOUT_RISK}"
        )
    if values["scope"] != SCOPE_ALL_EXCEPT_PROTECTED:
        # Refused rather than ignored: a setting that silently does nothing would let
        # an operator believe input devices are being enforced against.
        problems.add(
            "hid_enforcement",
            f'has no effect unless scope = "{SCOPE_ALL_EXCEPT_PROTECTED}" (scope is '
            f'"{values["scope"]}", which never covers input devices); change scope or '
            "turn hid_enforcement off",
        )


def _check_loopback(host: str | None, problems: _Problems) -> None:
    if host is None:
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        problems.add(
            "api.host",
            "must be a loopback IP address such as 127.0.0.1 or ::1 (host names are "
            f"refused because they can be made to resolve elsewhere), got {_describe(host)}",
        )
        return
    # An IPv4-mapped IPv6 address and a scoped address are refused outright: whether
    # they count as loopback has changed between Python versions, and neither is needed.
    mapped = isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
    if "%" in host or mapped or not address.is_loopback:
        problems.add(
            "api.host",
            "must be a loopback address (127.0.0.1 or ::1), because the API must not be "
            f"reachable from the network; got {_describe(host)}",
        )


def _check_engines(scan: _Table, problems: _Problems) -> list[str]:
    path = scan.path("engines")
    engines: list[str] = []
    for index, item in enumerate(scan.array("engines") or ()):
        if not isinstance(item, str) or item not in SCAN_ENGINES:
            problems.add(
                f"{path}[{index}]",
                f"must be one of {_quoted(SCAN_ENGINES)}, got {_describe(item)}",
            )
        elif item in engines:
            problems.add(f"{path}[{index}]", f"duplicate engine {item!r}")
        else:
            engines.append(item)
    return engines


def _check_sinks(audit: _Table, platform: str | None, problems: _Problems) -> list[dict[str, Any]]:
    path = audit.path("sinks")
    raw = audit.array("sinks") or []
    if len(raw) > _MAX_SINKS:
        problems.add(path, f"at most {_MAX_SINKS} sinks are supported, got {len(raw)}")
        return []
    sink_defaults = {"min_severity": Severity.INFO.value}
    severities = [severity.value for severity in Severity]
    sinks: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        item_path = f"{path}[{index}]"
        if not isinstance(item, Mapping):
            problems.add(item_path, f"expected a table, got {_describe(item)}")
            continue
        table = _Table(item, sink_defaults, f"{item_path}.", problems)
        kind = table.choice("type", AUDIT_SINK_TYPES, required=True)
        if not problems.clean(table.path("type")):
            # Without a usable type there is no telling what the target should be, so
            # it is only noted as a known key.
            target = table.string("target", optional=True)
        elif kind == "file":
            target = table.absolute_path("target", platform, required=True)
        else:
            target = table.string("target", required=True)
            if kind == "syslog" and target is not None:
                fault = _syslog_target_fault(target, platform)
                if fault is not None:
                    problems.add(table.path("target"), f"{fault}; got {_describe(target)}")
        severity = table.choice("min_severity", severities)
        table.finish()
        sinks.append({"type": kind, "target": target, "min_severity": severity})
    return sinks


def _build(values: Mapping[str, Any]) -> Config:
    paths, audit = values["paths"], values["audit"]
    return Config(
        paths=PathsConfig(state_dir=Path(paths["state_dir"]), config_dir=Path(paths["config_dir"])),
        mode=Mode(values["mode"]),
        scope=values["scope"],
        hid_enforcement=values["hid_enforcement"],
        acknowledge_lockout_risk=values["acknowledge_lockout_risk"],
        fail_closed=values["fail_closed"],
        commit_confirm_seconds=values["commit_confirm_seconds"],
        baseline_read_only=values["baseline_read_only"],
        api=ApiConfig(**values["api"]),
        scan=ScanConfig(**{**values["scan"], "engines": tuple(values["scan"]["engines"])}),
        lockdown=LockdownConfig(**values["lockdown"]),
        auth=AuthConfig(**values["auth"]),
        grants=GrantsConfig(**values["grants"]),
        flap_guard=FlapGuardConfig(**values["flap_guard"]),
        audit=AuditConfig(
            hmac_key_file=Path(audit["hmac_key_file"]) if audit["hmac_key_file"] else None,
            sinks=tuple(
                AuditSinkConfig(
                    type=sink["type"],
                    target=sink["target"],
                    min_severity=Severity(sink["min_severity"]),
                )
                for sink in audit["sinks"]
            ),
        ),
        polling_interval_seconds=values["polling_interval_seconds"],
        host_label=values["host_label"],
    )


# --- helpers ---------------------------------------------------------------------------


def _syslog_target_fault(text: str, platform: str | None) -> str | None:
    """Why ``text`` is not a usable syslog target, or ``None`` if it is one.

    Accepts what ``portlock.audit.sinks.SyslogSink.from_target`` accepts, so that a
    configuration which loads is one the sink can be built from. ``platform`` is ``None``
    when the platform the configuration is meant for is not known.
    """
    if text == _SYSLOG_LOCAL_TARGET or text.startswith("/"):
        if platform is not None and _is_windows(platform):
            return (
                "Windows has no local syslog socket; give a literal IP address and port "
                'such as "192.0.2.10:514"'
            )
        return None
    if _is_udp_address(text):
        return None
    return (
        f'must be "{_SYSLOG_LOCAL_TARGET}", a socket path such as "/dev/log", or a literal '
        'IP address and port such as "192.0.2.10:514" or "[2001:db8::1]:514" (host names '
        "are not resolved)"
    )


def _is_udp_address(text: str) -> bool:
    """True for ``ip:port`` or ``[ip]:port`` with a literal address and a port 1-65535."""
    host, separator, port_text = text.rpartition(":")
    if not separator or not port_text.isascii() or not port_text.isdigit():
        return False
    if len(port_text) > 5 or not 1 <= int(port_text) <= 65535:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        # A bare IPv6 address cannot be told apart from its port; require the brackets.
        return False
    if "%" in host:
        # A scoped address names a network interface of one particular machine.
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_absolute(text: str, platform: str | None) -> bool:
    if platform is None:
        return PureWindowsPath(text).is_absolute() or PurePosixPath(text).is_absolute()
    return _flavour(platform)(text).is_absolute()


def _section(value: Any, expected: type) -> Any:
    """A section as plain data; anything that is not the expected section is passed on
    untouched so that validation can report it instead of this function crashing."""
    return value.to_dict() if isinstance(value, expected) else value


def _path_text(value: Any) -> Any:
    """A path as text; anything else is passed on for validation to report."""
    if not isinstance(value, PurePath):
        return value
    if isinstance(value, PureWindowsPath) and value.root and not value.drive:
        # A rooted path without a drive is POSIX syntax that the Windows path type has
        # re-spelt with backslashes (a Linux configuration handled on a Windows host).
        # Give it back the way it was written.
        return value.as_posix()
    return str(value)


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Mode | Severity) else value


def _as_list(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value


def _quoted(choices: Sequence[str]) -> str:
    return ", ".join(f'"{choice}"' for choice in choices)


def _describe(value: Any) -> str:
    """Name a value and its TOML type for an error message, without dumping it whole."""
    if value is None:
        return "nothing"
    if isinstance(value, bool):
        return f"the boolean {'true' if value else 'false'}"
    if isinstance(value, int):
        return f"the integer {value}"
    if isinstance(value, float):
        return f"the number {value}"
    if isinstance(value, str):
        shown = value if len(value) <= 40 else value[:37] + "..."
        return f"the string {shown!r}"
    if isinstance(value, Mapping):
        return "a table"
    if isinstance(value, list | tuple):
        return "an array"
    return f"a value of type {type(value).__name__}"


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _toml_float(value: float) -> str:
    text = repr(float(value))
    # TOML wants digits on both sides of the point; repr() always gives them for the
    # finite values validation lets through.
    return text if "." in text or "e" in text else f"{text}.0"


def _toml_string(value: str) -> str:
    """A TOML basic string. Backslashes (Windows paths) and quotes are escaped."""
    escaped: list[str] = []
    for char in value:
        if char in ('"', "\\"):
            escaped.append("\\" + char)
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped.append("\\" + f"u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _toml_string_array(values: Sequence[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"
