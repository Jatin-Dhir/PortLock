"""Administrator accounts, roles, lockout and recovery codes.

:class:`AccountStore` owns three tables: the accounts, their recovery codes, and the
throttle that implements the lockout from ``docs/DESIGN.md`` sections 8 and 14.21.

Two channels
------------

Every attempt names its :class:`Channel`:

* :attr:`Channel.NETWORK` is the HTTP API, the path strangers can reach. It is the
  default. Password attempts on it are subject to the lockout below, and at most
  ``AuthPolicy.max_network_verifications`` (two) passwords are checked at once: a further
  attempt is answered at once with :attr:`AuthFailure.BUSY` and a one-second
  ``retry_after_seconds``, without being counted, evaluated or audited, instead of
  waiting for a turn. Each check needs about 128 MiB, so this is what bounds the memory
  and time a flood of logins can take.
* :attr:`Channel.LOCAL` is the elevated command line on the machine itself, usable only
  by someone the operating system already trusts with PortLock's state (the caller
  establishes that). It is **never** locked out and never refused as busy (it waits for
  a hashing slot instead), so guessing at the API cannot keep the administrator out.
  Failures on it are still audited.

Recovery codes are never locked out on either channel. They are 128-bit random values,
so a guess has no realistic chance, and refusing them would hand an attacker a way to
lock the administrator out of the very thing meant to let them back in.

How the lockout works
---------------------

It applies to password attempts on the network channel only. Five consecutive failures
start a delay of 30 seconds that doubles with every further failure up to 15 minutes.
The state is persisted and read with the injected clock, so neither a restart nor a
second process (the CLI beside the service) resets it.

* **An attempt is charged before the secret is looked at.** In one short transaction the
  attempt is either refused because a lockout is running, or counted as a failure. Only
  then is the password evaluated, outside any lock, and a success refunds the charge.
  However many threads or processes guess at once, no more than the threshold can get a
  password evaluated before the lockout engages.
* **A refused attempt changes nothing.** The password is not evaluated, the counter does
  not move and the lockout is not extended, so hammering a locked account cannot stretch
  a 15-minute delay into a permanent one. It is not even a database write, and only the
  first refusal of each lockout is audited, so it cannot flood the disk or the log. A
  lockout that reads as longer than the maximum (the wall clock was set back, or the row
  was edited) is cut to the maximum.
* **Unknown user names behave exactly like known ones.** They are charged, locked out
  and timed the same way: a decoy hash is verified so the work is comparable. The
  throttle is keyed by a digest of the name, kept in one bounded table for real and
  unknown names alike, so neither the responses nor the table's eviction reveal which
  names exist. Names that could never be a user name share a single entry.
* **Failures are forgotten after a quiet day** (``AuthPolicy.failure_memory``). This
  never gives a guesser more than the lockout already allows (one guess per 15 minutes).

The lockout as a denial-of-service lever
----------------------------------------

Anyone who can reach the API can lock an account's network password counter by guessing,
and can keep it locked by guessing again each time the delay runs out, or keep both
network verification slots busy. That must not keep the administrator out, and it
cannot:

* the local channel has no lockout and no busy answer;
* recovery codes are never locked out, on either channel;
* an operating-system administrator can always run the administrative reset
  (:meth:`AccountStore.set_password`), which also clears the counter, and another
  PortLock administrator can call :meth:`AccountStore.clear_lockout`;
* a lockout does not end sessions that are already open.

Logging in at the console does not reset the network counter: that would hand the API
guesser a fresh start.

Sessions follow the account
---------------------------

Given a ``sessions`` store, :class:`AccountStore` ends every session of an account in
the same transaction that changes its password (a change or a reset), changes its role,
disables it or deletes it, so a stolen bearer token stops working the moment the account
is secured.

What is recorded
----------------

Every security-relevant action is reported through the ``audit`` callback. The data
never contains a password, a hash, a recovery code or a token. A user name that does not
belong to an account is not recorded either (people type passwords into the user-name
field), only the fact that the name was unknown.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import math
import re
import secrets
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Protocol

from portlock.auth.passwords import (
    DEFAULT_PARAMS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    ScryptParams,
    check_password_policy,
    hash_password,
    needs_rehash,
    normalize_password,
    verify_password,
)
from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.db import Database
from portlock.core.errors import AuthError, ConfigError, StoreError
from portlock.core.models import Severity

__all__ = [
    "AccountStore",
    "AuditCallback",
    "AuthFailure",
    "AuthMethod",
    "AuthPolicy",
    "AuthResult",
    "AuthenticationError",
    "Channel",
    "InvalidUsernameError",
    "LastAdminError",
    "Permission",
    "Role",
    "SessionRevoker",
    "UnknownUserError",
    "User",
    "UserExistsError",
    "can",
    "normalize_username",
]

#: ``audit(event_type, severity, data)``.
AuditCallback = Callable[[str, Severity, dict[str, Any]], None]


class SessionRevoker(Protocol):
    """What :class:`AccountStore` needs from the session store: ending an account's sessions.

    ``portlock.auth.sessions.SessionStore`` provides it. It must work on the same
    :class:`~portlock.core.db.Database` as the account store, because it is called inside
    the account store's transaction so that the change and the revocation commit
    together.
    """

    def revoke_all(self, username: str) -> int:
        """End every session of ``username``; return how many were ended."""
        ...


EVENT_LOGIN = "auth.login"
EVENT_FAILURE = "auth.failure"
EVENT_LOCKOUT = "auth.lockout"
EVENT_PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105 - an event name
EVENT_RECOVERY_USED = "auth.recovery_used"
EVENT_USER_CREATED = "auth.user_created"
EVENT_USER_CHANGED = "auth.user_changed"

_USERNAME_PATTERN = re.compile(r"[a-z0-9._-]{3,32}\Z")
# Throttle name shared by every string that can never be a user name. "*" is not a legal
# user-name character, so it cannot collide with an account.
_UNUSABLE_NAME = "*"

# In-process serialization of attempts on one counter: how many locks the counters are
# spread over, and how long an attempt waits for its turn before going ahead regardless.
_ATTEMPT_LOCKS = 64
_ATTEMPT_WAIT_SECONDS = 5.0
# A stored failure count is read as at most this. Every count this high already earns
# the maximum delay (the threshold is at most 100 and the delay stops growing after 32
# doublings), so nothing is lost, and a counter edited to an absurd value can never be
# incremented past what SQLite is able to store.
_MAX_COUNTED_FAILURES = 1000
# What a network attempt refused as busy is told to wait. Verifications take well under
# a second, so by then a slot is normally free again.
_BUSY_RETRY_SECONDS = 1

_RECOVERY_CODE_BYTES = 16  # 128 bits
_RECOVERY_CODE_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_MAX_RECOVERY_CODE_INPUT = 128

_MIGRATIONS = (
    """
    CREATE TABLE auth_users (
        username            TEXT PRIMARY KEY CHECK (username = lower(username)),
        role                TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
        password_hash       TEXT NOT NULL,
        enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at          TEXT NOT NULL,
        password_changed_at TEXT NOT NULL,
        last_login_at       TEXT
    );
    CREATE TABLE auth_recovery_codes (
        id          INTEGER PRIMARY KEY,
        username    TEXT NOT NULL REFERENCES auth_users (username) ON DELETE CASCADE,
        code_digest TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        used_at     TEXT
    );
    CREATE INDEX auth_recovery_codes_username ON auth_recovery_codes (username);
    CREATE TABLE auth_throttle (
        subject         TEXT PRIMARY KEY,
        failures        INTEGER NOT NULL,
        locked_until    TEXT,
        last_failure_at TEXT NOT NULL,
        refused         INTEGER NOT NULL DEFAULT 0
    );
    """,
)


class Role(enum.StrEnum):
    """What an account is for."""

    ADMIN = "admin"
    #: Day-to-day handling of devices: approve, grant temporarily, scan, raise the alarm.
    OPERATOR = "operator"
    #: Reads everything, changes nothing.
    AUDITOR = "auditor"


class Permission(enum.StrEnum):
    """One thing the console or the API lets an account do."""

    VIEW = "view"
    APPROVE_DEVICE = "approve_device"
    ISSUE_TEMPORARY_GRANT = "issue_temporary_grant"
    MANAGE_TRUST = "manage_trust"
    EDIT_POLICY = "edit_policy"
    MANAGE_USERS = "manage_users"
    ENGAGE_LOCKDOWN = "engage_lockdown"
    LIFT_LOCKDOWN = "lift_lockdown"
    CHANGE_MODE = "change_mode"
    VIEW_AUDIT = "view_audit"
    EXPORT_AUDIT = "export_audit"
    RUN_SCAN = "run_scan"


_ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.ADMIN: frozenset(Permission),
        # An operator may raise a lockdown (it only ever restricts) but not lift one,
        # and may not grant permanent trust, edit policy or leave enforce mode: each of
        # those can open the machine up.
        Role.OPERATOR: frozenset(
            {
                Permission.VIEW,
                Permission.VIEW_AUDIT,
                Permission.APPROVE_DEVICE,
                Permission.ISSUE_TEMPORARY_GRANT,
                Permission.RUN_SCAN,
                Permission.ENGAGE_LOCKDOWN,
            }
        ),
        Role.AUDITOR: frozenset({Permission.VIEW, Permission.VIEW_AUDIT, Permission.EXPORT_AUDIT}),
    }
)


def can(role: Role | str, permission: Permission | str) -> bool:
    """Whether ``role`` includes ``permission``. Anything unrecognised is refused."""
    try:
        return Permission(permission) in _ROLE_PERMISSIONS[Role(role)]
    except (ValueError, TypeError, KeyError):
        return False


class Channel(enum.StrEnum):
    """Where an authentication attempt came from; see the module documentation."""

    #: The HTTP API. The default, because it is the one strangers can reach: locked out
    #: after repeated failures, and limited to a few verifications at once.
    NETWORK = "network"
    #: The elevated command line on the machine itself. Never locked out.
    LOCAL = "local"


class AuthMethod(enum.StrEnum):
    """What was presented. Recorded in audit data."""

    PASSWORD = "password"  # noqa: S105 - the name of a method
    RECOVERY_CODE = "recovery_code"


class AuthFailure(enum.StrEnum):
    """Why an authentication attempt did not succeed."""

    #: Wrong password, or no such account. Deliberately indistinguishable.
    INVALID_CREDENTIALS = "invalid_credentials"
    #: Refused without looking at the password; see ``retry_after_seconds``.
    LOCKED_OUT = "locked_out"
    #: The password was right, but the account has been disabled.
    ACCOUNT_DISABLED = "account_disabled"
    #: Network only: enough passwords are being checked already. Nothing was counted or
    #: evaluated; retry after ``retry_after_seconds``.
    BUSY = "busy"


class InvalidUsernameError(AuthError):
    """A user name is not 3 to 32 characters from ``a-z 0-9 . _ -``."""

    code = "invalid_username"


class UnknownUserError(AuthError):
    """An administrative operation named an account that does not exist."""

    code = "unknown_user"


class UserExistsError(AuthError):
    """An account with that name (in any letter case) already exists."""

    code = "user_exists"


class LastAdminError(AuthError):
    """The change would leave PortLock without an enabled administrator."""

    code = "last_admin"


class AuthenticationError(AuthError):
    """A password that had to be confirmed was not accepted.

    Attributes:
        reason: why; also available as ``code``.
        retry_after_seconds: how long a lockout has left to run, 0 if none.
    """

    def __init__(self, reason: AuthFailure, retry_after_seconds: int = 0) -> None:
        super().__init__(_FAILURE_MESSAGES[reason], code=reason.value)
        self.reason = reason
        self.retry_after_seconds = retry_after_seconds


_FAILURE_MESSAGES: Mapping[AuthFailure, str] = MappingProxyType(
    {
        AuthFailure.INVALID_CREDENTIALS: "the user name or password is not correct",
        AuthFailure.LOCKED_OUT: "too many failed attempts; try again later",
        AuthFailure.ACCOUNT_DISABLED: "this account is disabled",
        AuthFailure.BUSY: "too many sign-ins are being checked; retry in a moment",
    }
)


def normalize_username(username: object) -> str:
    """The stored form of a user name: lower case, validated.

    User names are unique without regard to case, so ``Alice`` and ``alice`` are the
    same account and both normalize to ``alice``. Only ASCII is folded.

    Raises:
        InvalidUsernameError: if it is not 3 to 32 characters from ``a-z 0-9 . _ -``.
    """
    if isinstance(username, str) and username.isascii():
        name = username.lower()
        if _USERNAME_PATTERN.match(name):
            return name
    raise InvalidUsernameError(
        "a user name is 3 to 32 characters: letters, digits, dot, underscore, hyphen"
    )


@dataclass(frozen=True, slots=True)
class User:
    """An account, without its secrets."""

    username: str
    role: Role
    enabled: bool
    created_at: datetime
    password_changed_at: datetime
    last_login_at: datetime | None = None

    def can(self, permission: Permission | str) -> bool:
        """Whether this account may do ``permission``. A disabled account may do nothing."""
        return self.enabled and can(self.role, permission)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable description for the API and the console."""
        return {
            "username": self.username,
            "role": self.role.value,
            "enabled": self.enabled,
            "created_at": utc_iso(self.created_at),
            "password_changed_at": utc_iso(self.password_changed_at),
            "last_login_at": utc_iso(self.last_login_at) if self.last_login_at else None,
        }


@dataclass(frozen=True, slots=True)
class AuthResult:
    """The outcome of :meth:`AccountStore.authenticate`.

    Attributes:
        ok: True if the password was accepted.
        user: the account, when ``ok``.
        reason: why not, when not ``ok``.
        retry_after_seconds: how long the caller must wait before another attempt is
            even considered. Set on a refused attempt and on the failure that starts a
            lockout; 0 otherwise.
    """

    ok: bool
    user: User | None = None
    reason: AuthFailure | None = None
    retry_after_seconds: int = 0


@dataclass(frozen=True, slots=True)
class AuthPolicy:
    """The knobs of account security. Defaults are the values in ``docs/DESIGN.md``.

    Attributes:
        scrypt: cost parameters for new password hashes.
        min_password_length: shortest acceptable password; cannot go below 12.
        lockout_threshold: consecutive failures that start the delay (1 to 100, the
            range the configuration file accepts).
        lockout_base: the first delay.
        lockout_max: the delay stops doubling here.
        failure_memory: failures older than this, with no lockout running, are forgotten.
        recovery_code_count: codes issued per account.
        max_throttle_entries: upper bound on lockout records kept, so that guessing at
            made-up names cannot grow the database without limit.
        max_concurrent_hashes: password hashes computed at once, on every path. Each
            needs about 128 MiB, so this bounds the memory hashing can take. Callers
            beyond it wait their turn.
        max_network_verifications: password checks on the network channel at once
            (design value 2). An attempt beyond it is not queued but answered
            :attr:`AuthFailure.BUSY`.

    Raises:
        ConfigError: if a value is of the wrong type or out of range.
    """

    scrypt: ScryptParams = DEFAULT_PARAMS
    min_password_length: int = MIN_PASSWORD_LENGTH
    lockout_threshold: int = 5
    lockout_base: timedelta = timedelta(seconds=30)
    lockout_max: timedelta = timedelta(minutes=15)
    failure_memory: timedelta = timedelta(hours=24)
    recovery_code_count: int = 8
    max_throttle_entries: int = 50_000
    max_concurrent_hashes: int = 4
    max_network_verifications: int = 2

    def __post_init__(self) -> None:
        if not isinstance(self.scrypt, ScryptParams):
            raise ConfigError("auth policy: scrypt must be a ScryptParams")
        for name, low, high in (
            ("min_password_length", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH),
            ("lockout_threshold", 1, 100),
            ("recovery_code_count", 1, 32),
            ("max_throttle_entries", 16, 10_000_000),
            ("max_concurrent_hashes", 1, 64),
            ("max_network_verifications", 1, 16),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ConfigError(f"auth policy: {name} must be an integer from {low} to {high}")
        for name in ("lockout_base", "lockout_max", "failure_memory"):
            if not isinstance(getattr(self, name), timedelta):
                raise ConfigError(f"auth policy: {name} must be a timedelta")
        if self.lockout_base < timedelta(seconds=1):
            raise ConfigError("auth policy: lockout_base must be at least one second")
        if self.lockout_max < self.lockout_base:
            raise ConfigError("auth policy: lockout_max must not be shorter than lockout_base")
        if self.failure_memory < self.lockout_max:
            raise ConfigError("auth policy: failure_memory must not be shorter than lockout_max")

    def lockout_delay(self, failures: int) -> timedelta | None:
        """The delay that ``failures`` consecutive failures earn, or ``None`` for none yet."""
        doublings = failures - self.lockout_threshold
        if doublings < 0:
            return None
        # Past 32 doublings the answer is the maximum whatever the base; stopping there
        # keeps the arithmetic small however large a stored counter is.
        if doublings >= 32:
            return self.lockout_max
        return min(self.lockout_base * (2**doublings), self.lockout_max)


@dataclass(frozen=True, slots=True)
class _Record:
    """An account together with the hash that was read with it."""

    user: User
    password_hash: str


@dataclass(frozen=True, slots=True)
class _Gate:
    """What the throttle decided about one attempt.

    Attributes:
        subject: the throttle key the attempt was counted under.
        locked: refused; the secret must not be evaluated.
        retry_after: seconds before another attempt will be considered.
        failures: consecutive failures including this attempt (if it turns out wrong).
        engaged: this attempt, if it turns out wrong, is one that starts a lockout.
        first_rejection: the first refused attempt of the lockout now running.
    """

    subject: str
    locked: bool
    retry_after: int = 0
    failures: int = 0
    engaged: bool = False
    first_rejection: bool = False


def _throttle_name(username: object) -> str:
    try:
        return normalize_username(username)
    except InvalidUsernameError:
        return _UNUSABLE_NAME


def _subject(name: str) -> str:
    """The throttle key of a name's network password counter.

    A digest, so the table never holds what was typed as a name.
    """
    material = f"portlock-throttle\x00network\x00password\x00{name}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _channel(value: Channel | str) -> Channel:
    try:
        return Channel(value)
    except ValueError:
        raise AuthError("unknown authentication channel", code="invalid_channel") from None


def _role(value: Role | str) -> Role:
    try:
        return Role(value)
    except ValueError:
        raise AuthError("unknown role", code="invalid_role") from None


def _whole_seconds(delta: timedelta) -> int:
    return max(0, math.ceil(delta.total_seconds()))


def _code_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _format_recovery_code(raw: bytes) -> str:
    text = raw.hex()
    return "-".join(text[index : index + 4] for index in range(0, len(text), 4))


def _parse_recovery_code(code: object) -> bytes | None:
    """The 16 bytes behind a code as a person might retype it, or ``None``."""
    if not isinstance(code, str) or len(code) > _MAX_RECOVERY_CODE_INPUT:
        return None
    compact = "".join(char for char in code.lower() if char != "-" and not char.isspace())
    if not _RECOVERY_CODE_PATTERN.match(compact):
        return None
    return bytes.fromhex(compact)


def _user_from_row(row: sqlite3.Row) -> User:
    try:
        if row["enabled"] not in (0, 1):
            raise ValueError("enabled flag")
        last_login = row["last_login_at"]
        return User(
            username=normalize_username(row["username"]),
            role=Role(row["role"]),
            enabled=row["enabled"] == 1,
            created_at=parse_utc_iso(row["created_at"]),
            password_changed_at=parse_utc_iso(row["password_changed_at"]),
            last_login_at=parse_utc_iso(last_login) if last_login is not None else None,
        )
    except (ValueError, TypeError, InvalidUsernameError) as exc:
        # Someone edited the table by hand. An account that cannot be read is not used.
        raise StoreError("an account record is corrupt and has been refused") from exc


class AccountStore:
    """Accounts, authentication, lockout and recovery codes, kept in one database.

    Safe to call from several threads, and from several processes that open the same
    database file: every read-then-write runs in a transaction, and the database is not
    held while a password is being hashed. Do not call :meth:`authenticate`,
    :meth:`change_password` or :meth:`use_recovery_code` from inside your own
    ``db.transaction()``: that would hold the database for the length of a hash.

    One known rough edge: attempts are charged before they are evaluated, so if more
    correct logins than the lockout threshold reach one account at the same instant
    *from different processes*, the surplus are refused as locked out and succeed when
    retried. Within one process they are queued instead.

    Account changes are audited inside the transaction that makes them, so a change is
    not kept if it could not be recorded. Authentication attempts are audited after
    their outcome is committed, so a slow audit sink never holds the database.

    With ``sessions``, :meth:`change_password`, :meth:`set_password`, :meth:`set_role`,
    :meth:`disable_user` and :meth:`delete_user` end every session of the account inside
    their own transaction, and the audit record says how many (``sessions_revoked``).
    Without it the caller must do that itself.

    Args:
        db: the database; the ``auth`` tables are created or migrated here.
        clock: source of time for lockouts and timestamps.
        audit: receives ``(event_type, severity, data)`` for every security-relevant
            action. ``None`` records nothing.
        policy: see :class:`AuthPolicy`.
        sessions: the session store to revoke from (normally a ``SessionStore`` on the
            same database), or ``None``.

    Raises:
        ConfigError: if ``policy`` is not an :class:`AuthPolicy`.
        StoreError: if the tables cannot be created or are from a newer version.
    """

    def __init__(
        self,
        db: Database,
        *,
        clock: Clock,
        audit: AuditCallback | None = None,
        policy: AuthPolicy,
        sessions: SessionRevoker | None = None,
    ) -> None:
        if not isinstance(policy, AuthPolicy):
            raise ConfigError("policy must be an AuthPolicy")
        if sessions is not None and not callable(getattr(sessions, "revoke_all", None)):
            raise ConfigError("sessions must provide revoke_all(username)")
        self._db = db
        self._clock = clock
        self._audit = audit
        self._policy = policy
        self._sessions = sessions
        self._hash_slots = threading.BoundedSemaphore(policy.max_concurrent_hashes)
        self._network_slots = threading.BoundedSemaphore(policy.max_network_verifications)
        self._attempt_locks = tuple(threading.Lock() for _ in range(_ATTEMPT_LOCKS))
        db.migrate("auth", _MIGRATIONS)
        # Verified in place of a real hash when the user name is unknown. Made now, with
        # the configured cost, so that such an attempt takes as long as any other.
        self._decoy_hash = self._hash(secrets.token_urlsafe(32))

    @property
    def policy(self) -> AuthPolicy:
        return self._policy

    # --- accounts --------------------------------------------------------------------

    def has_users(self) -> bool:
        """True once the first account exists (first-run set-up is over)."""
        return self._db.query_one("SELECT 1 FROM auth_users LIMIT 1") is not None

    def list_users(self) -> list[User]:
        """Every account, ordered by user name."""
        rows = self._db.query("SELECT * FROM auth_users ORDER BY username")
        return [_user_from_row(row) for row in rows]

    def get_user(self, username: str) -> User | None:
        """The account with this name (any letter case), or ``None``."""
        try:
            name = normalize_username(username)
        except InvalidUsernameError:
            return None
        row = self._fetch(name)
        return _user_from_row(row) if row is not None else None

    def create_user(
        self, username: str, password: str, role: Role | str, *, actor: str | None = None
    ) -> User:
        """Create an account.

        Args:
            username: 3 to 32 characters from ``a-z 0-9 . _ -``; upper case is folded.
            password: must satisfy the password policy.
            role: the first account must be an administrator.
            actor: who is doing this, for the audit record.

        Raises:
            InvalidUsernameError: for a malformed user name.
            PasswordPolicyError: if the password is too weak.
            UserExistsError: if the name is taken.
            AuthError: code ``invalid_role``, or ``first_user_must_be_admin``.
        """
        name = normalize_username(username)
        new_role = _role(role)
        self._require_acceptable(password, name)
        encoded = self._hash(password)
        with self._db.transaction():
            if self._fetch(name) is not None:
                raise UserExistsError(f"the user {name} already exists")
            if new_role is not Role.ADMIN and not self.has_users():
                raise AuthError(
                    "the first user must be an administrator", code="first_user_must_be_admin"
                )
            now = utc_iso(self._clock.now())
            self._db.execute(
                "INSERT INTO auth_users (username, role, password_hash, enabled, created_at,"
                " password_changed_at) VALUES (?, ?, ?, 1, ?, ?)",
                (name, new_role.value, encoded, now, now),
            )
            # Failures recorded against the name before it was an account are not this
            # account's failures.
            self._clear_throttle(name)
            user = self._require_user(name)
            self._emit(
                EVENT_USER_CREATED,
                Severity.NOTICE,
                {"username": name, "role": new_role.value, "actor": actor},
            )
        return user

    def set_role(self, username: str, role: Role | str, *, actor: str | None = None) -> User:
        """Change an account's role.

        Raises:
            UnknownUserError: if there is no such account.
            LastAdminError: if this would demote the last enabled administrator.
            AuthError: code ``invalid_role``.
        """
        name = normalize_username(username)
        new_role = _role(role)
        with self._db.transaction():
            user = self._require_user(name)
            if user.role is new_role:
                return user
            if new_role is not Role.ADMIN:
                self._refuse_if_last_admin(user, "demoted")
            self._db.execute(
                "UPDATE auth_users SET role = ? WHERE username = ?", (new_role.value, name)
            )
            self._emit(
                EVENT_USER_CHANGED,
                Severity.NOTICE,
                {
                    "username": name,
                    "change": "role",
                    "old_role": user.role.value,
                    "role": new_role.value,
                    "actor": actor,
                    **self._revoke_sessions(name),
                },
            )
            return replace(user, role=new_role)

    def disable_user(self, username: str, *, actor: str | None = None) -> User:
        """Stop an account from authenticating, keeping its record.

        Raises:
            UnknownUserError: if there is no such account.
            LastAdminError: if it is the last enabled administrator.
        """
        return self._set_enabled(username, False, actor)

    def enable_user(self, username: str, *, actor: str | None = None) -> User:
        """Let a disabled account authenticate again.

        Raises:
            UnknownUserError: if there is no such account.
        """
        return self._set_enabled(username, True, actor)

    def delete_user(self, username: str, *, actor: str | None = None) -> None:
        """Remove an account and its recovery codes.

        Raises:
            UnknownUserError: if there is no such account.
            LastAdminError: if it is the last enabled administrator.
        """
        name = normalize_username(username)
        with self._db.transaction():
            user = self._require_user(name)
            self._refuse_if_last_admin(user, "deleted")
            self._db.execute("DELETE FROM auth_users WHERE username = ?", (name,))
            self._emit(
                EVENT_USER_CHANGED,
                Severity.NOTICE,
                {
                    "username": name,
                    "change": "deleted",
                    "role": user.role.value,
                    "actor": actor,
                    **self._revoke_sessions(name),
                },
            )

    # --- passwords -------------------------------------------------------------------

    def authenticate(
        self, username: str, password: str, *, channel: Channel | str = Channel.NETWORK
    ) -> AuthResult:
        """Check a user name and password.

        Never raises for bad credentials or hostile input; the result says what
        happened. A wrong password and an unknown user name are indistinguishable, in
        the result and in the time taken. On success the stored hash is replaced if it
        was made with other parameters than the configured ones (:func:`needs_rehash`),
        and a network success resets the network failure counter.

        On the network channel the attempt may be refused without evaluation:
        :attr:`AuthFailure.LOCKED_OUT` during a lockout, :attr:`AuthFailure.BUSY` when
        enough passwords are already being checked. The local channel is never refused.

        Args:
            username: as typed; letter case is ignored.
            password: as typed.
            channel: where the attempt came from; see :class:`Channel`. Pass
                :attr:`Channel.LOCAL` only for the elevated command line.

        Raises:
            AuthError: code ``invalid_channel`` (a programming error in the caller).
            StoreError: if the database fails or the account record is corrupt.
        """
        return self._attempt_password(username, password, _channel(channel), login=True)

    def verify_password(
        self, username: str, password: str, *, channel: Channel | str = Channel.NETWORK
    ) -> AuthResult:
        """Check a password to confirm a sensitive action by an already signed-in user.

        Exactly :meth:`authenticate` (lockout, busy refusal, failure counting and the
        rest), except that a success is not a sign-in: it records no login and does not
        touch ``last_login_at``.

        Raises:
            AuthError: code ``invalid_channel`` (a programming error in the caller).
            StoreError: if the database fails or the account record is corrupt.
        """
        return self._attempt_password(username, password, _channel(channel), login=False)

    def change_password(
        self,
        username: str,
        old: str,
        new: str,
        *,
        channel: Channel | str = Channel.NETWORK,
    ) -> None:
        """Change a password, proving knowledge of the current one.

        The current password is checked exactly as :meth:`authenticate` checks it,
        lockout and busy refusal included, so this cannot be used to guess faster. With
        a session store, every session of the account ends, the caller's included.

        Raises:
            AuthenticationError: if the current password is not accepted (``reason``
                says why, including ``busy``).
            PasswordPolicyError: if the new password is too weak or unchanged.
        """
        result = self._attempt_password(username, old, _channel(channel), login=False)
        if not result.ok or result.user is None:
            raise AuthenticationError(
                result.reason or AuthFailure.INVALID_CREDENTIALS, result.retry_after_seconds
            )
        name = result.user.username
        problems = self._policy_problems(new, name)
        if not problems and normalize_password(new) == normalize_password(old):
            problems = ["must differ from the current password"]
        if problems:
            raise PasswordPolicyError(tuple(problems))
        self._store_password(name, self._hash(new), how="change", actor=name)

    def set_password(self, username: str, new: str, *, actor: str | None = None) -> None:
        """Set a password without knowing the old one, and clear the account's lockouts.

        This is the administrative reset. The caller is responsible for having
        authorized it (another administrator, or operating-system administrator rights
        on the console).

        Raises:
            UnknownUserError: if there is no such account.
            PasswordPolicyError: if the new password is too weak.
        """
        name = normalize_username(username)
        if self._fetch(name) is None:
            raise UnknownUserError(f"there is no user {name}")
        self._require_acceptable(new, name)
        self._store_password(name, self._hash(new), how="reset", actor=actor)

    def lockout_remaining(self, username: str, *, channel: Channel | str = Channel.NETWORK) -> int:
        """Seconds until a password attempt for this name would be considered again.

        0 if now, and always 0 on the local channel, which is never locked out. Answers
        for unknown names exactly as for accounts.

        Raises:
            AuthError: code ``invalid_channel``.
        """
        if _channel(channel) is Channel.LOCAL:
            return 0
        subject = _subject(_throttle_name(username))
        row = self._db.query_one("SELECT * FROM auth_throttle WHERE subject = ?", (subject,))
        if row is None:
            return 0
        now = self._clock.now()
        _failures, locked_until, _last = self._throttle_state(row, now)
        return _whole_seconds(locked_until - now) if locked_until is not None else 0

    def clear_lockout(self, username: str, *, actor: str | None = None) -> None:
        """Forget an account's failed network password attempts, ending any lockout.

        Raises:
            UnknownUserError: if there is no such account.
        """
        name = normalize_username(username)
        with self._db.transaction():
            self._require_user(name)
            self._clear_throttle(name)
            self._emit(
                EVENT_USER_CHANGED,
                Severity.NOTICE,
                {"username": name, "change": "lockout_cleared", "actor": actor},
            )

    # --- recovery codes --------------------------------------------------------------

    def generate_recovery_codes(self, username: str, *, actor: str | None = None) -> list[str]:
        """Issue a fresh set of single-use recovery codes, invalidating any earlier set.

        Each code is 128 random bits, shown as eight groups of four hexadecimal digits.
        Only SHA-256 digests are stored: this return value is the one time the codes
        exist in readable form.

        Raises:
            UnknownUserError: if there is no such account.
        """
        name = normalize_username(username)
        codes = [
            secrets.token_bytes(_RECOVERY_CODE_BYTES)
            for _ in range(self._policy.recovery_code_count)
        ]
        with self._db.transaction():
            self._require_user(name)
            now = utc_iso(self._clock.now())
            self._db.execute("DELETE FROM auth_recovery_codes WHERE username = ?", (name,))
            for raw in codes:
                self._db.execute(
                    "INSERT INTO auth_recovery_codes (username, code_digest, created_at)"
                    " VALUES (?, ?, ?)",
                    (name, _code_digest(raw), now),
                )
            self._emit(
                EVENT_USER_CHANGED,
                Severity.NOTICE,
                {
                    "username": name,
                    "change": "recovery_codes_generated",
                    "count": len(codes),
                    "actor": actor,
                },
            )
        return [_format_recovery_code(raw) for raw in codes]

    def use_recovery_code(
        self, username: str, code: str, *, channel: Channel | str = Channel.NETWORK
    ) -> bool:
        """Spend a recovery code. True exactly once per code.

        Never locked out, on either channel (see the module documentation), and not
        limited by the network verification slots: checking a code is one SHA-256.
        Returns False for a wrong, malformed or already-used code and for an unknown or
        disabled account; the caller cannot tell which. Every failure is audited.

        Args:
            username: the account the code belongs to.
            code: as typed; letter case, spaces and hyphens are ignored.
            channel: where the attempt came from.

        Raises:
            AuthError: code ``invalid_channel``.
        """
        return self._evaluate_recovery_code(_throttle_name(username), code, _channel(channel))

    def remaining_recovery_codes(self, username: str) -> int:
        """How many unused recovery codes an account has left.

        Raises:
            UnknownUserError: if there is no such account.
        """
        name = normalize_username(username)
        with self._db.transaction():
            self._require_user(name)
            return self._count_unused_codes(name)

    # --- internals: accounts ---------------------------------------------------------

    def _emit(self, event_type: str, severity: Severity, data: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit(event_type, severity, data)

    def _fetch(self, name: str) -> sqlite3.Row | None:
        return self._db.query_one("SELECT * FROM auth_users WHERE username = ?", (name,))

    def _require_user(self, name: str) -> User:
        row = self._fetch(name)
        if row is None:
            raise UnknownUserError(f"there is no user {name}")
        return _user_from_row(row)

    def _load(self, name: str) -> _Record | None:
        if name == _UNUSABLE_NAME:
            return None
        row = self._fetch(name)
        if row is None:
            return None
        return _Record(_user_from_row(row), str(row["password_hash"]))

    def _refuse_if_last_admin(self, user: User, verb: str) -> None:
        """Raise unless another enabled administrator would remain. Call in a transaction."""
        if user.role is not Role.ADMIN or not user.enabled:
            return
        others = self._db.query_one(
            "SELECT COUNT(*) AS n FROM auth_users WHERE role = ? AND enabled = 1 AND username != ?",
            (Role.ADMIN.value, user.username),
        )
        if others is None or int(others["n"]) == 0:
            raise LastAdminError(
                f"{user.username} is the last enabled administrator and cannot be {verb}"
            )

    def _set_enabled(self, username: str, enabled: bool, actor: str | None) -> User:
        name = normalize_username(username)
        with self._db.transaction():
            user = self._require_user(name)
            if user.enabled is enabled:
                return user
            if not enabled:
                self._refuse_if_last_admin(user, "disabled")
            self._db.execute(
                "UPDATE auth_users SET enabled = ? WHERE username = ?", (int(enabled), name)
            )
            self._emit(
                EVENT_USER_CHANGED,
                Severity.NOTICE,
                {
                    "username": name,
                    "change": "enabled" if enabled else "disabled",
                    "actor": actor,
                    **({} if enabled else self._revoke_sessions(name)),
                },
            )
            return replace(user, enabled=enabled)

    # --- internals: passwords --------------------------------------------------------

    def _hash(self, password: str) -> str:
        with self._hash_slots:
            return hash_password(password, params=self._policy.scrypt)

    def _verify(self, password: str, encoded: str) -> bool:
        with self._hash_slots:
            return verify_password(password, encoded)

    def _policy_problems(self, password: str, name: str) -> list[str]:
        return check_password_policy(
            password, min_length=self._policy.min_password_length, username=name
        )

    def _require_acceptable(self, password: str, name: str) -> None:
        problems = self._policy_problems(password, name)
        if problems:
            raise PasswordPolicyError(tuple(problems))

    def _store_password(self, name: str, encoded: str, *, how: str, actor: str | None) -> None:
        with self._db.transaction():
            cursor = self._db.execute(
                "UPDATE auth_users SET password_hash = ?, password_changed_at = ?"
                " WHERE username = ?",
                (encoded, utc_iso(self._clock.now()), name),
            )
            if cursor.rowcount != 1:
                raise UnknownUserError(f"there is no user {name}")
            # The counter counted guesses at the old password.
            self._clear_throttle(name)
            self._emit(
                EVENT_PASSWORD_CHANGED,
                Severity.NOTICE,
                {"username": name, "method": how, "actor": actor, **self._revoke_sessions(name)},
            )

    def _revoke_sessions(self, name: str) -> dict[str, Any]:
        """End the account's sessions; the audit data to add. Call in a transaction."""
        if self._sessions is None:
            return {}
        return {"sessions_revoked": self._sessions.revoke_all(name)}

    def _attempt_password(
        self, username: object, password: str, channel: Channel, *, login: bool
    ) -> AuthResult:
        name = _throttle_name(username)
        if channel is Channel.LOCAL:
            # No lockout and no busy answer: this is the administrator's way back in.
            return self._evaluate_password(name, password, channel, None, login=login)
        # Taken without waiting, before anything is counted: a refused attempt costs
        # nothing and changes nothing.
        if not self._network_slots.acquire(blocking=False):
            return AuthResult(False, None, AuthFailure.BUSY, _BUSY_RETRY_SECONDS)
        try:
            with self._one_at_a_time(name):
                gate = self._admit(name)
                if gate.locked:
                    self._report_rejected(name, channel, gate)
                    return AuthResult(False, None, AuthFailure.LOCKED_OUT, gate.retry_after)
                return self._evaluate_password(name, password, channel, gate, login=login)
        finally:
            self._network_slots.release()

    def _evaluate_password(
        self, name: str, password: str, channel: Channel, gate: _Gate | None, *, login: bool
    ) -> AuthResult:
        """Check the password; ``gate`` is the network attempt's charge, ``None`` locally."""
        record = self._load(name)
        # Always one verification, against the decoy if there is no such account.
        stored = record.password_hash if record is not None else self._decoy_hash
        if self._verify(password, stored) and record is not None:
            upgraded = self._hash(password) if needs_rehash(stored, self._policy.scrypt) else None
            result = self._settle_success(record, gate, channel, upgraded, login=login)
            if result is not None:
                return result
        self._report_failed(name, record is not None, channel, AuthMethod.PASSWORD, gate)
        retry_after = gate.retry_after if gate is not None else 0
        return AuthResult(False, None, AuthFailure.INVALID_CREDENTIALS, retry_after)

    def _settle_success(
        self,
        record: _Record,
        gate: _Gate | None,
        channel: Channel,
        upgraded: str | None,
        *,
        login: bool,
    ) -> AuthResult | None:
        """Turn a matching password into a result, or ``None`` if it no longer counts."""
        name = record.user.username
        with self._db.transaction():
            row = self._fetch(name)
            # The account was deleted or its password changed while the hash was being
            # computed: what was verified is no longer the account's password.
            if row is None or not hmac.compare_digest(
                str(row["password_hash"]).encode("utf-8", "replace"),
                record.password_hash.encode("utf-8", "replace"),
            ):
                return None
            user = _user_from_row(row)
            if gate is not None:
                # The password was right, so the attempt charged on entry was not a guess.
                self._db.execute("DELETE FROM auth_throttle WHERE subject = ?", (gate.subject,))
            if user.enabled:
                now = self._clock.now()
                if login:
                    self._db.execute(
                        "UPDATE auth_users SET last_login_at = ? WHERE username = ?",
                        (utc_iso(now), name),
                    )
                    user = replace(user, last_login_at=now)
                if upgraded is not None:
                    self._db.execute(
                        "UPDATE auth_users SET password_hash = ? WHERE username = ?",
                        (upgraded, name),
                    )
        if not user.enabled:
            self._emit(
                EVENT_FAILURE,
                Severity.NOTICE,
                {
                    "username": name,
                    "known_user": True,
                    "channel": channel.value,
                    "method": AuthMethod.PASSWORD.value,
                    "reason": AuthFailure.ACCOUNT_DISABLED.value,
                },
            )
            return AuthResult(False, None, AuthFailure.ACCOUNT_DISABLED, 0)
        if login:
            self._emit(
                EVENT_LOGIN,
                Severity.INFO,
                {
                    "username": name,
                    "role": user.role.value,
                    "channel": channel.value,
                    "method": AuthMethod.PASSWORD.value,
                    "hash_upgraded": upgraded is not None,
                },
            )
        return AuthResult(True, user)

    # --- internals: recovery codes ---------------------------------------------------

    def _evaluate_recovery_code(self, name: str, code: object, origin: Channel) -> bool:
        record = self._load(name)
        raw = _parse_recovery_code(code)
        # An unparsable code is compared as a random one, and a short list of stored
        # codes is padded with random ones, so every attempt does the same comparisons.
        candidate = _code_digest(
            raw if raw is not None else secrets.token_bytes(_RECOVERY_CODE_BYTES)
        ).encode()
        stored: list[tuple[int | None, str]] = []
        if record is not None:
            stored.extend(self._unused_codes(name))
        while len(stored) < self._policy.recovery_code_count:
            stored.append((None, _code_digest(secrets.token_bytes(_RECOVERY_CODE_BYTES))))
        matched: int | None = None
        for code_id, digest in stored:
            same = hmac.compare_digest(digest.encode("utf-8", "replace"), candidate)
            if same and code_id is not None and raw is not None:
                matched = code_id
        if matched is not None and self._spend_code(name, matched, origin):
            return True
        self._report_failed(name, record is not None, origin, AuthMethod.RECOVERY_CODE, None)
        return False

    def _unused_codes(self, name: str) -> list[tuple[int | None, str]]:
        rows = self._db.query(
            "SELECT id, code_digest FROM auth_recovery_codes"
            " WHERE username = ? AND used_at IS NULL ORDER BY id",
            (name,),
        )
        return [(int(row["id"]), str(row["code_digest"])) for row in rows]

    def _count_unused_codes(self, name: str) -> int:
        row = self._db.query_one(
            "SELECT COUNT(*) AS n FROM auth_recovery_codes WHERE username = ? AND used_at IS NULL",
            (name,),
        )
        return int(row["n"]) if row is not None else 0

    def _spend_code(self, name: str, code_id: int, channel: Channel) -> bool:
        """Mark a matched code used.

        False if the account is gone or disabled, or someone else spent the code first.
        """
        with self._db.transaction():
            row = self._fetch(name)
            if row is None or not _user_from_row(row).enabled:
                return False
            cursor = self._db.execute(
                "UPDATE auth_recovery_codes SET used_at = ?"
                " WHERE id = ? AND username = ? AND used_at IS NULL",
                (utc_iso(self._clock.now()), code_id, name),
            )
            if cursor.rowcount != 1:
                return False
            remaining = self._count_unused_codes(name)
        self._emit(
            EVENT_RECOVERY_USED,
            Severity.WARNING,
            {"username": name, "channel": channel.value, "remaining": remaining},
        )
        return True

    # --- internals: the throttle -----------------------------------------------------

    @contextmanager
    def _one_at_a_time(self, name: str) -> Iterator[None]:
        """Let network attempts on one name through one after another within this process.

        Nothing about the lockout depends on this; :meth:`_admit` enforces it, across
        processes too. This is a courtesy to honest callers: without it, several correct
        logins to one account arriving together would all be charged before any was
        refunded, and those beyond the threshold would be told the account is locked.

        The wait is bounded and then goes ahead anyway, so a caller that already holds
        the database lock (it should not) cannot deadlock against an attempt in progress.
        """
        index = int(_subject(name)[:8], 16) % len(self._attempt_locks)
        lock = self._attempt_locks[index]
        held = lock.acquire(timeout=_ATTEMPT_WAIT_SECONDS)
        try:
            yield
        finally:
            if held:
                lock.release()

    def _throttle_state(
        self, row: sqlite3.Row, now: datetime
    ) -> tuple[int, datetime | None, datetime]:
        """Read a throttle row as ``(failures, locked_until, last_failure_at)``.

        ``locked_until`` is ``None`` unless a lockout is running at ``now``, and is never
        further away than the maximum delay. ``failures`` is 0 if the row has aged out.
        """
        policy = self._policy
        try:
            counted = row["failures"]
            # Only what this module writes is a count: a whole number of at least one.
            # A fraction, text or a blob in the column is damage, not a number to round.
            if not isinstance(counted, int) or counted < 1:
                raise ValueError("failure count")
            failures = min(counted, _MAX_COUNTED_FAILURES)
            last = parse_utc_iso(row["last_failure_at"])
            until = row["locked_until"]
            locked_until = parse_utc_iso(until) if until is not None else None
        except (TypeError, ValueError):
            # An unreadable row is treated as a lockout, the safe reading, but a bounded
            # one: the caller rewrites the row, so this happens once.
            return policy.lockout_threshold, now + policy.lockout_max, now
        if locked_until is not None and locked_until > now:
            return failures, min(locked_until, now + policy.lockout_max), last
        if now - last >= policy.failure_memory:
            return 0, None, last
        return failures, None, last

    def _admit(self, name: str) -> _Gate:
        """Refuse a network password attempt, or charge it as a failure before evaluation.

        Runs in one transaction, which SQLite makes exclusive across threads and
        processes, so concurrent attempts are counted one after another.
        """
        subject = _subject(name)
        with self._db.transaction():
            now = self._clock.now()
            row = self._db.query_one("SELECT * FROM auth_throttle WHERE subject = ?", (subject,))
            failures = 0
            if row is not None:
                failures, locked_until, last = self._throttle_state(row, now)
                if locked_until is not None:
                    first = row["refused"] == 0
                    # The first refusal of a lockout is noted so that it is audited once.
                    # A row that was read as clamped or unreadable is stored in its
                    # bounded form. Any other refused attempt writes nothing at all.
                    if first or row["locked_until"] != utc_iso(locked_until):
                        self._write_throttle(subject, failures, locked_until, last, refused=True)
                    return _Gate(
                        subject,
                        locked=True,
                        retry_after=_whole_seconds(locked_until - now),
                        failures=failures,
                        first_rejection=first,
                    )
            failures += 1
            delay = self._policy.lockout_delay(failures)
            self._write_throttle(
                subject, failures, now + delay if delay is not None else None, now, refused=False
            )
            if row is None:
                self._trim_throttle(subject, now)
            return _Gate(
                subject,
                locked=False,
                retry_after=_whole_seconds(delay) if delay is not None else 0,
                failures=failures,
                engaged=delay is not None,
            )

    def _write_throttle(
        self,
        subject: str,
        failures: int,
        locked_until: datetime | None,
        last_failure_at: datetime,
        *,
        refused: bool,
    ) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO auth_throttle"
            " (subject, failures, locked_until, last_failure_at, refused)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                subject,
                failures,
                utc_iso(locked_until) if locked_until is not None else None,
                utc_iso(last_failure_at),
                int(refused),
            ),
        )

    def _trim_throttle(self, keep: str, now: datetime) -> None:
        """Keep the throttle table within its bound. Call in a transaction.

        Rows are dropped without regard to whether their name is an account, so what is
        kept says nothing about which names exist. Aged-out rows go first; after that
        the rows with the fewest failures, oldest first. To push out the record of a
        real attack an attacker would have to build up as many failures on tens of
        thousands of other names, which takes longer than waiting the lockout out.
        """
        limit = self._policy.max_throttle_entries
        row = self._db.query_one("SELECT COUNT(*) AS n FROM auth_throttle")
        if row is None or int(row["n"]) <= limit:
            return
        stamp = utc_iso(now)
        self._db.execute(
            "DELETE FROM auth_throttle WHERE subject != ? AND last_failure_at <= ?"
            " AND (locked_until IS NULL OR locked_until <= ?)",
            (keep, utc_iso(now - self._policy.failure_memory), stamp),
        )
        row = self._db.query_one("SELECT COUNT(*) AS n FROM auth_throttle")
        excess = (int(row["n"]) if row is not None else 0) - limit
        if excess > 0:
            self._db.execute(
                "DELETE FROM auth_throttle WHERE subject IN ("
                " SELECT subject FROM auth_throttle WHERE subject != ?"
                " ORDER BY failures ASC, last_failure_at ASC LIMIT ?)",
                (keep, excess),
            )

    def _clear_throttle(self, name: str) -> None:
        self._db.execute("DELETE FROM auth_throttle WHERE subject = ?", (_subject(name),))

    def _attempt_data(
        self, name: str, known: bool, channel: Channel, method: AuthMethod
    ) -> dict[str, Any]:
        return {
            # What was typed as the name of a non-existent account is not recorded: it
            # is sometimes a password.
            "username": name if known else None,
            "known_user": known,
            "channel": channel.value,
            "method": method.value,
        }

    def _report_rejected(self, name: str, channel: Channel, gate: _Gate) -> None:
        # One record per lockout, not one per refused attempt: a refused attempt costs
        # the caller nothing, so it must not be able to flood the audit log.
        if not gate.first_rejection:
            return
        known = name != _UNUSABLE_NAME and self._fetch(name) is not None
        data = self._attempt_data(name, known, channel, AuthMethod.PASSWORD)
        data.update(
            reason=AuthFailure.LOCKED_OUT.value,
            consecutive_failures=gate.failures,
            retry_after_seconds=gate.retry_after,
        )
        self._emit(EVENT_FAILURE, Severity.NOTICE, data)

    def _report_failed(
        self, name: str, known: bool, channel: Channel, method: AuthMethod, gate: _Gate | None
    ) -> None:
        """Audit a wrong secret; ``gate`` is the network charge (absent where nothing counts)."""
        data = self._attempt_data(name, known, channel, method)
        data.update(reason=AuthFailure.INVALID_CREDENTIALS.value)
        if gate is not None:
            data.update(consecutive_failures=gate.failures)
        self._emit(EVENT_FAILURE, Severity.NOTICE, data)
        if gate is not None and gate.engaged:
            lockout = self._attempt_data(name, known, channel, method)
            lockout.update(consecutive_failures=gate.failures, locked_for_seconds=gate.retry_after)
            self._emit(EVENT_LOCKOUT, Severity.WARNING, lockout)
