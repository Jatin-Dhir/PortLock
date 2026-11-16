"""Login sessions for the local API and the web console.

A session is one 256-bit random token, handed to the client once and presented as a
bearer token in the ``Authorization`` header (``docs/DESIGN.md`` sections 12 and 14.20).
There are no cookies, so a page on another local port cannot make the browser send it,
and there is therefore no separate CSRF token: the bearer token is the only secret. The
database keeps only its SHA-256 digest, so reading the database (a backup, a stolen
file) does not yield a usable session. A slow, salted hash is unnecessary here: unlike a
password, the token has too much entropy to guess.

Two clocks end a session (``docs/DESIGN.md`` section 8): 15 minutes without a request,
and 8 hours after it was created however busy it has been. Both are evaluated with the
injected clock. A session whose timestamps lie in the future, which is what setting the
wall clock back looks like, is ended rather than given extra life.

Sessions end when the account is secured (section 14.21): an
:class:`~portlock.auth.accounts.AccountStore` given this store as ``sessions`` calls
:meth:`SessionStore.revoke_all` in the same transaction that changes a password or a
role or disables or deletes the account. As a second line of defence, a store given an
``account_lookup`` re-checks the account on every request and ends a session whose
account is gone, disabled, has a different role, or changed its password after the
session began.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from portlock.auth.accounts import (
    InvalidUsernameError,
    Permission,
    Role,
    User,
    can,
    normalize_username,
)
from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.db import Database
from portlock.core.errors import AuthError, ConfigError

__all__ = [
    "DEFAULT_ABSOLUTE_TIMEOUT",
    "DEFAULT_IDLE_TIMEOUT",
    "Session",
    "SessionStore",
]

DEFAULT_IDLE_TIMEOUT = timedelta(minutes=15)
DEFAULT_ABSOLUTE_TIMEOUT = timedelta(hours=8)

_DEFAULT_TOUCH_INTERVAL = timedelta(seconds=60)

_TOKEN_BYTES = 32  # 256 bits
# What secrets.token_urlsafe(32) produces: 43 URL-safe base64 characters, no padding.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SESSION_ID_PATTERN = re.compile(r"[0-9a-f]{16}\Z")
_MAX_CLIENT_LENGTH = 128
# Ordinary clock corrections move time back by seconds. Anything stamped further ahead
# than this means the clock was set back, and the session's real age is unknown.
_CLOCK_TOLERANCE = timedelta(minutes=5)

# Published migrations are never edited; append new ones.
_MIGRATIONS = (
    """
    CREATE TABLE auth_sessions (
        token_digest TEXT PRIMARY KEY,
        session_id   TEXT NOT NULL UNIQUE,
        username     TEXT NOT NULL,
        role         TEXT NOT NULL,
        csrf_token   TEXT NOT NULL,
        client       TEXT,
        created_at   TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
    );
    CREATE INDEX auth_sessions_username ON auth_sessions (username, created_at);
    """,
    # Bearer tokens only (DESIGN.md 14.20): the CSRF token is gone. Sessions created
    # with one are ended, since their clients were built around the old scheme.
    """
    DELETE FROM auth_sessions;
    ALTER TABLE auth_sessions DROP COLUMN csrf_token;
    """,
)


@dataclass(frozen=True, slots=True)
class Session:
    """One authenticated session. The token itself is not part of it.

    Attributes:
        session_id: a non-secret handle for audit records and for ending this session
            from an administration screen.
        username: the account, in its stored (lower-case) form.
        role: the account's role when the session was created.
        created_at: when the session was created.
        last_seen_at: the last request recorded for it (see ``touch_interval``).
        expires_at: when it ends regardless of activity.
        idle_expires_at: when it ends unless another request arrives first.
        client: a short description of the client, as given at creation.
    """

    session_id: str
    username: str
    role: Role
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    client: str | None = None

    def can(self, permission: Permission | str) -> bool:
        """Whether this session's role includes ``permission``."""
        return can(self.role, permission)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable description. It never includes the token."""
        return {
            "session_id": self.session_id,
            "username": self.username,
            "role": self.role.value,
            "created_at": utc_iso(self.created_at),
            "last_seen_at": utc_iso(self.last_seen_at),
            "expires_at": utc_iso(self.expires_at),
            "idle_expires_at": utc_iso(self.idle_expires_at),
            "client": self.client,
        }


def _digest(token: object) -> str | None:
    """The stored form of a token, or ``None`` if it cannot be one of ours.

    Checking the shape first means a megabyte of junk in a header is never hashed.
    """
    if not isinstance(token, str) or not _TOKEN_PATTERN.match(token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _clean_client(client: object) -> str | None:
    """Bound and defuse a client description (it usually comes from request headers)."""
    if client is None:
        return None
    if not isinstance(client, str):
        raise AuthError("a client description must be text", code="invalid_client")
    cleaned = "".join(
        char if char.isprintable() else "?" for char in client[:_MAX_CLIENT_LENGTH]
    ).strip()
    return cleaned or None


class SessionStore:
    """Creates, validates and ends sessions. Safe to call from several threads.

    Args:
        db: the database; the ``auth_sessions`` table is created or migrated here.
        clock: source of time for both timeouts.
        idle_timeout: a session ends after this long without a request.
        absolute_timeout: a session ends this long after it was created.
        max_sessions_per_user: creating one more than this ends the account's oldest.
        touch_interval: ``last_seen_at`` is rewritten at most this often, so a busy
            console does not turn every request into a database write. The recorded
            time can lag the true last request by up to this much, which makes the idle
            timeout fire that much early, never late. ``None`` means one minute, or a
            tenth of the idle timeout if that is shorter, so that every idle timeout
            the configuration file accepts works without further tuning.
        account_lookup: if given (normally ``AccountStore.get_user``), every validation
            also requires the account to exist, be enabled, still hold the session's
            role, and not have changed its password after the session was created.

    Raises:
        ConfigError: if a timeout or limit is out of range.
        StoreError: if the table cannot be created or is from a newer version.
    """

    def __init__(
        self,
        db: Database,
        *,
        clock: Clock,
        idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
        absolute_timeout: timedelta = DEFAULT_ABSOLUTE_TIMEOUT,
        max_sessions_per_user: int = 5,
        touch_interval: timedelta | None = None,
        account_lookup: Callable[[str], User | None] | None = None,
    ) -> None:
        for name, value in (
            ("idle_timeout", idle_timeout),
            ("absolute_timeout", absolute_timeout),
        ):
            if not isinstance(value, timedelta):
                raise ConfigError(f"sessions: {name} must be a timedelta")
        if idle_timeout < timedelta(seconds=1):
            raise ConfigError("sessions: idle_timeout must be at least one second")
        if absolute_timeout < idle_timeout:
            raise ConfigError("sessions: absolute_timeout must not be shorter than idle_timeout")
        if touch_interval is None:
            touch_interval = min(_DEFAULT_TOUCH_INTERVAL, idle_timeout / 10)
        elif not isinstance(touch_interval, timedelta):
            raise ConfigError("sessions: touch_interval must be a timedelta")
        if not timedelta(0) <= touch_interval <= idle_timeout / 2:
            raise ConfigError(
                "sessions: touch_interval must be between zero and half the idle timeout"
            )
        if (
            isinstance(max_sessions_per_user, bool)
            or not isinstance(max_sessions_per_user, int)
            or not 1 <= max_sessions_per_user <= 1000
        ):
            raise ConfigError("sessions: max_sessions_per_user must be an integer from 1 to 1000")
        self._db = db
        self._clock = clock
        self._idle = idle_timeout
        self._absolute = absolute_timeout
        self._max_per_user = max_sessions_per_user
        self._touch_interval = touch_interval
        self._account_lookup = account_lookup
        db.migrate("auth_sessions", _MIGRATIONS)

    def create(self, username: str, role: Role | str, *, client: str | None) -> tuple[str, Session]:
        """Start a session for an account that has just authenticated.

        If the account already has the maximum number of live sessions, the oldest are
        ended to make room.

        Args:
            username: the account.
            role: the account's role.
            client: a short description of the client (address, user agent), or ``None``.
                It is truncated and stripped of control characters.

        Returns:
            ``(token, session)``. The token is the secret to give the client; it cannot
            be recovered later.

        Raises:
            InvalidUsernameError: for a malformed user name.
            AuthError: code ``invalid_role`` or ``invalid_client``.
        """
        name = normalize_username(username)
        try:
            session_role = Role(role)
        except ValueError:
            raise AuthError("unknown role", code="invalid_role") from None
        description = _clean_client(client)
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session_id = secrets.token_hex(8)
        with self._db.transaction():
            now = self._clock.now()
            self._delete_expired(now, name)
            live = self._db.query(
                "SELECT token_digest FROM auth_sessions WHERE username = ?"
                " ORDER BY created_at ASC, rowid ASC",
                (name,),
            )
            for row in live[: max(0, len(live) - self._max_per_user + 1)]:
                self._delete(row["token_digest"])
            stamp = utc_iso(now)
            self._db.execute(
                "INSERT INTO auth_sessions (token_digest, session_id, username, role,"
                " client, created_at, last_seen_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_digest(token), session_id, name, session_role.value, description, stamp, stamp),
            )
        return token, self._build(session_id, name, session_role, now, now, description)

    def validate(self, token: str) -> Session | None:
        """The live session a token belongs to, or ``None``.

        ``None`` covers everything that is not a live session: an unknown, malformed,
        revoked or expired token, a session whose stored record is damaged, and (with an
        ``account_lookup``) a session whose account no longer qualifies. Expired and
        damaged sessions are deleted on sight.
        """
        digest = _digest(token)
        if digest is None:
            return None
        with self._db.transaction():
            row = self._db.query_one(
                "SELECT * FROM auth_sessions WHERE token_digest = ?", (digest,)
            )
            if row is None:
                return None
            now = self._clock.now()
            session = self._from_row(row)
            if session is None or self._expired(session, now) or not self._account_ok(session):
                self._delete(digest)
                return None
            if now - session.last_seen_at >= self._touch_interval:
                self._db.execute(
                    "UPDATE auth_sessions SET last_seen_at = ? WHERE token_digest = ?",
                    (utc_iso(now), digest),
                )
                session = replace(session, last_seen_at=now, idle_expires_at=now + self._idle)
            return session

    def revoke(self, token: str) -> bool:
        """End the session a token belongs to (log out). True if there was one."""
        digest = _digest(token)
        return digest is not None and self._delete(digest)

    def revoke_by_id(self, session_id: str) -> bool:
        """End a session named by its non-secret id. True if there was one."""
        if not isinstance(session_id, str) or not _SESSION_ID_PATTERN.match(session_id):
            return False
        cursor = self._db.execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
        return cursor.rowcount > 0

    def revoke_all(self, username: str) -> int:
        """End every session of an account. Returns how many were ended.

        ``AccountStore`` calls this, inside its own transaction, when the account's
        password or role changes or it is disabled or deleted. None is spared, not even
        the one a password change was made from: its holder signs in again with the new
        password.

        Args:
            username: the account, in any letter case.
        """
        try:
            name = normalize_username(username)
        except InvalidUsernameError:
            return 0
        cursor = self._db.execute("DELETE FROM auth_sessions WHERE username = ?", (name,))
        return cursor.rowcount

    def purge_expired(self) -> int:
        """Delete every session that has timed out. Returns how many were deleted.

        Validation already refuses expired sessions; this only keeps the table small.
        Meant to be called periodically.
        """
        with self._db.transaction():
            return self._delete_expired(self._clock.now(), None)

    def list_sessions(self, username: str | None = None) -> list[Session]:
        """Live sessions, oldest first, for one account or for all of them.

        Does not count as activity: nothing is refreshed.
        """
        if username is None:
            rows = self._db.query("SELECT * FROM auth_sessions ORDER BY created_at ASC, rowid ASC")
        else:
            try:
                name = normalize_username(username)
            except InvalidUsernameError:
                return []
            rows = self._db.query(
                "SELECT * FROM auth_sessions WHERE username = ? ORDER BY created_at ASC, rowid ASC",
                (name,),
            )
        now = self._clock.now()
        sessions = (self._from_row(row) for row in rows)
        return [
            session
            for session in sessions
            if session is not None and not self._expired(session, now)
        ]

    # --- internals -------------------------------------------------------------------

    def _build(
        self,
        session_id: str,
        username: str,
        role: Role,
        created_at: datetime,
        last_seen_at: datetime,
        client: str | None,
    ) -> Session:
        return Session(
            session_id=session_id,
            username=username,
            role=role,
            created_at=created_at,
            last_seen_at=last_seen_at,
            expires_at=created_at + self._absolute,
            idle_expires_at=last_seen_at + self._idle,
            client=client,
        )

    def _from_row(self, row: sqlite3.Row) -> Session | None:
        """Rebuild a session, or ``None`` if the row was damaged or edited into nonsense."""
        try:
            client = row["client"]
            return self._build(
                str(row["session_id"]),
                normalize_username(row["username"]),
                Role(row["role"]),
                parse_utc_iso(row["created_at"]),
                parse_utc_iso(row["last_seen_at"]),
                str(client) if client is not None else None,
            )
        except (ValueError, TypeError, OverflowError, InvalidUsernameError):
            # OverflowError: a timestamp so close to the end of the calendar that adding
            # a timeout to it has no representation. Nothing this store wrote.
            return None

    def _expired(self, session: Session, now: datetime) -> bool:
        if now >= session.expires_at or now >= session.idle_expires_at:
            return True
        horizon = now + _CLOCK_TOLERANCE
        return session.created_at > horizon or session.last_seen_at > horizon

    def _account_ok(self, session: Session) -> bool:
        if self._account_lookup is None:
            return True
        user = self._account_lookup(session.username)
        return (
            user is not None
            and user.enabled
            and user.role is session.role
            # A password set after the session began means it was stolen or is stale.
            and user.password_changed_at <= session.created_at
        )

    def _delete(self, digest: str) -> bool:
        cursor = self._db.execute("DELETE FROM auth_sessions WHERE token_digest = ?", (digest,))
        return cursor.rowcount > 0

    def _delete_expired(self, now: datetime, username: str | None) -> int:
        """Delete timed-out sessions, of one account or of all. Timestamps sort as text."""
        sql = (
            "DELETE FROM auth_sessions"
            " WHERE (created_at <= ? OR last_seen_at <= ? OR created_at > ? OR last_seen_at > ?)"
        )
        horizon = utc_iso(now + _CLOCK_TOLERANCE)
        params: list[str] = [
            utc_iso(now - self._absolute),
            utc_iso(now - self._idle),
            horizon,
            horizon,
        ]
        if username is not None:
            sql += " AND username = ?"
            params.append(username)
        return self._db.execute(sql, params).rowcount
