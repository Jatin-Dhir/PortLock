"""Device grants: an administrator's decision to let one device in.

A grant is attached to a device *fingerprint* and comes in three kinds:

* ``trust`` has no expiry and lasts until it is revoked;
* ``temporary`` lasts until a set time, which may be no further away than a ceiling the
  caller passes in (the caller knows the role of whoever is granting: docs/DESIGN.md,
  section 14.13, sets 24 hours for operators and 30 days by default for administrators);
* ``once`` is valid for a single connection: it is bound to the connection that first
  uses it and is spent when that device is removed.

Each kind is either full access or ``read_only``.

Grants do not decide anything on their own. ``portlock.policy.decide.decide`` weighs the
active grant against safety, lockdown, scan results and policy. A grant acts only on a
``pending`` outcome: it never overrides what a policy rule decides and never removes a
scan requirement.

**Connections.** A one-time grant binds to :func:`connection_key`: the backend's
``UsbDevice.connection_id``, which differs for every physical connection. The OS
instance id is used only when a backend supplies no connection id, and it survives a
re-plug, so with such a backend a one-time grant also covers the device when it is
unplugged and plugged back into the same port before its removal is processed.

**Low-confidence fingerprints.** A fingerprint identifies a device only as well as its
serial number does. A device with no serial (or a generic one) has a ``low``-confidence
fingerprint that is shared by *every unit of that model*, so granting it grants them all.
Such a fingerprint may therefore only receive a ``once`` grant or a ``temporary`` grant
of at most :data:`LOW_CONFIDENCE_MAX_DURATION`, and the grant is bound to one port: it
matches only a device on that ``bus_path``. A ``trust`` grant is refused.
"""

from __future__ import annotations

import enum
import secrets
import sqlite3
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeAlias

from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.db import Database
from portlock.core.errors import AuthError, StoreError
from portlock.core.models import Access, Confidence, Fingerprint, UsbDevice

__all__ = [
    "ADMIN_MAX_DURATION",
    "LOW_CONFIDENCE_MAX_DURATION",
    "MAX_CONNECTION_LENGTH",
    "MAX_FINGERPRINT_LENGTH",
    "MAX_GRANTED_BY_LENGTH",
    "MAX_NOTE_LENGTH",
    "MAX_PORT_LENGTH",
    "OPERATOR_MAX_DURATION",
    "Grant",
    "GrantEnd",
    "GrantError",
    "GrantKind",
    "GrantStore",
    "connection_key",
]

MAX_FINGERPRINT_LENGTH = 128
MAX_GRANTED_BY_LENGTH = 128
MAX_NOTE_LENGTH = 512
MAX_CONNECTION_LENGTH = 1024
MAX_PORT_LENGTH = 1024

#: The longest temporary grant an operator may issue (docs/DESIGN.md, section 14.13).
OPERATOR_MAX_DURATION = timedelta(hours=24)
#: The default ceiling for administrators; configuration may lower it.
ADMIN_MAX_DURATION = timedelta(days=30)
#: The longest temporary grant for a low-confidence fingerprint, whoever issues it.
LOW_CONFIDENCE_MAX_DURATION = timedelta(hours=24)

_COMPONENT = "grants"

# Published migrations are never edited or reordered; append new ones.
_MIGRATIONS = (
    """
    CREATE TABLE grants (
        id             TEXT PRIMARY KEY,
        fingerprint    TEXT    NOT NULL,
        confidence     TEXT    NOT NULL CHECK (confidence IN ('high', 'low')),
        kind           TEXT    NOT NULL CHECK (kind IN ('trust', 'temporary', 'once')),
        read_only      INTEGER NOT NULL CHECK (read_only IN (0, 1)),
        created_at     TEXT    NOT NULL,
        expires_at     TEXT,
        granted_by     TEXT    NOT NULL,
        note           TEXT    NOT NULL DEFAULT '',
        bound_instance TEXT,
        bound_at       TEXT,
        ended_at       TEXT,
        end_reason     TEXT CHECK (end_reason IN ('revoked', 'expired', 'used')),
        ended_by       TEXT,
        CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
        CHECK ((bound_instance IS NULL) = (bound_at IS NULL)),
        CHECK (bound_instance IS NULL OR kind = 'once'),
        CHECK (kind != 'trust' OR expires_at IS NULL),
        CHECK (kind != 'temporary' OR expires_at IS NOT NULL)
    );
    CREATE INDEX grants_by_fingerprint ON grants (fingerprint, ended_at);
    CREATE INDEX grants_by_instance ON grants (bound_instance)
        WHERE bound_instance IS NOT NULL AND ended_at IS NULL;
    """,
    # Version 2 (docs/DESIGN.md, section 14.13). `bound_instance` keeps its name but now
    # holds the connection key (`connection_key`); for backends without connection ids
    # that is the instance id it always held. `bound_port` ties a grant to one port.
    """
    ALTER TABLE grants ADD COLUMN bound_port TEXT
        CHECK (bound_port IS NULL OR length(bound_port) > 0);
    """,
)


class GrantError(AuthError):
    """A grant request is invalid, or names a grant that cannot be used that way.

    ``code`` is one of ``grant_invalid``, ``grant_low_confidence``, ``grant_not_found``,
    ``grant_not_active`` and ``grant_bound_elsewhere``.
    """

    code = "grant_error"


class GrantKind(enum.StrEnum):
    """How long a grant lasts."""

    #: Until revoked. Has no expiry.
    TRUST = "trust"
    #: Until ``expires_at``, which is required and capped by the caller's ceiling.
    TEMPORARY = "temporary"
    #: For one connection of the device. An expiry is optional and, if given, also ends
    #: the grant while it waits for the device or while the device is still connected.
    ONCE = "once"


class GrantEnd(enum.StrEnum):
    """Why a grant is no longer active."""

    REVOKED = "revoked"
    EXPIRED = "expired"
    #: A one-time grant whose connection has ended.
    USED = "used"


def connection_key(device: UsbDevice) -> str:
    """The value that identifies one connection of ``device``, for one-time grants.

    This is ``device.connection_id``, which the backend makes different for every
    physical connection. When the backend supplies none, ``device.instance_id`` is used
    instead. That fallback is weaker: the OS instance id survives a re-plug on both
    platforms, so a device unplugged and plugged back into the same port before its
    removal was processed still counts as the connection a one-time grant was bound to.
    """
    return device.connection_id if device.connection_id else device.instance_id


@dataclass(frozen=True, slots=True)
class Grant:
    """One grant, as stored.

    Attributes:
        id: random identifier.
        fingerprint: the fingerprint value the grant is for.
        confidence: the fingerprint's confidence when the grant was made.
        kind: see :class:`GrantKind`.
        read_only: True if the grant gives read-only rather than full access.
        created_at: when it was made.
        granted_by: who made it.
        expires_at: when it stops being valid, if ever.
        note: free text from whoever made it.
        bound_connection: for a one-time grant in use, the :func:`connection_key` of the
            connection it belongs to.
        bound_at: when it was bound.
        ended_at: when it stopped being active, if it has.
        end_reason: why it stopped.
        ended_by: who revoked it, for a revoked grant.
        bound_port: the ``bus_path`` the grant is limited to, if any. Every grant for a
            low-confidence fingerprint has one; it matches only a device on that port.
    """

    id: str
    fingerprint: str
    confidence: Confidence
    kind: GrantKind
    read_only: bool
    created_at: datetime
    granted_by: str
    expires_at: datetime | None = None
    note: str = ""
    bound_connection: str | None = None
    bound_at: datetime | None = None
    ended_at: datetime | None = None
    end_reason: GrantEnd | None = None
    ended_by: str | None = None
    bound_port: str | None = None

    @property
    def access(self) -> Access:
        """The access this grant gives: ``read_only`` or ``allow``."""
        return Access.READ_ONLY if self.read_only else Access.ALLOW

    def is_active(self, now: datetime) -> bool:
        """True if the grant has not ended and has not reached its expiry at ``now``."""
        return self.ended_at is None and (self.expires_at is None or self.expires_at > now)

    def remaining(self, now: datetime) -> timedelta | None:
        """Time left before expiry (never negative), or ``None`` if it has no expiry."""
        if self.expires_at is None:
            return None
        return max(self.expires_at - now, timedelta(0))

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable description, for the API and the audit log."""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence.value,
            "kind": self.kind.value,
            "read_only": self.read_only,
            "created_at": utc_iso(self.created_at),
            "granted_by": self.granted_by,
            "expires_at": _iso(self.expires_at),
            "note": self.note,
            "bound_connection": self.bound_connection,
            "bound_port": self.bound_port,
            "bound_at": _iso(self.bound_at),
            "ended_at": _iso(self.ended_at),
            "end_reason": self.end_reason.value if self.end_reason is not None else None,
            "ended_by": self.ended_by,
        }


# `GrantStore.list` hides the built-in name inside the class body, so annotations there
# use this alias.
GrantList: TypeAlias = list[Grant]


def _iso(value: datetime | None) -> str | None:
    return utc_iso(value) if value is not None else None


def _parse(value: str | None) -> datetime | None:
    return parse_utc_iso(value) if value is not None else None


def _aware(value: Any, what: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GrantError(f"{what} must be a timezone-aware datetime", code="grant_invalid")
    return value.astimezone(UTC)


def _text(value: Any, what: str, *, max_length: int, allow_empty: bool) -> str:
    """Validate one line of operator-supplied text and return it trimmed."""
    if not isinstance(value, str):
        raise GrantError(f"{what} must be a string", code="grant_invalid")
    if len(value) > max_length:
        raise GrantError(
            f"{what} is too long ({len(value)} characters; the limit is {max_length})",
            code="grant_invalid",
        )
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in value):
        raise GrantError(f"{what} must not contain control characters", code="grant_invalid")
    trimmed = value.strip()
    if not trimmed and not allow_empty:
        raise GrantError(f"{what} must not be empty", code="grant_invalid")
    return trimmed


def _connection(device: Any) -> str:
    """The validated connection key of ``device``."""
    if not isinstance(device, UsbDevice):
        raise GrantError("a connection is named by its UsbDevice", code="grant_invalid")
    return _text(
        connection_key(device),
        "a connection id",
        max_length=MAX_CONNECTION_LENGTH,
        allow_empty=False,
    )


def _port(value: Any) -> str:
    return _text(value, "a port", max_length=MAX_PORT_LENGTH, allow_empty=False)


def _duration(value: Any, what: str) -> timedelta:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise GrantError(f"{what} must be a positive timedelta", code="grant_invalid")
    return value


def _from_row(row: sqlite3.Row) -> Grant:
    try:
        return Grant(
            id=row["id"],
            fingerprint=row["fingerprint"],
            confidence=Confidence(row["confidence"]),
            kind=GrantKind(row["kind"]),
            read_only=bool(row["read_only"]),
            created_at=parse_utc_iso(row["created_at"]),
            granted_by=row["granted_by"],
            expires_at=_parse(row["expires_at"]),
            note=row["note"],
            bound_connection=row["bound_instance"],
            bound_at=_parse(row["bound_at"]),
            ended_at=_parse(row["ended_at"]),
            end_reason=GrantEnd(row["end_reason"]) if row["end_reason"] is not None else None,
            ended_by=row["ended_by"],
            bound_port=row["bound_port"],
        )
    except ValueError as exc:
        # A row that does not parse was not written by this code: treat the store as
        # damaged rather than guess what the grant was meant to be.
        raise StoreError(f"grant record {row['id']!r} is corrupt: {exc}") from exc


def _preference(grant: Grant, connection: str | None) -> tuple[Any, ...]:
    """Sort key for choosing between grants that all apply; the smallest wins.

    1. Read-only before full: when an administrator has restricted a device, a second,
       broader grant must not quietly lift the restriction.
    2. Trust and temporary grants before one-time grants. A one-time grant lasts for
       this connection at most, so it is the shortest; and choosing it would spend it
       when a longer-lived grant already covers the device.
    3. A one-time grant already bound to this connection before an unused one, so a
       second one is not spent on the same connection.
    4. The longest remaining: no expiry first, then the latest expiry.
    5. Oldest first, then by id, so the choice never depends on storage order.
    """
    once = grant.kind is GrantKind.ONCE
    unbound = once and grant.bound_connection != connection
    if grant.expires_at is None:
        expiry: tuple[int, float] = (0, 0.0)
    else:
        expiry = (1, -grant.expires_at.timestamp())
    return (not grant.read_only, once, unbound, expiry, grant.created_at, grant.id)


class GrantStore:
    """Durable storage for device grants.

    Safe to share between threads: every operation that reads and then writes runs in
    one transaction on the shared :class:`~portlock.core.db.Database`, which holds its
    lock for the duration.

    Args:
        db: the database. The store creates and migrates its own table; on a read-only
            database the table must already be at this code's version.
        clock: the time source for ``created_at``, binding, revocation and listing.

    Raises:
        StoreError: if the table cannot be created or is from an incompatible version.
    """

    def __init__(self, db: Database, *, clock: Clock) -> None:
        self._db = db
        self._clock = clock
        if db.read_only:
            version = db.schema_version(_COMPONENT)
            if version != len(_MIGRATIONS):
                raise StoreError(
                    f"the grants tables are at version {version}, but this version of"
                    f" PortLock needs version {len(_MIGRATIONS)}"
                )
        else:
            db.migrate(_COMPONENT, _MIGRATIONS)

    def create(
        self,
        fingerprint: Fingerprint,
        kind: GrantKind,
        *,
        read_only: bool = False,
        expires_at: datetime | None = None,
        max_duration: timedelta | None = None,
        port: str | None = None,
        granted_by: str,
        note: str = "",
    ) -> Grant:
        """Record a new grant for a device fingerprint.

        Args:
            fingerprint: the fingerprint of the device being granted.
            kind: ``TRUST`` (``expires_at`` must be ``None``), ``TEMPORARY``
                (``expires_at`` is required) or ``ONCE`` (``expires_at`` is optional).
            read_only: give read-only rather than full access.
            expires_at: when the grant stops being valid; must be in the future.
            max_duration: the furthest ahead ``expires_at`` may be, measured from now.
                Required for a ``TEMPORARY`` grant: the caller passes the ceiling for
                the role of whoever is granting (:data:`OPERATOR_MAX_DURATION`,
                :data:`ADMIN_MAX_DURATION` or a configured value). For a ``ONCE``
                grant with an expiry it is applied when given.
            port: the ``bus_path`` to limit the grant to. Required for a low-confidence
                fingerprint; the grant then matches only a device on this port.
            granted_by: who is making the grant, for the audit trail.
            note: optional free text, one line.

        Returns:
            The stored grant, with a random id.

        Raises:
            GrantError: ``grant_invalid`` if an argument is malformed, does not fit the
                kind, or the expiry is beyond ``max_duration``;
                ``grant_low_confidence`` if the fingerprint has low confidence and the
                grant is a ``TRUST`` grant, a ``TEMPORARY`` grant longer than
                :data:`LOW_CONFIDENCE_MAX_DURATION`, or has no ``port``.
        """
        if not isinstance(fingerprint, Fingerprint) or not isinstance(
            fingerprint.confidence, Confidence
        ):
            raise GrantError("a grant needs a device fingerprint", code="grant_invalid")
        value = fingerprint.value
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_FINGERPRINT_LENGTH
            or not value.isascii()
            or not value.isprintable()
            or " " in value
        ):
            raise GrantError("the fingerprint value is malformed", code="grant_invalid")
        try:
            kind = GrantKind(kind)
        except ValueError:
            raise GrantError(
                "the grant kind must be trust, temporary or once", code="grant_invalid"
            ) from None
        if not isinstance(read_only, bool):
            raise GrantError("read_only must be true or false", code="grant_invalid")
        granted_by = _text(
            granted_by, "granted_by", max_length=MAX_GRANTED_BY_LENGTH, allow_empty=False
        )
        note = _text(note, "a note", max_length=MAX_NOTE_LENGTH, allow_empty=True)
        bound_port = _port(port) if port is not None else None
        ceiling = _duration(max_duration, "max_duration") if max_duration is not None else None

        now = self._clock.now()
        if expires_at is not None:
            expires_at = _aware(expires_at, "expires_at")
        if kind is GrantKind.TRUST and expires_at is not None:
            raise GrantError(
                "a trust grant has no expiry; use a temporary grant for one that ends",
                code="grant_invalid",
            )
        if kind is GrantKind.TEMPORARY and expires_at is None:
            raise GrantError("a temporary grant needs an expiry", code="grant_invalid")
        if kind is GrantKind.TEMPORARY and ceiling is None:
            # Fail closed: a caller that forgot the role's ceiling gets no grant at all,
            # rather than one of unlimited length.
            raise GrantError(
                "a temporary grant needs the ceiling for the granting role (max_duration)",
                code="grant_invalid",
            )
        if expires_at is not None and expires_at <= now:
            raise GrantError("the expiry must be in the future", code="grant_invalid")
        if expires_at is not None and ceiling is not None and expires_at - now > ceiling:
            raise GrantError(
                f"the expiry is further ahead than this role may grant ({_span(ceiling)})",
                code="grant_invalid",
            )
        if fingerprint.confidence is Confidence.LOW:
            self._check_low_confidence(kind, expires_at, now, bound_port)

        grant = Grant(
            id=secrets.token_hex(16),
            fingerprint=value,
            confidence=fingerprint.confidence,
            kind=kind,
            read_only=read_only,
            created_at=now,
            granted_by=granted_by,
            expires_at=expires_at,
            note=note,
            bound_port=bound_port,
        )
        self._db.execute(
            "INSERT INTO grants (id, fingerprint, confidence, kind, read_only, created_at,"
            " expires_at, granted_by, note, bound_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                grant.id,
                grant.fingerprint,
                grant.confidence.value,
                grant.kind.value,
                int(grant.read_only),
                utc_iso(grant.created_at),
                _iso(grant.expires_at),
                grant.granted_by,
                grant.note,
                grant.bound_port,
            ),
        )
        return grant

    @staticmethod
    def _check_low_confidence(
        kind: GrantKind, expires_at: datetime | None, now: datetime, port: str | None
    ) -> None:
        """Apply docs/DESIGN.md section 14.13 to a low-confidence fingerprint."""
        shared = (
            "this device has no unique serial number, so its fingerprint is shared by"
            " every unit of the same model"
        )
        if kind is GrantKind.TRUST:
            raise GrantError(
                f"{shared}; trusting it would trust all of them indefinitely. Use a"
                " one-time grant, or a temporary grant of at most"
                f" {_span(LOW_CONFIDENCE_MAX_DURATION)}",
                code="grant_low_confidence",
            )
        if (
            kind is GrantKind.TEMPORARY
            and expires_at is not None
            and expires_at - now > LOW_CONFIDENCE_MAX_DURATION
        ):
            raise GrantError(
                f"{shared}; a temporary grant for it may last at most"
                f" {_span(LOW_CONFIDENCE_MAX_DURATION)}",
                code="grant_low_confidence",
            )
        if port is None:
            raise GrantError(
                f"{shared}; a grant for it must be limited to the port the device is on",
                code="grant_low_confidence",
            )

    def get(self, grant_id: str) -> Grant:
        """Return one grant, active or not.

        Raises:
            GrantError: ``grant_not_found`` if there is no such grant.
        """
        row = self._db.query_one("SELECT * FROM grants WHERE id = ?", (str(grant_id),))
        if row is None:
            raise GrantError("no such grant", code="grant_not_found")
        return _from_row(row)

    def active_for(
        self, fingerprint_value: str, *, now: datetime, device: UsbDevice | None = None
    ) -> Grant | None:
        """Return the grant that applies to a device right now, or ``None``.

        A grant applies if it is for this fingerprint, has not ended and has not reached
        its expiry at ``now``. A one-time grant applies only while it is unused, or if it
        is bound to this connection (:func:`connection_key`); one bound to another
        connection never applies. A grant limited to a port applies only to a device
        reported on that ``bus_path``.

        When several grants apply the choice is deterministic: the most restrictive
        wins (read-only before full), then the one with the longest remaining validity
        (no expiry before a later expiry; a one-time grant, which lasts for this
        connection at most, after the others), then the oldest.

        This only reads. A one-time grant returned here becomes this connection's when
        the caller passes it to :meth:`bind`.

        Args:
            fingerprint_value: the device's fingerprint value.
            now: the instant to evaluate at.
            device: the connected device being evaluated, if there is one. Without it,
                only grants bound to neither a connection nor a port can apply.

        Raises:
            GrantError: ``grant_invalid`` if ``now`` is not timezone-aware or ``device``
                is not a usable :class:`UsbDevice`.
        """
        moment = _aware(now, "now")
        connection = _connection(device) if device is not None else None
        port = device.bus_path if device is not None else None
        rows = self._db.query(
            "SELECT * FROM grants WHERE fingerprint = ? AND ended_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?)",
            (str(fingerprint_value), utc_iso(moment)),
        )
        candidates = [
            grant
            for grant in map(_from_row, rows)
            if grant.bound_connection in (None, connection)
            and (grant.bound_port is None or grant.bound_port == port)
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda grant: _preference(grant, connection))

    def bind(self, grant_id: str, device: UsbDevice) -> Grant:
        """Tie a one-time grant to the connection of ``device`` that is using it.

        From then on the grant applies to that connection only, and :meth:`release`
        spends it when the device is removed. Binding again to the same connection
        changes nothing.

        Raises:
            GrantError: ``grant_not_found`` if there is no such grant; ``grant_invalid``
                if it is not a one-time grant or ``device`` is not usable;
                ``grant_not_active`` if it has ended or expired;
                ``grant_bound_elsewhere`` if another connection already has it, or the
                grant is limited to a port the device is not on.
        """
        connection = _connection(device)
        with self._db.transaction():
            grant = self.get(grant_id)
            now = self._clock.now()
            if grant.kind is not GrantKind.ONCE:
                raise GrantError("only a one-time grant can be bound", code="grant_invalid")
            if not grant.is_active(now):
                raise GrantError("the grant is no longer active", code="grant_not_active")
            if grant.bound_port is not None and grant.bound_port != device.bus_path:
                raise GrantError(
                    "the grant is limited to another port", code="grant_bound_elsewhere"
                )
            if grant.bound_connection == connection:
                return grant
            if grant.bound_connection is not None:
                raise GrantError(
                    "the grant is already in use by another connection",
                    code="grant_bound_elsewhere",
                )
            self._db.execute(
                "UPDATE grants SET bound_instance = ?, bound_at = ? WHERE id = ?",
                (connection, utc_iso(now), grant.id),
            )
            return self.get(grant.id)

    def release(self, device: UsbDevice) -> GrantList:
        """Spend the one-time grants bound to a connection that has ended.

        Call this when a device is removed, with the device as it was reported. Calling
        it again, or for a connection that holds no grant, returns an empty list.

        Returns:
            The grants that were spent, now ended with reason ``used``.

        Raises:
            GrantError: ``grant_invalid`` if ``device`` is not usable.
        """
        connection = _connection(device)
        with self._db.transaction():
            rows = self._db.query(
                "SELECT id FROM grants WHERE bound_instance = ? AND ended_at IS NULL"
                " ORDER BY created_at, id",
                (connection,),
            )
            return self._end([row["id"] for row in rows], GrantEnd.USED)

    def release_absent(self, present: Iterable[UsbDevice]) -> GrantList:
        """Spend every bound one-time grant whose connection is no longer present.

        For service start: a device removed while the service was not running never
        produced a removal event, and its one-time grant must not survive to cover the
        next connection.

        Args:
            present: the devices connected now.

        Returns:
            The grants that were spent.

        Raises:
            GrantError: ``grant_invalid`` if one of the devices is not usable.
        """
        connections = {_connection(device) for device in present}
        with self._db.transaction():
            rows = self._db.query(
                "SELECT id, bound_instance FROM grants WHERE bound_instance IS NOT NULL"
                " AND ended_at IS NULL ORDER BY created_at, id"
            )
            stale = [row["id"] for row in rows if row["bound_instance"] not in connections]
            return self._end(stale, GrantEnd.USED)

    def expire_due(self, now: datetime) -> GrantList:
        """Mark every grant whose expiry has been reached as expired and return them.

        Each grant is returned exactly once, by the call that marks it, however many
        threads or processes call this: the caller audits the expiry and re-evaluates
        any connected device the grant covered.

        Returns:
            The newly expired grants, earliest expiry first; ``ended_at`` is the expiry.

        Raises:
            GrantError: ``grant_invalid`` if ``now`` is not timezone-aware.
        """
        stamp = utc_iso(_aware(now, "now"))
        with self._db.transaction():
            rows = self._db.query(
                "SELECT id FROM grants WHERE ended_at IS NULL AND expires_at IS NOT NULL"
                " AND expires_at <= ? ORDER BY expires_at, id",
                (stamp,),
            )
            ids = [row["id"] for row in rows]
            for grant_id in ids:
                self._db.execute(
                    "UPDATE grants SET ended_at = expires_at, end_reason = ? WHERE id = ?",
                    (GrantEnd.EXPIRED.value, grant_id),
                )
            return [self.get(grant_id) for grant_id in ids]

    def revoke(self, grant_id: str, by: str) -> Grant:
        """End a grant now.

        Raises:
            GrantError: ``grant_not_found`` if there is no such grant;
                ``grant_not_active`` if it has already ended or reached its expiry (an
                expired grant is left for :meth:`expire_due` to report);
                ``grant_invalid`` if ``by`` is malformed.
        """
        revoker = _text(by, "by", max_length=MAX_GRANTED_BY_LENGTH, allow_empty=False)
        with self._db.transaction():
            grant = self.get(grant_id)
            now = self._clock.now()
            if not grant.is_active(now):
                raise GrantError("the grant is no longer active", code="grant_not_active")
            self._db.execute(
                "UPDATE grants SET ended_at = ?, end_reason = ?, ended_by = ? WHERE id = ?",
                (utc_iso(now), GrantEnd.REVOKED.value, revoker, grant.id),
            )
            return self.get(grant.id)

    def list(self, include_inactive: bool = False) -> GrantList:
        """Return the stored grants, oldest first.

        Args:
            include_inactive: also return grants that were revoked, spent or have
                expired. By default only grants active at the clock's current time are
                returned.
        """
        rows = self._db.query("SELECT * FROM grants ORDER BY created_at, id")
        grants = [_from_row(row) for row in rows]
        if include_inactive:
            return grants
        now = self._clock.now()
        return [grant for grant in grants if grant.is_active(now)]

    def _end(self, grant_ids: Iterable[str], reason: GrantEnd) -> GrantList:
        """End the given grants now. Must be called inside a transaction."""
        stamp = utc_iso(self._clock.now())
        ended: GrantList = []
        for grant_id in grant_ids:
            self._db.execute(
                "UPDATE grants SET ended_at = ?, end_reason = ? WHERE id = ?",
                (stamp, reason.value, grant_id),
            )
            ended.append(self.get(str(grant_id)))
        return ended


def _span(duration: timedelta) -> str:
    """``24 h`` or ``30 days``, for messages."""
    hours = duration.total_seconds() / 3600
    if hours % 24 == 0 and hours >= 48:
        return f"{int(hours // 24)} days"
    return f"{hours:g} h"
