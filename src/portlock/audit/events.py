"""The audit event catalogue and the shared security-event envelope.

Three things live here, and everything else in :mod:`portlock.audit` builds on them:

* the **catalogue**: every event type PortLock records, as a constant, with its default
  severity and a one-line meaning (:data:`CATALOGUE`), and the :class:`EventRegistry`
  that the audit log consults so a mistyped event type is refused instead of stored;
* :func:`redact`, which replaces the values of secret-bearing keys before anything is
  written. **Secrets are never logged**: no password, token, recovery code or key
  material may appear in an event, redacted or not if it can be avoided;
* the **security-event envelope** (:func:`build_security_event`,
  :func:`validate_security_event`), the cross-project format specified in
  ``docs/SECURITY_EVENT_FORMAT.md`` that ClawNet verifies. Signing it is
  :mod:`portlock.audit.signing`'s job.

Nothing in this module reads the machine's host name or any other local identity: the
``host`` of an envelope is a label the operator chose and the caller passes in.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from portlock import __version__
from portlock.core.canonical import MAX_DEPTH, canonicalize
from portlock.core.clock import parse_utc_iso
from portlock.core.errors import CanonicalError, PortLockError
from portlock.core.models import Severity

if TYPE_CHECKING:
    from portlock.audit.log import AuditRecord

__all__ = [
    "CATALOGUE",
    "DEFAULT_SECRET_KEYS",
    "ENVELOPE_VERSION",
    "MAX_EVENT_BYTES",
    "PRODUCT",
    "REDACTED",
    "REGISTRY",
    "AuditError",
    "EventRegistry",
    "EventSpec",
    "build_security_event",
    "coerce_severity",
    "redact",
    "security_event_from_record",
    "validate_security_event",
]


class AuditError(PortLockError):
    """An audit operation was refused: bad input, an unknown event type, a corrupt record.

    ``code`` is ``audit_error`` unless a more specific one is given (``audit_corrupt``
    when stored data does not parse, ``signing_unavailable`` when the optional
    ``cryptography`` package is missing).
    """

    code = "audit_error"


# --- the catalogue -------------------------------------------------------------------

DEVICE_CONNECTED = "device.connected"
DEVICE_REMOVED = "device.removed"
DEVICE_CHANGED = "device.changed"
DECISION_MADE = "decision.made"
ENFORCEMENT_APPLIED = "enforcement.applied"
ENFORCEMENT_WOULD_APPLY = "enforcement.would_apply"
ENFORCEMENT_FAILED = "enforcement.failed"
ENFORCEMENT_REFUSED = "enforcement.refused"
SAFETY_SUSPICIOUS_DEVICE = "safety.suspicious_device"
SAFETY_CLONE_DETECTED = "safety.clone_detected"
SAFETY_PORT_HELD = "safety.port_held"
GRANT_CREATED = "grant.created"
GRANT_USED = "grant.used"
GRANT_EXPIRED = "grant.expired"
GRANT_REVOKED = "grant.revoked"
TRUST_ADDED = "trust.added"
TRUST_REMOVED = "trust.removed"
ENROLL_ADDED = "enroll.added"
ENROLL_REMOVED = "enroll.removed"
POLICY_CHANGED = "policy.changed"
POLICY_INVALID = "policy.invalid"
SCAN_STARTED = "scan.started"
SCAN_FINISHED = "scan.finished"
SCAN_DETECTION = "scan.detection"
AUTH_LOGIN = "auth.login"
AUTH_LOGOUT = "auth.logout"
AUTH_FAILURE = "auth.failure"
AUTH_LOCKOUT = "auth.lockout"
AUTH_PASSWORD_CHANGED = "auth.password_changed"  # noqa: S105 - an event name, not a password
AUTH_RECOVERY_USED = "auth.recovery_used"
AUTH_USER_CREATED = "auth.user_created"
AUTH_USER_CHANGED = "auth.user_changed"
LOCKDOWN_ENGAGED = "lockdown.engaged"
LOCKDOWN_RENEWED = "lockdown.renewed"
LOCKDOWN_LIFTED = "lockdown.lifted"
LOCKDOWN_EXPIRED = "lockdown.expired"
KILLSWITCH_ACTIVATED = "killswitch.activated"
RECOVERY_RESTORED = "recovery.restored"
SERVICE_STARTED = "service.started"
SERVICE_STOPPED = "service.stopped"
SERVICE_RECOVERED = "service.recovered"
STORE_RECOVERED = "store.recovered"
MODE_CHANGED = "mode.changed"
CONFIG_CHANGED = "config.changed"
CHANGE_PENDING = "change.pending"
CHANGE_CONFIRMED = "change.confirmed"
CHANGE_ROLLED_BACK = "change.rolled_back"
CLOCK_ROLLBACK_DETECTED = "clock.rollback_detected"
AUDIT_VERIFIED = "audit.verified"
AUDIT_VERIFICATION_FAILED = "audit.verification_failed"

#: Longest event type accepted anywhere (the table, the envelope, a query filter).
MAX_EVENT_TYPE_LENGTH = 64

# Lowercase dotted names: ``area.what_happened``. At least two segments, so an event
# type can never be mistaken for a bare word in a filter or a syslog field.
_EVENT_TYPE_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+\Z")


@dataclass(frozen=True, slots=True)
class EventSpec:
    """One catalogue entry.

    Attributes:
        name: the event type, e.g. ``device.connected``.
        severity: the severity used when the caller does not give one.
        meaning: one line saying what the event records.
    """

    name: str
    severity: Severity
    meaning: str


#: Every event type PortLock records. ``docs/SECURITY_EVENT_FORMAT.md`` carries the same
#: table, and a test keeps the two in step.
CATALOGUE: tuple[EventSpec, ...] = (
    EventSpec(DEVICE_CONNECTED, Severity.INFO, "A USB device arrived, or was present at start-up."),
    EventSpec(DEVICE_REMOVED, Severity.INFO, "A USB device was unplugged."),
    EventSpec(
        DEVICE_CHANGED,
        Severity.INFO,
        "A connected device gained new information, typically a mounted volume.",
    ),
    EventSpec(DECISION_MADE, Severity.INFO, "The pipeline decided what a device may do, and why."),
    EventSpec(
        ENFORCEMENT_APPLIED,
        Severity.NOTICE,
        "The operating system was changed to enforce a decision.",
    ),
    EventSpec(
        ENFORCEMENT_WOULD_APPLY,
        Severity.INFO,
        "Monitor mode: what would have been enforced. Nothing was changed.",
    ),
    EventSpec(
        ENFORCEMENT_FAILED,
        Severity.ERROR,
        "An enforcement mechanism failed or is unavailable; the decision is not enforced.",
    ),
    EventSpec(
        ENFORCEMENT_REFUSED,
        Severity.WARNING,
        "The safety choke point refused to act on a protected device.",
    ),
    EventSpec(
        SAFETY_SUSPICIOUS_DEVICE,
        Severity.WARNING,
        "A device has a shape associated with attacks, such as storage paired with a keyboard.",
    ),
    EventSpec(
        SAFETY_CLONE_DETECTED,
        Severity.WARNING,
        "A second device presented an enrolled fingerprint while the first was connected; "
        "it was denied.",
    ),
    EventSpec(
        SAFETY_PORT_HELD,
        Severity.WARNING,
        "Too many arrivals on one port: it is held blocked for a cool-down and further "
        "arrivals are coalesced.",
    ),
    EventSpec(GRANT_CREATED, Severity.NOTICE, "An access grant was issued for a device."),
    EventSpec(GRANT_USED, Severity.INFO, "A grant permitted a device connection."),
    EventSpec(GRANT_EXPIRED, Severity.INFO, "A grant reached its expiry or was consumed."),
    EventSpec(GRANT_REVOKED, Severity.NOTICE, "A grant was withdrawn before it expired."),
    EventSpec(TRUST_ADDED, Severity.NOTICE, "A device was added to the trusted set."),
    EventSpec(TRUST_REMOVED, Severity.NOTICE, "A device was removed from the trusted set."),
    EventSpec(
        ENROLL_ADDED,
        Severity.NOTICE,
        "An input device was enrolled by fingerprint and port, so it is protected on that port.",
    ),
    EventSpec(ENROLL_REMOVED, Severity.NOTICE, "An enrolled input device lost its enrolment."),
    EventSpec(
        POLICY_CHANGED,
        Severity.NOTICE,
        "The policy was replaced; carries the old and new content hash.",
    ),
    EventSpec(POLICY_INVALID, Severity.ERROR, "A policy document was rejected by validation."),
    EventSpec(SCAN_STARTED, Severity.INFO, "A content scan of a mounted volume began."),
    EventSpec(SCAN_FINISHED, Severity.INFO, "A content scan ended; carries its totals and limits."),
    EventSpec(SCAN_DETECTION, Severity.WARNING, "A scan engine flagged a file on a volume."),
    EventSpec(AUTH_LOGIN, Severity.INFO, "An administrator, operator or auditor signed in."),
    EventSpec(AUTH_LOGOUT, Severity.INFO, "A session ended by sign-out or timeout."),
    EventSpec(AUTH_FAILURE, Severity.WARNING, "A sign-in or privileged confirmation failed."),
    EventSpec(AUTH_LOCKOUT, Severity.WARNING, "Repeated failures locked an account for a while."),
    EventSpec(AUTH_PASSWORD_CHANGED, Severity.NOTICE, "An account's password was changed."),
    EventSpec(AUTH_RECOVERY_USED, Severity.WARNING, "A single-use recovery code was spent."),
    EventSpec(AUTH_USER_CREATED, Severity.NOTICE, "An account was created."),
    EventSpec(
        AUTH_USER_CHANGED, Severity.NOTICE, "An account's role or state was changed, or removed."
    ),
    EventSpec(
        LOCKDOWN_ENGAGED,
        Severity.WARNING,
        "Emergency lockdown began: removable storage is blocked.",
    ),
    EventSpec(LOCKDOWN_RENEWED, Severity.NOTICE, "The lockdown dead-man timer was extended."),
    EventSpec(LOCKDOWN_LIFTED, Severity.NOTICE, "An administrator ended the lockdown."),
    EventSpec(
        LOCKDOWN_EXPIRED,
        Severity.WARNING,
        "The dead-man timer ran out and the lockdown lifted itself.",
    ),
    EventSpec(
        KILLSWITCH_ACTIVATED,
        Severity.CRITICAL,
        "The kill-switch file was found: enforcement is off and settings were restored.",
    ),
    EventSpec(
        RECOVERY_RESTORED,
        Severity.WARNING,
        "Journaled operating-system settings were put back, by the service or by "
        "'portlock recover'.",
    ),
    EventSpec(SERVICE_STARTED, Severity.INFO, "The PortLock service started."),
    EventSpec(SERVICE_STOPPED, Severity.NOTICE, "The PortLock service stopped cleanly."),
    EventSpec(
        SERVICE_RECOVERED,
        Severity.WARNING,
        "The service started after an unclean stop and reconciled its state.",
    ),
    EventSpec(
        STORE_RECOVERED,
        Severity.CRITICAL,
        "A damaged database was moved aside; this new log names its hash and last known head.",
    ),
    EventSpec(MODE_CHANGED, Severity.NOTICE, "The mode changed between monitor and enforce."),
    EventSpec(CONFIG_CHANGED, Severity.NOTICE, "A configuration setting was changed."),
    EventSpec(
        CHANGE_PENDING,
        Severity.NOTICE,
        "A change that could lock the operator out was applied and rolls back unless "
        "confirmed in time.",
    ),
    EventSpec(
        CHANGE_CONFIRMED,
        Severity.NOTICE,
        "A pending change was confirmed over the same channel and is kept.",
    ),
    EventSpec(
        CHANGE_ROLLED_BACK,
        Severity.WARNING,
        "A pending change was not confirmed in time, or was refused, and was rolled back.",
    ),
    EventSpec(
        CLOCK_ROLLBACK_DETECTED,
        Severity.WARNING,
        "The wall clock is behind the newest audit timestamp; expiries use the later time.",
    ),
    EventSpec(AUDIT_VERIFIED, Severity.INFO, "The audit chain was walked and found intact."),
    EventSpec(
        AUDIT_VERIFICATION_FAILED,
        Severity.CRITICAL,
        "The audit chain does not verify: the log was altered or damaged.",
    ),
)


def coerce_severity(value: Severity | str) -> Severity:
    """Return ``value`` as a :class:`Severity`.

    Raises:
        AuditError: if it is not one of the six severity names.
    """
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value)
        except ValueError:
            pass
    names = ", ".join(level.value for level in Severity)
    raise AuditError(f"unknown severity {value!r}; expected one of: {names}")


def _check_event_type(event_type: object) -> str:
    if (
        not isinstance(event_type, str)
        or len(event_type) > MAX_EVENT_TYPE_LENGTH
        or not _EVENT_TYPE_PATTERN.match(event_type)
    ):
        raise AuditError(
            f"invalid event type {event_type!r}: expected lowercase dotted words such as "
            f"'device.connected', at most {MAX_EVENT_TYPE_LENGTH} characters"
        )
    return event_type


class EventRegistry:
    """The set of event types the audit log accepts.

    In strict mode (the default) an event type that is not registered is refused when it
    is appended, so a typo cannot quietly create a new kind of event that no filter,
    alert or consumer knows about. In lenient mode an unregistered but well-formed type
    is accepted, provided the caller states its severity.

    Thread-safe.

    Args:
        specs: the entries to start with.
        strict: refuse unregistered event types.

    Raises:
        AuditError: if an entry is malformed or two entries disagree.
    """

    def __init__(self, specs: Iterable[EventSpec] = (), *, strict: bool = True) -> None:
        self._strict = bool(strict)
        self._lock = threading.Lock()
        self._specs: dict[str, EventSpec] = {}
        for spec in specs:
            self.register(spec.name, spec.severity, spec.meaning)

    @property
    def strict(self) -> bool:
        """True if unregistered event types are refused."""
        return self._strict

    def register(self, name: str, severity: Severity | str, meaning: str) -> EventSpec:
        """Add an event type. Registering an identical entry again is harmless.

        Raises:
            AuditError: if the name is malformed, the meaning is empty, or the name is
                already registered with a different severity or meaning.
        """
        spec = EventSpec(_check_event_type(name), coerce_severity(severity), meaning)
        if not isinstance(meaning, str) or not meaning.strip() or "\n" in meaning:
            raise AuditError(f"event type {name!r} needs a one-line meaning")
        with self._lock:
            existing = self._specs.get(spec.name)
            if existing is not None and existing != spec:
                raise AuditError(f"event type {name!r} is already registered differently")
            self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> EventSpec | None:
        """The entry for ``name``, or ``None`` if it is not registered."""
        return self._specs.get(name) if isinstance(name, str) else None

    def resolve(
        self, event_type: str, severity: Severity | str | None = None
    ) -> tuple[str, Severity]:
        """Check an event type and settle its severity.

        Args:
            event_type: the event type about to be recorded.
            severity: the caller's severity, or ``None`` for the catalogue default.

        Returns:
            The event type and the severity to record.

        Raises:
            AuditError: if the type is malformed, is unregistered in strict mode, or is
                unregistered and no severity was given.
        """
        name = _check_event_type(event_type)
        spec = self._specs.get(name)
        if spec is None:
            if self._strict:
                raise AuditError(
                    f"unknown event type {name!r}: register it in portlock.audit.events "
                    "or use a lenient registry",
                    code="unknown_event_type",
                )
            if severity is None:
                raise AuditError(f"event type {name!r} has no default severity; state one")
            return name, coerce_severity(severity)
        return name, spec.severity if severity is None else coerce_severity(severity)

    def copy(self, *, strict: bool | None = None) -> EventRegistry:
        """An independent registry with the same entries, optionally in the other mode."""
        return EventRegistry(self, strict=self._strict if strict is None else strict)

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __iter__(self) -> Iterator[EventSpec]:
        with self._lock:
            return iter(sorted(self._specs.values(), key=lambda spec: spec.name))

    def __len__(self) -> int:
        return len(self._specs)


#: The process-wide strict registry, pre-loaded with :data:`CATALOGUE`. This is what an
#: ``AuditLog`` uses unless it is given another one.
REGISTRY = EventRegistry(CATALOGUE, strict=True)


# --- redaction -----------------------------------------------------------------------

#: What :func:`redact` puts in place of a secret.
REDACTED = "[redacted]"

#: Keys whose values are never written to the audit log, compared without regard to case.
#: Deliberately specific: a bare ``key`` is not listed, because events legitimately name
#: configuration keys.
DEFAULT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "csrf_token",
        "current_password",
        "hmac_key",
        "new_password",
        "old_password",
        "passphrase",
        "passwd",
        "password",
        "private_key",
        "recovery_code",
        "recovery_codes",
        "secret",
        "session_token",
        "signing_key",
        "token",
    }
)


def redact(data: Any, keys: Iterable[str] = DEFAULT_SECRET_KEYS) -> Any:
    """Return a copy of ``data`` with the values of secret-bearing keys replaced.

    Objects and arrays are walked to any depth; wherever an object key equals one of
    ``keys`` (ignoring case) its whole value becomes :data:`REDACTED`. The input is not
    modified. Mappings come back as ``dict`` and sequences as ``list``.

    This is a safety net, not a licence: the rule is that secrets are not put into audit
    data in the first place.

    Args:
        data: the value to clean, normally the ``data`` of an event.
        keys: the key names to blank out.

    Raises:
        AuditError: if ``keys`` holds something other than strings, or ``data`` is nested
            deeper than canonical JSON allows (which also stops a self-referencing value).
    """
    names = [keys] if isinstance(keys, str) else list(keys)
    if not all(isinstance(name, str) for name in names):
        raise AuditError("redaction keys must be strings")
    return _redact(data, frozenset(name.casefold() for name in names), 0)


def _redact(value: Any, wanted: frozenset[str], depth: int) -> Any:
    if isinstance(value, Mapping):
        if depth >= MAX_DEPTH:
            raise AuditError(f"data is nested deeper than {MAX_DEPTH} levels")
        return {
            key: REDACTED
            if isinstance(key, str) and key.casefold() in wanted
            else _redact(item, wanted, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        if depth >= MAX_DEPTH:
            raise AuditError(f"data is nested deeper than {MAX_DEPTH} levels")
        return [_redact(item, wanted, depth + 1) for item in value]
    return value


# --- the security-event envelope -----------------------------------------------------

#: The envelope version this code writes and accepts (the ``v`` member).
ENVELOPE_VERSION = 1

#: The ``source.product`` of every event PortLock emits.
PRODUCT = "portlock"

#: Upper bound on the canonical encoding of one envelope, signature included.
MAX_EVENT_BYTES = 256 * 1024

_MAX_SAFE_INTEGER = 2**53 - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
# No C0 controls, DEL or C1 controls: these labels end up in log lines and terminals.
_LABEL_PATTERN = re.compile(r"[^\x00-\x1f\x7f-\x9f]+\Z")
_MAX_HOST_LENGTH = 255
_MAX_VERSION_LENGTH = 64

_UNSIGNED_MEMBERS = frozenset(
    {"v", "id", "ts", "source", "type", "severity", "subject", "data", "chain"}
)
_SOURCE_MEMBERS = frozenset({"product", "version", "host"})
_CHAIN_MEMBERS = frozenset({"seq", "hash"})
_SIG_MEMBERS = frozenset({"alg", "key", "value"})
_SEVERITIES = frozenset(level.value for level in Severity)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _epoch_millis(value: datetime | int) -> int:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AuditError("ts must be a timezone-aware datetime or integer milliseconds")
        # Integer arithmetic throughout: a float would round differently per platform.
        return (value.astimezone(UTC) - _EPOCH) // timedelta(milliseconds=1)
    if _is_int(value):
        return int(value)
    raise AuditError("ts must be a timezone-aware datetime or integer milliseconds")


def _plain_object(value: Mapping[str, Any] | None, member: str) -> dict[str, Any]:
    """Copy ``value`` into plain JSON types, proving on the way that it is canonical-safe."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AuditError(f"{member} must be an object")
    try:
        plain = json.loads(canonicalize(dict(value)))
    except CanonicalError as exc:
        raise AuditError(f"{member} cannot be written as canonical JSON: {exc}") from exc
    if not isinstance(plain, dict):
        raise AuditError(f"{member} must be an object")
    return plain


def build_security_event(
    event_type: str,
    *,
    host: str,
    ts: datetime | int,
    severity: Severity | str | None = None,
    subject: Mapping[str, Any] | None = None,
    data: Mapping[str, Any] | None = None,
    chain: tuple[int, str] | Mapping[str, Any] | None = None,
    version: str = __version__,
    event_id: str | None = None,
    registry: EventRegistry | None = None,
) -> dict[str, Any]:
    """Build an unsigned security-event envelope (``docs/SECURITY_EVENT_FORMAT.md``).

    ``subject`` and ``data`` pass through :func:`redact` with the default key list.

    Args:
        event_type: a catalogue event type.
        host: the operator-chosen label for this machine. It is never read from the
            operating system.
        ts: when the event happened: an aware datetime, or integer milliseconds since
            the Unix epoch. Sub-millisecond precision is dropped.
        severity: overrides the catalogue default.
        subject: who or what the event is about (``actor``, ``device_fp``, ...).
        data: event details.
        chain: the audit-log position this event commits to, as ``(seq, hash)`` or
            ``{"seq": ..., "hash": ...}``; ``None`` if it is not tied to the log.
        version: the emitting PortLock version.
        event_id: 32 lowercase hex characters; a random 128-bit id if omitted.
        registry: the registry to check ``event_type`` against (default :data:`REGISTRY`).

    Returns:
        The envelope, without a ``sig`` member, made only of plain JSON types.

    Raises:
        AuditError: if any member is invalid or the result exceeds
            :data:`MAX_EVENT_BYTES`.
    """
    name, level = (registry if registry is not None else REGISTRY).resolve(event_type, severity)
    if chain is None:
        chain_member: dict[str, Any] | None = None
    elif isinstance(chain, Mapping):
        chain_member = dict(chain)
    elif isinstance(chain, tuple) and len(chain) == 2:
        chain_member = {"seq": chain[0], "hash": chain[1]}
    else:
        raise AuditError("chain must be (seq, hash), an object with those members, or None")
    event: dict[str, Any] = {
        "v": ENVELOPE_VERSION,
        "id": secrets.token_hex(16) if event_id is None else event_id,
        "ts": _epoch_millis(ts),
        "source": {"product": PRODUCT, "version": version, "host": host},
        "type": name,
        "severity": level.value,
        "subject": redact(_plain_object(subject, "subject")),
        "data": redact(_plain_object(data, "data")),
        "chain": chain_member,
    }
    validate_security_event(event, signed=False)
    return event


def security_event_from_record(
    record: AuditRecord, *, host: str, version: str = __version__
) -> dict[str, Any]:
    """Build the unsigned envelope for one audit record.

    The envelope's ``chain`` is the record's ``seq`` and ``hash``, so a signature over it
    also commits to every earlier record: a signed event made this way is a checkpoint.
    The ``id`` is derived from the host label and the record hash, so exporting the same
    record twice yields the same id and a receiver can de-duplicate.

    Args:
        record: a record returned by the audit log.
        host: the operator-chosen label for this machine.
        version: the emitting PortLock version.

    Raises:
        AuditError: if the record or the host label is not valid for an envelope.
    """
    if not isinstance(host, str):
        raise AuditError("source.host must be a string")
    try:
        moment = parse_utc_iso(record.ts)
        digest = bytes.fromhex(record.hash)
    except ValueError as exc:
        raise AuditError(f"audit record {record.seq} is not well formed: {exc}") from exc
    try:
        label = host.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditError("source.host must be well-formed Unicode") from exc
    event_id = hashlib.sha256(b"portlock/1/event-id\x00" + label + b"\x00" + digest).hexdigest()
    subject = {
        name: value
        for name, value in (("actor", record.actor), ("device_fp", record.device_fp))
        if value is not None
    }
    event: dict[str, Any] = {
        "v": ENVELOPE_VERSION,
        "id": event_id[:32],
        "ts": _epoch_millis(moment),
        "source": {"product": PRODUCT, "version": version, "host": host},
        "type": record.event_type,
        "severity": coerce_severity(record.severity).value,
        "subject": subject,
        "data": _plain_object(record.data, "data"),
        "chain": {"seq": record.seq, "hash": record.hash},
    }
    validate_security_event(event, signed=False)
    return event


def _require_members(value: object, expected: frozenset[str], member: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuditError(f"{member} must be an object")
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(str(key) for key in set(value) - expected)
        detail = "; ".join(
            part
            for part in (
                f"missing {', '.join(missing)}" if missing else "",
                f"unexpected {', '.join(extra)}" if extra else "",
            )
            if part
        )
        raise AuditError(f"{member} has the wrong members ({detail})")
    return value


def _require_label(value: object, member: str, limit: int) -> None:
    if not isinstance(value, str) or not 0 < len(value) <= limit or not _LABEL_PATTERN.match(value):
        raise AuditError(f"{member} must be 1 to {limit} characters with no control characters")


def validate_security_event(event: object, *, signed: bool | None = None) -> None:
    """Check that ``event`` is a well-formed version-1 envelope.

    This checks structure and types only. It does not check the signature: that is
    :func:`portlock.audit.signing.verify_event`.

    Args:
        event: the parsed envelope.
        signed: ``True`` requires a ``sig`` member, ``False`` forbids one, ``None``
            accepts either.

    Raises:
        AuditError: naming the first member that is wrong.
    """
    if not isinstance(event, dict):
        raise AuditError("a security event must be an object")
    has_sig = "sig" in event
    if signed is True and not has_sig:
        raise AuditError("the event is not signed")
    if signed is False and has_sig:
        raise AuditError("the event is already signed")
    _require_members(event, _UNSIGNED_MEMBERS | ({"sig"} if has_sig else set()), "the event")

    if not _is_int(event["v"]) or event["v"] != ENVELOPE_VERSION:
        raise AuditError(f"v must be {ENVELOPE_VERSION}")
    if not isinstance(event["id"], str) or not _ID_PATTERN.match(event["id"]):
        raise AuditError("id must be 32 lowercase hexadecimal characters")
    if not _is_int(event["ts"]) or not 0 <= event["ts"] <= _MAX_SAFE_INTEGER:
        raise AuditError("ts must be integer milliseconds since the Unix epoch")

    source = _require_members(event["source"], _SOURCE_MEMBERS, "source")
    if source["product"] != PRODUCT:
        raise AuditError(f"source.product must be {PRODUCT!r}")
    _require_label(source["version"], "source.version", _MAX_VERSION_LENGTH)
    _require_label(source["host"], "source.host", _MAX_HOST_LENGTH)

    _check_event_type(event["type"])
    if not isinstance(event["severity"], str) or event["severity"] not in _SEVERITIES:
        raise AuditError("severity must be one of: " + ", ".join(s.value for s in Severity))
    for member in ("subject", "data"):
        if not isinstance(event[member], dict):
            raise AuditError(f"{member} must be an object")

    if event["chain"] is not None:
        chain = _require_members(event["chain"], _CHAIN_MEMBERS, "chain")
        if not _is_int(chain["seq"]) or not 0 <= chain["seq"] <= _MAX_SAFE_INTEGER:
            raise AuditError("chain.seq must be a non-negative integer")
        if not isinstance(chain["hash"], str) or not _HASH_PATTERN.match(chain["hash"]):
            raise AuditError("chain.hash must be 64 lowercase hexadecimal characters")

    if has_sig:
        sig = _require_members(event["sig"], _SIG_MEMBERS, "sig")
        if sig["alg"] != "ed25519":
            raise AuditError("sig.alg must be 'ed25519'")
        for member in ("key", "value"):
            if not isinstance(sig[member], str):
                raise AuditError(f"sig.{member} must be a base64 string")

    try:
        size = len(canonicalize(event).encode("utf-8"))
    except CanonicalError as exc:
        raise AuditError(f"the event cannot be written as canonical JSON: {exc}") from exc
    if size > MAX_EVENT_BYTES:
        raise AuditError(f"the event is {size} bytes; the limit is {MAX_EVENT_BYTES}")
