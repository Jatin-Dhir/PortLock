"""Emergency lockdown and the safeguards around everything that can lock the operator out.

What lives here (``docs/ARCHITECTURE.md`` 3.5 and 5.2, as amended by ``docs/DESIGN.md``
section 14):

* :class:`CommitConfirm`, the general commit-confirm mechanism (section 14.15): list
  what a change would block, write the change down, apply it, and roll it back unless it
  is confirmed over the same channel within the configured seconds. Engaging lockdown is
  one such change; switching to enforce mode, widening the scope and turning on
  default-deny register their own handlers with the same object.
* :class:`LockdownManager`, the persisted lockdown state machine. Its dead-man timer
  counts down on the monotonic clock and persists the time remaining, so a restart
  resumes the remainder (section 14.12); a one-shot operating-system timer, armed at
  engage and cancelled at lift or renewal, runs ``portlock recover`` at expiry even if
  the service has died (section 14.16). Lifting needs a credential, checked by an
  injected verifier.
* :class:`KillSwitch`, honoured only inside a directory an injected check says is
  private (section 14.18).
* :func:`rollback` and :func:`recover`, which put every journaled setting back. ``recover``
  needs neither the service nor the database, nor any PortLock credential: it reads the
  journal file alone, and the caller proves operating-system administrator rights.

The manager decides *whether* a lockdown is in force and *which* devices it holds;
blocking them is done by the service's convergence (the injected ``reconcile``), so one
code path blocks devices. Seams for the operating-system timer, the directory privacy
check and the credential check are small :class:`~typing.Protocol` classes defined here,
so any object with the right methods will do.

Nothing here holds a lock of its own: every method is called with the service's lock
held (``ARCHITECTURE.md`` 1.4), or from a single-threaded command-line process.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import logging
import math
import os
import secrets
import tempfile
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol

from portlock.core.clock import Clock, parse_utc_iso, utc_iso
from portlock.core.config import LockdownConfig
from portlock.core.errors import AuthError, NotPrivilegedError, PortLockError, StoreError
from portlock.core.models import UsbDevice
from portlock.core.store import (
    JOURNAL_FILE_NAME,
    LockdownRecord,
    PendingChangeRecord,
    RecoveryJournal,
    StateStore,
)
from portlock.guard.base import Action, EnforcementResult, Enforcer

__all__ = [
    "CHANGE_DEFAULT_DENY",
    "CHANGE_ENFORCE_MODE",
    "CHANGE_LOCKDOWN",
    "CHANGE_WIDEN_SCOPE",
    "CONFIRM_TIMER_PREFIX",
    "LOCKDOWN_TIMER",
    "RECOVER_MARKER",
    "AuditFn",
    "ChangeHandler",
    "CommitConfirm",
    "ConfirmationError",
    "Connected",
    "Credential",
    "CredentialCheck",
    "EngageResult",
    "ExternalTimer",
    "KillSwitch",
    "KillSwitchState",
    "LiftResult",
    "LockdownError",
    "LockdownManager",
    "LockdownState",
    "LockdownStatus",
    "PlanItem",
    "PrivacyCheck",
    "PrivacyReportLike",
    "ProtectionLike",
    "ReconcileSummary",
    "RollbackReport",
    "consume_recover_marker",
    "recover",
    "rollback",
    "write_recover_marker",
]

_LOG = logging.getLogger(__name__)

#: Name of the operating-system timer that ends a lockdown if the service cannot.
LOCKDOWN_TIMER = "portlock-lockdown"
#: Prefix of the timer that rolls back an unconfirmed change; the change id follows.
CONFIRM_TIMER_PREFIX = "portlock-confirm-"
#: The commit-confirm change kinds of section 14.15.
CHANGE_LOCKDOWN = "lockdown"
CHANGE_ENFORCE_MODE = "enforce_mode"
CHANGE_WIDEN_SCOPE = "widen_scope"
CHANGE_DEFAULT_DENY = "default_deny"
#: File ``portlock recover`` leaves in the state directory for the next start to audit.
RECOVER_MARKER = "last-recover.json"

_SYSTEM = "system"
_LOCAL_CONSOLE = "local-console"
_MAX_REASON = 256
_MAX_PREVIEW_IN_AUDIT = 50
# How long after the deadline (a confirmation's, or a lockdown's expiry) the
# out-of-process timer fires: the service ends it first when it is alive, on a tick that
# runs about once a second, and the timer is only the backstop for a service that died.
# Armed for the exact instant, it would race the service's own lift.
_CONFIRM_TIMER_GRACE_SECONDS = 30
_LOCKDOWN_TIMER_GRACE_SECONDS = 30
# A wall clock that drifts this far from the monotonic clock was changed; the timer that
# fires by wall-clock time is then re-armed.
_CLOCK_TOLERANCE_SECONDS = 60
_DEFAULT_CHECKPOINT_SECONDS = 10

# Audit event names (portlock.audit.events; lockdown.manager may not import audit).
_LOCKDOWN_ENGAGED = "lockdown.engaged"
_LOCKDOWN_RENEWED = "lockdown.renewed"
_LOCKDOWN_LIFTED = "lockdown.lifted"
_LOCKDOWN_EXPIRED = "lockdown.expired"
_CHANGE_PENDING = "change.pending"
_CHANGE_CONFIRMED = "change.confirmed"
_CHANGE_ROLLED_BACK = "change.rolled_back"

#: ``audit(event_type, *, severity=None, actor=None, device_fp=None, data=None)``.
AuditFn = Callable[..., None]


# --- errors and value types --------------------------------------------------------------


class LockdownError(PortLockError):
    """A lockdown request cannot be carried out.

    Codes: ``lockdown_active``, ``lockdown_not_active``, ``invalid_duration``,
    ``invalid_reason``, ``killswitch_active``, ``not_lifting``, ``in_transaction``.
    """

    code = "lockdown_error"


class ConfirmationError(PortLockError):
    """A commit-confirm request cannot be carried out.

    Codes: ``unknown_change_kind``, ``change_pending``, ``no_pending_change``,
    ``not_ready``, ``wrong_channel``, ``confirmation_expired``, ``timer_unavailable``.
    """

    code = "confirmation_error"


class LockdownState(StrEnum):
    """States of the lockdown state machine (``ARCHITECTURE.md`` 5.2)."""

    IDLE = "idle"
    ENGAGING = "engaging"
    ACTIVE = "active"
    LIFTING = "lifting"


@dataclass(frozen=True, slots=True)
class ReconcileSummary:
    """What one reconciliation of every connected device did."""

    evaluated: int = 0
    changed: int = 0
    blocked: int = 0
    read_only: int = 0
    released: int = 0
    failed: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "evaluated": self.evaluated,
            "changed": self.changed,
            "blocked": self.blocked,
            "read_only": self.read_only,
            "released": self.released,
            "failed": self.failed,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconcileSummary:
        values = {name: data.get(name, 0) for name in cls.__dataclass_fields__}
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class Credential:
    """A password or a recovery code offered to lift a lockdown. Never printed.

    ``local`` is True when it came over the elevated local command line (the request
    carried the secret from the private runtime file). Such a password is checked on the
    local channel, which the network lockout never refuses (DESIGN 14.21).
    """

    kind: Literal["password", "recovery_code"]
    secret: str = field(repr=False)
    local: bool = False


@dataclass(frozen=True, slots=True)
class LockdownStatus:
    """The lockdown as the API shows it (``API.md`` 4.12), plus commit-confirm state."""

    state: LockdownState
    active: bool
    engaged_at: datetime | None
    engaged_by: str | None
    reason: str | None
    expires_at: datetime | None
    remaining_seconds: int | None
    renew_count: int
    default_minutes: int
    max_minutes: int
    pending_change_id: str | None = None
    confirm_remaining_seconds: int | None = None
    external_timer_armed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "active": self.active,
            "engaged_at": _iso(self.engaged_at),
            "engaged_by": self.engaged_by,
            "reason": self.reason,
            "expires_at": _iso(self.expires_at),
            "remaining_seconds": self.remaining_seconds,
            "renew_count": self.renew_count,
            "default_minutes": self.default_minutes,
            "max_minutes": self.max_minutes,
            "pending_change_id": self.pending_change_id,
            "confirm_remaining_seconds": self.confirm_remaining_seconds,
            "external_timer_armed": self.external_timer_armed,
        }


@dataclass(frozen=True, slots=True)
class PlanItem:
    """What a lockdown does, or would do, with one connected device.

    Attributes:
        outcome: ``block`` (it will be blocked), ``protected`` (the safety layer keeps
            it working, whatever the lockdown says), ``exempt`` (the lockdown leaves it
            alone by its own rules) or ``not_enforced`` (outside the enforcement scope:
            *not* protected, just not something PortLock can block).
    """

    instance_id: str
    name: str
    vid_pid: str
    outcome: Literal["block", "protected", "exempt", "not_enforced"]
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "instance_id": self.instance_id,
            "name": self.name,
            "vid_pid": self.vid_pid,
            "outcome": self.outcome,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class EngageResult:
    """The outcome of :meth:`LockdownManager.engage`: in force, awaiting confirmation."""

    status: LockdownStatus
    change: PendingChangeRecord
    summary: ReconcileSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "lockdown": self.status.to_dict(),
            "summary": self.summary.to_dict(),
            "change": _change_dict(self.change),
        }


@dataclass(frozen=True, slots=True)
class LiftResult:
    """The outcome of :meth:`LockdownManager.lift`."""

    status: LockdownStatus
    summary: ReconcileSummary | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lockdown": self.status.to_dict(),
            "summary": None if self.summary is None else self.summary.to_dict(),
        }


# --- seams -------------------------------------------------------------------------------


class ExternalTimer(Protocol):
    """A one-shot operating-system timer that runs a command at a set time (14.16).

    ``arm`` runs ``argv`` (``portlock recover``) at ``at`` and replaces a timer of the
    same name if one exists. ``cancel`` succeeds when there is nothing to cancel. Both
    raise on failure.
    """

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None: ...

    def cancel(self, name: str) -> None: ...


class PrivacyReportLike(Protocol):
    """The answer of a :class:`PrivacyCheck`."""

    @property
    def private(self) -> bool: ...

    @property
    def problems(self) -> tuple[str, ...]: ...


class PrivacyCheck(Protocol):
    """Reports whether a directory is private: owned by the service account and not
    writable by anyone else (section 14.18). ``check`` never changes anything."""

    def check(self, path: str | os.PathLike[str]) -> PrivacyReportLike: ...


class CredentialCheck(Protocol):
    """Verifies the administrator password or a recovery code of ``actor``."""

    def verify(self, actor: str, credential: Credential) -> bool: ...


class ProtectionLike(Protocol):
    """What the manager reads from a safety verdict (``guard.safety.ProtectionVerdict``)."""

    @property
    def protected(self) -> bool: ...

    @property
    def in_scope(self) -> bool: ...

    @property
    def reasons(self) -> tuple[str, ...]: ...


class Connected(Protocol):
    """A connected device and when it arrived (``core.store.ConnectionRecord`` fits)."""

    @property
    def device(self) -> UsbDevice: ...

    @property
    def connected_at(self) -> datetime: ...


class ChangeHandler(Protocol):
    """One kind of change that commit-confirm can apply and roll back.

    ``preview`` lists what the change would block, before anything is applied.
    ``apply`` makes the change and returns what to report (JSON values, no floats), or
    ``None``. ``revert`` undoes it and must be idempotent: after a crash it can run for a
    change that was only partly applied, or already reverted. With ``at_start`` True it
    runs at service start-up, before devices are evaluated, and may leave the release
    itself to the first reconciliation.
    """

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]: ...

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None: ...

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None: ...


# --- commit-confirm ----------------------------------------------------------------------


class CommitConfirm:
    """Apply a risky change, and roll it back unless it is confirmed in time (14.15).

    Each change is written to the store *before* it is applied, so a crash at any point
    leaves a record that :meth:`resume` rolls back at the next start: an unconfirmed
    change never outlives the run that made it. While it waits, an operating-system timer
    (when one is given) is armed for shortly after the deadline, so the change is rolled
    back by ``portlock recover`` even if the service dies. The deadline itself is kept on
    the monotonic clock: moving the wall clock neither extends nor shortens it.

    Confirmation must come over the same *channel* (an identifier the caller chooses,
    such as an API session id; it is stored only as a SHA-256 digest) and in time.

    Args:
        store: where pending changes are written ahead.
        clock: wall and monotonic time.
        timeout_seconds: ``Config.commit_confirm_seconds``.
        audit: records ``change.pending``, ``change.confirmed``, ``change.rolled_back``.
        timer: the operating-system backstop, or ``None`` where there is none.
        recover_argv: the command the backstop runs (``portlock recover``); required
            with a timer.
    """

    def __init__(
        self,
        store: StateStore,
        *,
        clock: Clock,
        timeout_seconds: int,
        audit: AuditFn,
        timer: ExternalTimer | None = None,
        recover_argv: Sequence[str] = (),
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise TypeError("timeout_seconds must be an integer")
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        if timer is not None:
            _check_timer(timer)
            _check_argv(recover_argv)
        self._store = store
        self._clock = clock
        self._timeout = timeout_seconds
        self._audit = audit
        self._timer = timer
        self._argv = tuple(recover_argv)
        self._handlers: dict[str, ChangeHandler] = {}
        self._deadlines: dict[str, float] = {}

    @property
    def timeout_seconds(self) -> int:
        return self._timeout

    def register(self, kind: str, handler: ChangeHandler) -> None:
        """Make ``kind`` a change that can be proposed. One handler per kind."""
        if kind in self._handlers:
            raise ValueError(f"a handler for {kind!r} is already registered")
        for method in ("preview", "apply", "revert"):
            if not callable(getattr(handler, method, None)):
                raise TypeError(f"a change handler needs a {method}() method")
        self._handlers[kind] = handler

    def propose(
        self,
        kind: str,
        *,
        actor: str,
        channel: str,
        params: Mapping[str, Any] | None = None,
    ) -> PendingChangeRecord:
        """List, write down, apply. Returns the change, awaiting confirmation.

        Raises:
            ConfirmationError: ``unknown_change_kind``; ``change_pending`` if a change of
                this kind already waits; ``timer_unavailable`` if the backstop timer
                cannot be armed (nothing is applied then).
            Exception: whatever the handler's ``apply`` raised, after rolling back.
        """
        handler = self._handler(kind)
        _check_actor(actor)
        if not isinstance(channel, str) or not channel:
            raise ConfirmationError("a channel is required", code="wrong_channel")
        if self._store.pending_changes(kind=kind):
            raise ConfirmationError(
                f"a {kind} change is already waiting for confirmation", code="change_pending"
            )
        values = dict(params or {})
        preview = tuple(dict(item) for item in handler.preview(values))
        now = self._clock.now()
        record = self._store.add_pending_change(
            PendingChangeRecord(
                id=secrets.token_hex(8),
                kind=kind,
                status="applying",
                actor=actor,
                channel=_channel_digest(channel),
                params=values,
                preview=preview,
                result=None,
                created_at=now,
                deadline_at=now + timedelta(seconds=self._timeout),
                timeout_seconds=self._timeout,
            )
        )
        self._deadlines[record.id] = self._clock.monotonic() + self._timeout
        try:
            self._arm(record)
        except Exception as exc:
            self._store.delete_pending_change(record.id)
            self._deadlines.pop(record.id, None)
            raise ConfirmationError(
                f"the rollback timer could not be armed, so the change was not applied: {exc}",
                code="timer_unavailable",
            ) from exc
        try:
            result = handler.apply(record)
        except Exception as exc:
            self._roll_back(record, reason=f"applying failed: {exc}", at_start=False)
            raise
        record = self._store.set_pending_status(
            record.id, "awaiting", result=None if result is None else dict(result)
        )
        self._emit(
            _CHANGE_PENDING,
            actor=actor,
            data={
                "change_id": record.id,
                "kind": kind,
                "timeout_seconds": self._timeout,
                "deadline_at": utc_iso(record.deadline_at),
                "would_block": sum(1 for item in preview if item.get("outcome") == "block"),
                "preview": list(preview[:_MAX_PREVIEW_IN_AUDIT]),
            },
        )
        return record

    def confirm(self, change_id: str, *, actor: str, channel: str) -> PendingChangeRecord:
        """Keep a change. It must be awaiting confirmation, on its channel, in time.

        A confirmation that arrives after the deadline rolls the change back (if the
        tick has not already) and is refused.

        Raises:
            ConfirmationError: ``no_pending_change``, ``not_ready``, ``wrong_channel``,
                ``confirmation_expired``.
        """
        record = self._store.get_pending_change(change_id)
        if record is None:
            raise ConfirmationError(
                "there is no such change waiting for confirmation (it may have been rolled back)",
                code="no_pending_change",
            )
        if record.status != "awaiting":
            raise ConfirmationError("the change is still being applied", code="not_ready")
        if not secrets.compare_digest(record.channel, _channel_digest(channel)):
            raise ConfirmationError(
                "a change must be confirmed over the channel that made it", code="wrong_channel"
            )
        if self._clock.monotonic() >= self._deadline(record):
            self._roll_back(record, reason="the confirmation arrived too late", at_start=False)
            raise ConfirmationError(
                "the confirmation arrived after the deadline; the change was rolled back",
                code="confirmation_expired",
            )
        if not self._store.delete_pending_change(record.id):
            raise ConfirmationError("the change is no longer pending", code="no_pending_change")
        self._forget(record.id)
        self._emit(
            _CHANGE_CONFIRMED, actor=actor, data={"change_id": record.id, "kind": record.kind}
        )
        return record

    def cancel(self, change_id: str, *, actor: str, reason: str = "cancelled") -> bool:
        """Roll a pending change back now. Returns False if there was none."""
        record = self._store.get_pending_change(change_id)
        if record is None:
            return False
        _check_actor(actor)
        self._roll_back(record, reason=reason, at_start=False, actor=actor)
        return True

    def discard(self, change_id: str) -> None:
        """Stop tracking a change that ended by other means (its row is already gone).

        Cancels its backstop timer; nothing is reverted.
        """
        self._forget(change_id)

    def tick(self) -> list[str]:
        """Roll back every change whose deadline has passed. Returns their ids."""
        rolled: list[str] = []
        now = self._clock.monotonic()
        for record in self._store.pending_changes():
            if now >= self._deadline(record) and self._roll_back(
                record, reason="not confirmed in time", at_start=False
            ):
                rolled.append(record.id)
        return rolled

    def resume(self, *, kinds: Collection[str] | None = None) -> list[str]:
        """At start-up: roll back every change left pending by the previous run."""
        rolled: list[str] = []
        for record in self._store.pending_changes():
            if kinds is not None and record.kind not in kinds:
                continue
            if self._roll_back(
                record, reason="not confirmed before the service stopped", at_start=True
            ):
                rolled.append(record.id)
        return rolled

    def pending(self) -> list[PendingChangeRecord]:
        """Changes waiting for confirmation, oldest first."""
        return self._store.pending_changes()

    def remaining_seconds(self, change_id: str) -> int | None:
        """Whole seconds left to confirm ``change_id``, or ``None`` if it is not pending."""
        record = self._store.get_pending_change(change_id)
        if record is None:
            return None
        return max(0, math.ceil(self._deadline(record) - self._clock.monotonic()))

    # --- internals -------------------------------------------------------------------

    def _handler(self, kind: str) -> ChangeHandler:
        handler = self._handlers.get(kind)
        if handler is None:
            raise ConfirmationError(f"unknown change kind {kind!r}", code="unknown_change_kind")
        return handler

    def _deadline(self, record: PendingChangeRecord) -> float:
        deadline = self._deadlines.get(record.id)
        if deadline is None:
            # A change this process did not propose (it should have been rolled back at
            # start): trust its wall-clock deadline, never more than the full timeout.
            left = (record.deadline_at - self._clock.now()).total_seconds()
            deadline = self._clock.monotonic() + max(0.0, min(left, float(self._timeout)))
            self._deadlines[record.id] = deadline
        return deadline

    def _roll_back(
        self, record: PendingChangeRecord, *, reason: str, at_start: bool, actor: str = _SYSTEM
    ) -> bool:
        handler = self._handlers.get(record.kind)
        if handler is None:
            _LOG.error(
                "no handler for pending %s change %s; it cannot be reverted", record.kind, record.id
            )
            return False
        try:
            handler.revert(record, reason=reason, at_start=at_start)
        except Exception as exc:
            # Keep the record: the next tick (or start) tries again.
            _LOG.error("rolling back %s change %s failed", record.kind, record.id, exc_info=exc)
            return False
        self._store.delete_pending_change(record.id)
        self._forget(record.id)
        self._emit(
            _CHANGE_ROLLED_BACK,
            actor=actor,
            data={
                "change_id": record.id,
                "kind": record.kind,
                "reason": reason,
                "found_at_start": at_start,
            },
        )
        return True

    def _arm(self, record: PendingChangeRecord) -> None:
        if self._timer is None:
            return
        self._timer.arm(
            CONFIRM_TIMER_PREFIX + record.id,
            record.deadline_at + timedelta(seconds=_CONFIRM_TIMER_GRACE_SECONDS),
            self._argv,
        )

    def _forget(self, change_id: str) -> None:
        self._deadlines.pop(change_id, None)
        if self._timer is None:
            return
        try:
            self._timer.cancel(CONFIRM_TIMER_PREFIX + change_id)
        except Exception as exc:
            # A stray timer runs `portlock recover` later: harmless if nothing is
            # journaled by then, and logged so an operator can remove it.
            _LOG.error("cancelling the rollback timer of change %s failed", change_id, exc_info=exc)

    def _emit(self, event: str, *, actor: str, data: Mapping[str, Any]) -> None:
        _safe_audit(self._audit, event, actor=actor, data=dict(data))


# --- kill switch -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KillSwitchState:
    """What :meth:`KillSwitch.check` found.

    Attributes:
        present: the file exists (or its directory could not be read).
        honoured: it counts: present inside a directory verified to be private.
        reason: why a present file is not honoured; empty otherwise.
    """

    present: bool
    honoured: bool
    reason: str = ""


class KillSwitch:
    """The ``DISABLE_ENFORCEMENT`` file (``docs/DESIGN.md`` sections 11 and 14.18).

    The file is honoured only if ``privacy`` says its directory is private: in a
    directory anyone can write to, anyone could switch enforcement off. Inside a private
    directory, a file whose presence cannot be determined (the directory cannot be read)
    counts as present, so the switch fails towards releasing.

    Args:
        path: the kill-switch file (``PathsConfig.kill_switch_file``).
        privacy: the directory privacy check.
    """

    def __init__(self, path: str | os.PathLike[str], privacy: PrivacyCheck) -> None:
        if not callable(getattr(privacy, "check", None)):
            raise TypeError("privacy must have a check(path) method")
        self._path = Path(path)
        self._privacy = privacy

    @property
    def path(self) -> Path:
        return self._path

    def check(self) -> KillSwitchState:
        """Look for the file and decide whether it counts."""
        try:
            os.lstat(self._path)
            present = True
        except FileNotFoundError:
            present = False
        except OSError:
            present = True
        if not present:
            return KillSwitchState(present=False, honoured=False)
        problems: tuple[str, ...] = ()
        try:
            report = self._privacy.check(self._path.parent)
            private = getattr(report, "private", False) is True
            problems = tuple(str(item) for item in getattr(report, "problems", ()) or ())
        except Exception as exc:
            _LOG.error("the privacy check of %s failed", self._path.parent, exc_info=exc)
            private = False
        if not private:
            detail = f" ({'; '.join(problems[:3])})" if problems else ""
            return KillSwitchState(
                present=True,
                honoured=False,
                reason=f"ignored: its directory is not verified to be private{detail}",
            )
        return KillSwitchState(present=True, honoured=True)

    def is_set(self) -> bool:
        """True if the kill switch is present and honoured."""
        return self.check().honoured


# --- the lockdown manager ----------------------------------------------------------------


class _LockdownChange:
    """The commit-confirm handler through which a lockdown is engaged."""

    def __init__(self, manager: LockdownManager) -> None:
        self._manager = manager

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return [item.to_dict() for item in self._manager.plan()]

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None:
        return self._manager._apply_engage(change)

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None:
        self._manager._revert_engage(change, at_start=at_start)


class LockdownManager:
    """The persisted lockdown state machine with its dead-man timer.

    Args:
        store: holds the lockdown row, its history and the pending engage.
        clock: wall and monotonic time.
        config: ``Config.lockdown``.
        audit: records ``lockdown.*`` events.
        reconcile: the service's convergence; called with a trigger such as
            ``"lockdown.engaged"``, it blocks or releases devices to match :attr:`active`
            and returns what it did. It must apply default-deny while :attr:`active`.
        timer: the operating-system backstop (section 14.16).
        recover_argv: the command the timer runs at expiry (``portlock recover``).
        kill_switch: refuses engage while set.
        credentials: verifies the credential that :meth:`lift` requires.
        confirmations: the commit-confirm mechanism; the manager registers the
            ``lockdown`` change kind with it.
        devices: the currently connected devices, for the preview.
        protection: the safety verdict for a device (``SafeEnforcer.protection``).
        default_minutes: the run-time default duration (a setting may override the
            configuration); ``config.default_minutes`` if omitted.
        checkpoint_seconds: how often the time remaining is persisted while active.
    """

    def __init__(
        self,
        store: StateStore,
        *,
        clock: Clock,
        config: LockdownConfig,
        audit: AuditFn,
        reconcile: Callable[[str], ReconcileSummary],
        timer: ExternalTimer,
        recover_argv: Sequence[str],
        kill_switch: KillSwitch,
        credentials: CredentialCheck,
        confirmations: CommitConfirm,
        devices: Callable[[], Sequence[Connected]],
        protection: Callable[[UsbDevice], ProtectionLike],
        default_minutes: Callable[[], int] | None = None,
        checkpoint_seconds: int = _DEFAULT_CHECKPOINT_SECONDS,
    ) -> None:
        _check_timer(timer)
        _check_argv(recover_argv)
        if not callable(getattr(credentials, "verify", None)):
            raise TypeError("credentials must have a verify() method")
        if checkpoint_seconds < 1:
            raise ValueError("checkpoint_seconds must be at least 1")
        self._store = store
        self._clock = clock
        self._config = config
        self._audit = audit
        self._reconcile = reconcile
        self._timer = timer
        self._argv = tuple(recover_argv)
        self._kill_switch = kill_switch
        self._credentials = credentials
        self._confirmations = confirmations
        self._devices = devices
        self._protection = protection
        self._default_minutes = default_minutes or (lambda: config.default_minutes)
        self._checkpoint_seconds = checkpoint_seconds
        record = store.get_lockdown()
        self._state = LockdownState(record.state)
        self._engaged_at = record.engaged_at
        # A stored lockdown is not in force in this process until resume() has decided
        # what to do with it.
        self._resumed = self._state is LockdownState.IDLE
        self._deadline: float | None = None
        self._wall_ref = self._clock.now()
        self._mono_ref = self._clock.monotonic()
        self._last_checkpoint = self._mono_ref
        self._timer_ok = record.timer_armed
        # The end reason of a lift in progress in this process, for tick() to record if
        # the database refused it the first time.
        self._lift_reason = "expired"
        confirmations.register(CHANGE_LOCKDOWN, _LockdownChange(self))

    # --- reading ---------------------------------------------------------------------

    @property
    def state(self) -> LockdownState:
        return self._state

    @property
    def active(self) -> bool:
        """True while the lockdown is engaging or active in this process."""
        return self._resumed and self._state in (LockdownState.ENGAGING, LockdownState.ACTIVE)

    def status(self) -> LockdownStatus:
        """The lockdown as stored, with the time remaining by the monotonic clock."""
        record = self._store.get_lockdown()
        remaining: int | None = None
        if self.active and self._deadline is not None:
            remaining = max(0, math.ceil(self._deadline - self._clock.monotonic()))
        elif record.state != LockdownState.IDLE.value:
            remaining = record.remaining_seconds
        pending = self._store.pending_changes(kind=CHANGE_LOCKDOWN)
        change_id = pending[0].id if pending else None
        return LockdownStatus(
            state=LockdownState(record.state),
            active=self.active,
            engaged_at=record.engaged_at,
            engaged_by=record.engaged_by,
            reason=record.reason,
            expires_at=record.expires_at,
            remaining_seconds=remaining,
            renew_count=record.renew_count,
            default_minutes=self._safe_default_minutes(),
            max_minutes=self._config.max_minutes,
            pending_change_id=change_id,
            confirm_remaining_seconds=(
                None if change_id is None else self._confirmations.remaining_seconds(change_id)
            ),
            # A watch-only stand-in (``inert``) accepts the call but arms nothing, so it is
            # not reported as an operating-system timer.
            external_timer_armed=(
                record.timer_armed and self._timer_ok and not getattr(self._timer, "inert", False)
            ),
        )

    def plan(self, devices: Sequence[Connected] | None = None) -> list[PlanItem]:
        """What a lockdown does with each connected device (the commit-confirm preview).

        Protected devices are listed as ``protected`` and are never blocked by a
        lockdown, whatever else is true of them.
        """
        connected = list(self._devices() if devices is None else devices)
        engaged_at = self._engaged_at if self.active else None
        reference = engaged_at or self._clock.now()
        items: list[PlanItem] = []
        for item in connected:
            device = item.device
            verdict = self._protection(device)
            if verdict.protected:
                outcome: Literal["block", "protected", "exempt", "not_enforced"] = "protected"
                reason = "; ".join(verdict.reasons) or "protected by the safety layer"
            elif self._exempt(device, item.connected_at, reference):
                outcome, reason = "exempt", self._exempt_reason(device)
            elif not verdict.in_scope:
                outcome = "not_enforced"
                reason = "outside the enforcement scope; it is not blocked and not protected"
            else:
                outcome, reason = "block", "lockdown blocks removable storage and new devices"
            items.append(
                PlanItem(
                    instance_id=device.instance_id,
                    name=device.display_name,
                    vid_pid=device.vid_pid,
                    outcome=outcome,
                    reason=reason,
                )
            )
        return items

    def is_exempt(self, device: UsbDevice, *, connected_at: datetime) -> bool:
        """Whether an unprotected device is left alone by the active lockdown.

        Exempt: a device without storage that was connected before the lockdown began
        (lockdown blocks storage at once; it does not cut off a printer that was
        already there), and, if ``config.allow_new_input_devices``, a device that is an
        input device and nothing else. Every storage-like device and every other new
        device is held. A device that mixes input with another function is never exempt
        as an input device.
        """
        reference = self._engaged_at or self._clock.now()
        return self._exempt(device, connected_at, reference)

    # --- engage, renew, lift ---------------------------------------------------------

    def engage(
        self, *, actor: str, channel: str, minutes: int | None = None, reason: str = ""
    ) -> EngageResult:
        """Engage a lockdown under commit-confirm.

        Lists what would be blocked, applies the lockdown (state ``engaging``, the
        operating-system timer armed, devices reconciled, state ``active``) and returns
        it awaiting confirmation through :meth:`confirm` within the commit-confirm
        timeout; otherwise it is rolled back.

        Raises:
            LockdownError: ``killswitch_active``, ``lockdown_active``,
                ``invalid_duration``, ``invalid_reason``, ``in_transaction``.
            ConfirmationError: from the commit-confirm mechanism.
        """
        self._outside_transaction()
        _check_actor(actor)
        if self._kill_switch.is_set():
            raise LockdownError(
                "the kill switch is set; enforcement is disabled", code="killswitch_active"
            )
        duration = self._minutes(minutes)
        if not isinstance(reason, str) or len(reason) > _MAX_REASON or _has_control(reason):
            raise LockdownError(
                f"the reason must be at most {_MAX_REASON} printable characters",
                code="invalid_reason",
            )
        if self._store.get_lockdown().state != LockdownState.IDLE.value or not self._resumed:
            raise LockdownError("a lockdown is already in progress", code="lockdown_active")
        change = self._confirmations.propose(
            CHANGE_LOCKDOWN,
            actor=actor,
            channel=channel,
            params={"minutes": duration, "reason": reason},
        )
        summary = ReconcileSummary.from_dict((change.result or {}).get("summary", {}))
        return EngageResult(status=self.status(), change=change, summary=summary)

    def confirm(self, change_id: str, *, actor: str, channel: str) -> LockdownStatus:
        """Confirm an engaged lockdown so that it stays."""
        record = self._store.get_pending_change(change_id)
        if record is not None and record.kind != CHANGE_LOCKDOWN:
            raise ConfirmationError("that change is not a lockdown", code="no_pending_change")
        self._confirmations.confirm(change_id, actor=actor, channel=channel)
        return self.status()

    def renew(self, *, actor: str, minutes: int | None = None) -> LockdownStatus:
        """Restart the dead-man timer: the lockdown now ends ``minutes`` from now.

        The operating-system timer is cancelled and armed again for the new expiry.

        Raises:
            LockdownError: ``lockdown_not_active``, ``invalid_duration``.
        """
        self._outside_transaction()
        _check_actor(actor)
        duration = self._minutes(minutes)
        record = self._store.get_lockdown()
        if record.state != LockdownState.ACTIVE.value or not self.active:
            raise LockdownError("no lockdown is active", code="lockdown_not_active")
        now = self._clock.now()
        seconds = duration * 60
        expires = now + timedelta(seconds=seconds)
        record = self._store.save_lockdown(
            replace(
                record,
                minutes=duration,
                expires_at=expires,
                remaining_seconds=seconds,
                checkpoint_at=now,
                renewed_at=now,
                renew_count=record.renew_count + 1,
                timer_armed=True,
            ),
            expect={LockdownState.ACTIVE.value},
        )
        self._start_countdown(seconds)
        timer = self._rearm_timer(expires)
        self._emit(
            _LOCKDOWN_RENEWED,
            actor=actor,
            data={
                "expires_at": utc_iso(expires),
                "minutes": duration,
                "renew_count": record.renew_count,
                "external_timer": timer,
            },
        )
        return self.status()

    def lift(self, *, actor: str, credential: Credential) -> LiftResult:
        """Lift the lockdown. Needs the administrator password or a recovery code.

        Steps: verify the credential; persist ``lifting`` (from then on :attr:`active`
        is False); reconcile, which releases; cancel the operating-system timer; persist
        ``idle`` with a history row; audit ``lockdown.lifted``.

        Raises:
            LockdownError: ``lockdown_not_active``, ``in_transaction``.
            AuthError: ``reauthentication_failed``.
        """
        self._outside_transaction()
        _check_actor(actor)
        record = self._store.get_lockdown()
        if record.state not in (LockdownState.ACTIVE.value, LockdownState.ENGAGING.value):
            raise LockdownError("no lockdown is active", code="lockdown_not_active")
        if not self._verify(actor, credential):
            raise AuthError(
                "the password or recovery code was not accepted", code="reauthentication_failed"
            )
        summary = self._lift(end_reason="lifted", actor=actor)
        return LiftResult(status=self.status(), summary=summary)

    # --- timer, start-up, kill switch ------------------------------------------------

    def tick(self) -> None:
        """The dead-man timer. Called about once a second by the service.

        Lifts the lockdown with ``expired`` once the monotonic deadline passes; the
        wall clock is not consulted for that, so setting it back or forward cannot
        stretch or cut a lockdown within one run. A wall clock that has moved re-arms the
        operating-system timer for the true expiry. Persists the time remaining every
        ``checkpoint_seconds``. Completes a lift that an earlier failure left half done.
        """
        if not self._resumed:
            return
        if self._state is LockdownState.LIFTING:
            self._complete_lift()
            return
        if not self.active or self._deadline is None:
            return
        mono = self._clock.monotonic()
        remaining = self._deadline - mono
        if remaining <= 0:
            try:
                self._lift(end_reason="expired", actor=_SYSTEM, tolerate_store_errors=True)
            except Exception as exc:
                # State stays LIFTING in memory; the next tick tries again.
                _LOG.error("lifting the expired lockdown failed", exc_info=exc)
            return
        now = self._clock.now()
        drift = (now - self._wall_ref).total_seconds() - (mono - self._mono_ref)
        if abs(drift) > _CLOCK_TOLERANCE_SECONDS:
            _LOG.warning("the wall clock moved by %d s; re-arming the lockdown timer", int(drift))
            self._checkpoint(now, remaining, move_expiry=True)
            self._rearm_timer(now + timedelta(seconds=remaining))
            return
        if not self._timer_ok:
            self._rearm_timer(now + timedelta(seconds=remaining))
        if mono - self._last_checkpoint >= self._checkpoint_seconds:
            self._checkpoint(now, remaining, move_expiry=False)

    def resume(self, *, recovered_at: datetime | None = None) -> str:
        """Decide, once at service start and before devices are evaluated, what a stored
        lockdown means now.

        An engage left unconfirmed by the previous run is rolled back first. Then:
        ``idle`` stays idle (a timer that may still be armed is cancelled);
        ``lifting`` is ``lift_pending``; ``engaging`` or ``active`` resumes with the time
        remaining (``resumed``) unless it has expired, the stored remainder is impossible
        (``clock_anomaly``), or ``portlock recover`` ran after it was engaged
        (``recovered``), each of which becomes ``lifting`` and returns ``lift_pending``.

        The remainder is the persisted time remaining less the wall-clock time since it
        was persisted. A wall clock set back while the service was stopped cannot
        lengthen a lockdown beyond what was persisted; one set forward can only shorten
        it, the direction that never locks the operator out.

        After ``lift_pending`` the service reconciles (which releases, because
        :attr:`active` is False) and then calls :meth:`finish_lift`.
        """
        self._confirmations.resume(kinds={CHANGE_LOCKDOWN})
        record = self._store.get_lockdown()
        self._resumed = True
        self._engaged_at = record.engaged_at
        now = self._clock.now()
        if record.state == LockdownState.IDLE.value:
            self._state = LockdownState.IDLE
            if record.timer_armed:
                self._store.save_lockdown(
                    replace(record, timer_armed=not self._cancel_timer()),
                    expect={LockdownState.IDLE.value},
                )
            return "idle"
        if record.state == LockdownState.LIFTING.value:
            self._state = LockdownState.LIFTING
            return "lift_pending"
        if (
            recovered_at is not None
            and record.engaged_at is not None
            and recovered_at >= record.engaged_at
        ):
            return self._begin_lift_at_start(record, "recovered")
        remaining = self._remaining_at_start(record, now)
        if remaining is None:
            return self._begin_lift_at_start(record, "clock_anomaly")
        if remaining <= 0:
            return self._begin_lift_at_start(record, "expired")
        expires = now + timedelta(seconds=remaining)
        self._store.save_lockdown(
            replace(
                record,
                state=LockdownState.ACTIVE.value,
                expires_at=expires,
                remaining_seconds=int(remaining),
                checkpoint_at=now,
                timer_armed=True,
            ),
            expect={LockdownState.ENGAGING.value, LockdownState.ACTIVE.value},
        )
        self._state = LockdownState.ACTIVE
        self._start_countdown(remaining)
        self._rearm_timer(expires)
        return "resumed"

    def finish_lift(self, summary: ReconcileSummary | None = None) -> None:
        """Complete a ``lifting`` state found at start, after the service reconciled.

        Raises:
            LockdownError: ``not_lifting``.
        """
        if self._store.get_lockdown().state != LockdownState.LIFTING.value:
            raise LockdownError("no lift is in progress", code="not_lifting")
        self._state = LockdownState.LIFTING
        timer_cancelled = self._cancel_timer()
        self._finish(summary, found_at_start=True, timer_cancelled=timer_cancelled)

    def force_idle(self, *, end_reason: str = "killswitch", actor: str = _SYSTEM) -> None:
        """Return to idle without reconciling: the kill switch's rollback releases.

        Cancels the timers; writes the history row. No-op when idle.
        """
        record = self._store.get_lockdown()
        if record.state == LockdownState.IDLE.value:
            return
        pending = [change.id for change in self._store.pending_changes(kind=CHANGE_LOCKDOWN)]
        cancelled = self._cancel_timer()
        self._store.save_lockdown(
            LockdownRecord(state=LockdownState.IDLE.value, timer_armed=not cancelled),
            history_end=(self._clock.now(), actor, end_reason),
            delete_change=pending[0] if pending else None,
        )
        for change_id in pending:
            self._confirmations.discard(change_id)
        self._state = LockdownState.IDLE
        self._engaged_at = None
        self._deadline = None

    # --- internals: engage -----------------------------------------------------------

    def _apply_engage(self, change: PendingChangeRecord) -> Mapping[str, Any]:
        duration = int(change.params["minutes"])
        reason = str(change.params.get("reason", ""))
        now = self._clock.now()
        seconds = duration * 60
        expires = now + timedelta(seconds=seconds)
        record = self._store.save_lockdown(
            LockdownRecord(
                state=LockdownState.ENGAGING.value,
                engaged_at=now,
                engaged_by=change.actor,
                reason=reason,
                minutes=duration,
                expires_at=expires,
                remaining_seconds=seconds,
                checkpoint_at=now,
                change_id=change.id,
                # Written before the timer is armed: a crash in between leaves a record
                # that says a timer may exist, so it is cancelled later, never orphaned.
                timer_armed=True,
            ),
            expect={LockdownState.IDLE.value},
        )
        self._state = LockdownState.ENGAGING
        self._engaged_at = now
        self._start_countdown(seconds)
        # The out-of-process safety exists before anything is restricted. If it cannot
        # be armed, the engage fails and commit-confirm rolls it back.
        self._timer.arm(LOCKDOWN_TIMER, _timer_time(expires), self._argv)
        self._timer_ok = True
        summary = self._call_reconcile("lockdown.engaged")
        self._store.save_lockdown(
            replace(record, state=LockdownState.ACTIVE.value),
            expect={LockdownState.ENGAGING.value},
        )
        self._state = LockdownState.ACTIVE
        self._emit(
            _LOCKDOWN_ENGAGED,
            actor=change.actor,
            data={
                "expires_at": utc_iso(expires),
                "minutes": duration,
                "reason": reason,
                "renew_count": 0,
                "change_id": change.id,
                "confirm_seconds": change.timeout_seconds,
                "summary": summary.to_dict(),
            },
        )
        return {"summary": summary.to_dict(), "expires_at": utc_iso(expires)}

    def _revert_engage(self, change: PendingChangeRecord, *, at_start: bool) -> None:
        record = self._store.get_lockdown()
        if record.state == LockdownState.IDLE.value:
            self._state = LockdownState.IDLE
            return
        if at_start:
            self._begin_lift_at_start(record, "unconfirmed", delete_change=change.id)
            return
        self._lift(end_reason="unconfirmed", actor=_SYSTEM)

    # --- internals: lift -------------------------------------------------------------

    def _lift(
        self, *, end_reason: str, actor: str, tolerate_store_errors: bool = False
    ) -> ReconcileSummary | None:
        pending: list[str] = []
        self._lift_reason = end_reason
        try:
            pending = [change.id for change in self._store.pending_changes(kind=CHANGE_LOCKDOWN)]
            record = self._store.get_lockdown()
            self._store.save_lockdown(
                replace(
                    record, state=LockdownState.LIFTING.value, end_reason=end_reason, ended_by=actor
                ),
                expect={
                    LockdownState.ENGAGING.value,
                    LockdownState.ACTIVE.value,
                    LockdownState.LIFTING.value,
                },
                delete_change=pending[0] if pending else None,
            )
        except StoreError:
            if not tolerate_store_errors:
                raise
            # The dead-man timer does not depend on the database: release anyway. The
            # next start finds the stored lockdown expired and completes the record.
            _LOG.error("the lockdown state could not be written; lifting regardless", exc_info=True)
        self._state = LockdownState.LIFTING
        self._deadline = None
        for change_id in pending:
            self._confirmations.discard(change_id)
        summary = self._call_reconcile("lockdown." + end_reason)
        timer_cancelled = self._cancel_timer()
        try:
            self._finish(summary, found_at_start=False, timer_cancelled=timer_cancelled)
        except StoreError:
            if not tolerate_store_errors:
                raise
            _LOG.error("the end of the lockdown could not be recorded", exc_info=True)
        return summary

    def _complete_lift(self) -> None:
        """Finish a lift that an earlier failure left half done (called from tick)."""
        try:
            record = self._store.get_lockdown()
            if record.state in (LockdownState.ENGAGING.value, LockdownState.ACTIVE.value):
                # The database refused the "lifting" write earlier; record it now.
                record = self._store.save_lockdown(
                    replace(
                        record,
                        state=LockdownState.LIFTING.value,
                        end_reason=self._lift_reason,
                        ended_by=_SYSTEM,
                    ),
                    expect={LockdownState.ENGAGING.value, LockdownState.ACTIVE.value},
                )
            if record.state != LockdownState.LIFTING.value:
                self._state = LockdownState(record.state)
                return
            summary = self._call_reconcile("lockdown." + (record.end_reason or "lifted"))
            self._finish(summary, found_at_start=False, timer_cancelled=self._cancel_timer())
        except Exception as exc:
            _LOG.error("completing the lockdown lift failed; retrying later", exc_info=exc)

    def _finish(
        self, summary: ReconcileSummary | None, *, found_at_start: bool, timer_cancelled: bool
    ) -> None:
        record = self._store.get_lockdown()
        if record.state != LockdownState.LIFTING.value:
            # Either already finished, or the "lifting" write failed: in-memory state
            # stays LIFTING (never back to active) and tick() completes the record.
            if record.state == LockdownState.IDLE.value:
                self._state = LockdownState.IDLE
            return
        end_reason = record.end_reason or "lifted"
        ended_by = record.ended_by or _SYSTEM
        now = self._clock.now()
        self._store.save_lockdown(
            LockdownRecord(state=LockdownState.IDLE.value, timer_armed=not timer_cancelled),
            expect={LockdownState.LIFTING.value},
            history_end=(now, ended_by, end_reason),
        )
        self._state = LockdownState.IDLE
        self._engaged_at = None
        self._deadline = None
        event = (
            _LOCKDOWN_EXPIRED if end_reason in ("expired", "clock_anomaly") else _LOCKDOWN_LIFTED
        )
        self._emit(
            event,
            actor=ended_by,
            data={
                "end_reason": end_reason,
                "engaged_at": _iso(record.engaged_at),
                "engaged_by": record.engaged_by,
                "expires_at": _iso(record.expires_at),
                "renew_count": record.renew_count,
                "found_at_start": found_at_start,
                "summary": None if summary is None else summary.to_dict(),
                "external_timer_cancelled": timer_cancelled,
            },
        )

    def _begin_lift_at_start(
        self, record: LockdownRecord, end_reason: str, *, delete_change: str | None = None
    ) -> str:
        self._store.save_lockdown(
            replace(
                record, state=LockdownState.LIFTING.value, end_reason=end_reason, ended_by=_SYSTEM
            ),
            delete_change=delete_change,
        )
        self._state = LockdownState.LIFTING
        self._deadline = None
        return "lift_pending"

    def _remaining_at_start(self, record: LockdownRecord, now: datetime) -> float | None:
        """Seconds left for a stored lockdown, or ``None`` if the stored value is impossible."""
        limit = self._config.max_minutes * 60
        persisted = record.remaining_seconds
        since = record.checkpoint_at or record.engaged_at
        if persisted is None or since is None:
            if record.expires_at is None:
                return None
            persisted, since = int((record.expires_at - now).total_seconds()), now
        if persisted > limit or persisted < 0:
            return None
        elapsed = max(0.0, (now - since).total_seconds())
        return float(persisted) - elapsed

    # --- internals: the countdown and the timer --------------------------------------

    def _start_countdown(self, seconds: float) -> None:
        mono = self._clock.monotonic()
        self._deadline = mono + seconds
        self._wall_ref = self._clock.now()
        self._mono_ref = mono
        self._last_checkpoint = mono

    def _checkpoint(self, now: datetime, remaining: float, *, move_expiry: bool) -> None:
        try:
            record = self._store.get_lockdown()
            changes: dict[str, Any] = {"remaining_seconds": int(remaining), "checkpoint_at": now}
            if move_expiry:
                changes["expires_at"] = now + timedelta(seconds=remaining)
            self._store.save_lockdown(
                replace(record, **changes),
                expect={LockdownState.ACTIVE.value, LockdownState.ENGAGING.value},
            )
        except StoreError:
            # The countdown runs in memory regardless; only a restart would lose time.
            _LOG.error("could not persist the lockdown time remaining", exc_info=True)
        mono = self._clock.monotonic()
        self._last_checkpoint = mono
        if move_expiry:
            self._wall_ref = now
            self._mono_ref = mono

    def _rearm_timer(self, expires: datetime) -> str:
        """Cancel and arm the lockdown timer. Returns ``armed`` or why it failed."""
        try:
            self._timer.cancel(LOCKDOWN_TIMER)
            self._timer.arm(LOCKDOWN_TIMER, _timer_time(expires), self._argv)
        except Exception as exc:
            # The lockdown stays in force and the in-process countdown still ends it;
            # tick() retries arming until it succeeds.
            self._timer_ok = False
            _LOG.error("the lockdown timer could not be armed", exc_info=exc)
            return f"failed: {type(exc).__name__}: {exc}"
        self._timer_ok = True
        return "armed"

    def _cancel_timer(self) -> bool:
        try:
            self._timer.cancel(LOCKDOWN_TIMER)
        except Exception as exc:
            _LOG.error("the lockdown timer could not be cancelled", exc_info=exc)
            return False
        self._timer_ok = False
        return True

    # --- internals: helpers ----------------------------------------------------------

    def _exempt(self, device: UsbDevice, connected_at: datetime, reference: datetime) -> bool:
        if device.is_storage_like:
            return False
        if connected_at < reference:
            return True
        return self._config.allow_new_input_devices and device.is_input_only

    def _exempt_reason(self, device: UsbDevice) -> str:
        if device.is_input_only and self._config.allow_new_input_devices:
            return "an input device, and new input devices are allowed during lockdown"
        return "not storage, and connected before the lockdown began"

    def _call_reconcile(self, trigger: str) -> ReconcileSummary:
        self._outside_transaction()
        summary = self._reconcile(trigger)
        if not isinstance(summary, ReconcileSummary):
            raise TypeError("reconcile must return a ReconcileSummary")
        return summary

    def _verify(self, actor: str, credential: Credential) -> bool:
        if not isinstance(credential, Credential) or not credential.secret:
            return False
        try:
            return self._credentials.verify(actor, credential) is True
        except Exception as exc:
            # A verifier that cannot answer has not said yes.
            _LOG.error("credential verification failed", exc_info=exc)
            return False

    def _minutes(self, minutes: int | None) -> int:
        value = self._safe_default_minutes() if minutes is None else minutes
        if isinstance(value, bool) or not isinstance(value, int):
            raise LockdownError("minutes must be an integer", code="invalid_duration")
        if not 1 <= value <= self._config.max_minutes:
            raise LockdownError(
                f"minutes must be between 1 and {self._config.max_minutes}",
                code="invalid_duration",
            )
        return value

    def _safe_default_minutes(self) -> int:
        try:
            value = self._default_minutes()
        except Exception:
            value = self._config.default_minutes
        if isinstance(value, bool) or not isinstance(value, int):
            return self._config.default_minutes
        return max(1, min(value, self._config.max_minutes))

    def _outside_transaction(self) -> None:
        if self._store.db.in_transaction:
            raise LockdownError(
                "lockdown operations must not run inside a database transaction",
                code="in_transaction",
            )

    def _emit(self, event: str, *, actor: str, data: Mapping[str, Any]) -> None:
        _safe_audit(self._audit, event, actor=actor, data=dict(data))


# --- rollback and recover ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RollbackReport:
    """What :func:`rollback` put back.

    Attributes:
        restored: journal entries restored (or found already at their baseline).
        released: holds released or closed.
        readmitted: devices admitted after default-deny was turned off.
        failed: ``(journal record id, error)`` for each entry that stays open.
        remaining: open records left in the journal.
    """

    reason: str
    restored: int
    released: int
    readmitted: int
    failed: tuple[tuple[str, str], ...]
    remaining: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "restored": self.restored,
            "released": self.released,
            "readmitted": self.readmitted,
            "failed": [list(item) for item in self.failed],
            "remaining": self.remaining,
        }


def rollback(
    journal: RecoveryJournal,
    enforcer: Enforcer,
    devices: Sequence[UsbDevice],
    *,
    reason: str,
    readmit: Collection[str] | None = None,
) -> RollbackReport:
    """Put every journaled setting back, newest first. Never raises.

    1. Every open record that is not a hold is restored, one entry per call; when the
       restore was performed it is closed, otherwise it stays open and is reported.
    2. Every hold is released by unblocking its device if present, and closed (an
       absent device's hold went with it). A record is closed only on a result that was
       really performed (``EnforcementResult.performed``): a dry-run or watch-only
       stand-in changes nothing, so its "ok" never closes a record.
    3. If default-deny was journaled, the present devices are unblocked, hubs first
       (nothing behind an unauthorized hub can enumerate, so a dock is admitted before
       the keyboard plugged into it): a device that arrived under default-deny while
       nothing was watching has no record of its own. ``readmit`` limits this to the
       instance ids it names; a caller that knows which devices default-deny held back
       passes them, so that a device someone else disabled stays as they left it.
       ``None`` (``portlock recover`` without a service, which knows nothing about
       any device) admits every present device.

    It never calls a restricting method. ``enforcer`` must be the live
    ``SafeEnforcer``; its ``restore`` validates every entry before writing. Every call is
    made inside a journal recording, because an enforcer wired to the journal's
    write-ahead hook (as every real one is) refuses to write outside one.
    """
    restored = released = readmitted = 0
    failed: list[tuple[str, str]] = []
    try:
        records = journal.open_records()
    except Exception as exc:
        return RollbackReport(reason, 0, 0, 0, (("journal", f"{type(exc).__name__}: {exc}"),), 0)
    default_deny = any(record.action is Action.DEFAULT_DENY_ON for record in records)
    by_instance = {device.instance_id: device for device in devices}

    def releasing(
        scope: str, action: Action, call: Callable[[], EnforcementResult]
    ) -> EnforcementResult:
        # A releasing action never opens a baseline over an existing value, so this
        # records nothing new; it closes whatever the call returned to its baseline.
        with journal.recording(scope=scope, action=action, fingerprint=None):
            result = call()
            journal.record(result)
        return result

    for record in records:
        if record.entry is None:
            continue
        try:
            result = releasing(
                record.scope, Action.RESTORE, functools.partial(enforcer.restore, [record.entry])
            )
            if result.performed:
                journal.close([record.id], reason=reason)
                restored += 1
            else:
                failed.append((record.id, result.error or "restore failed"))
        except Exception as exc:
            failed.append((record.id, f"{type(exc).__name__}: {exc}"))
    for record in records:
        if record.entry is not None:
            continue
        try:
            device = by_instance.get(record.scope)
            if device is None:
                journal.close([record.id], reason=f"{reason}: device absent")
                released += 1
                continue
            result = releasing(
                device.instance_id, Action.UNBLOCK, functools.partial(enforcer.unblock, device)
            )
            if result.performed:
                journal.close([record.id], reason=reason)
                released += 1
            else:
                # A stand-in (dry-run, watch-only) "succeeds" without unblocking anything:
                # the device is still held, so the hold stays open.
                failed.append((record.id, result.error or f"not unblocked ({result.mechanism})"))
        except Exception as exc:
            failed.append((record.id, f"{type(exc).__name__}: {exc}"))
    if default_deny:
        wanted = None if readmit is None else frozenset(readmit)
        candidates = [d for d in devices if wanted is None or d.instance_id in wanted]
        for device in sorted(candidates, key=lambda item: not item.is_hub):
            try:
                result = releasing(
                    device.instance_id, Action.UNBLOCK, functools.partial(enforcer.unblock, device)
                )
            except Exception as exc:
                failed.append((device.instance_id, f"{type(exc).__name__}: {exc}"))
                continue
            if result.ok and result.changed:
                readmitted += 1
            elif not result.ok:
                failed.append((device.instance_id, result.error or "unblock failed"))
    remaining = 0
    try:
        journal.compact()
        remaining = len(journal.open_records())
    except Exception as exc:
        _LOG.error("journal compaction after rollback failed", exc_info=exc)
        with contextlib.suppress(Exception):
            remaining = len(journal.open_records())
    return RollbackReport(reason, restored, released, readmitted, tuple(failed), remaining)


def recover(
    state_dir: str | os.PathLike[str],
    enforcer: Enforcer,
    devices: Sequence[UsbDevice],
    *,
    clock: Clock,
    is_admin: Callable[[], bool],
    timer: ExternalTimer | None = None,
    reason: str = "recover",
) -> RollbackReport:
    """``portlock recover``: restore every journaled setting, without the service.

    Reads only the journal file in ``state_dir``: no database, no PortLock account, no
    password. The authority is operating-system administrator rights, which
    ``is_admin`` must confirm. Cancels the lockdown timer if one is given (when the
    timer itself runs this, its one shot is spent anyway), and leaves
    :data:`RECOVER_MARKER` for the next service start to audit and to end the lockdown
    the database still describes.

    Raises:
        NotPrivilegedError: if ``is_admin`` does not return True.
    """
    try:
        admin = is_admin() is True
    except Exception:
        admin = False
    if not admin:
        raise NotPrivilegedError("portlock recover needs operating-system administrator rights")
    directory = Path(state_dir)
    journal = RecoveryJournal(directory / JOURNAL_FILE_NAME, clock=clock)
    report = rollback(journal, enforcer, devices, reason=reason)
    if timer is not None:
        try:
            timer.cancel(LOCKDOWN_TIMER)
        except Exception as exc:
            _LOG.error("the lockdown timer could not be cancelled", exc_info=exc)
    try:
        write_recover_marker(directory, report, at=clock.now())
    except OSError as exc:
        _LOG.error("the recover marker could not be written", exc_info=exc)
    return report


def write_recover_marker(
    state_dir: str | os.PathLike[str], report: RollbackReport, *, at: datetime
) -> None:
    """Leave the result of ``portlock recover`` for the next start (atomically, owner-only)."""
    data = json.dumps(
        {"actor": _LOCAL_CONSOLE, "at": utc_iso(at), "report": report.to_dict()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    target = Path(state_dir) / RECOVER_MARKER
    handle, temp_name = tempfile.mkstemp(dir=target.parent, prefix=".recover.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        with contextlib.suppress(OSError):
            os.chmod(temp_name, 0o600)
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def consume_recover_marker(state_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Read and delete the recover marker. ``None`` if there is none.

    A marker that cannot be parsed is still deleted, and reported as
    ``{"invalid": True}`` so the start-up audit can say so.
    """
    target = Path(state_dir) / RECOVER_MARKER
    try:
        raw = target.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        _LOG.error("the recover marker cannot be read", exc_info=exc)
        return {"invalid": True}
    with contextlib.suppress(OSError):
        target.unlink()
    try:
        data = json.loads(raw.decode("utf-8")) if len(raw) <= 65536 else None
        if not isinstance(data, dict) or not isinstance(data.get("report"), dict):
            raise ValueError("not a recover marker")
        at = parse_utc_iso(data["at"])
    except (ValueError, UnicodeDecodeError, KeyError, TypeError):
        return {"invalid": True}
    return {"actor": _LOCAL_CONSOLE, "at": at, "report": data["report"]}


# --- small helpers -----------------------------------------------------------------------


def _timer_time(expires: datetime) -> datetime:
    """When the operating-system timer fires for a lockdown that ends at ``expires``."""
    return expires + timedelta(seconds=_LOCKDOWN_TIMER_GRACE_SECONDS)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else utc_iso(value)


def _has_control(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def _check_actor(actor: Any) -> None:
    if not isinstance(actor, str) or not actor or len(actor) > 128 or _has_control(actor):
        raise ValueError("actor must be a non-empty printable string of at most 128 characters")


def _check_timer(timer: Any) -> None:
    for method in ("arm", "cancel"):
        if not callable(getattr(timer, method, None)):
            raise TypeError(f"the timer must have an {method}() method")


def _check_argv(argv: Sequence[str]) -> None:
    if (
        isinstance(argv, str)
        or not argv
        or not all(isinstance(part, str) and part and "\x00" not in part for part in argv)
    ):
        raise ValueError("recover_argv must be a non-empty sequence of non-empty strings")


def _channel_digest(channel: str) -> str:
    return hashlib.sha256(channel.encode("utf-8")).hexdigest()


def _change_dict(change: PendingChangeRecord) -> dict[str, Any]:
    return {
        "id": change.id,
        "kind": change.kind,
        "status": change.status,
        "actor": change.actor,
        "created_at": utc_iso(change.created_at),
        "deadline_at": utc_iso(change.deadline_at),
        "timeout_seconds": change.timeout_seconds,
        "preview": [dict(item) for item in change.preview],
    }


def _safe_audit(audit: AuditFn, event: str, *, actor: str, data: dict[str, Any]) -> None:
    # A failure to audit never undoes or blocks a safety action (DESIGN 14.10).
    try:
        audit(event, actor=actor, data=data)
    except Exception as exc:
        _LOG.error("auditing %s failed", event, exc_info=exc)
