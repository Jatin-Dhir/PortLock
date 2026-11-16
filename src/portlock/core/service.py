"""The PortLock pipeline: detect, decide, journal, enforce, audit.

:class:`PortLockService` runs ``docs/DESIGN.md`` section 5 as amended by section 14
(``docs/ARCHITECTURE.md`` 3.6). It turns device events, time and operator actions into
decisions, makes the operating system match them through the safety choke point, and
audits every step.

How the pieces fit:

* **One lock (L1).** Every method that evaluates, enforces or changes lockdown, mode,
  policy or settings holds ``self._lock``. Enforcer calls are made holding L1 and
  nothing else (never inside a database transaction). Read methods take no L1: they
  read the store and an immutable snapshot.
* **In-memory connections are authoritative.** Each connected device is a ``_Conn``
  kept in memory and mirrored to the store. A store that fails never stops a device
  from being decided and enforced (section 14.10): its row is simply missing and the
  status shows ``store`` degraded.
* **Order.** For every evaluation: decide, journal (the enforcer's write-ahead hook),
  enforce, then store and audit. A failure to store or audit never skips enforcement.
* **Convergence.** The service computes what the operating system should be doing
  (open, read-only or blocked) from the decision, the mode, lockdown and the kill switch,
  and makes it so with idempotent calls. It only releases what it restricted itself:
  the journal says what that is.
* **Time.** Expiries (grants, rules, time windows) are evaluated against the later of
  the clock and the newest audit record, so setting the clock back revives nothing
  (section 14.12); the discrepancy is audited as ``clock.rollback_detected``.

Nothing here talks to the operating system directly: the backend, the enforcer, the
dead-man timer and the directory-privacy check are injected.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import queue
import secrets
import sys
import threading
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Generic, Protocol, TypeVar

from portlock import __version__
from portlock.audit import events as ev
from portlock.audit.events import REGISTRY, AuditError
from portlock.audit.log import AuditLog, AuditRecord, VerifyResult
from portlock.auth.grants import Grant, GrantError, GrantKind, GrantStore, connection_key
from portlock.core.clock import Clock, utc_iso
from portlock.core.config import SCOPES, Config
from portlock.core.errors import (
    BackendError,
    EnforcementError,
    PolicyError,
    PortLockError,
    StoreError,
)
from portlock.core.events import EventBus
from portlock.core.fingerprint import fingerprint as compute_fingerprint
from portlock.core.fingerprint import storage_identity
from portlock.core.models import (
    Access,
    Confidence,
    Decision,
    DecisionSource,
    DeviceEvent,
    DeviceEventType,
    Fingerprint,
    Mode,
    ScanRequirement,
    Severity,
    UsbDevice,
)
from portlock.core.store import (
    GLOBAL_SCOPE,
    VOLATILE_KINDS,
    ConnectionRecord,
    ConnectionState,
    DecisionRecord,
    DeviceRecord,
    EnrolmentRecord,
    Outcome,
    PendingChangeRecord,
    RecoveryJournal,
    ScanRecord,
    ScanState,
    StateStore,
)
from portlock.guard.base import Action, DeviceBackend, EnforcementResult, Enforcer, Tier
from portlock.guard.safety import (
    CODE_CLONE,
    CODE_ENROLLED,
    MECHANISM_DRY_RUN,
    MECHANISM_OUT_OF_SCOPE,
    MECHANISM_REFUSED,
    PortFlapGuard,
    ProtectionVerdict,
    SafeEnforcer,
    SafetyContext,
    detect_clone,
    is_protected,
)
from portlock.lockdown.manager import (
    CHANGE_DEFAULT_DENY,
    CHANGE_ENFORCE_MODE,
    CHANGE_LOCKDOWN,
    CHANGE_WIDEN_SCOPE,
    CommitConfirm,
    Credential,
    CredentialCheck,
    EngageResult,
    ExternalTimer,
    KillSwitch,
    LiftResult,
    LockdownManager,
    LockdownState,
    LockdownStatus,
    PrivacyReportLike,
    ReconcileSummary,
    RollbackReport,
    consume_recover_marker,
    rollback,
)
from portlock.policy import (
    DEFAULT_POLICY,
    IncompleteAction,
    Policy,
    PolicyEngine,
    PolicyResult,
    RuleTrace,
    ScanDetection,
    ScanPolicy,
    ScanVerdict,
    decide,
    load_policy_file,
    parse_policy,
    policy_hash,
    policy_to_dict,
    save_policy,
    scan_detection_for,
)
from portlock.scan.report import FindingSeverity, ScanReport

__all__ = [
    "Applied",
    "AuditWriter",
    "ConnectionView",
    "DecisionView",
    "DefaultDenyView",
    "DeviceDetail",
    "DeviceView",
    "DirPrivacyLike",
    "DoctorLike",
    "EnforcementView",
    "ModeInfo",
    "PolicyInfo",
    "PolicyTest",
    "PortLockService",
    "ScanView",
    "ScannerLike",
    "ServiceCheck",
    "ServiceError",
    "ServiceStatus",
    "SettingsView",
]

_LOG = logging.getLogger(__name__)

T = TypeVar("T")

# Operating-system states a connection can be in, as PortLock made or left it.
_OPEN = "open"
_READ_ONLY = "read_only"
_BLOCKED = "blocked"

_SYSTEM = "system"
_LOCAL_CONSOLE = "local-console"
_EVENT_QUEUE_SIZE = 1000
_SCAN_QUEUE_SIZE = 16
_RESYNC_SECONDS = 30
_PERIODIC_SECONDS = 60
_EXTERNAL_CHECK_SECONDS = 5
_SCAN_GRACE_SECONDS = 30
_MAX_ABANDONED_SCANS = 4
_MAX_DETECTIONS_AUDITED = 50
_MAX_PROBLEMS_AUDITED = 50
_TAIL_VERIFY_RECORDS = 256
_CLOCK_TOLERANCE_SECONDS = 1
_MOUNT_TEXT_LIMIT = 256
_MAX_NOTE = 512
_ENUMERATE_ATTEMPTS = 3
# Triggers after which a connection is converged even when nothing seems to have
# changed: the device or the machine is new to this run, or a failure is being retried.
_ALWAYS_CONVERGE = frozenset({"arrival", "start", "retry", "changed", "killswitch"})
# Narrowest first; moving right widens what can be enforced (DESIGN 14.5, 14.15).
_SCOPE_ORDER = {scope: index for index, scope in enumerate(SCOPES)}
_VERDICT_RANK = {
    ScanVerdict.CLEAN: 0,
    ScanVerdict.INCOMPLETE: 1,
    ScanVerdict.ERROR: 2,
    ScanVerdict.SUSPICIOUS: 3,
    ScanVerdict.MALICIOUS: 4,
}
_NOT_ENFORCED = frozenset({Outcome.FAILED, Outcome.UNSUPPORTED, Outcome.REFUSED})
_RELEASES = frozenset({Action.UNBLOCK, Action.READ_WRITE, Action.RESTORE})
# Pending changes that would make PortLock block something: refused in watch-only.
_ENFORCING_CHANGES = frozenset({CHANGE_ENFORCE_MODE, CHANGE_DEFAULT_DENY, CHANGE_LOCKDOWN})
# Said in the status and the doctor of a watch-only process (``service.daemon`` builds its
# scanner without the antivirus engines, which would start programs).
_NO_ANTIVIRUS_NOTE = (
    "Antivirus engines are not used in watch-only: ClamAV and Microsoft Defender would "
    "start programs, so files are checked only by PortLock's own heuristics and hash lists."
)
# Said wherever default-deny is reported in a watch-only process that finds it stored on.
_STORED_DEFAULT_DENY_IGNORED = (
    "A default-deny setting stored by an earlier run is ignored: this process is watch-only "
    "and denies nothing."
)
# Said wherever default-deny is reported stored on but not in force in a process that is
# not watch-only: the choice is kept and applies again once it can.
_STORED_DEFAULT_DENY_MONITOR = (
    "Default-deny is stored on but not in force: it applies only in enforce mode, and "
    "PortLock is in monitor mode now. The choice is kept."
)
_STORED_DEFAULT_DENY_KILLSWITCH = (
    "Default-deny is stored on but not in force: the kill switch is on, so PortLock "
    "enforces nothing until it is removed."
)


# --- errors and seams --------------------------------------------------------------------


class ServiceError(PortLockError):
    """A service request cannot be carried out.

    Codes (``console.api`` maps them to HTTP statuses): ``not_found``,
    ``invalid_request``, ``not_connected``, ``not_pending``, ``unknown_device``,
    ``low_confidence``, ``policy_invalid`` (with ``problems``), ``policy_conflict``,
    ``killswitch_active``, ``enforcement_unavailable``, ``not_private``,
    ``no_mounted_volume``, ``scan_unavailable``, ``scan_queue_full``,
    ``store_unavailable``.
    """

    code = "service_error"

    def __init__(
        self, message: str, *, code: str | None = None, problems: Sequence[str] = ()
    ) -> None:
        super().__init__(message, code=code)
        self.problems = tuple(problems)


class ScannerLike(Protocol):
    """What the service needs of ``portlock.scan.scanner.Scanner``."""

    def scan(
        self,
        root: str,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[Any], None] | None = None,
    ) -> ScanReport: ...


class DirPrivacyLike(Protocol):
    """``guard.seams.DirPrivacy``: make a directory private, and check that it is."""

    def ensure_private(self, path: str | Any) -> None: ...

    def check(self, path: str | Any) -> PrivacyReportLike: ...


class DoctorLike(Protocol):
    """What ``doctor()`` returns: ``guard.factory.DoctorReport`` or the service's own."""

    def to_dict(self) -> dict[str, Any]: ...


# --- the audit writer --------------------------------------------------------------------

_BACKLOGGED_AUDIT_CODES = frozenset({"audit_corrupt", "audit_key_ahead", "audit_key_behind"})


@dataclass(frozen=True, slots=True)
class _PendingAudit:
    event_type: str
    severity: Severity | str | None
    actor: str | None
    device_fp: str | None
    data: Mapping[str, Any]
    occurred_at: datetime


class AuditWriter:
    """Appends to the audit log and never raises into the pipeline.

    A failed append (the database is locked, full or damaged) is kept in a bounded
    in-memory backlog and written later by :meth:`flush_backlog` with ``data.delayed``
    and ``data.occurred_at`` set: failing to record must never become failing to protect
    (DESIGN 14.10). An event the registry does not know, or data the log refuses, is a
    programming error: it is logged and dropped rather than retried forever.

    Every record written is followed by an ``audit.appended`` bus event. The newest
    timestamp in the log is tracked so the service can evaluate expiries against it
    (DESIGN 14.12). Thread-safe.

    Args:
        log: the audit log.
        bus: where ``audit.appended`` is published.
        clock: timestamps for backlogged events.
        max_backlog: events kept while the log cannot be written; the oldest is dropped.
    """

    def __init__(
        self, log: AuditLog, *, bus: EventBus, clock: Clock, max_backlog: int = 1000
    ) -> None:
        self._log = log
        self._bus = bus
        self._clock = clock
        self._max = max_backlog
        # Guards the counters and the backlog only; never held across an append.
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._backlog: deque[_PendingAudit] = deque()
        self._dropped = 0
        self._rejected = 0
        self._newest: datetime | None = None
        try:
            # The highest timestamp, not the last record's: after a clock rollback the
            # records written since carry earlier times, and a restart must not forget
            # the later one (DESIGN 14.12).
            self._newest = log.newest_timestamp()
        except (StoreError, AuditError) as exc:
            _LOG.error("the newest audit timestamp could not be read: %s", exc)

    @property
    def log(self) -> AuditLog:
        return self._log

    @property
    def degraded(self) -> bool:
        """True while events wait in the backlog."""
        with self._lock:
            return bool(self._backlog)

    @property
    def backlog(self) -> int:
        with self._lock:
            return len(self._backlog)

    @property
    def dropped(self) -> int:
        """Events lost: pushed out of a full backlog, or refused as malformed."""
        with self._lock:
            return self._dropped + self._rejected

    @property
    def newest_timestamp(self) -> datetime | None:
        """The latest timestamp of any record in the log, as far as this writer knows."""
        with self._lock:
            return self._newest

    def __call__(
        self,
        event_type: str,
        *,
        severity: Severity | str | None = None,
        actor: str | None = None,
        device_fp: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> AuditRecord | None:
        """Append one event; ``None`` if it could not be written now."""
        if event_type not in REGISTRY:
            _LOG.error("refusing to audit unknown event type %r", event_type)
            with self._lock:
                self._rejected += 1
            return None
        pending = _PendingAudit(
            event_type, severity, actor, device_fp, dict(data or {}), self._clock.now()
        )
        with self._lock:
            if self._backlog:
                # Keep the log in order: nothing new is written ahead of older events.
                self._push_locked(pending)
                return None
        # The append runs without this lock: it takes the database lock, and a caller
        # inside a database transaction (AccountStore) may come here holding that one.
        return self._write(pending)

    def auth_hook(self, event_type: str, severity: Severity, data: dict[str, Any]) -> None:
        """The ``AuditCallback`` handed to ``AccountStore``."""
        actor = data.get("actor") or data.get("username")
        self(
            event_type,
            severity=severity,
            actor=actor if isinstance(actor, str) and actor else None,
            data=data,
        )

    def flush_backlog(self) -> int:
        """Write backlogged events in order. Returns how many were written."""
        written = 0
        with self._flush_lock:
            while True:
                with self._lock:
                    if not self._backlog:
                        break
                    # Left in the backlog while it is written: a caller that finds the
                    # backlog empty may write at once, and must not overtake an older event
                    # that is still on its way into the log.
                    pending = self._backlog[0]
                try:
                    record = self._append(pending, delayed=True)
                except (StoreError, OSError) as exc:
                    _LOG.warning("the audit backlog could not be flushed yet: %s", exc)
                    break
                except AuditError as exc:
                    if exc.code in _BACKLOGGED_AUDIT_CODES:
                        _LOG.warning("the audit backlog could not be flushed yet: %s", exc)
                        break
                    _LOG.error("a backlogged audit event was refused and dropped: %s", exc)
                    with self._lock:
                        self._rejected += 1
                        self._discard_locked(pending)
                    continue
                with self._lock:
                    self._discard_locked(pending)
                written += 1
                self._after_write(record)
        return written

    def _write(self, pending: _PendingAudit) -> AuditRecord | None:
        try:
            record = self._append(pending, delayed=False)
        except (StoreError, OSError) as exc:
            _LOG.error("audit append failed; keeping %s for later: %s", pending.event_type, exc)
            with self._lock:
                self._push_locked(pending)
            return None
        except AuditError as exc:
            with self._lock:
                if exc.code in _BACKLOGGED_AUDIT_CODES:
                    _LOG.error(
                        "audit append failed; keeping %s for later: %s", pending.event_type, exc
                    )
                    self._push_locked(pending)
                else:
                    _LOG.error(
                        "audit event %s was refused and dropped: %s", pending.event_type, exc
                    )
                    self._rejected += 1
            return None
        self._after_write(record)
        return record

    def _discard_locked(self, pending: _PendingAudit) -> None:
        """Remove ``pending`` from the front of the backlog (it may have been pushed out)."""
        if self._backlog and self._backlog[0] is pending:
            self._backlog.popleft()

    def _append(self, pending: _PendingAudit, *, delayed: bool) -> AuditRecord:
        data = dict(pending.data)
        if delayed:
            data["delayed"] = True
            data["occurred_at"] = utc_iso(pending.occurred_at)
        return self._log.append(
            pending.event_type,
            pending.severity,
            actor=pending.actor,
            device_fp=pending.device_fp,
            data=data,
        )

    def _push_locked(self, pending: _PendingAudit) -> None:
        if len(self._backlog) >= self._max:
            self._backlog.popleft()
            self._dropped += 1
        self._backlog.append(pending)

    def _after_write(self, record: AuditRecord) -> None:
        stamp = record.timestamp
        with self._lock:
            if self._newest is None or stamp > self._newest:
                self._newest = stamp
        try:
            self._bus.publish(
                "audit.appended",
                {
                    "seq": record.seq,
                    "ts": record.ts,
                    "event_type": record.event_type,
                    "severity": record.severity.value,
                    "actor": record.actor,
                    "device_fp": record.device_fp,
                },
            )
        except (ValueError, TypeError) as exc:
            _LOG.error("audit.appended could not be published: %s", exc)


# --- views (API.md section 4) ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DecisionView:
    """``API.md`` 4.4: a decision with where and when it was made."""

    id: int | None
    decided_at: datetime
    decision: Decision
    trigger: str
    policy_hash: str
    mode: Mode

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"id": self.id, "decided_at": utc_iso(self.decided_at)}
        data.update(self.decision.to_dict())
        data.update(
            {"trigger": self.trigger, "policy_hash": self.policy_hash, "mode": self.mode.value}
        )
        return data

    @classmethod
    def from_record(cls, record: DecisionRecord) -> DecisionView:
        return cls(
            record.id,
            record.decided_at,
            record.decision,
            record.trigger,
            record.policy_hash,
            record.mode,
        )


@dataclass(frozen=True, slots=True)
class EnforcementView:
    """``API.md`` 4.5: what the operating system was actually made to do."""

    outcome: Outcome
    os_state: str
    would: str | None = None
    mechanism: str | None = None
    tier: Tier = Tier.NONE
    detail: str | None = None
    error: str | None = None
    at: datetime | None = None
    extra: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "os_state": self.os_state,
            "would": self.would,
            "mechanism": self.mechanism,
            "tier": self.tier.value,
            "detail": self.detail,
            "error": self.error,
            "at": utc_iso(self.at) if self.at is not None else None,
        }


@dataclass(frozen=True, slots=True)
class ConnectionView:
    """``API.md`` 4.6: one device for one continuous presence, with its decision."""

    connection_id: int | None
    run_id: str
    fingerprint: str
    confidence: Confidence
    basis: tuple[str, ...]
    storage_identity: str | None
    device: UsbDevice
    connected_at: datetime
    removed_at: datetime | None
    close_reason: str | None
    present_at_start: bool
    state: ConnectionState
    provisional: bool
    protected: bool
    protection_codes: tuple[str, ...]
    decision: DecisionView | None
    enforcement: EnforcementView | None
    scan_state: ScanState
    scan_id: int | None
    resolution: Mapping[str, Any] | None
    first_seen: datetime | None
    connection_count: int

    @property
    def display_name(self) -> str:
        return self.device.display_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "connection_id": self.connection_id,
            "run_id": self.run_id,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence.value,
            "basis": list(self.basis),
            "storage_identity": self.storage_identity,
            "display_name": self.display_name,
            "device": _device_dict(self.device),
            "connected_at": utc_iso(self.connected_at),
            "removed_at": utc_iso(self.removed_at) if self.removed_at is not None else None,
            "close_reason": self.close_reason,
            "present_at_start": self.present_at_start,
            "state": self.state.value,
            "provisional": self.provisional,
            "protected": self.protected,
            "protection_codes": list(self.protection_codes),
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "enforcement": self.enforcement.to_dict() if self.enforcement is not None else None,
            "scan": {"state": self.scan_state.value, "scan_id": self.scan_id},
            "resolution": dict(self.resolution) if self.resolution is not None else None,
            "first_seen": utc_iso(self.first_seen) if self.first_seen is not None else None,
            "connection_count": self.connection_count,
        }


@dataclass(frozen=True, slots=True)
class DeviceView:
    """``API.md`` 4.7 ``KnownDevice``."""

    record: DeviceRecord
    connected: bool
    trust: str | None

    def to_dict(self) -> dict[str, Any]:
        record = self.record
        return {
            "fingerprint": record.fingerprint.value,
            "confidence": Confidence(record.fingerprint.confidence).value,
            "basis": list(record.fingerprint.basis),
            "storage_identity": record.storage_identity,
            "display_name": record.device.display_name,
            "device": _device_dict(record.device),
            "first_seen": utc_iso(record.first_seen),
            "last_seen": utc_iso(record.last_seen),
            "connection_count": record.connection_count,
            "connected": self.connected,
            "trust": self.trust,
        }


@dataclass(frozen=True, slots=True)
class DeviceDetail:
    """``API.md`` 4.7 ``DeviceDetail``: a known device with its history."""

    device: DeviceView
    connections: tuple[ConnectionView, ...]
    grants: tuple[Grant, ...]
    decisions: tuple[DecisionView, ...]

    def to_dict(self) -> dict[str, Any]:
        data = self.device.to_dict()
        data["connections"] = [item.to_dict() for item in self.connections]
        data["grants"] = [item.to_dict() for item in self.grants]
        data["decisions"] = [item.to_dict() for item in self.decisions]
        return data


@dataclass(frozen=True, slots=True)
class ScanView:
    """``API.md`` 4.11: one scan of one volume."""

    record: ScanRecord
    include_report: bool = False

    def to_dict(self) -> dict[str, Any]:
        record = self.record
        report = dict(record.report) if record.report is not None else None
        summary: dict[str, Any] | None = None
        if report is not None:
            findings = {severity.value: 0 for severity in FindingSeverity}
            for item in report.get("findings", ()):
                severity = item.get("severity") if isinstance(item, Mapping) else None
                if severity in findings:
                    findings[severity] += 1
            summary = {
                "files_seen": report.get("files_seen", 0),
                "files_hashed": report.get("files_hashed", 0),
                "bytes_hashed": report.get("bytes_hashed", 0),
                "findings": findings,
                "errors": len(report.get("errors", ())),
                "truncated_reason": report.get("truncated_reason"),
            }
        return {
            "id": record.id,
            "connection_id": record.connection_id,
            "fingerprint": record.fingerprint,
            "mount_point": record.mount_point,
            "trigger": record.trigger,
            "requested_by": record.requested_by,
            "state": record.state,
            "queued_at": utc_iso(record.queued_at),
            "started_at": _iso(record.started_at),
            "finished_at": _iso(record.finished_at),
            "verdict": record.verdict,
            "summary": summary,
            "report": report if self.include_report else None,
        }


@dataclass(frozen=True, slots=True)
class PolicyInfo:
    """``API.md`` 4.9: the active policy."""

    policy: Policy
    hash: str
    source: str
    loaded_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": policy_to_dict(self.policy),
            "hash": self.hash,
            "name": self.policy.name,
            "rules": len(self.policy.rules),
            "source": self.source,
            "loaded_at": utc_iso(self.loaded_at),
        }


@dataclass(frozen=True, slots=True)
class PolicyTest:
    """The answer to ``POST /policy/test``: what a policy makes of a device. Changes nothing."""

    fingerprint: Fingerprint
    policy_hash: str
    result: PolicyResult
    explain: tuple[RuleTrace, ...]
    decision: Decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint.value,
            "confidence": Confidence(self.fingerprint.confidence).value,
            "policy_hash": self.policy_hash,
            "matched_rule": self.result.rule.id if self.result.rule is not None else None,
            "matched_default": self.result.matched_default,
            "skipped": [list(item) for item in self.result.skipped],
            "valid_until": _iso(self.result.valid_until),
            "explain": [
                {
                    "rule_id": trace.rule_id,
                    "outcome": trace.outcome.value,
                    "would_match": trace.would_match,
                    "summary": trace.summary,
                    "criteria": [
                        {
                            "criterion": item.criterion,
                            "matched": item.matched,
                            "detail": item.detail,
                        }
                        for item in trace.criteria
                    ],
                }
                for trace in self.explain
            ],
            "decision": self.decision.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ModeInfo:
    """``API.md`` 4.13: the chosen and the effective mode.

    ``watch_only`` is True for a process that can never be trusted to enforce (DESIGN
    14.28); ``watch_only_reason`` then says why in one or two plain sentences, and is
    ``None`` otherwise. ``can_enforce`` is always False in a watch-only process.
    """

    mode: Mode
    effective_mode: Mode
    source: str
    killswitch: bool
    can_enforce: bool
    notes: tuple[str, ...] = ()
    watch_only: bool = False
    watch_only_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "effective_mode": self.effective_mode.value,
            "source": self.source,
            "killswitch": self.killswitch,
            "can_enforce": self.can_enforce,
            "notes": list(self.notes),
            "watch_only": self.watch_only,
            "watch_only_reason": self.watch_only_reason,
        }


@dataclass(frozen=True, slots=True)
class SettingsView:
    """``API.md`` 4.16: the configuration and the run-time settings.

    ``notes`` are sentences about settings that do not take effect as stored (a stored
    default-deny in a watch-only process).
    """

    config: Mapping[str, Any]
    runtime: Mapping[str, Any]
    effective: Mapping[str, Any]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": dict(self.config),
            "runtime": dict(self.runtime),
            "effective": dict(self.effective),
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class DefaultDenyView:
    """``API.md`` 6.12 (``GET /default-deny``): default-deny in force, and as stored.

    ``enabled`` is true only while it is in force: stored on, the effective mode is
    enforce and the kill switch is not latched (never in a watch-only process).
    ``stored`` keeps the stored choice, and ``note`` says why a stored "on" is not in
    force (monitor mode, the kill switch, or watch-only).
    """

    enabled: bool
    stored: bool
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "stored": self.stored, "note": self.note}


@dataclass(frozen=True, slots=True)
class ServiceCheck:
    """One line the service adds to ``portlock doctor``."""

    id: str
    status: str
    summary: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class _ServiceDoctor:
    """``doctor()`` without a guard report (the guard factory was not given)."""

    generated_at: datetime
    platform: str
    checks: tuple[ServiceCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        statuses = {check.status for check in self.checks}
        worst = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok"
        return {
            "generated_at": utc_iso(self.generated_at),
            "platform": self.platform,
            "version": __version__,
            "worst": worst,
            "backend": None,
            "enforcer": None,
            "mechanisms": [],
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass(frozen=True, slots=True)
class ServiceStatus:
    """``API.md`` 4.14: a snapshot, replaced under L1, read without it."""

    version: str
    run_id: str
    host_label: str
    platform: str
    started_at: datetime
    uptime_seconds: int
    simulation: bool
    mode: ModeInfo
    lockdown: LockdownStatus | None
    policy: Mapping[str, Any]
    backend: Mapping[str, Any]
    enforcer: Mapping[str, Any]
    counts: Mapping[str, int]
    audit: Mapping[str, Any]
    journal: Mapping[str, int]
    degraded: tuple[str, ...]
    setup_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": "portlock",
            "version": self.version,
            "run_id": self.run_id,
            "host_label": self.host_label,
            "platform": self.platform,
            "started_at": utc_iso(self.started_at),
            "uptime_seconds": self.uptime_seconds,
            "simulation": self.simulation,
            "mode": self.mode.to_dict(),
            "lockdown": self.lockdown.to_dict() if self.lockdown is not None else None,
            "policy": dict(self.policy),
            "backend": dict(self.backend),
            "enforcer": dict(self.enforcer),
            "counts": dict(self.counts),
            "audit": dict(self.audit),
            "journal": dict(self.journal),
            "degraded": list(self.degraded),
            "setup_required": self.setup_required,
        }


@dataclass(frozen=True, slots=True)
class Applied(Generic[T]):
    """The result of a mutating call, with what it caused."""

    value: T
    reevaluated: tuple[int, ...] = ()
    summary: ReconcileSummary | None = None
    extra: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


# --- internal state ----------------------------------------------------------------------


@dataclass(slots=True)
class _Conn:
    """One connected device, as this run sees it. Mutated only under L1."""

    device: UsbDevice
    fp: Fingerprint
    id: int | None
    run_id: str
    present_at_start: bool
    connected_at: datetime
    storage_id: str | None
    first_seen: datetime | None = None
    connection_count: int = 0
    decision: Decision | None = None
    decision_id: int | None = None
    decided_at: datetime | None = None
    trigger: str = "arrival"
    policy_hash: str = ""
    mode: Mode = Mode.MONITOR
    desired: tuple[str, str | None] | None = None
    enforcement: EnforcementView | None = None
    verdict: ProtectionVerdict | None = None
    state: ConnectionState = ConnectionState.NEW
    provisional: bool = False
    resolution: dict[str, Any] | None = None
    scan_state: ScanState = ScanState.NONE
    last_scan_id: int | None = None
    verdicts: dict[str, ScanVerdict] = field(default_factory=dict)
    pending_scans: set[str] = field(default_factory=set)
    scanned: set[str] = field(default_factory=set)
    clone: bool = False
    held: bool = False
    # True from arrival until PortLock has admitted the device: it arrived while an
    # operating-system default-deny was in force, so it is unauthorized and nothing
    # else (no journal record of its own) says who must authorize it.
    arrived_under_deny: bool = False
    used_grants: set[str] = field(default_factory=set)
    audited: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def instance_id(self) -> str:
        return self.device.instance_id

    @property
    def fingerprint(self) -> str:
        return self.fp.value

    def worst_verdict(self) -> ScanVerdict | None:
        if not self.verdicts:
            return None
        return max(self.verdicts.values(), key=lambda verdict: _VERDICT_RANK[verdict])


@dataclass(slots=True)
class _ScanJob:
    scan_id: int | None
    conn: _Conn
    mount_point: str
    trigger: str
    requested_by: str
    cancel: threading.Event = field(default_factory=threading.Event)
    started_mono: float | None = None
    cancel_mono: float | None = None
    last_progress: float = 0.0
    finished: bool = False


@dataclass(frozen=True, slots=True)
class _Loaded:
    policy: Policy
    engine: PolicyEngine
    hash: str
    source: str
    loaded_at: datetime


def _sentence(text: str) -> str:
    """``text`` as a sentence of its own: a capital first letter and a closing stop."""
    text = text.strip()
    if not text:
        return text
    text = text[0].upper() + text[1:]
    return text if text.endswith((".", "!", "?")) else text + "."


def _iso(value: datetime | None) -> str | None:
    return utc_iso(value) if value is not None else None


def _device_dict(device: UsbDevice) -> dict[str, Any]:
    """``UsbDevice.to_dict()`` without the per-connection token (API.md 4.3)."""
    data = device.to_dict()
    data.pop("connection_id", None)
    return data


def _audit_device(device: UsbDevice) -> dict[str, Any]:
    """A device description for the audit log: mount points capped (ARCHITECTURE 2.4)."""
    data = _device_dict(device)
    for volume in data.get("volumes", []):
        mount = volume.get("mount_point")
        if isinstance(mount, str) and len(mount) > _MOUNT_TEXT_LIMIT:
            volume["mount_point"] = mount[:_MOUNT_TEXT_LIMIT]
    return data


def _state_for(decision: Decision, resolution: Mapping[str, Any] | None) -> ConnectionState:
    if decision.source is DecisionSource.SAFETY:
        return ConnectionState.PROTECTED
    if decision.access is Access.ALLOW:
        return ConnectionState.ALLOWED
    if decision.access is Access.READ_ONLY:
        return ConnectionState.READ_ONLY
    if decision.access is Access.DENY:
        return ConnectionState.DENIED
    return ConnectionState.DENIED if resolution else ConnectionState.PENDING


def _target_of(decision: Decision, scan_state: ScanState) -> str:
    if decision.source is DecisionSource.SAFETY:
        return _OPEN
    if decision.access is Access.ALLOW:
        if decision.scan is ScanRequirement.REQUIRED and scan_state is not ScanState.CLEAN:
            return _READ_ONLY
        return _OPEN
    if decision.access is Access.READ_ONLY:
        return _READ_ONLY
    return _BLOCKED


def _result_enforcement(
    outcome: Outcome,
    os_state: str,
    result: EnforcementResult | None,
    at: datetime,
    *,
    would: str | None = None,
    detail: str | None = None,
    error: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> EnforcementView:
    return EnforcementView(
        outcome=outcome,
        os_state=os_state,
        would=would,
        mechanism=result.mechanism if result is not None else None,
        tier=result.tier if result is not None else Tier.NONE,
        detail=detail if detail is not None else (result.detail if result is not None else None),
        error=error if error is not None else (result.error if result is not None else None),
        at=at,
        extra=MappingProxyType(dict(extra or {})),
    )


# --- the service -------------------------------------------------------------------------


class PortLockService:
    """The decision pipeline (``ARCHITECTURE.md`` 3.6, amended by ``DESIGN.md`` 14).

    Args:
        config: the configuration.
        clock: wall and monotonic time.
        store: devices, connections, decisions, scans, enrolments, settings, lockdown.
        journal: the enforcement journal. The enforcer must have been built with
            ``write_ahead=journal.write_ahead`` (every real one is, by ``service.daemon``).
        audit: the audit writer.
        bus: in-process events for the console.
        backend: observes devices.
        enforcer: the **raw** enforcer. It is wrapped here in the two ``SafeEnforcer``
            instances (``live`` and ``dry``) and never called directly.
        grants: device grants.
        scanner: scans mounted volumes; ``None`` disables scanning.
        policy_path: the policy file, or ``None`` to run the built-in default policy.
        system_ids: instance ids of the devices backing the system volume; may raise
            ``BackendError``.
        timer: the operating-system dead-man timer (DESIGN 14.16).
        recover_argv: the command that timer runs (``portlock recover``).
        dir_privacy: makes and checks the state and configuration directories private
            (DESIGN 14.18); also decides whether the kill switch is honoured.
        credentials: verifies the password or recovery code that lifting a lockdown needs.
        guard_doctor: builds ``portlock doctor`` with the service's checks appended
            (``service.daemon`` passes one built on ``guard.factory.doctor``).
        has_users: True once an administrator account exists.
        simulation: reported in the status (``portlock simulate``).
        platform: a ``sys.platform`` value, for the status.
        watch_only_reason: set (to the plain reason) when this process is watch-only
            (DESIGN 14.28, ``guard.watchonly``): ``enforcer``, ``timer`` and
            ``dir_privacy`` are then inert stand-ins for the whole run. The service stays
            in monitor mode, neither checks nor changes directory permissions, and refuses
            enforce mode, a lockdown and default-deny with this reason (``watch_only``).

    The constructor reads the lockdown row and nothing else; everything else happens in
    :meth:`start`.
    """

    def __init__(
        self,
        *,
        config: Config,
        clock: Clock,
        store: StateStore,
        journal: RecoveryJournal,
        audit: AuditWriter,
        bus: EventBus,
        backend: DeviceBackend,
        enforcer: Enforcer,
        grants: GrantStore,
        scanner: ScannerLike | None,
        policy_path: Path | None,
        system_ids: Callable[[Sequence[UsbDevice]], frozenset[str]],
        timer: ExternalTimer,
        recover_argv: Sequence[str],
        dir_privacy: DirPrivacyLike,
        credentials: CredentialCheck,
        guard_doctor: Callable[[Sequence[ServiceCheck]], DoctorLike] | None = None,
        has_users: Callable[[], bool] | None = None,
        simulation: bool = False,
        platform: str | None = None,
        watch_only_reason: str | None = None,
    ) -> None:
        if watch_only_reason is not None and (
            not isinstance(watch_only_reason, str) or not watch_only_reason.strip()
        ):
            raise ValueError("watch_only_reason must be a non-empty sentence or None")
        self._config = config
        self._watch_only_reason = watch_only_reason
        self._clock = clock
        self._store = store
        self._journal = journal
        self._audit = audit
        self._bus = bus
        self._backend = backend
        self._grants = grants
        self._scanner = scanner
        self._policy_path = Path(policy_path) if policy_path is not None else None
        self._system_ids_probe = system_ids
        self._dir_privacy = dir_privacy
        self._guard_doctor = guard_doctor
        self._has_users = has_users
        self._simulation = bool(simulation)
        self._platform = platform if platform is not None else sys.platform
        self.run_id = secrets.token_hex(8)

        self._lock = threading.RLock()
        self._conns: dict[str, _Conn] = {}
        # Connections the previous run left open: instance id -> (backend token, plugged in
        # at). Read at start, before they are closed, so a device still connected keeps the
        # time it really arrived (a lockdown exempts what was there before it began).
        self._previous_connected: dict[str, tuple[str | None, datetime]] = {}
        self._context = SafetyContext(
            scope=config.scope, hid_enforcement_enabled=config.hid_enforcement_enabled
        )
        self._live = SafeEnforcer(
            enforcer, self._safety_context, dry_run=False, on_refusal=self._refused
        )
        self._dry = SafeEnforcer(enforcer, self._safety_context, dry_run=True)
        self._flap = PortFlapGuard(
            clock,
            config.flap_guard.max_arrivals,
            config.flap_guard.window_seconds,
            config.flap_guard.cooldown_seconds,
        )
        self._kill_switch = KillSwitch(config.paths.kill_switch_file, dir_privacy)
        self._killswitch_latched = False
        self._loaded = _Loaded(
            DEFAULT_POLICY,
            PolicyEngine(DEFAULT_POLICY),
            policy_hash(DEFAULT_POLICY),
            "default",
            clock.now(),
        )
        self._policy_stamp: tuple[int, int] | None = None
        self._settings: dict[str, Any] = {}
        self._system_ids: frozenset[str] = frozenset()
        self._system_ids_note = ""
        self._privacy_problems: tuple[str, ...] = ()
        self._degraded: dict[str, str] = {}
        self._backend_down_since: float | None = None
        self._events: queue.Queue[DeviceEvent] = queue.Queue(maxsize=_EVENT_QUEUE_SIZE)
        self._events_dropped = False
        self._resync_misses = 0
        self._global_audited: dict[str, tuple[str, ...]] = {}
        self._baseline_active = False
        self._baseline_note = ""
        self._released = 0
        self._started = False
        self._stopped = False
        self._started_at = clock.now()
        self._started_mono = clock.monotonic()
        self._last_resync = self._started_mono
        self._last_periodic = self._started_mono
        self._last_external = self._started_mono
        self._data_version: int | None = None
        self._clock_behind = False
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

        self._scan_queue: queue.Queue[_ScanJob] = queue.Queue(maxsize=_SCAN_QUEUE_SIZE)
        self._scan_generation = 0
        self._scan_threaded = False
        self._running_jobs: dict[int, _ScanJob] = {}
        self._job_counter = 0
        self._abandoned_scans = 0
        self._scan_disabled = False
        self._live_views: dict[int, ConnectionView] = {}
        self._status: ServiceStatus | None = None

        self._confirmations = CommitConfirm(
            store,
            clock=clock,
            timeout_seconds=config.commit_confirm_seconds,
            audit=audit,
            timer=timer,
            recover_argv=recover_argv,
        )
        self._confirmations.register(CHANGE_ENFORCE_MODE, _EnforceModeChange(self))
        self._confirmations.register(CHANGE_WIDEN_SCOPE, _WidenScopeChange(self))
        self._confirmations.register(CHANGE_DEFAULT_DENY, _DefaultDenyChange(self))
        self._lockdown = LockdownManager(
            store,
            clock=clock,
            config=config.lockdown,
            audit=audit,
            reconcile=self.reconcile,
            timer=timer,
            recover_argv=recover_argv,
            kill_switch=self._kill_switch,
            credentials=credentials,
            confirmations=self._confirmations,
            devices=lambda: list(self._conns.values()),
            protection=self._live.protection,
            default_minutes=self._default_lockdown_minutes,
        )

    # =====================================================================================
    # start, events, tick, stop
    # =====================================================================================

    def start(self, *, threads: bool = True) -> None:
        """Bring the service up (``ARCHITECTURE.md`` 3.6.2 as amended by DESIGN 14).

        Order: record the run; make and check the directories private; honour the kill
        switch; audit a ``portlock recover`` that ran meanwhile; load the policy and
        verify the tail of the audit log; close the previous run's connections; start
        the backend and enumerate; build the safety context; settle grants and the
        journal; resume lockdown and roll back unconfirmed changes; reconcile every
        device; finish a lift found at start; start the threads.

        Args:
            threads: start the pipeline and scan threads. Tests pass False and drive
                :meth:`drain_events`, :meth:`run_scans` and :meth:`tick` themselves.

        Raises:
            StoreError: if the first write to the store fails (the daemon exits 3).
        """
        with self._lock:
            if self._started:
                raise ServiceError("the service is already started", code="invalid_request")
            self._started = True
            now = self._clock.now()
            previous_run = self._safe(lambda: self._store.get_setting("service.run"), None)
            self._store.set_setting(
                "service.run", {"run_id": self.run_id, "started_at": utc_iso(now)}, by=_SYSTEM
            )
            self._load_settings()
            self._check_privacy()
            killswitch_at_start = self._kill_switch.is_set()
            marker = consume_recover_marker(self._config.paths.state_dir)
            if marker is not None:
                self._audit_recover_marker(marker)
            self._load_policy_at_start()
            self._verify_audit_tail()
            effective = self._effective_mode()
            self._audit(
                ev.SERVICE_STARTED,
                actor=_SYSTEM,
                data={
                    "version": __version__,
                    "mode": self._chosen_mode()[0].value,
                    "effective_mode": effective.value,
                    "platform": self._platform,
                    "run_id": self.run_id,
                    "previous_shutdown": "unclean" if previous_run is not None else "clean",
                    "simulation": self._simulation,
                    "killswitch": killswitch_at_start,
                },
            )
            self._previous_connected = {
                record.instance_id: (record.connection_token, record.connected_at)
                for record in self._safe(self._store.open_connections, [])
            }
            closed = self._safe(
                lambda: self._store.close_open_connections(
                    removed_at=now, reason="service_restart"
                ),
                0,
            )
            self._cancel_stale_scans()
            self._start_backend()
            devices = self._enumerate_at_start()
            fingerprints = {device.instance_id: compute_fingerprint(device) for device in devices}
            self._system_ids = self._probe_system_ids(devices)
            self._rebuild_context()
            spent = self._settle_grants_at_start(devices, fingerprints)
            found, discarded = self._journal_hygiene(fingerprints)
            if killswitch_at_start:
                self._activate_killswitch(devices=devices, reconcile_after=False)
            recovered_at = marker.get("at") if isinstance(marker, dict) else None
            resumed = self._lockdown.resume(
                recovered_at=recovered_at if isinstance(recovered_at, datetime) else None
            )
            self._confirmations.resume()
            summary = self._start_reconcile(devices)
            if resumed == "lift_pending":
                try:
                    self._lockdown.finish_lift(summary)
                except PortLockError as exc:
                    _LOG.error("finishing the lockdown lift at start failed: %s", exc)
                self._publish_lockdown("lifted")
            self._last_resync = self._clock.monotonic()
            if previous_run is not None:
                self._audit(
                    ev.SERVICE_RECOVERED,
                    actor=_SYSTEM,
                    data={
                        "component": "service",
                        "connections_closed": int(closed or 0),
                        "grants_spent": spent,
                        "journal_records_found": found,
                        "journal_records_discarded": discarded,
                        "lockdown": resumed,
                    },
                )
            self._refresh_status()
        if threads:
            self._start_threads()

    def on_backend_event(self, event: DeviceEvent) -> None:
        """The backend's callback: queue the event, never block (backend thread)."""
        try:
            self._events.put_nowait(event)
        except queue.Full:
            # The next tick enumerates and compares, so a storm cannot lose a device.
            self._events_dropped = True

    def drain_events(self, limit: int | None = None) -> int:
        """Handle queued backend events on the calling thread. Returns how many."""
        handled = 0
        while limit is None or handled < limit:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)
            handled += 1
        return handled

    def handle_event(self, event: DeviceEvent) -> None:
        """Process one device event (pipeline thread, or a test). Never raises."""
        with self._lock:
            try:
                if event.type is DeviceEventType.RESYNC:
                    self._resync(reason="backend")
                elif event.device is None:
                    return
                elif event.type is DeviceEventType.ARRIVED:
                    self._on_arrival(event.device, present_at_start=False)
                elif event.type is DeviceEventType.CHANGED:
                    self._on_changed(event.device)
                elif event.type is DeviceEventType.REMOVED:
                    self._on_removed(event.device, reason="removed")
            except Exception as exc:
                # A bug must not stop the pipeline: the event is logged and the 30-second
                # resync brings the device back into view.
                _LOG.error("handling a %s event failed", event.type.value, exc_info=exc)
                self._alert("error", "event handling failed", f"{type(exc).__name__}: {exc}")
            self._refresh_status()

    def tick(self) -> None:
        """Time-driven work, about once a second. Never raises."""
        with self._lock:
            steps: tuple[tuple[str, Callable[[], None]], ...] = (
                ("killswitch", self._tick_killswitch),
                ("confirmations", self._tick_confirmations),
                ("lockdown", self._tick_lockdown),
                ("clock", self._tick_clock),
                ("grants", self._tick_grants),
                ("expiry", self._tick_expiry),
                ("ports", self._tick_ports),
                ("external", self._tick_external),
                ("resync", self._tick_resync),
                ("periodic", self._tick_periodic),
                ("scans", self._tick_scans),
            )
            for name, step in steps:
                try:
                    step()
                except Exception as exc:
                    _LOG.error("tick step %s failed", name, exc_info=exc)
                    self._alert("error", f"periodic task {name} failed", f"{type(exc).__name__}")
            self._refresh_status()

    def stop(self) -> RollbackReport | None:
        """Stop cleanly: restore journaled state (unless ``fail_closed``) and close up.

        A clean stop puts everything back, an active lockdown included: lockdown is in
        force only while the service runs, its record stays and the next start resumes
        it (ARCHITECTURE D9). With ``fail_closed`` the restrictions stay in place and the
        journal keeps them for the next start. A watch-only process restores nothing and
        leaves the journal file as it found it. Safe to call twice.
        """
        with self._lock:
            if self._stopped or not self._started:
                return None
            self._stopped = True
            self._stop_event.set()
        with contextlib.suppress(Exception):
            self._backend.stop()
        for thread in self._threads:
            thread.join(timeout=5.0)
        with self._lock:
            for job in list(self._running_jobs.values()):
                job.cancel.set()
            self._cancel_queued_scans()
            report: RollbackReport | None = None
            # A watch-only process changed nothing, so it restores nothing, and it never
            # rewrites the journal (DESIGN 14.28): a rollback would compact it.
            if not self._config.fail_closed and not self._watch_only():
                report = rollback(
                    self._journal,
                    self._live,
                    [conn.device for conn in self._conns.values()],
                    reason="service_stop",
                    readmit=self._held_back_ids(),
                )
                self._baseline_active = False
                if report.restored + report.released + report.readmitted > 0 or report.failed:
                    self._audit(ev.RECOVERY_RESTORED, actor=_SYSTEM, data=report.to_dict())
            now = self._clock.now()
            for conn in self._conns.values():
                if conn.id is not None:
                    self._safe(
                        lambda c=conn: self._store.close_connection(
                            c.id, removed_at=now, reason="service_stop"
                        ),
                        None,
                    )
            self._conns.clear()
            self._live_views = {}
            self._safe(lambda: self._store.delete_setting("service.run"), None)
            self._audit(
                ev.SERVICE_STOPPED,
                actor=_SYSTEM,
                data={
                    "clean": True,
                    "fail_closed": self._config.fail_closed,
                    "report": report.to_dict() if report is not None else None,
                },
            )
            self._audit.flush_backlog()
            return report

    def run_scans(self, limit: int | None = None) -> int:
        """Run queued scans on the calling thread (tests and simulation without threads)."""
        done = 0
        while limit is None or done < limit:
            try:
                job = self._scan_queue.get_nowait()
            except queue.Empty:
                break
            self._run_scan_job(job)
            done += 1
        return done

    # =====================================================================================
    # read methods (no L1)
    # =====================================================================================

    @property
    def bus(self) -> EventBus:
        return self._bus

    @property
    def audit_log(self) -> AuditLog:
        return self._audit.log

    @property
    def audit_writer(self) -> AuditWriter:
        return self._audit

    @property
    def live_enforcer(self) -> SafeEnforcer:
        """The enforcing safety wrapper (never refuses a release)."""
        return self._live

    def status(self) -> ServiceStatus:
        """The status snapshot with the uptime brought up to date."""
        snapshot = self._status
        if snapshot is None:
            with self._lock:
                self._refresh_status()
            snapshot = self._status
        if snapshot is None:
            raise ServiceError("the status is not available", code="store_unavailable")
        uptime = max(0, int(self._clock.monotonic() - self._started_mono))
        return dataclasses.replace(snapshot, uptime_seconds=uptime)

    def list_connections(
        self,
        *,
        open_only: bool = True,
        state: ConnectionState | str | None = None,
        fingerprint: str | None = None,
        before_id: int | None = None,
        limit: int = 100,
    ) -> list[ConnectionView]:
        """Connections, newest first, with the live view for those still open."""
        wanted = ConnectionState(state) if state is not None else None
        try:
            records = self._store.list_connections(
                open_only=open_only, fingerprint=fingerprint, before_id=before_id, limit=limit
            )
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc
        views = [self._view_for_record(record) for record in records]
        return [view for view in views if wanted is None or view.state is wanted]

    def get_connection(self, connection_id: int) -> ConnectionView:
        live = self._live_views.get(connection_id)
        if live is not None:
            return live
        try:
            record = self._store.get_connection(connection_id)
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc
        if record is None:
            raise ServiceError("no such connection", code="not_found")
        return self._view_for_record(record)

    def list_devices(
        self, *, limit: int = 100, before: str | None = None, text: str | None = None
    ) -> list[DeviceView]:
        try:
            records = self._store.list_devices(limit=limit, before=before, text=text)
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc
        return [self._device_view(record) for record in records]

    def get_device(self, fingerprint: str) -> DeviceDetail:
        try:
            record = self._store.get_device(fingerprint)
            if record is None:
                raise ServiceError("no such device", code="not_found")
            connections = self._store.list_connections(fingerprint=fingerprint, limit=20)
            decisions = self._store.list_decisions(fingerprint=fingerprint, limit=50)
            grants = [
                g for g in self._grants.list(include_inactive=True) if g.fingerprint == fingerprint
            ]
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc
        grants.sort(key=lambda grant: (grant.created_at, grant.id), reverse=True)
        return DeviceDetail(
            device=self._device_view(record),
            connections=tuple(self._view_for_record(item) for item in connections),
            grants=tuple(grants[:50]),
            decisions=tuple(DecisionView.from_record(item) for item in decisions),
        )

    def list_decisions(self, **filters: Any) -> list[DecisionView]:
        try:
            return [
                DecisionView.from_record(item) for item in self._store.list_decisions(**filters)
            ]
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc

    def list_grants(
        self, *, include_inactive: bool = False, kind: GrantKind | str | None = None
    ) -> list[Grant]:
        wanted = GrantKind(kind) if kind is not None else None
        grants = self._grants.list(include_inactive=include_inactive)
        return [grant for grant in grants if wanted is None or grant.kind is wanted]

    def list_enrolments(self) -> list[EnrolmentRecord]:
        return self._store.list_enrolments()

    def get_policy(self) -> PolicyInfo:
        loaded = self._loaded
        return PolicyInfo(loaded.policy, loaded.hash, loaded.source, loaded.loaded_at)

    def list_scans(self, **filters: Any) -> list[ScanView]:
        try:
            return [ScanView(record) for record in self._store.list_scans(**filters)]
        except StoreError as exc:
            raise ServiceError(
                f"the store cannot be read: {exc}", code="store_unavailable"
            ) from exc

    def get_scan(self, scan_id: int) -> ScanView:
        record = self._store.get_scan(scan_id)
        if record is None:
            raise ServiceError("no such scan", code="not_found")
        return ScanView(record, include_report=True)

    def lockdown_status(self) -> LockdownStatus:
        return self._lockdown.status()

    def pending_changes(self) -> list[PendingChangeRecord]:
        """Changes waiting for commit-confirm."""
        return self._confirmations.pending()

    def get_mode(self) -> ModeInfo:
        return self._mode_info()

    def get_settings(self) -> SettingsView:
        settings = dict(self._settings)
        default_deny = self.get_default_deny()
        runtime = {
            "protected_fingerprints": list(settings.get("protected_fingerprints", [])),
            "scan.enabled": bool(settings.get("scan.enabled", self._config.scan.enabled)),
            "lockdown.default_minutes": self._default_lockdown_minutes(),
            "scope": self._scope(),
            # In force (GET /default-deny ``enabled``), not merely stored: a stored "on"
            # reads as off in monitor mode, under the kill switch and in watch-only.
            "default_deny": default_deny.enabled,
        }
        effective = {
            "scan_enabled": self._scanning_available(),
            "lockdown_default_minutes": self._default_lockdown_minutes(),
            "hid_enforcement_enabled": self._config.hid_enforcement_enabled,
            "scope": self._scope(),
            "fail_closed": self._config.fail_closed,
            "baseline_read_only": self._baseline_active,
            # What the service asks of the operating system right now: also true while a
            # lockdown is active, which denies new devices whatever is stored.
            "default_deny": self._want_default_deny(),
        }
        notes = (default_deny.note,) if default_deny.note else ()
        return SettingsView(self._config.to_dict(), runtime, effective, notes)

    def get_default_deny(self) -> DefaultDenyView:
        """Default-deny as it is in force, and as stored (``GET /default-deny``).

        ``enabled`` means in force: stored on, the effective mode is enforce and the kill
        switch is not latched. A watch-only process is never in enforce mode, so it is
        never in force there (DESIGN 14.28). When the stored choice is on but not in
        force, the note says why, so that the choice does not look lost.
        """
        stored = bool(self._settings.get("default_deny", False))
        if self._watch_only():
            return DefaultDenyView(False, stored, _STORED_DEFAULT_DENY_IGNORED if stored else None)
        latched = self._killswitch_latched
        in_force = stored and not latched and self._effective_mode() is Mode.ENFORCE
        note: str | None = None
        if stored and not in_force:
            note = _STORED_DEFAULT_DENY_KILLSWITCH if latched else _STORED_DEFAULT_DENY_MONITOR
        return DefaultDenyView(in_force, stored, note)

    def doctor(self) -> DoctorLike:
        """``portlock doctor``: the guard report with the service checks appended."""
        checks = tuple(self._service_checks())
        if self._guard_doctor is not None:
            return self._guard_doctor(checks)
        return _ServiceDoctor(self._clock.now(), self._platform, checks)

    # =====================================================================================
    # mutating methods (L1)
    # =====================================================================================

    def approve(
        self,
        connection_id: int,
        *,
        kind: GrantKind | str,
        read_only: bool = False,
        expires_at: datetime | None = None,
        note: str = "",
        role: str = "operator",
        actor: str,
    ) -> Applied[Grant]:
        """Grant a pending (or operator-denied) device and re-evaluate it.

        ``role`` (``admin`` or ``operator``) selects the duration ceiling of a temporary
        grant (DESIGN 14.13). A low-confidence device's grant is bound to its port; a
        ``once`` grant is bound to this connection at once.

        Raises:
            ServiceError: ``not_connected``, ``not_pending``.
            GrantError: from the grant store (``grant_low_confidence`` and so on).
        """
        with self._lock:
            conn = self._conn_by_id(connection_id)
            if conn.state not in (ConnectionState.PENDING, ConnectionState.DENIED) or (
                conn.state is ConnectionState.DENIED and conn.resolution is None
            ):
                raise ServiceError(
                    "only a pending device, or one an operator denied, can be approved",
                    code="not_pending",
                )
            grant_kind = GrantKind(kind)
            grant = self._grants.create(
                conn.fp,
                grant_kind,
                read_only=read_only,
                expires_at=expires_at,
                max_duration=self._grant_ceiling(role),
                port=conn.device.bus_path if conn.fp.confidence is Confidence.LOW else None,
                granted_by=actor,
                note=note,
            )
            if grant_kind is GrantKind.ONCE:
                grant = self._grants.bind(grant.id, conn.device)
            conn.resolution = None
            if conn.id is not None:
                self._safe(lambda: self._store.update_connection(conn.id, resolution=None), None)
            self._audit_grant_created(grant, conn.id)
            touched = self._reevaluate_fingerprint(grant.fingerprint, "grant")
            self._refresh_status()
            view = self._live_view(conn)
            return Applied(grant, reevaluated=touched, extra={"connection": view})

    def deny(
        self, connection_id: int, *, eject: bool = False, note: str = "", actor: str
    ) -> Applied[ConnectionView]:
        """Record an operator's denial of a pending device (this connection only).

        The decision stays ``pending`` and blocked; the connection's state becomes
        ``denied``. With ``eject`` the device is also asked to leave.

        Raises:
            ServiceError: ``not_connected``, ``not_pending``, ``invalid_request``.
        """
        if not isinstance(note, str) or len(note) > _MAX_NOTE:
            raise ServiceError("the note is at most 512 characters", code="invalid_request")
        with self._lock:
            conn = self._conn_by_id(connection_id)
            if conn.state is not ConnectionState.PENDING:
                raise ServiceError("only a pending device can be denied", code="not_pending")
            now = self._clock.now()
            conn.resolution = {"action": "denied", "by": actor, "at": utc_iso(now), "note": note}
            conn.state = ConnectionState.DENIED
            if conn.id is not None:
                self._safe(
                    lambda: self._store.update_connection(
                        conn.id, resolution=conn.resolution, state=conn.state
                    ),
                    None,
                )
            decision = conn.decision
            self._audit(
                ev.DECISION_MADE,
                actor=actor,
                device_fp=conn.fingerprint,
                data={
                    "connection_id": conn.id,
                    "decision": decision.to_dict() if decision is not None else None,
                    "trigger": "operator",
                    "resolution": "denied",
                    "note": note,
                },
            )
            ejected: EnforcementResult | None = None
            if eject:
                ejected = self._live.eject(conn.device)
                self._record_result(conn, Action.EJECT, ejected, cause="operator", actor=actor)
            view = self._live_view(conn)
            self._publish_connection("decision.made", view)
            self._refresh_status()
            return Applied(view, extra={"eject": ejected})

    def create_grant(
        self,
        fingerprint: str,
        kind: GrantKind | str,
        *,
        read_only: bool = False,
        expires_at: datetime | None = None,
        note: str = "",
        allow_low_confidence: bool = False,
        role: str = "operator",
        actor: str,
    ) -> Applied[Grant]:
        """Grant a known device by fingerprint (trust, temporary or once).

        Raises:
            ServiceError: ``unknown_device``, ``low_confidence``.
            GrantError: from the grant store.
        """
        with self._lock:
            record = self._store.get_device(fingerprint)
            if record is None:
                raise ServiceError("this fingerprint has never been seen", code="unknown_device")
            fp = record.fingerprint
            low = fp.confidence is Confidence.LOW
            if low and not allow_low_confidence:
                raise ServiceError(
                    "the device has no unique serial number; pass allow_low_confidence to "
                    "grant every unit of this model on its port",
                    code="low_confidence",
                )
            grant = self._grants.create(
                fp,
                GrantKind(kind),
                read_only=read_only,
                expires_at=expires_at,
                max_duration=self._grant_ceiling(role),
                port=record.device.bus_path if low else None,
                granted_by=actor,
                note=note,
            )
            self._audit_grant_created(grant, None)
            touched = self._reevaluate_fingerprint(grant.fingerprint, "grant")
            self._evaluate_orphans()
            self._refresh_status()
            return Applied(grant, reevaluated=touched)

    def revoke_grant(self, grant_id: str, *, actor: str) -> Applied[Grant]:
        """Withdraw a grant; devices it covered are re-evaluated (and revoked, 14.11)."""
        with self._lock:
            grant = self._grants.revoke(grant_id, actor)
            event = ev.TRUST_REMOVED if grant.kind is GrantKind.TRUST else ev.GRANT_REVOKED
            self._audit(
                event,
                actor=actor,
                device_fp=grant.fingerprint,
                data={"grant_id": grant.id, "kind": grant.kind.value},
            )
            self._publish("grant.changed", {"change": "revoked", "grant": grant.to_dict()})
            touched = self._reevaluate_fingerprint(grant.fingerprint, "grant")
            self._evaluate_orphans()
            self._refresh_status()
            return Applied(grant, reevaluated=touched)

    def enroll(
        self, connection_id: int, *, actor: str, label: str | None = None
    ) -> Applied[EnrolmentRecord]:
        """Enrol a connected device on its port (DESIGN 14.1): it stays protected there.

        Raises:
            ServiceError: ``not_connected``, ``invalid_request`` (no port).
        """
        with self._lock:
            conn = self._conn_by_id(connection_id)
            if not conn.device.bus_path:
                raise ServiceError(
                    "the platform reports no port for this device; it cannot be enrolled",
                    code="invalid_request",
                )
            record = self._store.add_enrolment(
                conn.fingerprint, conn.device.bus_path, by=actor, label=label
            )
            self._audit(
                ev.ENROLL_ADDED,
                actor=actor,
                device_fp=conn.fingerprint,
                data={
                    "connection_id": conn.id,
                    "bus_path": record.bus_path,
                    "label": record.label,
                    "input_only": conn.device.is_input_only,
                },
            )
            self._rebuild_context()
            touched = self._reevaluate_fingerprint(conn.fingerprint, "settings")
            self._refresh_status()
            return Applied(record, reevaluated=touched)

    def unenroll(
        self, fingerprint: str, *, bus_path: str | None = None, actor: str
    ) -> Applied[int]:
        """Remove an enrolment (one port, or every port of a fingerprint)."""
        with self._lock:
            removed = self._store.remove_enrolment(fingerprint, bus_path)
            if removed:
                self._audit(
                    ev.ENROLL_REMOVED,
                    actor=actor,
                    device_fp=fingerprint,
                    data={"bus_path": bus_path, "removed": removed},
                )
            self._rebuild_context()
            summary = self.reconcile("settings")
            return Applied(removed, summary=summary)

    def release_port(self, port: str, *, actor: str) -> Applied[bool]:
        """End a port hold-down early (an administrator's decision, DESIGN 14.6)."""
        with self._lock:
            release = self._flap.release(port)
            if release is None:
                return Applied(False)
            self._audit(
                ev.SAFETY_PORT_HELD,
                actor=actor,
                data={
                    "port": port,
                    "released": True,
                    "manual": True,
                    "coalesced": release.coalesced,
                    "held_seconds": int(release.held_seconds),
                },
            )
            touched = self._release_held(port)
            self._refresh_status()
            return Applied(True, reevaluated=touched)

    def validate_policy(self, data: Mapping[str, Any]) -> tuple[str | None, tuple[str, ...]]:
        """``(hash, problems)``: the hash when valid, else the problems."""
        try:
            policy = parse_policy(data)
        except PolicyError as exc:
            return None, tuple(exc.problems) or (str(exc),)
        return policy_hash(policy), ()

    def replace_policy(
        self, data: Mapping[str, Any], *, expected_hash: str | None = None, actor: str
    ) -> Applied[PolicyInfo]:
        """Validate, save and activate a new policy, then reconcile every device.

        Raises:
            ServiceError: ``policy_invalid`` (with ``problems``), ``policy_conflict``.
        """
        with self._lock:
            try:
                policy = parse_policy(data)
            except PolicyError as exc:
                problems = tuple(exc.problems) or (str(exc),)
                self._audit(
                    ev.POLICY_INVALID,
                    actor=actor,
                    data={"problems": list(problems[:_MAX_PROBLEMS_AUDITED]), "source": "api"},
                )
                raise ServiceError(
                    "the policy is invalid", code="policy_invalid", problems=problems
                ) from exc
            previous = self._loaded.hash
            if expected_hash is not None and expected_hash != previous:
                raise ServiceError(
                    "the policy was changed by someone else since it was read",
                    code="policy_conflict",
                )
            if self._policy_path is not None:
                save_policy(self._policy_path, policy)
                self._policy_stamp = self._stat_policy()
            self._activate_policy(policy, source="file" if self._policy_path else "default")
            self._audit_policy_changed(previous, actor)
            summary = self.reconcile("policy")
            return Applied(self.get_policy(), summary=summary, extra={"previous_hash": previous})

    def test_policy(
        self,
        *,
        device: UsbDevice,
        policy: Mapping[str, Any] | None = None,
        at: datetime | None = None,
    ) -> PolicyTest:
        """Evaluate a device against the active policy or a draft. Changes nothing.

        Raises:
            ServiceError: ``policy_invalid`` for a draft that does not validate.
        """
        if policy is not None:
            try:
                draft = parse_policy(policy)
            except PolicyError as exc:
                raise ServiceError(
                    "the policy is invalid", code="policy_invalid", problems=exc.problems
                ) from exc
            engine, digest = PolicyEngine(draft), policy_hash(draft)
        else:
            engine, digest = self._loaded.engine, self._loaded.hash
        moment = at if at is not None else self._now()
        fp = compute_fingerprint(device)
        with self._lock:
            verdict = self._live.protection(device)
            result = engine.evaluate(device, fp, now=moment)
            grant = self._grants.active_for(fp.value, now=moment, device=device)
            active = self._lockdown.active
            exempt = active and self._lockdown.is_exempt(device, connected_at=moment)
            decision = decide(
                device=device,
                fingerprint=fp,
                policy_result=result,
                grant=grant,
                protected=verdict.protected,
                protection_reasons=verdict.reasons,
                lockdown_active=active,
                lockdown_exempt=exempt,
                now=moment,
            )
        return PolicyTest(fp, digest, result, engine.explain(device, fp, now=moment), decision)

    def request_scan(
        self, connection_id: int, *, mount_point: str | None = None, actor: str
    ) -> list[ScanView]:
        """Queue a manual scan of a connection's mounted volumes (report-only when the
        decision asks for no scan, or the device is protected).

        Raises:
            ServiceError: ``not_connected``, ``no_mounted_volume``, ``scan_unavailable``,
                ``scan_queue_full``.
        """
        with self._lock:
            conn = self._conn_by_id(connection_id)
            if not self._scanning_available():
                raise ServiceError("scanning is not available", code="scan_unavailable")
            mounts = [
                volume.mount_point
                for volume in conn.device.volumes
                if volume.mount_point and (mount_point is None or volume.mount_point == mount_point)
            ]
            if not mounts:
                raise ServiceError("no mounted volume to scan", code="no_mounted_volume")
            views: list[ScanView] = []
            for mount in mounts:
                job = self._queue_scan(conn, mount, trigger="manual", requested_by=actor)
                if job is None:
                    raise ServiceError("the scan queue is full", code="scan_queue_full")
                if job.scan_id is not None:
                    record = self._store.get_scan(job.scan_id)
                    if record is not None:
                        views.append(ScanView(record))
            self._update_scan_state(conn)
            return views

    def lockdown_engage(
        self, *, minutes: int | None = None, reason: str = "", actor: str, channel: str
    ) -> Applied[EngageResult]:
        """Engage lockdown under commit-confirm (DESIGN 11, 14.15). Acts in monitor mode too.

        A watch-only process refuses (DESIGN 14.28): a lockdown that blocks nothing must
        never be reported as active, so it stays ``idle`` and nothing is recorded.

        Raises:
            ServiceError: ``watch_only``, ``killswitch_active``, ``enforcement_unavailable``.
            LockdownError, ConfirmationError: from the lockdown manager.
        """
        with self._lock:
            self._refuse_if_watch_only()
            if self._kill_switch.is_set() or self._killswitch_latched:
                raise ServiceError(
                    "the kill switch is set; enforcement is disabled", code="killswitch_active"
                )
            caps = self._live.capabilities()
            if not caps.privileged or not caps.block:
                raise ServiceError(
                    "this enforcer cannot block devices here: " + "; ".join(caps.notes),
                    code="enforcement_unavailable",
                )
            result = self._lockdown.engage(
                actor=actor, channel=channel, minutes=minutes, reason=reason
            )
            self._publish_lockdown("engaged")
            self._refresh_status()
            return Applied(result, summary=result.summary)

    def lockdown_confirm(self, change_id: str, *, actor: str, channel: str) -> LockdownStatus:
        """Confirm an engaged lockdown over the channel that engaged it."""
        with self._lock:
            self._refuse_if_watch_only()
            status = self._lockdown.confirm(change_id, actor=actor, channel=channel)
            self._refresh_status()
            return status

    def lockdown_renew(self, *, minutes: int | None = None, actor: str) -> Applied[LockdownStatus]:
        with self._lock:
            status = self._lockdown.renew(actor=actor, minutes=minutes)
            self._publish_lockdown("renewed")
            self._refresh_status()
            return Applied(status)

    def lockdown_lift(self, *, actor: str, credential: Credential) -> Applied[LiftResult]:
        """Lift the lockdown; needs the administrator password or a recovery code."""
        with self._lock:
            result = self._lockdown.lift(actor=actor, credential=credential)
            self._publish_lockdown("lifted")
            self._refresh_status()
            return Applied(result, summary=result.summary)

    def set_mode(self, mode: Mode | str, *, actor: str, channel: str) -> Applied[ModeInfo]:
        """Change the mode. Switching to enforce goes through commit-confirm (14.15).

        Returns the mode as now in force; ``extra["change"]`` holds the pending change
        that must be confirmed within ``Config.commit_confirm_seconds``.

        A watch-only process (DESIGN 14.28) refuses enforce mode with the reason (not
        elevated, or directories that are not system-wide); monitor stays allowed.

        Raises:
            ServiceError: ``watch_only``, ``killswitch_active``,
                ``enforcement_unavailable``, ``not_private``.
            ConfirmationError: from commit-confirm.
        """
        wanted = Mode(mode)
        with self._lock:
            if wanted is Mode.ENFORCE:
                self._refuse_if_watch_only()
            if wanted is Mode.MONITOR:
                before = self._effective_mode()
                for change in self._confirmations.pending():
                    if change.kind == CHANGE_ENFORCE_MODE:
                        self._confirmations.cancel(
                            change.id, actor=actor, reason="monitor requested"
                        )
                self._write_mode(Mode.MONITOR, actor=actor, reason="requested")
                summary = self.reconcile("mode") if before is not Mode.MONITOR else None
                return Applied(self._mode_info(), summary=summary)
            if self._kill_switch.is_set() or self._killswitch_latched:
                raise ServiceError(
                    "the kill switch is set; enforcement is disabled", code="killswitch_active"
                )
            if self._privacy_problems:
                raise ServiceError(
                    "enforce mode is refused: " + "; ".join(self._privacy_problems),
                    code="not_private",
                )
            caps = self._live.capabilities()
            if not caps.privileged or not caps.block:
                raise ServiceError(
                    "this enforcer cannot block devices here: " + "; ".join(caps.notes),
                    code="enforcement_unavailable",
                )
            if self._chosen_mode()[0] is Mode.ENFORCE:
                return Applied(self._mode_info())
            change = self._confirmations.propose(
                CHANGE_ENFORCE_MODE,
                actor=actor,
                channel=channel,
                params={"previous": self._settings.get("mode")},
            )
            return Applied(self._mode_info(), extra={"change": _change_dict(change)})

    def set_scope(self, scope: str, *, actor: str, channel: str) -> Applied[str]:
        """Change the enforcement scope. Widening goes through commit-confirm (14.15).

        Raises:
            ServiceError: ``invalid_request`` for an unknown scope.
        """
        if scope not in SCOPES:
            raise ServiceError(f"unknown scope {scope!r}", code="invalid_request")
        with self._lock:
            current = self._scope()
            if scope == current:
                return Applied(current)
            # A widening still waiting for confirmation would, at its deadline, write back
            # the scope from before it: possibly wider than this request. Cancel it (that
            # restores the previous scope) and decide from where that leaves things.
            waiting = [c for c in self._confirmations.pending() if c.kind == CHANGE_WIDEN_SCOPE]
            for change in waiting:
                self._confirmations.cancel(change.id, actor=actor, reason="scope changed")
            if waiting:
                current = self._scope()
                if scope == current:
                    return Applied(current)
            if _SCOPE_ORDER[scope] > _SCOPE_ORDER[current]:
                change = self._confirmations.propose(
                    CHANGE_WIDEN_SCOPE,
                    actor=actor,
                    channel=channel,
                    params={"scope": scope, "previous": self._settings.get("scope")},
                )
                return Applied(self._scope(), extra={"change": _change_dict(change)})
            self._write_scope(scope, actor=actor)
            summary = self.reconcile("settings")
            return Applied(self._scope(), summary=summary)

    def set_default_deny(self, enabled: bool, *, actor: str, channel: str) -> Applied[bool]:
        """Standing OS default-deny for new devices in enforce mode (commit-confirm to turn on).

        A watch-only process refuses to turn it on (DESIGN 14.28); turning it off is
        always allowed.

        Raises:
            ServiceError: ``watch_only``, ``killswitch_active``.
        """
        with self._lock:
            if enabled:
                self._refuse_if_watch_only()
            current = bool(self._settings.get("default_deny", False))
            if enabled == current:
                return Applied(current)
            if enabled:
                if self._kill_switch.is_set() or self._killswitch_latched:
                    raise ServiceError(
                        "the kill switch is set; enforcement is disabled", code="killswitch_active"
                    )
                change = self._confirmations.propose(
                    CHANGE_DEFAULT_DENY, actor=actor, channel=channel, params={"previous": False}
                )
                return Applied(True, extra={"change": _change_dict(change)})
            self._write_setting("default_deny", False, actor=actor)
            summary = self.reconcile("settings")
            return Applied(False, summary=summary)

    def confirm_change(self, change_id: str, *, actor: str, channel: str) -> PendingChangeRecord:
        """Confirm a pending change (enforce mode, scope, default-deny or lockdown).

        A watch-only process never proposes enforce mode, default-deny or a lockdown, and
        refuses to confirm one found in the store (``watch_only``).
        """
        with self._lock:
            record = self._store.get_pending_change(change_id)
            if record is not None and record.kind in _ENFORCING_CHANGES:
                self._refuse_if_watch_only()
            if record is not None and record.kind == CHANGE_LOCKDOWN:
                self._lockdown.confirm(change_id, actor=actor, channel=channel)
                return record
            confirmed = self._confirmations.confirm(change_id, actor=actor, channel=channel)
            self._refresh_status()
            return confirmed

    def cancel_change(self, change_id: str, *, actor: str) -> bool:
        """Roll a pending change back now."""
        with self._lock:
            done = self._confirmations.cancel(change_id, actor=actor)
            self._refresh_status()
            return done

    def update_settings(self, changes: Mapping[str, Any], *, actor: str) -> Applied[SettingsView]:
        """Change ``protected_fingerprints``, ``scan.enabled`` or ``lockdown.default_minutes``.

        Raises:
            ServiceError: ``invalid_request``, ``unknown_device``.
        """
        allowed = {"protected_fingerprints", "scan.enabled", "lockdown.default_minutes"}
        unknown = set(changes) - allowed
        if unknown or not changes:
            raise ServiceError(
                f"only {sorted(allowed)} can be changed here", code="invalid_request"
            )
        with self._lock:
            for key, value in changes.items():
                self._check_setting(key, value)
            for key, value in changes.items():
                old = self._settings.get(key)
                self._write_setting(key, value, actor=actor)
                self._audit(
                    ev.CONFIG_CHANGED, actor=actor, data={"key": key, "old": old, "new": value}
                )
            self._rebuild_context()
            self._publish("settings.changed", {"runtime": self.get_settings().runtime})
            summary = self.reconcile("settings")
            return Applied(self.get_settings(), summary=summary)

    def verify_audit(
        self,
        *,
        start_seq: int = 1,
        expected_head: tuple[int, str] | None = None,
        actor: str,
    ) -> VerifyResult:
        """Walk the audit chain and audit the outcome."""
        result = self._audit.log.verify(start_seq=start_seq, expected_head=expected_head)
        with self._lock:
            self._audit_verification(result, scope="full", actor=actor)
        return result

    # =====================================================================================
    # reconcile
    # =====================================================================================

    def reconcile(self, trigger: str) -> ReconcileSummary:
        """Re-evaluate every connection and converge the operating system onto it.

        Default-deny is applied first (nothing new slips in while devices are processed)
        and released last (restoring PortLock's own records, never "turning it off").
        """
        with self._lock:
            released_before = self._released
            self._converge_global(restricting=True)
            evaluated = changed = blocked = read_only = failed = 0
            for conn in list(self._conns.values()):
                if conn.instance_id not in self._conns:
                    continue
                evaluated += 1
                if self._reevaluate(conn, trigger):
                    changed += 1
                enforcement = conn.enforcement
                if enforcement is not None:
                    if enforcement.os_state == _BLOCKED:
                        blocked += 1
                    elif enforcement.os_state == _READ_ONLY:
                        read_only += 1
                    if enforcement.outcome in (Outcome.FAILED, Outcome.UNSUPPORTED):
                        failed += 1
            self._evaluate_orphans()
            self._converge_global(restricting=False)
            self._refresh_status()
            return ReconcileSummary(
                evaluated=evaluated,
                changed=changed,
                blocked=blocked,
                read_only=read_only,
                released=self._released - released_before,
                failed=failed,
            )

    # =====================================================================================
    # internals: start-up
    # =====================================================================================

    def _start_backend(self) -> None:
        try:
            self._backend.start(self.on_backend_event)
        except BackendError as exc:
            # Detection degrades to the 30-second resync.
            self._mark_degraded("backend", str(exc))
            _LOG.error("the device backend could not start: %s", exc)

    def _enumerate_at_start(self) -> list[UsbDevice]:
        for attempt in range(_ENUMERATE_ATTEMPTS):
            try:
                devices = self._backend.enumerate()
            except BackendError as exc:
                _LOG.error("enumeration failed (attempt %d): %s", attempt + 1, exc)
                last = str(exc)
                continue
            self._clear_degraded("backend")
            return list(devices)
        self._mark_degraded("backend", last)
        self._backend_down_since = self._clock.monotonic()
        self._alert("error", "devices cannot be listed", last)
        return []

    def _probe_system_ids(self, devices: Sequence[UsbDevice]) -> frozenset[str]:
        try:
            return frozenset(self._system_ids_probe(devices))
        except Exception as exc:
            # DESIGN D18: if the system volume cannot be traced, every storage device
            # present now is protected; one that arrives later cannot be backing it.
            _LOG.error("the system volume could not be traced: %s", exc)
            self._system_ids_note = f"{type(exc).__name__}: {exc}"
            return frozenset(device.instance_id for device in devices if device.is_storage)

    def _settle_grants_at_start(
        self, devices: Sequence[UsbDevice], fingerprints: Mapping[str, Fingerprint]
    ) -> int:
        spent: list[Grant] = []
        try:
            spent.extend(self._grants.release_absent(devices))
            for grant in self._grants.list():
                if grant.bound_connection is None:
                    continue
                for device in devices:
                    if (
                        connection_key(device) == grant.bound_connection
                        and fingerprints[device.instance_id].value != grant.fingerprint
                    ):
                        spent.extend(self._grants.release(device))
        except (StoreError, GrantError) as exc:
            self._mark_degraded("store", str(exc))
        for grant in spent:
            self._audit_grant_expired(grant, reason="service_restart")
        expired = self._safe(lambda: self._grants.expire_due(self._now()), [])
        for grant in expired:
            self._audit_grant_expired(grant, reason="expired")
        return len(spent) + len(expired)

    def _journal_hygiene(self, fingerprints: Mapping[str, Fingerprint]) -> tuple[int, int]:
        records = self._journal.open_records()
        discarded = 0
        scopes = {record.scope for record in records if record.scope != GLOBAL_SCOPE}
        for scope in scopes:
            present = fingerprints.get(scope)
            stale = present is None or any(
                record.fingerprint is not None and record.fingerprint != present.value
                for record in records
                if record.scope == scope
            )
            if stale:
                reason = "device absent at start" if present is None else "another device at start"
                try:
                    discarded += len(self._journal.discard_volatile(scope, reason=reason))
                except StoreError as exc:
                    self._mark_degraded("journal", str(exc))
        return len(records), discarded

    def _start_reconcile(self, devices: Sequence[UsbDevice]) -> ReconcileSummary:
        released_before = self._released
        self._converge_global(restricting=True)
        for device in devices:
            try:
                self._on_arrival(device, present_at_start=True)
            except Exception as exc:
                _LOG.error("evaluating %s at start failed", device.instance_id, exc_info=exc)
        self._evaluate_orphans()
        self._converge_global(restricting=False)
        conns = list(self._conns.values())
        return ReconcileSummary(
            evaluated=len(conns),
            changed=len(conns),
            blocked=sum(1 for c in conns if c.enforcement and c.enforcement.os_state == _BLOCKED),
            read_only=sum(
                1 for c in conns if c.enforcement and c.enforcement.os_state == _READ_ONLY
            ),
            released=self._released - released_before,
            failed=sum(
                1 for c in conns if c.enforcement and c.enforcement.outcome in _NOT_ENFORCED
            ),
        )

    def _start_threads(self) -> None:
        pipeline = threading.Thread(
            target=self._pipeline_loop, name="portlock-pipeline", daemon=True
        )
        self._threads.append(pipeline)
        pipeline.start()
        if self._scanner is not None:
            self._scan_threaded = True
            self._spawn_scan_thread()

    def _pipeline_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._events.get(timeout=0.25)
            except queue.Empty:
                continue
            self.handle_event(event)

    def _audit_recover_marker(self, marker: Mapping[str, Any]) -> None:
        if marker.get("invalid"):
            data: dict[str, Any] = {"reason": "recover", "invalid_marker": True}
        else:
            data = dict(marker.get("report") or {})
            data["recovered_at"] = (
                _iso(marker.get("at")) if isinstance(marker.get("at"), datetime) else None
            )
        self._audit(ev.RECOVERY_RESTORED, actor=_LOCAL_CONSOLE, data=data)

    def _verify_audit_tail(self) -> None:
        try:
            head, _ = self._audit.log.head()
        except (StoreError, AuditError) as exc:
            self._mark_degraded("audit_chain", str(exc))
            return
        start = max(1, head - _TAIL_VERIFY_RECORDS + 1)
        result = self._audit.log.verify(start_seq=start)
        self._audit_verification(result, scope="tail", actor=_SYSTEM)

    def _audit_verification(self, result: VerifyResult, *, scope: str, actor: str) -> None:
        data = {
            "scope": scope,
            "checked": result.checked,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
            "macs_checked": result.macs_checked,
            "head_checked": result.head_checked,
        }
        if result.ok:
            self._clear_degraded("audit_chain")
            self._audit(ev.AUDIT_VERIFIED, actor=actor, data=data)
        else:
            self._mark_degraded("audit_chain", result.reason or "the audit chain does not verify")
            self._audit(
                ev.AUDIT_VERIFICATION_FAILED, severity=Severity.CRITICAL, actor=actor, data=data
            )
            self._alert("critical", "the audit log does not verify", result.reason or "")

    def _cancel_stale_scans(self) -> None:
        try:
            for record in self._store.list_scans(limit=500):
                if record.state in ("queued", "running"):
                    self._store.update_scan(
                        record.id, state="cancelled", finished_at=self._clock.now()
                    )
        except StoreError as exc:
            self._mark_degraded("store", str(exc))

    # =====================================================================================
    # internals: policy
    # =====================================================================================

    def _load_policy_at_start(self) -> None:
        path = self._policy_path
        if path is None or not path.exists():
            self._activate_policy(DEFAULT_POLICY, source="default")
            self._policy_stamp = self._stat_policy()
            return
        self._policy_stamp = self._stat_policy()
        try:
            policy = load_policy_file(path)
        except (PolicyError, StoreError) as exc:
            problems = tuple(getattr(exc, "problems", ()) or (str(exc),))
            self._audit(
                ev.POLICY_INVALID,
                actor=_SYSTEM,
                data={"problems": list(problems[:_MAX_PROBLEMS_AUDITED]), "source": "file"},
            )
            last_good = self._settings.get("policy.last_good")
            if isinstance(last_good, dict):
                try:
                    self._activate_policy(parse_policy(last_good["policy"]), source="last_good")
                    return
                except (PolicyError, KeyError, TypeError) as inner:
                    _LOG.error("the last good policy is unusable: %s", inner)
            self._activate_policy(DEFAULT_POLICY, source="default")
            return
        self._activate_policy(policy, source="file")

    def _activate_policy(self, policy: Policy, *, source: str) -> None:
        digest = policy_hash(policy)
        self._loaded = _Loaded(policy, PolicyEngine(policy), digest, source, self._clock.now())
        if source == "file":
            value = {"hash": digest, "policy": policy_to_dict(policy)}
            if self._settings.get("policy.last_good", {}).get("hash") != digest:
                self._write_setting("policy.last_good", value, actor=_SYSTEM)

    def _audit_policy_changed(self, previous: str, actor: str) -> None:
        loaded = self._loaded
        self._audit(
            ev.POLICY_CHANGED,
            actor=actor,
            data={
                "old_hash": previous,
                "new_hash": loaded.hash,
                "name": loaded.policy.name,
                "rules": len(loaded.policy.rules),
                "source": loaded.source,
            },
        )
        self._publish(
            "policy.changed",
            {
                "hash": loaded.hash,
                "previous_hash": previous,
                "name": loaded.policy.name,
                "rules": len(loaded.policy.rules),
            },
        )

    def _stat_policy(self) -> tuple[int, int] | None:
        if self._policy_path is None:
            return None
        try:
            info = self._policy_path.stat()
        except OSError:
            return None
        return (info.st_mtime_ns, info.st_size)

    def _check_policy_file(self) -> None:
        """Re-read the policy file if it changed underneath the service."""
        stamp = self._stat_policy()
        if stamp == self._policy_stamp:
            return
        self._policy_stamp = stamp
        if stamp is None or self._policy_path is None:
            return  # Deleting the file does not change the policy in force.
        try:
            policy = load_policy_file(self._policy_path)
        except (PolicyError, StoreError) as exc:
            problems = tuple(getattr(exc, "problems", ()) or (str(exc),))
            self._audit(
                ev.POLICY_INVALID,
                actor=_SYSTEM,
                data={
                    "problems": list(problems[:_MAX_PROBLEMS_AUDITED]),
                    "source": "file",
                    "kept": self._loaded.hash,
                },
            )
            self._alert("warning", "the policy file changed and is invalid", problems[0])
            return
        digest = policy_hash(policy)
        if digest == self._loaded.hash:
            return
        previous = self._loaded.hash
        self._activate_policy(policy, source="file")
        self._audit_policy_changed(previous, _SYSTEM)
        self.reconcile("policy")

    # =====================================================================================
    # internals: settings, context, mode
    # =====================================================================================

    def _load_settings(self) -> None:
        try:
            self._settings = self._store.settings()
            self._data_version = self._read_data_version()
            self._clear_degraded("store")
        except StoreError as exc:
            self._mark_degraded("store", str(exc))

    def _read_data_version(self) -> int | None:
        row = self._store.db.query_one("PRAGMA data_version")
        return int(row[0]) if row is not None else None

    def _write_setting(self, key: str, value: Any, *, actor: str) -> None:
        self._store.set_setting(key, value, by=actor)
        self._settings[key] = value

    def _check_setting(self, key: str, value: Any) -> None:
        if key == "protected_fingerprints":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ServiceError(
                    "protected_fingerprints is a list of fingerprints", code="invalid_request"
                )
            if len(set(value)) != len(value):
                raise ServiceError(
                    "protected_fingerprints repeats a fingerprint", code="invalid_request"
                )
            for item in value:
                if self._store.get_device(item) is None:
                    raise ServiceError(f"{item} has never been seen", code="unknown_device")
        elif key == "scan.enabled":
            if not isinstance(value, bool):
                raise ServiceError("scan.enabled is true or false", code="invalid_request")
        elif key == "lockdown.default_minutes" and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= self._config.lockdown.max_minutes
        ):
            raise ServiceError(
                f"lockdown.default_minutes is 1 to {self._config.lockdown.max_minutes}",
                code="invalid_request",
            )

    def _scope(self) -> str:
        value = self._settings.get("scope")
        return value if value in SCOPES else self._config.scope

    def _write_scope(self, scope: str | None, *, actor: str) -> None:
        old = self._scope()
        if scope is None:
            self._store.delete_setting("scope")
            self._settings.pop("scope", None)
        else:
            self._write_setting("scope", scope, actor=actor)
        self._audit(
            ev.CONFIG_CHANGED, actor=actor, data={"key": "scope", "old": old, "new": self._scope()}
        )
        self._rebuild_context()

    def _default_lockdown_minutes(self) -> int:
        value = self._settings.get("lockdown.default_minutes")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return self._config.lockdown.default_minutes

    def _rebuild_context(self) -> None:
        """Replace the safety context (enrolments, pins, scope) atomically."""
        try:
            enrolled = self._store.enrolled_pairs()
        except StoreError as exc:
            # Keep the last good context: it is the best knowledge there is.
            self._mark_degraded("store", str(exc))
            enrolled = self._context.enrolled
        pinned = self._settings.get("protected_fingerprints", [])
        self._context = SafetyContext(
            enrolled=enrolled,
            pinned_fingerprints=frozenset(pinned if isinstance(pinned, list) else []),
            system_instance_ids=self._system_ids,
            hid_enforcement_enabled=self._config.hid_enforcement_enabled,
            scope=self._scope(),
        )

    def _safety_context(self) -> SafetyContext:
        return self._context

    def _chosen_mode(self) -> tuple[Mode, str]:
        value = self._settings.get("mode")
        if value in (Mode.MONITOR.value, Mode.ENFORCE.value):
            return Mode(value), "setting"
        return self._config.mode, "config"

    def _watch_only(self) -> bool:
        return self._watch_only_reason is not None

    def _refuse_if_watch_only(self) -> None:
        """DESIGN 14.28: a watch-only process refuses everything that would block."""
        if self._watch_only_reason is not None:
            raise ServiceError(self._watch_only_reason, code="watch_only")

    def _effective_mode(self) -> Mode:
        if self._killswitch_latched or self._watch_only():
            return Mode.MONITOR
        mode, _ = self._chosen_mode()
        if mode is Mode.ENFORCE and self._privacy_problems:
            # DESIGN 14.18: enforce mode is refused while the directories are not private.
            return Mode.MONITOR
        return mode

    def _mode_info(self) -> ModeInfo:
        mode, source = self._chosen_mode()
        notes: list[str] = []
        reason = self._watch_only_reason
        if reason is not None:
            notes.extend((reason, _NO_ANTIVIRUS_NOTE))
            can = False
        else:
            caps = self._live.capabilities()
            can = caps.privileged and caps.block and not self._privacy_problems
            if not caps.privileged or not caps.block:
                notes.extend(caps.notes or ("The enforcer cannot block devices here.",))
        notes.extend(self._privacy_problems)
        if self._killswitch_latched:
            source = "killswitch"
            notes.append("The kill switch disabled enforcement.")
        return ModeInfo(
            mode=mode,
            effective_mode=self._effective_mode(),
            source=source,
            killswitch=self._killswitch_latched,
            can_enforce=can and not self._killswitch_latched,
            # The console shows each note as a sentence of its own.
            notes=tuple(_sentence(note) for note in notes),
            watch_only=reason is not None,
            watch_only_reason=reason,
        )

    def _write_mode(self, mode: Mode, *, actor: str, reason: str) -> None:
        old = self._chosen_mode()[0]
        try:
            self._write_setting("mode", mode.value, actor=actor)
        except StoreError as exc:
            self._mark_degraded("store", str(exc))
            self._settings["mode"] = mode.value
        if old is not mode:
            self._audit(
                ev.MODE_CHANGED,
                actor=actor,
                data={"old": old.value, "new": mode.value, "reason": reason},
            )
        self._publish("mode.changed", {"mode": self._mode_info().to_dict()})

    def _check_privacy(self) -> None:
        if self._watch_only():
            # DESIGN 14.28: watch-only neither checks nor changes permissions (its
            # directory-privacy seam is an inert stand-in), and it never enforces, so
            # there is nothing a private directory would allow. The doctor says so.
            self._privacy_problems = ()
            return
        problems: list[str] = []
        for label, path in (
            ("state", self._config.paths.state_dir),
            ("configuration", self._config.paths.config_dir),
        ):
            try:
                self._dir_privacy.ensure_private(path)
            except (EnforcementError, OSError) as exc:
                problems.append(f"the {label} directory cannot be made private: {exc}")
                continue
            try:
                report = self._dir_privacy.check(path)
                if not report.private:
                    detail = "; ".join(tuple(report.problems)[:3])
                    problems.append(f"the {label} directory is not private: {detail}")
            except Exception as exc:
                problems.append(f"the {label} directory could not be checked: {exc}")
        self._privacy_problems = tuple(problems)
        if problems:
            self._alert("critical", "enforce mode refused", "; ".join(problems))

    # =====================================================================================
    # internals: device events
    # =====================================================================================

    def _on_arrival(
        self, device: UsbDevice, *, present_at_start: bool, synthesized: bool = False
    ) -> _Conn | None:
        existing = self._conns.get(device.instance_id)
        if existing is not None:
            if existing.device.connection_id == device.connection_id:
                # The backend reported this connection twice (start-then-enumerate).
                if existing.device != device:
                    self._on_changed(device)
                return existing
            self._on_removed(existing.device, reason="resync", synthesized=True)
        fp = compute_fingerprint(device)
        now = self._clock.now()
        connected_at = now
        if present_at_start:
            token, since = self._previous_connected.pop(device.instance_id, (None, now))
            # The same connection as the previous run's (the backend's token still matches),
            # so it has been here since `since`, not since this start. Without a token
            # nothing proves it is the same device: it counts as new.
            if token is not None and token == device.connection_id and since <= now:
                connected_at = since
        if not present_at_start:
            try:
                self._journal.discard_volatile(device.instance_id, reason="new connection")
            except StoreError as exc:
                self._mark_degraded("journal", str(exc))
        flap = None if present_at_start else self._flap.record_arrival(device.bus_path)
        conn = _Conn(
            device=device,
            fp=fp,
            id=None,
            run_id=self.run_id,
            present_at_start=present_at_start,
            connected_at=connected_at,
            storage_id=storage_identity(device),
        )
        conn.arrived_under_deny = not present_at_start and self._default_deny_on()
        try:
            record = self._store.open_connection(
                device,
                fp,
                run_id=self.run_id,
                present_at_start=present_at_start,
                connected_at=connected_at,
                storage_identity=conn.storage_id,
            )
            conn.id = record.id
            known = self._store.get_device(fp.value)
            if known is not None:
                conn.first_seen = known.first_seen
                conn.connection_count = known.connection_count
            self._clear_degraded("store")
        except StoreError as exc:
            # DESIGN 14.10: the device is still decided and enforced without its row.
            self._mark_degraded("store", str(exc))
        self._conns[device.instance_id] = conn
        coalesced = flap is not None and not flap.audit
        if flap is not None and flap.held:
            conn.held = True
            if flap.newly_held:
                self._audit(
                    ev.SAFETY_PORT_HELD,
                    severity=Severity.WARNING,
                    actor=_SYSTEM,
                    device_fp=fp.value,
                    data={
                        "connection_id": conn.id,
                        "port": device.bus_path,
                        "arrivals": flap.arrivals,
                        "window_seconds": int(self._flap.window_seconds),
                        "cooldown_seconds": int(self._flap.cooldown_seconds),
                    },
                )
                self._alert(
                    "warning",
                    "a port is held",
                    f"port {device.bus_path} re-enumerated {flap.arrivals} times; it is held",
                    conn=conn,
                )
        if not coalesced:
            self._audit(
                ev.DEVICE_CONNECTED,
                actor=_SYSTEM,
                device_fp=fp.value,
                data={
                    "connection_id": conn.id,
                    "device": _audit_device(device),
                    "present_at_start": present_at_start,
                    "confidence": Confidence(fp.confidence).value,
                    "storage_identity": conn.storage_id,
                    "synthesized": synthesized,
                },
            )
        self._publish_connection("device.connected", self._live_view(conn))
        self._audit_suspicious(conn)
        self._detect_clone(conn)
        self._reevaluate(conn, "start" if present_at_start else "arrival")
        return conn

    def _audit_suspicious(self, conn: _Conn) -> None:
        device = conn.device
        if device.mixes_input_with_other:
            reason = "storage_with_input" if device.pairs_storage_with_input else "input_with_other"
            severity = Severity.WARNING
        elif device.is_hid and not conn.present_at_start:
            reason, severity = "new_input_device", Severity.NOTICE
        else:
            return
        self._audit(
            ev.SAFETY_SUSPICIOUS_DEVICE,
            severity=severity,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={
                "connection_id": conn.id,
                "reason": reason,
                "present_at_start": conn.present_at_start,
            },
        )
        if severity is Severity.WARNING:
            self._alert("warning", "a device mixes input with another function", reason, conn=conn)

    def _detect_clone(self, conn: _Conn) -> None:
        context = self._context
        others = [(c.device, c.fp) for c in self._conns.values() if c is not conn]
        duplicates = detect_clone(conn.device, conn.fp, others, context)
        if not duplicates:
            return
        group = [conn] + [
            self._conns[item.instance_id] for item in duplicates if item.instance_id in self._conns
        ]
        flagged: list[_Conn] = []
        if CODE_ENROLLED in self._live.protection(conn.device).codes:
            # The newcomer sits on the enrolled port: the others are the copies.
            flagged = [
                c for c in group[1:] if CODE_ENROLLED not in self._live.protection(c.device).codes
            ]
        else:
            flagged = [conn]
        for item in flagged:
            item.clone = True
        self._audit(
            ev.SAFETY_CLONE_DETECTED,
            severity=Severity.CRITICAL,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={
                "code": CODE_CLONE,
                "connection_id": conn.id,
                "denied": [item.id for item in flagged],
                "connections": [item.id for item in group],
                "ports": [item.device.bus_path for item in group],
            },
        )
        self._alert(
            "critical",
            "an enrolled fingerprint is presented twice",
            "a second device copies an enrolled device; the copy is denied",
            conn=conn,
        )
        for item in flagged:
            if item is not conn:
                self._reevaluate(item, "retry")

    def _on_changed(self, device: UsbDevice) -> None:
        conn = self._conns.get(device.instance_id)
        if conn is None or (
            conn.device.connection_id is not None
            and device.connection_id is not None
            and conn.device.connection_id != device.connection_id
        ):
            self._on_arrival(device, present_at_start=False, synthesized=True)
            return
        before = {(v.device_node, v.mount_point) for v in conn.device.volumes}
        after = {(v.device_node, v.mount_point) for v in device.volumes}
        conn.device = device
        conn.storage_id = storage_identity(device) or conn.storage_id
        if conn.id is not None:
            self._safe(
                lambda: (
                    self._store.record_sighting(device, conn.fp, storage_identity=conn.storage_id),
                    self._store.update_connection(conn.id, device=device),
                ),
                None,
            )
        self._audit(
            ev.DEVICE_CHANGED,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={
                "connection_id": conn.id,
                "volumes_added": [
                    {"device_node": node, "mount_point": mount}
                    for node, mount in sorted(after - before, key=str)
                ],
                "volumes_removed": [
                    {"device_node": node, "mount_point": mount}
                    for node, mount in sorted(before - after, key=str)
                ],
            },
        )
        self._reevaluate(conn, "changed")
        self._publish_connection("device.changed", self._live_view(conn))

    def _on_removed(self, device: UsbDevice, *, reason: str, synthesized: bool = False) -> None:
        conn = self._conns.get(device.instance_id)
        if conn is None:
            return
        if (
            conn.device.connection_id is not None
            and device.connection_id is not None
            and conn.device.connection_id != device.connection_id
        ):
            return  # A removal of a connection already replaced.
        del self._conns[device.instance_id]
        now = self._clock.now()
        for job in list(self._running_jobs.values()):
            if job.conn is conn:
                job.cancel.set()
        spent = self._safe(lambda: self._grants.release(conn.device), [])
        for grant in spent:
            self._audit_grant_expired(grant, reason="consumed")
        try:
            self._journal.discard_volatile(device.instance_id, reason="device removed")
        except StoreError as exc:
            self._mark_degraded("journal", str(exc))
        if conn.id is not None:
            self._safe(
                lambda: self._store.close_connection(conn.id, removed_at=now, reason=reason), None
            )
            self._live_views = {k: v for k, v in self._live_views.items() if k != conn.id}
        self._audit(
            ev.DEVICE_REMOVED,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={
                "connection_id": conn.id,
                "duration_seconds": max(0, int((now - conn.connected_at).total_seconds())),
                "state": conn.state.value,
                "synthesized": synthesized,
                "reason": reason,
            },
        )
        self._publish(
            "device.removed",
            {
                "connection_id": conn.id,
                "fingerprint": conn.fingerprint,
                "removed_at": utc_iso(now),
                "close_reason": reason,
            },
        )

    def _resync(self, *, reason: str) -> int:
        """Enumerate and compare with the open connections. Returns differences found."""
        try:
            devices = self._backend.enumerate()
        except BackendError as exc:
            if "backend" not in self._degraded:
                self._backend_down_since = self._clock.monotonic()
                self._alert("error", "devices cannot be listed", str(exc))
            self._mark_degraded("backend", str(exc))
            return 0
        if "backend" in self._degraded:
            outage = (
                int(self._clock.monotonic() - self._backend_down_since)
                if self._backend_down_since is not None
                else 0
            )
            self._clear_degraded("backend")
            self._audit(
                ev.SERVICE_RECOVERED,
                actor=_SYSTEM,
                data={"component": "backend", "outage_seconds": outage},
            )
        present = {device.instance_id: device for device in devices}
        missed = 0
        for instance_id, conn in list(self._conns.items()):
            device = present.get(instance_id)
            if device is None:
                missed += 1
                self._on_removed(conn.device, reason="resync", synthesized=True)
            elif device.connection_id != conn.device.connection_id:
                missed += 1
                self._on_removed(conn.device, reason="resync", synthesized=True)
                self._on_arrival(device, present_at_start=False, synthesized=True)
            elif device != conn.device:
                missed += 1
                self._on_changed(device)
        for instance_id, device in present.items():
            if instance_id not in self._conns:
                missed += 1
                self._on_arrival(device, present_at_start=False, synthesized=True)
        self._last_resync = self._clock.monotonic()
        if missed and reason == "periodic":
            self._resync_misses += 1
            if self._resync_misses >= 3:
                # The notification thread may have died: restart it once.
                self._resync_misses = 0
                with contextlib.suppress(Exception):
                    self._backend.stop()
                self._start_backend()
        elif reason == "periodic":
            self._resync_misses = 0
        return missed

    # =====================================================================================
    # internals: evaluation
    # =====================================================================================

    def _now(self) -> datetime:
        """The later of the clock and the newest audit record (DESIGN 14.12)."""
        now = self._clock.now()
        newest = self._audit.newest_timestamp
        return newest if newest is not None and newest > now else now

    def _decide(self, conn: _Conn, verdict: ProtectionVerdict, now: datetime) -> Decision:
        device, fp = conn.device, conn.fp
        if conn.clone and CODE_ENROLLED not in verdict.codes:
            return Decision(
                access=Access.DENY,
                source=DecisionSource.DEFAULT,
                reasons=(
                    "a second device presents an enrolled fingerprint while the first is "
                    "connected; a fingerprint can be copied, so this one is denied",
                ),
                alert=True,
            )
        if conn.held and not verdict.protected:
            return Decision(
                access=Access.DENY,
                source=DecisionSource.DEFAULT,
                reasons=(
                    f"port {device.bus_path} is held: devices on it re-enumerated too often, "
                    "which replays the reactive window",
                ),
                alert=True,
            )
        loaded = self._loaded
        result = loaded.engine.evaluate(device, fp, now=now)
        grant = self._grants.active_for(fp.value, now=now, device=device)
        active = self._lockdown.active
        exempt = active and self._lockdown.is_exempt(device, connected_at=conn.connected_at)
        detection = self._scan_detection(conn, result, loaded.policy)
        return decide(
            device=device,
            fingerprint=fp,
            policy_result=result,
            grant=grant,
            protected=verdict.protected,
            protection_reasons=verdict.reasons,
            lockdown_active=active,
            lockdown_exempt=exempt,
            now=now,
            scan_detection=detection,
        )

    def _scan_detection(
        self, conn: _Conn, result: PolicyResult, policy: Policy
    ) -> ScanDetection | None:
        requirement = result.action.scan
        if requirement is ScanRequirement.NONE:
            return None
        verdict = conn.worst_verdict()
        if (
            verdict is None
            and requirement is ScanRequirement.REQUIRED
            and not self._scanning_available()
        ):
            # DESIGN 14.9: a required scan that cannot run never counts as clean.
            verdict = ScanVerdict.ERROR
        scan_policy = policy.scan
        if self._config.fail_closed and requirement is ScanRequirement.REQUIRED:
            scan_policy = ScanPolicy(scan_policy.on_detection, IncompleteAction.DENY)
        return scan_detection_for(verdict, requirement=requirement, scan_policy=scan_policy)

    def _failure_decision(self, verdict: ProtectionVerdict, exc: Exception) -> Decision:
        reason = f"evaluation failed ({type(exc).__name__}: {exc})"
        if verdict.protected:
            return Decision(
                Access.ALLOW,
                DecisionSource.SAFETY,
                reasons=(*verdict.reasons, reason),
                alert=True,
            )
        if self._config.fail_closed:
            return Decision(
                Access.DENY,
                DecisionSource.DEFAULT,
                reasons=(reason, "denied because fail_closed is set"),
                alert=True,
            )
        # DESIGN 14.10: a device that cannot be evaluated is pending (blocked in enforce).
        return Decision(
            Access.PENDING,
            DecisionSource.DEFAULT,
            reasons=(reason, "treated as pending"),
            alert=True,
        )

    def _desired(self, conn: _Conn, decision: Decision) -> tuple[str, str | None]:
        if self._killswitch_latched:
            return _OPEN, None
        target = _target_of(decision, conn.scan_state)
        if target == _OPEN:
            return _OPEN, None
        if self._watch_only():
            # Watch-only: even a lockdown's decision is only what PortLock *would* do.
            return _OPEN, target
        if self._effective_mode() is Mode.ENFORCE or decision.source is DecisionSource.LOCKDOWN:
            return target, None
        return _OPEN, target

    def _reevaluate(self, conn: _Conn, trigger: str) -> bool:
        """Decide, converge, store, audit. Returns True if anything changed."""
        if conn.instance_id not in self._conns:
            return False
        now = self._now()
        verdict = self._live.protection(conn.device)
        failure: Exception | None = None
        try:
            decision = self._decide(conn, verdict, now)
        except Exception as exc:
            _LOG.error("evaluating %s failed", conn.instance_id, exc_info=exc)
            failure = exc
            decision = self._failure_decision(verdict, exc)
        desired = self._desired(conn, decision)
        decision_changed = decision != conn.decision
        failed_before = conn.enforcement is not None and conn.enforcement.outcome is Outcome.FAILED
        # A failed enforcement is retried by reconciliations and the 30-second retry, not
        # by every tick that happens to look at the connection.
        retry = failed_before and trigger not in ("periodic", "expiry", "scan", "grant")
        if (
            not decision_changed
            and desired == conn.desired
            and trigger not in _ALWAYS_CONVERGE
            and not retry
            and conn.verdict == verdict
        ):
            return False
        conn.verdict = verdict
        enforcement = self._converge(conn, decision, desired, verdict)
        conn.decision = decision
        conn.desired = desired
        conn.enforcement = enforcement
        conn.provisional = (
            decision.access is Access.ALLOW
            and decision.scan is ScanRequirement.REQUIRED
            and conn.scan_state is not ScanState.CLEAN
            and decision.source is not DecisionSource.SAFETY
        )
        conn.state = _state_for(decision, conn.resolution)
        if decision_changed or failure is not None:
            conn.decided_at = self._clock.now()
            conn.trigger = trigger
            conn.policy_hash = self._loaded.hash
            conn.mode = self._effective_mode()
        self._store_decision(conn, decision_changed or conn.decision_id is None)
        self._use_grant(conn, decision)
        if decision_changed or failure is not None:
            severity = (
                Severity.WARNING if decision.alert or decision.access is Access.DENY else None
            )
            self._audit(
                ev.DECISION_MADE,
                severity=severity,
                actor=_SYSTEM,
                device_fp=conn.fingerprint,
                data={
                    "connection_id": conn.id,
                    "decision": decision.to_dict(),
                    "trigger": trigger,
                    "policy_hash": conn.policy_hash,
                    "mode": conn.mode.value,
                    "protection_codes": list(verdict.codes),
                    "in_scope": verdict.in_scope,
                    "enforcement": enforcement.to_dict(),
                    **dict(enforcement.extra),
                },
            )
        if failure is not None:
            self._audit(
                ev.ENFORCEMENT_FAILED,
                actor=_SYSTEM,
                device_fp=conn.fingerprint,
                data={
                    "connection_id": conn.id,
                    "action": "evaluate",
                    "error": f"evaluation failed: {type(failure).__name__}: {failure}",
                    "cause": decision.source.value,
                },
            )
        view = self._live_view(conn)
        self._publish_connection("decision.made", view)
        if (decision_changed and decision.alert) or enforcement.outcome is Outcome.FAILED:
            self._alert(
                "warning",
                "a device needs attention",
                "; ".join(decision.reasons[:2]) or enforcement.error or "",
                conn=conn,
            )
        self._schedule_scans(conn)
        return True

    def _store_decision(self, conn: _Conn, new_row: bool) -> None:
        if conn.id is None or conn.decision is None:
            return
        enforcement = conn.enforcement
        try:
            if new_row:
                record = self._store.add_decision(
                    conn.id,
                    conn.decision,
                    trigger=conn.trigger,
                    policy_hash=conn.policy_hash or self._loaded.hash,
                    mode=conn.mode,
                    decided_at=conn.decided_at or self._clock.now(),
                )
                conn.decision_id = record.id
            if enforcement is not None and conn.decision_id is not None:
                self._store.set_outcome(
                    conn.decision_id,
                    outcome=enforcement.outcome,
                    mechanism=enforcement.mechanism,
                    tier=enforcement.tier,
                    detail=enforcement.detail,
                    error=enforcement.error,
                    enforced_at=enforcement.at or self._clock.now(),
                )
            self._store.update_connection(
                conn.id,
                state=conn.state,
                provisional=conn.provisional,
                scan_state=conn.scan_state,
            )
            self._clear_degraded("store")
        except StoreError as exc:
            self._mark_degraded("store", str(exc))

    def _use_grant(self, conn: _Conn, decision: Decision) -> None:
        grant_id = decision.grant_id
        if grant_id is None or grant_id in conn.used_grants:
            return
        conn.used_grants.add(grant_id)
        try:
            grant = self._grants.get(grant_id)
            if grant.kind is GrantKind.ONCE:
                grant = self._grants.bind(grant_id, conn.device)
        except (GrantError, StoreError) as exc:
            _LOG.error("grant %s could not be bound: %s", grant_id, exc)
            return
        self._audit(
            ev.GRANT_USED,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={"grant_id": grant.id, "kind": grant.kind.value, "connection_id": conn.id},
        )
        self._publish("grant.changed", {"change": "used", "grant": grant.to_dict()})

    def _reevaluate_fingerprint(self, fingerprint: str, trigger: str) -> tuple[int, ...]:
        touched: list[int] = []
        for conn in list(self._conns.values()):
            if conn.fingerprint == fingerprint:
                self._reevaluate(conn, trigger)
                if conn.id is not None:
                    touched.append(conn.id)
        return tuple(touched)

    # =====================================================================================
    # internals: convergence
    # =====================================================================================

    def _caps(self) -> Any:
        return self._live.capabilities()

    def _blocked_by_us(self, instance_id: str) -> bool:
        return self._journal.has_open(scope=instance_id, actions={Action.BLOCK})

    def _default_deny_on(self) -> bool:
        return self._journal.has_open(scope=GLOBAL_SCOPE, actions={Action.DEFAULT_DENY_ON})

    def _held_back_ids(self) -> frozenset[str]:
        """Instance ids of the connected devices that arrived under default-deny and wait."""
        return frozenset(c.instance_id for c in self._conns.values() if c.arrived_under_deny)

    def _holds_back(self, conn: _Conn) -> bool:
        """True if PortLock itself keeps this device unauthorized, so only it can admit it.

        That is the case when PortLock blocked the device, or when it arrived under
        default-deny and was not admitted yet. A device that someone else disabled (the
        user in Device Manager, an administrator, USBGuard) is none of PortLock's
        business: admitting it would undo their decision and leave no record.
        """
        return self._blocked_by_us(conn.instance_id) or conn.arrived_under_deny

    def _call(
        self,
        scope: str,
        action: Action,
        fingerprint: str | None,
        fn: Callable[[], EnforcementResult],
    ) -> EnforcementResult:
        """One enforcer call bracketed by the journal (write-ahead, then settle)."""
        try:
            with self._journal.recording(scope=scope, action=action, fingerprint=fingerprint):
                result = fn()
                try:
                    self._journal.record(result)
                except StoreError as exc:
                    self._mark_degraded("journal", str(exc))
        except StoreError as exc:
            self._mark_degraded("journal", str(exc))
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism="journal",
                detail=f"{action.value} was not attempted: the journal cannot record it",
                error=f"journal unavailable: {exc}",
            )
        if result.error and result.error.startswith("journal unavailable"):
            self._mark_degraded("journal", result.error)
        return result

    def _converge(
        self,
        conn: _Conn,
        decision: Decision,
        desired: tuple[str, str | None],
        verdict: ProtectionVerdict,
    ) -> EnforcementView:
        want, would = desired
        cause = decision.source.value
        if want == _BLOCKED:
            return self._apply_blocked(conn, verdict, cause)
        if want == _READ_ONLY:
            return self._apply_read_only(conn, verdict, cause)
        return self._apply_open(conn, verdict, cause, would)

    def _not_restrictable(
        self, conn: _Conn, action: Action, verdict: ProtectionVerdict, cause: str
    ) -> EnforcementView | None:
        """The outcome when a restriction must not or cannot reach the OS, else None.

        A device the safety layer protects, or one outside the scope, must not stay
        restricted by PortLock either: whatever PortLock itself restricted earlier (a
        narrower scope now, a pin added, default-deny holding it back) is released.
        """
        now = self._clock.now()
        if verdict.protected or not verdict.in_scope:
            self._release_ours(conn, cause)
        if verdict.protected:
            result = EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_REFUSED,
                detail=f"not attempted: the device is protected ({'; '.join(verdict.reasons)})",
                error=f"protected device ({', '.join(verdict.codes)})",
            )
            self._record_result(conn, action, result, cause=cause)
            return _result_enforcement(Outcome.REFUSED, _OPEN, result, now)
        if not verdict.in_scope:
            result = EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_OUT_OF_SCOPE,
                detail=f"not enforced: {verdict.scope_reason}",
                error=f"out_of_scope: {verdict.scope_reason}",
            )
            self._record_result(conn, action, result, cause=cause)
            return _result_enforcement(Outcome.UNSUPPORTED, _OPEN, result, now)
        return None

    def _release_ours(self, conn: _Conn, cause: str) -> None:
        iid = conn.instance_id
        if self._journal.has_open(scope=iid, actions={Action.READ_ONLY}):
            self._release_read_only(conn, cause)
        if self._holds_back(conn):
            self._admit(conn, cause)

    def _apply_blocked(
        self, conn: _Conn, verdict: ProtectionVerdict, cause: str
    ) -> EnforcementView:
        device = conn.device
        stop = self._not_restrictable(conn, Action.BLOCK, verdict, cause)
        if stop is not None:
            return stop
        caps = self._caps()
        now = self._clock.now()
        if not caps.block:
            error = "unsupported: " + ("; ".join(caps.notes) or "this enforcer cannot block")
            result = EnforcementResult(Action.BLOCK, ok=False, mechanism="unsupported", error=error)
            self._record_result(conn, Action.BLOCK, result, cause=cause)
            return _result_enforcement(Outcome.UNSUPPORTED, _OPEN, result, now, error=error)
        extra: dict[str, Any] = {}
        if self._revocable(conn):
            outcome = self._revoke(conn, cause, caps)
            extra["revocation"] = outcome
            if outcome.get("clean"):
                return EnforcementView(
                    outcome=Outcome.APPLIED,
                    os_state=_BLOCKED,
                    mechanism=outcome.get("mechanism"),
                    tier=Tier.REACTIVE,
                    detail="revoked: made read-only and ejected cleanly; it is gone",
                    at=now,
                    extra=MappingProxyType(extra),
                )
        iid, fpv = device.instance_id, conn.fingerprint
        result = self._call(iid, Action.BLOCK, fpv, lambda: self._live.block(device))
        self._record_result(conn, Action.BLOCK, result, cause=cause, extra=extra)
        if not result.ok:
            return _result_enforcement(Outcome.FAILED, _OPEN, result, now, extra=extra)
        if result.performed and not self._blocked_by_us(iid):
            # Already unusable (default-deny, or a previous run): PortLock now owns
            # releasing it (ARCHITECTURE D4).
            try:
                self._journal.add_hold(scope=iid, fingerprint=fpv)
            except StoreError as exc:
                self._mark_degraded("journal", str(exc))
        return _result_enforcement(Outcome.APPLIED, _BLOCKED, result, now, extra=extra)

    def _revocable(self, conn: _Conn) -> bool:
        previous = conn.enforcement
        return (
            conn.decision is not None
            and conn.decision.permits_access
            and previous is not None
            and previous.os_state in (_OPEN, _READ_ONLY)
            and any(volume.mount_point for volume in conn.device.volumes)
        )

    def _revoke(self, conn: _Conn, cause: str, caps: Any) -> dict[str, Any]:
        """DESIGN 14.11: read-only first, then a clean eject, and only then a block."""
        device = conn.device
        iid, fpv = device.instance_id, conn.fingerprint
        report: dict[str, Any] = {
            "read_only": "unavailable",
            "eject": "unavailable",
            "clean": False,
        }
        if device.is_storage and caps.read_only:
            ro = self._call(
                iid, Action.READ_ONLY, fpv, lambda: self._live.set_read_only(device, True)
            )
            self._record_result(conn, Action.READ_ONLY, ro, cause=cause)
            report["read_only"] = "applied" if ro.ok else "failed"
        if caps.eject:
            ejected = self._live.eject(device)
            if ejected.ok and ejected.changed:
                report.update(eject="clean", clean=True, mechanism=ejected.mechanism)
            else:
                report["eject"] = "failed"
            self._record_result(
                conn, Action.EJECT, ejected, cause=cause, extra={"revocation": dict(report)}
            )
        return report

    def _apply_read_only(
        self, conn: _Conn, verdict: ProtectionVerdict, cause: str
    ) -> EnforcementView:
        device = conn.device
        stop = self._not_restrictable(conn, Action.READ_ONLY, verdict, cause)
        if stop is not None:
            return stop
        caps = self._caps()
        now = self._clock.now()
        if not device.is_storage:
            return self._cannot(conn, verdict, cause, "not a storage device", unsupported=True)
        if not caps.read_only:
            error = "unsupported: " + ("; ".join(caps.notes) or "no read-only mechanism")
            return self._cannot(conn, verdict, cause, error, unsupported=True)
        iid, fpv = device.instance_id, conn.fingerprint
        result = self._call(
            iid, Action.READ_ONLY, fpv, lambda: self._live.set_read_only(device, True)
        )
        self._record_result(conn, Action.READ_ONLY, result, cause=cause)
        if self._holds_back(conn):
            if not result.ok and self._config.fail_closed:
                return _result_enforcement(
                    Outcome.FAILED,
                    _BLOCKED,
                    result,
                    now,
                    detail="read-only could not be armed before admission; it stays blocked",
                )
            admitted = self._admit(conn, cause)
            if not admitted.ok:
                return _result_enforcement(Outcome.FAILED, _BLOCKED, admitted, now)
            if not result.ok:
                result = self._call(
                    iid, Action.READ_ONLY, fpv, lambda: self._live.set_read_only(device, True)
                )
                self._record_result(conn, Action.READ_ONLY, result, cause=cause)
        if result.ok:
            return _result_enforcement(Outcome.APPLIED, _READ_ONLY, result, now)
        return self._cannot(conn, verdict, cause, result.error or "read-only failed", result=result)

    def _cannot(
        self,
        conn: _Conn,
        verdict: ProtectionVerdict,
        cause: str,
        error: str,
        *,
        unsupported: bool = False,
        result: EnforcementResult | None = None,
    ) -> EnforcementView:
        """Read-only was decided but cannot be enforced (ARCHITECTURE 3.6.6, D16)."""
        if self._config.fail_closed:
            blocked = self._apply_blocked(conn, verdict, cause)
            return dataclasses.replace(
                blocked, detail="read-only unavailable; blocked because fail_closed is set"
            )
        if self._holds_back(conn):
            self._admit(conn, cause)
        if result is None:
            result = EnforcementResult(
                Action.READ_ONLY, ok=False, mechanism="unsupported", error=error
            )
            self._record_result(conn, Action.READ_ONLY, result, cause=cause)
        self._alert("warning", "read-only could not be enforced", error, conn=conn)
        return _result_enforcement(
            Outcome.UNSUPPORTED if unsupported else Outcome.FAILED,
            _OPEN,
            result,
            self._clock.now(),
            detail="read-only could not be enforced; the device is usable and writable",
            error=error,
        )

    def _apply_open(
        self, conn: _Conn, verdict: ProtectionVerdict, cause: str, would: str | None
    ) -> EnforcementView:
        device = conn.device
        iid, fpv = device.instance_id, conn.fingerprint
        now = self._clock.now()
        last: EnforcementResult | None = None
        failure: tuple[EnforcementResult, str] | None = None
        if self._journal.has_open(scope=iid, actions={Action.READ_ONLY}):
            released = self._release_read_only(conn, cause)
            last = released
            if not released.ok:
                failure = (released, _READ_ONLY)
        if self._baseline_active and device.is_storage and failure is None:
            freed = self._call(
                iid, Action.READ_WRITE, fpv, lambda: self._live.set_read_only(device, False)
            )
            self._record_result(conn, Action.READ_WRITE, freed, cause=cause)
            if freed.changed or not freed.ok:
                last = freed
        if self._holds_back(conn):
            admitted = self._admit(conn, cause)
            if admitted.changed or not admitted.ok:
                last = admitted
            if not admitted.ok:
                failure = (admitted, _BLOCKED)
        if failure is not None:
            return _result_enforcement(Outcome.FAILED, failure[1], failure[0], now)
        if would is not None:
            if would == _BLOCKED:
                dry = self._dry.block(device)
                action = Action.BLOCK
            else:
                dry = self._dry.set_read_only(device, True)
                action = Action.READ_ONLY
            self._record_result(conn, action, dry, cause=cause)
            return _result_enforcement(Outcome.WOULD_APPLY, _OPEN, dry, now, would=would)
        if last is not None and last.changed:
            return _result_enforcement(Outcome.APPLIED, _OPEN, last, now)
        return EnforcementView(outcome=Outcome.NOT_NEEDED, os_state=_OPEN, at=now)

    def _admit(self, conn: _Conn, cause: str) -> EnforcementResult:
        device = conn.device
        iid, fpv = device.instance_id, conn.fingerprint
        result = self._call(iid, Action.UNBLOCK, fpv, lambda: self._live.unblock(device))
        self._record_result(conn, Action.UNBLOCK, result, cause=cause)
        if not result.performed:
            # Failed, or a stand-in (dry-run, watch-only) that unblocked nothing: the device
            # is still held back, so PortLock must neither forget that nor close its record.
            return result
        conn.arrived_under_deny = False
        if result.changed:
            self._released += 1
        try:
            holds = [
                r.id
                for r in self._journal.open_records(scope=iid, actions={Action.BLOCK})
                if r.is_hold
            ]
            self._journal.close(holds, reason="released")
            for record in self._journal.open_records(scope=iid, actions={Action.BLOCK}):
                entry = record.entry
                if entry is None:
                    continue
                restored = self._call(
                    iid, Action.RESTORE, fpv, lambda e=entry: self._live.restore([e])
                )
                if restored.performed:
                    self._journal.close([record.id], reason="released")
        except StoreError as exc:
            self._mark_degraded("journal", str(exc))
        return result

    def _release_read_only(self, conn: _Conn, cause: str) -> EnforcementResult:
        device = conn.device
        iid, fpv = device.instance_id, conn.fingerprint
        result = self._call(
            iid, Action.READ_WRITE, fpv, lambda: self._live.set_read_only(device, False)
        )
        self._record_result(conn, Action.READ_WRITE, result, cause=cause)
        if not result.performed:
            # Failed, or a stand-in that made nothing writable: the records stay open.
            return result
        if result.changed:
            self._released += 1
        try:
            for record in self._journal.open_records(scope=iid, actions={Action.READ_ONLY}):
                entry = record.entry
                if entry is None:
                    continue
                restored = self._call(
                    iid, Action.RESTORE, fpv, lambda e=entry: self._live.restore([e])
                )
                if restored.performed:
                    self._journal.close([record.id], reason="released")
        except StoreError as exc:
            self._mark_degraded("journal", str(exc))
        return result

    def _want_default_deny(self) -> bool:
        if self._killswitch_latched:
            return False
        if self._lockdown.active:
            return True
        return bool(self._settings.get("default_deny")) and self._effective_mode() is Mode.ENFORCE

    def _want_baseline(self) -> bool:
        return (
            self._config.baseline_read_only
            and not self._killswitch_latched
            and self._effective_mode() is Mode.ENFORCE
        )

    def _converge_global(self, *, restricting: bool) -> None:
        caps = self._caps()
        if restricting:
            if self._want_default_deny():
                if caps.default_deny:
                    result = self._call(
                        GLOBAL_SCOPE,
                        Action.DEFAULT_DENY_ON,
                        None,
                        lambda: self._live.set_default_deny(True),
                    )
                else:
                    result = EnforcementResult(
                        Action.DEFAULT_DENY_ON,
                        ok=False,
                        mechanism="unsupported",
                        error="unsupported: "
                        + ("; ".join(caps.notes) or "no default-deny mechanism"),
                    )
                self._record_result(None, Action.DEFAULT_DENY_ON, result, cause="lockdown")
            if self._want_baseline() and not self._baseline_active:
                self._apply_baseline()
            return
        if not self._want_default_deny():
            self._restore_global({Action.DEFAULT_DENY_ON, Action.UNBLOCK}, cause="release")
        if not self._want_baseline():
            self._baseline_active = False
            wants_ro = any(
                conn.desired is not None and conn.desired[0] == _READ_ONLY
                for conn in self._conns.values()
            )
            if not wants_ro:
                self._restore_global({Action.READ_ONLY}, cause="release")

    def _apply_baseline(self) -> None:
        """DESIGN 14.14: the standing read-only baseline, where the safety layer offers it."""
        setter = getattr(self._live, "set_baseline_read_only", None)
        if not callable(setter):
            self._baseline_note = (
                "baseline_read_only is configured, but the safety layer offers no baseline "
                "read-only call yet; read-only stays per device and best effort"
            )
            return
        result = self._call(GLOBAL_SCOPE, Action.READ_ONLY, None, lambda: setter(True))
        self._record_result(None, Action.READ_ONLY, result, cause="baseline")
        self._baseline_active = bool(result.ok)
        self._baseline_note = "" if result.ok else (result.error or "baseline read-only failed")

    def _restore_global(self, actions: set[Action], *, cause: str) -> None:
        try:
            records = self._journal.open_records(scope=GLOBAL_SCOPE, actions=actions)
        except Exception as exc:
            _LOG.error("the journal cannot be read: %s", exc)
            return
        for record in records:
            entry = record.entry
            if entry is None:
                continue
            result = self._call(
                GLOBAL_SCOPE, Action.RESTORE, None, lambda e=entry: self._live.restore([e])
            )
            self._record_result(None, Action.RESTORE, result, cause=cause)
            if result.performed:
                try:
                    self._journal.close([record.id], reason="released")
                except StoreError as exc:
                    self._mark_degraded("journal", str(exc))
                if result.changed:
                    self._released += 1

    def _evaluate_orphans(self) -> None:
        """Release instance records whose device is not connected, if the decision allows."""
        try:
            records = self._journal.open_records()
        except Exception as exc:
            _LOG.error("the journal cannot be read: %s", exc)
            return
        by_scope: dict[str, list[Any]] = {}
        for record in records:
            if record.scope == GLOBAL_SCOPE or record.scope in self._conns:
                continue
            if record.entry is None or record.entry.kind in VOLATILE_KINDS:
                continue  # The OS forgot it when the device left; hygiene discards it.
            by_scope.setdefault(record.scope, []).append(record)
        for scope, items in by_scope.items():
            device = self._last_known(scope, items[0].fingerprint)
            release = self._killswitch_latched or self._effective_mode() is Mode.MONITOR
            if not release and device is not None:
                fp = compute_fingerprint(device)
                ghost = _Conn(
                    device=device,
                    fp=fp,
                    id=None,
                    run_id=self.run_id,
                    present_at_start=False,
                    connected_at=self._clock.now(),
                    storage_id=None,
                )
                verdict = self._live.protection(device)
                try:
                    decision = self._decide(ghost, verdict, self._now())
                except Exception as exc:
                    _LOG.error("evaluating orphan records of %s failed: %s", scope, exc)
                    continue
                release = self._desired(ghost, decision)[0] == _OPEN
            if not release:
                continue
            for record in items:
                entry = record.entry
                result = self._call(
                    scope,
                    Action.RESTORE,
                    record.fingerprint,
                    lambda e=entry: self._live.restore([e]),
                )
                self._record_result(
                    None,
                    Action.RESTORE,
                    result,
                    cause="orphan",
                    orphan=True,
                    fingerprint=record.fingerprint,
                )
                if result.performed:
                    try:
                        self._journal.close([record.id], reason="orphan released")
                    except StoreError as exc:
                        self._mark_degraded("journal", str(exc))

    def _last_known(self, instance_id: str, fingerprint: str | None) -> UsbDevice | None:
        if fingerprint is None:
            return None
        try:
            for record in self._store.list_connections(fingerprint=fingerprint, limit=50):
                if record.instance_id == instance_id:
                    return record.device
        except StoreError as exc:
            self._mark_degraded("store", str(exc))
        return None

    def _record_result(
        self,
        conn: _Conn | None,
        action: Action,
        result: EnforcementResult,
        *,
        cause: str,
        actor: str = _SYSTEM,
        extra: Mapping[str, Any] | None = None,
        orphan: bool = False,
        fingerprint: str | None = None,
    ) -> None:
        """Audit an enforcer result, once per change (ARCHITECTURE D26)."""
        if result.mechanism == MECHANISM_REFUSED:
            event, outcome = ev.ENFORCEMENT_REFUSED, "refused"
        elif result.mechanism == MECHANISM_DRY_RUN:
            event, outcome = ev.ENFORCEMENT_WOULD_APPLY, "would_apply"
        elif result.ok:
            event, outcome = ev.ENFORCEMENT_APPLIED, "applied"
        else:
            event, outcome = ev.ENFORCEMENT_FAILED, "failed"
        key = action.value
        if event == ev.ENFORCEMENT_FAILED:
            signature: tuple[str, ...] = (outcome, result.mechanism, result.error or "")
        else:
            signature = (outcome, result.mechanism)
        audited = conn.audited if conn is not None else self._global_audited
        if not orphan and not result.changed and audited.get(key) == signature:
            return
        audited[key] = signature
        if result.ok and not result.changed and not orphan and action in _RELEASES:
            # A release that found nothing to release is not worth a record.
            return
        data: dict[str, Any] = {
            "connection_id": conn.id if conn is not None else None,
            "decision_id": conn.decision_id if conn is not None else None,
            "action": action.value,
            "mechanism": result.mechanism,
            "tier": result.tier.value,
            "changed": result.changed,
            "detail": result.detail,
            "error": result.error,
            "cause": cause,
            "orphan": orphan,
        }
        if extra:
            data.update(dict(extra))
        if conn is not None and event == ev.ENFORCEMENT_REFUSED and conn.verdict is not None:
            data["protection_reasons"] = list(conn.verdict.reasons)
        severity = (
            Severity.ERROR
            if event == ev.ENFORCEMENT_REFUSED and conn is not None and not conn.clone
            else None
        )
        fp = conn.fingerprint if conn is not None else fingerprint
        self._audit(event, severity=severity, actor=actor, device_fp=fp, data=data)
        self._publish(
            "enforcement.result",
            {
                "connection_id": conn.id if conn is not None else None,
                "fingerprint": fp,
                "action": action.value,
                "enforcement": {
                    "outcome": outcome,
                    "mechanism": result.mechanism,
                    "tier": result.tier.value,
                    "detail": result.detail,
                    "error": result.error,
                    "changed": result.changed,
                },
            },
        )

    def _refused(self, device: UsbDevice, action: Action, verdict: ProtectionVerdict) -> None:
        """SafeEnforcer's refusal callback: the pipeline should never cause this."""
        _LOG.warning("the safety layer refused %s on %s", action.value, device.instance_id)

    # =====================================================================================
    # internals: kill switch, tick steps
    # =====================================================================================

    def _activate_killswitch(
        self, *, devices: Sequence[UsbDevice] | None = None, reconcile_after: bool = True
    ) -> None:
        self._killswitch_latched = True
        was_active = self._lockdown.state is not LockdownState.IDLE
        self._write_mode(Mode.MONITOR, actor=_SYSTEM, reason="killswitch")
        for change in self._confirmations.pending():
            if change.kind != CHANGE_LOCKDOWN:
                with contextlib.suppress(Exception):
                    self._confirmations.cancel(change.id, actor=_SYSTEM, reason="killswitch")
        try:
            self._lockdown.force_idle(end_reason="killswitch", actor=_SYSTEM)
        except StoreError as exc:
            self._mark_degraded("store", str(exc))
        targets = list(devices) if devices is not None else [c.device for c in self._conns.values()]
        # Devices handed in at start were enumerated before any connection existed: nothing
        # says which of them default-deny held back, so all are readmitted. Once the
        # service watches devices, only those it knows it held back are.
        readmit = self._held_back_ids() if devices is None else None
        report = rollback(self._journal, self._live, targets, reason="killswitch", readmit=readmit)
        self._baseline_active = False
        self._audit(
            ev.KILLSWITCH_ACTIVATED,
            severity=Severity.CRITICAL,
            actor=_SYSTEM,
            data={"lockdown_was_active": was_active, "path": str(self._kill_switch.path)},
        )
        self._audit(ev.RECOVERY_RESTORED, actor=_SYSTEM, data=report.to_dict())
        self._alert("critical", "the kill switch is set", "enforcement is disabled and restored")
        if was_active:
            self._publish_lockdown("lifted")
        if reconcile_after:
            self.reconcile("killswitch")

    def _tick_killswitch(self) -> None:
        state = self._kill_switch.check()
        if state.honoured and not self._killswitch_latched:
            self._activate_killswitch()
        elif not state.present and self._killswitch_latched:
            # The mode stays monitor: going back to enforce is an explicit set_mode.
            self._killswitch_latched = False
            self._publish("mode.changed", {"mode": self._mode_info().to_dict()})

    def _tick_confirmations(self) -> None:
        before = self._lockdown.state
        self._confirmations.tick()
        if before is not LockdownState.IDLE and self._lockdown.state is LockdownState.IDLE:
            self._publish_lockdown("lifted")

    def _tick_lockdown(self) -> None:
        before = self._lockdown.state
        self._lockdown.tick()
        after = self._lockdown.state
        if before is not after and after is LockdownState.IDLE:
            self._publish_lockdown("expired")

    def _tick_clock(self) -> None:
        newest = self._audit.newest_timestamp
        now = self._clock.now()
        if newest is not None and (newest - now).total_seconds() > _CLOCK_TOLERANCE_SECONDS:
            if not self._clock_behind:
                self._clock_behind = True
                self._audit(
                    ev.CLOCK_ROLLBACK_DETECTED,
                    actor=_SYSTEM,
                    data={
                        "clock": utc_iso(now),
                        "newest_audit": utc_iso(newest),
                        "behind_seconds": int((newest - now).total_seconds()),
                    },
                )
                self._alert(
                    "warning",
                    "the clock was set back",
                    "expiries are evaluated against the newest audit record instead",
                )
        elif self._clock_behind:
            self._clock_behind = False
        if self._audit.degraded:
            self._audit.flush_backlog()

    def _tick_grants(self) -> None:
        expired = self._grants.expire_due(self._now())
        touched: set[str] = set()
        for grant in expired:
            self._audit_grant_expired(grant, reason="expired")
            touched.add(grant.fingerprint)
        for fingerprint in touched:
            self._reevaluate_fingerprint(fingerprint, "grant")
        if expired:
            self._evaluate_orphans()

    def _tick_expiry(self) -> None:
        now = self._now()
        for conn in list(self._conns.values()):
            decision = conn.decision
            if (
                decision is not None
                and decision.expires_at is not None
                and decision.expires_at <= now
            ):
                self._reevaluate(conn, "expiry")

    def _tick_ports(self) -> None:
        for release in self._flap.release_expired():
            self._audit(
                ev.SAFETY_PORT_HELD,
                actor=_SYSTEM,
                data={
                    "port": release.port,
                    "released": True,
                    "manual": False,
                    "coalesced": release.coalesced,
                    "held_seconds": int(release.held_seconds),
                },
            )
            self._release_held(release.port)

    def _release_held(self, port: str) -> tuple[int, ...]:
        touched: list[int] = []
        for conn in list(self._conns.values()):
            if conn.held and conn.device.bus_path == port:
                conn.held = False
                self._reevaluate(conn, "expiry")
                if conn.id is not None:
                    touched.append(conn.id)
        return tuple(touched)

    def _tick_external(self) -> None:
        mono = self._clock.monotonic()
        if mono - self._last_external < _EXTERNAL_CHECK_SECONDS:
            return
        self._last_external = mono
        self._check_policy_file()
        try:
            version = self._read_data_version()
        except StoreError as exc:
            self._mark_degraded("store", str(exc))
            return
        if version == self._data_version:
            return
        # Another process (the command line) changed the database underneath us.
        self._data_version = version
        before_mode = self._effective_mode()
        self._load_settings()
        self._rebuild_context()
        trigger = "mode" if self._effective_mode() is not before_mode else "settings"
        self.reconcile(trigger)

    def _tick_resync(self) -> None:
        mono = self._clock.monotonic()
        if not self._events_dropped and mono - self._last_resync < _RESYNC_SECONDS:
            return
        dropped, self._events_dropped = self._events_dropped, False
        self._resync(reason="dropped" if dropped else "periodic")
        for conn in list(self._conns.values()):
            if conn.enforcement is not None and conn.enforcement.outcome is Outcome.FAILED:
                self._reevaluate(conn, "retry")
        self._evaluate_orphans()

    def _tick_periodic(self) -> None:
        mono = self._clock.monotonic()
        if mono - self._last_periodic < _PERIODIC_SECONDS:
            return
        self._last_periodic = mono
        for conn in list(self._conns.values()):
            self._reevaluate(conn, "periodic")
        self._audit.flush_backlog()

    # =====================================================================================
    # internals: scans
    # =====================================================================================

    def _scanning_available(self) -> bool:
        enabled = self._settings.get("scan.enabled", self._config.scan.enabled)
        return self._scanner is not None and bool(enabled) and not self._scan_disabled

    def _schedule_scans(self, conn: _Conn) -> None:
        decision = conn.decision
        if decision is None or decision.scan is ScanRequirement.NONE:
            return
        if decision.source is DecisionSource.SAFETY or not decision.permits_access:
            return
        mounts = [v.mount_point for v in conn.device.volumes if v.mount_point]
        if not self._scanning_available():
            return
        for mount in mounts:
            if mount in conn.scanned:
                continue
            if self._queue_scan(conn, mount, trigger="policy", requested_by=_SYSTEM) is None:
                conn.verdicts[mount] = ScanVerdict.ERROR
                self._alert("warning", "the scan queue is full", mount, conn=conn)
        before = conn.scan_state
        self._update_scan_state(conn)
        if conn.scan_state is not before:
            # The decision was converged on the scan state before these volumes were
            # queued. A volume that is not yet scanned makes a `required` scan stop being
            # clean, and the device must not stay writable until the scan finishes.
            self._reevaluate(conn, "scan")

    def _queue_scan(
        self, conn: _Conn, mount: str, *, trigger: str, requested_by: str
    ) -> _ScanJob | None:
        if self._scan_queue.full():
            return None
        scan_id: int | None = None
        if conn.id is not None:
            try:
                record = self._store.add_scan(
                    conn.id,
                    conn.fingerprint,
                    mount,
                    trigger=trigger,
                    requested_by=requested_by,
                    queued_at=self._clock.now(),
                )
                scan_id = record.id
            except StoreError as exc:
                self._mark_degraded("store", str(exc))
        job = _ScanJob(scan_id, conn, mount, trigger, requested_by)
        try:
            self._scan_queue.put_nowait(job)
        except queue.Full:
            return None
        conn.scanned.add(mount)
        conn.pending_scans.add(mount)
        # The previous verdict of this mount stays until the new scan replaces it: a
        # rescan must not hand back write access that the last scan took away.
        if scan_id is not None:
            conn.last_scan_id = scan_id
        return job

    def _update_scan_state(self, conn: _Conn) -> None:
        decision = conn.decision
        running = any(job.conn is conn for job in self._running_jobs.values())
        if running:
            state = ScanState.RUNNING
        elif conn.pending_scans:
            state = ScanState.QUEUED
        elif conn.verdicts:
            worst = conn.worst_verdict()
            state = ScanState(worst.value) if worst is not None else ScanState.NONE
        elif (
            decision is not None
            and decision.scan is not ScanRequirement.NONE
            and decision.permits_access
        ):
            state = ScanState.WAITING
        else:
            state = ScanState.NONE
        changed = conn.scan_state is not state
        conn.scan_state = state
        if changed and conn.instance_id in self._conns:
            self._live_view(conn)
        if conn.id is not None:
            self._safe(
                lambda: self._store.update_connection(
                    conn.id, scan_state=state, last_scan_id=conn.last_scan_id
                ),
                None,
            )

    def _spawn_scan_thread(self) -> None:
        self._scan_generation += 1
        generation = self._scan_generation
        thread = threading.Thread(
            target=self._scan_loop, args=(generation,), name="portlock-scan", daemon=True
        )
        self._threads.append(thread)
        thread.start()

    def _scan_loop(self, generation: int) -> None:
        while not self._stop_event.is_set() and generation == self._scan_generation:
            try:
                job = self._scan_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            self._run_scan_job(job)

    def _run_scan_job(self, job: _ScanJob) -> None:
        conn = job.conn
        with self._lock:
            if (
                job.cancel.is_set()
                or conn.instance_id not in self._conns
                or self._conns[conn.instance_id] is not conn
            ):
                self._finish_cancelled(job)
                return
            self._job_counter += 1
            token = self._job_counter
            job.started_mono = self._clock.monotonic()
            self._running_jobs[token] = job
            conn.pending_scans.discard(job.mount_point)
            if job.scan_id is not None:
                self._safe(
                    lambda: self._store.update_scan(
                        job.scan_id, state="running", started_at=self._clock.now()
                    ),
                    None,
                )
            self._audit(
                ev.SCAN_STARTED,
                actor=job.requested_by if job.trigger == "manual" else _SYSTEM,
                device_fp=conn.fingerprint,
                data={"scan_id": job.scan_id, "connection_id": conn.id, "trigger": job.trigger},
            )
            self._update_scan_state(conn)
            self._publish_scan("scan.started", job.scan_id)
        scanner = self._scanner
        report: ScanReport | None = None
        error: str | None = None
        try:
            if scanner is None:
                raise ServiceError("scanning is not available", code="scan_unavailable")
            report = scanner.scan(
                job.mount_point, cancel=job.cancel, progress=lambda p: self._progress(job, p)
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            _LOG.error("scanning %s failed: %s", job.mount_point, error)
        with self._lock:
            self._running_jobs.pop(token, None)
            if job.finished:
                return  # The watchdog gave up on it; its result arrives too late.
            self._finish_scan(job, report, error)

    def _progress(self, job: _ScanJob, progress: Any) -> None:
        mono = self._clock.monotonic()
        if mono - job.last_progress < 1.0:
            return
        job.last_progress = mono
        self._publish(
            "scan.progress",
            {
                "scan_id": job.scan_id,
                "files_seen": int(getattr(progress, "files_seen", 0) or 0),
                "bytes_hashed": int(getattr(progress, "bytes_hashed", 0) or 0),
            },
        )

    def _finish_cancelled(self, job: _ScanJob) -> None:
        job.finished = True
        job.conn.pending_scans.discard(job.mount_point)
        if job.scan_id is not None:
            self._safe(
                lambda: self._store.update_scan(
                    job.scan_id, state="cancelled", finished_at=self._clock.now()
                ),
                None,
            )

    def _finish_scan(self, job: _ScanJob, report: ScanReport | None, error: str | None) -> None:
        job.finished = True
        conn = job.conn
        if job.cancel.is_set() and (
            conn.instance_id not in self._conns or self._conns[conn.instance_id] is not conn
        ):
            self._finish_cancelled(job)
            return
        verdict = ScanVerdict(report.verdict.value) if report is not None else ScanVerdict.ERROR
        data_report = report.to_dict() if report is not None else None
        if job.scan_id is not None:
            self._safe(
                lambda: self._store.update_scan(
                    job.scan_id,
                    state="done",
                    finished_at=self._clock.now(),
                    verdict=verdict.value,
                    report=data_report,
                ),
                None,
            )
        counts = {severity.value: 0 for severity in FindingSeverity}
        if report is not None:
            for finding in report.findings:
                counts[finding.severity.value] += 1
        self._audit(
            ev.SCAN_FINISHED,
            severity=Severity.WARNING
            if verdict in (ScanVerdict.MALICIOUS, ScanVerdict.SUSPICIOUS)
            else None,
            actor=_SYSTEM,
            device_fp=conn.fingerprint,
            data={
                "scan_id": job.scan_id,
                "connection_id": conn.id,
                "verdict": verdict.value,
                "files_seen": report.files_seen if report is not None else 0,
                "files_hashed": report.files_hashed if report is not None else 0,
                "bytes_hashed": report.bytes_hashed if report is not None else 0,
                "truncated_reason": report.truncated_reason if report is not None else None,
                "findings": counts,
                "errors": len(report.errors) if report is not None else 1,
                "engines": [engine.to_dict() for engine in report.engines]
                if report is not None
                else [],
                "error": error,
            },
        )
        if report is not None:
            flagged = [f for f in report.findings if f.severity is not FindingSeverity.INFO]
            for finding in flagged[:_MAX_DETECTIONS_AUDITED]:
                self._audit(
                    ev.SCAN_DETECTION,
                    actor=_SYSTEM,
                    device_fp=conn.fingerprint,
                    data={
                        "scan_id": job.scan_id,
                        "path": finding.path,
                        "engine": finding.engine,
                        "rule": finding.rule,
                        "severity": finding.severity.value,
                        "sha256": finding.sha256,
                    },
                )
            if len(flagged) > _MAX_DETECTIONS_AUDITED:
                self._audit(
                    ev.SCAN_DETECTION,
                    actor=_SYSTEM,
                    device_fp=conn.fingerprint,
                    data={
                        "scan_id": job.scan_id,
                        "omitted": len(flagged) - _MAX_DETECTIONS_AUDITED,
                    },
                )
            if flagged:
                self._alert(
                    "warning", "a scan flagged files", f"{len(flagged)} findings", conn=conn
                )
        self._publish_scan("scan.finished", job.scan_id)
        if conn.instance_id not in self._conns or self._conns[conn.instance_id] is not conn:
            return
        conn.verdicts[job.mount_point] = verdict
        self._update_scan_state(conn)
        self._reevaluate(conn, "scan")
        self._refresh_status()

    def _tick_scans(self) -> None:
        if not self._running_jobs:
            return
        limit = self._config.scan.max_seconds + _SCAN_GRACE_SECONDS
        mono = self._clock.monotonic()
        for token, job in list(self._running_jobs.items()):
            if job.started_mono is None:
                continue
            if job.cancel_mono is None and mono >= job.started_mono + limit:
                job.cancel.set()
                job.cancel_mono = mono
            elif job.cancel_mono is not None and mono >= job.cancel_mono + _SCAN_GRACE_SECONDS:
                # It did not stop: abandon the thread (a daemon) and start another.
                self._running_jobs.pop(token, None)
                self._finish_scan(job, None, "scan did not stop")
                self._abandoned_scans += 1
                if self._abandoned_scans >= _MAX_ABANDONED_SCANS:
                    self._scan_disabled = True
                    self._mark_degraded(
                        "scan", "scans keep hanging; scanning is disabled until restart"
                    )
                elif self._scan_threaded:
                    self._spawn_scan_thread()

    def _cancel_queued_scans(self) -> None:
        while True:
            try:
                job = self._scan_queue.get_nowait()
            except queue.Empty:
                return
            self._finish_cancelled(job)

    def _publish_scan(self, topic: str, scan_id: int | None) -> None:
        if scan_id is None:
            return
        record = self._safe(lambda: self._store.get_scan(scan_id), None)
        if record is not None:
            self._publish(topic, {"scan": ScanView(record).to_dict()})

    # =====================================================================================
    # internals: views, status, helpers
    # =====================================================================================

    def _conn_by_id(self, connection_id: int) -> _Conn:
        for conn in self._conns.values():
            if conn.id == connection_id:
                return conn
        raise ServiceError("the device is not connected", code="not_connected")

    def _live_view(self, conn: _Conn) -> ConnectionView:
        verdict = conn.verdict
        decision_view = (
            DecisionView(
                conn.decision_id,
                conn.decided_at or conn.connected_at,
                conn.decision,
                conn.trigger,
                conn.policy_hash,
                conn.mode,
            )
            if conn.decision is not None
            else None
        )
        view = ConnectionView(
            connection_id=conn.id,
            run_id=conn.run_id,
            fingerprint=conn.fingerprint,
            confidence=Confidence(conn.fp.confidence),
            basis=tuple(conn.fp.basis),
            storage_identity=conn.storage_id,
            device=conn.device,
            connected_at=conn.connected_at,
            removed_at=None,
            close_reason=None,
            present_at_start=conn.present_at_start,
            state=conn.state,
            provisional=conn.provisional,
            protected=bool(verdict and verdict.protected),
            protection_codes=tuple(verdict.codes) if verdict is not None else (),
            decision=decision_view,
            enforcement=conn.enforcement,
            scan_state=conn.scan_state,
            scan_id=conn.last_scan_id,
            resolution=dict(conn.resolution) if conn.resolution is not None else None,
            first_seen=conn.first_seen,
            connection_count=conn.connection_count,
        )
        if conn.id is not None:
            views = dict(self._live_views)
            views[conn.id] = view
            self._live_views = views
        return view

    def _view_for_record(self, record: ConnectionRecord) -> ConnectionView:
        if record.removed_at is None:
            live = self._live_views.get(record.id)
            if live is not None:
                return live
        decision = self._store.get_decision(record.decision_id) if record.decision_id else None
        known = self._store.get_device(record.fingerprint.value)
        enforcement = None
        if decision is not None:
            target = _target_of(decision.decision, record.scan_state)
            os_state = target if decision.outcome is Outcome.APPLIED else _OPEN
            would = target if decision.outcome is Outcome.WOULD_APPLY else None
            enforcement = EnforcementView(
                outcome=decision.outcome,
                os_state=os_state,
                would=would,
                mechanism=decision.mechanism,
                tier=decision.tier,
                detail=decision.detail,
                error=decision.error,
                at=decision.enforced_at,
            )
        return ConnectionView(
            connection_id=record.id,
            run_id=record.run_id,
            fingerprint=record.fingerprint.value,
            confidence=Confidence(record.fingerprint.confidence),
            basis=tuple(record.fingerprint.basis),
            storage_identity=known.storage_identity if known is not None else None,
            device=record.device,
            connected_at=record.connected_at,
            removed_at=record.removed_at,
            close_reason=record.close_reason,
            present_at_start=record.present_at_start,
            state=record.state,
            provisional=record.provisional,
            protected=record.state is ConnectionState.PROTECTED,
            protection_codes=(),
            decision=DecisionView.from_record(decision) if decision is not None else None,
            enforcement=enforcement,
            scan_state=record.scan_state,
            scan_id=record.last_scan_id,
            resolution=record.resolution,
            first_seen=known.first_seen if known is not None else None,
            connection_count=known.connection_count if known is not None else 0,
        )

    def _device_view(self, record: DeviceRecord) -> DeviceView:
        value = record.fingerprint.value
        connected = any(conn.fingerprint == value for conn in list(self._conns.values()))
        trust: str | None = None
        try:
            kinds = {
                grant.read_only
                for grant in self._grants.list()
                if grant.fingerprint == value and grant.kind is GrantKind.TRUST
            }
        except StoreError:
            kinds = set()
        if kinds:
            # The most restrictive trust wins, as in GrantStore.active_for.
            trust = "read_only" if True in kinds else "full"
        return DeviceView(record, connected, trust)

    def _refresh_status(self) -> None:
        conns = list(self._conns.values())
        counts = {
            "connected": len(conns),
            "protected": sum(1 for c in conns if c.state is ConnectionState.PROTECTED),
            "allowed": sum(1 for c in conns if c.state is ConnectionState.ALLOWED),
            "read_only": sum(1 for c in conns if c.state is ConnectionState.READ_ONLY),
            "pending": sum(1 for c in conns if c.state is ConnectionState.PENDING),
            "denied": sum(1 for c in conns if c.state is ConnectionState.DENIED),
            "not_enforced": sum(
                1
                for c in conns
                if c.enforcement is not None and c.enforcement.outcome in _NOT_ENFORCED
            ),
        }
        try:
            head_seq, head_hash = self._audit.log.head()
        except (StoreError, AuditError):
            head_seq, head_hash = 0, ""
        backend_caps = None
        with contextlib.suppress(Exception):
            backend_caps = self._backend.capabilities()
        caps = self._caps()
        degraded = set(self._degraded)
        if self._audit.degraded:
            degraded.add("audit")
        if self._journal.corrupt_lines:
            degraded.add("journal")
        lockdown: LockdownStatus | None
        try:
            lockdown = self._lockdown.status()
        except StoreError:
            lockdown = None
        loaded = self._loaded
        previous = self._status
        has_users = True
        if self._has_users is not None:
            try:
                has_users = bool(self._has_users())
            except StoreError:
                has_users = True
        snapshot = ServiceStatus(
            version=__version__,
            run_id=self.run_id,
            host_label=self._config.host_label,
            platform=self._platform,
            started_at=self._started_at,
            uptime_seconds=max(0, int(self._clock.monotonic() - self._started_mono)),
            simulation=self._simulation,
            mode=self._mode_info(),
            lockdown=lockdown,
            policy={
                "name": loaded.policy.name,
                "hash": loaded.hash,
                "source": loaded.source,
                "rules": len(loaded.policy.rules),
            },
            backend={
                "name": backend_caps.name if backend_caps is not None else "unknown",
                "event_driven": bool(backend_caps.event_driven)
                if backend_caps is not None
                else False,
                "healthy": "backend" not in self._degraded,
                "last_error": self._degraded.get("backend"),
                "notes": list(backend_caps.notes) if backend_caps is not None else [],
            },
            enforcer={
                "name": caps.name,
                "privileged": caps.privileged,
                "block": caps.block,
                "read_only": caps.read_only,
                "eject": caps.eject,
                "default_deny": caps.default_deny,
                "notes": list(caps.notes),
            },
            counts=counts,
            audit={
                "head_seq": head_seq,
                "head_hash": head_hash,
                "keyed": self._audit.log.keyed,
                "backlog": self._audit.backlog,
                "sink_failures": self._audit.log.sink_failures,
            },
            journal={
                "open_records": len(self._journal.open_records()),
                "corrupt_lines": self._journal.corrupt_lines,
            },
            degraded=tuple(sorted(degraded)),
            setup_required=not has_users,
        )
        self._status = snapshot
        if previous is not None and (
            previous.degraded != snapshot.degraded or dict(previous.counts) != counts
        ):
            self._publish("status.changed", {"degraded": list(snapshot.degraded), "counts": counts})

    def _service_checks(self) -> list[ServiceCheck]:
        info = self._mode_info()
        checks = [
            ServiceCheck(
                "service.mode",
                "ok" if info.effective_mode is info.mode else "warn",
                f"mode {info.mode.value}, in force {info.effective_mode.value}",
                "; ".join(info.notes),
            ),
            ServiceCheck(
                "service.killswitch",
                "warn" if self._killswitch_latched else "ok",
                "the kill switch is set"
                if self._killswitch_latched
                else "the kill switch is not set",
            ),
            ServiceCheck(
                "service.journal",
                "warn" if self._journal.corrupt_lines or "journal" in self._degraded else "ok",
                f"{len(self._journal.open_records())} open records, "
                f"{self._journal.corrupt_lines} unreadable lines",
                self._degraded.get("journal", ""),
            ),
            ServiceCheck(
                "service.database",
                "fail" if "store" in self._degraded else "ok",
                "the database is " + ("failing" if "store" in self._degraded else "usable"),
                self._degraded.get("store", ""),
            ),
            ServiceCheck(
                "service.audit",
                "fail"
                if "audit_chain" in self._degraded
                else "warn"
                if self._audit.degraded
                else "ok",
                f"{self._audit.backlog} audit events waiting; chain "
                + ("broken" if "audit_chain" in self._degraded else "verified"),
                self._degraded.get("audit_chain", ""),
            ),
            ServiceCheck(
                "service.signing",
                "ok" if self._audit.log.keyed else "warn",
                "audit records carry forward-secure MACs"
                if self._audit.log.keyed
                else "audit records carry no MAC (no key store configured)",
            ),
            ServiceCheck(
                "service.scan_engines",
                "ok" if self._scanning_available() else "warn",
                "scanning is available"
                if self._scanning_available()
                else "scanning is not available",
                "; ".join(
                    part
                    for part in (
                        _NO_ANTIVIRUS_NOTE if self._watch_only() else "",
                        self._degraded.get("scan", ""),
                    )
                    if part
                ),
            ),
            ServiceCheck(
                "service.lockdown",
                "info",
                f"lockdown is {self._lockdown.state.value}",
            ),
            self._privacy_check(),
        ]
        if self._system_ids_note:
            checks.append(
                ServiceCheck(
                    "service.system_volume",
                    "warn",
                    "the system volume could not be traced; every storage device present at "
                    "start is protected",
                    self._system_ids_note,
                )
            )
        if self._config.baseline_read_only:
            checks.append(
                ServiceCheck(
                    "service.baseline_read_only",
                    "ok" if self._baseline_active else "warn",
                    "the read-only baseline is in place"
                    if self._baseline_active
                    else "the read-only baseline is not in place",
                    self._baseline_note,
                )
            )
        has_users = True
        if self._has_users is not None:
            with contextlib.suppress(StoreError):
                has_users = bool(self._has_users())
        checks.append(
            ServiceCheck(
                "service.setup",
                "ok" if has_users else "warn",
                "an administrator exists" if has_users else "no administrator account yet",
            )
        )
        return checks

    def _privacy_check(self) -> ServiceCheck:
        if self._watch_only():
            return ServiceCheck(
                "service.privacy",
                "info",
                "the state and configuration directories were not checked for privacy: "
                "watch-only neither checks nor changes permissions",
                "a watch-only PortLock enforces nothing, so no blocking depends on them",
            )
        return ServiceCheck(
            "service.privacy",
            "fail" if self._privacy_problems else "ok",
            "the state and configuration directories are private"
            if not self._privacy_problems
            else "a directory is not private; enforce mode is refused",
            "; ".join(self._privacy_problems),
        )

    def _audit_grant_created(self, grant: Grant, connection_id: int | None) -> None:
        event = ev.TRUST_ADDED if grant.kind is GrantKind.TRUST else ev.GRANT_CREATED
        self._audit(
            event,
            actor=grant.granted_by,
            device_fp=grant.fingerprint,
            data={
                "grant": {
                    "id": grant.id,
                    "kind": grant.kind.value,
                    "read_only": grant.read_only,
                    "expires_at": _iso(grant.expires_at),
                    "confidence": grant.confidence.value,
                    "bound_port": grant.bound_port,
                },
                "connection_id": connection_id,
            },
        )
        self._publish("grant.changed", {"change": "created", "grant": grant.to_dict()})

    def _audit_grant_expired(self, grant: Grant, *, reason: str) -> None:
        self._audit(
            ev.GRANT_EXPIRED,
            actor=_SYSTEM,
            device_fp=grant.fingerprint,
            data={"grant_id": grant.id, "kind": grant.kind.value, "reason": reason},
        )
        self._publish("grant.changed", {"change": "expired", "grant": grant.to_dict()})

    def _grant_ceiling(self, role: str) -> timedelta:
        hours = (
            self._config.grants.max_temporary_hours_admin
            if role == "admin"
            else self._config.grants.max_temporary_hours_operator
        )
        return timedelta(hours=hours)

    def _publish_lockdown(self, change: str) -> None:
        with contextlib.suppress(StoreError):
            self._publish(
                "lockdown.changed",
                {"change": change, "lockdown": self._lockdown.status().to_dict()},
            )

    def _publish_connection(self, topic: str, view: ConnectionView) -> None:
        self._publish(topic, {"connection": view.to_dict()})

    def _publish(self, topic: str, payload: Mapping[str, Any]) -> None:
        try:
            self._bus.publish(topic, payload)
        except (ValueError, TypeError) as exc:
            _LOG.error("publishing %s failed: %s", topic, exc)

    def _alert(self, severity: str, title: str, message: str, *, conn: _Conn | None = None) -> None:
        self._publish(
            "alert",
            {
                "severity": severity,
                "title": title,
                "message": message,
                "connection_id": conn.id if conn is not None else None,
                "fingerprint": conn.fingerprint if conn is not None else None,
                "audit_seq": None,
            },
        )

    def _mark_degraded(self, component: str, reason: str) -> None:
        self._degraded[component] = reason[:500]

    def _clear_degraded(self, component: str) -> None:
        self._degraded.pop(component, None)

    def _safe(self, fn: Callable[[], Any], default: Any) -> Any:
        """Run a store call; on ``StoreError`` mark the store degraded and return ``default``."""
        try:
            return fn()
        except (StoreError, GrantError) as exc:
            self._mark_degraded("store", str(exc))
            return default


# --- commit-confirm handlers -------------------------------------------------------------


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
        "result": dict(change.result) if change.result is not None else None,
    }


def _preview(
    service: PortLockService, *, enforce: bool, scope: str | None = None
) -> list[dict[str, Any]]:
    """What a change would do to each connected device (the commit-confirm listing)."""
    items: list[dict[str, Any]] = []
    context = service._context
    if scope is not None:
        context = dataclasses.replace(context, scope=scope)
    for conn in list(service._conns.values()):
        verdict = is_protected(conn.device, conn.fp, context)
        decision = conn.decision
        if verdict.protected:
            outcome, reason = "protected", "; ".join(verdict.reasons)
        elif not verdict.in_scope:
            outcome, reason = "not_enforced", verdict.scope_reason
        elif decision is None:
            outcome, reason = "block", "not yet evaluated"
        else:
            target = _target_of(decision, conn.scan_state)
            outcome = {"blocked": "block", "read_only": "read_only", "open": "open"}[target]
            if not enforce and decision.source is not DecisionSource.LOCKDOWN:
                outcome = "open"
            reason = "; ".join(decision.reasons[:2])
        items.append(
            {
                "instance_id": conn.instance_id,
                "name": conn.device.display_name,
                "vid_pid": conn.device.vid_pid,
                "outcome": outcome,
                "reason": reason[:300],
            }
        )
    return items


class _EnforceModeChange:
    """Commit-confirm handler for switching to enforce mode."""

    def __init__(self, service: PortLockService) -> None:
        self._service = service

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return _preview(self._service, enforce=True)

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None:
        service = self._service
        service._write_mode(Mode.ENFORCE, actor=change.actor, reason="confirm-pending")
        summary = service.reconcile("mode")
        return {"summary": summary.to_dict()}

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None:
        service = self._service
        previous = change.params.get("previous")
        if previous == Mode.MONITOR.value:
            service._write_mode(Mode.MONITOR, actor=_SYSTEM, reason=f"rolled back: {reason}")
        else:
            with contextlib.suppress(StoreError):
                service._store.delete_setting("mode")
            service._settings.pop("mode", None)
            service._audit(
                ev.MODE_CHANGED,
                actor=_SYSTEM,
                data={
                    "old": Mode.ENFORCE.value,
                    "new": service._chosen_mode()[0].value,
                    "reason": f"rolled back: {reason}",
                },
            )
            service._publish("mode.changed", {"mode": service._mode_info().to_dict()})
        if not at_start:
            service.reconcile("mode")


class _WidenScopeChange:
    """Commit-confirm handler for widening the enforcement scope."""

    def __init__(self, service: PortLockService) -> None:
        self._service = service

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        service = self._service
        return _preview(
            service, enforce=service._effective_mode() is Mode.ENFORCE, scope=str(params["scope"])
        )

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None:
        service = self._service
        service._write_scope(str(change.params["scope"]), actor=change.actor)
        summary = service.reconcile("settings")
        return {"summary": summary.to_dict()}

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None:
        service = self._service
        previous = change.params.get("previous")
        service._write_scope(previous if previous in SCOPES else None, actor=_SYSTEM)
        if not at_start:
            service.reconcile("settings")


class _DefaultDenyChange:
    """Commit-confirm handler for a standing OS default-deny (enforce mode only)."""

    def __init__(self, service: PortLockService) -> None:
        self._service = service

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return [
            {
                "instance_id": "",
                "name": "new devices",
                "vid_pid": "",
                "outcome": "block",
                "reason": "every device that arrives from now on is refused until it is decided",
            }
        ]

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None:
        service = self._service
        service._write_setting("default_deny", True, actor=change.actor)
        service._audit(
            ev.CONFIG_CHANGED,
            actor=change.actor,
            data={"key": "default_deny", "old": False, "new": True},
        )
        summary = service.reconcile("settings")
        return {"summary": summary.to_dict()}

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None:
        service = self._service
        try:
            service._write_setting("default_deny", False, actor=_SYSTEM)
        except StoreError as exc:
            service._mark_degraded("store", str(exc))
            service._settings["default_deny"] = False
        service._audit(
            ev.CONFIG_CHANGED,
            actor=_SYSTEM,
            data={"key": "default_deny", "old": True, "new": False, "reason": reason},
        )
        if not at_start:
            service.reconcile("settings")
