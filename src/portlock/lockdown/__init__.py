"""PortLock Lockdown: emergency lockdown and its recovery safeguards.

Everything lives in :mod:`portlock.lockdown.manager`:

* :class:`CommitConfirm` - apply a change that could lock the operator out, and roll it
  back unless it is confirmed over the same channel in time (``docs/DESIGN.md`` 14.15).
  Lockdown uses it; so do enforce mode, widening the scope and default-deny.
* :class:`LockdownManager` - the lockdown state machine, its monotonic dead-man timer
  with the persisted time remaining, and the operating-system timer that ends a lockdown
  even if the service has died (14.12, 14.16).
* :class:`KillSwitch` - the ``DISABLE_ENFORCEMENT`` file, honoured only in a private
  directory (14.18).
* :func:`rollback` and :func:`recover` - put every journaled setting back; ``recover``
  needs neither the service nor the database.

The seams (:class:`ExternalTimer`, :class:`PrivacyCheck`, :class:`CredentialCheck`) are
protocols: any object with the right methods satisfies them.
"""

from __future__ import annotations

from portlock.lockdown.manager import (
    CHANGE_DEFAULT_DENY,
    CHANGE_ENFORCE_MODE,
    CHANGE_LOCKDOWN,
    CHANGE_WIDEN_SCOPE,
    CONFIRM_TIMER_PREFIX,
    LOCKDOWN_TIMER,
    RECOVER_MARKER,
    AuditFn,
    ChangeHandler,
    CommitConfirm,
    ConfirmationError,
    Connected,
    Credential,
    CredentialCheck,
    EngageResult,
    ExternalTimer,
    KillSwitch,
    KillSwitchState,
    LiftResult,
    LockdownError,
    LockdownManager,
    LockdownState,
    LockdownStatus,
    PlanItem,
    PrivacyCheck,
    PrivacyReportLike,
    ProtectionLike,
    ReconcileSummary,
    RollbackReport,
    consume_recover_marker,
    recover,
    rollback,
    write_recover_marker,
)

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
