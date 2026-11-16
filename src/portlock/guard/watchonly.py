"""Watch-only: a PortLock process that can never be trusted to enforce changes nothing.

DESIGN 14.28. A process is **watch-only** exactly when it is not elevated (administrator,
root) or its state or configuration directory is not a system-wide location. Nothing else
decides it: not the mode, not a setting, not a request. It is decided once, when the
process starts (:func:`detect_posture`), and it holds for the whole life of the process;
there is no way out of it inside the process.

A watch-only process observes devices, decides, audits and serves the console. The
composition root (``service.daemon``) hands its service three inert stand-ins instead of
the real operating-system objects, and never builds the real ones:

=====================  ===================================================================
real object            watch-only stand-in
=====================  ===================================================================
platform ``Enforcer``  :class:`WatchOnlyEnforcer`: every call is recorded as "would" and
                       reaches nothing (a restore of a journaled change is reported as not
                       done, so the journal keeps it)
``ExternalTimer``      :class:`WatchOnlyTimer`: ``schtasks`` / ``systemd-run`` are never run
``DirPrivacy``         :class:`WatchOnlyDirPrivacy`: ``icacls`` and ``chown`` are never run
=====================  ===================================================================

Every other process (elevated, with system-wide directories) gets the real objects and is
never called watch-only; in monitor mode it is simply in monitor mode (DESIGN 14.18, 11).

The service never names this module: it is told the reason (:meth:`Posture.refusal`) and
sees ordinary ``Enforcer``, ``ExternalTimer`` and ``DirPrivacy`` objects.
"""

from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from portlock.core.config import Config, paths_per_user
from portlock.core.models import UsbDevice
from portlock.core.privilege import process_elevated
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
)
from portlock.guard.safety import MECHANISM_DRY_RUN
from portlock.guard.seams import MechanismStatus, PrivacyReport, validate_timer_name

__all__ = [
    "MECHANISM_WATCH_ONLY",
    "NO_ANTIVIRUS_NOTE",
    "WATCH_ONLY_ENGINES",
    "WATCH_ONLY_NOTE",
    "Posture",
    "StandIns",
    "WatchOnlyDirPrivacy",
    "WatchOnlyEnforcer",
    "WatchOnlyTimer",
    "WouldLog",
    "detect_posture",
]

#: The mechanism of a watch-only result that is *not* reported as done (a journal restore).
MECHANISM_WATCH_ONLY = "watch-only"
#: The note every watch-only capability report carries.
WATCH_ONLY_NOTE = (
    "watch-only: PortLock records what it would do and changes nothing on this computer "
    "outside its own folder"
)
#: The scan engines a watch-only process uses: they run inside PortLock and only read files.
WATCH_ONLY_ENGINES = frozenset({"heuristics", "hashset"})
#: Why the antivirus engines are left out in watch-only.
NO_ANTIVIRUS_NOTE = (
    "antivirus engines are not used in watch-only: ClamAV and Microsoft Defender would "
    "start programs, so files are checked only by PortLock's own heuristics and hash lists"
)
_PRIVACY_NOT_CHECKED = (
    "not checked: PortLock is watch-only and neither checks nor changes directory permissions"
)
_DEFAULT_LOG_SIZE = 256


@dataclass(frozen=True, slots=True)
class Posture:
    """What this process may do to the operating system, decided once at start.

    Attributes:
        elevated: the process runs as administrator (Windows) or root.
        system_wide: both the state and the configuration directory are system-wide
            locations (``core.config.paths_per_user`` is False for them). Anything that
            cannot be shown to be system-wide counts as not system-wide.
    """

    elevated: bool
    system_wide: bool

    @property
    def watch_only(self) -> bool:
        """True if the process can never be trusted to enforce. Never changes."""
        return not (self.elevated and self.system_wide)

    def refusal(self) -> str | None:
        """Why PortLock cannot change this computer, in plain words; ``None`` if it can.

        The same sentence answers every refused request (enforce mode, a lockdown,
        default-deny), so it names what PortLock cannot do and why, not one request.
        """
        if not self.watch_only:
            return None
        reasons: list[str] = []
        if not self.elevated:
            reasons.append("it is not running as administrator")
        if not self.system_wide:
            reasons.append(
                "its files are in this user's own folders, which every program this user "
                "runs could change"
            )
        return (
            "PortLock cannot change this computer: "
            + ", and ".join(reasons)
            + ". It stays watch-only: it shows and records, and blocks nothing."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "elevated": self.elevated,
            "system_wide": self.system_wide,
            "watch_only": self.watch_only,
            "reason": self.refusal(),
        }


def detect_posture(
    config: Config,
    *,
    elevated: bool | None = None,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> Posture:
    """The posture of a process with this configuration.

    Args:
        elevated: defaults to asking the operating system (read-only).
        env / platform: what :func:`~portlock.core.config.paths_per_user` consults.
    """
    return Posture(
        elevated=process_elevated() if elevated is None else elevated is True,
        system_wide=not paths_per_user(config.paths, platform=platform, env=env),
    )


class WouldLog:
    """A bounded, thread-safe record of what watch-only stood in for, newest last."""

    def __init__(self, size: int = _DEFAULT_LOG_SIZE) -> None:
        if size < 1:
            raise ValueError("the log must hold at least one entry")
        self._lock = threading.Lock()
        self._items: deque[str] = deque(maxlen=size)
        self._total = 0

    def add(self, text: str) -> None:
        with self._lock:
            self._items.append(text)
            self._total += 1

    def entries(self) -> tuple[str, ...]:
        """The most recent entries, oldest first."""
        with self._lock:
            return tuple(self._items)

    @property
    def total(self) -> int:
        """How many entries were ever added (older ones may have been dropped)."""
        with self._lock:
            return self._total


def _label(device: UsbDevice) -> str:
    return f"{device.display_name} [{device.vid_pid}]"


class WatchOnlyEnforcer(Enforcer):
    """An :class:`Enforcer` that reaches nothing and records what it would have done.

    Restricting and releasing calls return ``ok=True`` with ``mechanism="dry-run"`` and
    ``changed=False``, so the service audits them as "would apply", as monitor mode does.
    Such a result is never ``performed`` (``guard.base``), so no journal record is ever
    closed on it. A restore of real journal entries returns ``ok=False``
    (``mechanism="watch-only"``): those entries describe changes an enforcing run made,
    and claiming them undone would close records whose changes are still in place.
    """

    def __init__(self, *, elevated: bool, log: WouldLog | None = None) -> None:
        self._elevated = elevated is True
        self._log = log if log is not None else WouldLog()

    @property
    def log(self) -> WouldLog:
        return self._log

    def capabilities(self) -> EnforcerCapabilities:
        return EnforcerCapabilities(
            name="watch-only",
            privileged=self._elevated,
            block=False,
            read_only=False,
            eject=False,
            default_deny=False,
            notes=(WATCH_ONLY_NOTE,),
        )

    def mechanisms(self) -> tuple[MechanismStatus, ...]:
        """No mechanism is probed in watch-only."""
        return ()

    def _would(self, action: Action, what: str) -> EnforcementResult:
        self._log.add(f"would {what}")
        return EnforcementResult(
            action=action,
            ok=True,
            mechanism=MECHANISM_DRY_RUN,
            detail=f"watch-only: would {what}; nothing was changed",
        )

    def block(self, device: UsbDevice) -> EnforcementResult:
        return self._would(Action.BLOCK, f"block {_label(device)}")

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        return self._would(Action.UNBLOCK, f"unblock {_label(device)}")

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        if read_only:
            return self._would(Action.READ_ONLY, f"make {_label(device)} read-only")
        return self._would(Action.READ_WRITE, f"make {_label(device)} writable")

    def eject(self, device: UsbDevice) -> EnforcementResult:
        return self._would(Action.EJECT, f"eject {_label(device)}")

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        action = Action.DEFAULT_DENY_ON if enabled else Action.DEFAULT_DENY_OFF
        return self._would(action, f"turn default-deny {'on' if enabled else 'off'}")

    def set_baseline_read_only(self, enabled: bool) -> EnforcementResult:
        action = Action.READ_ONLY if enabled else Action.READ_WRITE
        return self._would(action, f"turn the read-only baseline {'on' if enabled else 'off'}")

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        frozen = tuple(entries)
        if not frozen:
            return self._would(Action.RESTORE, "restore nothing")
        self._log.add(f"would restore {len(frozen)} journal entries (not done)")
        return EnforcementResult(
            action=Action.RESTORE,
            ok=False,
            mechanism=MECHANISM_WATCH_ONLY,
            detail=f"watch-only: {len(frozen)} journaled change(s) were not restored",
            error=(
                "watch-only: this PortLock changes nothing on this computer, so a change "
                "an enforcing PortLock made stays in place"
            ),
        )


class WatchOnlyTimer:
    """An :class:`ExternalTimer` that never arms anything (no ``schtasks``, no
    ``systemd-run``) and records what it would have armed.

    ``inert`` tells the lockdown status not to claim an operating-system timer exists.
    """

    inert = True

    def __init__(self, log: WouldLog | None = None) -> None:
        self._log = log if log is not None else WouldLog()

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        validate_timer_name(name)
        self._log.add(f"would arm the operating-system timer {name} for {at.isoformat()}")

    def cancel(self, name: str) -> None:
        validate_timer_name(name)
        self._log.add(f"would cancel the operating-system timer {name}")

    def is_armed(self, name: str) -> bool:
        validate_timer_name(name)
        return False


class WatchOnlyDirPrivacy:
    """A :class:`DirPrivacy` that changes no permission (no ``icacls``, no ``chown``).

    ``ensure_private`` only creates a missing directory (owner-only, as every directory
    PortLock creates in its own folder) and records that it would have restricted it;
    ``check`` reports "not checked", so nothing that depends on a verified private
    directory (the kill switch, enforce mode) is enabled by it.
    """

    def __init__(self, log: WouldLog | None = None) -> None:
        self._log = log if log is not None else WouldLog()

    def ensure_private(self, path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        Path(text).mkdir(mode=0o700, parents=True, exist_ok=True)
        self._log.add(f"would make {text} private")

    def check(self, path: str | os.PathLike[str]) -> PrivacyReport:
        return PrivacyReport(os.fspath(path), False, (_PRIVACY_NOT_CHECKED,))


@dataclass(frozen=True, slots=True)
class StandIns:
    """The three stand-ins a watch-only process is given, sharing one "would" log."""

    enforcer: WatchOnlyEnforcer
    timer: WatchOnlyTimer
    dir_privacy: WatchOnlyDirPrivacy
    log: WouldLog

    @classmethod
    def create(cls, *, elevated: bool, log_size: int = _DEFAULT_LOG_SIZE) -> StandIns:
        log = WouldLog(log_size)
        return cls(
            enforcer=WatchOnlyEnforcer(elevated=elevated, log=log),
            timer=WatchOnlyTimer(log),
            dir_privacy=WatchOnlyDirPrivacy(log),
            log=log,
        )

    @property
    def would(self) -> tuple[str, ...]:
        """What the stand-ins were asked to do, most recent last."""
        return self.log.entries()
