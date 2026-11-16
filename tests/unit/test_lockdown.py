"""Lockdown, commit-confirm, the kill switch, rollback and recover (lockdown/manager.py).

The tests run a simulated machine: a :class:`FakeEnforcer` stands for the operating
system, a fake timer for the operating-system timer service, and real stores (a SQLite
file and a journal file in ``tmp_path``) for PortLock's state. A "crash" is an exception
that no handler catches (it derives from ``BaseException``, as a process dying would
skip every cleanup), after which a new process is built on the same files and the same
simulated operating system. Nothing here touches a real device or a real timer.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from factories import (
    CDC_ACM,
    flash_drive,
    hub,
    keyboard,
    make_device,
    mouse,
    phone,
    storage_with_keyboard,
)
from portlock.core.clock import FakeClock
from portlock.core.config import LockdownConfig
from portlock.core.db import Database
from portlock.core.errors import AuthError, NotPrivilegedError, StoreError
from portlock.core.fingerprint import fingerprint
from portlock.core.models import UsbDevice
from portlock.core.store import (
    GLOBAL_SCOPE,
    JOURNAL_FILE_NAME,
    PendingChangeRecord,
    RecoveryJournal,
    StateStore,
)
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
)
from portlock.guard.fake import FakeEnforcer
from portlock.guard.safety import SafeEnforcer, SafetyContext
from portlock.lockdown import (
    CHANGE_ENFORCE_MODE,
    CONFIRM_TIMER_PREFIX,
    LOCKDOWN_TIMER,
    RECOVER_MARKER,
    CommitConfirm,
    ConfirmationError,
    Credential,
    KillSwitch,
    LockdownError,
    LockdownManager,
    LockdownState,
    ReconcileSummary,
    consume_recover_marker,
    recover,
    rollback,
)

PASSWORD = Credential("password", "correct horse battery staple")
RECOVERY_CODE = "ABCD-EFGH-JKLM-NPQR"
CHANNEL = "session-1"
RECOVER_ARGV = ("portlock", "recover")
RESTRICTING = (Action.BLOCK, Action.READ_ONLY, Action.EJECT, Action.DEFAULT_DENY_ON)


class Crash(BaseException):
    """The process dies here: no handler runs, nothing is cleaned up."""


class FakeTimer:
    """The operating-system timer service. ``raise_on["arm:<name>"]`` injects a failure."""

    def __init__(self) -> None:
        self.armed: dict[str, datetime] = {}
        self.commands: dict[str, tuple[str, ...]] = {}
        self.log: list[tuple[str, str]] = []
        self.raise_on: dict[str, BaseException] = {}

    def arm(self, name: str, at: datetime, argv: Sequence[str]) -> None:
        self.log.append(("arm", name))
        self.commands[name] = tuple(argv)
        failure = self.raise_on.pop(f"arm:{name}", None)
        if failure is not None:
            raise failure
        self.armed[name] = at

    def cancel(self, name: str) -> None:
        self.log.append(("cancel", name))
        failure = self.raise_on.pop(f"cancel:{name}", None)
        if failure is not None:
            raise failure
        self.armed.pop(name, None)


@dataclass(frozen=True)
class PrivacyReport:
    path: str
    private: bool
    problems: tuple[str, ...] = ()


class Privacy:
    """The directory privacy check (the shape of ``guard.seams.DirPrivacy.check``)."""

    def __init__(self, private: bool = True) -> None:
        self.private = private
        self.asked: list[Path] = []

    def check(self, path: Any) -> PrivacyReport:
        self.asked.append(Path(path))
        problems = () if self.private else ("writable by other users",)
        return PrivacyReport(str(path), self.private, problems)


class Passwords:
    """Accepts the test password, and one recovery code once."""

    def __init__(self) -> None:
        self.codes = {RECOVERY_CODE}
        self.raises: Exception | None = None

    def verify(self, actor: str, credential: Credential) -> bool:
        if self.raises is not None:
            raise self.raises
        if credential.kind == "password":
            return actor == "alice" and credential.secret == PASSWORD.secret
        if credential.secret in self.codes:
            self.codes.discard(credential.secret)
            return True
        return False


@dataclass(frozen=True)
class Conn:
    device: UsbDevice
    connected_at: datetime


class Machine:
    """One simulated machine across service restarts.

    The operating system (``fake``, ``timer``, the devices, the files) survives a crash;
    the service process (database handle, journal object, manager) is rebuilt by
    :meth:`boot`. :meth:`reconcile` stands in for the service's convergence: while the
    lockdown is active it turns default-deny on and blocks what the manager's plan says
    to block, otherwise it releases everything journaled.
    """

    def __init__(
        self,
        tmp_path: Path,
        clock: FakeClock,
        *,
        config: LockdownConfig | None = None,
        confirm_seconds: int = 60,
    ) -> None:
        self.home = tmp_path
        self.config_dir = tmp_path / "config"
        self.config_dir.mkdir(exist_ok=True)
        self.clock = clock
        self.config = config or LockdownConfig(default_minutes=10, max_minutes=120)
        self.confirm_seconds = confirm_seconds
        self.fake = FakeEnforcer(write_ahead=self._write_ahead)
        self.timer = FakeTimer()
        self.privacy = Privacy()
        self.passwords = Passwords()
        self.connected: list[Conn] = []
        self.audit: list[tuple[str, dict[str, Any]]] = []
        self.triggers: list[str] = []
        self.reconcile_hook: Callable[[str], None] | None = None
        self.audit_hook: Callable[[str], None] | None = None
        self.boot()

    # the process
    def boot(self) -> None:
        self.db = Database(self.home / "portlock.db")
        self.store = StateStore(self.db, clock=self.clock)
        self.journal = RecoveryJournal(self.home / JOURNAL_FILE_NAME, clock=self.clock)
        self.live = SafeEnforcer(self.fake, self.context, dry_run=False)
        self.confirmations = CommitConfirm(
            self.store,
            clock=self.clock,
            timeout_seconds=self.confirm_seconds,
            audit=self.record,
            timer=self.timer,
            recover_argv=RECOVER_ARGV,
        )
        self.manager = LockdownManager(
            self.store,
            clock=self.clock,
            config=self.config,
            audit=self.record,
            reconcile=self.reconcile,
            timer=self.timer,
            recover_argv=RECOVER_ARGV,
            kill_switch=KillSwitch(self.config_dir / "DISABLE_ENFORCEMENT", self.privacy),
            credentials=self.passwords,
            confirmations=self.confirmations,
            devices=lambda: list(self.connected),
            protection=self.live.protection,
            checkpoint_seconds=10,
        )

    def start(self, *, recovered_at: datetime | None = None) -> str:
        """The service's start-up order: resume, roll back stale changes, reconcile."""
        outcome = self.manager.resume(recovered_at=recovered_at)
        self.confirmations.resume()
        summary = self.reconcile("start")
        if outcome == "lift_pending":
            self.manager.finish_lift(summary)
        return outcome

    def crash_and_restart(self, *, recovered_at: datetime | None = None) -> str:
        self.reconcile_hook = None
        self.audit_hook = None
        self.timer.raise_on.clear()
        self.db.close()
        self.boot()
        return self.start(recovered_at=recovered_at)

    # seams
    def _write_ahead(self, entry: JournalEntry) -> None:
        self.journal.write_ahead(entry)

    def context(self) -> SafetyContext:
        return SafetyContext(enrolled=self.store.enrolled_pairs())

    def record(self, event: str, **kwargs: Any) -> None:
        if self.audit_hook is not None:
            self.audit_hook(event)
        self.audit.append((event, dict(kwargs.get("data") or {})))

    def events(self) -> list[str]:
        return [event for event, _ in self.audit]

    def data(self, event: str) -> dict[str, Any]:
        return [data for name, data in self.audit if name == event][-1]

    def reconcile(self, trigger: str) -> ReconcileSummary:
        self.triggers.append(trigger)
        if self.reconcile_hook is not None:
            self.reconcile_hook(trigger)
        devices = [conn.device for conn in self.connected]
        if self.manager.active:
            failed = blocked = 0
            with self.journal.recording(
                scope=GLOBAL_SCOPE, action=Action.DEFAULT_DENY_ON, fingerprint=None
            ):
                result = self.live.set_default_deny(True)
                self.journal.record(result)
            failed += not result.ok
            by_id = {device.instance_id: device for device in devices}
            for item in self.manager.plan():
                if item.outcome != "block":
                    continue
                device = by_id[item.instance_id]
                with self.journal.recording(
                    scope=device.instance_id,
                    action=Action.BLOCK,
                    fingerprint=fingerprint(device).value,
                ):
                    result = self.live.block(device)
                    self.journal.record(result)
                blocked += result.ok and result.changed
                failed += not result.ok
            return ReconcileSummary(
                evaluated=len(devices), changed=blocked, blocked=blocked, failed=failed
            )
        report = rollback(self.journal, self.live, devices, reason=trigger)
        released = report.restored + report.released
        return ReconcileSummary(
            evaluated=len(devices), changed=released, released=released, failed=len(report.failed)
        )

    # devices
    def plug(self, device: UsbDevice, *, at: datetime | None = None) -> UsbDevice:
        self.connected.append(Conn(device, at or self.clock.now()))
        return device

    def blocked(self) -> set[str]:
        return {
            conn.device.instance_id for conn in self.connected if self.fake.is_blocked(conn.device)
        }

    def restricted_ids(self) -> set[str | None]:
        return {call.instance_id for call in self.fake.calls_for(*RESTRICTING)}

    # lockdown helpers
    def engage(self, minutes: int | None = 10, **kwargs: Any) -> Any:
        return self.manager.engage(actor="alice", channel=CHANNEL, minutes=minutes, **kwargs)

    def engage_confirmed(self, minutes: int = 10) -> None:
        result = self.engage(minutes)
        self.manager.confirm(result.change.id, actor="alice", channel=CHANNEL)

    def assert_released(self) -> None:
        """Nothing restricted, nothing journaled, no timer left, no change pending."""
        assert self.store.get_lockdown().state == "idle"
        assert self.manager.state is LockdownState.IDLE and not self.manager.active
        assert self.blocked() == set()
        assert not self.fake.default_deny
        assert self.journal.open_records() == []
        assert self.timer.armed == {}
        assert self.store.pending_changes() == []


BLOCKED = {"test/1-1", "test/1-6"}
PROTECTED = {"test/1-2", "test/1-4", "test/1-5", "test/1-9"}
EXEMPT = {"test/1-8"}


def populate(machine: Machine) -> None:
    """Devices present before the lockdown: what each should become is in the sets above."""
    before = machine.clock.now() - timedelta(minutes=5)
    machine.plug(flash_drive(), at=before)  # storage: blocked
    machine.plug(phone(), at=before)  # imaging counts as storage: blocked
    machine.plug(keyboard(), at=before)  # input only: protected
    machine.plug(hub(), at=before)  # hub: protected
    composite = machine.plug(storage_with_keyboard(), at=before)
    # Storage beside a keyboard has no category protection, but this one is enrolled.
    machine.store.add_enrolment(fingerprint(composite).value, "1-5", by="alice")
    serial = make_device(
        instance_id="test/1-8",
        product_id=0x0008,
        serial=None,
        product="Example Serial",
        interfaces=(CDC_ACM,),
        bus_path="1-8",
    )
    machine.plug(serial, at=before)  # not storage, there before: exempt
    built_in = flash_drive(instance_id="test/1-9", serial="TEST0009INTL", bus_path="1-9")
    machine.plug(replace(built_in, removable=False), at=before)  # built in: protected


@pytest.fixture
def machine(tmp_path: Path, clock: FakeClock) -> Machine:
    built = Machine(tmp_path, clock)
    populate(built)
    return built


# --- engage and commit-confirm -----------------------------------------------------------


def test_engage_lists_applies_and_waits_for_confirmation(
    machine: Machine, clock: FakeClock
) -> None:
    start = clock.now()
    result = machine.engage(10, reason="suspected intrusion")
    outcomes = {item["instance_id"]: item["outcome"] for item in result.change.preview}
    assert {key for key, value in outcomes.items() if value == "block"} == BLOCKED
    assert {key for key, value in outcomes.items() if value == "protected"} == PROTECTED
    assert {key for key, value in outcomes.items() if value == "exempt"} == EXEMPT
    status = result.status
    assert status.state is LockdownState.ACTIVE and status.active
    assert status.expires_at == start + timedelta(minutes=10) and status.remaining_seconds == 600
    assert status.pending_change_id == result.change.id
    assert status.confirm_remaining_seconds == 60 and status.external_timer_armed
    assert result.summary.blocked == 2 and result.change.status == "awaiting"
    assert machine.blocked() == BLOCKED and machine.fake.default_deny
    # The out-of-process safeties: the lockdown timer at expiry, and the rollback timer
    # shortly after the confirmation deadline.
    assert machine.timer.armed == {
        LOCKDOWN_TIMER: start + timedelta(minutes=10),
        CONFIRM_TIMER_PREFIX + result.change.id: start + timedelta(seconds=90),
    }
    assert set(machine.timer.commands.values()) == {RECOVER_ARGV}
    assert machine.events() == ["lockdown.engaged", "change.pending"]
    assert machine.data("change.pending")["would_block"] == 2
    assert machine.data("lockdown.engaged")["summary"]["blocked"] == 2

    status = machine.manager.confirm(result.change.id, actor="alice", channel=CHANNEL)
    assert status.pending_change_id is None and status.active
    assert machine.timer.armed == {LOCKDOWN_TIMER: start + timedelta(minutes=10)}
    assert machine.events()[-1] == "change.confirmed"
    assert machine.restricted_ids() & PROTECTED == set()


def test_an_unconfirmed_lockdown_rolls_back_by_itself(machine: Machine, clock: FakeClock) -> None:
    machine.engage(10)
    clock.advance(59)
    assert machine.confirmations.tick() == [] and machine.manager.active
    clock.advance(1)
    [rolled] = machine.confirmations.tick()
    machine.assert_released()
    [history] = machine.store.lockdown_history()
    assert history.end_reason == "unconfirmed" and history.ended_by == "system"
    assert machine.events()[-2:] == ["lockdown.lifted", "change.rolled_back"]
    assert machine.data("lockdown.lifted")["end_reason"] == "unconfirmed"
    assert machine.data("change.rolled_back")["change_id"] == rolled
    assert machine.restricted_ids() & PROTECTED == set()


def test_a_late_confirmation_rolls_back_and_is_refused(machine: Machine, clock: FakeClock) -> None:
    result = machine.engage(10)
    clock.advance(61)  # no tick ran in between
    with pytest.raises(ConfirmationError) as late:
        machine.manager.confirm(result.change.id, actor="alice", channel=CHANNEL)
    assert late.value.code == "confirmation_expired"
    machine.assert_released()
    with pytest.raises(ConfirmationError) as gone:
        machine.manager.confirm(result.change.id, actor="alice", channel=CHANNEL)
    assert gone.value.code == "no_pending_change"


def test_confirmation_needs_the_same_channel_and_moving_the_clock_does_not_help(
    machine: Machine, clock: FakeClock
) -> None:
    result = machine.engage(10)
    with pytest.raises(ConfirmationError) as wrong:
        machine.manager.confirm(result.change.id, actor="alice", channel="session-2")
    assert wrong.value.code == "wrong_channel"
    assert machine.manager.status().pending_change_id == result.change.id
    # Setting the wall clock back does not stretch the confirmation window.
    clock.set(clock.now() - timedelta(hours=1))
    clock.advance(60)
    assert machine.confirmations.tick() == [result.change.id]
    machine.assert_released()


def test_engage_is_refused_unless_idle_and_valid(machine: Machine) -> None:
    for minutes in (0, -5, 121, True, "10"):
        with pytest.raises(LockdownError) as bad:
            machine.engage(minutes)  # type: ignore[arg-type]
        assert bad.value.code == "invalid_duration"
    with pytest.raises(LockdownError) as bad_reason:
        machine.engage(10, reason="x" * 257)
    assert bad_reason.value.code == "invalid_reason"
    with pytest.raises(LockdownError):
        machine.engage(10, reason="line one" + chr(10) + "line two")
    with pytest.raises(ValueError):
        machine.manager.engage(actor="", channel=CHANNEL, minutes=5)
    assert machine.store.pending_changes() == [] and machine.fake.calls == ()
    machine.engage(None)  # the default duration
    assert machine.manager.status().remaining_seconds == 600
    with pytest.raises(LockdownError) as twice:
        machine.engage(10)
    assert twice.value.code == "lockdown_active"


def test_engage_fails_cleanly_when_the_lockdown_timer_cannot_be_armed(machine: Machine) -> None:
    machine.timer.raise_on["arm:" + LOCKDOWN_TIMER] = RuntimeError("timer service unavailable")
    with pytest.raises(RuntimeError, match="timer service unavailable"):
        machine.engage(10)
    machine.assert_released()
    assert machine.restricted_ids() == set()  # nothing was blocked without the safety net
    assert machine.events()[-1] == "change.rolled_back"


def test_lockdown_refuses_to_run_inside_a_database_transaction(machine: Machine) -> None:
    with machine.db.transaction(), pytest.raises(LockdownError) as caught:
        machine.engage(10)
    assert caught.value.code == "in_transaction"


def test_a_failing_audit_never_stops_a_lockdown(machine: Machine) -> None:
    def broken(event: str) -> None:
        raise RuntimeError("audit sink down")

    machine.audit_hook = broken
    machine.engage_confirmed()
    assert machine.blocked() == BLOCKED
    machine.manager.lift(actor="alice", credential=PASSWORD)
    machine.assert_released()


# --- renew and lift ----------------------------------------------------------------------


def test_renew_restarts_the_dead_man_timer(machine: Machine, clock: FakeClock) -> None:
    with pytest.raises(LockdownError) as idle:
        machine.manager.renew(actor="alice", minutes=5)
    assert idle.value.code == "lockdown_not_active"
    machine.engage_confirmed(10)
    clock.advance(timedelta(minutes=5))
    machine.timer.log.clear()
    status = machine.manager.renew(actor="alice", minutes=30)
    assert status.renew_count == 1 and status.remaining_seconds == 1800
    assert status.expires_at == clock.now() + timedelta(minutes=30)
    assert machine.timer.log == [("cancel", LOCKDOWN_TIMER), ("arm", LOCKDOWN_TIMER)]
    assert machine.timer.armed[LOCKDOWN_TIMER] == clock.now() + timedelta(minutes=30)
    assert machine.data("lockdown.renewed")["renew_count"] == 1
    with pytest.raises(LockdownError):
        machine.manager.renew(actor="alice", minutes=121)
    clock.advance(timedelta(minutes=30) - timedelta(seconds=1))
    machine.manager.tick()
    assert machine.manager.active
    clock.advance(1)
    machine.manager.tick()
    machine.assert_released()
    assert machine.store.lockdown_history()[0].renew_count == 1


def test_a_renewal_whose_timer_fails_keeps_the_lockdown_and_retries(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    machine.timer.raise_on["arm:" + LOCKDOWN_TIMER] = RuntimeError("busy")
    status = machine.manager.renew(actor="alice", minutes=20)
    assert status.active and not status.external_timer_armed
    assert machine.data("lockdown.renewed")["external_timer"].startswith("failed")
    clock.advance(1)
    machine.manager.tick()
    assert machine.manager.status().external_timer_armed
    assert machine.timer.armed[LOCKDOWN_TIMER] == clock.now() + timedelta(minutes=20) - timedelta(
        seconds=1
    )


def test_lifting_needs_the_password_or_a_recovery_code(machine: Machine) -> None:
    with pytest.raises(LockdownError) as idle:
        machine.manager.lift(actor="alice", credential=PASSWORD)
    assert idle.value.code == "lockdown_not_active"
    machine.engage_confirmed()
    for credential in (
        Credential("password", "guess"),
        Credential("password", ""),
        Credential("recovery_code", "WRONG"),
    ):
        with pytest.raises(AuthError) as refused:
            machine.manager.lift(actor="alice", credential=credential)
        assert refused.value.code == "reauthentication_failed"
    machine.passwords.raises = RuntimeError("account store unavailable")
    with pytest.raises(AuthError):
        machine.manager.lift(actor="alice", credential=PASSWORD)
    machine.passwords.raises = None
    # Still in force after every refusal.
    assert machine.manager.active and machine.blocked() == BLOCKED
    result = machine.manager.lift(
        actor="alice", credential=Credential("recovery_code", RECOVERY_CODE)
    )
    assert result.summary is not None and result.summary.released >= 3
    machine.assert_released()
    [history] = machine.store.lockdown_history()
    assert (history.end_reason, history.ended_by) == ("lifted", "alice")
    assert machine.data("lockdown.lifted")["found_at_start"] is False
    assert "secret" not in repr(PASSWORD) and PASSWORD.secret not in repr(PASSWORD)


def test_lifting_an_unconfirmed_lockdown_withdraws_the_pending_change(machine: Machine) -> None:
    result = machine.engage(10)
    machine.manager.lift(actor="alice", credential=PASSWORD)
    machine.assert_released()
    assert machine.confirmations.tick() == []
    with pytest.raises(ConfirmationError):
        machine.manager.confirm(result.change.id, actor="alice", channel=CHANNEL)


def test_force_idle_leaves_the_release_to_the_kill_switch_rollback(machine: Machine) -> None:
    machine.engage_confirmed()
    machine.manager.force_idle(actor="local-console")
    assert machine.store.get_lockdown().state == "idle" and not machine.manager.active
    assert machine.timer.armed == {}
    assert machine.store.lockdown_history()[0].end_reason == "killswitch"
    # State only: the devices are released by the rollback the service runs next.
    assert machine.blocked() == BLOCKED
    machine.reconcile("killswitch")
    machine.assert_released()
    machine.manager.force_idle()  # idle already: nothing happens
    assert len(machine.store.lockdown_history()) == 1
    with pytest.raises(LockdownError) as not_lifting:
        machine.manager.finish_lift()
    assert not_lifting.value.code == "not_lifting"
    with pytest.raises(ValueError):
        ReconcileSummary.from_dict({"blocked": 1.5})


# --- the dead-man timer and the clock ----------------------------------------------------


@pytest.mark.parametrize("jump", [timedelta(0), -timedelta(hours=1), timedelta(days=1)])
def test_expiry_while_running_follows_the_monotonic_clock(
    machine: Machine, clock: FakeClock, jump: timedelta
) -> None:
    machine.engage_confirmed(10)
    clock.advance(timedelta(minutes=2))
    machine.manager.tick()
    clock.set(clock.now() + jump)
    machine.manager.tick()
    assert machine.manager.active
    if jump:
        # The wall clock moved: the operating-system timer follows the true expiry.
        expected = clock.now() + timedelta(minutes=8)
        assert machine.timer.armed[LOCKDOWN_TIMER] == expected
        assert machine.manager.status().expires_at == expected
    clock.advance(timedelta(minutes=8) - timedelta(seconds=1))
    machine.manager.tick()
    assert machine.manager.active and machine.blocked() == BLOCKED
    clock.advance(1)
    machine.manager.tick()
    machine.assert_released()
    assert machine.events()[-1] == "lockdown.expired"
    assert machine.data("lockdown.expired")["found_at_start"] is False
    assert machine.restricted_ids() & PROTECTED == set()


def test_expiry_while_stopped_is_completed_at_start(machine: Machine, clock: FakeClock) -> None:
    machine.engage_confirmed(10)
    clock.advance(timedelta(minutes=11))
    assert machine.crash_and_restart() == "lift_pending"
    machine.assert_released()
    assert machine.data("lockdown.expired")["found_at_start"] is True
    assert machine.store.lockdown_history()[0].end_reason == "expired"
    # Lifting state means not active from the first instant: nothing was re-blocked.
    assert machine.triggers[-1] == "start" and machine.restricted_ids() & PROTECTED == set()


def test_a_restart_resumes_the_remainder(machine: Machine, clock: FakeClock) -> None:
    machine.engage_confirmed(10)
    clock.advance(timedelta(minutes=4))
    machine.manager.tick()  # persists 360 s remaining
    clock.advance(30)
    assert machine.crash_and_restart() == "resumed"
    status = machine.manager.status()
    assert status.active and status.remaining_seconds == 330
    assert machine.blocked() == BLOCKED
    assert machine.timer.armed[LOCKDOWN_TIMER] == clock.now() + timedelta(seconds=330)
    # A device plugged in after the restart is held too.
    machine.plug(flash_drive(instance_id="test/2-1", serial="TEST0021NEW1", bus_path="2-1"))
    machine.reconcile("arrival")
    assert "test/2-1" in machine.blocked()
    clock.advance(329)
    machine.manager.tick()
    assert machine.manager.active
    clock.advance(1)
    machine.manager.tick()
    machine.assert_released()


def test_a_clock_set_back_while_stopped_cannot_stretch_a_lockdown(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    clock.advance(timedelta(minutes=2))
    machine.manager.tick()  # persists 480 s remaining
    clock.set(clock.now() - timedelta(days=1))
    assert machine.crash_and_restart() == "resumed"
    assert machine.manager.status().remaining_seconds == 480
    assert machine.manager.status().expires_at == clock.now() + timedelta(seconds=480)
    clock.advance(480)
    machine.manager.tick()
    machine.assert_released()


def test_a_clock_set_forward_while_stopped_ends_a_lockdown(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    clock.set(clock.now() + timedelta(days=1))
    assert machine.crash_and_restart() == "lift_pending"
    machine.assert_released()
    assert machine.store.lockdown_history()[0].end_reason == "expired"


def test_an_impossible_remainder_is_a_clock_anomaly(machine: Machine) -> None:
    machine.engage_confirmed(10)
    machine.db.execute("UPDATE lockdown_state SET remaining_seconds = ?", (121 * 60,))
    assert machine.crash_and_restart() == "lift_pending"
    machine.assert_released()
    assert machine.data("lockdown.expired")["end_reason"] == "clock_anomaly"


def test_the_dead_man_lifts_even_when_the_database_refuses_writes(
    machine: Machine, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine.engage_confirmed(10)

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise StoreError("disk full")

    monkeypatch.setattr(machine.store, "save_lockdown", refuse)
    clock.advance(timedelta(minutes=10))
    machine.manager.tick()
    # Released although nothing could be recorded.
    assert (
        not machine.manager.active and machine.blocked() == set() and not machine.fake.default_deny
    )
    assert machine.store.get_lockdown().state == "active"
    monkeypatch.undo()
    machine.manager.tick()  # the database works again: the record is completed
    machine.assert_released()
    assert machine.store.lockdown_history()[0].end_reason == "expired"


def test_a_second_manager_on_the_same_database_sees_the_same_state(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    with Database(machine.home / "portlock.db") as other_db:
        store = StateStore(other_db, clock=clock)
        other = LockdownManager(
            store,
            clock=clock,
            config=machine.config,
            audit=machine.record,
            reconcile=machine.reconcile,
            timer=FakeTimer(),
            recover_argv=RECOVER_ARGV,
            kill_switch=KillSwitch(machine.config_dir / "DISABLE_ENFORCEMENT", Privacy()),
            credentials=Passwords(),
            confirmations=CommitConfirm(
                store, clock=clock, timeout_seconds=60, audit=machine.record
            ),
            devices=lambda: [],
            protection=machine.live.protection,
        )
        status = other.status()
        assert status.state is LockdownState.ACTIVE and status.engaged_by == "alice"
        # Not in force in that process until it has resumed.
        assert not other.active


# --- crashes between the steps of engage and lift ----------------------------------------


def _crash_on_call(target: Any, name: str, number: int, monkeypatch: pytest.MonkeyPatch) -> None:
    original = getattr(target, name)
    calls = {"n": 0}

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == number:
            raise Crash(f"{name} #{number}")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, name, wrapper)


def _crash_on_trigger(machine: Machine, trigger: str) -> None:
    def hook(seen: str) -> None:
        if seen == trigger:
            raise Crash(trigger)

    machine.reconcile_hook = hook


def _crash_on_event(machine: Machine, event: str) -> None:
    def hook(seen: str) -> None:
        if seen == event:
            raise Crash(event)

    machine.audit_hook = hook


ENGAGE_CRASHES: dict[str, Callable[[Machine, pytest.MonkeyPatch], None]] = {
    # The pending change is written ahead; the lockdown row is not yet engaging.
    "after the change was written": lambda m, mp: _crash_on_call(m.store, "save_lockdown", 1, mp),
    # Engaging is stored; the operating-system timer is not yet armed.
    "after engaging was stored": lambda m, mp: m.timer.raise_on.update(
        {"arm:" + LOCKDOWN_TIMER: Crash("arm")}
    ),
    # The timer is armed; no device is blocked yet.
    "after the timer was armed": lambda m, mp: _crash_on_trigger(m, "lockdown.engaged"),
    # Devices and default-deny are applied; "active" is not stored.
    "after devices were blocked": lambda m, mp: _crash_on_call(m.store, "save_lockdown", 2, mp),
    # Active is stored; the engage is not audited.
    "after active was stored": lambda m, mp: _crash_on_event(m, "lockdown.engaged"),
    # Audited; the change is not yet marked as awaiting confirmation.
    "after the engage was audited": lambda m, mp: _crash_on_call(
        m.store, "set_pending_status", 1, mp
    ),
    # Fully engaged, awaiting confirmation that never came.
    "while awaiting confirmation": lambda m, mp: None,
}


@pytest.mark.parametrize("point", list(ENGAGE_CRASHES))
def test_a_crash_during_engage_is_rolled_back_at_restart(
    machine: Machine, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    ENGAGE_CRASHES[point](machine, monkeypatch)
    if point == "while awaiting confirmation":
        machine.engage(10)
    else:
        with pytest.raises(Crash):
            machine.engage(10)
    monkeypatch.undo()
    outcome = machine.crash_and_restart()
    assert outcome in ("idle", "lift_pending")
    machine.assert_released()
    history = machine.store.lockdown_history()
    assert [h.end_reason for h in history] == ([] if outcome == "idle" else ["unconfirmed"])
    assert "change.rolled_back" in machine.events()
    assert machine.restricted_ids() & PROTECTED == set()
    # The machine is usable afterwards: a new lockdown engages and confirms.
    machine.engage_confirmed(5)
    assert machine.blocked() == BLOCKED


def test_a_confirmed_lockdown_survives_a_crash(machine: Machine, clock: FakeClock) -> None:
    machine.engage_confirmed(10)
    clock.advance(5)
    assert machine.crash_and_restart() == "resumed"
    assert machine.manager.active and machine.blocked() == BLOCKED and machine.fake.default_deny
    assert machine.store.pending_changes() == []
    assert machine.timer.armed == {LOCKDOWN_TIMER: clock.now() + timedelta(seconds=595)}


LIFT_CRASHES: dict[str, Callable[[Machine, pytest.MonkeyPatch], None]] = {
    # "lifting" is stored; nothing is released yet.
    "after lifting was stored": lambda m, mp: _crash_on_trigger(m, "lockdown.lifted"),
    # Released; the operating-system timer is still armed.
    "after devices were released": lambda m, mp: m.timer.raise_on.update(
        {"cancel:" + LOCKDOWN_TIMER: Crash("cancel")}
    ),
    # The timer is cancelled; "idle" and the history row are not stored.
    "after the timer was cancelled": lambda m, mp: _crash_on_call(m.store, "save_lockdown", 2, mp),
    # Idle is stored; the lift is not audited.
    "after idle was stored": lambda m, mp: _crash_on_event(m, "lockdown.lifted"),
}


@pytest.mark.parametrize("point", list(LIFT_CRASHES))
def test_a_crash_during_lift_is_completed_at_restart(
    machine: Machine, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    machine.engage_confirmed(10)
    LIFT_CRASHES[point](machine, monkeypatch)
    with pytest.raises(Crash):
        machine.manager.lift(actor="alice", credential=PASSWORD)
    monkeypatch.undo()
    outcome = machine.crash_and_restart()
    assert outcome == ("idle" if point == "after idle was stored" else "lift_pending")
    machine.assert_released()
    [history] = machine.store.lockdown_history()
    assert (history.end_reason, history.ended_by) == ("lifted", "alice")
    if outcome == "lift_pending":
        assert machine.data("lockdown.lifted")["found_at_start"] is True
    assert machine.restricted_ids() & PROTECTED == set()


# --- protection, exemptions and the plan -------------------------------------------------


def test_protected_devices_are_never_touched_through_a_whole_lockdown(
    machine: Machine, clock: FakeClock
) -> None:
    for plugged in (
        keyboard(instance_id="test/3-1", bus_path="3-1"),
        mouse(instance_id="test/3-2"),
    ):
        machine.plug(plugged)
    machine.engage_confirmed(10)
    machine.reconcile("periodic")
    machine.manager.renew(actor="alice", minutes=10)
    clock.advance(timedelta(minutes=10))
    machine.manager.tick()
    machine.assert_released()
    protected = PROTECTED | {"test/3-1", "test/3-2"}
    # No restricting call ever reached them...
    assert machine.restricted_ids() & protected == set()
    # ...and nothing about them changed: the only calls naming them are the re-admission
    # pass after default-deny, which found each one already usable.
    for call in machine.fake.calls:
        if call.instance_id in protected:
            assert call.action is Action.UNBLOCK
            assert call.result is not None and call.result.ok and not call.result.changed
    plan = {item.instance_id: item for item in machine.manager.plan()}
    assert plan["test/1-5"].outcome == "protected" and "enrolled" in plan["test/1-5"].reason
    assert plan["test/1-9"].outcome == "protected"


@pytest.mark.parametrize("storage", [True, False])
@pytest.mark.parametrize("before", [True, False])
@pytest.mark.parametrize("input_only", [True, False])
@pytest.mark.parametrize("allow_input", [True, False])
def test_the_exemption_truth_table(
    tmp_path: Path,
    clock: FakeClock,
    storage: bool,
    before: bool,
    input_only: bool,
    allow_input: bool,
) -> None:
    machine = Machine(tmp_path, clock, config=LockdownConfig(allow_new_input_devices=allow_input))
    machine.engage_confirmed(10)
    interfaces = (keyboard().interfaces if input_only else (CDC_ACM,)) + (
        flash_drive().interfaces if storage else ()
    )
    device = make_device(interfaces=interfaces)
    connected_at = clock.now() + (-timedelta(seconds=1) if before else timedelta(seconds=1))
    exempt = machine.manager.is_exempt(device, connected_at=connected_at)
    expected = not storage and (before or (allow_input and input_only))
    assert exempt is expected


def test_a_device_mixing_input_with_another_function_is_held(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    tap = make_device(
        instance_id="test/4-1",
        product_id=0x0041,
        serial="TEST0041TAP1",
        interfaces=(keyboard().interfaces[0], make_device(interfaces=(CDC_ACM,)).interfaces[0]),
        bus_path="4-1",
    )
    machine.plug(tap)
    assert not machine.manager.is_exempt(tap, connected_at=clock.now())
    [item] = [i for i in machine.manager.plan() if i.instance_id == "test/4-1"]
    # The default scope covers it (DESIGN 14.5), so the lockdown blocks it.
    assert item.outcome == "block"
    machine.reconcile("arrival")
    assert "test/4-1" in machine.blocked()


# --- the kill switch ---------------------------------------------------------------------


def test_the_kill_switch_is_honoured_only_in_a_private_directory(machine: Machine) -> None:
    switch_file = machine.config_dir / "DISABLE_ENFORCEMENT"
    switch = KillSwitch(switch_file, machine.privacy)
    assert switch.check().present is False and not switch.is_set()
    switch_file.write_text("")
    assert switch.is_set() and machine.privacy.asked[-1] == machine.config_dir
    with pytest.raises(LockdownError) as refused:
        machine.engage(10)
    assert refused.value.code == "killswitch_active"
    assert machine.fake.calls == ()

    machine.privacy.private = False
    state = switch.check()
    assert state.present and not state.honoured and "not verified to be private" in state.reason
    machine.engage(10)  # a planted file in a shared directory does not disable anything
    assert machine.blocked() == BLOCKED


def test_a_kill_switch_whose_privacy_cannot_be_checked_is_not_honoured(tmp_path: Path) -> None:
    class Broken:
        def check(self, path: Any) -> PrivacyReport:
            raise OSError("cannot stat")

    (tmp_path / "DISABLE_ENFORCEMENT").write_text("")
    assert not KillSwitch(tmp_path / "DISABLE_ENFORCEMENT", Broken()).is_set()
    with pytest.raises(TypeError):
        KillSwitch(tmp_path / "DISABLE_ENFORCEMENT", object())  # type: ignore[arg-type]


# --- rollback and recover ----------------------------------------------------------------


class Spy(Enforcer):
    """Delegates to a FakeEnforcer and remembers every entry given to restore."""

    def __init__(self, inner: FakeEnforcer) -> None:
        self.inner = inner
        self.restored: list[JournalEntry] = []

    def capabilities(self) -> EnforcerCapabilities:
        return self.inner.capabilities()

    def block(self, device: UsbDevice) -> EnforcementResult:
        return self.inner.block(device)

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        return self.inner.unblock(device)

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        return self.inner.set_read_only(device, read_only)

    def eject(self, device: UsbDevice) -> EnforcementResult:
        return self.inner.eject(device)

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        return self.inner.set_default_deny(enabled)

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        self.restored.extend(entries)
        return self.inner.restore(entries)


def test_rollback_restores_newest_first_and_never_restricts(
    tmp_path: Path, clock: FakeClock
) -> None:
    journal = RecoveryJournal(tmp_path / JOURNAL_FILE_NAME, clock=clock)
    journaling = [True]

    def hook(entry: JournalEntry) -> None:
        if journaling[0]:
            journal.write_ahead(entry)

    fake = FakeEnforcer(write_ahead=hook)
    a = flash_drive(instance_id="test/a")
    b = flash_drive(instance_id="test/b")
    held = flash_drive(instance_id="test/held")
    stray = flash_drive(instance_id="test/stray")
    a_hub = hub()

    def journaled(scope: str, action: Action, call: Callable[[], EnforcementResult]) -> None:
        with journal.recording(scope=scope, action=action, fingerprint=None):
            journal.record(call())

    journaled(GLOBAL_SCOPE, Action.DEFAULT_DENY_ON, lambda: fake.set_default_deny(True))
    journaled("test/a", Action.BLOCK, lambda: fake.block(a))
    journaled("test/b", Action.BLOCK, lambda: fake.block(b))
    journaled("test/a", Action.READ_ONLY, lambda: fake.set_read_only(a, True))
    journal.add_hold(scope="test/held", fingerprint=None)
    journal.add_hold(scope="test/absent", fingerprint=None)
    # Kept out while nothing was journaling (the hold's device, and a device that arrived
    # under default-deny while the service was down): no record of their own.
    journaling[0] = False
    for device in (held, stray, a_hub):
        assert fake.block(device).ok
    journaling[0] = True
    fake.clear_calls()
    fake.fail(Action.RESTORE, "device busy", times=1)
    spy = Spy(fake)

    report = rollback(journal, spy, [a, b, held, stray, a_hub], reason="stop")

    assert [entry.target for entry in spy.restored] == [
        "test/a/ro",
        "test/b/authorized",
        "test/a/authorized",
        "authorized_default",
    ]
    assert report.restored == 3 and report.released == 2 and report.readmitted == 1
    assert len(report.failed) == 1 and "device busy" in report.failed[0][1]
    assert report.remaining == 1  # the read-only entry that failed stays open
    assert [r.entry.target for r in journal.open_records() if r.entry] == ["test/a/ro"]
    assert not fake.is_blocked(a) and not fake.is_blocked(b) and not fake.is_blocked(held)
    assert not fake.is_blocked(stray) and fake.is_blocked(a_hub)  # hubs are not re-admitted
    assert not fake.default_deny
    assert fake.calls_for(*RESTRICTING) == ()
    assert report.to_dict()["failed"][0][1].startswith("device busy")


def test_rollback_without_default_deny_does_not_readmit(tmp_path: Path, clock: FakeClock) -> None:
    journal = RecoveryJournal(tmp_path / JOURNAL_FILE_NAME, clock=clock)
    fake = FakeEnforcer()
    other = flash_drive(instance_id="test/other")
    fake.block(other)  # blocked by something else entirely
    report = rollback(journal, fake, [other], reason="stop")
    assert report.readmitted == 0 and fake.is_blocked(other)


def test_recover_works_without_the_service_or_the_database(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    machine.db.close()
    (machine.home / "portlock.db").write_bytes(b"this is not a database" * 100)
    live = SafeEnforcer(machine.fake, SafetyContext, dry_run=False)
    devices = [conn.device for conn in machine.connected]
    with pytest.raises(NotPrivilegedError):
        recover(machine.home, live, devices, clock=clock, is_admin=lambda: False)
    assert machine.blocked() == BLOCKED  # refused: nothing changed

    report = recover(
        machine.home, live, devices, clock=clock, is_admin=lambda: True, timer=machine.timer
    )
    assert report.restored == 3 and report.failed == () and report.remaining == 0
    assert machine.blocked() == set() and not machine.fake.default_deny
    assert LOCKDOWN_TIMER not in machine.timer.armed
    marker = consume_recover_marker(machine.home)
    assert marker is not None and marker["actor"] == "local-console"
    assert marker["at"] == clock.now() and marker["report"]["restored"] == 3
    assert consume_recover_marker(machine.home) is None


def test_a_recovery_ends_the_lockdown_the_database_still_describes(
    machine: Machine, clock: FakeClock
) -> None:
    machine.engage_confirmed(10)
    clock.advance(60)
    machine.db.close()
    live = SafeEnforcer(machine.fake, SafetyContext, dry_run=False)
    recover(
        machine.home,
        live,
        [c.device for c in machine.connected],
        clock=clock,
        is_admin=lambda: True,
    )
    marker = consume_recover_marker(machine.home)
    assert marker is not None
    clock.advance(60)
    assert machine.crash_and_restart(recovered_at=marker["at"]) == "lift_pending"
    machine.assert_released()
    assert machine.store.lockdown_history()[0].end_reason == "recovered"


def test_recover_skips_a_tampered_journal_line(machine: Machine, clock: FakeClock) -> None:
    machine.engage_confirmed(10)
    machine.db.close()
    journal_file = machine.home / JOURNAL_FILE_NAME
    with journal_file.open("ab") as stream:
        stream.write(
            b'{"action":"block","entry":{"applied":"0","kind":"sysfs_authorized",'
            b'"previous":"1","target":"/etc/shadow"},"fp":null,"id":"ffffffffffffffff",'
            b'"op":"open","scope":"test/1-1","ts":"2026-01-01T00:00:00Z"}\n'
        )
        stream.write(b"rm -rf /\n")
    assert RecoveryJournal(journal_file, clock=clock).corrupt_lines == 2
    spy = Spy(machine.fake)
    report = recover(
        machine.home, spy, [c.device for c in machine.connected], clock=clock, is_admin=lambda: True
    )
    assert report.restored == 3 and report.failed == ()
    assert all(entry.target != "/etc/shadow" for entry in spy.restored)
    assert machine.blocked() == set()


def test_an_unreadable_recover_marker_is_reported_and_removed(tmp_path: Path) -> None:
    (tmp_path / RECOVER_MARKER).write_text("{not json")
    assert consume_recover_marker(tmp_path) == {"invalid": True}
    assert not (tmp_path / RECOVER_MARKER).exists()


# --- commit-confirm as a general mechanism -----------------------------------------------


class Toggle:
    """A change handler for a simple on/off setting (standing in for enforce mode)."""

    def __init__(self) -> None:
        self.on = False
        self.applied: list[str] = []
        self.reverted: list[tuple[str, bool]] = []
        self.fail_apply: Exception | None = None
        self.fail_revert = 0

    def preview(self, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return [{"instance_id": "test/1-1", "outcome": "block"}]

    def apply(self, change: PendingChangeRecord) -> Mapping[str, Any] | None:
        self.applied.append(change.id)
        self.on = True
        if self.fail_apply is not None:
            raise self.fail_apply
        return {"mode": "enforce"}

    def revert(self, change: PendingChangeRecord, *, reason: str, at_start: bool) -> None:
        if self.fail_revert:
            self.fail_revert -= 1
            raise RuntimeError("cannot revert yet")
        self.reverted.append((change.id, at_start))
        self.on = False


@pytest.fixture
def confirm_setup(
    db: Database, clock: FakeClock
) -> tuple[CommitConfirm, Toggle, FakeTimer, list[str]]:
    events: list[str] = []
    timer = FakeTimer()
    store = StateStore(db, clock=clock)
    confirmations = CommitConfirm(
        store,
        clock=clock,
        timeout_seconds=60,
        audit=lambda event, **_: events.append(event),
        timer=timer,
        recover_argv=RECOVER_ARGV,
    )
    toggle = Toggle()
    confirmations.register(CHANGE_ENFORCE_MODE, toggle)
    return confirmations, toggle, timer, events


def test_commit_confirm_keeps_a_confirmed_change(confirm_setup: Any) -> None:
    confirmations, toggle, timer, events = confirm_setup
    change = confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    assert toggle.on and change.status == "awaiting" and change.result == {"mode": "enforce"}
    assert CONFIRM_TIMER_PREFIX + change.id in timer.armed
    with pytest.raises(ConfirmationError) as again:
        confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    assert again.value.code == "change_pending"
    confirmations.confirm(change.id, actor="alice", channel="tty1")
    assert toggle.on and confirmations.pending() == [] and timer.armed == {}
    assert events == ["change.pending", "change.confirmed"]


def test_commit_confirm_rolls_back_a_change_that_fails_to_apply(confirm_setup: Any) -> None:
    confirmations, toggle, timer, events = confirm_setup
    toggle.fail_apply = RuntimeError("half applied")
    with pytest.raises(RuntimeError, match="half applied"):
        confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    assert not toggle.on and confirmations.pending() == [] and timer.armed == {}
    assert events == ["change.rolled_back"]


def test_commit_confirm_applies_nothing_without_its_backstop_timer(confirm_setup: Any) -> None:
    confirmations, toggle, timer, _ = confirm_setup

    def refuse(name: str, at: datetime, argv: Sequence[str]) -> None:
        raise RuntimeError("timer service down")

    timer.arm = refuse  # type: ignore[method-assign]
    with pytest.raises(ConfirmationError) as caught:
        confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    assert caught.value.code == "timer_unavailable"
    assert toggle.applied == [] and confirmations.pending() == []


def test_commit_confirm_retries_a_failed_rollback(confirm_setup: Any, clock: FakeClock) -> None:
    confirmations, toggle, _, events = confirm_setup
    change = confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    toggle.fail_revert = 1
    clock.advance(60)
    assert confirmations.tick() == []
    assert toggle.on and [p.id for p in confirmations.pending()] == [change.id]
    clock.advance(1)
    assert confirmations.tick() == [change.id]
    assert not toggle.on and events[-1] == "change.rolled_back"


def test_commit_confirm_rolls_back_at_start_and_on_cancel(
    confirm_setup: Any, db: Database, clock: FakeClock
) -> None:
    confirmations, toggle, timer, _ = confirm_setup
    change = confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    # A new process: the change is found pending and rolled back before anything else.
    restarted = CommitConfirm(
        StateStore(db, clock=clock),
        clock=clock,
        timeout_seconds=60,
        audit=lambda *a, **k: None,
        timer=timer,
        recover_argv=RECOVER_ARGV,
    )
    restarted.register(CHANGE_ENFORCE_MODE, toggle)
    assert restarted.resume() == [change.id]
    assert toggle.reverted == [(change.id, True)] and timer.armed == {}
    second = restarted.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="tty1")
    assert restarted.cancel(second.id, actor="alice") and not toggle.on
    assert not restarted.cancel(second.id, actor="alice")


def test_commit_confirm_validates_its_inputs(
    confirm_setup: Any, db: Database, clock: FakeClock
) -> None:
    confirmations, toggle, _, _ = confirm_setup
    with pytest.raises(ConfirmationError) as unknown:
        confirmations.propose("format_disk", actor="alice", channel="tty1")
    assert unknown.value.code == "unknown_change_kind"
    with pytest.raises(ConfirmationError):
        confirmations.propose(CHANGE_ENFORCE_MODE, actor="alice", channel="")
    with pytest.raises(ValueError):
        confirmations.register(CHANGE_ENFORCE_MODE, toggle)
    with pytest.raises(TypeError):
        confirmations.register("other", object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CommitConfirm(StateStore(db, clock=clock), clock=clock, timeout_seconds=0, audit=print)
    assert confirmations.remaining_seconds("0000000000000000") is None
    # A backstop timer needs the command it is to run.
    for argv in ((), "portlock recover", ("portlock", "")):
        with pytest.raises(ValueError):
            CommitConfirm(
                StateStore(db, clock=clock),
                clock=clock,
                timeout_seconds=60,
                audit=print,
                timer=FakeTimer(),
                recover_argv=argv,  # type: ignore[arg-type]
            )
    with pytest.raises(TypeError):
        CommitConfirm(
            StateStore(db, clock=clock),
            clock=clock,
            timeout_seconds=60,
            audit=print,
            timer=object(),  # type: ignore[arg-type]
            recover_argv=RECOVER_ARGV,
        )
