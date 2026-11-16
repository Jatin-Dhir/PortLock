"""Convergence: what reaches the enforcer, and what is recorded when it cannot."""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive, hub, internal_webcam, keyboard, mouse, phone
from integration.harness import ADMIN, RECOVER_ARGV, START, Harness, make_config
from portlock.core.clock import FakeClock
from portlock.core.errors import StoreError
from portlock.core.models import Mode, UsbDevice
from portlock.core.store import ConnectionState, Outcome
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
    Tier,
)
from portlock.guard.fake import FakeBackend
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.service.daemon import Runtime, build_runtime

RESTRICTING = (Action.BLOCK, Action.READ_ONLY, Action.EJECT)
DENY_ALL: dict[str, Any] = {"version": 1, "name": "deny all", "default": {"access": "deny"}}


def _harness(tmp_path: Path, **options: Any) -> Harness:
    harness = Harness(tmp_path, **options)
    harness.boot()
    return harness


def test_a_protected_device_never_receives_a_restricting_call(tmp_path: Path) -> None:
    rng = random.Random(20260302)
    protected = [keyboard(), mouse(), hub(), internal_webcam()]
    pinned = flash_drive(instance_id="test/2-9", bus_path="2-9", serial="TEST00029999")
    others = [
        flash_drive(instance_id=f"test/3-{i}", bus_path=f"3-{i}", serial=f"TEST0003{i:04d}")
        for i in range(4)
    ] + [phone()]
    for case, (mode, lockdown) in enumerate(
        [(Mode.MONITOR, False), (Mode.ENFORCE, False), (Mode.MONITOR, True), (Mode.ENFORCE, True)]
    ):
        harness = _harness(tmp_path / f"case{case}", devices=[*protected, pinned])
        harness.service.replace_policy(DENY_ALL, actor=ADMIN)
        pin = harness.view("test/2-9").fingerprint
        harness.service.update_settings({"protected_fingerprints": [pin]}, actor=ADMIN)
        if mode is Mode.ENFORCE:
            harness.set_mode(Mode.ENFORCE)
        if lockdown:
            harness.engage(30)
        present = {device.instance_id for device in [*protected, pinned]}
        pool: list[UsbDevice] = [*protected, pinned, *others]
        for _ in range(40):
            device = rng.choice(pool)
            if device.instance_id in present:
                harness.unplug(device.instance_id)
                present.discard(device.instance_id)
            else:
                harness.plug(device)
                present.add(device.instance_id)
            if rng.random() < 0.2:
                harness.tick(rng.choice([1, 30, 61]))
        safe = {device.instance_id for device in [*protected, pinned]}
        hit = [c for c in harness.enforcer.calls_for(*RESTRICTING) if c.instance_id in safe]
        assert hit == [], (mode, lockdown, hit)
        assert harness.records("enforcement.refused") == []
        harness.crash()


def test_a_missing_capability_is_recorded_as_unsupported_never_as_blocked(tmp_path: Path) -> None:
    capabilities = EnforcerCapabilities(
        name="fake",
        privileged=True,
        block=False,
        read_only=False,
        eject=False,
        default_deny=False,
        notes=("no block mechanism here",),
    )
    harness = _harness(tmp_path, capabilities=capabilities, mode=Mode.ENFORCE)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert view.enforcement is not None
    assert view.enforcement.outcome is Outcome.UNSUPPORTED
    assert view.enforcement.os_state == "open"
    assert view.enforcement.error == "unsupported: no block mechanism here"
    assert harness.enforcer.calls == ()
    failed = harness.records("enforcement.failed")[-1]
    assert failed.data["error"].startswith("unsupported")
    assert harness.service.get_mode().can_enforce is False


def test_portlock_only_releases_what_it_restricted(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.service.replace_policy({"version": 1, "default": {"access": "allow"}}, actor=ADMIN)
    harness.set_mode(Mode.ENFORCE)
    # Another program turned default-deny on behind PortLock's back.
    harness.enforcer.set_authorized_default_externally("0")
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.ALLOWED
    assert view.enforcement is not None and view.enforcement.outcome is Outcome.NOT_NEEDED
    assert harness.enforcer.is_blocked("test/1-1")
    assert harness.enforcer.calls_for(Action.UNBLOCK, Action.DEFAULT_DENY_OFF) == ()


def test_read_only_that_cannot_be_enforced_blocks_under_fail_closed(tmp_path: Path) -> None:
    harness = _harness(tmp_path, fail_closed=True)
    harness.service.replace_policy(
        {
            "version": 1,
            "rules": [
                {"id": "ro", "match": {"category": ["imaging"]}, "action": {"access": "read_only"}}
            ],
        },
        actor=ADMIN,
    )
    harness.set_mode(Mode.ENFORCE)
    harness.plug(phone())
    view = harness.view("test/1-6")
    assert view.state is ConnectionState.READ_ONLY
    assert view.enforcement is not None
    assert view.enforcement.os_state == "blocked"
    assert view.enforcement.detail == "read-only unavailable; blocked because fail_closed is set"
    assert harness.enforcer.is_blocked("test/1-6")


def test_an_enforcer_that_raises_is_recorded_as_failed(tmp_path: Path) -> None:
    harness = _harness(tmp_path, mode=Mode.ENFORCE)
    harness.enforcer.fail(Action.BLOCK, raises=RuntimeError("driver crashed"))
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.enforcement is not None and view.enforcement.outcome is Outcome.FAILED
    assert view.enforcement.mechanism == "error"
    assert view.enforcement.error == "RuntimeError: driver crashed"
    assert harness.view("test/1-1").state is ConnectionState.PENDING


def test_an_unwritable_journal_stops_restrictions_but_not_the_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness(tmp_path, mode=Mode.ENFORCE)
    journal = harness.rt.journal

    def unwritable(*args: object, **kwargs: object) -> None:
        raise StoreError("cannot write the enforcement journal: disk full")

    monkeypatch.setattr(journal, "_append_locked", unwritable)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.enforcement is not None and view.enforcement.outcome is Outcome.FAILED
    assert view.enforcement.error is not None
    assert view.enforcement.error.startswith("journal unavailable")
    assert not harness.enforcer.is_blocked("test/1-1")  # no change without its baseline
    assert "journal" in harness.service.status().degraded


# --- orphan records: a non-volatile restriction of a device that is not connected ---------


class DevnodeEnforcer(Enforcer):
    """A minimal enforcer with a non-volatile mechanism (a disabled Windows device node)."""

    def __init__(self, disabled: set[str], write_ahead: Callable[[JournalEntry], None]) -> None:
        self.disabled = disabled
        self.write_ahead = write_ahead

    def capabilities(self) -> EnforcerCapabilities:
        return EnforcerCapabilities("devnode", True, True, False, False, False)

    def _change(self, action: Action, device: UsbDevice, *, disable: bool) -> EnforcementResult:
        iid = device.instance_id
        if (iid in self.disabled) == disable:
            return EnforcementResult(action, ok=True, mechanism="cfgmgr:disable-devnode")
        before, after = ("enabled", "disabled") if disable else ("disabled", "enabled")
        entry = JournalEntry("win_devnode", iid, before, after)
        try:
            self.write_ahead(entry)
        except Exception as exc:
            return EnforcementResult(
                action, False, "cfgmgr:disable-devnode", error=f"journal unavailable: {exc}"
            )
        (self.disabled.add if disable else self.disabled.discard)(iid)
        return EnforcementResult(
            action, True, "cfgmgr:disable-devnode", Tier.REACTIVE, True, undo=(entry,)
        )

    def block(self, device: UsbDevice) -> EnforcementResult:
        return self._change(Action.BLOCK, device, disable=True)

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        return self._change(Action.UNBLOCK, device, disable=False)

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        return EnforcementResult(Action.READ_ONLY, False, "none", error="unsupported")

    def eject(self, device: UsbDevice) -> EnforcementResult:
        return EnforcementResult(Action.EJECT, False, "none", error="unsupported")

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        return EnforcementResult(Action.DEFAULT_DENY_ON, False, "none", error="unsupported")

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        changed = False
        for entry in reversed(list(entries)):
            current = "disabled" if entry.target in self.disabled else "enabled"
            if current == entry.applied:
                if entry.previous == "enabled":
                    self.disabled.discard(entry.target)
                else:
                    self.disabled.add(entry.target)
                changed = True
        return EnforcementResult(Action.RESTORE, True, "journal:restore", changed=changed)


def test_an_orphan_record_is_released_by_a_later_grant(tmp_path: Path) -> None:
    clock = FakeClock(START)
    device = flash_drive(instance_id="USB\\VID_1209&PID_0001\\TEST0001A7C3")
    backend = FakeBackend([device], clock=clock, synchronous=True)
    disabled: set[str] = set()
    config = make_config(tmp_path / "home", mode=Mode.ENFORCE)

    def boot() -> Runtime:
        runtime = build_runtime(
            config,
            clock=clock,
            backend=backend,
            enforcer_factory=lambda hook: DevnodeEnforcer(disabled, hook),
            scanner=None,
            timer=FakeExternalTimer(),
            dir_privacy=FakeDirPrivacy(),
            system_ids=lambda devices: frozenset(),
            recover_argv=RECOVER_ARGV,
        )
        runtime.service.start(threads=False)
        return runtime

    runtime = boot()
    assert disabled == {device.instance_id}
    fingerprint = runtime.service.list_connections()[0].fingerprint
    backend.stop()
    runtime.close()

    backend.unplug(device.instance_id)  # unplugged while disabled: no arrival will come
    runtime = boot()
    assert len(runtime.journal.open_records()) == 1  # kept: the device node stays disabled
    assert disabled == {device.instance_id}
    runtime.service.create_grant(fingerprint, "trust", actor=ADMIN, role="admin")
    assert disabled == set()
    assert runtime.journal.open_records() == []
    orphan = [r for r in runtime.audit_log.iterate() if r.data.get("orphan") is True]
    assert orphan and orphan[-1].event_type == "enforcement.applied"
    assert orphan[-1].data["action"] == "restore"
    backend.stop()
    runtime.close()


def test_an_untraceable_system_volume_protects_the_storage_present_at_start(
    tmp_path: Path,
) -> None:
    from portlock.core.errors import BackendError

    harness = Harness(tmp_path, devices=[flash_drive()], mode=Mode.ENFORCE)
    runtime = harness.build()

    def untraceable(devices: Sequence[UsbDevice]) -> frozenset[str]:
        raise BackendError("mount table unreadable")

    runtime.service._system_ids_probe = untraceable
    runtime.service.start(threads=False)
    present = harness.view("test/1-1")
    assert present.protection_codes == ("system_volume",)
    assert not harness.enforcer.is_blocked("test/1-1")
    harness.plug(flash_drive(instance_id="test/2-2", bus_path="2-2", serial="TEST00020002"))
    assert harness.enforcer.is_blocked("test/2-2")  # a later arrival cannot back the system
    checks = {c["id"]: c for c in harness.service.doctor().to_dict()["checks"]}
    assert checks["service.system_volume"]["status"] == "warn"
    assert "mount table unreadable" in checks["service.system_volume"]["detail"]
    harness.crash()
