"""The pipeline: events, evaluation, mutating calls and their validation."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive, keyboard, phone
from integration.harness import ADMIN, CHANNEL, Harness, with_volume
from portlock.core.config import SCOPE_ALL_EXCEPT_PROTECTED, SCOPE_STORAGE_AND_UNKNOWN
from portlock.core.models import Mode, UsbInterface
from portlock.core.service import ServiceError
from portlock.core.store import ConnectionState, Outcome
from portlock.lockdown.manager import ConfirmationError

VENDOR = UsbInterface(0xFF, 0x00, 0x00)


def _harness(tmp_path: Path, **options: Any) -> Harness:
    harness = Harness(tmp_path, **options)
    harness.boot()
    return harness


def test_a_duplicate_arrival_is_handled_once(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    stick = harness.plug(flash_drive())
    from portlock.core.models import DeviceEvent, DeviceEventType

    harness.service.handle_event(DeviceEvent(DeviceEventType.ARRIVED, stick, harness.clock.now()))
    assert len(harness.service.list_connections()) == 1
    assert len(harness.records("device.connected")) == 1


def test_a_changed_event_updates_the_device_and_audits_the_new_volume(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.plug(flash_drive())
    harness.update(with_volume(flash_drive()))
    view = harness.view("test/1-1")
    assert view.device.volumes[0].mount_point == "/media/stick"
    changed = harness.records("device.changed")[-1]
    assert changed.data["volumes_added"] == [
        {"device_node": "/dev/sdx1", "mount_point": "/media/stick"}
    ]
    assert changed.data["volumes_removed"] == []
    assert harness.service.list_devices()[0].record.storage_identity is not None


def test_fail_closed_denies_a_device_that_cannot_be_evaluated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _harness(tmp_path, fail_closed=True)
    harness.set_mode(Mode.ENFORCE)

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("bad rule")

    monkeypatch.setattr(harness.service._loaded.engine, "evaluate", broken)
    harness.plug(flash_drive())
    harness.plug(keyboard())
    stick = harness.view("test/1-1")
    assert stick.state is ConnectionState.DENIED
    assert stick.decision is not None and "fail_closed" in stick.decision.decision.reasons[1]
    assert harness.enforcer.is_blocked("test/1-1")
    # A protected device stays protected even when evaluation fails.
    assert harness.view("test/1-2").state is ConnectionState.PROTECTED
    assert not harness.enforcer.is_blocked("test/1-2")


def test_pinning_a_fingerprint_protects_the_device(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    fingerprint = harness.view("test/1-1").fingerprint
    applied = harness.service.update_settings(
        {"protected_fingerprints": [fingerprint]}, actor=ADMIN
    )
    assert applied.value.runtime["protected_fingerprints"] == [fingerprint]
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PROTECTED and view.protection_codes == ("pinned",)
    assert not harness.enforcer.is_blocked("test/1-1")
    changed = harness.records("config.changed")[-1]
    assert changed.data == {"key": "protected_fingerprints", "old": None, "new": [fingerprint]}


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"mode": "enforce"}, "invalid_request"),
        ({}, "invalid_request"),
        ({"scan.enabled": "yes"}, "invalid_request"),
        ({"lockdown.default_minutes": 0}, "invalid_request"),
        ({"lockdown.default_minutes": 241}, "invalid_request"),
        ({"protected_fingerprints": ["plk1:" + "a" * 32]}, "unknown_device"),
        ({"protected_fingerprints": "plk1:x"}, "invalid_request"),
    ],
)
def test_settings_changes_are_validated_before_anything_is_written(
    tmp_path: Path, changes: dict[str, Any], code: str
) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(ServiceError) as refused:
        harness.service.update_settings(changes, actor=ADMIN)
    assert refused.value.code == code
    assert harness.records("config.changed") == []


def test_widening_the_scope_goes_through_commit_confirm_and_narrowing_does_not(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    harness.set_mode(Mode.ENFORCE)
    vendor = flash_drive(instance_id="test/6-1", bus_path="6-1", interfaces=(VENDOR,))
    harness.plug(vendor)
    assert harness.view("test/6-1").enforcement.mechanism == "out-of-scope"  # type: ignore[union-attr]
    applied = harness.service.set_scope(SCOPE_STORAGE_AND_UNKNOWN, actor=ADMIN, channel=CHANNEL)
    change = applied.extra["change"]
    preview = {item["instance_id"]: item["outcome"] for item in change["preview"]}
    assert preview == {"test/6-1": "block"}
    assert harness.enforcer.is_blocked("test/6-1")
    with pytest.raises(ConfirmationError):
        harness.service.confirm_change(change["id"], actor=ADMIN, channel="elsewhere")
    harness.tick(60)  # not confirmed: rolled back
    assert harness.service.get_settings().effective["scope"] == "storage"
    assert not harness.enforcer.is_blocked("test/6-1")

    applied = harness.service.set_scope(SCOPE_ALL_EXCEPT_PROTECTED, actor=ADMIN, channel=CHANNEL)
    harness.service.confirm_change(applied.extra["change"]["id"], actor=ADMIN, channel=CHANNEL)
    harness.tick(120)
    assert harness.enforcer.is_blocked("test/6-1")
    narrowed = harness.service.set_scope("storage", actor=ADMIN, channel=CHANNEL)
    assert "change" not in narrowed.extra and narrowed.value == "storage"
    assert not harness.enforcer.is_blocked("test/6-1")
    with pytest.raises(ServiceError):
        harness.service.set_scope("everything", actor=ADMIN, channel=CHANNEL)


def test_standing_default_deny_needs_confirmation_and_is_restored_when_turned_off(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path)
    harness.set_mode(Mode.ENFORCE)
    applied = harness.service.set_default_deny(True, actor=ADMIN, channel=CHANNEL)
    assert harness.enforcer.default_deny
    harness.service.confirm_change(applied.extra["change"]["id"], actor=ADMIN, channel=CHANNEL)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.enforcement is not None and view.enforcement.tier.value == "preventive"
    harness.plug(keyboard())
    assert not harness.enforcer.is_blocked("test/1-2")  # protected: admitted at once
    harness.service.set_default_deny(False, actor=ADMIN, channel=CHANNEL)
    assert not harness.enforcer.default_deny
    assert harness.enforcer.is_blocked("test/1-1")  # still pending, still blocked


def test_an_enforce_switch_can_be_cancelled_and_needs_a_working_enforcer(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.plug(flash_drive())
    applied = harness.service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
    assert harness.service.cancel_change(applied.extra["change"]["id"], actor=ADMIN)
    assert harness.service.get_mode().effective_mode is Mode.MONITOR
    assert not harness.enforcer.is_blocked("test/1-1")

    from portlock.guard.fake import FakeEnforcer

    weak = Harness(tmp_path / "weak", capabilities=FakeEnforcer.unprivileged().capabilities())
    weak.boot()
    with pytest.raises(ServiceError) as refused:
        weak.service.set_mode(Mode.ENFORCE, actor=ADMIN, channel=CHANNEL)
    assert refused.value.code == "enforcement_unavailable"
    weak.crash()


def test_policy_validation_conflict_and_invalid_documents(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    digest, problems = harness.service.validate_policy({"version": 1})
    assert digest is not None and problems == ()
    none, problems = harness.service.validate_policy({"version": 2, "rules": "x"})
    assert none is None and len(problems) == 2
    with pytest.raises(ServiceError) as invalid:
        harness.service.replace_policy({"version": 1, "rules": [{"id": 3}]}, actor=ADMIN)
    assert invalid.value.code == "policy_invalid" and invalid.value.problems
    assert harness.records("policy.invalid")[-1].data["source"] == "api"
    with pytest.raises(ServiceError) as conflict:
        harness.service.replace_policy({"version": 1}, expected_hash="0" * 64, actor=ADMIN)
    assert conflict.value.code == "policy_conflict"
    current = harness.service.get_policy().hash
    applied = harness.service.replace_policy({"version": 1}, expected_hash=current, actor=ADMIN)
    assert applied.extra["previous_hash"] == current
    assert harness.records("policy.changed")[-1].data["old_hash"] == current


def test_testing_a_policy_changes_and_audits_nothing(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    before = harness.rt.audit_log.count()
    draft = {
        "version": 1,
        "rules": [
            {"id": "phones", "match": {"category": ["imaging"]}, "action": {"access": "deny"}}
        ],
    }
    tested = harness.service.test_policy(device=phone(), policy=draft)
    data = tested.to_dict()
    assert data["matched_rule"] == "phones" and data["decision"]["access"] == "deny"
    assert data["explain"][0]["outcome"] == "matched"
    assert harness.rt.audit_log.count() == before
    assert harness.service.list_connections() == []
    with pytest.raises(ServiceError):
        harness.service.test_policy(device=phone(), policy={"version": 9})


def test_an_invalid_policy_file_at_start_falls_back_to_the_last_good(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    harness.home.joinpath("config").mkdir(parents=True)
    policy_file = harness.config.paths.config_dir / "policy.json"
    policy_file.write_text(
        '{"version": 1, "name": "office", "default": {"access": "allow"}}', encoding="utf-8"
    )
    harness.boot()
    assert harness.service.get_policy().source == "file"
    harness.crash()
    policy_file.write_text('{"version": 1, "rules": 5}', encoding="utf-8")
    harness.boot()
    info = harness.service.get_policy()
    assert info.source == "last_good" and info.policy.name == "office"
    assert harness.records("policy.invalid")[-1].data["source"] == "file"


def test_enrolment_needs_a_port_and_a_connected_device(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    with pytest.raises(ServiceError) as missing:
        harness.service.enroll(42, actor=ADMIN)
    assert missing.value.code == "not_connected"
    harness.plug(dataclasses.replace(keyboard(), bus_path=None))
    with pytest.raises(ServiceError) as portless:
        harness.service.enroll(harness.connection_id("test/1-2"), actor=ADMIN)
    assert portless.value.code == "invalid_request"
    harness.unplug("test/1-2")
    harness.plug(keyboard())
    harness.service.enroll(harness.connection_id("test/1-2"), actor=ADMIN)
    assert harness.service.unenroll(harness.view("test/1-2").fingerprint, actor=ADMIN).value == 1
    assert harness.records("enroll.removed")[-1].data["removed"] == 1


def test_a_port_hold_can_be_released_early_by_an_administrator(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    for _ in range(6):
        harness.plug(flash_drive())
        if _ < 5:
            harness.unplug("test/1-1")
    assert harness.view("test/1-1").state is ConnectionState.DENIED
    released = harness.service.release_port("1-1", actor=ADMIN)
    assert released.value is True and released.reevaluated == (harness.connection_id("test/1-1"),)
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.records("safety.port_held")[-1].data["manual"] is True
    assert harness.service.release_port("1-1", actor=ADMIN).value is False


def test_a_manual_scan_request_is_validated(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    with pytest.raises(ServiceError) as unavailable:
        harness.service.request_scan(cid, actor=ADMIN)
    assert unavailable.value.code == "scan_unavailable"
    with pytest.raises(ServiceError) as gone:
        harness.service.request_scan(cid + 1, actor=ADMIN)
    assert gone.value.code == "not_connected"


def test_deny_validates_its_note_and_state(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.plug(keyboard())
    with pytest.raises(ServiceError) as protected:
        harness.service.deny(harness.connection_id("test/1-2"), actor=ADMIN)
    assert protected.value.code == "not_pending"
    with pytest.raises(ServiceError) as long_note:
        harness.service.deny(harness.connection_id("test/1-2"), note="x" * 513, actor=ADMIN)
    assert long_note.value.code == "invalid_request"
    assert harness.view("test/1-2").enforcement.outcome is Outcome.NOT_NEEDED  # type: ignore[union-attr]
