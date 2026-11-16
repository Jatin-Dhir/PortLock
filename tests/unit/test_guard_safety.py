"""The safety choke point: what is protected, what is in scope, clones and port hold-down."""

from __future__ import annotations

import dataclasses
import random
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

import pytest

import portlock.guard.safety as safety_module
from factories import (
    BOOT_KEYBOARD,
    BOOT_MOUSE,
    CDC_ACM,
    GENERIC_HID,
    HUB,
    MASS_STORAGE,
    MTP,
    flash_drive,
    hub,
    internal_webcam,
    keyboard,
    make_device,
    mounted_flash_drive,
    mouse,
    phone,
    storage_with_keyboard,
)
from portlock.core.clock import FakeClock
from portlock.core.config import SCOPES
from portlock.core.fingerprint import fingerprint
from portlock.core.models import UsbDevice, UsbInterface
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
    Tier,
)
from portlock.guard.fake import FakeEnforcer
from portlock.guard.safety import (
    CODE_BUILT_IN,
    CODE_CHECK_FAILED,
    CODE_CLONE,
    CODE_ENROLLED,
    CODE_HUB,
    CODE_INPUT_DEVICE,
    CODE_OUT_OF_SCOPE,
    CODE_PINNED,
    CODE_SYSTEM_VOLUME,
    MECHANISM_DRY_RUN,
    MECHANISM_ERROR,
    MECHANISM_OUT_OF_SCOPE,
    MECHANISM_REFUSED,
    FlapVerdict,
    PortFlapGuard,
    PortRelease,
    ProtectionVerdict,
    SafeEnforcer,
    SafetyContext,
    detect_clone,
    is_protected,
)

VENDOR = UsbInterface(0xFF, 0x00, 0x00)
DIAGNOSTIC = UsbInterface(0xDC, 0x01, 0x01)
AUDIO = UsbInterface(0x01, 0x01, 0x00)
CDC_ECM = UsbInterface(0x02, 0x06, 0x00)

ALL_SCOPE = SafetyContext(scope="all_except_protected")
RESTRICTING = (Action.BLOCK, Action.EJECT, Action.READ_ONLY)
CLEAN_STATE = {"default_deny": False, "blocked": [], "read_only": [], "ejected": []}
UNPROTECTED = ProtectionVerdict(protected=False, in_scope=True)


def _verdict(device: UsbDevice, context: SafetyContext | None = None) -> ProtectionVerdict:
    return is_protected(device, fingerprint(device), context or SafetyContext())


def _guard(
    inner: Enforcer,
    context: SafetyContext | None = None,
    *,
    dry_run: bool = False,
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] | None = None,
) -> SafeEnforcer:
    fixed = context or SafetyContext()
    on_refusal = None if refusals is None else lambda *call: refusals.append(call)
    return SafeEnforcer(inner, lambda: fixed, dry_run=dry_run, on_refusal=on_refusal)


def _restrict(guard: Enforcer, action: Action, device: UsbDevice) -> EnforcementResult:
    if action is Action.BLOCK:
        return guard.block(device)
    if action is Action.EJECT:
        return guard.eject(device)
    return guard.set_read_only(device, True)


def _enrolled(device: UsbDevice, bus_path: str | None = None) -> SafetyContext:
    port = bus_path if bus_path is not None else device.bus_path
    assert port is not None
    return SafetyContext(enrolled=frozenset({(fingerprint(device).value, port)}))


# --- is_protected: each rule -----------------------------------------------------------


def test_stable_codes() -> None:
    # These strings are stored in audit records; changing one is a format change.
    assert CODE_HUB == "hub"
    assert CODE_BUILT_IN == "built_in"
    assert CODE_SYSTEM_VOLUME == "system_volume"
    assert CODE_PINNED == "pinned"
    assert CODE_ENROLLED == "enrolled"
    assert CODE_INPUT_DEVICE == "input_device"
    assert CODE_OUT_OF_SCOPE == "out_of_scope"
    assert CODE_CHECK_FAILED == "safety_check_failed"
    assert CODE_CLONE == "enrolled_fingerprint_clone"
    assert (MECHANISM_REFUSED, MECHANISM_OUT_OF_SCOPE, MECHANISM_DRY_RUN, MECHANISM_ERROR) == (
        "refused",
        "out-of-scope",
        "dry-run",
        "error",
    )
    assert safety_module.MECHANISM_UNSUPPORTED == "unsupported"


def test_an_ordinary_flash_drive_is_not_protected_and_is_in_every_scope() -> None:
    for scope in SCOPES:
        for hid in (False, True):
            context = SafetyContext(scope=scope, hid_enforcement_enabled=hid)
            verdict = _verdict(flash_drive(), context)
            assert verdict == UNPROTECTED
            assert verdict.enforceable
    assert _verdict(mounted_flash_drive()) == UNPROTECTED
    assert _verdict(flash_drive(removable=None)) == UNPROTECTED


def test_a_hub_is_protected_in_every_configuration() -> None:
    for scope in SCOPES:
        for hid in (False, True):
            verdict = _verdict(hub(), SafetyContext(scope=scope, hid_enforcement_enabled=hid))
            assert verdict.protected and verdict.codes == (CODE_HUB,)
    assert _verdict(make_device(interfaces=(), device_class=0x09), ALL_SCOPE).codes == (CODE_HUB,)
    assert _verdict(make_device(interfaces=(HUB, HUB)), ALL_SCOPE).codes == (CODE_HUB,)


@pytest.mark.parametrize(
    "interfaces",
    [
        (HUB, MASS_STORAGE),
        (MASS_STORAGE, HUB, BOOT_KEYBOARD),
        (HUB, CDC_ECM),
        (HUB, VENDOR),
        (HUB, MTP),
    ],
)
def test_a_hub_interface_beside_another_function_is_not_a_hub(
    interfaces: tuple[UsbInterface, ...],
) -> None:
    # No real hub declares a function of its own on the same device; anything could
    # otherwise make itself untouchable by adding one interface descriptor.
    device = make_device(interfaces=interfaces)
    for scope in SCOPES:
        verdict = _verdict(device, SafetyContext(scope=scope))
        assert CODE_HUB not in verdict.codes
        assert verdict.protected is False


def test_a_hub_beside_input_only_is_protected_as_an_input_device_not_as_a_hub() -> None:
    device = make_device(interfaces=(HUB, BOOT_KEYBOARD))
    assert device.is_input_only
    assert _verdict(device, ALL_SCOPE).codes == (CODE_INPUT_DEVICE,)
    enabled = SafetyContext(scope="all_except_protected", hid_enforcement_enabled=True)
    assert _verdict(device, enabled) == UNPROTECTED


def test_a_built_in_device_is_protected() -> None:
    assert _verdict(internal_webcam(), ALL_SCOPE).codes == (CODE_BUILT_IN,)
    assert _verdict(flash_drive(removable=False)).codes == (CODE_BUILT_IN,)
    # Unknown is not the same as built in.
    assert _verdict(flash_drive(removable=None)).codes == ()


def test_a_device_backing_the_system_volume_is_protected() -> None:
    device = flash_drive(instance_id="USB\\VID_1209&PID_0001\\TEST0001A7C3")
    exact = SafetyContext(system_instance_ids=frozenset({device.instance_id}))
    assert _verdict(device, exact).codes == (CODE_SYSTEM_VOLUME,)
    # Windows instance ids are case-insensitive, so the comparison is too.
    lowered = SafetyContext(system_instance_ids=frozenset({device.instance_id.lower()}))
    assert _verdict(device, lowered).codes == (CODE_SYSTEM_VOLUME,)
    other = SafetyContext(system_instance_ids=frozenset({"USB\\VID_1209&PID_0001\\OTHER"}))
    assert _verdict(device, other).protected is False


def test_a_pinned_fingerprint_is_protected_on_any_port() -> None:
    device = flash_drive()
    value = fingerprint(device).value
    context = SafetyContext(pinned_fingerprints=frozenset({value}))
    assert _verdict(device, context).codes == (CODE_PINNED,)
    # Both the fingerprint object and its plain value are accepted.
    assert is_protected(device, value, context).codes == (CODE_PINNED,)
    # The same model with another serial has another fingerprint and is not covered.
    assert _verdict(flash_drive(serial="TEST0002B8D4"), context).protected is False
    # A pin follows the device to another port.
    moved = flash_drive(instance_id="test/2-9", bus_path="2-9")
    assert _verdict(moved, context).codes == (CODE_PINNED,)


def test_an_enrolment_protects_only_on_its_own_port() -> None:
    board = keyboard()
    context = dataclasses.replace(
        _enrolled(board), scope="all_except_protected", hid_enforcement_enabled=True
    )
    assert context.is_enrolled(fingerprint(board).value, "1-2")
    assert _verdict(board, context).codes == (CODE_ENROLLED,)
    assert "1-2" in _verdict(board, context).reasons[0]
    # Re-plugged into the same port: still the operator's keyboard, whatever the
    # instance id or connection.
    replugged = keyboard(instance_id="test/1-2#2", connection_id="second")
    assert _verdict(replugged, context).codes == (CODE_ENROLLED,)
    # The same fingerprint on another port is not covered by that enrolment.
    elsewhere = keyboard(instance_id="test/3-1", bus_path="3-1")
    assert _verdict(elsewhere, context) == UNPROTECTED
    # Nor is a device whose port the platform did not report.
    assert _verdict(keyboard(bus_path=None), context) == UNPROTECTED
    # Nor another model on the enrolled port.
    assert _verdict(keyboard(product="Other Keyboard"), context) == UNPROTECTED


def test_being_connected_confers_nothing() -> None:
    # There is no "present at start" rule any more: a storage device is unprotected
    # however long it has been connected, unless pinned or enrolled.
    assert not hasattr(SafetyContext(), "protected_fingerprints")
    assert _verdict(flash_drive()) == UNPROTECTED


@pytest.mark.parametrize(
    "device",
    [
        keyboard(),
        mouse(),
        make_device(interfaces=(GENERIC_HID,), serial=None),
        make_device(interfaces=(BOOT_KEYBOARD, BOOT_MOUSE)),
        make_device(interfaces=(BOOT_KEYBOARD, GENERIC_HID)),
        make_device(interfaces=(), device_class=0x03),
    ],
)
def test_input_only_devices_are_protected_unless_hid_enforcement_is_enabled(
    device: UsbDevice,
) -> None:
    assert device.is_input_only
    assert _verdict(device, ALL_SCOPE).codes == (CODE_INPUT_DEVICE,)
    enabled = SafetyContext(scope="all_except_protected", hid_enforcement_enabled=True)
    assert _verdict(device, enabled) == UNPROTECTED


@pytest.mark.parametrize(
    "interfaces",
    [
        (BOOT_KEYBOARD, VENDOR),
        (GENERIC_HID, AUDIO),
        (BOOT_KEYBOARD, CDC_ECM),
        (BOOT_KEYBOARD, CDC_ACM),
        (BOOT_MOUSE, MTP),
        (MASS_STORAGE, BOOT_KEYBOARD),
        (GENERIC_HID, MASS_STORAGE, VENDOR),
    ],
)
@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.parametrize("hid", [False, True])
def test_input_beside_any_other_function_gets_no_category_protection(
    interfaces: tuple[UsbInterface, ...], scope: str, hid: bool
) -> None:
    device = make_device(interfaces=interfaces)
    assert device.mixes_input_with_other
    verdict = _verdict(device, SafetyContext(scope=scope, hid_enforcement_enabled=hid))
    assert verdict.protected is False and verdict.codes == ()


def test_mixed_devices_are_protected_only_by_facts_they_cannot_fake() -> None:
    device = storage_with_keyboard()
    pinned = SafetyContext(pinned_fingerprints=frozenset({fingerprint(device).value}))
    assert _verdict(device, pinned).codes == (CODE_PINNED,)
    assert _verdict(device, _enrolled(device)).codes == (CODE_ENROLLED,)
    assert _verdict(storage_with_keyboard(removable=False)).codes == (CODE_BUILT_IN,)
    system = SafetyContext(system_instance_ids=frozenset({device.instance_id}))
    assert _verdict(device, system).codes == (CODE_SYSTEM_VOLUME,)


# --- is_protected: scope ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("device", "in_storage", "in_storage_and_unknown"),
    [
        (flash_drive(), True, True),
        (phone(), True, True),
        (make_device(interfaces=(MTP, MASS_STORAGE)), True, True),
        (make_device(interfaces=(), device_class=0x06), True, True),
        (storage_with_keyboard(), True, True),
        (make_device(interfaces=(VENDOR,)), False, True),
        (make_device(interfaces=(DIAGNOSTIC,)), False, True),
        (make_device(interfaces=(VENDOR, DIAGNOSTIC)), False, True),
        (make_device(interfaces=(), device_class=0x00), False, True),
        (make_device(interfaces=(), device_class=0xFF), False, True),
        (make_device(interfaces=(VENDOR, AUDIO)), False, False),
        (make_device(interfaces=(CDC_ACM,)), False, False),
        (make_device(interfaces=(CDC_ECM,)), False, False),
        (make_device(interfaces=(AUDIO,)), False, False),
        (make_device(interfaces=(UsbInterface(0xE0, 0x01, 0x01),)), False, False),
        # Input beside another function is in every scope (section 14.5).
        (make_device(interfaces=(BOOT_KEYBOARD, CDC_ECM)), True, True),
        (make_device(interfaces=(BOOT_KEYBOARD, CDC_ACM)), True, True),
        (make_device(interfaces=(GENERIC_HID, AUDIO)), True, True),
        (make_device(interfaces=(BOOT_MOUSE, VENDOR)), True, True),
        (make_device(interfaces=(BOOT_KEYBOARD, HUB, CDC_ECM)), True, True),
    ],
)
def test_scope_decides_which_devices_can_be_enforced_against(
    device: UsbDevice, in_storage: bool, in_storage_and_unknown: bool
) -> None:
    expectations = {
        "storage": in_storage,
        "storage_and_unknown": in_storage_and_unknown,
        "all_except_protected": True,
    }
    for scope, in_scope in expectations.items():
        verdict = _verdict(device, SafetyContext(scope=scope))
        assert verdict.in_scope is in_scope, scope
        # Being outside the scope is never protection.
        assert verdict.protected is False and verdict.codes == ()
        if in_scope:
            assert verdict.scope_reason == ""
        else:
            assert f'"{scope}"' in verdict.scope_reason
            assert verdict.enforceable is False


def test_the_storage_scope_covers_imaging_devices() -> None:
    # Phones and cameras in MTP or PTP mode move files in both directions too.
    verdict = _verdict(phone(), SafetyContext(scope="storage"))
    assert verdict == UNPROTECTED and verdict.enforceable
    reason = _verdict(make_device(interfaces=(AUDIO,))).scope_reason
    assert "mass storage and imaging devices" in reason
    assert "beside an input interface" in reason


def test_the_default_scope_enforces_input_mixed_with_another_function() -> None:
    # Section 14.5: the default policy denies these, and the default scope must let that
    # denial reach the operating system.
    fake = FakeEnforcer()
    safe = SafeEnforcer(fake, SafetyContext, dry_run=False)
    tap = make_device(instance_id="test/9-1", interfaces=(BOOT_KEYBOARD, CDC_ECM))
    verdict = safe.protection(tap)
    assert verdict.enforceable and verdict.scope_reason == ""
    result = safe.block(tap)
    assert result.ok and result.mechanism == "fake:authorized"
    assert fake.is_blocked(tap)
    # A keyboard that is only a keyboard stays protected and untouched.
    board = keyboard()
    assert safe.block(board).mechanism == "refused"
    assert not fake.is_blocked(board)


def test_scope_and_protection_are_reported_independently() -> None:
    # A keyboard under the default scope: protected (input only) and also out of scope.
    verdict = _verdict(keyboard())
    assert verdict.protected and verdict.codes == (CODE_INPUT_DEVICE,)
    assert verdict.in_scope is False and verdict.scope_reason
    # With HID enforcement on but the scope too narrow, it is merely out of scope.
    narrow = SafetyContext(scope="storage", hid_enforcement_enabled=True)
    assert _verdict(keyboard(), narrow).protected is False
    assert _verdict(keyboard(), narrow).in_scope is False


# --- is_protected: the verdict ---------------------------------------------------------


def test_every_applicable_rule_is_listed() -> None:
    device = hub(removable=False)
    value = fingerprint(device).value
    context = SafetyContext(
        enrolled=frozenset({(value, "1-4")}),
        pinned_fingerprints=frozenset({value}),
        system_instance_ids=frozenset({device.instance_id}),
    )
    verdict = _verdict(device, context)
    assert verdict.protected and verdict.in_scope is False
    assert verdict.codes == (
        CODE_HUB,
        CODE_BUILT_IN,
        CODE_SYSTEM_VOLUME,
        CODE_PINNED,
        CODE_ENROLLED,
    )
    assert len(verdict.reasons) == len(verdict.codes)
    assert all(isinstance(reason, str) and reason for reason in verdict.reasons)
    assert verdict.to_dict() == {
        "protected": True,
        "in_scope": False,
        "reasons": list(verdict.reasons),
        "codes": list(verdict.codes),
        "scope_reason": verdict.scope_reason,
    }


def test_is_protected_is_pure() -> None:
    device, context = keyboard(), _enrolled(keyboard())
    assert _verdict(device, context) == _verdict(device, context)


# --- SafetyContext ---------------------------------------------------------------------


def test_context_defaults_are_the_cautious_ones() -> None:
    context = SafetyContext()
    assert context.enrolled == frozenset()
    assert context.enrolled_fingerprints == frozenset()
    assert context.pinned_fingerprints == frozenset()
    assert context.system_instance_ids == frozenset()
    assert context.hid_enforcement_enabled is False
    assert context.scope == "storage"


def test_context_freezes_its_sets_and_is_immutable() -> None:
    pins = {"plk1:aaaa"}
    enrolments = [["plk1:bbbb", "1-2"], ("plk1:cccc", "1-3")]
    context = SafetyContext(
        enrolled=enrolments,  # type: ignore[arg-type]
        pinned_fingerprints=pins,  # type: ignore[arg-type]
        system_instance_ids=["test/1-1"],  # type: ignore[arg-type]
    )
    pins.add("plk1:dddd")
    enrolments.append(("plk1:eeee", "1-4"))
    assert context.pinned_fingerprints == frozenset({"plk1:aaaa"})
    assert context.enrolled == frozenset({("plk1:bbbb", "1-2"), ("plk1:cccc", "1-3")})
    assert context.enrolled_fingerprints == frozenset({"plk1:bbbb", "plk1:cccc"})
    assert context.system_instance_ids == frozenset({"test/1-1"})
    assert isinstance(context.system_instance_ids, frozenset)
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.scope = "all_except_protected"  # type: ignore[misc]
    assert SafetyContext(scope="storage") == SafetyContext()
    assert hash(SafetyContext()) == hash(SafetyContext())
    widened = dataclasses.replace(context, scope="all_except_protected")
    assert widened.scope == "all_except_protected"
    assert widened.backs_system_volume("TEST/1-1")
    assert widened.is_enrolled("plk1:bbbb", "1-2") and not widened.is_enrolled("plk1:bbbb", "1-3")
    assert not widened.is_enrolled("plk1:bbbb", None)


@pytest.mark.parametrize(
    "arguments",
    [
        {"scope": "everything"},
        {"scope": ""},
        {"scope": None},
        {"pinned_fingerprints": "plk1:aaaa"},
        {"pinned_fingerprints": frozenset({1, 2})},
        {"pinned_fingerprints": frozenset({""})},
        {"system_instance_ids": "test/1-1"},
        {"system_instance_ids": [None]},
        {"enrolled": "plk1:aaaa"},
        {"enrolled": [("plk1:aaaa",)]},
        {"enrolled": [("plk1:aaaa", "1-2", "extra")]},
        {"enrolled": [("plk1:aaaa", None)]},
        {"enrolled": [("", "1-2")]},
        {"enrolled": [("plk1:aaaa", "")]},
        {"enrolled": ["ab"]},
        {"enrolled": [5]},
        {"hid_enforcement_enabled": "yes"},
        {"hid_enforcement_enabled": 1},
    ],
)
def test_context_rejects_invalid_values(arguments: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        SafetyContext(**arguments)


# --- SafeEnforcer: refusing ------------------------------------------------------------


@pytest.mark.parametrize("action", RESTRICTING)
@pytest.mark.parametrize(
    ("device", "context", "code"),
    [
        (keyboard(), ALL_SCOPE, CODE_INPUT_DEVICE),
        (keyboard(), SafetyContext(), CODE_INPUT_DEVICE),
        (hub(), ALL_SCOPE, CODE_HUB),
        (internal_webcam(), ALL_SCOPE, CODE_BUILT_IN),
        (
            flash_drive(),
            SafetyContext(system_instance_ids=frozenset({"test/1-1"})),
            CODE_SYSTEM_VOLUME,
        ),
        (
            flash_drive(),
            SafetyContext(pinned_fingerprints=frozenset({fingerprint(flash_drive()).value})),
            CODE_PINNED,
        ),
        (flash_drive(), _enrolled(flash_drive()), CODE_ENROLLED),
    ],
)
def test_restricting_a_protected_device_is_refused(
    action: Action, device: UsbDevice, context: SafetyContext, code: str
) -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    result = _restrict(_guard(inner, context, refusals=refusals), action, device)

    assert result.ok is False
    assert result.mechanism == "refused"
    assert result.action is action
    assert result.changed is False
    assert result.tier is Tier.NONE
    assert result.undo == ()
    assert result.error is not None and code in result.error
    verdict = _verdict(device, context)
    for reason in verdict.reasons:
        assert reason in result.error
        assert reason in result.detail
    # The wrapped enforcer was never reached, and nothing changed.
    assert inner.calls == ()
    assert inner.state() == CLEAN_STATE
    # The refusal was reported exactly once, with what was asked and why.
    assert refusals == [(device, action, verdict)]


@pytest.mark.parametrize("action", RESTRICTING)
@pytest.mark.parametrize(
    ("device", "context"),
    [
        (make_device(interfaces=(CDC_ACM,)), SafetyContext()),
        (make_device(interfaces=(CDC_ECM,)), SafetyContext()),
        (make_device(interfaces=(AUDIO,)), SafetyContext(scope="storage_and_unknown")),
        (keyboard(), SafetyContext(hid_enforcement_enabled=True)),
    ],
)
def test_a_device_outside_the_scope_is_not_enforced_and_not_called_protected(
    action: Action, device: UsbDevice, context: SafetyContext
) -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    result = _restrict(_guard(inner, context, refusals=refusals), action, device)

    assert result.ok is False
    assert result.mechanism == "out-of-scope"
    assert result.action is action and result.changed is False and result.undo == ()
    assert result.error is not None and result.error.startswith("out_of_scope: ")
    assert f'"{context.scope}"' in result.error
    assert result.detail.startswith("not enforced: ")
    assert "refused" not in result.detail and "protected" not in result.detail
    assert inner.calls == ()
    # Not a refusal: nothing was protected, so nothing is reported as one.
    assert refusals == []


def test_a_protected_device_outside_the_scope_is_refused() -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    result = _guard(inner, refusals=refusals).block(hub())
    assert result.mechanism == "refused"
    assert len(refusals) == 1 and refusals[0][2].in_scope is False


@pytest.mark.parametrize("action", RESTRICTING)
def test_restricting_an_unprotected_device_reaches_the_inner_enforcer(action: Action) -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    device = flash_drive()
    result = _restrict(_guard(inner, refusals=refusals), action, device)

    assert result.ok is True and result.changed is True
    assert result.mechanism.startswith("fake:")
    assert [(call.action, call.instance_id) for call in inner.calls] == [(action, "test/1-1")]
    assert inner.calls[0].result is result
    assert refusals == []


def test_the_badusb_shape_can_be_blocked() -> None:
    inner = FakeEnforcer()
    device = storage_with_keyboard()
    result = _guard(inner).block(device)
    assert result.ok and result.changed
    assert inner.is_blocked(device)


def test_an_enrolled_fingerprint_on_another_port_can_be_blocked() -> None:
    inner = FakeEnforcer()
    stick = flash_drive()
    guard = _guard(inner, _enrolled(stick))
    copy_elsewhere = flash_drive(instance_id="test/2-7", bus_path="2-7")
    assert guard.block(copy_elsewhere).changed is True
    assert guard.block(stick).mechanism == "refused"


def test_restoring_access_is_never_refused() -> None:
    inner = FakeEnforcer()
    devices = [keyboard(), hub(), internal_webcam(), make_device(interfaces=(CDC_ACM,))]
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    guard = _guard(inner, refusals=refusals)
    for device in devices:
        assert not guard.protection(device).enforceable
        # Put the device into a restricted state behind the guard's back, as a crash
        # or an older configuration might have left it.
        assert inner.block(device).changed
    inner.clear_calls()

    for device in devices:
        result = guard.unblock(device)
        assert result.ok and result.changed and result.mechanism == "fake:authorized"
        assert not inner.is_blocked(device)
        assert guard.set_read_only(device, False).ok
    assert [call.action for call in inner.calls] == [Action.UNBLOCK, Action.READ_WRITE] * 4
    assert refusals == []


def test_restoring_access_does_not_even_consult_the_safety_context() -> None:
    inner = FakeEnforcer()
    device = flash_drive()
    inner.block(device)
    inner.set_read_only(device, True)

    def unavailable() -> SafetyContext:
        raise RuntimeError("the state store is down")

    guard = SafeEnforcer(inner, unavailable, dry_run=False)
    assert guard.unblock(device).changed is True
    assert guard.set_read_only(device, False).changed is True
    assert inner.state()["blocked"] == [] and inner.state()["read_only"] == []


def test_default_deny_and_restore_pass_through() -> None:
    inner = FakeEnforcer()
    guard = _guard(inner)
    on = guard.set_default_deny(True)
    assert on.ok and on.changed and on.action is Action.DEFAULT_DENY_ON
    assert inner.default_deny is True
    blocked = guard.block(flash_drive())

    restored = guard.restore([*on.undo, *blocked.undo])
    assert restored.ok and restored.changed and restored.action is Action.RESTORE
    assert inner.default_deny is False
    assert not inner.is_blocked(flash_drive())

    off = guard.set_default_deny(False)
    assert off.ok and off.changed is False
    assert [call.action for call in inner.calls] == [
        Action.DEFAULT_DENY_ON,
        Action.BLOCK,
        Action.RESTORE,
        Action.DEFAULT_DENY_OFF,
    ]


def test_the_context_is_read_afresh_for_every_call() -> None:
    inner = FakeEnforcer()
    device = flash_drive()
    current = [SafetyContext()]
    guard = SafeEnforcer(inner, lambda: current[0], dry_run=False)

    assert guard.block(device).ok is True
    assert guard.unblock(device).ok is True
    # An administrator enrols the device while the service is running.
    current[0] = _enrolled(device)
    refused = guard.block(device)
    assert refused.mechanism == "refused"
    assert not inner.is_blocked(device)
    assert len(inner.calls_for(Action.BLOCK)) == 1


# --- SafeEnforcer: failing safe --------------------------------------------------------


@pytest.mark.parametrize("action", RESTRICTING)
def test_if_the_safety_check_cannot_run_the_device_is_left_alone(action: Action) -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []

    def unavailable() -> SafetyContext:
        raise RuntimeError("the state store is down")

    guard = SafeEnforcer(
        inner, unavailable, dry_run=False, on_refusal=lambda *c: refusals.append(c)
    )
    result = _restrict(guard, action, flash_drive())
    assert result.ok is False and result.mechanism == "refused"
    assert "safety_check_failed" in (result.error or "")
    assert "the state store is down" in (result.error or "")
    assert inner.calls == ()
    assert len(refusals) == 1 and refusals[0][2].codes == (CODE_CHECK_FAILED,)


@pytest.mark.parametrize("bogus", [None, {"scope": "storage"}, "storage", 0])
def test_a_context_provider_returning_rubbish_counts_as_a_failed_check(bogus: object) -> None:
    inner = FakeEnforcer()
    guard = SafeEnforcer(inner, lambda: bogus, dry_run=False)  # type: ignore[arg-type,return-value]
    verdict = guard.protection(flash_drive())
    assert verdict.protected and verdict.codes == (CODE_CHECK_FAILED,)
    assert verdict.enforceable is False
    assert guard.block(flash_drive()).mechanism == "refused"
    assert inner.calls == ()


def test_a_device_that_cannot_be_fingerprinted_is_left_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(_device: UsbDevice) -> Any:
        raise TypeError("descriptor text must be a string")

    monkeypatch.setattr(safety_module, "compute_fingerprint", broken)
    inner = FakeEnforcer()
    result = _guard(inner).block(flash_drive())
    assert result.mechanism == "refused" and result.ok is False
    assert "descriptor text must be a string" in (result.error or "")
    assert inner.calls == ()


def test_a_failing_refusal_callback_does_not_undo_the_refusal() -> None:
    inner = FakeEnforcer()

    def broken(*_call: object) -> None:
        raise RuntimeError("the audit log is unavailable")

    guard = SafeEnforcer(inner, SafetyContext, dry_run=False, on_refusal=broken)
    result = guard.block(keyboard())
    assert result.ok is False and result.mechanism == "refused"
    assert inner.calls == ()


class _BrokenEnforcer(Enforcer):
    """An enforcer that breaks the contract in the way it is told to."""

    def __init__(self, behaviour: Callable[[], Any]) -> None:
        self.behaviour = behaviour
        self.reached = 0

    def _act(self) -> Any:
        self.reached += 1
        return self.behaviour()

    def capabilities(self) -> EnforcerCapabilities:
        return self._act()

    def block(self, device: UsbDevice) -> EnforcementResult:
        return self._act()

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        return self._act()

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        return self._act()

    def eject(self, device: UsbDevice) -> EnforcementResult:
        return self._act()

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        return self._act()

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        return self._act()


def _raise(error: Exception) -> Callable[[], Any]:
    def behaviour() -> Any:
        raise error

    return behaviour


CALLS: list[tuple[Action, Callable[[Enforcer], EnforcementResult]]] = [
    (Action.BLOCK, lambda guard: guard.block(flash_drive())),
    (Action.UNBLOCK, lambda guard: guard.unblock(flash_drive())),
    (Action.READ_ONLY, lambda guard: guard.set_read_only(flash_drive(), True)),
    (Action.READ_WRITE, lambda guard: guard.set_read_only(flash_drive(), False)),
    (Action.EJECT, lambda guard: guard.eject(flash_drive())),
    (Action.DEFAULT_DENY_ON, lambda guard: guard.set_default_deny(True)),
    (Action.DEFAULT_DENY_OFF, lambda guard: guard.set_default_deny(False)),
    (
        Action.RESTORE,
        lambda guard: guard.restore([JournalEntry("fake", "test/1-1/authorized", "1", "0")]),
    ),
]


@pytest.mark.parametrize(("action", "call"), CALLS, ids=[action.value for action, _ in CALLS])
def test_an_exception_from_the_inner_enforcer_becomes_a_failed_result(
    action: Action, call: Callable[[Enforcer], EnforcementResult]
) -> None:
    inner = _BrokenEnforcer(_raise(PermissionError("access denied by the OS")))
    result = call(_guard(inner))
    assert inner.reached == 1
    assert result.ok is False
    assert result.action is action
    assert result.mechanism == "error"
    assert result.changed is False and result.undo == ()
    assert result.error == "PermissionError: access denied by the OS"


@pytest.mark.parametrize(("action", "call"), CALLS, ids=[action.value for action, _ in CALLS])
@pytest.mark.parametrize("rubbish", [None, True, "ok", {"ok": True}])
def test_a_missing_result_from_the_inner_enforcer_becomes_a_failed_result(
    action: Action, call: Callable[[Enforcer], EnforcementResult], rubbish: object
) -> None:
    inner = _BrokenEnforcer(lambda: rubbish)
    result = call(_guard(inner))
    assert isinstance(result, EnforcementResult)
    assert result.ok is False and result.mechanism == "error" and result.action is action
    assert type(rubbish).__name__ in (result.error or "")


def test_injected_exceptions_in_the_fake_are_converted_too() -> None:
    inner = FakeEnforcer()
    inner.fail(Action.BLOCK, raises=OSError("device vanished"))
    result = _guard(inner).block(flash_drive())
    assert result.ok is False and result.mechanism == "error"
    assert result.error == "OSError: device vanished"
    assert not inner.is_blocked(flash_drive())


def test_expected_failures_from_the_inner_enforcer_are_passed_on_unchanged() -> None:
    inner = FakeEnforcer.unprivileged()
    result = _guard(inner).block(flash_drive())
    assert result.ok is False
    assert result.mechanism == "fake:authorized"
    assert result.error is not None and result.error.startswith("not_privileged")
    assert inner.calls[0].result is result


# --- SafeEnforcer: dry run -------------------------------------------------------------


@pytest.mark.parametrize(("action", "call"), CALLS, ids=[action.value for action, _ in CALLS])
def test_dry_run_changes_nothing_and_says_so(
    action: Action, call: Callable[[Enforcer], EnforcementResult]
) -> None:
    inner = _BrokenEnforcer(_raise(AssertionError("dry-run must not reach the enforcer")))
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    guard = _guard(inner, dry_run=True, refusals=refusals)
    assert guard.dry_run is True

    result = call(guard)
    assert result == EnforcementResult(
        action=action,
        ok=True,
        mechanism="dry-run",
        tier=Tier.NONE,
        changed=False,
        detail=result.detail,
        undo=(),
        error=None,
    )
    assert result.detail.startswith("dry-run: ")
    assert inner.reached == 0
    assert refusals == []


@pytest.mark.parametrize("action", RESTRICTING)
def test_dry_run_records_what_enforce_mode_would_have_done(action: Action) -> None:
    inner = FakeEnforcer()
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    guard = _guard(inner, dry_run=True, refusals=refusals)

    protected = _restrict(guard, action, keyboard())
    assert protected.ok is True and protected.mechanism == "dry-run"
    assert "would be refused" in protected.detail
    assert "input device" in protected.detail

    outside = _restrict(guard, action, make_device(interfaces=(CDC_ACM,)))
    assert outside.ok is True and outside.mechanism == "dry-run"
    assert "would not be enforced" in outside.detail and '"storage"' in outside.detail

    unprotected = _restrict(guard, action, flash_drive())
    assert unprotected.ok is True and unprotected.mechanism == "dry-run"
    assert "would be attempted" in unprotected.detail
    assert inner.calls == () and refusals == []


def test_dry_run_does_not_restore_either() -> None:
    inner = FakeEnforcer()
    device = flash_drive()
    undo = inner.block(device).undo
    inner.clear_calls()
    guard = _guard(inner, dry_run=True)
    assert guard.unblock(device).mechanism == "dry-run"
    assert guard.restore(undo).mechanism == "dry-run"
    # Documented consequence: a dry-run guard cannot undo; the enforcing one must.
    assert inner.is_blocked(device)
    assert inner.calls == ()
    assert _guard(inner).restore(undo).changed is True
    assert not inner.is_blocked(device)


# --- SafeEnforcer: capabilities and construction ---------------------------------------


def test_capabilities_are_the_inner_ones() -> None:
    inner = FakeEnforcer()
    assert _guard(inner).capabilities() == inner.capabilities()
    unprivileged = FakeEnforcer.unprivileged()
    assert _guard(unprivileged).capabilities() == unprivileged.capabilities()
    assert _guard(unprivileged).capabilities().block is False


def test_capabilities_carry_a_note_in_dry_run() -> None:
    inner = FakeEnforcer()
    reported = _guard(inner, dry_run=True).capabilities()
    original = inner.capabilities()
    assert reported.notes[: len(original.notes)] == original.notes
    assert len(reported.notes) == len(original.notes) + 1
    assert "dry-run" in reported.notes[-1]
    assert dataclasses.replace(reported, notes=original.notes) == original


@pytest.mark.parametrize("behaviour", [_raise(OSError("no access")), lambda: None, lambda: "all"])
def test_capabilities_that_cannot_be_determined_are_reported_as_none(
    behaviour: Callable[[], Any],
) -> None:
    reported = _guard(_BrokenEnforcer(behaviour)).capabilities()
    assert isinstance(reported, EnforcerCapabilities)
    assert (reported.privileged, reported.block, reported.read_only) == (False, False, False)
    assert (reported.eject, reported.default_deny) == (False, False)
    assert "could not be determined" in reported.notes[0]


def test_constructor_arguments_are_checked() -> None:
    inner = FakeEnforcer()
    with pytest.raises(TypeError):
        SafeEnforcer(object(), SafetyContext, dry_run=False)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SafeEnforcer(inner, SafetyContext(), dry_run=False)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SafeEnforcer(inner, SafetyContext, dry_run="no")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SafeEnforcer(inner, SafetyContext, dry_run=False, on_refusal="log")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SafeEnforcer(inner, SafetyContext)  # type: ignore[call-arg]
    guard = SafeEnforcer(inner, SafetyContext, dry_run=False)
    with pytest.raises(TypeError):
        guard.set_read_only(flash_drive(), 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        guard.set_default_deny("on")  # type: ignore[arg-type]


# --- SafeEnforcer: the standing read-only baseline -------------------------------------


class _BaselineEnforcer(_BrokenEnforcer):
    """An enforcer that offers the baseline, recording what it was asked."""

    def __init__(self, behaviour: Callable[[], Any]) -> None:
        super().__init__(behaviour)
        self.asked: list[bool] = []

    def set_baseline_read_only(self, enabled: bool) -> EnforcementResult:
        self.asked.append(enabled)
        return self._act()


def _baseline_result(action: Action) -> EnforcementResult:
    return EnforcementResult(
        action=action, ok=True, mechanism="udev-rule", tier=Tier.PREVENTIVE, changed=True
    )


@pytest.mark.parametrize(
    ("enabled", "action"), [(True, Action.READ_ONLY), (False, Action.READ_WRITE)]
)
def test_the_baseline_passes_through_without_a_protection_check(
    enabled: bool, action: Action
) -> None:
    inner = _BaselineEnforcer(lambda: _baseline_result(action))
    refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
    result = _guard(inner, refusals=refusals).set_baseline_read_only(enabled)
    assert result == _baseline_result(action)
    assert inner.asked == [enabled]
    assert refusals == []


@pytest.mark.parametrize("enabled", [True, False])
def test_the_baseline_in_dry_run_reaches_nothing(enabled: bool) -> None:
    inner = _BaselineEnforcer(_raise(AssertionError("dry-run must not reach the enforcer")))
    result = _guard(inner, dry_run=True).set_baseline_read_only(enabled)
    assert result.ok is True and result.mechanism == "dry-run" and result.changed is False
    assert result.action is (Action.READ_ONLY if enabled else Action.READ_WRITE)
    assert result.detail.startswith("dry-run: ") and "baseline" in result.detail
    assert inner.asked == [] and inner.reached == 0


def test_the_baseline_on_an_enforcer_without_one_is_reported_as_unsupported() -> None:
    inner = FakeEnforcer()
    assert not hasattr(inner, "set_baseline_read_only")
    result = _guard(inner).set_baseline_read_only(True)
    assert result.ok is False and result.mechanism == "unsupported"
    assert result.action is Action.READ_ONLY
    assert result.changed is False and result.undo == ()
    assert result.error is not None and result.error.startswith("unsupported: ")
    assert inner.calls == ()
    dry = _guard(inner, dry_run=True).set_baseline_read_only(True)
    assert dry.ok is True and "offers no baseline" in dry.detail


def test_the_baseline_turns_an_exception_or_rubbish_into_a_failed_result() -> None:
    raised = _guard(
        _BaselineEnforcer(_raise(PermissionError("udev is read-only")))
    ).set_baseline_read_only(True)
    assert raised.ok is False and raised.mechanism == "error"
    assert raised.error == "PermissionError: udev is read-only"
    rubbish = _guard(_BaselineEnforcer(lambda: None)).set_baseline_read_only(False)
    assert rubbish.ok is False and rubbish.mechanism == "error"
    assert rubbish.action is Action.READ_WRITE


def test_the_baseline_insists_on_a_real_boolean() -> None:
    guard = _guard(_BaselineEnforcer(lambda: _baseline_result(Action.READ_ONLY)))
    with pytest.raises(TypeError):
        guard.set_baseline_read_only(1)  # type: ignore[arg-type]


# --- the property: nothing protected or out of scope is ever restricted ----------------

INTERFACE_POOL = (
    MASS_STORAGE,
    BOOT_KEYBOARD,
    BOOT_MOUSE,
    GENERIC_HID,
    HUB,
    MTP,
    CDC_ACM,
    CDC_ECM,
    VENDOR,
    DIAGNOSTIC,
    AUDIO,
    UsbInterface(0x0E, 0x01, 0x00),
    UsbInterface(0x0B, 0x00, 0x00),
)
INSTANCE_POOL = tuple(f"test/{bus}-{port}" for bus in range(1, 4) for port in range(1, 5))
PORT_POOL = (None, "1-1", "1-2", "2-1", "2-1.3")
SERIAL_POOL = (None, "TEST0001A7C3", "TEST0002B8D4", "0123456789ABCDEF", "")


OPERATIONS: tuple[Callable[[Enforcer, UsbDevice], EnforcementResult], ...] = (
    lambda guard, device: guard.block(device),
    lambda guard, device: guard.eject(device),
    lambda guard, device: guard.set_read_only(device, True),
    lambda guard, device: guard.unblock(device),
    lambda guard, device: guard.set_read_only(device, False),
)


def _random_device(rng: random.Random) -> UsbDevice:
    return make_device(
        instance_id=rng.choice(INSTANCE_POOL),
        product_id=rng.randrange(1, 6),
        serial=rng.choice(SERIAL_POOL),
        device_class=rng.choice((0x00, 0x00, 0x03, 0x06, 0x08, 0x09, 0xEF, 0xFF)),
        interfaces=tuple(rng.sample(INTERFACE_POOL, rng.randrange(0, 4))),
        bus_path=rng.choice(PORT_POOL),
        removable=rng.choice((True, True, True, False, None)),
    )


def _random_context(rng: random.Random, own: str) -> SafetyContext:
    pinned = {f"plk1:{rng.randrange(10**6):032d}" for _ in range(rng.randrange(0, 3))}
    if rng.random() < 0.1:
        pinned.add(own)
    enrolled = {(f"plk1:{rng.randrange(10**6):032d}", "1-1") for _ in range(rng.randrange(0, 2))}
    if rng.random() < 0.15:
        # Sometimes on the device's own port, sometimes on another one.
        enrolled.add((own, rng.choice(("1-1", "1-2", "2-1", "2-1.3"))))
    system = set(rng.sample(INSTANCE_POOL, rng.randrange(0, 2)))
    return SafetyContext(
        enrolled=frozenset(enrolled),
        pinned_fingerprints=frozenset(pinned),
        system_instance_ids=frozenset(system),
        hid_enforcement_enabled=rng.random() < 0.5,
        scope=rng.choice(SCOPES),
    )


@pytest.mark.parametrize("seed", [20261116, 715517])
def test_nothing_protected_or_out_of_scope_is_ever_restricted(seed: int) -> None:
    # Two seeds of 2000 cases each: 4000 random devices and contexts in all.
    rng = random.Random(seed)
    cases = 2000
    outcomes = {"protected": 0, "out_of_scope": 0, "enforced": 0}
    codes_seen: set[str] = set()

    for _ in range(cases):
        device = _random_device(rng)
        own = fingerprint(device)
        context = _random_context(rng, own.value)
        inner = FakeEnforcer()
        refusals: list[tuple[UsbDevice, Action, ProtectionVerdict]] = []
        guard = _guard(inner, context, refusals=refusals)

        operations = list(OPERATIONS)
        rng.shuffle(operations)
        results = [operation(guard, device) for operation in operations]

        verdict = is_protected(device, own, context)
        restricted = inner.calls_for(*RESTRICTING)
        restoring = inner.calls_for(Action.UNBLOCK, Action.READ_WRITE)
        # Restoring access always reaches the enforcer, protected or not.
        assert len(restoring) == 2
        restricting_results = [result for result in results if result.action in RESTRICTING]
        if verdict.protected:
            outcomes["protected"] += 1
            codes_seen.update(verdict.codes)
            # The property: the enforcer was never asked to restrict this device.
            assert restricted == ()
            assert not inner.is_blocked(device)
            assert not inner.is_read_only(device)
            assert not inner.was_ejected(device)
            assert all(result.mechanism == "refused" for result in restricting_results)
            assert sorted(call[1] for call in refusals) == sorted(RESTRICTING)
        elif not verdict.in_scope:
            outcomes["out_of_scope"] += 1
            assert restricted == ()
            assert all(result.mechanism == "out-of-scope" for result in restricting_results)
            assert refusals == []
        else:
            outcomes["enforced"] += 1
            # And the guard is not simply refusing everything.
            assert sorted(call.action for call in restricted) == sorted(RESTRICTING)
            assert refusals == []
            assert all(result.mechanism not in ("refused", "out-of-scope") for result in results)

    # The generator really exercised every outcome and every rule.
    assert sum(outcomes.values()) == cases
    assert all(count > cases // 20 for count in outcomes.values()), outcomes
    assert codes_seen == {
        CODE_HUB,
        CODE_BUILT_IN,
        CODE_SYSTEM_VOLUME,
        CODE_PINNED,
        CODE_ENROLLED,
        CODE_INPUT_DEVICE,
    }


# --- detect_clone ------------------------------------------------------------------------


def test_a_second_connection_with_an_enrolled_fingerprint_is_a_clone() -> None:
    original = keyboard(connection_id="c1")
    context = _enrolled(original)
    copy = keyboard(instance_id="test/2-5", bus_path="2-5", connection_id="c2")
    value = fingerprint(original)
    connected = [(original, value), (copy, value), (flash_drive(), fingerprint(flash_drive()))]
    assert detect_clone(copy, value, connected, context) == (original,)
    # Seen from the other side, the copy is the duplicate: the caller decides which
    # connection the safety layer still protects (only the one on the enrolled port).
    assert detect_clone(original, value.value, connected, context) == (copy,)


def test_no_clone_without_a_second_connection() -> None:
    board = keyboard(connection_id="c1")
    context = _enrolled(board)
    value = fingerprint(board).value
    assert detect_clone(board, value, [], context) == ()
    # The connection itself, listed among the connected devices, is not a duplicate,
    # even when the platform spells its instance id in another case.
    same = keyboard(instance_id="TEST/1-2", connection_id="c1")
    assert detect_clone(board, value, [(same, value)], context) == ()
    # Without connection ids, one instance id is one connection.
    bare = keyboard()
    assert detect_clone(bare, value, [(keyboard(), value)], context) == ()


def test_a_new_connection_on_the_same_instance_id_counts_separately() -> None:
    # The instance id survives a re-plug, so a stale listing of the previous connection
    # is told apart by its connection id.
    board = keyboard(connection_id="c2")
    context = _enrolled(board)
    value = fingerprint(board).value
    stale = keyboard(connection_id="c1")
    assert detect_clone(board, value, [(stale, value)], context) == (stale,)


def test_fingerprints_that_are_not_enrolled_are_never_clones() -> None:
    # Two identical sticks without serial numbers share a fingerprint legitimately.
    first = flash_drive(serial=None, connection_id="c1")
    second = flash_drive(serial=None, instance_id="test/1-8", bus_path="1-8", connection_id="c2")
    value = fingerprint(first).value
    assert fingerprint(second).value == value
    connected = [(first, value), (second, value)]
    assert detect_clone(second, value, connected, SafetyContext()) == ()
    pinned = SafetyContext(pinned_fingerprints=frozenset({value}))
    assert detect_clone(second, value, connected, pinned) == ()
    # Once enrolled (on any port), the duplicate is reported.
    assert detect_clone(second, value, connected, _enrolled(first)) == (first,)


def test_every_duplicate_is_reported_in_order() -> None:
    board = keyboard(connection_id="c0")
    context = _enrolled(board)
    value = fingerprint(board).value
    copies = [
        keyboard(instance_id=f"test/4-{index}", bus_path=f"4-{index}", connection_id=f"c{index}")
        for index in range(1, 4)
    ]
    connected = [(copy, value) for copy in copies]
    assert detect_clone(board, value, connected, context) == tuple(copies)


# --- PortFlapGuard ---------------------------------------------------------------------


def _flap(clock: FakeClock, max_arrivals: int = 3) -> PortFlapGuard:
    return PortFlapGuard(clock, max_arrivals=max_arrivals, window_seconds=10, cooldown_seconds=60)


def test_arrivals_up_to_the_limit_are_not_held(clock: FakeClock) -> None:
    guard = _flap(clock)
    verdicts = [guard.record_arrival("1-2") for _ in range(3)]
    assert [verdict.arrivals for verdict in verdicts] == [1, 2, 3]
    assert all(not verdict.held and verdict.audit for verdict in verdicts)
    assert verdicts[0] == FlapVerdict(
        port="1-2", held=False, newly_held=False, audit=True, arrivals=1
    )
    assert guard.is_held("1-2") is False and guard.held_ports() == {}


def test_one_arrival_more_than_the_limit_holds_the_port(clock: FakeClock) -> None:
    guard = _flap(clock)
    for _ in range(3):
        guard.record_arrival("1-2")
    clock.advance(1)
    tipping = guard.record_arrival("1-2")
    start = clock.monotonic()
    assert tipping == FlapVerdict(
        port="1-2",
        held=True,
        newly_held=True,
        audit=True,
        arrivals=4,
        held_until=start + 60,
    )
    assert guard.is_held("1-2") and guard.held_ports() == {"1-2": start + 60}

    # Further arrivals stay held, are coalesced, and restart the cool-down.
    clock.advance(30)
    during = guard.record_arrival("1-2")
    assert (during.held, during.newly_held, during.audit) == (True, False, False)
    assert during.arrivals == 2
    assert during.held_until == start + 30 + 60
    # Other ports are unaffected.
    assert guard.record_arrival("1-3").held is False


def test_a_hold_ends_after_a_quiet_cool_down_and_is_reported_once(clock: FakeClock) -> None:
    guard = _flap(clock)
    for _ in range(4):
        guard.record_arrival("1-2")
    clock.advance(20)
    guard.record_arrival("1-2")
    guard.record_arrival("1-2")
    assert guard.release_expired() == ()

    clock.advance(59.5)
    assert guard.is_held("1-2")
    clock.advance(0.5)
    assert guard.is_held("1-2") is False
    clock.advance(1000)  # reported late, but the duration is the hold's own
    assert guard.release_expired() == (PortRelease(port="1-2", coalesced=2, held_seconds=80.0),)
    assert guard.release_expired() == ()
    # The port starts afresh: history from before the hold does not count.
    assert [guard.record_arrival("1-2").held for _ in range(3)] == [False, False, False]


def test_the_window_slides(clock: FakeClock) -> None:
    guard = _flap(clock)
    # Four arrivals, but never more than three within any ten seconds.
    for _ in range(12):
        assert guard.record_arrival("1-2").held is False
        clock.advance(10 / 3 + 0.01)
    # An arrival exactly one window old no longer counts. (A fresh clock keeps the
    # arithmetic exact.)
    exact = FakeClock()
    guard2 = _flap(exact, max_arrivals=1)
    guard2.record_arrival("2-1")
    exact.advance(10)
    assert guard2.record_arrival("2-1") == FlapVerdict(
        port="2-1", held=False, newly_held=False, audit=True, arrivals=1
    )
    exact.advance(9.5)
    assert guard2.record_arrival("2-1").newly_held is True


def test_holds_use_monotonic_time_not_the_wall_clock(clock: FakeClock) -> None:
    guard = _flap(clock, max_arrivals=1)
    guard.record_arrival("1-2")
    assert guard.record_arrival("1-2").newly_held
    # Setting the clock back (or forward) does not shorten or lengthen the hold.
    clock.set(datetime(2030, 1, 1, tzinfo=UTC))
    assert guard.is_held("1-2")
    clock.set(datetime(2000, 1, 1, tzinfo=UTC))
    assert guard.is_held("1-2")


def test_an_arrival_without_a_port_is_never_held(clock: FakeClock) -> None:
    guard = _flap(clock, max_arrivals=1)
    verdicts = [guard.record_arrival(None) for _ in range(5)]
    assert all(not verdict.held and verdict.audit for verdict in verdicts)
    assert guard.is_held(None) is False
    with pytest.raises(ValueError):
        guard.record_arrival("")


def test_an_administrator_can_end_a_hold_early(clock: FakeClock) -> None:
    guard = _flap(clock, max_arrivals=1)
    assert guard.release("1-2") is None
    guard.record_arrival("1-2")
    guard.record_arrival("1-2")
    guard.record_arrival("1-2")
    clock.advance(5)
    assert guard.release("1-2") == PortRelease(
        port="1-2", coalesced=1, held_seconds=5.0, manual=True
    )
    assert guard.is_held("1-2") is False
    assert guard.release_expired() == ()


@pytest.mark.parametrize(
    "arguments",
    [
        {"max_arrivals": 0},
        {"max_arrivals": -1},
        {"max_arrivals": 2.5},
        {"max_arrivals": True},
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"window_seconds": float("nan")},
        {"window_seconds": float("inf")},
        {"window_seconds": "10"},
        {"cooldown_seconds": 0},
        {"cooldown_seconds": False},
    ],
)
def test_flap_guard_settings_are_validated(clock: FakeClock, arguments: dict[str, Any]) -> None:
    settings: dict[str, Any] = {"max_arrivals": 3, "window_seconds": 10, "cooldown_seconds": 60}
    settings.update(arguments)
    with pytest.raises(ValueError):
        PortFlapGuard(clock, **settings)


def test_flap_guard_needs_a_clock() -> None:
    with pytest.raises(TypeError):
        PortFlapGuard(object(), 3, 10, 60)  # type: ignore[arg-type]
    guard = PortFlapGuard(FakeClock(), 3, 10, 60)
    assert (guard.max_arrivals, guard.window_seconds, guard.cooldown_seconds) == (3, 10.0, 60.0)


def test_concurrent_arrivals_are_counted_exactly(clock: FakeClock) -> None:
    guard = PortFlapGuard(clock, max_arrivals=500, window_seconds=10, cooldown_seconds=60)
    threads_count, per_thread = 8, 100
    start = threading.Barrier(threads_count)
    verdicts: list[FlapVerdict] = []
    lock = threading.Lock()

    def worker() -> None:
        start.wait(timeout=10)
        mine = [guard.record_arrival("1-2") for _ in range(per_thread)]
        with lock:
            verdicts.extend(mine)

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(verdicts) == threads_count * per_thread
    assert sum(verdict.newly_held for verdict in verdicts) == 1
    assert sum(not verdict.held for verdict in verdicts) == 500
    assert sum(verdict.audit for verdict in verdicts) == 501
    clock.advance(60)
    assert guard.release_expired()[0].coalesced == 299
