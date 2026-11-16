"""Policy evaluation: matching, rule order, expiry, time windows and the shipped policies."""

from __future__ import annotations

import dataclasses
import datetime as dt
import threading
import time
from typing import Any

import pytest

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
from portlock.core.models import (
    Access,
    Confidence,
    DeviceCategory,
    Fingerprint,
    ScanRequirement,
    UsbDevice,
    UsbInterface,
)
from portlock.policy.defaults import DEFAULT_POLICY, EXAMPLE_POLICY
from portlock.policy.engine import (
    MAX_SUBJECT_LENGTH,
    PolicyEngine,
    PolicyResult,
    RuleOutcome,
)
from portlock.policy.model import (
    MAX_PATTERN_WILDCARDS,
    MAX_RULES,
    Match,
    Policy,
    Rule,
    RuleAction,
    TimeWindow,
)

UTC = dt.UTC
#: Monday 5 January 2026, 10:00 UTC.
NOW = dt.datetime(2026, 1, 5, 10, 0, tzinfo=UTC)
FP_VALUE = "plk1:abcdefghijklmnopqrstuvwxyz234567"
HIGH = Fingerprint(FP_VALUE, Confidence.HIGH)
LOW = Fingerprint("plk1:" + "q" * 32, Confidence.LOW)

ALLOW = RuleAction(Access.ALLOW)
READ_ONLY = RuleAction(Access.READ_ONLY)
DENY = RuleAction(Access.DENY, alert=True)
OFFICE_HOURS = TimeWindow(days=(0, 1, 2, 3, 4), start=dt.time(9, 0), end=dt.time(17, 0))

#: The most characters ``UsbDevice`` keeps of a device string.
DEVICE_TEXT_LIMIT = 126
ZERO_WIDTH_SPACE = chr(0x200B)
FULLWIDTH_E = chr(0xFF25)

ALL_DEVICES = (
    flash_drive(),
    flash_drive(serial=None),
    mounted_flash_drive(),
    keyboard(),
    mouse(),
    hub(),
    storage_with_keyboard(),
    phone(),
    internal_webcam(),
)


def rule(rule_id: str, action: RuleAction = ALLOW, **criteria: Any) -> Rule:
    extras = {key: criteria.pop(key) for key in ("enabled", "expires") if key in criteria}
    return Rule(id=rule_id, match=Match(**criteria), action=action, **extras)


def engine(*rules: Rule, default: RuleAction | None = None) -> PolicyEngine:
    return PolicyEngine(Policy(rules=rules, default=default or RuleAction(Access.PENDING)))


def evaluate(
    policy_engine: PolicyEngine,
    device: UsbDevice | None = None,
    fingerprint: Fingerprint = HIGH,
    now: dt.datetime = NOW,
) -> PolicyResult:
    return policy_engine.evaluate(device or flash_drive(), fingerprint, now=now)


# --- rule order and the default -------------------------------------------------------


def test_the_first_matching_rule_wins() -> None:
    policy_engine = engine(
        rule("other-vendor", DENY, vendor_id=0x0001),
        rule("first", READ_ONLY, vendor_id=0x1209),
        rule("second", ALLOW, vendor_id=0x1209),
    )
    result = evaluate(policy_engine)
    assert result.rule is not None and result.rule.id == "first"
    assert result.action == READ_ONLY
    assert result.matched_default is False
    assert result.skipped == ()
    assert result.explanation == ("vendor_id 0x1209 is listed",)
    assert result.valid_until is None


def test_swapping_two_rules_swaps_the_outcome() -> None:
    allow_all_storage = rule("allow-storage", ALLOW, category=DeviceCategory.STORAGE)
    deny_vendor = rule("deny-vendor", DENY, vendor_id=0x1209)
    assert evaluate(engine(allow_all_storage, deny_vendor)).action == ALLOW
    assert evaluate(engine(deny_vendor, allow_all_storage)).action == DENY


def test_the_default_applies_when_no_rule_matches() -> None:
    default = RuleAction(Access.READ_ONLY, scan=ScanRequirement.REQUIRED, alert=True)
    result = evaluate(engine(rule("nope", ALLOW, vendor_id=0x0001), default=default))
    assert result.rule is None
    assert result.matched_default is True
    assert result.action == default
    assert result.explanation == ("no enabled, unexpired rule matched; the policy default applies",)


def test_a_policy_without_rules_gives_its_default() -> None:
    result = evaluate(PolicyEngine(Policy()))
    assert result.matched_default and result.action == RuleAction(Access.PENDING)


# --- disabled and expired rules -------------------------------------------------------


def test_disabled_and_expired_rules_are_skipped_with_a_reason() -> None:
    expiry = dt.datetime(2026, 1, 5, 9, 0, tzinfo=UTC)
    policy_engine = engine(
        rule("off", ALLOW, vendor_id=0x1209, enabled=False),
        rule("old", ALLOW, vendor_id=0x1209, expires=expiry),
        rule("live", DENY, vendor_id=0x1209),
        rule("after-the-winner", ALLOW, vendor_id=0x1209, enabled=False),
    )
    result = evaluate(policy_engine)
    assert result.rule is not None and result.rule.id == "live"
    # Rules after the winner are never reached, so they are not reported as skipped.
    assert result.skipped == (
        ("off", "disabled"),
        ("old", "expired at 2026-01-05T09:00:00.000000Z"),
    )


def test_skipped_rules_are_reported_when_the_default_applies() -> None:
    result = evaluate(engine(rule("off", ALLOW, vendor_id=0x1209, enabled=False)))
    assert result.matched_default
    assert result.skipped == (("off", "disabled"),)


def test_a_rule_expires_at_the_instant_itself() -> None:
    expiry = dt.datetime(2026, 1, 5, 10, 0, tzinfo=UTC)
    policy_engine = engine(rule("timed", ALLOW, vendor_id=0x1209, expires=expiry))

    before = evaluate(policy_engine, now=expiry - dt.timedelta(microseconds=1))
    assert before.rule is not None and before.rule.id == "timed"
    assert before.valid_until == expiry

    at_expiry = evaluate(policy_engine, now=expiry)
    assert at_expiry.matched_default
    assert at_expiry.skipped == (("timed", "expired at 2026-01-05T10:00:00.000000Z"),)
    assert at_expiry.valid_until is None


def test_the_expiry_of_a_rule_that_does_not_match_is_irrelevant() -> None:
    soon = NOW + dt.timedelta(minutes=5)
    policy_engine = engine(
        rule("other", DENY, vendor_id=0x0001, expires=soon),
        rule("mine", ALLOW, vendor_id=0x1209),
    )
    assert evaluate(policy_engine).valid_until is None


# --- individual criteria --------------------------------------------------------------

NO_SERIAL = flash_drive(serial=None)
BARE = make_device(serial=None, manufacturer=None, product=None, bus_path=None, removable=None)
CLASS_ONLY_HUB = make_device(interfaces=(), device_class=0x09)


@pytest.mark.parametrize(
    ("criteria", "device", "fingerprint", "expected"),
    [
        ({"vendor_id": 0x1209}, flash_drive(), HIGH, True),
        ({"vendor_id": 0x120A}, flash_drive(), HIGH, False),
        ({"vendor_id": [0x0001, 0x1209]}, flash_drive(), HIGH, True),
        ({"vendor_id": [0x0001, 0x0002]}, flash_drive(), HIGH, False),
        ({"product_id": 0x0001}, flash_drive(), HIGH, True),
        ({"product_id": 0x0002}, flash_drive(), HIGH, False),
        ({"product_id": [0x0009, 0x0002]}, keyboard(), HIGH, True),
        # Every present criterion has to match.
        ({"vendor_id": 0x1209, "product_id": 0x0001}, flash_drive(), HIGH, True),
        ({"vendor_id": 0x1209, "product_id": 0x0002}, flash_drive(), HIGH, False),
        ({"vendor_id": 0x0001, "product_id": 0x0001}, flash_drive(), HIGH, False),
        # Strings: case-insensitive globs over the whole value.
        ({"serial": "TEST0001A7C3"}, flash_drive(), HIGH, True),
        ({"serial": "test0001a7c3"}, flash_drive(), HIGH, True),
        ({"serial": "TEST*"}, flash_drive(), HIGH, True),
        ({"serial": "TEST????A7C3"}, flash_drive(), HIGH, True),
        ({"serial": "TEST???A7C3"}, flash_drive(), HIGH, False),
        ({"serial": "0001"}, flash_drive(), HIGH, False),
        ({"serial": ["NOPE*", "*A7C3"]}, flash_drive(), HIGH, True),
        ({"serial": ["NOPE*", "NADA*"]}, flash_drive(), HIGH, False),
        ({"manufacturer": "example corp"}, flash_drive(), HIGH, True),
        ({"manufacturer": "EXAMPLE*"}, flash_drive(), HIGH, True),
        ({"manufacturer": "Sample*"}, flash_drive(), HIGH, False),
        ({"product": "*flash*"}, flash_drive(), HIGH, True),
        ({"product": "*keyboard*"}, flash_drive(), HIGH, False),
        ({"product": "Example Flash [0-9][0-9]GB"}, flash_drive(), HIGH, True),
        ({"product": "Example Flash [!0-9]*"}, flash_drive(), HIGH, False),
        ({"bus_path": "1-1"}, flash_drive(), HIGH, True),
        ({"bus_path": "1-1"}, flash_drive(bus_path="1-10"), HIGH, False),
        ({"bus_path": ["1-1", "1-1.*"]}, flash_drive(bus_path="1-1.4"), HIGH, True),
        ({"bus_path": ["1-1", "1-1.*"]}, flash_drive(bus_path="1-10"), HIGH, False),
        # Bus paths: a pattern names a port and covers what is behind it, segment by
        # segment, so a port never matches another whose name merely starts the same.
        ({"bus_path": "1-2"}, flash_drive(bus_path="1-21"), HIGH, False),
        ({"bus_path": "1-2"}, flash_drive(bus_path="1-2.4.1"), HIGH, True),
        ({"bus_path": "1-2"}, flash_drive(bus_path="1-21.4"), HIGH, False),
        ({"bus_path": "1-2.4"}, flash_drive(bus_path="1-2"), HIGH, False),
        ({"bus_path": "1-2.*"}, flash_drive(bus_path="1-2"), HIGH, False),
        ({"bus_path": "1-2.*"}, flash_drive(bus_path="1-2.3"), HIGH, True),
        ({"bus_path": "1-*"}, flash_drive(bus_path="1-7.1.2"), HIGH, True),
        ({"bus_path": "1-*"}, flash_drive(bus_path="2-1"), HIGH, False),
        ({"bus_path": "1-2*"}, flash_drive(bus_path="1-20.3"), HIGH, True),
        (
            {"bus_path": "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)"},
            flash_drive(bus_path="PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)#USB(3)"),
            HIGH,
            True,
        ),
        (
            {"bus_path": "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)"},
            flash_drive(bus_path="PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(21)"),
            HIGH,
            False,
        ),
        (
            {"bus_path": "pciroot(0)#*#usb(2)"},
            flash_drive(bus_path="PCIROOT(0)#X#USB(2)"),
            HIGH,
            True,
        ),
        # A missing string never matches, not even a pattern that matches anything.
        ({"serial": "*"}, flash_drive(), HIGH, True),
        ({"serial": "*"}, NO_SERIAL, HIGH, False),
        ({"serial": "*"}, flash_drive(serial=""), HIGH, False),
        ({"serial": "*"}, flash_drive(serial="  \t "), HIGH, False),
        ({"manufacturer": "*"}, BARE, HIGH, False),
        ({"product": "*"}, BARE, HIGH, False),
        ({"bus_path": "*"}, BARE, HIGH, False),
        # Fingerprints: exact, in either spelling.
        ({"fingerprint": FP_VALUE}, flash_drive(), HIGH, True),
        ({"fingerprint": FP_VALUE.upper()}, flash_drive(), HIGH, True),
        ({"fingerprint": FP_VALUE}, flash_drive(), LOW, False),
        ({"fingerprint": [LOW.value, FP_VALUE]}, flash_drive(), HIGH, True),
        (
            {"fingerprint": FP_VALUE},
            flash_drive(),
            Fingerprint(FP_VALUE.upper(), Confidence.HIGH),
            True,
        ),
        # Categories and interface classes: any declared function counts.
        ({"category": DeviceCategory.STORAGE}, flash_drive(), HIGH, True),
        ({"category": DeviceCategory.KEYBOARD}, flash_drive(), HIGH, False),
        ({"category": DeviceCategory.KEYBOARD}, storage_with_keyboard(), HIGH, True),
        (
            {"category": [DeviceCategory.HUB, DeviceCategory.IMAGING]},
            phone(),
            HIGH,
            True,
        ),
        ({"category": [DeviceCategory.HUB, DeviceCategory.MOUSE]}, phone(), HIGH, False),
        ({"category": DeviceCategory.HUB}, CLASS_ONLY_HUB, HIGH, True),
        ({"interface_class": 0x08}, flash_drive(), HIGH, True),
        ({"interface_class": 0x03}, flash_drive(), HIGH, False),
        ({"interface_class": [0x03, 0xFF]}, storage_with_keyboard(), HIGH, True),
        ({"interface_class": 0x0E}, internal_webcam(), HIGH, True),
        # No interfaces reported: the device class stands in.
        ({"interface_class": 0x09}, CLASS_ONLY_HUB, HIGH, True),
        ({"interface_class": 0x08}, CLASS_ONLY_HUB, HIGH, False),
        ({"confidence": Confidence.HIGH}, flash_drive(), HIGH, True),
        ({"confidence": Confidence.HIGH}, flash_drive(), LOW, False),
        ({"confidence": Confidence.LOW}, flash_drive(), LOW, True),
        ({"composite": True}, storage_with_keyboard(), HIGH, True),
        ({"composite": True}, flash_drive(), HIGH, False),
        ({"composite": False}, flash_drive(), HIGH, True),
        ({"composite": False}, storage_with_keyboard(), HIGH, False),
        ({"storage_with_input": True}, storage_with_keyboard(), HIGH, True),
        (
            {"storage_with_input": True},
            make_device(interfaces=(MASS_STORAGE, GENERIC_HID)),
            HIGH,
            True,
        ),
        ({"storage_with_input": True}, flash_drive(), HIGH, False),
        ({"storage_with_input": True}, keyboard(), HIGH, False),
        ({"storage_with_input": False}, keyboard(), HIGH, True),
        ({"mixes_input_with_other": True}, storage_with_keyboard(), HIGH, True),
        (
            {"mixes_input_with_other": True},
            make_device(interfaces=(BOOT_KEYBOARD, CDC_ACM)),
            HIGH,
            True,
        ),
        ({"mixes_input_with_other": True}, keyboard(), HIGH, False),
        (
            {"mixes_input_with_other": True},
            make_device(interfaces=(BOOT_KEYBOARD, BOOT_MOUSE, HUB)),
            HIGH,
            False,
        ),
        ({"mixes_input_with_other": True}, flash_drive(), HIGH, False),
        ({"mixes_input_with_other": False}, flash_drive(), HIGH, True),
        ({"storage_like": True}, flash_drive(), HIGH, True),
        ({"storage_like": True}, phone(), HIGH, True),
        ({"storage_like": True}, keyboard(), HIGH, False),
        ({"storage_like": True}, internal_webcam(), HIGH, False),
        ({"storage_like": False}, keyboard(), HIGH, True),
        ({"removable": True}, flash_drive(), HIGH, True),
        ({"removable": False}, flash_drive(), HIGH, False),
        ({"removable": False}, internal_webcam(), HIGH, True),
        # Unknown is neither true nor false.
        ({"removable": True}, BARE, HIGH, False),
        ({"removable": False}, BARE, HIGH, False),
    ],
)
def test_criteria(
    criteria: dict[str, Any], device: UsbDevice, fingerprint: Fingerprint, expected: bool
) -> None:
    result = evaluate(engine(rule("probe", DENY, **criteria)), device, fingerprint)
    assert (result.rule is not None) is expected
    assert result.matched_default is not expected
    assert result.action.access is (Access.DENY if expected else Access.PENDING)


@pytest.mark.parametrize(
    "manufacturer",
    [
        "EVIL CORP",
        "evil corp",
        "  Evil   Corp  ",
        f"Ev{ZERO_WIDTH_SPACE}il Corp",
        f"{FULLWIDTH_E}vil Corp",
        "Evil\tCorp",
        "Evil\x00 Corp",
        f"Evil{chr(0x202E)} Corp",
        f"Evil{chr(0x2028)}Corp",
        f"{chr(0xFEFF)}Evil Corp{chr(0x200D)}",
    ],
)
def test_a_device_cannot_dodge_a_pattern_by_dressing_up_its_strings(manufacturer: str) -> None:
    policy_engine = engine(rule("deny-evil", DENY, manufacturer="Evil Corp"))
    device = flash_drive(manufacturer=manufacturer)
    # The model has already replaced the unsafe characters; matching still sees through.
    assert device.manufacturer is not None and device.manufacturer.isprintable()
    result = evaluate(policy_engine, device)
    assert result.rule is not None and result.rule.id == "deny-evil"


def test_a_string_of_nothing_but_unsafe_characters_counts_as_absent() -> None:
    policy_engine = engine(rule("any-serial", DENY, serial="*"))
    for serial in ("\x00\x01\x02", "\t \n", chr(0x202E) * 3):
        assert evaluate(policy_engine, flash_drive(serial=serial)).rule is None


def test_explanations_name_every_criterion_of_the_winning_rule() -> None:
    policy_engine = engine(
        rule(
            "detailed",
            ALLOW,
            vendor_id=[0x0001, 0x1209],
            serial="TEST*",
            category=DeviceCategory.STORAGE,
            interface_class=0x08,
            confidence=Confidence.HIGH,
            composite=False,
            removable=True,
            fingerprint=FP_VALUE,
            time=OFFICE_HOURS,
        )
    )
    assert evaluate(policy_engine).explanation == (
        "vendor_id 0x1209 is listed",
        "serial 'test0001a7c3' matches 'TEST*'",
        "the fingerprint is listed",
        "the device declares category storage",
        "the device has an interface of class 0x08",
        "fingerprint confidence is high",
        "composite is false",
        "removable is true",
        "the time mon 10:00 is inside the window mon,tue,wed,thu,fri 09:00-17:00 (UTC+0000)",
    )


# --- hostile input --------------------------------------------------------------------


def test_an_enormous_device_string_is_cut_not_choked_on() -> None:
    worst_case = "a*" * MAX_PATTERN_WILDCARDS + "b"
    policy_engine = engine(
        rule("backtracker", DENY, product=worst_case),
        rule("prefix", READ_ONLY, product="aaa*"),
    )
    device = flash_drive(product="a" * 2_000_000, manufacturer="\x00" * 500_000)
    started = time.perf_counter()
    result = evaluate(policy_engine, device)
    elapsed = time.perf_counter() - started
    assert result.rule is not None and result.rule.id == "prefix"
    assert result.explanation == (f"product {'a' * 60 + '...'!r} matches 'aaa*'",)
    assert elapsed < 2.0


def test_only_the_first_part_of_an_oversized_string_is_matched() -> None:
    policy_engine = engine(rule("tail", DENY, product="*tail"))
    # The device model caps device text at the 126 characters a string descriptor holds.
    fits = "x" * (DEVICE_TEXT_LIMIT - 4) + "tail"
    too_long = "x" * (DEVICE_TEXT_LIMIT - 3) + "tail"
    assert evaluate(policy_engine, flash_drive(product=fits)).rule is not None
    assert evaluate(policy_engine, flash_drive(product=too_long)).rule is None

    # A backend that got past the model is still cut, at the engine's own limit.
    bypass = flash_drive()
    object.__setattr__(bypass, "product", "x" * (MAX_SUBJECT_LENGTH - 4) + "tail")
    assert evaluate(policy_engine, bypass).rule is not None
    object.__setattr__(bypass, "product", "x" * (MAX_SUBJECT_LENGTH - 3) + "tail")
    assert evaluate(policy_engine, bypass).rule is None


def test_a_policy_at_the_rule_limit_evaluates() -> None:
    rules = [
        rule(f"r{index}", DENY, vendor_id=0x0001, serial=f"NOPE{index}*")
        for index in range(MAX_RULES - 1)
    ]
    rules.append(rule("last", ALLOW, serial="TEST*"))
    policy_engine = PolicyEngine(Policy(rules=rules))
    started = time.perf_counter()
    result = evaluate(policy_engine)
    assert time.perf_counter() - started < 1.0
    assert result.rule is not None and result.rule.id == "last"


# --- time windows ---------------------------------------------------------------------


def test_a_time_window_rule_applies_inside_the_window_only() -> None:
    policy_engine = engine(rule("hours", ALLOW, vendor_id=0x1209, time=OFFICE_HOURS))

    inside = evaluate(policy_engine, now=NOW)
    assert inside.rule is not None and inside.action == ALLOW
    # The caller is told when the window closes, so it can re-evaluate then.
    assert inside.valid_until == dt.datetime(2026, 1, 5, 17, 0, tzinfo=UTC)

    evening = dt.datetime(2026, 1, 5, 17, 0, tzinfo=UTC)
    outside = evaluate(policy_engine, now=evening)
    assert outside.matched_default
    # ...and when it opens again.
    assert outside.valid_until == dt.datetime(2026, 1, 6, 9, 0, tzinfo=UTC)


def test_a_window_that_cannot_apply_to_this_device_does_not_shorten_validity() -> None:
    policy_engine = engine(
        rule("other-device", ALLOW, vendor_id=0x0001, time=OFFICE_HOURS),
        rule("mine", READ_ONLY, vendor_id=0x1209),
    )
    result = evaluate(policy_engine, now=NOW.replace(hour=20))
    assert result.action == READ_ONLY
    assert result.valid_until is None


def test_validity_ends_at_the_earliest_change() -> None:
    expiry = dt.datetime(2026, 1, 6, 12, 0, tzinfo=UTC)
    policy_engine = engine(
        rule("hours", ALLOW, vendor_id=0x1209, time=OFFICE_HOURS),
        rule("fallback", READ_ONLY, vendor_id=0x1209, expires=expiry),
    )
    night = dt.datetime(2026, 1, 5, 20, 0, tzinfo=UTC)
    result = evaluate(policy_engine, now=night)
    assert result.rule is not None and result.rule.id == "fallback"
    # The earlier rule's window opens (Tuesday 09:00) before the fallback expires.
    assert result.valid_until == dt.datetime(2026, 1, 6, 9, 0, tzinfo=UTC)

    sooner = dt.datetime(2026, 1, 5, 22, 0, tzinfo=UTC)
    policy_engine = engine(
        rule("hours", ALLOW, vendor_id=0x1209, time=OFFICE_HOURS),
        rule("fallback", READ_ONLY, vendor_id=0x1209, expires=sooner),
    )
    assert evaluate(policy_engine, now=night).valid_until == sooner


def test_a_window_is_read_in_its_own_utc_offset() -> None:
    tokyo_hours = TimeWindow(
        days=(0,), start=dt.time(9, 0), end=dt.time(17, 0), utc_offset_minutes=540
    )
    policy_engine = engine(rule("tokyo", ALLOW, vendor_id=0x1209, time=tokyo_hours))
    # 01:00 UTC on Monday is 10:00 in Tokyo; 10:00 UTC is 19:00 there.
    assert evaluate(policy_engine, now=NOW.replace(hour=1)).rule is not None
    assert evaluate(policy_engine, now=NOW).rule is None


def test_the_evaluation_time_may_be_given_in_any_zone() -> None:
    policy_engine = engine(rule("hours", ALLOW, vendor_id=0x1209, time=OFFICE_HOURS))
    new_york = dt.timezone(dt.timedelta(hours=-5))
    same_instant = NOW.astimezone(new_york)
    assert evaluate(policy_engine, now=same_instant) == evaluate(policy_engine, now=NOW)


def test_a_naive_time_is_refused() -> None:
    policy_engine = engine(rule("any", ALLOW, vendor_id=0x1209))
    with pytest.raises(ValueError, match="timezone-aware"):
        policy_engine.evaluate(flash_drive(), HIGH, now=dt.datetime(2026, 1, 5, 10, 0))
    with pytest.raises(ValueError, match="timezone-aware"):
        policy_engine.explain(flash_drive(), HIGH, now=dt.datetime(2026, 1, 5, 10, 0))


# --- purity ---------------------------------------------------------------------------


def test_evaluation_is_deterministic_and_leaves_the_policy_alone() -> None:
    policy = Policy(
        rules=(
            rule("hours", ALLOW, vendor_id=0x1209, time=OFFICE_HOURS),
            rule("fallback", READ_ONLY, serial="TEST*"),
        )
    )
    snapshot = dataclasses.replace(policy)
    policy_engine = PolicyEngine(policy)
    first = evaluate(policy_engine)
    assert all(evaluate(policy_engine) == first for _ in range(5))
    assert PolicyEngine(policy).evaluate(flash_drive(), HIGH, now=NOW) == first
    assert policy_engine.policy is policy and policy == snapshot


def test_one_engine_can_be_shared_between_threads() -> None:
    policy_engine = engine(
        rule("deny-badusb", DENY, storage_with_input=True),
        rule("hours", ALLOW, vendor_id=0x1209, serial="TEST*", time=OFFICE_HOURS),
    )
    expected = [evaluate(policy_engine, device) for device in ALL_DEVICES]
    failures: list[str] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait(timeout=5)
        for _ in range(20):
            got = [evaluate(policy_engine, device) for device in ALL_DEVICES]
            if got != expected:
                failures.append("a concurrent evaluation gave a different result")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not failures and not any(thread.is_alive() for thread in threads)


def test_an_engine_needs_a_policy() -> None:
    with pytest.raises(TypeError):
        PolicyEngine({"version": 1})  # type: ignore[arg-type]


# --- explain --------------------------------------------------------------------------


def test_explain_reports_every_rule() -> None:
    expiry = dt.datetime(2026, 1, 1, tzinfo=UTC)
    policy_engine = engine(
        rule("off", DENY, vendor_id=0x1209, enabled=False),
        rule("off-and-different", DENY, vendor_id=0x0001, enabled=False),
        rule("old", DENY, vendor_id=0x1209, expires=expiry),
        rule("elsewhere", DENY, vendor_id=0x1209, product_id=0x0009, serial="TEST*"),
        rule("winner", READ_ONLY, vendor_id=0x1209, serial="TEST*"),
        rule("too-late", ALLOW, category=DeviceCategory.STORAGE),
    )
    traces = policy_engine.explain(flash_drive(), HIGH, now=NOW)
    assert [(trace.rule_id, trace.outcome, trace.would_match) for trace in traces] == [
        ("off", RuleOutcome.DISABLED, True),
        ("off-and-different", RuleOutcome.DISABLED, False),
        ("old", RuleOutcome.EXPIRED, True),
        ("elsewhere", RuleOutcome.NO_MATCH, False),
        ("winner", RuleOutcome.MATCHED, True),
        ("too-late", RuleOutcome.SHADOWED, True),
    ]
    assert [trace.summary for trace in traces] == [
        "disabled; it would match otherwise",
        "disabled",
        "expired at 2026-01-01T00:00:00.000000Z; it would match otherwise",
        "does not match: product_id 0x0001 is not one of 0x0009",
        "matches and decides: read_only",
        "matches, but rule 'winner' comes first",
    ]
    # Unlike evaluate, the trace does not stop at the first failing criterion.
    elsewhere = traces[3]
    assert [(item.criterion, item.matched) for item in elsewhere.criteria] == [
        ("vendor_id", True),
        ("product_id", False),
        ("serial", True),
    ]
    assert traces[4].action == READ_ONLY


def test_explain_says_why_a_criterion_failed() -> None:
    policy_engine = engine(
        rule(
            "picky",
            ALLOW,
            vendor_id=list(range(1, 9)),
            serial=["A*", "B*"],
            manufacturer="*",
            category=[DeviceCategory.HUB, DeviceCategory.MOUSE],
            interface_class=[0x03, 0x09],
            confidence=Confidence.HIGH,
            composite=True,
            removable=True,
            fingerprint=FP_VALUE,
            time=OFFICE_HOURS,
        )
    )
    device = make_device(manufacturer=None, removable=None)
    (trace,) = policy_engine.explain(device, LOW, now=NOW.replace(hour=18))
    assert trace.outcome is RuleOutcome.NO_MATCH and not trace.would_match
    assert {item.criterion: item.detail for item in trace.criteria} == {
        "vendor_id": (
            "vendor_id 0x1209 is not one of 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006"
            " and 2 more"
        ),
        "serial": "serial 'test0001a7c3' matches none of 'A*', 'B*'",
        "fingerprint": "the fingerprint is not listed",
        "manufacturer": "the device reports no manufacturer, so no pattern can match",
        "category": "the device's categories (storage) include none of hub, mouse",
        "interface_class": "the device's interface classes (0x08) include none of 0x03, 0x09",
        "confidence": "fingerprint confidence is low, not high",
        "composite": "composite is false, not true",
        "removable": "the platform does not report removable, so it matches neither value",
        "time": (
            "the time mon 18:00 is outside the window mon,tue,wed,thu,fri 09:00-17:00 (UTC+0000)"
        ),
    }
    assert all(not item.matched for item in trace.criteria)


def test_explain_and_evaluate_always_agree_on_the_winner() -> None:
    policy_engine = engine(
        rule("deny-badusb", DENY, storage_with_input=True),
        rule("off", ALLOW, category=DeviceCategory.STORAGE, enabled=False),
        rule("hubs", ALLOW, category=DeviceCategory.HUB, removable=True),
        rule("serials", READ_ONLY, serial="TEST*", confidence=Confidence.HIGH),
        rule("hours", ALLOW, interface_class=[0x03, 0x06], time=OFFICE_HOURS),
        rule("internal", ALLOW, removable=False),
    )
    winners: set[str | None] = set()
    for device in ALL_DEVICES:
        for fingerprint in (HIGH, LOW):
            for moment in (NOW, NOW.replace(hour=23)):
                result = policy_engine.evaluate(device, fingerprint, now=moment)
                traces = policy_engine.explain(device, fingerprint, now=moment)
                matched = [
                    trace.rule_id for trace in traces if trace.outcome is RuleOutcome.MATCHED
                ]
                expected = [result.rule.id] if result.rule is not None else []
                assert matched == expected
                assert len(traces) == len(policy_engine.policy.rules)
                winners.add(result.rule.id if result.rule is not None else None)
    # The matrix really does exercise every live rule and the default.
    assert winners == {"deny-badusb", "hubs", "serials", "hours", "internal", None}


# --- the shipped policies -------------------------------------------------------------


def test_the_default_policy_has_one_rule_and_allows_nothing() -> None:
    assert DEFAULT_POLICY.default.access is Access.PENDING
    assert [(item.id, item.enabled) for item in DEFAULT_POLICY.rules] == [
        ("deny-input-with-other", True)
    ]
    only = DEFAULT_POLICY.rules[0]
    assert only.match == Match(mixes_input_with_other=True)
    assert only.action == RuleAction(Access.DENY, alert=True)
    assert only.expires is None

    policy_engine = PolicyEngine(DEFAULT_POLICY)
    for device in ALL_DEVICES:
        for fingerprint in (HIGH, LOW):
            result = policy_engine.evaluate(device, fingerprint, now=NOW)
            assert result.action.access in (Access.PENDING, Access.DENY)


def test_the_default_policy_denies_input_beside_any_other_function_and_alerts() -> None:
    policy_engine = PolicyEngine(DEFAULT_POLICY)
    for device in (
        storage_with_keyboard(),
        make_device(interfaces=(MASS_STORAGE, GENERIC_HID)),
        make_device(interfaces=(BOOT_KEYBOARD, MASS_STORAGE), serial=None),
        # Not only storage: a keyboard that is also a network adapter or a serial port.
        make_device(interfaces=(BOOT_KEYBOARD, UsbInterface(0x02, 0x06, 0x00))),
        make_device(interfaces=(GENERIC_HID, CDC_ACM)),
        make_device(interfaces=(BOOT_MOUSE, UsbInterface(0xFF, 0x00, 0x00), HUB)),
        make_device(interfaces=(BOOT_KEYBOARD, MTP)),
    ):
        result = policy_engine.evaluate(device, HIGH, now=NOW)
        assert result.rule is not None and result.rule.id == "deny-input-with-other"
        assert result.action.access is Access.DENY and result.action.alert is True

    # Input devices alone, with or without a hub, and storage alone wait for a decision.
    for device in (
        flash_drive(),
        keyboard(),
        mouse(),
        hub(),
        phone(),
        make_device(interfaces=(BOOT_KEYBOARD, BOOT_MOUSE, HUB)),
    ):
        result = policy_engine.evaluate(device, HIGH, now=NOW)
        assert result.matched_default
        assert result.action == RuleAction(Access.PENDING, scan=ScanRequirement.ON_MOUNT)


def test_the_example_policy_unedited_behaves_like_the_default_policy() -> None:
    enabled = [item.id for item in EXAMPLE_POLICY.rules if item.enabled]
    assert enabled == ["deny-input-with-other"]
    assert len(EXAMPLE_POLICY.rules) == 5
    assert all("EXAMPLE, disabled." in item.description for item in EXAMPLE_POLICY.rules[1:])

    default_engine, example_engine = PolicyEngine(DEFAULT_POLICY), PolicyEngine(EXAMPLE_POLICY)
    for device in ALL_DEVICES:
        for fingerprint in (HIGH, LOW):
            default = default_engine.evaluate(device, fingerprint, now=NOW)
            example = example_engine.evaluate(device, fingerprint, now=NOW)
            assert example.action == default.action
            assert example.rule == default.rule


def test_the_example_rules_do_what_their_descriptions_say_once_enabled() -> None:
    enabled = dataclasses.replace(
        EXAMPLE_POLICY,
        rules=tuple(dataclasses.replace(item, enabled=True) for item in EXAMPLE_POLICY.rules),
    )
    policy_engine = PolicyEngine(enabled)

    def outcome(
        device: UsbDevice, fingerprint: Fingerprint = HIGH, now: dt.datetime = NOW
    ) -> tuple[str | None, RuleAction]:
        result = policy_engine.evaluate(device, fingerprint, now=now)
        return (result.rule.id if result.rule is not None else None, result.action)

    on_mount, required = ScanRequirement.ON_MOUNT, ScanRequirement.REQUIRED
    assert outcome(storage_with_keyboard()) == (
        "deny-input-with-other",
        RuleAction(Access.DENY, alert=True),
    )
    assert outcome(flash_drive(product_id=0x0005)) == (
        "example-deny-product",
        RuleAction(Access.DENY, alert=True),
    )
    # Monday 10:00: the working-hours rule. Monday 18:00: the vendor rule behind it.
    assert outcome(flash_drive()) == (
        "example-allow-working-hours",
        RuleAction(Access.ALLOW, scan=on_mount),
    )
    assert outcome(flash_drive(), now=NOW.replace(hour=18)) == (
        "example-trust-vendor-read-only",
        RuleAction(Access.READ_ONLY, scan=on_mount),
    )
    # Without a unique serial the vendor is not trusted; the device waits for a grant.
    assert outcome(flash_drive(serial=None), LOW) == (
        "example-require-scan",
        RuleAction(Access.PENDING, scan=required),
    )
    assert outcome(flash_drive(vendor_id=0x0001)) == (
        "example-require-scan",
        RuleAction(Access.PENDING, scan=required),
    )
    # Phones and cameras carry files too: storage_like covers them.
    assert outcome(phone(vendor_id=0x0001)) == (
        "example-require-scan",
        RuleAction(Access.PENDING, scan=required),
    )
    assert outcome(keyboard()) == (None, RuleAction(Access.PENDING, scan=on_mount))
