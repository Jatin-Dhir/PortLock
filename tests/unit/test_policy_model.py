"""The policy model: validation, limits, glob semantics and time windows."""

from __future__ import annotations

import datetime as dt
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from portlock.core.models import Access, Confidence, DeviceCategory, ScanRequirement
from portlock.policy.model import (
    ALL_DAYS,
    MAX_DESCRIPTION_LENGTH,
    MAX_ID_LENGTH,
    MAX_LIST_ITEMS,
    MAX_NAME_LENGTH,
    MAX_PATTERN_LENGTH,
    MAX_PATTERN_WILDCARDS,
    MAX_RULES,
    DetectionAction,
    IncompleteAction,
    Match,
    Policy,
    Rule,
    RuleAction,
    ScanPolicy,
    TimeWindow,
    check_bus_path,
    check_fingerprint,
    check_glob,
    compile_glob,
    normalize_text,
    split_bus_path,
)

UTC = dt.UTC
DENY = RuleAction(Access.DENY)
FINGERPRINT = "plk1:abcdefghijklmnopqrstuvwxyz234567"

ZERO_WIDTH_SPACE = chr(0x200B)
FULLWIDTH_ASTERISK = chr(0xFF0A)
FULLWIDTH_A = chr(0xFF21)
NO_BREAK_SPACE = chr(0xA0)
LONE_SURROGATE = chr(0xD800)


def at(day: int, hour: int, minute: int = 0, *, offset_minutes: int = 0) -> dt.datetime:
    """A moment in January 2026; the 5th is a Monday, so ``day=5`` is Monday."""
    zone = dt.timezone(dt.timedelta(minutes=offset_minutes))
    return dt.datetime(2026, 1, day, hour, minute, tzinfo=zone)


def rule(rule_id: str = "r1", **overrides: Any) -> Rule:
    fields: dict[str, Any] = {"id": rule_id, "match": Match(vendor_id=0x1209), "action": DENY}
    fields.update(overrides)
    return Rule(**fields)


# --- actions --------------------------------------------------------------------------


def test_an_action_defaults_to_no_scan_and_no_alert() -> None:
    action = RuleAction(Access.READ_ONLY)
    assert action.scan is ScanRequirement.NONE
    assert action.alert is False


@pytest.mark.parametrize(
    "arguments",
    [
        {"access": "deny"},
        {"access": Access.DENY, "scan": "none"},
        {"access": Access.DENY, "alert": 1},
        {"access": None},
    ],
)
def test_an_action_refuses_values_of_the_wrong_type(arguments: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        RuleAction(**arguments)


def test_scan_policy_defaults_to_the_protective_choice() -> None:
    assert ScanPolicy().on_detection is DetectionAction.DENY
    # A required scan that does not finish leaves the device read-only (DESIGN 14.9).
    assert ScanPolicy().on_incomplete is IncompleteAction.READ_ONLY
    assert ScanPolicy(on_incomplete=IncompleteAction.DENY).on_incomplete is IncompleteAction.DENY
    with pytest.raises(ValueError, match="on_detection"):
        ScanPolicy("deny")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="on_incomplete"):
        ScanPolicy(on_incomplete="deny")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="on_incomplete"):
        # An alert alone is not one of the choices: an unfinished required scan must
        # never end with the decided access.
        ScanPolicy(on_incomplete=DetectionAction.ALERT)  # type: ignore[arg-type]


# --- text normalization and globs -----------------------------------------------------


def test_normalization_folds_case_width_whitespace_and_invisible_characters() -> None:
    disguised = f"  Ex{ZERO_WIDTH_SPACE}ample{NO_BREAK_SPACE}\t CORP {FULLWIDTH_A}\x00"
    assert normalize_text(disguised) == "example corp a"
    assert normalize_text("Stra\N{LATIN SMALL LETTER SHARP S}e") == "strasse"
    assert normalize_text(" \t ") == ""


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("example*", "example flash 16gb", True),
        ("example*", "an example", False),
        ("*flash*", "example flash 16gb", True),
        ("*", "", True),
        ("test????", "test0001", True),
        ("test????", "test001", False),
        ("test????", "test00012", False),
        ("usb[12]", "usb1", True),
        ("usb[12]", "usb3", False),
        ("usb[0-9]", "usb7", True),
        ("usb[!0-9]", "usb7", False),
        ("usb[!0-9]", "usbx", True),
        ("a[*]b", "a*b", True),
        ("a[*]b", "axb", False),
        ("a[?]b", "a?b", True),
        ("a[?]b", "axb", False),
        ("plain", "plain", True),
        ("plain", "plainer", False),
        ("plain", "explain", False),
        ("EXAMPLE Corp", "example corp", True),
        ("a.b", "axb", False),
        ("a+b", "a+b", True),
        ("a/b", "a\\b", False),
        ("a\\b", "a\\b", True),
        ("[z-a]", "m", False),
        ("[abc", "[abc", True),
    ],
)
def test_glob_semantics_are_those_of_fnmatch(pattern: str, value: str, expected: bool) -> None:
    assert bool(compile_glob(pattern).match(value)) is expected


def test_a_pattern_is_normalized_like_the_text_it_is_compared_with() -> None:
    expression = compile_glob(f"  Ex{ZERO_WIDTH_SPACE}AMPLE   Corp{FULLWIDTH_ASTERISK} ")
    assert expression.match(normalize_text("example corp ltd"))
    assert not expression.match(normalize_text("sample corp"))


def test_check_glob_returns_the_pattern_trimmed() -> None:
    assert check_glob("  Example*  ") == "Example*"


@pytest.mark.parametrize(
    ("pattern", "fragment"),
    [
        (17, "must be a string"),
        (None, "must be a string"),
        ("", "must not be empty"),
        ("   ", "must not be empty"),
        (ZERO_WIDTH_SPACE, "must not be empty"),
        ("a" * (MAX_PATTERN_LENGTH + 1), "too long (129 characters; the limit is 128)"),
        ("bad\x00byte", "control characters"),
        ("new\nline", "control characters"),
        (LONE_SURROGATE, "control characters"),
        ("*" * (MAX_PATTERN_WILDCARDS + 1), "too many wildcards (17; the limit is 16)"),
        ("?[" * 9, "too many wildcards (18; the limit is 16)"),
        (FULLWIDTH_ASTERISK * 17, "too many wildcards (17; the limit is 16)"),
        # U+FDFA is one character that compatibility folding expands to eighteen.
        (chr(0xFDFA) * 8, "too long once normalized"),
    ],
)
def test_check_glob_rejects(pattern: Any, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment.replace("(", r"\(").replace(")", r"\)")):
        check_glob(pattern)


def test_a_pattern_at_the_limits_is_accepted() -> None:
    longest = "a" * MAX_PATTERN_LENGTH
    assert check_glob(longest) == longest
    busiest = "a*" * MAX_PATTERN_WILDCARDS
    assert check_glob(busiest) == busiest


def test_fingerprints_are_exact_values_in_one_spelling() -> None:
    assert check_fingerprint(FINGERPRINT) == FINGERPRINT
    assert check_fingerprint(FINGERPRINT.upper()) == FINGERPRINT
    assert check_fingerprint("plk1:" + "A" * 32) == "plk1:" + "a" * 32


@pytest.mark.parametrize(
    "value",
    [
        "plk1:*",
        "plk1:" + "A" * 31,
        "plk1:" + "A" * 33,
        "plk1:" + "A" * 31 + "1",
        "plk2:" + "A" * 32,
        "A" * 32,
        FINGERPRINT + "\n",
        "",
        None,
        12,
    ],
)
def test_malformed_fingerprints_are_rejected(value: Any) -> None:
    with pytest.raises(ValueError, match="32 base32 characters"):
        check_fingerprint(value)


# --- time windows ---------------------------------------------------------------------

OFFICE_HOURS = TimeWindow(days=(0, 1, 2, 3, 4), start=dt.time(9, 0), end=dt.time(17, 0))
FRIDAY_NIGHT = TimeWindow(days=(4,), start=dt.time(22, 0), end=dt.time(6, 0))
SATURDAY = TimeWindow(days=(5,))
FULL_DAY_FROM_NOON = TimeWindow(days=(2,), start=dt.time(12, 0), end=dt.time(12, 0))
EVERY_NIGHT = TimeWindow(start=dt.time(20, 0), end=dt.time(4, 0))
INDIA = TimeWindow(days=(0,), start=dt.time(9, 0), end=dt.time(10, 0), utc_offset_minutes=330)


@pytest.mark.parametrize(
    ("window", "moment", "expected"),
    [
        (OFFICE_HOURS, at(5, 8, 59), False),
        (OFFICE_HOURS, at(5, 9, 0), True),
        (OFFICE_HOURS, at(5, 16, 59), True),
        (OFFICE_HOURS, at(5, 17, 0), False),
        (OFFICE_HOURS, at(9, 12, 0), True),
        (OFFICE_HOURS, at(10, 12, 0), False),
        (OFFICE_HOURS, at(11, 12, 0), False),
        # 22:00 Friday (the 9th) until 06:00 Saturday, and no other night.
        (FRIDAY_NIGHT, at(9, 21, 59), False),
        (FRIDAY_NIGHT, at(9, 22, 0), True),
        (FRIDAY_NIGHT, at(10, 0, 0), True),
        (FRIDAY_NIGHT, at(10, 5, 59), True),
        (FRIDAY_NIGHT, at(10, 6, 0), False),
        (FRIDAY_NIGHT, at(9, 3, 0), False),
        (FRIDAY_NIGHT, at(10, 23, 0), False),
        (FRIDAY_NIGHT, at(11, 3, 0), False),
        (SATURDAY, at(9, 23, 59), False),
        (SATURDAY, at(10, 0, 0), True),
        (SATURDAY, at(10, 23, 59), True),
        (SATURDAY, at(11, 0, 0), False),
        # Equal start and end: 24 hours from Wednesday (the 7th) noon.
        (FULL_DAY_FROM_NOON, at(7, 11, 59), False),
        (FULL_DAY_FROM_NOON, at(7, 12, 0), True),
        (FULL_DAY_FROM_NOON, at(8, 11, 59), True),
        (FULL_DAY_FROM_NOON, at(8, 12, 0), False),
        (EVERY_NIGHT, at(6, 19, 59), False),
        (EVERY_NIGHT, at(6, 20, 0), True),
        (EVERY_NIGHT, at(7, 3, 59), True),
        (EVERY_NIGHT, at(7, 4, 0), False),
        # 09:00 to 10:00 on Monday at UTC+05:30 is 03:30 to 04:30 UTC.
        (INDIA, at(5, 3, 29), False),
        (INDIA, at(5, 3, 30), True),
        (INDIA, at(5, 4, 29), True),
        (INDIA, at(5, 4, 30), False),
        (INDIA, at(5, 9, 30), False),
        (INDIA, at(5, 9, 30, offset_minutes=330), True),
    ],
)
def test_a_window_contains(window: TimeWindow, moment: dt.datetime, expected: bool) -> None:
    assert window.contains(moment) is expected


def test_the_day_is_the_local_day_not_the_utc_day() -> None:
    # 02:00 on Tuesday at UTC+05:30 is still 20:30 on Monday in UTC.
    tuesday_morning_in_india = TimeWindow(
        days=(1,), start=dt.time(1, 0), end=dt.time(3, 0), utc_offset_minutes=330
    )
    assert tuesday_morning_in_india.contains(at(5, 20, 30))
    # The same UTC time a day later is Wednesday locally, a day earlier Monday.
    assert not tuesday_morning_in_india.contains(at(6, 20, 30))
    assert not tuesday_morning_in_india.contains(at(4, 20, 30))


@pytest.mark.parametrize(
    ("window", "moment", "expected"),
    [
        (OFFICE_HOURS, at(5, 10, 0), at(5, 17, 0)),
        (OFFICE_HOURS, at(5, 8, 0), at(5, 9, 0)),
        (OFFICE_HOURS, at(5, 9, 0), at(5, 17, 0)),
        (OFFICE_HOURS, at(5, 17, 0), at(6, 9, 0)),
        # Friday evening: closed until Monday morning.
        (OFFICE_HOURS, at(9, 18, 0), at(12, 9, 0)),
        (FRIDAY_NIGHT, at(9, 23, 0), at(10, 6, 0)),
        (FRIDAY_NIGHT, at(10, 7, 0), at(16, 22, 0)),
        (SATURDAY, at(10, 12, 0), at(11, 0, 0)),
        (FULL_DAY_FROM_NOON, at(7, 13, 0), at(8, 12, 0)),
        # Open every night: midnight is not a boundary, 04:00 is.
        (EVERY_NIGHT, at(6, 23, 0), at(7, 4, 0)),
        (INDIA, at(5, 0, 0), at(5, 3, 30)),
        (INDIA, at(5, 4, 0), at(5, 4, 30)),
    ],
)
def test_next_change_is_the_next_opening_or_closing(
    window: TimeWindow, moment: dt.datetime, expected: dt.datetime
) -> None:
    change = window.next_change(moment)
    assert change == expected
    assert change.utcoffset() == dt.timedelta(0)


@pytest.mark.parametrize(
    "window", [OFFICE_HOURS, FRIDAY_NIGHT, SATURDAY, FULL_DAY_FROM_NOON, EVERY_NIGHT, INDIA]
)
def test_next_change_never_skips_or_invents_a_change(window: TimeWindow) -> None:
    moment = dt.datetime(2026, 1, 4, 0, 0, 30, tzinfo=UTC)
    minute = dt.timedelta(minutes=1)
    for _step in range(280):
        state = window.contains(moment)
        change = window.next_change(moment)
        assert change > moment
        assert change - moment <= dt.timedelta(days=7)
        assert window.contains(change) is not state
        assert window.contains(change - minute) is state or change - minute < moment
        # Half-way to the reported change the state must still be the old one.
        assert window.contains(moment + (change - moment) / 2) is state
        moment += dt.timedelta(minutes=37)


def test_days_are_sorted_and_deduplicated() -> None:
    assert TimeWindow(days=[4, 0, 4, 2]).days == (0, 2, 4)
    assert TimeWindow(days=3).days == (3,)  # type: ignore[arg-type]
    assert TimeWindow(start=dt.time(1, 0), end=dt.time(2, 0)).days == ALL_DAYS


@pytest.mark.parametrize(
    ("arguments", "fragment"),
    [
        ({"days": ()}, "at least one day"),
        ({"days": (7,)}, "weekday numbers"),
        ({"days": (-1,)}, "weekday numbers"),
        ({"days": (True,)}, "weekday numbers"),
        ({"days": ("mon",)}, "weekday numbers"),
        ({"days": (1,), "start": "09:00"}, "start must be a time of day"),
        ({"days": (1,), "end": dt.time(9, 0, 30)}, "end must be a whole minute"),
        ({"days": (1,), "start": dt.time(9, 0, tzinfo=UTC)}, "without a time zone"),
        ({"days": (1,), "utc_offset_minutes": 841}, "utc_offset_minutes"),
        ({"days": (1,), "utc_offset_minutes": -721}, "utc_offset_minutes"),
        ({"days": (1,), "utc_offset_minutes": 60.0}, "utc_offset_minutes"),
        ({"days": (1,), "utc_offset_minutes": True}, "utc_offset_minutes"),
        ({}, "always matches"),
        ({"days": ALL_DAYS, "start": dt.time(8, 0), "end": dt.time(8, 0)}, "always matches"),
    ],
)
def test_time_window_validation(arguments: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        TimeWindow(**arguments)


def test_the_extreme_utc_offsets_are_accepted() -> None:
    assert TimeWindow(days=(0,), utc_offset_minutes=-720).utc_offset_minutes == -720
    assert TimeWindow(days=(0,), utc_offset_minutes=840).tzinfo.utcoffset(None) == dt.timedelta(
        hours=14
    )


def test_a_window_refuses_a_naive_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        OFFICE_HOURS.contains(dt.datetime(2026, 1, 5, 10, 0))
    with pytest.raises(ValueError, match="timezone-aware"):
        OFFICE_HOURS.next_change(dt.datetime(2026, 1, 5, 10, 0))


# --- match ----------------------------------------------------------------------------


def test_a_single_value_is_accepted_wherever_a_list_is() -> None:
    match = Match(
        vendor_id=0x1209,
        product_id=[1, 2],
        serial="TEST*",
        fingerprint=FINGERPRINT.upper(),
        category=DeviceCategory.STORAGE,
        interface_class=(0x08, 0x06),
    )
    assert match.vendor_id == (0x1209,)
    assert match.product_id == (1, 2)
    assert match.serial == ("TEST*",)
    assert match.fingerprint == (FINGERPRINT,)
    assert match.category == (DeviceCategory.STORAGE,)
    assert match.interface_class == (0x08, 0x06)


def test_criteria_lists_what_is_present_in_document_order() -> None:
    match = Match(
        time=OFFICE_HOURS, removable=False, vendor_id=1, confidence=Confidence.LOW, serial="x"
    )
    assert match.criteria == ("vendor_id", "serial", "confidence", "removable", "time")
    assert not match.is_empty
    assert Match().is_empty and Match().criteria == ()
    # False is a criterion, not an absent one.
    assert Match(composite=False).criteria == ("composite",)


@pytest.mark.parametrize(
    ("arguments", "fragment"),
    [
        ({"vendor_id": ()}, "vendor_id: an empty list can never match"),
        ({"serial": []}, "serial: an empty list can never match"),
        ({"vendor_id": 0x10000}, "vendor_id: a vendor or product id must be an integer"),
        ({"vendor_id": -1}, "vendor_id: a vendor or product id"),
        ({"vendor_id": True}, "vendor_id: a vendor or product id"),
        ({"vendor_id": "0x1209"}, "vendor_id: a vendor or product id"),
        ({"product_id": 1.0}, "product_id: a vendor or product id"),
        ({"interface_class": 0x100}, "interface_class: an interface class"),
        ({"product_id": range(MAX_LIST_ITEMS + 1)}, "product_id: too many values"),
        ({"serial": ["ok", ""]}, "serial: a pattern must not be empty"),
        ({"manufacturer": "*" * 17}, "manufacturer: a pattern has too many wildcards"),
        ({"product": "x" * 129}, "product: a pattern is too long"),
        ({"bus_path": 12}, "bus_path: a pattern must be a string"),
        ({"fingerprint": "plk1:*"}, "fingerprint: a fingerprint is"),
        ({"category": "storage"}, "category: a category must be a DeviceCategory"),
        ({"confidence": "high"}, "confidence must be a Confidence"),
        ({"composite": 1}, "composite must be true or false"),
        ({"storage_with_input": "yes"}, "storage_with_input must be true or false"),
        ({"mixes_input_with_other": 1}, "mixes_input_with_other must be true or false"),
        ({"storage_like": None, "removable": "no"}, "removable must be true or false"),
        ({"storage_like": "true"}, "storage_like must be true or false"),
        ({"bus_path": "1-2."}, "bus_path: a bus path pattern must not start or end"),
        ({"bus_path": ["1-2", ".1-2"]}, "bus_path: a bus path pattern must not start or end"),
        ({"bus_path": "USB(1)##USB(2)"}, "bus_path: a bus path pattern must not start or end"),
        ({"bus_path": "1-2. .3"}, "bus_path: a bus path pattern must not start or end"),
        ({"removable": 0}, "removable must be true or false"),
        ({"time": {"days": ["mon"]}}, "time must be a TimeWindow"),
    ],
)
def test_match_validation(arguments: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        Match(**arguments)


def test_bus_paths_split_into_segments() -> None:
    assert split_bus_path("1-2.3.4") == ("1-2", "3", "4")
    assert split_bus_path("PCIROOT(0)#USBROOT(0)#USB(2)") == ("PCIROOT(0)", "USBROOT(0)", "USB(2)")
    assert split_bus_path("1-2") == ("1-2",)
    assert check_bus_path(" 1-2.* ") == "1-2.*"
    match = Match(bus_path=["1-2", "1-*.4"], mixes_input_with_other=True, storage_like=False)
    assert match.criteria == ("mixes_input_with_other", "storage_like", "bus_path")


def test_a_list_at_the_limit_is_accepted() -> None:
    match = Match(product_id=range(MAX_LIST_ITEMS))
    assert match.product_id is not None and len(match.product_id) == MAX_LIST_ITEMS


def test_matches_are_immutable_values() -> None:
    match = Match(vendor_id=[0x1209], serial=["TEST*"])
    with pytest.raises(FrozenInstanceError):
        match.vendor_id = (1,)  # type: ignore[misc]
    assert match == Match(vendor_id=0x1209, serial="TEST*")
    assert len({match, Match(vendor_id=0x1209, serial="TEST*")}) == 1


# --- rule -----------------------------------------------------------------------------


def test_rule_defaults() -> None:
    made = rule()
    assert made.enabled is True
    assert made.description == ""
    assert made.expires is None


def test_a_rule_with_an_empty_match_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one match criterion"):
        Rule(id="everything", match=Match(), action=RuleAction(Access.ALLOW))


@pytest.mark.parametrize("rule_id", ["a", "A1", "deny-vendor.2_x", "0day", "x" * MAX_ID_LENGTH])
def test_well_formed_rule_ids(rule_id: str) -> None:
    assert rule(rule_id).id == rule_id


@pytest.mark.parametrize(
    "rule_id",
    ["", " ", "-lead", ".lead", "has space", "tab\t", "semi;colon", "x" * 65, "caf\xe9", 7, None],
)
def test_malformed_rule_ids_are_rejected(rule_id: Any) -> None:
    with pytest.raises(ValueError, match="a rule id"):
        rule(rule_id)


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"description": "x" * (MAX_DESCRIPTION_LENGTH + 1)}, "a description is too long"),
        ({"description": "line\nbreak"}, "control characters"),
        ({"description": None}, "a description must be a string"),
        ({"enabled": "yes"}, "enabled must be true or false"),
        ({"expires": dt.datetime(2026, 6, 1)}, "expires must be a timezone-aware datetime"),
        ({"expires": "2026-06-01T00:00:00Z"}, "expires must be a timezone-aware datetime"),
        ({"match": {"vendor_id": 1}}, "match must be a Match"),
        ({"action": Access.DENY}, "action must be a RuleAction"),
    ],
)
def test_rule_validation(overrides: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        rule(**overrides)


def test_expiry_is_kept_in_utc_and_is_reached_at_the_instant_itself() -> None:
    zone = dt.timezone(dt.timedelta(hours=2))
    made = rule(expires=dt.datetime(2026, 6, 1, 14, 0, tzinfo=zone))
    expiry = dt.datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    assert made.expires == expiry
    assert made.expires is not None and made.expires.utcoffset() == dt.timedelta(0)
    assert not made.is_expired(expiry - dt.timedelta(microseconds=1))
    assert made.is_expired(expiry)
    assert made.is_expired(expiry + dt.timedelta(days=1))
    assert not rule().is_expired(expiry)


# --- policy ---------------------------------------------------------------------------


def test_an_empty_policy_is_the_restrictive_one() -> None:
    policy = Policy()
    assert policy.version == 1
    assert policy.default == RuleAction(Access.PENDING)
    assert policy.rules == ()
    assert policy.scan == ScanPolicy(DetectionAction.DENY)


def test_rules_are_frozen_to_a_tuple_and_found_by_id() -> None:
    first, second = rule("first"), rule("Second")
    policy = Policy(rules=[first, second])
    assert policy.rules == (first, second)
    assert policy.rule("first") is first
    assert policy.rule("SECOND") is second
    assert policy.rule("third") is None
    assert len({policy, Policy(rules=(first, second))}) == 1


@pytest.mark.parametrize("version", [0, 2, True, "1", 1.0, None])
def test_only_version_one_is_understood(version: Any) -> None:
    with pytest.raises(ValueError, match="unsupported policy version"):
        Policy(version=version)


@pytest.mark.parametrize(
    ("arguments", "fragment"),
    [
        ({"name": "n" * (MAX_NAME_LENGTH + 1)}, "a policy name is too long"),
        ({"name": "bell\x07"}, "control characters"),
        ({"name": 5}, "a policy name must be a string"),
        ({"default": Access.ALLOW}, "default must be a RuleAction"),
        ({"scan": DetectionAction.DENY}, "scan must be a ScanPolicy"),
        ({"rules": ({"id": "x"},)}, "rules must be Rule values"),
    ],
)
def test_policy_validation(arguments: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        Policy(**arguments)


def test_rule_ids_must_be_unique_ignoring_case() -> None:
    with pytest.raises(ValueError, match="duplicate rule id 'same'"):
        Policy(rules=(rule("same"), rule("other"), rule("same")))
    with pytest.raises(ValueError, match="duplicate rule id 'BLOCK'"):
        Policy(rules=(rule("block"), rule("BLOCK")))


def test_the_number_of_rules_is_bounded() -> None:
    template = rule("r")
    action, match = template.action, template.match
    rules = [Rule(id=f"r{index}", match=match, action=action) for index in range(MAX_RULES + 1)]
    assert len(Policy(rules=rules[:MAX_RULES]).rules) == MAX_RULES
    with pytest.raises(ValueError, match="too many rules \\(2001; the limit is 2000\\)"):
        Policy(rules=rules)
