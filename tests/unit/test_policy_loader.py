"""Policy documents: validation with located problems, limits, files, output and hashing."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

import portlock.policy.loader as loader
from portlock.core.errors import PolicyError, PortLockError, StoreError
from portlock.core.models import Access, Confidence, DeviceCategory, ScanRequirement
from portlock.policy.defaults import DEFAULT_POLICY, EXAMPLE_POLICY
from portlock.policy.loader import (
    MAX_PROBLEMS,
    dump_policy_json,
    load_policy_file,
    parse_policy,
    policy_hash,
    policy_to_dict,
    save_policy,
)
from portlock.policy.model import (
    MAX_LIST_ITEMS,
    MAX_RULES,
    DetectionAction,
    IncompleteAction,
    Match,
    Policy,
    Rule,
    RuleAction,
    ScanPolicy,
    TimeWindow,
)

UTC = dt.UTC
FP_VALUE = "plk1:abcdefghijklmnopqrstuvwxyz234567"

#: What tests/fixtures/policies/office.json and office.toml both describe.
OFFICE_POLICY = Policy(
    name="Office policy",
    default=RuleAction(Access.PENDING, scan=ScanRequirement.ON_MOUNT),
    rules=(
        Rule(
            id="deny-badusb",
            description="Storage with an input interface.",
            match=Match(storage_with_input=True),
            action=RuleAction(Access.DENY, alert=True),
        ),
        Rule(
            id="deny-vendors",
            match=Match(vendor_id=(0x1209, 0x1234), product_id=0x0005),
            action=RuleAction(Access.DENY),
        ),
        Rule(
            id="office-hours",
            expires=dt.datetime(2027, 1, 1, tzinfo=UTC),
            match=Match(
                manufacturer="Example Corp*",
                serial=("TEST????A7C3", "TEST0002*"),
                category=DeviceCategory.STORAGE,
                interface_class=0x08,
                confidence=Confidence.HIGH,
                composite=False,
                removable=True,
                bus_path=("1-1", "1-1.*"),
                time=TimeWindow(
                    days=(0, 1, 2, 3, 4),
                    start=dt.time(9, 0),
                    end=dt.time(17, 30),
                    utc_offset_minutes=60,
                ),
            ),
            action=RuleAction(Access.ALLOW, scan=ScanRequirement.REQUIRED),
        ),
        Rule(
            id="known-stick",
            enabled=False,
            match=Match(fingerprint=FP_VALUE, product="*Flash*"),
            action=RuleAction(Access.READ_ONLY),
        ),
    ),
    scan=ScanPolicy(DetectionAction.READ_ONLY),
)


@pytest.fixture
def policies(fixtures_dir: Path) -> Path:
    return fixtures_dir / "policies"


def document(*rules: dict[str, Any], **top: Any) -> dict[str, Any]:
    return {"version": 1, "rules": list(rules), **top}


def one_rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "r1",
        "match": {"vendor_id": "0x1209"},
        "action": {"access": "deny"},
    }
    rule.update(overrides)
    return rule


def with_match(**criteria: Any) -> dict[str, Any]:
    return document(one_rule(match=criteria))


def problems_of(data: Any) -> tuple[str, ...]:
    with pytest.raises(PolicyError) as caught:
        parse_policy(data)
    return caught.value.problems


# --- well-formed documents ------------------------------------------------------------


def test_the_smallest_document_is_the_restrictive_policy() -> None:
    assert parse_policy({"version": 1}) == Policy()
    policy = parse_policy({"version": 1})
    assert policy.default.access is Access.PENDING
    assert policy.scan.on_detection is DetectionAction.DENY
    assert policy.scan.on_incomplete is IncompleteAction.READ_ONLY


def test_a_full_document_becomes_the_policy_it_describes() -> None:
    data = {
        "version": 1,
        "name": "Example",
        "default": {"access": "read_only", "scan": "required", "alert": True},
        "rules": [
            {
                "id": "everything",
                "description": "all the fields",
                "enabled": False,
                "expires": "2026-06-01T12:00:00Z",
                "match": {
                    "vendor_id": ["1209", "0x0781"],
                    "product_id": "0001",
                    "serial": "TEST*",
                    "fingerprint": [FP_VALUE.upper()],
                    "manufacturer": ["Example*", "Sample*"],
                    "product": "*Flash*",
                    "category": ["storage", "imaging"],
                    "interface_class": [8, "0x06"],
                    "confidence": "low",
                    "composite": True,
                    "storage_with_input": False,
                    "mixes_input_with_other": False,
                    "storage_like": True,
                    "removable": True,
                    "bus_path": "1-*",
                    "time": {"days": ["Sat", "sun"], "utc_offset_minutes": -300},
                },
                "action": {"access": "allow", "scan": "on_mount", "alert": True},
            }
        ],
        "scan": {"on_detection": "alert", "on_incomplete": "deny"},
    }
    assert parse_policy(data) == Policy(
        name="Example",
        default=RuleAction(Access.READ_ONLY, scan=ScanRequirement.REQUIRED, alert=True),
        rules=(
            Rule(
                id="everything",
                description="all the fields",
                enabled=False,
                expires=dt.datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
                match=Match(
                    vendor_id=(0x1209, 0x0781),
                    product_id=(0x0001,),
                    serial=("TEST*",),
                    fingerprint=(FP_VALUE,),
                    manufacturer=("Example*", "Sample*"),
                    product=("*Flash*",),
                    category=(DeviceCategory.STORAGE, DeviceCategory.IMAGING),
                    interface_class=(0x08, 0x06),
                    confidence=Confidence.LOW,
                    composite=True,
                    storage_with_input=False,
                    mixes_input_with_other=False,
                    storage_like=True,
                    removable=True,
                    bus_path=("1-*",),
                    time=TimeWindow(days=(5, 6), utc_offset_minutes=-300),
                ),
                action=RuleAction(Access.ALLOW, scan=ScanRequirement.ON_MOUNT, alert=True),
            ),
        ),
        scan=ScanPolicy(DetectionAction.ALERT, IncompleteAction.DENY),
    )


def test_parsing_does_not_modify_the_document() -> None:
    data = policy_to_dict(EXAMPLE_POLICY)
    before = copy.deepcopy(data)
    parse_policy(data)
    assert data == before


@pytest.mark.parametrize(
    ("written", "value"),
    [
        ("0x0000", 0),
        ("0", 0),
        ("0x0781", 0x0781),
        ("0X0781", 0x0781),
        ("0781", 0x0781),
        ("781", 0x0781),
        (" 0x0781 ", 0x0781),
        ("ffff", 0xFFFF),
        ("FFFF", 0xFFFF),
        # A string is always hexadecimal: this is 0x1209, not 1209.
        ("1209", 0x1209),
    ],
)
def test_vendor_and_product_ids_are_hex_strings(written: Any, value: int) -> None:
    policy = parse_policy(with_match(vendor_id=written, product_id=[written]))
    assert policy.rules[0].match.vendor_id == (value,)
    assert policy.rules[0].match.product_id == (value,)


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("2026-06-01T12:00:00Z", dt.datetime(2026, 6, 1, 12, 0, tzinfo=UTC)),
        ("2026-06-01T12:00:00.250Z", dt.datetime(2026, 6, 1, 12, 0, 0, 250000, tzinfo=UTC)),
        (None, None),
        (
            dt.datetime(2026, 6, 1, 14, 0, tzinfo=dt.timezone(dt.timedelta(hours=2))),
            dt.datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        ),
    ],
)
def test_expiry_forms(written: Any, expected: dt.datetime | None) -> None:
    assert parse_policy(document(one_rule(expires=written))).rules[0].expires == expected


def test_a_rule_that_has_already_expired_still_loads() -> None:
    policy = parse_policy(document(one_rule(expires="2001-01-01T00:00:00Z")))
    assert policy.rules[0].is_expired(dt.datetime(2026, 1, 1, tzinfo=UTC))


def test_time_window_forms() -> None:
    def window(**fields: Any) -> TimeWindow | None:
        return parse_policy(with_match(time=fields)).rules[0].match.time

    assert window(days="fri", start="22:00", end="06:00") == TimeWindow(
        days=(4,), start=dt.time(22, 0), end=dt.time(6, 0)
    )
    assert window(days=["MON", " tue "]) == TimeWindow(days=(0, 1))
    assert window(start="09:00", end="17:00") == TimeWindow(start=dt.time(9, 0), end=dt.time(17, 0))
    # TOML has its own time-of-day type.
    assert window(days=["sun"], start=dt.time(8, 0), end=dt.time(8, 30)) == TimeWindow(
        days=(6,), start=dt.time(8, 0), end=dt.time(8, 30)
    )


# --- every problem, each with its location --------------------------------------------


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        ([], "policy: expected an object, got a list"),
        (None, "policy: expected an object, got null"),
        ("version 1", "policy: expected an object, got a string"),
        ({}, "version: required (this PortLock reads version 1)"),
        ({"version": 2}, "version: unsupported policy version 2; this PortLock reads version 1"),
        ({"version": "1"}, "version: expected an integer, got '1'"),
        ({"version": True}, "version: expected an integer, got True"),
        ({"version": 1.0}, "version: expected an integer, got a number with a fraction"),
        ({"version": 1, "name": 7}, "name: a policy name must be a string"),
        (
            {"version": 1, "name": "n" * 129},
            "name: a policy name is too long (129 characters; the limit is 128)",
        ),
        (
            {"version": 1, "name": "tab\tbed"},
            "name: a policy name must not contain control characters",
        ),
        ({"version": 1, "default": "deny"}, "default: expected an object, got a string"),
        (
            {"version": 1, "default": {}},
            "default.access: required (allow, read_only, deny, pending)",
        ),
        (
            {"version": 1, "default": {"access": "block"}},
            "default.access: expected an access (allow, read_only, deny, pending), got 'block'",
        ),
        (
            {"version": 1, "default": {"access": "DENY"}},
            "default.access: expected an access (allow, read_only, deny, pending), got 'DENY'",
        ),
        (
            {"version": 1, "default": {"access": None}},
            "default.access: expected an access (allow, read_only, deny, pending), got null",
        ),
        (
            {"version": 1, "default": {"access": "deny", "scan": "always"}},
            "default.scan: expected a scan requirement (none, on_mount, required), got 'always'",
        ),
        (
            {"version": 1, "default": {"access": "deny", "alert": "yes"}},
            "default.alert: expected true or false, got 'yes'",
        ),
        (
            {"version": 1, "default": {"access": "deny", "alert": 1}},
            "default.alert: expected true or false, got 1",
        ),
        ({"version": 1, "rules": {}}, "rules: expected a list, got an object"),
        ({"version": 1, "rules": ["r1"]}, "rules[0]: expected an object, got a string"),
        ({"version": 1, "scan": []}, "scan: expected an object, got a list"),
        (
            {"version": 1, "scan": {"on_detection": "quarantine"}},
            "scan.on_detection: expected a detection action (deny, read_only, alert),"
            " got 'quarantine'",
        ),
    ],
)
def test_top_level_problems(data: Any, problem: str) -> None:
    assert problems_of(data) == (problem,)


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"id": None}, "rules[0].id: a rule id must be a string"),
        (
            {"id": "two words"},
            "rules[0].id: a rule id must start with a letter or digit and contain only"
            " letters, digits, '.', '_' and '-'",
        ),
        (
            {"id": "x" * 65},
            "rules[0].id: a rule id is too long (65 characters; the limit is 64)",
        ),
        ({"description": 5}, "rules[0].description: a description must be a string"),
        (
            {"description": "d" * 513},
            "rules[0].description: a description is too long (513 characters; the limit is 512)",
        ),
        ({"enabled": "true"}, "rules[0].enabled: expected true or false, got 'true'"),
        ({"enabled": None}, "rules[0].enabled: expected true or false, got None"),
        (
            {"expires": "tomorrow"},
            'rules[0].expires: expected null or a UTC timestamp such as "2026-06-01T12:00:00Z",'
            " got 'tomorrow'",
        ),
        (
            {"expires": "2026-06-01T12:00:00+02:00"},
            'rules[0].expires: expected null or a UTC timestamp such as "2026-06-01T12:00:00Z",'
            " got '2026-06-01T12:00:00+02:00'",
        ),
        (
            {"expires": 1780000000},
            'rules[0].expires: expected null or a UTC timestamp such as "2026-06-01T12:00:00Z",'
            " got 1780000000",
        ),
        (
            {"expires": dt.datetime(2026, 6, 1, 12, 0)},
            "rules[0].expires: a date-time must say its UTC offset, for example ...Z",
        ),
        ({"match": ["vendor_id"]}, "rules[0].match: expected an object, got a list"),
        (
            {"match": {}},
            "rules[0].match: a rule must have at least one match criterion; an empty match"
            " would apply to every device, which is what the policy default is for",
        ),
        ({"action": "deny"}, "rules[0].action: expected an object, got a string"),
        (
            {"action": {"scan": "none"}},
            "rules[0].action.access: required (allow, read_only, deny, pending)",
        ),
    ],
)
def test_rule_problems(overrides: dict[str, Any], problem: str) -> None:
    assert problems_of(document(one_rule(**overrides))) == (problem,)


@pytest.mark.parametrize("missing", ["id", "match", "action"])
def test_required_rule_keys(missing: str) -> None:
    rule = one_rule()
    del rule[missing]
    assert problems_of(document(rule)) == (f"rules[0].{missing}: required",)


HEX_HINT = 'expected a string of up to 4 hexadecimal digits such as "0x0781"'
NOT_A_NUMBER = "vendor and product ids must be hexadecimal strings, not bare numbers: the number"


@pytest.mark.parametrize(
    ("criteria", "problem"),
    [
        ({"vendor_id": "zz"}, f"rules[0].match.vendor_id: {HEX_HINT}, got 'zz'"),
        ({"vendor_id": "0x12345"}, f"rules[0].match.vendor_id: {HEX_HINT}, got '0x12345'"),
        ({"vendor_id": ""}, f"rules[0].match.vendor_id: {HEX_HINT}, got ''"),
        ({"vendor_id": "0x"}, f"rules[0].match.vendor_id: {HEX_HINT}, got '0x'"),
        ({"vendor_id": "-1"}, f"rules[0].match.vendor_id: {HEX_HINT}, got '-1'"),
        # A bare number is refused, and the message says why: 8087 is not 0x8087.
        (
            {"vendor_id": 8087},
            f"rules[0].match.vendor_id: {NOT_A_NUMBER} 8087 is not the id 0x8087, so a rule"
            ' written that way would silently never match; write it as "0x8087"',
        ),
        (
            {"product_id": 1},
            f"rules[0].match.product_id: {NOT_A_NUMBER} 1 is not the id 0x1, so a rule"
            ' written that way would silently never match; write it as "0x0001"',
        ),
        (
            {"vendor_id": 65536},
            f"rules[0].match.vendor_id: {NOT_A_NUMBER} 65536 is not the id 0x65536, so a rule"
            ' written that way would silently never match; write it as "0x0781" or "0781"',
        ),
        (
            {"vendor_id": -1},
            f"rules[0].match.vendor_id: {NOT_A_NUMBER} -1 is not the id 0x-1, so a rule"
            ' written that way would silently never match; write it as "0x0781" or "0781"',
        ),
        ({"product_id": True}, f"rules[0].match.product_id: {HEX_HINT}, got True"),
        (
            {"product_id": 1.0},
            f"rules[0].match.product_id: {HEX_HINT}, got a number with a fraction",
        ),
        ({"vendor_id": None}, f"rules[0].match.vendor_id: {HEX_HINT}, got None"),
        ({"vendor_id": {"hex": "1209"}}, f"rules[0].match.vendor_id: {HEX_HINT}, got an object"),
        (
            {"vendor_id": ["0x1", "nope", "0x3"]},
            f"rules[0].match.vendor_id[1]: {HEX_HINT}, got 'nope'",
        ),
        (
            {"vendor_id": []},
            "rules[0].match.vendor_id: an empty list can never match; remove the criterion"
            " or give a value",
        ),
        (
            {"vendor_id": list(range(MAX_LIST_ITEMS + 1))},
            "rules[0].match.vendor_id: too many values (65; the limit is 64)",
        ),
        (
            {"interface_class": "0x100"},
            "rules[0].match.interface_class: expected an integer or up to 2 hexadecimal"
            " digits such as \"0x08\", got '0x100'",
        ),
        (
            {"interface_class": 256},
            "rules[0].match.interface_class: an interface class must be an integer between 0"
            " and 0xff, got 256",
        ),
        ({"serial": ""}, "rules[0].match.serial: a pattern must not be empty"),
        ({"serial": 12345}, "rules[0].match.serial: a pattern must be a string"),
        (
            {"serial": ["ok", "x" * 129]},
            "rules[0].match.serial[1]: a pattern is too long (129 characters; the limit is 128)",
        ),
        (
            {"manufacturer": "*a" * 17},
            "rules[0].match.manufacturer: a pattern has too many wildcards (17; the limit is 16)",
        ),
        (
            {"product": "bad\x00"},
            "rules[0].match.product: a pattern must not contain control characters",
        ),
        ({"bus_path": [None]}, "rules[0].match.bus_path[0]: a pattern must be a string"),
        (
            {"bus_path": ["1-2", "1-2."]},
            "rules[0].match.bus_path[1]: a bus path pattern must not start or end with '.' or"
            " '#', or have two in a row",
        ),
        (
            {"bus_path": "1-2..3"},
            "rules[0].match.bus_path: a bus path pattern must not start or end with '.' or"
            " '#', or have two in a row",
        ),
        (
            {"bus_path": "#USB(2)"},
            "rules[0].match.bus_path: a bus path pattern must not start or end with '.' or"
            " '#', or have two in a row",
        ),
        (
            {"fingerprint": "plk1:*"},
            "rules[0].match.fingerprint: a fingerprint is 'plk1:' followed by 32 base32"
            " characters (a-z, 2-7); wildcards are not accepted",
        ),
        (
            {"category": "flash"},
            "rules[0].match.category: expected a category (storage, keyboard, mouse, hid,"
            " hub, network, serial, audio_video, imaging, printer, smart_card, wireless,"
            " vendor, other), got 'flash'",
        ),
        (
            {"confidence": "medium"},
            "rules[0].match.confidence: expected a confidence (high, low), got 'medium'",
        ),
        (
            {"confidence": ["high"]},
            "rules[0].match.confidence: expected a confidence (high, low), got a list",
        ),
        ({"composite": "no"}, "rules[0].match.composite: expected true or false, got 'no'"),
        (
            {"storage_with_input": 1},
            "rules[0].match.storage_with_input: expected true or false, got 1",
        ),
        ({"removable": None}, "rules[0].match.removable: expected true or false, got None"),
        (
            {"mixes_input_with_other": "yes"},
            "rules[0].match.mixes_input_with_other: expected true or false, got 'yes'",
        ),
        ({"storage_like": 0}, "rules[0].match.storage_like: expected true or false, got 0"),
        ({"time": "09:00-17:00"}, "rules[0].match.time: expected an object, got a string"),
        (
            {"time": {"days": ["funday"]}},
            "rules[0].match.time.days[0]: expected a day (mon, tue, wed, thu, fri, sat, sun),"
            " got 'funday'",
        ),
        (
            {"time": {"days": [0]}},
            "rules[0].match.time.days[0]: expected a day (mon, tue, wed, thu, fri, sat, sun),"
            " got 0",
        ),
        (
            {"time": {"days": []}},
            "rules[0].match.time.days: an empty list can never match; remove the criterion"
            " or give a value",
        ),
        (
            {"time": {"start": "09:00"}},
            "rules[0].match.time: start and end must be given together, or both left out",
        ),
        (
            {"time": {"start": "24:00", "end": "09:00"}},
            'rules[0].match.time.start: expected a time of day as "HH:MM" (00:00 to 23:59),'
            " got '24:00'",
        ),
        (
            {"time": {"start": "9:00", "end": "17:00"}},
            'rules[0].match.time.start: expected a time of day as "HH:MM" (00:00 to 23:59),'
            " got '9:00'",
        ),
        (
            {"time": {"start": "09:00", "end": 1700}},
            'rules[0].match.time.end: expected a time of day as "HH:MM" (00:00 to 23:59), got 1700',
        ),
        (
            {"time": {"start": dt.time(9, 0, 30), "end": "17:00"}},
            "rules[0].match.time.start: expected a time of day to the minute, without a time zone",
        ),
        (
            {"time": {"days": ["mon"], "utc_offset_minutes": 1.5}},
            "rules[0].match.time.utc_offset_minutes: expected an integer number of minutes,"
            " got a number with a fraction",
        ),
        (
            {"time": {"days": ["mon"], "utc_offset_minutes": 900}},
            "rules[0].match.time: utc_offset_minutes must be an integer between -720 and 840",
        ),
        (
            {"time": {}},
            "rules[0].match.time: a time window open all day on every day always matches;"
            " remove it or narrow the days or the hours",
        ),
    ],
)
def test_match_problems(criteria: dict[str, Any], problem: str) -> None:
    assert problems_of(with_match(**criteria)) == (problem,)


def test_unknown_keys_are_rejected_at_every_level() -> None:
    data = {
        "version": 1,
        "comment": "not a key",
        "default": {"access": "pending", "acess": "allow"},
        "rules": [
            {
                "id": "r1",
                "priority": 5,
                "match": {
                    "vendor": "0x1209",
                    "vendor_id": "0x1209",
                    "time": {"days": ["mon"], "timezone": "Europe/Paris"},
                },
                "action": {"access": "deny", "log": True},
            }
        ],
        "scan": {"on_detection": "deny", "engines": []},
    }
    assert problems_of(data) == (
        "comment: unknown key (known keys: version, name, default, rules, scan)",
        "default.acess: unknown key (known keys: access, scan, alert)",
        "rules[0].priority: unknown key (known keys: id, description, enabled, expires,"
        " match, action)",
        "rules[0].match.vendor: unknown key (known keys: vendor_id, product_id, serial,"
        " fingerprint, manufacturer, product, category, interface_class, confidence,"
        " composite, storage_with_input, mixes_input_with_other, storage_like, removable,"
        " bus_path, time)",
        "rules[0].match.time.timezone: unknown key (known keys: days, start, end,"
        " utc_offset_minutes)",
        "rules[0].action.log: unknown key (known keys: access, scan, alert)",
        "scan.engines: unknown key (known keys: on_detection, on_incomplete)",
    )


def test_every_problem_is_reported_not_just_the_first() -> None:
    data = {
        "version": 3,
        "name": 12,
        "default": {"access": "maybe", "scan": 1, "alert": "no"},
        "rules": [
            {
                "id": "bad id",
                "enabled": 1,
                "expires": "soon",
                "match": {
                    "vendor_id": ["0x1209", "wxyz", 70000],
                    "serial": "",
                    "category": ["storage", "disk"],
                    "removable": "yes",
                    "time": {"days": ["mon", "moonday"], "start": "25:00", "end": "17:00"},
                },
                "action": {"access": "deny", "scan": "sometimes"},
            },
            {"id": "fine", "match": {"serial": "TEST*"}, "action": {"access": "allow"}},
            {"match": {}, "action": {}},
        ],
        "scan": {"on_detection": 0, "on_incomplete": "alert"},
    }
    with pytest.raises(PolicyError) as caught:
        parse_policy(data)
    assert caught.value.problems == (
        "version: unsupported policy version 3; this PortLock reads version 1",
        "name: a policy name must be a string",
        "default.access: expected an access (allow, read_only, deny, pending), got 'maybe'",
        "default.scan: expected a scan requirement (none, on_mount, required), got an integer",
        "default.alert: expected true or false, got 'no'",
        "rules[0].id: a rule id must start with a letter or digit and contain only letters,"
        " digits, '.', '_' and '-'",
        "rules[0].enabled: expected true or false, got 1",
        'rules[0].expires: expected null or a UTC timestamp such as "2026-06-01T12:00:00Z",'
        " got 'soon'",
        f"rules[0].match.vendor_id[1]: {HEX_HINT}, got 'wxyz'",
        "rules[0].match.vendor_id[2]: vendor and product ids must be hexadecimal strings,"
        " not bare numbers: the number 70000 is not the id 0x70000, so a rule written that"
        ' way would silently never match; write it as "0x0781" or "0781"',
        "rules[0].match.serial: a pattern must not be empty",
        "rules[0].match.category[1]: expected a category (storage, keyboard, mouse, hid, hub,"
        " network, serial, audio_video, imaging, printer, smart_card, wireless, vendor,"
        " other), got 'disk'",
        "rules[0].match.removable: expected true or false, got 'yes'",
        "rules[0].match.time.days[1]: expected a day (mon, tue, wed, thu, fri, sat, sun),"
        " got 'moonday'",
        'rules[0].match.time.start: expected a time of day as "HH:MM" (00:00 to 23:59),'
        " got '25:00'",
        "rules[0].action.scan: expected a scan requirement (none, on_mount, required),"
        " got 'sometimes'",
        "rules[2].id: required",
        "rules[2].action.access: required (allow, read_only, deny, pending)",
        "scan.on_detection: expected a detection action (deny, read_only, alert), got an integer",
        "scan.on_incomplete: expected an incomplete-scan action (read_only, deny), got 'alert'",
    )
    error = caught.value
    assert isinstance(error, PortLockError) and error.code == "policy_error"
    assert str(error) == (
        "the policy is invalid (20 problems); first: version: unsupported policy version 3;"
        " this PortLock reads version 1"
    )


def test_a_single_problem_is_counted_in_the_singular() -> None:
    with pytest.raises(PolicyError, match=r"\(1 problem\); first: version: required"):
        parse_policy({})


def test_duplicate_rule_ids_are_rejected_with_both_locations() -> None:
    data = document(one_rule(id="same"), one_rule(id="other"), one_rule(id="same"))
    assert problems_of(data) == (
        "rules[2].id: duplicate rule id 'same' (already used by rules[0]); ids differing"
        " only in case count as the same",
    )
    data = document(one_rule(id="Block"), one_rule(id="BLOCK"), one_rule(id="block"))
    assert problems_of(data) == (
        "rules[1].id: duplicate rule id 'BLOCK' (already used by rules[0]); ids differing"
        " only in case count as the same",
        "rules[2].id: duplicate rule id 'block' (already used by rules[0]); ids differing"
        " only in case count as the same",
    )


def test_a_duplicate_id_is_found_even_when_the_first_rule_is_otherwise_broken() -> None:
    data = document(one_rule(id="twin", action={}), one_rule(id="twin"))
    assert problems_of(data) == (
        "rules[0].action.access: required (allow, read_only, deny, pending)",
        "rules[1].id: duplicate rule id 'twin' (already used by rules[0]); ids differing"
        " only in case count as the same",
    )


# --- limits and hostile documents -----------------------------------------------------


def test_the_rule_limit_is_enforced_without_looking_inside() -> None:
    # Every one of these "rules" is garbage; only the count is reported.
    assert problems_of({"version": 1, "rules": [None] * (MAX_RULES + 1)}) == (
        "rules: too many rules (2001; the limit is 2000)",
    )


def test_a_document_at_the_rule_limit_loads() -> None:
    rules = [one_rule(id=f"r{index}") for index in range(MAX_RULES)]
    policy = parse_policy({"version": 1, "rules": rules})
    assert len(policy.rules) == MAX_RULES
    assert policy.rules[-1].id == "r1999"


def test_the_number_of_reported_problems_is_bounded() -> None:
    rules = [one_rule(id=f"bad id {index}") for index in range(500)]
    with pytest.raises(PolicyError) as caught:
        parse_policy({"version": 1, "rules": rules})
    problems = caught.value.problems
    assert len(problems) == MAX_PROBLEMS + 1
    assert problems[0].startswith("rules[0].id: a rule id must start with")
    assert problems[MAX_PROBLEMS - 1].startswith("rules[99].id:")
    assert problems[-1] == "... and 400 more problems not shown"
    assert "(500 problems)" in str(caught.value)


def test_offending_values_are_shortened_in_messages() -> None:
    huge = "A" * 1_000_000
    problems = problems_of(
        {
            "version": 1,
            huge: 1,
            "default": {"access": huge},
            "rules": [one_rule(match={"vendor_id": huge, "serial": huge})],
        }
    )
    shortened = "A" * 40 + "..."
    assert problems == (
        f"{shortened}: unknown key (known keys: version, name, default, rules, scan)",
        f"default.access: expected an access (allow, read_only, deny, pending), got '{shortened}'",
        f"rules[0].match.vendor_id: {HEX_HINT}, got '{shortened}'",
        "rules[0].match.serial: a pattern is too long (1000000 characters; the limit is 128)",
    )
    assert all(len(problem) < 400 for problem in problems)


def test_keys_that_are_not_strings_are_rejected() -> None:
    assert problems_of({"version": 1, 7: "seven", None: 0}) == (
        "policy: keys must be strings, got an integer",
        "policy: keys must be strings, got null",
    )
    assert problems_of(with_match(**{"vendor_id": "0x1"}) | {"rules": [{1: 2}]})[0] == (
        "rules[0]: keys must be strings, got an integer"
    )


def test_deeply_nested_values_are_reported_not_followed() -> None:
    nested: Any = "bottom"
    for _level in range(50_000):
        nested = [nested]
    assert problems_of(with_match(vendor_id=nested, serial={"a": nested})) == (
        f"rules[0].match.vendor_id[0]: {HEX_HINT}, got a list",
        "rules[0].match.serial: a pattern must be a string",
    )


def test_tuples_are_accepted_where_lists_are() -> None:
    policy = parse_policy({"version": 1, "rules": (one_rule(match={"vendor_id": ("1", "2")}),)})
    assert policy.rules[0].match.vendor_id == (1, 2)


# --- output ---------------------------------------------------------------------------


@pytest.mark.parametrize("policy", [Policy(), DEFAULT_POLICY, EXAMPLE_POLICY, OFFICE_POLICY])
def test_a_policy_survives_the_round_trip_through_a_document(policy: Policy) -> None:
    assert parse_policy(policy_to_dict(policy)) == policy
    assert parse_policy(json.loads(dump_policy_json(policy))) == policy


def test_the_document_form_is_fixed() -> None:
    policy = Policy(
        name="Form",
        rules=(
            Rule(
                id="r1",
                expires=dt.datetime(2026, 6, 1, 14, 0, tzinfo=dt.timezone(dt.timedelta(hours=2))),
                match=Match(
                    vendor_id=0x781,
                    interface_class=8,
                    category=DeviceCategory.STORAGE,
                    serial="TEST*",
                    fingerprint=FP_VALUE.upper(),
                    confidence=Confidence.HIGH,
                    removable=False,
                    time=TimeWindow(days=(6, 0), start=dt.time(22, 0), end=dt.time(6, 30)),
                ),
                action=RuleAction(Access.READ_ONLY),
            ),
        ),
    )
    assert policy_to_dict(policy) == {
        "version": 1,
        "name": "Form",
        "default": {"access": "pending", "scan": "none", "alert": False},
        "rules": [
            {
                "id": "r1",
                "description": "",
                "enabled": True,
                "expires": "2026-06-01T12:00:00.000000Z",
                "match": {
                    "vendor_id": ["0x0781"],
                    "serial": ["TEST*"],
                    "fingerprint": [FP_VALUE],
                    "category": ["storage"],
                    "interface_class": ["0x08"],
                    "confidence": "high",
                    "removable": False,
                    "time": {
                        "days": ["mon", "sun"],
                        "start": "22:00",
                        "end": "06:30",
                        "utc_offset_minutes": 0,
                    },
                },
                "action": {"access": "read_only", "scan": "none", "alert": False},
            }
        ],
        "scan": {"on_detection": "deny", "on_incomplete": "read_only"},
    }
    # Key order is part of the form: it is what makes the text stable.
    rendered = policy_to_dict(policy)
    assert list(rendered) == ["version", "name", "default", "rules", "scan"]
    assert list(rendered["rules"][0]) == [
        "id",
        "description",
        "enabled",
        "expires",
        "match",
        "action",
    ]
    assert list(rendered["rules"][0]["match"]) == [
        "vendor_id",
        "serial",
        "fingerprint",
        "category",
        "interface_class",
        "confidence",
        "removable",
        "time",
    ]


def test_the_json_text_is_stable_and_matches_the_committed_default(policies: Path) -> None:
    text = dump_policy_json(DEFAULT_POLICY)
    assert text == dump_policy_json(DEFAULT_POLICY)
    assert text.endswith("}\n") and "\r" not in text
    assert text == (policies / "default.json").read_text(encoding="utf-8")
    assert dump_policy_json(parse_policy(json.loads(text))) == text


def test_text_outside_ascii_is_written_as_itself() -> None:
    name = "B\N{LATIN SMALL LETTER U WITH DIAERESIS}ro \N{CJK UNIFIED IDEOGRAPH-65E5}"
    policy = Policy(name=name, rules=())
    text = dump_policy_json(policy)
    assert name in text
    assert parse_policy(json.loads(text)).name == name


# --- hashing --------------------------------------------------------------------------


def test_the_hash_is_the_sha256_of_the_canonical_json() -> None:
    policy = Policy(
        name="Tiny",
        default=RuleAction(Access.DENY, alert=True),
        rules=(
            Rule(
                id="a",
                match=Match(vendor_id=0x1209, removable=True),
                action=RuleAction(Access.ALLOW, scan=ScanRequirement.ON_MOUNT),
            ),
        ),
        scan=ScanPolicy(DetectionAction.ALERT),
    )
    # Written out by hand: keys sorted at every level, no whitespace.
    canonical = (
        '{"default":{"access":"deny","alert":true,"scan":"none"},'
        '"name":"Tiny",'
        '"rules":[{"action":{"access":"allow","alert":false,"scan":"on_mount"},'
        '"description":"","enabled":true,"expires":null,"id":"a",'
        '"match":{"removable":true,"vendor_id":["0x1209"]}}],'
        '"scan":{"on_detection":"alert","on_incomplete":"read_only"},'
        '"version":1}'
    )
    assert policy_hash(policy) == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert len(policy_hash(policy)) == 64


def test_the_hash_depends_on_content_not_on_how_the_document_was_written() -> None:
    compact = {
        "version": 1,
        "rules": [
            {
                "id": "r1",
                "match": {"vendor_id": "1209", "serial": "TEST*", "interface_class": 8},
                "action": {"access": "deny"},
            }
        ],
    }
    verbose = {
        "scan": {"on_detection": "deny", "on_incomplete": "read_only"},
        "rules": [
            {
                "action": {"alert": False, "scan": "none", "access": "deny"},
                "match": {
                    "interface_class": ["0x08"],
                    "serial": ["TEST*"],
                    "vendor_id": ["0X1209"],
                },
                "expires": None,
                "enabled": True,
                "description": "",
                "id": "r1",
            }
        ],
        "default": {"access": "pending"},
        "name": "",
        "version": 1,
    }
    assert policy_hash(parse_policy(compact)) == policy_hash(parse_policy(verbose))


@pytest.mark.parametrize(
    "change",
    [
        {"name": "renamed"},
        {"default": {"access": "deny"}},
        {"scan": {"on_detection": "alert"}},
        {"scan": {"on_incomplete": "deny"}},
        {"rules": []},
        {"rules": [one_rule(enabled=False)]},
        {"rules": [one_rule(action={"access": "allow"})]},
        {"rules": [one_rule(match={"vendor_id": "0x120a"})]},
        {"rules": [one_rule(expires="2030-01-01T00:00:00Z")]},
        {"rules": [one_rule(), one_rule(id="r2")]},
    ],
)
def test_any_change_of_content_changes_the_hash(change: dict[str, Any]) -> None:
    base = document(one_rule())
    assert policy_hash(parse_policy(base | change)) != policy_hash(parse_policy(base))


def test_rule_order_is_content() -> None:
    first, second = one_rule(id="a"), one_rule(id="b", action={"access": "allow"})
    assert policy_hash(parse_policy(document(first, second))) != policy_hash(
        parse_policy(document(second, first))
    )


# --- files ----------------------------------------------------------------------------


def test_json_and_toml_files_describing_the_same_policy_load_equal(policies: Path) -> None:
    from_json = load_policy_file(policies / "office.json")
    from_toml = load_policy_file(policies / "office.toml")
    assert from_json == OFFICE_POLICY
    assert from_toml == OFFICE_POLICY
    assert policy_hash(from_json) == policy_hash(from_toml)


def test_a_toml_hexadecimal_integer_is_still_a_bare_number(tmp_path: Path) -> None:
    # TOML has hexadecimal integer literals, but they arrive as plain integers and cannot
    # be told apart from decimal ones, so they are refused like any other number.
    target = tmp_path / "hex.toml"
    target.write_text(
        "\n".join(
            (
                "version = 1",
                "[[rules]]",
                'id = "r"',
                "match = { vendor_id = 0x8087 }",
                'action = { access = "deny" }',
                "",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError) as caught:
        load_policy_file(target)
    (problem,) = caught.value.problems
    assert problem.startswith(
        "rules[0].match.vendor_id: vendor and product ids must be hexadecimal strings"
    )


def test_a_file_with_several_faults_reports_them_all(policies: Path) -> None:
    with pytest.raises(PolicyError) as caught:
        load_policy_file(policies / "broken.json")
    assert caught.value.problems == (
        "nmae: unknown key (known keys: version, name, default, rules, scan)",
        "default.access: expected an access (allow, read_only, deny, pending), got 'maybe'",
        "rules[1].match.colour: unknown key (known keys: vendor_id, product_id, serial,"
        " fingerprint, manufacturer, product, category, interface_class, confidence,"
        " composite, storage_with_input, mixes_input_with_other, storage_like, removable,"
        " bus_path, time)",
        f"rules[1].match.vendor_id: {HEX_HINT}, got '0x12345'",
        "rules[1].match.serial: a pattern must not be empty",
        "rules[1].action.alert: expected true or false, got 'yes'",
        "rules[1].id: duplicate rule id 'OK-RULE' (already used by rules[0]); ids differing"
        " only in case count as the same",
        "rules[2].match: a rule must have at least one match criterion; an empty match would"
        " apply to every device, which is what the policy default is for",
    )


def test_a_key_given_twice_in_json_is_an_error(policies: Path) -> None:
    with pytest.raises(PolicyError) as caught:
        load_policy_file(policies / "dupkey.json")
    message = (
        "policy file dupkey.json is not well-formed JSON: key 'access' is given more than"
        " once in the same object"
    )
    assert str(caught.value) == message
    assert caught.value.problems == (message,)


def write(directory: Path, name: str, content: bytes) -> Path:
    target = directory / name
    target.write_bytes(content)
    return target


@pytest.mark.parametrize(
    ("name", "content", "fragment"),
    [
        ("p.json", b'{"version": 1,', "p.json is not well-formed JSON"),
        ("p.json", b"", "p.json is not well-formed JSON"),
        ("p.json", b'{"version": NaN}', "not well-formed JSON: NaN is not valid JSON"),
        ("p.json", b'{"version": Infinity}', "Infinity is not valid JSON"),
        ("p.json", b'{"version": 1, "name": "\xff\xfe"}', "p.json is not well-formed JSON"),
        ("p.json", b"[" * 200_000, "p.json is not well-formed JSON"),
        ("p.json", b'{"version": ' + b"9" * 5000 + b"}", "p.json is not well-formed JSON"),
        ("p.toml", b"version = ", "p.toml is not well-formed TOML"),
        ("p.toml", b"version = 1\nversion = 1\n", "p.toml is not well-formed TOML"),
        ("p.toml", b"\xff\xfe", "p.toml is not well-formed TOML"),
        ("p.yaml", b"version: 1\n", "unsupported policy file type '.yaml'"),
        ("policy", b'{"version": 1}', "unsupported policy file type ''"),
    ],
)
def test_malformed_files_are_policy_errors(
    tmp_path: Path, name: str, content: bytes, fragment: str
) -> None:
    with pytest.raises(PolicyError, match=fragment) as caught:
        load_policy_file(write(tmp_path, name, content))
    assert len(caught.value.problems) == 1
    assert len(str(caught.value)) < 500


def test_a_well_formed_file_holding_an_invalid_policy_lists_located_problems(
    tmp_path: Path,
) -> None:
    target = write(tmp_path, "p.toml", b'version = 1\n[default]\naccess = "maybe"\n')
    with pytest.raises(PolicyError) as caught:
        load_policy_file(target)
    assert caught.value.problems == (
        "default.access: expected an access (allow, read_only, deny, pending), got 'maybe'",
    )


def test_a_byte_order_mark_and_an_uppercase_extension_are_tolerated(tmp_path: Path) -> None:
    target = write(tmp_path, "POLICY.JSON", b'\xef\xbb\xbf{"version": 1, "name": "bom"}')
    assert load_policy_file(target) == Policy(name="bom")
    assert load_policy_file(str(target)) == Policy(name="bom")


def test_an_oversized_file_is_refused_before_it_is_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loader, "MAX_POLICY_FILE_BYTES", 64)
    at_limit = b'{"version": 1, "name": "' + b"n" * 38 + b'"}'
    assert len(at_limit) == 64
    assert load_policy_file(write(tmp_path, "fits.json", at_limit)).name == "n" * 38
    # Not even valid JSON: the size check comes first.
    with pytest.raises(PolicyError, match=r"big\.json is larger than 64 bytes"):
        load_policy_file(write(tmp_path, "big.json", b"x" * 65))


def test_a_file_that_cannot_be_read_is_a_store_error(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="cannot read policy file"):
        load_policy_file(tmp_path / "missing.json")
    directory = tmp_path / "dir.json"
    directory.mkdir()
    with pytest.raises(StoreError, match="cannot read policy file"):
        load_policy_file(directory)


def test_saving_writes_the_stable_text_and_loads_back_equal(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    save_policy(target, EXAMPLE_POLICY)
    assert target.read_bytes() == dump_policy_json(EXAMPLE_POLICY).encode("utf-8")
    assert load_policy_file(target) == EXAMPLE_POLICY
    assert policy_hash(load_policy_file(target)) == policy_hash(EXAMPLE_POLICY)


def test_saving_replaces_the_previous_file_and_leaves_nothing_else(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    save_policy(target, EXAMPLE_POLICY)
    save_policy(str(target), DEFAULT_POLICY)
    assert load_policy_file(target) == DEFAULT_POLICY
    assert [item.name for item in tmp_path.iterdir()] == ["policy.json"]


def test_a_failed_save_leaves_the_previous_policy_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "policy.json"
    save_policy(target, DEFAULT_POLICY)

    def refuse(_source: Any, _destination: Any) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(StoreError, match=r"cannot write policy file .*Access is denied"):
        save_policy(target, EXAMPLE_POLICY)
    monkeypatch.undo()
    assert load_policy_file(target) == DEFAULT_POLICY
    assert [item.name for item in tmp_path.iterdir()] == ["policy.json"]


def test_saving_into_a_directory_that_does_not_exist_is_a_store_error(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="cannot write policy file"):
        save_policy(tmp_path / "absent" / "policy.json", DEFAULT_POLICY)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", ["policy.toml", "policy.txt", "policy"])
def test_policies_are_saved_as_json_only(tmp_path: Path, name: str) -> None:
    with pytest.raises(PolicyError, match=r"policies are saved as \.json files"):
        save_policy(tmp_path / name, DEFAULT_POLICY)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_a_saved_policy_is_readable_by_its_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "policy.json"
    save_policy(target, DEFAULT_POLICY)
    assert target.stat().st_mode & 0o777 == 0o600
