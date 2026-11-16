"""Reading, validating and writing policy documents.

A policy document is untrusted input: it may come from a download, a half-finished edit
or someone probing for a parser that falls over. :func:`parse_policy` therefore

* checks everything and reports **every** problem it finds, each with the location of the
  offending value (``rules[2].match.vendor_id: ...``), instead of stopping at the first;
* rejects what it does not understand (unknown keys, unknown versions) rather than
  ignoring it, because a misspelt ``"acces": "deny"`` that is silently dropped is a rule
  that does not do what its author thinks;
* bounds its own work: the number of rules, list sizes, string lengths, pattern
  complexity, the size of a file and the number of problems reported are all limited.

Documents are JSON. TOML is accepted on import; PortLock always writes JSON.
"""

from __future__ import annotations

import datetime as dt
import enum
import hashlib
import json
import os
import re
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar

from portlock.core.canonical import canonical_bytes
from portlock.core.clock import parse_utc_iso, utc_iso
from portlock.core.errors import PolicyError, StoreError
from portlock.core.fsutil import atomic_write_text
from portlock.core.models import Access, Confidence, DeviceCategory, ScanRequirement
from portlock.policy.model import (
    MAX_DESCRIPTION_LENGTH,
    MAX_LIST_ITEMS,
    MAX_NAME_LENGTH,
    MAX_RULES,
    POLICY_VERSION,
    WEEKDAYS,
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
    check_rule_id,
    check_text,
    check_usb_number,
)

__all__ = [
    "MAX_POLICY_FILE_BYTES",
    "MAX_PROBLEMS",
    "dump_policy_json",
    "load_policy_file",
    "parse_policy",
    "policy_hash",
    "policy_to_dict",
    "save_policy",
]

#: Largest policy file that will be read.
MAX_POLICY_FILE_BYTES = 8 * 1024 * 1024
#: Most problems one :class:`PolicyError` lists; the rest are counted, not shown.
MAX_PROBLEMS = 100

_T = TypeVar("_T")
_E = TypeVar("_E", bound=enum.StrEnum)

_POLICY_KEYS = ("version", "name", "default", "rules", "scan")
_RULE_KEYS = ("id", "description", "enabled", "expires", "match", "action")
_ACTION_KEYS = ("access", "scan", "alert")
_SCAN_KEYS = ("on_detection", "on_incomplete")
_TIME_KEYS = ("days", "start", "end", "utc_offset_minutes")
_FLAG_KEYS = (
    "composite",
    "storage_with_input",
    "mixes_input_with_other",
    "storage_like",
    "removable",
)
_MATCH_KEYS = (
    "vendor_id",
    "product_id",
    "serial",
    "fingerprint",
    "manufacturer",
    "product",
    "category",
    "interface_class",
    "confidence",
    *_FLAG_KEYS,
    "bus_path",
    "time",
)

_HEX_PATTERN = re.compile(r"(?:0[xX])?([0-9a-fA-F]+)\Z")
_CLOCK_PATTERN = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])\Z")


class _Problems:
    """Collects located problems, keeping at most :data:`MAX_PROBLEMS` of them."""

    def __init__(self) -> None:
        self._shown: list[str] = []
        self.count = 0

    def add(self, location: str, message: str) -> None:
        self.count += 1
        if len(self._shown) < MAX_PROBLEMS:
            self._shown.append(f"{location}: {message}")

    def as_tuple(self) -> tuple[str, ...]:
        hidden = self.count - len(self._shown)
        if hidden:
            return (*self._shown, f"... and {hidden} more problems not shown")
        return tuple(self._shown)


def _kind(value: Any) -> str:
    """Name a value's type the way the document's author would."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, float):
        return "a number with a fraction"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, Mapping):
        return "an object"
    if isinstance(value, list | tuple):
        return "a list"
    return f"a {type(value).__name__}"


def _show(value: Any) -> str:
    """A short rendering of an offending value, safe to put in an error message."""
    if isinstance(value, str):
        return repr(value if len(value) <= 40 else value[:40] + "...")
    if value is None or isinstance(value, bool | int):
        text = repr(value)
        return text if len(text) <= 40 else text[:40] + "..."
    return _kind(value)


def _join(parent: str, key: str) -> str:
    return f"{parent}.{key}" if parent else key


def _object(
    value: Any, location: str, allowed: tuple[str, ...], problems: _Problems
) -> Mapping[str, Any] | None:
    """Check that ``value`` is an object holding only known keys."""
    if not isinstance(value, Mapping):
        problems.add(location or "policy", f"expected an object, got {_kind(value)}")
        return None
    for key in value:
        if not isinstance(key, str):
            problems.add(location or "policy", f"keys must be strings, got {_kind(key)}")
        elif key not in allowed:
            problems.add(
                _join(location, _show(key)[1:-1]),
                f"unknown key (known keys: {', '.join(allowed)})",
            )
    return value


def _enum_member(value: Any, enum_type: type[_E], what: str) -> _E:
    """Convert a document string into a member of a string enum.

    Raises:
        ValueError: if the value is not one of the enum's values.
    """
    options = ", ".join(member.value for member in enum_type)
    if not isinstance(value, str):
        raise ValueError(f"expected {what} ({options}), got {_kind(value)}")
    try:
        return enum_type(value)
    except ValueError:
        raise ValueError(f"expected {what} ({options}), got {_show(value)}") from None


def _hex_string(value: str, upper: int, example: str, *, numbers_too: bool) -> int:
    """Read a string of hexadecimal digits with an optional ``0x`` prefix.

    Raises:
        ValueError: if it is not up to as many hex digits as ``upper`` has.
    """
    found = _HEX_PATTERN.match(value.strip())
    digits = len(f"{upper:x}")
    if found is None or len(found.group(1)) > digits:
        allowed = "an integer or up to" if numbers_too else "a string of up to"
        raise ValueError(
            f'expected {allowed} {digits} hexadecimal digits such as "{example}",'
            f" got {_show(value)}"
        )
    return int(found.group(1), 16)


def _hex_number(value: Any, what: str, upper: int, example: str) -> int:
    """An integer, or a string of hexadecimal digits with an optional ``0x`` prefix.

    A string is always read as hexadecimal: ``"14"`` is 0x14.
    """
    if isinstance(value, str):
        return _hex_string(value, upper, example, numbers_too=True)
    try:
        return check_usb_number(value, what, upper)
    except ValueError as exc:
        raise ValueError(f"{exc}, got {_show(value)}") from None


def _vendor_or_product(value: Any) -> int:
    """A vendor or product id, which a document must write as a hexadecimal string.

    A bare number is refused rather than read. Ids are written in hex everywhere else
    (``lsusb``, Device Manager, vendor data sheets), so an author who types ``8087``
    means 0x8087; read as the number it is, it would be 0x1F97, and the rule would
    silently never match the device it was written for.
    """
    if isinstance(value, str):
        return _hex_string(value, 0xFFFF, "0x0781", numbers_too=False)
    if isinstance(value, int) and not isinstance(value, bool):
        written = '"0x0781" or "0781"'
        if 0 <= value <= 9999:
            # Four decimal digits are also four hex digits: say what was probably meant.
            written = f'"0x{value:04d}"'
        raise ValueError(
            f"vendor and product ids must be hexadecimal strings, not bare numbers: the"
            f" number {value} is not the id 0x{value}, so a rule written that way would"
            f" silently never match; write it as {written}"
        )
    raise ValueError(
        f'expected a string of up to 4 hexadecimal digits such as "0x0781", got {_show(value)}'
    )


def _interface_class(value: Any) -> int:
    return _hex_number(value, "an interface class", 0xFF, "0x08")


def _category(value: Any) -> DeviceCategory:
    return _enum_member(value, DeviceCategory, "a category")


def _weekday(value: Any) -> int:
    name = value.strip().lower() if isinstance(value, str) else None
    if name not in WEEKDAYS:
        raise ValueError(f"expected a day ({', '.join(WEEKDAYS)}), got {_show(value)}")
    return WEEKDAYS.index(name)


def _items(
    value: Any, location: str, problems: _Problems, convert: Callable[[Any], _T]
) -> tuple[_T, ...]:
    """Convert one value or a list of values, reporting each bad element where it is."""
    if isinstance(value, list | tuple):
        if not value:
            problems.add(
                location,
                "an empty list can never match; remove the criterion or give a value",
            )
            return ()
        if len(value) > MAX_LIST_ITEMS:
            problems.add(location, f"too many values ({len(value)}; the limit is {MAX_LIST_ITEMS})")
            return ()
        located = [(f"{location}[{index}]", item) for index, item in enumerate(value)]
    else:
        located = [(location, value)]
    converted: list[_T] = []
    for where, item in located:
        try:
            converted.append(convert(item))
        except ValueError as exc:
            problems.add(where, str(exc))
    return tuple(converted)


def _flag(value: Any, location: str, problems: _Problems) -> bool:
    if not isinstance(value, bool):
        problems.add(location, f"expected true or false, got {_show(value)}")
        return False
    return value


def _clock_time(value: Any) -> dt.time:
    """``"HH:MM"`` (or a TOML local time with no seconds) as a time of day."""
    if isinstance(value, dt.time):
        if value.tzinfo is not None or value.second or value.microsecond:
            raise ValueError("expected a time of day to the minute, without a time zone")
        return value
    found = _CLOCK_PATTERN.match(value) if isinstance(value, str) else None
    if found is None:
        raise ValueError(f'expected a time of day as "HH:MM" (00:00 to 23:59), got {_show(value)}')
    return dt.time(int(found.group(1)), int(found.group(2)))


def _parse_time(value: Any, location: str, problems: _Problems) -> TimeWindow | None:
    data = _object(value, location, _TIME_KEYS, problems)
    if data is None:
        return None
    before = problems.count
    fields: dict[str, Any] = {}
    if "days" in data:
        fields["days"] = _items(data["days"], _join(location, "days"), problems, _weekday)
    if ("start" in data) != ("end" in data):
        problems.add(location, "start and end must be given together, or both left out")
    for name in ("start", "end"):
        if name in data:
            try:
                fields[name] = _clock_time(data[name])
            except ValueError as exc:
                problems.add(_join(location, name), str(exc))
    if "utc_offset_minutes" in data:
        offset = data["utc_offset_minutes"]
        if isinstance(offset, bool) or not isinstance(offset, int):
            problems.add(
                _join(location, "utc_offset_minutes"),
                f"expected an integer number of minutes, got {_show(offset)}",
            )
        else:
            fields["utc_offset_minutes"] = offset
    if problems.count != before:
        return None
    try:
        return TimeWindow(**fields)
    except ValueError as exc:
        problems.add(location, str(exc))
        return None


def _parse_match(value: Any, location: str, problems: _Problems) -> Match | None:
    data = _object(value, location, _MATCH_KEYS, problems)
    if data is None:
        return None
    before = problems.count
    fields: dict[str, Any] = {}
    converters: tuple[tuple[str, Callable[[Any], Any]], ...] = (
        ("vendor_id", _vendor_or_product),
        ("product_id", _vendor_or_product),
        ("serial", check_glob),
        ("fingerprint", check_fingerprint),
        ("manufacturer", check_glob),
        ("product", check_glob),
        ("category", _category),
        ("interface_class", _interface_class),
        ("bus_path", check_bus_path),
    )
    for name, convert in converters:
        if name in data:
            fields[name] = _items(data[name], _join(location, name), problems, convert)
    if "confidence" in data:
        try:
            fields["confidence"] = _enum_member(data["confidence"], Confidence, "a confidence")
        except ValueError as exc:
            problems.add(_join(location, "confidence"), str(exc))
    for name in _FLAG_KEYS:
        if name in data:
            fields[name] = _flag(data[name], _join(location, name), problems)
    if "time" in data:
        fields["time"] = _parse_time(data["time"], _join(location, "time"), problems)
    if problems.count != before:
        return None
    try:
        return Match(**fields)
    except ValueError as exc:
        problems.add(location, str(exc))
        return None


def _parse_action(value: Any, location: str, problems: _Problems) -> RuleAction | None:
    data = _object(value, location, _ACTION_KEYS, problems)
    if data is None:
        return None
    before = problems.count
    access: Access | None = None
    scan = ScanRequirement.NONE
    alert = False
    if "access" not in data:
        problems.add(
            _join(location, "access"),
            f"required ({', '.join(member.value for member in Access)})",
        )
    else:
        try:
            access = _enum_member(data["access"], Access, "an access")
        except ValueError as exc:
            problems.add(_join(location, "access"), str(exc))
    if "scan" in data:
        try:
            scan = _enum_member(data["scan"], ScanRequirement, "a scan requirement")
        except ValueError as exc:
            problems.add(_join(location, "scan"), str(exc))
    if "alert" in data:
        alert = _flag(data["alert"], _join(location, "alert"), problems)
    if problems.count != before or access is None:
        return None
    return RuleAction(access=access, scan=scan, alert=alert)


def _parse_expires(value: Any, location: str, problems: _Problems) -> dt.datetime | None:
    if value is None:
        return None
    # TOML has a native date-time type; accept it when it says which zone it is in.
    if isinstance(value, dt.datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            problems.add(location, "a date-time must say its UTC offset, for example ...Z")
            return None
        return value.astimezone(dt.UTC)
    try:
        return parse_utc_iso(value)
    except ValueError:
        problems.add(
            location,
            f'expected null or a UTC timestamp such as "2026-06-01T12:00:00Z", got {_show(value)}',
        )
        return None


def _parse_rule(value: Any, location: str, problems: _Problems) -> Rule | None:
    data = _object(value, location, _RULE_KEYS, problems)
    if data is None:
        return None
    before = problems.count
    fields: dict[str, Any] = {}
    if "id" not in data:
        problems.add(_join(location, "id"), "required")
    else:
        try:
            fields["id"] = check_rule_id(data["id"])
        except ValueError as exc:
            problems.add(_join(location, "id"), str(exc))
    if "description" in data:
        try:
            fields["description"] = check_text(
                data["description"], "a description", max_length=MAX_DESCRIPTION_LENGTH
            )
        except ValueError as exc:
            problems.add(_join(location, "description"), str(exc))
    if "enabled" in data:
        fields["enabled"] = _flag(data["enabled"], _join(location, "enabled"), problems)
    if "expires" in data:
        fields["expires"] = _parse_expires(data["expires"], _join(location, "expires"), problems)
    if "match" not in data:
        problems.add(_join(location, "match"), "required")
    else:
        fields["match"] = _parse_match(data["match"], _join(location, "match"), problems)
    if "action" not in data:
        problems.add(_join(location, "action"), "required")
    else:
        fields["action"] = _parse_action(data["action"], _join(location, "action"), problems)
    if problems.count != before:
        return None
    try:
        return Rule(**fields)
    except ValueError as exc:
        # The only fault left for the model to find is one that spans fields: a match
        # with no criteria.
        problems.add(_join(location, "match"), str(exc))
        return None


def _parse_rules(value: Any, problems: _Problems) -> tuple[Rule, ...]:
    if not isinstance(value, list | tuple):
        problems.add("rules", f"expected a list, got {_kind(value)}")
        return ()
    if len(value) > MAX_RULES:
        # Refuse before looking inside: validating an unbounded list is the work a
        # hostile document wants done.
        problems.add("rules", f"too many rules ({len(value)}; the limit is {MAX_RULES})")
        return ()
    rules: list[Rule] = []
    first_use: dict[str, int] = {}
    for index, item in enumerate(value):
        location = f"rules[{index}]"
        rule = _parse_rule(item, location, problems)
        raw_id = item.get("id") if isinstance(item, Mapping) else None
        if isinstance(raw_id, str):
            key = raw_id.casefold()
            if key in first_use:
                problems.add(
                    f"{location}.id",
                    f"duplicate rule id {_show(raw_id)} (already used by"
                    f" rules[{first_use[key]}]); ids differing only in case count as the same",
                )
            else:
                first_use[key] = index
        if rule is not None:
            rules.append(rule)
    return tuple(rules)


def _parse_scan(value: Any, problems: _Problems) -> ScanPolicy | None:
    data = _object(value, "scan", _SCAN_KEYS, problems)
    if data is None:
        return None
    before = problems.count
    fields: dict[str, Any] = {}
    for name, enum_type, what in (
        ("on_detection", DetectionAction, "a detection action"),
        ("on_incomplete", IncompleteAction, "an incomplete-scan action"),
    ):
        if name in data:
            try:
                fields[name] = _enum_member(data[name], enum_type, what)
            except ValueError as exc:
                problems.add(f"scan.{name}", str(exc))
    if problems.count != before:
        return None
    return ScanPolicy(**fields)


def parse_policy(data: Mapping[str, Any]) -> Policy:
    """Validate a policy document and build the :class:`~portlock.policy.model.Policy`.

    Only ``version`` is required. A missing ``default`` means ``pending``, missing
    ``rules`` means none, and a missing ``scan`` means detections deny and a required
    scan that does not finish leaves the device read-only (docs/DESIGN.md, section
    14.9). Vendor and product ids must be hexadecimal strings; a bare number is refused
    because it would be read as decimal and silently never match.

    Args:
        data: the parsed document (the result of ``json.loads`` or ``tomllib.loads``).

    Returns:
        The validated policy.

    Raises:
        PolicyError: if anything is wrong. ``problems`` lists every fault found, each as
            ``location: message``; at most :data:`MAX_PROBLEMS` are listed.
    """
    problems = _Problems()
    fields: dict[str, Any] = {}
    document = _object(data, "", _POLICY_KEYS, problems)
    if document is not None:
        if "version" not in document:
            problems.add("version", f"required (this PortLock reads version {POLICY_VERSION})")
        else:
            version = document["version"]
            if isinstance(version, bool) or not isinstance(version, int):
                problems.add("version", f"expected an integer, got {_show(version)}")
            elif version != POLICY_VERSION:
                problems.add(
                    "version",
                    f"unsupported policy version {_show(version)}; this PortLock reads"
                    f" version {POLICY_VERSION}",
                )
        if "name" in document:
            try:
                fields["name"] = check_text(
                    document["name"], "a policy name", max_length=MAX_NAME_LENGTH
                )
            except ValueError as exc:
                problems.add("name", str(exc))
        if "default" in document:
            fields["default"] = _parse_action(document["default"], "default", problems)
        if "rules" in document:
            fields["rules"] = _parse_rules(document["rules"], problems)
        if "scan" in document:
            fields["scan"] = _parse_scan(document["scan"], problems)
    if problems.count:
        listed = problems.as_tuple()
        noun = "problem" if problems.count == 1 else "problems"
        raise PolicyError(
            f"the policy is invalid ({problems.count} {noun}); first: {listed[0]}",
            problems=listed,
        )
    return Policy(**fields)


def _reject_constant(literal: str) -> Any:
    raise ValueError(f"{literal} is not valid JSON")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing a key given twice.

    JSON parsers disagree on which of two duplicate keys wins, so a document with
    ``"access"`` given twice would mean different things to different tools.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"key {_show(key)} is given more than once in the same object")
        result[key] = value
    return result


def _file_error(message: str) -> PolicyError:
    return PolicyError(message, problems=(message,))


def load_policy_file(path: str | os.PathLike[str]) -> Policy:
    """Read and validate a policy from a ``.json`` or ``.toml`` file.

    The file must be UTF-8 (a byte-order mark is tolerated) and no larger than
    :data:`MAX_POLICY_FILE_BYTES`. In JSON, a key given twice in one object is an error.

    Raises:
        StoreError: if the file cannot be read.
        PolicyError: if the file type is not supported, the file is too large, is not
            well-formed, or does not hold a valid policy.
    """
    target = Path(path)
    suffix = target.suffix.lower()
    if suffix not in (".json", ".toml"):
        raise _file_error(
            f"unsupported policy file type {suffix!r}: a policy is a .json or .toml file"
        )
    try:
        with target.open("rb") as stream:
            raw = stream.read(MAX_POLICY_FILE_BYTES + 1)
    except OSError as exc:
        raise StoreError(f"cannot read policy file {target}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise _file_error(f"policy file {target.name} is larger than {MAX_POLICY_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
        if suffix == ".json":
            data = json.loads(
                text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
            )
        else:
            data = tomllib.loads(text)
    except (ValueError, RecursionError) as exc:
        # UnicodeDecodeError, json.JSONDecodeError and tomllib.TOMLDecodeError are all
        # ValueErrors; RecursionError is what absurdly deep nesting produces.
        kind = "JSON" if suffix == ".json" else "TOML"
        detail = str(exc) if isinstance(exc, ValueError) else "nesting is too deep"
        raise _file_error(f"policy file {target.name} is not well-formed {kind}: {detail}") from exc
    return parse_policy(data)


def _hex(value: int, digits: int) -> str:
    return f"0x{value:0{digits}x}"


def _match_to_dict(match: Match) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for name in match.criteria:
        value = getattr(match, name)
        if name in ("vendor_id", "product_id"):
            data[name] = [_hex(item, 4) for item in value]
        elif name == "interface_class":
            data[name] = [_hex(item, 2) for item in value]
        elif name == "category":
            data[name] = [item.value for item in value]
        elif name == "confidence":
            data[name] = value.value
        elif name == "time":
            data[name] = {
                "days": [WEEKDAYS[day] for day in value.days],
                "start": f"{value.start:%H:%M}",
                "end": f"{value.end:%H:%M}",
                "utc_offset_minutes": value.utc_offset_minutes,
            }
        elif isinstance(value, bool):
            data[name] = value
        else:
            data[name] = list(value)
    return data


def _action_to_dict(action: RuleAction) -> dict[str, Any]:
    return {"access": action.access.value, "scan": action.scan.value, "alert": action.alert}


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Render a policy as a document that :func:`parse_policy` reads back unchanged.

    The output is in one fixed form whatever the input looked like: every optional key
    is written out, keys are in a fixed order, list-valued criteria are always lists,
    vendor ids, product ids and interface classes are ``0x``-prefixed lowercase
    hexadecimal strings, and timestamps are UTC. Two equal policies therefore always
    produce the same document.
    """
    return {
        "version": policy.version,
        "name": policy.name,
        "default": _action_to_dict(policy.default),
        "rules": [
            {
                "id": rule.id,
                "description": rule.description,
                "enabled": rule.enabled,
                "expires": utc_iso(rule.expires) if rule.expires is not None else None,
                "match": _match_to_dict(rule.match),
                "action": _action_to_dict(rule.action),
            }
            for rule in policy.rules
        ],
        "scan": {
            "on_detection": policy.scan.on_detection.value,
            "on_incomplete": policy.scan.on_incomplete.value,
        },
    }


def dump_policy_json(policy: Policy) -> str:
    """Render a policy as indented JSON text ending in a newline.

    The text is stable: the same policy always gives the same characters, so policy
    files can be compared and kept under version control.
    """
    return json.dumps(policy_to_dict(policy), indent=2, ensure_ascii=False) + "\n"


def save_policy(path: str | os.PathLike[str], policy: Policy) -> None:
    """Write a policy to a ``.json`` file, atomically.

    A reader sees the previous file or the new one, never part of each, and a crash
    midway leaves the previous file in place. The file is restricted to its owner.

    Raises:
        PolicyError: if ``path`` does not end in ``.json`` (PortLock reads TOML but
            writes only JSON).
        StoreError: if the file cannot be written.
    """
    target = Path(path)
    if target.suffix.lower() != ".json":
        raise _file_error(f"policies are saved as .json files, not {target.suffix!r}")
    try:
        atomic_write_text(target, dump_policy_json(policy))
    except OSError as exc:
        raise StoreError(f"cannot write policy file {target}: {exc.strerror or exc}") from exc


def policy_hash(policy: Policy) -> str:
    """The hex SHA-256 of the policy's canonical JSON.

    Audit records carry this for the policy in force and, on a change, for the old and
    the new policy. It depends only on the policy's content, not on how the file it came
    from was laid out.
    """
    return hashlib.sha256(canonical_bytes(policy_to_dict(policy))).hexdigest()
