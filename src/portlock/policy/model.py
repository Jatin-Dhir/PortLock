"""The policy model: immutable values describing what an administrator wants.

A :class:`Policy` is an ordered list of :class:`Rule` values and a default
:class:`RuleAction`. Each rule pairs a :class:`Match` (which devices) with an action (what
they may do). Nothing here evaluates anything against a device; that is
``portlock.policy.engine``. Nothing here reads a file; that is ``portlock.policy.loader``.

Every value validates itself on construction and raises :class:`ValueError`, so a policy
built in code is held to the same limits as one loaded from a document. The limits exist
so that a hostile or broken document cannot make evaluation expensive: the number of
rules, the size of every list and the length and wildcard count of every pattern are
bounded.
"""

from __future__ import annotations

import datetime as dt
import enum
import fnmatch
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from typing import Any

from portlock.core.models import Access, Confidence, DeviceCategory, ScanRequirement

__all__ = [
    "ALL_DAYS",
    "BUS_PATH_SEPARATORS",
    "MAX_DESCRIPTION_LENGTH",
    "MAX_ID_LENGTH",
    "MAX_LIST_ITEMS",
    "MAX_NAME_LENGTH",
    "MAX_PATTERN_LENGTH",
    "MAX_PATTERN_WILDCARDS",
    "MAX_RULES",
    "MAX_UTC_OFFSET_MINUTES",
    "MIN_UTC_OFFSET_MINUTES",
    "POLICY_VERSION",
    "WEEKDAYS",
    "DetectionAction",
    "IncompleteAction",
    "Match",
    "Policy",
    "Rule",
    "RuleAction",
    "ScanPolicy",
    "TimeWindow",
    "check_bus_path",
    "check_fingerprint",
    "check_glob",
    "check_rule_id",
    "check_text",
    "check_usb_number",
    "compile_glob",
    "normalize_text",
    "require_aware",
    "split_bus_path",
]

#: The only policy document version this code reads and writes.
POLICY_VERSION = 1

#: Most rules one policy may hold.
MAX_RULES = 2000
#: Most values one list-valued criterion may hold.
MAX_LIST_ITEMS = 64
MAX_ID_LENGTH = 64
MAX_NAME_LENGTH = 128
MAX_DESCRIPTION_LENGTH = 512
#: Longest glob pattern, in characters, before and after normalization.
MAX_PATTERN_LENGTH = 128
#: Most wildcards (``*``, ``?`` and ``[``) one pattern may contain.
MAX_PATTERN_WILDCARDS = 16

#: UTC-12:00 and UTC+14:00, the extremes in use anywhere.
MIN_UTC_OFFSET_MINUTES = -12 * 60
MAX_UTC_OFFSET_MINUTES = 14 * 60

#: Weekday names as written in policy documents; the index is ``datetime.weekday()``.
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)

_MIDNIGHT = dt.time(0, 0)
_RULE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_FINGERPRINT_PATTERN = re.compile(r"plk1:([a-z2-7]{32})\Z", re.IGNORECASE)
_WILDCARDS = frozenset("*?[")

#: What separates the segments of a bus path: ``.`` between the hub ports of a Linux
#: path (``1-2.3``), ``#`` between the elements of a Windows location path
#: (``PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)``).
BUS_PATH_SEPARATORS = ".#"
_BUS_PATH_SPLIT = re.compile("[" + re.escape(BUS_PATH_SEPARATORS) + "]")


class DetectionAction(enum.StrEnum):
    """What a scan detection does to a device that was given access."""

    #: Block the device.
    DENY = "deny"
    #: Leave the device readable but stop writes to it.
    READ_ONLY = "read_only"
    #: Leave access as decided and raise an alert.
    ALERT = "alert"


class IncompleteAction(enum.StrEnum):
    """What a ``required`` scan that did not finish, or failed, leaves a device with.

    Either way an alert is raised (docs/DESIGN.md, section 14.9).
    """

    #: Keep the device read-only, as it was while the scan ran.
    READ_ONLY = "read_only"
    #: Block the device.
    DENY = "deny"


def require_aware(value: dt.datetime, what: str = "time") -> dt.datetime:
    """Return ``value`` converted to UTC, refusing anything that is not an aware datetime.

    Raises:
        ValueError: if ``value`` is not a timezone-aware :class:`datetime.datetime`.
    """
    if not isinstance(value, dt.datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{what} must be a timezone-aware datetime")
    return value.astimezone(dt.UTC)


def normalize_text(value: str) -> str:
    """Put a device string or a pattern into the form that matching compares.

    Unicode compatibility forms are folded (NFKC), control and invisible format
    characters are dropped, runs of whitespace become one space, the ends are trimmed and
    case is folded. A device therefore cannot dodge a pattern with a zero-width space, a
    full-width letter or a change of case.
    """
    kept: list[str] = []
    for char in unicodedata.normalize("NFKC", value):
        if char.isspace():
            kept.append(" ")
        elif not unicodedata.category(char).startswith("C"):
            kept.append(char)
    return " ".join("".join(kept).split()).casefold()


def check_text(value: Any, what: str, *, max_length: int, allow_empty: bool = True) -> str:
    """Validate free text such as a policy name or a rule description.

    Returns:
        The text unchanged.

    Raises:
        ValueError: if it is not a string, is too long, is empty where that is not
            allowed, or contains control characters or unpaired surrogates.
    """
    if not isinstance(value, str):
        raise ValueError(f"{what} must be a string")
    if len(value) > max_length:
        raise ValueError(f"{what} is too long ({len(value)} characters; the limit is {max_length})")
    if not allow_empty and not value.strip():
        raise ValueError(f"{what} must not be empty")
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in value):
        raise ValueError(f"{what} must not contain control characters")
    return value


def check_rule_id(value: Any) -> str:
    """Validate a rule id: 1 to 64 of ``A-Z a-z 0-9 . _ -``, starting with a letter or digit.

    Raises:
        ValueError: if the id does not have that form.
    """
    if not isinstance(value, str):
        raise ValueError("a rule id must be a string")
    if len(value) > MAX_ID_LENGTH:
        raise ValueError(
            f"a rule id is too long ({len(value)} characters; the limit is {MAX_ID_LENGTH})"
        )
    if not _RULE_ID_PATTERN.match(value):
        raise ValueError(
            "a rule id must start with a letter or digit and contain only letters, digits,"
            " '.', '_' and '-'"
        )
    return value


def check_usb_number(value: Any, what: str, upper: int) -> int:
    """Validate a vendor id, product id or interface class as an integer in ``0..upper``.

    Raises:
        ValueError: if it is not an integer (booleans are refused) or is out of range.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= upper:
        raise ValueError(f"{what} must be an integer between 0 and {upper:#x}")
    return value


def check_fingerprint(value: Any) -> str:
    """Validate a fingerprint value and return it in canonical spelling.

    A fingerprint criterion is compared exactly; it is not a pattern. The spelling is
    normalized to the lowercase form ``portlock.core.fingerprint`` produces, because
    base32 is case-insensitive and operators paste and retype these by hand.

    Raises:
        ValueError: if it is not ``plk1:`` followed by 32 base32 characters.
    """
    found = _FINGERPRINT_PATTERN.match(value) if isinstance(value, str) else None
    if found is None:
        raise ValueError(
            "a fingerprint is 'plk1:' followed by 32 base32 characters (a-z, 2-7);"
            " wildcards are not accepted"
        )
    return "plk1:" + found.group(1).lower()


def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a glob into a regular expression over normalized text.

    The syntax is that of :mod:`fnmatch`: ``*`` matches any run of characters (including
    none), ``?`` matches exactly one, ``[abc]`` and ``[a-z]`` match one listed character
    and ``[!abc]`` one that is not listed. There is no escape character; write ``[*]`` to
    match a literal asterisk. The whole string must match.

    The pattern is normalized with :func:`normalize_text` first, and the expression is
    built by :func:`fnmatch.translate` rather than matched with :func:`fnmatch.fnmatch`,
    which would apply the host platform's path rules and make ``/`` and ``\\`` equivalent
    on Windows only.

    Raises:
        ValueError: if the pattern cannot be compiled.
    """
    try:
        return re.compile(fnmatch.translate(normalize_text(pattern)))
    except (re.error, RecursionError, OverflowError) as exc:
        raise ValueError(f"not a usable pattern: {exc}") from exc


def check_glob(value: Any) -> str:
    """Validate a glob pattern and return it with surrounding whitespace removed.

    Raises:
        ValueError: if it is not a string, is empty, is longer than
            :data:`MAX_PATTERN_LENGTH`, contains control characters, holds more than
            :data:`MAX_PATTERN_WILDCARDS` wildcards, or cannot be compiled.
    """
    if not isinstance(value, str):
        raise ValueError("a pattern must be a string")
    if len(value) > MAX_PATTERN_LENGTH:
        raise ValueError(
            f"a pattern is too long ({len(value)} characters; the limit is {MAX_PATTERN_LENGTH})"
        )
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in value):
        raise ValueError("a pattern must not contain control characters")
    normalized = normalize_text(value)
    if not normalized:
        raise ValueError("a pattern must not be empty")
    # Compatibility folding can lengthen text and can turn a full-width asterisk into a
    # real wildcard, so the limits are applied to what will actually be compiled.
    if len(normalized) > MAX_PATTERN_LENGTH:
        raise ValueError(
            f"a pattern is too long once normalized ({len(normalized)} characters; the"
            f" limit is {MAX_PATTERN_LENGTH})"
        )
    wildcards = sum(1 for char in normalized if char in _WILDCARDS)
    if wildcards > MAX_PATTERN_WILDCARDS:
        raise ValueError(
            f"a pattern has too many wildcards ({wildcards}; the limit is {MAX_PATTERN_WILDCARDS})"
        )
    compile_glob(value)
    return value.strip()


def split_bus_path(value: str) -> tuple[str, ...]:
    """Split a bus path, or a bus path pattern, into its segments.

    ``1-2.3`` is ``("1-2", "3")``; ``PCIROOT(0)#USBROOT(0)#USB(2)`` is
    ``("PCIROOT(0)", "USBROOT(0)", "USB(2)")``. See :data:`BUS_PATH_SEPARATORS`.
    """
    return tuple(_BUS_PATH_SPLIT.split(value))


def check_bus_path(value: Any) -> str:
    """Validate a bus path pattern: a glob (see :func:`check_glob`) with no empty segment.

    A bus path pattern is matched segment by segment (see :class:`Match`), so a
    separator at either end or two in a row would name a segment that no port has.

    Raises:
        ValueError: if the pattern is not a valid glob or has an empty segment.
    """
    pattern = check_glob(value)
    if any(not segment.strip() for segment in split_bus_path(pattern)):
        raise ValueError(
            "a bus path pattern must not start or end with '.' or '#', or have two in a row"
        )
    return pattern


def _check_flag(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be true or false")
    return value


def _as_tuple(value: Any) -> tuple[Any, ...]:
    """One value or many: a string or other scalar becomes a one-element tuple."""
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        return (value,)
    return tuple(value)


def _check_category(value: Any) -> DeviceCategory:
    if not isinstance(value, DeviceCategory):
        raise ValueError("a category must be a DeviceCategory")
    return value


def _check_vendor_or_product(value: Any) -> int:
    return check_usb_number(value, "a vendor or product id", 0xFFFF)


def _check_interface_class(value: Any) -> int:
    return check_usb_number(value, "an interface class", 0xFF)


@dataclass(frozen=True, slots=True)
class RuleAction:
    """What a rule (or the policy default) does with a device.

    Attributes:
        access: allow, read-only, deny, or pending (blocked until an administrator
            decides).
        scan: whether the device's volumes are scanned once access has been granted.
            ``on_mount`` scans after access is given, and a detection can take it
            away. ``required`` admits the device read-only, scans every volume, and
            applies the decided access only on a clean verdict; a scan that does not
            finish, or fails, leaves it read-only (or denied, by
            :attr:`ScanPolicy.on_incomplete`) and raises an alert (docs/DESIGN.md,
            section 14.9). A grant never removes a scan requirement.
        alert: raise an alert whenever this action is the one that applies.
    """

    access: Access
    scan: ScanRequirement = ScanRequirement.NONE
    alert: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.access, Access):
            raise ValueError("access must be an Access value")
        if not isinstance(self.scan, ScanRequirement):
            raise ValueError("scan must be a ScanRequirement value")
        _check_flag(self.alert, "alert")


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    """Policy-wide scan settings.

    Attributes:
        on_detection: what a scan detection does to a device that was given access.
            The default is the protective one.
        on_incomplete: what a ``required`` scan that did not finish or failed leaves
            the device with: read-only (the default, docs/DESIGN.md section 14.9) or
            denied. An alert is raised either way.
    """

    on_detection: DetectionAction = DetectionAction.DENY
    on_incomplete: IncompleteAction = IncompleteAction.READ_ONLY

    def __post_init__(self) -> None:
        if not isinstance(self.on_detection, DetectionAction):
            raise ValueError("on_detection must be a DetectionAction value")
        if not isinstance(self.on_incomplete, IncompleteAction):
            raise ValueError("on_incomplete must be an IncompleteAction value")


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """A weekly schedule: some days of the week, between two times of day.

    The window is evaluated in a fixed offset from UTC, not in a named time zone, so it
    does not follow daylight-saving changes; the standard library has no time-zone
    database on Windows and PortLock takes no dependencies.

    Attributes:
        days: the weekdays on which the window *opens*, as ``datetime.weekday()`` numbers
            (Monday is 0). Stored sorted and without duplicates.
        start: local time of day at which the window opens (inclusive), to the minute.
        end: local time of day at which it closes (exclusive). If ``end`` is not after
            ``start`` the window runs past midnight into the following day, and that
            tail belongs to the day on which the window opened: ``days=(4,)``,
            ``22:00`` to ``06:00`` covers Friday night until Saturday 06:00. Equal
            ``start`` and ``end`` mean a full 24 hours from ``start``.
        utc_offset_minutes: local time minus UTC, in minutes.

    A window that is open for the whole week is refused: it would always match, which is
    what leaving the criterion out already means.
    """

    days: tuple[int, ...] = ALL_DAYS
    start: dt.time = _MIDNIGHT
    end: dt.time = _MIDNIGHT
    utc_offset_minutes: int = 0

    def __post_init__(self) -> None:
        days = _as_tuple(self.days)
        if not days:
            raise ValueError("a time window must list at least one day")
        for day in days:
            if isinstance(day, bool) or not isinstance(day, int) or not 0 <= day <= 6:
                raise ValueError("days must be weekday numbers from 0 (Monday) to 6 (Sunday)")
        object.__setattr__(self, "days", tuple(sorted(set(days))))
        for name in ("start", "end"):
            value = getattr(self, name)
            if not isinstance(value, dt.time) or value.tzinfo is not None:
                raise ValueError(f"{name} must be a time of day without a time zone")
            if value.second or value.microsecond:
                raise ValueError(f"{name} must be a whole minute")
        offset = self.utc_offset_minutes
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not MIN_UTC_OFFSET_MINUTES <= offset <= MAX_UTC_OFFSET_MINUTES
        ):
            raise ValueError(
                f"utc_offset_minutes must be an integer between {MIN_UTC_OFFSET_MINUTES}"
                f" and {MAX_UTC_OFFSET_MINUTES}"
            )
        if len(self.days) == 7 and self.start == self.end:
            raise ValueError(
                "a time window open all day on every day always matches; remove it or"
                " narrow the days or the hours"
            )

    @property
    def tzinfo(self) -> dt.timezone:
        """The fixed-offset zone in which ``start`` and ``end`` are read."""
        return dt.timezone(dt.timedelta(minutes=self.utc_offset_minutes))

    def contains(self, moment: dt.datetime) -> bool:
        """Whether the window is open at ``moment``.

        Raises:
            ValueError: if ``moment`` is not timezone-aware.
        """
        local = require_aware(moment, "the evaluation time").astimezone(self.tzinfo)
        time_of_day = local.time()
        today = local.weekday()
        if self.start < self.end:
            return today in self.days and self.start <= time_of_day < self.end
        # The window runs past midnight: before `end` we are in the tail of the window
        # that opened yesterday, from `start` on we are in the one that opened today.
        if time_of_day >= self.start:
            return today in self.days
        if time_of_day < self.end:
            return (today - 1) % 7 in self.days
        return False

    def next_change(self, moment: dt.datetime) -> dt.datetime:
        """The first instant after ``moment`` at which the window opens or closes.

        Used to tell the caller when a decision that depends on this window has to be
        re-evaluated.

        Returns:
            A UTC datetime strictly later than ``moment``.

        Raises:
            ValueError: if ``moment`` is not timezone-aware.
        """
        local = require_aware(moment, "the evaluation time").astimezone(self.tzinfo)
        state = self.contains(local)
        midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
        boundaries = sorted(
            {
                midnight + dt.timedelta(days=day, hours=edge.hour, minutes=edge.minute)
                for day in range(9)
                for edge in (self.start, self.end)
            }
        )
        # The schedule repeats weekly and is never open (or closed) for a whole week, so
        # one of the boundaries in the coming eight days is a change of state.
        return next(
            boundary.astimezone(dt.UTC)
            for boundary in boundaries
            if boundary > local and self.contains(boundary) != state
        )


#: The criteria that take ``True`` or ``False``, in field order.
_FLAG_CRITERIA = (
    "composite",
    "storage_with_input",
    "mixes_input_with_other",
    "storage_like",
    "removable",
)


@dataclass(frozen=True, slots=True, kw_only=True)
class Match:
    """Which devices a rule applies to.

    Every criterion is optional. A device matches when **all** criteria that are present
    match. A list-valued criterion matches when **any** of its values matches (it is an
    "any of" list, never "all of"): ``category=(KEYBOARD, STORAGE)`` matches a keyboard,
    a flash drive and a device that is both. A single value may be given wherever a list
    is accepted.

    Attributes:
        vendor_id / product_id: ``idVendor`` / ``idProduct`` values.
        serial / manufacturer / product: glob patterns (see :func:`compile_glob`)
            compared, case-insensitively, with the normalized device string. A device
            that does not report the string never matches.
        bus_path: port patterns, compared segment by segment (see
            :data:`BUS_PATH_SEPARATORS`). A pattern names a port and matches a device
            on that port or anywhere behind it, through hubs: ``1-2`` matches ``1-2``,
            ``1-2.4`` and ``1-2.4.1`` but not ``1-21``. A wildcard stays inside its
            segment: ``1-*`` matches every port of bus 1 and what is behind them,
            ``1-2.*`` everything behind port ``1-2`` but not ``1-2`` itself.
        fingerprint: exact fingerprint values (not patterns).
        category: the device declares at least one of these functions.
        interface_class: at least one of the device's interfaces has one of these class
            codes (the device class is used for a device that reports no interfaces).
        confidence: the fingerprint's confidence is exactly this.
        composite: the device does, or does not, declare more than one function.
        storage_with_input: the device does, or does not, pair storage with an input
            interface (the "BadUSB" stick).
        mixes_input_with_other: the device does, or does not, put an input interface
            beside any other function, hubs aside (storage, network, serial, vendor
            and so on): the shape of a "BadUSB" stick or a network-tap implant. A
            superset of ``storage_with_input``.
        storage_like: the device is, or is not, mass storage or an imaging device (a
            phone or camera in MTP or PTP mode), the two kinds that carry files.
        removable: the device is, or is not, on an external port. A device whose
            platform does not say matches neither ``True`` nor ``False``.
        time: the evaluation time falls inside this weekly window.
    """

    vendor_id: tuple[int, ...] | None = None
    product_id: tuple[int, ...] | None = None
    serial: tuple[str, ...] | None = None
    fingerprint: tuple[str, ...] | None = None
    manufacturer: tuple[str, ...] | None = None
    product: tuple[str, ...] | None = None
    category: tuple[DeviceCategory, ...] | None = None
    interface_class: tuple[int, ...] | None = None
    confidence: Confidence | None = None
    composite: bool | None = None
    storage_with_input: bool | None = None
    mixes_input_with_other: bool | None = None
    storage_like: bool | None = None
    removable: bool | None = None
    bus_path: tuple[str, ...] | None = None
    time: TimeWindow | None = None

    def __post_init__(self) -> None:
        for name, check in (
            ("vendor_id", _check_vendor_or_product),
            ("product_id", _check_vendor_or_product),
            ("serial", check_glob),
            ("fingerprint", check_fingerprint),
            ("manufacturer", check_glob),
            ("product", check_glob),
            ("category", _check_category),
            ("interface_class", _check_interface_class),
            ("bus_path", check_bus_path),
        ):
            value = getattr(self, name)
            if value is None:
                continue
            items = _as_tuple(value)
            if not items:
                raise ValueError(f"{name}: an empty list can never match")
            if len(items) > MAX_LIST_ITEMS:
                raise ValueError(
                    f"{name}: too many values ({len(items)}; the limit is {MAX_LIST_ITEMS})"
                )
            try:
                checked = tuple(check(item) for item in items)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            object.__setattr__(self, name, checked)
        if self.confidence is not None and not isinstance(self.confidence, Confidence):
            raise ValueError("confidence must be a Confidence value")
        for name in _FLAG_CRITERIA:
            if getattr(self, name) is not None:
                _check_flag(getattr(self, name), name)
        if self.time is not None and not isinstance(self.time, TimeWindow):
            raise ValueError("time must be a TimeWindow")

    @property
    def criteria(self) -> tuple[str, ...]:
        """Names of the criteria that are present, in document order."""
        return tuple(item.name for item in fields(self) if getattr(self, item.name) is not None)

    @property
    def is_empty(self) -> bool:
        """True if no criterion is present, so every device would match."""
        return not self.criteria


@dataclass(frozen=True, slots=True, kw_only=True)
class Rule:
    """One policy rule.

    Attributes:
        id: unique within the policy; appears in decisions and audit records.
        description: free text for the operator.
        enabled: a disabled rule is skipped as if it were not there.
        expires: from this instant on the rule is skipped. ``None`` means never.
        match: which devices the rule applies to. An empty match is refused: it would
            silently apply to every device, and the policy default exists for that.
        action: what happens to a matching device.
    """

    id: str
    description: str = ""
    enabled: bool = True
    expires: dt.datetime | None = None
    match: Match
    action: RuleAction

    def __post_init__(self) -> None:
        check_rule_id(self.id)
        check_text(self.description, "a description", max_length=MAX_DESCRIPTION_LENGTH)
        _check_flag(self.enabled, "enabled")
        if self.expires is not None:
            object.__setattr__(self, "expires", require_aware(self.expires, "expires"))
        if not isinstance(self.match, Match):
            raise ValueError("match must be a Match")
        if not isinstance(self.action, RuleAction):
            raise ValueError("action must be a RuleAction")
        if self.match.is_empty:
            raise ValueError(
                "a rule must have at least one match criterion; an empty match would apply"
                " to every device, which is what the policy default is for"
            )

    def is_expired(self, now: dt.datetime) -> bool:
        """True once ``now`` has reached ``expires``."""
        return self.expires is not None and now >= self.expires


def _pending() -> RuleAction:
    return RuleAction(Access.PENDING)


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """A complete policy.

    Attributes:
        version: document format version; only :data:`POLICY_VERSION` is supported.
        name: a label for the operator.
        default: the action for a device that no rule matches. Defaults to ``pending``.
        rules: evaluated in order; the first enabled, unexpired, matching rule wins.
        scan: policy-wide scan settings.
    """

    version: int = POLICY_VERSION
    name: str = ""
    default: RuleAction = field(default_factory=_pending)
    rules: tuple[Rule, ...] = ()
    scan: ScanPolicy = field(default_factory=ScanPolicy)

    def __post_init__(self) -> None:
        if (
            isinstance(self.version, bool)
            or not isinstance(self.version, int)
            or self.version != POLICY_VERSION
        ):
            raise ValueError(
                f"unsupported policy version {self.version!r}; this version of PortLock"
                f" reads version {POLICY_VERSION}"
            )
        check_text(self.name, "a policy name", max_length=MAX_NAME_LENGTH)
        if not isinstance(self.default, RuleAction):
            raise ValueError("default must be a RuleAction")
        if not isinstance(self.scan, ScanPolicy):
            raise ValueError("scan must be a ScanPolicy")
        rules = tuple(self.rules)
        if len(rules) > MAX_RULES:
            raise ValueError(f"too many rules ({len(rules)}; the limit is {MAX_RULES})")
        seen: set[str] = set()
        for rule in rules:
            if not isinstance(rule, Rule):
                raise ValueError("rules must be Rule values")
            # Ids that differ only in case would be told apart by the machine and
            # confused by the person reading an audit record.
            key = rule.id.casefold()
            if key in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(key)
        object.__setattr__(self, "rules", rules)

    def rule(self, rule_id: str) -> Rule | None:
        """The rule with this id, or ``None``."""
        wanted = rule_id.casefold()
        return next((rule for rule in self.rules if rule.id.casefold() == wanted), None)
