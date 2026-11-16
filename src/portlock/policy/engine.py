"""Policy evaluation: one device, one policy, one instant in, one result out.

:class:`PolicyEngine` is pure. It reads no clock, no file and no device; given the same
policy, device, fingerprint and time it returns the same result. An engine never changes
after construction, so one instance can be shared between threads.

The engine answers "what does the policy say". Safety, lockdown and grants are combined
with that answer by :func:`portlock.policy.decide.decide`.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from portlock.core.clock import utc_iso
from portlock.core.models import Confidence, DeviceCategory, Fingerprint, UsbDevice
from portlock.policy.model import (
    WEEKDAYS,
    Match,
    Policy,
    Rule,
    RuleAction,
    TimeWindow,
    compile_glob,
    normalize_text,
    require_aware,
    split_bus_path,
)

__all__ = [
    "MAX_SUBJECT_LENGTH",
    "CriterionTrace",
    "PolicyEngine",
    "PolicyResult",
    "RuleOutcome",
    "RuleTrace",
]

#: Device strings are cut to this many characters before they are matched. A USB string
#: descriptor holds at most 126 characters, so only a faulty backend can exceed it; the
#: cut keeps matching time bounded whatever a backend hands over.
MAX_SUBJECT_LENGTH = 1024

_SHOWN_VALUES = 6
_SHOWN_TEXT = 60


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """What a policy says about one device at one instant.

    Attributes:
        action: the action of the winning rule, or the policy default.
        rule: the winning rule, or ``None`` if the default applied.
        matched_default: True if no rule matched and ``action`` is the policy default.
        skipped: ``(rule id, reason)`` for each disabled or expired rule that was passed
            over before the result was reached. Rules after the winning rule are never
            looked at and are not listed.
        explanation: one line per criterion saying why the winning rule matched, or a
            single line saying that the default applied.
        valid_until: the earliest instant at which evaluating the same device again
            could give a different result through the passage of time alone: the winning
            rule expires, its time window closes, or the time window of an earlier rule
            that otherwise matches opens. ``None`` if time alone never changes it.
    """

    action: RuleAction
    rule: Rule | None
    matched_default: bool
    skipped: tuple[tuple[str, str], ...] = ()
    explanation: tuple[str, ...] = ()
    valid_until: datetime | None = None


class RuleOutcome(enum.StrEnum):
    """What happened to one rule during an evaluation."""

    #: The first enabled, unexpired rule that matched: it decided the result.
    MATCHED = "matched"
    #: Matches, but an earlier rule already won.
    SHADOWED = "shadowed"
    NO_MATCH = "no_match"
    DISABLED = "disabled"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class CriterionTrace:
    """One criterion of one rule, tested against one device."""

    criterion: str
    matched: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RuleTrace:
    """One rule's part in an evaluation, for ``portlock policy test``.

    Attributes:
        rule_id: the rule.
        outcome: see :class:`RuleOutcome`.
        would_match: whether every criterion matched, regardless of the rule being
            disabled, expired or shadowed.
        action: the rule's action.
        criteria: every criterion with its result. Unlike :meth:`PolicyEngine.evaluate`,
            the trace does not stop at the first criterion that fails.
        summary: one line a person can read.
    """

    rule_id: str
    outcome: RuleOutcome
    would_match: bool
    action: RuleAction
    criteria: tuple[CriterionTrace, ...]
    summary: str


def _shorten(text: str) -> str:
    """A quoted, length-bounded rendering of device- or operator-supplied text."""
    return repr(text if len(text) <= _SHOWN_TEXT else text[:_SHOWN_TEXT] + "...")


def _listing(values: Sequence[str]) -> str:
    shown = ", ".join(values[:_SHOWN_VALUES])
    hidden = len(values) - _SHOWN_VALUES
    return f"{shown} and {hidden} more" if hidden > 0 else shown


# ``UsbDevice`` replaces every control and format character in a device string with
# U+FFFD before anything else sees it (docs/DESIGN.md, section 14.7).
_REPLACEMENT = chr(0xFFFD)


def _normalize_subject(value: str | None) -> tuple[str, ...] | None:
    """The forms of a device string that patterns are matched against.

    By the time a string reaches the engine, the device model has replaced each control
    or format character in it with U+FFFD, so whether the character was invisible (a
    zero-width space) or a break between words (a tab) can no longer be told. Both
    readings are kept: the replacement removed, and the replacement as a space. A
    pattern that matches either matches the device, so dressing a string up with such
    characters cannot dodge a rule. That gives a device nothing it lacked before: it
    could always have reported the plain string itself.

    Returns:
        One or two distinct normalized forms, or ``None`` if the device reports no
        string (or one made of nothing but whitespace and replaced characters).
    """
    if not isinstance(value, str):
        return None
    cut = value[:MAX_SUBJECT_LENGTH]
    forms = (
        normalize_text(cut.replace(_REPLACEMENT, ""))[:MAX_SUBJECT_LENGTH],
        normalize_text(cut.replace(_REPLACEMENT, " "))[:MAX_SUBJECT_LENGTH],
    )
    distinct = tuple(dict.fromkeys(form for form in forms if form))
    return distinct or None


def _normalize_bus_path(value: str | None) -> str | None:
    """A device's bus path ready for matching, or ``None`` if it has none."""
    if not isinstance(value, str):
        return None
    normalized = normalize_text(value[:MAX_SUBJECT_LENGTH].replace(_REPLACEMENT, ""))
    return normalized or None


class _Subject:
    """The facts about one device that criteria look at, normalized once."""

    __slots__ = (
        "bus_path",
        "categories",
        "composite",
        "confidence",
        "fingerprint",
        "interface_classes",
        "manufacturer",
        "mixes_input_with_other",
        "product",
        "product_id",
        "removable",
        "serial",
        "storage_like",
        "storage_with_input",
        "vendor_id",
    )

    def __init__(self, device: UsbDevice, fingerprint: Fingerprint) -> None:
        self.vendor_id: int = device.vendor_id
        self.product_id: int = device.product_id
        self.serial = _normalize_subject(device.serial)
        self.manufacturer = _normalize_subject(device.manufacturer)
        self.product = _normalize_subject(device.product)
        self.bus_path = _normalize_bus_path(device.bus_path)
        self.fingerprint: str = fingerprint.value.casefold()
        self.confidence: Confidence = fingerprint.confidence
        self.categories: frozenset[DeviceCategory] = device.categories
        # Like `categories`, fall back to the device class when no interface is known.
        self.interface_classes: frozenset[int] = (
            frozenset(interface.cls for interface in device.interfaces)
            if device.interfaces
            else frozenset({device.device_class})
        )
        self.composite: bool = device.is_composite
        self.storage_with_input: bool = device.pairs_storage_with_input
        self.mixes_input_with_other: bool = device.mixes_input_with_other
        self.storage_like: bool = device.is_storage_like
        self.removable: bool | None = device.removable


_Check = Callable[[_Subject], tuple[bool, str]]


def _number_check(
    name: str, allowed: tuple[int, ...], digits: int, getter: Callable[[_Subject], int]
) -> _Check:
    listed = frozenset(allowed)
    shown = _listing([f"0x{value:0{digits}x}" for value in allowed])

    def check(subject: _Subject) -> tuple[bool, str]:
        value = getter(subject)
        if value in listed:
            return True, f"{name} 0x{value:0{digits}x} is listed"
        return False, f"{name} 0x{value:0{digits}x} is not one of {shown}"

    return check


def _glob_check(
    name: str, patterns: tuple[str, ...], getter: Callable[[_Subject], tuple[str, ...] | None]
) -> _Check:
    compiled: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
        (pattern, compile_glob(pattern)) for pattern in patterns
    )
    shown = _listing([_shorten(pattern) for pattern in patterns])

    def check(subject: _Subject) -> tuple[bool, str]:
        forms = getter(subject)
        if forms is None:
            # Absence is not a wildcard: a rule about a serial says nothing about a
            # device that has none.
            return False, f"the device reports no {name}, so no pattern can match"
        for pattern, expression in compiled:
            for value in forms:
                if expression.match(value):
                    return True, f"{name} {_shorten(value)} matches {_shorten(pattern)}"
        return False, f"{name} {_shorten(forms[0])} matches none of {shown}"

    return check


def _bus_path_check(patterns: tuple[str, ...]) -> _Check:
    """Port patterns, matched segment by segment against the port and what is behind it."""
    compiled: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = tuple(
        (pattern, tuple(compile_glob(segment) for segment in split_bus_path(pattern)))
        for pattern in patterns
    )
    shown = _listing([_shorten(pattern) for pattern in patterns])

    def check(subject: _Subject) -> tuple[bool, str]:
        value = subject.bus_path
        if value is None:
            return False, "the device reports no bus_path, so no pattern can match"
        segments = split_bus_path(value)
        for pattern, expressions in compiled:
            # A pattern names a port: it matches that port and anything behind it,
            # never a port whose name merely starts the same way (1-2 is not 1-21).
            if len(segments) >= len(expressions) and all(
                expression.match(segment)
                for expression, segment in zip(expressions, segments, strict=False)
            ):
                return True, f"bus_path {_shorten(value)} is at or behind {_shorten(pattern)}"
        return False, f"bus_path {_shorten(value)} is not at or behind any of {shown}"

    return check


def _fingerprint_check(allowed: tuple[str, ...]) -> _Check:
    listed = frozenset(value.casefold() for value in allowed)

    def check(subject: _Subject) -> tuple[bool, str]:
        if subject.fingerprint in listed:
            return True, "the fingerprint is listed"
        return False, "the fingerprint is not listed"

    return check


def _category_check(wanted: tuple[DeviceCategory, ...]) -> _Check:
    shown = _listing([category.value for category in wanted])

    def check(subject: _Subject) -> tuple[bool, str]:
        present = ", ".join(sorted(category.value for category in subject.categories))
        for category in wanted:
            if category in subject.categories:
                return True, f"the device declares category {category.value}"
        return False, f"the device's categories ({present}) include none of {shown}"

    return check


def _interface_class_check(allowed: tuple[int, ...]) -> _Check:
    shown = _listing([f"0x{value:02x}" for value in allowed])

    def check(subject: _Subject) -> tuple[bool, str]:
        for value in allowed:
            if value in subject.interface_classes:
                return True, f"the device has an interface of class 0x{value:02x}"
        present = ", ".join(f"0x{value:02x}" for value in sorted(subject.interface_classes))
        return False, f"the device's interface classes ({present}) include none of {shown}"

    return check


def _confidence_check(wanted: Confidence) -> _Check:
    def check(subject: _Subject) -> tuple[bool, str]:
        actual = subject.confidence
        if actual is wanted:
            return True, f"fingerprint confidence is {actual.value}"
        return False, f"fingerprint confidence is {actual.value}, not {wanted.value}"

    return check


def _flag_check(name: str, wanted: bool, getter: Callable[[_Subject], bool | None]) -> _Check:
    def check(subject: _Subject) -> tuple[bool, str]:
        actual = getter(subject)
        if actual is None:
            # Unknown is neither true nor false; guessing either way could allow a
            # device the rule's author meant to exclude.
            return False, f"the platform does not report {name}, so it matches neither value"
        word = "true" if actual else "false"
        if actual is wanted:
            return True, f"{name} is {word}"
        return False, f"{name} is {word}, not {'true' if wanted else 'false'}"

    return check


def _compile_checks(match: Match) -> tuple[tuple[str, _Check], ...]:
    """Build one check per criterion present in ``match`` (the time window excepted)."""
    checks: list[tuple[str, _Check]] = []
    if match.vendor_id is not None:
        checks.append(
            ("vendor_id", _number_check("vendor_id", match.vendor_id, 4, lambda s: s.vendor_id))
        )
    if match.product_id is not None:
        checks.append(
            (
                "product_id",
                _number_check("product_id", match.product_id, 4, lambda s: s.product_id),
            )
        )
    if match.serial is not None:
        checks.append(("serial", _glob_check("serial", match.serial, lambda s: s.serial)))
    if match.fingerprint is not None:
        checks.append(("fingerprint", _fingerprint_check(match.fingerprint)))
    if match.manufacturer is not None:
        checks.append(
            (
                "manufacturer",
                _glob_check("manufacturer", match.manufacturer, lambda s: s.manufacturer),
            )
        )
    if match.product is not None:
        checks.append(("product", _glob_check("product", match.product, lambda s: s.product)))
    if match.category is not None:
        checks.append(("category", _category_check(match.category)))
    if match.interface_class is not None:
        checks.append(("interface_class", _interface_class_check(match.interface_class)))
    if match.confidence is not None:
        checks.append(("confidence", _confidence_check(match.confidence)))
    flags: tuple[tuple[str, bool | None, Callable[[_Subject], bool | None]], ...] = (
        ("composite", match.composite, lambda s: s.composite),
        ("storage_with_input", match.storage_with_input, lambda s: s.storage_with_input),
        (
            "mixes_input_with_other",
            match.mixes_input_with_other,
            lambda s: s.mixes_input_with_other,
        ),
        ("storage_like", match.storage_like, lambda s: s.storage_like),
        ("removable", match.removable, lambda s: s.removable),
    )
    for name, wanted, getter in flags:
        if wanted is not None:
            checks.append((name, _flag_check(name, wanted, getter)))
    if match.bus_path is not None:
        checks.append(("bus_path", _bus_path_check(match.bus_path)))
    return tuple(checks)


def _describe_window(window: TimeWindow, now: datetime) -> tuple[bool, str]:
    local = now.astimezone(window.tzinfo)
    days = ",".join(WEEKDAYS[day] for day in window.days)
    stamp = f"{WEEKDAYS[local.weekday()]} {local:%H:%M}"
    span = f"{days} {window.start:%H:%M}-{window.end:%H:%M} (UTC{local:%z})"
    if window.contains(now):
        return True, f"the time {stamp} is inside the window {span}"
    return False, f"the time {stamp} is outside the window {span}"


class _CompiledRule:
    """A rule with its patterns compiled, ready to be tested many times."""

    __slots__ = ("checks", "rule", "window")

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.checks = _compile_checks(rule.match)
        self.window = rule.match.time

    def static_match(self, subject: _Subject) -> bool:
        """Whether every criterion other than the time window matches."""
        return all(check(subject)[0] for _name, check in self.checks)

    def trace(self, subject: _Subject, now: datetime) -> tuple[CriterionTrace, ...]:
        """Every criterion with its result, the time window last."""
        traces = [CriterionTrace(name, *check(subject)) for name, check in self.checks]
        if self.window is not None:
            traces.append(CriterionTrace("time", *_describe_window(self.window, now)))
        return tuple(traces)


def _earliest(moments: Sequence[datetime]) -> datetime | None:
    return min(moments) if moments else None


class PolicyEngine:
    """Evaluates devices against one :class:`~portlock.policy.model.Policy`.

    Args:
        policy: the policy to evaluate. Its patterns are compiled once, here.
    """

    def __init__(self, policy: Policy) -> None:
        if not isinstance(policy, Policy):
            raise TypeError("PolicyEngine needs a Policy")
        self._policy = policy
        self._rules = tuple(_CompiledRule(rule) for rule in policy.rules)

    @property
    def policy(self) -> Policy:
        """The policy this engine evaluates."""
        return self._policy

    def evaluate(
        self, device: UsbDevice, fingerprint: Fingerprint, *, now: datetime
    ) -> PolicyResult:
        """Find the first enabled, unexpired rule that matches ``device``.

        Args:
            device: the device as the backend reported it.
            fingerprint: the device's fingerprint, computed by the caller.
            now: the instant to evaluate at; rule expiry and time windows use it.

        Returns:
            The winning rule's action, or the policy default if no rule matched.

        Raises:
            ValueError: if ``now`` is not timezone-aware.
        """
        moment = require_aware(now, "now")
        subject = _Subject(device, fingerprint)
        skipped: list[tuple[str, str]] = []
        changes: list[datetime] = []
        for compiled in self._rules:
            rule = compiled.rule
            if not rule.enabled:
                skipped.append((rule.id, "disabled"))
                continue
            if rule.expires is not None and rule.is_expired(moment):
                skipped.append((rule.id, f"expired at {utc_iso(rule.expires)}"))
                continue
            if not compiled.static_match(subject):
                continue
            window = compiled.window
            if window is not None:
                # Either way the result can change when the window next opens or closes.
                changes.append(window.next_change(moment))
                if not window.contains(moment):
                    continue
            if rule.expires is not None:
                changes.append(rule.expires)
            explanation = tuple(trace.detail for trace in compiled.trace(subject, moment))
            return PolicyResult(
                action=rule.action,
                rule=rule,
                matched_default=False,
                skipped=tuple(skipped),
                explanation=explanation,
                valid_until=_earliest(changes),
            )
        return PolicyResult(
            action=self._policy.default,
            rule=None,
            matched_default=True,
            skipped=tuple(skipped),
            explanation=("no enabled, unexpired rule matched; the policy default applies",),
            valid_until=_earliest(changes),
        )

    def explain(
        self, device: UsbDevice, fingerprint: Fingerprint, *, now: datetime
    ) -> tuple[RuleTrace, ...]:
        """Test every rule against ``device`` and say what happened to each.

        Unlike :meth:`evaluate` this looks at every rule and every criterion, including
        rules that are disabled, expired or come after the winner, so an operator can see
        why a rule did *not* apply. The rule marked :attr:`RuleOutcome.MATCHED` is always
        the one :meth:`evaluate` returns; if none is, the policy default applies.

        Raises:
            ValueError: if ``now`` is not timezone-aware.
        """
        moment = require_aware(now, "now")
        subject = _Subject(device, fingerprint)
        traces: list[RuleTrace] = []
        winner: str | None = None
        for compiled in self._rules:
            rule = compiled.rule
            criteria = compiled.trace(subject, moment)
            would_match = all(trace.matched for trace in criteria)
            if not rule.enabled:
                outcome = RuleOutcome.DISABLED
                summary = "disabled" + ("; it would match otherwise" if would_match else "")
            elif rule.expires is not None and rule.is_expired(moment):
                outcome = RuleOutcome.EXPIRED
                summary = f"expired at {utc_iso(rule.expires)}" + (
                    "; it would match otherwise" if would_match else ""
                )
            elif not would_match:
                outcome = RuleOutcome.NO_MATCH
                failed = next(trace for trace in criteria if not trace.matched)
                summary = f"does not match: {failed.detail}"
            elif winner is None:
                outcome = RuleOutcome.MATCHED
                winner = rule.id
                summary = f"matches and decides: {rule.action.access.value}"
            else:
                outcome = RuleOutcome.SHADOWED
                summary = f"matches, but rule {winner!r} comes first"
            traces.append(
                RuleTrace(
                    rule_id=rule.id,
                    outcome=outcome,
                    would_match=would_match,
                    action=rule.action,
                    criteria=criteria,
                    summary=summary,
                )
            )
        return tuple(traces)
