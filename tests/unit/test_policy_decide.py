"""The decision: precedence of safety, lockdown, scan, policy and grants, as truth tables."""

from __future__ import annotations

import ast
import datetime as dt
import itertools
from pathlib import Path
from typing import Any

import pytest

import portlock.auth.grants
import portlock.policy
from factories import flash_drive, keyboard, make_device, storage_with_keyboard
from portlock.auth.grants import ADMIN_MAX_DURATION, Grant, GrantEnd, GrantKind, GrantStore
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.models import (
    Access,
    Confidence,
    Decision,
    DecisionSource,
    Fingerprint,
    ScanRequirement,
    UsbDevice,
)
from portlock.policy.decide import ScanDetection, ScanVerdict, decide, scan_detection_for
from portlock.policy.defaults import DEFAULT_POLICY
from portlock.policy.engine import PolicyEngine, PolicyResult
from portlock.policy.model import (
    DetectionAction,
    IncompleteAction,
    Match,
    Policy,
    Rule,
    RuleAction,
    ScanPolicy,
    TimeWindow,
)
from portlock.scan.report import Verdict

UTC = dt.UTC
#: Monday 5 January 2026, 10:00 UTC.
NOW = dt.datetime(2026, 1, 5, 10, 0, tzinfo=UTC)
HIGH = Fingerprint("plk1:abcdefghijklmnopqrstuvwxyz234567", Confidence.HIGH)
LOW = Fingerprint("plk1:" + "q" * 32, Confidence.LOW)

ALLOW, READ_ONLY, DENY, PENDING = Access.ALLOW, Access.READ_ONLY, Access.DENY, Access.PENDING
SAFETY, LOCKDOWN, SCAN = DecisionSource.SAFETY, DecisionSource.LOCKDOWN, DecisionSource.SCAN
POLICY, GRANT, DEFAULT = DecisionSource.POLICY, DecisionSource.GRANT, DecisionSource.DEFAULT
NONE, ON_MOUNT, REQUIRED = ScanRequirement.NONE, ScanRequirement.ON_MOUNT, ScanRequirement.REQUIRED


def policy_result(
    origin: str,
    access: Access,
    *,
    scan: ScanRequirement = NONE,
    alert: bool = False,
    expires: dt.datetime | None = None,
    valid_until: dt.datetime | None = None,
) -> PolicyResult:
    """A policy result as the engine would give it, from a rule or from the default."""
    action = RuleAction(access, scan=scan, alert=alert)
    if origin == "default":
        return PolicyResult(
            action=action,
            rule=None,
            matched_default=True,
            explanation=("no enabled, unexpired rule matched; the policy default applies",),
            valid_until=valid_until,
        )
    rule = Rule(id="the-rule", match=Match(vendor_id=0x1209), action=action, expires=expires)
    return PolicyResult(
        action=action,
        rule=rule,
        matched_default=False,
        explanation=("vendor_id 0x1209 is listed",),
        valid_until=valid_until if valid_until is not None else expires,
    )


def grant(read_only: bool = False, **overrides: Any) -> Grant:
    fields: dict[str, Any] = {
        "id": "0123456789abcdef0123456789abcdef",
        "fingerprint": HIGH.value,
        "confidence": Confidence.HIGH,
        "kind": GrantKind.TRUST,
        "read_only": read_only,
        "created_at": NOW - dt.timedelta(days=1),
        "granted_by": "admin",
    }
    fields.update(overrides)
    return Grant(**fields)


GRANTS: dict[str, Grant | None] = {
    "none": None,
    "full": grant(read_only=False),
    "read_only": grant(read_only=True),
}

DETECTIONS: dict[str, ScanDetection | None] = {
    "none": None,
    "alert": ScanDetection(ScanVerdict.SUSPICIOUS, None, "a scan found suspicious content"),
    "read_only": ScanDetection(
        ScanVerdict.SUSPICIOUS, READ_ONLY, "a scan found suspicious content"
    ),
    "deny": ScanDetection(ScanVerdict.MALICIOUS, DENY, "a scan found malicious content"),
}


def run(
    result: PolicyResult,
    given: Grant | None = None,
    *,
    device: UsbDevice | None = None,
    fingerprint: Fingerprint = HIGH,
    protected: bool = False,
    protection_reasons: tuple[str, ...] = (),
    lockdown_active: bool = False,
    lockdown_exempt: bool = False,
    now: dt.datetime = NOW,
    detection: ScanDetection | None = None,
) -> Decision:
    return decide(
        device=device or flash_drive(),
        fingerprint=fingerprint,
        policy_result=result,
        grant=given,
        protected=protected,
        protection_reasons=protection_reasons,
        lockdown_active=lockdown_active,
        lockdown_exempt=lockdown_exempt,
        now=now,
        scan_detection=detection,
    )


# --- the truth tables -----------------------------------------------------------------

#: (where the policy verdict came from, the policy verdict, the grant) -> the decision
#: for a device that is neither protected, locked down nor caught by a scan. Written out
#: in full on purpose: this table is the specification, not a second implementation.
POLICY_AND_GRANT: dict[tuple[str, Access, str], tuple[Access, DecisionSource]] = {
    # A rule's allow, read_only and deny are final: a grant changes none of them.
    ("rule", DENY, "none"): (DENY, POLICY),
    ("rule", DENY, "full"): (DENY, POLICY),
    ("rule", DENY, "read_only"): (DENY, POLICY),
    ("rule", READ_ONLY, "none"): (READ_ONLY, POLICY),
    ("rule", READ_ONLY, "full"): (READ_ONLY, POLICY),
    ("rule", READ_ONLY, "read_only"): (READ_ONLY, POLICY),
    ("rule", ALLOW, "none"): (ALLOW, POLICY),
    ("rule", ALLOW, "full"): (ALLOW, POLICY),
    ("rule", ALLOW, "read_only"): (ALLOW, POLICY),
    # A rule that leaves the device pending is what a grant is for.
    ("rule", PENDING, "none"): (PENDING, POLICY),
    ("rule", PENDING, "full"): (ALLOW, GRANT),
    ("rule", PENDING, "read_only"): (READ_ONLY, GRANT),
    # The same holds for the default: a grant acts only on pending.
    ("default", DENY, "none"): (DENY, DEFAULT),
    ("default", DENY, "full"): (DENY, DEFAULT),
    ("default", DENY, "read_only"): (DENY, DEFAULT),
    ("default", READ_ONLY, "none"): (READ_ONLY, DEFAULT),
    ("default", READ_ONLY, "full"): (READ_ONLY, DEFAULT),
    ("default", READ_ONLY, "read_only"): (READ_ONLY, DEFAULT),
    ("default", ALLOW, "none"): (ALLOW, DEFAULT),
    ("default", ALLOW, "full"): (ALLOW, DEFAULT),
    ("default", ALLOW, "read_only"): (ALLOW, DEFAULT),
    ("default", PENDING, "none"): (PENDING, DEFAULT),
    ("default", PENDING, "full"): (ALLOW, GRANT),
    ("default", PENDING, "read_only"): (READ_ONLY, GRANT),
}

#: (what policy and grant give, the scan detection) -> the access after the scan. A
#: detection is a ceiling: it can only take access away. ``None`` means "unchanged".
SCAN_CEILING: dict[tuple[Access, str], Access | None] = {
    (ALLOW, "none"): None,
    (ALLOW, "alert"): None,
    (ALLOW, "read_only"): READ_ONLY,
    (ALLOW, "deny"): DENY,
    (READ_ONLY, "none"): None,
    (READ_ONLY, "alert"): None,
    (READ_ONLY, "read_only"): None,
    (READ_ONLY, "deny"): DENY,
    # Pending is already less than read-only; a grant would be held to read-only below.
    (PENDING, "none"): None,
    (PENDING, "alert"): None,
    (PENDING, "read_only"): None,
    (PENDING, "deny"): DENY,
    (DENY, "none"): None,
    (DENY, "alert"): None,
    (DENY, "read_only"): None,
    (DENY, "deny"): None,
}

#: (lockdown_active, lockdown_exempt)
LOCKDOWN_STATES = [(False, False), (False, True), (True, False), (True, True)]

EVERY_COMBINATION = list(
    itertools.product([False, True], LOCKDOWN_STATES, DETECTIONS, POLICY_AND_GRANT.items())
)


def test_the_tables_cover_every_combination() -> None:
    assert set(POLICY_AND_GRANT) == set(
        itertools.product(["rule", "default"], list(Access), ["none", "full", "read_only"])
    )
    assert set(SCAN_CEILING) == set(itertools.product(list(Access), DETECTIONS))
    assert len(EVERY_COMBINATION) == 2 * 4 * 4 * 24 == 768


def _case_id(case: Any) -> str:
    protected, (active, exempt), detection, ((origin, access, grant_name), _expected) = case
    return (
        f"{'protected' if protected else 'unprotected'}"
        f"-lockdown_{'on' if active else 'off'}{'_exempt' if exempt else ''}"
        f"-scan_{detection}-{origin}_{access.value}-grant_{grant_name}"
    )


@pytest.mark.parametrize("case", EVERY_COMBINATION, ids=_case_id)
def test_precedence(case: Any) -> None:
    protected, (active, exempt), detection_name, ((origin, access, grant_name), entry) = case
    capped = SCAN_CEILING[(entry[0], detection_name)]
    if protected:
        expected = (ALLOW, SAFETY)
    elif active and not exempt:
        expected = (DENY, LOCKDOWN)
    elif capped is not None:
        expected = (capped, SCAN)
    else:
        expected = entry

    result = policy_result(origin, access, scan=ON_MOUNT, alert=False)
    given = GRANTS[grant_name]
    detection = DETECTIONS[detection_name]
    decision = run(
        result,
        given,
        protected=protected,
        protection_reasons=("enrolled keyboard on its own port",) if protected else (),
        lockdown_active=active,
        lockdown_exempt=exempt,
        detection=detection,
    )

    assert (decision.access, decision.source) == expected
    assert decision.reasons, "every decision explains itself"
    if decision.source is SAFETY:
        assert decision.scan is NONE
    else:
        # A grant never removes a scan requirement.
        assert decision.scan is ON_MOUNT
    if decision.source in (SAFETY, LOCKDOWN):
        assert decision.rule_id is None and decision.grant_id is None
        assert decision.expires_at is None
        assert decision.alert is False
    else:
        # Every scan detection raises an alert; otherwise the policy action says.
        assert decision.alert is (detection is not None)
        assert decision.rule_id == ("the-rule" if origin == "rule" else None)
        acted = given is not None and access is PENDING
        assert decision.grant_id == (given.id if acted and given is not None else None)
    # The decision is a plain value that survives the audit log.
    assert Decision.from_dict(decision.to_dict()) == decision


# --- safety ---------------------------------------------------------------------------


def test_a_protected_device_is_allowed_whatever_else_is_true() -> None:
    decision = run(
        policy_result("rule", DENY, scan=REQUIRED, alert=True),
        None,
        device=keyboard(),
        protected=True,
        protection_reasons=("enrolled input device on its enrolled port",),
        lockdown_active=True,
        detection=DETECTIONS["deny"],
    )
    assert decision == Decision(
        access=ALLOW,
        source=SAFETY,
        reasons=(
            "enrolled input device on its enrolled port",
            "protected devices are always allowed and never enforced against",
            "rule 'the-rule' says deny; safety takes precedence",
            "lockdown is active; protected devices are not affected",
        ),
        scan=NONE,
        alert=True,
    )
    assert decision.permits_access


def test_a_protected_device_with_no_stated_reason_still_gets_one() -> None:
    decision = run(policy_result("default", ALLOW), protected=True, device=keyboard())
    assert decision.reasons == (
        "Example Corp Example Keyboard is a protected device",
        "protected devices are always allowed and never enforced against",
    )
    assert decision.alert is False

    long_name = make_device(manufacturer=None, product="P" * 500)
    reason = run(policy_result("default", ALLOW), protected=True, device=long_name).reasons[0]
    # The device model has already capped the name at 126 characters; decide shows 60.
    assert reason == "P" * 60 + "... is a protected device"


# --- lockdown -------------------------------------------------------------------------


def test_lockdown_denies_and_says_what_policy_would_have_done() -> None:
    decision = run(policy_result("rule", ALLOW), GRANTS["full"], lockdown_active=True)
    assert decision == Decision(
        access=DENY,
        source=LOCKDOWN,
        reasons=(
            "emergency lockdown is active; devices that are not protected are denied",
            "without lockdown, rule 'the-rule' would say allow",
        ),
    )
    assert decision.blocks


def test_an_exempt_device_is_decided_as_if_there_were_no_lockdown() -> None:
    result = policy_result("default", PENDING)
    exempt = run(result, GRANTS["full"], lockdown_active=True, lockdown_exempt=True)
    normal = run(result, GRANTS["full"])
    assert (exempt.access, exempt.source, exempt.grant_id) == (ALLOW, GRANT, normal.grant_id)
    assert exempt.reasons == (
        "lockdown is active, but this device is exempt from it",
        *normal.reasons,
    )


def test_exemption_without_lockdown_changes_nothing() -> None:
    result = policy_result("rule", READ_ONLY)
    assert run(result, lockdown_exempt=True) == run(result)


# --- scan detections ------------------------------------------------------------------


def test_a_malicious_detection_denies_even_a_device_a_rule_allows() -> None:
    decision = run(
        policy_result("rule", ALLOW, scan=ON_MOUNT, valid_until=NOW + dt.timedelta(hours=1)),
        detection=DETECTIONS["deny"],
    )
    assert decision == Decision(
        access=DENY,
        source=SCAN,
        reasons=(
            "a scan found malicious content; the device is limited to deny",
            "without the scan result, the decision would be allow",
            "rule 'the-rule' says allow",
            "vendor_id 0x1209 is listed",
        ),
        rule_id="the-rule",
        scan=ON_MOUNT,
        alert=True,
        expires_at=NOW + dt.timedelta(hours=1),
    )


def test_a_grant_cannot_lift_a_scan_detection() -> None:
    given = grant(kind=GrantKind.TEMPORARY, expires_at=NOW + dt.timedelta(hours=2))
    decision = run(
        policy_result("default", PENDING, scan=REQUIRED), given, detection=DETECTIONS["read_only"]
    )
    # The grant acted on the pending outcome; the detection then held it to read-only.
    assert (decision.access, decision.source, decision.grant_id) == (READ_ONLY, SCAN, given.id)
    assert decision.scan is REQUIRED and decision.alert is True
    assert decision.expires_at == NOW + dt.timedelta(hours=2)


def test_a_detection_that_changes_nothing_is_still_reported() -> None:
    decision = run(policy_result("rule", DENY), detection=DETECTIONS["read_only"])
    assert (decision.access, decision.source, decision.alert) == (DENY, POLICY, True)
    assert decision.reasons[-1] == "a scan found suspicious content"


def test_the_scan_reason_follows_an_exempting_lockdown_note() -> None:
    decision = run(
        policy_result("rule", ALLOW),
        lockdown_active=True,
        lockdown_exempt=True,
        detection=DETECTIONS["deny"],
    )
    assert decision.reasons[:3] == (
        "lockdown is active, but this device is exempt from it",
        "a scan found malicious content; the device is limited to deny",
        "without the scan result, the decision would be allow",
    )


SCAN_POLICIES = {
    "deny": ScanPolicy(DetectionAction.DENY, IncompleteAction.READ_ONLY),
    "read_only": ScanPolicy(DetectionAction.READ_ONLY, IncompleteAction.READ_ONLY),
    "alert": ScanPolicy(DetectionAction.ALERT, IncompleteAction.READ_ONLY),
    "deny_incomplete": ScanPolicy(DetectionAction.DENY, IncompleteAction.DENY),
}

#: (verdict, requirement, scan policy) -> the ceiling, or "alert" for an alert only, or
#: None for no detection. The policy's ``scan`` settings, as a table.
DETECTION_TABLE: list[tuple[ScanVerdict | None, ScanRequirement, str, Access | str | None]] = [
    (None, ON_MOUNT, "deny", None),
    (None, REQUIRED, "deny", None),
    (ScanVerdict.CLEAN, REQUIRED, "deny", None),
    # A scan of a device whose action says scan none is a report, not a decision.
    (ScanVerdict.MALICIOUS, NONE, "deny", None),
    (ScanVerdict.INCOMPLETE, NONE, "deny_incomplete", None),
    (ScanVerdict.MALICIOUS, ON_MOUNT, "deny", DENY),
    (ScanVerdict.MALICIOUS, REQUIRED, "deny", DENY),
    (ScanVerdict.MALICIOUS, ON_MOUNT, "read_only", READ_ONLY),
    (ScanVerdict.MALICIOUS, ON_MOUNT, "alert", "alert"),
    # Suspicious never denies on its own: heuristics recognise a shape, not malice.
    (ScanVerdict.SUSPICIOUS, ON_MOUNT, "deny", READ_ONLY),
    (ScanVerdict.SUSPICIOUS, REQUIRED, "read_only", READ_ONLY),
    (ScanVerdict.SUSPICIOUS, ON_MOUNT, "alert", "alert"),
    # A required scan that did not finish, or failed: on_incomplete decides (DESIGN 14.9).
    (ScanVerdict.INCOMPLETE, REQUIRED, "deny", READ_ONLY),
    (ScanVerdict.ERROR, REQUIRED, "alert", READ_ONLY),
    (ScanVerdict.INCOMPLETE, REQUIRED, "deny_incomplete", DENY),
    (ScanVerdict.ERROR, REQUIRED, "deny_incomplete", DENY),
    # An on_mount scan that did not finish leaves access as it was, with an alert.
    (ScanVerdict.INCOMPLETE, ON_MOUNT, "deny_incomplete", "alert"),
    (ScanVerdict.ERROR, ON_MOUNT, "deny", "alert"),
]


@pytest.mark.parametrize(("verdict", "requirement", "settings", "expected"), DETECTION_TABLE)
def test_scan_settings_turn_a_verdict_into_a_detection(
    verdict: ScanVerdict | None,
    requirement: ScanRequirement,
    settings: str,
    expected: Access | str | None,
) -> None:
    detection = scan_detection_for(
        verdict, requirement=requirement, scan_policy=SCAN_POLICIES[settings]
    )
    if expected is None:
        assert detection is None
        return
    assert detection is not None and detection.verdict is verdict
    assert detection.ceiling == (None if expected == "alert" else expected)
    assert detection.reason


def test_the_reasons_name_what_the_scan_found() -> None:
    policy = SCAN_POLICIES["deny"]
    reasons = {
        verdict: scan_detection_for(verdict, requirement=REQUIRED, scan_policy=policy)
        for verdict in (ScanVerdict.MALICIOUS, ScanVerdict.INCOMPLETE, ScanVerdict.ERROR)
    }
    assert {verdict: item.reason for verdict, item in reasons.items() if item is not None} == {
        ScanVerdict.MALICIOUS: "a scan found malicious content",
        ScanVerdict.INCOMPLETE: "the required scan did not finish",
        ScanVerdict.ERROR: "the required scan failed",
    }
    on_mount = scan_detection_for(ScanVerdict.ERROR, requirement=ON_MOUNT, scan_policy=policy)
    assert on_mount is not None and on_mount.reason == "the scan failed"


def test_verdicts_are_the_scanners_own_words() -> None:
    assert [member.value for member in ScanVerdict] == [member.value for member in Verdict]
    for verdict in Verdict:
        assert ScanVerdict(verdict).value == verdict.value
    detection = scan_detection_for(
        Verdict.MALICIOUS, requirement=ON_MOUNT, scan_policy=SCAN_POLICIES["deny"]
    )
    assert detection is not None and detection.ceiling is DENY
    assert scan_detection_for("clean", requirement=ON_MOUNT, scan_policy=ScanPolicy()) is None
    with pytest.raises(ValueError):
        scan_detection_for("infected", requirement=ON_MOUNT, scan_policy=ScanPolicy())


@pytest.mark.parametrize(
    ("verdict", "ceiling", "reason"),
    [
        (ScanVerdict.CLEAN, None, "x"),
        (ScanVerdict.MALICIOUS, ALLOW, "x"),
        (ScanVerdict.MALICIOUS, PENDING, "x"),
        (ScanVerdict.MALICIOUS, DENY, ""),
        ("nonsense", DENY, "x"),
    ],
)
def test_a_detection_is_validated(verdict: Any, ceiling: Any, reason: str) -> None:
    with pytest.raises(ValueError):
        ScanDetection(verdict, ceiling, reason)


# --- policy and grants ----------------------------------------------------------------


def test_a_rule_ignores_a_usable_grant_and_says_why() -> None:
    expiry = NOW + dt.timedelta(days=3)
    given = grant(expires_at=NOW + dt.timedelta(hours=1), kind=GrantKind.TEMPORARY)
    decision = run(policy_result("rule", DENY, alert=True, expires=expiry), given)
    assert decision == Decision(
        access=DENY,
        source=POLICY,
        reasons=(
            "rule 'the-rule' says deny",
            "vendor_id 0x1209 is listed",
            f"grant {given.id} is not used: a grant acts only on a pending outcome, and a"
            " rule is final; to change this decision, change the policy",
        ),
        rule_id="the-rule",
        grant_id=None,
        alert=True,
        # The grant plays no part, so neither does its expiry.
        expires_at=expiry,
    )


def test_a_read_only_grant_does_not_narrow_an_allow_rule() -> None:
    decision = run(policy_result("rule", ALLOW), GRANTS["read_only"])
    assert (decision.access, decision.source, decision.grant_id) == (ALLOW, POLICY, None)


def test_a_full_grant_does_not_widen_a_read_only_rule() -> None:
    decision = run(policy_result("rule", READ_ONLY), GRANTS["full"])
    assert (decision.access, decision.source, decision.grant_id) == (READ_ONLY, POLICY, None)


def test_a_grant_does_not_lift_a_default_of_deny() -> None:
    given = grant()
    decision = run(policy_result("default", DENY), given)
    assert (decision.access, decision.source, decision.grant_id) == (DENY, DEFAULT, None)
    assert decision.reasons[-1] == (
        f"grant {given.id} is not used: a grant acts only on a pending outcome, and the"
        " default is not pending; to change this decision, change the policy"
    )


def test_a_grant_upgrades_pending_and_keeps_the_policy_scan_and_alert() -> None:
    given = grant(read_only=True, kind=GrantKind.TEMPORARY, expires_at=NOW + dt.timedelta(hours=2))
    result = policy_result("default", PENDING, scan=REQUIRED, alert=True)
    decision = run(result, given)
    assert decision == Decision(
        access=READ_ONLY,
        source=GRANT,
        reasons=(
            f"temporary grant {given.id} from admin gives read_only until"
            " 2026-01-05T12:00:00.000000Z",
            "the policy default says pending",
            "no enabled, unexpired rule matched; the policy default applies",
        ),
        grant_id=given.id,
        scan=REQUIRED,
        alert=True,
        expires_at=NOW + dt.timedelta(hours=2),
    )


def test_a_grant_upgrades_a_pending_rule_and_names_the_rule() -> None:
    given = GRANTS["full"]
    assert given is not None
    decision = run(policy_result("rule", PENDING, scan=REQUIRED), given)
    assert (decision.access, decision.source) == (ALLOW, GRANT)
    assert decision.rule_id == "the-rule" and decision.grant_id == given.id
    # The rule's scan requirement stays: the device is read-only until a clean scan.
    assert decision.scan is REQUIRED


def test_with_no_grant_the_policy_stands() -> None:
    from_rule = run(policy_result("rule", ALLOW, scan=ON_MOUNT))
    assert from_rule == Decision(
        access=ALLOW,
        source=POLICY,
        reasons=("rule 'the-rule' says allow", "vendor_id 0x1209 is listed"),
        rule_id="the-rule",
        scan=ON_MOUNT,
    )
    from_default = run(policy_result("default", PENDING))
    assert from_default == Decision(
        access=PENDING,
        source=DEFAULT,
        reasons=(
            "the policy default says pending",
            "no enabled, unexpired rule matched; the policy default applies",
        ),
    )


def test_a_low_confidence_grant_is_flagged_in_the_reasons() -> None:
    given = grant(fingerprint=LOW.value, confidence=Confidence.LOW, bound_port="1-1")
    decision = run(policy_result("default", PENDING), given, fingerprint=LOW)
    assert (decision.access, decision.source) == (ALLOW, GRANT)
    assert decision.reasons[-1] == (
        "the fingerprint has low confidence: this grant covers every unit of this model on"
        " its port, not one device"
    )
    high = run(policy_result("default", PENDING), GRANTS["full"])
    assert not any("low confidence" in reason for reason in high.reasons)


# --- expiry ---------------------------------------------------------------------------

SOON = NOW + dt.timedelta(hours=1)
LATER = NOW + dt.timedelta(days=1)


@pytest.mark.parametrize(
    ("origin", "access", "rule_expiry", "grant_expiry", "expected"),
    [
        ("rule", PENDING, None, None, None),
        ("rule", PENDING, LATER, None, LATER),
        ("rule", PENDING, None, SOON, SOON),
        ("rule", PENDING, LATER, SOON, SOON),
        ("rule", PENDING, SOON, LATER, SOON),
        # A rule that decides leaves the grant out of play, its expiry with it.
        ("rule", ALLOW, SOON, LATER, SOON),
        ("rule", READ_ONLY, LATER, SOON, LATER),
        ("rule", DENY, LATER, SOON, LATER),
        ("rule", DENY, None, SOON, None),
        ("default", PENDING, None, SOON, SOON),
        ("default", PENDING, None, None, None),
        ("default", ALLOW, None, SOON, None),
    ],
)
def test_the_decision_expires_at_the_earliest_of_the_acting_grant_and_the_rule(
    origin: str,
    access: Access,
    rule_expiry: dt.datetime | None,
    grant_expiry: dt.datetime | None,
    expected: dt.datetime | None,
) -> None:
    kind = GrantKind.TEMPORARY if grant_expiry is not None else GrantKind.TRUST
    given = grant(kind=kind, expires_at=grant_expiry)
    decision = run(policy_result(origin, access, expires=rule_expiry), given)
    assert decision.expires_at == expected


def test_without_a_grant_the_decision_expires_with_the_rule() -> None:
    assert run(policy_result("rule", ALLOW, expires=LATER)).expires_at == LATER
    assert run(policy_result("rule", ALLOW)).expires_at is None


def test_a_time_window_bounds_the_decision_like_an_expiry() -> None:
    office_hours = TimeWindow(days=(0, 1, 2, 3, 4), start=dt.time(9, 0), end=dt.time(17, 0))
    policy = Policy(
        rules=(
            Rule(
                id="hours",
                match=Match(vendor_id=0x1209, time=office_hours),
                action=RuleAction(ALLOW),
                expires=LATER,
            ),
        )
    )
    engine = PolicyEngine(policy)
    closes = dt.datetime(2026, 1, 5, 17, 0, tzinfo=UTC)

    inside = run(engine.evaluate(flash_drive(), HIGH, now=NOW))
    assert (inside.access, inside.source, inside.expires_at) == (ALLOW, POLICY, closes)

    # After hours the default applies, but only until the window opens again.
    evening = NOW.replace(hour=19)
    opens = dt.datetime(2026, 1, 6, 9, 0, tzinfo=UTC)
    outside = run(engine.evaluate(flash_drive(), HIGH, now=evening), now=evening)
    assert (outside.access, outside.source, outside.expires_at) == (PENDING, DEFAULT, opens)


# --- grants that must not be honoured -------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "note"),
    [
        (
            {"kind": GrantKind.TEMPORARY, "expires_at": NOW},
            "expired at 2026-01-05T10:00:00.000000Z and was ignored",
        ),
        (
            {"kind": GrantKind.TEMPORARY, "expires_at": NOW - dt.timedelta(days=1)},
            "expired at 2026-01-04T10:00:00.000000Z and was ignored",
        ),
        (
            {"ended_at": NOW - dt.timedelta(hours=1), "end_reason": GrantEnd.REVOKED},
            "has ended and was ignored",
        ),
        ({"fingerprint": LOW.value}, "is for a different device and was ignored"),
        (
            {"kind": GrantKind.ONCE, "bound_connection": "conn-other", "bound_at": NOW},
            "belongs to another connection and was ignored",
        ),
        ({"bound_port": "1-2"}, "is limited to another port and was ignored"),
        ({"bound_port": "1-1.3"}, "is limited to another port and was ignored"),
    ],
)
@pytest.mark.parametrize("origin", ["rule", "default"])
def test_a_grant_that_is_not_usable_is_ignored(
    overrides: dict[str, Any], note: str, origin: str
) -> None:
    stale = grant(**overrides)
    result = policy_result(origin, PENDING)
    device = flash_drive(connection_id="conn-this")
    decision = run(result, stale, device=device)
    without = run(result, None, device=device)
    assert (decision.access, decision.source) == (PENDING, without.source)
    assert decision.grant_id is None and decision.expires_at is None
    assert decision.reasons == (*without.reasons, f"grant {stale.id} {note}")


def test_an_unusable_grant_is_named_as_such_under_a_deciding_rule() -> None:
    stale = grant(fingerprint=LOW.value)
    decision = run(policy_result("rule", DENY), stale)
    assert decision.access is DENY
    assert decision.reasons[-1] == f"grant {stale.id} is for a different device and was ignored"


def test_a_one_time_grant_bound_to_this_connection_is_honoured() -> None:
    device = flash_drive(connection_id="conn-7")
    bound = grant(kind=GrantKind.ONCE, bound_connection="conn-7", bound_at=NOW)
    decision = run(policy_result("default", PENDING), bound, device=device)
    assert (decision.access, decision.source, decision.grant_id) == (ALLOW, GRANT, bound.id)
    assert decision.reasons[0] == f"once grant {bound.id} from admin gives allow"

    # The same device re-plugged: same instance id, new connection id.
    replugged = flash_drive(connection_id="conn-8")
    assert replugged.instance_id == device.instance_id
    assert run(policy_result("default", PENDING), bound, device=replugged).access is PENDING


def test_without_a_connection_id_the_instance_id_identifies_the_connection() -> None:
    device = flash_drive(connection_id=None)
    bound = grant(kind=GrantKind.ONCE, bound_connection=device.instance_id, bound_at=NOW)
    assert run(policy_result("default", PENDING), bound, device=device).access is ALLOW


def test_a_port_bound_grant_is_honoured_on_its_port() -> None:
    bound = grant(fingerprint=LOW.value, confidence=Confidence.LOW, bound_port="1-4")
    decision = run(
        policy_result("default", PENDING),
        bound,
        device=flash_drive(bus_path="1-4"),
        fingerprint=LOW,
    )
    assert (decision.access, decision.source) == (ALLOW, GRANT)


def test_a_grant_is_honoured_until_the_instant_before_it_expires() -> None:
    expiring = grant(kind=GrantKind.TEMPORARY, expires_at=NOW + dt.timedelta(microseconds=1))
    decision = run(policy_result("default", PENDING), expiring)
    assert (decision.access, decision.source) == (ALLOW, GRANT)


def test_a_naive_time_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        run(policy_result("default", PENDING), now=dt.datetime(2026, 1, 5, 10, 0))


def test_the_time_may_be_given_in_any_zone() -> None:
    expiring = grant(kind=GrantKind.TEMPORARY, expires_at=NOW + dt.timedelta(minutes=30))
    elsewhere = NOW.astimezone(dt.timezone(dt.timedelta(hours=9)))
    assert run(policy_result("default", PENDING), expiring, now=elsewhere) == run(
        policy_result("default", PENDING), expiring
    )


# --- the real engine, the real store --------------------------------------------------


def test_the_default_policy_with_real_grants_end_to_end() -> None:
    clock = FakeClock(NOW)
    engine = PolicyEngine(DEFAULT_POLICY)
    with Database() as database:
        store = GrantStore(database, clock=clock)

        def decide_for(device: UsbDevice, verdict: ScanVerdict | None = None) -> Decision:
            now = clock.now()
            result = engine.evaluate(device, HIGH, now=now)
            return decide(
                device=device,
                fingerprint=HIGH,
                policy_result=result,
                grant=store.active_for(HIGH.value, now=now, device=device),
                protected=False,
                protection_reasons=(),
                lockdown_active=False,
                lockdown_exempt=False,
                now=now,
                scan_detection=scan_detection_for(
                    verdict, requirement=result.action.scan, scan_policy=DEFAULT_POLICY.scan
                ),
            )

        stick, bad_stick = flash_drive(), storage_with_keyboard()
        before = decide_for(stick)
        assert (before.access, before.source) == (PENDING, DEFAULT)

        expiry = NOW + dt.timedelta(hours=4)
        issued = store.create(
            HIGH,
            GrantKind.TEMPORARY,
            expires_at=expiry,
            max_duration=ADMIN_MAX_DURATION,
            granted_by="admin",
            read_only=True,
        )
        granted = decide_for(stick)
        assert (granted.access, granted.source) == (READ_ONLY, GRANT)
        assert granted.grant_id == issued.id and granted.expires_at == expiry
        # The default policy asks for a scan once a device has been let in.
        assert granted.scan is ON_MOUNT

        # A detection on that scan takes the access away again, grant or not.
        caught = decide_for(stick, ScanVerdict.MALICIOUS)
        assert (caught.access, caught.source, caught.alert) == (DENY, SCAN, True)

        # The same grant does nothing for a device the policy denies outright.
        denied = decide_for(bad_stick)
        assert (denied.access, denied.source) == (DENY, POLICY)
        assert denied.rule_id == "deny-input-with-other"
        assert denied.alert is True and denied.grant_id is None

        clock.advance(dt.timedelta(hours=4))
        after = decide_for(stick)
        assert (after.access, after.source, after.grant_id) == (PENDING, DEFAULT, None)


# --- dependencies ---------------------------------------------------------------------


def imported_modules(path: Path) -> tuple[set[str], set[str]]:
    """Modules a source file imports: (when it runs, only for type checking)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    typing_only = {
        id(node)
        for block in ast.walk(tree)
        if isinstance(block, ast.If) and "TYPE_CHECKING" in ast.unparse(block.test)
        for statement in block.body
        for node in ast.walk(statement)
    }
    found: tuple[set[str], set[str]] = (set(), set())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        found[id(node) in typing_only].update(names)
    return found


def test_the_decision_logic_imports_neither_the_guard_nor_the_auth_package() -> None:
    # DESIGN.md section 3: policy never imports guard. It has no need of the accounts
    # and sessions that come with the auth package either, nor of the scanner; grants
    # and scan results are passed in.
    package = Path(portlock.policy.__file__).parent
    sources = sorted(package.glob("*.py"))
    assert [source.name for source in sources] == [
        "__init__.py",
        "decide.py",
        "defaults.py",
        "engine.py",
        "loader.py",
        "model.py",
    ]
    for source in sources:
        at_runtime, _for_typing = imported_modules(source)
        outside = {
            name
            for name in at_runtime
            if name.startswith("portlock.") and name.split(".")[1] not in ("core", "policy")
        }
        assert outside == set(), f"{source.name} imports {sorted(outside)}"

    # The check sees what it should: decide.py does name the grant type, for typing only.
    at_runtime, for_typing = imported_modules(package / "decide.py")
    assert "portlock.policy.engine" in at_runtime
    assert for_typing == {"portlock.auth.grants"}

    # And grants, in turn, depend on neither the policy nor the guard.
    at_runtime, for_typing = imported_modules(Path(portlock.auth.grants.__file__))
    assert {name for name in at_runtime | for_typing if name.startswith("portlock.")} == {
        "portlock.core.clock",
        "portlock.core.db",
        "portlock.core.errors",
        "portlock.core.models",
    }
