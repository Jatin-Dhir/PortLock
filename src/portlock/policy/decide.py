"""Turning everything PortLock knows about a device into one decision.

:func:`decide` is the single place where safety, lockdown, scan results, policy and
grants are weighed against each other. It is a pure function: it reads no clock, no
database and no device, so every combination of its inputs can be, and is, tested.
``docs/POLICY.md`` section 6 has the truth table.

:func:`scan_detection_for` turns the result of a connection's scans into the
:class:`ScanDetection` that :func:`decide` takes, applying the policy's ``scan``
settings.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from portlock.core.clock import utc_iso
from portlock.core.models import (
    Access,
    Confidence,
    Decision,
    DecisionSource,
    Fingerprint,
    ScanRequirement,
    UsbDevice,
)
from portlock.policy.engine import PolicyResult
from portlock.policy.model import DetectionAction, IncompleteAction, ScanPolicy, require_aware

if TYPE_CHECKING:
    # Only the type is needed. Keeping the import out of the runtime path means the
    # decision logic does not load the authentication package.
    from portlock.auth.grants import Grant

__all__ = ["ScanDetection", "ScanVerdict", "decide", "scan_detection_for"]

_SHOWN_NAME = 60

#: How much each access lets through, least first. A scan detection is a ceiling: it
#: can move a decision down this list, never up it. ``deny`` and ``pending`` both block,
#: but ``deny`` is final while ``pending`` waits for an administrator.
_OPENNESS = {Access.DENY: 0, Access.PENDING: 1, Access.READ_ONLY: 2, Access.ALLOW: 3}


class ScanVerdict(enum.StrEnum):
    """The worst result among the scans of one connection.

    The values are those of ``portlock.scan.report.Verdict``, so a report's verdict
    converts directly (``ScanVerdict(report.verdict)``) without this package importing
    the scanner.
    """

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    #: A limit, a cancellation or an unreadable file left part of a volume unexamined.
    INCOMPLETE = "incomplete"
    #: An engine failed, or the scan could not run.
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ScanDetection:
    """What a scan of this connection obliges the decision to do.

    Build one with :func:`scan_detection_for` rather than by hand, so that the policy's
    ``scan`` settings are applied the same way everywhere.

    Attributes:
        verdict: what the scans found; never ``clean``.
        ceiling: the most the device may now have, ``deny`` or ``read_only``; ``None``
            when the detection only raises an alert.
        reason: one line for the decision's reasons.

    Raises:
        ValueError: if the verdict is ``clean`` or the ceiling is not ``deny``,
            ``read_only`` or ``None``.
    """

    verdict: ScanVerdict
    ceiling: Access | None
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", ScanVerdict(self.verdict))
        if self.verdict is ScanVerdict.CLEAN:
            raise ValueError("a clean scan is not a detection")
        if self.ceiling not in (Access.DENY, Access.READ_ONLY, None):
            raise ValueError("a scan detection limits a device to deny or read_only, or alerts")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("a scan detection needs a reason")


def scan_detection_for(
    verdict: ScanVerdict | str | None,
    *,
    requirement: ScanRequirement,
    scan_policy: ScanPolicy,
) -> ScanDetection | None:
    """Apply the policy's ``scan`` settings to the worst scan verdict of a connection.

    ==========================  ==============  =====================================
    verdict                     requirement     detection
    ==========================  ==============  =====================================
    none yet, or ``clean``      any             none
    any                         ``none``        none: the scan was only a report
    ``malicious``               scanned         ``on_detection``: deny, read_only, or
                                                alert only
    ``suspicious``              scanned         read_only, or alert only when
                                                ``on_detection`` is ``alert``
    ``incomplete``, ``error``   ``required``    ``on_incomplete``: read_only or deny
    ``incomplete``, ``error``   ``on_mount``    alert only
    ==========================  ==============  =====================================

    A suspicious finding never denies on its own: heuristics recognise a shape, not
    malice. Every detection raises an alert.

    Args:
        verdict: the worst verdict across the connection's volumes, or ``None`` if no
            scan has finished.
        requirement: the ``scan`` of the policy action that applies to the device.
        scan_policy: the policy's ``scan`` settings.

    Raises:
        ValueError: if ``verdict`` is not a scan verdict.
    """
    if verdict is None:
        return None
    found = ScanVerdict(verdict)
    if found is ScanVerdict.CLEAN or requirement is ScanRequirement.NONE:
        return None
    on_detection = scan_policy.on_detection
    if found is ScanVerdict.MALICIOUS:
        ceiling = {
            DetectionAction.DENY: Access.DENY,
            DetectionAction.READ_ONLY: Access.READ_ONLY,
            DetectionAction.ALERT: None,
        }[on_detection]
        return ScanDetection(found, ceiling, "a scan found malicious content")
    if found is ScanVerdict.SUSPICIOUS:
        ceiling = None if on_detection is DetectionAction.ALERT else Access.READ_ONLY
        return ScanDetection(found, ceiling, "a scan found suspicious content")
    what = "did not finish" if found is ScanVerdict.INCOMPLETE else "failed"
    if requirement is ScanRequirement.REQUIRED:
        ceiling = (
            Access.DENY if scan_policy.on_incomplete is IncompleteAction.DENY else Access.READ_ONLY
        )
        return ScanDetection(found, ceiling, f"the required scan {what}")
    return ScanDetection(found, None, f"the scan {what}")


def _usable_grant(
    grant: Grant | None, device: UsbDevice, fingerprint: Fingerprint, now: datetime
) -> tuple[Grant | None, str | None]:
    """Return the grant if it may be honoured, else ``None`` and why it was ignored.

    The caller is expected to pass only a grant that is active for this device. These
    checks are the second line: a grant that slipped through for the wrong device, the
    wrong connection, the wrong port or past its end is dropped here rather than
    honoured.
    """
    if grant is None:
        return None, None
    if grant.fingerprint != fingerprint.value:
        return None, f"grant {grant.id} is for a different device and was ignored"
    if grant.ended_at is not None:
        return None, f"grant {grant.id} has ended and was ignored"
    if grant.expires_at is not None and grant.expires_at <= now:
        return None, f"grant {grant.id} expired at {utc_iso(grant.expires_at)} and was ignored"
    # The same key as portlock.auth.grants.connection_key, which is not imported here.
    connection = device.connection_id or device.instance_id
    if grant.bound_connection is not None and grant.bound_connection != connection:
        return None, f"grant {grant.id} belongs to another connection and was ignored"
    if grant.bound_port is not None and grant.bound_port != device.bus_path:
        return None, f"grant {grant.id} is limited to another port and was ignored"
    return grant, None


def decide(
    *,
    device: UsbDevice,
    fingerprint: Fingerprint,
    policy_result: PolicyResult,
    grant: Grant | None,
    protected: bool,
    protection_reasons: tuple[str, ...],
    lockdown_active: bool,
    lockdown_exempt: bool,
    now: datetime,
    scan_detection: ScanDetection | None = None,
) -> Decision:
    """Decide what one device may do.

    Precedence, highest first (docs/DESIGN.md, sections 5 and 14.8)::

        safety > lockdown > scan detection > first matching policy rule > grant
               > policy default

    1. **Safety.** A protected device is ``allow`` with source ``safety``, whatever
       else is true. It is never scanned (``scan`` is ``none``) and the decision never
       expires. ``alert`` is still taken from the policy action, so an operator learns
       that policy objected to a device that safety let through.
    2. **Lockdown.** While lockdown is active, a device that is not protected is ``deny``
       with source ``lockdown`` unless ``lockdown_exempt`` is set (the lockdown
       manager's call). An exempt device is decided by the steps below.
    3. **Scan detection.** A detection is a ceiling over steps 4 to 6: the result is
       whichever of the detection's ceiling and their outcome lets less through (deny,
       then pending, then read_only, then allow). When the ceiling is what decides, the
       source is ``scan``. Every detection sets ``alert``.
    4. **First matching policy rule.** Its ``allow``, ``read_only`` or ``deny`` is final,
       with source ``policy``: no grant changes it, in either direction. A rule's
       ``pending`` falls through to step 5.
    5. **Grant.** A grant acts only on a ``pending`` outcome, from a rule or from the
       default. It gives ``allow``, or ``read_only`` for a read-only grant, with source
       ``grant``.
    6. **Policy default.** Otherwise the default action stands, with source
       ``default``.

    ``scan`` is always the applying policy action's (the rule's or the default's): a
    grant never removes a scan requirement. ``alert`` is that action's, or true if
    there is a scan detection. ``rule_id`` names the matching rule, if any, and
    ``grant_id`` the grant that acted, if one did. ``expires_at`` is the earliest of
    that grant's expiry and ``PolicyResult.valid_until``; the caller re-evaluates then.

    A grant that is not usable for this device at ``now`` (another fingerprint, ended
    or expired, bound to another connection or limited to another port) is ignored, and
    so is a usable grant that a rule or a non-pending default leaves nothing to do; the
    reasons say which.

    Args:
        device: the device being decided.
        fingerprint: its fingerprint.
        policy_result: what :meth:`PolicyEngine.evaluate` returned for it at ``now``.
        grant: the grant active for it (``GrantStore.active_for``), or ``None``.
        protected: True if the safety layer protects this device.
        protection_reasons: why it is protected, for the decision's reasons.
        lockdown_active: True while an emergency lockdown is in force.
        lockdown_exempt: True if the lockdown manager exempts this device.
        now: the instant of the decision.
        scan_detection: what this connection's scans oblige, from
            :func:`scan_detection_for`; ``None`` if nothing.

    Returns:
        The decision, with reasons a person can read.

    Raises:
        ValueError: if ``now`` is not timezone-aware.
    """
    moment = require_aware(now, "now")
    action = policy_result.action
    rule = policy_result.rule
    verdict = action.access.value
    origin = f"rule {rule.id!r}" if rule is not None else "the policy default"

    if protected:
        name = device.display_name
        if len(name) > _SHOWN_NAME:
            name = name[:_SHOWN_NAME] + "..."
        reasons: list[str] = [*protection_reasons] or [f"{name} is a protected device"]
        reasons.append("protected devices are always allowed and never enforced against")
        if action.access is not Access.ALLOW:
            reasons.append(f"{origin} says {verdict}; safety takes precedence")
        if lockdown_active:
            reasons.append("lockdown is active; protected devices are not affected")
        return Decision(
            access=Access.ALLOW,
            source=DecisionSource.SAFETY,
            reasons=tuple(reasons),
            scan=ScanRequirement.NONE,
            alert=action.alert,
        )

    if lockdown_active and not lockdown_exempt:
        return Decision(
            access=Access.DENY,
            source=DecisionSource.LOCKDOWN,
            reasons=(
                "emergency lockdown is active; devices that are not protected are denied",
                f"without lockdown, {origin} would say {verdict}",
            ),
            scan=action.scan,
            alert=action.alert,
        )

    reasons = []
    if lockdown_active:
        reasons.append("lockdown is active, but this device is exempt from it")
    usable, ignored = _usable_grant(grant, device, fingerprint, moment)
    acting: Grant | None = None

    if action.access is not Access.PENDING:
        # A rule's allow, read_only or deny is final, and so is a default that is not
        # pending: neither leaves anything for a grant to do.
        access = action.access
        source = DecisionSource.POLICY if rule is not None else DecisionSource.DEFAULT
        reasons.append(f"{origin} says {verdict}")
        reasons.extend(policy_result.explanation)
        if ignored is not None:
            reasons.append(ignored)
        elif usable is not None:
            final = "a rule is final" if rule is not None else "the default is not pending"
            reasons.append(
                f"grant {usable.id} is not used: a grant acts only on a pending outcome,"
                f" and {final}; to change this decision, change the policy"
            )
    elif usable is not None:
        acting = usable
        access, source = usable.access, DecisionSource.GRANT
        until = f" until {utc_iso(usable.expires_at)}" if usable.expires_at is not None else ""
        reasons.append(
            f"{usable.kind.value} grant {usable.id} from {usable.granted_by} gives"
            f" {usable.access.value}{until}"
        )
        reasons.append(f"{origin} says {verdict}")
        reasons.extend(policy_result.explanation)
        if fingerprint.confidence is Confidence.LOW:
            reasons.append(
                "the fingerprint has low confidence: this grant covers every unit of this"
                " model on its port, not one device"
            )
    else:
        access = Access.PENDING
        source = DecisionSource.POLICY if rule is not None else DecisionSource.DEFAULT
        reasons.append(f"{origin} says {verdict}")
        reasons.extend(policy_result.explanation)
        if ignored is not None:
            reasons.append(ignored)

    alert = action.alert
    if scan_detection is not None:
        alert = True
        ceiling = scan_detection.ceiling
        if ceiling is not None and _OPENNESS[ceiling] < _OPENNESS[access]:
            # What decided comes first, after the note about an exempting lockdown.
            first = 1 if lockdown_active else 0
            reasons[first:first] = [
                f"{scan_detection.reason}; the device is limited to {ceiling.value}",
                f"without the scan result, the decision would be {access.value}",
            ]
            access, source = ceiling, DecisionSource.SCAN
        else:
            reasons.append(scan_detection.reason)

    expiries = [
        limit
        for limit in (
            acting.expires_at if acting is not None else None,
            policy_result.valid_until,
        )
        if limit is not None
    ]
    return Decision(
        access=access,
        source=source,
        reasons=tuple(reasons),
        rule_id=rule.id if rule is not None else None,
        grant_id=acting.id if acting is not None else None,
        scan=action.scan,
        alert=alert,
        expires_at=min(expiries) if expiries else None,
    )
