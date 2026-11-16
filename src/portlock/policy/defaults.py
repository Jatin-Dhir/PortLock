"""The policies PortLock ships with.

:data:`DEFAULT_POLICY` is what a fresh install runs: nothing is allowed automatically.
:data:`EXAMPLE_POLICY` is what ``portlock policy init`` writes for an administrator to
edit. Its sample rules are written out in full but **disabled**, so installing the file
unedited behaves exactly like the default policy; a sample rule starts to matter only
when someone has read it, changed the made-up ids in it and enabled it.

The vendor and product ids in the examples are placeholders from the open-hardware test
range, not recommendations.
"""

from __future__ import annotations

import datetime as dt

from portlock.core.models import Access, Confidence, ScanRequirement
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

__all__ = ["DEFAULT_POLICY", "DENY_INPUT_WITH_OTHER", "EXAMPLE_POLICY"]

#: The one rule of the default policy. An input interface beside any other function
#: (storage, network, serial, vendor-specific, ...) is the shape of a "BadUSB" stick or a
#: network-tap implant (docs/DESIGN.md, sections 2 and 14.2). Such a device is not
#: covered by the protection that keeps the operator's keyboard working; it is denied
#: outright by a rule, so no grant can let it in, and an alert is raised.
DENY_INPUT_WITH_OTHER = Rule(
    id="deny-input-with-other",
    description=(
        "A keyboard, mouse or other input interface beside any other function (storage,"
        " network, serial, vendor-specific) is the shape of a BadUSB stick or a network"
        " implant. Denied, with an alert. A grant cannot override a rule; to permit such"
        " a device, put a more specific rule above this one."
    ),
    match=Match(mixes_input_with_other=True),
    action=RuleAction(Access.DENY, alert=True),
)

#: Unknown devices wait for an administrator. Once one is granted access its volumes are
#: scanned when they mount.
_DEFAULT_ACTION = RuleAction(Access.PENDING, scan=ScanRequirement.ON_MOUNT)

#: Detections deny; a required scan that does not finish leaves the device read-only.
_DEFAULT_SCAN = ScanPolicy(DetectionAction.DENY, IncompleteAction.READ_ONLY)

DEFAULT_POLICY = Policy(
    name="PortLock default policy",
    default=_DEFAULT_ACTION,
    rules=(DENY_INPUT_WITH_OTHER,),
    scan=_DEFAULT_SCAN,
)

EXAMPLE_POLICY = Policy(
    name="Example policy (edit before use)",
    default=_DEFAULT_ACTION,
    rules=(
        DENY_INPUT_WITH_OTHER,
        Rule(
            id="example-deny-product",
            description=(
                "EXAMPLE, disabled. Deny one product outright, by vendor and product id."
                " Deny rules belong at the top: the first matching rule wins, and a grant"
                " never overrides a rule."
            ),
            enabled=False,
            match=Match(vendor_id=0x1209, product_id=0x0005),
            action=RuleAction(Access.DENY, alert=True),
        ),
        Rule(
            id="example-allow-working-hours",
            description=(
                "EXAMPLE, disabled. Allow one product, but only Monday to Friday between"
                " 09:00 and 17:00 UTC; outside those hours the rule does not match and"
                " later rules decide. It stands above the vendor-wide rule below because"
                " the more specific rule has to come first."
            ),
            enabled=False,
            match=Match(
                vendor_id=0x1209,
                product_id=0x0001,
                confidence=Confidence.HIGH,
                time=TimeWindow(days=(0, 1, 2, 3, 4), start=dt.time(9, 0), end=dt.time(17, 0)),
            ),
            action=RuleAction(Access.ALLOW, scan=ScanRequirement.ON_MOUNT),
        ),
        Rule(
            id="example-trust-vendor-read-only",
            description=(
                "EXAMPLE, disabled. Let every storage device of one vendor in, read-only."
                " A vendor id is claimed by the device and is easy to copy, so this"
                " demands a high-confidence fingerprint and never gives write access. The"
                " rule is final: a grant does not change what it decides."
            ),
            enabled=False,
            match=Match(vendor_id=0x1209, storage_like=True, confidence=Confidence.HIGH),
            action=RuleAction(Access.READ_ONLY, scan=ScanRequirement.ON_MOUNT),
        ),
        Rule(
            id="example-require-scan",
            description=(
                "EXAMPLE, disabled. Keep every other storage device, phones and cameras"
                " included, pending, and require a clean scan before a grant takes full"
                " effect: the device is read-only while it is scanned and gets the"
                " granted access only on a clean verdict."
            ),
            enabled=False,
            match=Match(storage_like=True),
            action=RuleAction(Access.PENDING, scan=ScanRequirement.REQUIRED),
        ),
    ),
    scan=_DEFAULT_SCAN,
)
