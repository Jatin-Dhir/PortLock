"""PortLock Policy: the policy model, its validation and the pure decision logic.

* :mod:`portlock.policy.model` - the immutable policy values.
* :mod:`portlock.policy.loader` - reading, validating, writing and hashing documents.
* :mod:`portlock.policy.defaults` - the default policy and the example policy.
* :mod:`portlock.policy.engine` - evaluating a device against a policy.
* :mod:`portlock.policy.decide` - combining safety, lockdown, scan results, policy and
  grants.

Nothing in this package talks to the operating system, reads a clock or imports
``portlock.guard``. ``docs/POLICY.md`` is the reference for policy authors.
"""

from __future__ import annotations

from portlock.policy.decide import ScanDetection, ScanVerdict, decide, scan_detection_for
from portlock.policy.defaults import DEFAULT_POLICY, DENY_INPUT_WITH_OTHER, EXAMPLE_POLICY
from portlock.policy.engine import (
    CriterionTrace,
    PolicyEngine,
    PolicyResult,
    RuleOutcome,
    RuleTrace,
)
from portlock.policy.loader import (
    dump_policy_json,
    load_policy_file,
    parse_policy,
    policy_hash,
    policy_to_dict,
    save_policy,
)
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

__all__ = [
    "DEFAULT_POLICY",
    "DENY_INPUT_WITH_OTHER",
    "EXAMPLE_POLICY",
    "CriterionTrace",
    "DetectionAction",
    "IncompleteAction",
    "Match",
    "Policy",
    "PolicyEngine",
    "PolicyResult",
    "Rule",
    "RuleAction",
    "RuleOutcome",
    "RuleTrace",
    "ScanDetection",
    "ScanPolicy",
    "ScanVerdict",
    "TimeWindow",
    "decide",
    "dump_policy_json",
    "load_policy_file",
    "parse_policy",
    "policy_hash",
    "policy_to_dict",
    "save_policy",
    "scan_detection_for",
]
