"""The safety choke point: never lock the operator out.

PortLock can make an operating system stop talking to hardware. Pointed at the wrong
device, that takes away the keyboard the operator would use to undo it, or the disk the
system is running from. So nothing calls an :class:`~portlock.guard.base.Enforcer`
directly. Every call goes through :class:`SafeEnforcer`, which asks :func:`is_protected`
first and refuses to restrict a protected device **whatever policy, a grant or a lockdown
says** (``docs/DESIGN.md`` sections 2 and 14).

A device is protected when any of these holds:

* it is a hub, and nothing but a hub;
* it is built in (the platform reports it as not removable);
* it backs the system volume;
* its fingerprint is pinned by an administrator (on any port);
* it is enrolled: its fingerprint *and* its port match an enrolment;
* it is an input device and nothing else (hubs aside), unless HID enforcement is enabled.

Being connected when the service starts confers nothing (section 14.1): otherwise anyone
able to cause a restart could turn a hostile device into a protected one.

The two *category* rules (hub, input-only) look at descriptors the device chooses for
itself, so they apply only to the shapes real hubs and keyboards have. A device that puts
**any other function beside an input interface** (storage, network, serial, imaging,
vendor-specific) is the shape of a "BadUSB" stick or a network-tap implant, and a hub
interface beside anything else is not a hub anybody has built (a hub with a card reader
presents the reader as a separate device downstream). Such devices get no category
protection; they are still protected if pinned, enrolled, built in or backing the system
volume, because those facts come from the administrator or the platform.

Every scope, the default ``storage`` included, covers mass storage, imaging devices and
every device that mixes an input interface with another function (section 14.5), so the
default policy's denial of those devices is actually enforced.

Being **outside the enforcement scope is not protection** (section 14.5). It is reported
separately (``ProtectionVerdict.in_scope``), and :class:`SafeEnforcer` answers a
restricting call on such a device with ``mechanism="out-of-scope"``, never ``"refused"``,
so that it is recorded as *not enforced* rather than as *protected*.

Restoring access is never refused. ``unblock``, ``set_read_only(device, False)``,
``set_default_deny(False)`` and ``restore`` are not subject to either check.

This module also holds two other pieces of the protection design: :func:`detect_clone`
(section 14.1, a second connection presenting an enrolled fingerprint) and
:class:`PortFlapGuard` (section 14.6, port hold-down).
"""

from __future__ import annotations

import dataclasses
import logging
import math
import threading
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from portlock.core.clock import Clock
from portlock.core.config import (
    SCOPE_ALL_EXCEPT_PROTECTED,
    SCOPE_STORAGE,
    SCOPE_STORAGE_AND_UNKNOWN,
    SCOPES,
)
from portlock.core.fingerprint import fingerprint as compute_fingerprint
from portlock.core.models import DeviceCategory, Fingerprint, UsbDevice
from portlock.guard.base import (
    Action,
    EnforcementResult,
    Enforcer,
    EnforcerCapabilities,
    JournalEntry,
)

__all__ = [
    "CODE_BUILT_IN",
    "CODE_CHECK_FAILED",
    "CODE_CLONE",
    "CODE_ENROLLED",
    "CODE_HUB",
    "CODE_INPUT_DEVICE",
    "CODE_OUT_OF_SCOPE",
    "CODE_PINNED",
    "CODE_SYSTEM_VOLUME",
    "MECHANISM_DRY_RUN",
    "MECHANISM_ERROR",
    "MECHANISM_OUT_OF_SCOPE",
    "MECHANISM_REFUSED",
    "MECHANISM_UNSUPPORTED",
    "FlapVerdict",
    "PortFlapGuard",
    "PortRelease",
    "ProtectionVerdict",
    "RefusalCallback",
    "SafeEnforcer",
    "SafetyContext",
    "detect_clone",
    "is_protected",
]

#: The device is a USB hub and nothing else.
CODE_HUB = "hub"
#: The platform reports the device as built in (not removable).
CODE_BUILT_IN = "built_in"
#: The device backs the system volume.
CODE_SYSTEM_VOLUME = "system_volume"
#: An administrator pinned the device's fingerprint (any port).
CODE_PINNED = "pinned"
#: The device's fingerprint and port match an enrolment.
CODE_ENROLLED = "enrolled"
#: The device is input-only and HID enforcement is off.
CODE_INPUT_DEVICE = "input_device"
#: The protection check itself could not be carried out, so the device is left alone.
CODE_CHECK_FAILED = "safety_check_failed"
#: The device is outside the enforcement scope. Not a protection code: it never appears
#: in ``ProtectionVerdict.codes``; it prefixes the error of an out-of-scope result.
CODE_OUT_OF_SCOPE = "out_of_scope"
#: A second connection presents an enrolled fingerprint (see :func:`detect_clone`).
CODE_CLONE = "enrolled_fingerprint_clone"

#: ``EnforcementResult.mechanism`` when the safety layer declined to act.
MECHANISM_REFUSED = "refused"
#: ``EnforcementResult.mechanism`` when the device is outside the enforcement scope.
MECHANISM_OUT_OF_SCOPE = "out-of-scope"
#: ``EnforcementResult.mechanism`` when nothing was changed because of dry-run mode.
MECHANISM_DRY_RUN = "dry-run"
#: ``EnforcementResult.mechanism`` when the wrapped enforcer broke its no-raise contract.
MECHANISM_ERROR = "error"
#: ``EnforcementResult.mechanism`` when the wrapped enforcer has no such mechanism at all.
MECHANISM_UNSUPPORTED = "unsupported"

_LOG = logging.getLogger(__name__)
_UNKNOWN_CATEGORIES = frozenset({DeviceCategory.OTHER, DeviceCategory.VENDOR})
_HUB_ONLY = frozenset({DeviceCategory.HUB})
_DRY_RUN_NOTE = "dry-run: enforcement calls are recorded but nothing is changed"


@dataclass(frozen=True, slots=True)
class SafetyContext:
    """What the safety layer needs to know about this machine, at one moment.

    Attributes:
        enrolled: ``(fingerprint value, bus path)`` pairs recorded by ``portlock
            enroll``. A device is protected by an enrolment only when both match.
        pinned_fingerprints: fingerprint values an administrator pinned; they protect
            the device on any port.
        system_instance_ids: instance ids of the devices backing the system volume.
            Compared without regard to case, as Windows instance ids are.
        hid_enforcement_enabled: True only if *both* HID settings are on
            (``Config.hid_enforcement_enabled``).
        scope: the enforcement scope, one of ``portlock.core.config.SCOPES``.

    Raises:
        ValueError: if ``scope`` is not a known scope, a set holds something other than
            non-empty strings, or an enrolment is not a pair of non-empty strings.
    """

    enrolled: frozenset[tuple[str, str]] = frozenset()
    pinned_fingerprints: frozenset[str] = frozenset()
    system_instance_ids: frozenset[str] = frozenset()
    hid_enforcement_enabled: bool = False
    scope: str = SCOPE_STORAGE
    _folded_system_ids: frozenset[str] = field(
        default=frozenset(), init=False, repr=False, compare=False
    )
    _enrolled_values: frozenset[str] = field(
        default=frozenset(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        enrolled = _pair_set("enrolled", self.enrolled)
        pinned = _string_set("pinned_fingerprints", self.pinned_fingerprints)
        instance_ids = _string_set("system_instance_ids", self.system_instance_ids)
        if not isinstance(self.scope, str) or self.scope not in SCOPES:
            raise ValueError(f"unknown enforcement scope {self.scope!r}; expected one of {SCOPES}")
        if not isinstance(self.hid_enforcement_enabled, bool):
            raise ValueError("hid_enforcement_enabled must be True or False")
        object.__setattr__(self, "enrolled", enrolled)
        object.__setattr__(self, "pinned_fingerprints", pinned)
        object.__setattr__(self, "system_instance_ids", instance_ids)
        object.__setattr__(
            self, "_folded_system_ids", frozenset(value.casefold() for value in instance_ids)
        )
        object.__setattr__(self, "_enrolled_values", frozenset(value for value, _ in enrolled))

    @property
    def enrolled_fingerprints(self) -> frozenset[str]:
        """Every enrolled fingerprint value, whatever its port."""
        return self._enrolled_values

    def backs_system_volume(self, instance_id: str) -> bool:
        """True if ``instance_id`` names a device backing the system volume."""
        return instance_id.casefold() in self._folded_system_ids

    def is_enrolled(self, fingerprint_value: str, bus_path: str | None) -> bool:
        """True if this fingerprint is enrolled on exactly this port."""
        return bus_path is not None and (fingerprint_value, bus_path) in self.enrolled


@dataclass(frozen=True, slots=True)
class ProtectionVerdict:
    """Whether a device is protected, whether it is in scope, and why.

    Attributes:
        protected: True if PortLock must not restrict the device.
        in_scope: True if the enforcement scope covers the device. A device outside
            the scope is *not enforced*, which is not the same as protected.
        reasons: one sentence per protection rule that applies, for people.
        codes: the matching ``CODE_*`` constants, for programs; same order as
            ``reasons``. Empty exactly when ``protected`` is False.
        scope_reason: why the device is outside the scope; empty when it is in scope.
    """

    protected: bool
    in_scope: bool
    reasons: tuple[str, ...] = ()
    codes: tuple[str, ...] = ()
    scope_reason: str = ""

    @property
    def enforceable(self) -> bool:
        """True if a restricting call may reach the operating system."""
        return self.in_scope and not self.protected

    def to_dict(self) -> dict[str, object]:
        return {
            "protected": self.protected,
            "in_scope": self.in_scope,
            "reasons": list(self.reasons),
            "codes": list(self.codes),
            "scope_reason": self.scope_reason,
        }


RefusalCallback = Callable[[UsbDevice, Action, ProtectionVerdict], None]


def is_protected(
    device: UsbDevice, fingerprint: Fingerprint | str, context: SafetyContext
) -> ProtectionVerdict:
    """Decide whether ``device`` must be left alone, and whether the scope covers it.

    Pure: the answer depends only on the arguments. Every protection rule that applies
    is listed, not just the first.

    Args:
        device: the device as currently connected.
        fingerprint: its fingerprint (the object or just the value).
        context: the machine's safety facts and settings.

    Returns:
        The verdict; see the module docstring for the rules.
    """
    value = fingerprint.value if isinstance(fingerprint, Fingerprint) else fingerprint
    found: list[tuple[str, str]] = []

    if device.categories == _HUB_ONLY:
        found.append((CODE_HUB, "it is a USB hub; blocking it would cut off everything behind it"))
    if device.removable is False:
        found.append((CODE_BUILT_IN, "it is built into this machine"))
    if context.backs_system_volume(device.instance_id):
        found.append((CODE_SYSTEM_VOLUME, "it backs the system volume"))
    if value in context.pinned_fingerprints:
        found.append((CODE_PINNED, "its fingerprint is pinned by an administrator"))
    if context.is_enrolled(value, device.bus_path):
        found.append(
            (CODE_ENROLLED, f"it is enrolled on this port ({device.bus_path}) by an administrator")
        )
    if device.is_input_only and not context.hid_enforcement_enabled:
        found.append(
            (CODE_INPUT_DEVICE, "it is only an input device and HID enforcement is not enabled")
        )
    in_scope = _in_scope(device, context.scope)
    return ProtectionVerdict(
        protected=bool(found),
        in_scope=in_scope,
        reasons=tuple(reason for _, reason in found),
        codes=tuple(code for code, _ in found),
        scope_reason="" if in_scope else _scope_reason(context.scope),
    )


def _in_scope(device: UsbDevice, scope: str) -> bool:
    if scope == SCOPE_ALL_EXCEPT_PROTECTED:
        return True
    # Every scope covers storage-like devices and devices that put another function
    # beside an input interface (section 14.5). The default policy denies the latter as
    # the shape of a "BadUSB" or network-tap implant; leaving them outside the default
    # scope would make that denial a record that nothing enforces.
    if device.is_storage_like or device.mixes_input_with_other:
        return True
    if scope == SCOPE_STORAGE_AND_UNKNOWN:
        return device.categories <= _UNKNOWN_CATEGORIES
    # SCOPE_STORAGE covers nothing else.
    return False


def _scope_reason(scope: str) -> str:
    mixed = "devices that put another function beside an input interface"
    covered = {
        SCOPE_STORAGE: f"mass storage and imaging devices, and {mixed}",
        SCOPE_STORAGE_AND_UNKNOWN: (
            f"mass storage and imaging devices, {mixed}, and devices that declare "
            "nothing recognisable"
        ),
    }.get(scope, "every device")
    return f'it is outside the enforcement scope "{scope}", which covers only {covered}'


def detect_clone(
    device: UsbDevice,
    fingerprint: Fingerprint | str,
    connected: Iterable[tuple[UsbDevice, Fingerprint | str]],
    context: SafetyContext,
) -> tuple[UsbDevice, ...]:
    """Find the connections that ``device`` duplicates, if its fingerprint is enrolled.

    Section 14.1: a second device presenting an enrolled fingerprint while the first is
    connected is denied and raises an alert. A fingerprint is copied as easily as it is
    read, so two simultaneous connections with one enrolled fingerprint mean at least one
    of them is not the device that was enrolled. Fingerprints that are not enrolled are
    ignored: two identical sticks without serial numbers legitimately share one.

    Args:
        device: the connection being evaluated (typically the newest arrival).
        fingerprint: its fingerprint (the object or just the value).
        connected: every connection currently present, each with its fingerprint. The
            evaluated connection itself may be included; it is recognised and skipped.
        context: supplies the enrolments.

    Returns:
        The *other* connections presenting the same enrolled fingerprint, in the order
        given; empty if there are none. The caller denies ``device`` (unless the safety
        layer protects it on its own enrolled port) and raises an alert with
        :data:`CODE_CLONE`.
    """
    value = fingerprint.value if isinstance(fingerprint, Fingerprint) else fingerprint
    if value not in context.enrolled_fingerprints:
        return ()
    duplicates: list[UsbDevice] = []
    for other, other_fingerprint in connected:
        other_value = (
            other_fingerprint.value
            if isinstance(other_fingerprint, Fingerprint)
            else other_fingerprint
        )
        if other_value == value and not _same_connection(device, other):
            duplicates.append(other)
    return tuple(duplicates)


def _same_connection(first: UsbDevice, second: UsbDevice) -> bool:
    if first.instance_id.casefold() != second.instance_id.casefold():
        return False
    # The instance id survives a re-plug, so when both carry a connection id it decides.
    if first.connection_id is not None and second.connection_id is not None:
        return first.connection_id == second.connection_id
    return True


def _string_set(name: str, values: Iterable[str]) -> frozenset[str]:
    if isinstance(values, str | bytes):
        raise ValueError(f"{name} must be a set of strings, not a single string")
    result = frozenset(values)
    for value in result:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} must contain only non-empty strings, got {value!r}")
    return result


def _pair_set(name: str, values: Iterable[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    if isinstance(values, str | bytes):
        raise ValueError(f"{name} must be a set of (fingerprint, bus path) pairs")
    pairs: set[tuple[str, str]] = set()
    for item in values:
        if isinstance(item, str | bytes) or not isinstance(item, Sequence) or len(item) != 2:
            raise ValueError(f"{name} must contain (fingerprint, bus path) pairs, got {item!r}")
        value, bus_path = item
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name}: the fingerprint must be a non-empty string")
        if not isinstance(bus_path, str) or not bus_path:
            raise ValueError(f"{name}: the bus path must be a non-empty string")
        pairs.add((value, bus_path))
    return frozenset(pairs)


class SafeEnforcer(Enforcer):
    """The only way enforcement is reached: an :class:`Enforcer` that guards another.

    * ``block``, ``eject`` and ``set_read_only(device, True)`` on a protected device are
      refused: the result has ``ok=False`` and ``mechanism="refused"``, ``on_refusal``
      is told, and the wrapped enforcer is not called.
    * The same calls on a device outside the enforcement scope are not attempted: the
      result has ``ok=False`` and ``mechanism="out-of-scope"``, and the wrapped enforcer
      is not called. This is *not enforced*, not a refusal, so ``on_refusal`` is not
      told. A device that is both protected and out of scope is refused.
    * ``unblock``, ``set_read_only(device, False)``, ``set_default_deny(False)`` and
      ``restore`` are never refused.
    * If the protection check cannot be carried out (the context provider or the
      fingerprint computation fails), the device is treated as protected. The safety
      layer fails towards leaving hardware alone.
    * In dry-run mode **no** call reaches the wrapped enforcer, restoring calls
      included; each returns ``ok=True`` with ``mechanism="dry-run"`` and
      ``changed=False``. A dry-run enforcer therefore cannot undo anything: a service
      that leaves enforce mode must restore through its enforcing instance first.
    * The wrapped enforcer's promise not to raise is made good here: an exception from
      it, or a return value that is not an :class:`EnforcementResult`, becomes an
      ``ok=False`` result with ``mechanism="error"``.

    The object holds no mutable state and may be shared between threads; whether calls
    may overlap is up to the wrapped enforcer.

    Args:
        inner: the enforcer that actually changes the operating system.
        context_provider: returns the current :class:`SafetyContext`. Called on every
            restricting call, so pins, enrolments and settings can change while the
            service runs.
        dry_run: record what would be done and change nothing (monitor mode).
        on_refusal: told about every refused call, typically to audit it. An exception
            from it is logged and otherwise ignored.
    """

    def __init__(
        self,
        inner: Enforcer,
        context_provider: Callable[[], SafetyContext],
        *,
        dry_run: bool,
        on_refusal: RefusalCallback | None = None,
    ) -> None:
        if not isinstance(inner, Enforcer):
            raise TypeError(f"inner must be an Enforcer, got {type(inner).__name__}")
        if not callable(context_provider):
            raise TypeError("context_provider must be callable")
        if not isinstance(dry_run, bool):
            raise TypeError("dry_run must be True or False")
        if on_refusal is not None and not callable(on_refusal):
            raise TypeError("on_refusal must be callable or None")
        self._inner = inner
        self._context_provider = context_provider
        self._dry_run = dry_run
        self._on_refusal = on_refusal

    @property
    def dry_run(self) -> bool:
        """True if this enforcer never changes anything."""
        return self._dry_run

    def protection(self, device: UsbDevice) -> ProtectionVerdict:
        """The verdict this enforcer would act on for ``device`` right now.

        Never raises. If the check cannot be carried out, the verdict is "protected"
        with :data:`CODE_CHECK_FAILED`.
        """
        try:
            context = self._context_provider()
            if not isinstance(context, SafetyContext):
                raise TypeError(
                    f"context provider returned {type(context).__name__}, not a SafetyContext"
                )
            return is_protected(device, compute_fingerprint(device), context)
        except Exception as exc:
            _LOG.error("safety check failed; treating the device as protected", exc_info=exc)
            return ProtectionVerdict(
                protected=True,
                in_scope=False,
                reasons=(
                    "the safety check could not be completed "
                    f"({type(exc).__name__}: {exc}), so the device is left alone",
                ),
                codes=(CODE_CHECK_FAILED,),
            )

    def capabilities(self) -> EnforcerCapabilities:
        """The wrapped enforcer's capabilities, with a note when dry-run is active.

        If the wrapped enforcer cannot even report its capabilities, everything is
        reported as unavailable, with the reason in ``notes``.
        """
        try:
            capabilities = self._inner.capabilities()
            if not isinstance(capabilities, EnforcerCapabilities):
                raise TypeError(
                    f"capabilities() returned {type(capabilities).__name__}, "
                    "not EnforcerCapabilities"
                )
        except Exception as exc:
            _LOG.error("the enforcer could not report its capabilities", exc_info=exc)
            capabilities = EnforcerCapabilities(
                name=type(self._inner).__name__,
                privileged=False,
                block=False,
                read_only=False,
                eject=False,
                default_deny=False,
                notes=(f"capabilities could not be determined: {type(exc).__name__}: {exc}",),
            )
        if self._dry_run:
            return dataclasses.replace(capabilities, notes=(*capabilities.notes, _DRY_RUN_NOTE))
        return capabilities

    def block(self, device: UsbDevice) -> EnforcementResult:
        """Block ``device`` unless it is protected or out of scope."""
        return self._guarded(Action.BLOCK, device, lambda: self._inner.block(device))

    def unblock(self, device: UsbDevice) -> EnforcementResult:
        """Reverse a block. Never refused."""
        return self._unguarded(
            Action.UNBLOCK, f"unblock {_label(device)}", lambda: self._inner.unblock(device)
        )

    def set_read_only(self, device: UsbDevice, read_only: bool) -> EnforcementResult:
        """Make ``device`` read-only (guarded) or writable (never refused)."""
        if not isinstance(read_only, bool):
            raise TypeError("read_only must be True or False")
        if read_only:
            return self._guarded(
                Action.READ_ONLY, device, lambda: self._inner.set_read_only(device, True)
            )
        return self._unguarded(
            Action.READ_WRITE,
            f"make {_label(device)} writable",
            lambda: self._inner.set_read_only(device, False),
        )

    def eject(self, device: UsbDevice) -> EnforcementResult:
        """Eject ``device`` unless it is protected or out of scope."""
        return self._guarded(Action.EJECT, device, lambda: self._inner.eject(device))

    def set_default_deny(self, enabled: bool) -> EnforcementResult:
        """Turn default-deny for new devices on or off.

        This is not about one device, so there is nothing to check for protection.
        Whoever turns it on is responsible for authorizing protected devices that
        arrive afterwards; ``unblock`` is never refused, precisely so that they can.
        """
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.DEFAULT_DENY_ON if enabled else Action.DEFAULT_DENY_OFF
        return self._unguarded(
            action,
            f"turn default-deny {'on' if enabled else 'off'}",
            lambda: self._inner.set_default_deny(enabled),
        )

    def set_baseline_read_only(self, enabled: bool) -> EnforcementResult:
        """Turn the standing read-only baseline (DESIGN 14.14) on or off.

        Handled like :meth:`set_default_deny`: it is not about one device, so there is no
        protection check, and in dry-run mode nothing reaches the wrapped enforcer. The
        baseline is not part of the :class:`Enforcer` interface because only some
        enforcers can offer it. When the wrapped one cannot, the result is
        ``ok=False`` with ``mechanism="unsupported"``, so the caller records the
        baseline as not in place instead of assuming it is.
        """
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be True or False")
        action = Action.READ_ONLY if enabled else Action.READ_WRITE
        setter = getattr(self._inner, "set_baseline_read_only", None)
        what = f"turn the read-only baseline {'on' if enabled else 'off'}"
        if self._dry_run:
            note = "" if callable(setter) else " (this enforcer offers no baseline)"
            return EnforcementResult(
                action=action,
                ok=True,
                mechanism=MECHANISM_DRY_RUN,
                detail=f"dry-run: {what} was not attempted{note}",
            )
        if not callable(setter):
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_UNSUPPORTED,
                detail=f"not enforced: {what}: this enforcer offers no baseline",
                error="unsupported: this enforcer has no standing read-only baseline",
            )
        return self._call(action, lambda: setter(enabled))

    def restore(self, entries: Sequence[JournalEntry]) -> EnforcementResult:
        """Put journaled settings back. Never refused."""
        frozen = tuple(entries)
        return self._unguarded(
            Action.RESTORE,
            f"restore {len(frozen)} journal entries",
            lambda: self._inner.restore(frozen),
        )

    def _guarded(
        self, action: Action, device: UsbDevice, call: Callable[[], EnforcementResult]
    ) -> EnforcementResult:
        """Run a call that takes access away, after the protection and scope checks."""
        verdict = self.protection(device)
        what = f"{action.value} {_label(device)}"
        if self._dry_run:
            # Monitor mode changes nothing and reports success, but the record still
            # says what enforce mode would have done with this device.
            if verdict.protected:
                outcome = f"would be refused: {'; '.join(verdict.reasons)}"
            elif not verdict.in_scope:
                outcome = f"would not be enforced: {verdict.scope_reason}"
            else:
                outcome = "would be attempted"
            return EnforcementResult(
                action=action,
                ok=True,
                mechanism=MECHANISM_DRY_RUN,
                detail=f"dry-run: {what} {outcome}",
            )
        if verdict.protected:
            reasons = "; ".join(verdict.reasons)
            self._report_refusal(device, action, verdict)
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_REFUSED,
                detail=f"refused to {what}: {reasons}",
                error=f"protected device ({', '.join(verdict.codes)}): {reasons}",
            )
        if not verdict.in_scope:
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_OUT_OF_SCOPE,
                detail=f"not enforced: {what}: {verdict.scope_reason}",
                error=f"{CODE_OUT_OF_SCOPE}: {verdict.scope_reason}",
            )
        return self._call(action, call)

    def _unguarded(
        self, action: Action, what: str, call: Callable[[], EnforcementResult]
    ) -> EnforcementResult:
        """Run a call that is not subject to the protection check."""
        if self._dry_run:
            return EnforcementResult(
                action=action,
                ok=True,
                mechanism=MECHANISM_DRY_RUN,
                detail=f"dry-run: {what} was not attempted",
            )
        return self._call(action, call)

    def _call(self, action: Action, call: Callable[[], EnforcementResult]) -> EnforcementResult:
        try:
            result = call()
        except Exception as exc:
            _LOG.error("enforcer raised during %s", action.value, exc_info=exc)
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_ERROR,
                detail=f"{action.value} failed: the enforcer raised {type(exc).__name__}",
                error=f"{type(exc).__name__}: {exc}",
            )
        if not isinstance(result, EnforcementResult):
            return EnforcementResult(
                action=action,
                ok=False,
                mechanism=MECHANISM_ERROR,
                detail=f"{action.value} failed: the enforcer returned no result",
                error=f"enforcer returned {type(result).__name__} instead of an EnforcementResult",
            )
        return result

    def _report_refusal(
        self, device: UsbDevice, action: Action, verdict: ProtectionVerdict
    ) -> None:
        if self._on_refusal is None:
            return
        try:
            self._on_refusal(device, action, verdict)
        except Exception as exc:
            # The refusal stands whether or not it could be reported.
            _LOG.error("refusal callback failed", exc_info=exc)


def _label(device: UsbDevice) -> str:
    return f"{device.display_name} [{device.vid_pid}] at {device.instance_id}"


# --- port hold-down (section 14.6) -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class FlapVerdict:
    """What :meth:`PortFlapGuard.record_arrival` decided about one arrival.

    Attributes:
        port: the port the arrival was on (``None`` if the platform gave none).
        held: True if the port is held: the arrival must be blocked, whatever policy
            says, unless the safety layer protects the device.
        newly_held: True if this arrival started the hold (alert once, here).
        audit: True if this arrival deserves its own audit record. False while a hold
            is coalescing arrivals; their count is reported when the hold ends.
        arrivals: arrivals on the port within the window, this one included (while
            held: since the hold began, the one that started it included).
        held_until: monotonic time at which the hold ends, if held.
    """

    port: str | None
    held: bool
    newly_held: bool
    audit: bool
    arrivals: int
    held_until: float | None = None


@dataclass(frozen=True, slots=True)
class PortRelease:
    """A hold that has ended, for the one audit record that summarizes it.

    Attributes:
        port: the port that was held.
        coalesced: arrivals during the hold that got no audit record of their own.
        held_seconds: how long the hold lasted, by the monotonic clock.
        manual: True if an administrator ended it early (:meth:`PortFlapGuard.release`).
    """

    port: str
    coalesced: int
    held_seconds: float
    manual: bool = False


@dataclass(slots=True)
class _PortState:
    arrivals: deque[float] = field(default_factory=deque)
    held_since: float | None = None
    held_until: float | None = None
    coalesced: int = 0


class PortFlapGuard:
    """Port hold-down: stop a device replaying the reactive window by re-enumerating.

    Enforcement after arrival is reactive (``docs/DESIGN.md`` section 6): for a moment
    the device is usable. A device that disconnects and reconnects itself over and over
    gets that moment every time, and floods the audit log as well. So when a port sees
    **more than** ``max_arrivals`` arrivals within ``window_seconds``, the port is
    *held*: every arrival on it is blocked, and audited only in summary, until
    ``cooldown_seconds`` pass without a further arrival. Each arrival during a hold
    restarts the cool-down, so a device that keeps flapping keeps the port held.

    This is a pure state machine: it reads only the injected clock's ``monotonic()``,
    performs no input or output and takes no action. The caller blocks what
    :meth:`record_arrival` says is held, writes the audit records it asks for, and calls
    :meth:`release_expired` periodically to learn which holds have ended. Memory is
    bounded by the ports that saw an arrival within the last window or are held.

    All methods are thread-safe.

    Args:
        clock: supplies monotonic time (wall-clock changes do not affect a hold).
        max_arrivals: arrivals tolerated within the window; one more starts a hold.
        window_seconds: length of the sliding window.
        cooldown_seconds: how long a held port must stay quiet before it is released.

    Raises:
        ValueError: if a number is not positive and finite, or ``max_arrivals`` is not
            an integer of at least 1.
        TypeError: if ``clock`` has no ``monotonic`` method.
    """

    def __init__(
        self,
        clock: Clock,
        max_arrivals: int,
        window_seconds: float,
        cooldown_seconds: float,
    ) -> None:
        if not callable(getattr(clock, "monotonic", None)):
            raise TypeError("clock must provide monotonic()")
        if isinstance(max_arrivals, bool) or not isinstance(max_arrivals, int) or max_arrivals < 1:
            raise ValueError(f"max_arrivals must be an integer of at least 1, got {max_arrivals!r}")
        self._window = _positive_seconds("window_seconds", window_seconds)
        self._cooldown = _positive_seconds("cooldown_seconds", cooldown_seconds)
        self._clock = clock
        self._max_arrivals = max_arrivals
        self._lock = threading.Lock()
        self._ports: dict[str, _PortState] = {}
        self._released: list[PortRelease] = []

    @property
    def max_arrivals(self) -> int:
        return self._max_arrivals

    @property
    def window_seconds(self) -> float:
        return self._window

    @property
    def cooldown_seconds(self) -> float:
        return self._cooldown

    def record_arrival(self, port: str | None) -> FlapVerdict:
        """Count an arrival on ``port`` and say whether the port is held.

        An arrival without a port cannot be attributed and is never held.
        """
        if port is None:
            return FlapVerdict(port=None, held=False, newly_held=False, audit=True, arrivals=1)
        if not isinstance(port, str) or not port:
            raise ValueError("port must be a non-empty string or None")
        with self._lock:
            now = self._clock.monotonic()
            self._expire_locked(now)
            state = self._ports.setdefault(port, _PortState())
            if state.held_until is not None:
                state.coalesced += 1
                state.held_until = now + self._cooldown
                return FlapVerdict(
                    port=port,
                    held=True,
                    newly_held=False,
                    audit=False,
                    arrivals=state.coalesced + 1,
                    held_until=state.held_until,
                )
            self._trim_locked(state, now)
            state.arrivals.append(now)
            count = len(state.arrivals)
            if count <= self._max_arrivals:
                return FlapVerdict(
                    port=port, held=False, newly_held=False, audit=True, arrivals=count
                )
            state.arrivals.clear()
            state.held_since = now
            state.held_until = now + self._cooldown
            state.coalesced = 0
            return FlapVerdict(
                port=port,
                held=True,
                newly_held=True,
                audit=True,
                arrivals=count,
                held_until=state.held_until,
            )

    def is_held(self, port: str | None) -> bool:
        """True if ``port`` is held right now."""
        if port is None:
            return False
        with self._lock:
            self._expire_locked(self._clock.monotonic())
            state = self._ports.get(port)
            return state is not None and state.held_until is not None

    def held_ports(self) -> dict[str, float]:
        """Every held port and the monotonic time its hold ends."""
        with self._lock:
            self._expire_locked(self._clock.monotonic())
            return {
                port: state.held_until
                for port, state in self._ports.items()
                if state.held_until is not None
            }

    def release_expired(self) -> tuple[PortRelease, ...]:
        """Return every hold that has ended since the last call, oldest first."""
        with self._lock:
            self._expire_locked(self._clock.monotonic())
            released, self._released = tuple(self._released), []
            return released

    def release(self, port: str) -> PortRelease | None:
        """End a hold early (an administrator's decision). ``None`` if it was not held."""
        with self._lock:
            now = self._clock.monotonic()
            self._expire_locked(now)
            state = self._ports.get(port)
            if state is None or state.held_until is None or state.held_since is None:
                return None
            release = PortRelease(
                port=port,
                coalesced=state.coalesced,
                held_seconds=now - state.held_since,
                manual=True,
            )
            del self._ports[port]
            return release

    def _trim_locked(self, state: _PortState, now: float) -> None:
        # An arrival counts while it is less than one window old.
        while state.arrivals and now - state.arrivals[0] >= self._window:
            state.arrivals.popleft()

    def _expire_locked(self, now: float) -> None:
        for port in list(self._ports):
            state = self._ports[port]
            if state.held_until is not None:
                if now < state.held_until:
                    continue
                # The hold ended at held_until, however late this check runs.
                held_since = state.held_since if state.held_since is not None else now
                self._released.append(
                    PortRelease(
                        port=port,
                        coalesced=state.coalesced,
                        held_seconds=state.held_until - held_since,
                    )
                )
                # The port starts afresh: arrivals before or during the hold do not
                # count towards the next one.
                del self._ports[port]
                continue
            self._trim_locked(state, now)
            if not state.arrivals:
                del self._ports[port]


def _positive_seconds(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{name} must be a number, got {value!r}")
    if not (math.isfinite(value) and value > 0):
        raise ValueError(f"{name} must be positive and finite, got {value!r}")
    return float(value)
