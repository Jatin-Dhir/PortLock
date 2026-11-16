"""Error types.

Every error PortLock raises on purpose derives from :class:`PortLockError` and carries a
stable ``code``. Callers branch on the type or the code, never on message text. Messages
are written for the operator and never contain passwords, tokens or key material.
"""

from __future__ import annotations


class PortLockError(Exception):
    """Base class for all PortLock errors."""

    code: str = "portlock_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return self.message


class CanonicalError(PortLockError):
    """A value cannot be written as canonical JSON, or input is not in canonical form."""

    code = "canonical_error"


class ConfigError(PortLockError):
    """Configuration is missing, malformed or out of range."""

    code = "config_error"


class StoreError(PortLockError):
    """Durable state could not be read or written, or is from an incompatible version."""

    code = "store_error"


class PolicyError(PortLockError):
    """A policy document is invalid. ``problems`` lists each fault with its location."""

    code = "policy_error"

    def __init__(self, message: str, *, problems: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.problems = problems


class AuthError(PortLockError):
    """Authentication or authorization failed."""

    code = "auth_error"


class BackendError(PortLockError):
    """A device backend could not enumerate or monitor devices."""

    code = "backend_error"


class EnforcementError(PortLockError):
    """An enforcement mechanism failed or is unavailable on this machine."""

    code = "enforcement_error"


class SafetyViolation(EnforcementError):
    """An enforcement action was refused because it targets a protected device.

    Raised (or reported) by the safety choke point. Seeing this error means a bug or a
    dangerous policy was stopped before it reached the operating system.
    """

    code = "safety_violation"


class NotPrivilegedError(EnforcementError):
    """The operation needs administrator or root rights that this process lacks."""

    code = "not_privileged"


class ScanError(PortLockError):
    """A scan could not be carried out."""

    code = "scan_error"
