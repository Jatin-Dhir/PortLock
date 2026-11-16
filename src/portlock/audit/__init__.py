"""PortLock Audit: the hash-chained audit log, its event catalogue, sinks and signing.

* :mod:`portlock.audit.events` — the event types, the registry that refuses unknown
  ones, secret redaction, and the shared security-event envelope.
* :mod:`portlock.audit.log` — :class:`AuditLog`, the append-only, tamper-evident table,
  its forward-secure MAC key store (:class:`AuditKeyStore`) and head file, and
  :meth:`AuditLog.start_fresh` for starting again after a damaged database.
* :mod:`portlock.audit.sinks` — copies of each record to a file, syslog or a callback.
* :mod:`portlock.audit.signing` — Ed25519 signatures over the envelope (needs the
  optional ``cryptography`` package; everything else works without it).

What the log does and does not protect against is stated in :mod:`portlock.audit.log`
and in ``docs/DESIGN.md`` sections 10 and 14. The wire format is
``docs/SECURITY_EVENT_FORMAT.md``.
"""

from portlock.audit.events import (
    CATALOGUE,
    REGISTRY,
    AuditError,
    EventRegistry,
    EventSpec,
    build_security_event,
    redact,
    security_event_from_record,
    validate_security_event,
)
from portlock.audit.log import (
    GENESIS_HASH,
    AuditKey,
    AuditKeyStore,
    AuditLog,
    AuditRecord,
    FreshLog,
    VerifyResult,
    read_head_file,
)
from portlock.audit.signing import (
    EventSigner,
    SigningUnavailableError,
    VerifyOutcome,
    has_signing_support,
    load_or_create_key,
    verify_event,
)
from portlock.audit.sinks import (
    AuditSink,
    CallbackSink,
    FanOut,
    JsonlFileSink,
    MinSeveritySink,
    SinkStats,
    SyslogSink,
)

__all__ = [
    "CATALOGUE",
    "GENESIS_HASH",
    "REGISTRY",
    "AuditError",
    "AuditKey",
    "AuditKeyStore",
    "AuditLog",
    "AuditRecord",
    "AuditSink",
    "CallbackSink",
    "EventRegistry",
    "EventSigner",
    "EventSpec",
    "FanOut",
    "FreshLog",
    "JsonlFileSink",
    "MinSeveritySink",
    "SigningUnavailableError",
    "SinkStats",
    "SyslogSink",
    "VerifyOutcome",
    "VerifyResult",
    "build_security_event",
    "has_signing_support",
    "load_or_create_key",
    "read_head_file",
    "redact",
    "security_event_from_record",
    "validate_security_event",
    "verify_event",
]
