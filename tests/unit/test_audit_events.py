"""The event catalogue, the registry and the security-event envelope."""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from portlock import __version__
from portlock.audit import events, signing
from portlock.audit.events import (
    CATALOGUE,
    ENVELOPE_VERSION,
    MAX_EVENT_BYTES,
    REGISTRY,
    AuditError,
    EventRegistry,
    EventSpec,
    build_security_event,
    coerce_severity,
    security_event_from_record,
    validate_security_event,
)
from portlock.audit.log import GENESIS_HASH, RATCHET_DOMAIN, AuditLog
from portlock.audit.signing import SIGNING_DOMAIN
from portlock.core.canonical import canonical_bytes
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import PortLockError
from portlock.core.models import Severity

DOC = Path(__file__).resolve().parents[2] / "docs" / "SECURITY_EVENT_FORMAT.md"

# The contract: these names, exactly. Adding one means adding it here and in the document.
REQUIRED_EVENT_TYPES = [
    "device.connected",
    "device.removed",
    "device.changed",
    "decision.made",
    "enforcement.applied",
    "enforcement.would_apply",
    "enforcement.failed",
    "enforcement.refused",
    "safety.suspicious_device",
    "safety.clone_detected",
    "safety.port_held",
    "grant.created",
    "grant.used",
    "grant.expired",
    "grant.revoked",
    "trust.added",
    "trust.removed",
    "enroll.added",
    "enroll.removed",
    "policy.changed",
    "policy.invalid",
    "scan.started",
    "scan.finished",
    "scan.detection",
    "auth.login",
    "auth.logout",
    "auth.failure",
    "auth.lockout",
    "auth.password_changed",
    "auth.recovery_used",
    "auth.user_created",
    "auth.user_changed",
    "lockdown.engaged",
    "lockdown.renewed",
    "lockdown.lifted",
    "lockdown.expired",
    "killswitch.activated",
    "recovery.restored",
    "service.started",
    "service.stopped",
    "service.recovered",
    "store.recovered",
    "mode.changed",
    "config.changed",
    "change.pending",
    "change.confirmed",
    "change.rolled_back",
    "clock.rollback_detected",
    "audit.verified",
    "audit.verification_failed",
]

# What docs/DESIGN.md section 14 needs recorded, and where in it.
DESIGN_14_EVENTS = {
    "enroll.added": "14.1 enrolment",
    "enroll.removed": "14.1 enrolment",
    "safety.clone_detected": "14.1 a second device with an enrolled fingerprint",
    "safety.port_held": "14.6 port hold-down",
    "change.pending": "14.15 commit-confirm",
    "change.confirmed": "14.15 commit-confirm",
    "change.rolled_back": "14.15 commit-confirm",
    "clock.rollback_detected": "14.12 clock set back",
    "store.recovered": "14.23 damaged database",
    "recovery.restored": "14.17 portlock recover leaves an audit record",
}

HASH = "ab" * 32
EVENT_ID = "0123456789abcdef0123456789abcdef"


# --- the catalogue -------------------------------------------------------------------


def test_the_catalogue_holds_exactly_the_required_event_types() -> None:
    assert len(REQUIRED_EVENT_TYPES) == 50
    assert [spec.name for spec in CATALOGUE] == REQUIRED_EVENT_TYPES
    assert len({spec.name for spec in CATALOGUE}) == len(CATALOGUE)


@pytest.mark.parametrize(("event_type", "where"), sorted(DESIGN_14_EVENTS.items()))
def test_every_event_the_design_review_added_is_recordable(event_type: str, where: str) -> None:
    assert where
    spec = REGISTRY.get(event_type)
    assert spec is not None and spec.name == event_type
    assert REGISTRY.resolve(event_type) == (event_type, spec.severity)
    event = build_security_event(event_type, host="lab-1", ts=0, event_id=EVENT_ID)
    assert event["type"] == event_type and event["severity"] == spec.severity.value


@pytest.mark.parametrize("spec", CATALOGUE, ids=lambda spec: spec.name)
def test_every_entry_has_a_constant_a_severity_and_a_one_line_meaning(spec: EventSpec) -> None:
    constant = spec.name.upper().replace(".", "_")
    assert getattr(events, constant) == spec.name
    assert isinstance(spec.severity, Severity)
    assert len(spec.meaning) >= 20 and "\n" not in spec.meaning
    assert spec.meaning == spec.meaning.strip() and spec.meaning.endswith(".")
    assert REGISTRY.get(spec.name) == spec


@pytest.mark.parametrize(
    ("event_type", "severity"),
    [
        ("device.connected", Severity.INFO),
        ("enforcement.applied", Severity.NOTICE),
        ("enforcement.would_apply", Severity.INFO),
        ("enforcement.failed", Severity.ERROR),
        ("enforcement.refused", Severity.WARNING),
        ("safety.suspicious_device", Severity.WARNING),
        ("policy.invalid", Severity.ERROR),
        ("scan.detection", Severity.WARNING),
        ("auth.failure", Severity.WARNING),
        ("auth.lockout", Severity.WARNING),
        ("auth.recovery_used", Severity.WARNING),
        ("lockdown.engaged", Severity.WARNING),
        ("killswitch.activated", Severity.CRITICAL),
        ("audit.verified", Severity.INFO),
        ("audit.verification_failed", Severity.CRITICAL),
        ("enroll.added", Severity.NOTICE),
        ("enroll.removed", Severity.NOTICE),
        ("safety.clone_detected", Severity.WARNING),
        ("safety.port_held", Severity.WARNING),
        ("change.pending", Severity.NOTICE),
        ("change.confirmed", Severity.NOTICE),
        ("change.rolled_back", Severity.WARNING),
        ("clock.rollback_detected", Severity.WARNING),
        ("store.recovered", Severity.CRITICAL),
        ("recovery.restored", Severity.WARNING),
    ],
)
def test_default_severities(event_type: str, severity: Severity) -> None:
    assert REGISTRY.resolve(event_type) == (event_type, severity)


def test_no_catalogue_event_is_debug_by_default() -> None:
    assert all(spec.severity.rank >= Severity.INFO.rank for spec in CATALOGUE)


def test_the_format_document_lists_the_same_catalogue() -> None:
    text = DOC.read_text(encoding="utf-8")
    table = text.split("<!-- catalogue:begin -->")[1].split("<!-- catalogue:end -->")[0]
    rows = re.findall(r"^\| `([a-z0-9_.]+)` \| `([a-z]+)` \| (.+) \|$", table, flags=re.MULTILINE)
    assert rows == [(spec.name, spec.severity.value, spec.meaning) for spec in CATALOGUE]


def test_the_format_document_states_the_constants_the_code_uses() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert SIGNING_DOMAIN.decode("ascii") in text
    assert (SIGNING_DOMAIN + b"\x00").hex() in text
    assert GENESIS_HASH in text
    assert RATCHET_DOMAIN.decode("ascii") in text
    for small_order_y in sorted(signing._SMALL_ORDER_Y):
        assert small_order_y.to_bytes(32, "little").hex() in text
        if 1 < small_order_y < 2**255 - 20:  # the JavaScript sketch spells these out
            assert f"{small_order_y}n" in text
    for code in ("weak_key", "bad_key_encoding", "signature_mismatch", "untrusted_key"):
        assert f"`{code}`" in text
    assert str(MAX_EVENT_BYTES) in text
    for key in events.DEFAULT_SECRET_KEYS:
        assert f"`{key}`" in text
    for level in Severity:
        assert f"| `{level.value}` |" in text


# --- the registry --------------------------------------------------------------------


def test_the_shared_registry_is_strict_and_complete() -> None:
    assert REGISTRY.strict
    assert len(REGISTRY) >= len(CATALOGUE)
    assert all(name in REGISTRY for name in REQUIRED_EVENT_TYPES)
    assert "device.conected" not in REGISTRY
    assert REGISTRY.get("device.conected") is None
    assert REGISTRY.get(5) is None  # type: ignore[arg-type]


def test_a_strict_registry_refuses_unknown_types() -> None:
    registry = EventRegistry(CATALOGUE)
    with pytest.raises(AuditError, match=re.escape("unknown event type 'grant.create'")) as caught:
        registry.resolve("grant.create")
    assert caught.value.code == "unknown_event_type"
    assert isinstance(caught.value, PortLockError)
    with pytest.raises(AuditError, match="unknown event type"):
        registry.resolve("grant.create", "info")  # stating a severity does not help


def test_a_lenient_registry_needs_an_explicit_severity_for_unknown_types() -> None:
    registry = EventRegistry(CATALOGUE, strict=False)
    assert not registry.strict
    assert registry.resolve("plugin.loaded", "notice") == ("plugin.loaded", Severity.NOTICE)
    with pytest.raises(AuditError, match="no default severity"):
        registry.resolve("plugin.loaded")
    # Known types still get their default.
    assert registry.resolve("auth.failure") == ("auth.failure", Severity.WARNING)


def test_resolve_applies_overrides_and_validates_severity() -> None:
    assert REGISTRY.resolve("auth.login", Severity.DEBUG) == ("auth.login", Severity.DEBUG)
    assert REGISTRY.resolve("auth.login", "critical") == ("auth.login", Severity.CRITICAL)
    for bad in ("fatal", "INFO", "", 3, object()):
        with pytest.raises(AuditError, match="unknown severity"):
            REGISTRY.resolve("auth.login", bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name",
    [
        "",
        "single",
        "Upper.case",
        "trailing.",
        ".leading",
        "double..dot",
        "has space.x",
        "dash-ed.name",
        "9digit.first",
        "a.9b",
        "new\nline.x",
        "caf" + chr(0xE9) + ".x",
        "a." + "b" * 63,
        None,
        7,
    ],
)
def test_malformed_event_type_names_are_refused_everywhere(name: Any) -> None:
    registry = EventRegistry(strict=False)
    with pytest.raises(AuditError, match="invalid event type"):
        registry.resolve(name, "info")
    with pytest.raises(AuditError, match="invalid event type"):
        registry.register(name, "info", "A malformed name that must not be registered.")
    assert len(registry) == 0


def test_registering_new_event_types() -> None:
    registry = EventRegistry(CATALOGUE)
    spec = registry.register("plugin.loaded", "notice", "A plug-in was loaded.")
    assert spec == EventSpec("plugin.loaded", Severity.NOTICE, "A plug-in was loaded.")
    assert registry.resolve("plugin.loaded") == ("plugin.loaded", Severity.NOTICE)
    assert len(registry) == len(CATALOGUE) + 1
    # Registering the identical entry again is harmless; a different one is a conflict.
    assert registry.register("plugin.loaded", Severity.NOTICE, "A plug-in was loaded.") == spec
    with pytest.raises(AuditError, match="already registered differently"):
        registry.register("plugin.loaded", "error", "A plug-in was loaded.")
    with pytest.raises(AuditError, match="already registered differently"):
        registry.register("device.connected", "info", "Something else entirely.")
    for meaning in ("", "   ", "two\nlines", None):
        with pytest.raises(AuditError, match="one-line meaning"):
            registry.register("plugin.failed", "error", meaning)  # type: ignore[arg-type]
    with pytest.raises(AuditError, match="unknown severity"):
        registry.register("plugin.failed", "bad", "A plug-in failed.")
    assert "plugin.failed" not in registry
    assert "plugin.loaded" not in REGISTRY  # the shared registry was not touched


def test_copies_are_independent_and_iteration_is_sorted() -> None:
    lenient = REGISTRY.copy(strict=False)
    assert not lenient.strict and REGISTRY.strict
    assert REGISTRY.copy().strict
    lenient.register("zz.last", "info", "Sorts after everything else.")
    assert "zz.last" in lenient and "zz.last" not in REGISTRY
    names = [spec.name for spec in lenient]
    assert names == sorted(names) and names[-1] == "zz.last"
    assert len(lenient) == len(REGISTRY) + 1


def test_coerce_severity() -> None:
    assert coerce_severity("warning") is Severity.WARNING
    assert coerce_severity(Severity.ERROR) is Severity.ERROR
    with pytest.raises(AuditError, match="expected one of: debug, info, notice, warning"):
        coerce_severity("warn")


# --- building the envelope -----------------------------------------------------------


def build(**overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {"host": "lab-1", "ts": 1_767_225_600_000, "event_id": EVENT_ID}
    arguments.update(overrides)
    return build_security_event(arguments.pop("event_type", "device.connected"), **arguments)


def test_the_envelope_has_exactly_the_specified_shape() -> None:
    event = build(
        subject={"device_fp": "plk1:ABC"},
        data={"vendor_id": 0x1209, "tags": ("a", "b")},
        chain=(7, HASH),
    )
    assert event == {
        "v": 1,
        "id": EVENT_ID,
        "ts": 1_767_225_600_000,
        "source": {"product": "portlock", "version": __version__, "host": "lab-1"},
        "type": "device.connected",
        "severity": "info",
        "subject": {"device_fp": "plk1:ABC"},
        "data": {"vendor_id": 0x1209, "tags": ["a", "b"]},
        "chain": {"seq": 7, "hash": HASH},
    }
    assert ENVELOPE_VERSION == 1
    assert "sig" not in event
    validate_security_event(event, signed=False)


def test_defaults_are_empty_objects_no_chain_and_a_random_id() -> None:
    first = build_security_event("service.started", host="lab-1", ts=0)
    second = build_security_event("service.started", host="lab-1", ts=0)
    assert first["subject"] == {} and first["data"] == {} and first["chain"] is None
    assert first["ts"] == 0
    assert re.fullmatch(r"[0-9a-f]{32}", first["id"])
    assert first["id"] != second["id"]


def test_severity_default_and_override() -> None:
    assert build(event_type="enforcement.failed")["severity"] == "error"
    assert build(event_type="enforcement.failed", severity="critical")["severity"] == "critical"
    assert build(event_type="enforcement.failed", severity=Severity.DEBUG)["severity"] == "debug"
    with pytest.raises(AuditError, match="unknown severity"):
        build(severity="loud")


def test_event_types_are_checked_against_the_registry() -> None:
    with pytest.raises(AuditError, match="unknown event type"):
        build(event_type="plugin.loaded")
    lenient = EventRegistry(CATALOGUE, strict=False)
    event = build(event_type="plugin.loaded", severity="notice", registry=lenient)
    assert (event["type"], event["severity"]) == ("plugin.loaded", "notice")


@pytest.mark.parametrize(
    ("ts", "expected"),
    [
        (datetime(1970, 1, 1, tzinfo=UTC), 0),
        (datetime(2026, 1, 1, tzinfo=UTC), 1_767_225_600_000),
        (datetime(2026, 1, 1, 0, 0, 0, 999, tzinfo=UTC), 1_767_225_600_000),
        (datetime(2026, 1, 1, 0, 0, 0, 1000, tzinfo=UTC), 1_767_225_600_001),
        (datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC), 1_767_225_600_999),
        (
            datetime(2026, 1, 1, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            1_767_225_600_000,
        ),
        (datetime(9999, 12, 31, 23, 59, 59, 999_999, tzinfo=UTC), 253_402_300_799_999),
        (0, 0),
        (2**53 - 1, 2**53 - 1),
    ],
)
def test_timestamps_become_integer_milliseconds(ts: Any, expected: int) -> None:
    event = build(ts=ts)
    assert event["ts"] == expected and type(event["ts"]) is int


@pytest.mark.parametrize(
    "ts",
    [
        datetime(2026, 1, 1),
        datetime(1969, 12, 31, 23, 59, 59, tzinfo=UTC),
        -1,
        2**53,
        1_767_225_600.5,
        "2026-01-01T00:00:00Z",
        True,
        None,
    ],
    ids=["naive", "before-epoch", "negative", "unsafe", "float", "string", "bool", "none"],
)
def test_bad_timestamps_are_refused(ts: Any) -> None:
    with pytest.raises(AuditError, match="ts must be"):
        build(ts=ts)


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("host", "", "source.host"),
        ("host", "x" * 256, "source.host"),
        ("host", "two\nlines", "source.host"),
        ("host", "bell\x07", "source.host"),
        ("host", "c1" + chr(0x85), "source.host"),
        ("host", 5, "source.host"),
        ("host", None, "source.host"),
        ("version", "", "source.version"),
        ("version", "v" * 65, "source.version"),
        ("version", 2, "source.version"),
        ("event_id", "abc", "id must be"),
        ("event_id", EVENT_ID.upper(), "id must be"),
        ("event_id", EVENT_ID + "0", "id must be"),
        ("event_id", "g" * 32, "id must be"),
        ("event_id", 5, "id must be"),
        ("subject", ["actor"], "subject must be an object"),
        ("subject", "alice", "subject must be an object"),
        ("subject", {"ratio": 0.5}, "subject cannot be written as canonical JSON"),
        ("data", [1, 2], "data must be an object"),
        ("data", {"ratio": 0.5}, "data cannot be written as canonical JSON"),
        ("data", {"big": 2**53}, "data cannot be written as canonical JSON"),
        ("data", {"caf" + chr(0xE9): 1}, "data cannot be written as canonical JSON"),
        ("data", {"lone": chr(0xDFFF)}, "data cannot be written as canonical JSON"),
        ("chain", (1,), "chain must be"),
        ("chain", [1, HASH], "chain must be"),
        ("chain", "1:" + HASH, "chain must be"),
        ("chain", (-1, HASH), "chain.seq"),
        ("chain", ("1", HASH), "chain.seq"),
        ("chain", (True, HASH), "chain.seq"),
        ("chain", (1, HASH.upper()), "chain.hash"),
        ("chain", (1, HASH[:-1]), "chain.hash"),
        ("chain", (1, None), "chain.hash"),
        ("chain", {"seq": 1}, "chain has the wrong members"),
        ("chain", {"seq": 1, "hash": HASH, "mac": HASH}, "chain has the wrong members"),
    ],
)
def test_invalid_members_are_refused(argument: str, value: Any, message: str) -> None:
    with pytest.raises(AuditError, match=re.escape(message)):
        build(**{argument: value})


def test_host_labels_may_be_non_ascii() -> None:
    host = "b" + chr(0xFC) + "ro-" + chr(0x6771) + chr(0x4EAC)
    assert build(host=host)["source"]["host"] == host
    assert build(host="x" * 255)["source"]["host"] == "x" * 255
    assert build(chain={"seq": 0, "hash": HASH})["chain"] == {"seq": 0, "hash": HASH}


def test_secrets_are_redacted_from_subject_and_data() -> None:
    event = build(
        subject={"actor": "alice", "session_token": "tok-123"},
        data={"password": "hunter2", "attempt": {"Recovery_Code": "AAAA", "n": 1}},
    )
    assert event["subject"] == {"actor": "alice", "session_token": "[redacted]"}
    assert event["data"] == {
        "password": "[redacted]",
        "attempt": {"Recovery_Code": "[redacted]", "n": 1},
    }
    assert b"hunter2" not in canonical_bytes(event) and b"tok-123" not in canonical_bytes(event)


def test_the_envelope_does_not_share_state_with_its_inputs() -> None:
    data = {"list": [1, 2], "inner": {"a": 1}}
    event = build(data=data)
    data["list"].append(3)
    data["inner"]["a"] = 2
    assert event["data"] == {"list": [1, 2], "inner": {"a": 1}}


def test_an_oversized_envelope_is_refused() -> None:
    assert MAX_EVENT_BYTES == 256 * 1024
    fits = build(data={"blob": "x" * (MAX_EVENT_BYTES - 1024)})
    assert len(canonical_bytes(fits)) < MAX_EVENT_BYTES
    with pytest.raises(AuditError, match="the limit is 262144"):
        build(data={"blob": "x" * MAX_EVENT_BYTES})


# --- validating an envelope ----------------------------------------------------------


def signed_event() -> dict[str, Any]:
    event = build(subject={"actor": "alice"}, data={"n": 1}, chain=(3, HASH))
    event["sig"] = {"alg": "ed25519", "key": "A" * 43 + "=", "value": "B" * 86 + "=="}
    return event


def test_validation_accepts_signed_and_unsigned_as_asked() -> None:
    unsigned, signed = build(), signed_event()
    validate_security_event(unsigned)
    validate_security_event(unsigned, signed=False)
    validate_security_event(signed)
    validate_security_event(signed, signed=True)
    with pytest.raises(AuditError, match="not signed"):
        validate_security_event(unsigned, signed=True)
    with pytest.raises(AuditError, match="already signed"):
        validate_security_event(signed, signed=False)


def _set(path: tuple[str, ...], value: Any) -> Any:
    def apply(event: dict[str, Any]) -> None:
        target = event
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value

    return apply


def _delete(path: tuple[str, ...]) -> Any:
    def apply(event: dict[str, Any]) -> None:
        target = event
        for part in path[:-1]:
            target = target[part]
        del target[path[-1]]

    return apply


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_set(("v",), 2), "v must be 1"),
        (_set(("v",), "1"), "v must be 1"),
        (_set(("v",), True), "v must be 1"),
        (_set(("v",), 1.0), "v must be 1"),
        (_delete(("v",)), "missing v"),
        (_delete(("id",)), "missing id"),
        (_delete(("chain",)), "missing chain"),
        (_set(("extra",), 1), "unexpected extra"),
        (_set(("id",), "0" * 31), "id must be"),
        (_set(("ts",), "1767225600000"), "ts must be"),
        (_set(("ts",), 1.5), "ts must be"),
        (_set(("ts",), -1), "ts must be"),
        (_set(("ts",), True), "ts must be"),
        (_set(("source",), "portlock"), "source must be an object"),
        (_set(("source", "product"), "clawnet"), "source.product"),
        (_delete(("source", "host")), "missing host"),
        (_set(("source", "pid"), 1), "unexpected pid"),
        (_set(("source", "host"), ""), "source.host"),
        (_set(("source", "version"), None), "source.version"),
        (_set(("type",), "Device.Connected"), "invalid event type"),
        (_set(("type",), "device"), "invalid event type"),
        (_set(("severity",), "fatal"), "severity must be one of"),
        (_set(("severity",), 3), "severity must be one of"),
        (_set(("subject",), None), "subject must be an object"),
        (_set(("subject",), []), "subject must be an object"),
        (_set(("data",), "text"), "data must be an object"),
        (_set(("data", "ratio"), 0.25), "canonical JSON"),
        (_set(("data", "big"), 2**53), "canonical JSON"),
        (_set(("data", "blob"), "x" * MAX_EVENT_BYTES), "the limit is 262144"),
        (_set(("chain",), [3, HASH]), "chain must be an object"),
        (_set(("chain", "seq"), -1), "chain.seq"),
        (_set(("chain", "seq"), "3"), "chain.seq"),
        (_set(("chain", "hash"), "ab"), "chain.hash"),
        (_set(("chain", "prev"), HASH), "unexpected prev"),
        (_set(("sig",), "signature"), "sig must be an object"),
        (_set(("sig", "alg"), "Ed25519"), "sig.alg"),
        (_set(("sig", "alg"), "rsa"), "sig.alg"),
        (_set(("sig", "key"), 5), "sig.key"),
        (_set(("sig", "value"), None), "sig.value"),
        (_delete(("sig", "key")), "missing key"),
        (_set(("sig", "kid"), "1"), "unexpected kid"),
    ],
)
def test_validation_names_what_is_wrong(mutate: Any, message: str) -> None:
    event = signed_event()
    validate_security_event(event, signed=True)  # the starting point is valid
    mutate(event)
    with pytest.raises(AuditError, match=re.escape(message)):
        validate_security_event(event)


@pytest.mark.parametrize("value", [None, [], "event", 5, b"{}"])
def test_validation_refuses_things_that_are_not_objects(value: Any) -> None:
    with pytest.raises(AuditError, match="must be an object"):
        validate_security_event(value)


def test_unknown_event_types_are_structurally_valid() -> None:
    # A receiver must accept types added by later versions; only the shape is checked.
    event = build()
    event["type"] = "future.event_type"
    validate_security_event(event)


# --- envelopes from audit records ----------------------------------------------------


@pytest.fixture
def log(db: Database) -> AuditLog:
    clock = FakeClock(datetime(2026, 3, 14, 9, 26, 53, 589_793, tzinfo=UTC))
    return AuditLog(db, clock=clock)


def test_an_envelope_built_from_a_record_is_a_checkpoint(log: AuditLog) -> None:
    log.append("service.started", actor="system")
    record = log.append(
        "decision.made",
        "notice",
        actor="alice",
        device_fp="plk1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        data={"access": "deny", "reasons": ["blocked vendor"]},
    )
    event = security_event_from_record(record, host="lab-1", version="9.9.9")
    expected_id = hashlib.sha256(
        b"portlock/1/event-id\x00" + b"lab-1" + b"\x00" + bytes.fromhex(record.hash)
    ).hexdigest()[:32]
    assert event == {
        "v": 1,
        "id": expected_id,
        "ts": 1_773_480_413_589,  # 2026-03-14T09:26:53.589793Z, microseconds dropped
        "source": {"product": "portlock", "version": "9.9.9", "host": "lab-1"},
        "type": "decision.made",
        "severity": "notice",
        "subject": {"actor": "alice", "device_fp": "plk1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"},
        "data": {"access": "deny", "reasons": ["blocked vendor"]},
        "chain": {"seq": 2, "hash": record.hash},
    }
    validate_security_event(event, signed=False)
    assert (event["chain"]["seq"], event["chain"]["hash"]) == log.head()


def test_record_envelopes_are_deterministic_and_host_specific(log: AuditLog) -> None:
    record = log.append("service.started")
    first = security_event_from_record(record, host="lab-1")
    again = security_event_from_record(record, host="lab-1")
    elsewhere = security_event_from_record(record, host="lab-2")
    assert first == again
    assert first["source"]["version"] == __version__
    assert first["subject"] == {}  # null actor and fingerprint are left out
    assert first["id"] != elsewhere["id"]
    before = copy.deepcopy(first)
    first["data"]["mutated"] = True
    assert record.data == {} and security_event_from_record(record, host="lab-1") == before


@pytest.mark.parametrize("host", ["", "bad\nhost", 5, None, "x" * 256, chr(0xD800)])
def test_record_envelopes_validate_the_host(log: AuditLog, host: Any) -> None:
    record = log.append("service.started")
    with pytest.raises(AuditError, match=r"source\.host"):
        security_event_from_record(record, host=host)
