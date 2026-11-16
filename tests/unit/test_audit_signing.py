"""Event signing and verification, and the interoperability vectors.

Three layers, so that as much as possible runs everywhere:

* the vector file is checked against the canonicaliser and against a small independent
  Ed25519 verifier written from RFC 8032 (no third-party code, runs on every platform);
* behaviour without the optional ``cryptography`` package is simulated and checked;
* signing itself needs ``cryptography`` and is skipped where it cannot be imported.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from portlock.audit import signing
from portlock.audit.events import AuditError, build_security_event, validate_security_event
from portlock.audit.log import (
    GENESIS_HASH,
    RATCHET_DOMAIN,
    AuditKey,
    AuditKeyStore,
    AuditLog,
    ratchet_key,
    record_hash,
    record_mac,
)
from portlock.audit.signing import (
    ALGORITHM,
    SIGNING_DOMAIN,
    EventSigner,
    SigningUnavailableError,
    VerifyOutcome,
    has_signing_support,
    load_or_create_key,
    signing_input,
    verify_event,
)
from portlock.core.canonical import canonical_bytes, parse_canonical
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import PortLockError

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "security-event-vectors.json").read_text(
        encoding="utf-8"
    )
)
VALID = VECTORS["valid"]
INVALID = VECTORS["invalid"]

# RFC 8032 section 7.1, TEST 1.
RFC8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC8032_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


@pytest.fixture(scope="module")
def crypto() -> Any:
    """Skip the test unless Ed25519 from the optional ``cryptography`` package loads."""
    return pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        reason="the optional 'cryptography' package is not importable here",
        exc_type=ImportError,
    )


@pytest.fixture
def no_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the lazy import fail exactly as it does when ``cryptography`` is not installed."""
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric", None)
    monkeypatch.delitem(
        sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", raising=False
    )


def unsigned(event: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in event.items() if name != "sig"}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- an independent Ed25519 verifier (RFC 8032 section 6, pure Python) ---------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
Point = tuple[int, int, int, int]


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    return _P - x if (x & 1) != sign else x


def _decode_point(data: bytes) -> Point | None:
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


_BASE_Y = 4 * pow(5, -1, _P) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
assert _BASE_X is not None
_BASE: Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def reference_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature with nothing but integer arithmetic and SHA-512."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decode_point(public_key), _decode_point(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    digest = hashlib.sha512(signature[:32] + public_key + message).digest()
    left = _multiply(s, _BASE)
    right = _add(r, _multiply(int.from_bytes(digest, "little") % _L, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % _P == 0


def test_the_reference_verifier_agrees_with_rfc_8032() -> None:
    assert reference_verify(RFC8032_PUBLIC, b"", RFC8032_SIGNATURE)
    assert not reference_verify(RFC8032_PUBLIC, b"x", RFC8032_SIGNATURE)
    flipped = bytes([RFC8032_SIGNATURE[0] ^ 1]) + RFC8032_SIGNATURE[1:]
    assert not reference_verify(RFC8032_PUBLIC, b"", flipped)
    high_s = RFC8032_SIGNATURE[:32] + (
        int.from_bytes(RFC8032_SIGNATURE[32:], "little") + _L
    ).to_bytes(32, "little")
    assert not reference_verify(RFC8032_PUBLIC, b"", high_s)


# --- the vector file -----------------------------------------------------------------


def test_the_vector_file_describes_itself() -> None:
    assert VECTORS["specification"] == "docs/SECURITY_EVENT_FORMAT.md"
    assert VECTORS["envelope_version"] == 1
    assert VECTORS["signing"]["domain_utf8"] == SIGNING_DOMAIN.decode("ascii")
    assert bytes.fromhex(VECTORS["signing"]["prefix_hex"]) == SIGNING_DOMAIN + b"\x00"
    assert bytes.fromhex(VECTORS["signing"]["prefix_hex"]) == b"portlock/1/security-event\x00"
    for section in ("description", "encoding_of_this_file", "test_keys", "audit_chain"):
        assert VECTORS[section]
    assert len(VECTORS["how_to_check_a_valid_entry"]) == 6
    assert len(VALID) >= 3
    assert len({entry["name"] for entry in VALID + INVALID}) == len(VALID) + len(INVALID)
    assert len({entry["seed_hex"] for entry in VALID}) == len(VALID)


def test_the_vector_file_is_pure_ascii_with_unix_line_endings() -> None:
    raw = (
        Path(__file__).resolve().parents[1] / "fixtures" / "security-event-vectors.json"
    ).read_bytes()
    assert raw.isascii() and b"\r" not in raw and raw.endswith(b"}\n")


def test_one_vector_carries_non_ascii_text_in_every_tricky_form() -> None:
    entry = VALID[2]
    data = entry["event"]["data"]
    assert data["combining"] == "e" + chr(0x301) and len(data["combining"]) == 2
    assert chr(0x1F512) in data["path"] and "\\" in data["path"]
    assert data["controls"] == "tab\there\nnewline" + chr(0x1F) + chr(0x7F)
    assert data["separators"] == chr(0x2028) + chr(0x2029)
    assert data["size"] == 2**53 - 1 and data["delta"] == -(2**53 - 1)
    assert not entry["event"]["source"]["host"].isascii()
    canonical = base64.b64decode(entry["canonical_b64"])
    assert not canonical.isascii()
    # Raw UTF-8 for the emoji and the separators; escapes only where RFC 8785 demands.
    assert chr(0x1F512).encode("utf-8") in canonical
    assert chr(0x2028).encode("utf-8") in canonical and b"\\u2028" not in canonical
    assert b"tab\\there\\nnewline\\u001f\x7f" in canonical
    assert b'"nested":{"1":4,"B":2,"_":3,"a":{},"aa":5,"b":[1,{"a":[],"z":""}]}' in canonical


@pytest.mark.parametrize("entry", VALID, ids=[entry["name"] for entry in VALID])
def test_valid_vectors_match_the_canonicaliser_and_the_signing_input(entry: dict[str, Any]) -> None:
    event = entry["event"]
    validate_security_event(event, signed=True)
    canonical = canonical_bytes(unsigned(event))
    assert canonical == base64.b64decode(entry["canonical_b64"])
    assert canonical == entry["canonical_utf8"].encode("utf-8")
    assert parse_canonical(canonical) == unsigned(event)
    message = signing_input(event)
    assert message == b"portlock/1/security-event\x00" + canonical
    assert message == base64.b64decode(entry["signing_input_b64"])
    assert hashlib.sha256(message).hexdigest() == entry["signing_input_sha256"]
    assert signing_input(unsigned(event)) == message  # the sig member is never signed
    assert event["sig"] == {
        "alg": "ed25519",
        "key": entry["public_key_b64"],
        "value": entry["signature_b64"],
    }
    assert base64.b64decode(entry["public_key_b64"]).hex() == entry["public_key_hex"]
    assert base64.b64decode(entry["signature_b64"]).hex() == entry["signature_hex"]
    assert len(bytes.fromhex(entry["public_key_hex"])) == 32
    assert len(bytes.fromhex(entry["signature_hex"])) == 64
    assert len(bytes.fromhex(entry["seed_hex"])) == 32


@pytest.mark.parametrize("entry", VALID, ids=[entry["name"] for entry in VALID])
def test_valid_vectors_verify_with_an_independent_implementation(entry: dict[str, Any]) -> None:
    public_key = bytes.fromhex(entry["public_key_hex"])
    signature = bytes.fromhex(entry["signature_hex"])
    message = base64.b64decode(entry["signing_input_b64"])
    assert reference_verify(public_key, message, signature)
    # The domain separator is part of what is signed.
    assert not reference_verify(public_key, base64.b64decode(entry["canonical_b64"]), signature)
    assert not reference_verify(public_key, message + b" ", signature)


def _is_identity(point: Point) -> bool:
    return point[0] % _P == 0 and (point[1] - point[2]) % _P == 0


@pytest.mark.parametrize("entry", INVALID, ids=[entry["name"] for entry in INVALID])
def test_invalid_vectors_are_rejected_by_an_independent_implementation(
    entry: dict[str, Any],
) -> None:
    assert entry["why"] and entry["expect"] in {
        "signature_mismatch",
        "bad_signature_encoding",
        "bad_key_encoding",
        "weak_key",
        "malformed_event",
        "not_signed",
    }
    event = entry["event"]
    if entry["expect"] == "signature_mismatch":
        assert not reference_verify(
            base64.b64decode(event["sig"]["key"]),
            signing_input(event),
            base64.b64decode(event["sig"]["value"]),
        )
    elif entry["expect"] == "weak_key":
        key = base64.b64decode(event["sig"]["key"], validate=True)
        point = _decode_point(key)
        assert point is not None and _is_identity(_multiply(8, point)), "a small-order point"
        # Why the format refuses such keys before looking at the signature: the plain
        # Ed25519 equation holds, although no private key was ever involved.
        assert reference_verify(key, signing_input(event), base64.b64decode(event["sig"]["value"]))
    elif entry["name"] == "public key with a non-canonical y-coordinate":
        key = base64.b64decode(event["sig"]["key"], validate=True)
        assert int.from_bytes(key, "little") & ((1 << 255) - 1) >= _P
        assert _decode_point(key) is None


def test_the_refused_key_rule_in_the_vector_file_matches_the_code() -> None:
    rule = VECTORS["signing"]["refused_public_keys"]
    assert int.from_bytes(bytes.fromhex(rule["field_prime_hex_le"]), "little") == _P
    listed = [int.from_bytes(bytes.fromhex(text), "little") for text in rule["small_order_y_hex"]]
    assert set(listed) == signing._SMALL_ORDER_Y and len(listed) == 5
    # Every listed y, with either sign of x, is a point whose order divides 8 ...
    points = []
    for y in listed:
        for sign in (0, 1):
            x = _recover_x(y, sign)
            if x is not None:
                points.append((x, y, 1, x * y % _P))
    assert len({(point[0], point[1]) for point in points}) == 8
    assert all(_is_identity(_multiply(8, point)) for point in points)
    # ... and an honest key is not one of them.
    for entry in VALID:
        key = int.from_bytes(bytes.fromhex(entry["public_key_hex"]), "little")
        assert key & ((1 << 255) - 1) not in signing._SMALL_ORDER_Y


def test_the_audit_chain_vector_matches_the_log_implementation() -> None:
    chain = VECTORS["audit_chain"]
    assert chain["genesis_hash"] == GENESIS_HASH
    assert chain["ratchet_domain"].encode("ascii") == RATCHET_DOMAIN
    initial = AuditKey(0, bytes.fromhex(chain["initial_key_hex"]))
    key = initial.key
    prev_hash = GENESIS_HASH
    for number, item in enumerate(chain["records"], start=1):
        record = item["record"]
        body = {
            name: record[name]
            for name in ("seq", "ts", "event_type", "severity", "actor", "device_fp", "data")
        }
        assert record["seq"] == number and record["prev_hash"] == prev_hash
        assert canonical_bytes(body) == base64.b64decode(item["hashed_body_b64"])
        assert item["hashed_body_utf8"].encode("utf-8") == base64.b64decode(item["hashed_body_b64"])
        expected = hashlib.sha256(bytes.fromhex(prev_hash) + canonical_bytes(body)).hexdigest()
        assert record["hash"] == expected == record_hash(prev_hash, **body)
        # k_i = SHA-256("portlock-audit-ratchet" || k_(i-1)); record i is MACed with k_i.
        key = hashlib.sha256(b"portlock-audit-ratchet" + key).digest()
        assert item["mac_key_hex"] == key.hex() == initial.key_for(number).hex()
        assert key == ratchet_key(initial.key, number)
        assert record["mac"] == record_mac(key, record["hash"])
        assert record["mac"] == hmac.new(key, bytes.fromhex(record["hash"]), "sha256").hexdigest()
        prev_hash = record["hash"]
    assert chain["head"] == {"seq": 3, "hash": prev_hash}
    # The second signed vector is the envelope of the last record.
    assert VALID[1]["event"]["chain"] == chain["head"]
    assert VALID[1]["event"]["data"] == chain["records"][2]["record"]["data"]
    host = VALID[1]["event"]["source"]["host"].encode("utf-8")
    derived = hashlib.sha256(
        b"portlock/1/event-id\x00" + host + b"\x00" + bytes.fromhex(prev_hash)
    ).hexdigest()[:32]
    assert VALID[1]["event"]["id"] == derived


# --- without the optional dependency -------------------------------------------------


def test_without_cryptography_signing_raises_a_clear_error(no_crypto: None) -> None:
    assert has_signing_support() is False
    for make in (
        EventSigner.generate,
        lambda: EventSigner.from_seed(bytes(32)),
        lambda: EventSigner(bytes(32)),
    ):
        with pytest.raises(SigningUnavailableError, match="cryptography") as caught:
            make()
        assert isinstance(caught.value, PortLockError) and isinstance(caught.value, AuditError)
        assert caught.value.code == "signing_unavailable"
        assert "portlock[signing]" in str(caught.value)


def test_without_cryptography_verification_reports_missing_support(no_crypto: None) -> None:
    outcome = verify_event(VALID[0]["event"])
    assert outcome == VerifyOutcome(False, outcome.reason, "signing_unavailable", None)
    assert "cryptography" in outcome.reason
    trusted = verify_event(VALID[0]["event"], trusted_keys=[VALID[0]["public_key_b64"]])
    assert trusted.code == "signing_unavailable"
    # Everything that can be judged without Ed25519 still is.
    assert verify_event(unsigned(VALID[0]["event"])).code == "not_signed"
    assert verify_event({"sig": {}}).code == "malformed_event"
    assert verify_event(VALID[0]["event"], trusted_keys=[bytes(32)]).code == "untrusted_key"
    for entry in INVALID:
        if entry["expect"] != "signature_mismatch":
            assert verify_event(entry["event"]).code == entry["expect"], entry["name"]


def test_without_cryptography_no_key_file_is_created(no_crypto: None, tmp_path: Path) -> None:
    path = tmp_path / "keys" / "signing.key"
    with pytest.raises(SigningUnavailableError):
        load_or_create_key(path)
    assert not path.exists() and not path.parent.exists()


def test_without_cryptography_the_rest_of_the_audit_package_works(
    no_crypto: None, db: Database, clock: FakeClock, tmp_path: Path
) -> None:
    store, initial = AuditKeyStore.create(tmp_path / "audit.key")
    log = AuditLog(db, clock=clock, key_store=store, head_path=tmp_path / "audit.head")
    record = log.append("service.started", actor="system")
    assert log.verify(initial_key=initial).macs_checked == 1
    event = build_security_event("service.started", host="lab-1", ts=0, chain=log.head())
    assert event["chain"] == {"seq": 1, "hash": record.hash}
    assert signing_input(event) == SIGNING_DOMAIN + b"\x00" + canonical_bytes(event)


# --- signing (needs cryptography) ----------------------------------------------------


def test_signing_support_is_reported(crypto: Any) -> None:
    assert has_signing_support() is True
    assert ALGORITHM == "ed25519"


def test_a_seed_is_an_rfc_8032_private_key(crypto: Any) -> None:
    signer = EventSigner.from_seed(RFC8032_SEED)
    assert signer.public_key == RFC8032_PUBLIC
    assert signer.public_key_b64 == b64(RFC8032_PUBLIC)
    assert EventSigner.from_seed(bytearray(RFC8032_SEED)).public_key == RFC8032_PUBLIC


@pytest.mark.parametrize("entry", VALID, ids=[entry["name"] for entry in VALID])
def test_signing_reproduces_every_vector_from_its_seed(crypto: Any, entry: dict[str, Any]) -> None:
    signer = EventSigner.from_seed(bytes.fromhex(entry["seed_hex"]))
    assert signer.public_key.hex() == entry["public_key_hex"]
    assert signer.public_key_b64 == entry["public_key_b64"]
    signed = signer.sign_event(unsigned(entry["event"]))
    assert signed == entry["event"]
    assert signed["sig"]["value"] == entry["signature_b64"]
    assert signer.sign_event(unsigned(entry["event"])) == signed  # deterministic


@pytest.mark.parametrize("entry", VALID, ids=[entry["name"] for entry in VALID])
def test_valid_vectors_verify(crypto: Any, entry: dict[str, Any]) -> None:
    public_key = bytes.fromhex(entry["public_key_hex"])
    assert verify_event(entry["event"]) == VerifyOutcome(
        True, "the signature is valid", "ok", public_key
    )
    # A round trip through JSON text, as a receiver would see it.
    assert verify_event(json.loads(json.dumps(entry["event"]))).ok


@pytest.mark.parametrize("entry", INVALID, ids=[entry["name"] for entry in INVALID])
def test_invalid_vectors_are_rejected_for_the_stated_reason(
    crypto: Any, entry: dict[str, Any]
) -> None:
    outcome = verify_event(entry["event"])
    assert (outcome.ok, outcome.code, outcome.public_key) == (False, entry["expect"], None)
    assert outcome.reason


def test_sign_event_adds_sig_and_leaves_its_input_alone(crypto: Any) -> None:
    signer = EventSigner.from_seed(bytes(range(32)))
    event = build_security_event(
        "device.connected",
        host="lab-1",
        ts=1_767_225_600_000,
        event_id="0" * 32,
        data={"tags": ["a", "b"]},
    )
    before = copy.deepcopy(event)
    signed = signer.sign_event(event)
    assert event == before and "sig" not in event
    assert unsigned(signed) == event
    assert signed["sig"]["alg"] == "ed25519"
    assert signed["sig"]["key"] == signer.public_key_b64
    signature = base64.b64decode(signed["sig"]["value"], validate=True)
    assert len(signature) == 64
    assert reference_verify(signer.public_key, signing_input(event), signature)
    signed["data"]["tags"].append("c")  # the result does not alias the input
    assert event["data"]["tags"] == ["a", "b"]


def test_sign_event_refuses_signed_or_malformed_events(crypto: Any) -> None:
    signer = EventSigner.from_seed(bytes(range(32)))
    with pytest.raises(AuditError, match="already signed"):
        signer.sign_event(VALID[0]["event"])
    broken = unsigned(VALID[0]["event"])
    broken["ts"] = "now"
    with pytest.raises(AuditError, match="ts must be"):
        signer.sign_event(broken)
    for not_an_event in (None, [], "event", 5):
        with pytest.raises(AuditError, match="must be an object"):
            signer.sign_event(not_an_event)  # type: ignore[arg-type]


def test_generated_keys_are_distinct_and_round_trip(crypto: Any) -> None:
    first, second = EventSigner.generate(), EventSigner.generate()
    assert first.public_key != second.public_key
    assert len(first.public_key) == 32
    event = unsigned(VALID[0]["event"])
    outcome = verify_event(first.sign_event(event))
    assert outcome.ok and outcome.public_key == first.public_key
    assert first.sign_event(event)["sig"]["value"] != second.sign_event(event)["sig"]["value"]


@pytest.mark.parametrize("seed", [b"", bytes(31), bytes(33), "0" * 32, None, 5])
def test_seeds_must_be_exactly_32_bytes(crypto: Any, seed: Any) -> None:
    with pytest.raises(AuditError, match="exactly 32 bytes"):
        EventSigner.from_seed(seed)


def test_a_signer_never_reveals_its_seed(crypto: Any) -> None:
    seed = bytes.fromhex(VALID[0]["seed_hex"])
    signer = EventSigner.from_seed(seed)
    assert repr(signer) == f"EventSigner(public_key={VALID[0]['public_key_b64']!r})"
    for text in (repr(signer), str(signer)):
        assert seed.hex() not in text and b64(seed) not in text
    assert not hasattr(signer, "__dict__")
    assert not any("seed" in name for name in EventSigner.__slots__)


def test_trusted_keys_pin_the_signer(crypto: Any) -> None:
    entry, other = VALID[0], VALID[1]
    event = entry["event"]
    key = bytes.fromhex(entry["public_key_hex"])
    assert verify_event(event, trusted_keys=[key]).ok
    assert verify_event(event, trusted_keys=[entry["public_key_b64"]]).ok
    assert verify_event(event, trusted_keys=key).ok  # a single key, not a collection
    assert verify_event(event, trusted_keys={other["public_key_b64"], entry["public_key_b64"]}).ok
    stranger = verify_event(event, trusted_keys=[other["public_key_b64"]])
    assert (stranger.ok, stranger.code, stranger.public_key) == (False, "untrusted_key", None)
    assert verify_event(event, trusted_keys=[]).code == "untrusted_key"
    for malformed in ([b"short"], ["not base64!"], [entry["public_key_b64"][:-1]], [5], [None]):
        outcome = verify_event(event, trusted_keys=malformed)  # type: ignore[arg-type]
        assert (outcome.ok, outcome.code) == (False, "bad_trusted_keys")


def test_a_valid_signature_by_an_untrusted_key_is_still_only_a_claim(crypto: Any) -> None:
    # Anyone can generate a key and sign: without pinning, "ok" proves integrity only.
    forger = EventSigner.generate()
    forged = forger.sign_event(unsigned(VALID[1]["event"]))
    unpinned = verify_event(forged)
    assert unpinned.ok and unpinned.public_key == forger.public_key
    assert unpinned.public_key != bytes.fromhex(VALID[1]["public_key_hex"])
    assert verify_event(forged, trusted_keys=[VALID[1]["public_key_b64"]]).code == "untrusted_key"


def _mutations() -> list[tuple[str, Any]]:
    def set_at(*path_and_value: Any) -> Any:
        *path, value = path_and_value

        def apply(event: dict[str, Any]) -> None:
            target = event
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value

        return apply

    return [
        ("id", set_at("id", "f" * 32)),
        ("ts", set_at("ts", 1)),
        ("version", set_at("source", "version", "0.2.1")),
        ("host", set_at("source", "host", "lab-9")),
        ("type", set_at("type", "trust.added")),
        ("severity", set_at("severity", "debug")),
        ("subject", set_at("subject", {"actor": "mallory"})),
        ("data-added", set_at("data", "extra", 1)),
        ("data-reason", set_at("data", "reasons", ["rule matched"])),
        ("chain-seq", set_at("chain", "seq", 4)),
        ("chain-hash", set_at("chain", "hash", "0" * 64)),
        ("chain-null", set_at("chain", None)),
    ]


@pytest.mark.parametrize(("name", "mutate"), _mutations(), ids=[name for name, _ in _mutations()])
def test_changing_any_signed_member_breaks_the_signature(
    crypto: Any, name: str, mutate: Any
) -> None:
    event = copy.deepcopy(VALID[1]["event"])
    assert verify_event(event).ok
    mutate(event)
    outcome = verify_event(event)
    assert (outcome.ok, outcome.code) == (False, "signature_mismatch")


def test_every_single_bit_of_the_signature_matters(crypto: Any) -> None:
    event = copy.deepcopy(VALID[0]["event"])
    signature = bytearray(base64.b64decode(event["sig"]["value"]))
    for position in (0, 7, 255, 256, 300, 503):  # both halves, R and S
        tampered = bytearray(signature)
        tampered[position // 8] ^= 1 << (position % 8)
        event["sig"]["value"] = b64(bytes(tampered))
        assert verify_event(event).code == "signature_mismatch", position


def _first_y_off_the_curve() -> bytes:
    """The smallest y with no point on edwards25519, as a key encoding (found, not assumed)."""
    for y in range(2, 1000):
        if y not in signing._SMALL_ORDER_Y and _recover_x(y, 0) is None:
            return y.to_bytes(32, "little")
    raise AssertionError("no y off the curve below 1000")


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    [
        # y = 2^255 - 1 is not below the field prime: a second spelling of y = 18.
        ("y not below p", b"\xff" * 31 + b"\x7f", "bad_key_encoding"),
        ("y not below p, sign bit set", b"\xff" * 32, "bad_key_encoding"),
        # y = 0 is the point of order 4, (sqrt(-1), 0): on the curve, but small order.
        ("order-4 point", bytes(32), "weak_key"),
        ("identity with the sign bit set", b"\x01" + bytes(30) + b"\x80", "weak_key"),
        ("no such point", _first_y_off_the_curve(), "signature_mismatch"),
    ],
)
def test_keys_that_are_not_usable_points_are_rejected_not_raised(
    crypto: Any, name: str, raw: bytes, code: str
) -> None:
    event = copy.deepcopy(VALID[0]["event"])
    event["sig"]["key"] = b64(raw)
    outcome = verify_event(event)
    assert (outcome.ok, outcome.code, outcome.public_key) == (False, code, None), name
    if code == "signature_mismatch":
        assert _decode_point(raw) is None, "the independent decoder agrees: not a point"


@pytest.mark.parametrize(
    "garbage",
    [
        None,
        0,
        "",
        "{}",
        b"{}",
        [],
        [1, 2],
        {},
        {"sig": None},
        {"sig": {"alg": "ed25519", "key": "", "value": ""}},
        {"v": 1, "sig": {"alg": "ed25519"}},
        {1: 2, "sig": {}},
        {"sig": {}, "data": {"x": float("nan")}},
    ],
)
def test_verification_never_raises_on_garbage(garbage: Any) -> None:
    outcome = verify_event(garbage)
    assert outcome.ok is False and outcome.public_key is None
    assert outcome.code in {"not_signed", "malformed_event"}
    assert outcome.reason


def test_verification_survives_hostile_structures() -> None:
    deep: Any = "x"
    for _ in range(5000):
        deep = [deep]
    event = copy.deepcopy(VALID[0]["event"])
    event["data"] = {"deep": deep}
    assert verify_event(event).code == "malformed_event"

    cyclic = copy.deepcopy(VALID[0]["event"])
    cyclic["data"]["self"] = cyclic["data"]
    assert verify_event(cyclic).code == "malformed_event"

    class Explosive(dict[str, Any]):
        def __contains__(self, key: object) -> bool:
            raise RuntimeError("hostile mapping")

    outcome = verify_event(Explosive(VALID[0]["event"]))
    assert (outcome.ok, outcome.code) == (False, "verification_error")
    assert outcome.reason == "verification failed unexpectedly (RuntimeError)"


# --- the key file --------------------------------------------------------------------


def test_load_or_create_key_creates_then_reloads_the_same_key(crypto: Any, tmp_path: Path) -> None:
    path = tmp_path / "state" / "keys" / "signing.key"
    created = load_or_create_key(path)
    seed = path.read_bytes()
    assert len(seed) == 32
    assert created.public_key == EventSigner.from_seed(seed).public_key
    assert sorted(item.name for item in path.parent.iterdir()) == ["signing.key"]  # no leftovers
    reloaded = load_or_create_key(str(path))
    assert reloaded.public_key == created.public_key
    assert path.read_bytes() == seed  # loading does not rewrite the key
    other = load_or_create_key(tmp_path / "other.key")
    assert other.public_key != created.public_key
    outcome = verify_event(reloaded.sign_event(unsigned(VALID[0]["event"])))
    assert outcome.ok and outcome.public_key == created.public_key


def test_load_or_create_key_reads_an_existing_seed(crypto: Any, tmp_path: Path) -> None:
    path = tmp_path / "signing.key"
    path.write_bytes(RFC8032_SEED)
    if sys.platform != "win32":
        path.chmod(0o600)
    assert load_or_create_key(path).public_key == RFC8032_PUBLIC


@pytest.mark.parametrize("content", [b"", bytes(31), bytes(33), bytes(64), b"0" * 44])
def test_a_key_file_of_the_wrong_size_is_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "signing.key"
    path.write_bytes(content)
    if sys.platform != "win32":
        path.chmod(0o600)
    with pytest.raises(AuditError, match="not exactly 32 bytes") as caught:
        signing._read_seed(path)
    assert str(caught.value) == "the signing key signing.key is not exactly 32 bytes"
    assert path.read_bytes() == content  # refused, not repaired


def test_a_key_path_that_is_a_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AuditError, match="not a regular file"):
        signing._read_seed(tmp_path)
    assert signing._read_seed(tmp_path / "absent.key") is None


def test_creating_a_key_writes_32_random_bytes_and_nothing_else(tmp_path: Path) -> None:
    path = tmp_path / "new" / "signing.key"
    first = signing._create_seed(path)
    assert len(first) == 32 and path.read_bytes() == first
    assert signing._read_seed(path) == first
    assert os.listdir(path.parent) == ["signing.key"]
    second = signing._create_seed(tmp_path / "second.key")
    assert second != first


def test_a_key_that_appears_during_creation_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "signing.key"
    winner = bytes(range(32))
    real_link = os.link

    def racing_link(source: Any, target: Any) -> None:
        # Another process publishes its key between our check and our link.
        if not Path(target).exists():
            Path(target).write_bytes(winner)
            if sys.platform != "win32":
                Path(target).chmod(0o600)
        real_link(source, target)

    monkeypatch.setattr(signing.os, "link", racing_link)
    assert signing._create_seed(path) == winner  # ours was discarded, not written over theirs
    assert path.read_bytes() == winner
    assert os.listdir(tmp_path) == ["signing.key"]


def test_key_creation_works_without_hard_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_links(_source: Any, _target: Any) -> None:
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(signing.os, "link", no_links)
    path = tmp_path / "signing.key"
    seed = signing._create_seed(path)
    assert path.read_bytes() == seed and len(seed) == 32
    assert os.listdir(tmp_path) == ["signing.key"]


def test_a_key_that_cannot_be_created_is_reported(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"")
    with pytest.raises(AuditError, match="cannot create the signing key"):
        signing._create_seed(blocker / "signing.key")


@pytest.mark.linux_only
def test_new_key_files_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "signing.key"
    signing._create_seed(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.stat().st_nlink == 1  # the staging name is gone


@pytest.mark.linux_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o666, 0o700 | 0o040])
def test_a_key_file_other_users_can_reach_is_refused(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "signing.key"
    path.write_bytes(bytes(32))
    path.chmod(mode)
    with pytest.raises(AuditError, match="accessible to other users") as caught:
        signing._read_seed(path)
    assert f"{mode:04o}" in str(caught.value)
    path.chmod(0o600)
    assert signing._read_seed(path) == bytes(32)
    path.chmod(0o400)  # read-only for the owner is fine
    assert signing._read_seed(path) == bytes(32)


@pytest.mark.linux_only
def test_a_key_path_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "real.key"
    target.write_bytes(bytes(32))
    target.chmod(0o600)
    link = tmp_path / "signing.key"
    link.symlink_to(target)
    with pytest.raises(AuditError, match="not a regular file"):
        signing._read_seed(link)
