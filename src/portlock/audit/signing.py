"""Ed25519 signatures over security events.

The format is specified in ``docs/SECURITY_EVENT_FORMAT.md``; this module is its
reference implementation. A signature covers::

    utf8("portlock/1/security-event") || 0x00 || canonical_json(event without "sig")

The prefix is a domain separator: a signature made here can never be mistaken for a
signature over some other kind of message made with the same key.

Ed25519 comes from the optional ``cryptography`` package (the ``signing`` extra), which
is imported only when a signature is actually made or checked. Without it:

* :func:`has_signing_support` returns False;
* making or loading a signer raises :class:`SigningUnavailableError`, a
  :class:`~portlock.core.errors.PortLockError` that says what to install;
* :func:`verify_event` reports ``signing_unavailable`` instead of raising;
* everything else in :mod:`portlock.audit`, including this module's
  :func:`signing_input`, keeps working.

**A valid signature proves who signed only if the key is one you already trust.** The
public key travels inside the event, so :func:`verify_event` on its own shows that the
event is intact and was signed by *whoever holds that key*. Pass ``trusted_keys`` (keys
obtained out of band, at enrolment) to make it mean more than that.

Two things are decided here and not left to the Ed25519 library, because libraries
disagree about them and a verdict must not depend on which one a verifier happens to
use: a public key that is a point of small order is refused (``weak_key``: a signature
under it can be made without any secret), and so is a key whose encoding is not the
canonical one (``bad_key_encoding``).

The private key is a 32-byte seed. It is never logged, never included in an error
message and never part of a ``repr``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import secrets
import stat
import sys
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from portlock.audit.events import AuditError, validate_security_event
from portlock.core.canonical import canonical_bytes, canonicalize
from portlock.core.errors import CanonicalError
from portlock.core.fsutil import atomic_write_bytes, ensure_private_dir

__all__ = [
    "ALGORITHM",
    "PUBLIC_KEY_BYTES",
    "SEED_BYTES",
    "SIGNATURE_BYTES",
    "SIGNING_DOMAIN",
    "EventSigner",
    "SigningUnavailableError",
    "VerifyOutcome",
    "has_signing_support",
    "load_or_create_key",
    "signing_input",
    "verify_event",
]

#: The ``sig.alg`` value.
ALGORITHM = "ed25519"

#: Domain separator; followed by one zero byte and then the canonical event.
SIGNING_DOMAIN = b"portlock/1/security-event"

SEED_BYTES = 32
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


class SigningUnavailableError(AuditError):
    """Ed25519 is needed but the optional ``cryptography`` package cannot be imported."""

    code = "signing_unavailable"


_UNAVAILABLE = (
    "Ed25519 support is missing: install the optional 'cryptography' package "
    "(pip install 'portlock[signing]')"
)


def _ed25519() -> Any:
    """Import the Ed25519 primitives on first use.

    Raises:
        SigningUnavailableError: if ``cryptography`` is absent or its binary part does
            not load on this interpreter.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception as exc:
        # ImportError when the package is absent; a broken or mismatched binary wheel
        # can fail in other ways. Either way there is no Ed25519 here.
        raise SigningUnavailableError(_UNAVAILABLE) from exc
    return ed25519


def has_signing_support() -> bool:
    """True if events can be signed and verified in this process."""
    try:
        _ed25519()
    except SigningUnavailableError:
        return False
    return True


def signing_input(event: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers for ``event``.

    ``SIGNING_DOMAIN || 0x00 || canonical_json(event without its "sig" member)``.
    Needs no cryptography, so it is available everywhere.

    Raises:
        AuditError: if the event cannot be written as canonical JSON.
    """
    unsigned = {name: value for name, value in event.items() if name != "sig"}
    try:
        return SIGNING_DOMAIN + b"\x00" + canonical_bytes(unsigned)
    except CanonicalError as exc:
        raise AuditError(f"the event cannot be written as canonical JSON: {exc}") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _strict_b64decode(text: str, length: int) -> bytes | None:
    """Decode standard padded base64 that must be exactly ``length`` bytes, or ``None``.

    Strict means one accepted spelling per value: no whitespace, no URL-safe alphabet,
    no missing padding, no stray bits in the final character. Re-encoding and comparing
    enforces all of those at once.
    """
    if not isinstance(text, str) or not text.isascii():
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != length or _b64(raw) != text:
        return None
    return raw


_FIELD_PRIME = 2**255 - 19

# The y-coordinates of the eight points of small order on edwards25519: orders 4, 1, 8,
# 8 and 2, each y shared by a point and its negative. No honest key is one of them
# (a real public key is a multiple of the base point by a clamped scalar), and under
# such a key a signature can be made without any secret: for the identity point,
# ``R = identity, S = 0`` satisfies the verification equation for every message.
# Libraries disagree about refusing these keys, so the format refuses them itself and
# every implementation gives the same answer.
_SMALL_ORDER_Y = frozenset(
    {
        0,
        1,
        2707385501144840649318225287225658788936804267575313519463743609750303402022,
        55188659117513257062467267217118295137698188065244968500265048394206261417927,
        _FIELD_PRIME - 1,
    }
)


def _key_problem(public_key: bytes) -> tuple[str, str] | None:
    """Say why a 32-byte public key must not be used, as ``(code, reason)``, or ``None``.

    The y-coordinate is the little-endian value with the top bit (the sign of x)
    cleared. It must be below the field prime, so that a point has exactly one
    encoding, and it must not belong to a point of small order.
    """
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    if y >= _FIELD_PRIME:
        return (
            "bad_key_encoding",
            "sig.key is not a canonical point encoding: its y-coordinate is not below 2^255 - 19",
        )
    if y in _SMALL_ORDER_Y:
        return (
            "weak_key",
            "sig.key is a point of small order: anyone can make a signature that verifies "
            "under it, so it proves nothing",
        )
    return None


@dataclass(frozen=True, slots=True)
class VerifyOutcome:
    """The result of checking one signed event.

    Attributes:
        ok: True only if the event is well formed and its signature is valid for the
            embedded key (and that key is trusted, when trusted keys were given).
        reason: one sentence for the operator.
        code: a stable identifier to branch on: ``ok``, ``not_signed``,
            ``malformed_event``, ``bad_key_encoding``, ``bad_signature_encoding``,
            ``weak_key``, ``bad_trusted_keys``, ``untrusted_key``,
            ``signing_unavailable``, ``signature_mismatch`` or ``verification_error``.
        public_key: the 32-byte key the signature verified under; ``None`` unless ``ok``.
    """

    ok: bool
    reason: str
    code: str = "ok"
    public_key: bytes | None = None


class EventSigner:
    """Signs security events with one Ed25519 key.

    Create one with :meth:`generate`, :meth:`from_seed` or :func:`load_or_create_key`.
    Thread-safe: the key is immutable and signing has no state.
    """

    __slots__ = ("_private", "_public")

    def __init__(self, seed: bytes) -> None:
        """Build a signer from a 32-byte seed. Prefer the named constructors.

        Raises:
            SigningUnavailableError: if ``cryptography`` is not installed.
            AuditError: if the seed is not exactly 32 bytes.
        """
        ed25519 = _ed25519()
        if not isinstance(seed, bytes | bytearray) or len(seed) != SEED_BYTES:
            raise AuditError(f"an Ed25519 seed is exactly {SEED_BYTES} bytes")
        self._private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(seed))
        self._public: bytes = self._private.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> EventSigner:
        """A signer with a fresh random key that exists only in memory.

        Raises:
            SigningUnavailableError: if ``cryptography`` is not installed.
        """
        return cls(secrets.token_bytes(SEED_BYTES))

    @classmethod
    def from_seed(cls, seed: bytes) -> EventSigner:
        """A signer for the key derived from ``seed`` (RFC 8032 private key bytes).

        Raises:
            SigningUnavailableError: if ``cryptography`` is not installed.
            AuditError: if the seed is not exactly 32 bytes.
        """
        return cls(seed)

    @property
    def public_key(self) -> bytes:
        """The 32-byte public key."""
        return self._public

    @property
    def public_key_b64(self) -> str:
        """The public key in base64, as it appears in ``sig.key``."""
        return _b64(self._public)

    def sign_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Return a copy of ``event`` with its ``sig`` member added.

        The input is not modified. Ed25519 signatures are deterministic: the same key
        and event always give the same signature.

        Args:
            event: an unsigned envelope, as built by
                :func:`portlock.audit.events.build_security_event`.

        Raises:
            AuditError: if the event is malformed or already carries a signature.
        """
        candidate = dict(event) if isinstance(event, Mapping) else event
        validate_security_event(candidate, signed=False)
        # A deep copy made of plain JSON types, so the caller's object is left alone.
        signed: dict[str, Any] = json.loads(canonicalize(candidate))
        signature: bytes = self._private.sign(signing_input(signed))
        signed["sig"] = {"alg": ALGORITHM, "key": self.public_key_b64, "value": _b64(signature)}
        return signed

    def __repr__(self) -> str:
        return f"EventSigner(public_key={self.public_key_b64!r})"


def _normalise_trusted(trusted_keys: Collection[bytes | str]) -> frozenset[bytes] | None:
    if isinstance(trusted_keys, bytes | bytearray | str):
        trusted_keys = [trusted_keys]
    keys: set[bytes] = set()
    for key in trusted_keys:
        if isinstance(key, bytes | bytearray) and len(key) == PUBLIC_KEY_BYTES:
            keys.add(bytes(key))
            continue
        decoded = _strict_b64decode(key, PUBLIC_KEY_BYTES) if isinstance(key, str) else None
        if decoded is None:
            return None
        keys.add(decoded)
    return frozenset(keys)


def verify_event(
    event: object, *, trusted_keys: Collection[bytes | str] | None = None
) -> VerifyOutcome:
    """Check a signed security event. Never raises; the outcome says what is wrong.

    The envelope must be exactly the version-1 shape, ``sig.key`` and ``sig.value`` must
    be canonical padded base64 of exactly 32 and 64 bytes, the key must be a canonically
    encoded point that is not of small order, and the signature must verify over
    :func:`signing_input`.

    Args:
        event: the parsed event (a ``dict`` from a JSON parser).
        trusted_keys: public keys accepted as signers, each as 32 raw bytes or base64.
            When given, an event signed by any other key fails with ``untrusted_key``.
            When omitted, a successful outcome only shows the event is intact under the
            key it carries; check :attr:`VerifyOutcome.public_key` yourself.

    Returns:
        The outcome. With ``cryptography`` missing it is ``signing_unavailable`` for any
        event that passes every check that needs no Ed25519.
    """
    try:
        return _verify_event(event, trusted_keys)
    except Exception as exc:
        # Hostile input must never crash a verifier. The type is enough to diagnose;
        # the message could echo attacker-controlled bytes.
        return VerifyOutcome(
            False, f"verification failed unexpectedly ({type(exc).__name__})", "verification_error"
        )


def _verify_event(event: object, trusted_keys: Collection[bytes | str] | None) -> VerifyOutcome:
    if isinstance(event, dict) and "sig" not in event:
        return VerifyOutcome(False, "the event is not signed", "not_signed")
    try:
        validate_security_event(event, signed=True)
    except AuditError as exc:
        return VerifyOutcome(False, f"the event is malformed: {exc}", "malformed_event")
    if not isinstance(event, dict):  # validate_security_event has already refused it
        return VerifyOutcome(False, "the event is malformed", "malformed_event")
    sig = event["sig"]

    public_key = _strict_b64decode(sig["key"], PUBLIC_KEY_BYTES)
    if public_key is None:
        return VerifyOutcome(
            False,
            f"sig.key is not canonical base64 of {PUBLIC_KEY_BYTES} bytes",
            "bad_key_encoding",
        )
    signature = _strict_b64decode(sig["value"], SIGNATURE_BYTES)
    if signature is None:
        return VerifyOutcome(
            False,
            f"sig.value is not canonical base64 of {SIGNATURE_BYTES} bytes",
            "bad_signature_encoding",
        )
    # Decided here, not left to the Ed25519 library: libraries differ on these keys.
    problem = _key_problem(public_key)
    if problem is not None:
        return VerifyOutcome(False, problem[1], problem[0])

    if trusted_keys is not None:
        trusted = _normalise_trusted(trusted_keys)
        if trusted is None:
            return VerifyOutcome(
                False,
                f"a trusted key is not {PUBLIC_KEY_BYTES} bytes or its base64",
                "bad_trusted_keys",
            )
        if public_key not in trusted:
            return VerifyOutcome(
                False, "the event is signed by a key that is not trusted", "untrusted_key"
            )

    try:
        ed25519 = _ed25519()
    except SigningUnavailableError as exc:
        return VerifyOutcome(False, str(exc), "signing_unavailable")
    message = signing_input(event)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except Exception:
        # InvalidSignature for a wrong signature; a key that is not a valid curve point
        # is refused the same way.
        return VerifyOutcome(
            False, "the signature does not match the event and key", "signature_mismatch"
        )
    return VerifyOutcome(True, "the signature is valid", "ok", public_key)


def _read_seed(path: Path) -> bytes | None:
    """Read an existing key file; ``None`` if there is none."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuditError(f"cannot read the signing key {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise AuditError(f"the signing key {path.name} is not a regular file")
    # POSIX only: Windows permissions come from the state directory's ACL.
    if sys.platform != "win32" and info.st_mode & 0o077:
        raise AuditError(
            f"the signing key {path.name} is accessible to other users "
            f"(mode {stat.S_IMODE(info.st_mode):04o}); it must be 0600"
        )
    try:
        with open(path, "rb") as stream:
            seed = stream.read(SEED_BYTES + 1)
    except OSError as exc:
        raise AuditError(f"cannot read the signing key {path.name}: {exc}") from exc
    if len(seed) != SEED_BYTES:
        raise AuditError(f"the signing key {path.name} is not exactly {SEED_BYTES} bytes")
    return seed


def _create_seed(path: Path) -> bytes:
    """Create the key file, or return the key another process created first."""
    if not path.parent.exists():
        ensure_private_dir(path.parent)
    seed = secrets.token_bytes(SEED_BYTES)
    staging = path.with_name(f".{path.name}.{secrets.token_hex(8)}.new")
    try:
        # Written completely, flushed and owner-only before it can be seen as the key.
        atomic_write_bytes(staging, seed, private=True)
        try:
            # A hard link either creates the name or fails because it exists: two
            # processes starting together cannot both think they created the key.
            os.link(staging, path)
        except FileExistsError:
            existing = _read_seed(path)
            if existing is None:
                raise AuditError(f"the signing key {path.name} vanished while loading") from None
            return existing
        except OSError:
            # No hard links on this filesystem: fall back to a plain atomic rename.
            os.replace(staging, path)
    except OSError as exc:
        raise AuditError(f"cannot create the signing key {path.name}: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(staging)
    return seed


def load_or_create_key(path: str | os.PathLike[str]) -> EventSigner:
    """Load the signing key stored at ``path``, creating it on first use.

    The file holds the raw 32-byte seed and nothing else. It is created readable and
    writable by its owner only; on POSIX an existing key file that group or others can
    access is refused rather than used. A missing parent directory is created private.
    Nothing is created when signing support is missing.

    Args:
        path: the key file, normally inside PortLock's state directory.

    Returns:
        A signer for the stored key.

    Raises:
        SigningUnavailableError: if ``cryptography`` is not installed.
        AuditError: if the file is not a regular 32-byte file, has loose permissions,
            or cannot be read or created.
    """
    _ed25519()
    target = Path(path)
    seed = _read_seed(target)
    if seed is None:
        seed = _create_seed(target)
    return EventSigner.from_seed(seed)
