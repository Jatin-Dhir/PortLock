"""Device fingerprinting (``docs/DESIGN.md`` section 4).

A fingerprint is a short, stable name for "a device that describes itself like this". It
is computed only from what the device says in its descriptors, so the same stick gets the
same fingerprint on every port, on every connection, and on both Windows and Linux.

**A fingerprint identifies; it does not authenticate.** Every input is supplied by the
device and can be copied by a device built to copy it. The confidence attached to each
fingerprint says how far the value narrows a device down, not how far it can be trusted.

The value is ``plk1:`` followed by the first 32 characters (160 bits) of the lowercase,
unpadded RFC 4648 base32 encoding of ``SHA-256(canonical_bytes(payload))`` where
``payload`` is::

    {"v": 1, "vid": int, "pid": int,
     "serial": str | None, "manufacturer": str | None, "product": str | None,
     "bcd": int | None, "ifaces": [[cls, subcls, protocol], ...]}   # sorted

The ``plk1`` prefix and the ``"v": 1`` member version the scheme: any change to the
payload or to the normalization rules must introduce ``plk2`` rather than silently
re-labelling every device an administrator has already trusted.

The strings hashed are those of the :class:`~portlock.core.models.UsbDevice`, which has
already made device text safe (``sanitize_device_text``): control and format characters
are U+FFFD and each string is at most 126 characters. So a serial ending in a tab and the
same serial ending in a space are different devices here, exactly as they are different
in every listing and audit record. ``instance_id``, ``bus_path``, ``connection_id`` and
the rest of what describes one connection never take part.
"""

from __future__ import annotations

import base64
import hashlib
import unicodedata
from itertools import pairwise

from portlock.core.canonical import canonical_bytes
from portlock.core.models import Confidence, Fingerprint, UsbDevice

__all__ = [
    "FINGERPRINT_PREFIX",
    "KNOWN_SHARED_SERIALS",
    "MIN_UNIQUE_SERIAL_LENGTH",
    "STORAGE_IDENTITY_PREFIX",
    "fingerprint",
    "is_unique_looking_serial",
    "normalize_serial",
    "normalize_text",
    "storage_identity",
]

#: Prefix (and scheme version) of every fingerprint value.
FINGERPRINT_PREFIX = "plk1:"

#: Prefix (and scheme version) of every storage identity.
STORAGE_IDENTITY_PREFIX = "plv1:"

#: A serial shorter than this cannot look unique, however varied its characters.
MIN_UNIQUE_SERIAL_LENGTH = 8

_PAYLOAD_VERSION = 1
_DIGEST_CHARS = 32
_MIN_DISTINCT_CHARACTERS = 4
_REPLACEMENT_CHARACTER = "\N{REPLACEMENT CHARACTER}"

#: Serials that many separate units are known or built to report, written in normalized
#: (upper-case) form. A serial on this list narrows a device down no better than no
#: serial at all, so it never earns ``Confidence.HIGH``.
#:
#: The list is deliberately short. The structural tests in
#: :func:`is_unique_looking_serial` already reject one repeated character
#: (``000000000000``), counting runs (``0123456789ABCDEF``, ``123456789``) and repeated
#: blocks (``DEADBEEFDEADBEEF``, ``ABCDABCDAB``); only values that get past those need an
#: entry here.
KNOWN_SHARED_SERIALS: frozenset[str] = frozenset(
    {
        # Placeholder constants from firmware examples and unprogrammed controllers.
        "DEADBEEF",
        "1234567890ABCDEF",
        "ABCDEF1234567890",
        # Fixed serial reported by a whole family of Realtek USB card readers.
        "20100201396000",
        # Fixed serial reported by a whole family of Alcor Micro USB card readers.
        "058F63666485",
        # Placeholder text left in descriptors by firmware that was never personalized.
        "SERIALNUMBER",
        "SERIAL NUMBER",
        "DEFAULT STRING",
        "NOT SPECIFIED",
        "TO BE FILLED BY O.E.M.",
    }
)

# Alphabets in which a serial can "count". Each is treated as a ring, so 1234567890 and
# 89ABCDEF01234567 count just as 0123456789 does.
_RUN_ALPHABETS: tuple[str, ...] = (
    "0123456789",
    "0123456789ABCDEF",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
)
_RUN_INDEXES: tuple[dict[str, int], ...] = tuple(
    {char: position for position, char in enumerate(alphabet)} for alphabet in _RUN_ALPHABETS
)


def normalize_text(value: str | None) -> str | None:
    """Normalize a descriptor string so that equivalent spellings compare equal.

    Applies Unicode NFKC, strips leading and trailing whitespace and collapses every
    internal run of whitespace to one space. Text that is not well-formed Unicode (a
    device can put anything in a string descriptor) has each lone surrogate replaced by
    U+FFFD, so the result can always be hashed.

    Args:
        value: the string as the operating system reported it, or ``None``.

    Returns:
        The normalized text, or ``None`` if the input was ``None`` or nothing is left.

    Raises:
        TypeError: if ``value`` is neither a string nor ``None``.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"descriptor text must be a string or None, got {type(value).__name__}")
    text = _collapse(unicodedata.normalize("NFKC", _well_formed(value)))
    return text or None


def normalize_serial(value: str | None) -> str | None:
    """Normalize a serial number: :func:`normalize_text`, then upper-case.

    Windows upper-cases the serial when it builds a device instance id; Linux reports it
    exactly as the device sent it. Upper-casing makes the same stick fingerprint
    identically on both.

    Raises:
        TypeError: if ``value`` is neither a string nor ``None``.
    """
    text = normalize_text(value)
    if text is None:
        return None
    # Upper-casing can undo NFKC for a handful of characters (their upper-case form has a
    # compatibility decomposition of its own), and normalizing can in turn expose a
    # lower-case letter. Repeat until nothing changes so the function is idempotent; the
    # bound only guards against an endless loop should a future Unicode version contain
    # a cycle.
    for _ in range(4):
        folded = _collapse(unicodedata.normalize("NFKC", text.upper()))
        if folded == text:
            break
        text = folded
    return text or None


def is_unique_looking_serial(serial: str | None) -> bool:
    """Say whether a serial plausibly belongs to one unit only.

    The serial is normalized with :func:`normalize_serial` first. It looks unique when
    all of these hold:

    * it has at least :data:`MIN_UNIQUE_SERIAL_LENGTH` characters;
    * it uses at least four distinct characters (so it is not one repeated character,
      nor padding around a single digit);
    * it is not a counting run, ascending or descending, such as ``0123456789ABCDEF``,
      ``123456789`` or ``FEDCBA9876543210``;
    * it is not a shorter block repeated at least twice, such as ``DEADBEEFDEADBEEF``;
      the last copy may be cut short (``ABCDABCDAB``), as it is when a long repeated
      string meets the 126-character cap on device text;
    * it is not in :data:`KNOWN_SHARED_SERIALS`.

    This is a heuristic about *looks*. A serial that passes can still be shared by a
    whole production batch, or copied on purpose.

    Raises:
        TypeError: if ``serial`` is neither a string nor ``None``.
    """
    text = normalize_serial(serial)
    if text is None or len(text) < MIN_UNIQUE_SERIAL_LENGTH:
        return False
    if len(set(text)) < _MIN_DISTINCT_CHARACTERS:
        return False
    if _is_counting_run(text) or _is_repeated_block(text):
        return False
    return text not in KNOWN_SHARED_SERIALS


def fingerprint(device: UsbDevice) -> Fingerprint:
    """Compute the fingerprint of a device.

    Only descriptor content takes part: vendor id, product id, serial, manufacturer,
    product, ``bcdDevice`` and the interface triples, as the device model stores them
    (already sanitized). ``instance_id``, ``bus_path``, ``connection_id``, ``removable``,
    ``volumes``, ``device_class`` and ``backend_data`` never influence the value, so a
    device keeps its fingerprint when it is plugged in again, moves to another port, is
    mounted, or is seen by a different backend.

    Args:
        device: the device as reported for the current connection.

    Returns:
        The fingerprint, with ``confidence`` HIGH only if the device has a serial that
        :func:`is_unique_looking_serial` accepts, and ``basis`` naming the fields that
        were present, by their payload names (``vid`` and ``pid`` always are).

    Raises:
        TypeError: if a descriptor string is not text. A :class:`UsbDevice` refuses such
            a value when it is built, so this means the object was tampered with.
    """
    serial = normalize_serial(device.serial)
    manufacturer = normalize_text(device.manufacturer)
    product = normalize_text(device.product)
    interfaces = sorted(
        [interface.cls, interface.subcls, interface.protocol] for interface in device.interfaces
    )
    payload = {
        "v": _PAYLOAD_VERSION,
        "vid": device.vendor_id,
        "pid": device.product_id,
        "serial": serial,
        "manufacturer": manufacturer,
        "product": product,
        "bcd": device.bcd_device,
        "ifaces": interfaces,
    }
    basis = ["vid", "pid"]
    if serial is not None:
        basis.append("serial")
    if manufacturer is not None:
        basis.append("manufacturer")
    if product is not None:
        basis.append("product")
    if device.bcd_device is not None:
        basis.append("bcd")
    if interfaces:
        basis.append("ifaces")
    confidence = Confidence.HIGH if is_unique_looking_serial(serial) else Confidence.LOW
    return Fingerprint(
        value=FINGERPRINT_PREFIX + _digest(payload),
        confidence=confidence,
        basis=tuple(basis),
    )


def storage_identity(device: UsbDevice) -> str | None:
    """A secondary identifier for the storage a device currently exposes.

    Built from the filesystem UUIDs of the device's volumes (normalized, upper-cased,
    de-duplicated and sorted), so it does not depend on the order in which the volumes
    were discovered. It is for display and for the audit trail: it changes when a volume
    is reformatted, and a filesystem UUID is as easy to copy as a serial number, so it
    must never be used to decide access.

    Returns:
        ``plv1:`` followed by 32 base32 characters, or ``None`` if the device exposes no
        volume with a filesystem UUID.

    Raises:
        TypeError: if a volume's ``fs_uuid`` is neither a string nor ``None``.
    """
    uuids = sorted(
        {
            normalized
            for normalized in (normalize_serial(volume.fs_uuid) for volume in device.volumes)
            if normalized is not None
        }
    )
    if not uuids:
        return None
    return STORAGE_IDENTITY_PREFIX + _digest({"v": _PAYLOAD_VERSION, "fs_uuids": uuids})


def _digest(payload: dict[str, object]) -> str:
    digest = hashlib.sha256(canonical_bytes(payload)).digest()
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()[:_DIGEST_CHARS]


def _collapse(text: str) -> str:
    # str.split() with no argument splits on every Unicode whitespace character and
    # drops empty leading and trailing fields, which is exactly "strip and collapse".
    return " ".join(text.split())


def _well_formed(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # Lone surrogates cannot be encoded, and so cannot be hashed. Replace each with
        # U+FFFD, deterministically, instead of refusing to fingerprint the device.
        return "".join(_REPLACEMENT_CHARACTER if 0xD800 <= ord(c) <= 0xDFFF else c for c in text)
    return text


def _is_counting_run(text: str) -> bool:
    for index in _RUN_INDEXES:
        if any(char not in index for char in text):
            continue
        size = len(index)
        steps = {(index[second] - index[first]) % size for first, second in pairwise(text)}
        if steps in ({1}, {size - 1}):
            return True
    return False


def _is_repeated_block(text: str) -> bool:
    """True if ``text`` is a block of at most half its length repeated, the last copy
    possibly cut short: its smallest period ``p`` satisfies ``2 * p <= len(text)``.

    The smallest period is ``len(text)`` minus the longest proper prefix that is also a
    suffix (the Knuth-Morris-Pratt failure function), found in linear time, so even an
    absurdly long serial passed in directly costs little.
    """
    if not text:
        return False
    border = [0] * len(text)
    length = 0
    for index in range(1, len(text)):
        while length and text[index] != text[length]:
            length = border[length - 1]
        if text[index] == text[length]:
            length += 1
        border[index] = length
    period = len(text) - border[-1]
    return 2 * period <= len(text)
