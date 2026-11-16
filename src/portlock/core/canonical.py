"""Canonical JSON.

Hashes and signatures are computed over bytes, so the same value must always become the
same bytes. This module implements RFC 8785 (JSON Canonicalization Scheme) restricted to
a subset that is trivial to reproduce exactly in any language:

* object keys are printable ASCII (0x20..0x7e) and are emitted in ascending order;
* numbers are integers in the IEEE-754 safe range, emitted in plain decimal;
* strings are well-formed Unicode, emitted with the minimal escaping RFC 8785 mandates;
* no insignificant whitespace;
* at most :data:`MAX_DEPTH` containers nested inside one another.

Floats are excluded on purpose: number formatting is where canonicalization schemes
diverge between languages, and nothing PortLock signs needs them.

ClawNet's ``clawnet/src/core/wire/canonical.js`` implements the same rules, and both
projects run the same vector file (``tests/fixtures/canonical-json.json``), so either can
verify signatures made by the other.
"""

from __future__ import annotations

import json
import re
from typing import Any

from portlock.core.errors import CanonicalError

__all__ = ["MAX_DEPTH", "canonical_bytes", "canonicalize", "parse_canonical"]

#: Maximum number of containers (objects and arrays) nested inside one another.
MAX_DEPTH = 32

_MAX_SAFE_INTEGER = 2**53 - 1
_KEY_PATTERN = re.compile(r"[\x20-\x7e]*\Z")


def canonicalize(value: Any) -> str:
    """Serialize ``value`` to canonical JSON text.

    Raises:
        CanonicalError: if the value is outside the supported subset.
    """
    return _encode(value, 0)


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON as UTF-8 bytes. This is what gets signed."""
    return canonicalize(value).encode("utf-8")


def parse_canonical(data: str | bytes | bytearray | memoryview) -> Any:
    """Parse text that is required to already be in canonical form.

    Rejects anything a canonical encoder would not have produced: whitespace, unsorted or
    duplicate keys, floats, exponents, non-minimal escapes, a byte-order mark. Use this
    where accepting two encodings of one value would be a malleability problem.

    Raises:
        CanonicalError: if the input is not canonical JSON.
    """
    if isinstance(data, str):
        text = data
    else:
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError("input is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            parse_float=_reject_number,
            parse_constant=_reject_number,
            object_pairs_hook=_unique_pairs,
        )
    except CanonicalError:
        raise
    except (ValueError, RecursionError) as exc:
        raise CanonicalError("input is not valid JSON") from exc
    if canonicalize(value) != text:
        raise CanonicalError("input is not in canonical form")
    return value


def _reject_number(_literal: str) -> Any:
    raise CanonicalError("numbers must be integers in the safe range")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError("duplicate object key")
        result[key] = value
    return result


def _encode(value: Any, depth: int) -> str:
    if value is None:
        return "null"
    # bool is a subclass of int, so it has to be tested first.
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise CanonicalError("numbers must be integers in the safe range")
        return str(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, float):
        raise CanonicalError("numbers must be integers in the safe range")

    if isinstance(value, list | tuple):
        if depth >= MAX_DEPTH:
            raise CanonicalError(f"nesting exceeds {MAX_DEPTH} levels")
        return "[" + ",".join(_encode(item, depth + 1) for item in value) + "]"

    if isinstance(value, dict):
        if depth >= MAX_DEPTH:
            raise CanonicalError(f"nesting exceeds {MAX_DEPTH} levels")
        for key in value:
            if not isinstance(key, str) or not _KEY_PATTERN.match(key):
                raise CanonicalError("object keys must be printable ASCII strings")
        # Keys are ASCII, so code-point order is plain byte order.
        return (
            "{"
            + ",".join(
                f"{_encode_string(key)}:{_encode(value[key], depth + 1)}" for key in sorted(value)
            )
            + "}"
        )

    raise CanonicalError(f"unsupported type: {type(value).__name__}")


def _encode_string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalError("strings must not contain lone surrogates") from exc
    # With ensure_ascii=False this escapes exactly what RFC 8785 requires: the quote, the
    # backslash, and control characters below 0x20 (short forms where JSON has them,
    # lowercase \u00xx otherwise).
    return json.dumps(value, ensure_ascii=False)
