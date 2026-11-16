"""Canonical JSON: the shared vectors plus Python-specific behaviour."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from portlock.core.canonical import MAX_DEPTH, canonical_bytes, canonicalize, parse_canonical
from portlock.core.errors import CanonicalError

VECTORS = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "canonical-json.json").read_text(encoding="utf-8")
)


def _ids(entries: list[dict[str, str]]) -> list[str]:
    return [entry["name"] for entry in entries]


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=_ids(VECTORS["valid"]))
def test_valid_vectors_produce_the_expected_text(vector: dict[str, str]) -> None:
    assert canonicalize(json.loads(vector["input"])) == vector["canonical"]


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=_ids(VECTORS["valid"]))
def test_canonical_output_is_a_fixed_point(vector: dict[str, str]) -> None:
    value = parse_canonical(vector["canonical"])
    assert canonicalize(value) == vector["canonical"]


@pytest.mark.parametrize("vector", VECTORS["rejectValue"], ids=_ids(VECTORS["rejectValue"]))
def test_values_outside_the_subset_are_rejected(vector: dict[str, str]) -> None:
    value = json.loads(vector["input"])
    with pytest.raises(CanonicalError):
        canonicalize(value)


@pytest.mark.parametrize("vector", VECTORS["rejectStrict"], ids=_ids(VECTORS["rejectStrict"]))
def test_strict_parse_rejects_non_canonical_text(vector: dict[str, str]) -> None:
    with pytest.raises(CanonicalError):
        parse_canonical(vector["input"])


def test_strict_parse_accepts_bytes_and_rejects_bad_encodings() -> None:
    assert parse_canonical(b'{"a":1}') == {"a": 1}
    assert parse_canonical(bytearray(b"[1,2]")) == [1, 2]
    with pytest.raises(CanonicalError):
        parse_canonical(b'"\xff"')
    with pytest.raises(CanonicalError):
        parse_canonical(b"\xef\xbb\xbf{}")


def test_canonical_bytes_is_utf8_of_the_text() -> None:
    value = {"text": "h\xe9llo \U0001f600", "n": 1}
    assert canonical_bytes(value) == canonicalize(value).encode("utf-8")


def test_key_order_does_not_depend_on_insertion_order() -> None:
    first = {"x": 1, "y": [1, 2], "z": {"p": None, "q": True}}
    second = {"z": {"q": True, "p": None}, "y": [1, 2], "x": 1}
    assert canonicalize(first) == canonicalize(second)


def test_booleans_are_not_confused_with_integers() -> None:
    assert canonicalize([True, False, 1, 0]) == "[true,false,1,0]"


def test_tuples_serialize_as_arrays() -> None:
    assert canonicalize((1, ("a", None))) == '[1,["a",null]]'


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        float("nan"),
        float("inf"),
        Decimal("1"),
        b"bytes",
        {1, 2},
        object(),
        {1: "integer key"},
        {None: "none key"},
        {"nested": {"bad": 1.5}},
        2**53,
        -(2**53),
    ],
    ids=repr,
)
def test_python_only_values_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalError):
        canonicalize(value)


def test_nesting_limit_counts_containers_not_scalars() -> None:
    def build(depth: int) -> object:
        value: object = 1
        for _ in range(depth):
            value = {"k": value}
        return value

    canonicalize(build(MAX_DEPTH))
    with pytest.raises(CanonicalError):
        canonicalize(build(MAX_DEPTH + 1))


def test_deeply_nested_input_is_an_error_not_a_crash() -> None:
    with pytest.raises(CanonicalError):
        parse_canonical("[" * 100_000 + "]" * 100_000)
