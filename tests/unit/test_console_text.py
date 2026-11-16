"""``escape_control``: nothing a device says can act on a terminal."""

from __future__ import annotations

import unicodedata

import pytest

from portlock.console import escape_control

BACKSLASH = chr(92)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Example Flash 16GB", "Example Flash 16GB"),
        ("", ""),
        ("naïve café 数据", "naïve café 数据"),
        ("tab\there", f"tab{BACKSLASH}x09here"),
        ("line\nfeed", f"line{BACKSLASH}x0afeed"),
        ("carriage\rreturn", f"carriage{BACKSLASH}x0dreturn"),
        ("\x1b[2J\x1b[31mred", f"{BACKSLASH}x1b[2J{BACKSLASH}x1b[31mred"),
        ("bell\x07", f"bell{BACKSLASH}x07"),
        ("nul\x00byte", f"nul{BACKSLASH}x00byte"),
        ("del\x7f", f"del{BACKSLASH}x7f"),
        ("c1\x9bcontrol", f"c1{BACKSLASH}x9bcontrol"),
        ("keep a " + BACKSLASH + " backslash", "keep a " + BACKSLASH + " backslash"),
    ],
)
def test_control_characters_become_visible_escapes(text: str, expected: str) -> None:
    assert escape_control(text) == expected


@pytest.mark.parametrize(
    "char",
    [
        chr(0x202E),  # right-to-left override: reorders the text after it
        chr(0x202A),  # left-to-right embedding
        chr(0x2066),  # left-to-right isolate
        chr(0x200B),  # zero-width space
        chr(0x200D),  # zero-width joiner
        chr(0xFEFF),  # byte-order mark
        chr(0x2028),  # line separator
        chr(0x2029),  # paragraph separator
        chr(0xE000),  # private use
        chr(0xD800),  # a lone surrogate
        chr(0x0378),  # unassigned
        chr(0x10FFFF),  # unassigned, outside the BMP
    ],
)
def test_invisible_and_reordering_characters_are_written_out(char: str) -> None:
    result = escape_control("a" + char + "b")
    assert char not in result and result.startswith("a" + BACKSLASH) and result.endswith("b")
    assert f"{ord(char):04x}" in result or f"{ord(char):08x}" in result


def test_the_result_is_always_printable_whatever_goes_in() -> None:
    nasty = "".join(chr(code) for code in range(0x300)) + chr(0x202E) + chr(0x1F600) + "x"
    result = escape_control(nasty)
    for char in result:
        assert char == " " or (
            char.isprintable() and unicodedata.category(char) not in {"Cc", "Cf", "Zl", "Zp"}
        )


def test_ordinary_spaces_and_emoji_survive() -> None:
    assert escape_control("a b  c " + chr(0x1F600)) == "a b  c " + chr(0x1F600)


def test_newlines_can_be_kept_for_text_the_caller_has_already_split() -> None:
    assert escape_control("one\ntwo\r\n", keep_newlines=True) == f"one\ntwo{BACKSLASH}x0d\n"


@pytest.mark.parametrize("value", [None, 5, 3.5, b"bytes", ["a", "\x1b"], object])
def test_anything_can_be_passed_and_is_made_safe_as_text(value: object) -> None:
    text = escape_control(value)
    assert isinstance(text, str) and "\x1b" not in text


def test_an_escape_cannot_be_forged_by_the_text_that_follows_it() -> None:
    # A device name that already contains what an escape looks like stays ambiguous only
    # on the page, never on the terminal: the real control character is always escaped.
    assert escape_control(BACKSLASH + "x1b") == BACKSLASH + "x1b"
    assert escape_control("\x1b") == BACKSLASH + "x1b"
