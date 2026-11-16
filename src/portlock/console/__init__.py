"""PortLock Console: the local HTTP API, the command line, the simulator.

* :mod:`portlock.console.api` - the local HTTP API (``docs/API.md``), a client of
  :class:`~portlock.core.service.PortLockService` and the only place where sessions and
  roles are applied.
* :mod:`portlock.console.cli` - ``portlock``, the command line: an HTTP client of the API
  for everything the service owns, and direct file access for the few commands that must
  work without it.
* :mod:`portlock.console.simulate` - ``portlock simulate``: the whole product on a fake
  machine, so it can be explored anywhere.

This module holds the one helper every text output shares: :func:`escape_control`.
Everything a device says about itself is attacker-controlled text, and a terminal treats
some characters as instructions (escape sequences, carriage returns that overwrite a line,
bidirectional overrides that reorder it), so nothing a device supplied is printed
without passing through it.
"""

from __future__ import annotations

import unicodedata

__all__ = ["escape_control"]

# Control, format (zero-width and bidirectional controls), surrogate, private-use,
# unassigned and the two line-breaking separators: none of them can be seen, and several
# change how the text around them is shown.
_INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_BACKSLASH = chr(92)


def escape_control(text: object, *, keep_newlines: bool = False) -> str:
    """``text`` with every character a terminal could act on written out visibly.

    Control characters become ``\\xNN``, other invisible characters ``\\uNNNN`` (or
    ``\\UNNNNNNNN``), and a backslash stays a backslash, so the output is unambiguous to
    read but is not meant to be parsed back. Printable text, spaces and non-ASCII letters
    are left alone. With ``keep_newlines`` a line feed is kept, for multi-line values that
    the caller has already split into trusted lines.
    """
    parts: list[str] = []
    for char in str(text):
        if (
            (char == "\n" and keep_newlines)
            or char == " "
            or (char.isprintable() and unicodedata.category(char) not in _INVISIBLE)
        ):
            parts.append(char)
        else:
            code = ord(char)
            if code < 0x100:
                parts.append(f"{_BACKSLASH}x{code:02x}")
            elif code < 0x10000:
                parts.append(f"{_BACKSLASH}u{code:04x}")
            else:
                parts.append(f"{_BACKSLASH}U{code:08x}")
    return "".join(parts)
