"""Time as a dependency.

Grants expire, lockouts end and lockdowns lift themselves. All of that logic takes a
:class:`Clock`, so tests move time forward explicitly instead of sleeping, and nothing in
PortLock reads the wall clock directly.

All datetimes are timezone-aware UTC. Naive datetimes are rejected rather than guessed at.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Protocol

__all__ = [
    "Clock",
    "FakeClock",
    "SystemClock",
    "format_duration",
    "parse_duration",
    "parse_utc_iso",
    "utc_iso",
]


class Clock(Protocol):
    """Source of wall-clock and monotonic time."""

    def now(self) -> datetime:
        """Current time as a timezone-aware UTC datetime."""
        ...

    def monotonic(self) -> float:
        """Seconds from an arbitrary origin; never goes backwards."""
        ...


class SystemClock:
    """The real clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class FakeClock:
    """A clock that only moves when told to. For tests and simulation."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = _require_aware(start) if start is not None else datetime(2026, 1, 1, tzinfo=UTC)
        self._monotonic = 1000.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, delta: timedelta | float) -> datetime:
        """Move time forward by a timedelta or a number of seconds. Returns the new time."""
        step = delta if isinstance(delta, timedelta) else timedelta(seconds=delta)
        if step < timedelta(0):
            raise ValueError("a clock cannot be advanced by a negative amount")
        self._now += step
        self._monotonic += step.total_seconds()
        return self._now

    def set(self, when: datetime) -> None:
        """Jump the wall clock to ``when``. Monotonic time is unaffected, as on a real system."""
        self._now = _require_aware(when)


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive datetime: PortLock only handles timezone-aware datetimes")
    return value.astimezone(UTC)


def utc_iso(value: datetime) -> str:
    """Format a datetime as ``YYYY-MM-DDTHH:MM:SS.ffffffZ``.

    The width is fixed, so comparing two of these strings compares the times.
    """
    return _require_aware(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_ISO_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z\Z")


def parse_utc_iso(text: str) -> datetime:
    """Parse the format written by :func:`utc_iso` (fractional seconds optional).

    Raises:
        ValueError: if the text is not a UTC timestamp in that format.
    """
    if not isinstance(text, str) or not _ISO_PATTERN.match(text):
        raise ValueError(f"not a UTC timestamp: {text!r}")
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ" if "." in text else "%Y-%m-%dT%H:%M:%SZ"
    return datetime.strptime(text, fmt).replace(tzinfo=UTC)


_DURATION_PATTERN = re.compile(r"(\d+)\s*([smhdw])\Z", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> timedelta:
    """Parse ``90s``, ``30m``, ``2h``, ``7d`` or ``1w`` into a positive timedelta.

    Raises:
        ValueError: if the text is not a positive duration in that form.
    """
    match = _DURATION_PATTERN.match(text.strip()) if isinstance(text, str) else None
    if match is None:
        raise ValueError(f"not a duration (expected forms like 30m, 2h, 7d): {text!r}")
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2).lower()]
    if seconds <= 0:
        raise ValueError("a duration must be greater than zero")
    return timedelta(seconds=seconds)


def format_duration(delta: timedelta) -> str:
    """Render a timedelta the way a person would say it: ``2h 5m``, ``45s``, ``3d``."""
    remaining = max(0, int(delta.total_seconds()))
    if remaining == 0:
        return "0s"
    parts: list[str] = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        count, remaining = divmod(remaining, size)
        if count:
            parts.append(f"{count}{unit}")
    return " ".join(parts[:2])
