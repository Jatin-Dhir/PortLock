"""PortLock Guard for Windows: device enumeration and arrival/removal monitoring.

This package observes; it does not enforce. Everything in it is read-only and needs no
privilege. The enforcement mechanisms Windows offers, with their exact names, limits and
references, are specified in ``docs/enforcement/windows.md``.

Importing this package is safe on any platform: no Windows library is loaded until a
:class:`~portlock.guard.windows.api.WinApi` is constructed, and that only happens on
Windows.
"""

from portlock.guard.windows.api import WinApi
from portlock.guard.windows.backend import WindowsBackend
from portlock.guard.windows.enumerate import enumerate_usb_devices
from portlock.guard.windows.monitor import DeviceMonitor

__all__ = ["DeviceMonitor", "WinApi", "WindowsBackend", "enumerate_usb_devices"]
