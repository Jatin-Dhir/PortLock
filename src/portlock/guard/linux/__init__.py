"""PortLock Guard for Linux.

Detection only, and read-only: device enumeration from sysfs (:mod:`.sysfs`), mount
points from the kernel's mount table (:mod:`.mounts`), arrival and removal notifications
from the kernel's uevent socket with a polling fallback (:mod:`.netlink`), and the
:class:`LinuxBackend` that combines them behind the ``DeviceBackend`` interface.

Nothing in this package changes device or system state. How Linux can be made to refuse
a device, and the limits of each mechanism, is specified in
``docs/enforcement/linux.md``.

Importing this package is safe on any platform; the parts that need a Linux kernel
report their absence as :class:`~portlock.core.errors.BackendError` when used.
"""

from portlock.guard.linux.backend import ChangeTracker, LinuxBackend
from portlock.guard.linux.mounts import MountEntry, MountWatcher, attach_mounts, parse_mountinfo
from portlock.guard.linux.netlink import (
    PollingMonitor,
    UeventKind,
    UeventMonitor,
    classify_uevent,
    diff_devices,
    parse_uevent,
)
from portlock.guard.linux.sysfs import read_boot_id, read_usb_devices

__all__ = [
    "ChangeTracker",
    "LinuxBackend",
    "MountEntry",
    "MountWatcher",
    "PollingMonitor",
    "UeventKind",
    "UeventMonitor",
    "attach_mounts",
    "classify_uevent",
    "diff_devices",
    "parse_mountinfo",
    "parse_uevent",
    "read_boot_id",
    "read_usb_devices",
]
