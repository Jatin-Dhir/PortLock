"""Map a USB storage device to the volumes it exposes. Read-only.

Windows does not link a USB device to its drive letters directly. The documented route
has three steps, and this module follows it:

1. **Device-tree walk.** Below the USB device node sit the nodes its storage driver
   creates: ``USBSTOR\\Disk...`` for a bulk-only device, ``SCSI\\Disk...`` for a UASP
   one, one per logical unit. Each of those exposes the disk (or CD-ROM) device
   interface.
2. **Device number.** Opening that interface with no access rights and asking
   ``IOCTL_STORAGE_GET_DEVICE_NUMBER`` gives the disk's number: the *N* in
   ``\\\\.\\PhysicalDriveN``.
3. **Volume enumeration.** Every volume on the system is asked the same question. A
   volume whose device type and number match lives on that disk. Its drive letters,
   label, file system, serial number, size and read-only flag are then read.

Nothing here writes to a device, mounts or dismounts anything on purpose, or takes a
lock. Reading a volume's label and file system does make Windows mount the file system
if it has not done so yet, which reads a few sectors from the medium.

A phone in MTP mode exposes no volume at all (its storage is reached through the
Windows Portable Devices API, not a file system), so it maps to nothing here.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from portlock.core.errors import BackendError
from portlock.core.models import Volume
from portlock.guard.windows.api import (
    DEVPROP_TYPE_GUID,
    FILE_DEVICE_CD_ROM,
    FILE_DEVICE_DISK,
    FILE_READ_ONLY_VOLUME,
    GUID_DEVCLASS_CDROM,
    GUID_DEVCLASS_DISKDRIVE,
    GUID_DEVINTERFACE_CDROM,
    GUID_DEVINTERFACE_DISK,
    DEVPKEY_Device_ClassGuid,
    WinApi,
)

__all__ = [
    "DiskRef",
    "VolumeIndex",
    "find_disks",
    "format_volume_serial",
    "is_volume_guid_path",
    "pick_mount_point",
    "volumes_for_device",
]

_VOLUME_GUID_PATH = re.compile(
    r"\\\\\?\\Volume\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}\\\Z"
)
_DRIVE_ROOT = re.compile(r"[A-Za-z]:\\\Z")

# Limits on the device-tree walk. A storage device's subtree is a handful of nodes; the
# bounds only matter if the tree is not what it should be.
_MAX_DEPTH = 6
_MAX_NODES = 256
_MAX_SIBLINGS = 128

# Setup class of a storage node -> the device interface class it exposes.
_STORAGE_CLASSES = {
    GUID_DEVCLASS_DISKDRIVE.bytes_le: GUID_DEVINTERFACE_DISK,
    GUID_DEVCLASS_CDROM.bytes_le: GUID_DEVINTERFACE_CDROM,
}
_STORAGE_DEVICE_TYPES = frozenset({FILE_DEVICE_DISK, FILE_DEVICE_CD_ROM})


@dataclass(frozen=True, slots=True)
class DiskRef:
    """One disk or optical drive: its device node and its storage device number.

    ``device_type`` is ``FILE_DEVICE_DISK`` or ``FILE_DEVICE_CD_ROM``; the two number
    their devices independently, so both fields are needed to identify a drive.
    """

    instance_id: str
    device_type: int
    device_number: int


def is_volume_guid_path(text: str) -> bool:
    """True if ``text`` has the exact form ``\\\\?\\Volume{GUID}\\``."""
    return isinstance(text, str) and _VOLUME_GUID_PATH.match(text) is not None


def format_volume_serial(serial: int) -> str:
    """Format a volume serial number the way Windows shows it: ``1A2B-3C4D``."""
    return f"{(serial >> 16) & 0xFFFF:04X}-{serial & 0xFFFF:04X}"


def pick_mount_point(mount_points: list[str]) -> str | None:
    """Choose the mount point to report for a volume that may have several.

    A drive letter root (``E:\\``) is preferred over a mounted folder, and the choice is
    stable: lowest drive letter, otherwise the shortest and then alphabetically first
    path. ``None`` if the volume is not mounted anywhere.
    """
    candidates = [path for path in mount_points if isinstance(path, str) and path]
    if not candidates:
        return None
    drives = sorted(path.upper() for path in candidates if _DRIVE_ROOT.match(path))
    if drives:
        return drives[0]
    return min(candidates, key=lambda path: (len(path), path))


def _descendants(api: WinApi, devinst: int) -> Iterator[tuple[int, str]]:
    """Yield ``(devinst, instance id)`` for the nodes below a USB device.

    The walk does not descend into another USB *device*: for a hub that would be a
    different physical device altogether. It does pass through ``USB\\...&MI_xx`` nodes,
    which are the interfaces of the same composite device.
    """
    budget = _MAX_NODES
    stack: list[tuple[int, int]] = [(devinst, 0)]
    while stack and budget > 0:
        node, depth = stack.pop()
        child = api.get_child(node)
        siblings = 0
        while child is not None and siblings < _MAX_SIBLINGS and budget > 0:
            siblings += 1
            budget -= 1
            instance_id = api.get_device_id(child)
            if instance_id:
                upper = instance_id.upper()
                same_device = not upper.startswith("USB\\") or "&MI_" in upper
                if same_device:
                    yield child, instance_id
                    if depth + 1 < _MAX_DEPTH:
                        stack.append((child, depth + 1))
            child = api.get_sibling(child)


def find_disks(api: WinApi, devinst: int) -> tuple[DiskRef, ...]:
    """Find the disks and optical drives that belong to one USB device.

    Args:
        api: the Windows API seam.
        devinst: the USB device's node. For a hub or root hub pass nothing here: their
            children are other devices, and the caller is expected to skip them.

    Returns:
        One :class:`DiskRef` per logical unit that has a storage device number, in
        device-number order. Empty for a device with no storage.
    """
    disks: dict[tuple[int, int], DiskRef] = {}
    for node, instance_id in _descendants(api, devinst):
        class_guid = api.get_property(node, DEVPKEY_Device_ClassGuid)
        if class_guid is None or class_guid[0] != DEVPROP_TYPE_GUID:
            continue
        interface_class = _STORAGE_CLASSES.get(bytes(class_guid[1][:16]))
        if interface_class is None:
            continue
        for path in api.get_interface_paths(interface_class, instance_id):
            number = api.storage_device_number(path)
            if number is None or number.device_type not in _STORAGE_DEVICE_TYPES:
                continue
            key = (number.device_type, number.device_number)
            disks.setdefault(key, DiskRef(instance_id, number.device_type, number.device_number))
    return tuple(disks[key] for key in sorted(disks))


class VolumeIndex:
    """Which volumes live on which disk, computed once and reused.

    Building the index asks every volume on the system for its device number, so one
    index should serve a whole enumeration pass. It is built on first use; an
    enumeration that meets no storage device never builds it.

    Not thread-safe: use one index per enumeration pass.
    """

    def __init__(self, api: WinApi) -> None:
        self._api = api
        self._by_disk: dict[tuple[int, int], list[str]] | None = None

    def volume_names_on(self, device_type: int, device_number: int) -> tuple[str, ...]:
        """Return the volume GUID paths on one disk, sorted.

        Raises:
            BackendError: if the system's volumes cannot be enumerated.
        """
        if self._by_disk is None:
            self._by_disk = self._build()
        return tuple(self._by_disk.get((device_type, device_number), ()))

    def _build(self) -> dict[tuple[int, int], list[str]]:
        by_disk: dict[tuple[int, int], list[str]] = {}
        for name in self._api.volume_names():
            if not is_volume_guid_path(name):
                continue
            # The volume *device* is addressed without the trailing backslash; with it,
            # the path names the root directory of the mounted file system instead.
            device_path = name[:-1]
            number = self._api.storage_device_number(device_path)
            if number is not None and number.device_type in _STORAGE_DEVICE_TYPES:
                keys = [(number.device_type, number.device_number)]
            else:
                # A volume that spans disks does not have a single device number.
                keys = [
                    (FILE_DEVICE_DISK, disk) for disk in self._api.volume_disk_numbers(device_path)
                ]
            for key in keys:
                by_disk.setdefault(key, []).append(name)
        for names in by_disk.values():
            names.sort()
        return by_disk


def _describe_volume(api: WinApi, name: str) -> Volume:
    mount_point = pick_mount_point(api.volume_mount_points(name))
    info = api.volume_information(name)
    if info is None:
        # No medium, no recognised file system, or a locked (encrypted) volume.
        return Volume(device_node=name, mount_point=mount_point)
    return Volume(
        device_node=name,
        mount_point=mount_point,
        label=info.label or None,
        fs_type=info.filesystem or None,
        fs_uuid=format_volume_serial(info.serial_number),
        size_bytes=api.volume_total_bytes(name),
        read_only=bool(info.flags & FILE_READ_ONLY_VOLUME),
    )


def volumes_for_device(
    api: WinApi, devinst: int, *, index: VolumeIndex | None = None
) -> tuple[Volume, ...]:
    """Return the volumes exposed by one USB mass-storage device.

    Args:
        api: the Windows API seam.
        devinst: the USB device's node (not a hub).
        index: a :class:`VolumeIndex` to reuse across devices in one enumeration pass.

    Returns:
        One :class:`~portlock.core.models.Volume` per volume, ordered by volume path.
        ``device_node`` is the volume GUID path, ``mount_point`` a drive letter root or
        mounted folder (or ``None``), ``fs_uuid`` the volume serial number as
        ``XXXX-XXXX``. Label, file system, serial, size and ``read_only`` are ``None``
        when the volume cannot be read (no medium, raw, or locked).

    Raises:
        BackendError: if the system's volumes cannot be enumerated.
    """
    disks = find_disks(api, devinst)
    if not disks:
        return ()
    volume_index = index if index is not None else VolumeIndex(api)
    names: list[str] = []
    for disk in disks:
        for name in volume_index.volume_names_on(disk.device_type, disk.device_number):
            if name not in names:
                names.append(name)
    volumes: list[Volume] = []
    for name in sorted(names):
        try:
            volumes.append(_describe_volume(api, name))
        except BackendError:
            # The volume went away while it was being read; report what is known.
            volumes.append(Volume(device_node=name))
    return tuple(volumes)
