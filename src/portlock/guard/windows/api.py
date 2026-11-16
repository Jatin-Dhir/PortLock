"""Windows API bindings for the device backend: ``ctypes`` only, read-only calls only.

This module is the single place where PortLock's Windows *detection* code touches the
operating system. It binds exactly the functions needed to list devices, read their
properties, map disks to volumes, receive arrival and removal notifications and learn
that the system resumed from sleep. Nothing
bound here changes device or system state: there is no disable, eject, registry or
policy call in this file, and enforcement must not be added to it.

Three layers, all in this file so that the dependency order of the package stays
``api -> volumes -> enumerate -> monitor -> backend``:

* constants, GUIDs and structure layouts, usable on any platform (structure sizes are
  asserted by the unit tests on Windows and on Linux);
* pure decoders for the byte buffers the API fills in (UTF-16 strings, ``MULTI_SZ``
  lists, IOCTL results, notification payloads);
* :class:`WinApi`, a small class whose methods wrap the raw calls and return plain
  Python values. Everything above this module takes a :class:`WinApi`, so the tests
  substitute a fake and the enumeration logic runs unmodified on Linux.

Importing this module never loads a Windows DLL. The DLLs are loaded when a
:class:`WinApi` is constructed, and only on Windows.

Exact names, values and documentation references: ``docs/enforcement/windows.md``.
"""

from __future__ import annotations

import contextlib
import ctypes
import struct
import sys
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Final

from portlock.core.errors import BackendError

__all__ = [
    "CM_DEVCAP_REMOVABLE",
    "CM_DEVCAP_SURPRISEREMOVALOK",
    "CM_DEVCAP_UNIQUEID",
    "CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED",
    "CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED",
    "CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED",
    "CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL",
    "CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL",
    "CM_NOTIFY_FILTER",
    "CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE",
    "CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE",
    "CM_PROB_DISABLED",
    "CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL",
    "CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL",
    "CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL",
    "DEVICE_NOTIFY_CALLBACK",
    "DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS",
    "DEVINST",
    "DEVPROPKEY",
    "DEVPROP_TYPE_BOOLEAN",
    "DEVPROP_TYPE_FILETIME",
    "DEVPROP_TYPE_GUID",
    "DEVPROP_TYPE_INT32",
    "DEVPROP_TYPE_STRING",
    "DEVPROP_TYPE_STRING_LIST",
    "DEVPROP_TYPE_UINT32",
    "DN_DISABLEABLE",
    "DN_DRIVER_LOADED",
    "DN_HAS_PROBLEM",
    "DN_REMOVABLE",
    "DN_STARTED",
    "FILE_DEVICE_CD_ROM",
    "FILE_DEVICE_DISK",
    "FILE_READ_ONLY_VOLUME",
    "GUID",
    "GUID_DEVCLASS_CDROM",
    "GUID_DEVCLASS_DISKDRIVE",
    "GUID_DEVINTERFACE_CDROM",
    "GUID_DEVINTERFACE_DISK",
    "GUID_DEVINTERFACE_USB_DEVICE",
    "GUID_DEVINTERFACE_VOLUME",
    "HDEVINFO",
    "IOCTL_STORAGE_GET_DEVICE_NUMBER",
    "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    "MAX_DEVICE_ID_LEN",
    "PBT_APMRESUMEAUTOMATIC",
    "PBT_APMRESUMESUSPEND",
    "PBT_APMSUSPEND",
    "SP_DEVICE_INTERFACE_DATA",
    "SP_DEVICE_INTERFACE_DETAIL_DATA_W",
    "SP_DEVINFO_DATA",
    "DEVPKEY_Device_Address",
    "DEVPKEY_Device_BusReportedDeviceDesc",
    "DEVPKEY_Device_Capabilities",
    "DEVPKEY_Device_ClassGuid",
    "DEVPKEY_Device_CompatibleIds",
    "DEVPKEY_Device_ContainerId",
    "DEVPKEY_Device_DeviceDesc",
    "DEVPKEY_Device_HardwareIds",
    "DEVPKEY_Device_LastArrivalDate",
    "DEVPKEY_Device_LocationPaths",
    "DEVPKEY_Device_Manufacturer",
    "DEVPKEY_Device_RemovalPolicy",
    "DEVPKEY_Device_Service",
    "DevPropKey",
    "NotificationHandle",
    "NotificationSink",
    "NotifyEvent",
    "PowerSink",
    "PropertyValue",
    "StorageDeviceNumber",
    "VolumeInformation",
    "WinApi",
    "config_ret_name",
    "decode_disk_extents",
    "decode_multi_sz",
    "decode_notify_event",
    "decode_storage_device_number",
    "decode_utf16",
]

# --------------------------------------------------------------------------------------
# Scalar types
#
# Windows DWORD/ULONG are 32 bits. ``ctypes.c_ulong`` is 32 bits on Windows but 64 on
# LP64 Unix, so the fixed-width type is used wherever c_ulong is not already 32 bits.
# That keeps every structure below at its Windows layout on any platform, which is what
# lets the layout tests run on Linux.
# --------------------------------------------------------------------------------------

DWORD: Any = ctypes.c_ulong if ctypes.sizeof(ctypes.c_ulong) == 4 else ctypes.c_uint32
ULONG: Any = DWORD
#: A device instance handle. A 32-bit value, *not* a pointer.
DEVINST: Any = DWORD
#: ``CONFIGRET``: the return type of every ``CM_`` function.
CONFIGRET: Any = DWORD
DEVPROPTYPE: Any = DWORD
BOOL: Any = ctypes.c_int
#: Kernel handles and ``HDEVINFO`` are pointer-sized. Declaring them as ``c_void_p`` is
#: what keeps them from being truncated to 32 bits on 64-bit Windows.
HANDLE: Any = ctypes.c_void_p
HDEVINFO: Any = ctypes.c_void_p
HCMNOTIFICATION: Any = ctypes.c_void_p
HPOWERNOTIFY: Any = ctypes.c_void_p
WCHAR: Any = ctypes.c_uint16

_POINTER_SIZE: Final = ctypes.sizeof(ctypes.c_void_p)
# setupapi.h wraps its structures in ``#include <pshpack1.h>`` on 32-bit Windows and in
# the default (8-byte) packing on 64-bit Windows.
_SETUPAPI_BYTE_PACKED: Final = _POINTER_SIZE == 4

#: Maximum length of a device instance id in characters, including the terminator.
MAX_DEVICE_ID_LEN: Final = 200
_MAX_PATH: Final = 260

# --------------------------------------------------------------------------------------
# Constants (cfgmgr32.h, cfg.h, setupapi.h, winioctl.h, winbase.h, winerror.h)
# --------------------------------------------------------------------------------------

CR_SUCCESS: Final = 0x00
CR_INVALID_DEVNODE: Final = 0x05
CR_NO_SUCH_DEVNODE: Final = 0x0D
CR_FAILURE: Final = 0x13
CR_BUFFER_SMALL: Final = 0x1A
CR_NO_SUCH_VALUE: Final = 0x25
CR_ACCESS_DENIED: Final = 0x33
CR_CALL_NOT_IMPLEMENTED: Final = 0x34
CR_INVALID_PROPERTY: Final = 0x35
CR_NO_SUCH_DEVICE_INTERFACE: Final = 0x37

_CONFIG_RET_NAMES: Final = {
    0x00: "CR_SUCCESS",
    0x02: "CR_OUT_OF_MEMORY",
    0x03: "CR_INVALID_POINTER",
    0x04: "CR_INVALID_FLAG",
    0x05: "CR_INVALID_DEVNODE",
    0x0D: "CR_NO_SUCH_DEVNODE",
    0x13: "CR_FAILURE",
    0x1A: "CR_BUFFER_SMALL",
    0x1E: "CR_INVALID_DEVICE_ID",
    0x1F: "CR_INVALID_DATA",
    0x25: "CR_NO_SUCH_VALUE",
    0x33: "CR_ACCESS_DENIED",
    0x34: "CR_CALL_NOT_IMPLEMENTED",
    0x35: "CR_INVALID_PROPERTY",
    0x37: "CR_NO_SUCH_DEVICE_INTERFACE",
    0x3B: "CR_INVALID_STRUCTURE_SIZE",
}

CM_LOCATE_DEVNODE_NORMAL: Final = 0x0

# Device node status flags (cfg.h).
DN_DRIVER_LOADED: Final = 0x00000002
DN_STARTED: Final = 0x00000008
DN_HAS_PROBLEM: Final = 0x00000400
DN_DISABLEABLE: Final = 0x00002000
DN_REMOVABLE: Final = 0x00004000

#: Problem code 22: the device is disabled.
CM_PROB_DISABLED: Final = 0x16

# Capability flags (the value of DEVPKEY_Device_Capabilities).
CM_DEVCAP_REMOVABLE: Final = 0x00000004
CM_DEVCAP_UNIQUEID: Final = 0x00000010
CM_DEVCAP_SURPRISEREMOVALOK: Final = 0x00000080

CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL: Final = 1
CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL: Final = 2
CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL: Final = 3

# CM_NOTIFY_FILTER_TYPE / CM_NOTIFY_FILTER.Flags / CM_NOTIFY_ACTION.
CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE: Final = 0
CM_NOTIFY_FILTER_TYPE_DEVICEHANDLE: Final = 1
CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE: Final = 2
CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES: Final = 0x00000001
CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES: Final = 0x00000002
CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL: Final = 0
CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL: Final = 1
CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED: Final = 7
CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED: Final = 8
CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED: Final = 9

# PowerRegisterSuspendResumeNotification (powerbase.h, winuser.h).
DEVICE_NOTIFY_CALLBACK: Final = 0x00000002
PBT_APMSUSPEND: Final = 0x0004
PBT_APMRESUMESUSPEND: Final = 0x0007
PBT_APMRESUMEAUTOMATIC: Final = 0x0012

# SetupDiGetClassDevs flags.
DIGCF_PRESENT: Final = 0x00000002
DIGCF_ALLCLASSES: Final = 0x00000004
DIGCF_DEVICEINTERFACE: Final = 0x00000010

# Property data types (devpropdef.h).
DEVPROP_TYPE_INT32: Final = 0x00000006
DEVPROP_TYPE_UINT32: Final = 0x00000007
DEVPROP_TYPE_GUID: Final = 0x0000000D
DEVPROP_TYPE_FILETIME: Final = 0x00000010
DEVPROP_TYPE_BOOLEAN: Final = 0x00000011
DEVPROP_TYPE_STRING: Final = 0x00000012
DEVPROP_TYPE_STRING_LIST: Final = 0x00002012

# Win32 error codes.
ERROR_SUCCESS: Final = 0
ERROR_NO_MORE_FILES: Final = 18
ERROR_INSUFFICIENT_BUFFER: Final = 122
ERROR_MORE_DATA: Final = 234
ERROR_NO_MORE_ITEMS: Final = 259

# CreateFile / DeviceIoControl.
FILE_SHARE_READ: Final = 0x00000001
FILE_SHARE_WRITE: Final = 0x00000002
FILE_SHARE_DELETE: Final = 0x00000004
OPEN_EXISTING: Final = 3
FILE_DEVICE_CD_ROM: Final = 0x00000002
FILE_DEVICE_DISK: Final = 0x00000007
#: ``CTL_CODE(IOCTL_STORAGE_BASE, 0x0420, METHOD_BUFFERED, FILE_ANY_ACCESS)``
IOCTL_STORAGE_GET_DEVICE_NUMBER: Final = 0x002D1080
#: ``CTL_CODE(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)``
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: Final = 0x00560000

#: ``GetVolumeInformation`` file-system flag: the volume is read-only.
FILE_READ_ONLY_VOLUME: Final = 0x00080000
SEM_FAILCRITICALERRORS: Final = 0x0001
# Restrict the DLL search to System32: a privileged agent must not load a planted DLL.
_LOAD_LIBRARY_SEARCH_SYSTEM32: Final = 0x00000800

# Hard limits on what is accepted from the operating system. They exist so that a
# confused or hostile answer cannot make the agent loop or allocate without bound.
_MAX_ENUMERATED_DEVICES: Final = 65536
_MAX_INTERFACES_PER_DEVICE: Final = 64
_MAX_PROPERTY_BYTES: Final = 64 * 1024
_MAX_VOLUMES: Final = 1024
_MAX_NOTIFY_BYTES: Final = 4096
_MAX_DISK_EXTENTS: Final = 128

# --------------------------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------------------------


class GUID(ctypes.Structure):
    """The 16-byte Windows ``GUID`` layout."""

    _fields_ = (
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    )

    @classmethod
    def from_uuid(cls, value: uuid.UUID) -> GUID:
        """Build the structure from a :class:`uuid.UUID`."""
        return cls.from_buffer_copy(value.bytes_le)

    def to_uuid(self) -> uuid.UUID:
        """Return the value as a :class:`uuid.UUID`."""
        return uuid.UUID(bytes_le=bytes(self))


class DEVPROPKEY(ctypes.Structure):
    """``DEVPROPKEY``: a property category GUID plus a property id."""

    _fields_ = (("fmtid", GUID), ("pid", ctypes.c_uint32))


class SP_DEVINFO_DATA(ctypes.Structure):
    """``SP_DEVINFO_DATA``. ``cbSize`` must be set to the structure size before use."""

    if _SETUPAPI_BYTE_PACKED:
        _pack_ = 1
    _fields_ = (
        ("cbSize", ctypes.c_uint32),
        ("ClassGuid", GUID),
        ("DevInst", ctypes.c_uint32),
        ("Reserved", ctypes.c_size_t),
    )


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    """``SP_DEVICE_INTERFACE_DATA``. ``cbSize`` must be set before use."""

    if _SETUPAPI_BYTE_PACKED:
        _pack_ = 1
    _fields_ = (
        ("cbSize", ctypes.c_uint32),
        ("InterfaceClassGuid", GUID),
        ("Flags", ctypes.c_uint32),
        ("Reserved", ctypes.c_size_t),
    )


class SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    """The fixed part of ``SP_DEVICE_INTERFACE_DETAIL_DATA_W``.

    ``cbSize`` is the size of this fixed part (8 on 64-bit Windows, 6 on 32-bit), never
    the size of the buffer that also holds the variable-length path.
    """

    if _SETUPAPI_BYTE_PACKED:
        _pack_ = 1
    _fields_ = (("cbSize", ctypes.c_uint32), ("DevicePath", WCHAR * 1))


class _CM_NOTIFY_FILTER_U(ctypes.Union):
    _fields_ = (
        ("ClassGuid", GUID),
        ("hTarget", ctypes.c_void_p),
        ("InstanceId", WCHAR * MAX_DEVICE_ID_LEN),
    )


class CM_NOTIFY_FILTER(ctypes.Structure):
    """``CM_NOTIFY_FILTER``, the registration filter for ``CM_Register_Notification``."""

    _fields_ = (
        ("cbSize", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("FilterType", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
        ("u", _CM_NOTIFY_FILTER_U),
    )


# ``CM_NOTIFY_EVENT_DATA`` is variable-length and only ever read, so it is decoded from
# bytes (see :func:`decode_notify_event`) instead of being declared as a structure.
_NOTIFY_HEADER: Final = struct.Struct("<II")
_NOTIFY_INSTANCE_OFFSET: Final = _NOTIFY_HEADER.size
_NOTIFY_INTERFACE_LINK_OFFSET: Final = _NOTIFY_HEADER.size + ctypes.sizeof(GUID)

_STORAGE_DEVICE_NUMBER: Final = struct.Struct("<III")
# VOLUME_DISK_EXTENTS: DWORD count, padding to 8, then DISK_EXTENT records of
# { DWORD DiskNumber; padding; LARGE_INTEGER StartingOffset; LARGE_INTEGER ExtentLength }.
_DISK_EXTENTS_HEADER: Final = struct.Struct("<I4x")
_DISK_EXTENT: Final = struct.Struct("<I4xqq")

# --------------------------------------------------------------------------------------
# GUIDs and property keys
# --------------------------------------------------------------------------------------

#: Device interface class registered by the hub driver for every device on a hub port.
GUID_DEVINTERFACE_USB_DEVICE: Final = uuid.UUID("a5dcbf10-6530-11d2-901f-00c04fb951ed")
GUID_DEVINTERFACE_DISK: Final = uuid.UUID("53f56307-b6bf-11d0-94f2-00a0c91efb8b")
GUID_DEVINTERFACE_CDROM: Final = uuid.UUID("53f56308-b6bf-11d0-94f2-00a0c91efb8b")
GUID_DEVINTERFACE_VOLUME: Final = uuid.UUID("53f5630d-b6bf-11d0-94f2-00a0c91efb8b")
#: Device *setup* classes of the nodes that represent disks and optical drives.
GUID_DEVCLASS_DISKDRIVE: Final = uuid.UUID("4d36e967-e325-11ce-bfc1-08002be10318")
GUID_DEVCLASS_CDROM: Final = uuid.UUID("4d36e965-e325-11ce-bfc1-08002be10318")


@dataclass(frozen=True, slots=True)
class DevPropKey:
    """A device property key (``DEVPROPKEY``) with the name it has in ``devpkey.h``."""

    fmtid: uuid.UUID
    pid: int
    name: str

    def to_struct(self) -> DEVPROPKEY:
        """The ``DEVPROPKEY`` structure to pass to the API."""
        return DEVPROPKEY(GUID.from_uuid(self.fmtid), self.pid)


_FMTID_DEVICE: Final = uuid.UUID("a45c254e-df1c-4efd-8020-67d146a850e0")

DEVPKEY_Device_DeviceDesc: Final = DevPropKey(_FMTID_DEVICE, 2, "DEVPKEY_Device_DeviceDesc")
DEVPKEY_Device_HardwareIds: Final = DevPropKey(_FMTID_DEVICE, 3, "DEVPKEY_Device_HardwareIds")
DEVPKEY_Device_CompatibleIds: Final = DevPropKey(_FMTID_DEVICE, 4, "DEVPKEY_Device_CompatibleIds")
DEVPKEY_Device_Service: Final = DevPropKey(_FMTID_DEVICE, 6, "DEVPKEY_Device_Service")
DEVPKEY_Device_ClassGuid: Final = DevPropKey(_FMTID_DEVICE, 10, "DEVPKEY_Device_ClassGuid")
DEVPKEY_Device_Manufacturer: Final = DevPropKey(_FMTID_DEVICE, 13, "DEVPKEY_Device_Manufacturer")
DEVPKEY_Device_Capabilities: Final = DevPropKey(_FMTID_DEVICE, 17, "DEVPKEY_Device_Capabilities")
DEVPKEY_Device_Address: Final = DevPropKey(_FMTID_DEVICE, 30, "DEVPKEY_Device_Address")
DEVPKEY_Device_RemovalPolicy: Final = DevPropKey(_FMTID_DEVICE, 33, "DEVPKEY_Device_RemovalPolicy")
DEVPKEY_Device_LocationPaths: Final = DevPropKey(_FMTID_DEVICE, 37, "DEVPKEY_Device_LocationPaths")
DEVPKEY_Device_ContainerId: Final = DevPropKey(
    uuid.UUID("8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c"), 2, "DEVPKEY_Device_ContainerId"
)
DEVPKEY_Device_BusReportedDeviceDesc: Final = DevPropKey(
    uuid.UUID("540b947e-8b40-45bc-a8a2-6a0b894cbda2"), 4, "DEVPKEY_Device_BusReportedDeviceDesc"
)
DEVPKEY_Device_LastArrivalDate: Final = DevPropKey(
    uuid.UUID("83da6326-97a6-4088-9453-a1923f573b29"), 102, "DEVPKEY_Device_LastArrivalDate"
)

# --------------------------------------------------------------------------------------
# Values returned to callers
# --------------------------------------------------------------------------------------

#: A raw device property: its ``DEVPROP_TYPE_`` code and its bytes.
PropertyValue = tuple[int, bytes]
#: Receives ``(action, payload)`` for each notification, on an operating-system thread.
#: ``payload`` is the raw ``CM_NOTIFY_EVENT_DATA``; decode it with
#: :func:`decode_notify_event` on another thread.
NotificationSink = Callable[[int, bytes], None]
#: Receives the ``PBT_`` code of each power event, on an operating-system thread.
PowerSink = Callable[[int], None]


@dataclass(frozen=True, slots=True)
class StorageDeviceNumber:
    """``STORAGE_DEVICE_NUMBER``: which disk (and partition) a handle refers to.

    ``partition_number`` is ``None`` for a device that cannot be partitioned. The numbers
    hold until the device is removed or the system restarts, not beyond.
    """

    device_type: int
    device_number: int
    partition_number: int | None


@dataclass(frozen=True, slots=True)
class VolumeInformation:
    """What ``GetVolumeInformationW`` reports about a mounted volume."""

    label: str
    serial_number: int
    flags: int
    filesystem: str


@dataclass(frozen=True, slots=True)
class NotifyEvent:
    """A decoded ``CM_NOTIFY_EVENT_DATA``.

    ``name`` is a device interface symbolic link for interface events and a device
    instance id for instance events.
    """

    filter_type: int
    name: str
    class_guid: uuid.UUID | None = None


class NotificationHandle:
    """An active ``CM_Register_Notification`` registration.

    Holds the native callback object as well as the handle: the callback must stay
    referenced until ``CM_Unregister_Notification`` has returned, or the operating
    system would call into freed memory.
    """

    __slots__ = ("_callback", "description", "handle")

    def __init__(self, handle: int, callback: object, description: str) -> None:
        self.handle = handle
        self.description = description
        self._callback = callback

    def __repr__(self) -> str:
        return f"NotificationHandle({self.description})"


# --------------------------------------------------------------------------------------
# Pure decoders
# --------------------------------------------------------------------------------------


def decode_utf16(raw: bytes) -> str:
    """Decode a NUL-terminated UTF-16LE string from a buffer.

    Everything from the first NUL character on is ignored, and so is an odd trailing
    byte. Unpaired surrogates are replaced, never raised: the buffer comes from the
    operating system and, indirectly, from the device.
    """
    usable = len(raw) - (len(raw) % 2)
    text = raw[:usable].decode("utf-16-le", errors="replace")
    end = text.find("\x00")
    return text if end < 0 else text[:end]


def decode_multi_sz(raw: bytes) -> tuple[str, ...]:
    """Decode a ``REG_MULTI_SZ`` / ``DEVPROP_TYPE_STRING_LIST`` buffer.

    The format is a sequence of NUL-terminated UTF-16LE strings ended by an empty
    string. Decoding stops at the first empty string; a final string that is missing its
    terminator is kept. Malformed input yields fewer strings, never an exception.
    """
    usable = len(raw) - (len(raw) % 2)
    text = raw[:usable].decode("utf-16-le", errors="replace")
    strings: list[str] = []
    for part in text.split("\x00"):
        if not part:
            break
        strings.append(part)
    return tuple(strings)


def decode_storage_device_number(raw: bytes) -> StorageDeviceNumber | None:
    """Decode the output of ``IOCTL_STORAGE_GET_DEVICE_NUMBER``; ``None`` if truncated."""
    if len(raw) < _STORAGE_DEVICE_NUMBER.size:
        return None
    device_type, device_number, partition = _STORAGE_DEVICE_NUMBER.unpack_from(raw)
    # The API documents -1 for "cannot be partitioned"; as a DWORD that is 0xFFFFFFFF.
    return StorageDeviceNumber(
        device_type, device_number, None if partition == 0xFFFFFFFF else partition
    )


def decode_disk_extents(raw: bytes) -> tuple[int, ...]:
    """Decode ``VOLUME_DISK_EXTENTS`` into the distinct disk numbers, in order.

    Extents that the buffer does not fully contain are ignored, so a short buffer gives
    a short answer rather than garbage.
    """
    if len(raw) < _DISK_EXTENTS_HEADER.size:
        return ()
    (count,) = _DISK_EXTENTS_HEADER.unpack_from(raw)
    available = (len(raw) - _DISK_EXTENTS_HEADER.size) // _DISK_EXTENT.size
    disks: list[int] = []
    for index in range(min(count, available, _MAX_DISK_EXTENTS)):
        offset = _DISK_EXTENTS_HEADER.size + index * _DISK_EXTENT.size
        disk_number, _start, _length = _DISK_EXTENT.unpack_from(raw, offset)
        if disk_number not in disks:
            disks.append(disk_number)
    return tuple(disks)


def decode_notify_event(raw: bytes) -> NotifyEvent | None:
    """Decode a ``CM_NOTIFY_EVENT_DATA`` payload.

    Returns ``None`` for a payload that is too short or of a filter type PortLock does
    not register for. The caller treats ``None`` as "something changed, look again".
    """
    if len(raw) < _NOTIFY_HEADER.size:
        return None
    filter_type, _reserved = _NOTIFY_HEADER.unpack_from(raw)
    if filter_type == CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
        return NotifyEvent(filter_type, decode_utf16(raw[_NOTIFY_INSTANCE_OFFSET:]))
    if filter_type == CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE:
        if len(raw) < _NOTIFY_INTERFACE_LINK_OFFSET:
            return None
        class_guid = uuid.UUID(bytes_le=raw[_NOTIFY_HEADER.size : _NOTIFY_INTERFACE_LINK_OFFSET])
        return NotifyEvent(
            filter_type, decode_utf16(raw[_NOTIFY_INTERFACE_LINK_OFFSET:]), class_guid
        )
    return None


def config_ret_name(code: int) -> str:
    """A readable name for a ``CONFIGRET`` value, for error messages."""
    return _CONFIG_RET_NAMES.get(code, f"CONFIGRET {code:#04x}")


# --------------------------------------------------------------------------------------
# Library loading and prototypes
# --------------------------------------------------------------------------------------

_CALLBACK_FACTORY: Any = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
#: ``DWORD CALLBACK (HCMNOTIFICATION, PVOID, CM_NOTIFY_ACTION, PCM_NOTIFY_EVENT_DATA, DWORD)``
PCM_NOTIFY_CALLBACK: Any = _CALLBACK_FACTORY(
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_uint32,
)

#: ``ULONG CALLBACK DeviceNotifyCallbackRoutine(PVOID Context, ULONG Type, PVOID Setting)``
PDEVICE_NOTIFY_CALLBACK_ROUTINE: Any = _CALLBACK_FACTORY(
    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p
)


class DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS(ctypes.Structure):
    """``DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS``: the callback and its context pointer."""

    _fields_ = (("Callback", PDEVICE_NOTIFY_CALLBACK_ROUTINE), ("Context", ctypes.c_void_p))


_PDWORD: Any = ctypes.POINTER(DWORD)
_PGUID: Any = ctypes.POINTER(GUID)
_PDEVINFO: Any = ctypes.POINTER(SP_DEVINFO_DATA)
_PINTERFACE: Any = ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)
_LPCWSTR: Any = ctypes.c_wchar_p
_BUFFER: Any = ctypes.c_void_p

# name -> (argument types, return type). Every function this module calls is listed
# here, so a wrong or missing prototype is a one-line review.
_CFGMGR32_PROTOTYPES: Final[dict[str, tuple[tuple[Any, ...], Any]]] = {
    "CM_Locate_DevNodeW": ((_PDWORD, _LPCWSTR, ULONG), CONFIGRET),
    "CM_Get_Device_IDW": ((DEVINST, _BUFFER, ULONG, ULONG), CONFIGRET),
    "CM_Get_Parent": ((_PDWORD, DEVINST, ULONG), CONFIGRET),
    "CM_Get_Child": ((_PDWORD, DEVINST, ULONG), CONFIGRET),
    "CM_Get_Sibling": ((_PDWORD, DEVINST, ULONG), CONFIGRET),
    "CM_Get_DevNode_Status": ((_PDWORD, _PDWORD, DEVINST, ULONG), CONFIGRET),
    "CM_Get_DevNode_PropertyW": (
        (DEVINST, ctypes.POINTER(DEVPROPKEY), _PDWORD, _BUFFER, _PDWORD, ULONG),
        CONFIGRET,
    ),
}
# Windows 8 and later. Their absence selects the polling fallback.
_CFGMGR32_NOTIFY_PROTOTYPES: Final[dict[str, tuple[tuple[Any, ...], Any]]] = {
    "CM_Register_Notification": (
        (
            ctypes.POINTER(CM_NOTIFY_FILTER),
            ctypes.c_void_p,
            PCM_NOTIFY_CALLBACK,
            ctypes.POINTER(HCMNOTIFICATION),
        ),
        CONFIGRET,
    ),
    "CM_Unregister_Notification": ((HCMNOTIFICATION,), CONFIGRET),
}
_SETUPAPI_PROTOTYPES: Final[dict[str, tuple[tuple[Any, ...], Any]]] = {
    "SetupDiGetClassDevsW": ((_PGUID, _LPCWSTR, ctypes.c_void_p, DWORD), HDEVINFO),
    "SetupDiEnumDeviceInfo": ((HDEVINFO, DWORD, _PDEVINFO), BOOL),
    "SetupDiGetDeviceInstanceIdW": ((HDEVINFO, _PDEVINFO, _BUFFER, DWORD, _PDWORD), BOOL),
    "SetupDiEnumDeviceInterfaces": ((HDEVINFO, _PDEVINFO, _PGUID, DWORD, _PINTERFACE), BOOL),
    "SetupDiGetDeviceInterfaceDetailW": (
        (HDEVINFO, _PINTERFACE, _BUFFER, DWORD, _PDWORD, _PDEVINFO),
        BOOL,
    ),
    "SetupDiDestroyDeviceInfoList": ((HDEVINFO,), BOOL),
}
_KERNEL32_PROTOTYPES: Final[dict[str, tuple[tuple[Any, ...], Any]]] = {
    "CreateFileW": (
        (_LPCWSTR, DWORD, DWORD, ctypes.c_void_p, DWORD, DWORD, HANDLE),
        HANDLE,
    ),
    "DeviceIoControl": (
        (HANDLE, DWORD, _BUFFER, DWORD, _BUFFER, DWORD, _PDWORD, ctypes.c_void_p),
        BOOL,
    ),
    "CloseHandle": ((HANDLE,), BOOL),
    "FindFirstVolumeW": ((_BUFFER, DWORD), HANDLE),
    "FindNextVolumeW": ((HANDLE, _BUFFER, DWORD), BOOL),
    "FindVolumeClose": ((HANDLE,), BOOL),
    "GetVolumePathNamesForVolumeNameW": ((_LPCWSTR, _BUFFER, DWORD, _PDWORD), BOOL),
    "GetVolumeInformationW": (
        (_LPCWSTR, _BUFFER, DWORD, _PDWORD, _PDWORD, _PDWORD, _BUFFER, DWORD),
        BOOL,
    ),
    "GetDiskFreeSpaceExW": (
        (
            _LPCWSTR,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
        ),
        BOOL,
    ),
    "SetThreadErrorMode": ((DWORD, _PDWORD), BOOL),
}
# powrprof.dll, Windows 8 and later. Their absence leaves resume detection to the
# monitor's timing check.
_POWRPROF_PROTOTYPES: Final[dict[str, tuple[tuple[Any, ...], Any]]] = {
    "PowerRegisterSuspendResumeNotification": (
        (DWORD, ctypes.c_void_p, ctypes.POINTER(HPOWERNOTIFY)),
        DWORD,
    ),
    "PowerUnregisterSuspendResumeNotification": ((HPOWERNOTIFY,), DWORD),
}

_INVALID_HANDLE_VALUE: Final = ctypes.c_void_p(-1).value


def _bind(library: Any, prototypes: dict[str, tuple[tuple[Any, ...], Any]]) -> None:
    for name, (argtypes, restype) in prototypes.items():
        function = getattr(library, name)
        function.argtypes = argtypes
        function.restype = restype


@dataclass(frozen=True, slots=True)
class _Libraries:
    cfgmgr32: Any
    setupapi: Any
    kernel32: Any
    notifications: bool
    #: ``None`` if powrprof.dll or its suspend/resume registration is unavailable.
    powrprof: Any | None


def _load_powrprof(loader: Any) -> Any | None:
    try:
        powrprof = loader(
            "powrprof.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        _bind(powrprof, _POWRPROF_PROTOTYPES)
    except (OSError, AttributeError):
        return None
    return powrprof


def _load_libraries() -> _Libraries | None:
    """Load and prototype the DLLs. ``None`` anywhere but on Windows."""
    loader = getattr(ctypes, "WinDLL", None)
    if sys.platform != "win32" or loader is None:
        return None
    try:
        # Private instances (not ctypes.windll.*) so these prototypes cannot collide with
        # another module's. use_last_error makes GetLastError reliable from Python.
        cfgmgr32 = loader(
            "cfgmgr32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        setupapi = loader(
            "setupapi.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        kernel32 = loader(
            "kernel32.dll", use_last_error=True, winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        _bind(cfgmgr32, _CFGMGR32_PROTOTYPES)
        _bind(setupapi, _SETUPAPI_PROTOTYPES)
        _bind(kernel32, _KERNEL32_PROTOTYPES)
    except (OSError, AttributeError) as exc:
        raise BackendError(f"cannot load the Windows device API: {exc}") from exc
    try:
        _bind(cfgmgr32, _CFGMGR32_NOTIFY_PROTOTYPES)
        notifications = True
    except AttributeError:
        notifications = False
    return _Libraries(cfgmgr32, setupapi, kernel32, notifications, _load_powrprof(loader))


def _is_invalid_handle(handle: int | None) -> bool:
    return handle is None or handle == _INVALID_HANDLE_VALUE


def _last_error() -> int:
    return int(ctypes.get_last_error())  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------
# The seam
# --------------------------------------------------------------------------------------


class WinApi:
    """Read-only access to the Windows device tree, volumes and device notifications.

    Each method wraps one operating-system query and returns plain Python values, so a
    test can substitute a subclass that answers from a synthetic device tree. The class
    keeps no state besides the loaded libraries and is safe to call from any thread.

    Conventions shared by the methods:

    * "not there" (an unknown device, an absent property, a volume without media) is
      reported by returning ``None`` or an empty list;
    * a failure of the query itself raises :class:`~portlock.core.errors.BackendError`;
    * on a platform other than Windows every query raises ``BackendError`` and
      :attr:`available` is False.
    """

    def __init__(self) -> None:
        self._libs = _load_libraries()

    @property
    def available(self) -> bool:
        """True if the Windows device API was loaded."""
        return self._libs is not None

    def _require(self) -> _Libraries:
        if self._libs is None:
            raise BackendError(
                "the Windows device API is not available on this platform",
                code="unsupported_platform",
            )
        return self._libs

    # -- device tree -------------------------------------------------------------------

    def present_device_ids(self, enumerator: str) -> list[str]:
        """Return the instance id of every *present* device of one PnP enumerator.

        Uses ``SetupDiGetClassDevsW`` with ``DIGCF_PRESENT | DIGCF_ALLCLASSES``, so a
        device is listed whether or not a driver is installed or started for it.

        Args:
            enumerator: the enumerator name, e.g. ``"USB"``.

        Raises:
            BackendError: if the device information set cannot be built or walked.
        """
        libs = self._require()
        info = libs.setupapi.SetupDiGetClassDevsW(
            None, enumerator, None, DIGCF_PRESENT | DIGCF_ALLCLASSES
        )
        if _is_invalid_handle(info):
            raise BackendError(f"SetupDiGetClassDevsW failed (error {_last_error()})")
        try:
            ids: list[str] = []
            data = SP_DEVINFO_DATA()
            data.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            buffer = ctypes.create_string_buffer((MAX_DEVICE_ID_LEN + 1) * 2)
            for index in range(_MAX_ENUMERATED_DEVICES):
                if not libs.setupapi.SetupDiEnumDeviceInfo(info, index, ctypes.byref(data)):
                    error = _last_error()
                    if error == ERROR_NO_MORE_ITEMS:
                        break
                    raise BackendError(f"SetupDiEnumDeviceInfo failed (error {error})")
                # A device unplugged between the two calls fails here; it is simply not
                # listed.
                if libs.setupapi.SetupDiGetDeviceInstanceIdW(
                    info, ctypes.byref(data), buffer, MAX_DEVICE_ID_LEN + 1, None
                ):
                    ids.append(decode_utf16(buffer.raw))
            return ids
        finally:
            libs.setupapi.SetupDiDestroyDeviceInfoList(info)

    def locate_devnode(self, instance_id: str) -> int | None:
        """Return the device instance handle for an instance id, or ``None`` if absent.

        Only present devices are found (``CM_LOCATE_DEVNODE_NORMAL``).
        """
        libs = self._require()
        devinst = DEVINST(0)
        result = libs.cfgmgr32.CM_Locate_DevNodeW(
            ctypes.byref(devinst), instance_id, CM_LOCATE_DEVNODE_NORMAL
        )
        return int(devinst.value) if result == CR_SUCCESS else None

    def get_device_id(self, devinst: int) -> str | None:
        """Return the instance id of a device node, or ``None`` if the node is gone."""
        libs = self._require()
        buffer = ctypes.create_string_buffer((MAX_DEVICE_ID_LEN + 1) * 2)
        result = libs.cfgmgr32.CM_Get_Device_IDW(devinst, buffer, MAX_DEVICE_ID_LEN + 1, 0)
        return decode_utf16(buffer.raw) if result == CR_SUCCESS else None

    def get_parent(self, devinst: int) -> int | None:
        """Return the parent node (``CM_Get_Parent``), or ``None`` at the root."""
        return self._relative("CM_Get_Parent", devinst)

    def get_child(self, devinst: int) -> int | None:
        """Return the first child node (``CM_Get_Child``), or ``None`` if there is none."""
        return self._relative("CM_Get_Child", devinst)

    def get_sibling(self, devinst: int) -> int | None:
        """Return the next sibling (``CM_Get_Sibling``), or ``None`` after the last."""
        return self._relative("CM_Get_Sibling", devinst)

    def _relative(self, function: str, devinst: int) -> int | None:
        libs = self._require()
        found = DEVINST(0)
        result = getattr(libs.cfgmgr32, function)(ctypes.byref(found), devinst, 0)
        return int(found.value) if result == CR_SUCCESS else None

    def get_status(self, devinst: int) -> tuple[int, int] | None:
        """Return ``(DN_ status flags, CM_PROB_ problem code)`` for a node.

        The problem code is meaningful only when ``DN_HAS_PROBLEM`` is set. Returns
        ``None`` if the node no longer exists.
        """
        libs = self._require()
        status = ULONG(0)
        problem = ULONG(0)
        result = libs.cfgmgr32.CM_Get_DevNode_Status(
            ctypes.byref(status), ctypes.byref(problem), devinst, 0
        )
        if result != CR_SUCCESS:
            return None
        return int(status.value), int(problem.value)

    def get_property(self, devinst: int, key: DevPropKey) -> PropertyValue | None:
        """Read one device property with ``CM_Get_DevNode_PropertyW``.

        Returns:
            ``(DEVPROP_TYPE_ code, raw bytes)``, or ``None`` if the device has no such
            property, the node is gone, or the value is larger than PortLock accepts.
        """
        libs = self._require()
        prop_key = key.to_struct()
        prop_type = DEVPROPTYPE(0)
        size = ULONG(0)
        result = libs.cfgmgr32.CM_Get_DevNode_PropertyW(
            devinst, ctypes.byref(prop_key), ctypes.byref(prop_type), None, ctypes.byref(size), 0
        )
        if result == CR_SUCCESS:
            return int(prop_type.value), b""
        # The size can change between the sizing call and the read; one retry covers it.
        for _attempt in range(2):
            if result != CR_BUFFER_SMALL or not 0 < size.value <= _MAX_PROPERTY_BYTES:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            result = libs.cfgmgr32.CM_Get_DevNode_PropertyW(
                devinst,
                ctypes.byref(prop_key),
                ctypes.byref(prop_type),
                buffer,
                ctypes.byref(size),
                0,
            )
            if result == CR_SUCCESS:
                return int(prop_type.value), buffer.raw[: size.value]
        return None

    def get_interface_paths(self, class_guid: uuid.UUID, instance_id: str) -> list[str]:
        """Return the active device interface paths of one class exposed by one device.

        The paths (for example a disk's ``\\\\?\\usbstor#disk...`` path) can be opened
        with ``CreateFile``. An unknown device or a class it does not expose gives an
        empty list.
        """
        libs = self._require()
        guid = GUID.from_uuid(class_guid)
        info = libs.setupapi.SetupDiGetClassDevsW(
            ctypes.byref(guid), instance_id, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        )
        if _is_invalid_handle(info):
            return []
        try:
            paths: list[str] = []
            interface = SP_DEVICE_INTERFACE_DATA()
            interface.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            for index in range(_MAX_INTERFACES_PER_DEVICE):
                if not libs.setupapi.SetupDiEnumDeviceInterfaces(
                    info, None, ctypes.byref(guid), index, ctypes.byref(interface)
                ):
                    break
                path = self._interface_path(libs, info, interface)
                if path:
                    paths.append(path)
            return paths
        finally:
            libs.setupapi.SetupDiDestroyDeviceInfoList(info)

    @staticmethod
    def _interface_path(libs: _Libraries, info: int, interface: SP_DEVICE_INTERFACE_DATA) -> str:
        required = DWORD(0)
        # Sizing call: documented to fail with ERROR_INSUFFICIENT_BUFFER.
        libs.setupapi.SetupDiGetDeviceInterfaceDetailW(
            info, ctypes.byref(interface), None, 0, ctypes.byref(required), None
        )
        fixed = ctypes.sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)
        if _last_error() != ERROR_INSUFFICIENT_BUFFER or not fixed < required.value <= 65536:
            return ""
        buffer = ctypes.create_string_buffer(required.value)
        # cbSize is the size of the fixed part of the structure, not of the buffer.
        struct.pack_into("<I", buffer, 0, fixed)
        if not libs.setupapi.SetupDiGetDeviceInterfaceDetailW(
            info, ctypes.byref(interface), buffer, required.value, None, None
        ):
            return ""
        return decode_utf16(buffer.raw[SP_DEVICE_INTERFACE_DETAIL_DATA_W.DevicePath.offset :])

    # -- storage -----------------------------------------------------------------------

    def storage_device_number(self, path: str) -> StorageDeviceNumber | None:
        """Ask a disk, optical drive or volume which device number it has.

        The device is opened with *no* access rights (enough for this query, and it
        neither mounts nor locks anything) and asked ``IOCTL_STORAGE_GET_DEVICE_NUMBER``.

        Args:
            path: a device interface path or ``\\\\?\\Volume{...}`` *without* a trailing
                backslash.

        Returns:
            The device number, or ``None`` if the device cannot be opened or does not
            answer (a volume spanning several disks does not).
        """
        raw = self._query_ioctl(path, IOCTL_STORAGE_GET_DEVICE_NUMBER, 64)
        return decode_storage_device_number(raw) if raw is not None else None

    def volume_disk_numbers(self, path: str) -> tuple[int, ...]:
        """Return the disks a volume occupies (``IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS``).

        Used for volumes that span disks, which do not answer
        :meth:`storage_device_number`. Empty if the volume cannot be queried.
        """
        size = _DISK_EXTENTS_HEADER.size + _MAX_DISK_EXTENTS * _DISK_EXTENT.size
        raw = self._query_ioctl(path, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, size)
        return decode_disk_extents(raw) if raw is not None else ()

    def _query_ioctl(self, path: str, code: int, out_size: int) -> bytes | None:
        libs = self._require()
        with self._no_error_dialogs(libs):
            handle = libs.kernel32.CreateFileW(
                path,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if _is_invalid_handle(handle):
                return None
            try:
                buffer = ctypes.create_string_buffer(out_size)
                returned = DWORD(0)
                if not libs.kernel32.DeviceIoControl(
                    handle, code, None, 0, buffer, out_size, ctypes.byref(returned), None
                ):
                    return None
                return buffer.raw[: min(returned.value, out_size)]
            finally:
                libs.kernel32.CloseHandle(handle)

    def volume_names(self) -> list[str]:
        """Return every volume GUID path (``\\\\?\\Volume{...}\\``) on the system.

        Raises:
            BackendError: if the volume enumeration cannot be started.
        """
        libs = self._require()
        buffer = ctypes.create_string_buffer(_MAX_PATH * 2)
        handle = libs.kernel32.FindFirstVolumeW(buffer, _MAX_PATH)
        if _is_invalid_handle(handle):
            raise BackendError(f"FindFirstVolumeW failed (error {_last_error()})")
        try:
            names = [decode_utf16(buffer.raw)]
            while len(names) < _MAX_VOLUMES and libs.kernel32.FindNextVolumeW(
                handle, buffer, _MAX_PATH
            ):
                names.append(decode_utf16(buffer.raw))
            return names
        finally:
            libs.kernel32.FindVolumeClose(handle)

    def volume_mount_points(self, volume_name: str) -> list[str]:
        """Return the drive letters and mounted folders of a volume, possibly none."""
        libs = self._require()
        chars = _MAX_PATH
        for _attempt in range(2):
            buffer = ctypes.create_string_buffer(chars * 2)
            returned = DWORD(0)
            if libs.kernel32.GetVolumePathNamesForVolumeNameW(
                volume_name, buffer, chars, ctypes.byref(returned)
            ):
                return list(decode_multi_sz(buffer.raw))
            if _last_error() != ERROR_MORE_DATA or not chars < returned.value <= 32768:
                break
            chars = returned.value
        return []

    def volume_information(self, root: str) -> VolumeInformation | None:
        """Return label, serial number, flags and file system of a volume.

        This mounts the file system if it is not mounted yet, which reads from the
        device but writes nothing.

        Args:
            root: a volume root *with* a trailing backslash (a volume GUID path works).

        Returns:
            ``None`` if the volume has no medium, no recognised file system, is locked,
            or cannot be read.
        """
        libs = self._require()
        label = ctypes.create_string_buffer((_MAX_PATH + 1) * 2)
        filesystem = ctypes.create_string_buffer((_MAX_PATH + 1) * 2)
        serial = DWORD(0)
        component = DWORD(0)
        flags = DWORD(0)
        with self._no_error_dialogs(libs):
            ok = libs.kernel32.GetVolumeInformationW(
                root,
                label,
                _MAX_PATH + 1,
                ctypes.byref(serial),
                ctypes.byref(component),
                ctypes.byref(flags),
                filesystem,
                _MAX_PATH + 1,
            )
        if not ok:
            return None
        return VolumeInformation(
            label=decode_utf16(label.raw),
            serial_number=int(serial.value),
            flags=int(flags.value),
            filesystem=decode_utf16(filesystem.raw),
        )

    def volume_total_bytes(self, root: str) -> int | None:
        """Return the size of a volume's file system in bytes, or ``None`` if unknown."""
        libs = self._require()
        total = ctypes.c_uint64(0)
        with self._no_error_dialogs(libs):
            ok = libs.kernel32.GetDiskFreeSpaceExW(root, None, ctypes.byref(total), None)
        return int(total.value) if ok else None

    @staticmethod
    @contextlib.contextmanager
    def _no_error_dialogs(libs: _Libraries) -> Iterator[None]:
        """Keep Windows from showing "There is no disk in the drive" for this thread.

        Querying a card reader with no card raises a hard-error dialog in an
        interactive process unless critical-error dialogs are suppressed. The mode is
        per thread and is restored afterwards.
        """
        previous = DWORD(0)
        changed = bool(
            libs.kernel32.SetThreadErrorMode(SEM_FAILCRITICALERRORS, ctypes.byref(previous))
        )
        try:
            yield
        finally:
            if changed:
                libs.kernel32.SetThreadErrorMode(previous.value, None)

    # -- notifications -----------------------------------------------------------------

    def supports_notifications(self) -> bool:
        """True if ``CM_Register_Notification`` exists (Windows 8 and later)."""
        return self._libs is not None and self._libs.notifications

    def register_interface_notification(
        self, class_guid: uuid.UUID, sink: NotificationSink
    ) -> NotificationHandle:
        """Register for arrival and removal of device interfaces of one class.

        ``sink`` is called on an operating-system thread-pool thread and must return
        quickly without blocking; hand the payload to another thread.

        Raises:
            BackendError: if notifications are unsupported or registration fails.
        """
        notify_filter = CM_NOTIFY_FILTER()
        notify_filter.cbSize = ctypes.sizeof(CM_NOTIFY_FILTER)
        notify_filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE
        notify_filter.u.ClassGuid = GUID.from_uuid(class_guid)
        return self._register(notify_filter, sink, f"device interface {{{class_guid}}}")

    def register_instance_notification(self, sink: NotificationSink) -> NotificationHandle:
        """Register for enumeration, start and removal of *every* device instance.

        This is what reports a device that Windows enumerated but never started, for
        example one whose installation a policy refused. Same threading rules as
        :meth:`register_interface_notification`.

        Raises:
            BackendError: if notifications are unsupported or registration fails.
        """
        notify_filter = CM_NOTIFY_FILTER()
        notify_filter.cbSize = ctypes.sizeof(CM_NOTIFY_FILTER)
        notify_filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE
        # With this flag the instance id in the filter must be the empty string, which
        # the zero-initialised structure already holds.
        notify_filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES
        return self._register(notify_filter, sink, "all device instances")

    def _register(
        self, notify_filter: CM_NOTIFY_FILTER, sink: NotificationSink, description: str
    ) -> NotificationHandle:
        libs = self._require()
        if not libs.notifications:
            raise BackendError(
                "CM_Register_Notification is not available (it needs Windows 8 or later)",
                code="notifications_unsupported",
            )

        def thunk(_notify: int, _context: int, action: int, data: int, size: int) -> int:
            # Runs on a system thread-pool thread. Copy the payload (it is only valid
            # during this call) and hand it over. Nothing here may block, and no exception
            # may unwind into the operating system's thread pool.
            with contextlib.suppress(Exception):
                payload = ctypes.string_at(data, min(size, _MAX_NOTIFY_BYTES)) if data else b""
                sink(int(action), payload)
            return ERROR_SUCCESS

        callback = PCM_NOTIFY_CALLBACK(thunk)
        handle = HCMNOTIFICATION()
        result = libs.cfgmgr32.CM_Register_Notification(
            ctypes.byref(notify_filter), None, callback, ctypes.byref(handle)
        )
        if result != CR_SUCCESS or not handle.value:
            raise BackendError(
                f"CM_Register_Notification ({description}) failed: {config_ret_name(result)}"
            )
        return NotificationHandle(int(handle.value), callback, description)

    def unregister_notification(self, handle: NotificationHandle) -> None:
        """Close a registration. Blocks until callbacks in progress have returned.

        Must not be called from inside a notification callback: the operating system
        documents that as a deadlock.

        Raises:
            BackendError: if the operating system rejects the handle.
        """
        libs = self._require()
        result = libs.cfgmgr32.CM_Unregister_Notification(handle.handle)
        if result != CR_SUCCESS:
            raise BackendError(f"CM_Unregister_Notification failed: {config_ret_name(result)}")

    # -- power events ------------------------------------------------------------------

    def supports_resume_notifications(self) -> bool:
        """True if ``PowerRegisterSuspendResumeNotification`` exists (Windows 8 and later)."""
        return self._libs is not None and self._libs.powrprof is not None

    def register_resume_notification(self, sink: PowerSink) -> NotificationHandle:
        """Register for suspend and resume events with a callback (``DEVICE_NOTIFY_CALLBACK``).

        ``sink`` receives the ``PBT_`` code (``PBT_APMSUSPEND``, ``PBT_APMRESUMESUSPEND``,
        ``PBT_APMRESUMEAUTOMATIC``) on an operating-system thread and must return quickly.
        The registration only listens: it does not keep the system awake or change any
        power setting.

        Raises:
            BackendError: if the function is unavailable or registration fails.
        """
        libs = self._require()
        if libs.powrprof is None:
            raise BackendError(
                "PowerRegisterSuspendResumeNotification is not available "
                "(it needs Windows 8 or later)",
                code="notifications_unsupported",
            )

        def thunk(_context: int, event_type: int, _setting: int) -> int:
            # Same rules as the device notification thunk: hand over, never raise.
            with contextlib.suppress(Exception):
                sink(int(event_type))
            return ERROR_SUCCESS

        callback = PDEVICE_NOTIFY_CALLBACK_ROUTINE(thunk)
        parameters = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS(callback, None)
        handle = HPOWERNOTIFY()
        result = libs.powrprof.PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK, ctypes.byref(parameters), ctypes.byref(handle)
        )
        if result != ERROR_SUCCESS or not handle.value:
            raise BackendError(f"PowerRegisterSuspendResumeNotification failed (error {result})")
        # The parameters are kept with the callback in case the system reads them later.
        return NotificationHandle(int(handle.value), (callback, parameters), "suspend/resume")

    def unregister_resume_notification(self, handle: NotificationHandle) -> None:
        """Close a registration made by :meth:`register_resume_notification`.

        Raises:
            BackendError: if the function is unavailable or rejects the handle.
        """
        libs = self._require()
        if libs.powrprof is None:
            raise BackendError("PowerUnregisterSuspendResumeNotification is not available")
        result = libs.powrprof.PowerUnregisterSuspendResumeNotification(handle.handle)
        if result != ERROR_SUCCESS:
            raise BackendError(f"PowerUnregisterSuspendResumeNotification failed (error {result})")
