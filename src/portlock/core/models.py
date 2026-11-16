"""The device model and the decision vocabulary shared by every PortLock component.

Everything here is an immutable value. A :class:`UsbDevice` describes one device as the
operating system reports it for one connection; plugging the same stick in again yields
an equal description with a possibly different ``instance_id``. Nothing in this module
talks to the operating system.
"""

from __future__ import annotations

import enum
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from portlock.core.clock import parse_utc_iso, utc_iso

__all__ = [
    "Access",
    "Confidence",
    "Decision",
    "DecisionSource",
    "DeviceCategory",
    "DeviceEvent",
    "DeviceEventType",
    "Fingerprint",
    "Mode",
    "ScanRequirement",
    "Severity",
    "UsbClass",
    "UsbDevice",
    "UsbInterface",
    "Volume",
    "sanitize_device_text",
]


class UsbClass(enum.IntEnum):
    """USB-IF base class codes (the ones PortLock distinguishes)."""

    PER_INTERFACE = 0x00
    AUDIO = 0x01
    CDC_CONTROL = 0x02
    HID = 0x03
    PHYSICAL = 0x05
    IMAGE = 0x06
    PRINTER = 0x07
    MASS_STORAGE = 0x08
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    CONTENT_SECURITY = 0x0D
    VIDEO = 0x0E
    PERSONAL_HEALTHCARE = 0x0F
    AUDIO_VIDEO = 0x10
    BILLBOARD = 0x11
    DIAGNOSTIC = 0xDC
    WIRELESS = 0xE0
    MISCELLANEOUS = 0xEF
    APPLICATION_SPECIFIC = 0xFE
    VENDOR_SPECIFIC = 0xFF


class DeviceCategory(enum.StrEnum):
    """What a device (or one of its interfaces) does, as far as policy cares."""

    STORAGE = "storage"
    KEYBOARD = "keyboard"
    MOUSE = "mouse"
    HID = "hid"
    HUB = "hub"
    NETWORK = "network"
    SERIAL = "serial"
    AUDIO_VIDEO = "audio_video"
    IMAGING = "imaging"
    PRINTER = "printer"
    SMART_CARD = "smart_card"
    WIRELESS = "wireless"
    VENDOR = "vendor"
    OTHER = "other"


_HID_BOOT_SUBCLASS = 0x01
_HID_PROTOCOL_KEYBOARD = 0x01
_HID_PROTOCOL_MOUSE = 0x02
_CDC_SUBCLASS_ACM = 0x02
# CDC subclasses that carry network traffic: ECM, EEM, NCM, MBIM.
_CDC_NETWORK_SUBCLASSES = frozenset({0x06, 0x0C, 0x0D, 0x0E})
# Network adapters that do not use a CDC networking subclass: RNDIS in its three common
# spellings (wireless controller, miscellaneous, and the vendor protocol on CDC ACM).
_NETWORK_TRIPLES = frozenset({(0xE0, 0x01, 0x03), (0xEF, 0x04, 0x01), (0x02, 0x02, 0xFF)})

_CLASS_CATEGORIES: Mapping[int, DeviceCategory] = MappingProxyType(
    {
        UsbClass.AUDIO: DeviceCategory.AUDIO_VIDEO,
        UsbClass.VIDEO: DeviceCategory.AUDIO_VIDEO,
        UsbClass.AUDIO_VIDEO: DeviceCategory.AUDIO_VIDEO,
        UsbClass.IMAGE: DeviceCategory.IMAGING,
        UsbClass.PRINTER: DeviceCategory.PRINTER,
        UsbClass.MASS_STORAGE: DeviceCategory.STORAGE,
        UsbClass.HUB: DeviceCategory.HUB,
        UsbClass.CDC_DATA: DeviceCategory.NETWORK,
        UsbClass.SMART_CARD: DeviceCategory.SMART_CARD,
        UsbClass.WIRELESS: DeviceCategory.WIRELESS,
        UsbClass.VENDOR_SPECIFIC: DeviceCategory.VENDOR,
    }
)


_INPUT_CATEGORIES: frozenset[DeviceCategory] = frozenset(
    {DeviceCategory.KEYBOARD, DeviceCategory.MOUSE, DeviceCategory.HID}
)


def _categorize(cls: int, subcls: int, protocol: int) -> DeviceCategory:
    if (cls, subcls, protocol) in _NETWORK_TRIPLES:
        return DeviceCategory.NETWORK
    if cls == UsbClass.HID:
        # Only boot-protocol devices declare what they are in the descriptor. Any other
        # HID device may still type like a keyboard; it is reported as plain HID and
        # policy should treat it with the same suspicion.
        if subcls == _HID_BOOT_SUBCLASS and protocol == _HID_PROTOCOL_KEYBOARD:
            return DeviceCategory.KEYBOARD
        if subcls == _HID_BOOT_SUBCLASS and protocol == _HID_PROTOCOL_MOUSE:
            return DeviceCategory.MOUSE
        return DeviceCategory.HID
    if cls == UsbClass.CDC_CONTROL:
        if subcls == _CDC_SUBCLASS_ACM:
            return DeviceCategory.SERIAL
        if subcls in _CDC_NETWORK_SUBCLASSES:
            return DeviceCategory.NETWORK
        return DeviceCategory.OTHER
    return _CLASS_CATEGORIES.get(cls, DeviceCategory.OTHER)


def _check_range(name: str, value: int, upper: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= upper:
        raise ValueError(f"{name} must be an integer between 0 and {upper:#x}, got {value!r}")


#: A USB string descriptor holds at most 126 UTF-16 code units.
_MAX_DEVICE_TEXT = 126
_REPLACEMENT = chr(0xFFFD)
# Control, format (including bidirectional overrides and zero-width characters),
# surrogate, private-use and unassigned code points, and line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def sanitize_device_text(value: object, *, limit: int = _MAX_DEVICE_TEXT) -> str | None:
    """Make a string supplied by a device safe to store, log and display.

    Descriptor strings, volume labels and the like are chosen by the device. Left alone,
    an escape sequence in a product name could rewrite a line of a terminal listing and a
    right-to-left override could disguise it. Every unsafe character is replaced with
    U+FFFD (so it stays visible that something was there), surrounding whitespace is
    removed and the result is capped at ``limit`` characters. An empty result is ``None``.

    Raises:
        ValueError: if ``value`` is neither a string nor ``None``.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"device text must be a string or None, got {type(value).__name__}")
    cleaned = "".join(
        _REPLACEMENT if unicodedata.category(char) in _UNSAFE_CATEGORIES else char for char in value
    ).strip()
    return cleaned[:limit] or None


@dataclass(frozen=True, slots=True, order=True)
class UsbInterface:
    """One interface descriptor: class, subclass, protocol."""

    cls: int
    subcls: int = 0
    protocol: int = 0

    def __post_init__(self) -> None:
        _check_range("interface class", self.cls, 0xFF)
        _check_range("interface subclass", self.subcls, 0xFF)
        _check_range("interface protocol", self.protocol, 0xFF)

    @property
    def category(self) -> DeviceCategory:
        return _categorize(self.cls, self.subcls, self.protocol)

    def to_dict(self) -> dict[str, int]:
        return {"cls": self.cls, "subcls": self.subcls, "protocol": self.protocol}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UsbInterface:
        return cls(int(data["cls"]), int(data.get("subcls", 0)), int(data.get("protocol", 0)))


@dataclass(frozen=True, slots=True)
class Volume:
    """A filesystem (or raw block device) that a storage device exposes."""

    device_node: str
    mount_point: str | None = None
    label: str | None = None
    fs_type: str | None = None
    fs_uuid: str | None = None
    size_bytes: int | None = None
    read_only: bool | None = None

    def __post_init__(self) -> None:
        # The label, filesystem name and UUID come from the device. The device node and
        # mount point are left as the OS reports them because they are used as paths;
        # consoles must still render them as text only.
        for name in ("label", "fs_type", "fs_uuid"):
            object.__setattr__(self, name, sanitize_device_text(getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_node": self.device_node,
            "mount_point": self.mount_point,
            "label": self.label,
            "fs_type": self.fs_type,
            "fs_uuid": self.fs_uuid,
            "size_bytes": self.size_bytes,
            "read_only": self.read_only,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Volume:
        return cls(
            device_node=str(data["device_node"]),
            mount_point=data.get("mount_point"),
            label=data.get("label"),
            fs_type=data.get("fs_type"),
            fs_uuid=data.get("fs_uuid"),
            size_bytes=data.get("size_bytes"),
            read_only=data.get("read_only"),
        )


@dataclass(frozen=True, slots=True)
class UsbDevice:
    """One USB device as reported by the operating system for one connection.

    Attributes:
        instance_id: the OS handle for *this connection* (Windows device instance id,
            Linux sysfs path). Used to address the device for enforcement. Not part of
            the fingerprint: it can change when the device moves to another port.
        vendor_id / product_id: ``idVendor`` and ``idProduct``.
        serial: ``iSerialNumber`` string, or ``None`` if the device has none.
        manufacturer / product: descriptor strings, if present.
        bcd_device: device release number.
        device_class: ``bDeviceClass`` (0 means "see the interfaces").
        interfaces: interface descriptors of the active configuration.
        bus_path: physical port path, e.g. ``1-2.3``. Stable for a given port.
        removable: ``True`` for an external port, ``False`` for a built-in device,
            ``None`` if the platform does not say.
        volumes: filesystems exposed by a storage device, when known.
        connection_id: a token that differs for every physical connection, even of the
            same device on the same port (``instance_id`` survives a re-plug on both
            platforms). ``None`` if the backend cannot supply one. Ignored by equality,
            hashing and fingerprinting.
        backend_data: opaque extras for the backend that produced this object. Ignored
            by equality, hashing and fingerprinting.
    """

    instance_id: str
    vendor_id: int
    product_id: int
    serial: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    bcd_device: int | None = None
    device_class: int = 0
    interfaces: tuple[UsbInterface, ...] = ()
    bus_path: str | None = None
    removable: bool | None = None
    volumes: tuple[Volume, ...] = ()
    connection_id: str | None = field(default=None, compare=False, hash=False)
    backend_data: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({}), compare=False, hash=False, repr=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.instance_id, str) or not self.instance_id:
            raise ValueError("instance_id must be a non-empty string")
        _check_range("vendor_id", self.vendor_id, 0xFFFF)
        _check_range("product_id", self.product_id, 0xFFFF)
        _check_range("device_class", self.device_class, 0xFF)
        if self.bcd_device is not None:
            _check_range("bcd_device", self.bcd_device, 0xFFFF)
        for name in ("serial", "manufacturer", "product"):
            object.__setattr__(self, name, sanitize_device_text(getattr(self, name)))
        object.__setattr__(self, "interfaces", tuple(self.interfaces))
        object.__setattr__(self, "volumes", tuple(self.volumes))
        object.__setattr__(self, "backend_data", MappingProxyType(dict(self.backend_data)))

    @property
    def categories(self) -> frozenset[DeviceCategory]:
        """Every function this device declares.

        Derived from the interfaces; a device that reports none falls back to its
        device class. A device that declares nothing recognisable is ``OTHER``.
        """
        if self.interfaces:
            return frozenset(interface.category for interface in self.interfaces)
        return frozenset({_categorize(self.device_class, 0, 0)})

    @property
    def is_storage(self) -> bool:
        return DeviceCategory.STORAGE in self.categories

    @property
    def is_hid(self) -> bool:
        """True if any interface is a human-interface device (keyboard, mouse or other)."""
        return bool(
            self.categories & {DeviceCategory.KEYBOARD, DeviceCategory.MOUSE, DeviceCategory.HID}
        )

    @property
    def is_keyboard(self) -> bool:
        return DeviceCategory.KEYBOARD in self.categories

    @property
    def is_hub(self) -> bool:
        return DeviceCategory.HUB in self.categories

    @property
    def is_composite(self) -> bool:
        """True if the device declares more than one distinct function."""
        return len(self.categories) > 1

    @property
    def pairs_storage_with_input(self) -> bool:
        """True for storage that also presents an input device.

        Legitimate devices rarely do this; it is the shape of a "BadUSB" stick that
        mounts as a drive and types commands.
        """
        return self.is_storage and self.is_hid

    @property
    def is_storage_like(self) -> bool:
        """True for mass storage and for imaging devices.

        A phone or camera in MTP or PTP mode is not mass storage, but it exposes files
        in both directions all the same, so scope and lockdown treat the two alike.
        """
        return bool(self.categories & {DeviceCategory.STORAGE, DeviceCategory.IMAGING})

    @property
    def is_input_only(self) -> bool:
        """True if the device is an input device and nothing else (hubs aside).

        Only such a device qualifies for the category protection that keeps the
        operator's keyboard and mouse working.
        """
        functions = self.categories - {DeviceCategory.HUB}
        return bool(functions) and functions <= _INPUT_CATEGORIES

    @property
    def mixes_input_with_other(self) -> bool:
        """True if an input interface sits beside any other function.

        Storage that also types, or a keyboard that is also a network adapter: the shape
        of a "BadUSB" stick or a network-tap implant.
        """
        functions = self.categories - {DeviceCategory.HUB}
        return bool(functions & _INPUT_CATEGORIES) and not functions <= _INPUT_CATEGORIES

    @property
    def vid_pid(self) -> str:
        """``vvvv:pppp`` in lowercase hex, the way ``lsusb`` prints it."""
        return f"{self.vendor_id:04x}:{self.product_id:04x}"

    @property
    def display_name(self) -> str:
        """A short human-readable name for lists and log lines."""
        parts = [part for part in (self.manufacturer, self.product) if part]
        return " ".join(parts) if parts else f"USB device {self.vid_pid}"

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable description (for the API, the audit log and the store)."""
        return {
            "instance_id": self.instance_id,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial": self.serial,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "bcd_device": self.bcd_device,
            "device_class": self.device_class,
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "bus_path": self.bus_path,
            "removable": self.removable,
            "connection_id": self.connection_id,
            "volumes": [volume.to_dict() for volume in self.volumes],
            "categories": sorted(category.value for category in self.categories),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UsbDevice:
        """Rebuild a device from :meth:`to_dict` output (``backend_data`` is not kept)."""
        return cls(
            instance_id=str(data["instance_id"]),
            vendor_id=int(data["vendor_id"]),
            product_id=int(data["product_id"]),
            serial=data.get("serial"),
            manufacturer=data.get("manufacturer"),
            product=data.get("product"),
            bcd_device=data.get("bcd_device"),
            device_class=int(data.get("device_class", 0)),
            interfaces=tuple(UsbInterface.from_dict(item) for item in data.get("interfaces", ())),
            bus_path=data.get("bus_path"),
            removable=data.get("removable"),
            connection_id=data.get("connection_id"),
            volumes=tuple(Volume.from_dict(item) for item in data.get("volumes", ())),
        )


class Confidence(enum.StrEnum):
    """How much a fingerprint narrows a device down."""

    #: The device reports a serial number that looks unique.
    HIGH = "high"
    #: No serial, or a serial known to be shared by many units.
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A stable identifier derived from what a device says about itself.

    A fingerprint identifies; it does not authenticate. Every input is supplied by the
    device and can be copied by a device built to copy it.

    Attributes:
        value: ``plk1:`` followed by 32 base32 characters.
        confidence: see :class:`Confidence`.
        basis: the descriptor fields that went into the value, for explanation.
    """

    value: str
    confidence: Confidence
    basis: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.value


class Access(enum.StrEnum):
    """What a device is allowed to do."""

    ALLOW = "allow"
    READ_ONLY = "read_only"
    DENY = "deny"
    #: Blocked until an administrator decides.
    PENDING = "pending"


class ScanRequirement(enum.StrEnum):
    """Whether and when a storage device's contents are scanned."""

    NONE = "none"
    #: Scan after access is granted; a detection can revoke it.
    ON_MOUNT = "on_mount"
    #: Grant read-only access, scan, and only then apply the decided access.
    REQUIRED = "required"


class DecisionSource(enum.StrEnum):
    """Which part of the pipeline produced a decision. Listed highest precedence first."""

    SAFETY = "safety"
    LOCKDOWN = "lockdown"
    SCAN = "scan"
    POLICY = "policy"
    GRANT = "grant"
    DEFAULT = "default"


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating one device, with the reasons a person can read."""

    access: Access
    source: DecisionSource
    reasons: tuple[str, ...] = ()
    rule_id: str | None = None
    grant_id: str | None = None
    scan: ScanRequirement = ScanRequirement.NONE
    alert: bool = False
    expires_at: datetime | None = None

    @property
    def permits_access(self) -> bool:
        """True if the device may be used at all (fully or read-only)."""
        return self.access in (Access.ALLOW, Access.READ_ONLY)

    @property
    def blocks(self) -> bool:
        """True if the device must be kept from the system."""
        return not self.permits_access

    def to_dict(self) -> dict[str, Any]:
        return {
            "access": self.access.value,
            "source": self.source.value,
            "reasons": list(self.reasons),
            "rule_id": self.rule_id,
            "grant_id": self.grant_id,
            "scan": self.scan.value,
            "alert": self.alert,
            "expires_at": utc_iso(self.expires_at) if self.expires_at is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Decision:
        expires = data.get("expires_at")
        return cls(
            access=Access(data["access"]),
            source=DecisionSource(data["source"]),
            reasons=tuple(data.get("reasons", ())),
            rule_id=data.get("rule_id"),
            grant_id=data.get("grant_id"),
            scan=ScanRequirement(data.get("scan", ScanRequirement.NONE.value)),
            alert=bool(data.get("alert", False)),
            expires_at=parse_utc_iso(expires) if expires else None,
        )


class DeviceEventType(enum.StrEnum):
    ARRIVED = "arrived"
    REMOVED = "removed"
    #: Same connection, new information (typically a volume was mounted).
    CHANGED = "changed"
    #: The backend may have missed events; the receiver must enumerate again.
    RESYNC = "resync"


@dataclass(frozen=True, slots=True)
class DeviceEvent:
    """Something a device backend observed. ``device`` is ``None`` only for ``RESYNC``."""

    type: DeviceEventType
    device: UsbDevice | None
    at: datetime

    def __post_init__(self) -> None:
        if (self.device is None) != (self.type is DeviceEventType.RESYNC):
            raise ValueError("a device is required for every event type except RESYNC")


class Mode(enum.StrEnum):
    """Whether PortLock acts on its decisions."""

    #: Record what would have been done; change nothing.
    MONITOR = "monitor"
    #: Have the operating system enforce decisions.
    ENFORCE = "enforce"


class Severity(enum.StrEnum):
    """Severity of an audit event, least to most serious."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in the ordering, for ``>=`` style filters."""
        return list(Severity).index(self)
