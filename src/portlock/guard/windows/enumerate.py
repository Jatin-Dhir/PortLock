"""Enumerate USB devices on Windows from the Plug and Play device tree. Read-only.

Windows describes a USB device with identification strings rather than descriptors, so
most of this module is parsing:

* the **device instance id** ``USB\\VID_vvvv&PID_pppp\\<instance>`` carries the vendor
  and product ids, and the serial number *if the device has one*. When it has none,
  Windows writes a generated, port-specific value there instead (it contains ``&``);
  that value is never reported as a serial;
* the **hardware ids** carry ``REV_rrrr``, the ``bcdDevice`` release number;
* the **compatible ids** ``USB\\Class_cc&SubClass_ss&Prot_pp`` carry the interface
  class triple of a single-function device. A composite device driven by the generic
  parent driver (``usbccgp``) has one child node per function,
  ``USB\\VID_vvvv&PID_pppp&MI_nn\\...``, and each child's compatible ids carry that
  function's triple;
* the **location paths** give the physical port, e.g.
  ``PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)#USB(3)``.

The parsing functions are pure and are tested on their own against synthetic strings.
:func:`enumerate_usb_devices` applies them to what a :class:`~.api.WinApi` reports.

What Windows does not expose here, and what this module therefore does not claim:

* ``manufacturer`` is always ``None``. The only manufacturer string Windows keeps
  (``DEVPKEY_Device_Manufacturer``) comes from the INF file of the installed *driver*,
  not from the device, and changes when a driver is installed or replaced. Using it
  would make a device's fingerprint differ before and after its driver is installed.
  It is available, for display only, as ``backend_data["driver_manufacturer"]``.
* ``product`` is the bus-reported description (the device's own product string). A
  device that reports none has ``product`` ``None``; the driver's description is in
  ``backend_data["description"]``. Root hubs, which sit on no bus that could report
  one, use the driver's description.
* ``interfaces`` holds one entry per *function*, not per interface descriptor: Windows
  merges the interfaces of an interface association into one child node. A composite
  device whose generic parent driver is not running has no child nodes and therefore
  reports no interfaces until it starts.

Device-supplied text (the product string) is passed to :class:`UsbDevice` as Windows
reports it; the model sanitizes it. Only ``backend_data``, which the model does not
touch, is sanitized here.

See ``docs/enforcement/windows.md`` for the identifiers, with references.
"""

from __future__ import annotations

import enum
import logging
import re
import secrets
import threading
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from portlock.core.errors import BackendError
from portlock.core.models import UsbClass, UsbDevice, UsbInterface, Volume, sanitize_device_text
from portlock.guard.windows.api import (
    CM_DEVCAP_REMOVABLE,
    CM_DEVCAP_UNIQUEID,
    CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL,
    CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL,
    CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL,
    DEVPROP_TYPE_FILETIME,
    DEVPROP_TYPE_GUID,
    DEVPROP_TYPE_INT32,
    DEVPROP_TYPE_STRING,
    DEVPROP_TYPE_STRING_LIST,
    DEVPROP_TYPE_UINT32,
    DN_DISABLEABLE,
    DN_HAS_PROBLEM,
    DN_STARTED,
    MAX_DEVICE_ID_LEN,
    DEVPKEY_Device_Address,
    DEVPKEY_Device_BusReportedDeviceDesc,
    DEVPKEY_Device_Capabilities,
    DEVPKEY_Device_ClassGuid,
    DEVPKEY_Device_CompatibleIds,
    DEVPKEY_Device_ContainerId,
    DEVPKEY_Device_DeviceDesc,
    DEVPKEY_Device_HardwareIds,
    DEVPKEY_Device_LastArrivalDate,
    DEVPKEY_Device_LocationPaths,
    DEVPKEY_Device_Manufacturer,
    DEVPKEY_Device_RemovalPolicy,
    DEVPKEY_Device_Service,
    PropertyValue,
    WinApi,
    decode_multi_sz,
    decode_utf16,
)
from portlock.guard.windows.volumes import VolumeIndex, volumes_for_device

__all__ = [
    "CompatibleIds",
    "ConnectionTokens",
    "HardwareIds",
    "InstanceId",
    "LocationPath",
    "NodeKind",
    "connection_id_for",
    "decode_filetime",
    "decode_guid",
    "decode_int",
    "decode_multi_sz",
    "decode_string",
    "decode_string_list",
    "enumerate_usb_devices",
    "is_synthesized_instance",
    "parse_compatible_ids",
    "parse_hardware_ids",
    "parse_instance_id",
    "parse_location_paths",
]

_LOG = logging.getLogger(__name__)

#: The PnP enumerator name of the USB bus.
USB_ENUMERATOR = "USB"

# Windows forbids these in device identification strings: anything at or below a space,
# anything above 0x7E, and the comma. An id that contains one did not come from PnP.
_ID_TEXT = re.compile(r"[\x21-\x2b\x2d-\x7e]+\Z")
_HEX2 = r"([0-9A-Fa-f]{2})"
_HEX4 = r"([0-9A-Fa-f]{4})"
_VID = re.compile(rf"VID_{_HEX4}\Z", re.IGNORECASE)
_PID = re.compile(rf"PID_{_HEX4}\Z", re.IGNORECASE)
_MI = re.compile(rf"MI_{_HEX2}\Z", re.IGNORECASE)
# Hardware ids of root hubs write VIDvvvv, PIDpppp and REVrrrr without the underscore.
_HW_VID = re.compile(rf"VID_?{_HEX4}\Z", re.IGNORECASE)
_HW_PID = re.compile(rf"PID_?{_HEX4}\Z", re.IGNORECASE)
_HW_REV = re.compile(rf"REV_?{_HEX4}\Z", re.IGNORECASE)
_ROOT_HUB = re.compile(r"ROOT_HUB[0-9A-Za-z_]*\Z", re.IGNORECASE)
_CLASS = re.compile(rf"(Dev)?Class_{_HEX2}\Z", re.IGNORECASE)
_SUBCLASS = re.compile(rf"SubClass_{_HEX2}\Z", re.IGNORECASE)
# Windows 11 writes "Prot00" (no underscore) in the vendor-qualified device-class form.
_PROTOCOL = re.compile(rf"Prot_?{_HEX2}\Z", re.IGNORECASE)
_HUB_IDS = frozenset({"USB20_HUB", "USB30_HUB"})
# Compatible ids a device supplies through a Microsoft OS descriptor: MS_COMP_MTP, ...
_MS_COMPATIBLE_PREFIX = "MS_COMP_"
_HUB_SERVICES = frozenset({"USBHUB", "USBHUB3"})
_LOCATION_SEGMENT = re.compile(r"[A-Za-z0-9_]+\([A-Za-z0-9_]*\)\Z")
_USB_PORT_SEGMENT = re.compile(r"USB\(([0-9]{1,3})\)\Z", re.IGNORECASE)
_USB_ROOT_SEGMENT = re.compile(r"USBROOT\([0-9]+\)\Z", re.IGNORECASE)

_MAX_ID_LIST = 64
_MAX_LOCATION_PATH = 512
_MAX_INTERFACE_NODES = 64
_MAX_TREE_DEPTH = 16


class NodeKind(enum.StrEnum):
    """What a node enumerated by the USB bus represents."""

    #: A physical device attached to a hub port.
    DEVICE = "device"
    #: One function of a composite device (a ``&MI_nn`` child of the device node).
    INTERFACE = "interface"
    #: The hub built into a host controller.
    ROOT_HUB = "root_hub"


@dataclass(frozen=True, slots=True)
class InstanceId:
    """A parsed USB device instance id.

    Attributes:
        text: the id exactly as Windows reported it.
        enumerator: the first segment, always ``USB`` (in the reported case).
        device_id: the second segment, e.g. ``VID_1209&PID_0001``.
        instance: the third segment: a serial number, or a generated value.
        kind: what the node is.
        vendor_id / product_id: from ``VID_`` and ``PID_``; ``None`` for a root hub,
            whose id carries neither.
        interface_number: ``MI_nn`` for an interface node, else ``None``.
        serial: the device's serial number, or ``None`` when ``instance`` was generated
            by Windows or the node is not a device.
    """

    text: str
    enumerator: str
    device_id: str
    instance: str
    kind: NodeKind
    vendor_id: int | None
    product_id: int | None
    interface_number: int | None
    serial: str | None


@dataclass(frozen=True, slots=True)
class HardwareIds:
    """What the hardware ids of a node say. Each field is ``None`` if not stated."""

    vendor_id: int | None = None
    product_id: int | None = None
    revision: int | None = None
    interface_number: int | None = None


@dataclass(frozen=True, slots=True)
class CompatibleIds:
    """What the compatible ids of a node say.

    Attributes:
        interfaces: the class triples named by ``USB\\Class_...`` ids, most specific
            form of each, in the order given, without duplicates.
        device_class: the triple named by ``USB\\DevClass_...``, which Windows uses for
            the device-level class of a composite device; ``None`` if absent.
        composite: ``USB\\COMPOSITE`` is present.
        hub: the ids mark the node as a hub.
        tags: the recognised single-word ids, upper-cased: ``COMPOSITE``, the hub ids,
            and ``MS_COMP_...`` ids such as ``MS_COMP_MTP``.
    """

    interfaces: tuple[UsbInterface, ...] = ()
    device_class: UsbInterface | None = None
    composite: bool = False
    hub: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LocationPath:
    """A device's position in the device tree.

    Attributes:
        path: the chosen location path, as reported.
        controller: the part up to and including ``USBROOT(n)``, identifying the host
            controller; ``None`` if the path has no such segment.
        ports: the hub port numbers below the root hub, outermost first.
    """

    path: str
    controller: str | None
    ports: tuple[int, ...]


# --------------------------------------------------------------------------------------
# Identification strings
# --------------------------------------------------------------------------------------


def is_synthesized_instance(instance: str) -> bool:
    """True if the third segment of an instance id was generated by Windows.

    A device with a serial number reports it as its instance id and declares the id
    unique. For any other device the PnP manager builds an instance id from the parent's
    id and the port, of the form ``5&2f9d1c3a&0&2``. The ampersand is what tells the two
    apart: it cannot survive in a serial number the hub driver accepted.
    """
    return "&" in instance


def parse_instance_id(instance_id: str) -> InstanceId:
    """Parse a device instance id enumerated by the USB bus.

    Args:
        instance_id: e.g. ``USB\\VID_1209&PID_0001\\TEST0001A7C3``,
            ``USB\\VID_1209&PID_0002&MI_00\\6&1a2b3c4d&0&0000`` or
            ``USB\\ROOT_HUB30\\4&1a2b3c4d&0&0``.

    Raises:
        ValueError: if the text is not a well-formed USB instance id: wrong type or
            length, a character Windows does not allow in an id, not exactly three
            non-empty segments, another enumerator, or no ``VID_``/``PID_`` pair.
    """
    if not isinstance(instance_id, str):
        raise ValueError("a device instance id must be a string")
    if not 0 < len(instance_id) < MAX_DEVICE_ID_LEN:
        raise ValueError("device instance id is empty or longer than Windows allows")
    if not _ID_TEXT.match(instance_id):
        raise ValueError("device instance id contains a character Windows does not allow")
    parts = instance_id.split("\\")
    if len(parts) != 3 or not all(parts):
        raise ValueError("a device instance id has the form ENUMERATOR\\DEVICE\\INSTANCE")
    enumerator, device_id, instance = parts
    if enumerator.upper() != USB_ENUMERATOR:
        raise ValueError(f"not enumerated by the USB bus: {enumerator!r}")
    tokens = device_id.split("&")
    if len(tokens) == 1 and _ROOT_HUB.match(tokens[0]):
        return InstanceId(
            instance_id, enumerator, device_id, instance, NodeKind.ROOT_HUB, None, None, None, None
        )
    vendor = _VID.match(tokens[0])
    product = _PID.match(tokens[1]) if len(tokens) > 1 else None
    if vendor is None or product is None:
        raise ValueError("USB device id does not start with VID_xxxx&PID_xxxx")
    interface_number: int | None = None
    for token in tokens[2:]:
        match = _MI.match(token)
        if match is not None:
            interface_number = int(match.group(1), 16)
            break
    kind = NodeKind.DEVICE if interface_number is None else NodeKind.INTERFACE
    serial = instance if kind is NodeKind.DEVICE and not is_synthesized_instance(instance) else None
    return InstanceId(
        text=instance_id,
        enumerator=enumerator,
        device_id=device_id,
        instance=instance,
        kind=kind,
        vendor_id=int(vendor.group(1), 16),
        product_id=int(product.group(1), 16),
        interface_number=interface_number,
        serial=serial,
    )


def _usb_id_tokens(identifier: object) -> list[str] | None:
    """Split ``USB\\A&B&C`` into ``[A, B, C]``; ``None`` if it is not such an id."""
    if not isinstance(identifier, str) or len(identifier) >= MAX_DEVICE_ID_LEN:
        return None
    if not _ID_TEXT.match(identifier):
        return None
    prefix, separator, body = identifier.partition("\\")
    if prefix.upper() != USB_ENUMERATOR or not separator or not body or "\\" in body:
        return None
    return body.split("&")


def parse_hardware_ids(hardware_ids: Iterable[str]) -> HardwareIds:
    """Extract vendor id, product id, revision and interface number from hardware ids.

    Understands ``USB\\VID_vvvv&PID_pppp&REV_rrrr[&MI_nn]`` and the root hub form
    ``USB\\ROOT_HUB30&VIDvvvv&PIDpppp&REVrrrr``. Ids are listed most specific first, so
    the first id that states a value wins. Malformed ids are ignored.

    ``revision`` is ``bcdDevice``: ``REV_0100`` gives ``0x0100``.
    """
    vendor_id: int | None = None
    product_id: int | None = None
    revision: int | None = None
    interface_number: int | None = None
    for index, identifier in enumerate(hardware_ids):
        if index >= _MAX_ID_LIST:
            break
        tokens = _usb_id_tokens(identifier)
        if tokens is None:
            continue
        for token in tokens:
            if vendor_id is None and (match := _HW_VID.match(token)):
                vendor_id = int(match.group(1), 16)
            elif product_id is None and (match := _HW_PID.match(token)):
                product_id = int(match.group(1), 16)
            elif revision is None and (match := _HW_REV.match(token)):
                revision = int(match.group(1), 16)
            elif interface_number is None and (match := _MI.match(token)):
                interface_number = int(match.group(1), 16)
    return HardwareIds(vendor_id, product_id, revision, interface_number)


def _class_triple(tokens: list[str]) -> tuple[bool, tuple[int, int | None, int | None]] | None:
    """Parse ``[Dev]Class_cc[&SubClass_ss[&Prot_pp]]``.

    Returns ``(is_device_class, (class, subclass, protocol))`` with ``None`` for a part
    the id does not state, or ``None`` if the tokens are not a class id at all. Trailing
    tokens that do not fit make the whole id malformed rather than partly trusted.
    """
    head = _CLASS.match(tokens[0])
    if head is None or len(tokens) > 3:
        return None
    subclass: int | None = None
    protocol: int | None = None
    if len(tokens) > 1:
        match = _SUBCLASS.match(tokens[1])
        if match is None:
            return None
        subclass = int(match.group(1), 16)
    if len(tokens) > 2:
        match = _PROTOCOL.match(tokens[2])
        if match is None:
            return None
        protocol = int(match.group(1), 16)
    return head.group(1) is not None, (int(head.group(2), 16), subclass, protocol)


def _resolve_triples(
    stated: list[tuple[int, int | None, int | None]],
) -> tuple[UsbInterface, ...]:
    """Collapse the less specific forms of a class id into the most specific one.

    Windows lists ``Class_08&SubClass_06&Prot_50``, then ``Class_08&SubClass_06``, then
    ``Class_08`` for one interface. A shorter form adds an interface only if no longer
    form already covers it; missing parts become zero.
    """
    resolved: list[UsbInterface] = []
    # Longest forms first, keeping the given order within each length.
    for wanted in (3, 2, 1):
        for cls, subclass, protocol in stated:
            if 1 + (subclass is not None) + (protocol is not None) != wanted:
                continue
            candidate = UsbInterface(cls, subclass or 0, protocol or 0)
            if wanted == 3:
                covered = candidate in resolved
            else:
                covered = any(
                    known.cls == cls and (subclass is None or known.subcls == subclass)
                    for known in resolved
                )
            if not covered:
                resolved.append(candidate)
    return tuple(resolved)


def parse_compatible_ids(compatible_ids: Iterable[str]) -> CompatibleIds:
    """Extract class information from the compatible ids of a USB node.

    Understands ``USB\\Class_cc&SubClass_ss&Prot_pp`` and its two shorter forms,
    ``USB\\DevClass_...`` (the device-level class of a composite device),
    ``USB\\COMPOSITE``, the hub ids ``USB\\USB20_HUB`` and ``USB\\USB30_HUB``, and the
    vendor-qualified duplicates ``USB\\COMPAT_VID_vvvv&...`` that current Windows adds.
    Hex digits are accepted in either case. Malformed ids are ignored.
    """
    interface_triples: list[tuple[int, int | None, int | None]] = []
    device_triples: list[tuple[int, int | None, int | None]] = []
    composite = False
    hub = False
    tags: list[str] = []
    for index, identifier in enumerate(compatible_ids):
        if index >= _MAX_ID_LIST:
            break
        tokens = _usb_id_tokens(identifier)
        if tokens is None:
            continue
        if tokens[0].upper().startswith("COMPAT_VID_"):
            tokens = tokens[1:]
            if not tokens:
                continue
        head = tokens[0].upper()
        parsed = _class_triple(tokens)
        if parsed is not None:
            is_device_class, triple = parsed
            (device_triples if is_device_class else interface_triples).append(triple)
        elif len(tokens) == 1:
            if head == "COMPOSITE":
                composite = True
            elif head in _HUB_IDS:
                hub = True
            elif not head.startswith(_MS_COMPATIBLE_PREFIX):
                # Not an id this module knows the meaning of.
                continue
            if head not in tags:
                tags.append(head)
    interfaces = _resolve_triples(interface_triples)
    device_classes = _resolve_triples(device_triples)
    device_class = device_classes[0] if device_classes else None
    hub = (
        hub
        or any(interface.cls == UsbClass.HUB for interface in interfaces)
        or (device_class is not None and device_class.cls == UsbClass.HUB)
    )
    return CompatibleIds(interfaces, device_class, composite, hub, tuple(tags))


def parse_location_paths(location_paths: Iterable[str]) -> LocationPath | None:
    """Choose and parse a location path.

    A device usually has two: one through the PCI tree
    (``PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)#USB(3)``) and one through ACPI names. The
    first well-formed path that contains ``USBROOT(n)`` is preferred, because its
    ``USB(n)`` segments are the hub port numbers; failing that, the first well-formed
    path is used as it is.

    Returns:
        ``None`` if no path is well formed (``NAME(arg)`` segments joined by ``#``).
    """
    fallback: LocationPath | None = None
    for index, path in enumerate(location_paths):
        if index >= _MAX_ID_LIST:
            break
        if not isinstance(path, str) or not 0 < len(path) <= _MAX_LOCATION_PATH:
            continue
        segments = path.split("#")
        if not all(_LOCATION_SEGMENT.match(segment) for segment in segments):
            continue
        root_index = next(
            (i for i, segment in enumerate(segments) if _USB_ROOT_SEGMENT.match(segment)), None
        )
        if root_index is None:
            if fallback is None:
                fallback = LocationPath(path, None, ())
            continue
        ports: list[int] = []
        for segment in segments[root_index + 1 :]:
            match = _USB_PORT_SEGMENT.match(segment)
            if match is None:
                break
            ports.append(int(match.group(1)))
        return LocationPath(path, "#".join(segments[: root_index + 1]), tuple(ports))
    return fallback


# --------------------------------------------------------------------------------------
# Property values
# --------------------------------------------------------------------------------------


def decode_string(value: PropertyValue | None) -> str | None:
    """Decode a ``DEVPROP_TYPE_STRING`` property; ``None`` if absent, empty or mistyped."""
    if value is None or value[0] != DEVPROP_TYPE_STRING:
        return None
    return decode_utf16(value[1]) or None


def decode_string_list(value: PropertyValue | None) -> tuple[str, ...]:
    """Decode a ``DEVPROP_TYPE_STRING_LIST`` property; empty if absent or mistyped."""
    if value is None or value[0] != DEVPROP_TYPE_STRING_LIST:
        return ()
    return decode_multi_sz(value[1])


def decode_int(value: PropertyValue | None) -> int | None:
    """Decode a 32-bit integer property as an unsigned value.

    The documentation types ``Capabilities`` and ``RemovalPolicy`` as ``INT32`` while
    current Windows returns ``UINT32``; both are accepted. ``None`` if absent, mistyped
    or not four bytes long.
    """
    if value is None or value[0] not in (DEVPROP_TYPE_INT32, DEVPROP_TYPE_UINT32):
        return None
    if len(value[1]) != 4:
        return None
    return int.from_bytes(value[1], "little")


def decode_guid(value: PropertyValue | None) -> uuid.UUID | None:
    """Decode a ``DEVPROP_TYPE_GUID`` property; ``None`` if absent or malformed."""
    if value is None or value[0] != DEVPROP_TYPE_GUID or len(value[1]) != 16:
        return None
    return uuid.UUID(bytes_le=value[1])


def decode_filetime(value: PropertyValue | None) -> int | None:
    """Decode a ``DEVPROP_TYPE_FILETIME`` property to its 64-bit tick count."""
    if value is None or value[0] != DEVPROP_TYPE_FILETIME or len(value[1]) != 8:
        return None
    return int.from_bytes(value[1], "little")


# --------------------------------------------------------------------------------------
# Connection ids
# --------------------------------------------------------------------------------------


class ConnectionTokens:
    """Connection tokens for devices whose last-arrival time Windows does not report.

    A device instance id survives a re-plug, so it cannot tell two connections of the
    same device on the same port apart. Windows records ``DEVPKEY_Device_LastArrivalDate``
    for that purpose; where it is missing, a random token is issued the first time an
    instance is seen and kept until the instance is seen to be gone, either because an
    enumeration pass no longer lists it or because the monitor received its removal
    notification (:meth:`forget`). The next arrival then gets a new token.

    Tokens are random rather than counted, so a token from an earlier run of the service
    is never reissued to a different connection.

    Thread-safe: the caller's enumeration and the monitor's run concurrently.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Upper-cased instance id -> (token, sequence number at issue).
        self._tokens: dict[str, tuple[str, int]] = {}
        self._sequence = 0

    def begin_pass(self) -> int:
        """Mark the start of an enumeration pass; give the result to :meth:`end_pass`."""
        with self._lock:
            return self._sequence

    def token_for(self, instance_id: str) -> str:
        """Return the token of the current connection of ``instance_id``, issuing one."""
        key = instance_id.upper()
        with self._lock:
            known = self._tokens.get(key)
            if known is not None:
                return known[0]
            self._sequence += 1
            token = secrets.token_hex(8)
            self._tokens[key] = (token, self._sequence)
            return token

    def end_pass(self, marker: int, present: Iterable[str]) -> None:
        """Drop the tokens of instances a completed pass did not find.

        A token issued after ``marker`` is kept even if this pass missed its instance: it
        was issued by a concurrent pass that started later and saw a newer state.
        """
        keep = {instance_id.upper() for instance_id in present}
        with self._lock:
            for key in [k for k, (_t, issued) in self._tokens.items() if issued <= marker]:
                if key not in keep:
                    del self._tokens[key]

    def forget(self, instance_id: str) -> bool:
        """End the current connection of ``instance_id``; True if it had a token."""
        with self._lock:
            return self._tokens.pop(instance_id.upper(), None) is not None


def connection_id_for(
    instance_id: str, last_arrival: int | None, tokens: ConnectionTokens | None
) -> str | None:
    """Build the ``connection_id`` of one device.

    ``<instance id>@<last arrival>`` when Windows reports when the device last arrived
    (a FILETIME, so it changes on every arrival and is the same for every reader);
    otherwise ``<instance id>#<token>`` from ``tokens``; ``None`` if neither is available.
    """
    if last_arrival:
        return f"{instance_id}@{last_arrival}"
    if tokens is not None:
        return f"{instance_id}#{tokens.token_for(instance_id)}"
    return None


# --------------------------------------------------------------------------------------
# Reading the device tree
# --------------------------------------------------------------------------------------


def _parse_or_none(instance_id: str | None) -> InstanceId | None:
    if instance_id is None:
        return None
    try:
        return parse_instance_id(instance_id)
    except ValueError:
        return None


def _function_interfaces(api: WinApi, devinst: int, parent: InstanceId) -> list[UsbInterface]:
    """Read the class triples of a composite device from its ``&MI_nn`` child nodes."""
    functions: list[tuple[int, tuple[UsbInterface, ...]]] = []
    child = api.get_child(devinst)
    visited = 0
    while child is not None and visited < _MAX_INTERFACE_NODES:
        visited += 1
        node = _parse_or_none(api.get_device_id(child))
        if (
            node is not None
            and node.kind is NodeKind.INTERFACE
            and node.interface_number is not None
            and node.vendor_id == parent.vendor_id
            and node.product_id == parent.product_id
        ):
            compatible = parse_compatible_ids(
                decode_string_list(api.get_property(child, DEVPKEY_Device_CompatibleIds))
            )
            if compatible.interfaces:
                functions.append((node.interface_number, compatible.interfaces))
        child = api.get_sibling(child)
    functions.sort(key=lambda item: item[0])
    return [interface for _number, interfaces in functions for interface in interfaces]


def _windows_says_removable(api: WinApi, devinst: int) -> bool | None:
    """What Windows reports about one node: removable (True), fixed (False) or nothing.

    True if either the removal policy expects removal or the ``Removable`` capability is
    set; False if what is reported says fixed; ``None`` if neither property is readable
    or the policy holds a value this module does not know.
    """
    policy = decode_int(api.get_property(devinst, DEVPKEY_Device_RemovalPolicy))
    capabilities = decode_int(api.get_property(devinst, DEVPKEY_Device_Capabilities))
    if policy in (
        CM_REMOVAL_POLICY_EXPECT_ORDERLY_REMOVAL,
        CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL,
    ):
        return True
    if capabilities is not None and capabilities & CM_DEVCAP_REMOVABLE:
        return True
    if capabilities is not None or policy == CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL:
        return False
    return None


def _usb_ancestors(api: WinApi, devinst: int) -> Iterable[tuple[int, InstanceId]]:
    """Yield the USB nodes above a device, nearest first, stopping after the root hub."""
    node = devinst
    for _level in range(_MAX_TREE_DEPTH):
        parent = api.get_parent(node)
        if parent is None:
            return
        parsed = _parse_or_none(api.get_device_id(parent))
        if parsed is None:
            return
        yield parent, parsed
        if parsed.kind is NodeKind.ROOT_HUB:
            return
        node = parent


def _removable(api: WinApi, devinst: int, kind: NodeKind) -> bool | None:
    """Whether a device is external (True), built in (False) or unknown (None).

    ``False`` protects a device from enforcement, so it is claimed only for a device
    directly on a root-hub port that Windows reports as not removable (DESIGN.md 14.3).

    Which Windows properties this relies on, and why:

    * ``DEVPKEY_Device_Capabilities`` (``CM_DEVCAP_REMOVABLE``) is set by the hub driver
      for the port the device is on. For a **root-hub** port Windows takes it from the
      platform firmware: the ACPI ``_UPC`` (``PortIsConnectable``) and ``_PLD``
      (``UserVisible``) objects of that port. For a port of **any other hub** it takes it
      from the ``DeviceRemovable`` bitmap in that hub's own descriptor, which the hub
      supplies. A hub is a USB device like any other and may be hostile or simply wrong,
      so a "not removable" bit from it is never trusted: whatever sits behind a hub that
      is not a root hub is reported as external.
    * ``DEVPKEY_Device_RemovalPolicy`` is computed by Windows from those same
      capabilities, of the node and of its ancestors. It is read as a second opinion
      that can only make a device *more* external, never less.

    The root hub's own report is consulted too: a root hub belongs to a host controller,
    and a controller in a Thunderbolt or USB4 dock is itself removable, in which case
    nothing below it is built in.

    References: "How USB Devices are Assigned Container IDs" and
    ``DEVPKEY_Device_RemovalPolicy`` on Microsoft Learn; see
    ``docs/enforcement/windows.md``.
    """
    if kind is NodeKind.ROOT_HUB:
        # The hub of a host controller, not a device on a port: external only if the
        # controller is.
        return _windows_says_removable(api, devinst) is True
    parent = next(iter(_usb_ancestors(api, devinst)), None)
    if parent is None:
        # Not attached to anything this module recognises: make no claim.
        return None
    parent_devinst, parent_node = parent
    if parent_node.kind is not NodeKind.ROOT_HUB:
        return True
    own = _windows_says_removable(api, devinst)
    if own is not False:
        return own
    # A fixed root port: built in (False), unless the controller itself is removable.
    return _windows_says_removable(api, parent_devinst) is True


def _port_chain(api: WinApi, devinst: int) -> str | None:
    """Build ``USB(2)#USB(3)`` from port addresses when no location path is reported."""
    address = decode_int(api.get_property(devinst, DEVPKEY_Device_Address))
    if address is None:
        return None
    ports = [address]
    for ancestor, parsed in _usb_ancestors(api, devinst):
        if parsed.kind is not NodeKind.DEVICE:
            break
        above = decode_int(api.get_property(ancestor, DEVPKEY_Device_Address))
        if above is None:
            return None
        ports.append(above)
    return "#".join(f"USB({port})" for port in reversed(ports))


def _read_volumes(api: WinApi, devinst: int, index: VolumeIndex) -> tuple[tuple[Volume, ...], bool]:
    try:
        return volumes_for_device(api, devinst, index=index), True
    except BackendError as exc:
        # The device is still reported: hiding a present device because its volumes
        # could not be listed would hide it from policy too.
        _LOG.warning("could not list the volumes of a USB device: %s", exc)
        return (), False


def _read_device(
    api: WinApi, node: InstanceId, index: VolumeIndex, tokens: ConnectionTokens | None
) -> UsbDevice | None:
    """Build the description of one device or root hub; ``None`` if it has gone."""
    devinst = api.locate_devnode(node.text)
    if devinst is None:
        return None
    is_root_hub = node.kind is NodeKind.ROOT_HUB
    hardware = parse_hardware_ids(
        decode_string_list(api.get_property(devinst, DEVPKEY_Device_HardwareIds))
    )
    compatible = parse_compatible_ids(
        decode_string_list(api.get_property(devinst, DEVPKEY_Device_CompatibleIds))
    )
    capabilities = decode_int(api.get_property(devinst, DEVPKEY_Device_Capabilities))
    service = decode_string(api.get_property(devinst, DEVPKEY_Device_Service))
    is_hub = (
        is_root_hub or compatible.hub or (service is not None and service.upper() in _HUB_SERVICES)
    )

    interfaces: list[UsbInterface] = []
    if not is_hub:
        interfaces = _function_interfaces(api, devinst, node)
    if not interfaces:
        interfaces = list(compatible.interfaces)
    if is_hub and not interfaces:
        interfaces = [UsbInterface(UsbClass.HUB)]
    if compatible.device_class is not None:
        device_class = compatible.device_class.cls
    else:
        device_class = int(UsbClass.HUB) if is_hub else 0

    serial = node.serial
    if serial is not None and capabilities is not None and not capabilities & CM_DEVCAP_UNIQUEID:
        # Windows does not vouch for this instance id being unique, so it is not a
        # serial number whatever it looks like. Losing a serial lowers confidence, which
        # is the safe direction to be wrong in.
        serial = None

    # The product string is the device's own; UsbDevice sanitizes it. The description
    # comes from the driver's INF file and only goes into backend_data.
    description = decode_string(api.get_property(devinst, DEVPKEY_Device_DeviceDesc))
    product = decode_string(api.get_property(devinst, DEVPKEY_Device_BusReportedDeviceDesc))
    if product is None and is_root_hub:
        product = description

    location = parse_location_paths(
        decode_string_list(api.get_property(devinst, DEVPKEY_Device_LocationPaths))
    )
    if location is not None:
        bus_path: str | None = location.path
    else:
        # A root hub is not on a hub port, so it has no port chain to fall back on.
        bus_path = None if is_root_hub else _port_chain(api, devinst)
    removable = _removable(api, devinst, node.kind)
    last_arrival = decode_filetime(api.get_property(devinst, DEVPKEY_Device_LastArrivalDate))

    volumes: tuple[Volume, ...] = ()
    volumes_known = True
    if not is_hub:
        volumes, volumes_known = _read_volumes(api, devinst, index)

    # Read last: a node that vanished while it was being described has no status, and a
    # half-read description of a device that is no longer there must not be reported.
    status = api.get_status(devinst)
    if status is None:
        return None

    return UsbDevice(
        instance_id=node.text,
        vendor_id=node.vendor_id if node.vendor_id is not None else (hardware.vendor_id or 0),
        product_id=node.product_id if node.product_id is not None else (hardware.product_id or 0),
        serial=serial,
        manufacturer=None,
        product=product,
        bcd_device=hardware.revision,
        device_class=device_class,
        interfaces=tuple(interfaces),
        bus_path=bus_path,
        removable=removable,
        volumes=volumes,
        connection_id=connection_id_for(node.text, last_arrival, tokens),
        backend_data=_backend_data(
            api,
            devinst,
            node,
            status=status,
            service=service,
            description=description,
            location=location,
            composite=compatible.composite,
            tags=compatible.tags,
            volumes_known=volumes_known,
            last_arrival=last_arrival,
        ),
    )


def _backend_data(
    api: WinApi,
    devinst: int,
    node: InstanceId,
    *,
    status: tuple[int, int],
    service: str | None,
    description: str | None,
    location: LocationPath | None,
    composite: bool,
    tags: tuple[str, ...],
    volumes_known: bool,
    last_arrival: int | None,
) -> Mapping[str, str]:
    """Extras for the Windows enforcer and for display. Never part of the fingerprint.

    ``UsbDevice`` does not sanitize ``backend_data``, so the free-text values (driver
    description and manufacturer) are sanitized here; the rest are generated or are
    PnP identifiers restricted to printable ASCII.
    """
    flags, problem = status
    data: dict[str, str] = {
        "kind": node.kind.value,
        "dn_status": f"{flags:#010x}",
        "started": "1" if flags & DN_STARTED else "0",
        "disableable": "1" if flags & DN_DISABLEABLE else "0",
        "composite": "1" if composite else "0",
        "connection_basis": "last_arrival" if last_arrival else "token",
    }
    if flags & DN_HAS_PROBLEM:
        data["problem"] = str(problem)
    service = sanitize_device_text(service)
    if service:
        data["service"] = service
    description = sanitize_device_text(description)
    if description:
        data["description"] = description
    if tags:
        data["compatible_tags"] = ",".join(tags)
    if not volumes_known:
        data["volumes"] = "unavailable"
    if location is not None:
        data["location_path"] = location.path
        if location.controller is not None:
            data["controller"] = location.controller
            data["ports"] = ".".join(str(port) for port in location.ports)
    driver_manufacturer = sanitize_device_text(
        decode_string(api.get_property(devinst, DEVPKEY_Device_Manufacturer))
    )
    if driver_manufacturer:
        data["driver_manufacturer"] = driver_manufacturer
    class_guid = decode_guid(api.get_property(devinst, DEVPKEY_Device_ClassGuid))
    if class_guid is not None:
        data["class_guid"] = f"{{{class_guid}}}"
    container_id = decode_guid(api.get_property(devinst, DEVPKEY_Device_ContainerId))
    if container_id is not None:
        data["container_id"] = f"{{{container_id}}}"
    if last_arrival:
        # Changes each time the device arrives; it is what connection_id is built from.
        data["last_arrival"] = str(last_arrival)
    parent = api.get_parent(devinst)
    parent_id = api.get_device_id(parent) if parent is not None else None
    if parent_id:
        data["parent"] = parent_id
    return data


def enumerate_usb_devices(
    api: WinApi, *, tokens: ConnectionTokens | None = None
) -> list[UsbDevice]:
    """Return every USB device currently present, including hubs and root hubs.

    A device is listed whether or not it has a driver and whether or not it is started
    or disabled: presence is what matters to policy. Each ``&MI_nn`` interface node is
    folded into its parent device and is not listed on its own.

    Field sources: ``vendor_id``/``product_id``/``serial`` from the instance id;
    ``bcd_device`` from the hardware ids; ``interfaces`` and ``device_class`` from the
    compatible ids of the device and of its interface nodes; ``product`` from the
    bus-reported description; ``bus_path`` from the location paths (or, failing that,
    the chain of hub port numbers); ``removable`` from the port the device is on (see
    :func:`_removable`: False only directly on a root-hub port that Windows reports as
    fixed); ``connection_id`` from the instance id and the last-arrival time (or, failing
    that, a token from ``tokens``); ``volumes`` through
    :mod:`portlock.guard.windows.volumes`. ``manufacturer`` is always ``None``; see the
    module documentation for why.

    Root hubs are reported as hubs with the vendor and product ids Windows gives them,
    which are those of the host controller, and ``removable`` False unless the
    controller itself is removable.

    Args:
        api: the Windows API seam (a fake in tests).
        tokens: where to keep connection tokens for devices without a last-arrival
            time. Without it such devices have ``connection_id`` ``None``.

    Returns:
        The devices sorted by instance id, so that two passes over an unchanged system
        return equal lists.

    Raises:
        BackendError: if the device list itself cannot be obtained. A single device
            that disappears while it is being read is left out without an error.
    """
    index = VolumeIndex(api)
    marker = tokens.begin_pass() if tokens is not None else 0
    devices: dict[str, UsbDevice] = {}
    for text in api.present_device_ids(USB_ENUMERATOR):
        try:
            node = parse_instance_id(text)
        except ValueError as exc:
            _LOG.debug("ignoring a USB node with an id that does not parse: %s", exc)
            continue
        key = text.upper()
        if node.kind is NodeKind.INTERFACE or key in devices:
            continue
        device = _read_device(api, node, index, tokens)
        if device is not None:
            devices[key] = device
    if tokens is not None:
        tokens.end_pass(marker, devices)
    return [devices[key] for key in sorted(devices)]
