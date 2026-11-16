"""Read-only enumeration of USB devices from sysfs.

The kernel publishes every USB device as a directory of small text files. This module
turns ``<sysfs>/bus/usb/devices`` into :class:`~portlock.core.models.UsbDevice` values.
It opens files for reading and nothing else: no attribute is ever written here.

Three things about sysfs shape the code:

* **Names carry the topology.** ``usb1`` is the root hub of bus 1, ``1-2`` is the device on
  its port 2, ``1-2.3`` is the device on port 3 of that device (a hub), and ``1-2:1.0`` is
  interface 0 of configuration 1 of device ``1-2``. Devices and interfaces sit side by
  side in the bus directory, so they are told apart by name.
* **Everything can vanish mid-read.** A device that is being unplugged loses its files one
  by one. A missing, unreadable or half-written attribute is therefore normal: it reads
  as "unknown", and a device without ``idVendor`` and ``idProduct`` is skipped.
* **The strings come from the device.** ``serial``, ``manufacturer`` and ``product`` are
  copied from descriptors that the device supplies, so they are hostile input. This
  module only decodes them (undecodable bytes become U+FFFD). Replacing control and
  format characters and capping the length is done by
  :class:`~portlock.core.models.UsbDevice` itself, so that every backend applies exactly
  the same rule (DESIGN.md 14.7).

The sysfs root is a parameter so that everything here runs against a synthetic tree.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path

from portlock.core.errors import BackendError
from portlock.core.models import UsbClass, UsbDevice, UsbInterface, Volume

__all__ = [
    "DEFAULT_BOOT_ID",
    "SECTOR_BYTES",
    "connection_id",
    "decode_text",
    "is_device_name",
    "is_interface_name",
    "is_root_hub_name",
    "parent_device_name",
    "parse_descriptors",
    "parse_hex",
    "parse_removable",
    "read_attribute",
    "read_boot_id",
    "read_usb_devices",
]

_log = logging.getLogger(__name__)

#: The unit of every sysfs ``size`` attribute, whatever the device's own block size is.
SECTOR_BYTES = 512

#: A random UUID the kernel generates at every boot (``proc(5)``).
DEFAULT_BOOT_ID = Path("/proc/sys/kernel/random/boot_id")

# A sysfs attribute is at most one page; string descriptors are at most 126 UTF-16 units.
_MAX_ATTRIBUTE_BYTES = 4096
# The binary ``descriptors`` attribute: 18 bytes of device descriptor plus every
# configuration. 64 KiB is far beyond anything a real device has.
_MAX_DESCRIPTOR_BYTES = 65536
# A configuration has at most 32 interfaces (USB_MAXINTERFACES in the kernel).
_MAX_INTERFACES = 32

_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# The kernel prints the link speed in Mbit/s: 1.5, 12, 480, 5000, 10000, 20000, ...
_SPEED = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,3})?")

_ROOT_HUB = re.compile(r"usb([0-9]{1,5})")
_DEVICE = re.compile(r"([0-9]{1,5})-([0-9]{1,3}(?:\.[0-9]{1,3})*)")
_INTERFACE = re.compile(r"([0-9]{1,5})-([0-9]{1,3}(?:\.[0-9]{1,3})*):([0-9]{1,3})\.([0-9]{1,3})")
_HEX = re.compile(r"[0-9A-Fa-f]{1,8}")
_DECIMAL = re.compile(r"[0-9]{1,19}")
_DEV_NUMBER = re.compile(r"[0-9]{1,10}:[0-9]{1,10}")
_BLOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9!._+-]{0,63}")

_DESCRIPTOR_DEVICE = 0x01
_DESCRIPTOR_CONFIGURATION = 0x02
_DESCRIPTOR_INTERFACE = 0x04

# How far below an interface directory a ``block`` directory is looked for. usb-storage
# and UAS put it four levels down: host6/target6:0:0/6:0:0:0/block.
_MAX_BLOCK_DEPTH = 6
_SKIPPED_DIRECTORIES = frozenset({"power", "subsystem", "driver", "firmware_node"})


def is_root_hub_name(name: str) -> bool:
    """True for a root hub directory name such as ``usb1``."""
    return _ROOT_HUB.fullmatch(name) is not None


def is_device_name(name: str) -> bool:
    """True for a device directory name: ``usb1``, ``1-2`` or ``1-2.3``.

    Interface names (``1-2:1.0``) and anything else found in the bus directory are not
    device names.
    """
    return _ROOT_HUB.fullmatch(name) is not None or _DEVICE.fullmatch(name) is not None


def is_interface_name(name: str) -> bool:
    """True for an interface directory name such as ``1-2:1.0`` or ``1-2.3:1.1``."""
    return _INTERFACE.fullmatch(name) is not None


def parent_device_name(name: str) -> str | None:
    """The name of the device that ``name`` is plugged into.

    ``1-2.3`` hangs off ``1-2``, ``1-2`` hangs off the root hub ``usb1``, and a root hub
    has no parent.

    Raises:
        ValueError: if ``name`` is not a device name.
    """
    if _ROOT_HUB.fullmatch(name):
        return None
    match = _DEVICE.fullmatch(name)
    if match is None:
        raise ValueError(f"not a USB device name: {name!r}")
    bus, path = match.groups()
    head, dot, _port = path.rpartition(".")
    return f"{bus}-{head}" if dot else f"usb{bus}"


def read_attribute(path: str | os.PathLike[str], limit: int = _MAX_ATTRIBUTE_BYTES) -> bytes | None:
    """Read one sysfs attribute as raw bytes.

    Args:
        path: the attribute file.
        limit: read at most this many bytes.

    Returns:
        The content, or ``None`` if the file is missing, unreadable, or went away while it
        was being read. Unplugging a device makes all three happen, so none is an error.
    """
    try:
        with open(path, "rb", buffering=0) as stream:
            return stream.read(limit)
    except OSError:
        return None


def decode_text(raw: bytes | None) -> str | None:
    """Decode a string attribute such as ``product``.

    Bytes that are not UTF-8 become U+FFFD and surrounding whitespace (including the
    newline sysfs appends) is removed. Nothing else is done here: the text is still
    untrusted, and :class:`~portlock.core.models.UsbDevice` replaces its control and
    format characters and caps its length when the device object is built.

    Returns:
        The text, or ``None`` if there is nothing left.
    """
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace").strip() or None


def read_boot_id(path: str | os.PathLike[str] = DEFAULT_BOOT_ID) -> str | None:
    """Read the kernel's boot id: a random UUID that is new at every boot.

    Returns:
        The id in lowercase, or ``None`` if the file is missing, unreadable or does not
        hold a UUID (it is then better to have no connection ids than wrong ones).
    """
    raw = read_attribute(path, 64)
    if raw is None:
        return None
    text = raw.decode("ascii", errors="replace").strip().lower()
    return text if _BOOT_ID.fullmatch(text) else None


def connection_id(boot_id: str, busnum: int, devnum: int) -> str:
    """The token that tells one physical connection from every other one.

    ``devnum`` is assigned afresh by the kernel every time a device is enumerated on a
    bus, so a re-plug into the same port gets a new value, while the sysfs path (the
    ``instance_id``) stays the same. ``devnum`` restarts at every boot, hence the boot id.

    Limitation: the kernel hands out ``devnum`` round-robin from 1 to 127 per bus, so
    after 127 further enumerations on the same bus during one boot a value can come back.
    A connection id is therefore unique among the connections a caller can still be
    holding state for, not for ever.

    Raises:
        ValueError: if ``boot_id`` is not a lowercase UUID or a number is out of range.
    """
    if not _BOOT_ID.fullmatch(boot_id):
        raise ValueError("boot_id must be a lowercase UUID")
    for name, value in (("busnum", busnum), ("devnum", devnum)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 0xFFFF:
            raise ValueError(f"{name} must be an integer between 1 and 65535, got {value!r}")
    return f"{boot_id}:{busnum}:{devnum}"


def parse_hex(raw: bytes | None, upper: int) -> int | None:
    """Parse a hexadecimal attribute such as ``idVendor`` (``1209``) or ``bDeviceClass``.

    Returns:
        The value, or ``None`` if the attribute is absent, is not plain hexadecimal, or
        exceeds ``upper``.
    """
    return _parse_number(raw, _HEX, 16, upper)


def parse_removable(
    removable: bytes | None,
    connect_type: bytes | None = None,
    *,
    on_root_hub_port: bool = True,
) -> bool | None:
    """Decide whether a device sits on an external port, from its own attributes.

    Built in (``False``) has one meaning only (DESIGN.md 14.3): the device is directly on
    a root-hub port whose ``connect_type`` is ``hardwired``. For a root-hub port that
    attribute comes from platform firmware (ACPI ``_UPC``/``_PLD``). Everything else a
    device or a hub can claim is not believed in that direction:

    * ``connect_type`` of a port on an external hub is whatever the hub and its driver
      say, so ``hardwired`` there proves nothing;
    * the ``removable`` attribute is ``fixed`` whenever the hub's own descriptor marks the
      port non-removable, which a malicious hub does at will;
    * ``not used`` describes a port where firmware expects no device at all; a device
      found there is not thereby built in.

    Claims in the other direction are believed, because they only cost the device
    protection: ``hotplug`` or ``removable`` make it external.

    Args:
        removable: the device's ``removable`` attribute.
        connect_type: the ``connect_type`` attribute of the port it is plugged into.
        on_root_hub_port: whether that port belongs to a root hub. ``False`` for a port
            of any other hub, which can then never yield ``False``.

    Returns:
        ``True`` for external, ``False`` for built in, ``None`` if it cannot be told.
    """
    port = _token(connect_type)
    if port == "hardwired" and on_root_hub_port:
        return False
    if port == "hotplug" or _token(removable) == "removable":
        return True
    return None


def parse_descriptors(
    blob: bytes | None, configuration: int | None = None
) -> tuple[UsbInterface, ...]:
    """Extract interface descriptors from a device's cached ``descriptors`` attribute.

    The attribute holds the raw device descriptor followed by every configuration with
    its interfaces and endpoints. It is present even while a device is unauthorized or
    still being set up, which is exactly when the interface directories are missing.

    Args:
        blob: the attribute content.
        configuration: the active ``bConfigurationValue``. The interfaces of that
            configuration are returned; if it is ``None`` or not found, the first
            configuration is used (the one the kernel normally selects).

    Returns:
        One entry per interface number, in ascending order, taken from alternate setting
        0 where the interface has one. Parsing stops at the first malformed descriptor, as
        the kernel's own parser does, and returns what was valid up to that point.
    """
    if not blob:
        return ()
    data = blob[:_MAX_DESCRIPTOR_BYTES]
    # Per configuration, in the order found: interface number -> (alternate, interface).
    configurations: list[tuple[int, dict[int, tuple[int, UsbInterface]]]] = []
    offset = 0
    while offset + 2 <= len(data):
        length, kind = data[offset], data[offset + 1]
        if length < 2 or offset + length > len(data):
            break
        if kind == _DESCRIPTOR_CONFIGURATION and length >= 9:
            configurations.append((data[offset + 5], {}))
        elif kind == _DESCRIPTOR_INTERFACE and length >= 9 and configurations:
            number, alternate = data[offset + 2], data[offset + 3]
            interface = UsbInterface(data[offset + 5], data[offset + 6], data[offset + 7])
            found = configurations[-1][1]
            if number not in found:
                if len(found) < _MAX_INTERFACES:
                    found[number] = (alternate, interface)
            elif alternate < found[number][0]:
                found[number] = (alternate, interface)
        offset += length
    if not configurations:
        return ()
    chosen = next((found for value, found in configurations if value == configuration), None)
    if chosen is None:
        chosen = configurations[0][1]
    return tuple(interface for _number, (_alternate, interface) in sorted(chosen.items()))


def read_usb_devices(
    sysfs_root: Path = Path("/sys"), *, boot_id: str | None = None
) -> list[UsbDevice]:
    """List every USB device that sysfs shows, root hubs included.

    For each device directory under ``<sysfs_root>/bus/usb/devices`` this reads
    ``idVendor``, ``idProduct``, ``serial``, ``manufacturer``, ``product``, ``bcdDevice``
    and ``bDeviceClass``, the class triple of each interface, and the block devices
    found beneath its interfaces.

    * ``bus_path`` is the directory name (``1-2.3``) and ``instance_id`` the resolved
      sysfs path of the device.
    * ``connection_id`` is :func:`connection_id` of ``boot_id``, ``busnum`` and
      ``devnum``; ``None`` if no boot id is given or either number cannot be read.
    * ``removable`` follows :func:`parse_removable`: ``False`` only for a device directly
      on a root-hub port that firmware calls ``hardwired``. A device behind any other hub
      is never built in, whatever that hub says about its ports, and is external if the
      hub is. A root hub is reported as ``False``: it is the host controller itself, not
      something plugged into a port.
    * Each disk and partition becomes a :class:`~portlock.core.models.Volume` whose
      ``size_bytes`` is the ``size`` attribute times 512 and whose ``read_only`` is the
      ``ro`` attribute. Mount points are added separately, by
      :func:`portlock.guard.linux.mounts.attach_mounts`.
    * ``backend_data`` carries ``sysfs_name``, ``root_hub``, ``interface_source``
      (``sysfs``, ``descriptors`` or ``none``) and, where readable, ``busnum``,
      ``devnum``, ``authorized``, ``speed`` and one ``blockdev:<node>`` entry per volume
      holding its ``major:minor`` number.

    Devices that are half removed (no readable ``idVendor`` or ``idProduct``) are left
    out. Attributes that are missing, unreadable or not UTF-8 never raise.

    Args:
        sysfs_root: where sysfs is mounted.
        boot_id: the kernel's boot id (:func:`read_boot_id`), or ``None``.

    Returns:
        The devices, ordered so that a hub precedes what is plugged into it. An empty
        list if the kernel has no USB bus at all.

    Raises:
        BackendError: if ``sysfs_root`` is not a directory, or the bus directory exists
            but cannot be listed.
        ValueError: if ``boot_id`` is given and is not a lowercase UUID.
    """
    if boot_id is not None and not _BOOT_ID.fullmatch(boot_id):
        raise ValueError("boot_id must be a lowercase UUID")
    root = Path(sysfs_root)
    if not root.is_dir():
        raise BackendError(f"sysfs is not available at {root}")
    bus_directory = root / "bus" / "usb" / "devices"
    try:
        names = os.listdir(bus_directory)
    except (FileNotFoundError, NotADirectoryError):
        # No USB core in this kernel (or none loaded yet): there are no USB devices.
        return []
    except OSError as exc:
        raise BackendError(f"cannot list {bus_directory}: {exc.strerror or exc}") from exc

    found: dict[str, _Reading] = {}
    for name in names:
        if not is_device_name(name):
            continue
        reading = _read_device(bus_directory / name, name, boot_id)
        if reading is not None:
            found[name] = reading

    ordered = sorted(found, key=_topology_key)
    removable: dict[str, bool | None] = {}
    devices: list[UsbDevice] = []
    for name in ordered:
        reading = found[name]
        removable[name] = _effective_removable(name, reading.own_removable, removable)
        devices.append(replace(reading.device, removable=removable[name]))
    return devices


@dataclass(frozen=True, slots=True)
class _Reading:
    """A device as read, before its position in the hub tree is taken into account."""

    device: UsbDevice
    own_removable: bool | None


def _parse_number(raw: bytes | None, pattern: re.Pattern[str], base: int, upper: int) -> int | None:
    if raw is None:
        return None
    text = raw.decode("ascii", errors="replace").strip()
    if not pattern.fullmatch(text):
        return None
    value = int(text, base)
    return value if value <= upper else None


def _token(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    return raw.decode("ascii", errors="replace").strip().lower() or None


def _topology_key(name: str) -> tuple[int, tuple[int, ...]]:
    """Sort key that puts a root hub first on its bus and a hub before its children."""
    root = _ROOT_HUB.fullmatch(name)
    if root is not None:
        return int(root.group(1)), ()
    match = _DEVICE.fullmatch(name)
    if match is None:
        raise ValueError(f"not a USB device name: {name!r}")
    return int(match.group(1)), tuple(int(port) for port in match.group(2).split("."))


def _effective_removable(
    name: str, own: bool | None, decided: dict[str, bool | None]
) -> bool | None:
    parent = parent_device_name(name)
    if parent is None:
        return False
    if is_root_hub_name(parent):
        return own
    # Behind a hub, ``own`` is never False (parse_removable saw to that). Whatever is
    # plugged into an external hub is external too. A parent that is missing was
    # unplugged while the tree was being read and says nothing.
    if decided.get(parent) is True:
        return True
    return own


def _read_device(directory: Path, name: str, boot_id: str | None) -> _Reading | None:
    vendor_id = parse_hex(read_attribute(directory / "idVendor"), 0xFFFF)
    product_id = parse_hex(read_attribute(directory / "idProduct"), 0xFFFF)
    if vendor_id is None or product_id is None:
        # Not a device any more (being removed), or not one we can identify.
        return None

    root_hub = is_root_hub_name(name)
    device_class = parse_hex(read_attribute(directory / "bDeviceClass"), 0xFF)
    if device_class is None:
        device_class = int(UsbClass.HUB) if root_hub else 0

    interface_directories = _interface_directories(directory, name)
    interfaces, source = _read_interfaces(directory, interface_directories)
    if root_hub and not interfaces:
        # A root hub is a hub even when its attributes cannot be read.
        interfaces = (UsbInterface(int(UsbClass.HUB), 0, 0),)

    volumes: list[Volume] = []
    extras: dict[str, str] = {
        "sysfs_name": name,
        "root_hub": "1" if root_hub else "0",
        "interface_source": source,
    }
    for interface_directory in interface_directories:
        for volume, number in _read_volumes(interface_directory):
            volumes.append(volume)
            if number is not None:
                extras[f"blockdev:{volume.device_node}"] = number
    numbers: dict[str, int] = {}
    for attribute, upper in (("busnum", 0xFFFF), ("devnum", 0xFFFF), ("authorized", 1)):
        value = _parse_number(read_attribute(directory / attribute), _DECIMAL, 10, upper)
        if value is not None:
            numbers[attribute] = value
            extras[attribute] = str(value)
    # The speed is printed by the kernel, but it is kept only if it has the kernel's shape.
    speed = _token(read_attribute(directory / "speed"))
    if speed is not None and _SPEED.fullmatch(speed):
        extras["speed"] = speed
    busnum, devnum = numbers.get("busnum"), numbers.get("devnum")
    connection = None
    if boot_id is not None and busnum and devnum:
        connection = connection_id(boot_id, busnum, devnum)

    try:
        device = UsbDevice(
            # realpath gives the device's one true location under /sys/devices; the bus
            # directory only holds symlinks to it.
            instance_id=os.path.realpath(directory),
            vendor_id=vendor_id,
            product_id=product_id,
            serial=decode_text(read_attribute(directory / "serial")),
            manufacturer=decode_text(read_attribute(directory / "manufacturer")),
            product=decode_text(read_attribute(directory / "product")),
            bcd_device=parse_hex(read_attribute(directory / "bcdDevice"), 0xFFFF),
            device_class=device_class,
            interfaces=interfaces,
            bus_path=name,
            volumes=tuple(volumes),
            connection_id=connection,
            backend_data=extras,
        )
    except ValueError as exc:
        _log.warning("ignoring USB device %s: %s", name, exc)
        return None
    parent = parent_device_name(name)
    own_removable = parse_removable(
        read_attribute(directory / "removable"),
        read_attribute(directory / "port" / "connect_type"),
        on_root_hub_port=parent is not None and is_root_hub_name(parent),
    )
    return _Reading(device, own_removable)


def _interface_directories(directory: Path, name: str) -> list[Path]:
    """The interface directories of one device, ordered by configuration and number."""
    root = _ROOT_HUB.fullmatch(name)
    # A root hub's own interface is named after the bus with path 0: usb1 has 1-0:1.0.
    prefix = f"{root.group(1)}-0:" if root is not None else f"{name}:"
    found: list[tuple[int, int, Path]] = []
    for entry in _list_directory(directory):
        if not entry.startswith(prefix):
            continue
        match = _INTERFACE.fullmatch(entry)
        if match is None:
            continue
        path = directory / entry
        if path.is_dir():
            found.append((int(match.group(3)), int(match.group(4)), path))
    return [path for _configuration, _number, path in sorted(found)]


def _read_interfaces(
    directory: Path, interface_directories: list[Path]
) -> tuple[tuple[UsbInterface, ...], str]:
    from_sysfs: list[UsbInterface] = []
    for path in interface_directories:
        cls = parse_hex(read_attribute(path / "bInterfaceClass"), 0xFF)
        if cls is None:
            continue
        subcls = parse_hex(read_attribute(path / "bInterfaceSubClass"), 0xFF)
        protocol = parse_hex(read_attribute(path / "bInterfaceProtocol"), 0xFF)
        from_sysfs.append(UsbInterface(cls, subcls or 0, protocol or 0))

    # The kernel announces a device before it has created the interface directories, and
    # an unauthorized device never gets any. In both cases the directories understate
    # what the device is: a keyboard would look like "nothing recognisable". The cached
    # descriptors are complete from the first instant, so they fill the gap.
    expected = _parse_number(read_attribute(directory / "bNumInterfaces"), _DECIMAL, 10, 0xFF)
    if from_sysfs and (expected is None or len(from_sysfs) >= expected):
        return tuple(from_sysfs), "sysfs"
    configuration = _parse_number(
        read_attribute(directory / "bConfigurationValue"), _DECIMAL, 10, 0xFF
    )
    from_descriptors = parse_descriptors(
        read_attribute(directory / "descriptors", _MAX_DESCRIPTOR_BYTES), configuration
    )
    if len(from_descriptors) > len(from_sysfs):
        return from_descriptors, "descriptors"
    return tuple(from_sysfs), "sysfs" if from_sysfs else "none"


def _read_volumes(interface_directory: Path) -> list[tuple[Volume, str | None]]:
    """Disks and partitions beneath one interface, each with its ``major:minor``."""
    volumes: list[tuple[Volume, str | None]] = []
    for block_directory in _find_block_directories(interface_directory):
        for disk in _list_directory(block_directory):
            disk_directory = block_directory / disk
            if not _BLOCK_NAME.fullmatch(disk) or not disk_directory.is_dir():
                continue
            volumes.append(_read_block_device(disk_directory, disk))
            partitions: list[tuple[int, str]] = []
            for child in _list_directory(disk_directory):
                # Only a partition has a ``partition`` attribute (its number); the other
                # subdirectories of a disk (queue, holders, power, ...) do not.
                number = _parse_number(
                    read_attribute(disk_directory / child / "partition"), _DECIMAL, 10, 0xFFFF
                )
                if number is not None and _BLOCK_NAME.fullmatch(child):
                    partitions.append((number, child))
            for _number, child in sorted(partitions):
                volumes.append(_read_block_device(disk_directory / child, child))
    return volumes


def _read_block_device(directory: Path, name: str) -> tuple[Volume, str | None]:
    sectors = _parse_number(read_attribute(directory / "size"), _DECIMAL, 10, 2**63 - 1)
    read_only = _parse_number(read_attribute(directory / "ro"), _DECIMAL, 10, 1)
    number = _token(read_attribute(directory / "dev"))
    volume = Volume(
        # devtmpfs turns the "!" of names like cciss!c0d0 into a directory separator.
        device_node="/dev/" + name.replace("!", "/"),
        size_bytes=sectors * SECTOR_BYTES if sectors is not None else None,
        read_only=bool(read_only) if read_only is not None else None,
    )
    return volume, number if number and _DEV_NUMBER.fullmatch(number) else None


def _find_block_directories(interface_directory: Path) -> list[Path]:
    """Directories named ``block`` beneath an interface.

    The walk is bounded in depth and never follows a symlink, so it cannot leave the
    interface's own subtree or loop.
    """
    found: list[Path] = []
    pending: list[tuple[Path, int]] = [(interface_directory, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = [entry.name for entry in entries if _is_real_directory(entry)]
        except OSError:
            continue
        for child in children:
            if child in _SKIPPED_DIRECTORIES or child.startswith("ep_"):
                continue
            if child == "block":
                found.append(directory / child)
            elif depth + 1 < _MAX_BLOCK_DEPTH:
                pending.append((directory / child, depth + 1))
    return sorted(found)


def _is_real_directory(entry: os.DirEntry[str]) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def _list_directory(directory: Path) -> list[str]:
    try:
        return sorted(os.listdir(directory))
    except OSError:
        return []
