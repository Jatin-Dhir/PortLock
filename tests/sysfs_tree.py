"""Synthetic sysfs trees for the Linux backend tests.

:class:`SysfsTree` builds, inside a temporary directory, the part of ``/sys`` that the
Linux backend reads: ``bus/usb/devices`` with a directory of small text files per device.
Nothing here touches the real ``/sys``, and every value is made up (the vendor id is from
the pid.codes test range, serials start with ``TEST``).

Two layouts, because the real one cannot exist on Windows:

* **nested** (Linux): devices live under ``devices/<controller>/usb1/1-2/...`` exactly as
  in the kernel, hubs contain their children, interface directories (``1-2:1.0``) and SCSI
  directories (``target6:0:0``) carry their colons, and ``bus/usb/devices`` holds
  symlinks.
* **flat** (Windows): a colon cannot appear in a file name and symlinks need a
  privilege, so each device is a plain directory directly in ``bus/usb/devices`` and has
  no interface directories. Its ``descriptors`` attribute still describes its interfaces.

Tests that need interface directories or block devices are marked ``linux_only``.

The module also provides the other half of a synthetic kernel: :func:`uevent_message`
builds the bytes of a kernel uevent, and :class:`QueueTransport` stands in for the netlink
socket so that a test decides exactly which messages arrive, from whom, and in what order.
"""

from __future__ import annotations

import os
import queue
import shutil
import struct
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

from portlock.guard.linux.netlink import Datagram

Triple = tuple[int, int, int]

MASS_STORAGE: Triple = (0x08, 0x06, 0x50)
BOOT_KEYBOARD: Triple = (0x03, 0x01, 0x01)
BOOT_MOUSE: Triple = (0x03, 0x01, 0x02)
HUB: Triple = (0x09, 0x00, 0x00)
MTP: Triple = (0x06, 0x01, 0x01)
ADB: Triple = (0xFF, 0x42, 0x01)
VIDEO_CONTROL: Triple = (0x0E, 0x01, 0x00)
VIDEO_STREAMING: Triple = (0x0E, 0x02, 0x00)

#: True where the kernel's real layout (colons in names, symlinks) can be built.
NESTED = sys.platform != "win32"


def build_descriptors(
    interfaces: Sequence[Triple],
    *,
    vendor_id: int = 0x1209,
    product_id: int = 0x0001,
    bcd_device: int = 0x0100,
    device_class: int = 0x00,
    configuration: int = 1,
    alternates: Sequence[tuple[int, int, Triple]] = (),
) -> bytes:
    """The content of a ``descriptors`` attribute: device, configuration, interfaces.

    Args:
        interfaces: class triple of each interface, numbered from 0, alternate setting 0.
        alternates: extra ``(interface number, alternate setting, triple)`` descriptors.
    """
    device = struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01, 0x0200, device_class, 0, 0, 64, vendor_id, product_id, bcd_device, 1, 2, 3, 1,
    )  # fmt: skip
    body = b""
    for number, triple in enumerate(interfaces):
        body += _interface_descriptor(number, 0, triple)
    for number, alternate, triple in alternates:
        body += _interface_descriptor(number, alternate, triple)
    header = struct.pack(
        "<BBHBBBBB", 9, 0x02, 9 + len(body), len(interfaces), configuration, 0, 0x80, 50
    )
    return device + header + body


def _interface_descriptor(number: int, alternate: int, triple: Triple) -> bytes:
    interface = struct.pack("<BBBBBBBBB", 9, 0x04, number, alternate, 1, *triple, 0)
    endpoint = struct.pack("<BBBBHB", 7, 0x05, 0x81, 0x02, 512, 0)
    return interface + endpoint


class SysfsTree:
    """A fake ``/sys`` rooted at ``root``.

    Pass :attr:`root` to ``read_usb_devices`` or ``LinuxBackend(sysfs_root=...)``.

    Args:
        root: an empty directory, normally ``tmp_path / "sys"``.
        controller: where the host controller sits below ``devices/`` in the nested
            layout. The default has no colon; pass ``pci0000:00/0000:00:14.0`` for the
            shape of a real PC.
    """

    def __init__(self, root: Path, *, controller: str = "platform/vhci_hcd.0") -> None:
        self.root = root
        self.nested = NESTED
        self.bus_directory = root / "bus" / "usb" / "devices"
        self.bus_directory.mkdir(parents=True)
        self._controller = root / "devices" / Path(controller)
        self._device_numbers: dict[int, int] = {}

    # -- locations --------------------------------------------------------------------

    def device_directory(self, name: str) -> Path:
        """The real directory of device ``name`` (``usb1``, ``1-2``, ``1-2.3``)."""
        if not self.nested:
            return self.bus_directory / name
        chain = [name]
        while (parent := _parent(chain[-1])) is not None:
            chain.append(parent)
        return self._controller.joinpath(*reversed(chain))

    def interface_directory(self, device: str, number: int = 0, configuration: int = 1) -> Path:
        """The directory of one interface of ``device`` (it need not exist yet)."""
        return self.device_directory(device) / _interface_name(device, number, configuration)

    # -- building ---------------------------------------------------------------------

    def add_root_hub(self, bus: int = 1) -> str:
        """Add the root hub ``usb<bus>`` with the attributes the kernel gives one."""
        name = f"usb{bus}"
        directory = self._create_device(
            name,
            vendor_id=0x1D6B,
            product_id=0x0002,
            bcd_device=0x0601,
            device_class=0x09,
            serial="vhci_hcd.0",
            manufacturer="Linux 6.1.0-test vhci_hcd",
            product="USB/IP Virtual Host Controller",
            interfaces=(HUB,),
            removable="unknown",
            devnum=1,
            authorized=True,
            interface_directories=None,
            descriptors=True,
        )
        _write(directory / "authorized_default", "1")
        _write(directory / "interface_authorized_default", "1")
        return name

    def add_device(
        self,
        name: str,
        *,
        vendor_id: int = 0x1209,
        product_id: int = 0x0001,
        serial: str | None = "TEST0001A7C3",
        manufacturer: str | None = "Example Corp",
        product: str | None = "Example Flash 16GB",
        bcd_device: int = 0x0100,
        device_class: int = 0x00,
        interfaces: Sequence[Triple] = (MASS_STORAGE,),
        removable: str | None = "removable",
        connect_type: str | None = None,
        devnum: int | None = None,
        authorized: bool = True,
        interface_directories: bool | None = None,
        descriptors: bool = True,
    ) -> str:
        """Add a device. ``name`` gives its position: ``1-2`` or, behind a hub, ``1-2.3``.

        Args:
            removable: content of the ``removable`` attribute, or ``None`` to omit it.
            connect_type: content of the port's ``connect_type``, or ``None`` for no port.
            authorized: ``False`` builds a deauthorized device: no interface directories,
                empty configuration attributes, descriptors still present.
            interface_directories: ``True`` requires them (fails on Windows), ``False``
                omits them, ``None`` creates them where the platform can.
            descriptors: whether to write the binary ``descriptors`` attribute.
        """
        self._create_device(
            name,
            vendor_id=vendor_id,
            product_id=product_id,
            bcd_device=bcd_device,
            device_class=device_class,
            serial=serial,
            manufacturer=manufacturer,
            product=product,
            interfaces=tuple(interfaces),
            removable=removable,
            devnum=devnum,
            authorized=authorized,
            interface_directories=interface_directories,
            descriptors=descriptors,
        )
        if connect_type is not None:
            self.set_connect_type(name, connect_type)
        return name

    def add_interface(
        self, device: str, number: int, triple: Triple, *, configuration: int = 1
    ) -> Path:
        """Create one interface directory. Linux only: its name contains a colon."""
        self._require_nested("interface directories")
        directory = self.interface_directory(device, number, configuration)
        directory.mkdir()
        _write(directory / "bInterfaceClass", f"{triple[0]:02x}")
        _write(directory / "bInterfaceSubClass", f"{triple[1]:02x}")
        _write(directory / "bInterfaceProtocol", f"{triple[2]:02x}")
        _write(directory / "bInterfaceNumber", f"{number:02x}")
        _write(directory / "bAlternateSetting", " 0")
        _write(directory / "bNumEndpoints", "01")
        _write(directory / "authorized", "1")
        (directory / "ep_81").mkdir()
        (directory / "power").mkdir()
        return directory

    def add_disk(
        self,
        device: str,
        name: str = "sdb",
        *,
        sectors: int = 31_250_000,
        read_only: bool = False,
        partitions: Sequence[tuple[str, int]] = (),
        interface: int = 0,
        host: int = 6,
        number: str | None = "8:16",
    ) -> Path:
        """Add a SCSI disk below a mass-storage interface, with optional partitions.

        Args:
            sectors: the ``size`` attribute, in 512-byte sectors.
            partitions: ``(name, sectors)`` for each partition, numbered from 1.
            number: the disk's ``major:minor``; partitions get the following minors.
                ``None`` omits the ``dev`` attributes.
        """
        self._require_nested("block devices")
        disk = (
            self.interface_directory(device, interface)
            / f"host{host}"
            / f"target{host}:0:0"
            / f"{host}:0:0:0"
            / "block"
            / name
        )
        disk.mkdir(parents=True)
        _write(disk / "size", str(sectors))
        _write(disk / "ro", "1" if read_only else "0")
        _write(disk / "removable", "1")
        if number is not None:
            _write(disk / "dev", number)
        # Subdirectories every real disk has; none of them is a partition.
        for extra in ("queue", "holders", "slaves", "power"):
            (disk / extra).mkdir()
        for index, (partition, size) in enumerate(partitions, start=1):
            minor = None
            if number is not None:
                major, _, base = number.partition(":")
                minor = f"{major}:{int(base) + index}"
            self.add_partition(disk, partition, index, size, read_only=read_only, number=minor)
        return disk

    def add_partition(
        self,
        disk: Path,
        name: str,
        index: int,
        sectors: int,
        *,
        read_only: bool = False,
        number: str | None = None,
    ) -> Path:
        """Add one partition directory to a disk created by :meth:`add_disk`."""
        directory = disk / name
        directory.mkdir()
        _write(directory / "partition", str(index))
        _write(directory / "size", str(sectors))
        _write(directory / "start", str(2048 * index))
        _write(directory / "ro", "1" if read_only else "0")
        if number is not None:
            _write(directory / "dev", number)
        return directory

    # -- changing ---------------------------------------------------------------------

    def set_attribute(self, device: str, attribute: str, value: str | bytes) -> None:
        """Write an attribute. ``str`` gets the trailing newline sysfs adds; bytes are raw."""
        path = self.device_directory(device) / attribute
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            _write(path, value)

    def delete_attribute(self, device: str, attribute: str) -> None:
        (self.device_directory(device) / attribute).unlink()

    def make_unreadable(self, device: str, attribute: str) -> None:
        """Make reading an attribute fail with an ``OSError``, for any user on any OS.

        The file is replaced by a directory. Permission bits would not do: root ignores
        them, and Windows has none.
        """
        path = self.device_directory(device) / attribute
        path.unlink(missing_ok=True)
        path.mkdir()

    def set_connect_type(self, device: str, value: str) -> None:
        """Give the port that ``device`` is plugged into a ``connect_type``."""
        directory = self.device_directory(device)
        if not self.nested:
            (directory / "port").mkdir(exist_ok=True)
            _write(directory / "port" / "connect_type", value)
            return
        parent = _parent(device)
        if parent is None:
            raise ValueError("a root hub is not plugged into a port")
        port_number = device.rpartition(".")[2].rpartition("-")[2]
        hub_interface = self.interface_directory(parent)
        port = hub_interface / f"{parent}-port{port_number}"
        port.mkdir(parents=True, exist_ok=True)
        _write(port / "connect_type", value)
        link = directory / "port"
        if not link.is_symlink():
            link.symlink_to(Path("..") / hub_interface.name / port.name, target_is_directory=True)

    def strip_identity(self, device: str) -> None:
        """Half-remove a device: the directory stays, its descriptor attributes are gone."""
        directory = self.device_directory(device)
        for attribute in ("idVendor", "idProduct", "bcdDevice", "bDeviceClass", "descriptors"):
            (directory / attribute).unlink(missing_ok=True)

    def remove_device(self, device: str) -> None:
        """Unplug a device (and, for a hub, everything behind it)."""
        prefix = f"{device}."
        for entry in list(self.bus_directory.iterdir()):
            if entry.name == device or entry.name.startswith((prefix, f"{device}:")):
                _remove(entry)
        if self.nested:
            shutil.rmtree(self.device_directory(device))

    def leave_dangling_link(self, device: str) -> None:
        """Delete a device's directory but leave its bus symlink behind. Linux only."""
        self._require_nested("symlinks")
        shutil.rmtree(self.device_directory(device))

    # -- ready-made devices -----------------------------------------------------------

    def flash_drive(self, name: str = "1-1", *, serial: str | None = "TEST0001A7C3") -> str:
        """A 16 GB flash drive; with two partitions where block devices can be built."""
        self.add_device(name, serial=serial, connect_type="hotplug")
        if self.nested:
            self.add_disk(
                name,
                "sdb",
                sectors=31_250_000,
                partitions=(("sdb1", 204_800), ("sdb2", 31_043_152)),
            )
        return name

    def serialless_drive(self, name: str = "1-2") -> str:
        """A storage device that reports no serial number at all."""
        return self.add_device(name, product_id=0x0002, serial=None, product="Example Stick")

    def keyboard_mouse(self, name: str = "1-3") -> str:
        """One device with a boot keyboard and a boot mouse interface."""
        return self.add_device(
            name,
            product_id=0x0003,
            serial=None,
            product="Example Combo",
            interfaces=(BOOT_KEYBOARD, BOOT_MOUSE),
        )

    def hub(self, name: str = "1-4", *, removable: str | None = "removable") -> str:
        """An external hub. Add what is plugged into it as ``<name>.<port>``."""
        return self.add_device(
            name,
            product_id=0x0004,
            serial=None,
            product="Example Hub",
            device_class=0x09,
            interfaces=(HUB,),
            removable=removable,
        )

    def phone(self, name: str = "1-5") -> str:
        """A phone in file-transfer mode with debugging on: MTP plus a vendor interface."""
        return self.add_device(
            name,
            product_id=0x0006,
            serial="TEST0006PH0N",
            product="Example Phone",
            interfaces=(MTP, ADB),
        )

    def internal_webcam(self, name: str = "1-6") -> str:
        """A camera soldered to the board: ``fixed`` on a ``hardwired`` port."""
        return self.add_device(
            name,
            product_id=0x0007,
            serial=None,
            product="Integrated Camera",
            device_class=0xEF,
            interfaces=(VIDEO_CONTROL, VIDEO_STREAMING),
            removable="fixed",
            connect_type="hardwired",
        )

    # -- internals --------------------------------------------------------------------

    def _create_device(
        self,
        name: str,
        *,
        vendor_id: int,
        product_id: int,
        bcd_device: int,
        device_class: int,
        serial: str | None,
        manufacturer: str | None,
        product: str | None,
        interfaces: tuple[Triple, ...],
        removable: str | None,
        devnum: int | None,
        authorized: bool,
        interface_directories: bool | None,
        descriptors: bool,
    ) -> Path:
        directory = self.device_directory(name)
        directory.mkdir(parents=True)
        if self.nested:
            link = self.bus_directory / name
            link.symlink_to(
                os.path.relpath(directory, self.bus_directory), target_is_directory=True
            )
        bus = int(name[3:]) if name.startswith("usb") else int(name.partition("-")[0])
        if devnum is None:
            devnum = self._device_numbers.get(bus, 0) + 1
        self._device_numbers[bus] = max(devnum, self._device_numbers.get(bus, 0))

        _write(directory / "idVendor", f"{vendor_id:04x}")
        _write(directory / "idProduct", f"{product_id:04x}")
        _write(directory / "bcdDevice", f"{bcd_device:04x}")
        _write(directory / "bDeviceClass", f"{device_class:02x}")
        _write(directory / "busnum", str(bus))
        _write(directory / "devnum", str(devnum))
        _write(directory / "speed", "480")
        _write(directory / "authorized", "1" if authorized else "0")
        # The kernel prints these two from the active configuration: empty when there is
        # none, as for a deauthorized device.
        _write(directory / "bNumInterfaces", f"{len(interfaces):2d}" if authorized else "")
        _write(directory / "bConfigurationValue", "1" if authorized else "")
        # The kernel hides a string attribute when the device has no such descriptor.
        for attribute, value in (
            ("serial", serial),
            ("manufacturer", manufacturer),
            ("product", product),
        ):
            if value is not None:
                _write(directory / attribute, value)
        if removable is not None:
            _write(directory / "removable", removable)
        if descriptors:
            (directory / "descriptors").write_bytes(
                build_descriptors(
                    interfaces,
                    vendor_id=vendor_id,
                    product_id=product_id,
                    bcd_device=bcd_device,
                    device_class=device_class,
                )
            )
        (directory / "power").mkdir()
        (directory / "ep_00").mkdir()
        _write(directory / "uevent", f"DEVTYPE=usb_device\nPRODUCT={vendor_id:x}/{product_id:x}")

        if interface_directories is None:
            interface_directories = self.nested
        if interface_directories and authorized:
            for number, triple in enumerate(interfaces):
                interface = self.add_interface(name, number, triple)
                link = self.bus_directory / interface.name
                link.symlink_to(
                    os.path.relpath(interface, self.bus_directory), target_is_directory=True
                )
        return directory

    def _require_nested(self, what: str) -> None:
        if not self.nested:
            raise RuntimeError(f"{what} cannot be built on this platform; mark the test linux_only")


def _parent(name: str) -> str | None:
    if name.startswith("usb"):
        return None
    bus, _, path = name.partition("-")
    head, dot, _port = path.rpartition(".")
    return f"{bus}-{head}" if dot else f"usb{bus}"


def _interface_name(device: str, number: int, configuration: int) -> str:
    stem = f"{device[3:]}-0" if device.startswith("usb") else device
    return f"{stem}:{configuration}.{number}"


def _write(path: Path, text: str) -> None:
    # sysfs ends every text attribute with a newline.
    path.write_bytes(text.encode("utf-8") + b"\n")


def _remove(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


# -- synthetic kernel notifications -------------------------------------------------------


def uevent_message(action: str, devpath: str, subsystem: str = "usb", **fields: str) -> bytes:
    """The bytes of a kernel uevent: ``action@devpath``, then NUL-terminated pairs."""
    pairs = {"ACTION": action, "DEVPATH": devpath, "SUBSYSTEM": subsystem, **fields}
    body = b"".join(f"{key}={value}".encode() + b"\0" for key, value in pairs.items())
    return f"{action}@{devpath}".encode() + b"\0" + body


class QueueTransport:
    """A stand-in for the kernel uevent socket, fed by the test.

    ``push`` queues a message as if the kernel (or, with other arguments, some other
    sender) had sent it; ``push_error`` makes the next receive fail. ``settle`` blocks
    until the consumer has dealt with everything queued so far, which lets a test assert
    on the outcome without sleeping.
    """

    def __init__(self) -> None:
        self._items: queue.Queue[Datagram | OSError | None] = queue.Queue()
        self._state = threading.Condition()
        self._pushed = 0
        self._asked = 0
        self.interrupted = False
        self.closed = False

    def push(
        self, data: bytes, *, sender_pid: int = 0, sender_groups: int = 1, truncated: bool = False
    ) -> None:
        self._put(Datagram(data, sender_pid, sender_groups, truncated))

    def push_error(self, error: OSError) -> None:
        self._put(error)

    def settle(self, timeout: float = 5.0) -> None:
        """Wait until the consumer has come back for more after the last queued item."""
        with self._state:
            if not self._state.wait_for(lambda: self._asked > self._pushed, timeout):
                raise AssertionError("the consumer did not process its input in time")

    # The UeventTransport interface.

    def receive(self) -> Datagram | None:
        with self._state:
            self._asked += 1
            self._state.notify_all()
        item = self._items.get()
        if isinstance(item, OSError):
            raise item
        return item

    def interrupt(self) -> None:
        self.interrupted = True
        self._items.put(None)

    def close(self) -> None:
        self.closed = True

    def _put(self, item: Datagram | OSError) -> None:
        with self._state:
            self._pushed += 1
        self._items.put(item)
