"""The Windows backend against a synthetic device tree.

``FakeWinApi`` answers every :class:`~portlock.guard.windows.api.WinApi` query from
``tests/fixtures/win/tree.json``, so enumeration, volume mapping, the change tracker and
the monitor threads all run unmodified on any platform. Nothing here touches a real
device: the fake never calls the operating system.
"""

from __future__ import annotations

import collections
import copy
import json
import queue
import struct
import threading
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from portlock.core.clock import FakeClock
from portlock.core.errors import BackendError
from portlock.core.models import (
    DeviceCategory,
    DeviceEvent,
    DeviceEventType,
    UsbDevice,
    UsbInterface,
    Volume,
)
from portlock.guard.base import DeviceBackend
from portlock.guard.windows import WindowsBackend, api
from portlock.guard.windows.api import (
    NotificationHandle,
    NotificationSink,
    PowerSink,
    PropertyValue,
    StorageDeviceNumber,
    VolumeInformation,
    WinApi,
)
from portlock.guard.windows.enumerate import ConnectionTokens, enumerate_usb_devices
from portlock.guard.windows.monitor import ChangeTracker, DeviceMonitor, diff_snapshots
from portlock.guard.windows.volumes import DiskRef, VolumeIndex, find_disks, volumes_for_device

TREE: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "win" / "tree.json").read_text(encoding="utf-8")
)

BASE = "PCIROOT(0)#PCI(1400)#USBROOT(0)"
ROOT = "USB\\ROOT_HUB30\\4&0a0b0c0d&0&0"
FLASH = "USB\\VID_1209&PID_0001\\TEST0001A7C3"
KEYBOARD = "USB\\VID_1209&PID_0002\\5&1a2b3c4d&0&2"
RECEIVER = "USB\\VID_1209&PID_0008\\5&1a2b3c4d&0&3"
HUB = "USB\\VID_1209&PID_0004\\5&1a2b3c4d&0&4"
UASP = "USB\\VID_1209&PID_0010\\TEST0010UASP"
PHONE = "USB\\VID_1209&PID_0006\\TEST0006PH0N"
WEBCAM = "USB\\VID_1209&PID_0007\\TEST0007CAM0"
DISABLED = "USB\\VID_1209&PID_0009\\5&1a2b3c4d&0&6"
BADUSB = "USB\\VID_1209&PID_0005\\TEST0005BAD1"
FAKE_SERIAL = "USB\\VID_1209&PID_000A\\0123456789AB"
READER = "USB\\VID_1209&PID_000B\\TEST000BCARD"
ALL_DEVICES = sorted(
    [
        ROOT,
        FLASH,
        KEYBOARD,
        RECEIVER,
        HUB,
        UASP,
        PHONE,
        WEBCAM,
        DISABLED,
        BADUSB,
        FAKE_SERIAL,
        READER,
    ],
    key=str.upper,
)


def volume_name(number: int) -> str:
    return f"\\\\?\\Volume{{00000000-0000-4000-8000-0000000000{number:02x}}}\\"


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def encode_property(kind: str, value: Any) -> PropertyValue:
    """Encode a fixture value the way ``CM_Get_DevNode_PropertyW`` returns it."""
    if kind == "string":
        return api.DEVPROP_TYPE_STRING, utf16(value) + b"\x00\x00"
    if kind == "list":
        body = b"".join(utf16(item) + b"\x00\x00" for item in value) + b"\x00\x00"
        return api.DEVPROP_TYPE_STRING_LIST, body
    if kind == "uint32":
        return api.DEVPROP_TYPE_UINT32, struct.pack("<I", value)
    if kind == "guid":
        return api.DEVPROP_TYPE_GUID, uuid.UUID(value).bytes_le
    if kind == "filetime":
        return api.DEVPROP_TYPE_FILETIME, struct.pack("<Q", value)
    raise AssertionError(kind)


PROPERTY_FIELDS = {
    "DEVPKEY_Device_HardwareIds": ("hardware_ids", "list"),
    "DEVPKEY_Device_CompatibleIds": ("compatible_ids", "list"),
    "DEVPKEY_Device_Service": ("service", "string"),
    "DEVPKEY_Device_DeviceDesc": ("device_desc", "string"),
    "DEVPKEY_Device_BusReportedDeviceDesc": ("bus_desc", "string"),
    "DEVPKEY_Device_Manufacturer": ("manufacturer", "string"),
    "DEVPKEY_Device_Capabilities": ("capabilities", "uint32"),
    "DEVPKEY_Device_RemovalPolicy": ("removal_policy", "uint32"),
    "DEVPKEY_Device_Address": ("address", "uint32"),
    "DEVPKEY_Device_LocationPaths": ("location_paths", "list"),
    "DEVPKEY_Device_ClassGuid": ("class_guid", "guid"),
    "DEVPKEY_Device_ContainerId": ("container_id", "guid"),
    "DEVPKEY_Device_LastArrivalDate": ("last_arrival", "filetime"),
}


class FakeWinApi(WinApi):
    """Answers every ``WinApi`` query from a synthetic device tree held in memory.

    Tests change the tree with :meth:`detach` and :meth:`attach` and play the part of
    the operating system with the ``notify_*`` methods. ``fail`` names methods that
    should raise ``BackendError``; ``calls`` counts how often each method ran.
    """

    def __init__(
        self, tree: dict[str, Any], *, available: bool = True, notifications: bool = True
    ) -> None:
        # Deliberately no super().__init__(): the real one loads system libraries.
        self._lock = threading.RLock()
        self._available = available
        self._notifications = notifications
        self.nodes: list[dict[str, Any]] = copy.deepcopy(tree["nodes"])
        self.volumes: list[dict[str, Any]] = copy.deepcopy(tree["volumes"])
        self.device_numbers: dict[str, list[Any]] = dict(tree["device_numbers"])
        self._handles: dict[str, int] = {}
        self._sinks: dict[int, tuple[int, uuid.UUID | None, NotificationSink]] = {}
        self._power_sinks: dict[int, PowerSink] = {}
        self._next_notification = 1
        self.calls: collections.Counter[str] = collections.Counter()
        self.fail: set[str] = set()
        self.fail_register: set[str] = set()
        self.gone_before_status: set[str] = set()
        self.sibling_loop = False
        self.parent_loop = False

    # -- test controls -----------------------------------------------------------------

    def node(self, instance_id: str) -> dict[str, Any]:
        with self._lock:
            for node in self.nodes:
                if node["id"].upper() == instance_id.upper():
                    return node
        raise KeyError(instance_id)

    def detach(self, instance_id: str) -> list[dict[str, Any]]:
        """Unplug a device: remove its node and everything below, and return them."""
        with self._lock:
            removed = [self.node(instance_id)]
            grew = True
            while grew:
                grew = False
                ids = {node["id"] for node in removed}
                for node in self.nodes:
                    if node["parent"] in ids and node not in removed:
                        removed.append(node)
                        grew = True
            self.nodes = [node for node in self.nodes if node not in removed]
            return removed

    def attach(self, nodes: list[dict[str, Any]]) -> None:
        with self._lock:
            self.nodes.extend(nodes)

    @property
    def registrations(self) -> list[str]:
        with self._lock:
            labels = []
            for filter_type, class_guid, _sink in self._sinks.values():
                if filter_type == api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE:
                    labels.append("instances")
                elif class_guid == api.GUID_DEVINTERFACE_USB_DEVICE:
                    labels.append("usb")
                elif class_guid == api.GUID_DEVINTERFACE_VOLUME:
                    labels.append("volume")
            return sorted(labels)

    @property
    def resume_registrations(self) -> int:
        with self._lock:
            return len(self._power_sinks)

    def notify_power(self, event_type: int) -> None:
        with self._lock:
            sinks = list(self._power_sinks.values())
        for sink in sinks:
            sink(event_type)

    def notify_instance(
        self, instance_id: str, action: int = api.CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED
    ) -> None:
        header = struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0)
        self._deliver(
            api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
            None,
            action,
            header + utf16(instance_id) + b"\x00\x00",
        )

    def notify_interface(
        self,
        class_guid: uuid.UUID = api.GUID_DEVINTERFACE_USB_DEVICE,
        action: int = api.CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL,
    ) -> None:
        header = struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, 0)
        link = utf16(f"\\\\?\\SYNTHETIC#LINK#{{{class_guid}}}") + b"\x00\x00"
        self._deliver(
            api.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
            class_guid,
            action,
            header + class_guid.bytes_le + link,
        )

    def _deliver(
        self, filter_type: int, class_guid: uuid.UUID | None, action: int, payload: bytes
    ) -> None:
        with self._lock:
            sinks = [
                sink
                for registered_type, registered_guid, sink in self._sinks.values()
                if registered_type == filter_type and registered_guid == class_guid
            ]
        for sink in sinks:
            sink(action, payload)

    # -- plumbing ----------------------------------------------------------------------

    def _enter(self, name: str) -> None:
        self.calls[name] += 1
        if not self._available:
            raise BackendError("not available (simulated)", code="unsupported_platform")
        if name in self.fail:
            raise BackendError(f"{name} failed (simulated)")

    def _handle(self, instance_id: str) -> int:
        key = instance_id.upper()
        if key not in self._handles:
            self._handles[key] = 100 + len(self._handles)
        return self._handles[key]

    def _by_handle(self, devinst: int) -> dict[str, Any] | None:
        for node in self.nodes:
            if self._handle(node["id"]) == devinst:
                return node
        return None

    # -- WinApi ------------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._available

    def present_device_ids(self, enumerator: str) -> list[str]:
        with self._lock:
            self._enter("present_device_ids")
            prefix = enumerator.upper() + "\\"
            return [node["id"] for node in self.nodes if node["id"].upper().startswith(prefix)]

    def locate_devnode(self, instance_id: str) -> int | None:
        with self._lock:
            self._enter("locate_devnode")
            for node in self.nodes:
                if node["id"].upper() == instance_id.upper():
                    return self._handle(node["id"])
            return None

    def get_device_id(self, devinst: int) -> str | None:
        with self._lock:
            self._enter("get_device_id")
            node = self._by_handle(devinst)
            return node["id"] if node is not None else None

    def get_parent(self, devinst: int) -> int | None:
        with self._lock:
            self._enter("get_parent")
            if self.parent_loop:
                return devinst
            node = self._by_handle(devinst)
            if node is None or node["parent"] is None:
                return None
            return self.locate_devnode(node["parent"])

    def get_child(self, devinst: int) -> int | None:
        with self._lock:
            self._enter("get_child")
            node = self._by_handle(devinst)
            if node is None:
                return None
            for candidate in self.nodes:
                if candidate["parent"] == node["id"]:
                    return self._handle(candidate["id"])
            return None

    def get_sibling(self, devinst: int) -> int | None:
        with self._lock:
            self._enter("get_sibling")
            if self.sibling_loop:
                return devinst
            node = self._by_handle(devinst)
            if node is None:
                return None
            later = self.nodes[self.nodes.index(node) + 1 :]
            for candidate in later:
                if candidate["parent"] == node["parent"]:
                    return self._handle(candidate["id"])
            return None

    def get_status(self, devinst: int) -> tuple[int, int] | None:
        with self._lock:
            self._enter("get_status")
            node = self._by_handle(devinst)
            if node is None or node["id"] in self.gone_before_status:
                return None
            return node["status"], node["problem"]

    def get_property(self, devinst: int, key: api.DevPropKey) -> PropertyValue | None:
        with self._lock:
            self._enter("get_property")
            node = self._by_handle(devinst)
            if node is None or key.name not in PROPERTY_FIELDS:
                return None
            field, kind = PROPERTY_FIELDS[key.name]
            value = node["props"].get(field)
            if value is None:
                return None
            # A test may plant a ready-made (type, bytes) pair to simulate a wrong type.
            return value if isinstance(value, tuple) else encode_property(kind, value)

    def get_interface_paths(self, class_guid: uuid.UUID, instance_id: str) -> list[str]:
        with self._lock:
            self._enter("get_interface_paths")
            try:
                node = self.node(instance_id)
            except KeyError:
                return []
            interfaces = node["props"].get("disk_interfaces", {})
            return list(interfaces.get(f"{{{class_guid}}}", []))

    def storage_device_number(self, path: str) -> StorageDeviceNumber | None:
        with self._lock:
            self._enter("storage_device_number")
            number = self.device_numbers.get(path)
            if number is None:
                for volume in self.volumes:
                    if volume["name"][:-1] == path:
                        number = volume["device"]
            return StorageDeviceNumber(*number) if number is not None else None

    def volume_disk_numbers(self, path: str) -> tuple[int, ...]:
        with self._lock:
            self._enter("volume_disk_numbers")
            for volume in self.volumes:
                if volume["name"][:-1] == path:
                    return tuple(volume["extents"])
            return ()

    def volume_names(self) -> list[str]:
        with self._lock:
            self._enter("volume_names")
            return [volume["name"] for volume in self.volumes]

    def _volume(self, name: str) -> dict[str, Any] | None:
        return next((volume for volume in self.volumes if volume["name"] == name), None)

    def volume_mount_points(self, volume_name: str) -> list[str]:
        with self._lock:
            self._enter("volume_mount_points")
            volume = self._volume(volume_name)
            return list(volume["mount_points"]) if volume is not None else []

    def volume_information(self, root: str) -> VolumeInformation | None:
        with self._lock:
            self._enter("volume_information")
            volume = self._volume(root)
            if volume is None or volume["info"] is None:
                return None
            info = volume["info"]
            return VolumeInformation(
                info["label"], info["serial"], info["flags"], info["filesystem"]
            )

    def volume_total_bytes(self, root: str) -> int | None:
        with self._lock:
            self._enter("volume_total_bytes")
            volume = self._volume(root)
            return volume["total_bytes"] if volume is not None else None

    def supports_notifications(self) -> bool:
        return self._available and self._notifications

    def _add_sink(
        self, label: str, filter_type: int, class_guid: uuid.UUID | None, sink: NotificationSink
    ) -> NotificationHandle:
        with self._lock:
            self._enter("register_notification")
            if label in self.fail_register:
                raise BackendError(f"registration refused (simulated): {label}")
            handle = self._next_notification
            self._next_notification += 1
            self._sinks[handle] = (filter_type, class_guid, sink)
            return NotificationHandle(handle, None, label)

    def register_interface_notification(
        self, class_guid: uuid.UUID, sink: NotificationSink
    ) -> NotificationHandle:
        label = "usb" if class_guid == api.GUID_DEVINTERFACE_USB_DEVICE else "volume"
        return self._add_sink(label, api.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, class_guid, sink)

    def register_instance_notification(self, sink: NotificationSink) -> NotificationHandle:
        return self._add_sink("instances", api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, None, sink)

    def unregister_notification(self, handle: NotificationHandle) -> None:
        with self._lock:
            self._enter("unregister_notification")
            if handle.handle not in self._sinks:
                raise BackendError("unknown notification handle (simulated)")
            del self._sinks[handle.handle]

    def supports_resume_notifications(self) -> bool:
        # Windows versions without CM_Register_Notification lack this too.
        return self._available and self._notifications

    def register_resume_notification(self, sink: PowerSink) -> NotificationHandle:
        with self._lock:
            self._enter("register_resume_notification")
            if "resume" in self.fail_register:
                raise BackendError("registration refused (simulated): resume")
            handle = self._next_notification
            self._next_notification += 1
            self._power_sinks[handle] = sink
            return NotificationHandle(handle, None, "resume")

    def unregister_resume_notification(self, handle: NotificationHandle) -> None:
        with self._lock:
            self._enter("unregister_resume_notification")
            if handle.handle not in self._power_sinks:
                raise BackendError("unknown power notification handle (simulated)")
            del self._power_sinks[handle.handle]


class Collector:
    """An event callback that hands events to the test thread."""

    def __init__(self) -> None:
        self.events: queue.Queue[DeviceEvent] = queue.Queue()
        self.thread_names: set[str] = set()

    def __call__(self, event: DeviceEvent) -> None:
        self.thread_names.add(threading.current_thread().name)
        self.events.put(event)

    def next(self) -> DeviceEvent:
        # The timeout is only an upper bound for a broken build; a working monitor
        # delivers within milliseconds.
        return self.events.get(timeout=10)


@pytest.fixture
def fake() -> FakeWinApi:
    return FakeWinApi(TREE)


@pytest.fixture
def devices(fake: FakeWinApi) -> dict[str, UsbDevice]:
    return {device.instance_id: device for device in enumerate_usb_devices(fake)}


@pytest.fixture
def backend(fake: FakeWinApi, clock: FakeClock) -> Iterator[WindowsBackend]:
    """A backend whose monitor reacts immediately and never re-checks on its own.

    With no settle time the debounce does not depend on the clock advancing, so the
    injected clock can stay still and event timestamps are exact.
    """
    instance = WindowsBackend(
        fake,
        clock,
        settle_seconds=0,
        max_settle_seconds=0,
        followup_seconds=0,
        resync_interval=None,
    )
    try:
        yield instance
    finally:
        instance.stop()


def new_tracker(fake: FakeWinApi, clock: FakeClock, **options: Any) -> ChangeTracker:
    settings: dict[str, Any] = {
        "settle_seconds": 0.25,
        "max_settle_seconds": 1.0,
        "followup_seconds": 1.0,
    }
    settings.update(options)
    return ChangeTracker(lambda: enumerate_usb_devices(fake), clock, **settings)


# -- the fake itself -------------------------------------------------------------------


def test_the_fake_replaces_every_public_method_of_the_real_api() -> None:
    public = {name for name in vars(WinApi) if not name.startswith("_")}
    assert len(public) >= 18
    assert public <= set(vars(FakeWinApi)), public - set(vars(FakeWinApi))


# -- enumeration -----------------------------------------------------------------------


def test_every_device_is_listed_once_in_a_stable_order(fake: FakeWinApi) -> None:
    listed = [device.instance_id for device in enumerate_usb_devices(fake)]
    assert listed == ALL_DEVICES
    # Interface nodes are folded into their device; ids that do not parse are skipped.
    assert not any("&MI_" in instance_id for instance_id in listed)
    assert enumerate_usb_devices(fake) == enumerate_usb_devices(fake)


def test_flash_drive_with_a_serial(devices: dict[str, UsbDevice]) -> None:
    assert devices[FLASH] == UsbDevice(
        instance_id=FLASH,
        vendor_id=0x1209,
        product_id=0x0001,
        serial="TEST0001A7C3",
        manufacturer=None,
        product="Example Flash 16GB",
        bcd_device=0x0100,
        device_class=0,
        interfaces=(UsbInterface(0x08, 0x06, 0x50),),
        bus_path=f"{BASE}#USB(1)",
        removable=True,
        volumes=(
            Volume(
                device_node=volume_name(2),
                mount_point="E:\\",
                label="EXAMPLE",
                fs_type="FAT32",
                fs_uuid="1A2B-3C4D",
                size_bytes=16_000_000_000,
                read_only=False,
            ),
        ),
    )
    assert devices[FLASH].categories == {DeviceCategory.STORAGE}
    assert devices[FLASH].connection_id == FLASH + "@134000000010000000"


def test_backend_data_carries_what_the_enforcer_and_the_console_need(
    devices: dict[str, UsbDevice],
) -> None:
    assert dict(devices[FLASH].backend_data) == {
        "kind": "device",
        "dn_status": "0x0180600a",
        "started": "1",
        "disableable": "1",
        "composite": "0",
        "connection_basis": "last_arrival",
        "service": "USBSTOR",
        "description": "USB Mass Storage Device",
        "location_path": f"{BASE}#USB(1)",
        "controller": BASE,
        "ports": "1",
        "driver_manufacturer": "Compatible USB storage device",
        "class_guid": "{36fc9e60-c465-11cf-8056-444553540000}",
        "container_id": "{11111111-0000-4000-8000-000000000001}",
        "last_arrival": "134000000010000000",
        "parent": ROOT,
    }
    assert devices[UASP].backend_data["ports"] == "4.2"
    assert devices[UASP].backend_data["parent"] == HUB
    assert devices[RECEIVER].backend_data["disableable"] == "0"
    assert devices[RECEIVER].backend_data["compatible_tags"] == "COMPOSITE"
    assert devices[PHONE].backend_data["compatible_tags"] == "MS_COMP_MTP"


def test_manufacturer_is_never_taken_from_the_driver(devices: dict[str, UsbDevice]) -> None:
    assert all(device.manufacturer is None for device in devices.values())
    assert devices[PHONE].backend_data["driver_manufacturer"] == "Example Mobile"
    assert devices[FLASH].display_name == "Example Flash 16GB"


def test_a_device_without_a_serial_reports_none(devices: dict[str, UsbDevice]) -> None:
    keyboard = devices[KEYBOARD]
    assert keyboard.serial is None
    assert keyboard.interfaces == (UsbInterface(0x03, 0x01, 0x01),)
    assert keyboard.is_keyboard and keyboard.product == "Example Keyboard"
    assert keyboard.bcd_device == 0x0211
    assert keyboard.volumes == ()


def test_a_serial_windows_does_not_vouch_for_is_not_reported(
    fake: FakeWinApi, devices: dict[str, UsbDevice]
) -> None:
    # The id looks like it carries a serial, but the device lacks CM_DEVCAP_UNIQUEID.
    assert devices[FAKE_SERIAL].serial is None
    # With the capability the same id does carry one...
    fake.node(FAKE_SERIAL)["props"]["capabilities"] = 0x94
    assert {d.instance_id: d for d in enumerate_usb_devices(fake)}[FAKE_SERIAL].serial == (
        "0123456789AB"
    )
    # ...and if the capabilities cannot be read at all, the id is taken at its word.
    del fake.node(FAKE_SERIAL)["props"]["capabilities"]
    assert {d.instance_id: d for d in enumerate_usb_devices(fake)}[FAKE_SERIAL].serial == (
        "0123456789AB"
    )


def test_composite_receiver_takes_its_interfaces_from_its_child_nodes(
    devices: dict[str, UsbDevice],
) -> None:
    receiver = devices[RECEIVER]
    # In interface-number order, whatever order Windows lists the children in.
    assert receiver.interfaces == (
        UsbInterface(0x03, 0x01, 0x01),
        UsbInterface(0x03, 0x01, 0x02),
        UsbInterface(0x03, 0x00, 0x00),
    )
    assert receiver.categories == {
        DeviceCategory.KEYBOARD,
        DeviceCategory.MOUSE,
        DeviceCategory.HID,
    }
    assert receiver.device_class == 0
    assert receiver.is_composite and receiver.serial is None
    assert receiver.backend_data["composite"] == "1"
    assert receiver.backend_data["service"] == "usbccgp"


def test_a_composite_device_with_no_child_nodes_yet_reports_no_interfaces(
    fake: FakeWinApi,
) -> None:
    for child in fake.detach(RECEIVER)[1:]:
        assert "&MI_" in child["id"]
    parent = copy.deepcopy(next(n for n in TREE["nodes"] if n["id"] == RECEIVER))
    fake.attach([parent])
    receiver = {d.instance_id: d for d in enumerate_usb_devices(fake)}[RECEIVER]
    assert receiver.interfaces == ()
    assert receiver.categories == {DeviceCategory.OTHER}


def test_interface_nodes_of_another_device_are_not_adopted(fake: FakeWinApi) -> None:
    # A child with a different vendor/product id is not a function of this device.
    stray = fake.node("USB\\VID_1209&PID_0008&MI_01\\6&6f708192&0&0001")
    stray["id"] = "USB\\VID_1209&PID_00EE&MI_01\\6&6f708192&0&0001"
    receiver = {d.instance_id: d for d in enumerate_usb_devices(fake)}[RECEIVER]
    assert receiver.interfaces == (UsbInterface(0x03, 0x01, 0x01), UsbInterface(0x03))


def test_hub_and_root_hub_are_classified_as_hubs(devices: dict[str, UsbDevice]) -> None:
    hub = devices[HUB]
    assert hub.is_hub and hub.device_class == 0x09
    assert hub.interfaces == (UsbInterface(0x09),)
    assert hub.removable is True and hub.product == "Example Hub"
    # The enclosure behind the hub is its own device; its volumes are not the hub's.
    assert hub.volumes == ()

    root = devices[ROOT]
    assert root.is_hub and root.device_class == 0x09
    assert root.interfaces == (UsbInterface(0x09),)
    assert (root.vendor_id, root.product_id, root.bcd_device) == (0xFFFF, 0x0001, 0x0000)
    assert root.serial is None and root.removable is False
    assert root.product == "USB Root Hub (USB 3.0)"
    assert root.bus_path == BASE
    assert root.backend_data["kind"] == "root_hub"


def test_a_hub_is_recognised_by_its_driver_when_its_ids_say_nothing(fake: FakeWinApi) -> None:
    fake.node(HUB)["props"]["compatible_ids"] = []
    hub = {d.instance_id: d for d in enumerate_usb_devices(fake)}[HUB]
    assert hub.is_hub and hub.device_class == 0x09 and hub.volumes == ()


def test_a_root_hub_without_hardware_ids_still_enumerates(fake: FakeWinApi) -> None:
    del fake.node(ROOT)["props"]["hardware_ids"]
    del fake.node(ROOT)["props"]["location_paths"]
    root = {d.instance_id: d for d in enumerate_usb_devices(fake)}[ROOT]
    assert (root.vendor_id, root.product_id, root.bcd_device) == (0, 0, None)
    assert root.is_hub and root.bus_path is None


def test_uasp_enclosure_behind_a_hub(devices: dict[str, UsbDevice]) -> None:
    enclosure = devices[UASP]
    assert enclosure.interfaces == (UsbInterface(0x08, 0x06, 0x62), UsbInterface(0x08, 0x06, 0x50))
    assert enclosure.categories == {DeviceCategory.STORAGE}
    assert enclosure.serial == "TEST0010UASP"
    assert enclosure.bus_path == f"{BASE}#USB(4)#USB(2)"
    assert enclosure.volumes == (
        Volume(
            device_node=volume_name(3),
            # The lowest drive letter, not the mounted folder and not the later letter.
            mount_point="F:\\",
            label=None,
            fs_type="NTFS",
            fs_uuid="0000-0001",
            size_bytes=480_000_000_000,
            read_only=False,
        ),
        Volume(
            device_node=volume_name(4),
            mount_point=None,
            label="ARCHIVE",
            fs_type="exFAT",
            fs_uuid="FFFF-0000",
            size_bytes=20_000_000_000,
            read_only=True,
        ),
    )


def test_phone_in_mtp_mode_has_no_volumes(devices: dict[str, UsbDevice]) -> None:
    phone = devices[PHONE]
    assert phone.interfaces == (UsbInterface(0x06, 0x01, 0x01),)
    assert phone.categories == {DeviceCategory.IMAGING}
    assert phone.serial == "TEST0006PH0N" and phone.product == "Example Phone"
    assert phone.volumes == ()


def test_built_in_webcam_is_not_removable(devices: dict[str, UsbDevice]) -> None:
    webcam = devices[WEBCAM]
    assert webcam.removable is False
    assert webcam.device_class == 0xEF
    assert webcam.interfaces == (UsbInterface(0x0E, 0x03, 0x00),)
    assert webcam.categories == {DeviceCategory.AUDIO_VIDEO}
    assert webcam.serial == "TEST0007CAM0"


def test_a_disabled_device_without_a_product_string_is_still_listed(
    devices: dict[str, UsbDevice],
) -> None:
    radio = devices[DISABLED]
    assert radio.product is None
    assert radio.display_name == "USB device 1209:0009"
    assert radio.categories == {DeviceCategory.WIRELESS}
    assert radio.backend_data["problem"] == str(api.CM_PROB_DISABLED)
    assert radio.backend_data["started"] == "0"
    # The driver's description is kept for display, outside the identity fields.
    assert radio.backend_data["description"] == "Example Radio"
    assert "service" not in radio.backend_data
    # A device without a problem has no problem code at all.
    assert "problem" not in devices[FLASH].backend_data


def test_storage_paired_with_a_keyboard_is_visible_as_such(devices: dict[str, UsbDevice]) -> None:
    stick = devices[BADUSB]
    assert stick.interfaces == (UsbInterface(0x08, 0x06, 0x50), UsbInterface(0x03, 0x01, 0x01))
    assert stick.pairs_storage_with_input
    # Its disk hangs below the MI_00 interface node, two levels down.
    assert [volume.mount_point for volume in stick.volumes] == ["H:\\"]
    assert stick.volumes[0].fs_uuid == "0BAD-F00D"


def test_card_reader_without_a_card(devices: dict[str, UsbDevice]) -> None:
    assert devices[READER].volumes == (Volume(device_node=volume_name(6), mount_point="I:\\"),)


def test_volumes_of_other_disks_are_never_attributed_to_a_usb_device(
    devices: dict[str, UsbDevice],
) -> None:
    attributed = {volume.device_node for device in devices.values() for volume in device.volumes}
    assert attributed == {volume_name(n) for n in (2, 3, 4, 5, 6)}
    assert volume_name(1) not in attributed  # the system volume
    assert volume_name(7) not in attributed  # a volume spanning two internal disks


def test_a_hostile_product_string_is_sanitised(fake: FakeWinApi) -> None:
    fake.node(FLASH)["props"]["bus_desc"] = (
        "Flash\r\n2026-01-01T00:00:00Z policy allow" + chr(0x202E) + "evil" + chr(0)
    )
    fake.node(FLASH)["props"]["device_desc"] = "Driver" + chr(0x1B) + "[2J" + chr(0x202E)
    flash = {d.instance_id: d for d in enumerate_usb_devices(fake)}[FLASH]
    # The model replaces what is unsafe (visibly) and caps the length; the backend passes
    # the string through rather than cleaning it a second, different way.
    mark = chr(0xFFFD)
    assert flash.product == (
        "Flash" + mark * 2 + "2026-01-01T00:00:00Z policy allow" + mark + "evil"
    )
    # backend_data is not sanitized by the model, so the backend does it.
    assert flash.backend_data["description"] == "Driver" + mark + "[2J" + mark
    fake.node(FLASH)["props"]["bus_desc"] = "x" * 400
    long_name = {d.instance_id: d for d in enumerate_usb_devices(fake)}[FLASH].product
    assert long_name == "x" * 126


@pytest.mark.parametrize(
    ("field", "planted"),
    [
        ("hardware_ids", (api.DEVPROP_TYPE_STRING, utf16("USB\\VID_1209&PID_0001&REV_0100"))),
        ("compatible_ids", (api.DEVPROP_TYPE_UINT32, b"\x08\x00\x00\x00")),
        ("bus_desc", (api.DEVPROP_TYPE_STRING_LIST, utf16("Example") + b"\x00\x00\x00\x00")),
        ("capabilities", (api.DEVPROP_TYPE_UINT32, b"\x94")),
        ("removal_policy", (api.DEVPROP_TYPE_STRING, utf16("3") + b"\x00\x00")),
        ("location_paths", (api.DEVPROP_TYPE_STRING_LIST, b"\xff\xfe\xfd")),
        ("class_guid", (api.DEVPROP_TYPE_GUID, b"\x00" * 3)),
        ("last_arrival", (api.DEVPROP_TYPE_FILETIME, b"")),
    ],
)
def test_a_property_of_the_wrong_type_is_ignored_not_trusted(
    fake: FakeWinApi, field: str, planted: PropertyValue
) -> None:
    fake.node(FLASH)["props"][field] = planted
    flash = {d.instance_id: d for d in enumerate_usb_devices(fake)}[FLASH]
    # The device is still listed, identified by what could be read.
    assert (flash.vendor_id, flash.product_id) == (0x1209, 0x0001)
    if field == "hardware_ids":
        assert flash.bcd_device is None
    if field == "compatible_ids":
        assert flash.interfaces == ()
    if field == "bus_desc":
        assert flash.product is None
    if field == "location_paths":
        # Falls back to the chain of hub port numbers.
        assert flash.bus_path == "USB(1)"
    if field == "last_arrival":
        assert "last_arrival" not in flash.backend_data
        # No arrival time and no token store: no connection id rather than a wrong one.
        assert flash.connection_id is None
        assert flash.backend_data["connection_basis"] == "token"


def test_ids_differing_only_in_case_are_one_device(fake: FakeWinApi) -> None:
    duplicate = copy.deepcopy(fake.node(FLASH))
    duplicate["id"] = FLASH.lower()
    fake.attach([duplicate])
    listed = [device.instance_id for device in enumerate_usb_devices(fake)]
    assert len(listed) == len(ALL_DEVICES)
    assert [instance_id.upper() for instance_id in listed] == [i.upper() for i in ALL_DEVICES]


def test_a_device_that_vanishes_while_being_read_is_left_out(fake: FakeWinApi) -> None:
    fake.gone_before_status.add(KEYBOARD)
    listed = [device.instance_id for device in enumerate_usb_devices(fake)]
    assert listed == [instance_id for instance_id in ALL_DEVICES if instance_id != KEYBOARD]


def test_enumeration_fails_loudly_when_the_device_list_is_unavailable(fake: FakeWinApi) -> None:
    fake.fail.add("present_device_ids")
    with pytest.raises(BackendError, match="simulated"):
        enumerate_usb_devices(fake)


def test_a_device_stays_listed_when_its_volumes_cannot_be_read(fake: FakeWinApi) -> None:
    fake.fail.add("volume_names")
    devices = {device.instance_id: device for device in enumerate_usb_devices(fake)}
    assert sorted(devices, key=str.upper) == ALL_DEVICES
    assert devices[FLASH].volumes == ()
    assert devices[FLASH].backend_data["volumes"] == "unavailable"
    assert devices[FLASH].is_storage
    assert "volumes" not in devices[KEYBOARD].backend_data


def removable_of(fake: FakeWinApi, instance_id: str) -> bool | None:
    return {d.instance_id: d for d in enumerate_usb_devices(fake)}[instance_id].removable


def test_built_in_means_directly_on_a_root_port_windows_reports_as_fixed(
    fake: FakeWinApi,
) -> None:
    # The webcam sits on a root-hub port that firmware declares fixed.
    assert removable_of(fake, WEBCAM) is False
    props = fake.node(WEBCAM)["props"]
    # Either property saying "removable" makes the device external.
    props["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL
    assert removable_of(fake, WEBCAM) is True
    props["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL
    props["capabilities"] = 0x14
    assert removable_of(fake, WEBCAM) is True
    # One fixed answer is enough when the other property is missing...
    props["capabilities"] = 0x10
    del props["removal_policy"]
    assert removable_of(fake, WEBCAM) is False
    # ...but with neither, nothing is claimed.
    del props["capabilities"]
    assert removable_of(fake, WEBCAM) is None
    props["removal_policy"] = 99
    assert removable_of(fake, WEBCAM) is None


def test_a_device_behind_any_hub_is_never_built_in(fake: FakeWinApi) -> None:
    hub = fake.node(HUB)["props"]
    enclosure = fake.node(UASP)["props"]
    # The hub claims its own port is fixed and is itself on a fixed root port; the
    # enclosure says it is fixed too. The hub's descriptor is not trusted.
    hub["capabilities"] = 0x80
    hub["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL
    enclosure["capabilities"] = 0x80
    enclosure["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL
    assert removable_of(fake, UASP) is True
    # Even when nothing at all is reported about the enclosure.
    del enclosure["capabilities"]
    del enclosure["removal_policy"]
    assert removable_of(fake, UASP) is True
    # The hub itself is on a root port, so it can be built in.
    assert removable_of(fake, HUB) is False


def test_nothing_below_a_removable_host_controller_is_built_in(fake: FakeWinApi) -> None:
    # A controller in a dock: Windows reports its root hub as removable.
    root = fake.node(ROOT)["props"]
    root["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_SURPRISE_REMOVAL
    assert removable_of(fake, ROOT) is True
    assert removable_of(fake, WEBCAM) is True
    root["removal_policy"] = api.CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL
    root["capabilities"] = 0x84
    assert removable_of(fake, WEBCAM) is True
    del root["capabilities"]
    del root["removal_policy"]
    assert removable_of(fake, ROOT) is False
    assert removable_of(fake, WEBCAM) is False


def test_a_device_whose_parent_is_not_a_usb_node_makes_no_claim(fake: FakeWinApi) -> None:
    fake.node(WEBCAM)["parent"] = fake.node(ROOT)["parent"]
    assert removable_of(fake, WEBCAM) is None


def test_bus_path_falls_back_to_the_port_chain(fake: FakeWinApi) -> None:
    del fake.node(UASP)["props"]["location_paths"]
    enclosure = {d.instance_id: d for d in enumerate_usb_devices(fake)}[UASP]
    assert enclosure.bus_path == "USB(4)#USB(2)"
    assert "location_path" not in enclosure.backend_data
    del fake.node(HUB)["props"]["address"]
    assert {d.instance_id: d for d in enumerate_usb_devices(fake)}[UASP].bus_path is None


def test_a_tree_that_loops_does_not_hang_enumeration(fake: FakeWinApi) -> None:
    fake.sibling_loop = True
    assert len(enumerate_usb_devices(fake)) == len(ALL_DEVICES)
    fake.sibling_loop = False
    fake.parent_loop = True
    for instance_id in (UASP, HUB):
        props = fake.node(instance_id)["props"]
        del props["location_paths"]
        del props["removal_policy"]
        props["capabilities"] = 0x90
    listed = {d.instance_id: d for d in enumerate_usb_devices(fake)}
    assert len(listed) == len(ALL_DEVICES)
    assert fake.calls["get_parent"] < 2000


def test_enumeration_is_safe_from_several_threads(fake: FakeWinApi) -> None:
    results: list[list[str]] = []
    errors: list[Exception] = []

    def work() -> None:
        try:
            for _ in range(5):
                results.append([d.instance_id for d in enumerate_usb_devices(fake)])
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == []
    assert results == [ALL_DEVICES] * 20


# -- volumes ---------------------------------------------------------------------------


def test_find_disks_walks_only_the_devices_own_subtree(fake: FakeWinApi) -> None:
    def disks(instance_id: str) -> tuple[DiskRef, ...]:
        devinst = fake.locate_devnode(instance_id)
        assert devinst is not None
        return find_disks(fake, devinst)

    assert [(d.device_type, d.device_number) for d in disks(FLASH)] == [(api.FILE_DEVICE_DISK, 2)]
    assert disks(FLASH)[0].instance_id.startswith("USBSTOR\\DISK")
    assert [d.device_number for d in disks(UASP)] == [3]
    assert disks(UASP)[0].instance_id.startswith("SCSI\\DISK")
    assert [d.device_number for d in disks(BADUSB)] == [4]
    assert disks(KEYBOARD) == () and disks(PHONE) == ()
    # Walking from a hub must not reach the disk of the device plugged into it.
    assert disks(HUB) == () and disks(ROOT) == ()


def test_a_disk_that_does_not_answer_is_skipped(fake: FakeWinApi) -> None:
    fake.device_numbers.clear()
    devinst = fake.locate_devnode(FLASH)
    assert devinst is not None
    assert find_disks(fake, devinst) == ()
    assert volumes_for_device(fake, devinst) == ()
    # Without a disk there is nothing to look up, so the volumes are never enumerated.
    assert fake.calls["volume_names"] == 0


def test_the_volume_index_is_built_once_per_pass_and_only_when_needed(fake: FakeWinApi) -> None:
    enumerate_usb_devices(fake)
    assert fake.calls["volume_names"] == 1
    for instance_id in (FLASH, UASP, BADUSB, READER):
        fake.detach(instance_id)
    fake.calls.clear()
    enumerate_usb_devices(fake)
    assert fake.calls["volume_names"] == 0


def test_volume_index_handles_spanned_and_malformed_volumes(fake: FakeWinApi) -> None:
    fake.volumes.append(
        {
            "name": "\\\\?\\Volume{not-a-guid}\\",
            "device": [7, 2, 9],
            "extents": [2],
            "mount_points": ["Z:\\"],
            "info": None,
            "total_bytes": None,
        }
    )
    index = VolumeIndex(fake)
    assert index.volume_names_on(api.FILE_DEVICE_DISK, 2) == (volume_name(2),)
    assert index.volume_names_on(api.FILE_DEVICE_DISK, 3) == (volume_name(3), volume_name(4))
    # The spanned volume has no device number; it is found through its extents.
    assert index.volume_names_on(api.FILE_DEVICE_DISK, 6) == (volume_name(7),)
    assert index.volume_names_on(api.FILE_DEVICE_DISK, 7) == (volume_name(7),)
    # Disks and optical drives are numbered separately.
    assert index.volume_names_on(api.FILE_DEVICE_CD_ROM, 2) == ()
    assert index.volume_names_on(api.FILE_DEVICE_DISK, 99) == ()
    assert fake.calls["volume_names"] == 1


def test_a_volume_that_cannot_be_described_is_reported_bare(fake: FakeWinApi) -> None:
    fake.fail.add("volume_mount_points")
    devinst = fake.locate_devnode(FLASH)
    assert devinst is not None
    assert volumes_for_device(fake, devinst) == (Volume(device_node=volume_name(2)),)


# -- snapshots and the change tracker --------------------------------------------------


def test_diff_orders_removals_then_arrivals_then_changes(
    devices: dict[str, UsbDevice], clock: FakeClock
) -> None:
    old = {key.upper(): devices[key] for key in (FLASH, KEYBOARD, UASP)}
    changed = UsbDevice.from_dict({**devices[UASP].to_dict(), "volumes": []})
    new = {UASP.upper(): changed, PHONE.upper(): devices[PHONE], HUB.upper(): devices[HUB]}
    events = diff_snapshots(old, new, clock.now())
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.REMOVED, FLASH),
        (DeviceEventType.REMOVED, KEYBOARD),
        (DeviceEventType.ARRIVED, HUB),
        (DeviceEventType.ARRIVED, PHONE),
        (DeviceEventType.CHANGED, UASP),
    ]
    assert all(event.at == clock.now() for event in events)
    assert events[-1].device.volumes == ()
    assert diff_snapshots(old, old, clock.now()) == []


def test_devices_present_at_the_start_are_not_reported(fake: FakeWinApi, clock: FakeClock) -> None:
    tracker = new_tracker(fake, clock)
    tracker.prime()
    assert [device.instance_id for device in tracker.known] == ALL_DEVICES
    assert tracker.next_wait() is None
    tracker.trigger()
    clock.advance(0.25)
    assert tracker.step() == []


def test_an_arrival_is_reported_once_the_burst_has_settled(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    tracker = new_tracker(fake, clock)
    tracker.prime()

    fake.attach(unplugged)
    tracker.trigger()
    assert tracker.next_wait() == 0.25
    clock.advance(0.125)
    assert tracker.step() == []
    assert tracker.next_wait() == 0.125
    clock.advance(0.125)
    events = tracker.step()
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.ARRIVED, FLASH)
    ]
    assert events[0].at == clock.now()
    assert events[0].device.serial == "TEST0001A7C3"
    assert [volume.mount_point for volume in events[0].device.volumes] == ["E:\\"]


def test_a_composite_device_arriving_in_pieces_is_one_arrival(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    parent, *functions = fake.detach(RECEIVER)
    tracker = new_tracker(fake, clock)
    tracker.prime()

    # The device node appears first; its three interface nodes follow one by one.
    fake.attach([parent])
    tracker.trigger()
    for function in functions:
        clock.advance(0.125)
        assert tracker.step() == []
        fake.attach([function])
        tracker.trigger()
    clock.advance(0.125)
    assert tracker.step() == []
    clock.advance(0.125)
    events = tracker.step()
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.ARRIVED, RECEIVER)
    ]
    assert len(events[0].device.interfaces) == 3
    assert events[0].device.is_keyboard

    # The follow-up look finds nothing new, and then the tracker goes quiet.
    assert tracker.next_wait() == 1.0
    clock.advance(1.0)
    assert tracker.step() == []
    assert tracker.next_wait() is None


def test_a_burst_that_never_pauses_is_answered_at_the_cap(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(KEYBOARD)
    tracker = new_tracker(fake, clock, settle_seconds=0.25, max_settle_seconds=1.0)
    tracker.prime()
    fake.attach(unplugged)
    tracker.trigger()
    for _ in range(7):
        clock.advance(0.125)
        assert tracker.step() == []
        tracker.trigger()
    # 0.875 s after the first trigger and still being extended: the cap of 1 s decides.
    assert tracker.next_wait() == 0.125
    clock.advance(0.125)
    assert [event.type for event in tracker.step()] == [DeviceEventType.ARRIVED]


def test_a_storage_notification_does_not_postpone_a_pending_look(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    tracker = new_tracker(fake, clock)
    tracker.prime()
    fake.attach(unplugged)
    tracker.trigger()
    clock.advance(0.125)
    tracker.trigger(extend=False)
    assert tracker.next_wait() == 0.125
    clock.advance(0.125)
    assert [event.type for event in tracker.step()] == [DeviceEventType.ARRIVED]
    # Let the follow-up look pass, finding nothing.
    clock.advance(1.0)
    assert tracker.step() == []
    assert tracker.next_wait() is None
    # On its own, a non-extending trigger still causes a look.
    fake.detach(FLASH)
    tracker.trigger(extend=False)
    clock.advance(0.25)
    assert [event.type for event in tracker.step()] == [DeviceEventType.REMOVED]


def test_only_relevant_notifications_cause_a_look(fake: FakeWinApi, clock: FakeClock) -> None:
    tracker = new_tracker(fake, clock)
    tracker.prime()
    fake.calls.clear()

    def instance(instance_id: str) -> bytes:
        header = struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0)
        return header + utf16(instance_id) + b"\x00\x00"

    # Audio endpoints, HID collections and Bluetooth come and go all day long. None of
    # them may make the tracker enumerate.
    for unrelated in (
        "SWD\\MMDEVAPI\\{0.0.0.00000000}.{11111111-0000-4000-8000-0000000000aa}",
        "HID\\VID_1209&PID_0002\\6&5e6f7081&0&0000",
        "BTHENUM\\DEV_000000000000\\8&1&0&BLUETOOTHDEVICE",
    ):
        assert tracker.notify(instance(unrelated)) is False
    assert tracker.next_wait() is None
    clock.advance(10.0)
    assert tracker.step() == []
    assert fake.calls["present_device_ids"] == 0

    # A USB node extends the quiet period; a disk asks for a look without extending it.
    assert tracker.notify(instance(FLASH)) is True
    clock.advance(0.125)
    assert tracker.notify(instance("USBSTOR\\DISK&VEN_EXAMPLE\\TEST0001A7C3&0")) is True
    assert tracker.next_wait() == 0.125
    assert tracker.notify(instance(FLASH)) is True
    assert tracker.next_wait() == 0.25
    # A payload that cannot be decoded is treated as a reason to look.
    assert tracker.notify(b"\x00") is True
    clock.advance(0.25)
    assert tracker.step() == []
    assert fake.calls["present_device_ids"] == 1


def test_a_removal_carries_the_last_known_description(fake: FakeWinApi, clock: FakeClock) -> None:
    tracker = new_tracker(fake, clock)
    tracker.prime()
    fake.detach(UASP)
    tracker.trigger()
    clock.advance(0.25)
    events = tracker.step()
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.REMOVED, UASP)
    ]
    assert events[0].device.serial == "TEST0010UASP"
    assert len(events[0].device.volumes) == 2
    assert UASP not in [device.instance_id for device in tracker.known]


def test_a_volume_that_mounts_late_is_reported_as_a_change(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    flash_volume = fake.volumes.pop(1)
    assert flash_volume["name"] == volume_name(2)
    tracker = new_tracker(fake, clock)
    tracker.prime()

    fake.attach(unplugged)
    tracker.trigger()
    clock.advance(0.25)
    arrived = tracker.step()
    assert [event.type for event in arrived] == [DeviceEventType.ARRIVED]
    assert arrived[0].device.volumes == ()

    # Nothing announces the mount; the follow-up look one second later finds it.
    fake.volumes.append(flash_volume)
    clock.advance(1.0)
    changed = tracker.step()
    assert [(event.type, event.device.instance_id) for event in changed] == [
        (DeviceEventType.CHANGED, FLASH)
    ]
    assert [volume.mount_point for volume in changed[0].device.volumes] == ["E:\\"]
    # A follow-up that found something is followed by another, which finds nothing.
    clock.advance(1.0)
    assert tracker.step() == []
    assert tracker.next_wait() is None


def test_follow_ups_stop_even_if_the_devices_never_settle(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    tracker = new_tracker(fake, clock)
    tracker.prime()
    tracker.trigger()
    clock.advance(0.25)
    assert tracker.step() == []
    looks = 0
    while tracker.next_wait() is not None:
        # Flip a volume label before every follow-up so each one finds a change.
        fake.volumes[1]["info"]["label"] = f"LABEL{looks}"
        clock.advance(1.0)
        assert [event.type for event in tracker.step()] == [DeviceEventType.CHANGED]
        looks += 1
        assert looks < 20
    assert looks == 3


def test_a_replug_between_two_looks_is_a_removal_and_an_arrival(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    tracker = new_tracker(fake, clock)
    tracker.prime()
    # Same port, same device, but Windows recorded a newer arrival.
    fake.node(KEYBOARD)["props"]["last_arrival"] += 50_000_000
    tracker.trigger()
    clock.advance(0.25)
    events = tracker.step()
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.REMOVED, KEYBOARD),
        (DeviceEventType.ARRIVED, KEYBOARD),
    ]
    assert events[0].device.backend_data["last_arrival"] == "134000000020000000"
    assert events[1].device.backend_data["last_arrival"] == "134000000070000000"
    assert events[0].device.connection_id == KEYBOARD + "@134000000020000000"
    assert events[1].device.connection_id == KEYBOARD + "@134000000070000000"


def test_a_replug_without_an_arrival_time_is_seen_through_its_removal_notification(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    del fake.node(KEYBOARD)["props"]["last_arrival"]
    tokens = ConnectionTokens()
    tracker = ChangeTracker(
        lambda: enumerate_usb_devices(fake, tokens=tokens),
        clock,
        settle_seconds=0.25,
        max_settle_seconds=1.0,
        followup_seconds=0,
        tokens=tokens,
    )
    tracker.prime()
    before = next(device for device in tracker.known if device.instance_id == KEYBOARD)
    assert before.connection_id is not None and before.connection_id.startswith(KEYBOARD + "#")
    # Unplugged and plugged back in before the monitor looked: only the removal
    # notification tells the two connections apart.
    removal = (
        struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0)
        + utf16(KEYBOARD)
        + b"\x00\x00"
    )
    assert tracker.notify(removal, api.CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED) is True
    clock.advance(0.25)
    events = tracker.step()
    assert [(event.type, event.device.instance_id) for event in events] == [
        (DeviceEventType.REMOVED, KEYBOARD),
        (DeviceEventType.ARRIVED, KEYBOARD),
    ]
    assert events[0].device.connection_id == before.connection_id
    assert events[1].device.connection_id != before.connection_id
    # Any other notification leaves the connection alone.
    assert tracker.notify(removal, api.CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED) is True
    clock.advance(0.25)
    assert tracker.step() == []


def test_a_requested_resync_follows_the_events_of_its_look(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    tracker = new_tracker(fake, clock, followup_seconds=0)
    tracker.prime()
    fake.attach(unplugged)
    tracker.request_resync()
    tracker.request_resync()
    assert tracker.next_wait() == 0.25
    clock.advance(0.25)
    events = tracker.step()
    assert [event.type for event in events] == [DeviceEventType.ARRIVED, DeviceEventType.RESYNC]
    assert events[1].device is None and events[1].at == clock.now()
    # Answered once: the next look is an ordinary one.
    tracker.trigger()
    clock.advance(0.25)
    assert tracker.step() == []


def test_a_resync_whose_look_fails_is_answered_by_the_retry(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    tracker = new_tracker(fake, clock, followup_seconds=0)
    tracker.prime()
    fake.fail.add("present_device_ids")
    tracker.request_resync()
    clock.advance(0.25)
    assert tracker.step() == []
    fake.fail.clear()
    clock.advance(5.0)
    assert [event.type for event in tracker.step()] == [DeviceEventType.RESYNC]


def test_waking_long_after_the_planned_time_is_treated_as_a_resume(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    with pytest.raises(ValueError):
        new_tracker(fake, clock, sleep_gap_seconds=0)
    tracker = new_tracker(
        fake, clock, poll_interval=2.0, followup_seconds=0, sleep_gap_seconds=60.0
    )
    tracker.prime()
    assert tracker.next_wait() == 2.0
    # 59 s late is an ordinary delay.
    clock.advance(2.0 + 59.0)
    assert tracker.step() == []
    assert tracker.next_wait() == 2.0
    # 60 s late: the machine was most likely asleep, and anything may have changed.
    clock.advance(2.0 + 60.0)
    assert tracker.step() == []
    assert tracker.next_wait() == 0.25
    clock.advance(0.25)
    assert [event.type for event in tracker.step()] == [DeviceEventType.RESYNC]
    # A tracker that was idle (nothing scheduled) had no planned time to be late for.
    idle = new_tracker(fake, clock, followup_seconds=0, sleep_gap_seconds=60.0)
    idle.prime()
    assert idle.next_wait() is None
    clock.advance(3600.0)
    assert idle.step() == []
    assert idle.next_wait() is None


def test_an_unprimed_tracker_reports_its_first_look_as_a_resync(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    tracker = new_tracker(fake, clock)
    tracker.start_unprimed("enumeration failed (simulated)")
    assert tracker.primed is False
    assert tracker.last_error == "enumeration failed (simulated)"
    assert tracker.known == ()
    assert tracker.next_wait() == 5.0
    fake.fail.add("present_device_ids")
    clock.advance(5.0)
    assert tracker.step() == []
    assert tracker.next_wait() == 5.0
    fake.fail.clear()
    clock.advance(5.0)
    # Not one ARRIVED per present device: the receiver is told to enumerate instead.
    events = tracker.step()
    assert [(event.type, event.device) for event in events] == [(DeviceEventType.RESYNC, None)]
    assert tracker.primed is True
    assert [device.instance_id for device in tracker.known] == ALL_DEVICES
    fake.detach(FLASH)
    tracker.trigger()
    clock.advance(0.25)
    assert [event.type for event in tracker.step()] == [DeviceEventType.REMOVED]


def test_polling_finds_changes_without_any_notification(fake: FakeWinApi, clock: FakeClock) -> None:
    unplugged = fake.detach(PHONE)
    tracker = new_tracker(fake, clock, poll_interval=2.0, followup_seconds=0)
    tracker.prime()
    assert tracker.next_wait() == 2.0
    clock.advance(2.0)
    assert tracker.step() == []
    assert tracker.next_wait() == 2.0

    fake.attach(unplugged)
    clock.advance(2.0)
    # The poll notices the difference and waits for it to settle before reporting.
    assert tracker.step() == []
    assert tracker.next_wait() == 0.25
    clock.advance(0.25)
    assert [(event.type, event.device.instance_id) for event in tracker.step()] == [
        (DeviceEventType.ARRIVED, PHONE)
    ]

    fake.detach(PHONE)
    clock.advance(2.0)
    assert tracker.step() == []
    clock.advance(0.25)
    assert [event.type for event in tracker.step()] == [DeviceEventType.REMOVED]


def test_a_failed_look_keeps_the_baseline_and_is_retried(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    tracker = new_tracker(fake, clock)
    tracker.prime()
    fake.attach(unplugged)
    fake.fail.add("present_device_ids")
    tracker.trigger()
    clock.advance(0.25)
    assert tracker.step() == []
    assert tracker.last_error is not None and "simulated" in tracker.last_error
    assert FLASH not in [device.instance_id for device in tracker.known]
    assert tracker.next_wait() == 5.0

    fake.fail.clear()
    clock.advance(5.0)
    assert [(event.type, event.device.instance_id) for event in tracker.step()] == [
        (DeviceEventType.ARRIVED, FLASH)
    ]
    assert tracker.last_error is None


def test_a_failed_poll_is_recorded_and_the_next_poll_recovers(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    tracker = new_tracker(fake, clock, poll_interval=2.0)
    tracker.prime()
    fake.fail.add("present_device_ids")
    clock.advance(2.0)
    assert tracker.step() == []
    assert tracker.last_error is not None
    fake.fail.clear()
    clock.advance(2.0)
    assert tracker.step() == []
    assert tracker.last_error is None


def test_priming_fails_if_the_devices_cannot_be_enumerated(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    fake.fail.add("present_device_ids")
    with pytest.raises(BackendError):
        new_tracker(fake, clock).prime()


@pytest.mark.parametrize(
    "options",
    [
        {"settle_seconds": -0.1},
        {"followup_seconds": -1},
        {"settle_seconds": 2.0, "max_settle_seconds": 1.0},
        {"poll_interval": 0},
        {"poll_interval": -2.0},
    ],
)
def test_tracker_timing_arguments_are_validated(
    fake: FakeWinApi, clock: FakeClock, options: dict[str, float]
) -> None:
    with pytest.raises(ValueError):
        new_tracker(fake, clock, **options)


@pytest.mark.parametrize("options", [{"poll_interval": 0}, {"resync_interval": 0}])
def test_monitor_timing_arguments_are_validated(
    fake: FakeWinApi, clock: FakeClock, options: dict[str, float]
) -> None:
    with pytest.raises(ValueError):
        DeviceMonitor(fake, lambda: [], clock, **options)
    with pytest.raises(ValueError):
        WindowsBackend(fake, clock, settle_seconds=1.0, max_settle_seconds=0.5)


# -- the backend and its monitor thread ------------------------------------------------


def test_the_backend_is_a_device_backend_and_enumerates(backend: WindowsBackend) -> None:
    assert isinstance(backend, DeviceBackend)
    listed = backend.enumerate()
    assert isinstance(listed, list)
    assert [device.instance_id for device in listed] == ALL_DEVICES


def test_capabilities_before_start(backend: WindowsBackend) -> None:
    capabilities = backend.capabilities()
    assert capabilities.name == "windows"
    assert capabilities.can_enumerate is True
    assert capabilities.event_driven is True
    assert capabilities.notes[0] == "not started; will use CM_Register_Notification"
    assert any("manufacturer is not reported" in note for note in capabilities.notes)


def test_start_registers_and_stop_releases_every_notification(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    backend.start(Collector())
    assert fake.registrations == ["instances", "usb", "volume"]
    capabilities = backend.capabilities()
    assert capabilities.event_driven is True
    assert capabilities.notes[0] == (
        "notifications: CM_Register_Notification "
        "(USB device interface, volume interface, device instances)"
    )
    assert fake.resume_registrations == 1
    assert capabilities.notes[1] == "resume from sleep: PowerRegisterSuspendResumeNotification"
    backend.stop()
    assert fake.registrations == []
    assert fake.resume_registrations == 0
    assert fake.calls["unregister_notification"] == 3
    assert fake.calls["unregister_resume_notification"] == 1
    assert backend.capabilities().notes[0].startswith("not started")


def test_arrival_and_removal_reach_the_callback_from_the_backend_thread(
    fake: FakeWinApi, backend: WindowsBackend, clock: FakeClock
) -> None:
    unplugged = fake.detach(FLASH)
    collector = Collector()
    backend.start(collector)

    fake.attach(unplugged)
    fake.notify_interface(api.GUID_DEVINTERFACE_USB_DEVICE)
    arrived = collector.next()
    assert (arrived.type, arrived.device.instance_id) == (DeviceEventType.ARRIVED, FLASH)
    assert arrived.at == clock.now()
    assert arrived.device.serial == "TEST0001A7C3"

    fake.detach(FLASH)
    fake.notify_interface(
        api.GUID_DEVINTERFACE_USB_DEVICE, api.CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL
    )
    removed = collector.next()
    assert (removed.type, removed.device.instance_id) == (DeviceEventType.REMOVED, FLASH)

    backend.stop()
    assert collector.thread_names == {"portlock-win-monitor"}
    assert threading.current_thread().name not in collector.thread_names
    assert collector.events.empty()


def test_devices_present_at_start_are_not_reported_to_the_callback(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    unplugged = fake.detach(PHONE)
    collector = Collector()
    backend.start(collector)
    # A notification with nothing behind it produces a look, and the look finds nothing.
    fake.notify_instance(KEYBOARD, api.CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED)
    fake.attach(unplugged)
    fake.notify_instance(PHONE)
    first = collector.next()
    assert (first.type, first.device.instance_id) == (DeviceEventType.ARRIVED, PHONE)
    backend.stop()
    assert collector.events.empty()


def test_an_instance_notification_reports_a_device_that_never_started(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    # Enumerated but refused a driver: no device interface ever arrives for it.
    blocked = fake.detach(DISABLED)
    collector = Collector()
    backend.start(collector)
    fake.attach(blocked)
    fake.notify_instance(DISABLED, api.CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED)
    event = collector.next()
    assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, DISABLED)
    assert event.device.backend_data["started"] == "0"


def test_a_volume_notification_reports_a_change(fake: FakeWinApi, backend: WindowsBackend) -> None:
    flash_volume = fake.volumes.pop(1)
    collector = Collector()
    backend.start(collector)
    fake.volumes.append(flash_volume)
    fake.notify_interface(api.GUID_DEVINTERFACE_VOLUME)
    event = collector.next()
    assert (event.type, event.device.instance_id) == (DeviceEventType.CHANGED, FLASH)
    assert [volume.mount_point for volume in event.device.volumes] == ["E:\\"]


def test_unrelated_notifications_are_dropped_among_relevant_ones(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    unplugged = fake.detach(FLASH)
    collector = Collector()
    backend.start(collector)
    fake.attach(unplugged)
    for _ in range(50):
        fake.notify_instance(
            "SWD\\MMDEVAPI\\{0.0.0.00000000}.{11111111-0000-4000-8000-0000000000aa}"
        )
        fake.notify_instance("HID\\VID_1209&PID_0002\\6&5e6f7081&0&0000")
    fake.notify_instance(FLASH, api.CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED)
    event = collector.next()
    assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, FLASH)
    backend.stop()
    assert collector.events.empty()


def test_a_notification_storm_is_one_arrival_and_few_looks(fake: FakeWinApi) -> None:
    # Real time and a real settle period: 5000 notifications, far more than the queue
    # holds, must coalesce instead of causing 5000 enumerations or an error.
    unplugged = fake.detach(RECEIVER)
    backend = WindowsBackend(
        fake, settle_seconds=0.05, max_settle_seconds=0.2, followup_seconds=0, resync_interval=None
    )
    collector = Collector()
    backend.start(collector)
    try:
        fake.attach(unplugged)
        for _ in range(2500):
            fake.notify_instance(RECEIVER)
            fake.notify_interface(api.GUID_DEVINTERFACE_USB_DEVICE)
        event = collector.next()
        assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, RECEIVER)
        assert len(event.device.interfaces) == 3
        assert event.at.tzinfo is not None
        # The queue overflowed, so the receiver is told it may have missed something.
        resync = collector.next()
        assert (resync.type, resync.device) == (DeviceEventType.RESYNC, None)
    finally:
        backend.stop()
    # Further RESYNCs are allowed (the storm may outlast a look); anything else is not.
    while not collector.events.empty():
        assert collector.events.get().type is DeviceEventType.RESYNC
    assert fake.calls["present_device_ids"] <= 25


def test_starting_twice_is_an_error_and_stop_is_idempotent(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    backend.stop()  # not started: nothing to do, no error
    backend.start(Collector())
    with pytest.raises(BackendError) as raised:
        backend.start(Collector())
    assert raised.value.code == "already_started"
    # The failed second start must not have disturbed the first.
    assert fake.registrations == ["instances", "usb", "volume"]
    backend.stop()
    backend.stop()
    assert fake.registrations == []


def test_the_backend_can_be_restarted(fake: FakeWinApi, backend: WindowsBackend) -> None:
    first = Collector()
    backend.start(first)
    backend.stop()
    unplugged = fake.detach(KEYBOARD)
    second = Collector()
    backend.start(second)
    fake.attach(unplugged)
    fake.notify_interface()
    event = second.next()
    assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, KEYBOARD)
    assert first.events.empty()


def test_nothing_is_delivered_after_stop(fake: FakeWinApi, backend: WindowsBackend) -> None:
    unplugged = fake.detach(FLASH)
    collector = Collector()
    backend.start(collector)
    backend.stop()
    fake.attach(unplugged)
    fake.notify_interface()
    fake.notify_instance(FLASH)
    assert collector.events.empty()
    assert fake.calls["present_device_ids"] == 1  # only the baseline taken at start


def test_a_callback_that_raises_does_not_stop_the_backend(
    fake: FakeWinApi, backend: WindowsBackend, caplog: pytest.LogCaptureFixture
) -> None:
    collector = Collector()
    seen: list[str] = []

    def fragile(event: DeviceEvent) -> None:
        seen.append(event.device.instance_id)
        if len(seen) == 1:
            raise RuntimeError("callback bug")
        collector(event)

    flash = fake.detach(FLASH)
    phone = fake.detach(PHONE)
    backend.start(fragile)
    fake.attach(flash)
    fake.notify_interface()
    fake.attach(phone)
    fake.notify_interface()
    delivered = collector.next()
    backend.stop()
    assert seen[0] == FLASH
    assert delivered.device.instance_id == PHONE
    assert "the device event callback failed" in caplog.text


def test_stop_may_be_called_from_inside_the_callback(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    stopped = threading.Event()

    def stop_on_first_event(_event: DeviceEvent) -> None:
        backend.stop()
        stopped.set()

    unplugged = fake.detach(FLASH)
    backend.start(stop_on_first_event)
    fake.attach(unplugged)
    fake.notify_interface()
    assert stopped.wait(10)
    assert fake.registrations == []
    # And the backend is usable again afterwards.
    collector = Collector()
    backend.start(collector)
    assert fake.registrations == ["instances", "usb", "volume"]


def test_a_failed_baseline_starts_anyway_and_resyncs_once_devices_can_be_listed(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    fake.fail.add("present_device_ids")
    collector = Collector()
    backend.start(collector)
    assert fake.registrations == ["instances", "usb", "volume"]
    fake.fail.clear()
    fake.notify_interface()
    event = collector.next()
    assert (event.type, event.device) == (DeviceEventType.RESYNC, None)
    # From then on the devices listed at that moment are the baseline.
    fake.detach(FLASH)
    fake.notify_interface(
        api.GUID_DEVINTERFACE_USB_DEVICE, api.CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL
    )
    removed = collector.next()
    assert (removed.type, removed.device.instance_id) == (DeviceEventType.REMOVED, FLASH)
    backend.stop()
    assert collector.events.empty()


def test_a_resume_from_sleep_is_reported_as_resync(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    collector = Collector()
    backend.start(collector)
    # Going to sleep is not a reason to resynchronize; waking up is.
    unplugged = fake.detach(PHONE)
    fake.attach(unplugged)
    fake.notify_power(api.PBT_APMSUSPEND)
    fake.detach(FLASH)
    fake.notify_interface()
    first = collector.next()
    assert (first.type, first.device.instance_id) == (DeviceEventType.REMOVED, FLASH)
    fake.notify_power(api.PBT_APMRESUMEAUTOMATIC)
    fake.notify_power(api.PBT_APMRESUMESUSPEND)
    resync = collector.next()
    assert (resync.type, resync.device) == (DeviceEventType.RESYNC, None)
    backend.stop()
    # The two resume events may be answered together or one after the other.
    while not collector.events.empty():
        assert collector.events.get().type is DeviceEventType.RESYNC


def test_a_failed_resume_registration_is_explained_and_does_not_stop_monitoring(
    fake: FakeWinApi, clock: FakeClock
) -> None:
    fake.fail_register.add("resume")
    backend = WindowsBackend(
        fake,
        clock,
        settle_seconds=0,
        max_settle_seconds=0,
        followup_seconds=0,
        resync_interval=None,
    )
    backend.start(Collector())
    try:
        notes = backend.capabilities().notes
        assert notes[1] == (
            "no resume notifications: registration refused (simulated): resume; "
            "waking 60 s late is treated as a resume"
        )
        assert fake.registrations == ["instances", "usb", "volume"]
        assert fake.resume_registrations == 0
    finally:
        backend.stop()
    assert fake.calls["unregister_resume_notification"] == 0


def test_a_device_both_listed_and_reported_has_one_connection_id(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    unplugged = fake.detach(KEYBOARD)
    # No arrival time: the backend's token is what identifies the connection.
    del unplugged[0]["props"]["last_arrival"]
    collector = Collector()
    backend.start(collector)
    fake.attach(unplugged)
    # The caller enumerates after start; the device arrived in between.
    listed = {device.instance_id: device for device in backend.enumerate()}[KEYBOARD]
    assert listed.connection_id is not None and listed.connection_id.startswith(KEYBOARD + "#")
    fake.notify_instance(KEYBOARD)
    arrived = collector.next()
    assert arrived.type is DeviceEventType.ARRIVED
    assert arrived.device.connection_id == listed.connection_id
    # Unplugged and plugged back in: a new connection, a new id.
    fake.detach(KEYBOARD)
    fake.notify_instance(KEYBOARD, api.CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED)
    removed = collector.next()
    assert removed.type is DeviceEventType.REMOVED
    assert removed.device.connection_id == listed.connection_id
    fake.attach(unplugged)
    fake.notify_instance(KEYBOARD)
    again = collector.next()
    assert again.type is DeviceEventType.ARRIVED
    assert again.device.connection_id not in (None, listed.connection_id)
    # Every device the backend lists carries a connection id.
    assert all(device.connection_id for device in backend.enumerate())


def test_polling_fallback_when_notifications_do_not_exist(clock: FakeClock) -> None:
    fake = FakeWinApi(TREE, notifications=False)
    backend = WindowsBackend(
        fake, clock, settle_seconds=0, max_settle_seconds=0, followup_seconds=0, poll_interval=0.01
    )
    assert backend.capabilities().event_driven is False
    assert backend.capabilities().notes[0] == "not started; will poll every 0.01 s"
    unplugged = fake.detach(FLASH)
    collector = Collector()
    backend.start(collector)
    try:
        capabilities = backend.capabilities()
        assert capabilities.event_driven is False
        assert capabilities.notes[0] == (
            "polling every 0.01 s: CM_Register_Notification is not available"
        )
        assert fake.registrations == []
        fake.attach(unplugged)
        # No notification is sent. Time has to pass for a poll to come due.
        clock.advance(0.02)
        event = collector.next()
        assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, FLASH)
        fake.detach(FLASH)
        clock.advance(0.02)
        assert collector.next().type is DeviceEventType.REMOVED
    finally:
        backend.stop()


def test_polling_fallback_when_registration_is_refused(fake: FakeWinApi, clock: FakeClock) -> None:
    fake.fail_register.add("usb")
    backend = WindowsBackend(fake, clock, poll_interval=3.0)
    backend.start(Collector())
    try:
        capabilities = backend.capabilities()
        assert capabilities.event_driven is False
        assert capabilities.notes[0] == ("polling every 3 s: registration refused (simulated): usb")
        assert fake.registrations == []
    finally:
        backend.stop()


def test_optional_notifications_may_fail_without_losing_the_main_one(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    fake.fail_register.update({"volume", "instances"})
    unplugged = fake.detach(FLASH)
    collector = Collector()
    backend.start(collector)
    capabilities = backend.capabilities()
    assert capabilities.event_driven is True
    assert capabilities.notes[:3] == (
        "notifications: CM_Register_Notification (USB device interface)",
        "no volume interface notifications: registration refused (simulated): volume",
        "no device instances notifications: registration refused (simulated): instances",
    )
    assert fake.registrations == ["usb"]
    fake.attach(unplugged)
    fake.notify_interface()
    assert collector.next().device.instance_id == FLASH


def test_polling_can_be_forced(fake: FakeWinApi, clock: FakeClock) -> None:
    backend = WindowsBackend(fake, clock, force_polling=True, poll_interval=1.5)
    assert backend.capabilities().event_driven is False
    backend.start(Collector())
    try:
        assert backend.capabilities().notes[0] == (
            "polling every 1.5 s: notifications disabled by configuration"
        )
        assert fake.registrations == []
        assert fake.calls["register_notification"] == 0
    finally:
        backend.stop()


def test_the_safety_recheck_catches_a_change_no_notification_announced(clock: FakeClock) -> None:
    fake = FakeWinApi(TREE)
    backend = WindowsBackend(
        fake,
        clock,
        settle_seconds=0,
        max_settle_seconds=0,
        followup_seconds=0,
        resync_interval=0.01,
    )
    unplugged = fake.detach(PHONE)
    collector = Collector()
    backend.start(collector)
    try:
        assert backend.capabilities().notes[0].endswith("re-checked every 0.01 s")
        fake.attach(unplugged)
        clock.advance(0.02)
        event = collector.next()
        assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, PHONE)
    finally:
        backend.stop()


def test_a_failing_unregistration_does_not_prevent_stopping(
    fake: FakeWinApi, backend: WindowsBackend, caplog: pytest.LogCaptureFixture
) -> None:
    backend.start(Collector())
    fake.fail.add("unregister_notification")
    backend.stop()
    assert "could not unregister" in caplog.text
    assert backend.capabilities().notes[0].startswith("not started")
    fake.fail.clear()


def test_an_unavailable_api_is_reported_not_hidden(clock: FakeClock) -> None:
    backend = WindowsBackend(FakeWinApi(TREE, available=False), clock)
    capabilities = backend.capabilities()
    assert capabilities.can_enumerate is False
    assert capabilities.event_driven is False
    assert capabilities.notes == ("the Windows device API is not available on this platform",)
    with pytest.raises(BackendError) as raised:
        backend.enumerate()
    assert raised.value.code == "unsupported_platform"
    with pytest.raises(BackendError):
        backend.start(Collector())
    backend.stop()


def test_notifications_from_a_foreign_thread_are_handled(
    fake: FakeWinApi, backend: WindowsBackend
) -> None:
    # The operating system calls back on its own threads, several at once.
    unplugged = fake.detach(UASP)
    collector = Collector()
    backend.start(collector)
    fake.attach(unplugged)
    callers: list[Callable[[], None]] = [
        lambda: fake.notify_interface(),
        lambda: fake.notify_instance(UASP),
        lambda: fake.notify_interface(api.GUID_DEVINTERFACE_VOLUME),
    ]
    threads = [threading.Thread(target=call) for call in callers for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    event = collector.next()
    assert (event.type, event.device.instance_id) == (DeviceEventType.ARRIVED, UASP)
    backend.stop()
    assert collector.events.empty()
