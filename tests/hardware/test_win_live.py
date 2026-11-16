"""The Windows backend against the real machine. Read-only; opt-in with ``--run-hardware``.

These tests call the real Windows device API: they list the USB devices that are present,
read their properties and volumes, and register for (and release) device notifications.
They change nothing: no device is disabled, ejected or written to, and no setting is
touched.

Two rules keep real identifiers out of logs and reports:

* only **structure** is asserted (ranges, shapes, consistency), never a specific device;
* the only things printed are **counts and category names**. A failure is reported as a
  list of rule names with the position of the offending device in the enumeration, never
  with its instance id, serial number, product string or drive letter. That is why the
  assertions below compare lists of prepared messages instead of device fields.
"""

from __future__ import annotations

import collections
import re
import threading

import pytest

from portlock.core.errors import BackendError
from portlock.core.models import DeviceCategory, DeviceEvent, UsbDevice
from portlock.guard.base import BackendCapabilities
from portlock.guard.windows import DeviceMonitor, WinApi, WindowsBackend, enumerate_usb_devices
from portlock.guard.windows.api import (
    FILE_DEVICE_CD_ROM,
    FILE_DEVICE_DISK,
    GUID_DEVINTERFACE_USB_DEVICE,
)
from portlock.guard.windows.enumerate import NodeKind, parse_instance_id
from portlock.guard.windows.volumes import VolumeIndex, is_volume_guid_path

pytestmark = [pytest.mark.hardware, pytest.mark.windows_only]

_VOLUME_SERIAL = re.compile(r"[0-9A-F]{4}-[0-9A-F]{4}\Z")
_FLAG = frozenset({"0", "1"})
_WAIT_SECONDS = 20.0


def report(capsys: pytest.CaptureFixture[str], title: str, counts: dict[str, int]) -> None:
    """Print counts (and nothing else) even when output capture is on."""
    line = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    with capsys.disabled():
        print(f"\n[portlock live] {title}: {line}")


def stable_enumeration(api: WinApi) -> list[UsbDevice]:
    """Enumerate until two consecutive passes agree, so a device arriving mid-test is tolerated."""
    previous = enumerate_usb_devices(api)
    for _attempt in range(3):
        current = enumerate_usb_devices(api)
        if current == previous:
            return current
        previous = current
    pytest.skip("the set of USB devices kept changing while the test was running")


def check_identity(index: int, device: UsbDevice) -> list[str]:
    """Return the identity rules that device number ``index`` breaks, as safe messages."""
    broken: list[str] = []

    def require(condition: bool, rule: str) -> None:
        if not condition:
            broken.append(f"device #{index}: {rule}")

    try:
        node = parse_instance_id(device.instance_id)
    except ValueError:
        return [f"device #{index}: instance id does not parse"]
    require(node.kind in (NodeKind.DEVICE, NodeKind.ROOT_HUB), "an interface node was listed")
    require(0 <= device.vendor_id <= 0xFFFF, "vendor id out of range")
    require(0 <= device.product_id <= 0xFFFF, "product id out of range")
    require(0 <= device.device_class <= 0xFF, "device class out of range")
    require(device.bcd_device is None or 0 <= device.bcd_device <= 0xFFFF, "bcdDevice out of range")
    if node.kind is NodeKind.DEVICE:
        require(device.vendor_id == node.vendor_id, "vendor id differs from the instance id")
        require(device.product_id == node.product_id, "product id differs from the instance id")
    if device.serial is not None:
        require(bool(device.serial), "empty serial")
        require("&" not in device.serial, "a generated instance id was reported as a serial")
        require(device.serial == node.instance, "serial is not the instance segment")
        require(device.serial == device.serial.strip(), "serial has surrounding white space")
    require(device.manufacturer is None, "a driver manufacturer string was reported")
    if device.product is not None:
        # UsbDevice caps device text at 126 characters, a string descriptor's maximum.
        require(0 < len(device.product) <= 126, "product string length out of range")
        require(device.product.isprintable(), "product string has unprintable characters")
    return broken


def check_shape(index: int, device: UsbDevice) -> list[str]:
    """Return the classification, location and extras rules that device ``index`` breaks."""
    broken: list[str] = []

    def require(condition: bool, rule: str) -> None:
        if not condition:
            broken.append(f"device #{index}: {rule}")

    categories = device.categories
    require(len(categories) >= 1, "no category derived")
    require(all(isinstance(item, DeviceCategory) for item in categories), "foreign category")
    for interface in device.interfaces:
        require(
            0 <= interface.cls <= 0xFF
            and 0 <= interface.subcls <= 0xFF
            and 0 <= interface.protocol <= 0xFF,
            "interface triple out of range",
        )
    kind = device.backend_data.get("kind")
    require(kind in (NodeKind.DEVICE.value, NodeKind.ROOT_HUB.value), "unknown node kind")
    if kind == NodeKind.ROOT_HUB.value:
        require(device.is_hub, "a root hub is not classified as a hub")
        # A root hub is built in unless its host controller is removable (a dock).
        require(device.removable is not None, "a root hub's removability is unknown")
        require(device.serial is None, "a root hub has a serial")
    if device.is_hub:
        require(device.volumes == (), "a hub has volumes")
    require(device.removable in (True, False, None), "removable is not a tri-state")
    if kind == NodeKind.DEVICE.value and device.removable is False:
        # DESIGN.md 14.3: built in only directly on a root-hub port.
        parent = device.backend_data.get("parent", "")
        try:
            on_root_port = parse_instance_id(parent).kind is NodeKind.ROOT_HUB
        except ValueError:
            on_root_port = False
        require(on_root_port, "a device that is not on a root-hub port is reported as built in")
    if device.connection_id is not None:
        require(
            device.connection_id.startswith(device.instance_id),
            "connection id does not start with the instance id",
        )
        require(
            device.backend_data.get("connection_basis") == "last_arrival",
            "connection id present without an arrival time or a token store",
        )
    require(device.bus_path is None or bool(device.bus_path), "empty bus path")
    require(device.backend_data.get("started") in _FLAG, "started flag missing")
    require(device.backend_data.get("disableable") in _FLAG, "disableable flag missing")
    require(device.backend_data.get("composite") in _FLAG, "composite flag missing")
    status = device.backend_data.get("dn_status", "")
    require(re.fullmatch(r"0x[0-9a-f]{8}", status) is not None, "device status not recorded")
    try:
        rebuilt = UsbDevice.from_dict(device.to_dict())
    except (KeyError, TypeError, ValueError):
        rebuilt = None
    require(rebuilt == device, "the description does not survive serialization")
    return broken


def check_volumes(index: int, device: UsbDevice) -> list[str]:
    """Return the volume rules that device number ``index`` breaks."""
    broken: list[str] = []

    def require(condition: bool, rule: str) -> None:
        if not condition:
            broken.append(f"device #{index}: {rule}")

    nodes = [volume.device_node for volume in device.volumes]
    require(len(nodes) == len(set(nodes)), "a volume is listed twice")
    for volume in device.volumes:
        require(is_volume_guid_path(volume.device_node), "volume node is not a volume GUID path")
        require(volume.mount_point is None or bool(volume.mount_point), "empty mount point")
        require(
            volume.fs_uuid is None or _VOLUME_SERIAL.match(volume.fs_uuid) is not None,
            "volume serial has the wrong form",
        )
        require(volume.size_bytes is None or volume.size_bytes > 0, "volume size not positive")
        require(volume.read_only in (True, False, None), "read-only flag is not a tri-state")
        if volume.fs_type is None:
            # An unreadable volume (no medium, raw, locked) reports nothing about itself.
            require(
                (volume.label, volume.fs_uuid, volume.size_bytes, volume.read_only)
                == (None, None, None, None),
                "an unreadable volume reports details",
            )
    return broken


@pytest.fixture(scope="module")
def api() -> WinApi:
    real = WinApi()
    if not real.available:
        pytest.skip("the Windows device API could not be loaded")
    return real


@pytest.fixture(scope="module")
def devices(api: WinApi) -> list[UsbDevice]:
    found = stable_enumeration(api)
    if not found:
        pytest.skip("this machine has no USB host controller or device to enumerate")
    return found


def test_the_device_tree_answers_consistently(
    api: WinApi, capsys: pytest.CaptureFixture[str]
) -> None:
    node_ids = api.present_device_ids("USB")
    counts: collections.Counter[str] = collections.Counter(nodes=len(node_ids))
    problems: list[str] = []
    for index, instance_id in enumerate(node_ids):
        try:
            counts[f"kind_{parse_instance_id(instance_id).kind.value}"] += 1
        except ValueError:
            counts["unparsed"] += 1
        devinst = api.locate_devnode(instance_id)
        if devinst is None:
            # Unplugged between the two calls: allowed, and counted.
            counts["vanished"] += 1
            continue
        echoed = api.get_device_id(devinst)
        if echoed is None or echoed.upper() != instance_id.upper():
            problems.append(f"node #{index}: the instance id does not round-trip")
        status = api.get_status(devinst)
        if status is None or not all(0 <= value <= 0xFFFFFFFF for value in status):
            problems.append(f"node #{index}: no device status")
    report(capsys, "usb nodes", dict(counts))
    assert problems == []
    # Every node the USB bus enumerates has an id this module understands.
    assert counts["unparsed"] == 0


def test_enumeration_returns_well_formed_devices(
    api: WinApi, devices: list[UsbDevice], capsys: pytest.CaptureFixture[str]
) -> None:
    problems: list[str] = []
    for index, device in enumerate(devices):
        problems += check_identity(index, device)
        problems += check_shape(index, device)
        problems += check_volumes(index, device)
    keys = [device.instance_id.upper() for device in devices]
    is_sorted = keys == sorted(keys)
    is_unique = len(keys) == len(set(keys))

    counts: collections.Counter[str] = collections.Counter(devices=len(devices))
    for device in devices:
        counts[f"kind_{device.backend_data.get('kind', 'unknown')}"] += 1
        counts[f"removable_{str(device.removable).lower()}"] += 1
        counts["with_serial"] += device.serial is not None
        counts["with_arrival_time"] += device.connection_id is not None
        counts["with_product_string"] += device.product is not None
        counts["with_bcd_device"] += device.bcd_device is not None
        counts["with_bus_path"] += device.bus_path is not None
        counts["with_interfaces"] += bool(device.interfaces)
        counts["composite"] += device.is_composite
        counts["started"] += device.backend_data.get("started") == "1"
        counts["volumes"] += len(device.volumes)
        counts["mounted_volumes"] += sum(v.mount_point is not None for v in device.volumes)
    report(capsys, "devices", dict(counts))
    categories: collections.Counter[str] = collections.Counter(
        category.value for device in devices for category in device.categories
    )
    report(capsys, "categories", dict(categories))

    assert problems == []
    assert is_sorted
    assert is_unique
    # The enumeration lists exactly the device and root hub nodes the bus reports.
    expected = 0
    for instance_id in api.present_device_ids("USB"):
        try:
            expected += parse_instance_id(instance_id).kind is not NodeKind.INTERFACE
        except ValueError:
            continue
    assert abs(len(devices) - expected) <= 1, "more than one device changed during the test"


def test_the_volume_index_maps_the_systems_own_volumes(
    api: WinApi, capsys: pytest.CaptureFixture[str]
) -> None:
    """The disk-to-volume mapping, exercised on whatever volumes this machine has.

    No USB storage needs to be attached: the same three queries map any volume to its
    disk, and every Windows machine has at least the volume it started from.
    """
    names = api.volume_names()
    counts: collections.Counter[str] = collections.Counter(volumes=len(names))
    problems: list[str] = []
    index = VolumeIndex(api)
    disks: set[tuple[int, int]] = set()
    for position, name in enumerate(names):
        if not is_volume_guid_path(name):
            problems.append(f"volume #{position}: not a volume GUID path")
            continue
        number = api.storage_device_number(name[:-1])
        if number is not None and number.device_type in (FILE_DEVICE_DISK, FILE_DEVICE_CD_ROM):
            keys = [(number.device_type, number.device_number)]
            counts["with_device_number"] += 1
        else:
            keys = [(FILE_DEVICE_DISK, disk) for disk in api.volume_disk_numbers(name[:-1])]
            counts["by_disk_extents"] += bool(keys)
        if not keys:
            counts["unmapped"] += 1
        for key in keys:
            disks.add(key)
            if name not in index.volume_names_on(*key):
                problems.append(f"volume #{position}: missing from the index of its own disk")
        mount_points = api.volume_mount_points(name)
        if not all(isinstance(path, str) and path for path in mount_points):
            problems.append(f"volume #{position}: malformed mount point list")
        counts["mounted"] += bool(mount_points)
        information = api.volume_information(name)
        if information is not None:
            counts["readable"] += 1
            if not 0 <= information.serial_number <= 0xFFFFFFFF:
                problems.append(f"volume #{position}: serial number out of range")
            total = api.volume_total_bytes(name)
            if total is not None and total <= 0:
                problems.append(f"volume #{position}: size not positive")
    counts["disks"] = len(disks)
    report(capsys, "volumes", dict(counts))
    assert problems == []
    assert counts["volumes"] >= 1
    # Windows itself runs from a mounted, readable volume on a numbered disk.
    assert counts["mounted"] >= 1
    assert counts["readable"] >= 1
    assert counts["disks"] >= 1


def test_enumeration_is_repeatable_through_the_backend(devices: list[UsbDevice]) -> None:
    backend = WindowsBackend()
    capabilities = backend.capabilities()
    assert isinstance(capabilities, BackendCapabilities)
    assert capabilities.name == "windows"
    assert capabilities.can_enumerate is True
    again = backend.enumerate()
    same_count = len(again) == len(devices)
    same_devices = again == devices
    # A device plugged in or out at this very moment is the only excuse for a difference.
    assert same_devices or not same_count or again == backend.enumerate()
    # Through the backend every device has a connection id, and it is stable while the
    # device stays connected.
    assert all(device.connection_id for device in again)
    third = backend.enumerate()
    if third == again:
        assert [d.connection_id for d in third] == [d.connection_id for d in again]


def test_the_monitor_starts_and_stops_cleanly(
    api: WinApi, capsys: pytest.CaptureFixture[str]
) -> None:
    backend = WindowsBackend(api)
    events: list[DeviceEvent] = []
    expected_event_driven = api.supports_notifications()
    assert backend.capabilities().event_driven is expected_event_driven

    for _round in range(2):  # the second round proves a stopped backend can be started again
        backend.start(events.append)
        try:
            running = backend.capabilities()
            assert running.event_driven is expected_event_driven
            if expected_event_driven:
                assert any("CM_Register_Notification" in note for note in running.notes)
            else:
                assert any("polling" in note for note in running.notes)
            with pytest.raises(BackendError) as raised:
                backend.start(events.append)
            assert raised.value.code == "already_started"
        finally:
            backend.stop()
        backend.stop()  # stopping twice is harmless
        workers = [t for t in threading.enumerate() if t.name == "portlock-win-monitor"]
        assert workers == []

    # Devices already present are never reported; anything delivered was a real change.
    well_formed = all(isinstance(event, DeviceEvent) for event in events)
    assert well_formed
    report(
        capsys,
        "monitor",
        {
            "event_driven": int(expected_event_driven),
            "events_during_test": len(events),
            "start_stop_rounds": 2,
        },
    )


def test_the_polling_fallback_runs_against_the_real_device_tree(
    api: WinApi, capsys: pytest.CaptureFixture[str]
) -> None:
    looks = 0
    polled = threading.Event()

    def snapshot() -> list[UsbDevice]:
        nonlocal looks
        looks += 1
        if looks >= 3:  # the baseline plus two polls
            polled.set()
        return enumerate_usb_devices(api)

    events: list[DeviceEvent] = []
    monitor = DeviceMonitor(api, snapshot, poll_interval=0.05, force_polling=True)
    assert monitor.event_driven is False
    monitor.start(events.append)
    try:
        assert monitor.running is True
        assert monitor.event_driven is False
        assert any("polling" in note for note in monitor.notes)
        completed = polled.wait(_WAIT_SECONDS)
    finally:
        monitor.stop()
    assert completed, "the polling monitor did not take two snapshots in time"
    assert monitor.running is False
    report(capsys, "polling", {"snapshots": looks, "events_during_test": len(events)})


def test_notifications_register_and_unregister_directly(api: WinApi) -> None:
    if not api.supports_notifications():
        pytest.skip("CM_Register_Notification is not available on this Windows version")
    received: list[int] = []

    def sink(action: int, _payload: bytes) -> None:
        received.append(action)

    handles = [
        api.register_interface_notification(GUID_DEVINTERFACE_USB_DEVICE, sink),
        api.register_instance_notification(sink),
    ]
    released = 0
    for handle in handles:
        assert handle.handle != 0
        api.unregister_notification(handle)
        released += 1
    assert released == len(handles) == 2
    # Nothing has to arrive in this short window; whatever did was an action code.
    assert all(isinstance(action, int) for action in received)


def test_resume_notifications_register_and_unregister_directly(api: WinApi) -> None:
    if not api.supports_resume_notifications():
        pytest.skip("PowerRegisterSuspendResumeNotification is not available")
    received: list[int] = []
    handle = api.register_resume_notification(received.append)
    try:
        assert handle.handle != 0
    finally:
        api.unregister_resume_notification(handle)
    assert all(isinstance(event_type, int) for event_type in received)
