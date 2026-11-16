"""The Linux backend against the real machine. Read-only; opt-in with ``--run-hardware``.

These tests read the real ``/sys``, ``/proc/self/mountinfo`` and the kernel boot id, and
open (and close) the kernel uevent socket to listen. They change nothing: nothing is
written under ``/sys`` or ``/proc``, no device is deauthorized, unbound, ejected or made
read-only, and no setting is touched. No enforcement mechanism is exercised here.

Two rules keep real identifiers out of logs and reports:

* only **structure** is asserted (shapes, ranges, consistency), never a specific device;
* the only things printed are **counts and category names**. A failure names the rule
  that broke and the position of the device in the enumeration, never its path, serial
  number, product string or mount point.

Under WSL or in a container the kernel may expose no USB bus at all; the tests then
report zero devices and check that the backend says so, instead of failing.
"""

from __future__ import annotations

import collections
import re
import threading
from pathlib import Path

import pytest

from portlock.core.models import DeviceEvent, UsbDevice
from portlock.guard.linux import LinuxBackend, parse_mountinfo, read_boot_id, read_usb_devices
from portlock.guard.linux.sysfs import is_device_name, is_root_hub_name, parent_device_name

pytestmark = [pytest.mark.hardware, pytest.mark.linux_only]

SYS = Path("/sys")
MOUNTINFO = Path("/proc/self/mountinfo")
_CONNECTION_ID = re.compile(r"[0-9a-f-]{36}:[0-9]{1,5}:[0-9]{1,5}\Z")


def report(capsys: pytest.CaptureFixture[str], title: str, counts: dict[str, int]) -> None:
    """Print counts (and nothing else) even when output capture is on."""
    line = ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"
    with capsys.disabled():
        print(f"\n[portlock live] {title}: {line}")


def stable_enumeration(boot_id: str | None) -> list[UsbDevice]:
    """Enumerate until two consecutive passes agree, tolerating a device arriving mid-test."""
    previous = read_usb_devices(SYS, boot_id=boot_id)
    for _attempt in range(3):
        current = read_usb_devices(SYS, boot_id=boot_id)
        if current == previous:
            return current
        previous = current
    pytest.skip("the set of USB devices kept changing while the test was running")


def check_device(index: int, device: UsbDevice, boot_id: str | None) -> list[str]:
    """Return the structural rules that device number ``index`` breaks, as safe messages."""
    broken: list[str] = []

    def require(condition: bool, rule: str) -> None:
        if not condition:
            broken.append(f"device #{index}: {rule}")

    name = device.bus_path or ""
    require(is_device_name(name), "bus_path is a sysfs device name")
    require(device.instance_id.startswith("/sys/devices/"), "instance_id is under /sys/devices")
    require(device.backend_data.get("sysfs_name") == name, "sysfs_name matches bus_path")
    source = device.backend_data.get("interface_source")
    require(source in {"sysfs", "descriptors", "none"}, "interface_source is known")
    if is_root_hub_name(name):
        require(device.is_hub, "a root hub is a hub")
        require(device.removable is False, "a root hub is reported as built in")
    elif device.removable is False:
        parent = parent_device_name(name)
        require(
            parent is not None and is_root_hub_name(parent),
            "only a device directly on a root-hub port can be built in",
        )
    if boot_id is not None and "busnum" in device.backend_data:
        require(
            device.connection_id is not None
            and _CONNECTION_ID.fullmatch(device.connection_id) is not None
            and device.connection_id.startswith(boot_id + ":"),
            "connection_id is boot id, bus number and device number",
        )
    for text in (device.serial, device.manufacturer, device.product):
        if text is not None:
            require(len(text) <= 126, "device text is capped")
            require(text.isprintable(), "device text holds no control or format characters")
    for volume in device.volumes:
        require(volume.device_node.startswith("/dev/"), "volume nodes are under /dev")
    return broken


def test_the_boot_id_is_readable(capsys: pytest.CaptureFixture[str]) -> None:
    boot_id = read_boot_id()
    report(capsys, "boot id", {"readable": int(boot_id is not None)})
    assert boot_id is not None


def test_sysfs_enumeration_is_well_formed(capsys: pytest.CaptureFixture[str]) -> None:
    boot_id = read_boot_id()
    has_bus = (SYS / "bus" / "usb" / "devices").is_dir()
    devices = stable_enumeration(boot_id)
    counts: collections.Counter[str] = collections.Counter()
    counts["usb_bus_present"] = int(has_bus)
    counts["devices"] = len(devices)
    for device in devices:
        counts["root_hubs"] += int(is_root_hub_name(device.bus_path or ""))
        counts[f"removable_{str(device.removable).lower()}"] += 1
        counts["with_connection_id"] += int(device.connection_id is not None)
        counts["with_volumes"] += int(bool(device.volumes))
        counts[f"interfaces_from_{device.backend_data.get('interface_source')}"] += 1
        for category in device.categories:
            counts[f"category_{category.value}"] += 1
    report(capsys, "sysfs", dict(counts))

    if not has_bus:
        assert devices == []
        return
    broken = [
        rule
        for index, device in enumerate(devices)
        for rule in check_device(index, device, boot_id)
    ]
    assert broken == []
    ids = [device.instance_id for device in devices]
    assert len(set(ids)) == len(ids), "instance ids are unique"
    connections = [device.connection_id for device in devices if device.connection_id]
    assert len(set(connections)) == len(connections), "connection ids are unique"


def test_the_mount_table_parses(capsys: pytest.CaptureFixture[str]) -> None:
    entries = parse_mountinfo(MOUNTINFO)
    report(
        capsys,
        "mount table",
        {"entries": len(entries), "read_only": sum(entry.read_only for entry in entries)},
    )
    assert entries
    assert any(entry.mount_point == "/" for entry in entries)
    assert all(entry.mount_point.startswith("/") for entry in entries)


def test_capabilities_describe_this_machine(capsys: pytest.CaptureFixture[str]) -> None:
    capabilities = LinuxBackend().capabilities()
    report(
        capsys,
        "capabilities",
        {
            "can_enumerate": int(capabilities.can_enumerate),
            "event_driven": int(capabilities.event_driven),
            "notes": len(capabilities.notes),
        },
    )
    assert capabilities.name == "linux"
    assert capabilities.can_enumerate == (SYS / "bus" / "usb" / "devices").is_dir()
    if not capabilities.can_enumerate:
        assert any("no USB bus" in note for note in capabilities.notes)


def test_the_backend_starts_listens_and_stops(capsys: pytest.CaptureFixture[str]) -> None:
    """Start first, enumerate afterwards (the DeviceBackend contract), then stop cleanly."""
    backend = LinuxBackend()
    events: list[DeviceEvent] = []
    backend.start(events.append)
    try:
        running = backend.capabilities()
        devices = backend.enumerate()
    finally:
        backend.stop()
    leftover = [
        thread.name for thread in threading.enumerate() if thread.name.startswith("portlock-")
    ]
    report(
        capsys,
        "monitoring",
        {
            "event_driven": int(running.event_driven),
            "devices_after_start": len(devices),
            "events_during_test": len(events),
            "threads_left": len(leftover),
        },
    )
    assert leftover == []
