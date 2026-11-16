"""Synthetic devices for tests.

Every value here is made up. Vendor and product ids are from the USB-IF prototype range
or are obviously fake; serials start with ``TEST``. Never paste a real device's serial
number into a fixture.
"""

from __future__ import annotations

from typing import Any

from portlock.core.models import UsbDevice, UsbInterface, Volume

MASS_STORAGE = UsbInterface(0x08, 0x06, 0x50)
BOOT_KEYBOARD = UsbInterface(0x03, 0x01, 0x01)
BOOT_MOUSE = UsbInterface(0x03, 0x01, 0x02)
GENERIC_HID = UsbInterface(0x03, 0x00, 0x00)
HUB = UsbInterface(0x09, 0x00, 0x00)
MTP = UsbInterface(0x06, 0x01, 0x01)
CDC_ACM = UsbInterface(0x02, 0x02, 0x01)


def make_device(**overrides: Any) -> UsbDevice:
    """A flash drive unless told otherwise. Any field can be overridden by keyword."""
    fields: dict[str, Any] = {
        "instance_id": "test/1-1",
        "vendor_id": 0x1209,
        "product_id": 0x0001,
        "serial": "TEST0001A7C3",
        "manufacturer": "Example Corp",
        "product": "Example Flash 16GB",
        "bcd_device": 0x0100,
        "device_class": 0x00,
        "interfaces": (MASS_STORAGE,),
        "bus_path": "1-1",
        "removable": True,
    }
    fields.update(overrides)
    return UsbDevice(**fields)


def flash_drive(serial: str | None = "TEST0001A7C3", **overrides: Any) -> UsbDevice:
    return make_device(serial=serial, **overrides)


def mounted_flash_drive(mount_point: str = "/media/test", **overrides: Any) -> UsbDevice:
    volume = Volume(
        device_node="/dev/sdz1",
        mount_point=mount_point,
        label="EXAMPLE",
        fs_type="vfat",
        fs_uuid="TEST-0001",
        size_bytes=16_000_000_000,
        read_only=False,
    )
    return make_device(volumes=(volume,), **overrides)


def keyboard(**overrides: Any) -> UsbDevice:
    fields: dict[str, Any] = {
        "instance_id": "test/1-2",
        "product_id": 0x0002,
        "serial": None,
        "product": "Example Keyboard",
        "interfaces": (BOOT_KEYBOARD,),
        "bus_path": "1-2",
    }
    fields.update(overrides)
    return make_device(**fields)


def mouse(**overrides: Any) -> UsbDevice:
    fields: dict[str, Any] = {
        "instance_id": "test/1-3",
        "product_id": 0x0003,
        "serial": None,
        "product": "Example Mouse",
        "interfaces": (BOOT_MOUSE,),
        "bus_path": "1-3",
    }
    fields.update(overrides)
    return make_device(**fields)


def hub(**overrides: Any) -> UsbDevice:
    fields: dict[str, Any] = {
        "instance_id": "test/1-4",
        "product_id": 0x0004,
        "serial": None,
        "product": "Example Hub",
        "device_class": 0x09,
        "interfaces": (HUB,),
        "bus_path": "1-4",
    }
    fields.update(overrides)
    return make_device(**fields)


def storage_with_keyboard(**overrides: Any) -> UsbDevice:
    """Storage that also presents a keyboard: the shape of a "BadUSB" stick."""
    fields: dict[str, Any] = {
        "instance_id": "test/1-5",
        "product_id": 0x0005,
        "serial": "TEST0005BAD1",
        "product": "Example Flash 16GB",
        "interfaces": (MASS_STORAGE, BOOT_KEYBOARD),
        "bus_path": "1-5",
    }
    fields.update(overrides)
    return make_device(**fields)


def phone(**overrides: Any) -> UsbDevice:
    fields: dict[str, Any] = {
        "instance_id": "test/1-6",
        "product_id": 0x0006,
        "serial": "TEST0006PH0N",
        "product": "Example Phone",
        "interfaces": (MTP,),
        "bus_path": "1-6",
    }
    fields.update(overrides)
    return make_device(**fields)


def internal_webcam(**overrides: Any) -> UsbDevice:
    fields: dict[str, Any] = {
        "instance_id": "test/1-7",
        "product_id": 0x0007,
        "serial": None,
        "product": "Integrated Camera",
        "device_class": 0xEF,
        "interfaces": (UsbInterface(0x0E, 0x01, 0x00), UsbInterface(0x0E, 0x02, 0x00)),
        "bus_path": "1-7",
        "removable": False,
    }
    fields.update(overrides)
    return make_device(**fields)
