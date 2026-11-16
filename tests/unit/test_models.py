"""The device model: classification, validation and serialization."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from factories import (
    flash_drive,
    hub,
    internal_webcam,
    keyboard,
    make_device,
    mounted_flash_drive,
    mouse,
    phone,
    storage_with_keyboard,
)
from portlock.core.models import (
    Access,
    Decision,
    DecisionSource,
    DeviceCategory,
    ScanRequirement,
    Severity,
    UsbDevice,
    UsbInterface,
)
from portlock.guard.base import Action, EnforcementResult, JournalEntry, Tier


@pytest.mark.parametrize(
    ("triple", "category"),
    [
        ((0x08, 0x06, 0x50), DeviceCategory.STORAGE),
        ((0x03, 0x01, 0x01), DeviceCategory.KEYBOARD),
        ((0x03, 0x01, 0x02), DeviceCategory.MOUSE),
        ((0x03, 0x00, 0x00), DeviceCategory.HID),
        ((0x03, 0x00, 0x01), DeviceCategory.HID),
        ((0x09, 0x00, 0x00), DeviceCategory.HUB),
        ((0x02, 0x02, 0x01), DeviceCategory.SERIAL),
        ((0x02, 0x06, 0x00), DeviceCategory.NETWORK),
        ((0x02, 0x0D, 0x00), DeviceCategory.NETWORK),
        ((0x0A, 0x00, 0x00), DeviceCategory.NETWORK),
        ((0x06, 0x01, 0x01), DeviceCategory.IMAGING),
        ((0x0E, 0x01, 0x00), DeviceCategory.AUDIO_VIDEO),
        ((0x01, 0x01, 0x00), DeviceCategory.AUDIO_VIDEO),
        ((0x07, 0x01, 0x02), DeviceCategory.PRINTER),
        ((0x0B, 0x00, 0x00), DeviceCategory.SMART_CARD),
        ((0xE0, 0x01, 0x01), DeviceCategory.WIRELESS),
        ((0xFF, 0x00, 0x00), DeviceCategory.VENDOR),
        ((0xDC, 0x00, 0x00), DeviceCategory.OTHER),
    ],
)
def test_interface_classification(triple: tuple[int, int, int], category: DeviceCategory) -> None:
    assert UsbInterface(*triple).category is category


def test_device_predicates() -> None:
    assert flash_drive().is_storage and not flash_drive().is_hid
    assert keyboard().is_keyboard and keyboard().is_hid and not keyboard().is_storage
    assert mouse().is_hid and not mouse().is_keyboard
    assert hub().is_hub
    assert phone().categories == {DeviceCategory.IMAGING}
    assert not flash_drive().is_composite
    assert internal_webcam().removable is False


def test_storage_paired_with_input_is_flagged() -> None:
    device = storage_with_keyboard()
    assert device.is_composite
    assert device.pairs_storage_with_input
    assert not flash_drive().pairs_storage_with_input
    assert not keyboard().pairs_storage_with_input


def test_a_device_without_interfaces_falls_back_to_its_device_class() -> None:
    assert make_device(interfaces=(), device_class=0x09).is_hub
    assert make_device(interfaces=(), device_class=0x00).categories == {DeviceCategory.OTHER}


def test_display_helpers() -> None:
    device = flash_drive()
    assert device.vid_pid == "1209:0001"
    assert device.display_name == "Example Corp Example Flash 16GB"
    assert make_device(manufacturer=None, product=None).display_name == "USB device 1209:0001"


@pytest.mark.parametrize(
    "overrides",
    [
        {"instance_id": ""},
        {"vendor_id": -1},
        {"vendor_id": 0x10000},
        {"product_id": 0x10000},
        {"vendor_id": True},
        {"vendor_id": "0x1209"},
        {"device_class": 0x100},
        {"bcd_device": 0x10000},
    ],
)
def test_out_of_range_fields_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        make_device(**overrides)


def test_interface_fields_are_range_checked() -> None:
    with pytest.raises(ValueError):
        UsbInterface(0x100)
    with pytest.raises(ValueError):
        UsbInterface(0x08, -1)


def test_devices_are_immutable_and_hashable() -> None:
    device = flash_drive()
    with pytest.raises(FrozenInstanceError):
        device.serial = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        device.backend_data["k"] = "v"  # type: ignore[index]
    assert len({device, flash_drive()}) == 1


def test_backend_data_does_not_affect_equality() -> None:
    assert make_device(backend_data={"devinst": "17"}) == make_device(backend_data={})


def test_lists_are_accepted_and_frozen_to_tuples() -> None:
    device = make_device(interfaces=[UsbInterface(0x08, 0x06, 0x50)], volumes=[])
    assert isinstance(device.interfaces, tuple) and isinstance(device.volumes, tuple)


def test_device_round_trips_through_a_dict() -> None:
    device = mounted_flash_drive()
    data = device.to_dict()
    assert data["categories"] == ["storage"]
    assert UsbDevice.from_dict(data) == device


def test_decision_helpers_and_round_trip() -> None:
    allow = Decision(Access.ALLOW, DecisionSource.GRANT, grant_id="g1")
    read_only = Decision(Access.READ_ONLY, DecisionSource.POLICY, rule_id="r1")
    deny = Decision(Access.DENY, DecisionSource.POLICY, reasons=("blocked vendor",))
    pending = Decision(Access.PENDING, DecisionSource.DEFAULT)
    assert allow.permits_access and read_only.permits_access
    assert deny.blocks and pending.blocks

    timed = Decision(
        Access.ALLOW,
        DecisionSource.GRANT,
        reasons=("temporary grant",),
        grant_id="g2",
        scan=ScanRequirement.ON_MOUNT,
        alert=True,
        expires_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )
    assert Decision.from_dict(timed.to_dict()) == timed
    assert Decision.from_dict(deny.to_dict()) == deny


def test_severity_is_ordered() -> None:
    assert Severity.CRITICAL.rank > Severity.ERROR.rank > Severity.WARNING.rank
    assert Severity.WARNING.rank > Severity.NOTICE.rank > Severity.INFO.rank > Severity.DEBUG.rank


def test_journal_entry_and_result_serialize() -> None:
    entry = JournalEntry("sysfs", "/sys/bus/usb/devices/1-1/authorized", "1", "0")
    assert JournalEntry.from_dict(entry.to_dict()) == entry
    result = EnforcementResult(
        Action.BLOCK, True, "sysfs:authorized", Tier.REACTIVE, changed=True, undo=(entry,)
    )
    data = result.to_dict()
    assert data["action"] == "block" and data["tier"] == "reactive"
    assert data["undo"] == [entry.to_dict()]
