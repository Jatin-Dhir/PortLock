"""Enumeration from sysfs: name rules, attribute decoding, and walking synthetic trees.

Decoding tests are pure and run everywhere. Tree tests run against ``SysfsTree``; the
ones that need interface directories or block devices (names with a colon) are marked
``linux_only`` because such a tree cannot be built on Windows.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

import portlock.guard.linux.sysfs as sysfs_module
from portlock.core.errors import BackendError
from portlock.core.models import DeviceCategory, UsbDevice, UsbInterface, Volume
from portlock.guard.linux.sysfs import (
    SECTOR_BYTES,
    connection_id,
    decode_text,
    is_device_name,
    is_interface_name,
    is_root_hub_name,
    parent_device_name,
    parse_descriptors,
    parse_hex,
    parse_removable,
    read_attribute,
    read_boot_id,
    read_usb_devices,
)
from sysfs_tree import (
    ADB,
    BOOT_KEYBOARD,
    BOOT_MOUSE,
    HUB,
    MASS_STORAGE,
    MTP,
    NESTED,
    SysfsTree,
    build_descriptors,
)

REPLACEMENT = "\N{REPLACEMENT CHARACTER}"
STORAGE = UsbInterface(0x08, 0x06, 0x50)
# Made up: the shape of /proc/sys/kernel/random/boot_id, not any machine's value.
BOOT_ID = "00000000-0000-4000-8000-00000000b007"
OTHER_BOOT_ID = "00000000-0000-4000-8000-00000000b008"


@pytest.fixture
def tree(tmp_path: Path) -> SysfsTree:
    """An empty fake ``/sys`` with one root hub, ``usb1``."""
    built = SysfsTree(tmp_path / "sys")
    built.add_root_hub(1)
    return built


def by_path(devices: list[UsbDevice]) -> dict[str, UsbDevice]:
    return {device.bus_path or "": device for device in devices}


# --- names -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["usb1", "usb12", "1-2", "1-2.3", "3-1.4.2", "10-12.7"])
def test_device_names_are_recognised(name: str) -> None:
    assert is_device_name(name)
    assert not is_interface_name(name)


@pytest.mark.parametrize("name", ["1-2:1.0", "1-2.3:1.1", "1-0:1.0", "3-1.4.2:2.11"])
def test_interface_names_are_recognised(name: str) -> None:
    assert is_interface_name(name)
    assert not is_device_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "usb",
        "usbX",
        "1-",
        "-2",
        "1-2.",
        "1-2..3",
        "1-2:1",
        "1-2:1.0\n",
        "1_2",
        "../1-2",
        "ep_00",
    ],
)
def test_other_names_are_neither(name: str) -> None:
    assert not is_device_name(name)
    assert not is_interface_name(name)


def test_only_usbn_is_a_root_hub() -> None:
    assert is_root_hub_name("usb3")
    assert not is_root_hub_name("3-1")
    assert not is_root_hub_name("usb3 ")


@pytest.mark.parametrize(
    ("name", "parent"),
    [("usb1", None), ("1-2", "usb1"), ("1-2.3", "1-2"), ("7-1.4.2", "7-1.4"), ("12-3", "usb12")],
)
def test_parent_follows_from_the_name(name: str, parent: str | None) -> None:
    assert parent_device_name(name) == parent


def test_parent_of_a_non_device_name_is_an_error() -> None:
    with pytest.raises(ValueError):
        parent_device_name("1-2:1.0")


# --- attribute decoding ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "upper", "value"),
    [
        (b"1209\n", 0xFFFF, 0x1209),
        (b"ABCD\n", 0xFFFF, 0xABCD),
        (b"09\n", 0xFF, 9),
        (b"  ff  \n", 0xFF, 0xFF),
        (b"0\n", 0xFF, 0),
    ],
)
def test_hex_attributes_decode(raw: bytes, upper: int, value: int) -> None:
    assert parse_hex(raw, upper) == value


@pytest.mark.parametrize(
    "raw",
    [None, b"", b"\n", b"zz\n", b"0x12\n", b"-1\n", b"12 34\n", b"100\n", b"\xff\xfe\n", b"1" * 9],
)
def test_bad_hex_attributes_decode_to_none(raw: bytes | None) -> None:
    assert parse_hex(raw, 0xFF) is None


def test_text_loses_the_newline_and_surrounding_whitespace() -> None:
    assert decode_text(b"Example Corp\n") == "Example Corp"
    assert decode_text(b"  padded   \n") == "padded"
    accented = "caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    assert decode_text(accented.encode() + b"\n") == accented


@pytest.mark.parametrize("raw", [None, b"", b"\n", b"   \n", b"\t\r\n"])
def test_empty_text_is_none(raw: bytes | None) -> None:
    assert decode_text(raw) is None


def test_bytes_that_are_not_utf8_become_replacement_characters() -> None:
    assert decode_text(b"Fla\xffsh\n") == f"Fla{REPLACEMENT}sh"
    assert decode_text(b"\xc3\x28\n") == f"{REPLACEMENT}("


def test_decoding_leaves_cleaning_to_the_device_model() -> None:
    """One rule for every backend: UsbDevice cleans device text, sysfs only decodes it."""
    hostile = b"Good\nforged line \x1b[2J\x00\x7f end\n"
    assert decode_text(hostile) == "Good\nforged line \x1b[2J\x00\x7f end"
    assert decode_text(b"A" * 5000) == "A" * 5000


def test_control_characters_cannot_reach_a_log_line_or_terminal(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.set_attribute("1-1", "product", b"Good\nforged line \x1b[2J\x00\x7f end\n")
    tree.set_attribute("1-1", "manufacturer", "a\N{LINE SEPARATOR}b\N{RIGHT-TO-LEFT OVERRIDE}c")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    expected = f"Good{REPLACEMENT}forged line {REPLACEMENT}[2J{REPLACEMENT}{REPLACEMENT} end"
    assert device.product == expected
    # Line separators and bidirectional overrides are replaced too (format characters).
    assert device.manufacturer == f"a{REPLACEMENT}b{REPLACEMENT}c"


def test_device_text_is_capped_by_the_model(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.set_attribute("1-1", "serial", "A" * 5000)
    device = by_path(read_usb_devices(tree.root))["1-1"]
    # A string descriptor holds at most 126 UTF-16 code units; the model caps at that.
    assert device.serial == "A" * 126


@pytest.mark.parametrize(
    ("removable", "connect_type", "expected"),
    [
        (b"removable\n", None, True),
        # "fixed" alone comes from a hub descriptor bit, not from firmware: not built in.
        (b"fixed\n", None, None),
        (b"unknown\n", None, None),
        (None, None, None),
        (b"garbage\n", None, None),
        (b"\xff\xff", None, None),
        # On a root-hub port, connect_type comes from firmware and wins.
        (b"fixed\n", b"hotplug\n", True),
        (b"removable\n", b"hardwired\n", False),
        (b"removable\n", b"unknown\n", True),
        (b"fixed\n", b"not used\n", None),
        (None, b"hardwired\n", False),
        (None, b"HARDWIRED\n", False),
        (b"REMOVABLE\n", None, True),
    ],
)
def test_removable_is_decided_from_both_attributes(
    removable: bytes | None, connect_type: bytes | None, expected: bool | None
) -> None:
    assert parse_removable(removable, connect_type) is expected


@pytest.mark.parametrize(
    ("removable", "connect_type", "expected"),
    [
        # A hub claiming that its port is hardwired proves nothing.
        (b"fixed\n", b"hardwired\n", None),
        (None, b"hardwired\n", None),
        (b"removable\n", b"hardwired\n", True),
        (b"fixed\n", None, None),
        (b"fixed\n", b"hotplug\n", True),
        (None, None, None),
    ],
)
def test_behind_a_hub_nothing_is_ever_built_in(
    removable: bytes | None, connect_type: bytes | None, expected: bool | None
) -> None:
    assert parse_removable(removable, connect_type, on_root_hub_port=False) is expected


def test_read_attribute_tolerates_missing_and_unreadable_files(tmp_path: Path) -> None:
    present = tmp_path / "idVendor"
    present.write_bytes(b"1209\n")
    assert read_attribute(present) == b"1209\n"
    assert read_attribute(tmp_path / "absent") is None
    assert read_attribute(tmp_path) is None  # a directory: reading fails with an OSError
    assert read_attribute(present, limit=2) == b"12"


# --- the descriptors attribute -----------------------------------------------------------


def test_descriptors_yield_each_interface() -> None:
    blob = build_descriptors((BOOT_KEYBOARD, BOOT_MOUSE, MASS_STORAGE))
    assert parse_descriptors(blob) == (
        UsbInterface(0x03, 0x01, 0x01),
        UsbInterface(0x03, 0x01, 0x02),
        UsbInterface(0x08, 0x06, 0x50),
    )


def test_descriptors_prefer_alternate_setting_zero() -> None:
    # Interface 0 has a vendor-specific alternate setting 1; setting 0 is what counts.
    blob = build_descriptors((MASS_STORAGE,), alternates=[(0, 1, (0xFF, 0x00, 0x00))])
    assert parse_descriptors(blob) == (STORAGE,)


def test_descriptors_use_the_active_configuration() -> None:
    first = build_descriptors((MASS_STORAGE,), configuration=1)
    second = build_descriptors((BOOT_KEYBOARD,), configuration=2)[18:]  # without device part
    blob = first + second
    assert parse_descriptors(blob, 2) == (UsbInterface(0x03, 0x01, 0x01),)
    assert parse_descriptors(blob, 1) == (STORAGE,)
    # Unconfigured, or a value the device does not have: the first configuration.
    assert parse_descriptors(blob, None) == (STORAGE,)
    assert parse_descriptors(blob, 9) == (STORAGE,)


@pytest.mark.parametrize("blob", [None, b"", b"\x00", b"\x12", b"\x12\x01" + b"\x00" * 16])
def test_descriptors_without_a_configuration_give_nothing(blob: bytes | None) -> None:
    assert parse_descriptors(blob) == ()


def test_malformed_descriptors_stop_the_parse_without_raising() -> None:
    blob = build_descriptors((MASS_STORAGE, BOOT_KEYBOARD))
    storage_end = 18 + 9 + 9 + 7
    # A zero-length descriptor would loop for ever if it were not treated as the end.
    assert parse_descriptors(blob[:storage_end] + b"\x00\x04" + blob[storage_end:]) == (STORAGE,)
    # Cut in the middle of the second interface descriptor.
    assert parse_descriptors(blob[: storage_end + 5]) == (STORAGE,)
    # A descriptor that claims to be longer than what is left.
    assert parse_descriptors(blob[:storage_end] + b"\xff\x04\x01") == (STORAGE,)
    # An interface descriptor before any configuration belongs to nothing.
    assert parse_descriptors(blob[:18] + blob[27:36]) == ()


def test_descriptors_are_capped_at_thirty_two_interfaces() -> None:
    blob = build_descriptors([(0xFF, 0x00, index) for index in range(40)])
    parsed = parse_descriptors(blob)
    assert len(parsed) == 32
    assert parsed[0].protocol == 0 and parsed[-1].protocol == 31


# --- walking a tree ----------------------------------------------------------------------


def test_a_missing_sysfs_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(BackendError) as caught:
        read_usb_devices(tmp_path / "nowhere")
    assert caught.value.code == "backend_error"


def test_a_kernel_without_a_usb_bus_has_no_devices(tmp_path: Path) -> None:
    root = tmp_path / "sys"
    (root / "bus" / "pci").mkdir(parents=True)
    assert read_usb_devices(root) == []


def test_an_unlistable_bus_directory_is_an_error(
    tree: SysfsTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_path: object) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(sysfs_module.os, "listdir", refuse)
    with pytest.raises(BackendError, match="Permission denied"):
        read_usb_devices(tree.root)


def test_a_flash_drive_is_read_in_full(tree: SysfsTree) -> None:
    tree.add_device("1-1", devnum=7)
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.vendor_id == 0x1209 and device.product_id == 0x0001
    assert device.serial == "TEST0001A7C3"
    assert device.manufacturer == "Example Corp"
    assert device.product == "Example Flash 16GB"
    assert device.bcd_device == 0x0100
    assert device.device_class == 0x00
    assert device.interfaces == (STORAGE,)
    assert device.is_storage and not device.is_hid
    assert device.bus_path == "1-1"
    assert device.removable is True
    assert device.instance_id == os.path.realpath(tree.bus_directory / "1-1")
    assert device.backend_data["sysfs_name"] == "1-1"
    assert device.backend_data["devnum"] == "7"
    assert device.backend_data["busnum"] == "1"
    assert device.backend_data["authorized"] == "1"
    assert device.backend_data["root_hub"] == "0"
    assert device.backend_data["speed"] == "480"
    assert device.connection_id is None  # no boot id given


def test_the_connection_id_is_boot_id_bus_and_device_number(tree: SysfsTree) -> None:
    tree.add_device("1-1", devnum=7)
    devices = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))
    assert devices["1-1"].connection_id == f"{BOOT_ID}:1:7"
    assert devices["usb1"].connection_id == f"{BOOT_ID}:1:1"


def test_a_re_plug_into_the_same_port_is_a_new_connection(tree: SysfsTree) -> None:
    """The sysfs path survives a re-plug; the kernel's device number does not."""
    tree.add_device("1-1", devnum=7)
    before = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))["1-1"]
    tree.remove_device("1-1")
    tree.add_device("1-1", devnum=8)
    after = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))["1-1"]
    assert after.instance_id == before.instance_id
    assert after == before  # the same device, as far as identity goes
    assert after.connection_id != before.connection_id
    assert after.connection_id == f"{BOOT_ID}:1:8"


def test_the_same_numbers_after_a_reboot_are_a_new_connection(tree: SysfsTree) -> None:
    tree.add_device("1-1", devnum=7)
    first = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))["1-1"]
    second = by_path(read_usb_devices(tree.root, boot_id=OTHER_BOOT_ID))["1-1"]
    assert first.connection_id != second.connection_id


@pytest.mark.parametrize("attribute", ["devnum", "busnum"])
def test_without_both_numbers_there_is_no_connection_id(tree: SysfsTree, attribute: str) -> None:
    tree.add_device("1-1", devnum=7)
    tree.set_attribute("1-1", attribute, "0")
    tree.add_device("1-2", serial="TEST0002")
    tree.make_unreadable("1-2", attribute)
    devices = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))
    assert devices["1-1"].connection_id is None
    assert devices["1-2"].connection_id is None


def test_a_malformed_boot_id_is_refused(tree: SysfsTree) -> None:
    with pytest.raises(ValueError, match="boot_id"):
        read_usb_devices(tree.root, boot_id="1:2")


def test_the_boot_id_is_read_and_checked(tmp_path: Path) -> None:
    good = tmp_path / "boot_id"
    good.write_text(BOOT_ID.upper() + "\n")
    assert read_boot_id(good) == BOOT_ID
    bad = tmp_path / "bad"
    bad.write_text("not-a-uuid\n")
    assert read_boot_id(bad) is None
    injected = tmp_path / "injected"
    injected.write_text(BOOT_ID + ":9:9\n")
    assert read_boot_id(injected) is None
    assert read_boot_id(tmp_path / "missing") is None


@pytest.mark.parametrize(
    ("boot_id", "busnum", "devnum"),
    [("x", 1, 1), (BOOT_ID.upper(), 1, 1), (BOOT_ID, 0, 1), (BOOT_ID, 1, 0), (BOOT_ID, 1, True)],
)
def test_connection_id_arguments_are_validated(boot_id: str, busnum: int, devnum: int) -> None:
    with pytest.raises(ValueError):
        connection_id(boot_id, busnum, devnum)


def test_a_device_without_a_serial_has_none(tree: SysfsTree) -> None:
    tree.serialless_drive("1-2")
    device = by_path(read_usb_devices(tree.root))["1-2"]
    assert device.serial is None
    assert device.product == "Example Stick"
    assert device.is_storage


def test_a_composite_keyboard_and_mouse(tree: SysfsTree) -> None:
    tree.keyboard_mouse("1-3")
    device = by_path(read_usb_devices(tree.root))["1-3"]
    assert device.interfaces == (UsbInterface(*BOOT_KEYBOARD), UsbInterface(*BOOT_MOUSE))
    assert device.categories == {DeviceCategory.KEYBOARD, DeviceCategory.MOUSE}
    assert device.is_keyboard and device.is_composite and not device.pairs_storage_with_input


def test_a_phone_shows_both_of_its_functions(tree: SysfsTree) -> None:
    tree.phone("1-5")
    device = by_path(read_usb_devices(tree.root))["1-5"]
    assert device.interfaces == (UsbInterface(*MTP), UsbInterface(*ADB))
    assert device.categories == {DeviceCategory.IMAGING, DeviceCategory.VENDOR}
    assert device.serial == "TEST0006PH0N"


def test_hubs_come_before_what_is_plugged_into_them(tree: SysfsTree) -> None:
    tree.add_root_hub(2)
    tree.hub("1-4")
    tree.add_device("1-4.2", product_id=0x0011, serial="TEST0011")
    tree.add_device("1-4.1", product_id=0x0010, serial="TEST0010")
    tree.add_device("1-10", product_id=0x0012, serial="TEST0012")
    tree.add_device("2-1", product_id=0x0013, serial="TEST0013")
    devices = read_usb_devices(tree.root)
    # Numeric, not alphabetical: 1-10 sorts after 1-4, and a hub before its ports.
    assert [device.bus_path for device in devices] == [
        "usb1", "1-4", "1-4.1", "1-4.2", "1-10", "usb2", "2-1",
    ]  # fmt: skip
    assert by_path(devices)["1-4"].is_hub
    assert by_path(devices)["1-4.1"].serial == "TEST0010"


def test_a_root_hub_is_a_hub_and_never_removable(tree: SysfsTree) -> None:
    tree.set_attribute("usb1", "removable", "removable")
    hub = by_path(read_usb_devices(tree.root))["usb1"]
    assert hub.is_hub
    assert hub.device_class == 0x09
    assert hub.interfaces == (UsbInterface(*HUB),)
    assert hub.removable is False
    assert hub.backend_data["root_hub"] == "1"


def test_a_root_hub_with_unreadable_attributes_is_still_a_hub(tree: SysfsTree) -> None:
    tree.make_unreadable("usb1", "bDeviceClass")
    tree.delete_attribute("usb1", "descriptors")
    if NESTED:
        shutil.rmtree(tree.interface_directory("usb1"))
    hub = by_path(read_usb_devices(tree.root))["usb1"]
    assert hub.is_hub and hub.device_class == 0x09
    assert hub.interfaces == (UsbInterface(0x09, 0x00, 0x00),)
    assert hub.removable is False


def test_a_built_in_device_is_not_removable(tree: SysfsTree) -> None:
    tree.internal_webcam("1-6")
    device = by_path(read_usb_devices(tree.root))["1-6"]
    assert device.removable is False
    assert device.categories == {DeviceCategory.AUDIO_VIDEO}


def test_unknown_removability_is_none(tree: SysfsTree) -> None:
    tree.add_device("1-1", removable="unknown")
    tree.add_device("1-2", removable=None, serial="TEST0002")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-1"].removable is None
    assert devices["1-2"].removable is None


def test_fixed_behind_a_removable_hub_is_still_removable(tree: SysfsTree) -> None:
    """A hub describes its own ports, so a malicious one can call its child "fixed".

    That must not earn the child the protection PortLock gives to built-in hardware.
    """
    tree.hub("1-4", removable="removable")
    tree.add_device("1-4.1", removable="fixed", serial="TEST0041")
    tree.add_device("1-4.2", removable="removable", serial="TEST0042")
    tree.hub("1-4.3", removable="fixed")
    tree.add_device("1-4.3.1", removable="fixed", serial="TEST0431")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-4"].removable is True
    assert devices["1-4.1"].removable is True
    assert devices["1-4.2"].removable is True
    # Two levels down, still behind something that can be unplugged.
    assert devices["1-4.3"].removable is True
    assert devices["1-4.3.1"].removable is True


def test_fixed_behind_a_hub_of_unknown_position_is_unknown(tree: SysfsTree) -> None:
    tree.hub("1-4", removable="unknown")
    tree.add_device("1-4.1", removable="fixed", serial="TEST0041")
    tree.add_device("1-4.2", removable="removable", serial="TEST0042")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-4"].removable is None
    assert devices["1-4.1"].removable is None
    assert devices["1-4.2"].removable is True


def test_behind_a_built_in_hub_nothing_is_built_in(tree: SysfsTree) -> None:
    """Even a hub that firmware calls hardwired does not vouch for its own ports."""
    tree.hub("1-4", removable="fixed")
    tree.set_connect_type("1-4", "hardwired")
    tree.add_device("1-4.1", removable="fixed", serial="TEST0041")
    tree.add_device("1-4.2", removable="removable", serial="TEST0042")
    tree.add_device("1-4.3", removable="unknown", serial="TEST0043")
    tree.add_device("1-4.4", removable="fixed", connect_type="hardwired", serial="TEST0044")
    tree.add_device("1-4.5", removable="fixed", connect_type="hotplug", serial="TEST0045")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-4"].removable is False
    assert devices["1-4.1"].removable is None
    assert devices["1-4.2"].removable is True
    assert devices["1-4.3"].removable is None
    assert devices["1-4.4"].removable is None
    assert devices["1-4.5"].removable is True


def test_a_hostile_hub_cannot_make_its_children_built_in(tree: SysfsTree) -> None:
    """DESIGN.md 14.3: an external hub that marks its ports hardwired and non-removable.

    Without the rule, the stick plugged into it would get the protection meant for
    internal hardware, and a keyboard-and-storage implant would never be enforced on.
    """
    tree.hub("1-4", removable="removable")
    tree.set_connect_type("1-4", "hotplug")
    tree.add_device("1-4.1", removable="fixed", connect_type="hardwired", serial="TEST0041")
    tree.hub("1-4.2", removable="fixed")
    tree.set_connect_type("1-4.2", "hardwired")
    tree.add_device("1-4.2.1", removable="fixed", connect_type="hardwired", serial="TEST0421")
    devices = by_path(read_usb_devices(tree.root))
    assert [devices[name].removable for name in ("1-4", "1-4.1", "1-4.2", "1-4.2.1")] == [
        True, True, True, True,
    ]  # fmt: skip


def test_a_hostile_hub_on_a_port_of_unknown_kind_gains_nothing(tree: SysfsTree) -> None:
    tree.hub("1-4", removable="unknown")
    tree.add_device("1-4.1", removable="fixed", connect_type="hardwired", serial="TEST0041")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-4"].removable is None
    assert devices["1-4.1"].removable is None


def test_only_a_hardwired_root_hub_port_makes_a_device_built_in(tree: SysfsTree) -> None:
    tree.add_device("1-1", removable="fixed", connect_type="hotplug")
    tree.add_device("1-2", removable="removable", connect_type="hardwired", serial="TEST0002")
    tree.add_device("1-3", removable="removable", connect_type="unknown", serial="TEST0003")
    tree.add_device("1-4", removable="fixed", serial="TEST0004")
    tree.add_device("1-5", removable="fixed", connect_type="not used", serial="TEST0005")
    tree.add_device("1-7", removable="fixed", connect_type="unknown", serial="TEST0007")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-1"].removable is True
    assert devices["1-2"].removable is False
    assert devices["1-3"].removable is True
    # "fixed" without firmware saying "hardwired" is not enough.
    assert devices["1-4"].removable is None
    assert devices["1-5"].removable is None
    assert devices["1-7"].removable is None


def test_an_unreadable_attribute_reads_as_unknown(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.make_unreadable("1-1", "serial")
    tree.make_unreadable("1-1", "bcdDevice")
    tree.make_unreadable("1-1", "removable")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.serial is None
    assert device.bcd_device is None
    assert device.removable is None
    assert device.manufacturer == "Example Corp"
    assert device.vendor_id == 0x1209


def test_a_device_whose_ids_are_unreadable_is_left_out(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.add_device("1-2", serial="TEST0002")
    tree.make_unreadable("1-1", "idVendor")
    assert [device.bus_path for device in read_usb_devices(tree.root)] == ["usb1", "1-2"]


def test_strings_that_are_not_utf8_do_not_break_enumeration(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.set_attribute("1-1", "product", b"Fla\xff\xfesh \x80\n")
    tree.set_attribute("1-1", "manufacturer", b"Evil\x1b]0;owned\x07 Corp\n")
    tree.set_attribute("1-1", "serial", b"\xff\xff\xff\xff\n")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.product == f"Fla{REPLACEMENT}{REPLACEMENT}sh {REPLACEMENT}"
    assert device.manufacturer == f"Evil{REPLACEMENT}]0;owned{REPLACEMENT} Corp"
    assert device.serial == REPLACEMENT * 4
    # The result must survive the JSON encoding used by the API and the audit log.
    assert UsbDevice.from_dict(device.to_dict()) == device
    device.display_name.encode("utf-8")


@pytest.mark.parametrize(
    ("attribute", "content"),
    [
        ("idVendor", b"12345\n"),  # more than 16 bits
        ("idVendor", b"\n"),
        ("idVendor", b"zzzz\n"),
        ("idProduct", b"-1\n"),
        ("idProduct", b"\x00\x00\x00\x00"),
    ],
)
def test_a_device_with_nonsense_ids_is_left_out(
    tree: SysfsTree, attribute: str, content: bytes
) -> None:
    tree.add_device("1-1")
    tree.set_attribute("1-1", attribute, content)
    assert [device.bus_path for device in read_usb_devices(tree.root)] == ["usb1"]


def test_nonsense_in_optional_attributes_falls_back_to_defaults(tree: SysfsTree) -> None:
    tree.add_device("1-1", devnum=3)
    tree.set_attribute("1-1", "bDeviceClass", "zz")
    tree.set_attribute("1-1", "bcdDevice", "12345")
    tree.set_attribute("1-1", "devnum", "seven")
    tree.set_attribute("1-1", "authorized", "2")
    tree.set_attribute("1-1", "speed", "480\x1b[2J")
    device = by_path(read_usb_devices(tree.root, boot_id=BOOT_ID))["1-1"]
    assert device.device_class == 0
    assert device.bcd_device is None
    assert "devnum" not in device.backend_data
    assert "authorized" not in device.backend_data
    assert "speed" not in device.backend_data
    assert device.connection_id is None


def test_a_half_removed_device_is_left_out_and_the_rest_is_kept(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.keyboard_mouse("1-3")
    tree.strip_identity("1-1")
    assert [device.bus_path for device in read_usb_devices(tree.root)] == ["usb1", "1-3"]


def test_a_device_that_vanishes_while_being_read_does_not_raise(
    tree: SysfsTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree.add_device("1-1")
    tree.keyboard_mouse("1-3")
    real_read = sysfs_module.read_attribute
    unplugged: list[str] = []

    def unplug_then_read(path: os.PathLike[str] | str, *args: int) -> bytes | None:
        # The cable is pulled after idVendor was read and before anything else is.
        if Path(path).name == "idProduct" and Path(path).parent.name == "1-1" and not unplugged:
            tree.remove_device("1-1")
            unplugged.append("1-1")
        return real_read(path, *args)

    monkeypatch.setattr(sysfs_module, "read_attribute", unplug_then_read)
    devices = read_usb_devices(tree.root)
    assert unplugged == ["1-1"]
    assert [device.bus_path for device in devices] == ["usb1", "1-3"]


def test_a_device_that_loses_its_strings_mid_read_is_still_reported(
    tree: SysfsTree, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree.add_device("1-1")
    real_read = sysfs_module.read_attribute

    def lose_strings(path: os.PathLike[str] | str, *args: int) -> bytes | None:
        if Path(path).name in {"serial", "manufacturer", "product"}:
            return None  # what open() failing with ENODEV turns into
        return real_read(path, *args)

    monkeypatch.setattr(sysfs_module, "read_attribute", lose_strings)
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert (device.serial, device.manufacturer, device.product) == (None, None, None)
    assert device.vid_pid == "1209:0001"


def test_other_entries_in_the_bus_directory_are_ignored(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    (tree.bus_directory / "README").write_text("not a device")
    (tree.bus_directory / "usbmon").mkdir()
    (tree.bus_directory / "1-x").mkdir()
    (tree.bus_directory / "1-9").mkdir()  # a device name, but an empty directory
    assert [device.bus_path for device in read_usb_devices(tree.root)] == ["usb1", "1-1"]


def test_a_deauthorized_device_is_described_by_its_descriptors(tree: SysfsTree) -> None:
    """Deauthorizing unconfigures a device: no interface directories, yet it must still be
    recognisable as a keyboard, or policy would treat it as "nothing in particular"."""
    tree.add_device(
        "1-3", product_id=0x0003, serial=None, interfaces=(BOOT_KEYBOARD,), authorized=False
    )
    device = by_path(read_usb_devices(tree.root))["1-3"]
    assert device.interfaces == (UsbInterface(*BOOT_KEYBOARD),)
    assert device.is_keyboard
    assert device.backend_data["authorized"] == "0"
    assert device.backend_data["interface_source"] == "descriptors"


def test_without_interfaces_or_descriptors_the_device_class_decides(tree: SysfsTree) -> None:
    tree.add_device(
        "1-4", device_class=0x09, interfaces=(), interface_directories=False, descriptors=False
    )
    device = by_path(read_usb_devices(tree.root))["1-4"]
    assert device.interfaces == ()
    assert device.backend_data["interface_source"] == "none"
    assert device.is_hub


def test_reading_changes_nothing(tree: SysfsTree) -> None:
    tree.flash_drive("1-1")
    tree.keyboard_mouse("1-3")

    def listing() -> list[tuple[str, int, int]]:
        found = []
        for directory, _subdirectories, files in os.walk(tree.root):
            for name in files:
                status = os.stat(os.path.join(directory, name))
                found.append((os.path.join(directory, name), status.st_size, status.st_mtime_ns))
        return sorted(found)

    before = listing()
    first = read_usb_devices(tree.root)
    assert read_usb_devices(tree.root) == first
    assert listing() == before


# --- trees that only Linux can hold ------------------------------------------------------


@pytest.mark.linux_only
def test_interfaces_come_from_the_interface_directories(tree: SysfsTree) -> None:
    # The descriptors would say "keyboard"; the directories are what the kernel bound.
    tree.add_device("1-1", interfaces=(MASS_STORAGE,))
    tree.set_attribute("1-1", "descriptors", build_descriptors((BOOT_KEYBOARD,)))
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.interfaces == (STORAGE,)
    assert device.backend_data["interface_source"] == "sysfs"


@pytest.mark.linux_only
def test_interfaces_are_ordered_by_number_not_by_name(tree: SysfsTree) -> None:
    tree.add_device("1-1", interfaces=(), interface_directories=False, descriptors=False)
    tree.set_attribute("1-1", "bNumInterfaces", "11")
    for number in (10, 2, 0, 1, 3, 4, 5, 6, 7, 8, 9):
        tree.add_interface("1-1", number, (0xFF, 0x00, number))
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert [interface.protocol for interface in device.interfaces] == list(range(11))


@pytest.mark.linux_only
def test_an_interface_without_its_class_is_skipped(tree: SysfsTree) -> None:
    tree.add_device("1-3", interfaces=(BOOT_KEYBOARD, BOOT_MOUSE), descriptors=False)
    (tree.interface_directory("1-3", 1) / "bInterfaceClass").unlink()
    tree.set_attribute("1-3", "bNumInterfaces", " 1")
    device = by_path(read_usb_devices(tree.root))["1-3"]
    assert device.interfaces == (UsbInterface(*BOOT_KEYBOARD),)


@pytest.mark.linux_only
def test_missing_subclass_and_protocol_read_as_zero(tree: SysfsTree) -> None:
    tree.add_device("1-1", interfaces=(MASS_STORAGE,), descriptors=False)
    (tree.interface_directory("1-1") / "bInterfaceSubClass").unlink()
    (tree.interface_directory("1-1") / "bInterfaceProtocol").write_bytes(b"\xff\xff\n")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.interfaces == (UsbInterface(0x08, 0x00, 0x00),)


@pytest.mark.linux_only
def test_a_device_caught_between_its_interfaces_is_completed_from_descriptors(
    tree: SysfsTree,
) -> None:
    """The kernel announces a device, then creates its interface directories one by one.

    Read in between, a storage-plus-keyboard stick would look like plain storage and
    slip past the rule that exists for exactly that shape.
    """
    tree.add_device("1-5", interfaces=(MASS_STORAGE, BOOT_KEYBOARD), interface_directories=False)
    tree.add_interface("1-5", 0, MASS_STORAGE)  # the second directory is not there yet
    device = by_path(read_usb_devices(tree.root))["1-5"]
    assert device.interfaces == (STORAGE, UsbInterface(*BOOT_KEYBOARD))
    assert device.pairs_storage_with_input
    assert device.backend_data["interface_source"] == "descriptors"


@pytest.mark.linux_only
def test_a_flash_drive_exposes_its_disk_and_partitions(tree: SysfsTree) -> None:
    tree.flash_drive("1-1")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.volumes == (
        Volume("/dev/sdb", size_bytes=31_250_000 * 512, read_only=False),
        Volume("/dev/sdb1", size_bytes=204_800 * 512, read_only=False),
        Volume("/dev/sdb2", size_bytes=31_043_152 * 512, read_only=False),
    )
    assert SECTOR_BYTES == 512
    assert device.backend_data["blockdev:/dev/sdb"] == "8:16"
    assert device.backend_data["blockdev:/dev/sdb1"] == "8:17"
    assert device.backend_data["blockdev:/dev/sdb2"] == "8:18"
    assert all(volume.mount_point is None for volume in device.volumes)


@pytest.mark.linux_only
def test_the_read_only_flag_is_read_per_block_device(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    disk = tree.add_disk("1-1", "sdc", sectors=1000, read_only=True, partitions=[("sdc1", 900)])
    (disk / "sdc1" / "ro").write_bytes(b"0\n")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert [(volume.device_node, volume.read_only) for volume in device.volumes] == [
        ("/dev/sdc", True),
        ("/dev/sdc1", False),
    ]


@pytest.mark.linux_only
def test_block_attributes_that_are_missing_or_nonsense_read_as_unknown(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    disk = tree.add_disk("1-1", "sdb", partitions=[("sdb1", 10), ("sdb2", 20)])
    (disk / "size").unlink()
    (disk / "ro").write_bytes(b"maybe\n")
    (disk / "dev").write_bytes(b"not-a-number\n")
    (disk / "sdb1" / "size").write_bytes(b"-5\n")
    (disk / "sdb2" / "partition").write_bytes(b"\xff\n")  # no longer recognisable
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.volumes == (
        Volume("/dev/sdb", size_bytes=None, read_only=None),
        Volume("/dev/sdb1", size_bytes=None, read_only=False),
    )
    assert "blockdev:/dev/sdb" not in device.backend_data
    assert device.backend_data["blockdev:/dev/sdb1"] == "8:17"


@pytest.mark.linux_only
def test_partitions_are_ordered_by_number(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    names = [(f"sdb{index}", 100 * index) for index in range(1, 12)]
    tree.add_disk("1-1", "sdb", partitions=names)
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert [volume.device_node for volume in device.volumes] == ["/dev/sdb"] + [
        f"/dev/sdb{index}" for index in range(1, 12)
    ]


@pytest.mark.linux_only
def test_a_card_reader_lists_every_slot_even_an_empty_one(tree: SysfsTree) -> None:
    tree.add_device("1-1", product="Example Card Reader")
    tree.add_disk("1-1", "sdd", sectors=0, host=7, number="8:48")
    lun1 = tree.interface_directory("1-1") / "host7" / "target7:0:0" / "7:0:0:1" / "block" / "sde"
    lun1.mkdir(parents=True)
    (lun1 / "size").write_bytes(b"62333952\n")
    (lun1 / "ro").write_bytes(b"0\n")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.volumes == (
        Volume("/dev/sdd", size_bytes=0, read_only=False),
        Volume("/dev/sde", size_bytes=62_333_952 * 512, read_only=False),
    )


@pytest.mark.linux_only
def test_volumes_belong_to_the_device_they_hang_off(tree: SysfsTree) -> None:
    tree.hub("1-4")
    tree.add_device("1-4.1", serial="TEST0041")
    tree.add_disk("1-4.1", "sdf", sectors=4096, number="8:80")
    tree.keyboard_mouse("1-3")
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-4.1"].volumes == (Volume("/dev/sdf", size_bytes=4096 * 512, read_only=False),)
    assert devices["1-4"].volumes == ()
    assert devices["1-3"].volumes == ()
    assert devices["usb1"].volumes == ()


@pytest.mark.linux_only
def test_the_block_search_does_not_follow_symlinks(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.add_device("1-2", serial="TEST0002")
    disk = tree.add_disk("1-2", "sdg", sectors=8)
    # A link from one device's interface into another device's disk, and a loop.
    (tree.interface_directory("1-1") / "host9").symlink_to(disk.parent.parent.parent.parent)
    (tree.interface_directory("1-1") / "loop").symlink_to(tree.interface_directory("1-1"))
    devices = by_path(read_usb_devices(tree.root))
    assert devices["1-1"].volumes == ()
    assert [volume.device_node for volume in devices["1-2"].volumes] == ["/dev/sdg"]


@pytest.mark.linux_only
def test_block_names_that_could_escape_dev_are_not_reported(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    block = tree.add_disk("1-1", "sdb", sectors=8).parent
    for hostile in ("..", ".hidden", "sd b", "sd\nb"):
        if hostile != "..":
            (block / hostile).mkdir()
            (block / hostile / "size").write_bytes(b"8\n")
    (block / "cciss!c0d0").mkdir()
    (block / "cciss!c0d0" / "size").write_bytes(b"16\n")
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert [volume.device_node for volume in device.volumes] == ["/dev/cciss/c0d0", "/dev/sdb"]


@pytest.mark.linux_only
def test_a_dangling_bus_link_is_skipped(tree: SysfsTree) -> None:
    tree.add_device("1-1")
    tree.keyboard_mouse("1-3")
    tree.leave_dangling_link("1-1")
    assert (tree.bus_directory / "1-1").is_symlink()
    assert [device.bus_path for device in read_usb_devices(tree.root)] == ["usb1", "1-3"]


@pytest.mark.linux_only
def test_the_instance_id_is_the_resolved_device_path(tmp_path: Path) -> None:
    tree = SysfsTree(tmp_path / "sys", controller="pci0000:00/0000:00:14.0")
    tree.add_root_hub(1)
    tree.hub("1-4")
    tree.add_device("1-4.2", serial="TEST0042")
    devices = by_path(read_usb_devices(tree.root))
    base = os.path.realpath(tree.root / "devices" / "pci0000:00" / "0000:00:14.0")
    assert devices["usb1"].instance_id == f"{base}/usb1"
    assert devices["1-4"].instance_id == f"{base}/usb1/1-4"
    assert devices["1-4.2"].instance_id == f"{base}/usb1/1-4/1-4.2"
    # The bus directory itself only holds links.
    assert "bus/usb/devices" not in devices["1-4.2"].instance_id


@pytest.mark.linux_only
def test_an_attribute_without_read_permission_reads_as_unknown(tree: SysfsTree) -> None:
    if os.geteuid() == 0:
        pytest.skip("root reads files regardless of their mode")
    tree.add_device("1-1")
    (tree.device_directory("1-1") / "serial").chmod(0o000)
    device = by_path(read_usb_devices(tree.root))["1-1"]
    assert device.serial is None
    assert device.product == "Example Flash 16GB"
