"""Windows identification strings and API buffers: the pure parsing functions.

Everything here runs without Windows. The vectors in ``tests/fixtures/win/ids.json`` are
synthetic: vendor id 0x1209 and serials that start with ``TEST``.
"""

from __future__ import annotations

import ctypes
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

from portlock.core.errors import BackendError
from portlock.core.models import DeviceCategory, UsbInterface
from portlock.guard.windows import api
from portlock.guard.windows.enumerate import (
    CompatibleIds,
    ConnectionTokens,
    HardwareIds,
    NodeKind,
    connection_id_for,
    decode_filetime,
    decode_guid,
    decode_int,
    decode_multi_sz,
    decode_string,
    decode_string_list,
    is_synthesized_instance,
    parse_compatible_ids,
    parse_hardware_ids,
    parse_instance_id,
    parse_location_paths,
)
from portlock.guard.windows.monitor import classify_notification, removed_usb_instance
from portlock.guard.windows.volumes import (
    format_volume_serial,
    is_volume_guid_path,
    pick_mount_point,
)

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "win" / "ids.json").read_text(encoding="utf-8")
)
POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def multi_sz(*strings: str) -> bytes:
    return b"".join(utf16(text) + b"\x00\x00" for text in strings) + b"\x00\x00"


def by_case(section: str) -> list[Any]:
    return [pytest.param(vector, id=vector["case"]) for vector in VECTORS[section]]


# -- instance ids ----------------------------------------------------------------------


@pytest.mark.parametrize("vector", by_case("instance_ids"))
def test_instance_ids_parse(vector: dict[str, Any]) -> None:
    parsed = parse_instance_id(vector["id"])
    assert parsed.text == vector["id"]
    assert parsed.kind is NodeKind(vector["kind"])
    assert parsed.vendor_id == vector["vendor_id"]
    assert parsed.product_id == vector["product_id"]
    assert parsed.interface_number == vector["interface_number"]
    assert parsed.serial == vector["serial"]
    assert f"{parsed.enumerator}\\{parsed.device_id}\\{parsed.instance}" == vector["id"]


@pytest.mark.parametrize("text", VECTORS["malformed_instance_ids"], ids=repr)
def test_malformed_instance_ids_are_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        parse_instance_id(text)


@pytest.mark.parametrize("value", [None, b"USB\\VID_1209&PID_0001\\TEST0001A7C3", 7, ["USB"]])
def test_an_instance_id_must_be_a_string(value: object) -> None:
    with pytest.raises(ValueError):
        parse_instance_id(value)  # type: ignore[arg-type]


def test_a_real_serial_is_reported_and_a_generated_one_is_not() -> None:
    assert parse_instance_id("USB\\VID_1209&PID_0001\\TEST0001A7C3").serial == "TEST0001A7C3"
    generated = parse_instance_id("USB\\VID_1209&PID_0002\\5&1a2b3c4d&0&2")
    assert generated.serial is None
    assert generated.instance == "5&1a2b3c4d&0&2"
    assert is_synthesized_instance("5&1a2b3c4d&0&2")
    assert not is_synthesized_instance("TEST0001A7C3")
    # One ampersand anywhere is enough: the hub driver never lets one into a serial.
    assert parse_instance_id("USB\\VID_1209&PID_0001\\TEST&0001").serial is None


def test_an_interface_node_never_has_a_serial() -> None:
    node = parse_instance_id("USB\\VID_1209&PID_0008&MI_00\\NOAMPERSAND")
    assert node.kind is NodeKind.INTERFACE
    assert node.interface_number == 0
    assert node.serial is None


@pytest.mark.parametrize("device_id", ["ROOT_HUB", "ROOT_HUB20", "ROOT_HUB30", "root_hub31"])
def test_root_hub_generations_are_recognised(device_id: str) -> None:
    node = parse_instance_id(f"USB\\{device_id}\\4&0a0b0c0d&0&0")
    assert node.kind is NodeKind.ROOT_HUB
    assert (node.vendor_id, node.product_id, node.serial) == (None, None, None)


def test_an_id_at_the_length_limit_is_rejected_and_one_below_it_is_not() -> None:
    prefix = "USB\\VID_1209&PID_0001\\"
    longest = prefix + "S" * (api.MAX_DEVICE_ID_LEN - 1 - len(prefix))
    assert len(longest) == api.MAX_DEVICE_ID_LEN - 1
    assert parse_instance_id(longest).serial == longest[len(prefix) :]
    with pytest.raises(ValueError):
        parse_instance_id(longest + "S")


# -- hardware and compatible ids -------------------------------------------------------


@pytest.mark.parametrize("vector", by_case("hardware_ids"))
def test_hardware_ids_parse(vector: dict[str, Any]) -> None:
    assert parse_hardware_ids(vector["ids"]) == HardwareIds(
        vector["vendor_id"], vector["product_id"], vector["revision"], vector["interface_number"]
    )


def test_revision_is_bcd_device() -> None:
    # REV_0100 is release 1.00: the digits are the BCD value, not a decimal number.
    assert parse_hardware_ids(["USB\\VID_1209&PID_0001&REV_0100"]).revision == 0x0100
    assert parse_hardware_ids(["USB\\VID_1209&PID_0001&REV_9999"]).revision == 0x9999


@pytest.mark.parametrize("vector", by_case("compatible_ids"))
def test_compatible_ids_parse(vector: dict[str, Any]) -> None:
    parsed = parse_compatible_ids(vector["ids"])
    assert parsed.interfaces == tuple(UsbInterface(*triple) for triple in vector["interfaces"])
    expected_class = vector["device_class"]
    assert parsed.device_class == (UsbInterface(*expected_class) if expected_class else None)
    assert parsed.composite is vector["composite"]
    assert parsed.hub is vector["hub"]
    assert parsed.tags == tuple(vector["tags"])


def test_compatible_ids_classify_the_way_policy_expects() -> None:
    def categories(*ids: str) -> set[DeviceCategory]:
        return {interface.category for interface in parse_compatible_ids(ids).interfaces}

    assert categories("USB\\Class_08&SubClass_06&Prot_50") == {DeviceCategory.STORAGE}
    assert categories("USB\\Class_08&SubClass_06&Prot_62", "USB\\Class_08&SubClass_06&Prot_50") == {
        DeviceCategory.STORAGE
    }
    assert categories("USB\\Class_03&SubClass_01&Prot_01") == {DeviceCategory.KEYBOARD}
    assert categories("USB\\Class_03&SubClass_01&Prot_02") == {DeviceCategory.MOUSE}
    assert categories("USB\\MS_COMP_MTP", "USB\\Class_06&SubClass_01&Prot_01") == {
        DeviceCategory.IMAGING
    }
    assert categories("USB\\Class_09&SubClass_00&Prot_00") == {DeviceCategory.HUB}


def test_the_vendor_qualified_form_without_an_underscore_is_understood() -> None:
    # Current Windows writes "Prot00" in exactly this one form.
    parsed = parse_compatible_ids(["USB\\COMPAT_VID_1209&DevClass_EF&SubClass_02&Prot01"])
    assert parsed.device_class == UsbInterface(0xEF, 0x02, 0x01)
    assert parsed.interfaces == ()


def test_a_vendor_qualified_id_does_not_duplicate_the_plain_one() -> None:
    parsed = parse_compatible_ids(
        ["USB\\COMPAT_VID_1209&Class_03&SubClass_01&Prot_02", "USB\\Class_03&SubClass_01&Prot_02"]
    )
    assert parsed.interfaces == (UsbInterface(3, 1, 2),)
    assert parse_compatible_ids(["USB\\COMPAT_VID_1209"]) == CompatibleIds()


def test_only_a_bounded_number_of_ids_is_read() -> None:
    padding = ["USB\\Class_FF"] * 64
    assert parse_compatible_ids([*padding, "USB\\Class_08&SubClass_06&Prot_50"]).interfaces == (
        UsbInterface(0xFF),
    )
    assert parse_hardware_ids([*padding, "USB\\VID_1209&PID_0001&REV_0100"]) == HardwareIds()


def test_id_lists_tolerate_values_that_are_not_strings() -> None:
    assert parse_compatible_ids([None, 8, b"USB\\Class_08"]) == CompatibleIds()  # type: ignore[list-item]
    assert parse_hardware_ids([None, 8]) == HardwareIds()  # type: ignore[list-item]


# -- location paths --------------------------------------------------------------------


@pytest.mark.parametrize("vector", by_case("location_paths"))
def test_location_paths_parse(vector: dict[str, Any]) -> None:
    location = parse_location_paths(vector["paths"])
    assert location is not None
    assert location.path == vector["path"]
    assert location.controller == vector["controller"]
    assert location.ports == tuple(vector["ports"])


@pytest.mark.parametrize("paths", VECTORS["malformed_location_paths"], ids=repr)
def test_malformed_location_paths_give_nothing(paths: list[str]) -> None:
    assert parse_location_paths(paths) is None


def test_location_paths_tolerate_values_that_are_not_strings() -> None:
    assert parse_location_paths([None, 3]) is None  # type: ignore[list-item]


# -- string buffers --------------------------------------------------------------------


def test_decode_multi_sz() -> None:
    assert decode_multi_sz(multi_sz("USB\\VID_1209&PID_0001&REV_0100", "USB\\VID_1209")) == (
        "USB\\VID_1209&PID_0001&REV_0100",
        "USB\\VID_1209",
    )
    assert decode_multi_sz(multi_sz()) == ()
    assert decode_multi_sz(b"") == ()
    assert decode_multi_sz(multi_sz("only")) == ("only",)


def test_decode_multi_sz_survives_malformed_buffers() -> None:
    # No terminators at all: the one string is still returned.
    assert decode_multi_sz(utf16("unterminated")) == ("unterminated",)
    # An odd trailing byte is dropped, not decoded.
    assert decode_multi_sz(utf16("a") + b"\x00\x00" + b"\x41") == ("a",)
    # Decoding stops at the empty string that ends the list; what follows is not data.
    assert decode_multi_sz(multi_sz("first") + utf16("after the end") + b"\x00\x00") == ("first",)
    # A lone surrogate is replaced instead of raising.
    lone_surrogate = struct.pack("<H", 0xD800)
    decoded = decode_multi_sz(utf16("x") + lone_surrogate + b"\x00\x00\x00\x00")
    assert len(decoded) == 1 and decoded[0].startswith("x") and len(decoded[0]) == 2


def test_decode_utf16_stops_at_the_terminator() -> None:
    assert api.decode_utf16(utf16("E:\\") + b"\x00\x00" + utf16("junk")) == "E:\\"
    assert api.decode_utf16(utf16("no terminator")) == "no terminator"
    assert api.decode_utf16(b"") == ""
    assert api.decode_utf16(b"\x41") == ""


# -- property values -------------------------------------------------------------------


def test_string_properties_are_type_checked() -> None:
    assert decode_string((api.DEVPROP_TYPE_STRING, utf16("USBSTOR") + b"\x00\x00")) == "USBSTOR"
    assert decode_string((api.DEVPROP_TYPE_STRING, b"\x00\x00")) is None
    assert decode_string((api.DEVPROP_TYPE_STRING_LIST, multi_sz("USBSTOR"))) is None
    assert decode_string((api.DEVPROP_TYPE_UINT32, b"\x01\x00\x00\x00")) is None
    assert decode_string(None) is None
    assert decode_string_list((api.DEVPROP_TYPE_STRING_LIST, multi_sz("a", "b"))) == ("a", "b")
    assert decode_string_list((api.DEVPROP_TYPE_STRING, utf16("a") + b"\x00\x00")) == ()
    assert decode_string_list(None) == ()


def test_integer_properties_accept_both_documented_and_observed_types() -> None:
    raw = struct.pack("<I", 0x94)
    assert decode_int((api.DEVPROP_TYPE_UINT32, raw)) == 0x94
    assert decode_int((api.DEVPROP_TYPE_INT32, raw)) == 0x94
    # A value with the top bit set stays a bit mask rather than turning negative.
    assert decode_int((api.DEVPROP_TYPE_INT32, b"\xff\xff\xff\xff")) == 0xFFFFFFFF
    assert decode_int((api.DEVPROP_TYPE_UINT32, b"\x01\x00")) is None
    assert decode_int((api.DEVPROP_TYPE_UINT32, raw + b"\x00")) is None
    assert decode_int((api.DEVPROP_TYPE_STRING, raw)) is None
    assert decode_int(None) is None


def test_guid_and_filetime_properties() -> None:
    value = uuid.UUID("11111111-0000-4000-8000-000000000001")
    assert decode_guid((api.DEVPROP_TYPE_GUID, value.bytes_le)) == value
    assert decode_guid((api.DEVPROP_TYPE_GUID, value.bytes_le[:15])) is None
    assert decode_guid((api.DEVPROP_TYPE_STRING, value.bytes_le)) is None
    assert decode_guid(None) is None
    ticks = 134000000010000000
    assert decode_filetime((api.DEVPROP_TYPE_FILETIME, struct.pack("<Q", ticks))) == ticks
    assert decode_filetime((api.DEVPROP_TYPE_FILETIME, b"\x00" * 4)) is None
    assert decode_filetime((api.DEVPROP_TYPE_UINT32, struct.pack("<Q", ticks))) is None
    assert decode_filetime(None) is None


# -- connection ids --------------------------------------------------------------------


def test_connection_id_prefers_the_last_arrival_time() -> None:
    tokens = ConnectionTokens()
    instance = "USB\\VID_1209&PID_0001\\TEST0001A7C3"
    assert connection_id_for(instance, 134000000010000000, tokens) == (
        instance + "@134000000010000000"
    )
    # Nothing was issued: a device with an arrival time needs no token.
    assert tokens.forget(instance) is False
    # A zero FILETIME means "never recorded" and is not an arrival time.
    assert connection_id_for(instance, 0, None) is None
    assert connection_id_for(instance, None, None) is None


def test_a_token_lasts_until_the_instance_is_seen_gone() -> None:
    tokens = ConnectionTokens()
    instance = "USB\\VID_1209&PID_0002\\5&1a2b3c4d&0&2"
    first = connection_id_for(instance, None, tokens)
    assert first is not None and first.startswith(instance + "#")
    assert len(first) == len(instance) + 1 + 16
    # Same connection, any spelling of the id: same token.
    assert connection_id_for(instance.lower(), None, tokens) == instance.lower() + first[-17:]
    # A removal notification ends the connection.
    assert tokens.forget(instance) is True
    second = connection_id_for(instance, None, tokens)
    assert second != first
    # So does a completed pass that did not find it...
    marker = tokens.begin_pass()
    tokens.end_pass(marker, [])
    third = connection_id_for(instance, None, tokens)
    assert third not in (first, second)
    # ...but a pass that started before the token was issued cannot end it.
    stale = marker
    tokens.end_pass(stale, [])
    assert connection_id_for(instance, None, tokens) == third
    tokens.end_pass(tokens.begin_pass(), [instance.upper()])
    assert connection_id_for(instance, None, tokens) == third


def test_only_the_removal_of_a_usb_instance_ends_a_connection() -> None:
    removed = api.CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED
    flash = "USB\\VID_1209&PID_0001\\TEST0001A7C3"
    assert removed_usb_instance(removed, instance_payload(flash)) == flash
    assert (
        removed_usb_instance(api.CM_NOTIFY_ACTION_DEVICEINSTANCEENUMERATED, instance_payload(flash))
        is None
    )
    assert removed_usb_instance(None, instance_payload(flash)) is None
    assert removed_usb_instance(removed, instance_payload("HID\\VID_1209&PID_0002\\6&0")) is None
    link = interface_payload(api.GUID_DEVINTERFACE_USB_DEVICE, "\\\\?\\USB#VID_1209")
    assert removed_usb_instance(removed, link) is None
    assert removed_usb_instance(removed, b"\x02") is None


# -- IOCTL results and notification payloads -------------------------------------------


def test_storage_device_number_decoding() -> None:
    number = api.decode_storage_device_number(struct.pack("<III", 7, 2, 1))
    assert number == api.StorageDeviceNumber(api.FILE_DEVICE_DISK, 2, 1)
    whole = api.decode_storage_device_number(struct.pack("<III", 2, 0, 0xFFFFFFFF))
    assert whole == api.StorageDeviceNumber(api.FILE_DEVICE_CD_ROM, 0, None)
    assert api.decode_storage_device_number(struct.pack("<II", 7, 2)) is None
    assert api.decode_storage_device_number(b"") is None


def test_disk_extents_decoding() -> None:
    def extents(count: int, *disks: int) -> bytes:
        body = b"".join(struct.pack("<I4xqq", disk, 1 << 20, 1 << 30) for disk in disks)
        return struct.pack("<I4x", count) + body

    assert api.decode_disk_extents(extents(1, 3)) == (3,)
    assert api.decode_disk_extents(extents(3, 6, 7, 6)) == (6, 7)
    # The header promises more extents than the buffer holds: only whole ones count.
    assert api.decode_disk_extents(extents(5, 4)) == (4,)
    assert api.decode_disk_extents(extents(2, 4)[:-1]) == ()
    assert api.decode_disk_extents(extents(0)) == ()
    assert api.decode_disk_extents(b"\x01\x00") == ()
    # A hostile count cannot make the decoder read or loop without bound.
    assert api.decode_disk_extents(struct.pack("<I4x", 0xFFFFFFFF)) == ()


def instance_payload(instance_id: str) -> bytes:
    return (
        struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, 0)
        + utf16(instance_id)
        + (b"\x00\x00")
    )


def interface_payload(class_guid: uuid.UUID, link: str) -> bytes:
    header = struct.pack("<II", api.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, 0)
    return header + class_guid.bytes_le + utf16(link) + b"\x00\x00"


def test_notification_payload_decoding() -> None:
    instance = api.decode_notify_event(instance_payload("USB\\VID_1209&PID_0001\\TEST0001A7C3"))
    assert instance == api.NotifyEvent(
        api.CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, "USB\\VID_1209&PID_0001\\TEST0001A7C3"
    )
    link = "\\\\?\\USB#VID_1209&PID_0001#TEST0001A7C3#{a5dcbf10-6530-11d2-901f-00c04fb951ed}"
    interface = api.decode_notify_event(interface_payload(api.GUID_DEVINTERFACE_USB_DEVICE, link))
    assert interface == api.NotifyEvent(
        api.CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, link, api.GUID_DEVINTERFACE_USB_DEVICE
    )


def test_malformed_notification_payloads_decode_to_none() -> None:
    assert api.decode_notify_event(b"") is None
    assert api.decode_notify_event(b"\x00" * 7) is None
    # An interface event too short to hold its class GUID.
    assert api.decode_notify_event(struct.pack("<II", 0, 0) + b"\x00" * 15) is None
    # A device-handle event (filter type 1) is not something PortLock registers for.
    assert api.decode_notify_event(struct.pack("<II", 1, 0) + b"\x00" * 32) is None
    assert api.decode_notify_event(struct.pack("<II", 99, 0)) is None
    # A string with no terminator is taken to the end of the payload.
    unterminated = struct.pack("<II", 2, 0) + utf16("USB\\ROOT_HUB30\\4&0a0b0c0d&0&0")
    event = api.decode_notify_event(unterminated)
    assert event is not None and event.name == "USB\\ROOT_HUB30\\4&0a0b0c0d&0&0"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (instance_payload("USB\\VID_1209&PID_0001\\TEST0001A7C3"), True),
        (instance_payload("usb\\vid_1209&pid_0008&mi_00\\6&6f708192&0&0000"), True),
        (instance_payload("USBSTOR\\DISK&VEN_EXAMPLE\\TEST0001A7C3&0"), False),
        (instance_payload("SCSI\\DISK&VEN_EXAMPLE\\7&2b3c4d5e&0&000000"), False),
        (instance_payload("STORAGE\\VOLUME\\_??_USBSTOR#DISK"), False),
        (instance_payload("HID\\VID_1209&PID_0002\\6&5e6f7081&0&0000"), None),
        (instance_payload("SWD\\MMDEVAPI\\{0.0.0.00000000}"), None),
        (instance_payload("BTHENUM\\DEV_000000000000\\8&1&0&BLUETOOTHDEVICE"), None),
        (instance_payload(""), None),
        (interface_payload(api.GUID_DEVINTERFACE_USB_DEVICE, "\\\\?\\USB#VID_1209"), True),
        (interface_payload(api.GUID_DEVINTERFACE_VOLUME, "\\\\?\\STORAGE#Volume"), False),
        (b"", True),
        (b"\xff" * 5, True),
    ],
)
def test_notifications_are_classified(payload: bytes, expected: bool | None) -> None:
    assert classify_notification(payload) is expected


# -- structure layouts and prototypes --------------------------------------------------


def test_scalar_types_have_their_windows_widths() -> None:
    assert ctypes.sizeof(api.DWORD) == 4
    assert ctypes.sizeof(api.DEVINST) == 4
    assert ctypes.sizeof(api.CONFIGRET) == 4
    assert ctypes.sizeof(api.BOOL) == 4
    assert ctypes.sizeof(api.WCHAR) == 2
    # Handles are pointers: a 32-bit type here would truncate them on 64-bit Windows.
    assert ctypes.sizeof(api.HANDLE) == POINTER_SIZE
    assert ctypes.sizeof(api.HDEVINFO) == POINTER_SIZE
    assert ctypes.sizeof(api.HCMNOTIFICATION) == POINTER_SIZE


def test_structures_have_their_windows_layout() -> None:
    assert ctypes.sizeof(api.GUID) == 16
    assert ctypes.sizeof(api.DEVPROPKEY) == 20
    assert api.DEVPROPKEY.pid.offset == 16
    # setupapi.h is byte-packed on 32-bit Windows and naturally aligned on 64-bit.
    devinfo, detail = (32, 8) if POINTER_SIZE == 8 else (28, 6)
    assert ctypes.sizeof(api.SP_DEVINFO_DATA) == devinfo
    assert ctypes.sizeof(api.SP_DEVICE_INTERFACE_DATA) == devinfo
    assert ctypes.sizeof(api.SP_DEVICE_INTERFACE_DETAIL_DATA_W) == detail
    assert api.SP_DEVINFO_DATA.ClassGuid.offset == 4
    assert api.SP_DEVINFO_DATA.DevInst.offset == 20
    assert api.SP_DEVINFO_DATA.Reserved.offset == 24
    assert api.SP_DEVICE_INTERFACE_DATA.Flags.offset == 20
    assert api.SP_DEVICE_INTERFACE_DETAIL_DATA_W.DevicePath.offset == 4
    # cbSize, Flags, FilterType, Reserved, then a union as large as a 200-character id.
    assert ctypes.sizeof(api.CM_NOTIFY_FILTER) == 416
    assert api.CM_NOTIFY_FILTER.u.offset == 16


def test_guids_use_the_windows_byte_order() -> None:
    structure = api.GUID.from_uuid(api.GUID_DEVINTERFACE_USB_DEVICE)
    assert bytes(structure)[:8] == bytes.fromhex("10bfdca5 3065 d211")
    assert structure.Data1 == 0xA5DCBF10
    assert structure.to_uuid() == api.GUID_DEVINTERFACE_USB_DEVICE
    key = api.DEVPKEY_Device_BusReportedDeviceDesc.to_struct()
    assert key.pid == 4
    assert key.fmtid.to_uuid() == uuid.UUID("540b947e-8b40-45bc-a8a2-6a0b894cbda2")


def test_control_codes_match_the_ctl_code_macro() -> None:
    def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
        return (device_type << 16) | (access << 14) | (function << 2) | method

    assert ctl_code(0x2D, 0x0420, 0, 0) == api.IOCTL_STORAGE_GET_DEVICE_NUMBER
    assert ctl_code(0x56, 0, 0, 0) == api.IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS


def test_every_bound_function_declares_pointer_safe_types() -> None:
    tables = (
        api._CFGMGR32_PROTOTYPES,
        api._CFGMGR32_NOTIFY_PROTOTYPES,
        api._SETUPAPI_PROTOTYPES,
        api._KERNEL32_PROTOTYPES,
        api._POWRPROF_PROTOTYPES,
    )
    names = [name for table in tables for name in table]
    assert len(names) == len(set(names)) == 27
    for table in tables:
        for name, (argtypes, restype) in table.items():
            assert argtypes, name
            assert restype is not None, name
    # Functions that return a handle must not use the default 32-bit int return type.
    for name in ("CreateFileW", "FindFirstVolumeW"):
        assert api._KERNEL32_PROTOTYPES[name][1] is api.HANDLE
    assert api._SETUPAPI_PROTOTYPES["SetupDiGetClassDevsW"][1] is api.HDEVINFO
    for name, (_argtypes, restype) in api._CFGMGR32_PROTOTYPES.items():
        assert restype is api.CONFIGRET, name
    # The device instance is passed by value as a DWORD, in the documented position.
    assert api._CFGMGR32_PROTOTYPES["CM_Get_DevNode_Status"][0][2] is api.DEVINST
    assert api._CFGMGR32_PROTOTYPES["CM_Get_DevNode_PropertyW"][0][0] is api.DEVINST
    arity = {
        "CM_Locate_DevNodeW": 3,
        "CM_Get_Device_IDW": 4,
        "CM_Get_Parent": 3,
        "CM_Get_DevNode_Status": 4,
        "CM_Get_DevNode_PropertyW": 6,
        "CM_Register_Notification": 4,
        "SetupDiGetClassDevsW": 4,
        "SetupDiEnumDeviceInfo": 3,
        "SetupDiGetDeviceInstanceIdW": 5,
        "SetupDiEnumDeviceInterfaces": 5,
        "SetupDiGetDeviceInterfaceDetailW": 6,
        "CreateFileW": 7,
        "DeviceIoControl": 8,
        "GetVolumePathNamesForVolumeNameW": 4,
        "GetVolumeInformationW": 8,
        "GetDiskFreeSpaceExW": 4,
    }
    declared = {name: len(argtypes) for table in tables for name, (argtypes, _r) in table.items()}
    assert {name: declared[name] for name in arity} == arity
    register = api._CFGMGR32_NOTIFY_PROTOTYPES["CM_Register_Notification"][0]
    assert register[2] is api.PCM_NOTIFY_CALLBACK
    assert api._CFGMGR32_NOTIFY_PROTOTYPES["CM_Unregister_Notification"][0] == (
        api.HCMNOTIFICATION,
    )
    # The power registration hands back a pointer-sized handle and takes the callback
    # through DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS.
    register_power = api._POWRPROF_PROTOTYPES["PowerRegisterSuspendResumeNotification"][0]
    assert register_power[0] is api.DWORD and len(register_power) == 3
    assert api._POWRPROF_PROTOTYPES["PowerUnregisterSuspendResumeNotification"][0] == (
        api.HPOWERNOTIFY,
    )
    assert ctypes.sizeof(api.HPOWERNOTIFY) == POINTER_SIZE
    assert ctypes.sizeof(api.DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS) == 2 * POINTER_SIZE
    assert api.DEVICE_NOTIFY_CALLBACK == 2
    assert (api.PBT_APMSUSPEND, api.PBT_APMRESUMESUSPEND, api.PBT_APMRESUMEAUTOMATIC) == (
        0x4,
        0x7,
        0x12,
    )


def test_nothing_that_changes_device_state_is_bound() -> None:
    bound = {
        name.lower()
        for table in (
            api._CFGMGR32_PROTOTYPES,
            api._CFGMGR32_NOTIFY_PROTOTYPES,
            api._SETUPAPI_PROTOTYPES,
            api._KERNEL32_PROTOTYPES,
            api._POWRPROF_PROTOTYPES,
        )
        for name in table
    }
    forbidden = (
        "disable",
        "enable",
        "eject",
        "uninstall",
        "removedevice",
        "remove_subtree",
        "callclassinstaller",
        "changestate",
        "setdeviceregistryproperty",
        "setdeviceproperty",
        "set_devnode",
        "regsetvalue",
        "regcreatekey",
        "writefile",
        "setactivepwrscheme",
        "powersetactivescheme",
        "powerwrite",
        "setsuspendstate",
    )
    assert {name for name in bound if any(word in name for word in forbidden)} == set()
    # The only device control codes this module knows are the two read-only queries.
    assert sorted(name for name in dir(api) if name.startswith("IOCTL_")) == [
        "IOCTL_STORAGE_GET_DEVICE_NUMBER",
        "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    ]
    # Devices are opened with no access rights at all.
    assert not hasattr(api, "GENERIC_WRITE") and not hasattr(api, "GENERIC_READ")


def test_config_ret_names() -> None:
    assert api.config_ret_name(0x00) == "CR_SUCCESS"
    assert api.config_ret_name(0x0D) == "CR_NO_SUCH_DEVNODE"
    assert api.config_ret_name(0x7F) == "CONFIGRET 0x7f"


@pytest.mark.skipif(sys.platform == "win32", reason="checks the behaviour off Windows")
def test_the_real_api_refuses_cleanly_off_windows() -> None:
    real = api.WinApi()
    assert real.available is False
    assert real.supports_notifications() is False
    assert real.supports_resume_notifications() is False
    for call in (
        lambda: real.present_device_ids("USB"),
        lambda: real.locate_devnode("USB\\ROOT_HUB30\\4&0a0b0c0d&0&0"),
        lambda: real.get_status(1),
        lambda: real.volume_names(),
        lambda: real.register_instance_notification(lambda action, payload: None),
        lambda: real.register_resume_notification(lambda event_type: None),
    ):
        with pytest.raises(BackendError) as raised:
            call()
        assert raised.value.code == "unsupported_platform"


@pytest.mark.windows_only
def test_the_real_api_loads_on_windows() -> None:
    # Loads three system DLLs and declares prototypes; queries nothing.
    real = api.WinApi()
    assert real.available is True
    assert isinstance(real.supports_notifications(), bool)
    assert isinstance(real.supports_resume_notifications(), bool)


# -- volume helpers --------------------------------------------------------------------


def test_volume_guid_paths_are_recognised_exactly() -> None:
    good = "\\\\?\\Volume{00000000-0000-4000-8000-000000000002}\\"
    assert is_volume_guid_path(good)
    assert not is_volume_guid_path(good[:-1])
    assert not is_volume_guid_path(good + "\n")
    assert not is_volume_guid_path(good + "Windows")
    assert not is_volume_guid_path("\\\\?\\Volume{0000-0000}\\")
    assert not is_volume_guid_path("\\\\.\\PhysicalDrive0")
    assert not is_volume_guid_path("E:\\")
    assert not is_volume_guid_path(None)  # type: ignore[arg-type]


def test_volume_serials_are_formatted_like_windows_shows_them() -> None:
    assert format_volume_serial(0x1A2B3C4D) == "1A2B-3C4D"
    assert format_volume_serial(0x00000001) == "0000-0001"
    assert format_volume_serial(0xFFFF0000) == "FFFF-0000"


def test_the_reported_mount_point_is_chosen_deterministically() -> None:
    assert pick_mount_point(["C:\\Mounts\\Enclosure\\", "G:\\", "F:\\"]) == "F:\\"
    assert pick_mount_point(["g:\\"]) == "G:\\"
    assert pick_mount_point(["C:\\Mounts\\B\\", "C:\\Mounts\\A\\", "C:\\Mounts\\Longer\\"]) == (
        "C:\\Mounts\\A\\"
    )
    assert pick_mount_point([]) is None
    assert pick_mount_point(["", None]) is None  # type: ignore[list-item]
