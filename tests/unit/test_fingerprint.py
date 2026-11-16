"""Fingerprinting: the value, what does and does not influence it, and its confidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

import pytest

from factories import (
    BOOT_KEYBOARD,
    MASS_STORAGE,
    flash_drive,
    keyboard,
    make_device,
    mounted_flash_drive,
    storage_with_keyboard,
)
from portlock.core.fingerprint import (
    FINGERPRINT_PREFIX,
    KNOWN_SHARED_SERIALS,
    MIN_UNIQUE_SERIAL_LENGTH,
    STORAGE_IDENTITY_PREFIX,
    fingerprint,
    is_unique_looking_serial,
    normalize_serial,
    normalize_text,
    storage_identity,
)
from portlock.core.models import Confidence, Fingerprint, UsbInterface, Volume

VALUE_PATTERN = re.compile(r"plk1:[a-z2-7]{32}\Z")

# Code points built with chr() so that this file stays plain ASCII.
NBSP = chr(0x00A0)
IDEOGRAPHIC_SPACE = chr(0x3000)
FULLWIDTH_A = chr(0xFF21)
FULLWIDTH_ONE = chr(0xFF11)
LIGATURE_FI = chr(0xFB01)
LONE_SURROGATE = chr(0xD800)
REPLACEMENT = chr(0xFFFD)
E_ACUTE = chr(0x00E9)
COMBINING_ACUTE = chr(0x0301)
EM_SPACE = chr(0x2003)
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)


def _reference_value(payload: dict[str, Any]) -> str:
    """The documented formula, written out independently of the implementation."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return "plk1:" + base64.b32encode(digest).decode("ascii").lower().rstrip("=")[:32]


# --- the value -------------------------------------------------------------------------


def test_value_follows_the_documented_formula() -> None:
    expected = _reference_value(
        {
            "v": 1,
            "vid": 0x1209,
            "pid": 0x0001,
            "serial": "TEST0001A7C3",
            "manufacturer": "Example Corp",
            "product": "Example Flash 16GB",
            "bcd": 0x0100,
            "ifaces": [[0x08, 0x06, 0x50]],
        }
    )
    assert fingerprint(flash_drive()).value == expected


def test_value_is_pinned_so_a_change_of_scheme_cannot_go_unnoticed() -> None:
    # Trusted devices are stored by fingerprint. If either value changes, the scheme
    # changed and needs a new prefix, not an edit to this test.
    assert fingerprint(flash_drive()).value == "plk1:q7eqjhmc5qmjukgxr6m2xkzel76kj3qk"
    assert fingerprint(keyboard()).value == "plk1:grtru3vvp6nhiofbxexwaz3rf23bjcgq"


def test_value_shape() -> None:
    result = fingerprint(flash_drive())
    assert isinstance(result, Fingerprint)
    assert VALUE_PATTERN.match(result.value)
    assert result.value.startswith(FINGERPRINT_PREFIX)
    assert len(result.value) == len("plk1:") + 32
    assert str(result) == result.value


def test_absent_fields_are_hashed_as_null_and_interfaces_are_sorted() -> None:
    device = make_device(
        serial=None,
        manufacturer=None,
        product=None,
        bcd_device=None,
        interfaces=(BOOT_KEYBOARD, MASS_STORAGE),
    )
    expected = _reference_value(
        {
            "v": 1,
            "vid": 0x1209,
            "pid": 0x0001,
            "serial": None,
            "manufacturer": None,
            "product": None,
            "bcd": None,
            "ifaces": [[0x03, 0x01, 0x01], [0x08, 0x06, 0x50]],
        }
    )
    assert fingerprint(device).value == expected


@pytest.mark.parametrize(
    "overrides",
    [
        {"instance_id": "USB\\VID_1209&PID_0001\\TEST0001A7C3"},
        {"instance_id": "/sys/devices/pci0000:00/usb3/3-4"},
        {"bus_path": "3-4.1"},
        {"bus_path": None},
        {"removable": False},
        {"removable": None},
        {"volumes": (Volume(device_node="/dev/sdz1", fs_uuid="TEST-0001", label="X"),)},
        {"backend_data": {"devinst": "17", "driver": "usb-storage"}},
        {"connection_id": "fake-0a1b2c3d-7"},
        {"device_class": 0xEF},
    ],
)
def test_connection_details_never_influence_the_value(overrides: dict[str, Any]) -> None:
    changed = make_device(**overrides)
    if "backend_data" in overrides:
        # Excluded from equality by design, so check the override took effect directly.
        assert dict(changed.backend_data) == overrides["backend_data"]
    elif "connection_id" in overrides:
        assert changed.connection_id == overrides["connection_id"]
    else:
        assert changed != flash_drive()
    assert fingerprint(changed) == fingerprint(flash_drive())


def test_mounting_a_volume_does_not_change_the_fingerprint() -> None:
    assert fingerprint(mounted_flash_drive()) == fingerprint(flash_drive())


def test_every_connection_of_one_device_has_the_same_fingerprint() -> None:
    # connection_id differs for every physical connection, even on the same port.
    connections = [flash_drive(connection_id=f"conn-{index}") for index in range(5)]
    assert len({device.connection_id for device in connections}) == 5
    assert len({fingerprint(device) for device in connections}) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"vendor_id": 0x1210},
        {"product_id": 0x0002},
        {"serial": "TEST0001A7C4"},
        {"serial": None},
        {"manufacturer": "Example Corporation"},
        {"manufacturer": None},
        {"product": "Example Flash 32GB"},
        {"product": None},
        {"bcd_device": 0x0101},
        {"bcd_device": None},
        {"interfaces": (UsbInterface(0x08, 0x06, 0x62),)},
        {"interfaces": (MASS_STORAGE, BOOT_KEYBOARD)},
        {"interfaces": (MASS_STORAGE, MASS_STORAGE)},
        {"interfaces": ()},
    ],
)
def test_every_descriptor_field_influences_the_value(overrides: dict[str, Any]) -> None:
    assert fingerprint(make_device(**overrides)).value != fingerprint(flash_drive()).value


def test_all_single_field_variations_are_distinct_from_each_other() -> None:
    variants = [
        flash_drive(),
        make_device(vendor_id=0x0001, product_id=0x1209),  # ids swapped
        make_device(manufacturer="Example Flash 16GB", product="Example Corp"),  # strings swapped
        make_device(serial="Example Corp", manufacturer="TEST0001A7C3"),
        make_device(bcd_device=0x1209, vendor_id=0x0100),
        make_device(serial=None, manufacturer=None),
        make_device(serial=None, product=None),
    ]
    assert len({fingerprint(device).value for device in variants}) == len(variants)


def test_interface_order_does_not_matter() -> None:
    forward = make_device(interfaces=(MASS_STORAGE, BOOT_KEYBOARD, UsbInterface(0xFF)))
    backward = make_device(interfaces=(UsbInterface(0xFF), BOOT_KEYBOARD, MASS_STORAGE))
    assert fingerprint(forward) == fingerprint(backward)


# --- the same stick on Windows and on Linux --------------------------------------------


def test_serial_case_does_not_matter() -> None:
    # Windows upper-cases the serial in the instance id; Linux reports it as sent.
    as_linux = flash_drive(serial="test0001a7c3")
    as_windows = flash_drive(serial="TEST0001A7C3")
    assert fingerprint(as_linux) == fingerprint(as_windows)


def test_manufacturer_and_product_case_does_matter() -> None:
    assert fingerprint(make_device(product="EXAMPLE FLASH 16GB")) != fingerprint(flash_drive())


@pytest.mark.parametrize(
    "overrides",
    [
        {"serial": "  TEST0001A7C3  "},
        {"serial": f"TEST0001A7C3{NBSP}"},
        {"manufacturer": "Example   Corp"},
        {"manufacturer": f"Example{NBSP}Corp"},
        {"manufacturer": f"Example{IDEOGRAPHIC_SPACE}Corp "},
        {"product": f"Example{EM_SPACE}Flash  {NBSP} 16GB"},
        {"product": f"Example Flash {FULLWIDTH_ONE}6GB"},
    ],
)
def test_equivalent_spellings_fingerprint_identically(overrides: dict[str, Any]) -> None:
    assert fingerprint(make_device(**overrides)) == fingerprint(flash_drive())


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        ("TEST0001A7C3\t", f"TEST0001A7C3{REPLACEMENT}"),
        ("TEST0001A7C3\n", f"TEST0001A7C3{REPLACEMENT}"),
        (f"TEST{RIGHT_TO_LEFT_OVERRIDE}0001A7C3", f"TEST{REPLACEMENT}0001A7C3"),
        ("\x1b[2JTEST0001A7C3", f"{REPLACEMENT}[2JTEST0001A7C3"),
    ],
)
def test_control_and_format_characters_are_hashed_as_the_model_stores_them(
    raw: str, stored: str
) -> None:
    # The device model replaces them before anything else sees the text, so the
    # fingerprint is computed from exactly what is stored, listed and audited.
    device = make_device(serial=raw)
    assert device.serial == stored
    assert fingerprint(device) == fingerprint(make_device(serial=stored))
    assert fingerprint(device).value != fingerprint(flash_drive()).value


@pytest.mark.parametrize("empty", ["", " ", EM_SPACE * 2, NBSP, IDEOGRAPHIC_SPACE * 3])
def test_blank_strings_count_as_absent(empty: str) -> None:
    blank = make_device(serial=empty, manufacturer=empty, product=empty)
    absent = make_device(serial=None, manufacturer=None, product=None)
    assert fingerprint(blank) == fingerprint(absent)
    assert fingerprint(blank).basis == ("vid", "pid", "bcd", "ifaces")
    assert fingerprint(blank).confidence is Confidence.LOW


def test_composed_and_decomposed_text_fingerprint_identically() -> None:
    composed = make_device(product=f"Cl{E_ACUTE} USB")
    decomposed = make_device(product=f"Cle{COMBINING_ACUTE} USB")
    assert composed.product != decomposed.product
    assert fingerprint(composed) == fingerprint(decomposed)


# --- normalization ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("abc", "abc"),
        ("  a  b\t\tc \n", "a b c"),
        (f"a{NBSP}{NBSP}b", "a b"),
        (FULLWIDTH_A + FULLWIDTH_ONE, "A1"),
        (LIGATURE_FI + "x", "fix"),
        ("Mixed Case", "Mixed Case"),
        ("a\x00b", "a\x00b"),
    ],
)
def test_normalize_text(raw: str | None, expected: str | None) -> None:
    assert normalize_text(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("  ", None),
        ("abc123", "ABC123"),
        (" ab  cd ", "AB CD"),
        (FULLWIDTH_A + "b", "AB"),
        ("stra" + chr(0x00DF) + "e", "STRASSE"),
    ],
)
def test_normalize_serial(raw: str | None, expected: str | None) -> None:
    assert normalize_serial(raw) == expected


def test_normalization_is_idempotent_even_where_case_and_nfkc_interact() -> None:
    # U+0390, U+03B0 and U+1FD3 upper-case to sequences that NFKC recomposes.
    awkward = [chr(0x0390), chr(0x03B0), chr(0x1FD3), chr(0x00DF), chr(0x0149), LIGATURE_FI]
    samples = [*awkward, "".join(awkward), "  mixed " + "".join(awkward) + "  x ", "TEST0001A7C3"]
    for sample in samples:
        once = normalize_serial(sample)
        assert once is not None
        assert normalize_serial(once) == once
        text = normalize_text(sample)
        assert normalize_text(text) == text


@pytest.mark.parametrize("bad", [b"TEST0001", 12345678, 1.5, ["TEST0001"], object()])
def test_non_string_input_is_rejected(bad: object) -> None:
    with pytest.raises(TypeError):
        normalize_text(bad)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        normalize_serial(bad)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        is_unique_looking_serial(bad)  # type: ignore[arg-type]
    # A device cannot even be built with such a value, so it never reaches hashing.
    with pytest.raises(ValueError):
        make_device(serial=bad)


def test_a_tampered_device_object_is_refused_rather_than_hashed() -> None:
    device = flash_drive()
    object.__setattr__(device, "product", 1234)
    with pytest.raises(TypeError):
        fingerprint(device)


# --- hostile descriptor content --------------------------------------------------------


def test_lone_surrogates_are_replaced_instead_of_crashing() -> None:
    assert normalize_text(f"ab{LONE_SURROGATE}cd") == f"ab{REPLACEMENT}cd"
    hostile = make_device(serial=f"TEST{LONE_SURROGATE}0001A7C3", product=LONE_SURROGATE)
    result = fingerprint(hostile)
    assert VALUE_PATTERN.match(result.value)
    assert result == fingerprint(hostile)
    assert result.value != fingerprint(flash_drive()).value
    # The replacement is visible in the hashed text, so it is exactly reproducible.
    assert (
        result.value
        == fingerprint(make_device(serial=f"TEST{REPLACEMENT}0001A7C3", product=REPLACEMENT)).value
    )


@pytest.mark.parametrize(
    "text",
    [
        'quote " and backslash \\',
        "control \x01\x1f chars",
        "null\x00byte",
        "emoji " + chr(0x1F512),
        "{'serial': null}",
        '","serial":"FORGED',
    ],
)
def test_awkward_text_is_hashed_not_interpreted(text: str) -> None:
    device = make_device(product=text)
    result = fingerprint(device)
    assert VALUE_PATTERN.match(result.value)
    assert result.value != fingerprint(flash_drive()).value
    assert result == fingerprint(make_device(product=text))


def test_fields_cannot_be_forged_by_moving_text_between_them() -> None:
    # If the fields were simply concatenated, these two devices would collide.
    first = make_device(manufacturer="Example", product="Corp Flash")
    second = make_device(manufacturer="Example Corp", product="Flash")
    assert fingerprint(first).value != fingerprint(second).value


def test_oversized_strings_are_handled() -> None:
    huge = "A1b2" * 50_000
    device = make_device(serial=huge, manufacturer=huge, product=huge)
    # The model caps device text at 126 characters, cutting the last block short.
    assert device.serial is not None and len(device.serial) == 126
    result = fingerprint(device)
    assert VALUE_PATTERN.match(result.value)
    assert result.confidence is Confidence.LOW  # one block repeated, the last cut short
    cut = huge[:126]
    assert result == fingerprint(make_device(serial=cut, manufacturer=cut, product=cut))
    # Called directly, the heuristic copes with the full length too (it is linear).
    assert is_unique_looking_serial(huge) is False


# --- confidence ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "serial",
    [
        "TEST0001A7C3",
        "test0001a7c3",
        "4C5300012304",
        "AA11BB22CC33",
        "0A1B2C3D",
        "S3RIAL-N0-0042",
        "13579BDF02468ACE",
        "0123456789ABCDEX",
    ],
)
def test_serials_that_look_unique(serial: str) -> None:
    assert is_unique_looking_serial(serial)
    assert fingerprint(flash_drive(serial=serial)).confidence is Confidence.HIGH


@pytest.mark.parametrize(
    "serial",
    [
        None,
        "",
        "    ",
        # too short
        "A1B2C3D",
        "1",
        # too few distinct characters
        "00000000",
        "000000000000",
        "FFFFFFFFFFFFFFFF",
        "0000000000000001",
        "AAAABBBBCCCC",
        "            1234",  # collapses to four characters
        # counting runs, ascending, descending and wrapping round
        "0123456789ABCDEF",
        "0123456789abcdef",
        "123456789",
        "1234567890",
        "12345678901234567890",
        "0123456789",
        "FEDCBA9876543210",
        "9876543210",
        "ABCDEFGH",
        "ZYXWVUTSRQ",
        "89ABCDEF01234567",
        "0123456789ABCDEFGHIJ",
        # one block repeated
        "DEADBEEFDEADBEEF",
        "ABCD1234ABCD1234",
        "A1B2A1B2A1B2",
        # ... with the last copy cut short
        "ABCDABCDAB",
        "TEST01TEST01TES",
        "A1B2C3A1B2C3A1",
        # documented shared serials
        "DEADBEEF",
        "deadbeef",
        "1234567890ABCDEF",
        "20100201396000",
        "058F63666485",
        "058f63666485",
        "Default string",
        "To Be Filled By O.E.M.",
        "  serial   number ",
    ],
)
def test_serials_that_do_not_look_unique(serial: str | None) -> None:
    assert not is_unique_looking_serial(serial)
    assert fingerprint(flash_drive(serial=serial)).confidence is Confidence.LOW


def test_length_threshold_is_exact() -> None:
    assert MIN_UNIQUE_SERIAL_LENGTH == 8
    assert not is_unique_looking_serial("A1B2C3D")
    assert is_unique_looking_serial("A1B2C3D4")
    # Whitespace does not count towards the length: it is collapsed first.
    assert not is_unique_looking_serial("   A1B2C3D   ")


def test_a_repeated_block_needs_two_full_copies_to_count() -> None:
    # Period 5 in nine characters: less than two full copies, so it may be unique.
    assert is_unique_looking_serial("ABC12ABC1")
    # Period 5 in ten characters: exactly two copies.
    assert not is_unique_looking_serial("ABC12ABC12")


def test_distinct_character_threshold_is_exact() -> None:
    assert not is_unique_looking_serial("AAB1AAB1A")  # three distinct characters
    assert is_unique_looking_serial("AAB1AAB1C")  # four


def test_known_shared_serials_are_stored_normalized_and_are_all_needed() -> None:
    assert KNOWN_SHARED_SERIALS
    for serial in KNOWN_SHARED_SERIALS:
        assert normalize_serial(serial) == serial
        assert not is_unique_looking_serial(serial)
        assert not is_unique_looking_serial(serial.lower())
    # An entry that the structural rules already reject would be dead weight.
    structural_only = [
        serial
        for serial in KNOWN_SHARED_SERIALS
        if len(serial) < MIN_UNIQUE_SERIAL_LENGTH or len(set(serial)) < 4
    ]
    assert structural_only == []


def test_a_low_confidence_serial_still_distinguishes_devices() -> None:
    # Confidence says how much to rely on the value, not whether the serial is hashed.
    generic = fingerprint(flash_drive(serial="0123456789ABCDEF"))
    absent = fingerprint(flash_drive(serial=None))
    assert generic.confidence is Confidence.LOW and absent.confidence is Confidence.LOW
    assert generic.value != absent.value


# --- basis -----------------------------------------------------------------------------


def test_basis_lists_the_fields_that_were_present() -> None:
    assert fingerprint(flash_drive()).basis == (
        "vid",
        "pid",
        "serial",
        "manufacturer",
        "product",
        "bcd",
        "ifaces",
    )
    assert fingerprint(keyboard()).basis == (
        "vid",
        "pid",
        "manufacturer",
        "product",
        "bcd",
        "ifaces",
    )
    bare = make_device(serial=None, manufacturer=None, product=None, bcd_device=None, interfaces=())
    assert fingerprint(bare).basis == ("vid", "pid")
    assert fingerprint(bare).confidence is Confidence.LOW


def test_storage_paired_with_keyboard_has_its_own_fingerprint() -> None:
    plain = flash_drive(serial="TEST0005BAD1", product_id=0x0005)
    assert fingerprint(storage_with_keyboard()).value != fingerprint(plain).value


# --- storage identity ------------------------------------------------------------------


def _with_uuids(*uuids: str | None) -> Any:
    volumes = tuple(
        Volume(device_node=f"/dev/sdz{index}", fs_uuid=uuid) for index, uuid in enumerate(uuids, 1)
    )
    return make_device(volumes=volumes)


def test_storage_identity_is_none_without_filesystem_uuids() -> None:
    assert storage_identity(flash_drive()) is None
    assert storage_identity(_with_uuids(None)) is None
    assert storage_identity(_with_uuids("", "   ")) is None


def test_storage_identity_shape_and_formula() -> None:
    identity = storage_identity(mounted_flash_drive())
    assert identity is not None
    assert re.fullmatch(r"plv1:[a-z2-7]{32}", identity)
    assert identity.startswith(STORAGE_IDENTITY_PREFIX)
    canonical = json.dumps({"fs_uuids": ["TEST-0001"], "v": 1}, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    assert identity == "plv1:" + base64.b32encode(digest).decode("ascii").lower()[:32]


def test_storage_identity_ignores_order_case_duplicates_and_empty_volumes() -> None:
    reference = storage_identity(_with_uuids("TEST-0001", "test-0002"))
    assert reference is not None
    assert storage_identity(_with_uuids("TEST-0002", "TEST-0001")) == reference
    assert storage_identity(_with_uuids("test-0001", "TEST-0002", None, " ")) == reference
    assert storage_identity(_with_uuids("TEST-0001", "TEST-0002", "TEST-0001")) == reference


def test_storage_identity_depends_on_the_uuids_and_nothing_else() -> None:
    reference = storage_identity(_with_uuids("TEST-0001"))
    assert storage_identity(_with_uuids("TEST-0003")) != reference
    assert storage_identity(_with_uuids("TEST-0001", "TEST-0002")) != reference
    other_device = make_device(
        serial="TEST9999ZZZZ",
        vendor_id=0x1210,
        volumes=(Volume(device_node="/dev/sdy7", mount_point="/mnt/x", fs_uuid="TEST-0001"),),
    )
    assert storage_identity(other_device) == reference
    assert fingerprint(other_device).value != fingerprint(_with_uuids("TEST-0001")).value


def test_storage_identity_rejects_a_non_string_uuid() -> None:
    # The volume model refuses it outright.
    with pytest.raises(ValueError):
        _with_uuids(1234)  # type: ignore[arg-type]
    # And should one be smuggled in, the identity is not computed from it.
    device = _with_uuids("TEST-0001")
    object.__setattr__(device.volumes[0], "fs_uuid", 1234)
    with pytest.raises(TypeError):
        storage_identity(device)


def test_storage_identity_uses_the_sanitized_uuid() -> None:
    assert storage_identity(_with_uuids("TEST-0001\t")) == storage_identity(
        _with_uuids(f"TEST-0001{REPLACEMENT}")
    )
