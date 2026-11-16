"""The Windows enforcer, run in full against in-memory seams, on Windows and on Linux.

No test here writes the registry, calls a Configuration Manager function or opens a disk:
every seam is a fake from :mod:`portlock.guard.seams`.
"""

from __future__ import annotations

import errno
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from factories import keyboard, make_device
from portlock.core.errors import BackendError
from portlock.core.models import UsbDevice
from portlock.guard.base import Action, JournalEntry, JournalKind, Tier
from portlock.guard.seams import (
    REG_DWORD,
    REG_MULTI_SZ,
    FakeCfgMgr,
    FakeDisks,
    FakeRegistry,
    RegValue,
)
from portlock.guard.windows.api import (
    DEVPROP_TYPE_GUID,
    FILE_DEVICE_DISK,
    GUID_DEVCLASS_DISKDRIVE,
    StorageDeviceNumber,
)
from portlock.guard.windows.enforce import (
    ALLOW_INSTANCE_IDS_KEY,
    DISK_CLASS_KEY,
    MECHANISM_DENY_WRITE,
    MECHANISM_DISABLE,
    MECHANISM_DISK_READ_ONLY,
    MECHANISM_EJECT,
    MECHANISM_INSTALL_RESTRICTIONS,
    RESTRICTIONS_KEY,
    WPD_CLASS_KEY,
    WindowsEnforcer,
    disk_target,
    policy_target,
    system_device_ids,
)

STICK = "USB\\VID_1209&PID_0001\\TEST0001A7C3"
OTHER = "USB\\VID_1209&PID_0009\\TEST0009B2D1"
ROOT_HUB = "USB\\ROOT_HUB30\\4&1A2B3C4D&0&0"
INTERFACE = "USB\\VID_1209&PID_0005&MI_00\\6&1A2B3C4D&0&0000"
ON = RegValue(REG_DWORD, 1)

CR_NO_SUCH_DEVNODE = 0x0D
CR_REMOVE_VETOED = 0x17
CR_ACCESS_DENIED = 0x33
PNP_VETO_OUTSTANDING_OPEN = 5


@dataclass
class Rig:
    cfg: FakeCfgMgr
    registry: FakeRegistry
    disks: FakeDisks
    admin: list[bool]
    journal: list[JournalEntry] = field(default_factory=list)
    enforcer: WindowsEnforcer | None = None

    def make(self, write_ahead: Callable[[JournalEntry], None] | None = None) -> WindowsEnforcer:
        return WindowsEnforcer(
            cfgmgr=self.cfg,
            registry=self.registry,
            disks=self.disks,
            is_admin=lambda: self.admin[0],
            write_ahead=write_ahead if write_ahead is not None else self.journal.append,
        )

    @property
    def win(self) -> WindowsEnforcer:
        assert self.enforcer is not None
        return self.enforcer

    def value(self, key: str, name: str) -> RegValue | None:
        return self.registry.get(key, name)

    def allow_list(self) -> dict[str, RegValue]:
        return self.registry.values(ALLOW_INSTANCE_IDS_KEY)


@pytest.fixture
def rig() -> Rig:
    cfg = FakeCfgMgr()
    cfg.add(STICK)
    cfg.add(OTHER)
    disks = FakeDisks()
    disks.attach(STICK, 3)
    result = Rig(cfg, FakeRegistry(), disks, [True])
    result.enforcer = result.make()
    return result


def stick(**overrides: object) -> UsbDevice:
    fields: dict[str, object] = {"instance_id": STICK}
    fields.update(overrides)
    return make_device(**fields)


def default_deny_on(rig: Rig) -> None:
    rig.registry.put(RESTRICTIONS_KEY, "DenyRemovableDevices", ON)
    rig.registry.put(RESTRICTIONS_KEY, "AllowDenyLayered", ON)


# --- block and unblock --------------------------------------------------------------------


def test_block_disables_the_node_persistently_and_journals_it(rig: Rig) -> None:
    seen: list[bool] = []

    def hook(entry: JournalEntry) -> None:
        seen.append(rig.cfg.node(STICK).disabled)
        rig.journal.append(entry)

    result = rig.make(hook).block(stick())
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_DISABLE and result.tier is Tier.REACTIVE
    assert result.undo == (JournalEntry(JournalKind.WIN_DEVNODE, STICK, "enabled", "disabled"),)
    assert seen == [False]
    node = rig.cfg.node(STICK)
    assert node.disabled and node.persisted
    assert "CM_DISABLE_PERSIST" in result.detail


def test_block_is_idempotent(rig: Rig) -> None:
    rig.win.block(stick())
    again = rig.win.block(stick())
    assert again.ok and not again.changed and again.undo == ()
    assert [call for call in rig.cfg.calls if call[0] == "disable"] == [("disable", STICK)]


def test_block_refuses_a_node_that_cannot_be_disabled(rig: Rig) -> None:
    rig.cfg.node(STICK).disableable = False
    result = rig.win.block(stick())
    assert not result.ok
    assert result.error is not None and "DN_DISABLEABLE" in result.error
    assert not rig.cfg.node(STICK).disabled and rig.journal == []


def test_a_vetoed_disable_leaves_no_undo(rig: Rig) -> None:
    rig.cfg.node(STICK).disable_veto = True
    result = rig.win.block(stick())
    assert not result.ok and result.undo == ()
    assert result.error is not None and "CR_REMOVE_VETOED" in result.error
    # The entry went to the journal ahead of the call that was then vetoed.
    assert len(rig.journal) == 1


def test_a_failing_write_ahead_hook_prevents_the_disable(rig: Rig) -> None:
    def refuse(entry: JournalEntry) -> None:
        raise OSError("journal unavailable here")

    result = rig.make(refuse).block(stick())
    assert not result.ok and result.error is not None
    assert result.error.startswith("journal unavailable")
    assert not rig.cfg.node(STICK).disabled
    assert [call for call in rig.cfg.calls if call[0] == "disable"] == []


def test_without_administrator_rights_nothing_is_attempted(rig: Rig) -> None:
    rig.admin[0] = False
    for call in (
        lambda: rig.win.block(stick()),
        lambda: rig.win.unblock(stick()),
        lambda: rig.win.eject(stick()),
        lambda: rig.win.set_default_deny(True),
        lambda: rig.win.set_read_only(stick(), True),
        lambda: rig.win.set_baseline_read_only(True),
    ):
        result = call()
        assert not result.ok
        assert result.error is not None and result.error.startswith("not_privileged")
    assert rig.cfg.calls == [] and rig.registry.calls == []
    assert [call for call in rig.disks.calls if call[0] == "set"] == []


def test_access_denied_from_the_api_is_not_privileged(rig: Rig) -> None:
    rig.cfg.privileged = False
    result = rig.win.block(stick())
    assert not result.ok and result.error is not None and "not_privileged" in result.error
    assert "CR_ACCESS_DENIED" in result.error


def test_a_device_that_has_gone(rig: Rig) -> None:
    rig.cfg.unplug(STICK)
    result = rig.win.block(stick())
    assert not result.ok and result.error is not None and result.error.startswith("device is gone")


@pytest.mark.parametrize(
    "instance_id",
    [ROOT_HUB, INTERFACE, "PCI\\VEN_8086&DEV_1234\\3&11583659&0&A0", "USB\\nonsense", "/sys/x"],
)
def test_ids_other_than_a_usb_device_are_refused(rig: Rig, instance_id: str) -> None:
    result = rig.win.block(make_device(instance_id=instance_id))
    assert not result.ok and result.error is not None and result.error.startswith("refused")
    assert rig.cfg.calls == []


def test_block_of_a_device_the_installation_policy_kept_out_is_preventive(rig: Rig) -> None:
    default_deny_on(rig)
    rig.cfg.node(STICK).installed = False
    result = rig.win.block(stick())
    assert result.ok and not result.changed and result.tier is Tier.PREVENTIVE
    assert "never installed" in result.detail
    assert not rig.cfg.node(STICK).disabled


def test_under_default_deny_unblock_allows_and_admits_and_block_withdraws(rig: Rig) -> None:
    default_deny_on(rig)
    rig.registry.put(ALLOW_INSTANCE_IDS_KEY, "1", RegValue.sz(OTHER))
    rig.cfg.node(STICK).installed = False
    admitted = rig.win.unblock(stick())
    assert admitted.ok and admitted.changed
    assert admitted.undo == (
        JournalEntry(
            JournalKind.WIN_POLICY_VALUE,
            policy_target(RESTRICTIONS_KEY, "AllowInstanceIDs"),
            None,
            "dword:1",
        ),
        JournalEntry(
            JournalKind.WIN_POLICY_VALUE,
            policy_target(ALLOW_INSTANCE_IDS_KEY, "2"),
            None,
            f"sz:{STICK}",
        ),
    )
    node = rig.cfg.node(STICK)
    # Admission (E4): re-enumerated so Windows installs it, and not journaled.
    assert node.reenumerations == 1 and node.installed and not node.disabled
    again = rig.win.unblock(stick())
    assert again.ok and not again.changed and again.undo == ()

    blocked = rig.win.block(stick())
    assert blocked.ok
    assert blocked.undo == (
        JournalEntry(JournalKind.WIN_DEVNODE, STICK, "enabled", "disabled"),
        JournalEntry(
            JournalKind.WIN_POLICY_VALUE,
            policy_target(ALLOW_INSTANCE_IDS_KEY, "2"),
            f"sz:{STICK}",
            None,
        ),
    )
    assert rig.allow_list() == {"1": RegValue.sz(OTHER)}


def test_unblock_re_enables_a_disabled_node(rig: Rig) -> None:
    rig.win.block(stick())
    result = rig.win.unblock(stick())
    assert result.ok and result.changed
    assert result.undo == (JournalEntry(JournalKind.WIN_DEVNODE, STICK, "disabled", "enabled"),)
    assert not rig.cfg.node(STICK).disabled
    assert rig.cfg.node(STICK).reenumerations == 0


def test_unblock_of_a_device_that_went_keeps_the_allow_list_undo(rig: Rig) -> None:
    default_deny_on(rig)
    rig.cfg.unplug(STICK)
    result = rig.win.unblock(stick())
    assert not result.ok and len(result.undo) == 2
    assert result.error is not None and "gone" in result.error


# --- eject --------------------------------------------------------------------------------


def test_eject_requests_safe_removal(rig: Rig) -> None:
    result = rig.win.eject(stick())
    assert result.ok and result.changed and result.undo == ()
    assert result.mechanism == MECHANISM_EJECT and result.tier is Tier.REACTIVE
    assert not rig.cfg.node(STICK).present


def test_a_vetoed_eject_names_the_veto_and_sanitizes_the_name(rig: Rig) -> None:
    rig.cfg.node(STICK).eject_veto = (
        PNP_VETO_OUTSTANDING_OPEN,
        "\\Device\\Evil" + chr(0x1B) + "[2J",
    )
    result = rig.win.eject(stick())
    assert not result.ok and result.error is not None
    assert "PNP_VetoOutstandingOpen" in result.error and "CR_REMOVE_VETOED" in result.error
    assert chr(0x1B) not in result.error and chr(0xFFFD) in result.error
    assert rig.cfg.node(STICK).present


def test_eject_of_a_device_that_has_gone(rig: Rig) -> None:
    rig.cfg.fail("eject", CR_NO_SUCH_DEVNODE)
    result = rig.win.eject(stick())
    assert not result.ok and result.error is not None and "gone" in result.error


# --- default-deny -------------------------------------------------------------------------


def test_default_deny_sets_the_restriction_values_and_says_what_it_covers(rig: Rig) -> None:
    result = rig.win.set_default_deny(True)
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_INSTALL_RESTRICTIONS
    assert result.tier is Tier.PREVENTIVE
    assert "never-installed devices only" in result.detail and "restart" in result.detail
    assert [entry.target for entry in result.undo] == [
        policy_target(RESTRICTIONS_KEY, "AllowDenyLayered"),
        policy_target(RESTRICTIONS_KEY, "DenyRemovableDevices"),
    ]
    assert all(entry.previous is None and entry.applied == "dword:1" for entry in result.undo)
    assert rig.win.default_deny_active()
    again = rig.win.set_default_deny(True)
    assert again.ok and not again.changed and again.undo == ()


def test_default_deny_is_refused_beside_a_foreign_policy(rig: Rig) -> None:
    rig.registry.put(RESTRICTIONS_KEY, "AllowAdminInstall", ON)
    result = rig.win.set_default_deny(True)
    assert not result.ok and result.error is not None and "AllowAdminInstall" in result.error
    assert rig.registry.calls == []
    capabilities = rig.win.capabilities()
    assert not capabilities.default_deny
    assert any(
        note.startswith("conflict") and "AllowAdminInstall" in note for note in capabilities.notes
    )


def test_default_deny_off_removes_only_portlock_values(rig: Rig) -> None:
    rig.win.set_default_deny(True)
    rig.registry.put(RESTRICTIONS_KEY, "AllowDenyLayered", RegValue.dword(0))
    result = rig.win.set_default_deny(False)
    assert result.ok and result.action is Action.DEFAULT_DENY_OFF
    assert rig.value(RESTRICTIONS_KEY, "DenyRemovableDevices") is None
    assert rig.value(RESTRICTIONS_KEY, "AllowDenyLayered") == RegValue.dword(0)
    assert "left alone" in result.detail


def test_a_registry_failure_part_way_keeps_the_undo(rig: Rig) -> None:
    writes: list[JournalEntry] = []

    def second_fails(entry: JournalEntry) -> None:
        writes.append(entry)
        if len(writes) == 2:
            rig.registry.fail("set", errno.EIO)

    result = rig.make(second_fails).set_default_deny(True)
    assert not result.ok
    assert [entry.target for entry in result.undo] == [
        policy_target(RESTRICTIONS_KEY, "AllowDenyLayered")
    ]


# --- read-only ----------------------------------------------------------------------------


def test_read_only_sets_the_disk_attribute_as_best_effort(rig: Rig) -> None:
    result = rig.win.set_read_only(stick(), True)
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_DISK_READ_ONLY and result.tier is Tier.REACTIVE
    assert "best effort" in result.detail
    assert result.undo == (JournalEntry(JournalKind.WIN_DISK_READ_ONLY, disk_target(3), "0", "1"),)
    assert disk_target(3) == "\\\\.\\PhysicalDrive3"
    assert rig.disks.is_read_only(3) is True
    again = rig.win.set_read_only(stick(), True)
    assert again.ok and not again.changed


def test_read_only_refuses_a_device_without_storage(rig: Rig) -> None:
    result = rig.win.set_read_only(keyboard(instance_id=STICK), True)
    assert not result.ok and result.error == "not a storage device"


def test_read_only_of_a_device_with_no_disk_now(rig: Rig) -> None:
    rig.disks.detach(STICK)
    result = rig.win.set_read_only(stick(), True)
    assert not result.ok and result.error is not None and "call again" in result.error
    rig.win.set_baseline_read_only(True)
    covered = rig.win.set_read_only(stick(), True)
    assert covered.ok and covered.tier is Tier.PREVENTIVE


def test_release_is_refused_under_the_class_wide_baseline(rig: Rig) -> None:
    rig.win.set_read_only(stick(), True)
    plain = rig.win.set_read_only(stick(), False)
    assert plain.ok and plain.undo[0].applied == "0"
    rig.win.set_read_only(stick(), True)
    rig.win.set_baseline_read_only(True)
    result = rig.win.set_read_only(stick(), False)
    assert not result.ok and result.error is not None and "class-wide" in result.error
    assert rig.disks.is_read_only(3) is False and len(result.undo) == 1


def test_a_disk_that_vanishes_is_reported(rig: Rig) -> None:
    rig.disks.fail("set", errno.ENOENT)
    result = rig.win.set_read_only(stick(), True)
    assert not result.ok and result.error is not None and "gone" in result.error


def test_the_baseline_is_class_wide_deny_write(rig: Rig) -> None:
    result = rig.win.set_baseline_read_only(True)
    assert result.ok and result.mechanism == MECHANISM_DENY_WRITE
    assert result.tier is Tier.PREVENTIVE and "class-wide" in result.detail
    assert rig.value(DISK_CLASS_KEY, "Deny_Write") == ON
    assert rig.value(WPD_CLASS_KEY, "Deny_Write") == ON
    assert rig.win.baseline_active()
    off = rig.win.set_baseline_read_only(False)
    assert off.ok and rig.value(DISK_CLASS_KEY, "Deny_Write") is None


# --- restore ------------------------------------------------------------------------------


def test_restore_round_trips_every_kind(rig: Rig) -> None:
    undo: list[JournalEntry] = []
    for result in (
        rig.win.set_default_deny(True),
        rig.win.block(stick()),
        rig.win.set_baseline_read_only(True),
    ):
        assert result.ok
        undo.extend(result.undo)
    rig.disks.attach(STICK, 3)
    read_only = rig.win.set_read_only(stick(), True)
    undo.extend(read_only.undo)
    restored = rig.win.restore(undo)
    assert restored.ok and restored.changed
    assert f"restored {len(undo)} of {len(undo)}" in restored.detail
    assert not rig.cfg.node(STICK).disabled
    assert rig.registry.snapshot() == {}
    assert rig.disks.is_read_only(3) is False
    assert rig.win.restore(undo).ok


def test_a_value_present_before_is_restored_exactly_type_included(rig: Rig) -> None:
    rig.registry.put(RESTRICTIONS_KEY, "DenyRemovableDevices", RegValue.dword(0))
    rig.registry.put(DISK_CLASS_KEY, "Deny_Write", RegValue(REG_DWORD, 0))
    undo = [*rig.win.set_default_deny(True).undo, *rig.win.set_baseline_read_only(True).undo]
    assert (
        JournalEntry(
            JournalKind.WIN_POLICY_VALUE,
            policy_target(RESTRICTIONS_KEY, "DenyRemovableDevices"),
            "dword:0",
            "dword:1",
        )
        in undo
    )
    assert rig.win.restore(undo).ok
    assert rig.value(RESTRICTIONS_KEY, "DenyRemovableDevices") == RegValue.dword(0)
    assert rig.value(DISK_CLASS_KEY, "Deny_Write") == RegValue.dword(0)
    assert rig.value(RESTRICTIONS_KEY, "AllowDenyLayered") is None


def test_an_allow_entry_withdrawn_by_block_is_put_back(rig: Rig) -> None:
    default_deny_on(rig)
    rig.registry.put(ALLOW_INSTANCE_IDS_KEY, "4", RegValue.sz(STICK))
    undo = rig.win.block(stick()).undo
    assert rig.allow_list() == {}
    assert rig.win.restore(undo).ok
    assert rig.allow_list() == {"4": RegValue.sz(STICK)}
    assert not rig.cfg.node(STICK).disabled


def test_a_disconnected_device_is_re_enabled_through_its_phantom_node(rig: Rig) -> None:
    undo = rig.win.block(stick()).undo
    rig.cfg.unplug(STICK)
    result = rig.win.restore(undo)
    assert result.ok and result.changed
    assert not rig.cfg.node(STICK).disabled


def test_restore_of_an_uninstalled_node_fails(rig: Rig) -> None:
    undo = rig.win.block(stick()).undo
    rig.cfg.uninstall(STICK)
    result = rig.win.restore(undo)
    assert not result.ok and result.error is not None and "no longer exists" in result.error


def test_restore_leaves_what_someone_else_changed(rig: Rig) -> None:
    undo = rig.win.set_default_deny(True).undo
    # A Group Policy refresh replaces PortLock's value with its own.
    rig.registry.put(RESTRICTIONS_KEY, "DenyRemovableDevices", RegValue.dword(2))
    result = rig.win.restore(undo)
    assert result.ok and "left alone" in result.detail
    assert "DenyRemovableDevices (now dword:2)" in result.detail
    assert rig.value(RESTRICTIONS_KEY, "DenyRemovableDevices") == RegValue.dword(2)
    assert rig.value(RESTRICTIONS_KEY, "AllowDenyLayered") is None


def test_restore_of_a_device_someone_already_enabled(rig: Rig) -> None:
    undo = rig.win.block(stick()).undo
    rig.cfg.node(STICK).disabled = False
    result = rig.win.restore(undo)
    assert result.ok and not result.changed and "already held" in result.detail


def test_restore_of_a_disk_that_went_away_succeeds(rig: Rig) -> None:
    undo = rig.win.set_read_only(stick(), True).undo
    rig.disks.detach(STICK)
    result = rig.win.restore(undo)
    assert result.ok and "disappeared" in result.detail


def test_restore_without_administrator_rights(rig: Rig) -> None:
    undo = rig.win.block(stick()).undo
    rig.admin[0] = False
    result = rig.win.restore(undo)
    assert not result.ok and result.error is not None and "not_privileged" in result.error
    assert rig.cfg.node(STICK).disabled


TAMPERED = [
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil",
        None,
        "sz:C:\\evil.exe",
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        "HKCU\\" + RESTRICTIONS_KEY + "\\DenyRemovableDevices",
        None,
        "dword:1",
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(RESTRICTIONS_KEY, "AllowAdminInstall"),
        "dword:1",
        None,
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(ALLOW_INSTANCE_IDS_KEY, "1"),
        "sz:C:\\Windows\\evil.exe",
        None,
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(ALLOW_INSTANCE_IDS_KEY, "1"),
        f"sz:{ROOT_HUB}",
        None,
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(RESTRICTIONS_KEY, "DenyRemovableDevices"),
        "sz:1",
        "dword:1",
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(RESTRICTIONS_KEY, "DenyRemovableDevices"),
        None,
        "dword:5",
    ),
    JournalEntry(
        JournalKind.WIN_POLICY_VALUE,
        policy_target(DISK_CLASS_KEY, "Deny_Write"),
        "garbage",
        None,
    ),
    JournalEntry(
        JournalKind.WIN_DEVNODE, "PCI\\VEN_8086&DEV_1234\\3&11583659&0&A0", "enabled", "disabled"
    ),
    JournalEntry(JournalKind.WIN_DEVNODE, ROOT_HUB, "enabled", "disabled"),
    JournalEntry(JournalKind.WIN_DEVNODE, STICK, "maybe", "disabled"),
    JournalEntry(JournalKind.WIN_DISK_READ_ONLY, "\\\\.\\C:", "0", "1"),
    JournalEntry(JournalKind.WIN_DISK_READ_ONLY, "\\\\.\\PhysicalDrive0;x", "0", "1"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, "/sys/devices/x/1-2/authorized", "1", "0"),
    JournalEntry(JournalKind.FAKE, "authorized_default", "1", "0"),
]


@pytest.mark.parametrize("entry", TAMPERED, ids=lambda entry: f"{entry.kind}:{entry.target[-24:]}")
def test_restore_refuses_a_tampered_entry(rig: Rig, entry: JournalEntry) -> None:
    result = rig.win.restore([entry])
    assert not result.ok and result.error is not None
    assert rig.registry.calls == [] and rig.cfg.calls == []
    assert [call for call in rig.disks.calls if call[0] == "set"] == []


def test_one_bad_entry_does_not_stop_the_valid_ones(rig: Rig) -> None:
    undo = rig.win.block(stick()).undo
    result = rig.win.restore([TAMPERED[0], *undo])
    assert not result.ok and "restored 1 of 2" in result.detail
    assert not rig.cfg.node(STICK).disabled


def test_programming_errors_raise(rig: Rig) -> None:
    with pytest.raises(TypeError):
        rig.win.block(STICK)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        rig.win.set_default_deny(1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        rig.win.restore([{"kind": "win_devnode"}])  # type: ignore[list-item]


# --- capabilities -------------------------------------------------------------------------


def test_capabilities_as_administrator(rig: Rig) -> None:
    capabilities = rig.win.capabilities()
    assert capabilities.name == "windows" and capabilities.privileged
    assert capabilities.block and capabilities.eject and capabilities.default_deny
    assert capabilities.read_only
    assert any("never-installed" in note for note in capabilities.notes)
    roles = {status.role: status for status in rig.win.mechanisms()}
    assert all(status.available for status in roles.values())
    assert "class-wide" in roles["baseline_read_only"].tier


def test_capabilities_without_administrator_rights(rig: Rig) -> None:
    rig.admin[0] = False
    capabilities = rig.win.capabilities()
    assert not capabilities.privileged
    assert not any(
        (capabilities.block, capabilities.eject, capabilities.default_deny, capabilities.read_only)
    )
    assert {status.reason for status in rig.win.mechanisms()} == {"not running as an administrator"}


def test_capabilities_without_the_api(rig: Rig) -> None:
    rig.cfg = FakeCfgMgr(available=False)
    roles = {status.role: status for status in rig.make().mechanisms()}
    assert not roles["block"].available and "cfgmgr32" in roles["block"].reason
    assert roles["default_deny"].available


def test_capabilities_change_nothing(rig: Rig) -> None:
    rig.win.capabilities()
    rig.win.mechanisms()
    assert rig.cfg.calls == [] and rig.registry.calls == [] and rig.disks.calls == []


def test_the_module_needs_no_windows_library_to_import() -> None:
    # This module imported it at the top; on Linux that is the whole test. The real
    # seams report themselves unavailable there instead of failing.
    from portlock.guard.seams import WinCfgMgr, WinDisks, WinRegistry

    if sys.platform != "win32":
        assert not WinCfgMgr().available
        assert not WinRegistry().available
        assert not WinDisks().available
    assert WindowsEnforcer.__module__ == "portlock.guard.windows.enforce"


def test_a_multi_string_value_is_not_mistaken_for_a_policy_value() -> None:
    value = RegValue(REG_MULTI_SZ, ("a", "b"))
    assert RegValue.decode(value.encode()) == value


# --- system volume ------------------------------------------------------------------------

SYSTEM_VOLUME = "\\\\?\\Volume{00000000-0000-0000-0000-000000000001}\\"
DATA_VOLUME = "\\\\?\\Volume{00000000-0000-0000-0000-000000000002}\\"
HUB = "USB\\VID_1209&PID_0004\\5&2B3C4D5E&0&1"


class TreeApi:
    """Just enough of ``WinApi`` for the system-volume walk: a hub, a disk below it."""

    def __init__(self, system_disk: int) -> None:
        self.ids = {1: HUB, 2: STICK, 3: "USBSTOR\\DISK&VEN_TEST&PROD_FLASH\\7&1&0", 4: OTHER}
        self.parents = {2: 1, 3: 2, 4: 1}
        self.system_disk = system_disk

    def volume_names(self) -> list[str]:
        return [SYSTEM_VOLUME, DATA_VOLUME]

    def volume_mount_points(self, name: str) -> list[str]:
        return ["C:\\"] if name == SYSTEM_VOLUME else ["E:\\"]

    def storage_device_number(self, path: str) -> StorageDeviceNumber | None:
        if path == SYSTEM_VOLUME[:-1]:
            return StorageDeviceNumber(FILE_DEVICE_DISK, self.system_disk, 1)
        if path == DATA_VOLUME[:-1]:
            return StorageDeviceNumber(FILE_DEVICE_DISK, 9, 1)
        if path == "disk-interface-of-3":
            return StorageDeviceNumber(FILE_DEVICE_DISK, 3, None)
        return None

    def volume_disk_numbers(self, path: str) -> tuple[int, ...]:
        return ()

    def locate_devnode(self, instance_id: str) -> int | None:
        return next((key for key, value in self.ids.items() if value == instance_id), None)

    def get_child(self, devinst: int) -> int | None:
        return next((child for child, parent in self.parents.items() if parent == devinst), None)

    def get_sibling(self, devinst: int) -> int | None:
        parent = self.parents.get(devinst)
        siblings = sorted(child for child, owner in self.parents.items() if owner == parent)
        index = siblings.index(devinst)
        return siblings[index + 1] if index + 1 < len(siblings) else None

    def get_parent(self, devinst: int) -> int | None:
        return self.parents.get(devinst)

    def get_device_id(self, devinst: int) -> str | None:
        return self.ids.get(devinst)

    def get_property(self, devinst: int, key: object) -> tuple[int, bytes] | None:
        if devinst == 3:
            return DEVPROP_TYPE_GUID, GUID_DEVCLASS_DISKDRIVE.bytes_le
        return DEVPROP_TYPE_GUID, uuid.UUID(int=0).bytes_le

    def get_interface_paths(self, interface_class: object, instance_id: str) -> list[str]:
        return ["disk-interface-of-3"] if instance_id == self.ids[3] else []


def test_a_usb_disk_holding_the_system_drive_and_its_hub_are_found() -> None:
    devices = [stick(), make_device(instance_id=HUB), make_device(instance_id=OTHER)]
    env = {"SystemDrive": "C:", "SystemRoot": "C:\\Windows"}
    found = system_device_ids(devices, env=env, api=TreeApi(system_disk=3))
    assert found == frozenset({STICK, HUB})


def test_an_internal_system_disk_protects_no_usb_device() -> None:
    devices = [stick(), make_device(instance_id=HUB)]
    found = system_device_ids(devices, env={"SystemDrive": "C:"}, api=TreeApi(system_disk=0))
    assert found == frozenset()


def test_an_unknown_system_drive_is_an_error() -> None:
    with pytest.raises(BackendError):
        system_device_ids([stick()], env={}, api=TreeApi(system_disk=0))
    with pytest.raises(BackendError):
        system_device_ids([stick()], env={"SystemDrive": "Q:"}, api=TreeApi(system_disk=0))


def test_access_denied_codes_are_named(rig: Rig) -> None:
    rig.cfg.fail("disable", CR_ACCESS_DENIED)
    result = rig.win.block(stick())
    assert not result.ok and result.error is not None and "CR_ACCESS_DENIED" in result.error
    rig.cfg.fail("disable", CR_REMOVE_VETOED)
    assert "vetoed" in (rig.win.block(stick()).error or "")
