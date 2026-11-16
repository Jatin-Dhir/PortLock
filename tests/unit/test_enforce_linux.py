"""The Linux enforcer, run in full against in-memory seams.

Every sysfs path here is synthetic and lives in a :class:`FakeSysfs`: sysfs names contain
colons, which Windows file names cannot, and no test may write under the real ``/sys``.
Nothing in this file touches a real device, block node or udev.
"""

from __future__ import annotations

import errno
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from factories import keyboard, make_device, mounted_flash_drive
from portlock.core.errors import BackendError
from portlock.core.models import UsbDevice, Volume
from portlock.guard.base import Action, JournalEntry, JournalKind, Tier
from portlock.guard.linux.enforce import (
    BASELINE_RULE_NAME,
    MECHANISM_AUTHORIZED,
    MECHANISM_AUTHORIZED_DEFAULT,
    MECHANISM_BLKROSET,
    MECHANISM_REMOVE,
    MECHANISM_UDEV_BLKROSET,
    MECHANISM_UDEV_RULE,
    LinuxEnforcer,
    baseline_rule_text,
    parse_authorized_default_param,
    system_device_ids,
)
from portlock.guard.seams import (
    CommandResult,
    FakeBlockIO,
    FakeCommandRunner,
    FakeRuleFiles,
    FakeSysfs,
)

PCI = "/sys/devices/pci0000:00/0000:00:14.0"
HUB1 = f"{PCI}/usb1"
HUB2 = f"{PCI}/usb2"
DEV = f"{HUB1}/1-2"
DEV_AUTH = f"{DEV}/authorized"
STORAGE = f"{DEV}/1-2:1.0/host6/target6:0:0/6:0:0:0/block"
SATA = "/sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block"
MODULE = "/sys/module/usbcore/parameters/authorized_default"
RULES_DIR = "/etc/udev/rules.d"
RULE_PATH = f"{RULES_DIR}/{BASELINE_RULE_NAME}"
UDEVADM = ("/usr/bin/udevadm", "control", "--reload")


def relative(target: str, link_dir: str) -> str:
    """A relative link target, the way sysfs writes them."""
    up = "../" * len([part for part in link_dir.split("/") if part][1:])
    return up + target.removeprefix("/sys/")


def build_sysfs() -> FakeSysfs:
    sysfs = FakeSysfs()
    for hub in (HUB1, HUB2):
        sysfs.add_file(f"{hub}/authorized", "1")
        sysfs.add_file(f"{hub}/authorized_default", "1")
        sysfs.add_file(f"{hub}/remove", "")
        name = hub.rsplit("/", 1)[1]
        sysfs.add_link(f"/sys/bus/usb/devices/{name}", relative(hub, "/sys/bus/usb/devices"))
    sysfs.add_file(DEV_AUTH, "1")
    sysfs.add_file(f"{DEV}/remove", "")
    sysfs.add_link("/sys/bus/usb/devices/1-2", relative(DEV, "/sys/bus/usb/devices"))
    for base, disk, numbers in ((STORAGE, "sdb", (16, 17)), (SATA, "sda", (0, 1))):
        sysfs.add_file(f"{base}/{disk}/dev", f"8:{numbers[0]}")
        sysfs.add_file(f"{base}/{disk}/{disk}1/dev", f"8:{numbers[1]}")
        for name, path, number in (
            (disk, f"{base}/{disk}", numbers[0]),
            (f"{disk}1", f"{base}/{disk}/{disk}1", numbers[1]),
        ):
            sysfs.add_link(f"/sys/class/block/{name}", relative(path, "/sys/class/block"))
            sysfs.add_link(f"/sys/dev/block/8:{number}", relative(path, "/sys/dev/block"))
    sysfs.add_file(MODULE, "-1")
    return sysfs


@dataclass
class Rig:
    sysfs: FakeSysfs
    block: FakeBlockIO
    rules: FakeRuleFiles
    runner: FakeCommandRunner
    root: list[bool]
    journal: list[JournalEntry] = field(default_factory=list)
    enforcer: LinuxEnforcer | None = None

    def make(self, write_ahead: Callable[[JournalEntry], None] | None = None) -> LinuxEnforcer:
        return LinuxEnforcer(
            sysfs=self.sysfs,
            block=self.block,
            rules=self.rules,
            runner=self.runner,
            is_root=lambda: self.root[0],
            write_ahead=write_ahead if write_ahead is not None else self.journal.append,
        )

    @property
    def lx(self) -> LinuxEnforcer:
        assert self.enforcer is not None
        return self.enforcer


@pytest.fixture
def rig() -> Rig:
    block = FakeBlockIO()
    for node in ("/dev/sda", "/dev/sda1", "/dev/sdb", "/dev/sdb1"):
        block.add(node)
    result = Rig(build_sysfs(), block, FakeRuleFiles([RULES_DIR]), FakeCommandRunner(), [True])
    result.enforcer = result.make()
    return result


def stick(**overrides: object) -> UsbDevice:
    fields: dict[str, object] = {"instance_id": DEV, "bus_path": "1-2"}
    fields.update(overrides)
    return make_device(**fields)


# --- block and unblock --------------------------------------------------------------------


def test_block_deauthorizes_and_journals_the_previous_value(rig: Rig) -> None:
    seen: list[str | None] = []

    def hook(entry: JournalEntry) -> None:
        # Write-ahead: the hook sees the entry while the old value is still in place.
        seen.append(rig.sysfs.value(DEV_AUTH))
        rig.journal.append(entry)

    result = rig.make(hook).block(stick())
    assert result.ok and result.changed
    assert result.action is Action.BLOCK
    assert result.mechanism == MECHANISM_AUTHORIZED
    assert result.tier is Tier.REACTIVE
    assert result.undo == (JournalEntry(JournalKind.SYSFS_AUTHORIZED, DEV_AUTH, "1", "0"),)
    assert rig.journal == list(result.undo)
    assert seen == ["1"]
    assert rig.sysfs.value(DEV_AUTH) == "0"


def test_block_is_idempotent(rig: Rig) -> None:
    rig.lx.block(stick())
    again = rig.lx.block(stick())
    assert again.ok and not again.changed and again.undo == ()
    assert again.tier is Tier.REACTIVE
    assert rig.sysfs.writes == [(DEV_AUTH, "0")]


def test_block_of_a_device_default_deny_kept_out_is_preventive_and_adds_nothing(rig: Rig) -> None:
    rig.sysfs.add_file(f"{HUB1}/authorized_default", "0")
    rig.sysfs.add_file(DEV_AUTH, "0")
    result = rig.lx.block(stick())
    assert result.ok and not result.changed
    assert result.tier is Tier.PREVENTIVE
    assert rig.sysfs.writes == [] and rig.journal == []


def test_unblock_reverses_a_block_and_is_journaled(rig: Rig) -> None:
    rig.lx.block(stick())
    result = rig.lx.unblock(stick())
    assert result.ok and result.changed
    assert result.undo == (JournalEntry(JournalKind.SYSFS_AUTHORIZED, DEV_AUTH, "0", "1"),)
    assert rig.sysfs.value(DEV_AUTH) == "1"
    again = rig.lx.unblock(stick())
    assert again.ok and not again.changed and again.undo == ()


def test_admitting_a_device_default_deny_kept_out_is_not_journaled(rig: Rig) -> None:
    rig.sysfs.add_file(f"{HUB1}/authorized_default", "0")
    rig.sysfs.add_file(DEV_AUTH, "0")
    result = rig.lx.unblock(stick())
    assert result.ok and result.changed
    assert result.undo == ()
    assert rig.journal == []
    assert rig.sysfs.value(DEV_AUTH) == "1"
    assert "default-deny" in result.detail


def test_a_failing_write_ahead_hook_prevents_the_write(rig: Rig) -> None:
    def refuse(entry: JournalEntry) -> None:
        raise OSError("disk full")

    result = rig.make(refuse).block(stick())
    assert not result.ok
    assert result.error is not None and result.error.startswith("journal unavailable")
    assert result.undo == ()
    assert rig.sysfs.value(DEV_AUTH) == "1"


def test_without_root_nothing_is_written(rig: Rig) -> None:
    rig.root[0] = False
    for call in (
        lambda: rig.lx.block(stick()),
        lambda: rig.lx.eject(stick()),
        lambda: rig.lx.set_default_deny(True),
        lambda: rig.lx.set_read_only(stick(), True),
        lambda: rig.lx.set_baseline_read_only(True),
    ):
        result = call()
        assert not result.ok
        assert result.error is not None and result.error.startswith("not_privileged")
    assert rig.sysfs.writes == [] and rig.journal == []
    assert [call for call in rig.block.calls if call[0] == "set"] == []
    assert rig.rules.files() == {}


def test_an_operating_system_refusal_is_reported_as_not_privileged(rig: Rig) -> None:
    rig.sysfs.privileged = False
    result = rig.lx.block(stick())
    assert not result.ok and result.undo == ()
    assert result.error is not None and "not_privileged" in result.error
    assert "EACCES" in result.error


def test_a_read_only_sysfs_is_reported_as_not_enforced(rig: Rig) -> None:
    rig.sysfs.read_only_fs = True
    result = rig.lx.block(stick())
    assert not result.ok
    assert result.error is not None and "read-only" in result.error and "EROFS" in result.error


def test_a_device_that_has_gone_is_reported(rig: Rig) -> None:
    rig.sysfs.remove_tree(DEV)
    result = rig.lx.block(stick())
    assert not result.ok
    assert result.error is not None and result.error.startswith("device is gone")


def test_a_device_that_goes_during_the_write_leaves_no_undo(rig: Rig) -> None:
    rig.sysfs.fail("write", DEV_AUTH, errno.ENODEV)
    result = rig.lx.block(stick())
    assert not result.ok and result.undo == ()
    assert result.error is not None and "device is gone" in result.error
    # The entry was journaled ahead of the write that then failed.
    assert len(rig.journal) == 1


@pytest.mark.parametrize(
    "instance_id",
    [
        HUB1,
        f"{DEV}/1-2:1.0",
        "/sys/devices/../../etc/1-2",
        "/etc/1-2",
        "/sys/bus/usb/devices/1-2",
        f"{HUB2}/1-2",
        f"{PCI}/1-2",
        f"{DEV}/",
        "relative/1-2",
        f"{HUB1}/1-2\\x",
    ],
)
def test_paths_outside_a_usb_device_directory_are_refused(rig: Rig, instance_id: str) -> None:
    result = rig.lx.block(stick(instance_id=instance_id))
    assert not result.ok
    assert result.error is not None and result.error.startswith("refused")
    assert rig.sysfs.writes == []


def test_a_device_path_that_is_a_symbolic_link_is_refused(rig: Rig) -> None:
    rig.sysfs.add_link(f"{HUB1}/1-9", "1-2")
    result = rig.lx.block(stick(instance_id=f"{HUB1}/1-9"))
    assert not result.ok
    assert result.error is not None and "symbolic link" in result.error
    assert rig.sysfs.writes == []


def test_unexpected_attribute_content_is_not_overwritten(rig: Rig) -> None:
    rig.sysfs.add_file(DEV_AUTH, "garbage")
    assert not rig.lx.block(stick()).ok
    assert not rig.lx.unblock(stick()).ok
    assert rig.sysfs.writes == []


# --- eject --------------------------------------------------------------------------------


def test_eject_writes_remove_and_journals_nothing(rig: Rig) -> None:
    result = rig.lx.eject(mounted_flash_drive(instance_id=DEV, bus_path="1-2"))
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_REMOVE
    assert result.tier is Tier.REACTIVE
    assert result.undo == () and rig.journal == []
    assert rig.sysfs.writes == [(f"{DEV}/remove", "1")]
    assert "still mounted" in result.detail


def test_eject_of_a_device_that_has_gone(rig: Rig) -> None:
    rig.sysfs.remove_tree(DEV)
    result = rig.lx.eject(stick())
    assert not result.ok and result.error is not None and "gone" in result.error


# --- default-deny -------------------------------------------------------------------------


def test_default_deny_covers_every_controller_and_later_ones(rig: Rig) -> None:
    result = rig.lx.set_default_deny(True)
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_AUTHORIZED_DEFAULT
    assert result.tier is Tier.PREVENTIVE
    assert result.undo == (
        JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, f"{HUB1}/authorized_default", "1", "0"),
        JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, f"{HUB2}/authorized_default", "1", "0"),
        JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, MODULE, "-1", "0"),
    )
    assert rig.sysfs.value(MODULE) == "0"
    assert "kernel command line" in result.detail
    again = rig.lx.set_default_deny(True)
    assert again.ok and not again.changed and again.undo == ()
    assert again.tier is Tier.PREVENTIVE


def test_default_deny_off_authorizes_new_devices_again(rig: Rig) -> None:
    rig.lx.set_default_deny(True)
    result = rig.lx.set_default_deny(False)
    assert result.ok and result.action is Action.DEFAULT_DENY_OFF
    assert {entry.applied for entry in result.undo} == {"1"}
    assert rig.sysfs.value(f"{HUB1}/authorized_default") == "1"
    assert rig.sysfs.value(MODULE) == "1"


def test_a_partial_failure_keeps_the_undo_of_what_was_done(rig: Rig) -> None:
    rig.sysfs.fail("write", f"{HUB2}/authorized_default", errno.EIO)
    result = rig.lx.set_default_deny(True)
    assert not result.ok
    assert [entry.target for entry in result.undo] == [f"{HUB1}/authorized_default", MODULE]
    assert result.error is not None and f"{HUB2}/authorized_default" in result.error
    assert rig.sysfs.value(f"{HUB2}/authorized_default") == "1"


def test_the_journal_failing_part_way_stops_further_writes(rig: Rig) -> None:
    calls: list[JournalEntry] = []

    def second_fails(entry: JournalEntry) -> None:
        calls.append(entry)
        if len(calls) == 2:
            raise OSError("journal file locked")

    result = rig.make(second_fails).set_default_deny(True)
    assert not result.ok
    assert result.error is not None and result.error.startswith("journal unavailable")
    assert [entry.target for entry in result.undo] == [f"{HUB1}/authorized_default"]
    assert rig.sysfs.value(f"{HUB2}/authorized_default") == "1"
    assert rig.sysfs.value(MODULE) == "-1"


def test_a_value_the_kernel_does_not_keep_is_not_enforced(rig: Rig) -> None:
    rig.sysfs.on_write(f"{HUB1}/authorized_default", lambda _value: "1")
    result = rig.lx.set_default_deny(True)
    assert not result.ok
    assert result.error is not None and "kernel kept '1'" in result.error
    # The write happened, so it stays undoable.
    assert result.undo[0].target == f"{HUB1}/authorized_default"


def test_a_missing_module_parameter_is_a_warning(rig: Rig) -> None:
    rig.sysfs.remove_tree(MODULE)
    result = rig.lx.set_default_deny(True)
    assert result.ok and len(result.undo) == 2
    assert "registered later are not covered" in result.detail


def test_a_read_only_module_parameter_is_a_warning(rig: Rig) -> None:
    rig.sysfs.add_file(MODULE, "-1", writable=False)
    result = rig.lx.set_default_deny(True)
    assert result.ok and len(result.undo) == 2
    assert "registered later are not covered" in result.detail


def test_default_deny_without_any_controller_fails(rig: Rig) -> None:
    rig.sysfs.remove_tree("/sys/bus/usb")
    result = rig.lx.set_default_deny(True)
    assert not result.ok and result.error is not None and "no USB host controller" in result.error


# --- read-only ----------------------------------------------------------------------------


def test_read_only_sets_blkroset_on_the_disk_and_its_partitions(rig: Rig) -> None:
    result = rig.lx.set_read_only(stick(), True)
    assert result.ok and result.changed
    assert result.mechanism == MECHANISM_BLKROSET
    assert result.tier is Tier.REACTIVE
    assert result.undo == (
        JournalEntry(JournalKind.BLOCK_READ_ONLY, "/dev/sdb", "0", "1"),
        JournalEntry(JournalKind.BLOCK_READ_ONLY, "/dev/sdb1", "0", "1"),
    )
    assert rig.block.is_read_only("/dev/sdb") and rig.block.is_read_only("/dev/sdb1")
    assert not rig.block.is_read_only("/dev/sda")
    assert "best effort" in result.detail
    again = rig.lx.set_read_only(stick(), True)
    assert again.ok and not again.changed and again.undo == ()


def test_read_only_says_a_mounted_volume_stays_writable(rig: Rig) -> None:
    device = stick(volumes=(Volume("/dev/sdb1", mount_point="/media/test", read_only=False),))
    result = rig.lx.set_read_only(device, True)
    assert result.ok and result.tier is Tier.REACTIVE
    assert "remain writable until remounted" in result.detail


def test_read_only_refuses_a_device_without_storage(rig: Rig) -> None:
    result = rig.lx.set_read_only(keyboard(instance_id=DEV), True)
    assert not result.ok and result.error == "not a storage device"
    assert rig.block.calls == []


def test_read_only_of_a_device_without_block_nodes_needs_the_baseline(rig: Rig) -> None:
    rig.sysfs.remove_tree(f"{DEV}/1-2:1.0")
    result = rig.lx.set_read_only(stick(), True)
    assert not result.ok
    assert result.error is not None and "call again" in result.error
    rig.lx.set_baseline_read_only(True)
    armed = rig.lx.set_read_only(stick(), True)
    assert armed.ok and armed.tier is Tier.PREVENTIVE
    assert armed.mechanism == MECHANISM_UDEV_BLKROSET


def test_under_the_baseline_read_only_storage_is_preventive(rig: Rig) -> None:
    rig.lx.set_baseline_read_only(True)
    rig.block.add("/dev/sdb", read_only=True)
    rig.block.add("/dev/sdb1", read_only=True)
    result = rig.lx.set_read_only(stick(), True)
    assert result.ok and not result.changed
    assert result.tier is Tier.PREVENTIVE and result.mechanism == MECHANISM_UDEV_BLKROSET


def test_release_from_read_only_is_journaled(rig: Rig) -> None:
    rig.block.add("/dev/sdb", read_only=True)
    rig.block.add("/dev/sdb1", read_only=True)
    result = rig.lx.set_read_only(stick(), False)
    assert result.ok and result.action is Action.READ_WRITE
    assert [(entry.previous, entry.applied) for entry in result.undo] == [("1", "0"), ("1", "0")]
    assert not rig.block.is_read_only("/dev/sdb")


def test_a_block_node_that_vanishes_mid_way_keeps_the_partial_undo(rig: Rig) -> None:
    rig.block.fail("set", "/dev/sdb1", errno.ENXIO)
    result = rig.lx.set_read_only(stick(), True)
    assert not result.ok
    assert [entry.target for entry in result.undo] == ["/dev/sdb"]
    assert result.error is not None and "gone" in result.error


def test_read_only_without_the_ioctl(rig: Rig) -> None:
    rig.block = FakeBlockIO(available=False)
    enforcer = rig.make()
    result = enforcer.set_read_only(stick(), True)
    assert not result.ok and result.error is not None and "BLKROSET" in result.error


# --- the baseline rule --------------------------------------------------------------------


def test_the_baseline_rule_is_written_and_udev_reloaded(rig: Rig) -> None:
    result = rig.lx.set_baseline_read_only(True)
    assert result.ok and result.mechanism == MECHANISM_UDEV_RULE
    assert result.tier is Tier.PREVENTIVE
    assert result.undo == (
        JournalEntry(JournalKind.UDEV_RULE, RULE_PATH, None, baseline_rule_text()),
    )
    assert rig.rules.files() == {RULE_PATH: baseline_rule_text()}
    assert rig.runner.commands() == [UDEVADM]
    assert rig.lx.baseline_active()
    again = rig.lx.set_baseline_read_only(True)
    assert again.ok and not again.changed and rig.runner.commands() == [UDEVADM]


def test_the_rule_text_matches_usb_disks_and_partitions_only() -> None:
    text = baseline_rule_text("/sbin/blockdev")
    assert 'SUBSYSTEM=="block"' in text and 'ENV{ID_BUS}=="usb"' in text
    assert 'ENV{DEVTYPE}=="disk|partition"' in text
    assert 'RUN+="/sbin/blockdev --setro $devnode"' in text
    with pytest.raises(ValueError):
        baseline_rule_text('/sbin/blockdev"; rm -rf /')


def test_a_foreign_rules_file_is_never_touched(rig: Rig) -> None:
    rig.rules.put(RULE_PATH, "# someone else's rule\n")
    for enabled in (True, False):
        result = rig.lx.set_baseline_read_only(enabled)
        assert not result.ok and result.error is not None and "left alone" in result.error
    assert rig.rules.files() == {RULE_PATH: "# someone else's rule\n"}
    assert rig.rules.calls == []


def test_a_failed_reload_is_reported_with_the_undo(rig: Rig) -> None:
    rig.runner.respond(UDEVADM, CommandResult(1, stderr="Failed to send reload request"))
    result = rig.lx.set_baseline_read_only(True)
    assert not result.ok and len(result.undo) == 1
    assert result.error is not None and "Failed to send reload request" in result.error


def test_removing_the_baseline_is_journaled(rig: Rig) -> None:
    rig.lx.set_baseline_read_only(True)
    result = rig.lx.set_baseline_read_only(False)
    assert result.ok
    assert result.undo == (
        JournalEntry(JournalKind.UDEV_RULE, RULE_PATH, baseline_rule_text(), None),
    )
    assert rig.rules.files() == {}


# --- restore ------------------------------------------------------------------------------


def test_restore_round_trips_every_kind(rig: Rig) -> None:
    undo: list[JournalEntry] = []
    for result in (
        rig.lx.block(stick()),
        rig.lx.set_default_deny(True),
        rig.lx.set_read_only(stick(), True),
        rig.lx.set_baseline_read_only(True),
    ):
        assert result.ok
        undo.extend(result.undo)
    restored = rig.lx.restore(undo)
    assert restored.ok and restored.changed
    assert restored.action is Action.RESTORE
    assert f"restored {len(undo)} of {len(undo)}" in restored.detail
    assert rig.sysfs.value(DEV_AUTH) == "1"
    assert rig.sysfs.value(f"{HUB1}/authorized_default") == "1"
    assert rig.sysfs.value(MODULE) == "-1"
    assert not rig.block.is_read_only("/dev/sdb")
    assert rig.rules.files() == {}
    assert rig.runner.commands()[-1] == UDEVADM
    # Restoring twice is harmless.
    second = rig.lx.restore(undo)
    assert second.ok and not second.changed
    assert "already held" in second.detail


def test_restore_works_in_a_process_that_made_no_change(rig: Rig) -> None:
    undo = rig.lx.block(stick()).undo
    fresh = rig.make()
    assert fresh.restore(undo).ok
    assert rig.sysfs.value(DEV_AUTH) == "1"


def test_restore_goes_newest_first(rig: Rig) -> None:
    blocked = rig.lx.block(stick()).undo
    unblocked = rig.lx.unblock(stick()).undo
    result = rig.lx.restore([*blocked, *unblocked])
    assert result.ok and "restored 2 of 2" in result.detail
    assert rig.sysfs.writes[-2:] == [(DEV_AUTH, "0"), (DEV_AUTH, "1")]


def test_restore_leaves_a_value_someone_else_changed(rig: Rig) -> None:
    undo = rig.lx.set_default_deny(True).undo
    rule_undo = rig.lx.set_baseline_read_only(True).undo
    rig.sysfs.add_file(f"{HUB1}/authorized_default", "2")
    rig.rules.put(RULE_PATH, baseline_rule_text() + "# edited\n")
    result = rig.lx.restore([*undo, *rule_undo])
    assert result.ok
    assert "left alone" in result.detail
    assert f"{HUB1}/authorized_default (now '2')" in result.detail
    assert rig.sysfs.value(f"{HUB1}/authorized_default") == "2"
    assert rig.sysfs.value(f"{HUB2}/authorized_default") == "1"
    assert rig.rules.files()[RULE_PATH].endswith("# edited\n")


def test_restore_of_a_device_that_has_gone_succeeds(rig: Rig) -> None:
    undo = [*rig.lx.block(stick()).undo, *rig.lx.set_read_only(stick(), True).undo]
    rig.sysfs.remove_tree(DEV)
    rig.sysfs.remove_tree("/sys/class/block/sdb")
    rig.sysfs.remove_tree("/sys/class/block/sdb1")
    result = rig.lx.restore(undo)
    assert result.ok and not result.changed
    assert "3 disappeared with their device" in result.detail


def test_restore_of_a_controller_that_has_gone_fails(rig: Rig) -> None:
    undo = rig.lx.set_default_deny(True).undo
    rig.sysfs.remove_tree(HUB2)
    result = rig.lx.restore(undo)
    assert not result.ok
    assert result.error is not None and f"{HUB2}/authorized_default" in result.error
    assert rig.sysfs.value(f"{HUB1}/authorized_default") == "1"


def test_restore_without_root_writes_nothing(rig: Rig) -> None:
    undo = rig.lx.block(stick()).undo
    rig.root[0] = False
    writes = list(rig.sysfs.writes)
    result = rig.lx.restore(undo)
    assert not result.ok and result.error is not None and "not_privileged" in result.error
    assert rig.sysfs.writes == writes


TAMPERED = [
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, "/etc/shadow", "1", "0"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, f"{DEV}/../../../../../etc/authorized", "0", "1"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, f"{DEV}/bConfigurationValue", "0", "1"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, f"{HUB1}/authorized", "0", "1"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, DEV_AUTH, "5", "0"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED, DEV_AUTH, None, "0"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, DEV_AUTH, "1", "0"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, "/proc/sys/kernel/modprobe", "1", "0"),
    JournalEntry(JournalKind.SYSFS_AUTHORIZED_DEFAULT, f"{HUB1}/authorized_default", "7", "0"),
    JournalEntry(JournalKind.BLOCK_READ_ONLY, "/dev/../etc/passwd", "0", "1"),
    JournalEntry(JournalKind.BLOCK_READ_ONLY, "/etc/passwd", "0", "1"),
    JournalEntry(JournalKind.UDEV_RULE, RULE_PATH, 'RUN+="/bin/sh -c evil"', None),
    JournalEntry(JournalKind.UDEV_RULE, f"{RULES_DIR}/99-evil.rules", None, baseline_rule_text()),
    JournalEntry(JournalKind.WIN_POLICY_VALUE, "HKLM\\SOFTWARE\\x\\y", None, "dword:1"),
    JournalEntry(JournalKind.FAKE, "authorized_default", "1", "0"),
]


@pytest.mark.parametrize("entry", TAMPERED, ids=lambda entry: f"{entry.kind}:{entry.target}")
def test_restore_refuses_a_tampered_entry(rig: Rig, entry: JournalEntry) -> None:
    result = rig.lx.restore([entry])
    assert not result.ok and result.error is not None
    assert rig.sysfs.writes == []
    assert [call for call in rig.block.calls if call[0] == "set"] == []
    assert rig.rules.calls == []


def test_restore_refuses_the_read_only_flag_of_an_internal_disk(rig: Rig) -> None:
    rig.block.add("/dev/sda", read_only=True)
    result = rig.lx.restore([JournalEntry(JournalKind.BLOCK_READ_ONLY, "/dev/sda", "0", "1")])
    assert not result.ok and result.error is not None and "not a USB disk" in result.error
    assert rig.block.is_read_only("/dev/sda") is True


def test_restore_refuses_a_controller_reached_through_a_link(rig: Rig) -> None:
    rig.sysfs.add_link(f"{PCI}/usb7", "usb1")
    entry = JournalEntry(
        JournalKind.SYSFS_AUTHORIZED_DEFAULT, f"{PCI}/usb7/authorized_default", "1", "0"
    )
    result = rig.lx.restore([entry])
    assert not result.ok and result.error is not None and "link" in result.error
    assert rig.sysfs.writes == []


def test_one_bad_entry_does_not_stop_the_valid_ones(rig: Rig) -> None:
    undo = rig.lx.block(stick()).undo
    result = rig.lx.restore([TAMPERED[0], *undo])
    assert not result.ok and "restored 1 of 2" in result.detail
    assert rig.sysfs.value(DEV_AUTH) == "1"


def test_restore_of_nothing(rig: Rig) -> None:
    result = rig.lx.restore([])
    assert result.ok and not result.changed


def test_programming_errors_raise(rig: Rig) -> None:
    with pytest.raises(TypeError):
        rig.lx.block("not a device")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        rig.lx.set_read_only(stick(), "yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        rig.lx.restore(["entry"])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        LinuxEnforcer(
            sysfs=rig.sysfs,
            block=rig.block,
            rules=rig.rules,
            runner=rig.runner,
            is_root=lambda: True,
            sysfs_root="sys",
        )


# --- capabilities -------------------------------------------------------------------------


def test_capabilities_as_root(rig: Rig) -> None:
    capabilities = rig.lx.capabilities()
    assert capabilities.name == "linux" and capabilities.privileged
    assert capabilities.block and capabilities.eject and capabilities.default_deny
    assert capabilities.read_only
    assert any("kernel command line" in note for note in capabilities.notes)
    roles = {status.role: status for status in rig.lx.mechanisms()}
    assert set(roles) == {"block", "eject", "default_deny", "read_only", "baseline_read_only"}
    assert all(status.available for status in roles.values())
    assert roles["block"].mechanism == MECHANISM_AUTHORIZED
    assert (
        "reactive" in roles["read_only"].tier and "preventive" in roles["baseline_read_only"].tier
    )


def test_capabilities_without_root(rig: Rig) -> None:
    rig.root[0] = False
    capabilities = rig.lx.capabilities()
    assert not capabilities.privileged
    assert not (capabilities.block or capabilities.eject or capabilities.default_deny)
    assert not capabilities.read_only
    assert all(status.reason == "not running as root" for status in rig.lx.mechanisms())


def test_capabilities_in_a_container_with_read_only_sysfs(rig: Rig) -> None:
    rig.sysfs.read_only_fs = True
    roles = {status.role: status for status in rig.lx.mechanisms()}
    assert not roles["block"].available and "read-only" in roles["block"].reason
    assert not rig.lx.capabilities().default_deny


def test_capabilities_without_a_usb_bus(rig: Rig) -> None:
    rig.sysfs.remove_tree("/sys/bus/usb")
    roles = {status.role: status for status in rig.lx.mechanisms()}
    assert not roles["block"].available and "no USB host controller" in roles["block"].reason


def test_capabilities_name_usbguard_as_a_conflict(rig: Rig) -> None:
    rig.sysfs.add_file("/etc/usbguard/usbguard-daemon.conf", "")
    rig.sysfs.remove_tree(MODULE)
    notes = rig.lx.capabilities().notes
    assert any(note.startswith("conflict: USBGuard") for note in notes)
    assert any("module parameter is missing" in note for note in notes)


def test_baseline_unavailable_without_the_rules_directory(rig: Rig) -> None:
    rig.rules = FakeRuleFiles()
    roles = {status.role: status for status in rig.make().mechanisms()}
    assert not roles["baseline_read_only"].available
    assert RULES_DIR in roles["baseline_read_only"].reason


def test_capabilities_change_nothing(rig: Rig) -> None:
    rig.lx.capabilities()
    rig.lx.mechanisms()
    assert rig.sysfs.writes == [] and rig.block.calls == [] and rig.rules.calls == []
    assert rig.runner.calls == []


# --- kernel command line ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        ("BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet", None),
        ("root=/dev/sda1 usbcore.authorized_default=0 quiet", "0"),
        ("usbcore.authorized_default=1 usbcore.authorized_default=2", "2"),
        ("usbcore.authorized_default=-1\n", "-1"),
        ("xusbcore.authorized_default=0", None),
        ("", None),
    ],
)
def test_parse_authorized_default_param(cmdline: str, expected: str | None) -> None:
    assert parse_authorized_default_param(cmdline) == expected


# --- system volume ------------------------------------------------------------------------


def mount_line(mount_id: int, number: str, point: str, source: str, fs: str = "ext4") -> str:
    return f"{mount_id} 1 {number} / {point} rw,relatime shared:1 - {fs} {source} rw"


def test_a_usb_disk_holding_the_root_filesystem_is_found(rig: Rig) -> None:
    table = "\n".join(
        [
            mount_line(20, "8:17", "/", "/dev/sdb1"),
            mount_line(21, "8:1", "/boot", "/dev/sda1"),
            mount_line(22, "0:21", "/run", "tmpfs", "tmpfs"),
        ]
    )
    other = make_device(instance_id=f"{HUB2}/2-1", bus_path="2-1")
    found = system_device_ids([stick(), other], sysfs=rig.sysfs, mountinfo=table)
    assert found == frozenset({DEV})


def test_an_internal_root_disk_protects_no_usb_device(rig: Rig) -> None:
    table = mount_line(20, "8:1", "/", "/dev/sda1")
    assert system_device_ids([stick()], sysfs=rig.sysfs, mountinfo=table) == frozenset()


def test_a_device_mapper_stack_is_followed_to_the_usb_disk(rig: Rig) -> None:
    rig.sysfs.add_file("/sys/devices/virtual/block/dm-0/dev", "253:0")
    rig.sysfs.add_link("/sys/dev/block/253:0", "../../devices/virtual/block/dm-0")
    rig.sysfs.add_link("/sys/class/block/dm-0", "../../devices/virtual/block/dm-0")
    rig.sysfs.add_link(
        "/sys/devices/virtual/block/dm-0/slaves/sdb1",
        relative(f"{STORAGE}/sdb/sdb1", "/sys/devices/virtual/block/dm-0/slaves"),
    )
    table = mount_line(20, "253:0", "/", "/dev/mapper/root")
    assert system_device_ids([stick()], sysfs=rig.sysfs, mountinfo=table) == frozenset({DEV})


def test_an_anonymous_device_number_falls_back_to_the_source(rig: Rig) -> None:
    table = mount_line(20, "0:33", "/", "/dev/sdb1", "btrfs")
    assert system_device_ids([stick()], sysfs=rig.sysfs, mountinfo=table) == frozenset({DEV})


def test_a_mount_table_without_root_is_an_error(rig: Rig) -> None:
    with pytest.raises(BackendError):
        system_device_ids(
            [stick()], sysfs=rig.sysfs, mountinfo=mount_line(20, "8:1", "/boot", "/dev/sda1")
        )


def test_an_unresolvable_root_device_is_an_error(rig: Rig) -> None:
    table = mount_line(20, "8:99", "/", "/dev/sdq1")
    with pytest.raises(BackendError):
        system_device_ids([stick()], sysfs=rig.sysfs, mountinfo=table)


def test_a_virtual_root_protects_nothing(rig: Rig) -> None:
    table = mount_line(20, "0:30", "/", "overlay", "overlay")
    assert system_device_ids([stick()], sysfs=rig.sysfs, mountinfo=table) == frozenset()
