"""The Linux backend: mount table parsing, debouncing, and events end to end.

``ChangeTracker`` is driven with ``FakeClock`` and no threads, so every timing assertion
is exact. ``LinuxBackend`` runs its real threads against a synthetic sysfs tree and a
scripted uevent transport; those tests wait on queues, never on the clock. Tests that
need block devices in the tree are ``linux_only``.
"""

from __future__ import annotations

import errno
import queue
import threading
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path

import pytest

import portlock.guard.linux.backend as backend_module
from factories import flash_drive, keyboard, mounted_flash_drive
from portlock.core.clock import FakeClock
from portlock.core.errors import BackendError
from portlock.core.models import DeviceEvent, DeviceEventType, UsbDevice, Volume
from portlock.guard.base import DeviceBackend
from portlock.guard.linux import LinuxBackend as ExportedBackend
from portlock.guard.linux.backend import ChangeTracker, LinuxBackend
from portlock.guard.linux.mounts import (
    MountEntry,
    MountWatcher,
    attach_mounts,
    parse_mountinfo,
    unescape_mount_field,
)
from sysfs_tree import BOOT_KEYBOARD, NESTED, QueueTransport, SysfsTree, uevent_message

REPLACEMENT = "\N{REPLACEMENT CHARACTER}"

# --- the mount table ---------------------------------------------------------------------

MOUNTINFO = (
    "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro\n"
    "23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
    "98 22 8:17 / /media/user/EXAMPLE rw,nosuid,nodev,relatime shared:55 - vfat /dev/sdb1"
    " rw,fmask=0022,dmask=0022,codepage=437\n"
    "99 22 8:18 / /media/user/My\\040Stick\\011x ro,nosuid,nodev - fuse.exfat /dev/sdb2 ro\n"
)


def test_the_documented_example_line_parses() -> None:
    line = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue"
    assert parse_mountinfo(line) == [
        MountEntry(
            mount_id=36,
            parent_id=35,
            device="98:0",
            root="/mnt1",
            mount_point="/mnt2",
            options=("rw", "noatime"),
            fs_type="ext3",
            source="/dev/root",
            super_options=("rw", "errors=continue"),
        )
    ]


def test_a_table_parses_line_by_line() -> None:
    entries = parse_mountinfo(MOUNTINFO)
    assert [entry.mount_point for entry in entries] == [
        "/",
        "/proc",
        "/media/user/EXAMPLE",
        "/media/user/My Stick\tx",
    ]
    assert [entry.fs_type for entry in entries] == ["ext4", "proc", "vfat", "fuse.exfat"]
    assert entries[2].device == "8:17" and entries[2].source == "/dev/sdb1"
    assert entries[2].super_options[:2] == ("rw", "fmask=0022")
    assert [entry.read_only for entry in entries] == [False, False, False, True]
    assert parse_mountinfo(MOUNTINFO.encode()) == entries


@pytest.mark.parametrize(
    ("escaped", "plain"),
    [
        (r"/media/a\040b", "/media/a b"),
        (r"/media/tab\011here", "/media/tab\there"),
        (r"/media/new\012line", "/media/new\nline"),
        (r"/media/back\134slash", "/media/back\\slash"),
        (r"/media/\040\040two", "/media/  two"),
        (r"/media/caf\303\251", "/media/caf\N{LATIN SMALL LETTER E WITH ACUTE}"),
        ("/media/plain", "/media/plain"),
        # Not escapes: too few digits, not octal, or beyond one byte.
        (r"/media/a\04", r"/media/a\04"),
        (r"/media/a\089", r"/media/a\089"),
        (r"/media/a\777", r"/media/a\777"),
        (r"/media/a\\", r"/media/a\\"),
    ],
)
def test_octal_escapes_are_undone(escaped: str, plain: str) -> None:
    assert unescape_mount_field(escaped) == plain
    assert unescape_mount_field(escaped.encode()) == plain


def test_an_escaped_backslash_is_not_expanded_twice() -> None:
    # \134 is a backslash; the "040" that follows it is then just three digits.
    assert unescape_mount_field(r"/media/a\134040b") == r"/media/a\040b"


def test_mount_points_that_are_not_utf8_stay_well_formed() -> None:
    line = b"40 22 8:33 / /media/bad\\377\\376name rw - vfat /dev/sdc1 rw\n"
    (entry,) = parse_mountinfo(line)
    assert entry.mount_point == f"/media/bad{REPLACEMENT}{REPLACEMENT}name"
    entry.mount_point.encode("utf-8")
    (raw,) = parse_mountinfo(b"41 22 8:34 / /media/raw\xff rw - vfat /dev/sdc2 rw\n")
    assert raw.mount_point == f"/media/raw{REPLACEMENT}"


def test_optional_fields_may_be_absent_or_many() -> None:
    none = "30 22 8:17 / /a rw - vfat /dev/sdb1 rw"
    many = "31 22 8:17 / /b rw shared:1 master:2 propagate_from:3 unbindable - vfat /dev/sdb1 rw"
    unknown = "32 22 8:17 / /c rw some-future-tag:9 - vfat /dev/sdb1 rw"
    entries = parse_mountinfo("\n".join([none, many, unknown]))
    assert [(entry.mount_point, entry.fs_type) for entry in entries] == [
        ("/a", "vfat"),
        ("/b", "vfat"),
        ("/c", "vfat"),
    ]


def test_a_hyphen_in_a_path_is_not_the_separator() -> None:
    # A mount point may itself begin with a hyphen; the separator is only looked for
    # after the per-mount options.
    (entry,) = parse_mountinfo("33 22 8:17 / /- rw shared:1 - vfat /dev/sdb1 rw")
    assert entry.mount_point == "/-" and entry.fs_type == "vfat"


def test_missing_super_options_and_windows_line_ends_are_tolerated() -> None:
    entries = parse_mountinfo(
        "34 22 8:17 / /a rw - vfat /dev/sdb1\r\n35 22 8:18 / /b rw - ext4 x rw\r\n"
    )
    assert [(entry.mount_point, entry.source, entry.super_options) for entry in entries] == [
        ("/a", "/dev/sdb1", ()),
        ("/b", "x", ("rw",)),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "36 35 98:0 /mnt1 /mnt2 rw,noatime",  # ends before the separator
        "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 ext3 /dev/root rw",  # no separator
        "36 35 98:0 /mnt1 /mnt2 rw - ext3",  # nothing after the filesystem type
        "x 35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw",
        "36 -1 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw",
        "36 35 98 /mnt1 /mnt2 rw - ext3 /dev/root rw",
        "36 35 a:b /mnt1 /mnt2 rw - ext3 /dev/root rw",
        "36 35 98:0 /mnt1 mnt2 rw - ext3 /dev/root rw",  # a relative mount point
        "36  35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw",  # doubled space shifts every field
    ],
)
def test_malformed_lines_are_skipped_without_hiding_the_rest(line: str) -> None:
    good = "98 22 8:17 / /media/ok rw - vfat /dev/sdb1 rw"
    entries = parse_mountinfo(f"{line}\n{good}\n")
    assert [entry.mount_point for entry in entries] == ["/media/ok"]


def test_a_table_can_be_read_from_a_path(tmp_path: Path) -> None:
    table = tmp_path / "mountinfo"
    table.write_bytes(MOUNTINFO.encode())
    assert parse_mountinfo(table) == parse_mountinfo(MOUNTINFO)


def test_an_unreadable_table_is_a_backend_error(tmp_path: Path) -> None:
    with pytest.raises(BackendError, match="cannot read mount table") as caught:
        parse_mountinfo(tmp_path / "absent")
    assert caught.value.code == "backend_error"


def storage_with_volumes(**numbers: str) -> UsbDevice:
    volumes = (
        Volume("/dev/sdb", size_bytes=16_000_000_000, read_only=False),
        Volume("/dev/sdb1", size_bytes=104_857_600, read_only=False),
        Volume("/dev/sdb2", size_bytes=15_000_000_000, read_only=True),
    )
    return flash_drive(volumes=volumes, backend_data=numbers)


def test_mount_points_are_attached_by_device_number() -> None:
    device = storage_with_volumes(**{"blockdev:/dev/sdb1": "8:17", "blockdev:/dev/sdb2": "8:18"})
    # The mount sources are aliases, so only the numbers can match.
    table = MOUNTINFO.replace("/dev/sdb1", "/dev/disk/by-uuid/TEST-0001").replace(
        "/dev/sdb2", "/dev/disk/by-label/x"
    )
    (attached,) = attach_mounts([device], parse_mountinfo(table))
    assert attached.volumes == (
        Volume("/dev/sdb", size_bytes=16_000_000_000, read_only=False),
        Volume(
            "/dev/sdb1",
            mount_point="/media/user/EXAMPLE",
            fs_type="vfat",
            size_bytes=104_857_600,
            read_only=False,
        ),
        Volume(
            "/dev/sdb2",
            mount_point="/media/user/My Stick\tx",
            fs_type="fuse.exfat",
            size_bytes=15_000_000_000,
            read_only=True,
        ),
    )
    assert attached.backend_data == device.backend_data
    assert attached.instance_id == device.instance_id


def test_mount_points_are_attached_by_source_when_the_number_is_unknown() -> None:
    # btrfs reports a device number of its own, so the node name has to do.
    table = "70 22 0:44 / /mnt/btr rw - btrfs /dev/sdb1 rw\n"
    (attached,) = attach_mounts([storage_with_volumes()], parse_mountinfo(table))
    assert attached.volumes[1].mount_point == "/mnt/btr"
    assert attached.volumes[1].fs_type == "btrfs"
    assert attached.volumes[0].mount_point is None
    (by_number_miss,) = attach_mounts(
        [storage_with_volumes(**{"blockdev:/dev/sdb1": "8:17"})], parse_mountinfo(table)
    )
    assert by_number_miss.volumes[1].mount_point == "/mnt/btr"


def test_the_whole_filesystem_mount_is_preferred_over_bind_mounts() -> None:
    table = (
        "80 22 8:17 /sub /srv/bind rw - vfat /dev/sdb1 rw\n"
        "95 22 8:17 / /media/second rw - vfat /dev/sdb1 rw\n"
        "90 22 8:17 / /media/first rw - vfat /dev/sdb1 rw\n"
    )
    device = storage_with_volumes(**{"blockdev:/dev/sdb1": "8:17"})
    (attached,) = attach_mounts([device], parse_mountinfo(table))
    assert attached.volumes[1].mount_point == "/media/first"
    (only_bind,) = attach_mounts([device], parse_mountinfo(table.splitlines()[0]))
    assert only_bind.volumes[1].mount_point == "/srv/bind"


def test_a_read_only_mount_does_not_claim_a_read_only_device() -> None:
    table = "99 22 8:17 / /media/ro ro,nosuid - vfat /dev/sdb1 ro\n"
    device = storage_with_volumes(**{"blockdev:/dev/sdb1": "8:17"})
    (attached,) = attach_mounts([device], parse_mountinfo(table))
    assert attached.volumes[1].mount_point == "/media/ro"
    assert attached.volumes[1].read_only is False


def test_devices_without_matching_mounts_are_left_alone() -> None:
    plain, storage = keyboard(), storage_with_volumes()
    attached = attach_mounts(
        [plain, storage], parse_mountinfo("22 1 8:2 / / rw - ext4 /dev/sda2 rw")
    )
    assert attached[0] is plain
    assert attached[1] == storage
    assert attach_mounts([], []) == []


def test_watching_needs_a_table_that_can_be_opened(tmp_path: Path) -> None:
    watcher = MountWatcher(lambda: None, tmp_path / "absent")
    with pytest.raises(BackendError):
        watcher.start()
    watcher.stop()  # nothing was started


@pytest.mark.windows_only
def test_watching_is_unavailable_without_poll(tmp_path: Path) -> None:
    table = tmp_path / "mountinfo"
    table.write_bytes(MOUNTINFO.encode())
    with pytest.raises(BackendError, match="cannot watch the mount table"):
        MountWatcher(lambda: None, table).start()


@pytest.mark.linux_only
def test_a_watcher_starts_and_stops_cleanly(tmp_path: Path) -> None:
    table = tmp_path / "mountinfo"
    table.write_bytes(MOUNTINFO.encode())
    calls: list[int] = []
    watcher = MountWatcher(lambda: calls.append(1), table)
    watcher.start()
    with pytest.raises(BackendError, match="already running"):
        watcher.start()
    assert any(thread.name == "portlock-mounts" for thread in threading.enumerate())
    watcher.stop()
    assert not any(thread.name == "portlock-mounts" for thread in threading.enumerate())
    # An ordinary file never signals a mount change.
    assert calls == []
    watcher.stop()
    watcher.start()
    watcher.stop()


# --- ChangeTracker: exact timing, no threads ---------------------------------------------


class Present:
    """A mutable device list standing in for sysfs, counting how often it is read."""

    def __init__(self, *devices: UsbDevice) -> None:
        self.devices = list(devices)
        self.error: BackendError | None = None
        self.reads = 0

    def __call__(self) -> list[UsbDevice]:
        self.reads += 1
        if self.error is not None:
            raise self.error
        return list(self.devices)


@pytest.fixture
def present() -> Present:
    return Present(keyboard())


@pytest.fixture
def tracker(present: Present, clock: FakeClock) -> ChangeTracker:
    built = ChangeTracker(present, clock, settle_seconds=0.25, max_delay_seconds=2.0)
    built.prime()
    return built


def test_an_idle_tracker_reads_nothing(tracker: ChangeTracker, present: Present) -> None:
    assert tracker.due_in() is None
    assert tracker.collect() == []
    assert present.reads == 1  # the baseline only


def test_devices_present_at_the_start_are_not_reported(
    tracker: ChangeTracker, clock: FakeClock
) -> None:
    tracker.hint()
    clock.advance(1)
    assert tracker.collect() == []


def test_a_burst_of_hints_yields_one_read_and_one_arrival(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    """One plug-in: the device, two interfaces, two driver bindings. Five uevents."""
    stick = flash_drive()
    present.devices.append(stick)
    for _ in range(5):
        tracker.hint()
        clock.advance(0.03125)
        assert tracker.collect() == []  # still inside the burst
    assert present.reads == 1
    # The last hint was 1/32 s ago; a quarter of a second of quiet is required.
    assert tracker.due_in() == 0.21875

    clock.advance(0.21875)
    assert tracker.due_in() == 0.0
    events = tracker.collect()
    assert events == [DeviceEvent(DeviceEventType.ARRIVED, stick, clock.now())]
    assert present.reads == 2

    # Nothing is left over: no second arrival, no further read.
    assert tracker.due_in() is None
    clock.advance(10)
    assert tracker.collect() == []
    assert present.reads == 2


def test_a_volume_appearing_later_is_a_change_not_an_arrival(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    present.devices.append(flash_drive())
    tracker.hint()
    clock.advance(0.25)
    assert [event.type for event in tracker.collect()] == [DeviceEventType.ARRIVED]

    # About a second later the disk shows up and is mounted.
    clock.advance(1.1)
    present.devices[-1] = mounted = mounted_flash_drive()
    tracker.hint()
    clock.advance(0.25)
    (event,) = tracker.collect()
    assert event.type is DeviceEventType.CHANGED
    assert event.device == mounted
    assert event.device.volumes[0].mount_point == "/media/test"
    assert event.at == clock.now()


def test_a_removal_is_reported_once(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    gone = present.devices.pop()
    tracker.hint()
    tracker.hint()
    clock.advance(0.25)
    assert tracker.collect() == [DeviceEvent(DeviceEventType.REMOVED, gone, clock.now())]
    tracker.hint()
    clock.advance(0.25)
    assert tracker.collect() == []


def test_plugged_in_and_out_within_one_burst_is_not_an_event(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    present.devices.append(flash_drive())
    tracker.hint()
    clock.advance(0.1)
    present.devices.pop()
    tracker.hint()
    clock.advance(0.25)
    assert tracker.collect() == []
    assert present.reads == 2


def test_an_endless_stream_of_hints_cannot_postpone_the_read_for_ever(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    stick = flash_drive()
    present.devices.append(stick)
    for _ in range(15):  # a hint every 1/8 s: the quiet period never completes
        tracker.hint()
        assert tracker.collect() == []
        clock.advance(0.125)
    tracker.hint()
    assert tracker.due_in() == 0.125  # capped by the limit, not the quiet period
    clock.advance(0.125)  # two seconds after the first hint
    assert [event.device for event in tracker.collect()] == [stick]
    assert present.reads == 2


def test_an_urgent_hint_is_due_at_once(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    stick = flash_drive()
    present.devices.append(stick)
    tracker.hint()
    assert tracker.due_in() == 0.25
    tracker.hint(urgent=True)
    assert tracker.due_in() == 0.0
    assert [event.type for event in tracker.collect()] == [DeviceEventType.ARRIVED]
    # Urgency does not stick to later hints.
    tracker.hint()
    assert tracker.due_in() == 0.25


def test_lost_notifications_end_the_read_with_a_resync(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    stick = flash_drive()
    present.devices.append(stick)
    tracker.hint(resync=True)
    assert tracker.due_in() == 0.0  # no point waiting for quiet
    assert tracker.collect() == [
        DeviceEvent(DeviceEventType.ARRIVED, stick, clock.now()),
        DeviceEvent(DeviceEventType.RESYNC, None, clock.now()),
    ]
    # Reported once only.
    tracker.hint()
    clock.advance(0.25)
    assert tracker.collect() == []


def test_a_resync_is_reported_even_when_nothing_changed(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    tracker.hint()
    tracker.hint(resync=True)
    assert tracker.collect() == [DeviceEvent(DeviceEventType.RESYNC, None, clock.now())]
    assert present.reads == 2


def test_a_failed_read_keeps_the_resync_pending(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    tracker.hint(resync=True)
    present.error = BackendError("sysfs is not available at /sys")
    with pytest.raises(BackendError):
        tracker.collect()
    # Retried after a settle period, not at once: an immediate retry would fail again.
    assert tracker.due_in() == 0.25
    present.error = None
    clock.advance(0.25)
    assert tracker.collect() == [DeviceEvent(DeviceEventType.RESYNC, None, clock.now())]


def test_hints_that_arrive_before_the_baseline_are_kept(clock: FakeClock) -> None:
    present = Present()
    tracker = ChangeTracker(present, clock, settle_seconds=0.25, max_delay_seconds=2.0)
    tracker.hint()  # the uevent socket was opened first
    tracker.prime()
    stick = flash_drive()
    present.devices.append(stick)  # arrived while the baseline was being read
    clock.advance(0.25)
    assert [event.device for event in tracker.collect()] == [stick]


def test_a_failed_read_loses_nothing(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    stick = flash_drive()
    present.devices.append(stick)
    tracker.hint()
    clock.advance(0.25)
    present.error = BackendError("sysfs is not available at /sys")
    with pytest.raises(BackendError):
        tracker.collect()
    # The tracker re-armed itself: the read is retried after another settle period.
    assert tracker.due_in() == 0.25
    present.error = None
    assert tracker.collect() == []
    clock.advance(0.25)
    assert tracker.collect() == [DeviceEvent(DeviceEventType.ARRIVED, stick, clock.now())]


def test_event_times_come_from_the_injected_clock(
    tracker: ChangeTracker, present: Present, clock: FakeClock
) -> None:
    present.devices.append(flash_drive())
    tracker.hint(urgent=True)
    clock.advance(timedelta(hours=3))
    (event,) = tracker.collect()
    assert event.at == clock.now()
    assert event.at.utcoffset() == timedelta(0)


def test_zero_settle_time_reads_immediately(clock: FakeClock) -> None:
    present = Present()
    tracker = ChangeTracker(present, clock, settle_seconds=0, max_delay_seconds=0)
    tracker.prime()
    present.devices.append(keyboard())
    tracker.hint()
    assert tracker.due_in() == 0.0
    assert len(tracker.collect()) == 1


@pytest.mark.parametrize(("settle", "limit"), [(-0.1, 2.0), (1.0, 0.5), (0.0, -1.0)])
def test_tracker_delays_are_validated(clock: FakeClock, settle: float, limit: float) -> None:
    with pytest.raises(ValueError):
        ChangeTracker(Present(), clock, settle_seconds=settle, max_delay_seconds=limit)


# --- LinuxBackend: real threads, synthetic kernel ----------------------------------------

CONTROLLER = "/devices/platform/vhci_hcd.0"
# Made up: the shape of /proc/sys/kernel/random/boot_id, not any machine's value.
BOOT_ID = "00000000-0000-4000-8000-00000000b007"
MOUNTED_LINE = b"98 22 8:17 / /media/user/EXAMPLE rw - vfat /dev/sdb1 rw"


def device_path(name: str) -> str:
    """The DEVPATH the kernel would use for a device of the synthetic tree."""
    chain = [name]
    while not chain[-1].startswith("usb"):
        bus, _, path = chain[-1].partition("-")
        head, dot, _port = path.rpartition(".")
        chain.append(f"{bus}-{head}" if dot else f"usb{bus}")
    return CONTROLLER + "/" + "/".join(reversed(chain))


def device_event(action: str, name: str) -> bytes:
    return uevent_message(action, device_path(name), DEVTYPE="usb_device")


class FakeWatcher:
    """Stands in for ``MountWatcher``; the test fires the change itself."""

    def __init__(self, on_change: Callable[[], None], path: Path) -> None:
        self.on_change = on_change
        self.path = path
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


class GatedBackend(LinuxBackend):
    """A backend whose reads of the tree never overlap with a test changing the tree.

    The kernel fills in a device's directory before it announces the device. A test
    writes the files one by one, so without the gate a read could catch a device with
    half of its attributes, which never happens after a real uevent.
    """

    def __init__(self, gate: threading.Lock, **options: object) -> None:
        super().__init__(**options)  # type: ignore[arg-type]
        self._gate = gate

    def enumerate(self) -> list[UsbDevice]:
        with self._gate:
            return super().enumerate()


class Harness:
    """A backend wired to a synthetic tree, a scripted uevent source and an event queue."""

    def __init__(self, tmp_path: Path, **options: object) -> None:
        self.gate = threading.Lock()
        self.tree = SysfsTree(tmp_path / "sys")
        self.tree.add_root_hub(1)
        self.mountinfo = tmp_path / "mountinfo"
        self.mountinfo.write_bytes(b"22 1 8:2 / / rw - ext4 /dev/sda2 rw\n")
        self.boot_id = tmp_path / "boot_id"
        self.boot_id.write_text(BOOT_ID + "\n")
        self.transports: list[QueueTransport] = []
        self.watchers: list[FakeWatcher] = []
        self.events: queue.Queue[DeviceEvent] = queue.Queue()
        settings: dict[str, object] = {
            "sysfs_root": self.tree.root,
            "mountinfo": self.mountinfo,
            "settle_seconds": 0.0,
            "max_delay_seconds": 0.0,
            "poll_interval": 0.005,
            "transport_factory": self.open_transport,
            "mount_watcher_factory": self.open_watcher,
            "boot_id_path": self.boot_id,
        }
        settings.update(options)
        self.backend = GatedBackend(self.gate, **settings)

    def open_transport(self) -> QueueTransport:
        self.transports.append(QueueTransport())
        return self.transports[-1]

    def open_watcher(self, on_change: Callable[[], None], path: Path) -> FakeWatcher:
        self.watchers.append(FakeWatcher(on_change, path))
        return self.watchers[-1]

    @property
    def transport(self) -> QueueTransport:
        return self.transports[-1]

    def start(self) -> None:
        self.backend.start(self.events.put)

    def changing(self) -> threading.Lock:
        """``with harness.changing():`` makes a change to the tree atomic for the backend."""
        return self.gate

    def announce(self, action: str, name: str) -> None:
        self.transport.push(device_event(action, name))

    def next_event(self) -> DeviceEvent:
        return self.events.get(timeout=5)

    def expect_nothing_before(self, name: str) -> DeviceEvent:
        """Plug in a marker device and require that its arrival is the very next event.

        Anything the backend had still been going to report would come out first, so this
        proves "no further event" without waiting for one not to happen.
        """
        with self.changing():
            self.tree.add_device(name, product_id=0x0EEE, serial=f"TESTMARK{name}")
        self.announce("add", name)
        event = self.next_event()
        assert (event.type, event.device.bus_path) == (DeviceEventType.ARRIVED, name)
        return event


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    built = Harness(tmp_path)
    try:
        yield built
    finally:
        built.backend.stop()


def backend_threads() -> list[str]:
    """Names of the backend threads still running.

    The short-lived thread that switches a backend to polling is given the chance to
    finish first; it has done its work by the time polling delivers an event.
    """
    for thread in threading.enumerate():
        if thread.name == "portlock-linux-fallback":
            thread.join(5)
    return sorted(
        thread.name for thread in threading.enumerate() if thread.name.startswith("portlock-")
    )


def test_the_backend_is_a_device_backend() -> None:
    assert issubclass(LinuxBackend, DeviceBackend)
    assert ExportedBackend is LinuxBackend


def test_enumerate_lists_the_tree(harness: Harness) -> None:
    harness.tree.add_device("1-1")
    harness.tree.keyboard_mouse("1-3")
    devices = harness.backend.enumerate()
    assert [device.bus_path for device in devices] == ["usb1", "1-1", "1-3"]
    assert devices[1].serial == "TEST0001A7C3"
    assert devices[2].is_keyboard
    assert backend_threads() == []  # enumerating starts nothing


def test_enumerate_without_sysfs_is_a_backend_error(tmp_path: Path) -> None:
    backend = LinuxBackend(sysfs_root=tmp_path / "nowhere", mountinfo=None)
    with pytest.raises(BackendError):
        backend.enumerate()
    assert backend.capabilities().can_enumerate is False


def test_capabilities_before_start_reflect_what_can_be_opened(harness: Harness) -> None:
    capabilities = harness.backend.capabilities()
    assert capabilities.name == "linux"
    assert capabilities.can_enumerate is True
    assert capabilities.event_driven is True
    assert capabilities.notes == ()
    # The probe opened the socket and closed it again.
    assert len(harness.transports) == 1 and harness.transport.closed


def test_capabilities_say_when_there_is_no_usb_bus(tmp_path: Path) -> None:
    (tmp_path / "sys" / "bus").mkdir(parents=True)
    backend = LinuxBackend(
        sysfs_root=tmp_path / "sys", mountinfo=None, transport_factory=QueueTransport
    )
    capabilities = backend.capabilities()
    assert capabilities.can_enumerate is False
    assert capabilities.event_driven is True
    assert any("no USB bus" in note for note in capabilities.notes)
    assert any("without mount points" in note for note in capabilities.notes)
    assert backend.enumerate() == []


def test_devices_present_at_start_are_not_reported(harness: Harness) -> None:
    harness.tree.add_device("1-1")
    harness.start()
    harness.announce("change", "1-1")
    harness.expect_nothing_before("1-9")
    assert harness.events.empty()
    assert harness.backend.capabilities().event_driven is True


def test_one_arrival_with_several_uevents_is_one_event(harness: Harness) -> None:
    harness.start()
    with harness.changing():
        harness.tree.keyboard_mouse("1-3")
    path = device_path("1-3")
    harness.announce("add", "1-3")
    for interface in ("1-3:1.0", "1-3:1.1"):
        harness.transport.push(
            uevent_message("add", f"{path}/{interface}", DEVTYPE="usb_interface")
        )
        harness.transport.push(
            uevent_message("bind", f"{path}/{interface}", DEVTYPE="usb_interface")
        )
    harness.announce("bind", "1-3")

    event = harness.next_event()
    assert event.type is DeviceEventType.ARRIVED
    assert event.device.bus_path == "1-3"
    assert event.device.is_keyboard
    assert event.device.interfaces[0].cls == BOOT_KEYBOARD[0]
    assert len(event.device.interfaces) == 2
    harness.transport.settle()
    harness.expect_nothing_before("1-9")
    assert harness.events.empty()


def test_removal_is_reported_with_the_device_that_left(harness: Harness) -> None:
    harness.tree.add_device("1-1")
    harness.start()
    with harness.changing():
        harness.tree.remove_device("1-1")
    harness.announce("remove", "1-1")
    event = harness.next_event()
    assert event.type is DeviceEventType.REMOVED
    assert event.device.bus_path == "1-1"
    assert event.device.serial == "TEST0001A7C3"
    harness.expect_nothing_before("1-9")


def test_a_hub_and_what_is_behind_it_arrive_in_order(harness: Harness) -> None:
    harness.start()
    with harness.changing():
        harness.tree.hub("1-4")
        harness.tree.add_device("1-4.1", serial="TEST0041")
    harness.announce("add", "1-4.1")
    first, second = harness.next_event(), harness.next_event()
    assert [(event.type, event.device.bus_path) for event in (first, second)] == [
        (DeviceEventType.ARRIVED, "1-4"),
        (DeviceEventType.ARRIVED, "1-4.1"),
    ]
    assert first.device.is_hub


def test_lost_uevents_are_recovered_and_the_caller_told_to_resync(harness: Harness) -> None:
    harness.tree.add_device("1-2", serial="TEST0002")
    harness.start()
    with harness.changing():
        harness.tree.add_device("1-1")
        harness.tree.remove_device("1-2")
    # The uevents never arrive: the kernel reports that its buffer overflowed.
    harness.transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
    removed, arrived, resync = (harness.next_event() for _ in range(3))
    assert (removed.type, removed.device.bus_path) == (DeviceEventType.REMOVED, "1-2")
    assert (arrived.type, arrived.device.bus_path) == (DeviceEventType.ARRIVED, "1-1")
    # Whatever came and went while messages were dropped is invisible to any snapshot,
    # so the caller is told to enumerate again.
    assert resync.type is DeviceEventType.RESYNC and resync.device is None
    harness.expect_nothing_before("1-9")


def test_an_overrun_with_nothing_changed_is_still_a_resync(harness: Harness) -> None:
    harness.tree.add_device("1-1")
    harness.start()
    harness.transport.push(b"", truncated=True)  # part of a uevent was cut off
    event = harness.next_event()
    assert event.type is DeviceEventType.RESYNC
    assert harness.backend.enumerate()[1].bus_path == "1-1"
    harness.expect_nothing_before("1-9")


def test_a_callback_failing_on_resync_does_not_stop_detection(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    seen: queue.Queue[DeviceEventType] = queue.Queue()

    def fail_on_resync(event: DeviceEvent) -> None:
        seen.put(event.type)
        if event.type is DeviceEventType.RESYNC:
            raise RuntimeError("the pipeline fell over")

    harness.backend.start(fail_on_resync)
    try:
        harness.transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
        assert seen.get(timeout=5) is DeviceEventType.RESYNC
        with harness.changing():
            harness.tree.add_device("1-1")
        harness.announce("add", "1-1")
        assert seen.get(timeout=5) is DeviceEventType.ARRIVED
    finally:
        harness.backend.stop()


def test_devices_carry_a_connection_id(harness: Harness) -> None:
    harness.tree.add_device("1-1", devnum=7)
    harness.start()
    with harness.changing():
        harness.tree.remove_device("1-1")
        harness.tree.add_device("1-1", devnum=8)
    harness.announce("add", "1-1")
    # Same port, same device, new connection: the old one left, a new one arrived.
    removed, arrived = harness.next_event(), harness.next_event()
    assert (removed.type, removed.device.connection_id) == (
        DeviceEventType.REMOVED,
        f"{BOOT_ID}:1:7",
    )
    assert (arrived.type, arrived.device.connection_id) == (
        DeviceEventType.ARRIVED,
        f"{BOOT_ID}:1:8",
    )
    assert removed.device.instance_id == arrived.device.instance_id


def test_without_a_boot_id_there_are_no_connection_ids(tmp_path: Path) -> None:
    harness = Harness(tmp_path, boot_id_path=tmp_path / "missing")
    harness.tree.add_device("1-1")
    assert [device.connection_id for device in harness.backend.enumerate()] == [None, None]
    assert any("boot id cannot be read" in note for note in harness.backend.capabilities().notes)
    # Once readable, it is used (and then kept).
    (tmp_path / "missing").write_text(BOOT_ID + "\n")
    assert harness.backend.enumerate()[1].connection_id == f"{BOOT_ID}:1:2"
    (tmp_path / "missing").unlink()
    assert harness.backend.enumerate()[1].connection_id == f"{BOOT_ID}:1:2"


def test_event_times_come_from_the_backends_clock(tmp_path: Path, clock: FakeClock) -> None:
    harness = Harness(tmp_path, clock=clock)
    harness.start()
    try:
        clock.advance(timedelta(days=2))
        with harness.changing():
            harness.tree.add_device("1-1")
        harness.announce("add", "1-1")
        assert harness.next_event().at == clock.now()
    finally:
        harness.backend.stop()


def test_a_failing_callback_does_not_stop_detection(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    seen: queue.Queue[str | None] = queue.Queue()

    def fail_first(event: DeviceEvent) -> None:
        seen.put(event.device.bus_path)
        if event.device.bus_path == "1-1":
            raise RuntimeError("the pipeline fell over")

    harness.backend.start(fail_first)
    try:
        with harness.changing():
            harness.tree.add_device("1-1")
        harness.announce("add", "1-1")
        assert seen.get(timeout=5) == "1-1"
        with harness.changing():
            harness.tree.add_device("1-2", serial="TEST0002")
        harness.announce("add", "1-2")
        assert seen.get(timeout=5) == "1-2"
    finally:
        harness.backend.stop()


def test_start_twice_is_an_error_and_stop_is_idempotent(harness: Harness) -> None:
    harness.backend.stop()  # never started
    harness.start()
    assert backend_threads() == ["portlock-linux-backend", "portlock-uevent"]
    with pytest.raises(BackendError, match="already started"):
        harness.backend.start(harness.events.put)
    # The failed second start must not have disturbed the first.
    with harness.changing():
        harness.tree.add_device("1-1")
    harness.announce("add", "1-1")
    assert harness.next_event().device.bus_path == "1-1"

    harness.backend.stop()
    assert backend_threads() == []
    assert harness.transport.closed
    assert harness.watchers[-1].started and harness.watchers[-1].stopped
    harness.backend.stop()


def test_nothing_is_reported_after_stop_and_the_backend_restarts(harness: Harness) -> None:
    harness.start()
    harness.backend.stop()
    stale = harness.transport
    harness.tree.add_device("1-1")
    stale.push(device_event("add", "1-1"))
    assert harness.events.empty()

    harness.start()  # 1-1 is part of the new baseline
    assert harness.transport is not stale
    harness.expect_nothing_before("1-9")
    assert harness.events.empty()


def test_the_backend_can_be_stopped_from_its_own_callback(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    stopped = threading.Event()

    calls: list[str | None] = []

    def stop_on_first(event: DeviceEvent) -> None:
        calls.append(event.device.bus_path)
        harness.backend.stop()
        stopped.set()

    harness.backend.start(stop_on_first)
    worker = next(t for t in threading.enumerate() if t.name == "portlock-linux-backend")
    with harness.changing():
        harness.tree.add_device("1-1")
        harness.tree.add_device("1-2", serial="TEST0002")
    harness.announce("add", "1-1")
    assert stopped.wait(5)
    # The callback could not wait for its own thread; it ends once the callback returns,
    # and the second arrival is never delivered to a backend that was told to stop.
    worker.join(5)
    assert backend_threads() == []
    assert calls == ["1-1"]
    assert harness.transport.closed


def test_start_fails_when_sysfs_cannot_be_read_and_can_be_retried(tmp_path: Path) -> None:
    harness = Harness(tmp_path, sysfs_root=tmp_path / "not-mounted")
    with pytest.raises(BackendError, match="sysfs is not available"):
        harness.start()
    assert backend_threads() == []
    assert harness.transport.closed
    # Not left half-started: once sysfs is there, the same object starts normally.
    (tmp_path / "not-mounted" / "bus" / "usb" / "devices").mkdir(parents=True)
    harness.start()
    try:
        assert harness.backend.capabilities().event_driven is True
    finally:
        harness.backend.stop()


# --- polling fallback --------------------------------------------------------------------


def refuse_socket() -> QueueTransport:
    raise BackendError("cannot open the kernel uevent socket: Address family not supported")


def test_without_the_uevent_socket_the_backend_polls(tmp_path: Path) -> None:
    harness = Harness(tmp_path, transport_factory=refuse_socket)
    before = harness.backend.capabilities()
    assert before.event_driven is False
    assert any("polling every 0.005 s" in note for note in before.notes)

    harness.tree.add_device("1-1")
    harness.start()
    try:
        running = harness.backend.capabilities()
        assert running.event_driven is False
        assert any("Address family not supported" in note for note in running.notes)
        assert any("not seen" in note for note in running.notes)
        assert backend_threads() == ["portlock-poll"]

        with harness.changing():
            harness.tree.keyboard_mouse("1-3")
        arrived = harness.next_event()
        assert (arrived.type, arrived.device.bus_path) == (DeviceEventType.ARRIVED, "1-3")
        with harness.changing():
            harness.tree.remove_device("1-1")
        removed = harness.next_event()
        assert (removed.type, removed.device.bus_path) == (DeviceEventType.REMOVED, "1-1")
        assert harness.watchers == []  # polling re-reads the mount table anyway
    finally:
        harness.backend.stop()
    assert backend_threads() == []


def test_a_socket_that_dies_while_running_is_replaced_by_polling(harness: Harness) -> None:
    harness.start()
    assert harness.backend.capabilities().event_driven is True
    harness.transport.push_error(OSError(errno.EIO, "Input/output error"))
    # From here on no uevent can arrive; the device must be found all the same.
    with harness.changing():
        harness.tree.add_device("1-1")
    event = harness.next_event()
    assert (event.type, event.device.bus_path) == (DeviceEventType.ARRIVED, "1-1")
    capabilities = harness.backend.capabilities()
    assert capabilities.event_driven is False
    assert any("Input/output error" in note for note in capabilities.notes)
    assert backend_threads() == ["portlock-poll"]
    assert harness.transport.closed


@pytest.mark.windows_only
def test_on_windows_the_default_backend_falls_back_to_polling(tmp_path: Path) -> None:
    tree = SysfsTree(tmp_path / "sys")
    tree.add_root_hub(1)
    backend = LinuxBackend(sysfs_root=tree.root, mountinfo=None)
    capabilities = backend.capabilities()
    assert capabilities.can_enumerate is True
    assert capabilities.event_driven is False
    assert any("not available on this platform" in note for note in capabilities.notes)


@pytest.mark.parametrize(
    "options",
    [
        {"settle_seconds": -1.0},
        {"settle_seconds": 3.0, "max_delay_seconds": 1.0},
        {"poll_interval": 0.0},
        {"poll_interval": -2.0},
    ],
)
def test_backend_delays_are_validated(options: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        LinuxBackend(**options)  # type: ignore[arg-type]


def test_a_read_failure_while_running_is_retried_not_fatal(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backend_module, "_RETRY_SECONDS", 0.005)
    real_read = backend_module.read_usb_devices
    failures = [BackendError("sysfs briefly unreadable")] * 3
    attempted = threading.Event()

    def flaky(root: Path, *, boot_id: str | None) -> list[UsbDevice]:
        if failures:
            attempted.set()
            raise failures.pop()
        return real_read(root, boot_id=boot_id)

    harness.start()
    monkeypatch.setattr(backend_module, "read_usb_devices", flaky)
    with harness.changing():
        harness.tree.add_device("1-1")
    harness.announce("add", "1-1")
    event = harness.next_event()
    assert attempted.is_set() and failures == []
    assert (event.type, event.device.bus_path) == (DeviceEventType.ARRIVED, "1-1")


def test_an_unexpected_error_while_reading_does_not_kill_detection(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(backend_module, "_RETRY_SECONDS", 0.005)
    real_read = backend_module.read_usb_devices
    failures: list[Exception] = [ValueError("a bug in one read")]

    def buggy(root: Path, *, boot_id: str | None) -> list[UsbDevice]:
        if failures:
            raise failures.pop()
        return real_read(root, boot_id=boot_id)

    harness.start()
    monkeypatch.setattr(backend_module, "read_usb_devices", buggy)
    with harness.changing():
        harness.tree.add_device("1-1")
    harness.transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
    # The failed read lost neither the arrival nor the pending RESYNC.
    first, second = harness.next_event(), harness.next_event()
    assert failures == []
    assert (first.type, first.device.bus_path) == (DeviceEventType.ARRIVED, "1-1")
    assert second.type is DeviceEventType.RESYNC
    assert backend_threads() == ["portlock-linux-backend", "portlock-uevent"]


# --- volumes and mounts (need block devices in the tree) ---------------------------------


@pytest.mark.linux_only
def test_enumerate_attaches_mount_points(harness: Harness) -> None:
    harness.tree.flash_drive("1-1")
    harness.mountinfo.write_bytes(
        b"22 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
        b"98 22 8:17 / /media/user/EXAMPLE rw,nosuid,nodev - vfat /dev/sdb1 rw\n"
    )
    (root_hub, stick) = harness.backend.enumerate()
    assert root_hub.volumes == ()
    assert stick.volumes == (
        Volume("/dev/sdb", size_bytes=31_250_000 * 512, read_only=False),
        Volume(
            "/dev/sdb1",
            mount_point="/media/user/EXAMPLE",
            fs_type="vfat",
            size_bytes=204_800 * 512,
            read_only=False,
        ),
        Volume("/dev/sdb2", size_bytes=31_043_152 * 512, read_only=False),
    )


@pytest.mark.linux_only
def test_an_unreadable_mount_table_only_costs_the_mount_points(harness: Harness) -> None:
    harness.tree.flash_drive("1-1")
    harness.mountinfo.unlink()
    stick = harness.backend.enumerate()[1]
    assert [volume.device_node for volume in stick.volumes] == [
        "/dev/sdb",
        "/dev/sdb1",
        "/dev/sdb2",
    ]
    assert all(volume.mount_point is None for volume in stick.volumes)


@pytest.mark.linux_only
def test_arrival_then_volume_then_mount(harness: Harness) -> None:
    """The life of a plugged-in stick: ARRIVED, then CHANGED twice, never ARRIVED again."""
    assert NESTED
    harness.start()
    with harness.changing():
        harness.tree.add_device("1-1")
    harness.announce("add", "1-1")
    arrived = harness.next_event()
    assert (arrived.type, arrived.device.volumes) == (DeviceEventType.ARRIVED, ())

    # About a second later the SCSI disk and its partition appear.
    with harness.changing():
        disk = harness.tree.add_disk("1-1", "sdb", sectors=4096, partitions=[("sdb1", 2048)])
    block_path = device_path("1-1") + "/1-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb"
    harness.transport.push(uevent_message("add", block_path, "block", DEVTYPE="disk"))
    harness.transport.push(
        uevent_message("add", block_path + "/sdb1", "block", DEVTYPE="partition")
    )
    appeared = harness.next_event()
    assert appeared.type is DeviceEventType.CHANGED
    assert appeared.device.instance_id == arrived.device.instance_id
    assert appeared.device.volumes == (
        Volume("/dev/sdb", size_bytes=4096 * 512, read_only=False),
        Volume("/dev/sdb1", size_bytes=2048 * 512, read_only=False),
    )
    harness.transport.settle()

    # Mounting sends no uevent; the mount watcher reports it.
    with harness.changing():
        harness.mountinfo.write_bytes(MOUNTED_LINE)
    (watcher,) = harness.watchers
    assert watcher.started and watcher.path == harness.mountinfo
    watcher.on_change()
    mounted = harness.next_event()
    assert mounted.type is DeviceEventType.CHANGED
    assert mounted.device.volumes[1].mount_point == "/media/user/EXAMPLE"
    assert mounted.device.volumes[1].fs_type == "vfat"

    # The block device turning read-only is a change as well.
    with harness.changing():
        (disk / "ro").write_bytes(b"1")
    harness.transport.push(uevent_message("change", block_path, "block", DISK_RO="1"))
    read_only = harness.next_event()
    assert read_only.type is DeviceEventType.CHANGED
    assert read_only.device.volumes[0].read_only is True

    harness.expect_nothing_before("1-9")
    assert harness.events.empty()


def test_capabilities_admit_an_unwatched_mount_table(tmp_path: Path) -> None:
    class Unavailable(FakeWatcher):
        def start(self) -> None:
            raise BackendError("this platform cannot watch the mount table")

    harness = Harness(tmp_path, mount_watcher_factory=Unavailable)
    harness.start()
    try:
        capabilities = harness.backend.capabilities()
        assert capabilities.event_driven is True
        assert any("cannot be watched" in note for note in capabilities.notes)
    finally:
        harness.backend.stop()
