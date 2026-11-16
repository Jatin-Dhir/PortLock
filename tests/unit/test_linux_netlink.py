"""Kernel uevents: parsing, sender verification, overrun handling and the polling fallback.

Parsing and the monitor's logic run everywhere, the monitor against ``QueueTransport``
so that a test decides which messages arrive and from whom. The tests marked
``linux_only`` use real netlink sockets on the ``NETLINK_USERSOCK`` protocol, where an
unprivileged process may send to another: a genuine user-space sender, which is exactly
what the monitor must refuse to believe. No test touches the kernel's uevent channel.
"""

from __future__ import annotations

import errno
import queue
import socket
import threading
from collections.abc import Callable, Iterator, Mapping

import pytest

from factories import flash_drive, hub, keyboard, make_device, mounted_flash_drive
from portlock.core.errors import BackendError
from portlock.core.models import DeviceEventType, UsbDevice
from portlock.guard.linux.netlink import (
    KERNEL_GROUP,
    NETLINK_KOBJECT_UEVENT,
    Datagram,
    DeviceChange,
    KernelUeventSocket,
    MonitorStats,
    PollingMonitor,
    UeventKind,
    UeventMonitor,
    classify_uevent,
    diff_devices,
    open_kernel_uevent_socket,
    parse_uevent,
)
from sysfs_tree import QueueTransport, uevent_message

USB_PATH = "/devices/pci0000:00/0000:00:14.0/usb1/1-2"
BLOCK_PATH = USB_PATH + "/1-2:1.0/host6/target6:0:0/6:0:0:0/block/sdb"


def usb_add(devpath: str = USB_PATH, **fields: str) -> bytes:
    return uevent_message("add", devpath, DEVTYPE="usb_device", SEQNUM="4711", **fields)


# --- parse_uevent ------------------------------------------------------------------------


def test_a_kernel_uevent_parses_into_its_pairs() -> None:
    data = (
        b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-2\0"
        b"ACTION=add\0"
        b"DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-2\0"
        b"SUBSYSTEM=usb\0"
        b"MAJOR=189\0MINOR=5\0"
        b"DEVNAME=bus/usb/001/006\0"
        b"DEVTYPE=usb_device\0"
        b"PRODUCT=1209/1/100\0"
        b"TYPE=0/0/0\0BUSNUM=001\0DEVNUM=006\0"
        b"SEQNUM=4711\0"
    )
    assert parse_uevent(data) == {
        "ACTION": "add",
        "DEVPATH": "/devices/pci0000:00/0000:00:14.0/usb1/1-2",
        "SUBSYSTEM": "usb",
        "MAJOR": "189",
        "MINOR": "5",
        "DEVNAME": "bus/usb/001/006",
        "DEVTYPE": "usb_device",
        "PRODUCT": "1209/1/100",
        "TYPE": "0/0/0",
        "BUSNUM": "001",
        "DEVNUM": "006",
        "SEQNUM": "4711",
    }


@pytest.mark.parametrize(
    "action", ["add", "remove", "change", "move", "online", "offline", "bind", "unbind"]
)
def test_every_kernel_action_is_accepted(action: str) -> None:
    parsed = parse_uevent(uevent_message(action, USB_PATH))
    assert parsed is not None and parsed["ACTION"] == action


def test_values_may_contain_equals_signs_and_be_empty() -> None:
    parsed = parse_uevent(uevent_message("change", USB_PATH, MODALIAS="usb:v=1209", ID_X=""))
    assert parsed is not None
    assert parsed["MODALIAS"] == "usb:v=1209"
    assert parsed["ID_X"] == ""


def test_a_missing_final_terminator_is_tolerated() -> None:
    data = uevent_message("add", USB_PATH, DEVTYPE="usb_device")
    assert data.endswith(b"\0")
    assert parse_uevent(data[:-1]) == parse_uevent(data)


def test_device_supplied_bytes_in_a_value_cannot_make_parsing_raise() -> None:
    data = uevent_message("add", USB_PATH) + b"NAME=Fla\xff\xfesh\0"
    parsed = parse_uevent(data)
    assert parsed is not None
    assert parsed["NAME"] == "Fla\N{REPLACEMENT CHARACTER}\N{REPLACEMENT CHARACTER}sh"


def test_messages_in_libudev_format_are_ignored() -> None:
    # What udev re-broadcasts after running its rules: a binary header, then the pairs.
    libudev = (
        b"libudev\0\xfe\xed\xca\xfe" + b"\x28\x00\x00\x00" * 6 + b"ACTION=add\0DEVPATH=/devices/x\0"
    )
    assert parse_uevent(libudev) is None


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\0",
        b"add@/devices/x",  # no terminator after the header
        b"add/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0",  # no @
        b"explode@/devices/x\0ACTION=explode\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0",
        b"ADD@/devices/x\0ACTION=ADD\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0",
        b"add@devices/x\0ACTION=add\0DEVPATH=devices/x\0SUBSYSTEM=usb\0",  # relative path
        b"add@\0ACTION=add\0DEVPATH=\0SUBSYSTEM=usb\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0garbage\0",  # no =
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0=value\0",  # no key
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0BAD KEY=1\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0K\xc3\xa9Y=1\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0\0X=1\0",  # empty pair
        # The header and the pairs must tell the same story.
        b"add@/devices/x\0ACTION=remove\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/y\0SUBSYSTEM=usb\0",
        b"add@/devices/x\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0",  # no ACTION
        b"add@/devices/x\0ACTION=add\0SUBSYSTEM=usb\0",  # no DEVPATH
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0",  # no SUBSYSTEM
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=\0",
        # A repeated key would let two readers disagree about which value counts.
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0SUBSYSTEM=block\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0SEQNUM=12a\0",
        b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SUBSYSTEM=usb\0SEQNUM=-1\0",
        b"add@/devices/\xff\0ACTION=add\0DEVPATH=/devices/\xff\0SUBSYSTEM=usb\0",
        b"\xff\xfe\xfd\xfc" * 64,
    ],
)
def test_malformed_messages_are_rejected(data: bytes) -> None:
    assert parse_uevent(data) is None


def test_oversized_messages_are_rejected() -> None:
    padding = "x" * 9000
    assert parse_uevent(uevent_message("add", USB_PATH, PADDING=padding)) is None
    assert parse_uevent(uevent_message("add", USB_PATH, PADDING="x" * 100)) is not None


def test_input_that_is_not_bytes_is_rejected() -> None:
    assert parse_uevent("add@/devices/x\0ACTION=add\0") is None  # type: ignore[arg-type]
    assert parse_uevent(None) is None  # type: ignore[arg-type]
    as_bytearray = bytearray(uevent_message("add", USB_PATH))
    assert parse_uevent(as_bytearray) is not None  # type: ignore[arg-type]


# --- classify_uevent ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "kind"),
    [
        ({"SUBSYSTEM": "usb", "DEVTYPE": "usb_device", "DEVPATH": USB_PATH}, UeventKind.USB_DEVICE),
        (
            {"SUBSYSTEM": "usb", "DEVTYPE": "usb_interface", "DEVPATH": USB_PATH + "/1-2:1.0"},
            UeventKind.USB_INTERFACE,
        ),
        ({"SUBSYSTEM": "block", "DEVTYPE": "disk", "DEVPATH": BLOCK_PATH}, UeventKind.BLOCK),
        (
            {"SUBSYSTEM": "block", "DEVTYPE": "partition", "DEVPATH": BLOCK_PATH + "/sdb1"},
            UeventKind.BLOCK,
        ),
        (
            {
                "SUBSYSTEM": "block",
                "DEVPATH": "/devices/platform/vhci_hcd.0/usb12/12-1/x/block/sdc",
            },
            UeventKind.BLOCK,
        ),
        # Block devices that are not behind a USB host controller are someone else's.
        (
            {"SUBSYSTEM": "block", "DEVTYPE": "disk", "DEVPATH": "/devices/virtual/block/loop0"},
            None,
        ),
        (
            {"SUBSYSTEM": "block", "DEVPATH": "/devices/pci0000:00/0000:00:17.0/ata1/block/sda"},
            None,
        ),
        ({"SUBSYSTEM": "block"}, None),
        ({"SUBSYSTEM": "usb", "DEVPATH": USB_PATH}, None),  # no DEVTYPE: e.g. a usbmisc node
        ({"SUBSYSTEM": "usb", "DEVTYPE": "usb_port", "DEVPATH": USB_PATH}, None),
        ({"SUBSYSTEM": "net", "DEVPATH": USB_PATH + "/net/usb0"}, None),
        ({"SUBSYSTEM": "input", "DEVPATH": USB_PATH}, None),
        ({}, None),
    ],
)
def test_only_usb_and_usb_backed_block_events_matter(
    fields: dict[str, str], kind: UeventKind | None
) -> None:
    assert classify_uevent(fields) is kind


# --- UeventMonitor against a scripted transport ------------------------------------------


class Recorder:
    """Collects what a monitor reports, for assertions after ``transport.settle()``."""

    def __init__(self) -> None:
        self.events: list[tuple[UeventKind, Mapping[str, str]]] = []
        self.overruns = 0
        self.failures: queue.Queue[OSError] = queue.Queue()

    def on_event(self, kind: UeventKind, fields: Mapping[str, str]) -> None:
        self.events.append((kind, fields))

    def on_overrun(self) -> None:
        self.overruns += 1


@pytest.fixture
def transport() -> QueueTransport:
    return QueueTransport()


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def monitor(transport: QueueTransport, recorder: Recorder) -> Iterator[UeventMonitor]:
    running = UeventMonitor(
        recorder.on_event,
        recorder.on_overrun,
        on_failure=recorder.failures.put,
        transport_factory=lambda: transport,
    )
    running.start()
    try:
        yield running
    finally:
        running.stop()


def test_usb_and_block_events_from_the_kernel_are_delivered(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    transport.push(usb_add())
    transport.push(
        uevent_message("add", USB_PATH + "/1-2:1.0", DEVTYPE="usb_interface", INTERFACE="8/6/80")
    )
    transport.push(uevent_message("add", BLOCK_PATH, "block", DEVTYPE="disk", DEVNAME="sdb"))
    transport.push(uevent_message("remove", USB_PATH, DEVTYPE="usb_device"))
    transport.settle()
    assert [kind for kind, _fields in recorder.events] == [
        UeventKind.USB_DEVICE,
        UeventKind.USB_INTERFACE,
        UeventKind.BLOCK,
        UeventKind.USB_DEVICE,
    ]
    assert recorder.events[0][1]["DEVPATH"] == USB_PATH
    assert recorder.events[2][1]["DEVNAME"] == "sdb"
    assert recorder.events[3][1]["ACTION"] == "remove"
    assert monitor.stats == MonitorStats(received=4, accepted=4)


def test_events_about_other_subsystems_are_counted_and_dropped(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    transport.push(uevent_message("add", "/devices/virtual/net/veth0", "net"))
    transport.push(uevent_message("change", "/devices/virtual/block/loop0", "block"))
    transport.push(usb_add())
    transport.settle()
    assert len(recorder.events) == 1
    assert monitor.stats == MonitorStats(received=3, accepted=1, ignored=2)


@pytest.mark.parametrize(
    ("sender_pid", "sender_groups"),
    [
        (4242, KERNEL_GROUP),  # a process broadcasting on the kernel's group
        (4242, 0),  # a process sending straight to our port
        (4242, 2),  # udev's own re-broadcast group
        (0, 0),  # from the kernel, but not a uevent broadcast
        (0, 2),
        (0xFFFFFFFF, KERNEL_GROUP),
    ],
)
def test_a_message_not_broadcast_by_the_kernel_is_never_believed(
    monitor: UeventMonitor,
    transport: QueueTransport,
    recorder: Recorder,
    sender_pid: int,
    sender_groups: int,
) -> None:
    """The forged message is byte-for-byte what the kernel would send for a real arrival."""
    transport.push(usb_add(), sender_pid=sender_pid, sender_groups=sender_groups)
    transport.settle()
    assert recorder.events == []
    assert recorder.overruns == 0
    assert monitor.stats == MonitorStats(received=1, foreign=1)

    # The same bytes from the kernel are accepted, so only the sender made the difference.
    transport.push(usb_add())
    transport.settle()
    assert len(recorder.events) == 1
    assert monitor.stats == MonitorStats(received=2, accepted=1, foreign=1)


def test_a_flood_of_forged_messages_does_not_stop_real_ones(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    for _ in range(2500):
        transport.push(usb_add(), sender_pid=31337)
    transport.push(usb_add())
    transport.settle()
    assert len(recorder.events) == 1
    assert monitor.stats == MonitorStats(received=2501, accepted=1, foreign=2500)


def test_malformed_and_libudev_messages_from_the_kernel_address_are_dropped(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    transport.push(b"libudev\0\xfe\xed\xca\xfe" + b"\0" * 32)
    transport.push(b"not a uevent at all")
    transport.push(b"")
    transport.settle()
    assert recorder.events == []
    assert monitor.stats == MonitorStats(received=3, malformed=3)


def test_enobufs_asks_for_a_full_re_enumeration_and_monitoring_continues(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    transport.push(usb_add())
    transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
    transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
    transport.push(usb_add(USB_PATH.replace("1-2", "1-3")))
    transport.settle()
    assert recorder.overruns == 2
    assert [fields["DEVPATH"][-3:] for _kind, fields in recorder.events] == ["1-2", "1-3"]
    assert monitor.stats == MonitorStats(received=2, accepted=2, overruns=2)
    assert monitor.running
    assert recorder.failures.empty()


def test_a_truncated_message_counts_as_a_lost_event(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    transport.push(usb_add()[:40], truncated=True)
    transport.settle()
    assert recorder.events == []
    assert recorder.overruns == 1
    assert monitor.stats == MonitorStats(received=1, overruns=1)


def test_a_truncated_message_from_a_stranger_is_just_dropped(
    monitor: UeventMonitor, transport: QueueTransport, recorder: Recorder
) -> None:
    # Otherwise any local process could make the agent re-enumerate at will.
    transport.push(usb_add()[:40], sender_pid=77, truncated=True)
    transport.settle()
    assert recorder.overruns == 0
    assert monitor.stats == MonitorStats(received=1, foreign=1)


def test_a_dead_socket_is_reported_once_and_ends_the_thread(
    transport: QueueTransport, recorder: Recorder
) -> None:
    monitor = UeventMonitor(
        recorder.on_event,
        recorder.on_overrun,
        on_failure=recorder.failures.put,
        transport_factory=lambda: transport,
    )
    monitor.start()
    transport.push(usb_add())
    transport.push_error(OSError(errno.EBADF, "Bad file descriptor"))
    failure = recorder.failures.get(timeout=5)
    assert failure.errno == errno.EBADF
    assert len(recorder.events) == 1
    assert recorder.overruns == 0
    monitor.stop()
    assert not monitor.running
    assert transport.closed
    assert recorder.failures.empty()


def test_a_failing_callback_does_not_end_monitoring(transport: QueueTransport) -> None:
    seen: list[str] = []

    def explode_once(_kind: UeventKind, fields: Mapping[str, str]) -> None:
        seen.append(fields["DEVPATH"])
        if len(seen) == 1:
            raise RuntimeError("the pipeline fell over")

    def explode() -> None:
        seen.append("overrun")
        raise RuntimeError("so did this")

    monitor = UeventMonitor(explode_once, explode, transport_factory=lambda: transport)
    monitor.start()
    try:
        transport.push(usb_add("/devices/usb1/1-1"))
        transport.push_error(OSError(errno.ENOBUFS, "No buffer space available"))
        transport.push(usb_add("/devices/usb1/1-2"))
        transport.settle()
        assert seen == ["/devices/usb1/1-1", "overrun", "/devices/usb1/1-2"]
        assert monitor.running
    finally:
        monitor.stop()


def test_stop_ends_the_thread_and_closes_the_socket(
    transport: QueueTransport, recorder: Recorder
) -> None:
    monitor = UeventMonitor(
        recorder.on_event, recorder.on_overrun, transport_factory=lambda: transport
    )
    monitor.stop()  # not started: nothing to do
    assert not transport.interrupted and not transport.closed
    monitor.start()
    assert monitor.running
    monitor.stop()
    assert not monitor.running
    assert transport.interrupted and transport.closed
    assert not any(thread.name == "portlock-uevent" for thread in threading.enumerate())
    monitor.stop()  # and again


def test_a_monitor_can_be_stopped_from_its_own_callback(transport: QueueTransport) -> None:
    stopped = threading.Event()
    monitor: UeventMonitor

    def stop_now(_kind: UeventKind, _fields: Mapping[str, str]) -> None:
        monitor.stop()
        stopped.set()

    monitor = UeventMonitor(stop_now, lambda: None, transport_factory=lambda: transport)
    monitor.start()
    transport.push(usb_add())
    assert stopped.wait(5)
    assert transport.closed


def test_starting_twice_is_an_error(monitor: UeventMonitor) -> None:
    with pytest.raises(BackendError, match="already running"):
        monitor.start()
    assert monitor.running


def test_a_monitor_can_be_restarted(recorder: Recorder) -> None:
    transports = [QueueTransport(), QueueTransport()]
    remaining = iter(transports)
    monitor = UeventMonitor(
        recorder.on_event, recorder.on_overrun, transport_factory=lambda: next(remaining)
    )
    monitor.start()
    monitor.stop()
    monitor.start()
    try:
        transports[1].push(usb_add())
        transports[1].settle()
        assert len(recorder.events) == 1
        assert transports[0].closed and not transports[1].closed
    finally:
        monitor.stop()


def test_a_socket_that_cannot_be_opened_is_a_backend_error(recorder: Recorder) -> None:
    def refuse() -> QueueTransport:
        raise BackendError("cannot open the kernel uevent socket: Operation not permitted")

    monitor = UeventMonitor(recorder.on_event, recorder.on_overrun, transport_factory=refuse)
    with pytest.raises(BackendError, match="Operation not permitted"):
        monitor.start()
    assert not monitor.running
    monitor.stop()


@pytest.mark.windows_only
def test_without_netlink_the_socket_reports_its_absence() -> None:
    with pytest.raises(BackendError, match="not available on this platform"):
        open_kernel_uevent_socket()


def test_the_protocol_constants_match_the_kernel_headers() -> None:
    # linux/netlink.h: #define NETLINK_KOBJECT_UEVENT 15; the kernel broadcasts on group 1.
    assert NETLINK_KOBJECT_UEVENT == 15
    assert KERNEL_GROUP == 1


# --- real netlink sockets (user-to-user protocol; nothing here reaches a device) ---------


@pytest.fixture
def usersock() -> Iterator[tuple[KernelUeventSocket, socket.socket]]:
    """A real netlink receiver and a second, unrelated user-space socket to send from."""
    try:
        receiver = KernelUeventSocket(protocol=socket.NETLINK_USERSOCK, groups=0)
    except BackendError as exc:
        pytest.skip(f"netlink sockets cannot be opened here: {exc}")
    sender = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_USERSOCK)
    try:
        sender.bind((0, 0))
        yield receiver, sender
    finally:
        sender.close()
        receiver.close()


@pytest.mark.linux_only
def test_the_kernel_reports_a_user_space_sender_as_such(
    usersock: tuple[KernelUeventSocket, socket.socket],
) -> None:
    receiver, sender = usersock
    forged = usb_add()
    sender.sendto(forged, (receiver.port_id, 0))
    datagram = receiver.receive()
    assert datagram is not None
    assert datagram.data == forged
    assert datagram.sender_pid == sender.getsockname()[0]
    assert datagram.sender_pid != 0
    assert datagram.truncated is False


@pytest.mark.linux_only
def test_a_forged_uevent_from_a_real_local_process_is_rejected(
    usersock: tuple[KernelUeventSocket, socket.socket], recorder: Recorder
) -> None:
    receiver, sender = usersock
    handled = threading.Semaphore(0)

    class Announcing:
        """Signals each time the monitor comes back for the next message."""

        def receive(self) -> Datagram | None:
            handled.release()
            return receiver.receive()

        def interrupt(self) -> None:
            receiver.interrupt()

        def close(self) -> None:
            receiver.close()

    monitor = UeventMonitor(recorder.on_event, recorder.on_overrun, transport_factory=Announcing)
    monitor.start()
    try:
        assert handled.acquire(timeout=5)  # the monitor is waiting for its first message
        sender.sendto(usb_add(), (receiver.port_id, 0))
        assert handled.acquire(timeout=5)  # ... and has finished with the forged one
        assert recorder.events == []
        assert recorder.overruns == 0
        assert monitor.stats == MonitorStats(received=1, foreign=1)
    finally:
        monitor.stop()
    assert not monitor.running


@pytest.mark.linux_only
def test_a_message_larger_than_the_buffer_is_flagged_as_truncated(
    usersock: tuple[KernelUeventSocket, socket.socket],
) -> None:
    receiver, sender = usersock
    sender.sendto(b"x" * 20000, (receiver.port_id, 0))
    datagram = receiver.receive()
    assert datagram is not None
    assert datagram.truncated is True
    assert 0 < len(datagram.data) < 20000


@pytest.mark.linux_only
def test_interrupt_wakes_a_blocked_receive(
    usersock: tuple[KernelUeventSocket, socket.socket],
) -> None:
    receiver, _sender = usersock
    result: queue.Queue[Datagram | None] = queue.Queue()
    thread = threading.Thread(target=lambda: result.put(receiver.receive()))
    thread.start()
    receiver.interrupt()
    assert result.get(timeout=5) is None
    thread.join(5)
    assert not thread.is_alive()


# --- diff_devices ------------------------------------------------------------------------


def snapshot(*devices: UsbDevice) -> dict[str, UsbDevice]:
    return {device.instance_id: device for device in devices}


def test_identical_snapshots_have_no_differences() -> None:
    devices = snapshot(flash_drive(), keyboard())
    assert diff_devices(devices, dict(devices)) == []
    assert diff_devices({}, {}) == []


def test_arrivals_removals_and_changes_are_told_apart() -> None:
    stays, leaves, arrives = keyboard(), hub(), flash_drive(instance_id="test/1-9", bus_path="1-9")
    plain = flash_drive()
    mounted = mounted_flash_drive()
    changes = diff_devices(snapshot(stays, leaves, plain), snapshot(stays, arrives, mounted))
    assert changes == [
        DeviceChange(DeviceEventType.REMOVED, leaves),
        DeviceChange(DeviceEventType.ARRIVED, arrives),
        DeviceChange(DeviceEventType.CHANGED, mounted),
    ]
    assert changes[2].device.volumes[0].mount_point == "/media/test"


def test_a_port_reused_between_snapshots_is_a_removal_and_an_arrival() -> None:
    old = flash_drive(serial="TEST0001A7C3")
    for new in (
        flash_drive(serial="TEST9999ZZZZ"),
        flash_drive(serial=None),
        make_device(product_id=0x0BAD),
        make_device(vendor_id=0x1234),
        make_device(bcd_device=0x0200),
    ):
        assert new.instance_id == old.instance_id
        assert diff_devices(snapshot(old), snapshot(new)) == [
            DeviceChange(DeviceEventType.REMOVED, old),
            DeviceChange(DeviceEventType.ARRIVED, new),
        ]


def test_the_same_looking_device_with_a_new_devnum_is_a_new_connection() -> None:
    # Two units of a serial-less model swapped on one port: only the address differs.
    old = flash_drive(serial=None, backend_data={"devnum": "5"})
    new = flash_drive(serial=None, backend_data={"devnum": "6"})
    assert old == new
    changes = diff_devices(snapshot(old), snapshot(new))
    assert [change.type for change in changes] == [
        DeviceEventType.REMOVED,
        DeviceEventType.ARRIVED,
    ]
    assert changes[0].device.backend_data["devnum"] == "5"
    assert changes[1].device.backend_data["devnum"] == "6"


def test_the_connection_id_decides_when_both_sides_have_one() -> None:
    # The same devnum after a reboot: only the boot id in the connection id differs.
    old = flash_drive(connection_id="boot-a:1:5", backend_data={"devnum": "5"})
    new = flash_drive(connection_id="boot-b:1:5", backend_data={"devnum": "5"})
    assert [change.type for change in diff_devices(snapshot(old), snapshot(new))] == [
        DeviceEventType.REMOVED,
        DeviceEventType.ARRIVED,
    ]
    same = flash_drive(connection_id="boot-a:1:5", backend_data={"devnum": "5"})
    assert diff_devices(snapshot(old), snapshot(same)) == []


def test_without_connection_ids_the_device_number_decides() -> None:
    old = flash_drive(connection_id="boot-a:1:5", backend_data={"devnum": "5"})
    new = flash_drive(connection_id=None, backend_data={"devnum": "6"})
    assert [change.type for change in diff_devices(snapshot(old), snapshot(new))] == [
        DeviceEventType.REMOVED,
        DeviceEventType.ARRIVED,
    ]


def test_backend_details_alone_are_not_a_change() -> None:
    old = flash_drive(backend_data={"devnum": "5", "authorized": "1"})
    new = flash_drive(backend_data={"devnum": "5", "authorized": "0"})
    assert diff_devices(snapshot(old), snapshot(new)) == []


def test_hubs_arrive_before_and_leave_after_their_children() -> None:
    root = hub(instance_id="t/usb1", bus_path="usb1")
    outer = hub(instance_id="t/usb1/1-4", bus_path="1-4")
    inner = hub(instance_id="t/usb1/1-4/1-4.3", bus_path="1-4.3")
    leaf = flash_drive(instance_id="t/usb1/1-4/1-4.3/1-4.3.1", bus_path="1-4.3.1")
    everything = snapshot(leaf, inner, root, outer)  # deliberately out of order
    arriving = [change.device.bus_path for change in diff_devices({}, everything)]
    leaving = [change.device.bus_path for change in diff_devices(everything, {})]
    assert arriving == ["usb1", "1-4", "1-4.3", "1-4.3.1"]
    assert leaving == ["1-4.3.1", "1-4.3", "1-4", "usb1"]


# --- PollingMonitor ----------------------------------------------------------------------


class Present:
    """A mutable set of devices standing in for sysfs."""

    def __init__(self, *devices: UsbDevice) -> None:
        self.devices = list(devices)
        self.error: BackendError | None = None
        self.failures_left = 0
        self.reads = 0

    def __call__(self) -> list[UsbDevice]:
        self.reads += 1
        if self.error is not None:
            raise self.error
        if self.failures_left > 0:
            self.failures_left -= 1
            raise BackendError("sysfs briefly unreadable")
        return list(self.devices)


def discard(_changes: list[DeviceChange]) -> None:
    raise AssertionError("no change was expected")


def test_polling_reports_only_what_changed_since_the_last_poll() -> None:
    present = Present(keyboard())
    poller = PollingMonitor(present, discard)
    poller.prime()
    assert poller.poll_once() == []

    stick = flash_drive()
    present.devices.append(stick)
    assert poller.poll_once() == [DeviceChange(DeviceEventType.ARRIVED, stick)]
    assert poller.poll_once() == []

    present.devices[-1] = mounted = mounted_flash_drive()
    assert poller.poll_once() == [DeviceChange(DeviceEventType.CHANGED, mounted)]

    present.devices.clear()
    removed = poller.poll_once()
    assert {change.type for change in removed} == {DeviceEventType.REMOVED}
    assert {change.device.bus_path for change in removed} == {"1-1", "1-2"}
    assert present.reads == 6


def test_the_first_poll_without_priming_only_records_the_baseline() -> None:
    present = Present(keyboard(), flash_drive())
    poller = PollingMonitor(present, discard)
    assert poller.poll_once() == []
    present.devices.pop()
    assert [change.type for change in poller.poll_once()] == [DeviceEventType.REMOVED]


def test_a_failed_poll_loses_nothing() -> None:
    present = Present(keyboard())
    poller = PollingMonitor(present, discard)
    poller.prime()
    stick = flash_drive()
    present.devices.append(stick)
    present.error = BackendError("sysfs went away")
    with pytest.raises(BackendError, match="sysfs went away"):
        poller.poll_once()
    present.error = None
    assert poller.poll_once() == [DeviceChange(DeviceEventType.ARRIVED, stick)]


def test_priming_fails_loudly_when_sysfs_cannot_be_read() -> None:
    present = Present()
    present.error = BackendError("sysfs is not available at /sys")
    poller = PollingMonitor(present, discard)
    with pytest.raises(BackendError):
        poller.prime()
    with pytest.raises(BackendError):
        poller.start()
    poller.stop()


@pytest.mark.parametrize("interval", [0, -1, float("nan")])
def test_the_polling_interval_must_be_positive(interval: float) -> None:
    with pytest.raises(ValueError):
        PollingMonitor(Present(), discard, interval=interval)


def run_poller(
    present: Present, on_changes: Callable[[list[DeviceChange]], None]
) -> PollingMonitor:
    poller = PollingMonitor(present, on_changes, interval=0.005)
    poller.start()
    return poller


def test_the_polling_thread_delivers_changes_and_stops_cleanly() -> None:
    present = Present(keyboard())
    delivered: queue.Queue[list[DeviceChange]] = queue.Queue()
    poller = run_poller(present, delivered.put)
    try:
        with pytest.raises(BackendError, match="already running"):
            poller.start()
        stick = flash_drive()
        present.devices.append(stick)
        assert delivered.get(timeout=5) == [DeviceChange(DeviceEventType.ARRIVED, stick)]
        present.devices.remove(stick)
        assert delivered.get(timeout=5) == [DeviceChange(DeviceEventType.REMOVED, stick)]
    finally:
        poller.stop()
    assert not any(thread.name == "portlock-poll" for thread in threading.enumerate())
    reads = present.reads
    poller.stop()
    assert present.reads == reads  # nothing is polling any more


def test_the_polling_thread_survives_an_unexpected_error() -> None:
    present = Present()
    bugs = [TypeError("a bug in one read")]

    def buggy() -> list[UsbDevice]:
        if bugs and present.reads >= 1:
            raise bugs.pop()
        return present()

    delivered: queue.Queue[list[DeviceChange]] = queue.Queue()
    poller = PollingMonitor(buggy, delivered.put, interval=0.005)
    poller.start()
    try:
        stick = flash_drive()
        present.devices.append(stick)
        assert delivered.get(timeout=5) == [DeviceChange(DeviceEventType.ARRIVED, stick)]
        assert bugs == []
    finally:
        poller.stop()


def test_the_polling_thread_survives_errors_and_a_failing_callback() -> None:
    present = Present()
    delivered: queue.Queue[list[DeviceChange]] = queue.Queue()
    calls: list[int] = []

    def fail_first(changes: list[DeviceChange]) -> None:
        calls.append(len(changes))
        delivered.put(changes)
        if len(calls) == 1:
            raise RuntimeError("the pipeline fell over")

    poller = run_poller(present, fail_first)
    try:
        first, second = keyboard(), flash_drive()
        present.devices.append(first)
        assert delivered.get(timeout=5) == [DeviceChange(DeviceEventType.ARRIVED, first)]
        # The next three polls fail; the change must still come out once reading works.
        present.failures_left = 3
        present.devices.append(second)
        assert delivered.get(timeout=5) == [DeviceChange(DeviceEventType.ARRIVED, second)]
        assert present.failures_left == 0
    finally:
        poller.stop()
