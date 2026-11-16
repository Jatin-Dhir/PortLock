"""``portlock simulate``: the whole product on a fake machine.

A :class:`Simulation` is the complete service (the real decision pipeline, audit log,
accounts, lockdown and HTTP API) on a simulated machine: a
:class:`~portlock.guard.fake.FakeBackend` that reports the devices an operator "plugs in",
and a :class:`~portlock.guard.fake.FakeEnforcer` that remembers what it was told to do
and touches nothing. It lets anyone explore PortLock on any machine without a device, an
administrator account or a risk.

**It cannot reach the real machine.** There is no parameter that selects an enforcer, a
backend, a timer or a directory-privacy check: this module constructs the fakes itself and
hands every one of them to ``build_runtime`` explicitly, so the platform factories are
never consulted. State lives in a fresh temporary directory (never the real state or
configuration directory), the scanner is a stand-in that reads no file, and the status
reports ``simulation: true``. A test replaces every platform factory with a function that
fails and runs the whole simulation to prove it.

Devices are synthetic. Their names say so and their serial numbers start with ``TEST``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import secrets
import shutil
import sys
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import IO, Any

from portlock import __version__
from portlock.audit.log import AuditRecord
from portlock.console import escape_control
from portlock.console.api import ApiServer
from portlock.core.clock import Clock, FakeClock, SystemClock, utc_iso
from portlock.core.config import ApiConfig, Config, LockdownConfig, PathsConfig, ScanConfig
from portlock.core.errors import PortLockError
from portlock.core.fsutil import atomic_write_bytes
from portlock.core.models import Mode, UsbDevice, UsbInterface, Volume
from portlock.core.service import ConnectionView
from portlock.guard.base import EnforcerCapabilities, JournalEntry
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.lockdown.manager import Credential
from portlock.scan.report import Finding, FindingSeverity, ScanReport
from portlock.service.daemon import RUNTIME_FILE_NAME, Runtime, build_runtime

__all__ = [
    "BANNER",
    "DEVICES",
    "SCENARIOS",
    "Simulation",
    "SimulationError",
    "run_simulation",
    "tour",
]

#: What every simulated output starts with, so nobody mistakes it for a real machine.
BANNER = "SIMULATION: nothing real is read, blocked, ejected or changed on this machine."

_ADMIN = "admin"
_CHANNEL = "simulation"
_ACTOR = "simulation"
_PUMP_SECONDS = 0.25

_MASS_STORAGE = UsbInterface(0x08, 0x06, 0x50)
_KEYBOARD = UsbInterface(0x03, 0x01, 0x01)
_MOUSE = UsbInterface(0x03, 0x01, 0x02)
_HUB = UsbInterface(0x09, 0x00, 0x00)
_MTP = UsbInterface(0x06, 0x01, 0x01)
_CAMERA = (UsbInterface(0x0E, 0x01, 0x00), UsbInterface(0x0E, 0x02, 0x00))


class SimulationError(PortLockError):
    """A simulated action cannot be carried out (an unknown device name, and so on)."""

    code = "simulation_error"


def _device(
    name: str,
    number: int,
    product: str,
    interfaces: Sequence[UsbInterface],
    *,
    serial: str | None,
    mounted: bool = False,
    removable: bool = True,
    device_class: int = 0,
) -> Callable[[], UsbDevice]:
    def build() -> UsbDevice:
        volumes: tuple[Volume, ...] = ()
        if mounted:
            volumes = (
                Volume(
                    device_node=f"simulated-disk-{number}",
                    mount_point=f"/simulated/{name}",
                    label="SIMULATED",
                    fs_type="vfat",
                    fs_uuid=f"TEST-{number:04d}",
                    size_bytes=16_000_000_000,
                    read_only=False,
                ),
            )
        return UsbDevice(
            instance_id=f"simulated/1-{number}",
            vendor_id=0x1209,
            product_id=number,
            serial=serial,
            manufacturer="Simulated Corp",
            product=product,
            bcd_device=0x0100,
            device_class=device_class,
            interfaces=tuple(interfaces),
            bus_path=f"1-{number}",
            removable=removable,
            volumes=volumes,
        )

    return build


#: The devices ``plug NAME`` can plug in. All are synthetic.
DEVICES: Mapping[str, Callable[[], UsbDevice]] = {
    "keyboard": _device("keyboard", 1, "Simulated Keyboard", [_KEYBOARD], serial=None),
    "mouse": _device("mouse", 2, "Simulated Mouse", [_MOUSE], serial=None),
    "hub": _device("hub", 3, "Simulated Hub", [_HUB], serial=None, device_class=0x09),
    "trusted-stick": _device(
        "trusted-stick",
        4,
        "Simulated Flash Drive 16GB",
        [_MASS_STORAGE],
        serial="TESTSIM0004",
        mounted=True,
    ),
    "unknown-stick": _device(
        "unknown-stick",
        5,
        "Simulated Flash Drive 32GB",
        [_MASS_STORAGE],
        serial="TESTSIM0005",
        mounted=True,
    ),
    "second-stick": _device(
        "second-stick",
        6,
        "Simulated Flash Drive 64GB",
        [_MASS_STORAGE],
        serial="TESTSIM0006",
        mounted=True,
    ),
    "blank-stick": _device(
        "blank-stick",
        7,
        "Simulated Flash Drive (no serial)",
        [_MASS_STORAGE],
        serial=None,
        mounted=True,
    ),
    "badusb": _device(
        "badusb",
        8,
        "Simulated Flash Drive with hidden keyboard",
        [_MASS_STORAGE, _KEYBOARD],
        serial="TESTSIM0008",
        mounted=True,
    ),
    "phone": _device("phone", 9, "Simulated Phone (MTP)", [_MTP], serial="TESTSIM0009"),
    "webcam": _device(
        "webcam",
        10,
        "Simulated Built-in Camera",
        _CAMERA,
        serial=None,
        removable=False,
        device_class=0xEF,
    ),
}


class _SimScanner:
    """A scanner that reads nothing: it answers from the volume's name.

    Real scanners walk the mount point they are given. Simulated volumes have made-up
    mount points, so this stand-in never touches a file system: a volume named after a
    suspicious device reports one finding, every other volume is clean.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def scan(self, root: str, *, cancel: Any = None, progress: Any = None) -> ScanReport:
        now = self._clock.now()
        findings: tuple[Finding, ...] = ()
        if "badusb" in root or "suspicious" in root:
            findings = (
                Finding(
                    "autorun.inf",
                    "heuristics",
                    "autorun-inf",
                    FindingSeverity.SUSPICIOUS,
                    "simulated finding: open=setup.exe",
                ),
            )
        return ScanReport(
            root=root,
            started_at=now,
            finished_at=now,
            files_seen=12,
            files_hashed=12,
            bytes_hashed=4096,
            findings=findings,
        )


class Simulation:
    """The complete service on a simulated machine, driven step by step.

    Args:
        home: the directory the simulation keeps its state in (a fresh temporary
            directory if omitted; it is removed by :meth:`close`).
        clock: time. A :class:`~portlock.core.clock.FakeClock` makes :meth:`advance`
            available and every step deterministic; the system clock is for serving.
        enforce: run in enforce mode (the default) or in monitor mode.
        port: the API port when serving (0: the system picks a free one).

    The service is started without its own threads: :meth:`pump` does the work they would
    do, and is called after every step (and, when serving, every quarter of a second).
    """

    def __init__(
        self,
        *,
        home: Path | None = None,
        clock: Clock | None = None,
        enforce: bool = True,
        port: int = 0,
    ) -> None:
        self._own_home = home is None
        self.home = (
            Path(home) if home is not None else Path(tempfile.mkdtemp(prefix="portlock-sim-"))
        )
        self.clock: Clock = clock if clock is not None else SystemClock()
        self.backend = FakeBackend(clock=self.clock, synchronous=True, name="simulated")
        self._hook: Callable[[JournalEntry], None] | None = None
        self.enforcer = FakeEnforcer(
            EnforcerCapabilities(
                name="simulated",
                privileged=True,
                block=True,
                read_only=True,
                eject=True,
                default_deny=True,
                notes=("simulated: no operating system setting is changed",),
            ),
            backend=self.backend,
            write_ahead=self._write_ahead,
        )
        self.config = Config(
            paths=PathsConfig.under(self.home),
            mode=Mode.ENFORCE if enforce else Mode.MONITOR,
            api=ApiConfig(host="127.0.0.1", port=port),
            scan=ScanConfig(enabled=True),
            lockdown=LockdownConfig(default_minutes=60, max_minutes=1440),
            host_label="simulation",
        )
        # Every seam is given explicitly, so no platform factory is ever consulted.
        self.runtime: Runtime = build_runtime(
            self.config,
            clock=self.clock,
            backend=self.backend,
            enforcer_factory=self._enforcer_factory,
            scanner=_SimScanner(self.clock),
            simulation=True,
            timer=FakeExternalTimer(),
            dir_privacy=FakeDirPrivacy(),
            system_ids=lambda devices: frozenset(),
            recover_argv=("portlock", "recover"),
        )
        if not isinstance(self.runtime.enforcer, FakeEnforcer) or not isinstance(
            self.runtime.backend, FakeBackend
        ):
            raise SimulationError("the simulation must run on the fake backend and enforcer")
        self._pump_lock = threading.Lock()
        self._pump_thread: threading.Thread | None = None
        self._pump_stop = threading.Event()
        self._out: list[str] = []
        self._last_seq = 0
        self._api: ApiServer | None = None
        self._password: str | None = None
        self._started = False
        self._closed = False

    # --- construction helpers --------------------------------------------------------

    def _write_ahead(self, entry: JournalEntry) -> None:
        if self._hook is None:
            raise RuntimeError("the journal is not wired")
        self._hook(entry)

    def _enforcer_factory(self, hook: Callable[[JournalEntry], None]) -> FakeEnforcer:
        self._hook = hook
        return self.enforcer

    # --- lifecycle -------------------------------------------------------------------

    @property
    def service(self) -> Any:
        """The :class:`~portlock.core.service.PortLockService`."""
        return self.runtime.service

    def start(self) -> None:
        """Start the service (no threads) and handle what the backend queued."""
        if self._started:
            return
        self._started = True
        self.service.start(threads=False)
        self.pump()

    def create_admin(self, username: str = _ADMIN) -> str:
        """Create the administrator of the simulation and return its random password."""
        password = secrets.token_urlsafe(18)
        self.runtime.accounts.create_user(username, password, "admin", actor=_ACTOR)
        self._password = password
        return password

    def pump(self) -> None:
        """Do the service's background work once: handle events, time, scans."""
        with self._pump_lock:
            service = self.service
            service.drain_events()
            service.tick()
            service.run_scans()
            service.drain_events()

    def serve(self) -> ApiServer:
        """Start the real API (and the console, if installed) on a loopback port.

        Also writes ``runtime.json`` into the simulation's state directory, so that
        ``portlock`` pointed at it with ``PORTLOCK_HOME`` finds and authenticates the
        service exactly as it would a real one, and starts the pump thread.

        Raises:
            OSError: if the port cannot be bound.
        """
        self.start()
        api = ApiServer(self.runtime)
        api.start()
        self._api = api
        data = {
            "v": 1,
            "pid": 0,
            "host": api.host,
            "port": api.port,
            "run_id": self.service.run_id,
            "started_at": utc_iso(self.clock.now()),
            "version": __version__,
            "secret": self.runtime.cli_secret,
        }
        atomic_write_bytes(
            Path(self.config.paths.state_dir) / RUNTIME_FILE_NAME,
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            private=True,
        )
        self._pump_stop.clear()
        self._pump_thread = threading.Thread(
            target=self._pump_loop, name="portlock-simulate-pump", daemon=True
        )
        self._pump_thread.start()
        return api

    def _pump_loop(self) -> None:
        while not self._pump_stop.wait(_PUMP_SECONDS):
            try:
                self.pump()
            except Exception as exc:
                self._out.append(f"pump failed: {type(exc).__name__}: {exc}")

    @property
    def url(self) -> str | None:
        """Where the API listens, once :meth:`serve` has run."""
        api = self._api
        return None if api is None else f"http://{api.host}:{api.port}"

    def close(self) -> None:
        """Stop everything and remove the temporary directory. Safe to call twice."""
        if self._closed:
            return
        self._closed = True
        self._pump_stop.set()
        if self._pump_thread is not None:
            self._pump_thread.join(5.0)
        if self._api is not None:
            self._api.stop()
        with contextlib.suppress(PortLockError):
            if self._started:
                self.service.stop()
        self.runtime.close()
        self.backend.stop()
        if self._own_home:
            shutil.rmtree(self.home, ignore_errors=True)

    def __enter__(self) -> Simulation:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- the simulated machine -------------------------------------------------------

    def plug(self, name: str) -> UsbDevice:
        """Plug in the synthetic device called ``name`` (see :data:`DEVICES`)."""
        build = DEVICES.get(name)
        if build is None:
            raise SimulationError(f"no such device {name!r}; try one of: {', '.join(DEVICES)}")
        device = build()
        if self.backend.is_present(device.instance_id):
            raise SimulationError(f"{name} is already plugged in")
        plugged = self.backend.plug(device)
        self.pump()
        return plugged

    def unplug(self, name: str) -> None:
        """Remove the synthetic device called ``name``."""
        build = DEVICES.get(name)
        if build is None:
            raise SimulationError(f"no such device {name!r}; try one of: {', '.join(DEVICES)}")
        instance_id = build().instance_id
        if not self.backend.is_present(instance_id):
            raise SimulationError(f"{name} is not plugged in")
        self.backend.unplug(instance_id)
        self.pump()

    def advance(self, seconds: int) -> None:
        """Move a fake clock forward and let the service notice."""
        if not isinstance(self.clock, FakeClock):
            raise SimulationError("only a simulation on a fake clock can be advanced")
        self.clock.advance(seconds)
        self.pump()

    def connection(self, name: str) -> ConnectionView:
        """The open connection of the plugged-in device called ``name``."""
        instance_id = DEVICES[name]().instance_id
        for view in self.service.list_connections(open_only=True):
            if view.device.instance_id == instance_id:
                return view
        raise SimulationError(f"{name} is not connected")

    # --- operator actions (what a person would click) --------------------------------

    def approve(self, name: str, *, kind: str = "once", read_only: bool = False) -> None:
        """Approve a pending device (``once``, ``temporary`` for 2 hours, or ``trust``)."""
        expires = self.clock.now() + timedelta(hours=2) if kind == "temporary" else None
        self.service.approve(
            self.connection(name).connection_id,
            kind=kind,
            read_only=read_only,
            expires_at=expires,
            note="simulated approval",
            role="admin",
            actor=_ADMIN,
        )
        self.pump()

    def deny(self, name: str) -> None:
        """Record the operator's refusal of a pending device."""
        self.service.deny(
            self.connection(name).connection_id, note="simulated refusal", actor=_ADMIN
        )
        self.pump()

    def engage_lockdown(self, minutes: int = 60, reason: str = "simulated intrusion") -> None:
        """Engage lockdown and confirm it over the same channel."""
        result = self.service.lockdown_engage(
            minutes=minutes, reason=reason, actor=_ADMIN, channel=_CHANNEL
        )
        self.service.lockdown_confirm(result.value.change.id, actor=_ADMIN, channel=_CHANNEL)
        self.pump()

    def lift_lockdown(self) -> None:
        """Lift the lockdown with the administrator's password (needs :meth:`create_admin`)."""
        if self._password is None:
            raise SimulationError("there is no administrator: call create_admin() first")
        self.service.lockdown_lift(actor=_ADMIN, credential=Credential("password", self._password))
        self.pump()

    # --- the timeline ----------------------------------------------------------------

    def note(self, text: str) -> None:
        """Add a narration line to the timeline, after what has happened so far."""
        self._collect()
        self._out.append(f"== {text}")

    def _collect(self) -> None:
        for record in self.runtime.audit_log.iterate(since_seq=self._last_seq + 1):
            self._last_seq = record.seq
            self._out.append(_describe(record))

    def timeline(self) -> list[str]:
        """One line per audit record (and narration) since the last call."""
        self._collect()
        lines, self._out = self._out, []
        return lines


def _describe(record: AuditRecord) -> str:
    """One line for an audit record: the time, the severity, the event and what it says."""
    data = record.data
    detail = ""
    if record.event_type == "device.connected":
        device = data.get("device") or {}
        detail = " ".join(
            str(part) for part in (device.get("manufacturer"), device.get("product")) if part
        )
    elif record.event_type == "decision.made":
        decision = data.get("decision") or {}
        detail = (
            f"{decision.get('access')} (source {decision.get('source')}, "
            f"trigger {data.get('trigger')})"
        )
        if decision.get("alert"):
            detail += " ALERT"
    elif record.event_type.startswith("enforcement."):
        detail = f"{data.get('action')} via {data.get('mechanism')}"
    elif record.event_type.startswith(("lockdown.", "grant.", "trust.")):
        detail = str(data.get("reason") or data.get("kind") or data.get("end_reason") or "")
    elif data:
        detail = ", ".join(
            f"{key}={value}"
            for key, value in list(data.items())[:3]
            if isinstance(value, str | int)
        )
    actor = f" by {record.actor}" if record.actor and record.actor != "system" else ""
    text = f"{record.ts[11:19]}  {record.severity.value:<7} {record.event_type:<22} {detail}{actor}"
    return escape_control(text.rstrip())[:200]


def tour(sim: Simulation) -> None:
    """The scripted scenario: a keyboard, two unknown sticks (one approved, one denied), a
    stick with a hidden keyboard, a trusted stick, and a lockdown that is engaged and
    confirmed. Every step narrates itself, so the timeline reads as a story."""
    sim.note("The operator's keyboard arrives. Input devices are protected: never blocked.")
    sim.plug("keyboard")
    sim.note("A stick nobody knows arrives. The default policy says 'pending', so it is blocked.")
    sim.plug("unknown-stick")
    sim.note("The operator approves it, read-only, for two hours.")
    sim.approve("unknown-stick", kind="temporary", read_only=True)
    sim.note("A stick with a hidden keyboard arrives. The default policy denies it and alerts.")
    sim.plug("badusb")
    sim.note("A second unknown stick arrives and waits for a decision.")
    sim.plug("second-stick")
    sim.note("The operator looks at it and denies it. It stays blocked.")
    sim.deny("second-stick")
    sim.note("A stick the operator knows. The first time it is approved and trusted.")
    sim.plug("trusted-stick")
    sim.approve("trusted-stick", kind="trust")
    sim.note("It is unplugged and plugged in again: PortLock remembers it.")
    sim.unplug("trusted-stick")
    sim.plug("trusted-stick")
    sim.note("Suspected intrusion: the operator engages a lockdown and confirms it within 60 s.")
    sim.engage_lockdown(60, "simulated intrusion")


#: The scenarios ``portlock simulate`` can run. ``tour`` is the default; ``none`` starts empty.
SCENARIOS: Mapping[str, Callable[[Simulation], None]] = {
    "tour": tour,
    "none": lambda sim: None,
}


def _usage(out: IO[str]) -> None:
    out.write("Commands: plug NAME | unplug NAME | list | devices | help | quit\n")
    out.write("Devices:  " + ", ".join(DEVICES) + "\n")


def _interact(sim: Simulation, stdin: IO[str], out: IO[str], stop: threading.Event) -> None:
    """Read ``plug NAME``, ``unplug NAME``, ``list`` and ``quit`` from ``stdin``."""
    for line in stdin:
        words = line.split()
        if not words:
            continue
        command = words[0].lower()
        try:
            if command in ("quit", "exit", "q"):
                stop.set()
                return
            if command == "plug" and len(words) == 2:
                sim.plug(words[1])
            elif command == "unplug" and len(words) == 2:
                sim.unplug(words[1])
            elif command in ("list", "devices"):
                for view in sim.service.list_connections(open_only=True):
                    out.write(f"  {escape_control(view.display_name)}: {view.state.value}\n")
            else:
                _usage(out)
        except PortLockError as exc:
            out.write(f"  {escape_control(exc.message)}\n")
        for entry in sim.timeline():
            out.write(entry + "\n")
        out.flush()


def run_simulation(
    args: argparse.Namespace,
    *,
    stdin: IO[str] | None = None,
    out: IO[str] | None = None,
) -> int:
    """``portlock simulate``. Returns the exit code.

    ``args`` carries ``scenario`` (a key of :data:`SCENARIOS`), ``port`` and ``serve``
    (False: print the scenario's timeline and exit). The simulation runs on the system
    clock in a fresh temporary directory; the administrator's random password is shown once.
    """
    stream = out if out is not None else sys.stdout
    source = stdin if stdin is not None else sys.stdin
    scenario = SCENARIOS.get(getattr(args, "scenario", "tour"))
    if scenario is None:
        sys.stderr.write(f"portlock: no such scenario; choose one of: {', '.join(SCENARIOS)}\n")
        return 2
    stream.write(BANNER + "\n")
    stream.write("Everything below happens on a simulated machine with synthetic devices.\n\n")
    sim = Simulation(port=int(getattr(args, "port", 0) or 0))
    try:
        sim.start()
        password = sim.create_admin()
        scenario(sim)
        for entry in sim.timeline():
            stream.write(entry + "\n")
        if not getattr(args, "serve", True):
            return 0
        try:
            sim.serve()
        except OSError as exc:
            sys.stderr.write(f"portlock: the simulated API cannot listen ({exc})\n")
            return 5
        stream.write("\n" + BANNER + "\n")
        stream.write(f"API and console: {sim.url}/\n")
        stream.write(f"Administrator:   {_ADMIN}\n")
        stream.write(f"Password:        {password}   (shown once; it exists only in this run)\n")
        stream.write(
            f"Command line:    portlock --url {sim.url} --user {_ADMIN} devices\n"
            f"State directory: {sim.home} (removed when you quit)\n"
            f"Point the command line at it: PORTLOCK_HOME={sim.home} portlock devices\n\n"
        )
        _usage(stream)
        stream.write(
            "Type quit (or press Ctrl-C) to stop; nothing outlives this process." + chr(10)
        )
        stream.flush()
        stop = threading.Event()
        reader = threading.Thread(
            target=_interact,
            args=(sim, source, stream, stop),
            name="portlock-simulate-input",
            daemon=True,
        )
        reader.start()
        try:
            while not stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            stream.write("\nStopping the simulation.\n")
        return 0
    finally:
        sim.close()
