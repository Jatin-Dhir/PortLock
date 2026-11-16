"""A whole PortLock process on a simulated machine, for the service and integration tests.

``Harness`` builds the runtime with :func:`portlock.service.daemon.build_runtime` on a
``tmp_path`` home: real SQLite stores, a real journal file and a real audit log, with a
synchronous :class:`FakeBackend`, a :class:`FakeEnforcer` (the simulated operating
system, which survives a "restart" of the process just as the real one would), a
:class:`FakeClock`, an in-memory dead-man timer and an in-memory privacy check. Nothing
here touches a real device, timer, registry or ``/sys``.

The service is started without threads; tests drive it with :meth:`Harness.plug`,
:meth:`Harness.tick` and :meth:`Harness.run_scans`, so every step is deterministic and
nothing sleeps.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from portlock.audit.log import AuditRecord
from portlock.core.clock import FakeClock
from portlock.core.config import Config, LockdownConfig, PathsConfig, ScanConfig
from portlock.core.models import Mode, UsbDevice, Volume
from portlock.core.service import ConnectionView, PortLockService
from portlock.guard.base import EnforcerCapabilities, JournalEntry
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.guard.seams import FakeDirPrivacy, FakeExternalTimer
from portlock.lockdown.manager import Credential
from portlock.scan.report import Finding, FindingSeverity, ScanReport
from portlock.service.daemon import Runtime, build_runtime

START = datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
RECOVER_ARGV = ("portlock", "recover", "--config", "test")
ADMIN = "alice"
ADMIN_PASSWORD = "correct horse battery staple 7"
CHANNEL = "session-0001"


class StubScanner:
    """A scanner that reports what the test says, without reading anything.

    ``verdicts`` maps a mount point to ``"clean"``, ``"suspicious"``, ``"malicious"``,
    ``"incomplete"`` or ``"error"`` (default clean). With ``hold`` set, a scan waits on
    that event (to simulate one that hangs) and honours its cancel event.
    """

    def __init__(self, clock: FakeClock, verdicts: Mapping[str, str] | None = None) -> None:
        self.clock = clock
        self.verdicts = dict(verdicts or {})
        self.calls: list[str] = []
        self.hold: threading.Event | None = None
        self.entered = threading.Event()

    def scan(
        self,
        root: str,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[Any], None] | None = None,
    ) -> ScanReport:
        self.calls.append(str(root))
        self.entered.set()
        if self.hold is not None:
            self.hold.wait(timeout=30)
        verdict = self.verdicts.get(str(root), "clean")
        now = self.clock.now()
        findings: tuple[Finding, ...] = ()
        truncated_reason = None
        if verdict == "malicious":
            findings = (
                Finding("autorun.inf", "hashset", "known-bad", FindingSeverity.MALICIOUS, "test"),
            )
        elif verdict == "suspicious":
            findings = (
                Finding("run.lnk", "heuristics", "shell-link", FindingSeverity.SUSPICIOUS, "t"),
            )
        elif verdict == "incomplete":
            truncated_reason = "max_files"
        report = ScanReport(
            root=str(root),
            started_at=now,
            finished_at=now,
            files_seen=3,
            files_hashed=3,
            bytes_hashed=30,
            findings=findings,
            truncated=truncated_reason is not None,
            truncated_reason=truncated_reason,
        )
        if verdict == "error":
            raise OSError("simulated scanner failure")
        return report


def make_config(home: Path, **overrides: Any) -> Config:
    fields: dict[str, Any] = {
        "paths": PathsConfig.under(home),
        "mode": Mode.MONITOR,
        "scan": ScanConfig(enabled=False),
        "lockdown": LockdownConfig(default_minutes=30, max_minutes=240),
        "commit_confirm_seconds": 60,
    }
    fields.update(overrides)
    return Config(**fields)


class Harness:
    """One simulated machine and the PortLock process running on it."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        devices: Iterable[UsbDevice] = (),
        clock: FakeClock | None = None,
        scanner: StubScanner | None = None,
        capabilities: EnforcerCapabilities | None = None,
        **config: Any,
    ) -> None:
        self.home = tmp_path / "home"
        if scanner is not None and "scan" not in config:
            config["scan"] = ScanConfig(enabled=True, max_seconds=60)
        self.config = make_config(self.home, **config)
        self.clock = clock if clock is not None else FakeClock(START)
        self.backend = FakeBackend(devices, clock=self.clock, synchronous=True)
        self._hook: Callable[[JournalEntry], None] | None = None
        self.enforcer = FakeEnforcer(
            capabilities, backend=self.backend, write_ahead=self._write_ahead
        )
        self.timer = FakeExternalTimer()
        self.privacy = FakeDirPrivacy()
        self.scanner = scanner
        self.runtime: Runtime | None = None

    # --- lifecycle ---------------------------------------------------------------------

    def _write_ahead(self, entry: JournalEntry) -> None:
        if self._hook is None:
            raise RuntimeError("no journal is wired")
        self._hook(entry)

    def _factory(self, hook: Callable[[JournalEntry], None]) -> FakeEnforcer:
        self._hook = hook
        return self.enforcer

    def build(self) -> Runtime:
        self.runtime = build_runtime(
            self.config,
            clock=self.clock,
            backend=self.backend,
            enforcer_factory=self._factory,
            scanner=self.scanner,
            timer=self.timer,
            dir_privacy=self.privacy,
            system_ids=lambda devices: frozenset(),
            recover_argv=RECOVER_ARGV,
        )
        return self.runtime

    def boot(self) -> PortLockService:
        """Build and start (no threads), then handle whatever the backend queued."""
        runtime = self.build()
        runtime.service.start(threads=False)
        runtime.service.drain_events()
        return runtime.service

    def crash(self) -> None:
        """End the process without ``stop()``: the OS state (the fake) stays as it is."""
        runtime = self.rt
        self.backend.stop()
        runtime.close()
        self.runtime = None

    def stop(self) -> None:
        runtime = self.rt
        runtime.service.stop()
        runtime.close()
        self.runtime = None

    def restart(self) -> PortLockService:
        self.crash()
        return self.boot()

    # --- shortcuts ---------------------------------------------------------------------

    @property
    def rt(self) -> Runtime:
        if self.runtime is None:
            raise RuntimeError("the harness is not running")
        return self.runtime

    @property
    def service(self) -> PortLockService:
        return self.rt.service

    def plug(self, device: UsbDevice) -> UsbDevice:
        connected = self.backend.plug(device)
        self.service.drain_events()
        return connected

    def unplug(self, instance_id: str) -> None:
        self.backend.unplug(instance_id)
        self.service.drain_events()

    def update(self, device: UsbDevice) -> UsbDevice:
        updated = self.backend.update(device)
        self.service.drain_events()
        return updated

    def tick(self, seconds: float = 0) -> None:
        if seconds:
            self.clock.advance(seconds)
        self.service.tick()
        self.service.drain_events()

    def run_scans(self) -> int:
        done = self.service.run_scans()
        self.service.drain_events()
        return done

    def view(self, instance_id: str) -> ConnectionView:
        for view in self.service.list_connections(open_only=True):
            if view.device.instance_id == instance_id:
                return view
        raise KeyError(instance_id)

    def connection_id(self, instance_id: str) -> int:
        cid = self.view(instance_id).connection_id
        assert cid is not None
        return cid

    def records(self, *types: str) -> list[AuditRecord]:
        found = list(self.rt.audit_log.iterate())
        return [r for r in found if not types or r.event_type in types]

    def event_types(self) -> list[str]:
        return [record.event_type for record in self.records()]

    def add_admin(self, name: str = ADMIN, password: str = ADMIN_PASSWORD) -> None:
        if self.rt.accounts.get_user(name) is None:
            self.rt.accounts.create_user(name, password, "admin", actor="setup")

    def set_mode(self, mode: Mode, *, confirm: bool = True) -> None:
        applied = self.service.set_mode(mode, actor=ADMIN, channel=CHANNEL)
        change = applied.extra.get("change")
        if change is not None and confirm:
            self.service.confirm_change(change["id"], actor=ADMIN, channel=CHANNEL)

    def engage(self, minutes: int = 30, *, confirm: bool = True) -> str:
        result = self.service.lockdown_engage(
            minutes=minutes, reason="test", actor=ADMIN, channel=CHANNEL
        )
        change_id = result.value.change.id
        if confirm:
            self.service.lockdown_confirm(change_id, actor=ADMIN, channel=CHANNEL)
        return change_id

    def lift(self) -> None:
        self.add_admin()
        self.service.lockdown_lift(actor=ADMIN, credential=Credential("password", ADMIN_PASSWORD))

    def journal_open(self) -> int:
        return len(self.rt.journal.open_records())


def with_volume(device: UsbDevice, mount: str = "/media/stick") -> UsbDevice:
    """The device with one mounted volume."""
    volume = Volume(device_node="/dev/sdx1", mount_point=mount, fs_type="vfat", fs_uuid="ABCD-0001")
    return dataclasses.replace(device, volumes=(volume,))
