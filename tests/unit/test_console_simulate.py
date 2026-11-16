"""``portlock simulate``: the whole product on a fake machine, and the proof that it cannot
reach the real one."""

from __future__ import annotations

import argparse
import inspect
import io
import os
import re
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from test_console_support import ApiClient, Reply

import portlock.guard.factory as guard_factory
from portlock.audit.log import AuditRecord
from portlock.console import simulate as simulate_module
from portlock.console.simulate import (
    BANNER,
    DEVICES,
    SCENARIOS,
    Simulation,
    SimulationError,
    run_simulation,
    tour,
)
from portlock.core.clock import FakeClock
from portlock.core.models import Severity
from portlock.guard.fake import FakeBackend, FakeEnforcer
from portlock.service.daemon import read_runtime_file

START = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)


@pytest.fixture
def sim(tmp_path: Path) -> Iterator[Simulation]:
    simulation = Simulation(home=tmp_path / "sim", clock=FakeClock(START))
    try:
        yield simulation
    finally:
        simulation.close()


def event_types(lines: list[str]) -> list[str]:
    """The event type of every audit line of a timeline (narration lines are skipped)."""
    types = []
    for line in lines:
        if line.startswith("=="):
            continue
        fields = line.split()
        types.append(fields[2])
    return types


# --- the scripted tour --------------------------------------------------------------------


def test_the_tour_tells_its_story_in_order(sim: Simulation) -> None:
    sim.start()
    sim.create_admin()
    sim.timeline()  # start-up records
    tour(sim)
    lines = sim.timeline()
    narration = [line[3:] for line in lines if line.startswith("== ")]
    assert narration == [
        "The operator's keyboard arrives. Input devices are protected: never blocked.",
        "A stick nobody knows arrives. The default policy says 'pending', so it is blocked.",
        "The operator approves it, read-only, for two hours.",
        "A stick with a hidden keyboard arrives. The default policy denies it and alerts.",
        "A second unknown stick arrives and waits for a decision.",
        "The operator looks at it and denies it. It stays blocked.",
        "A stick the operator knows. The first time it is approved and trusted.",
        "It is unplugged and plugged in again: PortLock remembers it.",
        "Suspected intrusion: the operator engages a lockdown and confirms it within 60 s.",
    ]
    story = [line for line in lines if not line.startswith("==")]
    decisions = [
        re.search(r"decision\.made\s+(\w+) \(source (\w+)", line).groups()  # type: ignore[union-attr]
        for line in story
        if " decision.made " in line
    ]
    # keyboard protected; unknown stick pending, then read-only by grant; BadUSB denied by
    # policy; second stick pending, then its refusal; the trusted stick pending, allowed by
    # trust, allowed again on re-plugging; then the lockdown denies what it blocks.
    assert decisions[:3] == [("allow", "safety"), ("pending", "default"), ("read_only", "grant")]
    assert ("deny", "policy") in decisions and ("allow", "grant") in decisions
    assert decisions[-1][1] == "lockdown" or any(source == "lockdown" for _, source in decisions)
    types = event_types(story)
    for expected in (
        "device.connected",
        "grant.created",
        "trust.added",
        "device.removed",
        "lockdown.engaged",
        "change.pending",
        "change.confirmed",
        "scan.finished",
    ):
        assert expected in types, expected
    assert types.index("lockdown.engaged") < types.index("change.confirmed")
    assert types.count("device.connected") == 6  # the trusted stick came twice
    assert any("ALERT" in line for line in story)
    assert all(len(line) <= 200 for line in lines)


def test_after_the_tour_the_machine_is_in_a_known_state(sim: Simulation) -> None:
    sim.start()
    sim.create_admin()
    tour(sim)
    service = sim.service
    status = service.status()
    assert status.simulation is True and status.mode.effective_mode.value == "enforce"
    lockdown = service.lockdown_status()
    assert lockdown.active is True and lockdown.pending_change_id is None  # confirmed
    states = {
        view.device.product: view.state.value for view in service.list_connections(open_only=True)
    }
    assert states["Simulated Keyboard"] == "protected"
    assert states["Simulated Flash Drive with hidden keyboard"] == "denied"
    assert states["Simulated Flash Drive 64GB"] == "denied"
    assert sim.enforcer.is_blocked(DEVICES["badusb"]()) and sim.enforcer.is_blocked(
        DEVICES["second-stick"]()
    )
    assert not sim.enforcer.is_blocked(DEVICES["keyboard"]())
    assert service.list_grants(kind="trust")


def test_the_tour_can_be_replayed_to_the_same_story(tmp_path: Path) -> None:
    runs = []
    for number in range(2):
        with Simulation(home=tmp_path / f"run{number}", clock=FakeClock(START)) as simulation:
            simulation.start()
            simulation.create_admin()
            simulation.timeline()
            tour(simulation)
            lines = simulation.timeline()
            runs.append([re.sub(r"[0-9a-f]{16}", "ID", line[9:]) for line in lines])
    assert runs[0] == runs[1]


def test_the_scenario_registry(sim: Simulation) -> None:
    assert set(SCENARIOS) == {"tour", "none"} and SCENARIOS["tour"] is tour
    sim.start()
    SCENARIOS["none"](sim)
    assert sim.service.list_connections(open_only=True) == []


# --- driving it by hand -------------------------------------------------------------------


def test_devices_are_plugged_unplugged_and_named(sim: Simulation) -> None:
    sim.start()
    assert set(DEVICES) == {
        "keyboard",
        "mouse",
        "hub",
        "trusted-stick",
        "unknown-stick",
        "second-stick",
        "blank-stick",
        "badusb",
        "phone",
        "webcam",
    }
    for build in DEVICES.values():
        device = build()
        assert device.manufacturer == "Simulated Corp" and "Simulated" in (device.product or "")
        assert device.serial is None or device.serial.startswith("TEST")
        assert device.instance_id.startswith("simulated/")
    plugged = sim.plug("unknown-stick")
    assert plugged.volumes and plugged.volumes[0].mount_point == "/simulated/unknown-stick"
    assert sim.connection("unknown-stick").state.value == "pending"
    with pytest.raises(SimulationError, match="already plugged in"):
        sim.plug("unknown-stick")
    sim.unplug("unknown-stick")
    with pytest.raises(SimulationError, match="not plugged in"):
        sim.unplug("unknown-stick")
    with pytest.raises(SimulationError, match="no such device"):
        sim.plug("toaster")
    with pytest.raises(SimulationError, match="no such device"):
        sim.unplug("toaster")
    with pytest.raises(SimulationError, match="not connected"):
        sim.connection("phone")


def test_a_temporary_grant_expires_when_the_fake_clock_moves(sim: Simulation) -> None:
    sim.start()
    sim.plug("unknown-stick")
    sim.approve("unknown-stick", kind="temporary")
    assert sim.connection("unknown-stick").state.value == "allowed"
    sim.timeline()
    sim.advance(2 * 3600 + 5)
    lines = sim.timeline()
    assert any("grant.expired" in line for line in lines)
    # Revoking access to a mounted volume asks for a clean eject first (DESIGN 14.11), and
    # the simulated eject unplugs the stick.
    assert any("eject" in line for line in lines)
    assert not sim.backend.is_present(DEVICES["unknown-stick"]().instance_id)


def test_advancing_needs_a_fake_clock(tmp_path: Path) -> None:
    with Simulation(home=tmp_path / "real-clock") as real:
        real.start()
        with pytest.raises(SimulationError, match="fake clock"):
            real.advance(10)


def test_lockdown_is_engaged_and_lifted_with_the_administrators_password(sim: Simulation) -> None:
    sim.start()
    with pytest.raises(SimulationError, match="create_admin"):
        sim.lift_lockdown()
    sim.create_admin()
    sim.plug("trusted-stick")
    sim.approve("trusted-stick", kind="trust")
    sim.engage_lockdown()
    assert sim.service.lockdown_status().active
    sim.lift_lockdown()
    assert not sim.service.lockdown_status().active


def test_the_timeline_returns_each_record_once_and_escapes_what_a_terminal_would_obey(
    sim: Simulation,
) -> None:
    sim.start()
    first = sim.timeline()
    assert first and sim.timeline() == []
    record = AuditRecord(
        seq=1,
        ts="2026-05-01T09:00:00.000000Z",
        event_type="device.connected",
        severity=Severity.INFO,
        actor=None,
        device_fp=None,
        data={"device": {"manufacturer": "Evil\x1b[2J", "product": "Name\rOverwritten"}},
        prev_hash="0" * 64,
        hash="1" * 64,
    )
    line = simulate_module._describe(record)
    assert "\x1b" not in line and "\r" not in line and "\\x1b" in line and "\\x0d" in line


# --- nothing real is reachable ------------------------------------------------------------


def test_there_is_no_way_to_pick_a_real_enforcer_backend_timer_or_directory_check() -> None:
    assert set(inspect.signature(Simulation.__init__).parameters) == {
        "self",
        "home",
        "clock",
        "enforce",
        "port",
    }
    assert set(inspect.signature(run_simulation).parameters) == {"args", "stdin", "out"}
    source = inspect.getsource(simulate_module)
    assert "guard.factory" not in source and "import factory" not in source


def test_every_platform_factory_is_booby_trapped_and_the_whole_simulation_still_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the simulation reached for something real")

    for name in (
        "create_backend",
        "create_enforcer",
        "create_guard",
        "create_external_timer",
        "create_dir_privacy",
        "system_instance_ids",
    ):
        monkeypatch.setattr(guard_factory, name, refuse)
    import portlock.guard.linux.enforce as linux_enforce
    import portlock.guard.windows.enforce as windows_enforce

    monkeypatch.setattr(
        linux_enforce.LinuxEnforcer, "system", classmethod(lambda cls, **kw: refuse())
    )
    monkeypatch.setattr(
        windows_enforce.WindowsEnforcer, "system", classmethod(lambda cls, **kw: refuse())
    )
    monkeypatch.setattr(os, "system", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    with Simulation(home=tmp_path / "trapped", clock=FakeClock(START)) as simulation:
        assert isinstance(simulation.runtime.enforcer, FakeEnforcer)
        assert isinstance(simulation.runtime.backend, FakeBackend)
        simulation.start()
        simulation.create_admin()
        tour(simulation)
        api = simulation.serve()
        client = ApiClient(api.port)
        assert client.get("/ping").json["simulation"] is True
        status = simulation.service.status()
        assert status.enforcer["name"] == "simulated" and status.backend["name"] == "simulated"
        assert simulation.service.doctor() is not None


def test_the_simulation_keeps_everything_in_its_own_temporary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("PORTLOCK_HOME", str(tmp_path / "real-looking-home"))
    with Simulation(clock=FakeClock(START)) as simulation:
        home = simulation.home
        assert home.is_dir() and home.name.startswith("portlock-sim-")
        simulation.start()
        simulation.create_admin()
        tour(simulation)
        assert Path(simulation.config.paths.state_dir).is_relative_to(home)
        assert Path(simulation.config.paths.config_dir).is_relative_to(home)
        assert (Path(simulation.config.paths.state_dir) / "portlock.db").is_file()
    assert not home.exists()  # removed on close
    assert list(elsewhere.iterdir()) == []
    assert not (tmp_path / "real-looking-home").exists()


def test_a_home_that_is_given_is_kept(tmp_path: Path) -> None:
    home = tmp_path / "kept"
    with Simulation(home=home, clock=FakeClock(START)) as simulation:
        simulation.start()
    assert home.is_dir()


def test_the_scanner_reads_no_file(sim: Simulation, tmp_path: Path) -> None:
    sim.start()
    sim.plug("badusb")
    sim.plug("trusted-stick")
    sim.approve("trusted-stick", kind="trust")
    scans = {scan.record.mount_point: scan.record for scan in sim.service.list_scans()}
    assert "/simulated/trusted-stick" in scans
    # The mount point is made up; a real scanner would fail on it. This one never opens it.
    assert all(record.state == "done" for record in scans.values())
    assert not Path("/simulated").exists()


# --- serving ------------------------------------------------------------------------------


def test_serving_publishes_the_api_the_runtime_file_and_the_pump(tmp_path: Path) -> None:
    with Simulation(home=tmp_path / "served") as simulation:
        simulation.start()
        password = simulation.create_admin()
        api = simulation.serve()
        assert simulation.url == f"http://127.0.0.1:{api.port}"
        runtime = read_runtime_file(simulation.config.paths.state_dir)
        assert runtime is not None and runtime["port"] == api.port
        assert (
            runtime["run_id"] == simulation.service.run_id
            and runtime["secret"] == simulation.runtime.cli_secret
        )
        client = ApiClient(api.port)
        ping = client.get("/ping").json
        assert ping["simulation"] is True and ping["setup_required"] is False
        login: Reply = client.post("/auth/login", {"username": "admin", "password": password})
        assert login.status == 200
        status = ApiClient(api.port, login.json["token"]).get("/status").json
        assert status["simulation"] is True and status["platform"]
        simulation.backend.plug(DEVICES["phone"]())  # appears without anyone calling pump()
        deadline = 100
        while deadline and not simulation.service.list_connections(open_only=True):
            time.sleep(0.05)
            deadline -= 1
        assert simulation.service.list_connections(open_only=True)


# --- the command ---------------------------------------------------------------------------


def run(args: dict[str, Any], stdin: str = "quit\n") -> tuple[int, str]:
    out = io.StringIO()
    namespace = argparse.Namespace(**{"scenario": "tour", "port": 0, "serve": True, **args})
    code = run_simulation(namespace, stdin=io.StringIO(stdin), out=out)
    return code, out.getvalue()


def test_the_command_prints_the_banner_the_tour_and_how_to_connect() -> None:
    code, text = run({}, "list\nplug phone\nunplug phone\nplug toaster\nhelp\nquit\n")
    assert code == 0
    assert text.startswith(BANNER) and text.count(BANNER) == 2
    assert "== The operator's keyboard arrives." in text
    assert re.search(r"API and console: http://127\.0\.0\.1:\d+/", text)
    assert re.search(r"Administrator:\s+admin", text) and re.search(r"Password:\s+\S{20,}", text)
    assert "PORTLOCK_HOME=" in text and "portlock --url http://127.0.0.1:" in text
    assert "Commands: plug NAME | unplug NAME" in text
    assert "Simulated Corp Simulated Keyboard: protected" in text
    assert "Simulated Corp Simulated Phone (MTP)" in text  # the plugged phone was narrated
    assert "no such device 'toaster'" in text
    home = re.search(r"State directory: (.+?) \(removed", text).group(1)  # type: ignore[union-attr]
    assert not Path(home).exists()


def test_the_command_without_serving_prints_the_timeline_and_stops() -> None:
    code, text = run({"serve": False}, "")
    assert code == 0 and BANNER in text and "API and console" not in text and "Password" not in text
    assert "lockdown.engaged" in text


def test_the_password_is_shown_once_and_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("DEBUG"):
        _code, text = run({})
    password = re.search(r"Password:\s+(\S+)", text).group(1)  # type: ignore[union-attr]
    assert text.count(password) == 1
    assert password not in caplog.text


def test_an_unknown_scenario_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    out = io.StringIO()
    code = run_simulation(
        argparse.Namespace(scenario="nope", port=0, serve=False), stdin=io.StringIO(""), out=out
    )
    assert code == 2 and out.getvalue() == ""
    assert "no such scenario" in capsys.readouterr().err


def test_a_taken_port_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        port = holder.getsockname()[1]
        out = io.StringIO()
        code = run_simulation(
            argparse.Namespace(scenario="none", port=port, serve=True),
            stdin=io.StringIO(""),
            out=out,
        )
    assert code == 5 and "cannot listen" in capsys.readouterr().err
