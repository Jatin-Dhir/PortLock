"""Scans: scheduling, the verdict overlay, unavailable scanning and the watchdog."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive
from integration.harness import ADMIN, START, Harness, StubScanner, with_volume
from portlock.core.clock import FakeClock
from portlock.core.config import ScanConfig
from portlock.core.models import Mode
from portlock.core.store import ConnectionState


def _policy(scan: str, *, on_detection: str = "deny", access: str = "allow") -> dict[str, Any]:
    return {
        "version": 1,
        "rules": [
            {
                "id": "storage",
                "match": {"category": ["storage"]},
                "action": {"access": access, "scan": scan},
            }
        ],
        "scan": {"on_detection": on_detection, "on_incomplete": "read_only"},
    }


def _harness(tmp_path: Path, verdicts: dict[str, str] | None = None, **options: Any) -> Harness:
    clock = FakeClock(START)
    harness = Harness(tmp_path, clock=clock, scanner=StubScanner(clock, verdicts), **options)
    harness.boot()
    harness.set_mode(Mode.ENFORCE)
    return harness


@pytest.mark.parametrize(
    ("verdict", "on_detection", "state", "alert"),
    [
        ("clean", "deny", ConnectionState.ALLOWED, False),
        ("malicious", "read_only", ConnectionState.READ_ONLY, True),
        ("malicious", "alert", ConnectionState.ALLOWED, True),
        ("suspicious", "deny", ConnectionState.READ_ONLY, True),
        ("suspicious", "alert", ConnectionState.ALLOWED, True),
        ("incomplete", "deny", ConnectionState.ALLOWED, True),
        ("error", "deny", ConnectionState.ALLOWED, True),
    ],
)
def test_the_on_mount_overlay_narrows_but_never_widens(
    tmp_path: Path, verdict: str, on_detection: str, state: ConnectionState, alert: bool
) -> None:
    harness = _harness(tmp_path, {"/media/stick": verdict})
    harness.service.replace_policy(_policy("on_mount", on_detection=on_detection), actor=ADMIN)
    harness.plug(with_volume(flash_drive()))
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert harness.run_scans() == 1
    view = harness.view("test/1-1")
    assert view.state is state
    assert view.decision is not None and view.decision.decision.alert is alert
    assert view.scan_state.value == verdict
    scan = harness.service.list_scans()[0].to_dict()
    assert scan["state"] == "done" and scan["verdict"] == verdict
    assert scan["report"] is None and (scan["summary"] is not None) == (verdict != "error")


def test_a_required_scan_without_a_mounted_volume_waits_read_only(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    harness.service.replace_policy(_policy("required"), actor=ADMIN)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.provisional and view.scan_state.value == "waiting"
    assert harness.enforcer.is_read_only("test/1-1")
    harness.update(with_volume(flash_drive()))  # the volume is mounted later
    assert harness.view("test/1-1").scan_state.value == "queued"
    harness.run_scans()
    view = harness.view("test/1-1")
    assert not view.provisional and not harness.enforcer.is_read_only("test/1-1")


def test_required_scanning_that_is_unavailable_keeps_the_device_read_only(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path, scan=ScanConfig(enabled=False))
    harness.boot()
    harness.set_mode(Mode.ENFORCE)
    harness.service.replace_policy(_policy("required"), actor=ADMIN)
    harness.plug(with_volume(flash_drive()))
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.READ_ONLY
    assert view.decision is not None and view.decision.decision.alert
    assert "the required scan failed" in view.decision.decision.reasons[0]
    assert harness.enforcer.is_read_only("test/1-1")


def test_fail_closed_denies_a_device_whose_required_scan_did_not_finish(tmp_path: Path) -> None:
    harness = _harness(tmp_path, {"/media/stick": "incomplete"}, fail_closed=True)
    harness.service.replace_policy(_policy("required"), actor=ADMIN)
    harness.plug(with_volume(flash_drive()))
    harness.run_scans()
    decision = harness.records("decision.made")[-1].data
    assert decision["decision"]["access"] == "deny"
    assert decision["decision"]["source"] == "scan"
    # Revoked as DESIGN 14.11 says: it had a mounted volume, so it was ejected.
    assert harness.enforcer.was_ejected("test/1-1")


def test_a_manual_scan_of_a_device_whose_policy_asks_for_none_is_report_only(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path, {"/media/stick": "malicious"})
    harness.service.replace_policy(_policy("none"), actor=ADMIN)
    harness.plug(with_volume(flash_drive()))
    queued = harness.service.request_scan(harness.connection_id("test/1-1"), actor=ADMIN)
    assert [scan.record.trigger for scan in queued] == ["manual"]
    harness.run_scans()
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert harness.records("scan.detection")[-1].data["severity"] == "malicious"
    started = harness.records("scan.started")[-1]
    assert started.actor == ADMIN and started.data["trigger"] == "manual"


def test_the_watchdog_abandons_a_scan_that_does_not_stop(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    scanner = harness.scanner
    assert scanner is not None
    scanner.hold = threading.Event()
    harness.service.replace_policy(_policy("required"), actor=ADMIN)
    harness.plug(with_volume(flash_drive()))
    worker = threading.Thread(target=harness.service.run_scans)
    worker.start()
    try:
        assert scanner.entered.wait(10)
        assert harness.view("test/1-1").scan_state.value == "running"
        harness.tick(60 + 30)  # max_seconds + grace: asked to stop
        assert harness.view("test/1-1").scan_state.value == "running"
        harness.tick(30)  # still running 30 s later: abandoned
        view = harness.view("test/1-1")
        assert view.scan_state.value == "error"
        assert view.state is ConnectionState.READ_ONLY  # a failed required scan never counts
        finished = harness.records("scan.finished")[-1]
        assert finished.data["error"] == "scan did not stop"
    finally:
        scanner.hold.set()
        worker.join(10)
    assert not worker.is_alive()
    # The late result is discarded: one finish only.
    assert len(harness.records("scan.finished")) == 1
