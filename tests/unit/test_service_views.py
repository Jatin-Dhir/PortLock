"""The service's read methods: each view's to_dict() is the API.md section 4 object."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from factories import flash_drive, keyboard
from integration.harness import ADMIN, Harness, with_volume
from portlock.core.models import Mode
from portlock.core.service import ServiceError

CONNECTION_KEYS = {
    "connection_id",
    "run_id",
    "fingerprint",
    "confidence",
    "basis",
    "storage_identity",
    "display_name",
    "device",
    "connected_at",
    "removed_at",
    "close_reason",
    "present_at_start",
    "state",
    "provisional",
    "protected",
    "protection_codes",
    "decision",
    "enforcement",
    "scan",
    "resolution",
    "first_seen",
    "connection_count",
}
DECISION_KEYS = {
    "id",
    "decided_at",
    "access",
    "source",
    "reasons",
    "rule_id",
    "grant_id",
    "scan",
    "alert",
    "expires_at",
    "trigger",
    "policy_hash",
    "mode",
}
ENFORCEMENT_KEYS = {"outcome", "os_state", "would", "mechanism", "tier", "detail", "error", "at"}
STATUS_KEYS = {
    "service",
    "version",
    "run_id",
    "host_label",
    "platform",
    "started_at",
    "uptime_seconds",
    "simulation",
    "mode",
    "lockdown",
    "policy",
    "backend",
    "enforcer",
    "counts",
    "audit",
    "journal",
    "degraded",
    "setup_required",
}


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    built = Harness(tmp_path, devices=[keyboard()])
    built.boot()
    built.set_mode(Mode.ENFORCE)
    return built


def test_a_connection_view_has_exactly_the_api_fields_and_is_json(harness: Harness) -> None:
    harness.plug(with_volume(flash_drive()))
    view = harness.view("test/1-1")
    data = view.to_dict()
    assert set(data) == CONNECTION_KEYS
    assert set(data["decision"]) == DECISION_KEYS
    assert set(data["enforcement"]) == ENFORCEMENT_KEYS
    assert "connection_id" not in data["device"]  # the per-connection token is internal
    assert data["scan"] == {"state": "none", "scan_id": None}
    assert data["storage_identity"].startswith("plv1:")
    assert data["enforcement"] == {
        "outcome": "applied",
        "os_state": "blocked",
        "would": None,
        "mechanism": "fake:authorized",
        "tier": "reactive",
        "detail": "blocked test/1-1",
        "error": None,
        "at": "2026-03-02T09:00:00.000000Z",
    }
    json.dumps(data)  # no float, no datetime left
    assert harness.service.get_connection(view.connection_id or 0) == view


def test_a_closed_connection_is_read_back_from_the_store(harness: Harness) -> None:
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    harness.unplug("test/1-1")
    closed = harness.service.get_connection(cid)
    data = closed.to_dict()
    assert set(data) == CONNECTION_KEYS
    assert data["removed_at"] is not None and data["close_reason"] == "removed"
    assert data["decision"]["access"] == "pending"
    assert data["enforcement"]["outcome"] == "applied"
    assert data["enforcement"]["os_state"] == "blocked"
    with pytest.raises(ServiceError) as missing:
        harness.service.get_connection(9999)
    assert missing.value.code == "not_found"


def test_device_detail_lists_connections_grants_and_decisions(harness: Harness) -> None:
    harness.plug(flash_drive())
    fingerprint = harness.view("test/1-1").fingerprint
    harness.service.approve(
        harness.connection_id("test/1-1"), kind="trust", actor=ADMIN, role="admin"
    )
    detail = harness.service.get_device(fingerprint).to_dict()
    assert detail["trust"] == "full" and detail["connected"] is True
    assert len(detail["connections"]) == 1 and len(detail["grants"]) == 1
    assert [d["access"] for d in detail["decisions"]] == ["allow", "pending"]
    with pytest.raises(ServiceError) as missing:
        harness.service.get_device("plk1:" + "a" * 32)
    assert missing.value.code == "not_found"


def test_the_status_snapshot_has_the_api_fields(harness: Harness) -> None:
    harness.plug(flash_drive())
    harness.clock.advance(7)
    data = harness.service.status().to_dict()
    assert set(data) == STATUS_KEYS
    assert data["uptime_seconds"] == 7
    assert data["counts"] == {
        "connected": 2,
        "protected": 1,
        "allowed": 0,
        "read_only": 0,
        "pending": 1,
        "denied": 0,
        "not_enforced": 0,
    }
    assert data["mode"]["effective_mode"] == "enforce" and data["mode"]["source"] == "setting"
    assert data["journal"] == {"open_records": 1, "corrupt_lines": 0}
    assert data["setup_required"] is True and data["degraded"] == []
    assert data["policy"]["source"] == "default"
    json.dumps(data)


def test_mode_settings_policy_and_doctor_views(harness: Harness) -> None:
    mode = harness.service.get_mode().to_dict()
    assert mode == {
        "mode": "enforce",
        "effective_mode": "enforce",
        "source": "setting",
        "killswitch": False,
        "can_enforce": True,
        "notes": [],
        "watch_only": False,
        "watch_only_reason": None,
    }
    settings = harness.service.get_settings().to_dict()
    assert settings["runtime"]["lockdown.default_minutes"] == 30
    assert settings["effective"]["scope"] == "storage"
    assert settings["config"]["mode"] == "monitor"
    policy = harness.service.get_policy().to_dict()
    assert policy["name"] == "PortLock default policy" and policy["rules"] == 1
    doctor = harness.service.doctor().to_dict()
    ids = {check["id"] for check in doctor["checks"]}
    assert {"service.mode", "service.journal", "service.audit", "service.setup"} <= ids
    assert {"guard.enforcer", "guard.block"} & ids
    json.dumps(doctor)
