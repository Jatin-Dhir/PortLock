"""Security event logging: every step leaves the documented records and the chain verifies."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from factories import flash_drive, keyboard, storage_with_keyboard
from integration.harness import ADMIN, Harness
from portlock.audit.events import REGISTRY
from portlock.core.errors import StoreError
from portlock.core.models import Mode

SECRET_WORDS = ("password", "secret", "token", "recovery_code", "credential")


def _walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        keys = list(value)
        for item in value.values():
            keys.extend(_walk_keys(item))
        return keys
    if isinstance(value, list):
        return [key for item in value for key in _walk_keys(item)]
    return []


def test_a_scripted_session_produces_the_documented_records_in_order(
    machine: Callable[..., Harness],
) -> None:
    harness = machine(devices=[keyboard()])
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    harness.service.approve(harness.connection_id("test/1-1"), kind="once", actor=ADMIN)
    harness.unplug("test/1-1")
    harness.service.stop()

    types = harness.event_types()
    assert types == [
        # start: the tail check, the start record, the keyboard found at start
        "audit.verified",
        "service.started",
        "device.connected",
        "decision.made",
        # the switch to enforce, under commit-confirm
        "mode.changed",
        "change.pending",
        "change.confirmed",
        # the stick arrives and is blocked
        "device.connected",
        "enforcement.applied",
        "decision.made",
        # an operator approves it once
        "grant.created",
        "enforcement.applied",
        "grant.used",
        "decision.made",
        # it leaves; its one-time grant is spent
        "grant.expired",
        "device.removed",
        "service.stopped",
    ]
    by_type = {record.event_type: record for record in harness.records()}
    blocked = harness.records("enforcement.applied")[0]
    assert blocked.data["action"] == "block" and blocked.data["mechanism"] == "fake:authorized"
    assert blocked.device_fp == by_type["device.removed"].device_fp
    decision = harness.records("decision.made")[1]
    assert decision.data["decision"]["access"] == "pending"
    assert decision.data["mode"] == "enforce" and decision.data["trigger"] == "arrival"
    assert decision.data["enforcement"]["outcome"] == "applied"
    assert by_type["grant.used"].data["kind"] == "once"


def test_the_chain_verifies_after_a_long_mixed_scenario(machine: Callable[..., Harness]) -> None:
    harness = machine(devices=[keyboard()])
    harness.set_mode(Mode.ENFORCE)
    for index in range(5):
        stick = flash_drive(
            instance_id=f"test/4-{index}", bus_path=f"4-{index}", serial=f"TEST0004000{index}"
        )
        harness.plug(stick)
        if index % 2 == 0:
            harness.service.approve(
                harness.connection_id(stick.instance_id), kind="trust", actor=ADMIN, role="admin"
            )
    harness.plug(storage_with_keyboard())
    harness.engage(15)
    harness.tick(15 * 60)
    harness.unplug("test/4-1")

    result = harness.service.verify_audit(actor=ADMIN)
    assert result.ok and result.checked == harness.rt.audit_log.count() - 1
    assert result.head_checked
    assert harness.records("audit.verified")[-1].data["scope"] == "full"
    records = harness.records()
    assert all(record.event_type in REGISTRY for record in records)
    for record in records:
        for key in _walk_keys(dict(record.data)):
            assert not any(word in key.lower() for word in SECRET_WORDS), (record.event_type, key)


def test_an_audit_failure_does_not_stop_enforcement_and_the_backlog_is_flushed(
    machine: Callable[..., Harness], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = machine()
    harness.set_mode(Mode.ENFORCE)
    log = harness.rt.audit_log
    real_append = log.append

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise StoreError("database is locked")

    monkeypatch.setattr(log, "append", broken)
    harness.plug(flash_drive())
    assert harness.enforcer.is_blocked("test/1-1")  # enforced although nothing was audited
    status = harness.service.status()
    assert "audit" in status.degraded and status.audit["backlog"] >= 3

    monkeypatch.setattr(log, "append", real_append)
    harness.tick()
    assert harness.rt.audit.backlog == 0
    delayed = [record for record in harness.records() if record.data.get("delayed")]
    assert {record.event_type for record in delayed} >= {"device.connected", "decision.made"}
    assert all("occurred_at" in record.data for record in delayed)
    assert harness.rt.audit_log.verify().ok
