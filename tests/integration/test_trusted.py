"""Trusted device handling: trust lets a device in on every connection until revoked."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from factories import flash_drive
from integration.harness import ADMIN, Harness
from portlock.core.models import DecisionSource, Mode
from portlock.core.store import ConnectionState


def _trusted(
    machine: Callable[..., Harness], *, read_only: bool = False, **options: object
) -> Harness:
    harness = machine(**options)
    harness.set_mode(Mode.ENFORCE)
    harness.plug(flash_drive())
    harness.service.approve(
        harness.connection_id("test/1-1"),
        kind="trust",
        read_only=read_only,
        actor=ADMIN,
        role="admin",
    )
    return harness


def test_a_trusted_device_is_allowed_now_and_after_reconnecting(
    machine: Callable[..., Harness],
) -> None:
    harness = _trusted(machine)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert harness.records("trust.added")[-1].data["grant"]["kind"] == "trust"
    first = harness.connection_id("test/1-1")
    harness.unplug("test/1-1")
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.connection_id != first
    assert view.state is ConnectionState.ALLOWED
    assert view.decision is not None and view.decision.decision.source is DecisionSource.GRANT
    assert not harness.enforcer.is_blocked("test/1-1")
    devices = harness.service.list_devices()
    assert devices[0].trust == "full" and devices[0].connected


def test_read_only_trust_gives_a_read_only_device(machine: Callable[..., Harness]) -> None:
    harness = _trusted(machine, read_only=True)
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.READ_ONLY
    assert view.enforcement is not None and view.enforcement.os_state == "read_only"
    assert harness.enforcer.is_read_only("test/1-1")
    assert not harness.enforcer.is_blocked("test/1-1")
    # Read-only was armed while the device was still blocked: preventive.
    assert view.enforcement.tier.value == "preventive"


def test_trust_does_not_beat_a_deny_rule(machine: Callable[..., Harness], tmp_path: Path) -> None:
    harness = _trusted(machine)
    policy = {
        "version": 1,
        "name": "deny one product",
        "rules": [
            {
                "id": "deny-example",
                "match": {"vendor_id": ["0x1209"], "product_id": ["0x0001"]},
                "action": {"access": "deny", "alert": True},
            }
        ],
    }
    harness.service.replace_policy(policy, actor=ADMIN)
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.DENIED
    assert view.decision is not None and view.decision.decision.rule_id == "deny-example"
    assert harness.enforcer.is_blocked("test/1-1")
    saved = json.loads((harness.config.paths.config_dir / "policy.json").read_text("utf-8"))
    assert saved["rules"][0]["id"] == "deny-example"


def test_revoking_trust_blocks_the_device_within_the_same_call(
    machine: Callable[..., Harness],
) -> None:
    harness = _trusted(machine)
    grant = harness.service.list_grants()[0]
    applied = harness.service.revoke_grant(grant.id, actor=ADMIN)
    assert applied.reevaluated == (harness.connection_id("test/1-1"),)
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    removed = harness.records("trust.removed")[-1]
    assert removed.data["grant_id"] == grant.id and removed.actor == ADMIN
