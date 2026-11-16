"""Device authorization: unknown devices wait; an operator's approval lets one in."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

from factories import flash_drive, storage_with_keyboard
from integration.harness import ADMIN, Harness
from portlock.auth.grants import GrantError
from portlock.core.models import Access, DecisionSource, Mode
from portlock.core.service import ServiceError
from portlock.core.store import ConnectionState, Outcome


def _enforcing(machine: Callable[..., Harness], **options: object) -> Harness:
    harness = machine(**options)
    harness.set_mode(Mode.ENFORCE)
    return harness


def test_an_unknown_device_waits_blocked_until_an_operator_approves_it(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    view = harness.view("test/1-1")
    assert view.state is ConnectionState.PENDING
    assert view.enforcement is not None and view.enforcement.os_state == "blocked"
    assert harness.enforcer.is_blocked("test/1-1")

    applied = harness.service.approve(view.connection_id or 0, kind="once", actor="olivia")

    after = harness.view("test/1-1")
    assert after.state is ConnectionState.ALLOWED
    assert after.decision is not None and after.decision.decision.source is DecisionSource.GRANT
    assert after.decision.decision.grant_id == applied.value.id
    assert not harness.enforcer.is_blocked("test/1-1")
    assert applied.reevaluated == (view.connection_id,)
    assert applied.value.bound_connection is not None  # once: bound to this connection
    used = harness.records("grant.used")
    assert [record.data["grant_id"] for record in used] == [applied.value.id]
    created = harness.records("grant.created")[-1]
    assert created.actor == "olivia" and created.data["grant"]["kind"] == "once"


def test_an_operator_cannot_grant_beyond_the_operator_ceiling(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    too_long = harness.clock.now() + timedelta(hours=25)
    with pytest.raises(GrantError) as refused:
        harness.service.approve(cid, kind="temporary", expires_at=too_long, actor="olivia")
    assert refused.value.code == "grant_invalid"
    assert harness.view("test/1-1").state is ConnectionState.PENDING
    # An administrator's ceiling is longer.
    harness.service.approve(cid, kind="temporary", expires_at=too_long, actor=ADMIN, role="admin")
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED


def test_a_low_confidence_device_cannot_be_trusted_but_can_be_let_in_once_on_its_port(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive(serial=None))
    cid = harness.connection_id("test/1-1")
    with pytest.raises(GrantError) as refused:
        harness.service.approve(cid, kind="trust", actor=ADMIN, role="admin")
    assert refused.value.code == "grant_low_confidence"
    grant = harness.service.approve(cid, kind="once", actor=ADMIN).value
    assert grant.bound_port == "1-1"
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED


def test_only_a_pending_connected_device_can_be_approved(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    harness.service.approve(cid, kind="trust", actor=ADMIN, role="admin")
    with pytest.raises(ServiceError) as again:
        harness.service.approve(cid, kind="once", actor=ADMIN)
    assert again.value.code == "not_pending"
    harness.unplug("test/1-1")
    with pytest.raises(ServiceError) as gone:
        harness.service.approve(cid, kind="once", actor=ADMIN)
    assert gone.value.code == "not_connected"


def test_an_operator_denial_keeps_the_device_blocked_and_can_be_overturned(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(flash_drive())
    cid = harness.connection_id("test/1-1")
    denied = harness.service.deny(cid, note="not ours", actor="olivia").value
    assert denied.state is ConnectionState.DENIED
    assert denied.resolution is not None and denied.resolution["by"] == "olivia"
    assert denied.decision is not None and denied.decision.decision.access is Access.PENDING
    assert harness.enforcer.is_blocked("test/1-1")
    record = harness.records("decision.made")[-1]
    assert record.data["resolution"] == "denied" and record.actor == "olivia"

    harness.service.approve(cid, kind="once", actor=ADMIN)
    assert harness.view("test/1-1").state is ConnectionState.ALLOWED
    assert harness.view("test/1-1").resolution is None


def test_a_badusb_shaped_device_stays_denied_whatever_is_approved(
    machine: Callable[..., Harness],
) -> None:
    harness = _enforcing(machine)
    harness.plug(storage_with_keyboard())
    view = harness.view("test/1-5")
    assert view.state is ConnectionState.DENIED
    with pytest.raises(ServiceError) as refused:
        harness.service.approve(view.connection_id or 0, kind="once", actor=ADMIN)
    assert refused.value.code == "not_pending"
    # A trust grant by fingerprint is stored, but a rule is final: still denied.
    harness.service.create_grant(view.fingerprint, "trust", actor=ADMIN, role="admin")
    after = harness.view("test/1-5")
    assert after.state is ConnectionState.DENIED
    assert after.enforcement is not None and after.enforcement.outcome is Outcome.APPLIED
    assert any(
        "a grant acts only on a pending outcome" in r for r in after.decision.decision.reasons
    )  # type: ignore[union-attr]
    assert harness.enforcer.is_blocked("test/1-5")
