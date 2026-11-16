"""Whole workflows through the HTTP API on a simulated machine in enforce mode.

The machine is ``integration.harness`` (real stores, journal and audit log, fake backend and
enforcer, fake clock); nothing here calls the service directly except to look at what the
simulated operating system was told to do. What a person or a program can do is what the
API lets them do."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from factories import flash_drive, keyboard, mouse
from integration.harness import ADMIN, ADMIN_PASSWORD
from portlock.console.api import ROUTES, ApiServer
from portlock.core.models import Mode, UsbDevice
from unit.test_console_support import OPERATOR, ApiClient, ApiRig, raw_exchange, status_of

WAIT = 10.0


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path, mode=Mode.ENFORCE)
    try:
        yield machine
    finally:
        machine.close()


def state_of(rig: ApiRig, device: UsbDevice) -> str:
    return rig.harness.view(device.instance_id).state.value


def blocked(rig: ApiRig, device: UsbDevice) -> bool:
    return rig.harness.enforcer.is_blocked(device)


def connection_id(rig: ApiRig, device: UsbDevice) -> int:
    return rig.harness.connection_id(device.instance_id)


# --- a stick nobody knows ----------------------------------------------------------------


def test_an_unknown_stick_waits_is_approved_once_and_is_pending_again_next_time(
    rig: ApiRig,
) -> None:
    operator = rig.client("operator")
    stick = rig.harness.plug(flash_drive("TEST0001ONCE"))
    assert state_of(rig, stick) == "pending" and blocked(rig, stick)  # the OS refuses it
    listed = operator.get("/devices").json["devices"]
    assert [item["state"] for item in listed] == ["pending"]
    assert listed[0]["enforcement"]["os_state"] == "blocked"
    approved = operator.post(f"/connections/{connection_id(rig, stick)}/approve", {})
    assert approved.status == 200 and not blocked(rig, stick)  # now usable
    assert approved.json["connection"]["enforcement"]["os_state"] == "open"
    rig.harness.unplug(stick.instance_id)
    again = rig.harness.plug(flash_drive("TEST0001ONCE"))
    assert state_of(rig, again) == "pending" and blocked(rig, again)  # the one-time grant was used
    grants = operator.get("/grants", query={"include_inactive": "true"}).json["grants"]
    assert [(g["kind"], g["end_reason"]) for g in grants] == [("once", "used")]


def test_a_temporary_grant_ends_by_itself_and_the_device_is_taken_away(rig: ApiRig) -> None:
    admin = rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0002TIME"))
    reply = admin.post(
        f"/connections/{connection_id(rig, stick)}/approve",
        {"kind": "temporary", "expires_in": "1h", "read_only": True},
    )
    assert reply.status == 200 and state_of(rig, stick) == "read_only"
    assert rig.harness.enforcer.is_read_only(stick) and not blocked(rig, stick)
    rig.harness.tick(59 * 60)
    assert state_of(rig, stick) == "read_only"
    rig.harness.tick(2 * 60)  # an hour and a minute: no request made
    assert state_of(rig, stick) == "pending" and blocked(rig, stick)
    admin = rig.client("admin")  # the first session idled out while the clock ran
    decisions = admin.get("/decisions", query={"connection_id": connection_id(rig, stick)}).json[
        "decisions"
    ]
    assert decisions[0]["trigger"] in ("expiry", "grant") and decisions[0]["access"] == "pending"
    assert any(
        g["end_reason"] == "expired"
        for g in admin.get("/grants", query={"include_inactive": "true"}).json["grants"]
    )


def test_trusting_a_stick_and_then_revoking_it_takes_effect_at_once(rig: ApiRig) -> None:
    admin = rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0003TRUST"))
    fingerprint = rig.harness.view(stick.instance_id).fingerprint
    trust = admin.post("/trust", {"fingerprint": fingerprint, "note": "backup drive"})
    assert trust.status == 201 and state_of(rig, stick) == "allowed" and not blocked(rig, stick)
    rig.harness.unplug(stick.instance_id)
    back = rig.harness.plug(flash_drive("TEST0003TRUST"))
    assert state_of(rig, back) == "allowed"  # remembered
    revoked = admin.delete(f"/trust/{trust.json['grant']['id']}")
    assert revoked.status == 200 and revoked.json["reevaluated"]
    assert state_of(rig, back) == "pending" and blocked(rig, back)  # before the response was sent
    detail = admin.get(f"/devices/{fingerprint}").json
    assert detail["trust"] is None and detail["connection_count"] == 2


def test_a_policy_change_over_the_api_reevaluates_every_connected_device(rig: ApiRig) -> None:
    admin = rig.client("admin")
    sticks = [
        rig.harness.plug(
            flash_drive(f"TEST004{n}POL", instance_id=f"test/4-{n}", bus_path=f"4-{n}")
        )
        for n in range(3)
    ]
    assert all(state_of(rig, stick) == "pending" for stick in sticks)
    policy = {
        "version": 1,
        "name": "lab policy",
        "default": {"access": "pending"},
        "rules": [
            {
                "id": "lab",
                "match": {"vendor_id": "0x1209"},
                "action": {"access": "read_only", "scan": "none"},
            }
        ],
    }
    reply = admin.put("/policy", {"policy": policy})
    assert reply.status == 200 and reply.json["summary"]["evaluated"] == 3
    assert all(state_of(rig, stick) == "read_only" for stick in sticks)
    assert all(rig.harness.enforcer.is_read_only(stick) for stick in sticks)
    deny = {"version": 1, "name": "closed", "default": {"access": "deny"}, "rules": []}
    assert admin.put("/policy", {"policy": deny}).status == 200
    assert all(state_of(rig, stick) == "denied" and blocked(rig, stick) for stick in sticks)
    records = [r for r in rig.runtime.audit_log.iterate() if r.event_type == "policy.changed"]
    assert [r.actor for r in records] == [ADMIN, ADMIN] and len(records) == 2


# --- lockdown, the dead-man switch and commit-confirm -------------------------------------


def test_a_lockdown_blocks_what_is_there_and_what_arrives_and_is_lifted_with_the_password(
    rig: ApiRig,
) -> None:
    operator, admin = rig.client("operator"), rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0005LOCK"))
    operator.post(
        f"/connections/{connection_id(rig, stick)}/approve",
        {"kind": "temporary", "expires_in": "8h"},
    )
    typing = rig.harness.plug(keyboard())
    assert not blocked(rig, stick)
    engaged = operator.post("/lockdown/engage", {"minutes": 30, "reason": "suspected intrusion"})
    assert engaged.status == 200
    assert operator.post(f"/changes/{engaged.json['change']['id']}/confirm").status == 200
    assert blocked(rig, stick) and state_of(rig, stick) == "denied"
    assert not blocked(rig, typing)  # the operator's keyboard is never touched
    newcomer = rig.harness.plug(flash_drive("TEST0005NEW", instance_id="test/5-9", bus_path="5-9"))
    assert blocked(rig, newcomer)
    assert rig.harness.enforcer.default_deny is True
    assert operator.post("/lockdown/lift", {"password": ADMIN_PASSWORD}).status == 403
    assert admin.post("/lockdown/lift", {"password": "nope nope nope nope"}).status == 401
    assert blocked(rig, stick)
    lifted = admin.post("/lockdown/lift", {"password": ADMIN_PASSWORD})
    assert lifted.status == 200 and not rig.harness.enforcer.default_deny
    assert not blocked(rig, stick) and state_of(rig, stick) == "allowed"
    assert blocked(rig, newcomer)  # nothing approved it: still waiting


def test_a_lockdown_that_is_not_confirmed_undoes_itself(rig: ApiRig) -> None:
    admin = rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0006UNDO"))
    admin.post(
        f"/connections/{connection_id(rig, stick)}/approve",
        {"kind": "temporary", "expires_in": "8h"},
    )
    reply = admin.post("/lockdown/engage", {"minutes": 60})
    assert reply.status == 200 and blocked(rig, stick) and rig.harness.enforcer.default_deny
    rig.harness.tick(61)  # the operator's only way in was one of the blocked devices
    assert not blocked(rig, stick) and not rig.harness.enforcer.default_deny
    assert admin.get("/lockdown").json["active"] is False
    assert admin.get("/changes").json == {"changes": []}
    late = admin.post(f"/changes/{reply.json['change']['id']}/confirm")
    assert late.status == 404 and late.error == "no_pending_change"
    types = [r.event_type for r in rig.runtime.audit_log.iterate()]
    assert "change.rolled_back" in types and "change.confirmed" not in types


def test_a_confirmed_lockdown_expires_by_itself_when_nobody_renews_it(rig: ApiRig) -> None:
    admin = rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0007DEAD"))
    admin.post(
        f"/connections/{connection_id(rig, stick)}/approve",
        {"kind": "temporary", "expires_in": "8h"},
    )
    change = admin.post("/lockdown/engage", {"minutes": 10}).json["change"]["id"]
    assert admin.post(f"/changes/{change}/confirm").status == 200
    rig.harness.tick(9 * 60)
    assert blocked(rig, stick)
    assert admin.post("/lockdown/renew", {"minutes": 10}).json["lockdown"]["renew_count"] == 1
    rig.harness.tick(9 * 60)
    assert blocked(rig, stick)  # renewed: still on
    rig.harness.tick(2 * 60)  # the dead-man timer runs out
    assert admin.get("/lockdown").json["active"] is False and not blocked(rig, stick)
    assert any(r.event_type == "lockdown.expired" for r in rig.runtime.audit_log.iterate())


def test_the_mode_can_be_changed_and_changed_back_without_leaving_anything_behind(
    rig: ApiRig,
) -> None:
    admin = rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0008MODE"))
    assert blocked(rig, stick)
    assert admin.put("/mode", {"mode": "monitor"}).status == 200
    assert not blocked(rig, stick) and admin.get("/mode").json["effective_mode"] == "monitor"
    reply = admin.put("/mode", {"mode": "enforce"})
    assert reply.json["change"]["kind"] == "enforce_mode"
    assert admin.post(f"/changes/{reply.json['change']['id']}/confirm").status == 200
    assert blocked(rig, stick) and admin.get("/mode").json["effective_mode"] == "enforce"


# --- the process restarts ------------------------------------------------------------------


def test_after_a_restart_sessions_grants_and_the_audit_chain_carry_on(rig: ApiRig) -> None:
    admin_token = rig.token("admin")
    admin = ApiClient(rig.port, admin_token)
    stick = rig.harness.plug(flash_drive("TEST0009BOOT"))
    fingerprint = rig.harness.view(stick.instance_id).fingerprint
    assert admin.post("/trust", {"fingerprint": fingerprint}).status == 201
    before = admin.get("/ping", token=None).json["run_id"]
    head = admin.get("/audit", query={"limit": 1}).json["head"]
    rig.server.stop()
    rig.harness.restart()
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0)
    server.start()
    try:
        client = ApiClient(server.port, admin_token)  # the same bearer token
        assert client.get("/auth/session").status == 200
        assert client.get("/ping", token=None).json["run_id"] != before
        assert [view["state"] for view in client.get("/devices").json["devices"]] == ["allowed"]
        assert client.get("/trust").json["trust"][0]["fingerprint"] == fingerprint
        verify = client.post("/audit/verify", {"expected_head": head}).json
        assert verify["ok"] is True and verify["head"]["seq"] > head["seq"]
    finally:
        server.stop()
        rig.server = server  # so the fixture's close() has something to stop


# --- who may do what, and what shows up in the log ----------------------------------------


def test_an_operator_cannot_reach_what_only_an_administrator_may(rig: ApiRig) -> None:
    operator = rig.client("operator")
    stick = rig.harness.plug(flash_drive("TEST0010ESC"))
    fingerprint = rig.harness.view(stick.instance_id).fingerprint
    before = rig.runtime.audit_log.head()
    attempts = [
        operator.post("/trust", {"fingerprint": fingerprint}),
        operator.post(
            "/users",
            {"username": "mallory", "password": "a stolen passphrase 98765", "role": "admin"},
        ),
        operator.put(f"/users/{OPERATOR}/role", {"role": "admin"}),
        operator.put(
            "/policy",
            {"policy": {"version": 1, "name": "open", "default": {"access": "allow"}, "rules": []}},
        ),
        operator.put("/mode", {"mode": "monitor"}),
        operator.patch("/settings", {"scan.enabled": False}),
        operator.post("/lockdown/lift", {"password": ADMIN_PASSWORD}),
        operator.post(f"/connections/{connection_id(rig, stick)}/approve", {"kind": "trust"}),
        operator.post("/enrolments", {"connection_id": connection_id(rig, stick)}),
        operator.put("/default-deny", {"enabled": True}),
    ]
    assert [reply.status for reply in attempts] == [403] * len(attempts)
    assert rig.runtime.accounts.get_user("mallory") is None
    assert rig.runtime.accounts.get_user(OPERATOR).role.value == "operator"  # type: ignore[union-attr]
    assert (
        state_of(rig, stick) == "pending"
        and rig.harness.service.get_mode().effective_mode.value == "enforce"
    )
    after = rig.runtime.audit_log.head()
    assert after[0] == before[0]  # a refused request leaves no trace of a change


def test_an_auditor_can_read_everything_and_change_nothing(rig: ApiRig) -> None:
    auditor = rig.client("auditor")
    rig.harness.plug(flash_drive("TEST0011AUD"))
    for route in ROUTES:
        if (
            route.method != "GET"
            or route.public
            or "{" in route.pattern
            or route.pattern == "/events"
        ):
            continue
        reply = auditor.get(route.pattern)
        if route.permission is not None and route.permission.value in ("manage_users",):
            assert reply.status == 403, route.pattern
        else:
            assert reply.status == 200, (route.pattern, reply.status)
    for route in ROUTES:
        if route.method in ("POST", "PUT", "PATCH", "DELETE") and not route.public:
            if route.pattern in (
                "/auth/logout",
                "/auth/password",
                "/policy/validate",
                "/policy/test",
                "/audit/verify",
                "/users/{username}/recovery-codes",
            ):
                continue  # these act only on the caller's own session or change nothing
            path = route.pattern.replace("{connection_id}", "1").replace("{grant_id}", "0" * 32)
            path = path.replace("{fingerprint}", "plk1:" + "a" * 32).replace(
                "{change_id}", "0" * 16
            )
            path = path.replace("{username}", ADMIN).replace("{scan_id}", "1")
            if route.pattern.startswith("/changes/"):
                continue  # needs a real pending change: below
            reply = auditor.request(route.method, path, {} if route.method != "DELETE" else None)
            assert reply.status == 403, (route.method, route.pattern, reply.status)
    change = rig.client("operator").post("/lockdown/engage", {}).json["change"]["id"]
    for action in ("confirm", "cancel"):
        reply = auditor.post(f"/changes/{change}/{action}", {})
        assert reply.status == 403 and reply.json["error"]["details"] == {
            "permission": "engage_lockdown"
        }
    assert rig.harness.service.pending_changes()  # still waiting, untouched
    admin = rig.client("admin")
    assert admin.post(f"/changes/{change}/cancel").status == 200


def test_every_change_made_through_the_api_is_in_the_audit_log_under_the_callers_name(
    rig: ApiRig,
) -> None:
    operator, admin = rig.client("operator"), rig.client("admin")
    stick = rig.harness.plug(flash_drive("TEST0012LOG"))
    other = rig.harness.plug(flash_drive("TEST0012OTH", instance_id="test/12-2", bus_path="12-2"))
    fingerprint = rig.harness.view(stick.instance_id).fingerprint
    operator.post(f"/connections/{connection_id(rig, stick)}/approve", {"note": "for the audit"})
    operator.post(f"/connections/{connection_id(rig, other)}/deny", {"note": "no"})
    trust = admin.post("/trust", {"fingerprint": fingerprint}).json["grant"]["id"]
    admin.delete(f"/trust/{trust}")
    admin.post(
        "/users", {"username": "newcomer", "password": "a fresh passphrase 4321", "role": "auditor"}
    )
    admin.put("/mode", {"mode": "monitor"})
    records = list(rig.runtime.audit_log.iterate())
    by_actor: dict[str, set[str]] = {}
    for record in records:
        if record.actor:
            by_actor.setdefault(record.actor, set()).add(record.event_type)
    assert {"grant.created", "decision.made"} <= by_actor[OPERATOR]
    assert {"trust.added", "trust.removed", "auth.user_created", "mode.changed"} <= by_actor[ADMIN]
    approved = next(r for r in records if r.event_type == "grant.created" and r.actor == OPERATOR)
    assert approved.device_fp == fingerprint
    text = " ".join(str(r.to_dict()) for r in records)
    assert "a fresh passphrase 4321" not in text and ADMIN_PASSWORD not in text


def test_two_operators_cannot_both_approve_the_same_device(rig: ApiRig) -> None:
    stick = rig.harness.plug(flash_drive("TEST0013RACE"))
    path = f"/connections/{connection_id(rig, stick)}/approve"
    clients = [rig.client("operator") for _ in range(2)]
    barrier = threading.Barrier(2)
    replies: list[Any] = []

    def approve(client: ApiClient) -> None:
        barrier.wait(WAIT)
        replies.append(client.post(path, {"kind": "temporary", "expires_in": "1h"}))

    threads = [threading.Thread(target=approve, args=(client,)) for client in clients]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WAIT)
    assert sorted(reply.status for reply in replies) == [200, 409]
    assert [reply.error for reply in replies if reply.status == 409] == ["not_pending"]
    assert len(rig.client().get("/grants").json["grants"]) == 1


def test_a_page_that_resolves_its_own_name_to_the_loopback_address_gets_nothing(
    rig: ApiRig,
) -> None:
    token = rig.token("admin")
    stick = rig.harness.plug(flash_drive("TEST0014REB"))
    request = (
        f"GET /api/v1/devices HTTP/1.1\r\nHost: attacker.example:{rig.port}\r\n"
        f"Authorization: Bearer {token}\r\nOrigin: http://attacker.example:{rig.port}\r\n\r\n"
    ).encode()
    raw = raw_exchange(rig.port, request)
    assert status_of(raw) == 421 and stick.serial and stick.serial.encode() not in raw
    forged = ApiClient(rig.port, token).get(
        "/devices", headers={"Origin": "http://attacker.example"}
    )
    assert forged.status == 403 and stick.serial and stick.serial.encode() not in forged.body


def test_a_lot_of_devices_and_requests_at_once(rig: ApiRig) -> None:
    admin = rig.client("admin")
    sticks = [
        rig.harness.plug(mouse(instance_id=f"test/9-{n}", product=f"Mouse {n}", bus_path=f"9-{n}"))
        for n in range(12)
    ]
    assert all(state_of(rig, stick) == "protected" for stick in sticks)
    results: list[int] = []

    def read() -> None:
        results.append(admin.get("/devices").status)
        results.append(admin.get("/status").status)

    threads = [threading.Thread(target=read) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WAIT)
    assert results == [200] * 32
    assert len(admin.get("/devices").json["devices"]) == 12
