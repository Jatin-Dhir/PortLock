"""Every endpoint of ``docs/API.md``: the role that is allowed and the role that is refused,
one success and the failures that matter, against a real server on a simulated machine.

The route table is checked against the document (every route is in section 8 and the other
way round), the role matrix is driven from the table and from ``auth.accounts.can``, and
each endpoint is then exercised with real devices on the fake backend."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from test_console_support import AUDITOR, OPERATOR, ApiClient, ApiRig, Reply

from factories import flash_drive, keyboard
from integration.harness import ADMIN, ADMIN_PASSWORD, START, StubScanner, with_volume
from portlock.auth.accounts import Permission, can
from portlock.console.api import ROUTES, Route
from portlock.core.canonical import parse_canonical
from portlock.core.clock import FakeClock
from portlock.core.models import UsbDevice
from portlock.lockdown.manager import Credential
from portlock.policy import DEFAULT_POLICY, policy_to_dict

DOCS = Path(__file__).resolve().parents[2] / "docs" / "API.md"
FP = "plk1:" + "a" * 32
HEX32 = "0" * 32
HEX16 = "0" * 16
SAMPLE = {
    "connection_id": "999999",
    "scan_id": "999999",
    "fingerprint": FP,
    "grant_id": HEX32,
    "change_id": HEX16,
    "username": "nobody-here",
}


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ApiRig]:
    clock = FakeClock(START)
    machine = ApiRig(tmp_path_factory.mktemp("endpoints"), clock=clock, scanner=StubScanner(clock))
    try:
        yield machine
    finally:
        machine.close()


@pytest.fixture
def plug(rig: ApiRig) -> Iterator[Callable[..., UsbDevice]]:
    """Plug in synthetic devices (unique ones); they are unplugged when the test ends."""
    plugged: list[str] = []
    counter = [len(rig.harness.service.list_connections(open_only=False, limit=500))]

    def make(device: UsbDevice | None = None, **overrides: Any) -> UsbDevice:
        counter[0] += 1
        n = counter[0]
        fields: dict[str, Any] = {
            "instance_id": f"test/7-{n}",
            "serial": f"TEST07{n:05d}",
            "product_id": 0x0100 + n,
            "bus_path": f"7-{n}",
        }
        fields.update(overrides)
        built = device if device is not None else flash_drive(**fields)
        result = rig.harness.plug(built)
        plugged.append(result.instance_id)
        return result

    yield make
    for instance_id in plugged:
        if rig.harness.backend.is_present(instance_id):
            rig.harness.unplug(instance_id)
    rig.harness.service.tick()


def cid(rig: ApiRig, device: UsbDevice) -> int:
    return rig.harness.connection_id(device.instance_id)


def fingerprint(rig: ApiRig, device: UsbDevice) -> str:
    return rig.harness.view(device.instance_id).fingerprint


def clean_lockdown(rig: ApiRig) -> None:
    status = rig.runtime.service.lockdown_status()
    for change in rig.runtime.service.pending_changes():
        rig.runtime.service.cancel_change(change.id, actor=ADMIN)
    if rig.runtime.service.lockdown_status().active:
        rig.runtime.service.lockdown_lift(
            actor=ADMIN, credential=Credential("password", ADMIN_PASSWORD)
        )
    assert not status.active or not rig.runtime.service.lockdown_status().active


@pytest.fixture
def lockdown_cleanup(rig: ApiRig) -> Iterator[None]:
    yield
    clean_lockdown(rig)


# --- the route table and the document -----------------------------------------------------


def documented_routes() -> set[tuple[str, str]]:
    text = DOCS.read_text(encoding="utf-8")
    index = text[text.index("## 8. Endpoint index") :]
    return {
        (method, path)
        for method, path in re.findall(r"^\| ([A-Z]+) \| `(/[^`]*)` \|", index, re.MULTILINE)
    }


def test_every_route_is_documented_and_every_documented_route_exists() -> None:
    in_code = {(route.method, route.pattern) for route in ROUTES}
    in_docs = documented_routes()
    assert in_code - in_docs == set(), "routes missing from docs/API.md section 8"
    assert in_docs - in_code == set(), "documented routes that do not exist"
    assert len(in_code) == len(ROUTES), "a route is listed twice"


def test_every_documented_route_has_a_section_in_the_document() -> None:
    text = DOCS.read_text(encoding="utf-8")
    body = text[: text.index("## 8. Endpoint index")]
    for method, path in sorted(documented_routes()):
        assert re.search(rf"`{method} {re.escape(path)}`", body), (
            f"{method} {path} is not described"
        )


def test_every_route_says_who_may_call_it() -> None:
    open_to_any_session = {
        ("POST", "/auth/logout"),
        ("GET", "/auth/session"),
        ("POST", "/auth/password"),
        ("POST", "/users/{username}/recovery-codes"),
    }
    without = {
        (route.method, route.pattern)
        for route in ROUTES
        if route.permission is None and not route.public
    }
    assert without == open_to_any_session
    assert {(r.method, r.pattern) for r in ROUTES if r.public} == {
        ("GET", "/ping"),
        ("POST", "/auth/login"),
        ("POST", "/auth/recovery"),
    }
    # Everything that changes state needs more than "view" (policy test and validate only read).
    reads_by_post = {"/policy/validate", "/policy/test"}
    for route in ROUTES:
        if route.method != "GET" and route.permission is Permission.VIEW:
            assert route.pattern in reads_by_post | {
                "/changes/{change_id}/confirm",
                "/changes/{change_id}/cancel",
            }
    for route in ROUTES:
        if route.method in ("POST", "PUT", "PATCH", "DELETE") and route.pattern.startswith(
            "/changes/"
        ):
            assert (
                route.refine is not None
            )  # the permission of the change, checked after it is found


def path_for(route: Route) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: SAMPLE[m.group(1)], route.pattern)


ROLE_ROUTES = [route for route in ROUTES if not route.public]


@pytest.mark.parametrize("route", ROLE_ROUTES, ids=lambda r: f"{r.method} {r.pattern}")
def test_the_role_matrix_every_role_without_the_permission_is_refused_before_anything_happens(
    rig: ApiRig, route: Route
) -> None:
    path = path_for(route)
    anonymous = ApiClient(rig.port).request(
        route.method, path, {"x": 1} if route.method != "GET" else None
    )
    assert anonymous.status == 401 and anonymous.error == "unauthenticated"
    for role in ("admin", "operator", "auditor"):
        client = rig.client(role)
        # An unknown member makes every body-taking route answer 400 before it acts, so
        # an allowed role can never change anything here; a refused role gets 403.
        body = {"__probe__": 1} if route.method in ("POST", "PUT", "PATCH") else None
        if route.pattern == "/events" and can(role, Permission.VIEW):
            continue  # an allowed role opens a stream that does not end: tested on its own
        reply = client.request(route.method, path, body)
        if route.permission is not None and not can(role, route.permission):
            assert reply.status == 403, (role, reply.json)
            assert reply.error == "forbidden"
            assert reply.json["error"]["details"] == {"permission": route.permission.value}
        elif route.refine is not None and role != "admin":
            # Permissions that depend on the request are checked after the body is parsed.
            assert reply.status not in (401, 405, 500), (role, reply.status, reply.json)
        else:
            assert reply.status not in (401, 403, 405, 500), (role, reply.status, reply.json)


# --- status, doctor, settings and the small getters --------------------------------------


def test_status_is_the_services_snapshot(rig: ApiRig) -> None:
    data = rig.client().get("/status").json
    assert data["service"] == "portlock" and data["simulation"] is False
    assert data["mode"]["effective_mode"] == "monitor"
    assert data["lockdown"]["state"] == "idle" and data["setup_required"] is False
    assert set(data["counts"]) == {
        "connected",
        "protected",
        "allowed",
        "read_only",
        "pending",
        "denied",
        "not_enforced",
    }
    assert set(data["audit"]) >= {"head_seq", "head_hash", "keyed", "backlog", "sink_failures"}
    assert rig.client("auditor").get("/status").status == 200


def test_doctor_settings_mode_scope_and_default_deny_can_be_read_by_everyone(rig: ApiRig) -> None:
    for role in ("admin", "operator", "auditor"):
        client = rig.client(role)
        doctor = client.get("/doctor").json
        assert doctor["worst"] in ("ok", "warn", "fail") and doctor["checks"]
        assert any(check["id"].startswith("service.") for check in doctor["checks"])
        settings = client.get("/settings").json
        assert set(settings) == {"config", "runtime", "effective"}
        assert (
            settings["runtime"]["scope"] == "storage"
            and settings["runtime"]["default_deny"] is False
        )
        assert client.get("/mode").json["mode"] == "monitor"
        assert client.get("/scope").json == {
            "scope": "storage",
            "scopes": ["storage", "storage_and_unknown", "all_except_protected"],
        }
        assert client.get("/default-deny").json == {"enabled": False}


def test_the_doctor_report_has_no_serial_numbers(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    text = rig.client().get("/doctor").body.decode()
    assert device.serial is not None and device.serial not in text
    assert device.instance_id not in text


# --- devices, connections, decisions ----------------------------------------------------


def test_the_device_lists(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    first, second = plug(), plug()
    client = rig.client()
    listed = client.get("/devices").json["devices"]
    ids = [item["connection_id"] for item in listed]
    assert ids == sorted(ids)  # oldest connection first
    mine = [
        item
        for item in listed
        if item["device"]["instance_id"] in (first.instance_id, second.instance_id)
    ]
    assert [item["state"] for item in mine] == ["pending", "pending"]
    assert client.get("/devices", query={"state": "pending"}).json["devices"]
    assert all(
        item["state"] == "allowed"
        for item in client.get("/devices", query={"state": "allowed"}).json["devices"]
    )
    page = client.get("/devices/history", query={"limit": 1}).json
    assert len(page["connections"]) == 1 and page["next"] == page["connections"][0]["connection_id"]
    older = client.get("/devices/history", query={"limit": 1, "before_id": page["next"]}).json
    assert older["connections"][0]["connection_id"] < page["next"]
    open_only = client.get("/devices/history", query={"open": "true", "limit": 500}).json[
        "connections"
    ]
    assert open_only and all(item["removed_at"] is None for item in open_only)
    rig.harness.unplug(second.instance_id)
    closed = client.get("/devices/history", query={"open": "false", "limit": 500}).json[
        "connections"
    ]
    assert closed and all(item["removed_at"] is not None for item in closed)
    by_fp = client.get("/devices/history", query={"fingerprint": fingerprint(rig, first)}).json
    assert {item["fingerprint"] for item in by_fp["connections"]} == {fingerprint(rig, first)}


def test_known_devices_are_paged_by_fingerprint_and_searchable(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug(product="Needle in a Haystack Drive")
    client = rig.client()
    found = client.get("/devices/known", query={"text": "Needle in a Haystack"}).json["devices"]
    assert [item["fingerprint"] for item in found] == [fingerprint(rig, device)]
    assert found[0]["connected"] is True and found[0]["trust"] is None
    page = client.get("/devices/known", query={"limit": 1}).json
    assert len(page["devices"]) == 1 and page["next"] == page["devices"][0]["fingerprint"]
    following = client.get("/devices/known", query={"limit": 1, "before": page["next"]}).json
    assert following["devices"][0]["fingerprint"] != page["next"]
    assert client.get("/devices/known", query={"before": "nope"}).status == 400


def test_a_device_and_a_connection_in_detail(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug()
    client = rig.client("auditor")
    fp = fingerprint(rig, device)
    detail = client.get(f"/devices/{fp}").json
    assert detail["fingerprint"] == fp and detail["connected"] is True
    assert detail["connections"] and detail["decisions"] and detail["grants"] == []
    connection = client.get(f"/connections/{cid(rig, device)}").json
    assert connection["connection"]["state"] == "pending"
    assert connection["decisions"] and connection["scans"] == []
    assert client.get(f"/devices/{FP}").error == "not_found"
    assert client.get("/connections/999999").error == "not_found"


def test_decisions_can_be_filtered(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug()
    client = rig.client()
    mine = client.get("/decisions", query={"connection_id": cid(rig, device)}).json
    assert mine["decisions"] and all(item["access"] == "pending" for item in mine["decisions"])
    assert "connection_id" not in mine["decisions"][0]
    by_fp = client.get(
        "/decisions", query={"fingerprint": fingerprint(rig, device), "access": "pending"}
    ).json
    assert by_fp["decisions"]
    assert (
        client.get("/decisions", query={"access": "deny", "limit": 500}).json["decisions"]
        is not None
    )
    page = client.get("/decisions", query={"limit": 1}).json
    assert page["next"] == page["decisions"][0]["id"]
    assert client.get("/decisions", query={"access": "maybe"}).status == 400


# --- approving and denying ---------------------------------------------------------------


def test_an_operator_approves_a_pending_device_once(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    reply = rig.client("operator").post(f"/connections/{cid(rig, device)}/approve", {})
    assert reply.status == 200
    body = reply.json
    assert body["grant"]["kind"] == "once" and body["grant"]["granted_by"] == OPERATOR
    assert body["connection"]["state"] == "allowed" and body["reevaluated"] == [
        body["connection"]["connection_id"]
    ]
    again = rig.client("operator").post(f"/connections/{cid(rig, device)}/approve", {})
    assert again.status == 409 and again.error == "not_pending"


def test_approval_permissions_follow_the_kind(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug()
    path = f"/connections/{cid(rig, device)}/approve"
    operator, auditor, admin = rig.client("operator"), rig.client("auditor"), rig.client("admin")
    assert auditor.post(path, {}).error == "forbidden"
    denied = operator.post(path, {"kind": "trust"})
    assert denied.status == 403 and denied.json["error"]["details"] == {
        "permission": "manage_trust"
    }
    temporary = operator.post(
        path, {"kind": "temporary", "expires_in": "2h", "read_only": True, "note": "backup"}
    )
    assert temporary.status == 200
    assert temporary.json["connection"]["state"] == "read_only"
    grant = temporary.json["grant"]
    assert grant["kind"] == "temporary" and grant["read_only"] is True and grant["note"] == "backup"
    assert grant["expires_at"] == "2026-03-02T11:00:00.000000Z"
    other = plug()
    trusted = admin.post(
        f"/connections/{cid(rig, other)}/approve", {"kind": "trust", "note": "mine"}
    )
    assert trusted.status == 200 and trusted.json["grant"]["expires_at"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"kind": "trust", "expires_in": "2h"},
        {"kind": "temporary"},
        {"kind": "temporary", "expires_in": "2h", "expires_at": "2027-01-01T00:00:00Z"},
        {"kind": "temporary", "expires_in": "soon"},
        {"kind": "temporary", "expires_in": "0m"},
        {"kind": "forever"},
        {"expires_at": "yesterday"},
        {"note": "x" * 513},
        {"note": "line\nbreak"},
    ],
)
def test_an_approval_that_does_not_make_sense_is_refused(
    rig: ApiRig, plug: Callable[..., UsbDevice], body: dict[str, Any]
) -> None:
    device = plug()
    reply = rig.client().post(f"/connections/{cid(rig, device)}/approve", body)
    assert reply.status == 400 and reply.error == "invalid_request"
    assert rig.harness.view(device.instance_id).state.value == "pending"


def test_a_temporary_grant_is_limited_to_the_roles_ceiling(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    reply = rig.client("operator").post(
        f"/connections/{cid(rig, device)}/approve", {"kind": "temporary", "expires_in": "3d"}
    )
    assert reply.status == 409 and reply.error == "grant_invalid"


def test_a_device_without_a_unique_serial_can_never_be_trusted_but_can_be_approved_by_port(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug(serial=None, product="Serial-less stick")
    path = f"/connections/{cid(rig, device)}/approve"
    refused = rig.client().post(path, {"kind": "trust"})
    assert refused.status == 409 and refused.error == "low_confidence"
    assert "one-time grant" in refused.json["error"]["message"]
    assert rig.client().post(path, {"kind": "trust", "allow_low_confidence": True}).status == 400
    once = rig.client().post(path, {})
    assert once.status == 200 and once.json["grant"]["confidence"] == "low"
    assert once.json["grant"]["bound_port"] == device.bus_path


def test_a_denial_is_recorded_and_a_denied_device_can_still_be_approved(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    path = f"/connections/{cid(rig, device)}"
    assert rig.client("auditor").post(path + "/deny", {}).status == 403
    reply = rig.client("operator").post(
        path + "/deny", {"note": "found in the car park", "eject": False}
    )
    assert reply.status == 200
    connection = reply.json["connection"]
    assert connection["state"] == "denied" and reply.json["eject"] is None
    assert (
        connection["resolution"]["by"] == OPERATOR
        and connection["resolution"]["note"] == "found in the car park"
    )
    assert rig.client("operator").post(path + "/deny", {}).error == "not_pending"
    approved = rig.client("operator").post(path + "/approve", {})
    assert approved.status == 200 and approved.json["connection"]["state"] == "allowed"


def test_a_denial_may_ask_for_an_eject(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug()
    reply = rig.client().post(f"/connections/{cid(rig, device)}/deny", {"eject": True})
    assert reply.status == 200 and reply.json["eject"]["ok"] is True


def test_approving_or_denying_something_that_is_not_there(rig: ApiRig) -> None:
    for action in ("approve", "deny"):
        reply = rig.client().post(f"/connections/999999/{action}", {})
        assert reply.status == 409 and reply.error == "not_connected"
    gone = flash_drive("TEST0799GONE", instance_id="test/7-799", bus_path="7-799")
    rig.harness.plug(gone)
    connection = rig.harness.connection_id(gone.instance_id)
    rig.harness.unplug(gone.instance_id)
    assert rig.client().post(f"/connections/{connection}/approve", {}).error == "not_connected"


def test_a_protected_device_is_not_pending(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug(keyboard(instance_id="test/7-900", bus_path="7-900"))
    reply = rig.client().post(f"/connections/{cid(rig, device)}/approve", {})
    assert reply.status == 409 and reply.error == "not_pending"
    assert rig.harness.view(device.instance_id).state.value == "protected"


# --- trust and grants ---------------------------------------------------------------------


def test_trust_is_added_listed_and_removed(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug()
    fp = fingerprint(rig, device)
    admin = rig.client("admin")
    assert rig.client("operator").post("/trust", {"fingerprint": fp}).error == "forbidden"
    added = admin.post("/trust", {"fingerprint": fp, "read_only": True, "note": "backup drive"})
    assert added.status == 201
    grant = added.json["grant"]
    assert grant["kind"] == "trust" and grant["read_only"] is True and added.json["reevaluated"]
    assert rig.harness.view(device.instance_id).state.value == "read_only"
    listed = rig.client("auditor").get("/trust").json["trust"]
    assert grant["id"] in [item["id"] for item in listed]
    assert rig.client("operator").delete(f"/trust/{grant['id']}").error == "forbidden"
    removed = admin.delete(f"/trust/{grant['id']}")
    assert removed.status == 200
    assert (
        removed.json["grant"]["end_reason"] == "revoked"
        and removed.json["grant"]["ended_by"] == ADMIN
    )
    assert rig.harness.view(device.instance_id).state.value == "pending"
    assert admin.delete(f"/trust/{grant['id']}").error == "not_found"
    assert grant["id"] not in [item["id"] for item in admin.get("/trust").json["trust"]]


def test_trust_for_an_unknown_or_ambiguous_device_is_refused(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    admin = rig.client("admin")
    assert admin.post("/trust", {"fingerprint": FP}).error == "unknown_device"
    device = plug(serial=None, product="Another serial-less stick")
    fp = fingerprint(rig, device)
    refused = admin.post("/trust", {"fingerprint": fp})
    assert refused.status == 409 and refused.error == "low_confidence"
    plain = admin.post("/grants", {"fingerprint": fp, "kind": "temporary", "expires_in": "1h"})
    assert plain.status == 409 and plain.error == "low_confidence"
    limited = admin.post(
        "/grants",
        {"fingerprint": fp, "kind": "temporary", "expires_in": "1h", "allow_low_confidence": True},
    )
    assert limited.status == 201 and limited.json["grant"]["bound_port"] == device.bus_path
    too_long = admin.post(
        "/grants",
        {"fingerprint": fp, "kind": "temporary", "expires_in": "3d", "allow_low_confidence": True},
    )
    assert too_long.status == 409 and too_long.error == "low_confidence"


def test_a_trust_id_is_not_a_grant_for_the_trust_endpoint(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    temp = rig.client().post(
        "/grants",
        {"fingerprint": fingerprint(rig, device), "kind": "temporary", "expires_in": "1h"},
    )
    assert temp.status == 201
    assert rig.client().delete(f"/trust/{temp.json['grant']['id']}").error == "not_found"


def test_grants_are_issued_listed_and_revoked_by_the_roles_that_may(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    fp = fingerprint(rig, device)
    operator, admin, auditor = rig.client("operator"), rig.client("admin"), rig.client("auditor")
    assert auditor.post("/grants", {"fingerprint": fp, "kind": "once"}).error == "forbidden"
    assert operator.post("/grants", {"fingerprint": fp, "kind": "trust"}).status == 400
    created = operator.post(
        "/grants",
        {
            "fingerprint": fp,
            "kind": "temporary",
            "expires_in": "2h",
            "read_only": True,
            "note": "n",
        },
    )
    assert created.status == 201 and created.json["grant"]["granted_by"] == OPERATOR
    assert created.json["reevaluated"]
    grant_id = created.json["grant"]["id"]
    assert [g["id"] for g in auditor.get("/grants", query={"fingerprint": fp}).json["grants"]] == [
        grant_id
    ]
    assert auditor.get("/grants", query={"kind": "once"}).json["grants"] == [] or all(
        g["kind"] == "once" for g in auditor.get("/grants", query={"kind": "once"}).json["grants"]
    )
    revoked = operator.delete(f"/grants/{grant_id}")
    assert revoked.status == 200 and revoked.json["grant"]["end_reason"] == "revoked"
    assert operator.delete(f"/grants/{grant_id}").error == "not_found"
    inactive = auditor.get("/grants", query={"include_inactive": "true", "fingerprint": fp}).json[
        "grants"
    ]
    assert grant_id in [g["id"] for g in inactive]
    assert grant_id not in [
        g["id"] for g in auditor.get("/grants", query={"fingerprint": fp}).json["grants"]
    ]
    trust = admin.post("/trust", {"fingerprint": fp}).json["grant"]["id"]
    forbidden = operator.delete(f"/grants/{trust}")
    assert forbidden.status == 403 and forbidden.json["error"]["details"] == {
        "permission": "manage_trust"
    }
    assert admin.delete(f"/grants/{trust}").status == 200


def test_a_grant_for_a_device_never_seen_is_refused(rig: ApiRig) -> None:
    reply = rig.client().post("/grants", {"fingerprint": FP, "kind": "once"})
    assert reply.status == 409 and reply.error == "unknown_device"
    assert rig.client().post("/grants", {"fingerprint": FP, "kind": "temporary"}).status == 400


def test_a_grant_for_a_device_that_is_not_connected_applies_when_it_arrives(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    fp = fingerprint(rig, device)
    rig.harness.unplug(device.instance_id)
    created = rig.client().post(
        "/grants", {"fingerprint": fp, "kind": "temporary", "expires_in": "1h"}
    )
    assert created.status == 201 and created.json["reevaluated"] == []
    again = plug(device)
    assert rig.harness.view(again.instance_id).state.value == "allowed"


# --- enrolments and held ports -----------------------------------------------------------


def test_enrolment_protects_an_input_device_on_its_port(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug(keyboard(instance_id="test/7-901", bus_path="7-901", product="Enrolled Keyboard"))
    fp = fingerprint(rig, device)
    admin = rig.client("admin")
    assert (
        rig.client("operator").post("/enrolments", {"connection_id": cid(rig, device)}).error
        == "forbidden"
    )
    created = admin.post("/enrolments", {"connection_id": cid(rig, device), "label": "my keyboard"})
    assert created.status == 201
    assert (
        created.json["enrolment"]["fingerprint"] == fp
        and created.json["enrolment"]["bus_path"] == "7-901"
    )
    assert created.json["enrolment"]["label"] == "my keyboard"
    listed = rig.client("auditor").get("/enrolments").json["enrolments"]
    assert [item["fingerprint"] for item in listed] == [fp]
    removed = admin.delete(f"/enrolments/{fp}", query={"bus_path": "7-901"})
    assert removed.status == 200 and removed.json["removed"] == 1
    assert admin.delete(f"/enrolments/{fp}").error == "not_found"
    assert rig.client().post("/enrolments", {"connection_id": 999999}).error == "not_connected"
    assert rig.client().post("/enrolments", {"connection_id": 0}).status == 400


def test_a_held_port_can_be_released_by_an_administrator(rig: ApiRig) -> None:
    assert rig.client().post("/ports/release", {"port": "7-950"}).error == "not_found"
    for _ in range(7):
        stick = flash_drive("TEST0795FLAP", instance_id="test/7-950", bus_path="7-950")
        rig.harness.plug(stick)
        rig.harness.unplug(stick.instance_id)
    again = rig.harness.plug(
        flash_drive("TEST0795FLAP", instance_id="test/7-950", bus_path="7-950")
    )
    try:
        assert rig.client("operator").post("/ports/release", {"port": "7-950"}).error == "forbidden"
        released = rig.client().post("/ports/release", {"port": "7-950"})
        assert released.status == 200 and released.json["released"] is True
    finally:
        rig.harness.unplug(again.instance_id)


# --- policy -------------------------------------------------------------------------------

SITE_POLICY = {
    "version": 1,
    "name": "site policy",
    "default": {"access": "pending"},
    "rules": [
        {
            "id": "lab",
            "match": {"vendor_id": "0x1209", "confidence": "high"},
            "action": {"access": "read_only", "scan": "none"},
        }
    ],
}


@pytest.fixture
def default_policy(rig: ApiRig) -> Iterator[None]:
    yield
    rig.client().put("/policy", {"policy": policy_to_dict(DEFAULT_POLICY)})


def test_the_policy_can_be_read_by_everyone(rig: ApiRig) -> None:
    for role in ("admin", "operator", "auditor"):
        data = rig.client(role).get("/policy").json
        assert data["name"] == DEFAULT_POLICY.name and data["rules"] == 1
        assert (
            data["policy"]["rules"][0]["id"] == "deny-input-with-other" and len(data["hash"]) == 64
        )


def test_a_policy_draft_is_validated_without_changing_anything(rig: ApiRig) -> None:
    client = rig.client("auditor")
    before = client.get("/policy").json["hash"]
    good = client.post("/policy/validate", {"policy": SITE_POLICY}).json
    assert good["valid"] is True and good["problems"] == [] and len(good["hash"]) == 64
    bad = client.post(
        "/policy/validate",
        {
            "policy": {
                "version": 1,
                "name": "x",
                "default": {"access": "pending"},
                "rules": [
                    {"id": "r1", "match": {"vendor_id": "0xZZZZ"}, "action": {"access": "allow"}}
                ],
            }
        },
    ).json
    assert bad["valid"] is False and bad["hash"] is None
    assert bad["problems"][0].startswith("rules[0].match.vendor_id")
    assert client.get("/policy").json["hash"] == before
    assert client.post("/policy/validate", {}).status == 400
    assert client.post("/policy/validate", {"policy": "nope"}).status == 400


def test_the_policy_is_replaced_atomically_and_devices_are_reevaluated(
    rig: ApiRig, plug: Callable[..., UsbDevice], default_policy: None
) -> None:
    device = plug()
    admin = rig.client("admin")
    assert rig.client("operator").put("/policy", {"policy": SITE_POLICY}).error == "forbidden"
    current = admin.get("/policy").json["hash"]
    stale = admin.put("/policy", {"policy": SITE_POLICY, "expected_hash": "0" * 64})
    assert stale.status == 409 and stale.error == "policy_conflict"
    assert stale.json["error"]["details"] == {"hash": current}
    reply = admin.put("/policy", {"policy": SITE_POLICY, "expected_hash": current})
    assert reply.status == 200
    body = reply.json
    assert (
        body["name"] == "site policy"
        and body["previous_hash"] == current
        and body["source"] == "file"
    )
    assert body["summary"]["evaluated"] >= 1 and body["hash"] != current
    assert rig.harness.view(device.instance_id).state.value == "read_only"
    assert admin.get("/policy").json["hash"] == body["hash"]
    changed = [r for r in rig.runtime.audit_log.iterate() if r.event_type == "policy.changed"]
    assert changed and changed[-1].actor == ADMIN


def test_an_invalid_policy_is_refused_with_the_location_of_every_fault(rig: ApiRig) -> None:
    broken = {
        "version": 1,
        "name": "x",
        "default": {"access": "pending"},
        "rules": [
            {"id": "a", "match": {"vendor_id": "0xZZZZ"}, "action": {"access": "allow"}},
            {"id": "a", "match": {}, "action": {"access": "nope"}},
        ],
    }
    reply = rig.client().put("/policy", {"policy": broken})
    assert reply.status == 400 and reply.error == "policy_invalid"
    problems = reply.json["error"]["details"]["problems"]
    assert len(problems) >= 2 and all(isinstance(item, str) for item in problems)
    assert (
        rig.client().put("/policy", {"policy": SITE_POLICY, "expected_hash": "short"}).status == 400
    )


def test_what_would_the_policy_do(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    client = rig.client("auditor")
    device = {
        "vendor_id": 4617,
        "product_id": 5,
        "serial": "TEST0005BAD1",
        "product": "Example Flash 16GB",
        "interfaces": [
            {"cls": 8, "subcls": 6, "protocol": 80},
            {"cls": 3, "subcls": 1, "protocol": 1},
        ],
        "removable": True,
    }
    result = client.post("/policy/test", {"device": device}).json
    assert (
        result["decision"]["access"] == "deny" and result["matched_rule"] == "deny-input-with-other"
    )
    assert result["decision"]["alert"] is True and result["explain"][0]["outcome"] == "matched"
    assert result["confidence"] == "high" and result["fingerprint"].startswith("plk1:")
    stick = plug()
    by_connection = client.post("/policy/test", {"connection_id": cid(rig, stick)}).json
    by_fingerprint = client.post("/policy/test", {"fingerprint": fingerprint(rig, stick)}).json
    assert by_connection["decision"]["access"] == by_fingerprint["decision"]["access"] == "pending"
    assert by_connection["matched_default"] is True
    draft = client.post(
        "/policy/test", {"connection_id": cid(rig, stick), "policy": SITE_POLICY}
    ).json
    assert draft["decision"]["access"] == "read_only" and draft["matched_rule"] == "lab"
    assert draft["policy_hash"] != by_connection["policy_hash"]
    later = client.post("/policy/test", {"device": device, "at": "2030-01-01T00:00:00Z"})
    assert later.status == 200


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({}, 400, "invalid_request"),
        ({"connection_id": 1, "fingerprint": FP}, 400, "invalid_request"),
        ({"device": {"vendor_id": 1}}, 400, "invalid_request"),
        ({"device": {"vendor_id": 1, "product_id": 1, "colour": "red"}}, 400, "invalid_request"),
        ({"device": {"vendor_id": 70000, "product_id": 1}}, 400, "invalid_request"),
        ({"device": {"vendor_id": "x", "product_id": 1}}, 400, "invalid_request"),
        (
            {"device": {"vendor_id": 1, "product_id": 1}, "policy": {"version": 1, "rules": "no"}},
            400,
            "policy_invalid",
        ),
        ({"fingerprint": FP}, 404, "not_found"),
        ({"connection_id": 999999}, 404, "not_found"),
    ],
)
def test_a_policy_test_that_cannot_be_answered(
    rig: ApiRig, body: dict[str, Any], status: int, code: str
) -> None:
    reply = rig.client().post("/policy/test", body)
    assert (reply.status, reply.error) == (status, code)


# --- audit --------------------------------------------------------------------------------


def test_the_audit_log_can_be_searched_and_paged(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    device = plug()
    client = rig.client("operator")
    fp = fingerprint(rig, device)
    mine = client.get("/audit", query={"device_fp": fp, "order": "asc"}).json
    types = [record["event_type"] for record in mine["records"]]
    assert types[0] == "device.connected" and "decision.made" in types
    assert [r["seq"] for r in mine["records"]] == sorted(r["seq"] for r in mine["records"])
    assert mine["head"]["seq"] >= mine["records"][-1]["seq"] and len(mine["head"]["hash"]) == 64
    first = client.get("/audit", query={"limit": 2}).json
    assert [r["seq"] for r in first["records"]] == sorted(
        (r["seq"] for r in first["records"]), reverse=True
    )
    assert first["next"] == first["records"][-1]["seq"] - 1
    second = client.get("/audit", query={"limit": 2, "until_seq": first["next"]}).json
    assert second["records"][0]["seq"] == first["next"]
    asc = client.get("/audit", query={"limit": 2, "order": "asc"}).json
    assert asc["records"][0]["seq"] == 1 and asc["next"] == 3
    assert (
        client.get("/audit", query={"limit": 1, "order": "asc", "until_seq": 1}).json["next"] == 2
    )
    typed = client.get(
        "/audit", query={"type": ["device.connected", "device.removed"], "limit": 500}
    ).json
    assert {r["event_type"] for r in typed["records"]} <= {"device.connected", "device.removed"}
    wild = client.get("/audit", query={"type": "auth.*", "limit": 5}).json
    assert all(r["event_type"].startswith("auth.") for r in wild["records"])
    assert (
        client.get("/audit", query={"min_severity": "warning", "limit": 500}).json["records"]
        is not None
    )
    assert client.get("/audit", query={"text": device.serial or "", "limit": 5}).json["records"]
    assert (
        client.get(
            "/audit", query={"since": "2026-03-02T09:00:00Z", "until": "2999-01-01T00:00:00Z"}
        ).status
        == 200
    )
    for bad in (
        {"limit": 0},
        {"order": "sideways"},
        {"since": "tomorrow"},
        {"type": ""},
        {"min_severity": "loud"},
    ):
        assert client.get("/audit", query=bad).status == 400, bad


def test_the_audit_log_is_not_for_everyone(rig: ApiRig) -> None:
    for role in ("admin", "operator", "auditor"):
        assert rig.client(role).get("/audit").status == 200
    assert rig.client("operator").get("/audit/export").error == "forbidden"
    assert rig.client("operator").get("/audit/checkpoint").error == "forbidden"
    assert rig.client("auditor").get("/audit/export").status == 200


def test_verifying_the_chain_is_itself_recorded(rig: ApiRig) -> None:
    client = rig.client("auditor")
    before = client.get("/audit", query={"limit": 1}).json["head"]
    result = client.post("/audit/verify", {}).json
    assert (
        result["ok"] is True
        and result["first_bad_seq"] is None
        and result["checked"] >= before["seq"]
    )
    assert (
        result["keyed"] is False
        and result["macs_checked"] == 0
        and result["head"]["seq"] >= before["seq"]
    )
    recorded = [r for r in rig.runtime.audit_log.iterate() if r.event_type == "audit.verified"]
    assert recorded and recorded[-1].actor == "arthur"
    ok = client.post(
        "/audit/verify",
        {"expected_head": {"seq": before["seq"], "hash": before["hash"]}, "start_seq": 1},
    )
    assert ok.json["ok"] is True
    forged = client.post(
        "/audit/verify", {"expected_head": {"seq": before["seq"], "hash": "0" * 64}}
    ).json
    assert forged["ok"] is False and forged["reason"]
    for bad in (
        {"start_seq": 0},
        {"expected_head": {"seq": 1}},
        {"expected_head": {"seq": 1, "hash": "xyz"}},
        {"expected_head": "x"},
        {"expected_head": {"seq": 1, "hash": "0" * 64, "x": 1}},
    ):
        assert client.post("/audit/verify", bad).status == 400, bad


def test_the_export_is_the_chain_as_canonical_json_lines(rig: ApiRig) -> None:
    reply = rig.client("auditor").get("/audit/export")
    assert reply.status == 200
    assert reply.headers["content-type"] == "application/x-ndjson"
    assert reply.headers["content-disposition"] == 'attachment; filename="portlock-audit.jsonl"'
    assert "content-length" not in reply.headers
    lines = reply.body.split(b"\n")
    assert lines[-1] == b"" and len(lines) > 5
    records = [parse_canonical(line) for line in lines[:-1]]
    assert [r["seq"] for r in records] == list(range(1, len(records) + 1))
    assert all(records[i]["prev_hash"] == records[i - 1]["hash"] for i in range(1, len(records)))
    assert records == [r.to_dict() for r in rig.runtime.audit_log.iterate()][: len(records)]
    tail = (
        rig.client("auditor")
        .get("/audit/export", query={"since_seq": len(records)})
        .body.split(b"\n")
    )
    assert parse_canonical(tail[0])["seq"] == len(records)
    assert rig.client("auditor").get("/audit/export", query={"since_seq": 0}).status == 400


def test_the_checkpoint_is_the_head(rig: ApiRig) -> None:
    reply = rig.client("auditor").get("/audit/checkpoint")
    assert reply.status == 200
    checkpoint = reply.json["checkpoint"]
    head = rig.runtime.audit_log.head()
    assert (checkpoint["seq"], checkpoint["hash"]) == head and checkpoint["count"] == head[0]
    signed = reply.json["signed_event"]
    from portlock.audit.signing import has_signing_support, verify_event

    if has_signing_support():
        assert signed["chain"] == {"seq": head[0], "hash": head[1]}
        assert verify_event(signed).ok
    else:
        assert signed is None


# --- scans --------------------------------------------------------------------------------


def test_a_scan_is_queued_run_and_reported(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    device = plug(
        with_volume(
            flash_drive("TEST0777SCAN", instance_id="test/7-777", bus_path="7-777"), "/media/scanme"
        )
    )
    cid_ = cid(rig, device)
    assert rig.client("auditor").post("/scans", {"connection_id": cid_}).error == "forbidden"
    queued = rig.client("operator").post("/scans", {"connection_id": cid_})
    assert queued.status == 202
    scan = queued.json["scans"][0]
    assert (
        scan["state"] == "queued"
        and scan["trigger"] == "manual"
        and scan["requested_by"] == OPERATOR
    )
    assert scan["mount_point"] == "/media/scanme" and scan["report"] is None
    rig.harness.run_scans()
    done = rig.client("auditor").get(f"/scans/{scan['id']}").json["scan"]
    assert done["state"] == "done" and done["verdict"] == "clean"
    assert done["summary"]["files_seen"] == 3 and done["report"]["root"] == "/media/scanme"
    listed = rig.client().get("/scans", query={"connection_id": cid_}).json
    assert [item["id"] for item in listed["scans"]] == [scan["id"]] and listed["scans"][0][
        "report"
    ] is None
    assert (
        rig.client()
        .get("/scans", query={"fingerprint": fingerprint(rig, device), "limit": 1})
        .json["next"]
        == scan["id"]
    )
    assert rig.client().get(f"/connections/{cid_}").json["scans"][0]["id"] == scan["id"]
    assert rig.client().get("/scans/999999").error == "not_found"


def test_scans_that_cannot_be_started(rig: ApiRig, plug: Callable[..., UsbDevice]) -> None:
    client = rig.client()
    assert client.post("/scans", {"connection_id": 999999}).error == "not_connected"
    bare = plug()
    assert client.post("/scans", {"connection_id": cid(rig, bare)}).error == "no_mounted_volume"
    mounted = plug(
        with_volume(flash_drive("TEST0778SCAN", instance_id="test/7-778", bus_path="7-778"))
    )
    reply = client.post(
        "/scans", {"connection_id": cid(rig, mounted), "mount_point": "/not/mounted"}
    )
    assert reply.status == 409 and reply.error == "no_mounted_volume"
    assert client.post("/scans", {"connection_id": 0}).status == 400


# --- lockdown, commit-confirm -------------------------------------------------------------


def test_lockdown_is_engaged_confirmed_renewed_and_lifted(
    rig: ApiRig, plug: Callable[..., UsbDevice], lockdown_cleanup: None
) -> None:
    device = plug()
    rig.client("operator").post(f"/connections/{cid(rig, device)}/approve", {})
    operator, admin, auditor = rig.client("operator"), rig.client("admin"), rig.client("auditor")
    assert auditor.post("/lockdown/engage", {}).error == "forbidden"
    engaged = operator.post("/lockdown/engage", {"minutes": 30, "reason": "suspected intrusion"})
    assert engaged.status == 200
    body = engaged.json
    assert (
        body["lockdown"]["active"] is True and body["lockdown"]["reason"] == "suspected intrusion"
    )
    assert (
        body["lockdown"]["remaining_seconds"] == 1800
        and body["lockdown"]["pending_change_id"] == body["change"]["id"]
    )
    assert set(body["summary"]) == {
        "evaluated",
        "changed",
        "blocked",
        "read_only",
        "released",
        "failed",
    }
    change = body["change"]
    assert (
        change["kind"] == "lockdown"
        and change["status"] == "awaiting"
        and change["actor"] == OPERATOR
    )
    assert change["timeout_seconds"] == 60 and change["remaining_seconds"] == 60
    assert any(item["outcome"] == "block" for item in change["preview"])
    assert rig.harness.view(device.instance_id).state.value in ("denied", "pending")
    assert auditor.get("/changes").json["changes"][0]["id"] == change["id"]
    assert operator.post("/lockdown/engage", {}).error == "lockdown_active"
    confirmed = operator.post(f"/changes/{change['id']}/confirm")
    assert confirmed.status == 200 and confirmed.json["confirmed"] is True
    assert operator.get("/lockdown").json["pending_change_id"] is None
    assert operator.post("/lockdown/renew", {"minutes": 60}).json["lockdown"]["renew_count"] == 1
    assert operator.post("/lockdown/lift", {"password": ADMIN_PASSWORD}).error == "forbidden"
    assert (
        admin.post("/lockdown/lift", {"password": "wrong wrong wrong"}).error
        == "reauthentication_failed"
    )
    assert admin.post("/lockdown/lift", {}).status == 400
    assert (
        admin.post("/lockdown/lift", {"password": ADMIN_PASSWORD, "recovery_code": "x"}).status
        == 400
    )
    lifted = admin.post("/lockdown/lift", {"password": ADMIN_PASSWORD})
    assert lifted.status == 200 and lifted.json["lockdown"]["state"] == "idle"
    assert admin.post("/lockdown/lift", {"password": ADMIN_PASSWORD}).error == "lockdown_not_active"
    assert admin.post("/lockdown/renew", {}).error == "lockdown_not_active"


def test_lockdown_can_be_lifted_with_a_recovery_code(rig: ApiRig, lockdown_cleanup: None) -> None:
    admin = rig.client("admin")
    change = admin.post("/lockdown/engage", {}).json["change"]["id"]
    assert admin.post(f"/changes/{change}/confirm").status == 200
    code = rig.runtime.accounts.generate_recovery_codes(ADMIN, actor="setup")[0]
    assert admin.post("/lockdown/lift", {"recovery_code": code}).status == 200
    admin2 = rig.client("admin")
    change = admin2.post("/lockdown/engage", {}).json["change"]["id"]
    assert admin2.post(f"/changes/{change}/confirm").status == 200
    assert admin2.post("/lockdown/lift", {"recovery_code": code}).error == "reauthentication_failed"


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({"minutes": 0}, 409, "invalid_duration"),
        ({"minutes": 100000}, 409, "invalid_duration"),
        ({"minutes": "ten"}, 400, "invalid_request"),
        ({"minutes": True}, 400, "invalid_request"),
        ({"reason": "x" * 300}, 400, "invalid_request"),
        ({"reason": "a\nb"}, 400, "invalid_request"),
    ],
)
def test_a_lockdown_request_that_makes_no_sense(
    rig: ApiRig, body: dict[str, Any], status: int, code: str
) -> None:
    reply = rig.client().post("/lockdown/engage", body)
    assert (reply.status, reply.error) == (status, code)
    if code == "invalid_duration":
        assert reply.json["error"]["details"] == {"max_minutes": 240}
    assert rig.client().get("/lockdown").json["active"] is False


def test_an_unconfirmed_lockdown_is_rolled_back_and_a_late_confirmation_is_refused(
    rig: ApiRig, lockdown_cleanup: None
) -> None:
    admin = rig.client("admin")
    change = admin.post("/lockdown/engage", {}).json["change"]["id"]
    rig.runtime.clock.advance(61)
    late = admin.post(f"/changes/{change}/confirm")
    assert late.status == 409 and late.error == "confirmation_expired"
    assert admin.get("/lockdown").json["active"] is False
    assert admin.post(f"/changes/{change}/confirm").error == "no_pending_change"


def test_a_change_is_confirmed_only_over_the_channel_that_made_it_by_a_role_that_may(
    rig: ApiRig, lockdown_cleanup: None
) -> None:
    admin, operator, auditor = rig.client("admin"), rig.client("operator"), rig.client("auditor")
    change = admin.post("/lockdown/engage", {}).json["change"]["id"]
    wrong = rig.client("admin").post(f"/changes/{change}/confirm")  # a different session
    assert wrong.status == 409 and wrong.error == "wrong_channel"
    assert auditor.post(f"/changes/{change}/confirm").json["error"]["details"] == {
        "permission": "engage_lockdown"
    }
    assert operator.post(f"/changes/{change}/confirm").error == "wrong_channel"
    assert admin.post(f"/changes/{change}/confirm").status == 200


def test_a_pending_change_can_be_cancelled(rig: ApiRig, lockdown_cleanup: None) -> None:
    admin = rig.client("admin")
    change = admin.post("/lockdown/engage", {}).json["change"]["id"]
    assert rig.client("auditor").post(f"/changes/{change}/cancel").error == "forbidden"
    cancelled = admin.post(f"/changes/{change}/cancel")
    assert cancelled.status == 200 and cancelled.json["cancelled"] is True
    assert admin.get("/lockdown").json["active"] is False
    assert admin.post(f"/changes/{change}/cancel").error == "no_pending_change"
    assert admin.post(f"/changes/{HEX16}/confirm").status == 404
    assert admin.get("/changes").json == {"changes": []}


# --- mode, scope, default-deny ------------------------------------------------------------


@pytest.fixture
def monitor_mode(rig: ApiRig) -> Iterator[None]:
    yield
    for change in rig.runtime.service.pending_changes():
        rig.runtime.service.cancel_change(change.id, actor=ADMIN)
    rig.runtime.service.set_mode("monitor", actor=ADMIN, channel="cleanup")
    rig.runtime.service.set_scope("storage", actor=ADMIN, channel="cleanup")
    rig.runtime.service.set_default_deny(False, actor=ADMIN, channel="cleanup")


def test_switching_to_enforce_is_applied_under_commit_confirm(
    rig: ApiRig, monitor_mode: None
) -> None:
    admin, operator = rig.client("admin"), rig.client("operator")
    assert operator.put("/mode", {"mode": "enforce"}).error == "forbidden"
    assert admin.put("/mode", {"mode": "loud"}).status == 400
    reply = admin.put("/mode", {"mode": "enforce"})
    assert reply.status == 200
    change = reply.json["change"]
    assert change["kind"] == "enforce_mode" and change["timeout_seconds"] == 60
    assert reply.json["mode"]["effective_mode"] == "enforce"
    wrong_role = operator.post(f"/changes/{change['id']}/confirm")
    assert wrong_role.status == 403 and wrong_role.json["error"]["details"] == {
        "permission": "change_mode"
    }
    assert admin.get("/changes").json["changes"][0]["id"] == change["id"]
    confirmed = admin.post(f"/changes/{change['id']}/confirm")
    assert confirmed.status == 200 and confirmed.json["change"]["kind"] == "enforce_mode"
    assert admin.get("/mode").json["effective_mode"] == "enforce"
    back = admin.put("/mode", {"mode": "monitor"})
    assert back.status == 200 and back.json["change"] is None
    assert admin.get("/mode").json["effective_mode"] == "monitor"


def test_enforce_mode_that_is_not_confirmed_rolls_back_by_itself(
    rig: ApiRig, monitor_mode: None
) -> None:
    admin = rig.client("admin")
    assert admin.put("/mode", {"mode": "enforce"}).status == 200
    assert admin.get("/mode").json["effective_mode"] == "enforce"
    rig.runtime.clock.advance(61)
    rig.runtime.service.tick()
    assert admin.get("/mode").json["effective_mode"] == "monitor"
    assert admin.get("/changes").json == {"changes": []}


def test_enforce_mode_is_refused_where_enforcement_is_impossible(tmp_path: Path) -> None:
    from portlock.guard.base import EnforcerCapabilities

    caps = EnforcerCapabilities(
        name="fake",
        privileged=False,
        block=False,
        read_only=False,
        eject=False,
        default_deny=False,
        notes=("not running as administrator",),
    )
    machine = ApiRig(tmp_path, roles=(), capabilities=caps)
    try:
        reply = machine.client().put("/mode", {"mode": "enforce"})
        assert reply.status == 409 and reply.error == "enforcement_unavailable"
        assert "not running as administrator" in reply.json["error"]["message"]
        assert machine.client().post("/lockdown/engage", {}).error == "enforcement_unavailable"
    finally:
        machine.close()


def test_the_scope_can_be_narrowed_at_once_and_widened_only_under_commit_confirm(
    rig: ApiRig, monitor_mode: None
) -> None:
    admin = rig.client("admin")
    assert rig.client("operator").put("/scope", {"scope": "storage"}).error == "forbidden"
    assert admin.put("/scope", {"scope": "everything"}).status == 400
    same = admin.put("/scope", {"scope": "storage"})
    assert same.status == 200 and same.json["change"] is None and same.json["scope"] == "storage"
    wider = admin.put("/scope", {"scope": "storage_and_unknown"})
    assert wider.status == 200 and wider.json["change"]["kind"] == "widen_scope"
    assert wider.json["change"]["preview"] is not None
    assert admin.post(f"/changes/{wider.json['change']['id']}/confirm").status == 200
    assert admin.get("/scope").json["scope"] == "storage_and_unknown"
    narrow = admin.put("/scope", {"scope": "storage"})
    assert (
        narrow.status == 200 and narrow.json["change"] is None and narrow.json["scope"] == "storage"
    )
    assert admin.get("/scope").json["scope"] == "storage"


def test_default_deny_is_a_commit_confirm_change_when_turned_on(
    rig: ApiRig, monitor_mode: None
) -> None:
    admin = rig.client("admin")
    assert rig.client("operator").put("/default-deny", {"enabled": True}).error == "forbidden"
    assert admin.put("/default-deny", {}).status == 400
    assert admin.put("/default-deny", {"enabled": "yes"}).status == 400
    off = admin.put("/default-deny", {"enabled": False})
    assert off.status == 200 and off.json["enabled"] is False and off.json["change"] is None
    on = admin.put("/default-deny", {"enabled": True})
    assert on.status == 200 and on.json["change"]["kind"] == "default_deny"
    assert admin.get("/default-deny").json == {"enabled": True}
    assert admin.post(f"/changes/{on.json['change']['id']}/cancel").status == 200
    assert admin.get("/default-deny").json == {"enabled": False}


# --- settings -----------------------------------------------------------------------------


def test_the_three_runtime_settings_can_be_changed_and_nothing_else(
    rig: ApiRig, plug: Callable[..., UsbDevice]
) -> None:
    admin = rig.client("admin")
    device = plug()
    fp = fingerprint(rig, device)
    assert rig.client("operator").patch("/settings", {"scan.enabled": False}).error == "forbidden"
    reply = admin.patch(
        "/settings",
        {"protected_fingerprints": [fp], "scan.enabled": False, "lockdown.default_minutes": 45},
    )
    assert reply.status == 200
    runtime = reply.json["runtime"]
    assert runtime["protected_fingerprints"] == [fp] and runtime["scan.enabled"] is False
    assert runtime["lockdown.default_minutes"] == 45 and reply.json["summary"]["evaluated"] >= 1
    assert rig.harness.view(device.instance_id).protected is True
    assert admin.get("/lockdown").json["default_minutes"] == 45
    restored = admin.patch(
        "/settings",
        {"protected_fingerprints": [], "scan.enabled": True, "lockdown.default_minutes": 30},
    )
    assert restored.json["runtime"]["protected_fingerprints"] == []
    changed = [r for r in rig.runtime.audit_log.iterate() if r.event_type == "config.changed"]
    assert {r.data["key"] for r in changed} >= {
        "protected_fingerprints",
        "scan.enabled",
        "lockdown.default_minutes",
    }


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({}, 400, "invalid_request"),
        ({"mode": "enforce"}, 400, "invalid_request"),
        ({"scan.enabled": "no"}, 400, "invalid_request"),
        ({"lockdown.default_minutes": 0}, 400, "invalid_request"),
        ({"protected_fingerprints": ["nope"]}, 400, "invalid_request"),
        ({"protected_fingerprints": [FP]}, 409, "unknown_device"),
        ({"lockdown.default_minutes": 99999}, 400, "invalid_request"),
    ],
)
def test_settings_that_cannot_be_changed(
    rig: ApiRig, body: dict[str, Any], status: int, code: str
) -> None:
    reply = rig.client().patch("/settings", body)
    assert (reply.status, reply.error) == (status, code)


# --- users --------------------------------------------------------------------------------


def test_accounts_are_managed_by_administrators(rig: ApiRig) -> None:
    admin, operator = rig.client("admin"), rig.client("operator")
    assert operator.get("/users").error == "forbidden"
    created = admin.post(
        "/users",
        {"username": "Case-Test", "password": "a long operator passphrase 1", "role": "operator"},
    )
    assert created.status == 201 and created.json["user"]["username"] == "case-test"
    assert (
        admin.post(
            "/users",
            {
                "username": "CASE-TEST",
                "password": "a long operator passphrase 1",
                "role": "operator",
            },
        ).error
        == "user_exists"
    )
    for bad in (
        {"username": "ab", "password": "a long operator passphrase 1", "role": "operator"},
        {"username": "bad name!", "password": "a long operator passphrase 1", "role": "operator"},
        {"username": "weak-pw", "password": "short", "role": "operator"},
        {"username": "bad-role", "password": "a long operator passphrase 1", "role": "root"},
    ):
        assert admin.post("/users", bad).status == 400, bad
    listing = admin.get("/users").json["users"]
    entry = next(item for item in listing if item["username"] == "case-test")
    assert (
        entry["role"] == "operator"
        and entry["enabled"] is True
        and entry["recovery_codes_remaining"] == 0
    )
    assert entry["locked_out_seconds"] == 0 and "password_hash" not in json.dumps(listing)
    assert admin.put("/users/CASE-test/role", {"role": "auditor"}).json["user"]["role"] == "auditor"
    assert admin.post("/users/case-test/disable").json["user"]["enabled"] is False
    assert admin.post("/users/case-test/enable").json["user"]["enabled"] is True
    reset = admin.post(
        "/users/case-test/password", {"new_password": "a reset operator passphrase 2"}
    )
    assert (
        reset.status == 200
        and rig.login("case-test", "a reset operator passphrase 2").status == 200
    )
    assert (
        admin.post("/users/case-test/password", {"new_password": "weak"}).error == "password_policy"
    )
    assert admin.post("/users/case-test/unlock").json["user"]["username"] == "case-test"
    assert admin.delete("/users/case-test").status == 204
    assert admin.delete("/users/case-test").error == "not_found"
    assert admin.put("/users/nobody-here/role", {"role": "admin"}).error == "not_found"


def test_the_last_administrator_cannot_be_removed_demoted_or_disabled(rig: ApiRig) -> None:
    admin = rig.client("admin")
    assert admin.delete(f"/users/{ADMIN}").error == "last_admin"
    assert admin.put(f"/users/{ADMIN}/role", {"role": "operator"}).error == "last_admin"
    assert admin.post(f"/users/{ADMIN}/disable").error == "last_admin"


def test_recovery_codes_are_shown_once_to_the_administrator_or_the_owner(rig: ApiRig) -> None:
    operator, admin, auditor = rig.client("operator"), rig.client("admin"), rig.client("auditor")
    own = operator.post(f"/users/{OPERATOR}/recovery-codes")
    assert own.status == 200 and len(own.json["codes"]) == 8 and own.json["username"] == OPERATOR
    assert re.fullmatch(r"[0-9A-Za-z-]+", own.json["codes"][0])
    assert operator.post(f"/users/{ADMIN}/recovery-codes").json["error"]["details"] == {
        "permission": "manage_users"
    }
    assert auditor.post(f"/users/{AUDITOR}/recovery-codes").status == 200
    other = admin.post(f"/users/{AUDITOR}/recovery-codes")
    assert other.status == 200 and other.json["codes"] != own.json["codes"]
    assert rig.runtime.accounts.remaining_recovery_codes(OPERATOR) == 8
    stored = " ".join(
        str(tuple(row)) for row in rig.runtime.db.query("SELECT * FROM auth_recovery_codes")
    )
    assert own.json["codes"][0].replace("-", "").lower() not in stored.lower()
    assert admin.get("/users").json["users"][0]["recovery_codes_remaining"] >= 0


# --- failures inside the service ----------------------------------------------------------


def test_a_bug_is_a_500_with_a_request_id_and_nothing_else(
    rig: ApiRig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom() -> None:
        raise RuntimeError("secret internal detail /var/lib/portlock")

    monkeypatch.setattr(rig.runtime.service, "status", boom)
    with caplog.at_level("ERROR"):
        reply = rig.client().get("/status")
    assert reply.status == 500 and reply.error == "internal_error"
    assert (
        "secret internal detail" not in reply.body.decode()
        and "Traceback" not in reply.body.decode()
    )
    assert reply.json["error"]["request_id"] == reply.headers["x-request-id"]
    assert any(reply.headers["x-request-id"] in record.getMessage() for record in caplog.records)
    assert any(
        "secret internal detail" in str(record.exc_info)
        for record in caplog.records
        if record.exc_info
    )


def test_an_unreadable_database_is_a_503(rig: ApiRig, monkeypatch: pytest.MonkeyPatch) -> None:
    from portlock.core.errors import StoreError

    def broken(*args: Any, **kwargs: Any) -> None:
        raise StoreError("disk I/O error on /var/lib/portlock/portlock.db")

    monkeypatch.setattr(rig.runtime.service, "list_grants", broken)
    reply = rig.client().get("/trust")
    assert reply.status == 503 and reply.error == "store_unavailable"
    assert "/var/lib" not in reply.body.decode()


def test_nothing_in_an_error_is_a_secret(rig: ApiRig) -> None:
    replies: list[Reply] = [
        rig.login(ADMIN, "wrong wrong wrong 9"),
        rig.client("operator").post("/lockdown/lift", {"password": ADMIN_PASSWORD}),
        rig.client().post("/audit/verify", {"start_seq": 0}),
    ]
    for reply in replies:
        text = reply.body.decode()
        for secret in (ADMIN_PASSWORD, rig.runtime.cli_secret, "wrong wrong wrong 9"):
            assert secret not in text
