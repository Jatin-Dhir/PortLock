"""Regression tests for the code review of the API: each fails without its fix.

They run the real API on a loopback port against the simulated machine (fake backend,
fake enforcer, fake clock), exactly like the other console tests. ``docs/REVIEW.md`` lists
the findings.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_console_support import (
    AUDITOR,
    AUDITOR_PASSWORD,
    OPERATOR,
    OPERATOR_PASSWORD,
    ApiClient,
    ApiRig,
    raw_exchange,
    status_of,
)

from integration.harness import ADMIN, ADMIN_PASSWORD
from portlock.auth.accounts import Channel
from portlock.console.api import CLI_SECRET_HEADER, ApiServer
from portlock.lockdown.manager import Credential
from portlock.service.daemon import AccountCredentials

WRONG = "a wrong passphrase 123"


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path)
    try:
        yield machine
    finally:
        machine.close()


def _engage(client: ApiClient) -> str:
    reply = client.post("/lockdown/engage", {"minutes": 30, "reason": "review"})
    assert reply.status == 200, reply.body
    return str(reply.json["change"]["id"])


def _lock_out_from_the_network(rig: ApiRig) -> None:
    anonymous = ApiClient(rig.port)
    for _ in range(6):
        reply = anonymous.post("/auth/login", {"username": ADMIN, "password": WRONG})
    assert reply.status == 429 and reply.error == "locked_out"


# --- recovery codes need the caller's own password ---------------------------------------


def test_a_bare_token_cannot_mint_recovery_codes(rig: ApiRig) -> None:
    accounts = rig.runtime.accounts
    offline = accounts.generate_recovery_codes(ADMIN, actor="setup")
    stolen = rig.client("admin")  # a bearer token and nothing else
    assert stolen.post(f"/users/{ADMIN}/recovery-codes").error == "invalid_request"
    wrong = stolen.post(f"/users/{ADMIN}/recovery-codes", {"current_password": WRONG})
    assert wrong.status == 401 and wrong.error == "reauthentication_failed"
    assert accounts.remaining_recovery_codes(ADMIN) == len(offline)
    assert accounts.use_recovery_code(ADMIN, offline[0])  # the operator's offline set stands


def test_minted_codes_cannot_lift_a_lockdown_without_the_password(rig: ApiRig) -> None:
    stolen = rig.client("admin")
    _engage(stolen)
    refused = stolen.post(f"/users/{ADMIN}/recovery-codes", {"current_password": WRONG})
    assert refused.status == 401
    assert rig.runtime.service.lockdown_status().active
    issued = stolen.post(f"/users/{ADMIN}/recovery-codes", {"current_password": ADMIN_PASSWORD})
    assert issued.status == 200 and len(issued.json["codes"]) == 8


def test_an_administrator_proves_their_own_password_to_issue_codes_for_another(
    rig: ApiRig,
) -> None:
    admin = rig.client("admin")
    assert admin.post(f"/users/{AUDITOR}/recovery-codes", {"current_password": WRONG}).status == 401
    assert rig.runtime.accounts.remaining_recovery_codes(AUDITOR) == 0
    # The password of the account the codes are for does not count; the caller's does.
    other = admin.post(f"/users/{AUDITOR}/recovery-codes", {"current_password": AUDITOR_PASSWORD})
    assert other.status == 401
    done = admin.post(f"/users/{AUDITOR}/recovery-codes", {"current_password": ADMIN_PASSWORD})
    assert done.status == 200
    assert rig.runtime.accounts.remaining_recovery_codes(AUDITOR) == 8


def test_the_password_check_for_codes_is_not_a_sign_in_but_is_rate_limited(rig: ApiRig) -> None:
    accounts = rig.runtime.accounts
    before = accounts.get_user(OPERATOR)
    assert before is not None
    operator = rig.client("operator")
    ok = operator.post(f"/users/{OPERATOR}/recovery-codes", {"current_password": OPERATOR_PASSWORD})
    assert ok.status == 200
    after = accounts.get_user(OPERATOR)
    assert after is not None and after.last_login_at == before.last_login_at
    for _ in range(6):
        reply = operator.post(f"/users/{OPERATOR}/recovery-codes", {"current_password": WRONG})
    assert reply.status == 429 and reply.error == "locked_out"


# --- the local command line is never locked out of lifting -------------------------------


def test_the_local_cli_lifts_a_lockdown_during_a_network_lockout(rig: ApiRig) -> None:
    anonymous = ApiClient(rig.port)
    cli = ApiClient(rig.port)
    secret = {CLI_SECRET_HEADER: rig.runtime.cli_secret}
    login = cli.post("/auth/login", {"username": ADMIN, "password": ADMIN_PASSWORD}, headers=secret)
    assert login.status == 200
    cli.token = login.json["token"]
    change = _engage(cli)
    assert cli.post(f"/changes/{change}/confirm").status == 200
    _lock_out_from_the_network(rig)
    assert anonymous.post("/auth/login", {"username": ADMIN, "password": WRONG}).status == 429
    lifted = cli.post("/lockdown/lift", {"password": ADMIN_PASSWORD}, headers=secret)
    assert lifted.status == 200, lifted.body
    assert not rig.runtime.service.lockdown_status().active


def test_a_lift_from_the_network_is_still_refused_during_a_lockout(rig: ApiRig) -> None:
    admin = rig.client("admin")
    change = _engage(admin)
    assert admin.post(f"/changes/{change}/confirm").status == 200
    _lock_out_from_the_network(rig)
    refused = admin.post("/lockdown/lift", {"password": ADMIN_PASSWORD})
    assert refused.status == 429 and refused.error == "locked_out"
    assert rig.runtime.service.lockdown_status().active


def test_the_account_credential_check_honours_the_local_channel(rig: ApiRig) -> None:
    accounts = rig.runtime.accounts
    for _ in range(6):
        accounts.authenticate(ADMIN, WRONG, channel=Channel.NETWORK)
    check = AccountCredentials(accounts)
    assert not check.verify(ADMIN, Credential("password", ADMIN_PASSWORD))
    assert check.verify(ADMIN, Credential("password", ADMIN_PASSWORD, local=True))
    assert not check.verify(ADMIN, Credential("password", WRONG, local=True))


# --- cancelling a lockdown is lifting it -------------------------------------------------


def test_an_operator_cannot_lift_a_lockdown_by_cancelling_its_pending_change(
    rig: ApiRig,
) -> None:
    admin, operator = rig.client("admin"), rig.client("operator")
    change = _engage(admin)
    assert rig.runtime.service.lockdown_status().active
    assert operator.post("/lockdown/lift", {"password": OPERATOR_PASSWORD}).status == 403
    refused = operator.post(f"/changes/{change}/cancel")
    assert refused.status == 403
    assert refused.json["error"]["details"] == {"permission": "lift_lockdown"}
    assert rig.runtime.service.lockdown_status().active
    assert [c.id for c in rig.runtime.service.pending_changes()] == [change]


def test_an_operator_can_still_confirm_and_an_administrator_can_cancel(rig: ApiRig) -> None:
    admin, operator = rig.client("admin"), rig.client("operator")
    change = _engage(operator)
    assert operator.post(f"/changes/{change}/confirm").status == 200
    assert rig.runtime.service.lockdown_status().active
    rig.runtime.service.lockdown_lift(
        actor=ADMIN, credential=Credential("password", ADMIN_PASSWORD)
    )
    second = _engage(admin)
    cancelled = admin.post(f"/changes/{second}/cancel")
    assert cancelled.status == 200 and cancelled.json["cancelled"] is True
    assert not rig.runtime.service.lockdown_status().active


def test_other_changes_are_still_cancelled_with_their_own_permission(rig: ApiRig) -> None:
    operator = rig.client("operator")
    assert operator.put("/mode", {"mode": "enforce"}).status == 403  # CHANGE_MODE: admin only
    admin = rig.client("admin")
    reply = admin.put("/mode", {"mode": "enforce"})
    change = reply.json["change"]["id"]
    assert operator.post(f"/changes/{change}/cancel").status == 403
    assert admin.post(f"/changes/{change}/cancel").status == 200


# --- idle connections cannot hold every slot ---------------------------------------------


def _wait_until(condition: object, what: str) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if condition():  # type: ignore[operator]
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def test_idle_connections_do_not_shut_out_a_client_that_sends_its_request(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, max_in_flight=3)
    server.start()
    idle: list[socket.socket] = []
    try:
        for _ in range(3):
            sock = socket.create_connection(("127.0.0.1", server.port))
            sock.sendall(b"GET /api/v1/ping HTTP/1.1\r\n")  # the head never ends
            idle.append(sock)
        _wait_until(lambda: server._in_flight == 3, "three connections in flight")
        client = ApiClient(server.port)
        for _ in range(5):  # each newcomer displaces the connection that waited longest
            assert client.get("/ping").status == 200
        assert server._in_flight <= 3
    finally:
        for sock in idle:
            sock.close()
        server.stop()


def test_a_connection_with_a_complete_head_is_never_evicted(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, max_in_flight=2)
    server.start()
    working: list[socket.socket] = []
    try:
        for _ in range(2):
            sock = socket.create_connection(("127.0.0.1", server.port))
            # A complete head that promises a body which never comes: a request in flight.
            sock.sendall(
                b"POST /api/v1/auth/login HTTP/1.1\r\n"
                + f"Host: 127.0.0.1:{server.port}\r\n".encode()
                + b"Content-Type: application/json\r\nContent-Length: 50\r\n\r\n"
            )
            working.append(sock)
        _wait_until(lambda: server._in_flight == 2, "two requests in flight")
        live = server._server._live  # type: ignore[union-attr]
        _wait_until(lambda: not any(item.awaiting_head for item in live), "both heads read")
        reply = raw_exchange(
            server.port,
            b"GET /api/v1/ping HTTP/1.1\r\n" + f"Host: 127.0.0.1:{server.port}\r\n\r\n".encode(),
        )
        # Refused (503, or a reset where the system drops unread data), never served.
        assert status_of(reply) in (0, 503)
        for sock in working:
            sock.settimeout(0.2)
            with pytest.raises(TimeoutError):
                sock.recv(1)  # still open: nobody cut a request that was being served
    finally:
        for sock in working:
            sock.close()
        server.stop()
