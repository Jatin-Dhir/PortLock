"""Bearer-token authentication: login, logout, sessions, passwords, recovery, the three
login limits, and how the command line proves what it is talking to
(``docs/API.md`` section 5)."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from test_console_support import WAIT, ApiClient, ApiRig, Reply

from integration.harness import ADMIN, ADMIN_PASSWORD, Harness
from portlock.auth.accounts import AuthFailure, AuthResult
from portlock.console.api import (
    CHALLENGE_HEADER,
    CLI_SECRET_HEADER,
    ApiServer,
    ping_proof,
)
from portlock.lockdown.manager import Credential

PASSWORD = "a long and unremarkable passphrase 9"


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path_factory.mktemp("auth"))
    try:
        yield machine
    finally:
        machine.close()


@pytest.fixture(autouse=True)
def fresh_login_budget(rig: ApiRig) -> None:
    """Every test starts a new minute: one test's login budget never spills into the next."""
    rig.runtime.clock.advance(61)


def make_user(rig: ApiRig, name: str, role: str = "admin", password: str = PASSWORD) -> None:
    if rig.runtime.accounts.get_user(name) is None:
        rig.runtime.accounts.create_user(name, password, role, actor="setup")


def strip_request_id(reply: Reply) -> tuple[int, Any]:
    body = reply.json
    body["error"]["request_id"] = "x"
    return reply.status, body


# --- login -------------------------------------------------------------------------------


def test_login_returns_a_bearer_token_that_authenticates_later_requests(rig: ApiRig) -> None:
    make_user(rig, "login-ok", "operator")
    reply = rig.login("login-ok", PASSWORD)
    assert reply.status == 200
    body = reply.json
    assert set(body) == {"user", "session", "token"}
    assert body["user"]["username"] == "login-ok" and body["user"]["role"] == "operator"
    assert body["user"]["last_login_at"] is not None
    assert len(body["token"]) == 43
    assert "csrf_token" not in body and "set-cookie" not in reply.headers
    assert body["session"]["client"] == "api"
    assert "token" not in body["session"]
    me = ApiClient(rig.port, body["token"]).get("/auth/session")
    assert me.status == 200 and me.json["session"]["session_id"] == body["session"]["session_id"]
    assert "view_audit" in me.json["permissions"] and "manage_users" not in me.json["permissions"]
    assert "token" not in me.json


def test_only_a_digest_of_the_token_is_stored(rig: ApiRig) -> None:
    make_user(rig, "login-digest")
    token = rig.login("login-digest", PASSWORD).json["token"]
    rows = rig.runtime.db.query("SELECT * FROM auth_sessions")
    assert rows and all(token not in str(tuple(row)) for row in rows)


def test_the_client_label_comes_from_the_request_not_from_what_it_says(rig: ApiRig) -> None:
    make_user(rig, "login-label")
    own = f"http://127.0.0.1:{rig.port}"
    console = rig.login("login-label", PASSWORD, headers={"Origin": own})
    assert console.json["session"]["client"] == "console"
    spoof = rig.login("login-label", PASSWORD, headers={"User-Agent": "cli"})
    assert spoof.json["session"]["client"] == "api"
    secret = rig.runtime.cli_secret
    cli = rig.login("login-label", PASSWORD, headers={CLI_SECRET_HEADER: secret})
    assert cli.json["session"]["client"] == "cli"
    wrong = rig.login("login-label", PASSWORD, headers={CLI_SECRET_HEADER: "not-the-secret"})
    assert wrong.status == 200 and wrong.json["session"]["client"] == "api"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"username": "x"},
        {"password": "x"},
        {"username": 5, "password": "x"},
        {"username": "x", "password": ["x"]},
        {"username": "", "password": "x"},
        {"username": "x", "password": "x", "remember": True},
        {"username": "a" * 200, "password": "x"},
    ],
)
def test_a_malformed_login_is_an_invalid_request(rig: ApiRig, body: dict[str, Any]) -> None:
    reply = ApiClient(rig.port).post("/auth/login", body)
    assert reply.status == 400 and reply.error == "invalid_request"


def test_a_wrong_password_and_an_unknown_name_are_indistinguishable(rig: ApiRig) -> None:
    wrong = rig.login(ADMIN, "definitely not the password")
    unknown = rig.login("nobody-by-this-name", "definitely not the password")
    garbage = rig.login("Not A Valid Name!", "definitely not the password")
    assert strip_request_id(wrong) == strip_request_id(unknown) == strip_request_id(garbage)
    assert wrong.status == 401 and wrong.error == "invalid_credentials"
    assert "token" not in wrong.body.decode()


def test_a_disabled_account_is_told_so_only_with_the_right_password(rig: ApiRig) -> None:
    make_user(rig, "login-disabled")
    rig.runtime.accounts.disable_user("login-disabled", actor="setup")
    assert rig.login("login-disabled", PASSWORD).error == "account_disabled"
    assert rig.login("login-disabled", "the wrong one").error == "invalid_credentials"


def test_login_is_audited_without_the_password(rig: ApiRig) -> None:
    make_user(rig, "login-audit")
    rig.login("login-audit", PASSWORD)
    rig.login("login-audit", "wrong wrong wrong")
    text = " ".join(str(record.to_dict()) for record in rig.runtime.audit_log.iterate())
    assert "auth.login" in text and "auth.failure" in text
    assert PASSWORD not in text and "wrong wrong wrong" not in text


# --- lockout and the limits --------------------------------------------------------------


def test_five_failures_lock_the_account_for_the_network_but_not_for_the_command_line(
    rig: ApiRig,
) -> None:
    make_user(rig, "locked-out")
    for _ in range(5):
        assert rig.login("locked-out", "wrong wrong wrong 1").status == 401
    refused = rig.login("locked-out", PASSWORD)  # the right password, refused all the same
    assert refused.status == 429 and refused.error == "locked_out"
    retry = refused.json["error"]["details"]["retry_after_seconds"]
    assert 1 <= retry <= 30 and refused.headers["retry-after"] == str(retry)
    local = rig.login("locked-out", PASSWORD, headers={CLI_SECRET_HEADER: rig.runtime.cli_secret})
    assert local.status == 200 and local.json["session"]["client"] == "cli"
    rig.runtime.clock.advance(31)
    assert rig.login("locked-out", PASSWORD).status == 200


def test_an_unknown_name_is_locked_out_exactly_like_a_real_one(rig: ApiRig) -> None:
    for _ in range(5):
        rig.login("ghost-user", "wrong wrong wrong 2")
    ghost = rig.login("ghost-user", "wrong wrong wrong 2")
    assert ghost.status == 429 and ghost.error == "locked_out"
    assert 1 <= ghost.json["error"]["details"]["retry_after_seconds"] <= 30


def test_too_many_passwords_being_checked_is_a_busy_answer_not_a_wait(
    rig: ApiRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts = rig.runtime.accounts
    gate, entered = threading.Event(), threading.Semaphore(0)
    real = accounts._verify

    def slow(password: str, encoded: str) -> bool:
        entered.release()
        gate.wait(WAIT)
        return real(password, encoded)

    monkeypatch.setattr(accounts, "_verify", slow)
    slots = accounts.policy.max_network_verifications
    results: list[Reply] = []

    def attempt(name: str) -> None:
        results.append(rig.login(name, "whatever whatever 33"))

    threads = [threading.Thread(target=attempt, args=(f"busy-{n}",)) for n in range(slots)]
    for thread in threads:
        thread.start()
    for _ in range(slots):
        assert entered.acquire(timeout=WAIT)
    try:
        busy = rig.login("busy-extra", "whatever whatever 33")
        assert busy.status == 429 and busy.error == "busy"
        assert busy.json["error"]["details"]["retry_after_seconds"] >= 1
        assert busy.headers["retry-after"] == str(
            busy.json["error"]["details"]["retry_after_seconds"]
        )
    finally:
        gate.set()
        for thread in threads:
            thread.join(WAIT)
    assert [reply.status for reply in results] == [401] * slots


def test_a_budget_of_thirty_credential_checks_a_minute_is_shared_by_all_names(
    rig: ApiRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        rig.runtime.accounts,
        "authenticate",
        lambda *a, **k: AuthResult(False, None, AuthFailure.INVALID_CREDENTIALS, 0),
    )
    statuses = [rig.login(f"budget-{n}", "x" * 14).status for n in range(30)]
    assert statuses == [401] * 30
    over = rig.login("budget-31", "x" * 14)
    assert over.status == 429 and over.error == "rate_limited"
    assert 1 <= over.json["error"]["details"]["retry_after_seconds"] <= 60
    assert over.headers["retry-after"] == str(over.json["error"]["details"]["retry_after_seconds"])
    # The command line (local channel) is never counted against it.
    cli = rig.login("budget-cli", "x" * 14, headers={CLI_SECRET_HEADER: rig.runtime.cli_secret})
    assert cli.status == 401
    rig.runtime.clock.advance(61)
    assert rig.login("budget-after", "x" * 14).status == 401


def test_the_budget_also_covers_recovery_and_password_change(
    rig: ApiRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig.runtime.clock.advance(61)
    monkeypatch.setattr(
        rig.runtime.accounts,
        "authenticate",
        lambda *a, **k: AuthResult(False, None, AuthFailure.INVALID_CREDENTIALS, 0),
    )
    for n in range(30):
        rig.login(f"shared-{n}", "x" * 14)
    recovery = ApiClient(rig.port).post(
        "/auth/recovery",
        {"username": "someone", "recovery_code": "x", "new_password": PASSWORD},
    )
    assert recovery.status == 429 and recovery.error == "rate_limited"
    rig.runtime.clock.advance(61)


# --- sessions ----------------------------------------------------------------------------


def test_a_session_ends_after_fifteen_idle_minutes(rig: ApiRig) -> None:
    make_user(rig, "idle-user")
    client = ApiClient(rig.port, rig.login("idle-user", PASSWORD).json["token"])
    assert client.get("/auth/session").status == 200
    rig.runtime.clock.advance(14 * 60)
    assert client.get("/auth/session").status == 200  # a request refreshes the idle timer
    rig.runtime.clock.advance(14 * 60)
    assert client.get("/auth/session").status == 200
    rig.runtime.clock.advance(16 * 60)
    ended = client.get("/auth/session")
    assert ended.status == 401 and ended.error == "unauthenticated"
    assert ended.headers["www-authenticate"] == 'Bearer realm="portlock"'


def test_a_session_ends_eight_hours_after_login_however_busy_it_is(rig: ApiRig) -> None:
    make_user(rig, "busy-user")
    client = ApiClient(rig.port, rig.login("busy-user", PASSWORD).json["token"])
    for _ in range(47):  # 47 x 10 minutes
        rig.runtime.clock.advance(10 * 60)
        assert client.get("/auth/session").status == 200
    rig.runtime.clock.advance(11 * 60)  # 8 h 1 min in all
    assert client.get("/auth/session").status == 401


def test_logout_ends_this_session_only_and_is_audited(rig: ApiRig) -> None:
    make_user(rig, "logout-user")
    one = ApiClient(rig.port, rig.login("logout-user", PASSWORD).json["token"])
    two = ApiClient(rig.port, rig.login("logout-user", PASSWORD).json["token"])
    reply = one.post("/auth/logout")
    assert reply.status == 204 and reply.body == b""
    assert one.get("/auth/session").status == 401
    assert two.get("/auth/session").status == 200
    logouts = [
        record for record in rig.runtime.audit_log.iterate() if record.event_type == "auth.logout"
    ]
    assert logouts and logouts[-1].actor == "logout-user"
    assert "token" not in str(logouts[-1].to_dict())
    assert one.post("/auth/logout").status == 401


def test_changing_a_role_or_disabling_or_deleting_an_account_ends_its_sessions(rig: ApiRig) -> None:
    for name in ("end-role", "end-disable", "end-delete"):
        make_user(rig, name, "operator")
    admin = rig.client("admin")
    clients = {
        name: ApiClient(rig.port, rig.login(name, PASSWORD).json["token"])
        for name in ("end-role", "end-disable", "end-delete")
    }
    assert admin.put("/users/end-role/role", {"role": "auditor"}).status == 200
    assert admin.post("/users/end-disable/disable").status == 200
    assert admin.delete("/users/end-delete").status == 204
    for client in clients.values():
        assert client.get("/auth/session").status == 401


def test_at_most_five_sessions_per_account_the_oldest_is_ended(rig: ApiRig) -> None:
    make_user(rig, "five-user")
    tokens = [rig.login("five-user", PASSWORD).json["token"] for _ in range(6)]
    assert ApiClient(rig.port, tokens[0]).get("/auth/session").status == 401
    assert all(
        ApiClient(rig.port, token).get("/auth/session").status == 200 for token in tokens[1:]
    )


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic YWxpY2U6cGFzcw==",
        "bearer",
        "Token abc",
        "Bearer a b",
        "Bearer " + "x" * 43,
        "Bearer " + "x" * 5000,
        "Bearer \x01bad",
    ],
)
def test_anything_but_a_live_bearer_token_is_unauthenticated(rig: ApiRig, header: str) -> None:
    reply = ApiClient(rig.port).get("/status", headers={"Authorization": header})
    assert reply.status == 401 and reply.error == "unauthenticated"


def test_a_token_in_the_query_string_is_not_accepted(rig: ApiRig) -> None:
    token = rig.token("admin")
    reply = ApiClient(rig.port).get("/status", query={"token": token, "access_token": token})
    assert reply.status == 400  # unknown query fields are errors, and no session is made of them
    assert ApiClient(rig.port).get("/status").status == 401


# --- passwords and recovery codes --------------------------------------------------------


def test_changing_the_password_ends_every_session_and_returns_a_new_token(rig: ApiRig) -> None:
    make_user(rig, "change-pw")
    first = rig.login("change-pw", PASSWORD).json["token"]
    other = rig.login("change-pw", PASSWORD).json["token"]
    new = "an even longer replacement passphrase 7"
    reply = ApiClient(rig.port, first).post(
        "/auth/password", {"current_password": PASSWORD, "new_password": new}
    )
    assert reply.status == 200 and set(reply.json) == {"user", "session", "token"}
    token = reply.json["token"]
    assert ApiClient(rig.port, first).get("/auth/session").status == 401
    assert ApiClient(rig.port, other).get("/auth/session").status == 401
    assert ApiClient(rig.port, token).get("/auth/session").status == 200
    assert rig.login("change-pw", PASSWORD).status == 401
    assert rig.login("change-pw", new).status == 200


def test_changing_the_password_needs_the_current_one_and_a_good_new_one(rig: ApiRig) -> None:
    make_user(rig, "change-bad")
    client = ApiClient(rig.port, rig.login("change-bad", PASSWORD).json["token"])
    wrong = client.post(
        "/auth/password",
        {"current_password": "wrong wrong wrong 4", "new_password": PASSWORD + "x"},
    )
    assert wrong.status == 401 and wrong.error == "reauthentication_failed"
    weak = client.post("/auth/password", {"current_password": PASSWORD, "new_password": "short"})
    assert weak.status == 400 and weak.error == "password_policy"
    assert weak.json["error"]["details"]["problems"]
    same = client.post("/auth/password", {"current_password": PASSWORD, "new_password": PASSWORD})
    assert same.status == 400 and same.error == "password_policy"
    assert client.get("/auth/session").status == 200  # nothing changed


def test_the_current_password_is_subject_to_the_lockout(rig: ApiRig) -> None:
    make_user(rig, "change-lock")
    client = ApiClient(rig.port, rig.login("change-lock", PASSWORD).json["token"])
    for _ in range(5):
        client.post(
            "/auth/password",
            {"current_password": "wrong wrong wrong 5", "new_password": PASSWORD + "y"},
        )
    locked = client.post(
        "/auth/password", {"current_password": PASSWORD, "new_password": PASSWORD + "y"}
    )
    assert locked.status == 429 and locked.error == "locked_out"
    rig.runtime.clock.advance(31)


def test_a_recovery_code_resets_a_password_once(rig: ApiRig) -> None:
    make_user(rig, "recover-me")
    accounts = rig.runtime.accounts
    codes = accounts.generate_recovery_codes("recover-me", actor="setup")
    old = rig.login("recover-me", PASSWORD).json["token"]
    new = "a passphrase chosen after recovery 8"
    weak = ApiClient(rig.port).post(
        "/auth/recovery",
        {"username": "recover-me", "recovery_code": codes[0], "new_password": "weak"},
    )
    assert weak.status == 400 and weak.error == "password_policy"
    assert accounts.remaining_recovery_codes("recover-me") == len(codes)  # the code was not spent
    ok = ApiClient(rig.port).post(
        "/auth/recovery",
        {"username": "RECOVER-ME", "recovery_code": codes[0].lower(), "new_password": new},
    )
    assert ok.status == 200 and set(ok.json) == {"user", "session", "token"}
    assert accounts.remaining_recovery_codes("recover-me") == len(codes) - 1
    assert ApiClient(rig.port, old).get("/auth/session").status == 401
    assert ApiClient(rig.port, ok.json["token"]).get("/auth/session").status == 200
    assert rig.login("recover-me", new).status == 200
    again = ApiClient(rig.port).post(
        "/auth/recovery",
        {"username": "recover-me", "recovery_code": codes[0], "new_password": new + "z"},
    )
    assert again.status == 401 and again.error == "invalid_credentials"


def test_recovery_failures_look_alike(rig: ApiRig) -> None:
    make_user(rig, "recover-fail")
    rig.runtime.accounts.generate_recovery_codes("recover-fail", actor="setup")
    body = {"recovery_code": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0000", "new_password": PASSWORD + "q"}
    client = ApiClient(rig.port)
    wrong = client.post("/auth/recovery", {"username": "recover-fail", **body})
    unknown = client.post("/auth/recovery", {"username": "no-such-user", **body})
    invalid = client.post("/auth/recovery", {"username": "x", **body})
    assert strip_request_id(wrong) == strip_request_id(unknown) == strip_request_id(invalid)
    assert wrong.status == 401


def test_recovery_codes_are_never_locked_out(rig: ApiRig) -> None:
    make_user(rig, "recover-spam")
    rig.runtime.clock.advance(61)
    codes = rig.runtime.accounts.generate_recovery_codes("recover-spam", actor="setup")
    for n in range(8):
        reply = ApiClient(rig.port).post(
            "/auth/recovery",
            {
                "username": "recover-spam",
                "recovery_code": f"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-{n:04d}",
                "new_password": PASSWORD + "r",
            },
        )
        assert reply.status == 401
    ok = ApiClient(rig.port).post(
        "/auth/recovery",
        {"username": "recover-spam", "recovery_code": codes[0], "new_password": PASSWORD + "s"},
    )
    assert ok.status == 200


# --- the command line's proof of what it is talking to -----------------------------------


def test_ping_proves_possession_of_the_secret_without_revealing_it(rig: ApiRig) -> None:
    secret = rig.runtime.cli_secret
    plain = ApiClient(rig.port).get("/ping")
    assert plain.status == 200 and "proof" not in plain.json
    assert set(plain.json) == {
        "service",
        "api",
        "version",
        "run_id",
        "setup_required",
        "simulation",
    }
    challenge = "0123456789abcdef0123456789abcdef"
    proven = ApiClient(rig.port).get("/ping", headers={CHALLENGE_HEADER: challenge})
    assert proven.json["proof"] == ping_proof(secret, challenge)
    assert secret not in proven.body.decode()
    other = ApiClient(rig.port).get(
        "/ping", headers={CHALLENGE_HEADER: "fedcba9876543210fedcba9876543210"}
    )
    assert other.json["proof"] != proven.json["proof"]
    assert proven.json["run_id"] == rig.runtime.service.run_id


@pytest.mark.parametrize("challenge", ["", "short", "G" * 32, "a" * 129, "A" * 32])
def test_a_malformed_challenge_is_refused(rig: ApiRig, challenge: str) -> None:
    reply = ApiClient(rig.port).get("/ping", headers={CHALLENGE_HEADER: challenge})
    assert reply.status == 400 and reply.error == "invalid_request"


def test_ping_reports_that_setup_is_required_until_an_administrator_exists(tmp_path: Path) -> None:
    machine = Harness(tmp_path)
    machine.boot()
    server = ApiServer(machine.rt, host="127.0.0.1", port=0)
    server.start()
    try:
        client = ApiClient(server.port)
        assert client.get("/ping").json["setup_required"] is True
        assert (
            client.post("/auth/login", {"username": ADMIN, "password": ADMIN_PASSWORD}).status
            == 401
        )
        machine.add_admin()
        assert client.get("/ping").json["setup_required"] is False
    finally:
        server.stop()
        machine.crash()


def test_commit_confirm_channels_follow_the_client(rig: ApiRig) -> None:
    make_user(rig, "channel-user")
    cli_login = rig.login(
        "channel-user", PASSWORD, headers={CLI_SECRET_HEADER: rig.runtime.cli_secret}
    )
    cli_token = cli_login.json["token"]
    engaged = ApiClient(rig.port, cli_token).post("/lockdown/engage", {"minutes": 5})
    assert engaged.status == 200
    change = engaged.json["change"]["id"]
    # A second command-line session of the same user is the same channel; a browser's is not.
    second = ApiClient(
        rig.port,
        rig.login(
            "channel-user", PASSWORD, headers={CLI_SECRET_HEADER: rig.runtime.cli_secret}
        ).json["token"],
    )
    browser = ApiClient(rig.port, rig.login("channel-user", PASSWORD).json["token"])
    assert browser.post(f"/changes/{change}/confirm").error == "wrong_channel"
    assert second.post(f"/changes/{change}/confirm").status == 200
    assert rig.client("admin").get("/lockdown").json["active"] is True
    rig.runtime.service.lockdown_lift(
        actor=ADMIN, credential=Credential("password", ADMIN_PASSWORD)
    )


def test_the_clock_is_the_injected_one(rig: ApiRig) -> None:
    before = rig.runtime.clock.now()
    session = rig.login(ADMIN, ADMIN_PASSWORD).json["session"]
    assert session["created_at"].startswith(before.strftime("%Y-%m-%dT%H:%M"))
    expires = rig.runtime.clock.now() + timedelta(hours=8)
    assert session["expires_at"].startswith(expires.strftime("%Y-%m-%dT%H"))
