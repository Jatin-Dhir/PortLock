"""The API's transport rules: limits, ``Host`` and ``Origin``, methods, strict parsing, the
static files, and the headers on every response (``docs/API.md`` section 2)."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_console_support import (
    WAIT,
    ApiClient,
    ApiRig,
    body_of,
    raw_exchange,
    status_of,
)

from factories import flash_drive
from portlock.console.api import CONTENT_SECURITY_POLICY, ApiServer


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path_factory.mktemp("http"))
    try:
        yield machine
    finally:
        machine.close()


def head(
    rig: ApiRig, request_line: str, *headers: str, host: bool = True, body: bytes = b""
) -> bytes:
    lines = [request_line]
    if host:
        lines.append(f"Host: 127.0.0.1:{rig.port}")
    lines += list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def authed(rig: ApiRig, role: str = "admin") -> str:
    return f"Authorization: Bearer {rig.token(role)}"


# --- headers on every response -----------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "role", "status"),
    [
        ("GET", "/ping", None, 200),
        ("GET", "/status", "admin", 200),
        ("GET", "/status", None, 401),
        ("GET", "/nothing", "admin", 404),
        ("POST", "/status", "admin", 405),
        ("DELETE", "/users/olivia-not-here", "admin", 404),
    ],
)
def test_every_response_carries_the_security_headers_and_no_cookie_or_cors(
    rig: ApiRig, method: str, path: str, role: str | None, status: int
) -> None:
    reply = rig.client(role).request(method, path)
    assert reply.status == status
    headers = reply.headers
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["connection"] == "close"
    assert headers["server"] == "PortLock"
    assert headers["content-type"].startswith("application/json")
    assert len(headers["x-request-id"]) == 16
    assert not any(name.startswith("access-control-") for name in headers)
    assert "set-cookie" not in headers
    if status >= 400:
        assert reply.json["error"]["request_id"] == headers["x-request-id"]


def test_a_cookie_is_neither_set_nor_believed(rig: ApiRig) -> None:
    token = rig.token("admin")
    client = ApiClient(rig.port)
    reply = client.get("/status", headers={"Cookie": f"portlock_session={token}"})
    assert reply.status == 401 and reply.error == "unauthenticated"
    login = rig.login("alice", "wrong password entirely")
    assert "set-cookie" not in login.headers


def test_the_json_never_contains_html_significant_characters(rig: ApiRig) -> None:
    hostile = flash_drive(
        "TEST0099XSS1", instance_id="test/9-9", product="<script>alert(1)</script> & co"
    )
    rig.harness.plug(hostile)
    try:
        reply = rig.client().get("/devices")
        assert b"<script>" not in reply.body and b"</script>" not in reply.body
        assert b"&" not in reply.body.replace(b"\\u0026", b"")
        names = [item["device"]["product"] for item in reply.json["devices"]]
        assert "<script>alert(1)</script> & co" in names  # the data itself is intact
    finally:
        rig.harness.unplug("test/9-9")


# --- Host and Origin ---------------------------------------------------------------------


@pytest.mark.parametrize("host", ["{ip}:{port}", "localhost:{port}", "LOCALHOST:{port}"])
def test_the_host_allowlist_accepts_the_names_it_serves(rig: ApiRig, host: str) -> None:
    value = host.format(ip="127.0.0.1", port=rig.port)
    assert rig.client().get("/status", headers={"Host": value}).status == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example:{port}",
        "127.0.0.1",
        "127.0.0.1:1",
        "localhost",
        "127.0.0.1.evil.example:{port}",
        "[::1]:{port}",
        "0.0.0.0:{port}",
        "",
    ],
)
def test_any_other_host_is_misdirected_even_for_a_public_route(rig: ApiRig, host: str) -> None:
    value = host.format(port=rig.port)
    reply = rig.client(None).get("/ping", headers={"Host": value})
    assert reply.status == 421 and reply.error == "host_not_allowed"


def test_a_missing_or_repeated_host_header_is_refused(rig: ApiRig) -> None:
    missing = raw_exchange(rig.port, head(rig, "GET /api/v1/ping HTTP/1.1", host=False))
    assert status_of(missing) == 421
    twice = raw_exchange(
        rig.port,
        head(rig, "GET /api/v1/ping HTTP/1.1", f"Host: evil.example:{rig.port}"),
    )
    assert status_of(twice) == 400
    old = raw_exchange(rig.port, b"GET /api/v1/ping HTTP/1.0\r\n\r\n")
    assert status_of(old) == 421


def test_http_1_0_with_a_host_header_is_served(rig: ApiRig) -> None:
    raw = raw_exchange(rig.port, head(rig, "GET /api/v1/ping HTTP/1.0"))
    assert status_of(raw) == 200 and body_of(raw)["service"] == "portlock"


@pytest.mark.parametrize(
    "origin",
    ["http://evil.example", "http://127.0.0.1:1", "null", "https://127.0.0.1:{port}", "file://"],
)
def test_a_foreign_origin_is_refused_for_every_method(rig: ApiRig, origin: str) -> None:
    value = origin.format(port=rig.port)
    client = rig.client()
    for method in ("GET", "POST", "DELETE"):
        reply = client.request(method, "/status", headers={"Origin": value})
        assert reply.status == 403 and reply.error == "origin_not_allowed"


def test_the_servers_own_origin_and_same_origin_fetches_pass(rig: ApiRig) -> None:
    client = rig.client()
    own = f"http://127.0.0.1:{rig.port}"
    assert client.get("/status", headers={"Origin": own}).status == 200
    assert client.get("/status", headers={"Sec-Fetch-Site": "same-origin"}).status == 200
    assert client.get("/status", headers={"Sec-Fetch-Site": "none"}).status == 200
    for site in ("cross-site", "same-site"):
        reply = client.get("/status", headers={"Sec-Fetch-Site": site})
        assert reply.status == 403 and reply.error == "origin_not_allowed"


# --- methods and paths -------------------------------------------------------------------


@pytest.mark.parametrize("method", ["OPTIONS", "TRACE", "CONNECT"])
def test_options_trace_and_connect_are_refused_and_never_get_cors_headers(
    rig: ApiRig, method: str
) -> None:
    for path in ("/status", "/nothing"):
        reply = rig.client().request(method, path)
        assert reply.status == 405 and reply.error == "method_not_allowed"
        assert not any(name.startswith("access-control-") for name in reply.headers)


def test_a_known_path_with_the_wrong_method_lists_what_is_allowed(rig: ApiRig) -> None:
    reply = rig.client().request("POST", "/status")
    assert reply.status == 405 and reply.headers["allow"] == "GET"
    reply = rig.client().request("DELETE", "/policy")
    assert reply.status == 405 and reply.headers["allow"] == "GET, PUT"


@pytest.mark.parametrize(
    "path",
    [
        "//status",
        "/status/",
        "/devices/../status",
        "/devices/%2e%2e%2fstatus",
        "/status%00",
        "/Status",
    ],
)
def test_paths_are_matched_exactly_with_no_normalisation(rig: ApiRig, path: str) -> None:
    assert rig.client().get(path).status == 404


@pytest.mark.parametrize(
    "path",
    [
        "/devices/plk1:short",
        "/devices/PLK1",
        "/connections/abc",
        "/connections/-1",
        "/trust/x",
        "/scans/1.5",
    ],
)
def test_ids_of_the_wrong_shape_are_not_routes(rig: ApiRig, path: str) -> None:
    assert rig.client().get(path).status == 404


def test_a_fingerprint_may_be_percent_encoded_in_a_path(rig: ApiRig) -> None:
    rig.harness.plug(flash_drive("TEST0098ENC1", instance_id="test/9-8"))
    try:
        fingerprint = rig.harness.view("test/9-8").fingerprint
        plain = rig.client().get(f"/devices/{fingerprint}")
        encoded = rig.client().get("/devices/" + fingerprint.replace(":", "%3A"))
        assert plain.status == encoded.status == 200
        assert plain.json["fingerprint"] == encoded.json["fingerprint"] == fingerprint
    finally:
        rig.harness.unplug("test/9-8")


# --- the body ----------------------------------------------------------------------------


def test_a_body_needs_the_json_content_type(rig: ApiRig) -> None:
    client = rig.client()
    body = {"policy": {"version": 1}}
    assert (
        client.post("/policy/validate", body, content_type=None).error == "unsupported_media_type"
    )
    assert client.post("/policy/validate", body, content_type="text/plain").status == 415
    assert (
        client.post(
            "/policy/validate", body, content_type="application/x-www-form-urlencoded"
        ).status
        == 415
    )
    assert (
        client.post(
            "/policy/validate", body, content_type="application/json; charset=utf-16"
        ).status
        == 415
    )
    assert (
        client.post("/policy/validate", body, content_type="application/json; charset=utf-8").status
        == 200
    )
    assert client.post("/policy/validate", body, content_type="Application/JSON").status == 200


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[1, 2]",
        b'"text"',
        b"null",
        b'{"policy": {}, "policy": {}}',
        b'{"policy": 1.5}',
        b'{"policy": NaN}',
        b'{"policy": Infinity}',
        b"\xff\xfe",
        b'{"policy": ' + b"[" * 200 + b"]" * 200 + b"}",
    ],
)
def test_a_body_that_is_not_strict_json_is_an_invalid_request(rig: ApiRig, raw: bytes) -> None:
    reply = rig.client().post("/policy/validate", raw=raw)
    assert reply.status == 400 and reply.error == "invalid_request"


def test_every_problem_in_a_request_is_reported_at_once(rig: ApiRig) -> None:
    reply = rig.client().post(
        "/trust", {"fingerprint": "nope", "read_only": "yes", "note": 5, "surprise": 1}
    )
    assert reply.status == 400 and reply.error == "invalid_request"
    problems = {
        item["path"]: item["message"] for item in reply.json["error"]["details"]["problems"]
    }
    assert set(problems) == {"fingerprint", "read_only", "note", "surprise"}
    assert problems["surprise"] == "is not a known field"


def test_a_missing_required_field_is_named(rig: ApiRig) -> None:
    reply = rig.client().post("/trust", {})
    assert reply.status == 400
    assert reply.json["error"]["details"]["problems"] == [
        {"path": "fingerprint", "message": "is required"}
    ]


def test_unknown_query_fields_are_an_error_not_ignored(rig: ApiRig) -> None:
    reply = rig.client().get("/devices", query={"state": "pending", "colour": "red"})
    assert reply.status == 400
    assert reply.json["error"]["details"]["problems"][0]["path"] == "colour"
    assert rig.client().get("/status", query={"x": "1"}).status == 400
    assert rig.client().get("/devices", query={"state": "nonsense"}).status == 400
    assert rig.client().get("/devices/history", query={"limit": "501"}).status == 400
    assert rig.client().get("/devices/history", query={"limit": "abc"}).status == 400
    assert rig.client().get("/devices/history", query={"limit": ["1", "2"]}).status == 400


@pytest.mark.parametrize("query", ["state=%ff", "a=1&&b", "=1", "x" + "&y=1" * 40])
def test_a_malformed_query_string_is_refused(rig: ApiRig, query: str) -> None:
    raw = raw_exchange(rig.port, head(rig, f"GET /api/v1/devices?{query} HTTP/1.1", authed(rig)))
    assert status_of(raw) == 400


def test_a_body_over_two_mebibytes_is_refused_and_the_answer_is_read(rig: ApiRig) -> None:
    big = b'{"policy": {"name": "' + b"a" * (2 * 1024 * 1024) + b'"}}'
    reply = rig.client().post("/policy/validate", raw=big)
    assert reply.status == 413 and reply.error == "body_too_large"
    exact = b'{"policy": {"name": "' + b"a" * 1000 + b'"}}'
    assert rig.client().post("/policy/validate", raw=exact).status == 200


def test_a_huge_declared_length_is_refused_without_reading_anything(rig: ApiRig) -> None:
    raw = raw_exchange(
        rig.port,
        head(
            rig,
            "POST /api/v1/policy/validate HTTP/1.1",
            authed(rig),
            "Content-Type: application/json",
            "Content-Length: 999999999999",
        ),
    )
    assert status_of(raw) == 413


def test_an_unauthenticated_body_is_never_read_but_the_error_still_arrives(rig: ApiRig) -> None:
    reply = ApiClient(rig.port).post("/policy/validate", raw=b"x" * (1024 * 1024))
    assert reply.status == 401


@pytest.mark.parametrize(
    "extra",
    [
        ["Transfer-Encoding: chunked"],
        ["Content-Length: abc"],
        ["Content-Length: -1"],
        ["Content-Length: 1", "Content-Length: 1"],
        ["Content-Length: 2", "Transfer-Encoding: chunked"],
        ["Authorization: Bearer x", "Authorization: Bearer y"],
        ["X Bad: header"],
        ["NoColonHere"],
        [" folded: header"],
    ],
)
def test_ambiguous_framing_and_malformed_headers_are_refused(rig: ApiRig, extra: list[str]) -> None:
    raw = raw_exchange(
        rig.port,
        head(
            rig,
            "POST /api/v1/policy/validate HTTP/1.1",
            "Content-Type: application/json",
            *extra,
            body=b"{}",
        ),
    )
    assert status_of(raw) == 400


def test_a_body_on_a_get_or_delete_is_refused(rig: ApiRig) -> None:
    for method, path in (("GET", "/status"), ("DELETE", "/users/nobody")):
        raw = raw_exchange(
            rig.port,
            head(
                rig,
                f"{method} /api/v1{path} HTTP/1.1",
                authed(rig),
                "Content-Length: 2",
                body=b"{}",
            ),
        )
        assert status_of(raw) == 400


def test_expect_continue_is_honoured(rig: ApiRig) -> None:
    payload = json.dumps({"policy": {"version": 1}}).encode()
    request = head(
        rig,
        "POST /api/v1/policy/validate HTTP/1.1",
        authed(rig),
        "Content-Type: application/json",
        f"Content-Length: {len(payload)}",
        "Expect: 100-continue",
    )
    with socket.create_connection(("127.0.0.1", rig.port), timeout=WAIT) as sock:
        sock.sendall(request)
        assert sock.recv(64).startswith(b"HTTP/1.1 100 Continue")
        sock.sendall(payload)
        chunks = b""
        while chunk := sock.recv(65536):
            chunks += chunk
    assert status_of(chunks) == 200


def test_other_expectations_are_refused(rig: ApiRig) -> None:
    raw = raw_exchange(
        rig.port,
        head(
            rig,
            "POST /api/v1/policy/validate HTTP/1.1",
            authed(rig),
            "Content-Type: application/json",
            "Content-Length: 2",
            "Expect: magic",
            body=b"{}",
        ),
    )
    assert status_of(raw) == 400


# --- the request line and the head -------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "GET /api/v1/ping",
        "get /api/v1/ping HTTP/1.1",
        "GET /api/v1/ping HTTP/2.0",
        "GET /api/v1/ping HTTP/1.1 extra",
        "GET http://127.0.0.1/api/v1/ping HTTP/1.1",
        "GET api/v1/ping HTTP/1.1",
        "GET /api/v1/ping#frag HTTP/1.1",
        "G\x00T /api/v1/ping HTTP/1.1",
        "GET /api/v1/ping\x00 HTTP/1.1",
        "GET /api/v1/p\u00efng HTTP/1.1",
    ],
)
def test_a_malformed_request_line_is_refused(rig: ApiRig, line: str) -> None:
    raw = raw_exchange(rig.port, head(rig, line))
    assert status_of(raw) == 400


def test_headers_over_sixteen_kibibytes_are_refused(rig: ApiRig) -> None:
    raw = raw_exchange(rig.port, head(rig, "GET /api/v1/ping HTTP/1.1", "X-Pad: " + "a" * 20000))
    assert status_of(raw) == 431
    long_line = raw_exchange(rig.port, ("GET /" + "a" * 20000 + " HTTP/1.1\r\n\r\n").encode())
    assert status_of(long_line) == 431
    many = [f"X-{n}: v" for n in range(3000)]
    assert status_of(raw_exchange(rig.port, head(rig, "GET /api/v1/ping HTTP/1.1", *many))) == 431


def test_only_one_request_is_served_per_connection(rig: ApiRig) -> None:
    one = head(rig, "GET /api/v1/ping HTTP/1.1")
    raw = raw_exchange(rig.port, one + one)
    assert raw.count(b"HTTP/1.1 200 OK") == 1


def test_a_client_that_stops_sending_is_disconnected(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, request_timeout=0.4)
    server.start()
    try:
        started = time.monotonic()
        raw = raw_exchange(server.port, b"GET /api/v1/ping HTTP/1.1\r\nHost: 127")
        assert raw == b""  # nothing to answer: the request never completed
        assert time.monotonic() - started < WAIT
        # A client that dribbles bytes still has only the total time to finish.
        with socket.create_connection(("127.0.0.1", server.port), timeout=WAIT) as sock:
            started = time.monotonic()
            try:
                for byte in b"GET /api/v1/ping HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX: " + b"a" * 100:
                    sock.sendall(bytes([byte]))
                    time.sleep(0.05)
            except OSError:
                pass
            assert time.monotonic() - started < 5.0
    finally:
        server.stop()


def test_a_busy_server_answers_503_without_reading_and_recovers(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, max_in_flight=2, request_timeout=30.0)
    server.start()
    held = [socket.create_connection(("127.0.0.1", server.port)) for _ in range(2)]
    try:
        deadline = time.monotonic() + WAIT
        reply = None
        while time.monotonic() < deadline:
            raw = raw_exchange(server.port, head(rig, "GET /api/v1/ping HTTP/1.1"))
            if status_of(raw) == 503:
                reply = body_of(raw)
                break
        assert reply is not None and reply["error"]["code"] == "server_busy"
        for sock in held:
            sock.close()
        recovered = False
        while time.monotonic() < deadline:
            raw = raw_exchange(
                server.port,
                f"GET /api/v1/ping HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode(),
            )
            if status_of(raw) == 200:
                recovered = True
                break
        assert recovered
    finally:
        for sock in held:
            sock.close()
        server.stop()


# --- the listener ------------------------------------------------------------------------


def test_the_listener_refuses_address_reuse_and_restarts_on_the_same_port(rig: ApiRig) -> None:
    first = ApiServer(rig.runtime, host="127.0.0.1", port=0)
    first.start()
    port = first.port
    try:
        second = ApiServer(rig.runtime, host="127.0.0.1", port=port)
        with pytest.raises(OSError):
            second.start()
        # A refused start leaves nothing listening that it owns.
        assert ApiClient(port).get("/ping").status == 200
    finally:
        first.stop()
    again = ApiServer(rig.runtime, host="127.0.0.1", port=port)
    again.start()
    try:
        assert ApiClient(port).get("/ping").status == 200
    finally:
        again.stop()


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "192.0.2.1", "::", "example.com", "localhost"],  # noqa: S104
)
def test_the_server_refuses_to_listen_anywhere_but_loopback(rig: ApiRig, host: str) -> None:
    with pytest.raises(ValueError):
        ApiServer(rig.runtime, host=host, port=0)


def test_the_bound_port_is_reported_and_stop_is_idempotent(rig: ApiRig) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0)
    assert server.port == 0
    server.start()
    assert server.port != 0 and server.address == ("127.0.0.1", server.port)
    with pytest.raises(RuntimeError):
        server.start()
    server.stop()
    server.stop()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", server.port), timeout=1).close()


# --- static files ------------------------------------------------------------------------


@pytest.fixture
def console(rig: ApiRig, tmp_path: Path) -> Iterator[tuple[ApiServer, Path]]:
    root = tmp_path / "static"
    (root / "sub").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>PortLock</title>", encoding="utf-8")
    (root / "app.js").write_text("console.log('ok');", encoding="utf-8")
    (root / "app.css").write_text("body{margin:0}", encoding="utf-8")
    (root / "sub" / "icon.svg").write_text(
        "<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8"
    )
    (root / "secret.py").write_text("not served", encoding="utf-8")
    (root / "portlock.db").write_bytes(b"SQLite format 3")
    (root / ".hidden.js").write_text("hidden", encoding="utf-8")
    (root / "big.js").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, static_root=root)
    server.start()
    try:
        yield server, root
    finally:
        server.stop()


def test_the_console_files_are_served_with_the_strict_policy(
    console: tuple[ApiServer, Path],
) -> None:
    server, _root = console
    client = ApiClient(server.port)
    for path, kind in (
        ("/", "text/html; charset=utf-8"),
        ("/static/index.html", "text/html; charset=utf-8"),
        ("/static/app.js", "text/javascript; charset=utf-8"),
        ("/app.css", "text/css; charset=utf-8"),
        ("/static/sub/icon.svg", "image/svg+xml"),
    ):
        reply = client.get(path, token=None, base="")
        assert reply.status == 200, path
        assert reply.headers["content-type"] == kind
        assert reply.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
        assert reply.headers["x-content-type-options"] == "nosniff"
        assert reply.headers["x-frame-options"] == "DENY"
        assert "set-cookie" not in reply.headers
    assert client.get("/", token=None, base="").body.startswith(b"<!doctype html>")
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY
    assert (
        "'unsafe-inline'" not in CONTENT_SECURITY_POLICY
        and "'unsafe-eval'" not in CONTENT_SECURITY_POLICY
    )
    assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY


def test_static_files_support_etags_and_head(console: tuple[ApiServer, Path]) -> None:
    server, _root = console
    client = ApiClient(server.port)
    first = client.get("/static/app.js", token=None, base="")
    tag = first.headers["etag"]
    assert (
        client.get("/static/app.js", token=None, base="", headers={"If-None-Match": tag}).status
        == 304
    )
    assert (
        client.get(
            "/static/app.js", token=None, base="", headers={"If-None-Match": '"other"'}
        ).status
        == 200
    )
    head_reply = client.request("HEAD", "/static/app.js", token=None, base="")
    assert head_reply.status == 200 and head_reply.body == b""
    assert head_reply.headers["content-type"].startswith("text/javascript")


@pytest.mark.parametrize(
    "path",
    [
        "/static/../portlock.db",
        "/static/%2e%2e/portlock.db",
        "/static/..%2fportlock.db",
        "/..%2fportlock.db",
        "/static/secret.py",
        "/secret.py",
        "/portlock.db",
        "/static/.hidden.js",
        "/static/big.js",
        "/static/",
        "/static/sub",
        "/static/sub/",
        "/static//app.js",
        "/static/app.js/",
        "/etc/passwd",
        "/static/C:/Windows/win.ini",
        "/static/app.js%00.txt",
    ],
)
def test_nothing_but_the_loaded_console_files_is_served(
    console: tuple[ApiServer, Path], path: str
) -> None:
    server, _root = console
    reply = ApiClient(server.port).get(path, token=None, base="")
    assert reply.status == 404 and reply.error == "not_found"


def test_static_files_are_loaded_once_the_file_system_is_not_consulted_per_request(
    console: tuple[ApiServer, Path],
) -> None:
    server, root = console
    (root / "app.js").write_text("changed on disk", encoding="utf-8")
    (root / "index.html").unlink()
    client = ApiClient(server.port)
    assert client.get("/static/app.js", token=None, base="").body == b"console.log('ok');"
    assert client.get("/", token=None, base="").status == 200


def test_static_files_only_answer_get_and_head_and_still_check_the_host(
    console: tuple[ApiServer, Path],
) -> None:
    server, _root = console
    client = ApiClient(server.port)
    reply = client.post("/static/app.js", {}, token=None, base="")
    assert reply.status == 405 and reply.headers["allow"] == "GET, HEAD"
    assert client.get("/", token=None, base="", headers={"Host": "evil.example"}).status == 421
    assert (
        client.get(
            "/static/app.js", token=None, base="", headers={"Origin": "http://evil.example"}
        ).status
        == 403
    )


def test_without_a_console_the_root_is_a_json_404(rig: ApiRig, tmp_path: Path) -> None:
    server = ApiServer(rig.runtime, host="127.0.0.1", port=0, static_root=tmp_path / "nothing")
    server.start()
    try:
        reply = ApiClient(server.port).get("/", token=None, base="")
        assert reply.status == 404 and reply.error == "not_found"
        assert ApiClient(server.port).get("/ping", token=None).status == 200
    finally:
        server.stop()


def test_the_api_itself_does_not_serve_the_static_policy_but_still_refuses_sniffing(
    rig: ApiRig,
) -> None:
    reply = rig.client().get("/status")
    assert "content-security-policy" not in reply.headers
    assert reply.headers["x-content-type-options"] == "nosniff"


def test_a_concurrent_burst_of_requests_is_answered(rig: ApiRig) -> None:
    results: list[int] = []
    lock = threading.Lock()

    client = rig.client()

    def one() -> None:
        reply = client.get("/status")
        with lock:
            results.append(reply.status)

    threads = [threading.Thread(target=one) for _ in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WAIT)
    assert sorted(results) == [200] * 24
