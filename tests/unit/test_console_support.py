"""Helpers for the console tests (no tests of its own).

``ApiRig`` is a whole PortLock process on a simulated machine (``integration.harness``:
real SQLite stores, a real journal, the fake backend and enforcer, a fake clock) with the
real HTTP API listening on an ephemeral loopback port and one logged-in session per role.
``ApiClient`` talks to it over a real socket; ``raw_exchange`` sends arbitrary bytes, for
the requests a well-behaved client never makes.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import threading
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from integration.harness import ADMIN, ADMIN_PASSWORD, Harness
from portlock.console.api import ApiServer

OPERATOR = "olivia"
AUDITOR = "arthur"
OPERATOR_PASSWORD = "operator passphrase number 12"
AUDITOR_PASSWORD = "auditor passphrase number 345"
ROLES = ("admin", "operator", "auditor")
WAIT = 10.0


@dataclass(slots=True)
class Reply:
    """One HTTP response."""

    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8")) if self.body else None

    @property
    def error(self) -> str | None:
        data = self.json
        return data["error"]["code"] if isinstance(data, dict) and "error" in data else None


class ApiClient:
    """A client of the API on ``port``; ``token`` is sent as the bearer token."""

    def __init__(self, port: int, token: str | None = None) -> None:
        self.port = port
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        token: str | None = ...,  # type: ignore[assignment]
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, Any] | None = None,
        raw: bytes | None = None,
        content_type: str | None = "application/json",
        base: str = "/api/v1",
    ) -> Reply:
        use = self.token if token is ... else token
        target = base + path
        if query:
            target += "?" + urllib.parse.urlencode(query, doseq=True)
        send: dict[str, str] = {}
        if use is not None:
            send["Authorization"] = f"Bearer {use}"
        data = raw
        if data is None and body is not None:
            data = json.dumps(body).encode("utf-8")
        if data is not None and content_type is not None:
            send["Content-Type"] = content_type
        send.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=WAIT)
        try:
            connection.request(method, target, body=data, headers=send)
            response = connection.getresponse()
            payload = response.read()
            return Reply(response.status, {k.lower(): v for k, v in response.getheaders()}, payload)
        finally:
            connection.close()

    def get(self, path: str, **kwargs: Any) -> Reply:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, body: Any = None, **kwargs: Any) -> Reply:
        return self.request("POST", path, body, **kwargs)

    def put(self, path: str, body: Any = None, **kwargs: Any) -> Reply:
        return self.request("PUT", path, body, **kwargs)

    def patch(self, path: str, body: Any = None, **kwargs: Any) -> Reply:
        return self.request("PATCH", path, body, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Reply:
        return self.request("DELETE", path, **kwargs)


def raw_exchange(
    port: int, data: bytes, *, timeout: float = 5.0, close_write: bool = False
) -> bytes:
    """Send ``data`` as it is and return everything the server answers until it closes."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        with contextlib.suppress(OSError):
            sock.sendall(data)
        if close_write:
            sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        try:
            while chunk := sock.recv(65536):
                chunks.append(chunk)
        except OSError:
            pass
        return b"".join(chunks)


def status_of(raw: bytes) -> int:
    """The status code of a raw HTTP response (0 if there is none)."""
    first = raw.split(b"\r\n", 1)[0].split(b" ")
    return int(first[1]) if len(first) >= 2 and first[1].isdigit() else 0


def body_of(raw: bytes) -> Any:
    _head, _, payload = raw.partition(b"\r\n\r\n")
    return json.loads(payload.decode("utf-8")) if payload else None


class ApiRig:
    """The machine, the process and the API, with a session for each role."""

    def __init__(self, tmp_path: Path, *, roles: tuple[str, ...] = ROLES, **options: Any) -> None:
        self.harness = Harness(tmp_path, **options)
        self.harness.boot()
        self.harness.add_admin()
        accounts = self.runtime.accounts
        if "operator" in roles:
            accounts.create_user(OPERATOR, OPERATOR_PASSWORD, "operator", actor="setup")
        if "auditor" in roles:
            accounts.create_user(AUDITOR, AUDITOR_PASSWORD, "auditor", actor="setup")
        self.server = ApiServer(self.runtime, host="127.0.0.1", port=0)
        self.server.start()

    @property
    def runtime(self) -> Any:
        return self.harness.rt

    @property
    def port(self) -> int:
        return self.server.port

    def token(self, role: str) -> str:
        """A fresh session token for the account of ``role``.

        Made directly in the session store, so it is as old as the fake clock says: tests
        that move the clock far get a new one instead of an expired one.
        """
        name = {"admin": ADMIN, "operator": OPERATOR, "auditor": AUDITOR}[role]
        token, _session = self.runtime.sessions.create(name, role, client="api")
        return token

    def client(self, role: str | None = "admin") -> ApiClient:
        return ApiClient(self.port, self.token(role) if role is not None else None)

    def login(self, username: str, password: str, **kwargs: Any) -> Reply:
        return ApiClient(self.port).post(
            "/auth/login", {"username": username, "password": password}, **kwargs
        )

    def close(self) -> None:
        self.server.stop()
        if self.harness.runtime is not None:
            self.harness.crash()


def admin_login_body() -> dict[str, str]:
    return {"username": ADMIN, "password": ADMIN_PASSWORD}


def wait_for(event: threading.Event) -> None:
    if not event.wait(WAIT):
        raise AssertionError("timed out waiting for a thread")
