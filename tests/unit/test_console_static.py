"""The web console's static files (``console/static/``): what they may contain, whether they
agree with the API, and that the server really serves them under the content security policy.

There is no browser here, so these tests check what can be checked from the source and over a
real socket: the policy the files are served under forbids inline script and style and any
other host, so a file that needs one would be dead on arrival; every API call the scripts make
must be a route of ``docs/API.md`` with only query fields that route accepts; and nothing a
device says may reach the page as markup, which in a no-build console means no ``innerHTML``
anywhere."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_console_support import ApiClient, ApiRig

from integration.harness import START
from portlock.console.api import CONTENT_SECURITY_POLICY, ROUTES, _load_static
from portlock.core.clock import FakeClock

STATIC = Path(__file__).resolve().parents[2] / "src" / "portlock" / "console" / "static"
ROOT = STATIC.parents[3]
FILES = sorted(path for path in STATIC.rglob("*") if path.is_file())
JS_FILES = [path for path in FILES if path.suffix == ".js"]
CSS_FILES = [path for path in FILES if path.suffix == ".css"]


def rel(path: Path) -> str:
    return path.relative_to(STATIC).as_posix()


def code_of(path: Path) -> str:
    """JavaScript with comments removed, so a banned word in a comment is not a finding."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$|(?<=[\s;,)])//\s.*$", "", text)


# --- the files exist and are within what the server will serve --------------------------


def test_the_console_has_its_files() -> None:
    names = {rel(path) for path in FILES}
    assert {"index.html", "favicon.svg", "js/main.js", "js/api.js", "js/events.js"} <= names
    assert {"css/tokens.css", "css/base.css", "css/components.css", "css/views.css"} <= names


def test_every_file_fits_the_servers_limits_and_the_path_budget() -> None:
    assert len(FILES) <= 256
    for path in FILES:
        assert path.stat().st_size <= 2 * 1024 * 1024, rel(path)
        assert path.name.isascii() and not path.name.startswith("."), rel(path)
        # The checkout path is long on Windows: repository-relative paths stay short.
        assert len(path.relative_to(ROOT).as_posix()) < 80, rel(path)
    served = _load_static(STATIC)  # type: ignore[arg-type]
    assert {rel(path) for path in FILES} == set(served)


# --- what the content security policy forbids -------------------------------------------


def test_index_html_needs_no_inline_script_style_or_other_host() -> None:
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert re.findall(r"<script\b[^>]*>", html) == ['<script type="module" src="js/main.js">']
    assert "<style" not in html.lower()
    assert not re.search(r"\sstyle\s*=", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert not re.search(r"(?:src|href|action)\s*=\s*[\"'](?:[a-z]+:)?//", html, re.I)
    assert "http://" not in html and "https://" not in html


def test_stylesheets_load_nothing_from_anywhere() -> None:
    for path in CSS_FILES:
        text = path.read_text(encoding="utf-8")
        assert "@import" not in text, rel(path)
        assert "@font-face" not in text, rel(path)  # font-src is 'none': system fonts only
        assert "data:" not in text, rel(path)  # img-src is 'self'
        assert not re.search(r"url\(\s*[\"']?(?:[a-z]+:)?//", text, re.I), rel(path)
        assert "http://" not in text and "https://" not in text, rel(path)


BANNED = {
    # Device text must reach the page as text nodes only.
    "innerHTML": r"\binnerHTML\b",
    "outerHTML": r"\bouterHTML\b",
    "insertAdjacentHTML": r"\binsertAdjacentHTML\b",
    "document.write": r"\bdocument\s*\.\s*write(?:ln)?\b",
    "DOMParser": r"\bDOMParser\b",
    "createContextualFragment": r"\bcreateContextualFragment\b",
    "srcdoc": r"\bsrcdoc\b",
    # No code from strings, and no inline style (style-src 'self').
    "eval": r"\beval\s*\(",
    "new Function": r"\bnew\s+Function\b",
    "string timer": r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]",
    "setAttribute style": r"setAttribute\(\s*[\"']style[\"']",
    "cssText": r"\bcssText\b",
    # The bearer token lives in memory: never a cookie, a URL or web storage.
    "cookie": r"\bdocument\s*\.\s*cookie\b",
    "localStorage": r"\blocalStorage\b",
    "sessionStorage": r"\bsessionStorage\b",
    "indexedDB": r"\bindexedDB\b",
    "EventSource": r"\bEventSource\b",  # cannot send an Authorization header
    "XMLHttpRequest": r"\bXMLHttpRequest\b",
    "WebSocket": r"\bWebSocket\b",
    "sendBeacon": r"\bsendBeacon\b",
    "location redirect": r"\blocation\s*\.\s*(?:href|assign|replace)\s*=",
    "external URL": r"[\"'`](?:https?:)?//[a-z0-9]",
    "token in URL": r"[?&]token=",
    "script injection": r"createElement\(\s*[\"'](?:script|style|link|iframe)[\"']",
}


@pytest.mark.parametrize("name", sorted(BANNED))
def test_no_script_uses_a_banned_construct(name: str) -> None:
    pattern = re.compile(BANNED[name])
    offenders = [rel(path) for path in JS_FILES if pattern.search(code_of(path))]
    assert offenders == [], f"{name} is not allowed in the console: {offenders}"


def test_dynamic_imports_name_only_the_consoles_own_modules() -> None:
    main = code_of(STATIC / "js" / "main.js")
    modules = re.findall(r'module:\s*"(\./views/[a-z]+\.js)"', main)
    assert len(modules) >= 11
    for module in modules:
        assert (STATIC / "js" / module).is_file(), module
    # The one dynamic import takes its target from that table, never from the URL or the page.
    assert re.findall(r"\bimport\(([^)]*)\)", main) == ["view.module"]


def test_static_imports_resolve_and_views_export_mount() -> None:
    for path in JS_FILES:
        for target in re.findall(
            r'(?m)^\s*(?:import|export)\b[^;]*?from\s+"([^"]+)"', code_of(path)
        ):
            assert target.startswith("./") or target.startswith("../"), (rel(path), target)
            resolved = (path.parent / target).resolve()
            assert resolved.is_file(), f"{rel(path)} imports {target}, which does not exist"
            assert STATIC in resolved.parents
    for path in (STATIC / "js" / "views").glob("*.js"):
        assert re.search(
            r"(?m)^export (?:async )?function mount\(root\)", path.read_text("utf-8")
        ), path.name


def test_the_page_never_builds_markup_from_a_string() -> None:
    """``h()`` is the only way to make elements; it takes tags and text, never HTML."""
    dom = code_of(STATIC / "js" / "dom.js")
    assert "createElement(tag)" in dom and "createTextNode" in dom
    assert "style" in dom and "blocked by the content security policy" in dom


# --- the scripts and the API agree ------------------------------------------------------

CALL = re.compile(r"\bapi\.(get|post|put|patch|del)\(")
VERB = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "del": "DELETE"}


def split_arguments(source: str, start: int) -> list[str]:
    """The top-level arguments of the call whose ``(`` is just before ``start``."""
    arguments: list[str] = []
    depth = 0
    current: list[str] = []
    quote = ""
    i = start
    while i < len(source):
        char = source[i]
        if quote:
            current.append(char)
            if char == "\\":
                current.append(source[i + 1])
                i += 1
            elif char == quote:
                quote = ""
        elif char in "\"'`":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            if depth == 0:
                arguments.append("".join(current).strip())
                return arguments
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        i += 1
    raise AssertionError("unterminated call")


def calls() -> Iterator[tuple[str, str, str, list[str]]]:
    for path in JS_FILES:
        source = code_of(path)
        for match in CALL.finditer(source):
            arguments = split_arguments(source, match.end())
            literal = arguments[0]
            assert literal[0] in "\"'`", f"{rel(path)}: an API path must be a literal: {literal}"
            target = re.sub(r"\$\{[^}]*\}", "X", literal[1:-1])
            yield rel(path), VERB[match.group(1)], target, arguments


def route_for(method: str, path: str):  # type: ignore[no-untyped-def]
    for route in ROUTES:
        if route.method != method:
            continue
        pattern = "^" + re.sub(r"\{[a-z_]+\}", "[^/]+", route.pattern) + "$"
        if re.match(pattern, path):
            return route
    return None


def test_the_scripts_make_calls() -> None:
    assert len(list(calls())) >= 60


def test_every_api_call_is_a_route_of_the_api() -> None:
    for file, method, path, _arguments in calls():
        assert route_for(method, path) is not None, f"{file}: {method} {path} is not an endpoint"


def test_every_query_field_a_script_sends_is_accepted_by_its_route() -> None:
    checked = 0
    for file, method, path, arguments in calls():
        route = route_for(method, path)
        assert route is not None
        position = 1 if method in ("GET", "DELETE") else None
        if (
            position is None
            or len(arguments) <= position
            or not arguments[position].startswith("{")
        ):
            continue
        body = arguments[position][1:-1]
        fields = [part.strip() for part in re.split(r",(?![^{(\[]*[})\]])", body) if part.strip()]
        for part in fields:
            if part.startswith("..."):
                continue
            name = re.match(r"([A-Za-z_]\w*)", part)
            assert name, (file, part)
            assert name.group(1) in route.query, (
                f"{file}: {method} {path} does not take {name.group(1)}"
            )
            checked += 1
    assert checked >= 8


def test_the_event_stream_is_read_with_fetch_and_the_authorization_header() -> None:
    events = code_of(STATIC / "js" / "events.js")
    assert '"/api/v1/events"' in events
    assert "authHeaders()" in events
    assert "Last-Event-ID" in events
    assert route_for("GET", "/events") is not None
    api = code_of(STATIC / "js" / "api.js")
    assert 'credentials: "omit"' in api  # the API ignores cookies; the page sends none
    assert "Authorization" in api


def test_every_event_the_console_applies_is_in_the_documented_list() -> None:
    documented = set(
        re.findall(r"(?m)^\| `([a-z.]+)` \|", (ROOT / "docs" / "API.md").read_text("utf-8"))
    )
    store = code_of(STATIC / "js" / "store.js")
    used = set(re.findall(r'case "([a-z.]+)":', store))
    assert used, "no events found in store.js"
    assert used <= documented, sorted(used - documented)


# --- served for real, under the policy --------------------------------------------------


@pytest.fixture(scope="module")
def rig(tmp_path_factory: pytest.TempPathFactory) -> Iterator[ApiRig]:
    machine = ApiRig(tmp_path_factory.mktemp("console"), roles=("admin",), clock=FakeClock(START))
    try:
        yield machine
    finally:
        machine.close()


def test_the_server_serves_the_console_under_the_policy(rig: ApiRig) -> None:
    client = ApiClient(rig.port)
    page = client.request("GET", "/", base="")
    assert page.status == 200
    assert page.headers["content-type"] == "text/html; charset=utf-8"
    assert page.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "set-cookie" not in page.headers
    assert page.body == (STATIC / "index.html").read_bytes()
    kinds = {
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
    }
    for path in FILES:
        if path.suffix in kinds:
            reply = client.request("GET", "/" + rel(path), base="")
            assert reply.status == 200, rel(path)
            assert reply.headers["content-type"] == kinds[path.suffix], rel(path)
            assert reply.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
            assert reply.body == path.read_bytes()
    missing = client.request("GET", "/js/not-there.js", base="")
    assert missing.status == 404


def test_the_console_files_need_no_session_and_hold_no_data(rig: ApiRig) -> None:
    anonymous = ApiClient(rig.port)
    assert anonymous.request("GET", "/js/main.js", base="").status == 200
    assert anonymous.request("GET", "/status").status == 401
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        assert "portlock-sim" not in text and "BEGIN " not in text, rel(path)
