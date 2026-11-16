"""Sessions: tokens, the two timeouts, revocation, the per-user cap."""

from __future__ import annotations

import hashlib
import re
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from portlock.auth import sessions as sessions_module
from portlock.auth.accounts import (
    AccountStore,
    AuthPolicy,
    InvalidUsernameError,
    Permission,
    Role,
)
from portlock.auth.passwords import ScryptParams
from portlock.auth.sessions import (
    DEFAULT_ABSOLUTE_TIMEOUT,
    DEFAULT_IDLE_TIMEOUT,
    Session,
    SessionStore,
)
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import AuthError, ConfigError

TOKEN_FORMAT = re.compile(r"[A-Za-z0-9_-]{43}\Z")
PASSWORD = "granite-otter-73-lamp"
MINUTE = timedelta(minutes=1)


@pytest.fixture
def sessions(db: Database, clock: FakeClock) -> SessionStore:
    return SessionStore(db, clock=clock)


def row_count(db: Database) -> int:
    row = db.query_one("SELECT COUNT(*) AS n FROM auth_sessions")
    assert row is not None
    return int(row["n"])


def last_seen(db: Database) -> str:
    row = db.query_one("SELECT last_seen_at FROM auth_sessions")
    assert row is not None
    return str(row["last_seen_at"])


# --- creation ------------------------------------------------------------------------


def test_defaults_are_the_design_timeouts() -> None:
    assert timedelta(minutes=15) == DEFAULT_IDLE_TIMEOUT
    assert timedelta(hours=8) == DEFAULT_ABSOLUTE_TIMEOUT


def test_create_returns_a_256_bit_token_and_a_session(
    sessions: SessionStore, clock: FakeClock
) -> None:
    token, session = sessions.create("Root-Admin", Role.ADMIN, client="127.0.0.1 console")
    assert TOKEN_FORMAT.match(token), "43 URL-safe characters carry 256 bits"
    assert re.fullmatch(r"[0-9a-f]{16}", session.session_id)
    assert (session.username, session.role, session.client) == (
        "root-admin",
        Role.ADMIN,
        "127.0.0.1 console",
    )
    assert session.created_at == session.last_seen_at == clock.now()
    assert session.expires_at == clock.now() + timedelta(hours=8)
    assert session.idle_expires_at == clock.now() + timedelta(minutes=15)
    assert sessions.validate(token) == session


def test_only_a_digest_of_the_token_is_stored(sessions: SessionStore, db: Database) -> None:
    token, session = sessions.create("root-admin", Role.ADMIN, client=None)
    rows = db.query("SELECT * FROM auth_sessions")
    assert len(rows) == 1
    assert token not in "|".join(str(value) for value in tuple(rows[0]))
    assert rows[0]["token_digest"] == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert rows[0]["session_id"] == session.session_id
    # The digest is not accepted in place of the token.
    assert sessions.validate(rows[0]["token_digest"]) is None


def test_tokens_and_ids_are_all_distinct(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=100)
    made = [sessions.create("root-admin", Role.ADMIN, client=None) for _ in range(40)]
    values = [token for token, _ in made]
    values += [session.session_id for _, session in made]
    assert len(set(values)) == 80


def test_roles_are_accepted_by_name_and_kept(sessions: SessionStore) -> None:
    token, session = sessions.create("day-shift", "operator", client=None)
    assert session.role is Role.OPERATOR
    validated = sessions.validate(token)
    assert validated is not None and validated.role is Role.OPERATOR
    assert validated.can(Permission.APPROVE_DEVICE) and not validated.can(Permission.EDIT_POLICY)


@pytest.mark.parametrize("username", ["", "ab", "has space", "x" * 33, None, 7])
def test_create_refuses_malformed_usernames(sessions: SessionStore, username: object) -> None:
    with pytest.raises(InvalidUsernameError):
        sessions.create(username, Role.ADMIN, client=None)  # type: ignore[arg-type]


def test_create_refuses_unknown_roles_and_non_text_clients(
    sessions: SessionStore, db: Database
) -> None:
    with pytest.raises(AuthError) as caught:
        sessions.create("root-admin", "superuser", client=None)
    assert caught.value.code == "invalid_role"
    with pytest.raises(AuthError) as caught:
        sessions.create("root-admin", Role.ADMIN, client=b"curl")  # type: ignore[arg-type]
    assert caught.value.code == "invalid_client"
    assert row_count(db) == 0


@pytest.mark.parametrize(
    ("client", "stored"),
    [
        ("Mozilla/5.0 (X11)", "Mozilla/5.0 (X11)"),
        ("line\r\nbreak\x00nul\x1b[31m", "line??break?nul?[31m"),
        ("a" * 500, "a" * 128),
        ("   ", None),
        ("", None),
        (chr(0xD800) + "x", "?x"),
    ],
    ids=["plain", "control", "long", "blank", "empty", "surrogate"],
)
def test_client_descriptions_are_bounded_and_defused(
    sessions: SessionStore, client: str, stored: str | None
) -> None:
    token, session = sessions.create("root-admin", Role.ADMIN, client=client)
    assert session.client == stored
    validated = sessions.validate(token)
    assert validated is not None and validated.client == stored


# --- validation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "a" * 42,
        "a" * 44,
        "a" * 43,
        "!" * 43,
        "a" * 42 + "\n",
        "a" * 42 + "=",
        "\N{LATIN SMALL LETTER A WITH ACUTE}" * 43,
        "x" * 1_000_000,
        b"a" * 43,
        12345,
    ],
    ids=[
        "none",
        "empty",
        "short",
        "long",
        "unknown",
        "symbols",
        "newline",
        "padding",
        "non-ascii",
        "huge",
        "bytes",
        "int",
    ],
)
def test_unknown_and_malformed_tokens_are_not_sessions(
    sessions: SessionStore, token: object
) -> None:
    real, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    assert sessions.validate(token) is None  # type: ignore[arg-type]
    assert sessions.revoke(token) is False  # type: ignore[arg-type]
    assert sessions.validate(real) is not None


def test_malformed_tokens_are_rejected_before_being_hashed(
    sessions: SessionStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    hashed: list[int] = []
    real = hashlib.sha256

    def counting(data: bytes = b"") -> Any:
        hashed.append(len(data))
        return real(data)

    monkeypatch.setattr("portlock.auth.sessions.hashlib.sha256", counting)
    assert sessions.validate("x" * 1_000_000) is None
    assert hashed == []
    assert sessions.validate("a" * 43) is None
    assert hashed == [43]


def test_a_session_ends_after_fifteen_idle_minutes(
    sessions: SessionStore, clock: FakeClock, db: Database
) -> None:
    token, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(timedelta(minutes=14, seconds=59))
    assert sessions.validate(token) is not None
    clock.advance(timedelta(minutes=14, seconds=59))
    assert sessions.validate(token) is not None, "the earlier request restarted the idle clock"
    clock.advance(timedelta(minutes=15))
    assert sessions.validate(token) is None
    assert row_count(db) == 0, "an expired session is deleted when it is seen"
    clock.advance(1)
    assert sessions.validate(token) is None


def test_a_session_ends_eight_hours_after_creation_however_busy(
    sessions: SessionStore, clock: FakeClock
) -> None:
    token, created = sessions.create("root-admin", Role.ADMIN, client=None)
    for _ in range(47):
        clock.advance(10 * MINUTE)
        session = sessions.validate(token)
        assert session is not None
        assert session.last_seen_at == clock.now()
        assert session.expires_at == created.expires_at, "activity never moves the hard limit"
    assert clock.now() - created.created_at == timedelta(hours=7, minutes=50)
    clock.advance(timedelta(minutes=9, seconds=59))
    assert sessions.validate(token) is not None
    clock.advance(1)
    assert sessions.validate(token) is None


def test_custom_timeouts_are_honoured(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(
        db, clock=clock, idle_timeout=timedelta(minutes=2), absolute_timeout=timedelta(minutes=5)
    )
    token, session = sessions.create("root-admin", Role.ADMIN, client=None)
    assert session.idle_expires_at - session.created_at == timedelta(minutes=2)
    for _ in range(4):
        clock.advance(MINUTE)
        assert sessions.validate(token) is not None
    clock.advance(MINUTE)
    assert sessions.validate(token) is None

    other, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(timedelta(minutes=2))
    assert sessions.validate(other) is None


def test_last_seen_is_written_at_most_once_a_minute(
    sessions: SessionStore, clock: FakeClock, db: Database
) -> None:
    token, created = sessions.create("root-admin", Role.ADMIN, client=None)
    at_creation = last_seen(db)
    for _ in range(5):
        clock.advance(11)
        session = sessions.validate(token)
        assert session is not None and session.last_seen_at == created.last_seen_at
    assert last_seen(db) == at_creation, "55 seconds of requests wrote nothing"

    clock.advance(5)
    session = sessions.validate(token)
    assert session is not None and session.last_seen_at == clock.now()
    assert session.idle_expires_at == clock.now() + timedelta(minutes=15)
    assert last_seen(db) == "2026-01-01T00:01:00.000000Z"


def test_write_throttling_can_only_end_a_session_early_never_late(
    sessions: SessionStore, clock: FakeClock
) -> None:
    token, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(59)
    assert sessions.validate(token) is not None  # seen, but too soon to be written down
    clock.advance(timedelta(minutes=15) - timedelta(seconds=59))
    # Truly idle for 14 min 1 s; the record says 15 min, and the record decides.
    assert sessions.validate(token) is None


def test_touch_interval_zero_records_every_request(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(db, clock=clock, touch_interval=timedelta(0))
    token, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(1)
    session = sessions.validate(token)
    assert session is not None and session.last_seen_at == clock.now()
    assert last_seen(db) == "2026-01-01T00:00:01.000000Z"


def test_a_short_idle_timeout_gets_a_proportionally_short_write_interval(
    db: Database, clock: FakeClock
) -> None:
    sessions = SessionStore(
        db, clock=clock, idle_timeout=MINUTE, absolute_timeout=timedelta(hours=1)
    )
    token, created = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(5)
    session = sessions.validate(token)
    assert session is not None and session.last_seen_at == created.last_seen_at
    clock.advance(1)
    session = sessions.validate(token)
    assert session is not None and session.last_seen_at == clock.now(), "written every 6 s"
    # Kept alive by a request every 50 seconds, which a one-minute write interval
    # (longer than the timeout itself) could never record in time.
    for _ in range(10):
        clock.advance(50)
        assert sessions.validate(token) is not None
    clock.advance(60)
    assert sessions.validate(token) is None


@pytest.mark.parametrize(
    ("idle", "absolute"),
    [
        (timedelta(minutes=1), timedelta(hours=1)),
        (timedelta(minutes=60), timedelta(hours=1)),
        (timedelta(minutes=1440), timedelta(hours=168)),
    ],
)
def test_every_timeout_the_configuration_file_allows_is_accepted(
    db: Database, clock: FakeClock, idle: timedelta, absolute: timedelta
) -> None:
    # The limits of api.session_idle_minutes and api.session_max_hours in core.config.
    sessions = SessionStore(db, clock=clock, idle_timeout=idle, absolute_timeout=absolute)
    token, session = sessions.create("root-admin", Role.ADMIN, client=None)
    assert session.idle_expires_at == clock.now() + idle
    assert session.expires_at == clock.now() + absolute
    clock.advance(idle - timedelta(seconds=1))
    assert sessions.validate(token) is not None
    clock.advance(idle)
    assert sessions.validate(token) is None


def test_a_clock_set_back_ends_sessions_instead_of_extending_them(
    sessions: SessionStore, clock: FakeClock, db: Database
) -> None:
    kept, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.set(clock.now() - timedelta(seconds=30))
    assert sessions.validate(kept) is not None, "a small correction is tolerated"

    clock.set(clock.now() - timedelta(hours=3))
    assert sessions.validate(kept) is None
    assert row_count(db) == 0


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE auth_sessions SET role = 'superuser'",
        "UPDATE auth_sessions SET created_at = 'never'",
        "UPDATE auth_sessions SET last_seen_at = '9999'",
        "UPDATE auth_sessions SET username = 'Not A Name'",
        "UPDATE auth_sessions SET created_at = '2999-01-01T00:00:00.000000Z'",
        "UPDATE auth_sessions SET last_seen_at = '2999-01-01T00:00:00.000000Z'",
        # So late that adding a timeout to it is past the end of the calendar.
        "UPDATE auth_sessions SET created_at = '9999-12-31T23:59:59.999999Z'",
        "UPDATE auth_sessions SET last_seen_at = '9999-12-31T23:59:59.999999Z'",
        "UPDATE auth_sessions SET created_at = '0001-01-01T00:00:00.000000Z'",
        "UPDATE auth_sessions SET last_seen_at = 7",
        "UPDATE auth_sessions SET role = x'61646d696e'",
    ],
)
def test_a_damaged_session_record_is_not_a_session(
    sessions: SessionStore, db: Database, tamper: str
) -> None:
    token, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    assert len(sessions.list_sessions()) == 1
    db.execute(tamper)
    assert sessions.list_sessions() == []
    assert sessions.validate(token) is None
    assert row_count(db) == 0


def test_sessions_survive_a_restart(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "portlock.db"
    with Database(path) as first:
        token, created = SessionStore(first, clock=clock).create(
            "root-admin", Role.ADMIN, client="cli"
        )
    clock.advance(30)
    with Database(path) as second:
        sessions = SessionStore(second, clock=clock)
        assert sessions.validate(token) == created
        clock.advance(timedelta(minutes=15))
        assert sessions.validate(token) is None


# --- bearer tokens only --------------------------------------------------------------


def test_a_session_has_one_secret_the_bearer_token(sessions: SessionStore, db: Database) -> None:
    token, session = sessions.create("root-admin", Role.ADMIN, client="console")
    assert not hasattr(session, "csrf_token") and not hasattr(session, "csrf_matches")
    columns = [row["name"] for row in db.query("PRAGMA table_info(auth_sessions)")]
    assert columns == [
        "token_digest",
        "session_id",
        "username",
        "role",
        "client",
        "created_at",
        "last_seen_at",
    ]
    assert session.to_dict() == {
        "session_id": session.session_id,
        "username": "root-admin",
        "role": "admin",
        "created_at": "2026-01-01T00:00:00.000000Z",
        "last_seen_at": "2026-01-01T00:00:00.000000Z",
        "expires_at": "2026-01-01T08:00:00.000000Z",
        "idle_expires_at": "2026-01-01T00:15:00.000000Z",
        "client": "console",
    }
    assert token not in repr(session) and token not in repr(session.to_dict())


def test_sessions_from_the_csrf_era_are_ended_by_the_migration(clock: FakeClock) -> None:
    with Database() as db:
        db.migrate("auth_sessions", sessions_module._MIGRATIONS[:1])
        stamp = "2026-01-01T00:00:00.000000Z"
        db.execute(
            "INSERT INTO auth_sessions VALUES (?, ?, 'root-admin', 'admin', ?, NULL, ?, ?)",
            ("ab" * 32, "0123456789abcdef", "c" * 43, stamp, stamp),
        )
        store = SessionStore(db, clock=clock)
        assert db.schema_version("auth_sessions") == 2
        assert row_count(db) == 0
        columns = {row["name"] for row in db.query("PRAGMA table_info(auth_sessions)")}
        assert "csrf_token" not in columns
        token, _ = store.create("root-admin", Role.ADMIN, client=None)
        assert store.validate(token) is not None


# --- revocation ----------------------------------------------------------------------


def test_revoke_ends_one_session(sessions: SessionStore) -> None:
    first, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    second, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    assert sessions.revoke(first) is True
    assert sessions.validate(first) is None
    assert sessions.validate(second) is not None
    assert sessions.revoke(first) is False


def test_revoke_by_id(sessions: SessionStore) -> None:
    token, session = sessions.create("root-admin", Role.ADMIN, client=None)
    for junk in ("", session.session_id[:-1], session.session_id + "0", "g" * 16, None, 5):
        assert sessions.revoke_by_id(junk) is False  # type: ignore[arg-type]
    assert sessions.validate(token) is not None
    assert sessions.revoke_by_id(session.session_id) is True
    assert sessions.validate(token) is None


def test_revoke_all_ends_every_session_of_one_account(sessions: SessionStore) -> None:
    mine = [sessions.create("root-admin", Role.ADMIN, client=None)[0] for _ in range(3)]
    theirs, _ = sessions.create("day-shift", Role.OPERATOR, client=None)
    assert sessions.revoke_all("ROOT-ADMIN") == 3
    assert [sessions.validate(token) for token in mine] == [None, None, None]
    assert sessions.validate(theirs) is not None
    assert sessions.revoke_all("root-admin") == 0
    assert sessions.revoke_all("not a name") == 0
    assert sessions.revoke_all(None) == 0  # type: ignore[arg-type]


def test_revoke_all_spares_no_session(sessions: SessionStore) -> None:
    tokens = [sessions.create("root-admin", Role.ADMIN, client=None)[0] for _ in range(4)]
    with pytest.raises(TypeError):
        sessions.revoke_all("root-admin", keep=tokens[2])  # type: ignore[call-arg]
    assert sessions.revoke_all("root-admin") == 4
    assert [sessions.validate(token) for token in tokens] == [None] * 4


def test_purge_expired_removes_only_dead_sessions(
    sessions: SessionStore, clock: FakeClock, db: Database
) -> None:
    old, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    clock.advance(10 * MINUTE)
    recent, _ = sessions.create("day-shift", Role.OPERATOR, client=None)
    assert sessions.purge_expired() == 0

    clock.advance(5 * MINUTE)
    assert sessions.purge_expired() == 1
    assert row_count(db) == 1
    assert sessions.validate(old) is None
    assert sessions.validate(recent) is not None

    # Kept alive by activity, the survivor still falls to the absolute limit.
    for _ in range(47):
        clock.advance(10 * MINUTE)
        assert sessions.validate(recent) is not None
    assert sessions.purge_expired() == 0
    clock.advance(10 * MINUTE)
    assert sessions.purge_expired() == 1
    assert row_count(db) == 0


def test_list_sessions_shows_live_sessions_oldest_first(
    sessions: SessionStore, clock: FakeClock
) -> None:
    _, first = sessions.create("root-admin", Role.ADMIN, client="one")
    clock.advance(10 * MINUTE)
    _, second = sessions.create("day-shift", Role.OPERATOR, client="two")
    _, third = sessions.create("root-admin", Role.ADMIN, client="three")
    assert sessions.list_sessions() == [first, second, third]
    assert sessions.list_sessions("ROOT-ADMIN") == [first, third]
    assert sessions.list_sessions("nobody-here") == []
    assert sessions.list_sessions("not a name") == []
    clock.advance(5 * MINUTE)
    assert sessions.list_sessions() == [second, third], "the first has idled out"


# --- the per-user cap ----------------------------------------------------------------


def test_the_oldest_session_is_evicted_at_the_cap(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=3)
    tokens = []
    for _ in range(5):
        tokens.append(sessions.create("root-admin", Role.ADMIN, client=None)[0])
        clock.advance(1)
    other, _ = sessions.create("day-shift", Role.OPERATOR, client=None)
    assert [sessions.validate(token) is not None for token in tokens] == [
        False,
        False,
        True,
        True,
        True,
    ]
    assert sessions.validate(other) is not None
    assert len(sessions.list_sessions("root-admin")) == 3


def test_the_cap_evicts_in_creation_order_even_within_one_instant(
    db: Database, clock: FakeClock
) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=2)
    tokens = [sessions.create("root-admin", Role.ADMIN, client=None)[0] for _ in range(4)]
    assert [sessions.validate(token) is not None for token in tokens] == [False, False, True, True]


def test_expired_sessions_do_not_count_towards_the_cap(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=2)
    stale = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    clock.advance(14 * MINUTE)
    live = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    clock.advance(2 * MINUTE)
    newest = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    assert sessions.validate(stale) is None
    assert sessions.validate(live) is not None, "the expired one made room, not this one"
    assert sessions.validate(newest) is not None


def test_a_dead_session_makes_room_before_an_older_live_one_is_evicted(
    db: Database, clock: FakeClock
) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=2)
    in_use = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    clock.advance(MINUTE)
    abandoned = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    for _ in range(4):
        clock.advance(4 * MINUTE)
        assert sessions.validate(in_use) is not None
    # The older session is alive and the newer one idled out a minute ago.
    newest = sessions.create("root-admin", Role.ADMIN, client=None)[0]
    assert sessions.validate(in_use) is not None, "evicted in place of a dead session"
    assert sessions.validate(newest) is not None
    assert sessions.validate(abandoned) is None
    assert row_count(db) == 2


def test_concurrent_logins_never_exceed_the_cap(db: Database, clock: FakeClock) -> None:
    sessions = SessionStore(db, clock=clock, max_sessions_per_user=3)
    barrier = threading.Barrier(12)
    tokens: list[str] = []
    errors: list[BaseException] = []

    def login() -> None:
        try:
            barrier.wait(timeout=10)
            tokens.append(sessions.create("root-admin", Role.ADMIN, client=None)[0])
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=login) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == [] and len(tokens) == 12
    assert row_count(db) == 3
    assert sum(sessions.validate(token) is not None for token in tokens) == 3


def test_concurrent_requests_and_a_revocation_leave_nothing_behind(
    sessions: SessionStore, db: Database
) -> None:
    token, _ = sessions.create("root-admin", Role.ADMIN, client=None)
    barrier = threading.Barrier(9)
    seen: list[list[Session | None]] = [[] for _ in range(8)]
    errors: list[BaseException] = []

    def request(index: int) -> None:
        try:
            barrier.wait(timeout=10)
            for _ in range(20):
                seen[index].append(sessions.validate(token))
        except BaseException as exc:
            errors.append(exc)

    def revoke() -> None:
        try:
            barrier.wait(timeout=10)
            sessions.revoke_all("root-admin")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=request, args=(index,)) for index in range(8)]
    threads.append(threading.Thread(target=revoke))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == [] and [len(results) for results in seen] == [20] * 8
    assert sessions.validate(token) is None
    assert row_count(db) == 0
    # Once a thread has seen the revocation, it never sees the session again.
    for results in seen:
        gone = [value is None for value in results]
        assert gone == sorted(gone)


# --- configuration -------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"idle_timeout": timedelta(0)},
        {"idle_timeout": 900},
        {"absolute_timeout": timedelta(minutes=5)},
        {"absolute_timeout": None},
        {"touch_interval": timedelta(minutes=8)},
        {"touch_interval": timedelta(seconds=-1)},
        {"touch_interval": 60},
        {"max_sessions_per_user": 0},
        {"max_sessions_per_user": True},
        {"max_sessions_per_user": 2.5},
    ],
)
def test_out_of_range_settings_are_refused(
    db: Database, clock: FakeClock, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(ConfigError):
        SessionStore(db, clock=clock, **kwargs)


# --- following the account -----------------------------------------------------------


@pytest.fixture
def accounts(db: Database, clock: FakeClock) -> AccountStore:
    policy = AuthPolicy(scrypt=ScryptParams.insecure_fast_for_tests())
    store = AccountStore(db, clock=clock, policy=policy)
    store.create_user("root-admin", PASSWORD, Role.ADMIN)
    store.create_user("day-shift", PASSWORD, Role.OPERATOR)
    return store


@pytest.fixture
def checked(db: Database, clock: FakeClock, accounts: AccountStore) -> SessionStore:
    return SessionStore(db, clock=clock, account_lookup=accounts.get_user)


def test_a_session_ends_when_its_account_is_disabled(
    accounts: AccountStore, checked: SessionStore, db: Database
) -> None:
    token, _ = checked.create("day-shift", Role.OPERATOR, client=None)
    admin_token, _ = checked.create("root-admin", Role.ADMIN, client=None)
    assert checked.validate(token) is not None
    accounts.disable_user("day-shift")
    assert checked.validate(token) is None
    assert row_count(db) == 1
    # Re-enabling the account does not bring the old session back.
    accounts.enable_user("day-shift")
    assert checked.validate(token) is None
    assert checked.validate(admin_token) is not None


def test_a_session_ends_when_its_account_changes_role(
    accounts: AccountStore, checked: SessionStore
) -> None:
    token, session = checked.create("day-shift", Role.OPERATOR, client=None)
    assert session.can(Permission.APPROVE_DEVICE)
    accounts.set_role("day-shift", Role.AUDITOR)
    assert checked.validate(token) is None


def test_a_session_ends_when_its_account_is_deleted(
    accounts: AccountStore, checked: SessionStore
) -> None:
    token, _ = checked.create("day-shift", Role.OPERATOR, client=None)
    accounts.delete_user("day-shift")
    assert checked.validate(token) is None


def test_a_session_for_an_account_that_never_existed_is_refused(checked: SessionStore) -> None:
    token, _ = checked.create("nobody-here", Role.ADMIN, client=None)
    assert checked.validate(token) is None


def test_a_session_cannot_claim_more_than_its_account_has(
    accounts: AccountStore, checked: SessionStore, db: Database
) -> None:
    token, _ = checked.create("day-shift", Role.OPERATOR, client=None)
    db.execute("UPDATE auth_sessions SET role = 'admin'")
    assert checked.validate(token) is None


def test_a_session_ends_when_its_password_changes_after_it_began(
    accounts: AccountStore, checked: SessionStore, clock: FakeClock
) -> None:
    token, _ = checked.create("day-shift", Role.OPERATOR, client=None)
    clock.advance(MINUTE)
    accounts.set_password("day-shift", "another-fine-secret-9")
    assert checked.validate(token) is None
    # A session started after the change is fine.
    fresh, _ = checked.create("day-shift", Role.OPERATOR, client=None)
    clock.advance(MINUTE)
    assert checked.validate(fresh) is not None


def test_without_either_link_sessions_do_not_follow_the_account(
    accounts: AccountStore, sessions: SessionStore
) -> None:
    """The documented contract: with neither ``sessions`` nor ``account_lookup``, revoke."""
    token, _ = sessions.create("day-shift", Role.OPERATOR, client=None)
    accounts.disable_user("day-shift")
    assert sessions.validate(token) is not None
    assert sessions.revoke_all("day-shift") == 1
    assert sessions.validate(token) is None


# --- revoked by the account store -----------------------------------------------------


Event = tuple[str, Any, dict[str, Any]]


@pytest.fixture
def linked(db: Database, clock: FakeClock) -> tuple[AccountStore, SessionStore, list[Event]]:
    """An account store that ends sessions itself, as the service wires it."""
    events: list[Event] = []
    sessions = SessionStore(db, clock=clock)
    store = AccountStore(
        db,
        clock=clock,
        policy=AuthPolicy(scrypt=ScryptParams.insecure_fast_for_tests()),
        audit=lambda name, severity, data: events.append((name, severity, dict(data))),
        sessions=sessions,
    )
    store.create_user("root-admin", PASSWORD, Role.ADMIN)
    store.create_user("day-shift", PASSWORD, Role.OPERATOR)
    return store, sessions, events


def open_sessions(sessions: SessionStore, name: str, role: Role, count: int) -> list[str]:
    return [sessions.create(name, role, client=None)[0] for _ in range(count)]


@pytest.mark.parametrize(
    ("change", "event", "expected"),
    [
        (
            lambda store: store.change_password("day-shift", PASSWORD, "another-fine-secret-9"),
            "auth.password_changed",
            {"method": "change", "actor": "day-shift"},
        ),
        (
            lambda store: store.set_password("day-shift", "another-fine-secret-9", actor="cli"),
            "auth.password_changed",
            {"method": "reset", "actor": "cli"},
        ),
        (
            lambda store: store.set_role("day-shift", Role.AUDITOR, actor="root-admin"),
            "auth.user_changed",
            {"change": "role", "old_role": "operator", "role": "auditor", "actor": "root-admin"},
        ),
        (
            lambda store: store.disable_user("day-shift", actor="root-admin"),
            "auth.user_changed",
            {"change": "disabled", "actor": "root-admin"},
        ),
        (
            lambda store: store.delete_user("day-shift", actor="root-admin"),
            "auth.user_changed",
            {"change": "deleted", "role": "operator", "actor": "root-admin"},
        ),
    ],
    ids=["change_password", "reset", "role", "disable", "delete"],
)
def test_securing_an_account_ends_all_its_sessions_at_once(
    linked: tuple[AccountStore, SessionStore, list[Event]],
    change: Any,
    event: str,
    expected: dict[str, Any],
) -> None:
    store, sessions, events = linked
    theirs = open_sessions(sessions, "day-shift", Role.OPERATOR, 3)
    others = open_sessions(sessions, "root-admin", Role.ADMIN, 2)
    change(store)
    assert [sessions.validate(token) for token in theirs] == [None] * 3
    assert all(sessions.validate(token) is not None for token in others)
    assert events[-1][0] == event
    assert events[-1][2] == {"username": "day-shift", **expected, "sessions_revoked": 3}


def test_re_enabling_or_a_no_op_does_not_end_sessions(
    linked: tuple[AccountStore, SessionStore, list[Event]],
) -> None:
    store, sessions, events = linked
    store.disable_user("day-shift")
    token = open_sessions(sessions, "day-shift", Role.OPERATOR, 1)[0]
    store.enable_user("day-shift", actor="root-admin")
    store.set_role("day-shift", Role.OPERATOR)
    assert sessions.validate(token) is not None
    assert events[-1][2] == {"username": "day-shift", "change": "enabled", "actor": "root-admin"}


def test_revocation_and_the_change_commit_together(db: Database, clock: FakeClock) -> None:
    """If the change cannot be audited, neither it nor the revocation is kept."""
    sessions = SessionStore(db, clock=clock)
    failing = {"on": False}

    def audit(_name: str, _severity: Any, _data: dict[str, Any]) -> None:
        if failing["on"]:
            raise RuntimeError("the audit log is unavailable")

    store = AccountStore(
        db,
        clock=clock,
        policy=AuthPolicy(scrypt=ScryptParams.insecure_fast_for_tests()),
        audit=audit,
        sessions=sessions,
    )
    store.create_user("root-admin", PASSWORD, Role.ADMIN)
    store.create_user("day-shift", PASSWORD, Role.OPERATOR)
    token = open_sessions(sessions, "day-shift", Role.OPERATOR, 1)[0]
    failing["on"] = True
    with pytest.raises(RuntimeError):
        store.disable_user("day-shift")
    assert sessions.validate(token) is not None
    user = store.get_user("day-shift")
    assert user is not None and user.enabled


def test_the_account_store_refuses_something_that_cannot_revoke(
    db: Database, clock: FakeClock
) -> None:
    with pytest.raises(ConfigError, match="revoke_all"):
        AccountStore(
            db,
            clock=clock,
            policy=AuthPolicy(scrypt=ScryptParams.insecure_fast_for_tests()),
            sessions=object(),  # type: ignore[arg-type]
        )
