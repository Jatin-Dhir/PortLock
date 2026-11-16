"""Accounts, roles, lockout, recovery codes and what gets audited."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from portlock.auth import accounts
from portlock.auth.accounts import (
    AccountStore,
    AuthenticationError,
    AuthFailure,
    AuthPolicy,
    AuthResult,
    Channel,
    InvalidUsernameError,
    LastAdminError,
    Permission,
    Role,
    UnknownUserError,
    User,
    UserExistsError,
    can,
    normalize_username,
)
from portlock.auth.passwords import (
    DEFAULT_PARAMS,
    PasswordPolicyError,
    ScryptParams,
    verify_password,
)
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import AuthError, ConfigError, StoreError
from portlock.core.models import Severity

FAST = ScryptParams.insecure_fast_for_tests()
PASSWORD = "granite-otter-73-lamp"
OTHER = "violet-harbor-58-kite"
WRONG = "not-the-password-at-all"
ADMIN = "root-admin"

INVALID = AuthFailure.INVALID_CREDENTIALS
LOCKED = AuthFailure.LOCKED_OUT
DISABLED = AuthFailure.ACCOUNT_DISABLED
BUSY = AuthFailure.BUSY
# Room for every thread of a concurrency test to be checked at once, so that what those
# tests measure is the lockout, not the network verification limit.
WIDE = AuthPolicy(scrypt=FAST, max_network_verifications=16)

Event = tuple[str, Severity, dict[str, Any]]
CODE_FORMAT = re.compile(r"(?:[0-9a-f]{4}-){7}[0-9a-f]{4}\Z")


def make_store(
    db: Database,
    clock: FakeClock,
    events: list[Event] | None = None,
    policy: AuthPolicy | None = None,
) -> AccountStore:
    def audit(event_type: str, severity: Severity, data: dict[str, Any]) -> None:
        assert events is not None
        events.append((event_type, severity, dict(data)))

    return AccountStore(
        db,
        clock=clock,
        audit=audit if events is not None else None,
        policy=policy if policy is not None else AuthPolicy(scrypt=FAST),
    )


@pytest.fixture
def events() -> list[Event]:
    return []


@pytest.fixture
def store(db: Database, clock: FakeClock, events: list[Event]) -> AccountStore:
    return make_store(db, clock, events)


@pytest.fixture
def admin(store: AccountStore) -> User:
    return store.create_user(ADMIN, PASSWORD, Role.ADMIN)


@pytest.fixture
def verifications(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every password hash the store evaluates, in order (list.append is atomic)."""
    seen: list[str] = []
    real = accounts.verify_password

    def counting(password: str, encoded: str) -> bool:
        seen.append(encoded)
        return real(password, encoded)

    monkeypatch.setattr(accounts, "verify_password", counting)
    return seen


def names(events: list[Event]) -> list[str]:
    return [event_type for event_type, _severity, _data in events]


def fail(store: AccountStore, times: int, username: str = ADMIN, **kwargs: Any) -> list[AuthResult]:
    return [store.authenticate(username, WRONG, **kwargs) for _ in range(times)]


def outcome(result: AuthResult) -> tuple[AuthFailure | None, int]:
    return result.reason, result.retry_after_seconds


def stored_hash(db: Database, username: str = ADMIN) -> str:
    row = db.query_one("SELECT password_hash FROM auth_users WHERE username = ?", (username,))
    assert row is not None
    return str(row["password_hash"])


def total_changes(db: Database) -> int:
    """Rows inserted, updated or deleted on this connection so far."""
    row = db.query_one("SELECT total_changes() AS n")
    assert row is not None
    return int(row["n"])


def run_together(count: int, work: Callable[[int], Any]) -> list[Any]:
    """Run ``work(i)`` on ``count`` threads released at the same instant."""
    barrier = threading.Barrier(count)
    results: list[Any] = [None] * count
    errors: list[BaseException] = []

    def runner(index: int) -> None:
        try:
            barrier.wait(timeout=10)
            results[index] = work(index)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=runner, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads), "a worker thread is stuck"
    assert errors == []
    return results


# --- roles and permissions -----------------------------------------------------------


def test_administrators_may_do_everything() -> None:
    assert all(can(Role.ADMIN, permission) for permission in Permission)
    assert len(Permission) == 12


def test_operators_handle_devices_but_cannot_open_the_machine_up() -> None:
    allowed = {permission for permission in Permission if can(Role.OPERATOR, permission)}
    assert allowed == {
        Permission.VIEW,
        Permission.VIEW_AUDIT,
        Permission.APPROVE_DEVICE,
        Permission.ISSUE_TEMPORARY_GRANT,
        Permission.RUN_SCAN,
        Permission.ENGAGE_LOCKDOWN,
    }
    assert can(Role.OPERATOR, Permission.ENGAGE_LOCKDOWN)
    assert not can(Role.OPERATOR, Permission.LIFT_LOCKDOWN)
    assert not can(Role.OPERATOR, Permission.MANAGE_TRUST)
    assert not can(Role.OPERATOR, Permission.MANAGE_USERS)


def test_auditors_are_read_only() -> None:
    allowed = {permission for permission in Permission if can(Role.AUDITOR, permission)}
    assert allowed == {Permission.VIEW, Permission.VIEW_AUDIT, Permission.EXPORT_AUDIT}


def test_can_accepts_names_and_refuses_anything_unknown() -> None:
    assert can("admin", "edit_policy") is True
    assert can("operator", "approve_device") is True
    assert can("operator", "edit_policy") is False
    assert can("root", "view") is False
    assert can("admin", "format_disk") is False
    assert can(None, Permission.VIEW) is False  # type: ignore[arg-type]
    assert can(Role.ADMIN, ["view"]) is False  # type: ignore[arg-type]


def test_a_disabled_account_has_no_permissions(store: AccountStore, admin: User) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    assert admin.can(Permission.MANAGE_USERS)
    assert not store.disable_user(ADMIN).can(Permission.VIEW)


# --- policy object -------------------------------------------------------------------


def test_policy_defaults_are_the_design_values() -> None:
    policy = AuthPolicy()
    assert policy.scrypt == DEFAULT_PARAMS
    assert policy.min_password_length == 12
    assert policy.lockout_threshold == 5
    assert policy.lockout_base == timedelta(seconds=30)
    assert policy.lockout_max == timedelta(minutes=15)
    assert policy.recovery_code_count == 8
    assert policy.max_network_verifications == 2
    assert (policy.scrypt.n, policy.scrypt.r, policy.scrypt.p) == (2**17, 8, 1)
    assert Channel.NETWORK.value == "network" and Channel.LOCAL.value == "local"
    assert [channel.value for channel in Channel] == ["network", "local"]


def test_lockout_delay_doubles_from_thirty_seconds_to_fifteen_minutes() -> None:
    policy = AuthPolicy()
    assert [policy.lockout_delay(failures) for failures in range(5)] == [None] * 5
    seconds = [policy.lockout_delay(failures).total_seconds() for failures in range(5, 13)]  # type: ignore[union-attr]
    assert seconds == [30, 60, 120, 240, 480, 900, 900, 900]
    assert policy.lockout_delay(10**9) == timedelta(minutes=15)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scrypt": {"n": 2**15}},
        {"min_password_length": 11},
        {"min_password_length": 2000},
        {"lockout_threshold": 0},
        {"lockout_threshold": 101},
        {"lockout_threshold": True},
        {"lockout_base": 30},
        {"lockout_base": timedelta(0)},
        {"lockout_max": timedelta(seconds=10)},
        {"failure_memory": timedelta(minutes=1)},
        {"recovery_code_count": 0},
        {"max_throttle_entries": 3},
        {"max_concurrent_hashes": 0},
        {"max_network_verifications": 0},
        {"max_network_verifications": 17},
        {"max_network_verifications": 2.0},
    ],
)
def test_out_of_range_policy_is_refused(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        AuthPolicy(**kwargs)


def test_every_value_the_configuration_file_allows_is_a_valid_policy() -> None:
    # The limits of the [auth] section in portlock.core.config, at both ends.
    low = AuthPolicy(
        min_password_length=12,
        lockout_threshold=1,
        lockout_base=timedelta(seconds=1),
        lockout_max=timedelta(seconds=1),
    )
    assert low.lockout_delay(1) == timedelta(seconds=1)
    high = AuthPolicy(
        min_password_length=128,
        lockout_threshold=100,
        lockout_base=timedelta(seconds=3600),
        lockout_max=timedelta(seconds=86_400),
    )
    assert high.lockout_delay(99) is None
    assert high.lockout_delay(100) == timedelta(hours=1)
    assert high.lockout_delay(105) == timedelta(hours=24)


def test_a_high_threshold_is_counted_exactly(db: Database, clock: FakeClock) -> None:
    store = make_store(db, clock, policy=AuthPolicy(scrypt=FAST, lockout_threshold=100))
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    assert [outcome(result) for result in fail(store, 99)] == [(INVALID, 0)] * 99
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 30)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)


def test_the_store_requires_a_real_policy(db: Database, clock: FakeClock) -> None:
    with pytest.raises(ConfigError):
        AccountStore(db, clock=clock, policy={"lockout_threshold": 99})  # type: ignore[arg-type]


# --- user names ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "stored"),
    [("abc", "abc"), ("Alice", "alice"), ("a.b_c-1", "a.b_c-1"), ("X" * 32, "x" * 32)],
)
def test_usernames_are_folded_to_lower_case(typed: str, stored: str) -> None:
    assert normalize_username(typed) == stored


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "ab",
        "x" * 33,
        "has space",
        " padded ",
        "semi;colon",
        "slash/name",
        "new\nline",
        "nul\x00byte",
        "*",
        "\N{LATIN SMALL LETTER U WITH DIAERESIS}ser",
        # The Kelvin sign lower-cases to an ASCII "k"; it must not alias a real account.
        "\N{KELVIN SIGN}evin",
        None,
        42,
        b"bytes",
    ],
    ids=lambda value: repr(value)[:16].encode("ascii", "replace").decode(),
)
def test_malformed_usernames_are_refused(typed: object) -> None:
    with pytest.raises(InvalidUsernameError) as caught:
        normalize_username(typed)
    assert caught.value.code == "invalid_username"
    assert isinstance(caught.value, AuthError)


# --- creating accounts ---------------------------------------------------------------


def test_first_user_must_be_an_administrator(store: AccountStore) -> None:
    assert store.has_users() is False
    for role in (Role.OPERATOR, Role.AUDITOR):
        with pytest.raises(AuthError) as caught:
            store.create_user("first-user", PASSWORD, role)
        assert caught.value.code == "first_user_must_be_admin"
    assert store.has_users() is False

    user = store.create_user("first-user", PASSWORD, Role.ADMIN)
    assert store.has_users() is True
    assert (user.username, user.role, user.enabled, user.last_login_at) == (
        "first-user",
        Role.ADMIN,
        True,
        None,
    )
    assert store.create_user("day-shift", OTHER, "operator").role is Role.OPERATOR


def test_create_user_records_time_and_audits(
    store: AccountStore, clock: FakeClock, events: list[Event]
) -> None:
    user = store.create_user("Root-Admin", PASSWORD, Role.ADMIN, actor="installer")
    assert user.username == ADMIN
    assert user.created_at == user.password_changed_at == clock.now()
    assert events == [
        (
            "auth.user_created",
            Severity.NOTICE,
            {"username": ADMIN, "role": "admin", "actor": "installer"},
        )
    ]
    assert user.to_dict() == {
        "username": ADMIN,
        "role": "admin",
        "enabled": True,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "password_changed_at": "2026-01-01T00:00:00.000000Z",
        "last_login_at": None,
    }


def test_usernames_are_unique_without_regard_to_case(store: AccountStore, admin: User) -> None:
    for variant in ("root-admin", "ROOT-ADMIN", "Root-Admin"):
        with pytest.raises(UserExistsError) as caught:
            store.create_user(variant, OTHER, Role.OPERATOR)
        assert caught.value.code == "user_exists"
    assert [user.username for user in store.list_users()] == [ADMIN]
    assert store.get_user("ROOT-ADMIN") == admin
    assert store.get_user("nobody-here") is None
    assert store.get_user("not a name") is None


def test_malformed_username_or_role_creates_nothing(store: AccountStore) -> None:
    with pytest.raises(InvalidUsernameError):
        store.create_user("no", PASSWORD, Role.ADMIN)
    with pytest.raises(AuthError) as caught:
        store.create_user("root-admin", PASSWORD, "superuser")
    assert caught.value.code == "invalid_role"
    assert store.has_users() is False


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("short-one", "at least 12"),
        ("portlock123", "commonly used"),
        ("password1234", "commonly used"),
        ("xx-root-admin-xx", "username"),
        ("ROOT-ADMIN", "username"),
        ("aaaaaaaaaaaaaaaa", "repeated"),
        ("abcdefghijklmnop", "sequence"),
    ],
)
def test_weak_passwords_are_refused_at_creation(
    store: AccountStore, events: list[Event], password: str, problem: str
) -> None:
    with pytest.raises(PasswordPolicyError) as caught:
        store.create_user(ADMIN, password, Role.ADMIN)
    assert any(problem in text for text in caught.value.problems)
    assert store.has_users() is False
    assert events == []


def test_only_a_hash_of_the_password_is_stored(
    store: AccountStore, admin: User, db: Database
) -> None:
    row = db.query_one("SELECT * FROM auth_users")
    assert row is not None
    assert PASSWORD not in "|".join(str(value) for value in tuple(row))
    assert stored_hash(db).startswith("scrypt$16$8$1$")
    assert verify_password(PASSWORD, stored_hash(db))


def test_list_users_is_sorted(store: AccountStore, admin: User) -> None:
    store.create_user("zoe-night", OTHER, Role.AUDITOR)
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    assert [(user.username, user.role) for user in store.list_users()] == [
        ("day-shift", Role.OPERATOR),
        (ADMIN, Role.ADMIN),
        ("zoe-night", Role.AUDITOR),
    ]


# --- authentication ------------------------------------------------------------------


def test_correct_password_logs_in(
    store: AccountStore, admin: User, clock: FakeClock, events: list[Event]
) -> None:
    clock.advance(90)
    result = store.authenticate("ROOT-admin", PASSWORD)
    assert result.ok is True and result.reason is None and result.retry_after_seconds == 0
    assert result.user is not None
    assert result.user.username == ADMIN and result.user.role is Role.ADMIN
    assert result.user.last_login_at == clock.now()
    assert store.get_user(ADMIN) == result.user
    assert events[-1] == (
        "auth.login",
        Severity.INFO,
        {
            "username": ADMIN,
            "role": "admin",
            "channel": "network",
            "method": "password",
            "hash_upgraded": False,
        },
    )


def test_wrong_password_and_unknown_user_look_the_same(
    store: AccountStore,
    admin: User,
    db: Database,
    events: list[Event],
    verifications: list[str],
) -> None:
    wrong = store.authenticate(ADMIN, WRONG)
    unknown = store.authenticate("nobody-here", WRONG)
    assert wrong == unknown == AuthResult(False, None, INVALID, 0)
    # Both did one real key derivation: the unknown name was checked against a decoy.
    assert len(verifications) == 2
    assert verifications[0] == stored_hash(db)
    assert verifications[1].startswith("scrypt$16$8$1$") and verifications[1] != verifications[0]

    failures = [data for name, _severity, data in events if name == "auth.failure"]
    assert failures == [
        {
            "username": ADMIN,
            "known_user": True,
            "channel": "network",
            "method": "password",
            "reason": "invalid_credentials",
            "consecutive_failures": 1,
        },
        {
            "username": None,
            "known_user": False,
            "channel": "network",
            "method": "password",
            "reason": "invalid_credentials",
            "consecutive_failures": 1,
        },
    ]
    assert store.get_user(ADMIN).last_login_at is None  # type: ignore[union-attr]


def test_five_failures_start_a_delay_that_doubles_to_fifteen_minutes(
    store: AccountStore, admin: User, clock: FakeClock
) -> None:
    assert [outcome(result) for result in fail(store, 4)] == [(INVALID, 0)] * 4
    delays = []
    for _ in range(8):
        result = store.authenticate(ADMIN, WRONG)
        assert result.reason is INVALID, "the delay has run out, so the password is evaluated"
        delays.append(result.retry_after_seconds)
        clock.advance(result.retry_after_seconds)
    assert delays == [30, 60, 120, 240, 480, 900, 900, 900]


def test_attempts_during_a_lockout_are_refused_without_evaluating_the_password(
    store: AccountStore, admin: User, clock: FakeClock, verifications: list[str]
) -> None:
    assert outcome(fail(store, 5)[-1]) == (INVALID, 30)
    assert len(verifications) == 5

    assert store.authenticate(ADMIN, PASSWORD) == AuthResult(False, None, LOCKED, 30)
    clock.advance(29)
    assert store.authenticate(ADMIN, PASSWORD) == AuthResult(False, None, LOCKED, 1)
    assert len(verifications) == 5, "the correct password was not even looked at"

    clock.advance(1)
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert len(verifications) == 6


def test_hammering_a_locked_account_does_not_extend_the_lockout(
    store: AccountStore, admin: User, clock: FakeClock, db: Database, events: list[Event]
) -> None:
    fail(store, 5)
    clock.advance(10)
    assert outcome(store.authenticate(ADMIN, WRONG)) == (LOCKED, 20)
    record = tuple(db.query("SELECT * FROM auth_throttle")[0])
    written = total_changes(db)
    for _ in range(50):
        assert outcome(store.authenticate(ADMIN, WRONG)) == (LOCKED, 20)
    assert store.lockout_remaining(ADMIN) == 20
    assert tuple(db.query("SELECT * FROM auth_throttle")[0]) == record
    assert total_changes(db) == written, "a refused attempt must not write to the database"
    clock.advance(20)
    assert store.lockout_remaining(ADMIN) == 0
    assert store.authenticate(ADMIN, PASSWORD).ok is True

    # Fifty-one refused attempts leave one audit record.
    refused = [data for name, _s, data in events if data.get("reason") == "locked_out"]
    assert len(refused) == 1
    assert refused[0]["retry_after_seconds"] == 20 and refused[0]["consecutive_failures"] == 5
    assert names(events).count("auth.lockout") == 1
    lockout = next(event for event in events if event[0] == "auth.lockout")
    assert lockout[1] is Severity.WARNING
    assert lockout[2] == {
        "username": ADMIN,
        "known_user": True,
        "channel": "network",
        "method": "password",
        "consecutive_failures": 5,
        "locked_for_seconds": 30,
    }


def test_success_resets_the_counter(store: AccountStore, admin: User) -> None:
    fail(store, 4)
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert [outcome(result) for result in fail(store, 4)] == [(INVALID, 0)] * 4
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 30)


def test_the_escalation_continues_after_a_lockout_until_a_success(
    store: AccountStore, admin: User, clock: FakeClock
) -> None:
    fail(store, 5)
    clock.advance(30)
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 60)
    clock.advance(60)
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert [outcome(result) for result in fail(store, 5)] == [(INVALID, 0)] * 4 + [(INVALID, 30)]


def test_unknown_usernames_are_locked_out_exactly_like_real_ones(
    store: AccountStore, admin: User, clock: FakeClock, verifications: list[str]
) -> None:
    expected = [(INVALID, 0)] * 4 + [(INVALID, 30), (LOCKED, 30), (LOCKED, 30)]
    assert [outcome(result) for result in fail(store, 7)] == expected
    assert [outcome(result) for result in fail(store, 7, "nobody-here")] == expected
    assert len(verifications) == 10
    assert store.lockout_remaining("nobody-here") == store.lockout_remaining(ADMIN) == 30
    # Each name has its own counter.
    assert outcome(store.authenticate("someone-else", WRONG)) == (INVALID, 0)


def test_strings_that_cannot_be_usernames_share_one_counter(
    store: AccountStore, admin: User, db: Database
) -> None:
    junk = ["a b", "x" * 5000, "", "semi;colon", "\N{KELVIN SIGN}evin"]
    results = [store.authenticate(name, WRONG) for name in junk]
    assert [outcome(result) for result in results] == [(INVALID, 0)] * 4 + [(INVALID, 30)]
    assert outcome(store.authenticate("yet another", WRONG)) == (LOCKED, 30)
    assert db.query_one("SELECT COUNT(*) AS n FROM auth_throttle")["n"] == 1  # type: ignore[index]
    assert store.authenticate(ADMIN, PASSWORD).ok is True


@pytest.mark.parametrize(
    "username",
    [None, 42, "", "x" * 100_000, "root-admin\x00", chr(0xD800), "root-admin ", ["root-admin"]],
    ids=["none", "int", "empty", "huge", "nul", "surrogate", "padded", "list"],
)
def test_hostile_usernames_fail_quietly(store: AccountStore, admin: User, username: object) -> None:
    result = store.authenticate(username, PASSWORD)  # type: ignore[arg-type]
    assert result == AuthResult(False, None, INVALID, 0)


@pytest.mark.parametrize(
    "password",
    [None, 42, "", "x" * 100_000, chr(0xDC00) * 20, b"granite-otter-73-lamp"],
    ids=["none", "int", "empty", "huge", "surrogates", "bytes"],
)
def test_hostile_passwords_fail_quietly(store: AccountStore, admin: User, password: object) -> None:
    result = store.authenticate(ADMIN, password)  # type: ignore[arg-type]
    assert result == AuthResult(False, None, INVALID, 0)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_lockout_survives_a_restart(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "portlock.db"
    with Database(path) as first:
        store = make_store(first, clock)
        store.create_user(ADMIN, PASSWORD, Role.ADMIN)
        fail(store, 5)
    clock.advance(10)
    with Database(path) as second:
        store = make_store(second, clock)
        assert store.lockout_remaining(ADMIN) == 20
        assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 20)
        clock.advance(20)
        # The count survived too: one more failure earns the doubled delay.
        assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 60)


def test_a_clock_set_back_cannot_stretch_a_lockout_past_the_maximum(
    store: AccountStore, admin: User, clock: FakeClock
) -> None:
    fail(store, 5)
    clock.set(clock.now() - timedelta(days=1))
    assert store.lockout_remaining(ADMIN) == 900
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 900)
    clock.advance(450)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 450)
    clock.advance(450)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_a_clock_set_back_in_the_middle_of_a_lockout_is_bounded_too(
    store: AccountStore, admin: User, clock: FakeClock
) -> None:
    fail(store, 5)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)
    clock.set(clock.now() - timedelta(days=1))
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 900)
    clock.advance(450)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 450)
    assert store.lockout_remaining(ADMIN) == 450
    clock.advance(450)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_an_unreadable_throttle_record_is_a_bounded_lockout(
    store: AccountStore, admin: User, clock: FakeClock, db: Database
) -> None:
    fail(store, 1)
    db.execute(
        "UPDATE auth_throttle SET failures = 'many', last_failure_at = 'yesterday', refused = 1"
    )
    assert store.lockout_remaining(ADMIN) == 900
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 900)
    clock.advance(100)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 800)
    clock.advance(800)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


@pytest.mark.parametrize("failures", [0, -3, 2.5, 1e300, float("inf"), "9" * 40, b""])
def test_an_impossible_failure_count_is_a_bounded_lockout(
    store: AccountStore, admin: User, clock: FakeClock, db: Database, failures: object
) -> None:
    fail(store, 1)
    db.execute("UPDATE auth_throttle SET failures = ?", (failures,))
    assert store.lockout_remaining(ADMIN) == 900
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 900)
    clock.advance(900)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


@pytest.mark.parametrize("failures", [10**6, 2**63 - 1])
def test_an_absurd_failure_count_earns_the_maximum_delay_and_nothing_worse(
    store: AccountStore, admin: User, clock: FakeClock, db: Database, failures: int
) -> None:
    # 2**63 - 1 is the largest integer SQLite stores: adding one to it must not be tried.
    fail(store, 1)
    db.execute("UPDATE auth_throttle SET failures = ?", (failures,))
    assert store.lockout_remaining(ADMIN) == 0, "a count alone is not a running lockout"
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 900)
    row = db.query_one("SELECT failures FROM auth_throttle")
    assert row is not None and row["failures"] == 1001, "stored in its bounded form"
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 900)
    clock.advance(900)
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert db.query("SELECT * FROM auth_throttle") == []


def test_failures_are_forgotten_after_a_quiet_day(
    store: AccountStore, admin: User, clock: FakeClock
) -> None:
    fail(store, 4)
    clock.advance(timedelta(hours=23, minutes=59))
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 30), "not yet forgotten"

    clock.advance(timedelta(hours=24))
    assert [outcome(result) for result in fail(store, 4)] == [(INVALID, 0)] * 4


def test_the_network_lockout_never_blocks_the_local_channel(
    store: AccountStore, admin: User, events: list[Event], verifications: list[str]
) -> None:
    fail(store, 5)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)
    # Guessing through the API has not locked the console...
    result = store.authenticate(ADMIN, PASSWORD, channel=Channel.LOCAL)
    assert result.ok is True
    assert events[-1][2]["channel"] == "local"
    # ...and logging in at the console has not handed the API guesser a fresh start.
    assert outcome(store.authenticate(ADMIN, PASSWORD, channel="network")) == (LOCKED, 30)


def test_the_local_channel_is_never_locked_out_however_often_it_fails(
    store: AccountStore, admin: User, db: Database, events: list[Event], verifications: list[str]
) -> None:
    local = fail(store, 40, channel=Channel.LOCAL)
    assert [outcome(result) for result in local] == [(INVALID, 0)] * 40
    assert len(verifications) == 40, "every local attempt is really evaluated"
    assert store.lockout_remaining(ADMIN, channel="local") == 0
    assert db.query("SELECT * FROM auth_throttle") == [], "nothing is counted locally"
    assert store.authenticate(ADMIN, PASSWORD, channel="local").ok is True
    # Each failure is still audited, without a counter that does not exist.
    failures = [data for name, _s, data in events if name == "auth.failure"]
    assert len(failures) == 40 and "auth.lockout" not in names(events)
    assert failures[0] == {
        "username": ADMIN,
        "known_user": True,
        "channel": "local",
        "method": "password",
        "reason": "invalid_credentials",
    }
    # Nor did the local failures count against the network.
    assert [outcome(result) for result in fail(store, 4)] == [(INVALID, 0)] * 4


def test_an_unknown_channel_is_a_caller_error(store: AccountStore, admin: User) -> None:
    for call in (
        lambda: store.authenticate(ADMIN, PASSWORD, channel="carrier-pigeon"),
        lambda: store.authenticate(ADMIN, PASSWORD, channel="remote"),
        lambda: store.lockout_remaining(ADMIN, channel="carrier-pigeon"),
        lambda: store.use_recovery_code(ADMIN, "0" * 32, channel="carrier-pigeon"),
        lambda: store.change_password(ADMIN, PASSWORD, OTHER, channel=None),  # type: ignore[arg-type]
    ):
        with pytest.raises(AuthError) as caught:
            call()
        assert caught.value.code == "invalid_channel"


# --- at most two network verifications at once ----------------------------------------


def hold_verifications(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[threading.Semaphore, threading.Event]:
    """Make every password check wait inside the check until released."""
    in_check = threading.Semaphore(0)
    release = threading.Event()
    real = accounts.verify_password

    def held(password: str, encoded: str) -> bool:
        in_check.release()
        assert release.wait(timeout=20)
        return real(password, encoded)

    monkeypatch.setattr(accounts, "verify_password", held)
    return in_check, release


def test_a_third_network_verification_is_told_busy_not_made_to_wait(
    store: AccountStore,
    admin: User,
    db: Database,
    events: list[Event],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    in_check, release = hold_verifications(monkeypatch)
    results: list[AuthResult] = []
    threads = [
        threading.Thread(target=lambda name=name: results.append(store.authenticate(name, WRONG)))
        for name in (ADMIN, "day-shift")
    ]
    local = threading.Thread(
        target=lambda: results.append(store.authenticate(ADMIN, PASSWORD, channel="local"))
    )
    for thread in threads:
        thread.start()
    try:
        assert in_check.acquire(timeout=20) and in_check.acquire(timeout=20)
        before = (len(events), total_changes(db))
        # Both slots are taken. A third attempt is answered at once, for any name.
        for name in (ADMIN, "nobody-here", "day-shift"):
            assert store.authenticate(name, PASSWORD) == AuthResult(False, None, BUSY, 1)
        with pytest.raises(AuthenticationError) as caught:
            store.change_password(ADMIN, PASSWORD, "another-fine-secret-9")
        assert (caught.value.reason, caught.value.code) == (BUSY, "busy")
        assert caught.value.retry_after_seconds == 1
        assert in_check.acquire(timeout=0.2) is False, "nothing else reached a check"
        # Refused as busy: not counted, not evaluated, not audited.
        assert (len(events), total_changes(db)) == before
        # The console is never refused: it waits for a hashing slot instead.
        local.start()
        assert in_check.acquire(timeout=20), "the local attempt reached the check"
    finally:
        release.set()
        for thread in [*threads, local]:
            if thread.is_alive():
                thread.join(timeout=20)
    assert sorted(result.ok for result in results) == [False, False, True]
    # Once the slots are free the network answers normally again.
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert store.lockout_remaining(ADMIN) == 0


def test_a_disabled_account_cannot_log_in(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    store.disable_user(ADMIN)
    for _ in range(8):
        assert store.authenticate(ADMIN, PASSWORD) == AuthResult(False, None, DISABLED, 0)
    assert events[-1][0] == "auth.failure" and events[-1][2]["reason"] == "account_disabled"
    # Without the password, a disabled account is indistinguishable from any other.
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 0)
    assert "auth.login" not in names(events)

    store.enable_user(ADMIN)
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_a_successful_login_upgrades_an_old_hash(
    store: AccountStore, admin: User, db: Database, events: list[Event]
) -> None:
    salt = b"old-salt-16bytes"
    digest = hashlib.scrypt(PASSWORD.encode(), salt=salt, n=32, r=8, p=1, dklen=32)
    old = "$".join(
        (
            "scrypt",
            "32",
            "8",
            "1",
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )
    db.execute("UPDATE auth_users SET password_hash = ?", (old,))

    assert store.authenticate(ADMIN, WRONG).ok is False
    assert stored_hash(db) == old, "a failed login must not touch the hash"

    assert store.authenticate(ADMIN, PASSWORD).ok is True
    upgraded = stored_hash(db)
    assert upgraded != old and upgraded.startswith("scrypt$16$8$1$")
    assert verify_password(PASSWORD, upgraded)
    assert events[-1][2]["hash_upgraded"] is True

    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert stored_hash(db) == upgraded
    assert events[-1][2]["hash_upgraded"] is False


def test_a_password_changed_mid_verification_does_not_log_in(
    store: AccountStore, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = accounts.verify_password

    def racing(password: str, encoded: str) -> bool:
        matched = real(password, encoded)
        # An administrator resets the password while this login is still being hashed.
        store.set_password(ADMIN, OTHER)
        return matched

    monkeypatch.setattr(accounts, "verify_password", racing)
    assert store.authenticate(ADMIN, PASSWORD) == AuthResult(False, None, INVALID, 0)
    monkeypatch.undo()
    assert store.authenticate(ADMIN, PASSWORD).ok is False
    assert store.authenticate(ADMIN, OTHER).ok is True


def test_an_account_disabled_mid_verification_does_not_log_in(
    store: AccountStore, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    real = accounts.verify_password

    def racing(password: str, encoded: str) -> bool:
        matched = real(password, encoded)
        store.disable_user(ADMIN)
        return matched

    monkeypatch.setattr(accounts, "verify_password", racing)
    assert store.authenticate(ADMIN, PASSWORD) == AuthResult(False, None, DISABLED, 0)


def test_a_corrupt_account_record_is_refused(
    store: AccountStore, admin: User, db: Database
) -> None:
    db.execute("PRAGMA ignore_check_constraints = ON")
    db.execute("UPDATE auth_users SET role = 'superuser'")
    with pytest.raises(StoreError):
        store.authenticate(ADMIN, PASSWORD)
    with pytest.raises(StoreError):
        store.list_users()
    db.execute("UPDATE auth_users SET role = 'admin', enabled = 7")
    with pytest.raises(StoreError):
        store.get_user(ADMIN)


# --- changing and resetting passwords ------------------------------------------------


def test_change_password(
    store: AccountStore, admin: User, clock: FakeClock, events: list[Event]
) -> None:
    clock.advance(3600)
    store.change_password("Root-Admin", PASSWORD, OTHER)
    assert store.authenticate(ADMIN, PASSWORD).ok is False
    assert store.authenticate(ADMIN, OTHER).ok is True
    changed = store.get_user(ADMIN)
    assert changed is not None and changed.password_changed_at == clock.now()
    assert events[1][:2] == ("auth.password_changed", Severity.NOTICE)
    assert events[1][2] == {"username": ADMIN, "method": "change", "actor": ADMIN}
    # Confirming the old password is not a login.
    assert names(events)[:2] == ["auth.user_created", "auth.password_changed"]


def test_change_password_needs_the_current_password_and_is_throttled(
    store: AccountStore, admin: User, db: Database, verifications: list[str]
) -> None:
    before = stored_hash(db)
    for expected_retry in (0, 0, 0, 0, 30):
        with pytest.raises(AuthenticationError) as caught:
            store.change_password(ADMIN, WRONG, OTHER)
        assert caught.value.reason is INVALID and caught.value.code == "invalid_credentials"
        assert caught.value.retry_after_seconds == expected_retry
    with pytest.raises(AuthenticationError) as caught:
        store.change_password(ADMIN, PASSWORD, OTHER)
    assert caught.value.reason is LOCKED and caught.value.retry_after_seconds == 30
    assert len(verifications) == 5
    assert stored_hash(db) == before
    # It is the same counter the login uses.
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)


def test_change_password_enforces_the_policy_on_the_new_password(
    store: AccountStore, admin: User, db: Database
) -> None:
    before = stored_hash(db)
    with pytest.raises(PasswordPolicyError) as caught:
        store.change_password(ADMIN, PASSWORD, "portlock123")
    assert "is one of the most commonly used passwords" in caught.value.problems
    with pytest.raises(PasswordPolicyError) as caught:
        store.change_password(ADMIN, PASSWORD, PASSWORD)
    assert caught.value.problems == ("must differ from the current password",)
    with pytest.raises(PasswordPolicyError):
        store.change_password(ADMIN, PASSWORD, "my-root-admin-pass")
    assert stored_hash(db) == before
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_change_password_for_unknown_or_disabled_accounts(store: AccountStore, admin: User) -> None:
    with pytest.raises(AuthenticationError) as caught:
        store.change_password("nobody-here", PASSWORD, OTHER)
    assert caught.value.reason is INVALID
    store.create_user("second-admin", OTHER, Role.ADMIN)
    store.disable_user(ADMIN)
    with pytest.raises(AuthenticationError) as caught:
        store.change_password(ADMIN, PASSWORD, "another-fine-secret-9")
    assert caught.value.reason is DISABLED


def test_administrative_reset_sets_the_password_and_clears_the_lockout(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    fail(store, 5)
    assert store.lockout_remaining(ADMIN) == 30

    store.set_password(ADMIN, OTHER, actor="console")
    assert store.lockout_remaining(ADMIN) == 0
    assert store.authenticate(ADMIN, OTHER).ok is True
    assert store.authenticate(ADMIN, PASSWORD).ok is False
    reset = next(event for event in events if event[0] == "auth.password_changed")
    assert reset[2] == {"username": ADMIN, "method": "reset", "actor": "console"}


def test_administrative_reset_validates_its_input(
    store: AccountStore, admin: User, db: Database
) -> None:
    before = stored_hash(db)
    with pytest.raises(UnknownUserError):
        store.set_password("nobody-here", OTHER)
    with pytest.raises(PasswordPolicyError):
        store.set_password(ADMIN, "portlock123")
    with pytest.raises(PasswordPolicyError):
        store.set_password(ADMIN, "x" * 2000)
    with pytest.raises(InvalidUsernameError):
        store.set_password("not a name", OTHER)
    assert stored_hash(db) == before


def test_clear_lockout(store: AccountStore, admin: User, events: list[Event]) -> None:
    fail(store, 5)
    store.clear_lockout(ADMIN, actor="second-admin")
    assert store.lockout_remaining(ADMIN) == 0
    assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert (
        "auth.user_changed",
        Severity.NOTICE,
        {
            "username": ADMIN,
            "change": "lockout_cleared",
            "actor": "second-admin",
        },
    ) in events
    with pytest.raises(UnknownUserError):
        store.clear_lockout("nobody-here")


# --- roles, disabling and deleting ---------------------------------------------------


def test_the_last_enabled_administrator_cannot_be_removed_in_any_way(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    before = len(events)
    with pytest.raises(LastAdminError):
        store.delete_user(ADMIN)
    with pytest.raises(LastAdminError):
        store.disable_user(ADMIN)
    for role in (Role.OPERATOR, Role.AUDITOR):
        with pytest.raises(LastAdminError) as caught:
            store.set_role(ADMIN, role)
        assert caught.value.code == "last_admin"
    assert store.get_user(ADMIN) == admin
    assert len(events) == before, "nothing happened, so nothing is audited"


def test_a_disabled_administrator_does_not_count_as_a_spare(
    store: AccountStore, admin: User
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    store.disable_user("second-admin")
    with pytest.raises(LastAdminError):
        store.disable_user(ADMIN)
    with pytest.raises(LastAdminError):
        store.delete_user(ADMIN)
    with pytest.raises(LastAdminError):
        store.set_role(ADMIN, Role.AUDITOR)
    # The disabled one is not an *enabled* administrator, so it can go.
    store.delete_user("second-admin")
    assert [user.username for user in store.list_users()] == [ADMIN]


def test_with_a_second_administrator_the_first_can_be_changed(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    demoted = store.set_role(ADMIN, "auditor", actor="second-admin")
    assert demoted.role is Role.AUDITOR and store.get_user(ADMIN) == demoted
    assert events[-1] == (
        "auth.user_changed",
        Severity.NOTICE,
        {
            "username": ADMIN,
            "change": "role",
            "old_role": "admin",
            "role": "auditor",
            "actor": "second-admin",
        },
    )
    # Now second-admin is the last one.
    with pytest.raises(LastAdminError):
        store.delete_user("second-admin")


def test_no_op_changes_are_not_audited(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    before = len(events)
    assert store.set_role(ADMIN, Role.ADMIN) == admin
    assert store.enable_user(ADMIN) == admin
    assert len(events) == before


def test_disable_enable_and_delete_are_audited(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    assert store.disable_user("Day-Shift", actor=ADMIN).enabled is False
    assert store.enable_user("day-shift", actor=ADMIN).enabled is True
    store.delete_user("day-shift", actor=ADMIN)
    changes = [data for name, _s, data in events if name == "auth.user_changed"]
    assert changes == [
        {"username": "day-shift", "change": "disabled", "actor": ADMIN},
        {"username": "day-shift", "change": "enabled", "actor": ADMIN},
        {"username": "day-shift", "change": "deleted", "role": "operator", "actor": ADMIN},
    ]
    assert store.get_user("day-shift") is None
    assert store.authenticate("day-shift", OTHER) == AuthResult(False, None, INVALID, 0)


def test_deleting_an_account_deletes_its_recovery_codes(
    store: AccountStore, admin: User, db: Database
) -> None:
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    codes = store.generate_recovery_codes("day-shift")
    store.delete_user("day-shift")
    assert db.query("SELECT * FROM auth_recovery_codes") == []
    # A new account of the same name does not inherit the old codes.
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    assert store.use_recovery_code("day-shift", codes[0]) is False


@pytest.mark.parametrize(
    "operation",
    [
        lambda store: store.set_role("nobody-here", Role.ADMIN),
        lambda store: store.disable_user("nobody-here"),
        lambda store: store.enable_user("nobody-here"),
        lambda store: store.delete_user("nobody-here"),
        lambda store: store.generate_recovery_codes("nobody-here"),
        lambda store: store.remaining_recovery_codes("nobody-here"),
    ],
)
def test_administrative_operations_on_unknown_accounts(
    store: AccountStore, admin: User, operation: Callable[[AccountStore], Any]
) -> None:
    with pytest.raises(UnknownUserError) as caught:
        operation(store)
    assert caught.value.code == "unknown_user"


def test_a_change_that_cannot_be_audited_is_not_kept(db: Database, clock: FakeClock) -> None:
    audit_works = True

    def audit(event_type: str, severity: Severity, data: dict[str, Any]) -> None:
        if not audit_works:
            raise StoreError("the audit log is unavailable")

    store = AccountStore(db, clock=clock, audit=audit, policy=AuthPolicy(scrypt=FAST))
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    store.create_user("second-admin", OTHER, Role.ADMIN)
    before = stored_hash(db, "second-admin")

    audit_works = False
    with pytest.raises(StoreError):
        store.create_user("day-shift", OTHER, Role.OPERATOR)
    with pytest.raises(StoreError):
        store.set_role("second-admin", Role.AUDITOR)
    with pytest.raises(StoreError):
        store.disable_user("second-admin")
    with pytest.raises(StoreError):
        store.delete_user("second-admin")
    with pytest.raises(StoreError):
        store.set_password("second-admin", "another-fine-secret-9")
    with pytest.raises(StoreError):
        store.generate_recovery_codes("second-admin")

    assert store.get_user("day-shift") is None
    second = store.get_user("second-admin")
    assert second is not None and second.role is Role.ADMIN and second.enabled
    assert stored_hash(db, "second-admin") == before
    assert db.query("SELECT * FROM auth_recovery_codes") == []


# --- recovery codes ------------------------------------------------------------------


def test_recovery_codes_are_eight_random_128_bit_codes_stored_as_digests(
    store: AccountStore, admin: User, db: Database
) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    assert len(codes) == len(set(codes)) == 8
    assert all(CODE_FORMAT.match(code) for code in codes)
    assert all(len(bytes.fromhex(code.replace("-", ""))) * 8 == 128 for code in codes)

    rows = db.query("SELECT * FROM auth_recovery_codes ORDER BY id")
    everything = "|".join(str(value) for row in rows for value in tuple(row))
    for code in codes:
        assert code not in everything and code.replace("-", "") not in everything
    assert sorted(row["code_digest"] for row in rows) == sorted(
        hashlib.sha256(bytes.fromhex(code.replace("-", ""))).hexdigest() for code in codes
    )
    assert store.remaining_recovery_codes(ADMIN) == 8
    assert store.generate_recovery_codes(ADMIN) != codes


def test_a_recovery_code_works_exactly_once(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    assert store.use_recovery_code(ADMIN, codes[3]) is True
    assert store.use_recovery_code(ADMIN, codes[3]) is False
    assert store.remaining_recovery_codes(ADMIN) == 7
    used = [event for event in events if event[0] == "auth.recovery_used"]
    assert used == [
        (
            "auth.recovery_used",
            Severity.WARNING,
            {"username": ADMIN, "channel": "network", "remaining": 7},
        )
    ]
    # The other seven are untouched and each works once.
    others = [code for index, code in enumerate(codes) if index != 3]
    assert [store.use_recovery_code(ADMIN, code) for code in others] == [True] * 7
    assert store.remaining_recovery_codes(ADMIN) == 0
    assert [store.use_recovery_code(ADMIN, code) for code in codes[:2]] == [False, False]


def test_recovery_codes_tolerate_how_people_retype_them(store: AccountStore, admin: User) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    assert store.use_recovery_code("ROOT-ADMIN", codes[0].upper()) is True
    assert store.use_recovery_code(ADMIN, codes[1].replace("-", "")) is True
    assert store.use_recovery_code(ADMIN, "  " + codes[2].replace("-", " ") + "\n") is True
    assert store.remaining_recovery_codes(ADMIN) == 5


def test_generating_new_codes_invalidates_the_old_ones(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    old = store.generate_recovery_codes(ADMIN)
    new = store.generate_recovery_codes(ADMIN, actor=ADMIN)
    assert set(old).isdisjoint(new)
    assert store.use_recovery_code(ADMIN, old[0]) is False
    assert store.use_recovery_code(ADMIN, new[0]) is True
    assert store.remaining_recovery_codes(ADMIN) == 7
    assert events[2] == (
        "auth.user_changed",
        Severity.NOTICE,
        {"username": ADMIN, "change": "recovery_codes_generated", "count": 8, "actor": ADMIN},
    )


def test_recovery_codes_belong_to_one_account(store: AccountStore, admin: User) -> None:
    store.create_user("day-shift", OTHER, Role.OPERATOR)
    admin_codes = store.generate_recovery_codes(ADMIN)
    operator_codes = store.generate_recovery_codes("day-shift")
    assert store.use_recovery_code("day-shift", admin_codes[0]) is False
    assert store.use_recovery_code("nobody-here", admin_codes[0]) is False
    assert store.use_recovery_code(ADMIN, operator_codes[0]) is False
    assert store.use_recovery_code(ADMIN, admin_codes[0]) is True
    assert store.remaining_recovery_codes("day-shift") == 8


@pytest.mark.parametrize(
    "code",
    [
        None,
        "",
        "zzzz-zzzz",
        "0000-0000-0000-0000-0000-0000-0000-0000",
        "f" * 31,
        "f" * 33,
        "x" * 100_000,
        b"0123",
        12345678,
        chr(0xD800) * 32,
    ],
    ids=[
        "none",
        "empty",
        "not-hex",
        "zeros",
        "short",
        "long",
        "huge",
        "bytes",
        "int",
        "surrogates",
    ],
)
def test_malformed_recovery_codes_fail_quietly(
    store: AccountStore, admin: User, code: object
) -> None:
    store.generate_recovery_codes(ADMIN)
    assert store.use_recovery_code(ADMIN, code) is False  # type: ignore[arg-type]
    assert store.remaining_recovery_codes(ADMIN) == 8


@pytest.mark.parametrize("channel", [Channel.NETWORK, Channel.LOCAL])
def test_recovery_codes_are_never_locked_out(
    store: AccountStore, admin: User, db: Database, events: list[Event], channel: Channel
) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    wrong = "0123-4567-89ab-cdef-0123-4567-89ab-cdef"
    attempts = [store.use_recovery_code(ADMIN, wrong, channel=channel) for _ in range(50)]
    assert attempts == [False] * 50
    assert db.query("SELECT * FROM auth_throttle") == [], "recovery attempts are not counted"
    # A genuine code still works at once, after any number of wrong ones.
    assert store.use_recovery_code(ADMIN, codes[0], channel=channel) is True
    assert store.remaining_recovery_codes(ADMIN) == 7

    failures = [data for name, _s, data in events if name == "auth.failure"]
    assert len(failures) == 50 and "auth.lockout" not in names(events)
    assert failures[0] == {
        "username": ADMIN,
        "known_user": True,
        "channel": channel.value,
        "method": "recovery_code",
        "reason": "invalid_credentials",
    }


def test_a_password_lockout_does_not_block_recovery(store: AccountStore, admin: User) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    fail(store, 5)
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)
    assert store.use_recovery_code(ADMIN, codes[0]) is True
    # Using a code proves who is asking; the reset that follows clears the lockout.
    assert outcome(store.authenticate(ADMIN, PASSWORD)) == (LOCKED, 30)
    store.set_password(ADMIN, OTHER)
    assert store.authenticate(ADMIN, OTHER).ok is True
    assert store.use_recovery_code(ADMIN, codes[1], channel=Channel.LOCAL) is True


def test_recovery_codes_do_not_take_a_network_verification_slot(
    store: AccountStore, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    in_check, release = hold_verifications(monkeypatch)
    threads = [
        threading.Thread(target=lambda name=name: store.authenticate(name, WRONG))
        for name in ("ghost-001", "ghost-002")
    ]
    for thread in threads:
        thread.start()
    try:
        assert in_check.acquire(timeout=20) and in_check.acquire(timeout=20)
        assert outcome(store.authenticate(ADMIN, PASSWORD)) == (BUSY, 1)
        assert store.use_recovery_code(ADMIN, codes[0]) is True
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=20)


def test_unknown_accounts_answer_recovery_attempts_the_same_way(
    store: AccountStore, admin: User, events: list[Event]
) -> None:
    code = "0123-4567-89ab-cdef-0123-4567-89ab-cdef"
    assert [store.use_recovery_code("nobody-here", code) for _ in range(6)] == [False] * 6
    failure = events[-1][2]
    assert failure["username"] is None and failure["known_user"] is False


def test_a_disabled_account_cannot_use_recovery_codes(store: AccountStore, admin: User) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    codes = store.generate_recovery_codes(ADMIN)
    store.disable_user(ADMIN)
    assert store.use_recovery_code(ADMIN, codes[0]) is False
    assert store.remaining_recovery_codes(ADMIN) == 8
    store.enable_user(ADMIN)
    assert store.use_recovery_code(ADMIN, codes[0]) is True


def test_an_account_disabled_while_its_code_is_checked_cannot_spend_it(
    store: AccountStore, admin: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    codes = store.generate_recovery_codes(ADMIN)
    spend = store._spend_code

    def disabled_meanwhile(name: str, code_id: int, channel: Channel) -> bool:
        store.disable_user(ADMIN)
        return spend(name, code_id, channel)

    monkeypatch.setattr(store, "_spend_code", disabled_meanwhile)
    assert store.use_recovery_code(ADMIN, codes[0]) is False
    assert store.remaining_recovery_codes(ADMIN) == 8


def test_a_tampered_code_digest_does_not_break_or_match(
    store: AccountStore, admin: User, db: Database
) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    garbage = "\N{SNOWMAN}" * 8
    db.execute("UPDATE auth_recovery_codes SET code_digest = ? WHERE id = 1", (garbage,))
    assert store.use_recovery_code(ADMIN, codes[0]) is False
    assert store.use_recovery_code(ADMIN, codes[1]) is True


# --- what the audit trail may contain ------------------------------------------------


def test_the_audit_trail_never_contains_a_secret(
    store: AccountStore, admin: User, db: Database, clock: FakeClock, events: list[Event]
) -> None:
    typed_as_username = "hunter2-oops-my-pass"
    codes = store.generate_recovery_codes(ADMIN)
    store.create_user("day-shift", OTHER, Role.OPERATOR, actor=ADMIN)
    store.authenticate(ADMIN, PASSWORD)
    store.authenticate(typed_as_username, WRONG)
    fail(store, 6)
    clock.advance(30)
    store.use_recovery_code(ADMIN, codes[0])
    store.use_recovery_code(ADMIN, "dead-beef-dead-beef-dead-beef-dead-beef")
    store.change_password("day-shift", OTHER, "another-fine-secret-9")
    store.set_password(ADMIN, "reset-by-the-console-4", actor="console")
    store.set_role("day-shift", Role.AUDITOR, actor=ADMIN)
    store.disable_user("day-shift", actor=ADMIN)
    store.delete_user("day-shift", actor=ADMIN)

    assert set(names(events)) == {
        "auth.login",
        "auth.failure",
        "auth.lockout",
        "auth.password_changed",
        "auth.recovery_used",
        "auth.user_created",
        "auth.user_changed",
    }
    trail = json.dumps([(name, severity.value, data) for name, severity, data in events])
    secrets_seen = [
        PASSWORD,
        OTHER,
        WRONG,
        "another-fine-secret-9",
        "reset-by-the-console-4",
        typed_as_username,
        "dead-beef-dead-beef",
        "deadbeefdeadbeef",
        *codes,
        *(code.replace("-", "") for code in codes),
    ]
    for row in db.query("SELECT password_hash FROM auth_users"):
        secrets_seen.extend(row["password_hash"].split("$")[4:])
    for row in db.query("SELECT code_digest FROM auth_recovery_codes"):
        secrets_seen.append(row["code_digest"])
    assert len(secrets_seen) > 30
    for secret in secrets_seen:
        assert secret not in trail
    assert "scrypt$" not in trail


def test_the_throttle_table_does_not_keep_what_was_typed_as_a_name(
    store: AccountStore, admin: User, db: Database
) -> None:
    store.authenticate("hunter2-oops-my-pass", WRONG)
    store.authenticate(ADMIN, WRONG)
    rows = db.query("SELECT * FROM auth_throttle")
    assert len(rows) == 2
    everything = "|".join(str(value) for row in rows for value in tuple(row))
    assert "hunter2" not in everything and ADMIN not in everything
    assert all(re.fullmatch(r"[0-9a-f]{64}", row["subject"]) for row in rows)


# --- the throttle table stays bounded ------------------------------------------------


def test_guessing_at_made_up_names_cannot_grow_the_table_or_free_a_locked_account(
    db: Database, clock: FakeClock
) -> None:
    store = make_store(db, clock, policy=AuthPolicy(scrypt=FAST, max_throttle_entries=16))
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    fail(store, 5)
    for index in range(60):
        clock.advance(0.01)
        assert outcome(store.authenticate(f"ghost-{index:03d}", WRONG)) == (INVALID, 0)

    assert db.query_one("SELECT COUNT(*) AS n FROM auth_throttle")["n"] == 16  # type: ignore[index]
    # The account under attack kept its record: it has the most failures, so it goes last.
    assert outcome(store.authenticate(ADMIN, PASSWORD))[0] is LOCKED
    # The newest made-up names are the ones remembered.
    assert outcome(fail(store, 4, "ghost-059")[-1]) == (INVALID, 30)


def test_aged_out_records_are_dropped_first(db: Database, clock: FakeClock) -> None:
    store = make_store(db, clock, policy=AuthPolicy(scrypt=FAST, max_throttle_entries=16))
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    for index in range(16):
        store.authenticate(f"ghost-{index:03d}", WRONG)
    clock.advance(timedelta(hours=24, seconds=1))
    store.authenticate("fresh-name", WRONG)
    assert db.query_one("SELECT COUNT(*) AS n FROM auth_throttle")["n"] == 1  # type: ignore[index]


# --- concurrency ---------------------------------------------------------------------


def test_concurrent_wrong_passwords_never_exceed_the_threshold(
    db: Database, clock: FakeClock, verifications: list[str]
) -> None:
    store = make_store(db, clock, policy=WIDE)
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    results = run_together(16, lambda _index: store.authenticate(ADMIN, WRONG))
    reasons = [result.reason for result in results]
    assert reasons.count(INVALID) == 5 and reasons.count(LOCKED) == 11
    assert len(verifications) == 5
    row = db.query_one("SELECT failures FROM auth_throttle")
    assert row is not None and row["failures"] == 5


def test_the_threshold_holds_while_evaluations_are_still_in_flight(
    db: Database, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guarantee comes from charging attempts in the database, not from a lock.

    The in-process queue is switched off, and every admitted attempt is held inside the
    password check until all the others have been answered. If attempts were only
    counted after evaluation, all sixteen would be in the check at once.
    """
    # Room for all five admitted attempts to be hashing at the same time, and for all
    # sixteen to be admitted to the network path.
    store = make_store(
        db,
        clock,
        policy=AuthPolicy(scrypt=FAST, max_concurrent_hashes=8, max_network_verifications=16),
    )
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    for lock in store._attempt_locks:
        lock.acquire()
    monkeypatch.setattr(accounts, "_ATTEMPT_WAIT_SECONDS", 0)

    release = threading.Event()
    in_check = threading.Semaphore(0)
    answered = threading.Semaphore(0)
    entered: list[int] = []
    real = accounts.verify_password

    def held(password: str, encoded: str) -> bool:
        entered.append(1)
        in_check.release()
        assert release.wait(timeout=20)
        return real(password, encoded)

    monkeypatch.setattr(accounts, "verify_password", held)
    results: list[AuthResult] = []

    def attempt() -> None:
        result = store.authenticate(ADMIN, WRONG)
        results.append(result)
        answered.release()

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for thread in threads:
        thread.start()
    try:
        # Five reach the password check and stay there; eleven are answered meanwhile.
        for _ in range(5):
            assert in_check.acquire(timeout=20)
        for _ in range(11):
            assert answered.acquire(timeout=20), "an attempt past the threshold was not refused"
        assert len(entered) == 5
        assert [result.reason for result in results] == [LOCKED] * 11
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=20)
    assert len(entered) == 5
    assert sorted(result.reason for result in results) == [INVALID] * 5 + [LOCKED] * 11


def test_only_so_many_passwords_are_hashed_at_once_on_the_local_channel(
    db: Database, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = make_store(db, clock, policy=AuthPolicy(scrypt=FAST, max_concurrent_hashes=2))
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    in_check, release = hold_verifications(monkeypatch)
    results: list[AuthResult] = []
    # Six different names; locally nobody is refused, they wait their turn.
    threads = [
        threading.Thread(
            target=lambda name=f"ghost-{index:03d}": results.append(
                store.authenticate(name, WRONG, channel="local")
            )
        )
        for index in range(6)
    ]
    for thread in threads:
        thread.start()
    try:
        assert in_check.acquire(timeout=20) and in_check.acquire(timeout=20)
        # Two are hashing. A third does not start until one of them has finished.
        assert in_check.acquire(timeout=0.2) is False
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=20)
    assert [outcome(result) for result in results] == [(INVALID, 0)] * 6


def test_the_threshold_holds_across_two_handles_on_one_database(
    tmp_path: Path, clock: FakeClock, verifications: list[str]
) -> None:
    """Two stores on two connections, as the service and the CLI are."""
    path = tmp_path / "portlock.db"
    with Database(path) as first, Database(path) as second:
        service = make_store(first, clock, policy=WIDE)
        service.create_user(ADMIN, PASSWORD, Role.ADMIN)
        cli = make_store(second, clock, policy=WIDE)
        stores = [service, cli]
        results = run_together(12, lambda index: stores[index % 2].authenticate(ADMIN, WRONG))
        reasons = [result.reason for result in results]
        assert reasons.count(INVALID) == 5 and reasons.count(LOCKED) == 7
        assert len(verifications) == 5
        assert cli.lockout_remaining(ADMIN) == service.lockout_remaining(ADMIN) == 30


def test_concurrent_correct_logins_all_succeed(db: Database, clock: FakeClock) -> None:
    store = make_store(db, clock, policy=WIDE)
    store.create_user(ADMIN, PASSWORD, Role.ADMIN)
    results = run_together(12, lambda _index: store.authenticate(ADMIN, PASSWORD))
    assert [result.ok for result in results] == [True] * 12
    assert store.lockout_remaining(ADMIN) == 0


def test_concurrent_logins_with_the_default_limit_succeed_or_are_told_to_retry(
    store: AccountStore, admin: User
) -> None:
    results = run_together(12, lambda _index: store.authenticate(ADMIN, PASSWORD))
    assert {result.reason for result in results} <= {None, BUSY}
    assert any(result.ok for result in results)
    assert all(result.retry_after_seconds == 1 for result in results if not result.ok)
    # Nobody was counted for being refused as busy.
    assert store.lockout_remaining(ADMIN) == 0
    assert store.authenticate(ADMIN, PASSWORD).ok is True


def test_an_attempt_does_not_deadlock_when_it_cannot_take_its_turn(
    store: AccountStore, admin: User, db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    for lock in store._attempt_locks:
        lock.acquire()
    monkeypatch.setattr(accounts, "_ATTEMPT_WAIT_SECONDS", 0.01)
    with db.transaction():
        assert store.authenticate(ADMIN, PASSWORD).ok is True
    assert outcome(store.authenticate(ADMIN, WRONG)) == (INVALID, 0)
    # A turn that was never taken is not given back.
    assert all(lock.locked() for lock in store._attempt_locks)


def test_a_recovery_code_used_concurrently_works_once(store: AccountStore, admin: User) -> None:
    codes = store.generate_recovery_codes(ADMIN)
    results = run_together(4, lambda _index: store.use_recovery_code(ADMIN, codes[0]))
    assert sorted(results) == [False, False, False, True]
    assert store.remaining_recovery_codes(ADMIN) == 7


def test_a_recovery_code_spent_by_another_process_first_is_not_spent_twice(
    store: AccountStore,
    admin: User,
    db: Database,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both sides matched the code; only the first to record it may succeed."""
    codes = store.generate_recovery_codes(ADMIN)
    elsewhere = make_store(db, clock)
    spend = store._spend_code

    def beaten_to_it(name: str, code_id: int, channel: Channel) -> bool:
        assert elsewhere.use_recovery_code(ADMIN, codes[0]) is True
        return spend(name, code_id, channel)

    monkeypatch.setattr(store, "_spend_code", beaten_to_it)
    assert store.use_recovery_code(ADMIN, codes[0]) is False
    assert store.remaining_recovery_codes(ADMIN) == 7


def test_concurrent_creation_of_one_name_creates_one_account(
    store: AccountStore, admin: User
) -> None:
    def create(_index: int) -> str:
        try:
            store.create_user("Day-Shift", OTHER, Role.OPERATOR)
        except UserExistsError:
            return "exists"
        return "created"

    results = run_together(8, create)
    assert sorted(results) == ["created"] + ["exists"] * 7
    assert [user.username for user in store.list_users()] == ["day-shift", ADMIN]


def test_two_administrators_cannot_remove_each_other_at_the_same_time(
    store: AccountStore, admin: User
) -> None:
    store.create_user("second-admin", OTHER, Role.ADMIN)
    targets = [ADMIN, "second-admin"]

    def disable(index: int) -> str:
        try:
            store.disable_user(targets[index % 2])
        except LastAdminError:
            return "refused"
        return "disabled"

    results = run_together(8, disable)
    assert results.count("refused") >= 1
    enabled_admins = [user for user in store.list_users() if user.enabled]
    assert len(enabled_admins) == 1 and enabled_admins[0].role is Role.ADMIN
