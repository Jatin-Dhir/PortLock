"""Device grants: validation, selection, one-time binding, expiry and revocation."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import portlock.auth.grants as grants_module
from factories import make_device
from portlock.auth.grants import (
    ADMIN_MAX_DURATION,
    LOW_CONFIDENCE_MAX_DURATION,
    MAX_GRANTED_BY_LENGTH,
    MAX_NOTE_LENGTH,
    OPERATOR_MAX_DURATION,
    Grant,
    GrantEnd,
    GrantError,
    GrantKind,
    GrantStore,
    connection_key,
)
from portlock.core.clock import FakeClock
from portlock.core.db import Database
from portlock.core.errors import AuthError, PortLockError, StoreError
from portlock.core.models import Access, Confidence, Fingerprint, UsbDevice

HIGH = Fingerprint("plk1:abcdefghijklmnopqrstuvwxyz234567", Confidence.HIGH)
OTHER = Fingerprint("plk1:" + "b" * 32, Confidence.HIGH)
LOW = Fingerprint("plk1:" + "q" * 32, Confidence.LOW)

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
#: The ceiling an administrator's request carries (docs/DESIGN.md, section 14.13).
CEILING = ADMIN_MAX_DURATION
PORT = "1-1"


def conn(connection: str, *, port: str | None = PORT, instance: str = "test/1-1") -> UsbDevice:
    """One connection of a device: same instance id, a different connection id each time."""
    return make_device(instance_id=instance, connection_id=connection, bus_path=port)


@pytest.fixture
def store(db: Database, clock: FakeClock) -> GrantStore:
    return GrantStore(db, clock=clock)


def code_of(action: Callable[[], Any]) -> str:
    """Run ``action``, require that it raises a GrantError, and return its code."""
    with pytest.raises(GrantError) as caught:
        action()
    return caught.value.code


# --- creating -------------------------------------------------------------------------


def test_a_trust_grant_has_no_expiry(store: GrantStore, clock: FakeClock) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="  admin  ", note=" my own stick ")
    assert grant == Grant(
        id=grant.id,
        fingerprint=HIGH.value,
        confidence=Confidence.HIGH,
        kind=GrantKind.TRUST,
        read_only=False,
        created_at=clock.now(),
        granted_by="admin",
        expires_at=None,
        note="my own stick",
    )
    assert grant.access is Access.ALLOW
    assert store.get(grant.id) == grant


def test_a_temporary_grant_keeps_its_expiry_in_utc(store: GrantStore, clock: FakeClock) -> None:
    local = (clock.now() + 2 * HOUR).astimezone(timezone(timedelta(hours=5, minutes=30)))
    grant = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=local,
        granted_by="op",
        read_only=True,
    )
    assert grant.expires_at == clock.now() + 2 * HOUR
    assert grant.expires_at is not None and grant.expires_at.utcoffset() == timedelta(0)
    assert grant.access is Access.READ_ONLY
    assert store.get(grant.id) == grant


def test_a_one_time_grant_may_have_an_expiry_or_not(store: GrantStore, clock: FakeClock) -> None:
    open_ended = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    bounded = store.create(HIGH, GrantKind.ONCE, granted_by="op", expires_at=clock.now() + HOUR)
    assert open_ended.expires_at is None and open_ended.bound_connection is None
    assert bounded.expires_at == clock.now() + HOUR


def test_the_kind_may_be_given_by_name(store: GrantStore) -> None:
    grant = store.create(HIGH, "trust", granted_by="admin")  # type: ignore[arg-type]
    assert grant.kind is GrantKind.TRUST


def test_ids_are_random_and_unguessable_in_form(store: GrantStore) -> None:
    ids = [store.create(HIGH, GrantKind.TRUST, granted_by="admin").id for _ in range(200)]
    assert len(set(ids)) == 200
    assert all(re.fullmatch(r"[0-9a-f]{32}", grant_id) for grant_id in ids)
    # Not a counter, not derived from the fingerprint: consecutive ids share no prefix.
    assert len({grant_id[:8] for grant_id in ids}) == 200


@pytest.mark.parametrize(
    ("kind", "arguments", "fragment"),
    [
        (GrantKind.TRUST, {"expires_at": "future"}, "a trust grant has no expiry"),
        (GrantKind.TEMPORARY, {}, "a temporary grant needs an expiry"),
        (GrantKind.TEMPORARY, {"expires_at": "now"}, "the expiry must be in the future"),
        (GrantKind.TEMPORARY, {"expires_at": "past"}, "the expiry must be in the future"),
        (GrantKind.ONCE, {"expires_at": "past"}, "the expiry must be in the future"),
        (GrantKind.TEMPORARY, {"expires_at": "naive"}, "expires_at must be a timezone-aware"),
        (GrantKind.TEMPORARY, {"expires_at": "2026-06-01"}, "expires_at must be a timezone-aware"),
        ("forever", {}, "the grant kind must be trust, temporary or once"),
        (None, {}, "the grant kind must be trust, temporary or once"),
        (GrantKind.TRUST, {"granted_by": ""}, "granted_by must not be empty"),
        (GrantKind.TRUST, {"granted_by": "   "}, "granted_by must not be empty"),
        (GrantKind.TRUST, {"granted_by": None}, "granted_by must be a string"),
        (
            GrantKind.TRUST,
            {"granted_by": "a" * (MAX_GRANTED_BY_LENGTH + 1)},
            "granted_by is too long",
        ),
        (GrantKind.TRUST, {"granted_by": "ad\x00min"}, "granted_by must not contain control"),
        (GrantKind.TRUST, {"note": "n" * (MAX_NOTE_LENGTH + 1)}, "a note is too long"),
        (GrantKind.TRUST, {"note": "two\nlines"}, "a note must not contain control"),
        (GrantKind.TRUST, {"note": 5}, "a note must be a string"),
        (GrantKind.TRUST, {"read_only": 1}, "read_only must be true or false"),
        (GrantKind.TRUST, {"read_only": "yes"}, "read_only must be true or false"),
        (
            GrantKind.TEMPORARY,
            {"expires_at": "future", "max_duration": None},
            "a temporary grant needs the ceiling for the granting role",
        ),
        (
            GrantKind.TEMPORARY,
            {"expires_at": "beyond", "max_duration": OPERATOR_MAX_DURATION},
            "the expiry is further ahead than this role may grant \\(24 h\\)",
        ),
        (
            GrantKind.ONCE,
            {"expires_at": "beyond", "max_duration": OPERATOR_MAX_DURATION},
            "the expiry is further ahead than this role may grant",
        ),
        (
            GrantKind.TEMPORARY,
            {"expires_at": "future", "max_duration": timedelta(0)},
            "max_duration must be a positive timedelta",
        ),
        (
            GrantKind.TEMPORARY,
            {"expires_at": "future", "max_duration": 3600},
            "max_duration must be a positive timedelta",
        ),
        (GrantKind.TRUST, {"port": ""}, "a port must not be empty"),
        (GrantKind.TRUST, {"port": "1-1\x00"}, "a port must not contain control"),
    ],
)
def test_create_validation(
    store: GrantStore, clock: FakeClock, kind: Any, arguments: dict[str, Any], fragment: str
) -> None:
    moments = {
        "future": clock.now() + HOUR,
        "now": clock.now(),
        "past": clock.now() - HOUR,
        "naive": datetime(2030, 1, 1),
        "beyond": clock.now() + OPERATOR_MAX_DURATION + timedelta(seconds=1),
    }
    if "expires_at" in arguments:
        arguments = {**arguments, "expires_at": moments.get(arguments["expires_at"], "2026-06-01")}
    arguments.setdefault("granted_by", "admin")
    arguments.setdefault("max_duration", CEILING)
    with pytest.raises(GrantError, match=fragment) as caught:
        store.create(HIGH, kind, **arguments)
    assert caught.value.code == "grant_invalid"
    assert isinstance(caught.value, AuthError) and isinstance(caught.value, PortLockError)
    assert store.list(include_inactive=True) == []


@pytest.mark.parametrize(
    "fingerprint",
    [
        HIGH.value,
        None,
        Fingerprint("", Confidence.HIGH),
        Fingerprint("plk1:with space", Confidence.HIGH),
        Fingerprint("plk1:" + "A" * 200, Confidence.HIGH),
        Fingerprint("plk1:caf\xe9", Confidence.HIGH),
        Fingerprint("plk1:tab\there", Confidence.HIGH),
        Fingerprint(HIGH.value, "high"),  # type: ignore[arg-type]
    ],
)
def test_a_grant_needs_a_real_fingerprint(store: GrantStore, fingerprint: Any) -> None:
    assert code_of(lambda: store.create(fingerprint, GrantKind.TRUST, granted_by="admin")) == (
        "grant_invalid"
    )
    assert store.list(include_inactive=True) == []


# --- low-confidence fingerprints ------------------------------------------------------


def test_a_low_confidence_fingerprint_is_never_trusted(store: GrantStore) -> None:
    for port in (None, PORT):
        with pytest.raises(GrantError, match="every unit of the same model") as caught:
            store.create(LOW, GrantKind.TRUST, granted_by="admin", port=port)
        assert caught.value.code == "grant_low_confidence"
    assert store.list(include_inactive=True) == []


def test_a_low_confidence_temporary_grant_is_capped_whatever_the_role(
    store: GrantStore, clock: FakeClock
) -> None:
    longest = clock.now() + LOW_CONFIDENCE_MAX_DURATION
    with pytest.raises(GrantError, match="may last at most 24 h") as caught:
        store.create(
            LOW,
            GrantKind.TEMPORARY,
            expires_at=longest + timedelta(seconds=1),
            max_duration=ADMIN_MAX_DURATION,
            port=PORT,
            granted_by="admin",
        )
    assert caught.value.code == "grant_low_confidence"
    grant = store.create(
        LOW,
        GrantKind.TEMPORARY,
        expires_at=longest,
        max_duration=ADMIN_MAX_DURATION,
        port=PORT,
        granted_by="admin",
    )
    assert grant.confidence is Confidence.LOW and grant.bound_port == PORT
    assert store.get(grant.id) == grant


def test_a_low_confidence_grant_must_name_its_port(store: GrantStore, clock: FakeClock) -> None:
    for kind, extra in (
        (GrantKind.ONCE, {}),
        (GrantKind.TEMPORARY, {"expires_at": clock.now() + HOUR, "max_duration": CEILING}),
    ):
        with pytest.raises(GrantError, match="limited to the port") as caught:
            store.create(LOW, kind, granted_by="op", **extra)
        assert caught.value.code == "grant_low_confidence"
    assert store.list(include_inactive=True) == []
    once = store.create(LOW, GrantKind.ONCE, granted_by="op", port=f"  {PORT} ")
    assert once.bound_port == PORT and once.expires_at is None


def test_a_port_bound_grant_matches_only_on_its_port(store: GrantStore, clock: FakeClock) -> None:
    grant = store.create(
        LOW,
        GrantKind.TEMPORARY,
        expires_at=clock.now() + HOUR,
        max_duration=OPERATOR_MAX_DURATION,
        port="1-2",
        granted_by="op",
    )
    now = clock.now()
    assert store.active_for(LOW.value, now=now, device=conn("c1", port="1-2")) == grant
    # Another unit of the same model elsewhere, a port that merely starts the same way,
    # a device behind a hub on that port, and a device with no known port: none of them.
    for port in ("1-3", "1-21", "1-2.1", None):
        assert store.active_for(LOW.value, now=now, device=conn("c2", port=port)) is None
    # Without a device to look at, a port-bound grant cannot be confirmed to apply.
    assert store.active_for(LOW.value, now=now) is None


def test_a_high_confidence_grant_may_be_limited_to_a_port_too(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin", port="1-4")
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("c1", port="1-4")) == grant
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("c1")) is None


def test_a_one_time_grant_limited_to_a_port_binds_only_there(store: GrantStore) -> None:
    grant = store.create(LOW, GrantKind.ONCE, granted_by="op", port="1-2")
    assert code_of(lambda: store.bind(grant.id, conn("c1", port="1-3"))) == (
        "grant_bound_elsewhere"
    )
    assert store.get(grant.id).bound_connection is None
    bound = store.bind(grant.id, conn("c1", port="1-2"))
    assert (bound.bound_connection, bound.bound_port) == ("c1", "1-2")


def test_the_role_ceiling_is_the_callers_to_pass(store: GrantStore, clock: FakeClock) -> None:
    # The defaults docs/DESIGN.md section 14.13 sets for the two roles.
    assert OPERATOR_MAX_DURATION.total_seconds() == 24 * 3600
    assert ADMIN_MAX_DURATION.days == 30
    exactly = clock.now() + OPERATOR_MAX_DURATION
    grant = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        expires_at=exactly,
        max_duration=OPERATOR_MAX_DURATION,
        granted_by="op",
    )
    assert grant.expires_at == exactly
    later = clock.now() + 2 * DAY
    refused = code_of(
        lambda: store.create(
            HIGH,
            GrantKind.TEMPORARY,
            expires_at=later,
            max_duration=OPERATOR_MAX_DURATION,
            granted_by="op",
        )
    )
    assert refused == "grant_invalid"
    allowed = store.create(
        HIGH, GrantKind.TEMPORARY, expires_at=later, max_duration=CEILING, granted_by="admin"
    )
    assert allowed.expires_at == later


# --- connections ----------------------------------------------------------------------


def test_a_one_time_grant_binds_to_the_connection_id_not_the_instance_id(
    store: GrantStore,
) -> None:
    first, replug = conn("conn-1"), conn("conn-2")
    # The OS gives the re-plugged stick the same instance id; the backend does not.
    assert first.instance_id == replug.instance_id
    assert connection_key(first) == "conn-1"
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    store.bind(grant.id, first)
    assert store.active_for(HIGH.value, now=store.get(grant.id).created_at, device=replug) is None
    assert code_of(lambda: store.bind(grant.id, replug)) == "grant_bound_elsewhere"


def test_without_a_connection_id_the_instance_id_stands_in(store: GrantStore) -> None:
    bare = make_device(instance_id="test/9-9", connection_id=None)
    assert connection_key(bare) == "test/9-9"
    assert connection_key(make_device(instance_id="test/9-9", connection_id="")) == "test/9-9"
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    assert store.bind(grant.id, bare).bound_connection == "test/9-9"
    assert [item.id for item in store.release(bare)] == [grant.id]


# --- which grant applies --------------------------------------------------------------


def test_no_grant_applies_to_an_unknown_device(store: GrantStore, clock: FakeClock) -> None:
    store.create(OTHER, GrantKind.TRUST, granted_by="admin")
    assert store.active_for(HIGH.value, now=clock.now()) is None
    assert store.active_for("", now=clock.now()) is None
    assert store.active_for("x' OR '1'='1", now=clock.now()) is None


def test_a_trust_grant_applies_until_revoked(store: GrantStore, clock: FakeClock) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    assert store.active_for(HIGH.value, now=clock.now()) == grant
    assert store.active_for(HIGH.value, now=clock.now() + 3650 * DAY) == grant
    store.revoke(grant.id, "admin")
    assert store.active_for(HIGH.value, now=clock.now()) is None


def test_a_temporary_grant_stops_applying_at_its_expiry(
    store: GrantStore, clock: FakeClock
) -> None:
    expiry = clock.now() + HOUR
    grant = store.create(
        HIGH, GrantKind.TEMPORARY, max_duration=CEILING, expires_at=expiry, granted_by="op"
    )
    assert store.active_for(HIGH.value, now=expiry - timedelta(microseconds=1)) == grant
    assert store.active_for(HIGH.value, now=expiry) is None
    assert store.active_for(HIGH.value, now=expiry + DAY) is None
    # Asking does not mark anything: the expiry is still there to be reported.
    assert [item.id for item in store.expire_due(expiry)] == [grant.id]


def test_the_time_must_be_timezone_aware(store: GrantStore) -> None:
    assert code_of(lambda: store.active_for(HIGH.value, now=datetime(2026, 1, 1))) == (
        "grant_invalid"
    )
    assert code_of(lambda: store.expire_due(datetime(2026, 1, 1))) == "grant_invalid"


def test_read_only_wins_over_full(store: GrantStore, clock: FakeClock) -> None:
    store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    narrow = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
        read_only=True,
    )
    # The most restrictive grant applies, even though the full one lasts longer...
    assert store.active_for(HIGH.value, now=clock.now()) == narrow
    # ...and once it has run out, the broader one takes over.
    after = store.active_for(HIGH.value, now=clock.now() + HOUR)
    assert after is not None and after.kind is GrantKind.TRUST and not after.read_only


def test_the_longest_remaining_wins_among_equally_restrictive_grants(
    store: GrantStore, clock: FakeClock
) -> None:
    now = clock.now()
    short = store.create(
        HIGH, GrantKind.TEMPORARY, max_duration=CEILING, expires_at=now + HOUR, granted_by="op"
    )
    long = store.create(
        HIGH, GrantKind.TEMPORARY, max_duration=CEILING, expires_at=now + DAY, granted_by="op"
    )
    assert store.active_for(HIGH.value, now=now) == long

    forever = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    assert store.active_for(HIGH.value, now=now) == forever
    store.revoke(forever.id, "admin")
    store.revoke(long.id, "admin")
    assert store.active_for(HIGH.value, now=now) == short


def test_a_one_time_grant_is_not_spent_while_a_longer_grant_covers_the_device(
    store: GrantStore, clock: FakeClock
) -> None:
    now = clock.now()
    once = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    temporary = store.create(
        HIGH, GrantKind.TEMPORARY, max_duration=CEILING, expires_at=now + HOUR, granted_by="op"
    )
    assert store.active_for(HIGH.value, now=now, device=conn("usb/1")) == temporary
    # The same holds when no particular connection is being asked about.
    assert store.active_for(HIGH.value, now=now) == temporary
    # When the temporary grant has run out, the unused one-time grant is still there.
    assert store.active_for(HIGH.value, now=now + HOUR, device=conn("usb/1")) == once


def test_a_longer_grant_takes_over_from_a_one_time_grant_already_in_use(
    store: GrantStore, clock: FakeClock
) -> None:
    once = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    store.bind(once.id, conn("usb/1"))
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1")) == store.get(once.id)

    temporary = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
    )
    # A one-time grant has no expiry of its own, but it is still the shorter of the two.
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1")) == temporary
    # It stays bound, and is spent when its connection ends.
    assert [grant.id for grant in store.release(conn("usb/1"))] == [once.id]
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1")) == temporary


def test_the_oldest_wins_a_tie_whatever_the_ids_are(store: GrantStore, clock: FakeClock) -> None:
    first = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    clock.advance(1)
    for _ in range(20):
        store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    assert store.active_for(HIGH.value, now=clock.now()) == first


def test_grants_made_at_the_same_instant_tie_break_on_id(
    store: GrantStore, clock: FakeClock
) -> None:
    grants = [store.create(HIGH, GrantKind.TRUST, granted_by="admin") for _ in range(20)]
    expected = min(grants, key=lambda grant: grant.id)
    assert store.active_for(HIGH.value, now=clock.now()) == expected


def test_the_choice_does_not_depend_on_the_order_grants_were_made_in(clock: FakeClock) -> None:
    recipes: list[dict[str, Any]] = [
        {"kind": GrantKind.TRUST, "read_only": False},
        {"kind": GrantKind.TEMPORARY, "read_only": True, "expires_at": clock.now() + HOUR},
        {"kind": GrantKind.TEMPORARY, "read_only": True, "expires_at": clock.now() + DAY},
        {"kind": GrantKind.ONCE, "read_only": True},
        {"kind": GrantKind.TEMPORARY, "read_only": False, "expires_at": clock.now() + 7 * DAY},
        {"kind": GrantKind.TRUST, "read_only": True, "port": "1-9"},
    ]
    chosen = []
    for ordering in (recipes, recipes[::-1], recipes[2:] + recipes[:2]):
        with Database() as database:
            store = GrantStore(database, clock=clock)
            for recipe in ordering:
                store.create(HIGH, granted_by="admin", max_duration=CEILING, **recipe)
            winner = store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1"))
            assert winner is not None
            chosen.append((winner.kind, winner.read_only, winner.expires_at))
    # Read-only first, then not one-time, then the later expiry.
    assert chosen == [(GrantKind.TEMPORARY, True, clock.now() + DAY)] * 3


# --- one-time grants ------------------------------------------------------------------


def test_a_one_time_grant_lives_for_exactly_one_connection(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op", read_only=True)
    now = clock.now()
    # Unused, it is waiting for whichever connection comes first.
    assert store.active_for(HIGH.value, now=now, device=conn("usb/1")) == grant
    assert store.active_for(HIGH.value, now=now, device=conn("usb/2")) == grant
    assert store.active_for(HIGH.value, now=now) == grant

    clock.advance(5)
    bound = store.bind(grant.id, conn("usb/1"))
    assert bound.bound_connection == "usb/1" and bound.bound_at == clock.now()
    assert bound.ended_at is None
    assert store.get(grant.id) == bound

    # Bound, it belongs to that connection and to no other.
    now = clock.now()
    assert store.active_for(HIGH.value, now=now, device=conn("usb/1")) == bound
    assert store.active_for(HIGH.value, now=now, device=conn("usb/2")) is None
    assert store.active_for(HIGH.value, now=now) is None
    assert store.list() == [bound]

    clock.advance(60)
    (spent,) = store.release(conn("usb/1"))
    assert spent.id == grant.id
    assert spent.end_reason is GrantEnd.USED and spent.ended_at == clock.now()
    assert spent.bound_connection == "usb/1"

    # Spent, it covers nothing: not even the same port again.
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1")) is None
    assert store.release(conn("usb/1")) == []
    assert store.list() == []
    assert store.get(grant.id) == spent


def test_binding_again_to_the_same_connection_changes_nothing(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    first = store.bind(grant.id, conn("usb/1"))
    clock.advance(30)
    assert store.bind(grant.id, conn("usb/1")) == first


def test_a_bound_grant_cannot_be_taken_by_another_connection(store: GrantStore) -> None:
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    store.bind(grant.id, conn("usb/1"))
    assert code_of(lambda: store.bind(grant.id, conn("usb/2"))) == "grant_bound_elsewhere"
    assert store.get(grant.id).bound_connection == "usb/1"


def test_a_bound_one_time_grant_is_preferred_to_spending_a_second_one(
    store: GrantStore, clock: FakeClock
) -> None:
    first = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    clock.advance(1)
    second = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    store.bind(second.id, conn("usb/1"))
    now = clock.now()
    assert store.active_for(HIGH.value, now=now, device=conn("usb/1")) == store.get(second.id)
    # Another unit of the same model on another port gets the unused one.
    assert store.active_for(HIGH.value, now=now, device=conn("usb/2")) == first


def test_bind_refuses_grants_it_cannot_bind(store: GrantStore, clock: FakeClock) -> None:
    trust = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    assert code_of(lambda: store.bind(trust.id, conn("usb/1"))) == "grant_invalid"
    assert code_of(lambda: store.bind("0" * 32, conn("usb/1"))) == "grant_not_found"

    revoked = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    store.revoke(revoked.id, "admin")
    assert code_of(lambda: store.bind(revoked.id, conn("usb/1"))) == "grant_not_active"

    timed = store.create(HIGH, GrantKind.ONCE, granted_by="op", expires_at=clock.now() + HOUR)
    clock.advance(HOUR)
    assert code_of(lambda: store.bind(timed.id, conn("usb/1"))) == "grant_not_active"
    assert store.get(timed.id).bound_connection is None

    usable = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    for bad in (None, 7, "usb/1", conn("x" * 1025), conn("bad\x00id"), conn("   ")):
        assert code_of(lambda bad=bad: store.bind(usable.id, bad)) == "grant_invalid"
    assert store.get(usable.id).bound_connection is None


def test_release_only_touches_the_named_connection(store: GrantStore) -> None:
    mine = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    theirs = store.create(OTHER, GrantKind.ONCE, granted_by="op")
    unused = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    trust = store.create(OTHER, GrantKind.TRUST, granted_by="admin")
    store.bind(mine.id, conn("usb/1"))
    store.bind(theirs.id, conn("usb/2"))

    assert store.release(conn("usb/3")) == []
    assert [grant.id for grant in store.release(conn("usb/1"))] == [mine.id]
    active = {grant.id for grant in store.list()}
    assert active == {theirs.id, unused.id, trust.id}
    assert code_of(lambda: store.release("usb/1")) == "grant_invalid"  # type: ignore[arg-type]


def test_instance_ids_are_data_not_sql(store: GrantStore, clock: FakeClock) -> None:
    hostile = "usb/1' OR '1'='1"
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    other = store.create(OTHER, GrantKind.ONCE, granted_by="op")
    store.bind(other.id, conn("usb/2"))
    assert store.release(conn(hostile)) == []
    store.bind(grant.id, conn(hostile))
    assert store.active_for(HIGH.value, now=clock.now(), device=conn(hostile)) is not None
    assert [item.id for item in store.release(conn(hostile))] == [grant.id]
    assert store.get(other.id).ended_at is None


def test_grants_bound_to_connections_that_are_gone_are_spent_at_start_up(
    store: GrantStore, clock: FakeClock
) -> None:
    still_here = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    gone = store.create(OTHER, GrantKind.ONCE, granted_by="op")
    unused = store.create(LOW, GrantKind.ONCE, granted_by="op", port=PORT)
    store.bind(still_here.id, conn("usb/1"))
    store.bind(gone.id, conn("usb/2"))

    clock.advance(600)
    spent = store.release_absent([conn("usb/1"), conn("usb/7")])
    assert [(grant.id, grant.end_reason, grant.ended_at) for grant in spent] == [
        (gone.id, GrantEnd.USED, clock.now())
    ]
    assert {grant.id for grant in store.list()} == {still_here.id, unused.id}
    assert store.release_absent([conn("usb/1")]) == []
    assert [grant.id for grant in store.release_absent([])] == [still_here.id]


def test_a_one_time_grant_with_an_expiry_ends_even_while_connected(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op", expires_at=clock.now() + HOUR)
    store.bind(grant.id, conn("usb/1"))
    clock.advance(HOUR)
    assert store.active_for(HIGH.value, now=clock.now(), device=conn("usb/1")) is None
    (expired,) = store.expire_due(clock.now())
    assert expired.id == grant.id and expired.end_reason is GrantEnd.EXPIRED
    # Removal afterwards has nothing left to spend.
    assert store.release(conn("usb/1")) == []


def test_only_one_of_many_racing_connections_gets_a_one_time_grant(store: GrantStore) -> None:
    grant = store.create(HIGH, GrantKind.ONCE, granted_by="op")
    outcomes: list[str] = []
    barrier = threading.Barrier(12)

    def claim(instance: str) -> None:
        barrier.wait(timeout=5)
        try:
            store.bind(grant.id, conn(instance))
        except GrantError as exc:
            outcomes.append(exc.code)
        else:
            outcomes.append(f"bound:{instance}")

    threads = [threading.Thread(target=claim, args=(f"usb/{n}",)) for n in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    winners = [outcome for outcome in outcomes if outcome.startswith("bound:")]
    assert len(outcomes) == 12 and len(winners) == 1
    assert outcomes.count("grant_bound_elsewhere") == 11
    assert store.get(grant.id).bound_connection == winners[0].removeprefix("bound:")


# --- expiry ---------------------------------------------------------------------------


def test_each_expired_grant_is_reported_exactly_once(store: GrantStore, clock: FakeClock) -> None:
    start = clock.now()
    later = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=start + 3 * HOUR,
        granted_by="op",
    )
    sooner = store.create(
        OTHER, GrantKind.TEMPORARY, max_duration=CEILING, expires_at=start + HOUR, granted_by="op"
    )
    once = store.create(
        LOW, GrantKind.ONCE, expires_at=start + 2 * HOUR, granted_by="op", port=PORT
    )
    trust = store.create(HIGH, GrantKind.TRUST, granted_by="admin")

    assert store.expire_due(start) == []
    assert store.expire_due(start + HOUR - timedelta(microseconds=1)) == []

    # Due at the instant of expiry itself.
    (first,) = store.expire_due(start + HOUR)
    assert first.id == sooner.id
    assert first.end_reason is GrantEnd.EXPIRED and first.ended_at == start + HOUR
    assert first.ended_by is None
    assert store.expire_due(start + HOUR) == []

    # Processing late still reports each grant once, earliest expiry first, and records
    # the moment the grant stopped being valid rather than the moment it was noticed.
    clock.advance(10 * HOUR)
    due = store.expire_due(clock.now())
    assert [grant.id for grant in due] == [once.id, later.id]
    assert [grant.ended_at for grant in due] == [start + 2 * HOUR, start + 3 * HOUR]
    assert store.expire_due(clock.now()) == []
    assert store.expire_due(clock.now() + 3650 * DAY) == []
    assert store.list() == [trust]


def test_a_revoked_grant_is_not_later_reported_as_expired(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
    )
    store.revoke(grant.id, "admin")
    assert store.expire_due(clock.now() + DAY) == []
    assert store.get(grant.id).end_reason is GrantEnd.REVOKED


def test_concurrent_expiry_sweeps_report_each_grant_once(
    store: GrantStore, clock: FakeClock
) -> None:
    expected = {
        store.create(
            HIGH,
            GrantKind.TEMPORARY,
            max_duration=CEILING,
            expires_at=clock.now() + timedelta(seconds=n + 1),
            granted_by="op",
        ).id
        for n in range(60)
    }
    clock.advance(HOUR)
    now = clock.now()
    reported: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def sweep() -> None:
        barrier.wait(timeout=5)
        for _ in range(3):
            found = [grant.id for grant in store.expire_due(now)]
            with lock:
                reported.extend(found)

    threads = [threading.Thread(target=sweep) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert len(reported) == 60 and set(reported) == expected


# --- revoking, listing, reading -------------------------------------------------------


def test_revoking_records_who_and_when(store: GrantStore, clock: FakeClock) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    clock.advance(90)
    revoked = store.revoke(grant.id, " security-officer ")
    assert revoked.ended_at == clock.now()
    assert revoked.end_reason is GrantEnd.REVOKED
    assert revoked.ended_by == "security-officer"
    assert store.get(grant.id) == revoked
    assert not revoked.is_active(clock.now())


def test_revoke_refuses_what_it_cannot_revoke(store: GrantStore, clock: FakeClock) -> None:
    assert code_of(lambda: store.revoke("f" * 32, "admin")) == "grant_not_found"

    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    for who in ("", None, "x" * 129, "new\nline"):
        assert code_of(lambda bad=who: store.revoke(grant.id, bad)) == "grant_invalid"
    assert store.get(grant.id).ended_at is None

    store.revoke(grant.id, "admin")
    assert code_of(lambda: store.revoke(grant.id, "admin")) == "grant_not_active"
    assert store.get(grant.id).ended_by == "admin"


def test_a_grant_past_its_expiry_is_left_for_the_expiry_sweep(
    store: GrantStore, clock: FakeClock
) -> None:
    grant = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
    )
    clock.advance(2 * HOUR)
    assert code_of(lambda: store.revoke(grant.id, "admin")) == "grant_not_active"
    # Had revoke marked it, the expiry would never have been audited.
    assert [item.id for item in store.expire_due(clock.now())] == [grant.id]


def test_listing_shows_active_grants_oldest_first(store: GrantStore, clock: FakeClock) -> None:
    assert store.list() == [] and store.list(include_inactive=True) == []
    first = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    clock.advance(1)
    second = store.create(
        OTHER,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
    )
    clock.advance(1)
    third = store.create(LOW, GrantKind.ONCE, granted_by="op", port=PORT)
    clock.advance(1)
    fourth = store.create(HIGH, GrantKind.TRUST, granted_by="admin", read_only=True)
    assert store.list() == [first, second, third, fourth]

    revoked = store.revoke(first.id, "admin")
    clock.advance(HOUR)
    # `second` has reached its expiry but no sweep has run: it is already not active.
    assert store.list() == [third, fourth]
    assert store.list(include_inactive=True) == [revoked, second, third, fourth]


def test_get_reports_a_missing_grant(store: GrantStore) -> None:
    with pytest.raises(GrantError, match="no such grant") as caught:
        store.get("nope")
    assert caught.value.code == "grant_not_found"
    assert code_of(lambda: store.get("' OR 1=1 --")) == "grant_not_found"


def test_grant_helpers(clock: FakeClock) -> None:
    now = clock.now()
    grant = Grant(
        id="a" * 32,
        fingerprint=HIGH.value,
        confidence=Confidence.HIGH,
        kind=GrantKind.TEMPORARY,
        read_only=True,
        created_at=now,
        granted_by="op",
        expires_at=now + HOUR,
        note="loan",
    )
    assert grant.is_active(now) and not grant.is_active(now + HOUR)
    assert grant.remaining(now) == HOUR
    assert grant.remaining(now + DAY) == timedelta(0)
    assert grant.to_dict() == {
        "id": "a" * 32,
        "fingerprint": HIGH.value,
        "confidence": "high",
        "kind": "temporary",
        "read_only": True,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "granted_by": "op",
        "expires_at": "2026-01-01T01:00:00.000000Z",
        "note": "loan",
        "bound_connection": None,
        "bound_port": None,
        "bound_at": None,
        "ended_at": None,
        "end_reason": None,
        "ended_by": None,
    }
    trust = Grant("b" * 32, HIGH.value, Confidence.HIGH, GrantKind.TRUST, False, now, "admin")
    assert trust.remaining(now) is None and trust.is_active(now + 3650 * DAY)
    assert trust.access is Access.ALLOW


# --- storage --------------------------------------------------------------------------


def test_grants_survive_a_restart(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "state.db"
    with Database(path) as database:
        store = GrantStore(database, clock=clock)
        trust = store.create(HIGH, GrantKind.TRUST, granted_by="admin", note="kept")
        clock.advance(1)
        once = store.create(OTHER, GrantKind.ONCE, granted_by="op", read_only=True)
        bound = store.bind(once.id, conn("usb/1"))
        assert database.schema_version("grants") == 2

    with Database(path) as database:
        # Creating the store again must not disturb what is there.
        store = GrantStore(database, clock=clock)
        assert database.schema_version("grants") == 2
        assert store.list() == [trust, bound]
        assert store.active_for(OTHER.value, now=clock.now(), device=conn("usb/1")) == bound


def test_a_version_1_table_is_upgraded_in_place(db: Database, clock: FakeClock) -> None:
    # The table as the first release created it, holding a one-time grant in use.
    db.migrate("grants", grants_module._MIGRATIONS[:1])
    db.execute(
        "INSERT INTO grants (id, fingerprint, confidence, kind, read_only, created_at,"
        " granted_by, bound_instance, bound_at) VALUES (?, ?, 'high', 'once', 0, ?, 'op', ?, ?)",
        (
            "c" * 32,
            HIGH.value,
            "2026-01-01T00:00:00.000000Z",
            "test/1-1",
            "2026-01-01T00:00:00.000000Z",
        ),
    )
    store = GrantStore(db, clock=clock)
    assert db.schema_version("grants") == 2
    kept = store.get("c" * 32)
    # What the first release stored was the instance id, which is what a backend without
    # connection ids still uses; the grant carries on covering that connection.
    assert (kept.bound_connection, kept.bound_port) == ("test/1-1", None)
    device = make_device(instance_id="test/1-1", connection_id=None)
    assert store.active_for(HIGH.value, now=clock.now(), device=device) == kept


def test_a_read_only_database_can_be_read_but_not_changed(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "state.db"
    with Database(path) as database:
        grant = GrantStore(database, clock=clock).create(HIGH, GrantKind.TRUST, granted_by="admin")

    with Database(path, read_only=True) as database:
        store = GrantStore(database, clock=clock)
        assert store.list() == [grant]
        assert store.active_for(HIGH.value, now=clock.now()) == grant
        with pytest.raises(StoreError):
            store.create(HIGH, GrantKind.TRUST, granted_by="admin")
        with pytest.raises(StoreError):
            store.revoke(grant.id, "admin")

    with Database(path) as database:
        assert GrantStore(database, clock=clock).list() == [grant]


def test_a_read_only_database_without_the_tables_is_refused(
    tmp_path: Path, clock: FakeClock
) -> None:
    path = tmp_path / "empty.db"
    Database(path).close()
    with (
        Database(path, read_only=True) as database,
        pytest.raises(StoreError, match="grants tables are at version 0"),
    ):
        GrantStore(database, clock=clock)


def test_a_database_from_a_newer_portlock_is_refused(db: Database, clock: FakeClock) -> None:
    GrantStore(db, clock=clock)
    db.execute(
        "INSERT INTO schema_migrations (component, version, applied_at)"
        " VALUES ('grants', 3, '2026-01-01T00:00:00.000Z')"
    )
    with pytest.raises(StoreError, match="upgrade PortLock"):
        GrantStore(db, clock=clock)


def test_a_corrupt_record_is_a_store_error_not_a_grant(
    store: GrantStore, db: Database, clock: FakeClock
) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    db.execute("UPDATE grants SET created_at = 'yesterday' WHERE id = ?", (grant.id,))
    with pytest.raises(StoreError, match="is corrupt"):
        store.get(grant.id)
    with pytest.raises(StoreError, match="is corrupt"):
        store.active_for(HIGH.value, now=clock.now())


def test_the_table_itself_refuses_inconsistent_rows(store: GrantStore, db: Database) -> None:
    grant = store.create(HIGH, GrantKind.TRUST, granted_by="admin")
    for statement in (
        "UPDATE grants SET kind = 'forever' WHERE id = ?",
        "UPDATE grants SET expires_at = '2030-01-01T00:00:00.000000Z' WHERE id = ?",
        "UPDATE grants SET bound_instance = 'usb/1', bound_at = created_at WHERE id = ?",
        "UPDATE grants SET ended_at = created_at WHERE id = ?",
        "UPDATE grants SET end_reason = 'bored', ended_at = created_at WHERE id = ?",
        "UPDATE grants SET read_only = 2 WHERE id = ?",
    ):
        with pytest.raises(StoreError):
            db.execute(statement, (grant.id,))
    assert store.get(grant.id) == grant


def test_two_stores_on_one_file_see_each_other(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "state.db"
    with Database(path) as service_db, Database(path) as cli_db:
        service = GrantStore(service_db, clock=clock)
        cli = GrantStore(cli_db, clock=clock)
        grant = cli.create(
            HIGH,
            GrantKind.TEMPORARY,
            max_duration=CEILING,
            expires_at=clock.now() + HOUR,
            granted_by="op",
        )
        assert service.active_for(HIGH.value, now=clock.now()) == grant
        clock.advance(HOUR)
        # Whichever process sweeps first reports the expiry; the other finds nothing.
        assert [item.id for item in service.expire_due(clock.now())] == [grant.id]
        assert cli.expire_due(clock.now()) == []
        assert cli.get(grant.id).end_reason is GrantEnd.EXPIRED


def test_timestamps_are_stored_as_utc(store: GrantStore, db: Database, clock: FakeClock) -> None:
    grant = store.create(
        HIGH,
        GrantKind.TEMPORARY,
        max_duration=CEILING,
        expires_at=clock.now() + HOUR,
        granted_by="op",
    )
    row = db.query_one("SELECT created_at, expires_at FROM grants WHERE id = ?", (grant.id,))
    assert row is not None
    assert (row["created_at"], row["expires_at"]) == (
        "2026-01-01T00:00:00.000000Z",
        "2026-01-01T01:00:00.000000Z",
    )
    assert grant.created_at == datetime(2026, 1, 1, tzinfo=UTC)
