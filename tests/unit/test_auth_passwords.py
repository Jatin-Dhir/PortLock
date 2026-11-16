"""Password hashing, verification of untrusted stored hashes, and the password policy."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sys
import types
from pathlib import Path

import pytest

import portlock
from portlock.auth import passwords
from portlock.auth.passwords import (
    DEFAULT_PARAMS,
    HASH_BYTES,
    MAX_PASSWORD_LENGTH,
    SALT_BYTES,
    PasswordPolicyError,
    ScryptParams,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from portlock.core.errors import AuthError, ConfigError

FAST = ScryptParams.insecure_fast_for_tests()
GOOD = "granite-otter-73-lamp"


def encode(n: int, r: int, p: int, salt: bytes, digest: bytes) -> str:
    """Build a stored hash by hand, independently of the code under test."""
    return "$".join(
        (
            "scrypt",
            str(n),
            str(r),
            str(p),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def handmade(password: str, *, n: int = 32, r: int = 8, p: int = 1, salt: bytes = b"s" * 16) -> str:
    """A valid stored hash computed straight from hashlib."""
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return encode(n, r, p, salt, digest)


@pytest.fixture
def derivations(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int, int]]:
    """Replace the key derivation with a recorder, so no work is done and calls are seen."""
    calls: list[tuple[int, int, int]] = []

    def record(secret: bytes, salt: bytes, n: int, r: int, p: int, length: int) -> bytes:
        calls.append((n, r, p))
        return b"\x00" * length

    monkeypatch.setattr(passwords, "_derive", record)
    return calls


# --- hashing -------------------------------------------------------------------------


def test_default_hash_has_the_documented_format_and_parameters() -> None:
    encoded = hash_password(GOOD)
    scheme, n, r, p, salt_text, digest_text = encoded.split("$")
    salt = base64.b64decode(salt_text, validate=True)
    digest = base64.b64decode(digest_text, validate=True)

    assert (scheme, n, r, p) == ("scrypt", "131072", "8", "1")
    assert (len(salt), len(digest)) == (16, 32) == (SALT_BYTES, HASH_BYTES)
    assert (DEFAULT_PARAMS.n, DEFAULT_PARAMS.r, DEFAULT_PARAMS.p) == (2**17, 8, 1)
    # The digest really is scrypt of the password under those parameters.
    expected = hashlib.scrypt(
        GOOD.encode("utf-8"), salt=salt, n=2**17, r=8, p=1, dklen=32, maxmem=2**28
    )
    assert digest == expected
    assert verify_password(GOOD, encoded) is True
    assert needs_rehash(encoded) is False


def test_openssl_is_always_told_exactly_how_much_memory_it_may_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, int]] = []

    def record(secret: bytes, **kwargs: int) -> bytes:
        seen.append({name: kwargs[name] for name in ("n", "r", "p", "maxmem")})
        return b"\x00" * kwargs["dklen"]

    monkeypatch.setattr(passwords.hashlib, "scrypt", record)
    hash_password(GOOD)
    verify_password(GOOD, encode(2**15, 8, 2, b"s" * 16, b"d" * 32))
    assert seen == [
        {"n": 2**17, "r": 8, "p": 1, "maxmem": 128 * 8 * (2**17 + 1 + 2)},
        {"n": 2**15, "r": 8, "p": 2, "maxmem": 128 * 8 * (2**15 + 2 + 2)},
    ]
    # Above OpenSSL's 32 MiB default, below what a 31-bit maxmem argument can carry.
    assert 2**25 < passwords.scrypt_maxmem(2**17, 8, 1) < 2**31 - 1
    assert passwords.scrypt_maxmem(2**18, 8, 2) < 2**31 - 1


def test_verification_agrees_with_the_rfc_7914_test_vector() -> None:
    # RFC 7914 section 12: scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, 64).
    digest = bytes.fromhex(
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
        "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    )
    encoded = encode(16384, 8, 1, b"SodiumChloride", digest)
    assert verify_password("pleaseletmein", encoded) is True
    assert verify_password("pleaseletmeim", encoded) is False


def test_round_trip_and_wrong_password() -> None:
    encoded = hash_password(GOOD, params=FAST)
    assert encoded.startswith("scrypt$16$8$1$")
    assert verify_password(GOOD, encoded) is True
    assert verify_password(GOOD + "x", encoded) is False
    assert verify_password(GOOD.upper(), encoded) is False


def test_every_hash_gets_its_own_salt() -> None:
    first, second = hash_password(GOOD, params=FAST), hash_password(GOOD, params=FAST)
    assert first != second
    assert first.split("$")[4] != second.split("$")[4]
    assert verify_password(GOOD, first) and verify_password(GOOD, second)


def test_passwords_are_nfkc_normalized_before_hashing() -> None:
    composed = "caf\N{LATIN SMALL LETTER E WITH ACUTE}-au-lait-2026"
    decomposed = "cafe\N{COMBINING ACUTE ACCENT}-au-lait-2026"
    ligature = "of\N{LATIN SMALL LIGATURE FI}ce-door-number-9"
    assert composed != decomposed

    encoded = hash_password(composed, params=FAST)
    assert verify_password(decomposed, encoded) is True
    assert verify_password("office-door-number-9", hash_password(ligature, params=FAST)) is True
    # Normalization is not case folding or accent stripping.
    assert verify_password("cafe-au-lait-2026", encoded) is False


def test_the_longest_password_is_accepted_and_one_more_character_is_not() -> None:
    longest = "k" * (MAX_PASSWORD_LENGTH - 1) + "!"
    assert MAX_PASSWORD_LENGTH == 1024
    encoded = hash_password(longest, params=FAST)
    assert verify_password(longest, encoded) is True
    with pytest.raises(AuthError) as caught:
        hash_password(longest + "!", params=FAST)
    assert caught.value.code == "invalid_password"


@pytest.mark.parametrize(
    "password",
    ["", None, 12345, b"bytes-are-not-text", chr(0xD800) * 12],
    ids=["empty", "none", "int", "bytes", "surrogates"],
)
def test_unusable_passwords_cannot_be_hashed(password: object) -> None:
    with pytest.raises(AuthError) as caught:
        hash_password(password, params=FAST)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_password"


def test_hashing_refuses_parameters_that_are_not_scrypt_params() -> None:
    with pytest.raises(ConfigError):
        hash_password(GOOD, params={"n": 16, "r": 8, "p": 1})  # type: ignore[arg-type]


# --- verifying untrusted stored hashes ----------------------------------------------

_VALID = handmade(GOOD)
_SALT_TEXT, _DIGEST_TEXT = _VALID.split("$")[4:]

MALFORMED = [
    "",
    "scrypt",
    "scrypt$32$8$1",
    f"scrypt$32$8$1${_SALT_TEXT}",
    f"scrypt$32$8$1${_SALT_TEXT}${_DIGEST_TEXT}$extra",
    f"argon2id$32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"SCRYPT$32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"$32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$0$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$1$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$33$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$-32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$+32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$ 32$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$032$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$3_2$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32.0$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$0x20$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    # "32" with an Arabic-Indic two, which int() and \d would happily accept.
    f"scrypt$3{chr(0x662)}$8$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32${chr(0x668)}$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32$0$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32$8$0${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32$$1${_SALT_TEXT}${_DIGEST_TEXT}",
    f"scrypt$32$8$1$$${_DIGEST_TEXT}",
    f"scrypt$32$8$1${_SALT_TEXT}$",
    f"scrypt$32$8$1$not base64!${_DIGEST_TEXT}",
    f"scrypt$32$8$1${_SALT_TEXT}${_DIGEST_TEXT[:-1]}",
    # Salt and digest outside the accepted lengths.
    f"scrypt$32$8$1${base64.b64encode(b'short').decode()}${_DIGEST_TEXT}",
    f"scrypt$32$8$1${base64.b64encode(b's' * 65).decode()}${_DIGEST_TEXT}",
    f"scrypt$32$8$1${_SALT_TEXT}${base64.b64encode(b'd' * 15).decode()}",
    f"scrypt$32$8$1${_SALT_TEXT}${base64.b64encode(b'd' * 65).decode()}",
    f"scrypt$32$8$1${_SALT_TEXT.rstrip('=')}${_DIGEST_TEXT}",
    _VALID + "\n",
    " " + _VALID,
    _VALID.replace("$", ":"),
    "scrypt$" * 150_000,
    None,
    42,
    _VALID.encode("ascii"),
]


@pytest.mark.parametrize("encoded", MALFORMED, ids=[f"m{i}" for i in range(len(MALFORMED))])
def test_malformed_hashes_never_verify_and_never_raise(
    encoded: object, derivations: list[tuple[int, int, int]]
) -> None:
    assert verify_password(GOOD, encoded) is False  # type: ignore[arg-type]
    assert derivations == [], "a malformed hash must be rejected before any key derivation"
    assert needs_rehash(encoded, FAST) is True  # type: ignore[arg-type]


def test_the_hand_built_reference_hash_is_valid() -> None:
    # Guards the malformed-hash cases above: they are all one edit away from this.
    assert verify_password(GOOD, _VALID) is True
    assert verify_password("not-" + GOOD, _VALID) is False


def test_a_stored_hash_has_exactly_one_accepted_spelling() -> None:
    """Base64 ignores the unused bits of the last character; the parser must not."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert _SALT_TEXT.endswith("==") and _DIGEST_TEXT.endswith("=")
    twisted = {}
    for name, text, padding in (("salt", _SALT_TEXT, 2), ("digest", _DIGEST_TEXT, 1)):
        last = len(text) - padding - 1
        other = alphabet[alphabet.index(text[last]) ^ 1]
        twisted[name] = text[:last] + other + text[last + 1 :]
        # The precondition: a lenient decoder reads both spellings as the same bytes.
        assert twisted[name] != text
        assert base64.b64decode(twisted[name], validate=True) == base64.b64decode(text)

    assert verify_password(GOOD, f"scrypt$32$8$1${_SALT_TEXT}${_DIGEST_TEXT}") is True
    assert verify_password(GOOD, f"scrypt$32$8$1${twisted['salt']}${_DIGEST_TEXT}") is False
    assert verify_password(GOOD, f"scrypt$32$8$1${_SALT_TEXT}${twisted['digest']}") is False


@pytest.mark.parametrize(
    ("n", "r", "p"),
    [
        (2**40, 8, 1),  # terabytes of memory
        (2**19, 8, 1),  # 512 MiB: past the memory ceiling
        (2**17, 32, 1),  # same, reached through r
        (2**17, 8, 8),  # within memory, eight times the default work
        (2**15, 8, 64),
        (2**16, 1, 1),  # N too large for r (RFC 7914)
        (32, 8, 99_999_999),
        (32, 99_999_999, 1),
    ],
)
def test_a_tampered_hash_cannot_demand_unbounded_work(
    n: int, r: int, p: int, derivations: list[tuple[int, int, int]]
) -> None:
    encoded = encode(n, r, p, b"s" * 16, b"d" * 32)
    assert verify_password(GOOD, encoded) is False
    assert derivations == []


@pytest.mark.parametrize(
    ("n", "r", "p"), [(2**18, 8, 1), (2**17, 16, 1), (2**17, 8, 4), (2**15, 8, 16), (2, 1, 1)]
)
def test_parameters_up_to_the_ceiling_are_evaluated(
    n: int, r: int, p: int, derivations: list[tuple[int, int, int]]
) -> None:
    verify_password(GOOD, encode(n, r, p, b"s" * 16, b"d" * 32))
    assert derivations == [(n, r, p)]


def test_any_change_to_a_stored_hash_stops_it_verifying() -> None:
    scheme, n, r, p, salt_text, digest_text = handmade(GOOD).split("$")
    other_salt = base64.b64encode(b"t" * 16).decode("ascii")
    flipped = base64.b64encode(
        bytes([base64.b64decode(digest_text)[0] ^ 1]) + base64.b64decode(digest_text)[1:]
    ).decode("ascii")

    assert verify_password(GOOD, "$".join((scheme, n, r, p, salt_text, digest_text))) is True
    assert verify_password(GOOD, "$".join((scheme, "64", r, p, salt_text, digest_text))) is False
    assert verify_password(GOOD, "$".join((scheme, n, "4", p, salt_text, digest_text))) is False
    assert verify_password(GOOD, "$".join((scheme, n, r, "2", salt_text, digest_text))) is False
    assert verify_password(GOOD, "$".join((scheme, n, r, p, other_salt, digest_text))) is False
    assert verify_password(GOOD, "$".join((scheme, n, r, p, salt_text, flipped))) is False


@pytest.mark.parametrize(
    "password",
    ["", "x" * (MAX_PASSWORD_LENGTH + 1), None, 7, b"granite", chr(0xDC00) * 12],
    ids=["empty", "too-long", "none", "int", "bytes", "surrogates"],
)
def test_unusable_passwords_do_not_verify_and_cost_nothing(
    password: object, derivations: list[tuple[int, int, int]]
) -> None:
    assert verify_password(password, _VALID) is False  # type: ignore[arg-type]
    assert derivations == []


def test_openssl_refusing_the_parameters_is_a_failed_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> bytes:
        raise ValueError("memory limit exceeded")

    monkeypatch.setattr(passwords.hashlib, "scrypt", refuse)
    assert verify_password(GOOD, _VALID) is False


# --- rehash --------------------------------------------------------------------------


def test_needs_rehash_compares_against_the_wanted_parameters() -> None:
    encoded = hash_password(GOOD, params=FAST)
    assert needs_rehash(encoded, FAST) is False
    assert needs_rehash(encoded, DEFAULT_PARAMS) is True
    assert needs_rehash(encoded) is True, "the default target is the production parameters"
    assert needs_rehash(handmade(GOOD, n=32), FAST) is True
    assert needs_rehash(handmade(GOOD, n=16, p=2), FAST) is True
    assert needs_rehash(handmade(GOOD, n=16), FAST) is False


def test_hashes_made_with_the_old_default_are_upgraded() -> None:
    # N = 2**15 was the design value before section 14.21 raised it.
    old_default = encode(2**15, 8, 1, b"s" * 16, b"d" * 32)
    assert needs_rehash(old_default) is True
    assert needs_rehash(encode(2**17, 8, 1, b"s" * 16, b"d" * 32)) is False
    assert needs_rehash(encode(2**18, 8, 1, b"s" * 16, b"d" * 32)) is True, "converges down too"


def test_needs_rehash_notices_old_salt_and_digest_lengths() -> None:
    short_salt = handmade(GOOD, n=16, salt=b"s" * 8)
    long_digest = encode(16, 8, 1, b"s" * 16, b"d" * 64)
    assert verify_password(GOOD, short_salt) is True
    assert needs_rehash(short_salt, FAST) is True
    assert needs_rehash(long_digest, FAST) is True


# --- parameters and the test-only preset ---------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"n": 2**15},  # the old design value is now below the floor
        {"n": 2**16},
        {"n": 16},
        {"r": 4},
        {"p": 0},
        {"n": 2**17 + 1},
        {"n": 0},
        {"n": -(2**17)},
        {"n": 2**19},
        {"r": 32},
        {"n": 2**17, "r": 8, "p": 8},
        {"n": True},
        {"n": 131072.0},
        {"n": "131072"},
        {"r": None},
    ],
)
def test_parameters_below_the_floor_or_above_the_ceiling_are_refused(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ConfigError):
        ScryptParams(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs", [{}, {"n": 2**18}, {"r": 16}, {"p": 2}, {"p": 4}, {"n": 2**18, "p": 2}]
)
def test_parameters_can_be_raised_within_the_ceiling(kwargs: dict[str, int]) -> None:
    params = ScryptParams(**kwargs)
    assert params.n >= 2**17 and params.r >= 8 and params.p >= 1


def test_the_fast_preset_is_weaker_than_anything_the_constructor_allows() -> None:
    assert (FAST.n, FAST.r, FAST.p) == (16, 8, 1)
    with pytest.raises(ConfigError):
        ScryptParams(n=FAST.n, r=FAST.r, p=FAST.p)
    # Deriving from it goes back through the constructor, so it cannot be "adjusted".
    with pytest.raises(ConfigError):
        dataclasses.replace(FAST, p=2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        FAST.n = 2  # type: ignore[misc]


def test_the_fast_preset_is_refused_outside_a_test_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Give the module a view of sys.modules as a deployed process has it: no pytest.
    assert "pytest" in sys.modules
    deployed = {name: module for name, module in sys.modules.items() if name != "pytest"}
    monkeypatch.setattr(passwords, "sys", types.SimpleNamespace(modules=deployed))
    with pytest.raises(ConfigError, match="test suite"):
        ScryptParams.insecure_fast_for_tests()
    monkeypatch.undo()
    assert ScryptParams.insecure_fast_for_tests() == FAST


def test_no_production_module_selects_the_fast_preset() -> None:
    source_root = Path(portlock.__file__).parent
    modules = sorted(source_root.rglob("*.py"))
    assert source_root / "auth" / "passwords.py" in modules
    offenders = [
        path.relative_to(source_root).as_posix()
        for path in modules
        if "insecure_fast_for_tests" in path.read_text(encoding="utf-8")
    ]
    assert offenders == ["auth/passwords.py"]


# --- policy --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        GOOD,
        "correct horse battery staple",
        "Tr0ub4dor&3-and-more",
        "abcdefghijkm",  # a sequence broken at the end
        "aaaaaaaaaaab",
        "x7!" * 4,
        "\N{GREEK SMALL LETTER ALPHA}" * 6 + "\N{GREEK SMALL LETTER OMEGA}" * 6,
    ],
)
def test_reasonable_passwords_pass(password: str) -> None:
    assert check_password_policy(password) == []


def test_length_is_enforced_and_configurable() -> None:
    assert check_password_policy("Tr0ub4dor&3") == ["must be at least 12 characters long"]
    assert check_password_policy("Tr0ub4dor&3!") == []
    assert check_password_policy("Tr0ub4dor&3!", min_length=16) == [
        "must be at least 16 characters long"
    ]
    assert check_password_policy("zq8#", min_length=4) == []


def test_length_is_counted_after_normalization() -> None:
    # Twelve code points that normalize to six characters.
    decomposed = "".join(letter + "\N{COMBINING ACUTE ACCENT}" for letter in "aeioun")
    assert len(decomposed) == 12
    assert check_password_policy(decomposed) == ["must be at least 12 characters long"]


@pytest.mark.parametrize(
    ("password", "username"),
    [
        ("mallory.keeper", "mallory.keeper"),
        ("MALLORY.KEEPER", "mallory.keeper"),
        ("xx-mallory.keeper-2026", "Mallory.Keeper"),
    ],
)
def test_passwords_containing_the_username_are_refused(password: str, username: str) -> None:
    assert check_password_policy(password, username=username) == [
        "must not be the same as, or contain, the username"
    ]
    assert check_password_policy(password, username="someone-else") == []
    assert check_password_policy(password) == []


def test_the_prototype_default_password_is_refused_by_name() -> None:
    problems = check_password_policy("portlock123")
    assert "is one of the most commonly used passwords" in problems
    # Still refused when the length rule is relaxed far enough to let it through.
    assert check_password_policy("portlock123", min_length=8) == [
        "is one of the most commonly used passwords"
    ]
    assert check_password_policy("PortLock123", min_length=8) == [
        "is one of the most commonly used passwords"
    ]


@pytest.mark.parametrize(
    "password",
    ["password1234", "Password12345", "administrator", "qwertyuiop123", "letmeinletmein"],
)
def test_common_passwords_are_refused(password: str) -> None:
    assert "is one of the most commonly used passwords" in check_password_policy(password)


@pytest.mark.parametrize("password", ["Password2024!", "welcome_2026!!", "Sunshine#1999"])
def test_common_passwords_with_decoration_are_refused(password: str) -> None:
    assert check_password_policy(password) == [
        "is a commonly used password with digits or symbols added"
    ]


@pytest.mark.parametrize("password", ["aaaaaaaaaaaa", "000000000000000", "AaAaAaAaAaAa", " " * 14])
def test_one_repeated_character_is_refused(password: str) -> None:
    assert "must not be one character repeated" in check_password_policy(password)


@pytest.mark.parametrize(
    "password",
    [
        "abcdefghijkl",
        "ABCDEFGHIJKL",
        "lkjihgfedcba",
        "234567890123",
        "987654321098",
        "uiopasdfghjk",
    ],
)
def test_pure_sequences_are_refused(password: str) -> None:
    assert check_password_policy(password) == [
        "must not be a simple sequence such as 123456 or abcdef"
    ]


def test_several_problems_are_all_reported() -> None:
    assert check_password_policy("admin", username="admin") == [
        "must be at least 12 characters long",
        "must not be the same as, or contain, the username",
        "is one of the most commonly used passwords",
    ]


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("x" * (MAX_PASSWORD_LENGTH + 1), ["must be at most 1024 characters long"]),
        (None, ["must be text"]),
        (123456789012, ["must be text"]),
        ("", ["must not be empty or contain invalid characters"]),
        (chr(0xD800) * 12, ["must not be empty or contain invalid characters"]),
    ],
    ids=["too-long", "none", "int", "empty", "surrogates"],
)
def test_unusable_passwords_are_reported_not_raised(password: object, expected: list[str]) -> None:
    assert check_password_policy(password) == expected  # type: ignore[arg-type]


def test_problems_never_quote_the_password() -> None:
    for password in ("portlock123", "Password2024!", "abcdefghijkl", "short", "zzzzzzzzzzzz"):
        problems = check_password_policy(password, username="zzz")
        assert problems
        assert all(password not in problem for problem in problems)


def test_policy_error_carries_the_problems() -> None:
    error = PasswordPolicyError(("must be at least 12 characters long", "too plain"))
    assert isinstance(error, AuthError)
    assert error.code == "weak_password"
    assert error.problems == ("must be at least 12 characters long", "too plain")
    assert "at least 12" in str(error)
