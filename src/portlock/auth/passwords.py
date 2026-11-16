"""Password hashing and password policy.

Passwords are hashed with scrypt (:func:`hashlib.scrypt`) and stored as one string::

    scrypt$<N>$<r>$<p>$<salt, base64>$<hash, base64>

New hashes use ``N = 2**17``, ``r = 8``, ``p = 1`` (``docs/DESIGN.md`` sections 8 and
14.21): about 128 MiB and a few hundred milliseconds each. The memory OpenSSL may use is
always passed explicitly (``maxmem``), sized exactly for the parameters, because its
default of 32 MiB is too small for them and a larger blanket value would let a tampered
hash ask for more.

The cost parameters travel with the hash, so they can be raised later: a login with an
old hash (such as one made with the earlier ``N = 2**15``) still verifies,
:func:`needs_rehash` reports it, and the caller stores a fresh hash while it still holds
the password.

Two things here are deliberately defensive:

* **A stored hash is untrusted input.** Whoever can write the database chooses the
  parameters :func:`verify_password` would run. They are therefore parsed strictly and
  bounded (:data:`MAX_MEMORY_BYTES`, :data:`MAX_WORK`) before any work is done, so a
  tampered record cannot make the service allocate gigabytes or spin for minutes.
  Anything malformed simply does not verify.
* **Weak parameters cannot be configured.** See :class:`ScryptParams` for how the fast
  preset that the test suite needs is kept out of production code paths.

Passwords are normalized to Unicode NFKC before hashing, so the same password typed on
keyboards that compose characters differently produces the same hash.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import sys
import unicodedata
from dataclasses import dataclass
from itertools import pairwise

from portlock.core.errors import AuthError, ConfigError

__all__ = [
    "DEFAULT_PARAMS",
    "HASH_BYTES",
    "MAX_MEMORY_BYTES",
    "MAX_PASSWORD_LENGTH",
    "MAX_WORK",
    "MIN_PASSWORD_LENGTH",
    "SALT_BYTES",
    "PasswordPolicyError",
    "ScryptParams",
    "check_password_policy",
    "hash_password",
    "needs_rehash",
    "normalize_password",
    "scrypt_maxmem",
    "verify_password",
]

#: Longest password accepted, in characters before normalization. Bounds the work an
#: unauthenticated caller can demand; far beyond anything a person or a manager types.
MAX_PASSWORD_LENGTH = 1024
#: Shortest password the policy accepts unless the caller asks for more.
MIN_PASSWORD_LENGTH = 12
#: Salt length for new hashes.
SALT_BYTES = 16
#: Derived-key length for new hashes.
HASH_BYTES = 32

#: Most memory any accepted parameter set may use: scrypt needs about ``128 * N * r``.
#: Twice the default, so ``N`` (or ``r``) can be raised one step.
MAX_MEMORY_BYTES = 256 * 1024 * 1024
#: Largest accepted ``N * r * p``, which is what the running time is proportional to.
#: Four times the default: one to two seconds on ordinary hardware.
MAX_WORK = 2**22

_SCHEME = "scrypt"
# The design values (docs/DESIGN.md sections 8 and 14.21). Configuration may raise them,
# never lower.
_FLOOR_N = 2**17
_FLOOR_R = 8
_FLOOR_P = 1
# Limits on what is read back from storage. Wider than what this version writes, so
# hashes written by a future version with other lengths still verify.
_SALT_RANGE = range(8, 65)
_HASH_RANGE = range(16, 65)
_MAX_ENCODED_LENGTH = 256
# ASCII digits only: str.isdigit() and int() also accept other scripts' digits.
_COST_PATTERN = re.compile(r"[1-9][0-9]{0,7}\Z")


class PasswordPolicyError(AuthError):
    """A new password was refused. ``problems`` says why, one sentence fragment each."""

    code = "weak_password"

    def __init__(self, problems: tuple[str, ...]) -> None:
        super().__init__("the password is not acceptable: " + "; ".join(problems))
        self.problems = problems


def _limit_problem(n: int, r: int, p: int) -> str | None:
    """Why (n, r, p) is outside what PortLock will ever compute, or ``None`` if it is fine."""
    for name, value in (("N", n), ("r", r), ("p", p)):
        if isinstance(value, bool) or not isinstance(value, int):
            return f"{name} must be an integer"
    if n < 2 or n & (n - 1):
        return "N must be a power of two greater than 1"
    if r < 1 or p < 1:
        return "r and p must be at least 1"
    if 128 * n * r > MAX_MEMORY_BYTES:
        return f"N * r needs more than {MAX_MEMORY_BYTES // (1024 * 1024)} MiB of memory"
    if n * r * p > MAX_WORK:
        return f"N * r * p exceeds the work limit of {MAX_WORK}"
    # RFC 7914 section 6: N must be less than 2^(128 * r / 8).
    if n.bit_length() - 1 >= 16 * r:
        return "N is too large for this r"
    return None


def _running_under_test_runner() -> bool:
    """True only inside a pytest process.

    pytest is a development dependency. The service, the CLI and the installer never
    import it, so this cannot become true in a deployed process without someone already
    being able to run arbitrary code in it.
    """
    return "pytest" in sys.modules


@dataclass(frozen=True, slots=True)
class ScryptParams:
    """scrypt cost parameters.

    Constructing an instance validates it against a *floor* (the design values,
    ``N = 2**17``, ``r = 8``, ``p = 1``) and against the same ceiling that protects
    :func:`verify_password`. Configuration can therefore make hashing slower but never
    faster than the design.

    The test suite needs hashing to be instant, and that is the one way to get below the
    floor: :meth:`insecure_fast_for_tests`. Production code cannot pick it by accident,
    for three reasons that hold together:

    1. There is no weak preset *value* to name. Nothing in this module, and no
       configuration key, evaluates to weak parameters; ``ScryptParams(n=16)`` and
       ``dataclasses.replace(fast, ...)`` both go through the constructor and are
       refused. A configuration file can only ever reach the constructor.
    2. The factory refuses to run outside a pytest process (see
       :func:`_running_under_test_runner`), so even a stray call in shipped code fails
       loudly at start-up instead of silently weakening every password.
    3. ``tests/unit/test_auth_passwords.py`` scans ``src/portlock`` and fails if any
       module other than this one mentions the factory.

    A hash made with the fast preset still *verifies* in production (verification must
    accept whatever is stored, within the ceiling), but it is reported by
    :func:`needs_rehash` and replaced at the next successful login.

    Attributes:
        n: CPU and memory cost; a power of two.
        r: block size.
        p: parallelization.

    Raises:
        ConfigError: if the values are malformed, below the floor or above the ceiling.
    """

    n: int = _FLOOR_N
    r: int = _FLOOR_R
    p: int = _FLOOR_P

    def __post_init__(self) -> None:
        problem = _limit_problem(self.n, self.r, self.p)
        if problem is not None:
            raise ConfigError(f"invalid scrypt parameters: {problem}")
        if self.n < _FLOOR_N or self.r < _FLOOR_R or self.p < _FLOOR_P:
            raise ConfigError(
                "invalid scrypt parameters: weaker than the minimum "
                f"(N = {_FLOOR_N}, r = {_FLOOR_R}, p = {_FLOOR_P})"
            )

    @classmethod
    def insecure_fast_for_tests(cls) -> ScryptParams:
        """Parameters that hash in microseconds. For the test suite only.

        Raises:
            ConfigError: when called outside a pytest process.
        """
        if not _running_under_test_runner():
            raise ConfigError(
                "the fast scrypt preset exists for the test suite and is refused elsewhere"
            )
        # Built without the constructor on purpose: the constructor is the gate that
        # keeps every other caller above the floor.
        params = object.__new__(cls)
        object.__setattr__(params, "n", 2**4)
        object.__setattr__(params, "r", 8)
        object.__setattr__(params, "p", 1)
        return params


#: The parameters new hashes are made with unless configuration raises them.
DEFAULT_PARAMS = ScryptParams()


def normalize_password(password: object) -> bytes | None:
    """The bytes that are actually hashed for ``password``, or ``None`` if it is unusable.

    Unusable means: not a string, empty, longer than :data:`MAX_PASSWORD_LENGTH`
    characters, or not encodable as UTF-8 (lone surrogates). The length is checked
    before normalizing so that normalization itself works on bounded input.
    """
    if not isinstance(password, str) or not 0 < len(password) <= MAX_PASSWORD_LENGTH:
        return None
    try:
        return unicodedata.normalize("NFKC", password).encode("utf-8")
    except UnicodeEncodeError:
        return None


def scrypt_maxmem(n: int, r: int, p: int) -> int:
    """The ``maxmem`` passed to OpenSSL for these parameters: exactly what scrypt needs.

    OpenSSL allocates ``128 * r * p`` bytes for B and ``128 * r * (N + 2)`` for V and
    refuses to run if their sum exceeds ``maxmem``; its default (32 MiB) is too small for
    ``N = 2**17``. The ceilings on ``N * r`` and ``N * r * p`` keep this bounded.
    """
    return 128 * r * (n + p + 2)


def _derive(secret: bytes, salt: bytes, n: int, r: int, p: int, length: int) -> bytes:
    return hashlib.scrypt(
        secret, salt=salt, n=n, r=r, p=p, dklen=length, maxmem=scrypt_maxmem(n, r, p)
    )


def hash_password(password: str, *, params: ScryptParams = DEFAULT_PARAMS) -> str:
    """Hash a password with a fresh random salt.

    This does not judge the password's strength; see :func:`check_password_policy`.

    Args:
        password: the password as typed.
        params: cost parameters. Leave at the default outside tests and configuration.

    Returns:
        ``scrypt$N$r$p$<salt base64>$<hash base64>``.

    Raises:
        AuthError: (code ``invalid_password``) if the password is not a non-empty string
            of at most :data:`MAX_PASSWORD_LENGTH` characters.
        ConfigError: if ``params`` is not a :class:`ScryptParams`.
    """
    if not isinstance(params, ScryptParams):
        raise ConfigError("params must be a ScryptParams instance")
    secret = normalize_password(password)
    if secret is None:
        raise AuthError(
            f"a password must be text of 1 to {MAX_PASSWORD_LENGTH} characters",
            code="invalid_password",
        )
    salt = secrets.token_bytes(SALT_BYTES)
    derived = _derive(secret, salt, params.n, params.r, params.p, HASH_BYTES)
    return "$".join(
        (
            _SCHEME,
            str(params.n),
            str(params.r),
            str(params.p),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(derived).decode("ascii"),
        )
    )


@dataclass(frozen=True, slots=True)
class _ParsedHash:
    n: int
    r: int
    p: int
    salt: bytes
    digest: bytes


def _decode_field(text: str, allowed: range) -> bytes | None:
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        return None
    # Only the canonical spelling is accepted, so one hash has exactly one stored form.
    if len(raw) not in allowed or base64.b64encode(raw).decode("ascii") != text:
        return None
    return raw


def _parse(encoded: object) -> _ParsedHash | None:
    """Parse a stored hash, or return ``None`` for anything not exactly well-formed."""
    if not isinstance(encoded, str) or len(encoded) > _MAX_ENCODED_LENGTH:
        return None
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != _SCHEME:
        return None
    if not all(_COST_PATTERN.match(part) for part in parts[1:4]):
        return None
    n, r, p = (int(part) for part in parts[1:4])
    if _limit_problem(n, r, p) is not None:
        return None
    salt = _decode_field(parts[4], _SALT_RANGE)
    digest = _decode_field(parts[5], _HASH_RANGE)
    if salt is None or digest is None:
        return None
    return _ParsedHash(n, r, p, salt, digest)


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored hash in constant time.

    Never raises for bad input: a malformed, truncated, unknown-format or out-of-bounds
    hash, and an unusable password, all return ``False``. No key derivation is run for
    them, so a tampered record costs nothing.

    Args:
        password: the candidate password.
        encoded: a string produced by :func:`hash_password`.
    """
    parsed = _parse(encoded)
    secret = normalize_password(password)
    if parsed is None or secret is None:
        return False
    try:
        derived = _derive(secret, parsed.salt, parsed.n, parsed.r, parsed.p, len(parsed.digest))
    except (ValueError, OverflowError):
        # OpenSSL rejected a combination the bounds above let through. Fail closed.
        return False
    return hmac.compare_digest(derived, parsed.digest)


def needs_rehash(encoded: str, params: ScryptParams = DEFAULT_PARAMS) -> bool:
    """Whether a stored hash should be replaced at the next successful login.

    True when the hash was not made with exactly ``params`` and the current salt and key
    lengths, and for anything that does not parse. Stronger-than-configured hashes are
    reported too, so the stored form always converges on the configured one.
    """
    parsed = _parse(encoded)
    if parsed is None:
        return True
    return (
        (parsed.n, parsed.r, parsed.p) != (params.n, params.r, params.p)
        or len(parsed.salt) != SALT_BYTES
        or len(parsed.digest) != HASH_BYTES
    )


# Passwords that head every breach list, plus the obvious ones for this product. The
# minimum length already rejects most of the short ones; they are listed anyway because
# the minimum is a parameter and because the suffix check below builds on them.
_WORDLIST = """
000000 111111 11111111 112233 121212 123123 123321 1234 12345 123456 1234567 12345678
123456789 1234567890 123456789012 1234567890123 12345678901234 123qwe 123qweasd
131313 159753 1q2w3e 1q2w3e4r 1q2w3e4r5t 1q2w3e4r5t6y 1qaz2wsx 1qaz2wsx3edc 555555
654321 666666 696969 7777777 777777 87654321 987654321 9876543210 a1b2c3d4 a1b2c3d4e5f6
aaaaaa abc123 abc123abc123 abcd1234 access admin admin123 admin1234 adminadmin
adminadminadmin administrator amanda andrew asdfgh asdfghjkl ashley austin baseball
batman biteme buster changeme changemechangeme changeme123 charlie cheese chelsea
computer correcthorsebatterystaple daniel default dragon flower football freedom
george ginger harley hello hello123 hockey hunter hunter2 iloveyou iloveyou1234 jennifer
jessica jordan joshua killer letmein letmein123 letmeinletmein login love maggie master
matrix matthew michael michelle monkey mustang nicole ninja pass passw0rd passw0rd123
password password1 password12 password123 password1234 password12345 password123456
passwordpassword pepper portlock portlock1 portlock12 portlock123 portlock1234
portlock12345 portlockadmin portlockportlock princess p@ssw0rd p@ssw0rd123 p@ssword
q1w2e3r4 q1w2e3r4t5 q1w2e3r4t5y6 qazwsx qazwsxedc qwerty qwerty123 qwerty1234
qwerty123456 qwertyuiop qwertyuiop123 ranger robert root rootroot secret secret123
shadow soccer starwars summer sunshine superman taylor temp temp1234 test test1234
testtest thomas thunder tigger toor trustno1 trustno1trustno1 welcome welcome1
welcome123 welcome1234 welcome12345 whatever yankees zaq12wsx zaq12wsxcde3 zxcvbn
zxcvbnm
"""
_COMMON_PASSWORDS = frozenset(_WORDLIST.split())

# Runs along which "the next character" is a predictable step. The first two wrap round
# (9 is followed by 0, z by a); the third is the letter rows of a QWERTY keyboard.
_SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm")
_TRAILING_DECORATION = "0123456789!@#$%^&*()-_=+.,;:?~ "


def _is_sequential(text: str) -> bool:
    """True if every character is the one before it stepped the same way along a run."""
    if len(text) < 2:
        return False
    for run in _SEQUENCES:
        if any(char not in run for char in text):
            continue
        positions = [run.index(char) for char in text]
        for step in (1, -1):
            if all((before + step) % len(run) == after for before, after in pairwise(positions)):
                return True
    return False


def check_password_policy(
    password: str, *, min_length: int = MIN_PASSWORD_LENGTH, username: str | None = None
) -> list[str]:
    """Explain what is wrong with a proposed password.

    The checks are the ones that stop the passwords attackers try first; they are not a
    strength meter. Length is measured on the normalized password, the form that is
    hashed. Comparisons ignore case.

    Args:
        password: the proposed password.
        min_length: minimum number of characters.
        username: the account the password is for, if known.

    Returns:
        Human-readable problems, empty if the password is acceptable. The text never
        contains the password.
    """
    if not isinstance(password, str):
        return ["must be text"]
    if len(password) > MAX_PASSWORD_LENGTH:
        return [f"must be at most {MAX_PASSWORD_LENGTH} characters long"]
    if normalize_password(password) is None:
        return ["must not be empty or contain invalid characters"]

    normalized = unicodedata.normalize("NFKC", password)
    folded = normalized.casefold()
    problems: list[str] = []
    if len(normalized) < min_length:
        problems.append(f"must be at least {min_length} characters long")
    if isinstance(username, str) and username and username.casefold() in folded:
        problems.append("must not be the same as, or contain, the username")
    if folded in _COMMON_PASSWORDS:
        problems.append("is one of the most commonly used passwords")
    else:
        # "Password2024!" is the same guess as "password" to anyone running a wordlist.
        stem = folded.rstrip(_TRAILING_DECORATION)
        if stem != folded and stem in _COMMON_PASSWORDS:
            problems.append("is a commonly used password with digits or symbols added")
    if len(set(folded)) == 1:
        problems.append("must not be one character repeated")
    elif _is_sequential(folded):
        problems.append("must not be a simple sequence such as 123456 or abcdef")
    return problems
