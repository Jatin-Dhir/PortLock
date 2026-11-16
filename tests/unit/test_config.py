"""Configuration: defaults, strict loading, the HID safeguards and the generated file."""

from __future__ import annotations

import dataclasses
import json
import platform as platform_module
import socket
import sys
import tomllib
from pathlib import Path

import pytest

from portlock.core.config import (
    CONFIG_FILE_NAME,
    MAX_CONFIG_BYTES,
    SCAN_ENGINES,
    SCOPES,
    ApiConfig,
    AuditConfig,
    AuditSinkConfig,
    AuthConfig,
    Config,
    FlapGuardConfig,
    GrantsConfig,
    InvalidConfigError,
    LockdownConfig,
    PathsConfig,
    ScanConfig,
    config_to_toml,
    default_config,
    load_config,
)
from portlock.core.errors import ConfigError, PortLockError
from portlock.core.models import Mode, Severity

LINUX = "linux"
WINDOWS = "win32"


def _write(tmp_path: Path, text: str, name: str = "portlock.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _problems(tmp_path: Path, text: str, platform: str = LINUX) -> tuple[str, ...]:
    """Load a file that must be invalid and return its problems."""
    with pytest.raises(InvalidConfigError) as caught:
        load_config(_write(tmp_path, text), env={}, platform=platform)
    return caught.value.problems


def _paths_of(problems: tuple[str, ...]) -> list[str]:
    return [problem.split(": ", 1)[0] for problem in problems]


# --- defaults --------------------------------------------------------------------------


def test_defaults_are_the_documented_ones() -> None:
    config = default_config(LINUX, {})
    assert config.mode is Mode.MONITOR
    assert config.scope == "storage"
    assert config.hid_enforcement is False
    assert config.acknowledge_lockout_risk is False
    assert config.hid_enforcement_enabled is False
    assert config.fail_closed is False
    assert config.commit_confirm_seconds == 60
    assert config.baseline_read_only is False
    assert config.polling_interval_seconds == 2.0
    assert config.host_label == "unnamed-host"
    assert config.api == ApiConfig(
        host="127.0.0.1", port=47600, session_idle_minutes=15, session_max_hours=8
    )
    assert config.scan == ScanConfig(
        enabled=True,
        max_files=20000,
        max_bytes=2 * 1024**3,
        max_seconds=120,
        follow_symlinks=False,
        engines=("heuristics", "hashset", "clamav", "defender"),
    )
    assert config.lockdown == LockdownConfig(
        default_minutes=60, max_minutes=1440, allow_new_input_devices=True
    )
    assert config.auth == AuthConfig(
        min_password_length=12,
        lockout_threshold=5,
        lockout_base_seconds=30,
        lockout_max_seconds=900,
        scrypt_n=131072,
        max_concurrent_verifications=2,
    )
    assert config.grants == GrantsConfig(
        max_temporary_hours_operator=24,
        max_temporary_hours_admin=720,
        low_confidence_max_hours=24,
    )
    assert config.flap_guard == FlapGuardConfig(
        max_arrivals=5, window_seconds=30, cooldown_seconds=120
    )
    assert config.audit == AuditConfig(hmac_key_file=None, sinks=())
    assert SCOPES == ("storage", "storage_and_unknown", "all_except_protected")


def test_default_paths_on_linux() -> None:
    paths = default_config(LINUX, {}).paths
    assert paths.state_dir == Path("/var/lib/portlock")
    assert paths.config_dir == Path("/etc/portlock")


@pytest.mark.parametrize("variable", ["ProgramData", "PROGRAMDATA", "programdata"])
def test_default_paths_on_windows_follow_program_data(variable: str) -> None:
    paths = default_config(WINDOWS, {variable: "D:\\Data"}).paths
    assert paths.state_dir == Path("D:\\Data\\PortLock")
    assert paths.config_dir == Path("D:\\Data\\PortLock")


def test_default_paths_on_windows_without_program_data() -> None:
    for env in ({}, {"ProgramData": ""}, {"ProgramData": "   "}):
        paths = default_config(WINDOWS, env).paths
        assert paths.state_dir == Path("C:\\ProgramData\\PortLock")
        assert paths.config_dir == Path("C:\\ProgramData\\PortLock")


def test_a_relative_program_data_is_refused() -> None:
    with pytest.raises(ConfigError, match="ProgramData"):
        default_config(WINDOWS, {"ProgramData": "Data"})


def test_portlock_home_overrides_both_directories() -> None:
    linux = default_config(LINUX, {"PORTLOCK_HOME": "/srv/portlock"}).paths
    assert linux.state_dir == Path("/srv/portlock/state")
    assert linux.config_dir == Path("/srv/portlock/config")
    windows = default_config(WINDOWS, {"PORTLOCK_HOME": "E:\\pl", "ProgramData": "D:\\Data"}).paths
    assert windows.state_dir == Path("E:\\pl\\state")
    assert windows.config_dir == Path("E:\\pl\\config")


def test_an_empty_portlock_home_is_ignored() -> None:
    assert default_config(LINUX, {"PORTLOCK_HOME": ""}).paths.state_dir == Path("/var/lib/portlock")
    assert default_config(LINUX, {"PORTLOCK_HOME": "  "}).paths.config_dir == Path("/etc/portlock")


@pytest.mark.parametrize(
    ("platform", "home"),
    [(LINUX, "relative/home"), (LINUX, "C:\\pl"), (WINDOWS, "pl"), (WINDOWS, "/srv/portlock")],
)
def test_a_relative_portlock_home_is_refused(platform: str, home: str) -> None:
    with pytest.raises(ConfigError, match="PORTLOCK_HOME must be an absolute path"):
        default_config(platform, {"PORTLOCK_HOME": home})
    with pytest.raises(ConfigError, match="PORTLOCK_HOME"):
        load_config(env={"PORTLOCK_HOME": home}, platform=platform)


def test_the_process_environment_and_platform_are_the_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PORTLOCK_HOME", str(tmp_path))
    paths = default_config().paths
    assert paths == PathsConfig.under(tmp_path)
    assert paths.state_dir == tmp_path / "state"
    assert paths.config_dir == tmp_path / "config"
    assert load_config().paths == paths


def test_derived_file_locations() -> None:
    paths = PathsConfig(state_dir=Path("/var/lib/portlock"), config_dir=Path("/etc/portlock"))
    assert paths.config_file == Path("/etc/portlock/portlock.toml")
    assert paths.database_file == Path("/var/lib/portlock/portlock.db")
    assert paths.kill_switch_file == Path("/etc/portlock/DISABLE_ENFORCEMENT")
    assert CONFIG_FILE_NAME == "portlock.toml"


def test_host_label_never_comes_from_the_machine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("configuration must not ask the machine for its name")

    monkeypatch.setattr(socket, "gethostname", forbidden)
    monkeypatch.setattr(socket, "getfqdn", forbidden)
    monkeypatch.setattr(platform_module, "node", forbidden)
    for variable in ("COMPUTERNAME", "HOSTNAME"):
        monkeypatch.setenv(variable, "sentinel-machine-name")
    monkeypatch.setenv("PORTLOCK_HOME", str(tmp_path))

    config = load_config()
    assert config.host_label == "unnamed-host"
    assert "sentinel-machine-name" not in config_to_toml(config)
    assert "sentinel-machine-name" not in json.dumps(config.to_dict())


# --- loading ---------------------------------------------------------------------------


def test_a_missing_default_file_gives_the_defaults_and_creates_nothing(tmp_path: Path) -> None:
    home = tmp_path / "home"
    env = {"PORTLOCK_HOME": str(home)}
    config = load_config(env=env)
    assert config == default_config(sys.platform, env)
    assert config.paths.state_dir == home / "state"
    assert not home.exists()
    assert list(tmp_path.iterdir()) == []


def test_the_default_file_is_found_in_the_configuration_directory(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "portlock.toml").write_text('host_label = "lab-7"\n', encoding="utf-8")
    config = load_config(env={"PORTLOCK_HOME": str(tmp_path)})
    assert config.host_label == "lab-7"
    assert config.paths.config_dir == config_dir
    assert not (tmp_path / "state").exists()


def test_an_explicitly_named_file_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found") as caught:
        load_config(tmp_path / "absent.toml", env={}, platform=LINUX)
    assert not isinstance(caught.value, InvalidConfigError)
    assert list(tmp_path.iterdir()) == []


def test_a_directory_is_not_a_configuration_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path, env={}, platform=LINUX)


def test_settings_left_out_keep_their_defaults(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        mode = "enforce"
        fail_closed = true
        polling_interval_seconds = 5

        [api]
        port = 0

        [lockdown]
        default_minutes = 30
        """,
    )
    config = load_config(path, env={}, platform=LINUX)
    defaults = default_config(LINUX, {})
    assert config.mode is Mode.ENFORCE
    assert config.fail_closed is True
    assert config.polling_interval_seconds == 5.0
    assert isinstance(config.polling_interval_seconds, float)
    assert config.api == dataclasses.replace(defaults.api, port=0)
    assert config.lockdown == dataclasses.replace(defaults.lockdown, default_minutes=30)
    assert config.scan == defaults.scan
    assert config.auth == defaults.auth
    assert config.paths == defaults.paths


def test_an_empty_file_is_the_defaults(tmp_path: Path) -> None:
    assert load_config(_write(tmp_path, ""), env={}, platform=LINUX) == default_config(LINUX, {})


def test_paths_in_the_file_win_over_portlock_home(tmp_path: Path) -> None:
    path = _write(tmp_path, '[paths]\nstate_dir = "/data/portlock"\n')
    config = load_config(path, env={"PORTLOCK_HOME": "/srv/portlock"}, platform=LINUX)
    assert config.paths.state_dir == Path("/data/portlock")
    assert config.paths.config_dir == Path("/srv/portlock/config")


def test_a_full_file_is_read(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        mode = "enforce"
        scope = "all_except_protected"
        hid_enforcement = true
        acknowledge_lockout_risk = true
        fail_closed = true
        commit_confirm_seconds = 120
        baseline_read_only = true
        polling_interval_seconds = 0.5
        host_label = "front-desk.2"

        [paths]
        state_dir = "/data/state"
        config_dir = "/data/config"

        [api]
        host = "::1"
        port = 8443
        session_idle_minutes = 5
        session_max_hours = 2

        [scan]
        enabled = false
        max_files = 10
        max_bytes = 4096
        max_seconds = 3
        follow_symlinks = true
        engines = ["hashset", "heuristics"]

        [lockdown]
        default_minutes = 10
        max_minutes = 20
        allow_new_input_devices = false

        [auth]
        min_password_length = 16
        lockout_threshold = 3
        lockout_base_seconds = 60
        lockout_max_seconds = 3600
        scrypt_n = 262144
        max_concurrent_verifications = 1

        [grants]
        max_temporary_hours_operator = 8
        max_temporary_hours_admin = 168
        low_confidence_max_hours = 4

        [flap_guard]
        max_arrivals = 3
        window_seconds = 10
        cooldown_seconds = 600

        [audit]
        hmac_key_file = "/data/keys/audit.key"

        [[audit.sinks]]
        type = "file"
        target = "/var/log/portlock/events.jsonl"
        min_severity = "warning"

        [[audit.sinks]]
        type = "syslog"
        target = "/dev/log"

        [[audit.sinks]]
        type = "clawnet"
        target = "security-events"
        """,
    )
    config = load_config(path, env={}, platform=LINUX)
    assert config == Config(
        paths=PathsConfig(state_dir=Path("/data/state"), config_dir=Path("/data/config")),
        mode=Mode.ENFORCE,
        scope="all_except_protected",
        hid_enforcement=True,
        acknowledge_lockout_risk=True,
        fail_closed=True,
        commit_confirm_seconds=120,
        baseline_read_only=True,
        api=ApiConfig(host="::1", port=8443, session_idle_minutes=5, session_max_hours=2),
        scan=ScanConfig(
            enabled=False,
            max_files=10,
            max_bytes=4096,
            max_seconds=3,
            follow_symlinks=True,
            engines=("hashset", "heuristics"),
        ),
        lockdown=LockdownConfig(default_minutes=10, max_minutes=20, allow_new_input_devices=False),
        auth=AuthConfig(
            min_password_length=16,
            lockout_threshold=3,
            lockout_base_seconds=60,
            lockout_max_seconds=3600,
            scrypt_n=262144,
            max_concurrent_verifications=1,
        ),
        grants=GrantsConfig(
            max_temporary_hours_operator=8,
            max_temporary_hours_admin=168,
            low_confidence_max_hours=4,
        ),
        flap_guard=FlapGuardConfig(max_arrivals=3, window_seconds=10, cooldown_seconds=600),
        audit=AuditConfig(
            hmac_key_file=Path("/data/keys/audit.key"),
            sinks=(
                AuditSinkConfig(
                    type="file",
                    target="/var/log/portlock/events.jsonl",
                    min_severity=Severity.WARNING,
                ),
                AuditSinkConfig(type="syslog", target="/dev/log", min_severity=Severity.INFO),
                AuditSinkConfig(type="clawnet", target="security-events"),
            ),
        ),
        polling_interval_seconds=0.5,
        host_label="front-desk.2",
    )
    assert config.hid_enforcement_enabled is True


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    path = tmp_path / "bom.toml"
    path.write_bytes(b"\xef\xbb\xbf" + b'host_label = "with-bom"\n')
    assert load_config(path, env={}, platform=LINUX).host_label == "with-bom"


@pytest.mark.parametrize(
    "content",
    [
        b"mode = \n",
        b'mode = "monitor"\nmode = "enforce"\n',
        b"[api\nport = 1\n",
        b"just some words\n",
        b"\x00\x01\x02",
    ],
)
def test_malformed_toml_is_a_config_error_naming_the_file(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "broken.toml"
    path.write_bytes(content)
    with pytest.raises(ConfigError, match="not valid TOML") as caught:
        load_config(path, env={}, platform=LINUX)
    assert "broken.toml" in str(caught.value)
    assert isinstance(caught.value, PortLockError)
    assert caught.value.code == "config_error"


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "latin1.toml"
    path.write_bytes(b'host_label = "caf\xe9"\n')
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_config(path, env={}, platform=LINUX)


def test_an_oversized_file_is_refused_unparsed(tmp_path: Path) -> None:
    path = tmp_path / "huge.toml"
    path.write_bytes(b"# padding\n" * (MAX_CONFIG_BYTES // 10 + 1))
    assert path.stat().st_size > MAX_CONFIG_BYTES
    with pytest.raises(ConfigError, match="larger than"):
        load_config(path, env={}, platform=LINUX)
    exact = tmp_path / "exact.toml"
    exact.write_bytes(b"#" * MAX_CONFIG_BYTES)
    assert load_config(exact, env={}, platform=LINUX) == default_config(LINUX, {})


# --- strict validation -----------------------------------------------------------------


def test_every_problem_is_reported_at_once_with_its_exact_path(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        """
        mode = "enforcing"
        scop = "storage"
        fail_closed = "yes"
        polling_interval_seconds = 0.0
        host_label = "bad label!"

        [paths]
        state_dir = "relative/state"

        [api]
        host = "0.0.0.0"
        port = 70000
        sesion_idle_minutes = 5

        [scan]
        max_files = 0
        engines = ["heuristics", "clamv", 3, "heuristics"]

        [lockdown]
        default_minutes = 90
        max_minutes = 60

        [auth]
        min_password_length = "12"

        [audit]
        hmac_key_file = "relative/key"

        [[audit.sinks]]
        type = "file"

        [[audit.sinks]]
        typo = 1

        [[audit.sinks]]
        type = "syslog"
        target = "logs.example:514"
        min_severity = "loud"

        [telemetry]
        enabled = true
        """,
    )
    assert sorted(_paths_of(problems)) == sorted(
        [
            "mode",
            "scop",
            "fail_closed",
            "polling_interval_seconds",
            "host_label",
            "paths.state_dir",
            "api.host",
            "api.port",
            "api.sesion_idle_minutes",
            "scan.max_files",
            "scan.engines[1]",
            "scan.engines[2]",
            "scan.engines[3]",
            "lockdown.default_minutes",
            "auth.min_password_length",
            "audit.hmac_key_file",
            "audit.sinks[0].target",
            "audit.sinks[1].type",
            "audit.sinks[1].typo",
            "audit.sinks[2].target",
            "audit.sinks[2].min_severity",
            "telemetry",
        ]
    )


def test_the_error_message_lists_every_problem_and_the_file(tmp_path: Path) -> None:
    path = _write(tmp_path, 'mode = "x"\n[api]\nport = -1\n')
    with pytest.raises(InvalidConfigError) as caught:
        load_config(path, env={}, platform=LINUX)
    error = caught.value
    assert isinstance(error, ConfigError)
    assert error.code == "config_error"
    assert error.source == str(path)
    assert len(error.problems) == 2
    message = str(error)
    assert str(path) in message
    assert "2 problems" in message
    for problem in error.problems:
        assert problem in message


@pytest.mark.parametrize(
    ("text", "path", "fragment"),
    [
        # unknown keys, at every level
        ("colour = 1", "colour", "unknown key"),
        ("mod = 'monitor'", "mod", "did you mean 'mode'"),
        ("[api]\nprot = 1", "api.prot", "did you mean 'port'"),
        ("[api.tls]\ncert = 'x'", "api.tls", "unknown key"),
        ("[scan]\nengine = []", "scan.engine", "did you mean 'engines'"),
        (
            "[[audit.sinks]]\ntype='syslog'\ntarget='local'\nlevel='x'",
            "audit.sinks[0].level",
            "unknown key",
        ),
        ("[nonsense]", "nonsense", "unknown key"),
        ("[grants]\nmax_hours = 1", "grants.max_hours", "unknown key"),
        ("[flap_guard]\nwindow = 1", "flap_guard.window", "did you mean 'window_seconds'"),
        # the API uses bearer tokens: cookie and CSRF settings do not exist
        ("[api]\ncookie_secure = true", "api.cookie_secure", "unknown key"),
        ("[api]\ncookie_name = 'portlock_session'", "api.cookie_name", "unknown key"),
        ("[api]\ncsrf_header = 'X-PortLock-CSRF'", "api.csrf_header", "unknown key"),
        ("csrf = true", "csrf", "unknown key"),
        # wrong types
        ("mode = 1", "mode", "must be one of"),
        ("mode = true", "mode", "the boolean true"),
        ("scope = ['storage']", "scope", "an array"),
        ("hid_enforcement = 'false'", "hid_enforcement", "expected true or false"),
        ("acknowledge_lockout_risk = 1", "acknowledge_lockout_risk", "expected true or false"),
        ("fail_closed = 0", "fail_closed", "expected true or false"),
        ("baseline_read_only = 'no'", "baseline_read_only", "expected true or false"),
        ("commit_confirm_seconds = 60.0", "commit_confirm_seconds", "expected an integer"),
        ("grants = 24", "grants", "expected a table"),
        ("flap_guard = []", "flap_guard", "expected a table"),
        ("[auth]\nscrypt_n = '131072'", "auth.scrypt_n", "expected an integer"),
        (
            "[grants]\nlow_confidence_max_hours = 1.5",
            "grants.low_confidence_max_hours",
            "an integer",
        ),
        ("[flap_guard]\nmax_arrivals = true", "flap_guard.max_arrivals", "expected an integer"),
        ("polling_interval_seconds = '2'", "polling_interval_seconds", "expected a number"),
        ("polling_interval_seconds = true", "polling_interval_seconds", "expected a number"),
        ("host_label = 7", "host_label", "expected a string"),
        ("api = 5", "api", "expected a table"),
        ("paths = 'here'", "paths", "expected a table"),
        ("[api]\nport = '47600'", "api.port", "expected an integer"),
        ("[api]\nport = 47600.0", "api.port", "expected an integer"),
        ("[api]\nport = true", "api.port", "expected an integer"),
        ("[api]\nhost = 127", "api.host", "expected a string"),
        ("[scan]\nenabled = 'true'", "scan.enabled", "expected true or false"),
        ("[scan]\nengines = 'heuristics'", "scan.engines", "expected an array"),
        ("[scan]\nmax_bytes = 1.5", "scan.max_bytes", "expected an integer"),
        ("[audit]\nsinks = 'syslog'", "audit.sinks", "expected an array"),
        ("[audit]\nsinks = ['syslog']", "audit.sinks[0]", "expected a table"),
        ("[audit]\nhmac_key_file = 3", "audit.hmac_key_file", "expected a string"),
        ("[lockdown]\nallow_new_input_devices = 'no'", "lockdown.allow_new_input_devices", "true"),
        ("[paths]\nstate_dir = 1979-05-27", "paths.state_dir", "expected a string"),
        # out of range
        ("mode = 'ENFORCE'", "mode", "must be one of"),
        ("scope = 'everything'", "scope", "must be one of"),
        ("polling_interval_seconds = 0.05", "polling_interval_seconds", "between 0.1 and 3600"),
        ("polling_interval_seconds = 3601", "polling_interval_seconds", "between 0.1 and 3600"),
        ("polling_interval_seconds = nan", "polling_interval_seconds", "between"),
        ("polling_interval_seconds = inf", "polling_interval_seconds", "between"),
        ("polling_interval_seconds = -inf", "polling_interval_seconds", "between"),
        ("host_label = ''", "host_label", "must not be empty"),
        ("host_label = 'two words'", "host_label", "letters, digits"),
        ("host_label = '-leading'", "host_label", "start with a letter or digit"),
        ('host_label = "x\\ny"', "host_label", "control characters"),
        (f"host_label = '{'a' * 64}'", "host_label", "1 to 63 characters"),
        ("[api]\nport = -1", "api.port", "between 0 and 65535"),
        ("[api]\nport = 65536", "api.port", "between 0 and 65535"),
        ("[api]\nsession_idle_minutes = 0", "api.session_idle_minutes", "between 1 and 1440"),
        ("[api]\nsession_max_hours = 169", "api.session_max_hours", "between 1 and 168"),
        (
            "[api]\nsession_idle_minutes = 121\nsession_max_hours = 2",
            "api.session_idle_minutes",
            "must not exceed api.session_max_hours (120 minutes)",
        ),
        ("[scan]\nmax_files = 0", "scan.max_files", "between 1 and"),
        ("[scan]\nmax_bytes = 0", "scan.max_bytes", "between 1 and"),
        ("[scan]\nmax_seconds = 86401", "scan.max_seconds", "between 1 and 86400"),
        ("[scan]\nengines = ['yara']", "scan.engines[0]", "must be one of"),
        ("[scan]\nengines = ['hashset', 'hashset']", "scan.engines[1]", "duplicate"),
        ("[lockdown]\ndefault_minutes = 0", "lockdown.default_minutes", "between 1 and"),
        ("[lockdown]\nmax_minutes = 10081", "lockdown.max_minutes", "between 1 and 10080"),
        (
            "[lockdown]\ndefault_minutes = 61\nmax_minutes = 60",
            "lockdown.default_minutes",
            "must not exceed lockdown.max_minutes (60 minutes)",
        ),
        ("[auth]\nmin_password_length = 11", "auth.min_password_length", "between 12 and 128"),
        ("[auth]\nlockout_threshold = 0", "auth.lockout_threshold", "between 1 and 100"),
        (
            "[auth]\nlockout_base_seconds = 901",
            "auth.lockout_base_seconds",
            "must not exceed auth.lockout_max_seconds (900 seconds)",
        ),
        ("commit_confirm_seconds = 9", "commit_confirm_seconds", "between 10 and 600"),
        ("commit_confirm_seconds = 601", "commit_confirm_seconds", "between 10 and 600"),
        ("[auth]\nscrypt_n = 65536", "auth.scrypt_n", "between 131072 and 524288"),
        ("[auth]\nscrypt_n = 1048576", "auth.scrypt_n", "between 131072 and 524288"),
        ("[auth]\nscrypt_n = 200000", "auth.scrypt_n", "must be a power of two"),
        (
            "[auth]\nmax_concurrent_verifications = 0",
            "auth.max_concurrent_verifications",
            "1 and 8",
        ),
        (
            "[auth]\nmax_concurrent_verifications = 9",
            "auth.max_concurrent_verifications",
            "1 and 8",
        ),
        (
            "[grants]\nmax_temporary_hours_operator = 25",
            "grants.max_temporary_hours_operator",
            "between 1 and 24",
        ),
        (
            "[grants]\nmax_temporary_hours_admin = 0",
            "grants.max_temporary_hours_admin",
            "between 1 and 8760",
        ),
        (
            "[grants]\nmax_temporary_hours_admin = 8761",
            "grants.max_temporary_hours_admin",
            "between 1 and 8760",
        ),
        (
            "[grants]\nlow_confidence_max_hours = 25",
            "grants.low_confidence_max_hours",
            "between 1 and 24",
        ),
        (
            "[grants]\nmax_temporary_hours_operator = 12\nmax_temporary_hours_admin = 6",
            "grants.max_temporary_hours_operator",
            "must not exceed grants.max_temporary_hours_admin (6 hours)",
        ),
        ("[flap_guard]\nmax_arrivals = 1", "flap_guard.max_arrivals", "between 2 and 100"),
        ("[flap_guard]\nwindow_seconds = 0", "flap_guard.window_seconds", "between 1 and 3600"),
        (
            "[flap_guard]\ncooldown_seconds = 86401",
            "flap_guard.cooldown_seconds",
            "between 1 and 86400",
        ),
        ("[paths]\nstate_dir = 'state'", "paths.state_dir", "absolute path"),
        ("[paths]\nconfig_dir = ''", "paths.config_dir", "must not be empty"),
        ("[paths]\nconfig_dir = 'C:\\\\ProgramData\\\\PortLock'", "paths.config_dir", "absolute"),
        ("[audit]\nhmac_key_file = 'keys/audit.key'", "audit.hmac_key_file", "absolute path"),
        ("[audit]\nhmac_key_file = ''", "audit.hmac_key_file", "must not be empty"),
        ("[[audit.sinks]]\ntarget='x'", "audit.sinks[0].type", "is required"),
        ("[[audit.sinks]]\ntype='smtp'", "audit.sinks[0].type", "must be one of"),
        ("[[audit.sinks]]\ntype='file'", "audit.sinks[0].target", "is required"),
        ("[[audit.sinks]]\ntype='file'\ntarget='events.log'", "audit.sinks[0].target", "absolute"),
        ("[[audit.sinks]]\ntype='clawnet'", "audit.sinks[0].target", "is required"),
        ("[[audit.sinks]]\ntype='clawnet'\ntarget=''", "audit.sinks[0].target", "not be empty"),
        ("[[audit.sinks]]\ntype='syslog'", "audit.sinks[0].target", "is required"),
        ("[[audit.sinks]]\ntype='syslog'\ntarget=514", "audit.sinks[0].target", "a string"),
        (
            "[[audit.sinks]]\ntype='syslog'\ntarget='/dev/log'\nmin_severity='fatal'",
            "audit.sinks[0].min_severity",
            "must be one of",
        ),
        (
            "[[audit.sinks]]\ntype='file'\ntarget='/var/log/x'\nmin_severity=3",
            "audit.sinks[0].min_severity",
            "must be one of",
        ),
    ],
)
def test_each_kind_of_fault_is_reported_at_its_path(
    tmp_path: Path, text: str, path: str, fragment: str
) -> None:
    problems = _problems(tmp_path, text)
    matching = [problem for problem in problems if problem.startswith(f"{path}: ")]
    assert len(matching) == 1, problems
    assert fragment in matching[0]
    assert len(problems) == 1, problems


def test_a_broken_table_is_reported_once_not_once_per_setting(tmp_path: Path) -> None:
    assert _paths_of(_problems(tmp_path, "api = 5\nscan = 'x'\nauth = []\n")) == [
        "api",
        "scan",
        "auth",
    ]


def test_too_many_sinks_are_refused(tmp_path: Path) -> None:
    text = "[[audit.sinks]]\ntype = 'syslog'\n" * 17
    assert _paths_of(_problems(tmp_path, text)) == ["audit.sinks"]


def test_windows_paths_are_judged_by_windows_rules(tmp_path: Path) -> None:
    good = _write(tmp_path, '[paths]\nstate_dir = "D:\\\\PortLock\\\\state"\n', "good.toml")
    config = load_config(good, env={}, platform=WINDOWS)
    assert config.paths.state_dir == Path("D:\\PortLock\\state")
    for bad in ('"/var/lib/portlock"', '"C:state"', '"state"', '"\\\\state"'):
        problems = _problems(tmp_path, f"[paths]\nstate_dir = {bad}\n", WINDOWS)
        assert _paths_of(problems) == ["paths.state_dir"], bad


def test_values_in_messages_are_truncated(tmp_path: Path) -> None:
    (problem,) = _problems(tmp_path, f"mode = '{'x' * 5000}'")
    assert len(problem) < 300


def test_unknown_keys_are_reported_in_nested_arrays_too(tmp_path: Path) -> None:
    problems = _problems(
        tmp_path,
        "[[audit.sinks]]\ntype = 'syslog'\ntarget = 'local'\n[audit.sinks.options]\na = 1\n",
    )
    assert _paths_of(problems) == ["audit.sinks[0].options"]


# --- audit sinks -----------------------------------------------------------------------

SYSLOG_ADDRESSES = [
    "192.0.2.10:514",
    "127.0.0.1:1",
    "192.0.2.10:65535",
    "[2001:db8::1]:514",
    "[::1]:6514",
    "[192.0.2.10]:514",
]
SYSLOG_SOCKETS = ["local", "/dev/log", "/run/systemd/journal/syslog"]


def _syslog(target: str) -> str:
    return f'[[audit.sinks]]\ntype = "syslog"\ntarget = "{target}"\n'


@pytest.mark.parametrize("target", SYSLOG_ADDRESSES + SYSLOG_SOCKETS)
def test_syslog_targets_accepted_on_linux(tmp_path: Path, target: str) -> None:
    config = load_config(_write(tmp_path, _syslog(target)), env={}, platform=LINUX)
    assert config.audit.sinks == (AuditSinkConfig(type="syslog", target=target),)
    assert config.audit.sinks[0].min_severity is Severity.INFO


@pytest.mark.parametrize("target", SYSLOG_ADDRESSES)
def test_syslog_addresses_are_accepted_on_windows(tmp_path: Path, target: str) -> None:
    config = load_config(_write(tmp_path, _syslog(target)), env={}, platform=WINDOWS)
    assert config.audit.sinks == (AuditSinkConfig(type="syslog", target=target),)


@pytest.mark.parametrize("target", SYSLOG_SOCKETS)
def test_a_syslog_socket_is_refused_on_windows(tmp_path: Path, target: str) -> None:
    (problem,) = _problems(tmp_path, _syslog(target), WINDOWS)
    assert problem.startswith("audit.sinks[0].target: Windows has no local syslog socket")
    # Built in code the platform is not known, so the same sink is accepted there.
    sink = AuditSinkConfig(type="syslog", target=target)
    config = Config(paths=PathsConfig.under("/srv/portlock"), audit=AuditConfig(sinks=(sink,)))
    assert config.audit.sinks == (sink,)


UNUSABLE_SYSLOG_TARGETS = [
    "logs.example:514",  # a host name would mean a DNS lookup for every event
    "localhost:514",
    "192.0.2.10",  # no port
    "192.0.2.10:",
    "192.0.2.10:0",
    "192.0.2.10:65536",
    "192.0.2.10:514000",
    "192.0.2.10:5x4",
    "192.0.2.10:-1",
    "192.0.2:514",
    ":514",
    "2001:db8::1:514",  # an IPv6 address needs its brackets
    "[2001:db8::1]",
    "[fe80::1%eth0]:514",  # a scoped address names one machine's interface
    "[logs.example]:514",
    "udp://192.0.2.10:514",
    "dev/log",
    "Local",
    "C:/logs/syslog",
]


@pytest.mark.parametrize("target", UNUSABLE_SYSLOG_TARGETS)
@pytest.mark.parametrize("platform", [LINUX, WINDOWS])
def test_unusable_syslog_targets_are_refused(tmp_path: Path, platform: str, target: str) -> None:
    (problem,) = _problems(tmp_path, _syslog(target), platform)
    assert problem.startswith("audit.sinks[0].target: must be ")
    assert "host names are not resolved" in problem
    with pytest.raises(InvalidConfigError, match=r"audit\.sinks\[0\]\.target"):
        Config(
            paths=PathsConfig.under("/srv/portlock"),
            audit=AuditConfig(sinks=(AuditSinkConfig(type="syslog", target=target),)),
        )


def test_syslog_validation_agrees_with_the_sink_that_consumes_the_target(tmp_path: Path) -> None:
    # A configuration that loads must be one the syslog sink can be built from, and the
    # other way round. Building a sink opens no socket; that happens on the first event.
    from portlock.audit.sinks import SyslogSink

    for target in SYSLOG_ADDRESSES:
        address = SyslogSink.from_target(target).target
        assert isinstance(address, tuple), target
        assert address[1] == int(target.rpartition(":")[2])
    for target in UNUSABLE_SYSLOG_TARGETS:
        with pytest.raises(PortLockError):
            SyslogSink.from_target(target)
    # The socket forms are usable exactly where this module accepts them for the
    # platform it is told about: everywhere but Windows.
    for target in SYSLOG_SOCKETS:
        path = _write(tmp_path, _syslog(target))
        if sys.platform == "win32":
            with pytest.raises(PortLockError):
                SyslogSink.from_target(target)
            with pytest.raises(InvalidConfigError):
                load_config(path, env={}, platform=sys.platform)
        else:
            assert isinstance(SyslogSink.from_target(target).target, str)
            config = load_config(path, env={}, platform=sys.platform)
            assert config.audit.sinks[0].target == target


def test_every_sink_needs_a_target_even_when_built_in_code() -> None:
    with pytest.raises(TypeError):
        AuditSinkConfig(type="syslog")  # type: ignore[call-arg]
    with pytest.raises(InvalidConfigError) as caught:
        Config(
            paths=PathsConfig.under("/srv/portlock"),
            audit=AuditConfig(
                sinks=(
                    AuditSinkConfig(type="syslog", target=None),  # type: ignore[arg-type]
                    AuditSinkConfig(type="clawnet", target="  "),
                    AuditSinkConfig(type="pager", target="x"),
                    "syslog",  # type: ignore[arg-type]
                )
            ),
        )
    assert _paths_of(caught.value.problems) == [
        "audit.sinks[0].target",
        "audit.sinks[1].target",
        "audit.sinks[2].type",
        "audit.sinks[3]",
    ]


# --- the API must stay on loopback -----------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "0:0:0:0:0:0:0:1"])
def test_loopback_addresses_are_accepted(tmp_path: Path, host: str) -> None:
    config = load_config(_write(tmp_path, f'[api]\nhost = "{host}"\n'), env={}, platform=LINUX)
    assert config.api.host == host


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # noqa: S104 - the point of the test is that this is refused
        "::",
        "192.168.1.10",
        "10.0.0.1",
        "169.254.1.1",
        "8.8.8.8",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::1%lo",
        "localhost",
        "example.com",
        "127.0.0.1:47600",
        "127.0.0.1 ",
        "127.1",
        "*",
    ],
)
def test_anything_but_a_loopback_address_is_refused(tmp_path: Path, host: str) -> None:
    (problem,) = _problems(tmp_path, f'[api]\nhost = "{host}"\n')
    assert problem.startswith("api.host: ")
    assert "loopback" in problem
    with pytest.raises(InvalidConfigError, match=r"api\.host"):
        Config(paths=PathsConfig.under("/srv/portlock"), api=ApiConfig(host=host))


# --- HID enforcement needs two settings ------------------------------------------------


def test_hid_enforcement_without_the_acknowledgement_explains_the_risk(tmp_path: Path) -> None:
    (problem,) = _problems(tmp_path, 'scope = "all_except_protected"\nhid_enforcement = true\n')
    assert problem.startswith("hid_enforcement: requires acknowledge_lockout_risk = true")
    assert "keyboard" in problem
    assert "nobody able to undo it" in problem
    assert "DISABLE_ENFORCEMENT" in problem


def test_hid_enforcement_with_the_acknowledgement_is_accepted(tmp_path: Path) -> None:
    config = load_config(
        _write(
            tmp_path,
            'scope = "all_except_protected"\nhid_enforcement = true\n'
            "acknowledge_lockout_risk = true\n",
        ),
        env={},
        platform=LINUX,
    )
    assert config.hid_enforcement is True
    assert config.hid_enforcement_enabled is True


def test_every_power_of_two_in_range_is_an_accepted_scrypt_cost(tmp_path: Path) -> None:
    for exponent in (17, 18, 19):
        path = _write(tmp_path, f"[auth]\nscrypt_n = {2**exponent}\n")
        assert load_config(path, env={}, platform=LINUX).auth.scrypt_n == 2**exponent


def test_the_grant_ceilings_can_be_lowered_but_not_raised_past_the_design(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        "[grants]\nmax_temporary_hours_operator = 24\nmax_temporary_hours_admin = 24\n"
        "low_confidence_max_hours = 1\n",
    )
    grants = load_config(path, env={}, platform=LINUX).grants
    assert grants == GrantsConfig(
        max_temporary_hours_operator=24, max_temporary_hours_admin=24, low_confidence_max_hours=1
    )
    with pytest.raises(InvalidConfigError, match=r"grants.max_temporary_hours_operator"):
        Config(
            paths=PathsConfig.under("/srv/portlock"),
            grants=GrantsConfig(max_temporary_hours_operator=48),
        )


def test_the_default_scope_is_documented_as_covering_imaging_devices() -> None:
    text = config_to_toml(default_config(LINUX, {}))
    assert 'scope = "storage"' in text
    assert "imaging devices" in text and "MTP or PTP" in text
    # The old rule that being connected at start-up protected an input device is gone.
    assert "present when the service starts" not in text
    assert "enroll" in text


def test_the_new_sections_are_validated_in_code_too() -> None:
    with pytest.raises(InvalidConfigError) as caught:
        Config(
            paths=PathsConfig.under("/srv/portlock"),
            commit_confirm_seconds=0,
            baseline_read_only="yes",  # type: ignore[arg-type]
            auth=AuthConfig(scrypt_n=1000, max_concurrent_verifications=0),
            grants=GrantsConfig(low_confidence_max_hours=48),
            flap_guard=FlapGuardConfig(max_arrivals=0),
        )
    assert sorted(_paths_of(caught.value.problems)) == sorted(
        [
            "commit_confirm_seconds",
            "baseline_read_only",
            "auth.scrypt_n",
            "auth.max_concurrent_verifications",
            "grants.low_confidence_max_hours",
            "flap_guard.max_arrivals",
        ]
    )


def test_the_acknowledgement_alone_enables_nothing(tmp_path: Path) -> None:
    config = load_config(
        _write(tmp_path, "acknowledge_lockout_risk = true\n"), env={}, platform=LINUX
    )
    assert config.acknowledge_lockout_risk is True
    assert config.hid_enforcement_enabled is False


@pytest.mark.parametrize("scope", ["storage", "storage_and_unknown"])
def test_hid_enforcement_that_could_never_apply_is_refused(tmp_path: Path, scope: str) -> None:
    (problem,) = _problems(
        tmp_path,
        f'scope = "{scope}"\nhid_enforcement = true\nacknowledge_lockout_risk = true\n',
    )
    assert problem.startswith("hid_enforcement: has no effect unless scope")
    assert scope in problem


def test_the_hid_rule_cannot_be_bypassed_by_building_the_object_in_code() -> None:
    paths = PathsConfig.under("/srv/portlock")
    with pytest.raises(InvalidConfigError) as caught:
        Config(paths=paths, scope="all_except_protected", hid_enforcement=True)
    assert caught.value.source is None
    assert _paths_of(caught.value.problems) == ["hid_enforcement"]
    with pytest.raises(InvalidConfigError):
        dataclasses.replace(Config(paths=paths, scope="all_except_protected"), hid_enforcement=True)
    enabled = Config(
        paths=paths,
        scope="all_except_protected",
        hid_enforcement=True,
        acknowledge_lockout_risk=True,
    )
    assert enabled.hid_enforcement_enabled is True
    with pytest.raises(InvalidConfigError):
        dataclasses.replace(enabled, acknowledge_lockout_risk=False)


def test_a_faulty_hid_setting_is_reported_once(tmp_path: Path) -> None:
    # The type error is the problem; the cross-check must not pile on.
    problems = _problems(tmp_path, "hid_enforcement = 1\n")
    assert _paths_of(problems) == ["hid_enforcement"]


# --- building a Config in code ---------------------------------------------------------


def test_a_config_built_in_code_is_validated_like_a_file() -> None:
    paths = PathsConfig.under("/srv/portlock")
    with pytest.raises(InvalidConfigError) as caught:
        Config(
            paths=paths,
            mode="sometimes",  # type: ignore[arg-type]
            api=ApiConfig(port=70000),
            scan=ScanConfig(engines=("yara",)),
            auth=AuthConfig(min_password_length=4),
            lockdown="off",  # type: ignore[arg-type]
            audit=AuditConfig(sinks=(AuditSinkConfig(type="file", target="relative.log"),)),
            host_label="",
        )
    assert sorted(_paths_of(caught.value.problems)) == sorted(
        [
            "mode",
            "host_label",
            "api.port",
            "scan.engines[0]",
            "lockdown",
            "auth.min_password_length",
            "audit.sinks[0].target",
        ]
    )


@pytest.mark.parametrize(
    "paths",
    [
        PathsConfig(state_dir=Path("state"), config_dir=Path("/etc/portlock")),
        PathsConfig(state_dir=Path("/var/lib/portlock"), config_dir=Path("config")),
        PathsConfig(state_dir=None, config_dir=Path("/etc/portlock")),  # type: ignore[arg-type]
    ],
)
def test_paths_built_in_code_must_be_absolute(paths: PathsConfig) -> None:
    with pytest.raises(InvalidConfigError, match="paths"):
        Config(paths=paths)


def test_plain_values_are_settled_into_their_types() -> None:
    config = Config(
        paths=PathsConfig(state_dir="/var/lib/portlock", config_dir="/etc/portlock"),  # type: ignore[arg-type]
        mode="enforce",  # type: ignore[arg-type]
        polling_interval_seconds=3,
        scan=ScanConfig(engines=["hashset"]),  # type: ignore[arg-type]
        audit=AuditConfig(
            hmac_key_file="/etc/portlock/audit.key",  # type: ignore[arg-type]
            sinks=[AuditSinkConfig(type="syslog", target="local", min_severity="error")],  # type: ignore[arg-type]
        ),
    )
    assert config.mode is Mode.ENFORCE
    assert isinstance(config.polling_interval_seconds, float)
    assert config.paths.state_dir == Path("/var/lib/portlock")
    assert config.scan.engines == ("hashset",)
    assert config.audit.hmac_key_file == Path("/etc/portlock/audit.key")
    assert config.audit.sinks == (
        AuditSinkConfig(type="syslog", target="local", min_severity=Severity.ERROR),
    )
    assert config.audit.sinks[0].min_severity is Severity.ERROR


def test_config_is_immutable_and_hashable() -> None:
    config = default_config(LINUX, {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.mode = Mode.ENFORCE  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.api.port = 1  # type: ignore[misc]
    assert hash(config) == hash(default_config(LINUX, {}))
    assert config != dataclasses.replace(config, fail_closed=True)


def test_to_dict_is_json_serializable_and_complete() -> None:
    data = default_config(LINUX, {}).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["mode"] == "monitor"
    assert data["paths"] == {"state_dir": "/var/lib/portlock", "config_dir": "/etc/portlock"}
    assert data["audit"] == {"hmac_key_file": None, "sinks": []}
    assert data["scan"]["engines"] == list(SCAN_ENGINES)
    assert set(data) == {field.name for field in dataclasses.fields(Config)}


# --- the generated file ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "env"),
    [
        (LINUX, {}),
        (LINUX, {"PORTLOCK_HOME": "/srv/portlock"}),
        (WINDOWS, {}),
        (WINDOWS, {"ProgramData": "D:\\Program Data"}),
        (WINDOWS, {"PORTLOCK_HOME": "\\\\server\\share\\portlock"}),
    ],
)
def test_the_default_file_round_trips(tmp_path: Path, platform: str, env: dict[str, str]) -> None:
    config = default_config(platform, env)
    path = _write(tmp_path, config_to_toml(config))
    assert load_config(path, env=env, platform=platform) == config
    # The file pins the paths, so it reads the same under a different environment.
    assert load_config(path, env={}, platform=platform) == config


def test_a_customized_config_round_trips(tmp_path: Path) -> None:
    config = Config(
        paths=PathsConfig(
            state_dir=Path('C:\\Port "Lock"\\state'), config_dir=Path("C:\\PortLock\\config")
        ),
        mode=Mode.ENFORCE,
        scope="all_except_protected",
        hid_enforcement=True,
        acknowledge_lockout_risk=True,
        fail_closed=True,
        api=ApiConfig(host="::1", port=0, session_idle_minutes=1, session_max_hours=1),
        commit_confirm_seconds=10,
        baseline_read_only=True,
        scan=ScanConfig(enabled=False, max_files=1, max_bytes=1, max_seconds=1, engines=()),
        lockdown=LockdownConfig(default_minutes=5, max_minutes=5, allow_new_input_devices=False),
        auth=AuthConfig(
            min_password_length=20,
            lockout_threshold=1,
            lockout_base_seconds=1,
            lockout_max_seconds=1,
            scrypt_n=524288,
            max_concurrent_verifications=8,
        ),
        grants=GrantsConfig(
            max_temporary_hours_operator=1,
            max_temporary_hours_admin=8760,
            low_confidence_max_hours=1,
        ),
        flap_guard=FlapGuardConfig(max_arrivals=100, window_seconds=3600, cooldown_seconds=1),
        audit=AuditConfig(
            hmac_key_file=Path("C:\\PortLock\\keys\\audit.key"),
            sinks=(
                AuditSinkConfig(type="file", target="D:\\logs\\portlock.jsonl"),
                AuditSinkConfig(type="syslog", target="192.0.2.10:6514", min_severity="error"),
                AuditSinkConfig(type="syslog", target="[2001:db8::1]:514"),
                AuditSinkConfig(type="clawnet", target='ops "red" team', min_severity="critical"),
            ),
        ),
        polling_interval_seconds=0.25,
        host_label="lab_7.east-wing",
    )
    text = config_to_toml(config)
    assert load_config(_write(tmp_path, text), env={}, platform=WINDOWS) == config
    assert config_to_toml(load_config(_write(tmp_path, text), env={}, platform=WINDOWS)) == text


def test_the_generated_file_is_commented_and_complete() -> None:
    config = default_config(LINUX, {})
    text = config_to_toml(config)
    document = tomllib.loads(text)
    # Every setting is present with its value, except the two that are unset by default.
    expected = config.to_dict()
    del expected["audit"]["hmac_key_file"]
    del expected["audit"]["sinks"]
    assert document == expected

    lines = text.splitlines()
    assert text.endswith("\n") and "\r" not in text
    assert sum(line.startswith("#") for line in lines) >= 30
    # Each setting is introduced by a comment block rather than left bare.
    for key in (
        "mode",
        "scope",
        "hid_enforcement",
        "fail_closed",
        "commit_confirm_seconds",
        "baseline_read_only",
        "host_label",
    ):
        index = next(i for i, line in enumerate(lines) if line.startswith(f"{key} = "))
        assert lines[index - 1].startswith("#"), key
    # The unset options are shown as commented examples.
    assert '# hmac_key_file = "' in text
    assert "# [[audit.sinks]]" in text
    # The lockout warning is in the file an operator will actually read.
    assert "acknowledge_lockout_risk" in text and "keyboard" in text


def test_strings_are_escaped_in_the_generated_file() -> None:
    config = dataclasses.replace(
        default_config(LINUX, {}),
        audit=AuditConfig(sinks=(AuditSinkConfig(type="clawnet", target='a"b\\c'),)),
    )
    text = config_to_toml(config)
    assert 'target = "a\\"b\\\\c"' in text
    assert tomllib.loads(text)["audit"]["sinks"][0]["target"] == 'a"b\\c'
