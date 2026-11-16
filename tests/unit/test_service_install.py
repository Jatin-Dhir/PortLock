"""Service definitions: the systemd unit and the Windows scheduled task are text for an
administrator to review. Nothing is installed, written or run."""

from __future__ import annotations

import configparser
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from portlock.core.config import Config, PathsConfig, default_config
from portlock.core.errors import ConfigError
from portlock.service.install import install_instructions, systemd_unit, windows_task_xml

LINUX = default_config(platform="linux", env={})
EXECUTABLE = "/usr/local/bin/portlock"
WIN_EXECUTABLE = "C:\\Program Files\\PortLock\\python.exe"
WIN_CONFIG = "C:\\ProgramData\\PortLock\\portlock.toml"
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


@pytest.fixture(autouse=True)
def nothing_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Producing a definition starts no process and touches no file."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("generating a service definition must not run anything")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(os, "system", refuse)
    monkeypatch.chdir(tmp_path)


def parse_unit(text: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=True, delimiters=("=",), interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(text)
    return parser


# --- the systemd unit ---------------------------------------------------------------------


def test_the_unit_parses_and_runs_the_service_with_the_documented_directives() -> None:
    text = systemd_unit(LINUX, executable=EXECUTABLE)
    unit = parse_unit(text)
    assert unit.sections() == ["Unit", "Service", "Install"]
    service = unit["Service"]
    assert service["Type"] == "simple"
    assert service["ExecStart"] == f"{EXECUTABLE} run --config /etc/portlock/portlock.toml"
    assert service["ExecStop"] == f"{EXECUTABLE} stop --config /etc/portlock/portlock.toml"
    assert service["Restart"] == "always" and service["RestartSec"] == "2"
    assert unit["Install"]["WantedBy"] == "multi-user.target"
    assert unit["Unit"]["Description"].startswith("PortLock")
    assert text.endswith("\n")


def test_the_unit_is_hardened_as_the_enforcement_document_says() -> None:
    service = parse_unit(systemd_unit(LINUX, executable=EXECUTABLE))["Service"]
    assert service["NoNewPrivileges"] == "yes"
    assert service["ProtectSystem"] == "strict"
    assert service["CapabilityBoundingSet"] == "CAP_SYS_ADMIN"
    assert service["DevicePolicy"] == "closed" and service["DeviceAllow"] == "block-sd rw"
    assert set(service["RestrictAddressFamilies"].split()) == {
        "AF_UNIX",
        "AF_NETLINK",
        "AF_INET",
        "AF_INET6",
    }
    for option in (
        "ProtectKernelModules",
        "ProtectControlGroups",
        "RestrictNamespaces",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "PrivateTmp",
        "ProtectHome",
    ):
        assert service[option] == "yes", option
    assert service["SystemCallArchitectures"] == "native" and service["UMask"] == "0077"


def test_the_unit_leaves_sys_writable_and_only_three_paths_writable() -> None:
    text = systemd_unit(LINUX, executable=EXECUTABLE)
    service = parse_unit(text)["Service"]
    # Options that would stop PortLock from enforcing appear only in the explaining comments.
    directives = [
        line.split("=")[0] for line in text.splitlines() if "=" in line and not line.startswith("#")
    ]
    for forbidden in ("ProtectKernelTunables", "PrivateDevices", "PrivateNetwork"):
        assert forbidden not in directives
        assert f"#   {forbidden}" in text
    assert service["ReadWritePaths"].split() == [
        "/var/lib/portlock",
        "/etc/portlock",
        "/etc/udev/rules.d",
    ]


def test_a_python_command_line_is_accepted_as_the_executable() -> None:
    service = parse_unit(
        systemd_unit(LINUX, executable=("/usr/bin/python3", "-I", "-m", "portlock"))
    )["Service"]
    assert (
        service["ExecStart"]
        == "/usr/bin/python3 -I -m portlock run --config /etc/portlock/portlock.toml"
    )


def test_a_config_file_elsewhere_is_passed_through_and_quoted_when_it_needs_to_be() -> None:
    text = systemd_unit(
        LINUX, executable=EXECUTABLE, config_file="/srv/port lock/50%/a$b/it's.toml"
    )
    start = parse_unit(text)["Service"]["ExecStart"]
    assert start.endswith('--config "/srv/port lock/50%%/a$$b/it\'s.toml"')
    quoted = systemd_unit(LINUX, executable=EXECUTABLE, config_file='/srv/a"b\\c.toml')
    assert r'"/srv/a\"b\\c.toml"' in quoted


def test_directories_with_spaces_are_quoted_in_the_writable_list() -> None:
    config = Config(
        paths=PathsConfig(state_dir=Path("/var/lib/port lock"), config_dir=Path("/etc/port lock"))
    )
    writable = parse_unit(systemd_unit(config, executable=EXECUTABLE))["Service"]["ReadWritePaths"]
    assert writable == '"/var/lib/port lock" "/etc/port lock" /etc/udev/rules.d'


@pytest.mark.parametrize(
    "executable",
    [
        "portlock",
        "./portlock",
        "-/usr/bin/portlock",
        "@/usr/bin/portlock",
        "/usr/bin/port\nlock",
        "/usr/bin/port\x00lock",
        "",
        ("/usr/bin/python3", "-m\nExecStartPost=/bin/sh"),
        (),
    ],
)
def test_a_hostile_or_relative_executable_is_refused(executable: object) -> None:
    with pytest.raises(ConfigError):
        systemd_unit(LINUX, executable=executable)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path",
    [
        "/etc/portlock/x\nExecStartPost=/bin/sh",
        "relative/portlock.toml",
        "/etc//portlock.toml",
        "/etc/../portlock.toml",
        "C:\\ProgramData\\PortLock\\portlock.toml",
        "/etc/portlock/\x07.toml",
    ],
)
def test_a_hostile_config_path_is_refused(path: str) -> None:
    with pytest.raises(ConfigError):
        systemd_unit(LINUX, executable=EXECUTABLE, config_file=path)


def test_directories_that_are_not_posix_paths_are_refused() -> None:
    # (A control character in a directory never gets this far: Config itself refuses it.)
    windows_style = Config(
        paths=PathsConfig(
            state_dir=Path("C:/ProgramData/PortLock"), config_dir=Path("C:/ProgramData/PortLock")
        )
    )
    with pytest.raises(ConfigError, match="POSIX"):
        systemd_unit(windows_style, executable=EXECUTABLE)


# --- the Windows task ---------------------------------------------------------------------


def test_the_task_runs_at_boot_as_system_with_the_highest_privileges() -> None:
    text = windows_task_xml(
        default_config(platform="win32", env={}), executable=WIN_EXECUTABLE, config_file=WIN_CONFIG
    )
    root = ET.fromstring(text.split("?>", 1)[1])  # noqa: S314 - our own generated text
    assert root.tag == f"{{{NS['t']}}}Task"
    assert root.find("t:Triggers/t:BootTrigger/t:Enabled", NS).text == "true"  # type: ignore[union-attr]
    principals = root.findall("t:Principals/t:Principal", NS)
    assert len(principals) == 1
    assert principals[0].find("t:UserId", NS).text == "S-1-5-18"  # type: ignore[union-attr]
    assert principals[0].find("t:RunLevel", NS).text == "HighestAvailable"  # type: ignore[union-attr]
    user_ids = [element.text for element in root.iter(f"{{{NS['t']}}}UserId")]
    assert user_ids == ["S-1-5-18"]  # no other account named anywhere
    assert root.find("t:Settings/t:ExecutionTimeLimit", NS).text == "PT0S"  # type: ignore[union-attr]
    restart = root.find("t:Settings/t:RestartOnFailure", NS)
    assert restart is not None and restart.find("t:Count", NS).text == "999"  # type: ignore[union-attr]
    assert root.find("t:Settings/t:MultipleInstancesPolicy", NS).text == "IgnoreNew"  # type: ignore[union-attr]
    assert root.find("t:Settings/t:DisallowStartIfOnBatteries", NS).text == "false"  # type: ignore[union-attr]
    assert text.startswith('<?xml version="1.0" encoding="UTF-16"?>')
    assert text.isascii()


def test_the_task_command_and_arguments_round_trip_through_the_xml() -> None:
    text = windows_task_xml(
        default_config(platform="win32", env={}),
        executable=(WIN_EXECUTABLE, "-I", "-m", "portlock"),
        config_file="C:\\Data & Files\\<PortLock>\\portlock.toml",
    )
    root = ET.fromstring(text.split("?>", 1)[1])  # noqa: S314 - our own generated text
    assert root.find("t:Actions/t:Exec/t:Command", NS).text == WIN_EXECUTABLE  # type: ignore[union-attr]
    arguments = root.find("t:Actions/t:Exec/t:Arguments", NS).text  # type: ignore[union-attr]
    assert arguments == '-I -m portlock run --config "C:\\Data & Files\\<PortLock>\\portlock.toml"'
    assert "&amp;" in text and "&lt;PortLock&gt;" in text


@pytest.mark.parametrize(
    ("executable", "config_file"),
    [
        ("python.exe", WIN_CONFIG),
        ("/usr/bin/python3", WIN_CONFIG),
        (WIN_EXECUTABLE, "portlock.toml"),
        ('C:\\Program Files\\"Evil"\\python.exe', WIN_CONFIG),
        ("C:\\Program%PATH%\\python.exe", WIN_CONFIG),
        ("C:\\Program Files\\a\nb.exe", WIN_CONFIG),
        (WIN_EXECUTABLE, "C:\\x\\a\x00b.toml"),
        (WIN_EXECUTABLE, 'C:\\x\\"quoted".toml'),
        ("", WIN_CONFIG),
    ],
)
def test_a_hostile_or_relative_path_in_the_task_is_refused(
    executable: str, config_file: str
) -> None:
    with pytest.raises(ConfigError):
        windows_task_xml(
            default_config(platform="win32", env={}), executable=executable, config_file=config_file
        )


def test_unc_paths_are_accepted() -> None:
    text = windows_task_xml(
        default_config(platform="win32", env={}),
        executable="\\\\server\\share\\portlock.exe",
        config_file="\\\\server\\share\\portlock.toml",
    )
    assert "<Command>\\\\server\\share\\portlock.exe</Command>" in text


# --- instructions and the promise to install nothing -------------------------------------


def test_the_instructions_say_what_the_administrator_runs_and_run_nothing() -> None:
    linux = install_instructions("linux")
    assert "systemctl daemon-reload" in linux and "systemctl enable --now portlock" in linux
    assert "usbcore.authorized_default=0" in linux and "portlock doctor" in linux
    assert "yourself" in linux and "monitor mode" in linux
    windows = install_instructions("win32")
    assert 'schtasks /Create /TN "\\PortLock\\Service" /XML portlock-task.xml' in windows
    assert "SYSTEM" in windows and "elevated" in windows
    assert install_instructions("linux2") == linux  # any linux flavour
    with pytest.raises(ConfigError):
        install_instructions("darwin")


def test_generating_definitions_writes_no_file_and_starts_no_process(tmp_path: Path) -> None:
    systemd_unit(LINUX, executable=EXECUTABLE)
    windows_task_xml(
        default_config(platform="win32", env={}), executable=WIN_EXECUTABLE, config_file=WIN_CONFIG
    )
    install_instructions("linux")
    install_instructions("win32")
    assert list(tmp_path.iterdir()) == []


def test_the_output_is_deterministic() -> None:
    assert systemd_unit(LINUX, executable=EXECUTABLE) == systemd_unit(LINUX, executable=EXECUTABLE)
    config = default_config(platform="win32", env={})
    assert windows_task_xml(
        config, executable=WIN_EXECUTABLE, config_file=WIN_CONFIG
    ) == windows_task_xml(config, executable=WIN_EXECUTABLE, config_file=WIN_CONFIG)
