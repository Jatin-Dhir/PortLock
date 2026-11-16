"""Service definitions for the administrator to review and install.

:func:`systemd_unit` and :func:`windows_task_xml` return the *text* of a hardened systemd
unit and of a Windows Task Scheduler definition. **Nothing here installs anything, starts
anything or changes any system state**: no file is written, no ``systemctl`` or
``schtasks`` is run. ``portlock service print-unit`` and ``print-task`` show the text;
:func:`install_instructions` says, as plain text, what the administrator then does.

Linux (``docs/enforcement/linux.md`` section 10 is authoritative for the option list): the
unit runs as root with a bounding set of ``CAP_SYS_ADMIN`` (``BLKROSET``), keeps ``/sys``
writable, allows ``AF_NETLINK`` (kernel device events), ``AF_UNIX`` and ``AF_INET*`` (the
local API), and makes only PortLock's state directory, its configuration directory and the
udev rules directory writable. ``ProtectKernelTunables`` and ``PrivateDevices`` are left out
on purpose: the first makes ``authorized`` and ``authorized_default`` read-only, the second
removes the block device nodes ``BLKROSET`` needs. ``Restart=always`` because the dead-man
timer and the release of held devices need the service alive.

Windows: a scheduled task that runs at boot as ``SYSTEM`` with the highest privileges,
restarts on failure and has no execution time limit. A scheduled task is used because a
real Windows service needs a service-control dispatcher, which the standard library does
not provide (``docs/ARCHITECTURE.md`` decision D20). ``portlock stop`` is the graceful
stop; ending the task is a crash as far as ``docs/ARCHITECTURE.md`` section 6 is concerned.

Every path is validated before it is quoted for the target format: a path with a control
character, or one that the format cannot carry, raises
:class:`~portlock.core.errors.ConfigError`.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from portlock.core.config import Config
from portlock.core.errors import ConfigError

__all__ = ["install_instructions", "systemd_unit", "windows_task_xml"]

_DOCS = "https://github.com/Jatin-Dhir/PortLock"
_UDEV_RULES_DIR = "/etc/udev/rules.d"
_SID_LOCAL_SYSTEM = "S-1-5-18"
_TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
_TASK_URI = "\\PortLock\\Service"
_WINDOWS_ABSOLUTE = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)")


def _argv(executable: str | Sequence[str], what: str) -> tuple[str, ...]:
    parts = (executable,) if isinstance(executable, str) else tuple(executable)
    if not parts or not all(isinstance(part, str) and part for part in parts):
        raise ConfigError(f"{what}: the executable must be a non-empty path or argument list")
    for part in parts:
        _check_text(part, what)
    return parts


def _check_text(value: str, what: str) -> None:
    """Refuse control characters (a newline would start a new directive or element)."""
    for char in value:
        if ord(char) < 0x20 or ord(char) == 0x7F or 0x80 <= ord(char) < 0xA0:
            raise ConfigError(f"{what}: {value[:40]!r} contains a control character")


def _posix_path(path: str | Path, what: str) -> str:
    text = Path(path).as_posix() if not isinstance(path, str) else path
    _check_text(text, what)
    if not text.startswith("/") or "//" in text or "/./" in text or "/../" in text:
        raise ConfigError(
            f"{what}: {text!r} is not a clean absolute POSIX path; a systemd unit needs one "
            "(use the Linux defaults: default_config(platform='linux'))"
        )
    return text


def _systemd_quote(value: str) -> str:
    """One word of an ``ExecStart=`` line or a path list, as systemd reads it.

    Words with whitespace, quotes, semicolons or backslashes are double-quoted with
    C-style escapes; ``%`` and ``$`` are doubled because systemd expands specifiers and
    environment variables in these settings.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    if not value or re.search(r"[\s\"';\\]", value):
        return f'"{escaped}"'
    return escaped


def systemd_unit(
    config: Config,
    *,
    executable: str | Sequence[str],
    config_file: str | Path | None = None,
) -> str:
    """The text of ``portlock.service`` for ``config``.

    Args:
        config: the configuration the service will run with (its state and configuration
            directories are the only writable paths, besides the udev rules directory).
        executable: the program that runs PortLock: an absolute path to the ``portlock``
            script, or an argument list such as ``("/usr/bin/python3", "-I", "-m",
            "portlock")``.
        config_file: the configuration file to pass as ``--config``; default
            ``portlock.toml`` in the configuration directory.

    Raises:
        ConfigError: if a path is not a clean absolute POSIX path, or contains a control
            character, or the executable is not absolute.
    """
    argv = _argv(executable, "executable")
    if not argv[0].startswith("/"):
        raise ConfigError("executable: a systemd unit needs an absolute path to the program")
    state_dir = _posix_path(config.paths.state_dir, "paths.state_dir")
    config_dir = _posix_path(config.paths.config_dir, "paths.config_dir")
    settings = _posix_path(
        config_file if config_file is not None else config.paths.config_file, "config file"
    )
    command = " ".join(_systemd_quote(part) for part in (*argv, "run", "--config", settings))
    stop = " ".join(_systemd_quote(part) for part in (*argv, "stop", "--config", settings))
    writable = " ".join(
        _systemd_quote(path) for path in dict.fromkeys((state_dir, config_dir, _UDEV_RULES_DIR))
    )
    lines = [
        "# PortLock service unit, written by 'portlock service print-unit'.",
        "# Nothing has been installed: review this file, then install it yourself.",
        "# The option list follows docs/enforcement/linux.md section 10.",
        "#",
        "# Left out on purpose, because PortLock could not enforce with them:",
        "#   ProtectKernelTunables=yes  makes 'authorized' and 'authorized_default' read-only",
        "#   PrivateDevices=yes         removes the block device nodes that BLKROSET needs",
        "#   PrivateNetwork=yes         removes AF_NETLINK, so no device events would arrive",
        "",
        "[Unit]",
        "Description=PortLock USB device security agent",
        f"Documentation={_DOCS}",
        "After=local-fs.target systemd-udevd.service",
        "Wants=systemd-udevd.service",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={command}",
        f"ExecStop={stop}",
        "# The dead-man timer and the release of held devices need the service alive.",
        "Restart=always",
        "RestartSec=2",
        "TimeoutStopSec=30",
        "KillSignal=SIGTERM",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_SYS_ADMIN",
        "ProtectSystem=strict",
        f"ReadWritePaths={writable}",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "DevicePolicy=closed",
        "DeviceAllow=block-sd rw",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "MemoryDenyWriteExecute=yes",
        "SystemCallArchitectures=native",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def windows_task_xml(
    config: Config,
    *,
    executable: str | Sequence[str],
    config_file: str | Path | None = None,
) -> str:
    """The Task Scheduler definition (XML) of the PortLock service for ``config``.

    The text declares UTF-16, as Task Scheduler expects: save it as UTF-16 (the command
    line's ``--output`` does) before importing it.

    Raises:
        ConfigError: if the executable is not an absolute Windows path, or a path
            contains a control character, a double quote or a ``%``.
    """
    argv = _argv(executable, "executable")
    settings = str(config_file if config_file is not None else config.paths.config_file)
    for text, what in ((argv[0], "executable"), (settings, "config file")):
        if not _WINDOWS_ABSOLUTE.match(text):
            raise ConfigError(f"{what}: {text!r} is not an absolute Windows path")
    for text in (*argv, settings):
        _check_text(text, "task")
        if '"' in text or "%" in text:
            raise ConfigError(f"task: {text[:40]!r} contains a character the task cannot carry")
    arguments = subprocess.list2cmdline([*argv[1:], "run", "--config", settings])
    lines = [
        '<?xml version="1.0" encoding="UTF-16"?>',
        f'<Task version="1.4" xmlns="{_TASK_NAMESPACE}">',
        "  <RegistrationInfo>",
        "    <Description>PortLock USB device security agent</Description>",
        f"    <URI>{xml_escape(_TASK_URI)}</URI>",
        "  </RegistrationInfo>",
        "  <Triggers>",
        "    <BootTrigger><Enabled>true</Enabled></BootTrigger>",
        "  </Triggers>",
        "  <Principals>",
        '    <Principal id="Author">',
        f"      <UserId>{_SID_LOCAL_SYSTEM}</UserId>",
        "      <RunLevel>HighestAvailable</RunLevel>",
        "    </Principal>",
        "  </Principals>",
        "  <Settings>",
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
        "    <AllowHardTerminate>true</AllowHardTerminate>",
        "    <StartWhenAvailable>true</StartWhenAvailable>",
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
        "    <AllowStartOnDemand>true</AllowStartOnDemand>",
        "    <Enabled>true</Enabled>",
        "    <Hidden>false</Hidden>",
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
        "    <Priority>6</Priority>",
        "    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>",
        "  </Settings>",
        '  <Actions Context="Author">',
        "    <Exec>",
        f"      <Command>{xml_escape(argv[0])}</Command>",
        f"      <Arguments>{xml_escape(arguments)}</Arguments>",
        "    </Exec>",
        "  </Actions>",
        "</Task>",
        "",
    ]
    return "\n".join(lines)


def install_instructions(platform: str) -> str:
    """What the administrator does with the text above, in words. Runs nothing.

    Args:
        platform: ``"linux"`` or ``"win32"``.

    Raises:
        ConfigError: for any other platform.
    """
    if platform.startswith("linux"):
        steps = [
            "Install the PortLock service on Linux (run these yourself, as root):",
            "",
            "  1. portlock service print-unit --executable /usr/local/bin/portlock \\",
            "         --output portlock.service",
            "  2. Read portlock.service. Compare it with docs/enforcement/linux.md section 10.",
            "  3. install -m 0644 portlock.service /etc/systemd/system/portlock.service",
            "  4. systemctl daemon-reload",
            "  5. portlock init            # creates the first administrator, once",
            "  6. systemctl enable --now portlock",
            "  7. portlock doctor          # says what this machine can and cannot enforce",
            "",
            "A fresh install runs in monitor mode and changes nothing. For protection from",
            "boot, also add usbcore.authorized_default=0 to the kernel command line (doctor",
            "reports whether it is set). Stop the service with 'systemctl stop portlock'.",
        ]
    elif platform == "win32":
        steps = [
            "Install the PortLock service on Windows (run these yourself, in an elevated",
            "prompt):",
            "",
            "  1. portlock service print-task --executable C:\\PortLock\\python.exe",
            "         --output portlock-task.xml",
            "  2. Read portlock-task.xml: it runs as SYSTEM at boot, restarts on failure.",
            "  3. portlock init            # creates the first administrator, once",
            '  4. schtasks /Create /TN "\\PortLock\\Service" /XML portlock-task.xml',
            '  5. schtasks /Run /TN "\\PortLock\\Service"',
            "  6. portlock doctor          # says what this machine can and cannot enforce",
            "",
            "A fresh install runs in monitor mode and changes nothing. Stop the service with",
            "'portlock stop'; ending the task by force counts as a crash.",
        ]
    else:
        raise ConfigError(f"no installation instructions for platform {platform!r}")
    return "\n".join(steps) + "\n"
