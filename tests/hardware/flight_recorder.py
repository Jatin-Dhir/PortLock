"""Run the real ``portlock`` command line in this process under a flight recorder.

This is a launcher, not a test module. ``test_watch_only_live.py`` starts it as a child
process to check, on a real operating system, the promise watch-only makes: the process
changes nothing on the machine. It does not rely on PortLock's own guard; it sits under it.

Two layers:

1. A Python audit hook (:func:`sys.addaudithook`) sees every attempt, by any code in the
   process, to start another program, touch the registry, open a file for writing, change
   the file system, open a database, or bind or connect a socket. Starting a program and
   writing the registry are **refused** (an exception is raised before anything happens)
   and recorded. Everything else is recorded and sorted into "inside" or "outside" the
   PortLock home directory.
2. Every method of PortLock's real operating-system seams that changes something (disable
   or eject a device, set a disk read-only, write a registry value, create a timer or a
   scheduled task, change directory permissions, run a command) is replaced by a tripwire
   that records the call and refuses it.

What it cannot see: a change made by native code that goes round both layers. PortLock's
own native calls all pass through the seams of layer 2, so a call this recorder misses
would have to come from a library PortLock does not use.

Usage, with ``PORTLOCK_HOME`` and ``PORTLOCK_FLIGHT_REPORT`` set and ``portlock`` on the
import path::

    python -B flight_recorder.py <portlock arguments...>

The report (JSON) is written once the tripwires are armed, then once a second and at exit,
so it survives a hard kill; its ``writes`` counter lets a test wait for a report that
covers what the process did up to a moment it chose. It
holds counts, program names, option words and paths under the home directory, and never a
device name, serial number or instance identifier.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

REPORT_ENV = "PORTLOCK_FLIGHT_REPORT"
HOME_ENV = "PORTLOCK_HOME"

_MAX_ITEMS = 400
# winreg access bits that allow a change: KEY_SET_VALUE, KEY_CREATE_SUB_KEY,
# KEY_CREATE_LINK, DELETE, WRITE_DAC, WRITE_OWNER.
_REG_WRITE_BITS = 0x0002 | 0x0004 | 0x0020 | 0x00010000 | 0x00040000 | 0x00080000
_REG_REFUSED = frozenset(
    {
        "winreg.CreateKey",
        "winreg.SetValue",
        "winreg.DeleteKey",
        "winreg.DeleteValue",
        "winreg.SaveKey",
        "winreg.LoadKey",
        "winreg.DisableReflectionKey",
        "winreg.EnableReflectionKey",
    }
)
_PROCESS_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.startfile",
        "os.startfile/2",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "os.fork",
        "os.forkpty",
        "pty.spawn",
        "_winapi.CreateProcess",
    }
)
# File-system events and the positions of the paths in their arguments.
_FS_EVENTS: dict[str, tuple[int, ...]] = {
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.mkdir": (0,),
    "os.rmdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "os.truncate": (0,),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "os.utime": (0,),
    "shutil.rmtree": (0,),
    "shutil.move": (0, 1),
    "shutil.copyfile": (1,),
    "shutil.copytree": (1,),
    "shutil.chown": (0,),
    "tempfile.mkstemp": (0,),
    "tempfile.mkdtemp": (0,),
}
# Mutating methods of the real seams (``portlock.guard.seams``), by class.
_SEAM_PLAN: dict[str, tuple[str, ...]] = {
    "WinCfgMgr": ("disable", "enable", "request_eject", "reenumerate"),
    "WinRegistry": ("set", "delete"),
    "WinDisks": ("set_read_only",),
    "ScheduledTaskTimer": ("arm", "cancel", "is_armed"),
    "SystemdRunTimer": ("arm", "cancel", "is_armed"),
    "IcaclsDirPrivacy": ("ensure_private", "check"),
    "PosixDirPrivacy": ("ensure_private",),
    "SubprocessRunner": ("run",),
    "RealSysfs": ("write_text",),
    "RealBlockIO": ("set_read_only",),
    "RealRuleFiles": ("write", "remove"),
}


class Refused(PermissionError):
    """Raised instead of letting the process change the operating system."""


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    try:
        return os.fspath(value)  # type: ignore[arg-type]
    except TypeError:
        return repr(value)


def _options(argv: object) -> list[str]:
    """The option words of a command line (those starting with ``/`` or ``-``); operands
    are replaced, because they can name a device or a path."""
    words: list[str] = []
    if isinstance(argv, list | tuple):
        for word in list(argv)[1:12]:
            text = _text(word)
            words.append(text if text[:1] in "/-" else "<operand>")
    return words


class Recorder:
    """The audit hook, the seam tripwires and the report they fill."""

    def __init__(self, report_path: str, home: str) -> None:
        self._report = os.path.abspath(report_path)
        self._home = os.path.normcase(os.path.abspath(home))
        self._lock = threading.Lock()
        self._local = threading.local()
        self.state: dict[str, Any] = {
            "started_at": time.time(),
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "blocked": [],
            "seam_calls": [],
            "armed": [],
            "missing": [],
            "writes_inside_home": {},
            "writes_outside_home": {},
            "fs_changes_inside_home": {},
            "fs_changes_outside_home": {},
            "databases_inside_home": {},
            "databases_outside_home": {},
            "registry_reads": 0,
            "sockets_bound": {},
            "sockets_connected": {},
            "exit": None,
            "writes": 0,
        }

    # --- helpers ---------------------------------------------------------------------

    def _inside(self, path: str) -> bool:
        try:
            full = os.path.normcase(os.path.abspath(path))
        except (OSError, ValueError):
            return False
        return full == self._home or full.startswith(self._home + os.sep)

    def _show(self, path: str) -> str:
        """A path as the report holds it: relative to the home when it lies inside."""
        full = os.path.abspath(path)
        if self._inside(full):
            return "<home>" + full[len(self._home) :].replace("\\", "/")
        return full.replace("\\", "/")

    def _count(self, table: str, key: str) -> None:
        bucket: dict[str, int] = self.state[table]
        if key in bucket or len(bucket) < _MAX_ITEMS:
            bucket[key] = bucket.get(key, 0) + 1

    def _refuse(self, kind: str, detail: dict[str, object]) -> None:
        with self._lock:
            blocked: list[dict[str, object]] = self.state["blocked"]
            if len(blocked) < _MAX_ITEMS:
                blocked.append({"kind": kind, **detail})
        raise Refused(f"flight recorder: {kind} refused")

    def _is_report(self, path: str) -> bool:
        return os.path.abspath(path).startswith(self._report)

    # --- layer 1: the audit hook -----------------------------------------------------

    def hook(self, event: str, args: tuple[object, ...]) -> None:
        if getattr(self._local, "busy", False):
            return
        if event in _PROCESS_EVENTS:
            self._on_process(event, args)
        elif event.startswith("winreg."):
            self._on_registry(event, args)
        elif event == "open":
            self._on_open(args)
        elif event in _FS_EVENTS:
            self._on_fs_change(event, args)
        elif event == "sqlite3.connect":
            self._on_database(args)
        elif event in ("socket.bind", "socket.connect"):
            self._on_socket(event, args)

    def _on_process(self, event: str, args: tuple[object, ...]) -> None:
        first = args[0] if args else None
        argv = args[1] if event == "subprocess.Popen" and len(args) > 1 else None
        if not first and isinstance(argv, list | tuple) and argv:
            first = argv[0]  # Popen without an explicit executable: argv[0] is the program
        detail: dict[str, object] = {
            "program": os.path.basename(_text(first)).lower() if first else "?"
        }
        if argv is not None:
            detail["options"] = _options(argv)
        self._refuse(event, detail)

    def _on_registry(self, event: str, args: tuple[object, ...]) -> None:
        if event in _REG_REFUSED:
            self._refuse(event, {})
        if event == "winreg.OpenKey":
            access = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            if access & _REG_WRITE_BITS:
                self._refuse("winreg.OpenKey with write access", {})
        with self._lock:
            self.state["registry_reads"] += 1

    def _on_open(self, args: tuple[object, ...]) -> None:
        path, mode, flags = (*args, None, None, None)[:3]
        if isinstance(path, int) or path is None:
            return
        if isinstance(mode, str):
            writing = any(letter in mode for letter in "wax+")
        elif isinstance(flags, int):
            writing = bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC)
            )
        else:
            writing = False
        text = _text(path)
        if not writing or self._is_report(text):
            return
        with self._lock:
            table = "writes_inside_home" if self._inside(text) else "writes_outside_home"
            self._count(table, self._show(text))

    def _on_fs_change(self, event: str, args: tuple[object, ...]) -> None:
        for index in _FS_EVENTS[event]:
            if index >= len(args) or args[index] is None or isinstance(args[index], int):
                continue
            text = _text(args[index])
            if self._is_report(text):
                continue
            with self._lock:
                inside = self._inside(text)
                table = "fs_changes_inside_home" if inside else "fs_changes_outside_home"
                self._count(table, f"{event} {self._show(text)}")

    def _on_database(self, args: tuple[object, ...]) -> None:
        text = _text(args[0]) if args else "?"
        if text.startswith("file:"):
            # A URI such as file:/C:/dir/portlock.db?mode=ro: keep the path part only.
            text = urllib.parse.unquote(text[5:].split("?", 1)[0])
            if sys.platform == "win32":
                text = text.lstrip("/")
        with self._lock:
            inside = text == ":memory:" or self._inside(text)
            table = "databases_inside_home" if inside else "databases_outside_home"
            self._count(table, self._show(text) if text != ":memory:" else text)

    def _on_socket(self, event: str, args: tuple[object, ...]) -> None:
        sock = args[0] if args else None
        family = getattr(getattr(sock, "family", None), "name", "?")
        address = args[1] if len(args) > 1 else None
        if family in ("AF_INET", "AF_INET6") and isinstance(address, tuple) and address:
            shown = f"{family} {address[0]}"
        else:
            shown = family
        table = "sockets_bound" if event == "socket.bind" else "sockets_connected"
        with self._lock:
            self._count(table, shown)

    # --- layer 2: the seam tripwires -------------------------------------------------

    def _tripwire(self, owner: str, name: str) -> Callable[..., Any]:
        label = f"{owner}.{name}"

        def refused(_self: object, *args: object, **kwargs: object) -> None:
            detail: dict[str, object] = {"call": label}
            if name == "run" and args and isinstance(args[0], list | tuple) and args[0]:
                detail["program"] = os.path.basename(_text(args[0][0])).lower()
                detail["options"] = _options(args[0])
            with self._lock:
                calls: list[dict[str, object]] = self.state["seam_calls"]
                if len(calls) < _MAX_ITEMS:
                    calls.append(detail)
            raise Refused(f"flight recorder: {label} refused")

        refused.__name__ = name
        return refused

    def arm_seams(self) -> None:
        """Replace every mutating method of the real seams. A name that no longer exists
        is listed under ``missing``, so that a renamed seam fails the test loudly instead
        of leaving a hole."""
        import portlock.guard.seams as seams
        import portlock.scan.av as av

        for owner, methods in _SEAM_PLAN.items():
            cls = getattr(seams, owner, None)
            for method in methods:
                label = f"guard.seams.{owner}.{method}"
                if cls is None or not callable(getattr(cls, method, None)):
                    self.state["missing"].append(label)
                    continue
                setattr(cls, method, self._tripwire(owner, method))
                self.state["armed"].append(label)
        runner = getattr(av, "SubprocessRunner", None)
        if runner is None or not callable(getattr(runner, "run", None)):
            self.state["missing"].append("scan.av.SubprocessRunner.run")
        else:
            runner.run = self._tripwire("scan.av.SubprocessRunner", "run")
            self.state["armed"].append("scan.av.SubprocessRunner.run")

    # --- the report ------------------------------------------------------------------

    def write(self) -> None:
        self._local.busy = True
        try:
            with self._lock:
                self.state["writes"] += 1
                snapshot = json.dumps(self.state, indent=1, sort_keys=True, default=str)
            temporary = self._report + ".tmp"
            with contextlib.suppress(OSError):
                with open(temporary, "w", encoding="utf-8") as handle:
                    handle.write(snapshot)
                os.replace(temporary, self._report)
        finally:
            self._local.busy = False

    def keep_writing(self) -> None:
        while True:
            time.sleep(1.0)
            self.write()


def main() -> int:
    sys.dont_write_bytecode = True
    recorder = Recorder(os.environ[REPORT_ENV], os.environ[HOME_ENV])
    sys.addaudithook(recorder.hook)
    threading.Thread(target=recorder.keep_writing, name="flight-recorder", daemon=True).start()
    code: object = None
    try:
        recorder.arm_seams()
        # A report exists from the start: a process killed within its first second (a
        # fast machine) must not leave none at all.
        recorder.write()
        from portlock.console.cli import main as portlock_main

        code = portlock_main(sys.argv[1:])
    except SystemExit as exc:
        code = exc.code
    except BaseException as exc:
        recorder.state["exit"] = f"{type(exc).__name__}: {exc}"
        recorder.write()
        raise
    recorder.state["exit"] = code
    recorder.write()
    if isinstance(code, int):
        return code
    return 0 if code is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
