"""Whether this process runs with administrator (Windows) or root (POSIX) rights.

This is a read-only question to the operating system: on Windows it asks
``shell32.IsUserAnAdmin``, on POSIX it compares the effective user id with 0. It lives in
``core`` so that the configuration defaults (``core.config``) and the guard layer can share
one answer without the configuration importing the guard.
"""

from __future__ import annotations

import ctypes
import os
import sys

__all__ = ["process_elevated"]

# Restrict the DLL search to System32: a privileged agent must not load a planted DLL.
_SEARCH_SYSTEM32 = 0x00000800


def process_elevated() -> bool:
    """True if this process runs as root (POSIX) or as an administrator (Windows).

    Never raises: anything that prevents the question from being answered counts as
    "not elevated", the answer that grants nothing.
    """
    if sys.platform == "win32":
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            return False
        try:
            shell32 = loader("shell32.dll", use_last_error=True, winmode=_SEARCH_SYSTEM32)
            return bool(shell32.IsUserAnAdmin())
        except (OSError, AttributeError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0
