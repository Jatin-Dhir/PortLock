"""Filesystem helpers for state that must not be half-written or world-readable."""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

__all__ = ["atomic_write_bytes", "atomic_write_text", "ensure_private_dir", "restrict_to_owner"]


def ensure_private_dir(path: str | os.PathLike[str]) -> Path:
    """Create a directory (and parents) that only its owner can enter.

    On POSIX the directory is created with mode 0700 and an existing directory is
    tightened to that mode. On Windows permissions come from the parent directory's
    access control list; ``docs/OPERATIONS.md`` describes the ACL the installer sets on
    the state directory.
    """
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            directory.chmod(0o700)
    return directory


def restrict_to_owner(path: str | os.PathLike[str]) -> None:
    """Make a file readable and writable by its owner only (POSIX mode 0600).

    A no-op on Windows, where the file inherits the state directory's ACL.
    """
    if sys.platform != "win32":
        Path(path).chmod(0o600)


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes, *, private: bool = True) -> None:
    """Replace a file's contents so that a reader sees the old or the new, never a mix.

    Writes to a temporary file in the same directory, flushes it to disk, then renames it
    over the target. A crash at any point leaves either the previous file or the new one.

    Args:
        path: the file to write.
        data: the complete new contents.
        private: restrict the file to its owner before it becomes visible under ``path``.
    """
    target = Path(path)
    handle, temp_name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if private:
            restrict_to_owner(temp_name)
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    _sync_directory(target.parent)


def atomic_write_text(path: str | os.PathLike[str], text: str, *, private: bool = True) -> None:
    """:func:`atomic_write_bytes` for UTF-8 text. Newlines are written as given."""
    atomic_write_bytes(path, text.encode("utf-8"), private=private)


def _sync_directory(directory: Path) -> None:
    """Flush a directory entry so a rename survives power loss. Not possible on Windows."""
    if sys.platform == "win32":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
