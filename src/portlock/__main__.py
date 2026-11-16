"""``python -m portlock``: the same program as the ``portlock`` command.

The dead-man timer runs ``python -I -m portlock recover --config <file>``, so this entry
point must work without the ``portlock`` script on the path.
"""

from __future__ import annotations

from portlock.console.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
