from __future__ import annotations

import sys
from pathlib import Path


def current_process_executable() -> Path:
    """Return the executable image that owns the current process."""
    if (getattr(sys, "frozen", False) or "__compiled__" in globals()) and sys.argv:
        return Path(sys.argv[0]).resolve()
    return Path(sys.executable).resolve()
