from __future__ import annotations

import os
import tempfile
from pathlib import Path

from sunpack.support.runtime_identity import runtime_id


def runtime_working_directory() -> str:
    """Return a process cwd that cannot pin an input, output, or install directory."""
    # Packaged processes receive the opaque namespace from the native
    # launcher. Direct source execution uses a deliberately separate fixed
    # namespace and never participates in the packaged persistent protocol.
    identity = runtime_id() or "direct"
    root = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "SunPack" / "runtime-cwd"
    target = root / identity
    target.mkdir(parents=True, exist_ok=True)
    return str(target)
