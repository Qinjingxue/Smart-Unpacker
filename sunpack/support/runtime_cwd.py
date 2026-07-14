from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path


def runtime_working_directory() -> str:
    """Return a process cwd that cannot pin an input, output, or install directory."""
    executable_dir = os.path.normcase(os.path.dirname(os.path.abspath(sys.executable)))
    identity = hashlib.sha256(executable_dir.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    root = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "SunPack" / "runtime-cwd"
    target = root / identity
    target.mkdir(parents=True, exist_ok=True)
    return str(target)
