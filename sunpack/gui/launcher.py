from __future__ import annotations

import sys
from pathlib import Path


WATCH_EXECUTABLE_NAME = "sunpack-watch.exe"


def packaged_watch_executable(executable: str | Path | None = None) -> Path | None:
    current = Path(executable or sys.executable).resolve()
    candidate = current.parent / WATCH_EXECUTABLE_NAME
    return candidate if candidate.is_file() else None


def watch_launch_argv(*, prefer_windowed_python: bool = False) -> list[str]:
    packaged = packaged_watch_executable()
    if packaged is not None:
        return [str(packaged)]
    executable = Path(sys.executable).resolve()
    if prefer_windowed_python and executable.name.lower() == "python.exe":
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.is_file():
            executable = pythonw
    return [str(executable), "-m", "sunpack.gui"]
