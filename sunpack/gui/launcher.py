from __future__ import annotations

import sys
from pathlib import Path

from sunpack.support.runtime_identity import runtime_id, runtime_id_argument
from sunpack.support.runtime_mode import RUNTIME_MODE_WATCH, runtime_mode_argument


RUNTIME_EXECUTABLE_NAME = "sunpack-runtime.exe"


def packaged_runtime_executable(executable: str | Path | None = None) -> Path | None:
    current = Path(executable or sys.executable).resolve()
    candidate = current.parent / RUNTIME_EXECUTABLE_NAME
    return candidate if candidate.is_file() else None


def watch_launch_argv(
    *,
    once: bool = False,
    no_tray: bool = False,
    initial_scan: bool = False,
    prefer_windowed_python: bool = False,
) -> list[str]:
    packaged = packaged_runtime_executable()
    if packaged is not None:
        argv = [str(packaged), runtime_mode_argument(RUNTIME_MODE_WATCH)]
    else:
        executable = Path(sys.executable).resolve()
        if prefer_windowed_python and executable.name.lower() == "python.exe":
            pythonw = executable.with_name("pythonw.exe")
            if pythonw.is_file():
                executable = pythonw
        argv = [str(executable), "-m", "sunpack.gui"]
    if runtime_id() is not None:
        argv.append(runtime_id_argument())
    if once:
        argv.append("--once")
    if no_tray:
        argv.append("--no-tray")
    if initial_scan:
        argv.append("--initial-scan")
    return argv
