from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from typing import Sequence


SW_SHOWNORMAL = 1


def relaunch_elevated(argv: Sequence[str], *, cwd: str | None = None) -> bool:
    """Request an elevated replacement process.

    Returns True only when Windows accepted the launch. A rejected UAC prompt
    or any launch failure returns False so the caller can continue normally.
    """

    command = [str(item) for item in argv if str(item)]
    if sys.platform != "win32" or not command or is_process_elevated():
        return False
    parameters = subprocess.list2cmdline(command[1:]) if len(command) > 1 else None
    return _shell_execute_runas(command[0], parameters, cwd) > 32


def is_process_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        check = shell32.IsUserAnAdmin
        check.argtypes = []
        check.restype = wintypes.BOOL
        return bool(check())
    except (AttributeError, OSError):
        return False


def _shell_execute_runas(executable: str, parameters: str | None, cwd: str | None) -> int:
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        execute = shell32.ShellExecuteW
        execute.argtypes = [
            wintypes.HWND,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_int,
        ]
        execute.restype = ctypes.c_ssize_t
        return int(
            execute(
                None,
                "runas",
                os.path.abspath(executable),
                parameters,
                cwd,
                SW_SHOWNORMAL,
            )
            or 0
        )
    except (AttributeError, OSError, ValueError):
        return 0
