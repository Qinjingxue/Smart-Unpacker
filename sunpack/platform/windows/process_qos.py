from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes


BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000


def enter_background_processing() -> str:
    """Apply Windows background processing to the current process.

    Background mode lowers CPU, disk I/O, and memory scheduling priority while
    retaining the ability to consume idle resources. Below-normal is used only
    when the full background mode is unavailable.
    """

    if sys.platform != "win32":
        return "unsupported"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        current_process = kernel32.GetCurrentProcess
        current_process.argtypes = []
        current_process.restype = wintypes.HANDLE
        set_priority_class = kernel32.SetPriorityClass
        set_priority_class.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        set_priority_class.restype = wintypes.BOOL
        process = current_process()
        if set_priority_class(process, PROCESS_MODE_BACKGROUND_BEGIN):
            return "background"
        if set_priority_class(process, BELOW_NORMAL_PRIORITY_CLASS):
            return "below_normal"
    except (AttributeError, OSError):
        pass
    return "unavailable"
