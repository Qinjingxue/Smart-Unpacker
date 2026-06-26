from __future__ import annotations

import sys
from pathlib import Path
import winreg


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "SunPackWatchService"


def startup_command() -> str:
    executable = Path(sys.executable).resolve()
    repo_script = Path(__file__).resolve().parents[3] / "sunpack.py"
    if executable.name.lower() == "python.exe" and repo_script.exists():
        return f'"{executable}" "{repo_script}" watch start'
    return f'"{executable}" watch start'


def enable_startup(command: str | None = None) -> str:
    command = command or startup_command()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    return command


def disable_startup() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def startup_status() -> tuple[bool, str]:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
        return True, str(value)
    except FileNotFoundError:
        return False, ""
