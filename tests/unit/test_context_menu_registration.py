import ctypes
import json
import ntpath
import os
import subprocess
from ctypes import wintypes
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows context-menu contract")


def test_context_menu_commands_are_safe_for_drive_roots_and_keep_password_flag():
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "register_context_menu.ps1"
    executable = repo / "dist" / "sunpack-x64-lite" / "sunpack.exe"
    if not executable.exists():
        executable = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"))

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-AppPath",
            str(executable),
            "-DryRun",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
    )
    commands = json.loads(completed.stdout.strip().splitlines()[-1])

    for key in ("folder_prompt", "background_prompt"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == "D:\\"
        assert ntpath.normpath(argv[argv.index("--out-dir") + 1]) == "D:\\"
        assert "--ask-pw" in argv
        assert "--pause" in argv


def test_context_menu_directory_token_is_stable_for_normal_paths():
    command = 'sunpack.exe extract "%V\\." --out-dir "%V\\." --ask-pw --pause'
    argv = _windows_argv(command.replace("%V", r"D:\Archives"))

    assert ntpath.normpath(argv[2]) == r"D:\Archives"
    assert ntpath.normpath(argv[4]) == r"D:\Archives"
    assert argv[5:] == ["--ask-pw", "--pause"]


def _windows_argv(command: str) -> list[str]:
    parse = ctypes.windll.shell32.CommandLineToArgvW
    parse.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(wintypes.LPWSTR)
    argc = ctypes.c_int()
    argv = parse(command, ctypes.byref(argc))
    try:
        return [argv[index] for index in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)
