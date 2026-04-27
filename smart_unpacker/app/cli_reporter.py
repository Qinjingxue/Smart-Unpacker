import os
import sys
from dataclasses import asdict

from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.support.json_format import to_json_text


RESET = "\033[0m"
COLORS = {
    "info": "\033[36m",
    "detail": "\033[90m",
    "error": "\033[31m",
}


class CliReporter:
    def __init__(self, json_mode: bool = False, quiet: bool = False, verbose: bool = False, color: str = "auto"):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose
        self.color = color
        self.use_color = self._should_use_color(color)
        self.logs: list[str] = []

    def info(self, message: str):
        if not self.json_mode and not self.quiet:
            print(self._style(message, "info"), flush=True)

    def detail(self, message: str):
        if not self.json_mode and self.verbose and not self.quiet:
            print(self._style(message, "detail"), flush=True)

    def error(self, message: str):
        if not self.json_mode:
            print(self._style(message, "error"), file=sys.stderr, flush=True)

    def emit_result(self, result: CliCommandResult):
        if self.json_mode:
            print(to_json_text(asdict(result)), flush=True)

    def _style(self, message: str, role: str) -> str:
        if not self.use_color:
            return message
        color = COLORS.get(role)
        if not color:
            return message
        return f"{color}{message}{RESET}"

    def _should_use_color(self, mode: str) -> bool:
        if self.json_mode or mode == "never" or os.environ.get("NO_COLOR") is not None:
            return False
        if mode == "always":
            return _enable_windows_virtual_terminal()
        return _stream_supports_color(sys.stdout) and _enable_windows_virtual_terminal()


def _stream_supports_color(stream) -> bool:
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _enable_windows_virtual_terminal() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        enabled = True
        for handle_id in (-11, -12):
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                continue
            enabled = bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004)) and enabled
        return enabled
    except Exception:
        return False
