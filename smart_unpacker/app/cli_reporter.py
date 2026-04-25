import sys
from dataclasses import asdict

from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.support.json_format import to_json_text


class CliReporter:
    def __init__(self, json_mode: bool = False, quiet: bool = False, verbose: bool = False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose
        self.logs: list[str] = []

    def info(self, message: str):
        if not self.json_mode and not self.quiet:
            print(message, flush=True)

    def detail(self, message: str):
        if not self.json_mode and self.verbose and not self.quiet:
            print(message, flush=True)

    def error(self, message: str):
        if not self.json_mode:
            print(message, file=sys.stderr, flush=True)

    def emit_result(self, result: CliCommandResult):
        if self.json_mode:
            print(to_json_text(asdict(result)), flush=True)
