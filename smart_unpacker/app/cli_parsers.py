import argparse

from smart_unpacker.app.cli_constants import SCHEDULER_PROFILES
from smart_unpacker.app.cli_context import CliContext
from smart_unpacker.app.cli_values import parse_archive_cleanup_value, parse_recursive_extract_value


class CliHelpFormatter(argparse.RawDescriptionHelpFormatter):
    language = "en"

    def __init__(self, prog: str):
        super().__init__(prog, max_help_position=44, width=120)

    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None and self.language == "zh":
            prefix = "用法: "
        return super().add_usage(usage, actions, groups, prefix)

    def start_section(self, heading):
        if self.language == "zh":
            heading = {
                "positional arguments": "位置参数",
                "options": "选项",
            }.get(heading, heading)
        return super().start_section(heading)


def localize_help_action(parser: argparse.ArgumentParser, ctx: CliContext):
    if ctx.language != "zh":
        return
    for action in parser._actions:
        if "-h" in getattr(action, "option_strings", []):
            action.help = "显示此帮助信息并退出"


def build_common_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-j", "--json", action="store_true", help=ctx.core_text("json"))
    parser.add_argument("-q", "--quiet", action="store_true", help=ctx.core_text("quiet"))
    parser.add_argument("-v", "--verbose", action="store_true", help=ctx.core_text("verbose"))
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help=ctx.core_text("color"))
    pause_group = parser.add_mutually_exclusive_group()
    pause_group.add_argument("--no-pause", action="store_true", help=ctx.core_text("no_pause"))
    pause_group.add_argument("--pause", dest="pause_on_exit", action="store_true", help=ctx.core_text("pause"))
    return parser


def build_json_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-j", "--json", action="store_true", help=ctx.core_text("json"))
    return parser


def build_config_output_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = build_json_parser(ctx)
    parser.add_argument("-q", "--quiet", action="store_true", help=ctx.core_text("quiet"))
    return parser


def build_password_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", "--password", action="append", default=[], help=ctx.core_text("password"))
    parser.add_argument("--pw-file", dest="password_file", help=ctx.core_text("password_file"))
    parser.add_argument("--ask-pw", dest="prompt_passwords", action="store_true", help=ctx.core_text("prompt_passwords"))
    parser.add_argument("--no-builtin-pw", dest="no_builtin_passwords", action="store_true", help=ctx.core_text("no_builtin_passwords"))
    return parser


def build_extract_config_override_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--recur", dest="recursive_extract", type=parse_recursive_extract_value, help=ctx.core_text("recursive_extract"))
    parser.add_argument("--sched", dest="scheduler_profile", choices=sorted(SCHEDULER_PROFILES), help=ctx.core_text("scheduler_profile"))
    parser.add_argument("--cleanup", dest="archive_cleanup_mode", type=parse_archive_cleanup_value, help=ctx.core_text("archive_cleanup_mode"))
    parser.add_argument("-o", "--out-dir", dest="output_dir", help=ctx.core_text("output_dir"))
    flatten_group = parser.add_mutually_exclusive_group()
    flatten_group.add_argument("--flatten", dest="flatten_single_directory", action="store_true", default=None, help=ctx.core_text("flatten"))
    flatten_group.add_argument("--no-flatten", dest="flatten_single_directory", action="store_false", help=ctx.core_text("no_flatten"))
    return parser
