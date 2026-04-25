import argparse
import os
import sys

from smart_unpacker.app.cli_commands import command_map, discover_command_modules
from smart_unpacker.app.cli_constants import EXIT_OK, EXIT_RUNTIME, EXIT_USAGE
from smart_unpacker.app.cli_context import (
    CliContext,
)
from smart_unpacker.config.cli_settings import DEFAULT_CLI_LANG, load_cli_language_from_config, normalize_cli_language
from smart_unpacker.app.cli_parsers import (
    CliHelpFormatter,
    localize_help_action,
)
from smart_unpacker.app.cli_reporter import CliReporter
from smart_unpacker.app.cli_types import CliCommandResult

CURRENT_CLI_LANG = DEFAULT_CLI_LANG


def configure_stdio_fallback():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass


def preprocess_sys_argv(argv: list[str]) -> list[str]:
    cleaned = []
    for arg in argv:
        if isinstance(arg, str) and arg.endswith('"'):
            path = arg[:-1]
            if path.endswith("\\"):
                path = path[:-1]
            cleaned.append(path)
        else:
            cleaned.append(arg)
    return cleaned


def build_cli_parser(ctx: CliContext | None = None) -> argparse.ArgumentParser:
    ctx = ctx or CliContext(language=CURRENT_CLI_LANG)
    CliHelpFormatter.language = ctx.language
    modules = discover_command_modules()
    ctx.commands = command_map(modules)

    parser = argparse.ArgumentParser(
        description=ctx.core_text("description"),
        usage=ctx.core_text("usage"),
        epilog=(
            "Examples:\n"
            "  sunpack extract C:\\Archives\n"
            "  sunpack inspect .\\fixtures\n"
            "  sunpack passwords --ask-pw"
        ),
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=argparse.ArgumentParser)
    for module in modules:
        module.register(subparsers, ctx)
    return parser


def dispatch_command(args, ctx: CliContext) -> tuple[int, CliCommandResult]:
    if ctx.commands is None:
        ctx.commands = command_map()
    module = ctx.commands.get(getattr(args, "command", None))
    if module is None:
        command = getattr(args, "command", "")
        return EXIT_USAGE, CliCommandResult(
            command="",
            inputs={},
            summary={},
            errors=[ctx.core_text("unknown_command").format(command=command)],
        )
    return module.handle(args, ctx)


def maybe_pause(args, ctx: CliContext):
    if getattr(args, "pause_on_exit", False):
        print(ctx.core_text("pause_prompt"), flush=True)
        os.system("pause >nul" if os.name == "nt" else "read -n 1 -s")


def main(argv=None):
    global CURRENT_CLI_LANG
    if argv is None:
        argv = sys.argv[1:]

    configure_stdio_fallback()
    argv = preprocess_sys_argv(argv)
    CURRENT_CLI_LANG = load_cli_language_from_config()
    ctx = CliContext(language=CURRENT_CLI_LANG)
    parser = build_cli_parser(ctx)
    if not argv:
        parser.print_help()
        return EXIT_OK
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    args.json = bool(getattr(args, "json", False) or "-j" in argv or "--json" in argv)
    args.quiet = bool(getattr(args, "quiet", False) or "-q" in argv or "--quiet" in argv)
    args.verbose = bool(getattr(args, "verbose", False) or "-v" in argv or "--verbose" in argv)
    args.pause_on_exit = bool(getattr(args, "pause_on_exit", False) or "--pause" in argv)

    reporter = CliReporter(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)
    ctx.reporter = reporter
    try:
        exit_code, result = dispatch_command(args, ctx)
    except Exception as exc:
        reporter.error(ctx.core_text("runtime_failure").format(error=exc))
        result = CliCommandResult(
            command=getattr(args, "command", ""),
            inputs={"argv": argv},
            summary={},
            errors=[str(exc)],
        )
        reporter.emit_result(result)
        maybe_pause(args, ctx)
        return EXIT_RUNTIME

    reporter.emit_result(result)
    maybe_pause(args, ctx)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
