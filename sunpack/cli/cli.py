import argparse
import contextlib
import os
import sys

from sunpack.cli.cli_commands import command_map, discover_command_modules
from sunpack.cli.cli_constants import EXIT_OK, EXIT_RUNTIME, EXIT_USAGE
from sunpack.cli.cli_context import (
    CliContext,
)
from sunpack.config.cli_settings import DEFAULT_CLI_LANG, load_cli_language_from_config
from sunpack.cli.cli_parsers import (
    CliHelpFormatter,
    localize_help_action,
)
from sunpack.cli.cli_reporter import CliReporter
from sunpack.cli.cli_types import CliCommandResult

CURRENT_CLI_LANG = DEFAULT_CLI_LANG
_PARSER_CACHE: dict[str, argparse.ArgumentParser] = {}


def configure_stdio_encoding():
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
        description=ctx.t("cli.description"),
        usage=ctx.t("cli.usage"),
        epilog=(
            f"{ctx.t('cli.examples')}\n"
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


def cached_cli_parser(ctx: CliContext) -> argparse.ArgumentParser:
    parser = _PARSER_CACHE.get(ctx.language)
    if parser is None:
        parser = build_cli_parser(ctx)
        _PARSER_CACHE[ctx.language] = parser
    elif ctx.commands is None:
        ctx.commands = command_map()
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
            errors=[ctx.t("cli.unknown_command", command=command)],
        )
    return module.handle(args, ctx)


def maybe_pause(args, ctx: CliContext, exit_code: int, result: CliCommandResult):
    successful_extract = (
        getattr(args, "command", "") == "extract"
        and exit_code == EXIT_OK
        and not result.errors
    )
    if getattr(args, "pause_on_exit", False) and not successful_extract:
        print(ctx.t("cli.pause_prompt"), flush=True)
        os.system("pause >nul")


def main(argv=None):
    global CURRENT_CLI_LANG
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in {"--reuse", "--persistent-shutdown"}:
        from sunpack.cli.persistent_process import handle_early_argv

        result = handle_early_argv(list(argv))
        if result is not None:
            return result

    configure_stdio_encoding()
    argv = preprocess_sys_argv(argv)
    CURRENT_CLI_LANG = load_cli_language_from_config()
    ctx = CliContext(language=CURRENT_CLI_LANG)
    parser = cached_cli_parser(ctx)
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
    if args.json and getattr(args, "prompt_passwords", False):
        result = CliCommandResult(
            command=getattr(args, "command", ""),
            inputs={"argv": argv},
            summary={},
            errors=[ctx.t("cli.json_password_prompt_unavailable")],
        )
        reporter.emit_result(result)
        return EXIT_USAGE
    if args.json:
        args.pause_on_exit = False
    try:
        if args.json:
            with contextlib.redirect_stdout(sys.stderr):
                exit_code, result = dispatch_command(args, ctx)
        else:
            exit_code, result = dispatch_command(args, ctx)
    except Exception as exc:
        reporter.error(ctx.t("cli.runtime_failure", error=exc))
        result = CliCommandResult(
            command=getattr(args, "command", ""),
            inputs={"argv": argv},
            summary={},
            errors=[str(exc)],
        )
        reporter.emit_result(result)
        maybe_pause(args, ctx, EXIT_RUNTIME, result)
        return EXIT_RUNTIME

    reporter.emit_result(result)
    maybe_pause(args, ctx, exit_code, result)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
