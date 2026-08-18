from __future__ import annotations

import sys
from pathlib import Path

from sunpack.support.runtime_cwd import runtime_working_directory

from sunpack.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.cli.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.cli.cli_types import CliCommandResult
from sunpack.cli.persistent_runtime import load_request_config
from sunpack.filesystem.watcher.service import (
    add_watch_roots,
    is_watch_lock_active,
    list_watch_roots,
    remove_watch_roots,
    service_state_dir,
    signal_reload,
    signal_stop,
)


COMMAND = "watch"
ORDER = 15


def register(subparsers, ctx):
    common = build_common_parser(ctx)
    parser = subparsers.add_parser(
        COMMAND,
        parents=[common],
        help=ctx.t("cli.watch.help"),
        usage="sunpack watch <add|remove|list|start|stop|reload|status|startup> [options]",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    actions = parser.add_subparsers(dest="watch_action", required=True)

    start_parser = actions.add_parser("start", parents=[common], help=ctx.t("cli.watch.start"), formatter_class=CliHelpFormatter)
    start_parser.add_argument("--once", action="store_true", help=ctx.t("cli.watch.once"))
    start_parser.add_argument("--no-tray", action="store_true", help=ctx.t("cli.watch.no_tray"))

    add_parser = actions.add_parser("add", parents=[common], help=ctx.t("cli.watch.add"), formatter_class=CliHelpFormatter)
    add_parser.add_argument("paths", nargs="+", help=ctx.t("cli.watch.paths"))
    add_parser.add_argument("--start", action="store_true", help=ctx.t("cli.watch.start_after_add"))

    remove_parser = actions.add_parser("remove", parents=[common], help=ctx.t("cli.watch.remove"), formatter_class=CliHelpFormatter)
    remove_parser.add_argument("paths", nargs="+", help=ctx.t("cli.watch.paths"))

    actions.add_parser("list", parents=[common], help=ctx.t("cli.watch.list"), formatter_class=CliHelpFormatter)
    actions.add_parser("reload", parents=[common], help=ctx.t("cli.watch.reload"), formatter_class=CliHelpFormatter)
    actions.add_parser("stop", parents=[common], help=ctx.t("cli.watch.stop"), formatter_class=CliHelpFormatter)
    actions.add_parser("status", parents=[common], help=ctx.t("cli.watch.status"), formatter_class=CliHelpFormatter)

    startup_parser = actions.add_parser("startup", parents=[common], help=ctx.t("cli.watch.startup"), formatter_class=CliHelpFormatter)
    startup_parser.add_argument("startup_action", choices=["enable", "disable", "status"])


async def handle(args, ctx):
    try:
        action = args.watch_action
        if action == "start":
            return await _handle_start(args, ctx)
        if action == "add":
            return _handle_add(args, ctx)
        if action == "remove":
            return _handle_remove(args, ctx)
        if action == "list":
            return _handle_list()
        if action == "reload":
            return _handle_reload(ctx)
        if action == "stop":
            return _handle_stop(ctx)
        if action == "status":
            return _handle_status(ctx)
        if action == "startup":
            return _handle_startup(args)
    except Exception as exc:
        return EXIT_TASK_FAILED, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[str(exc)])
    return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.watch.unknown_action", action=action)])


async def _handle_start(args, ctx):
    if _request_watch_elevation(args):
        return 0, CliCommandResult(
            command=COMMAND,
            inputs={"action": "start"},
            summary={"elevated_relaunch": True},
        )
    from sunpack.coordinator.watch_runtime import run_watch_service

    code = await run_watch_service(
        tray_enabled=not bool(getattr(args, "no_tray", False)),
        once=bool(getattr(args, "once", False)),
    )
    if code == 2:
        return EXIT_TASK_FAILED, CliCommandResult(
            command=COMMAND,
            inputs={"action": "start"},
            summary={"running": True},
            errors=[ctx.t("cli.watch.already_running")],
        )
    return code, CliCommandResult(command=COMMAND, inputs={"action": "start"}, summary={"exit_code": code})


def _handle_add(args, ctx):
    roots_path, added = add_watch_roots(list(args.paths or []))
    config = load_request_config(ctx.cwd)
    reload_event = signal_reload(config)
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "add", "paths": list(args.paths or [])},
        summary={
            "roots_path": str(roots_path),
            "added": added,
            "reload_event": reload_event,
            "start_requested": bool(getattr(args, "start", False)),
        },
        items=added,
    )


def _handle_remove(args, ctx):
    roots_path, removed = remove_watch_roots(list(args.paths or []))
    reload_event = signal_reload(load_request_config(ctx.cwd))
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "remove", "paths": list(args.paths or [])},
        summary={"roots_path": str(roots_path), "removed": removed, "reload_event": reload_event},
        items=removed,
    )


def _handle_list():
    roots_path, roots = list_watch_roots()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "list"},
        summary={"roots_path": str(roots_path), "count": len(roots)},
        items=roots,
    )


def _handle_reload(ctx):
    path = signal_reload(load_request_config(ctx.cwd))
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "reload"}, summary={"reload_event": path})


def _handle_stop(ctx):
    path = signal_stop(load_request_config(ctx.cwd))
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "stop"}, summary={"stop_event": path})


def _handle_status(ctx):
    config = load_request_config(ctx.cwd)
    _, roots = list_watch_roots()
    running = _watch_running(config)
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "status"},
        summary={"running": running, "count": len(roots), "state_dir": service_state_dir(config)},
        items=roots,
    )


def _handle_startup(args):
    from sunpack.platform.windows.startup import disable_startup, enable_startup, startup_status

    if args.startup_action == "enable":
        command = enable_startup()
        return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "enable"}, summary={"enabled": True, "command": command})
    if args.startup_action == "disable":
        changed = disable_startup()
        return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "disable"}, summary={"enabled": False, "changed": changed})
    enabled, command = startup_status()
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "status"}, summary={"enabled": enabled, "command": command})


def _watch_running(config: dict) -> bool:
    return is_watch_lock_active(config)


def _request_watch_elevation(args) -> bool:
    from sunpack.platform.windows.elevation import relaunch_elevated

    return relaunch_elevated(
        _watch_cli_start_argv(args),
        cwd=runtime_working_directory(),
    )


def _watch_cli_start_argv(args) -> list[str]:
    command = ["watch", "start"]
    if bool(getattr(args, "once", False)):
        command.append("--once")
    if bool(getattr(args, "no_tray", False)):
        command.append("--no-tray")
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), *command]
    entry = Path(__file__).resolve().parents[3] / "sunpack.py"
    if entry.is_file():
        return [str(Path(sys.executable).resolve()), str(entry), *command]
    return [str(Path(sys.executable).resolve()), "-m", "sunpack", *command]
