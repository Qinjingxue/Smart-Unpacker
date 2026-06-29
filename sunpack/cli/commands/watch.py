from __future__ import annotations

import subprocess

from sunpack.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.cli.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.cli.cli_types import CliCommandResult
from sunpack.config.loader import load_config
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


def handle(args, ctx):
    try:
        action = args.watch_action
        if action == "start":
            return _handle_start(args, ctx)
        if action == "add":
            return _handle_add(args)
        if action == "remove":
            return _handle_remove(args)
        if action == "list":
            return _handle_list()
        if action == "reload":
            return _handle_reload()
        if action == "stop":
            return _handle_stop()
        if action == "status":
            return _handle_status()
        if action == "startup":
            return _handle_startup(args)
    except Exception as exc:
        return EXIT_TASK_FAILED, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[str(exc)])
    return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.watch.unknown_action", action=action)])


def _handle_start(args, ctx):
    from sunpack.coordinator.watch_runtime import run_watch_service

    code = run_watch_service(
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


def _handle_add(args):
    roots_path, added = add_watch_roots(list(args.paths or []))
    config = load_config()
    reload_event = signal_reload(config)
    started = False
    if getattr(args, "start", False) and not _watch_running(config):
        started = _start_watch_background()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "add", "paths": list(args.paths or [])},
        summary={"roots_path": str(roots_path), "added": added, "reload_event": reload_event, "started": started},
        items=added,
    )


def _handle_remove(args):
    roots_path, removed = remove_watch_roots(list(args.paths or []))
    reload_event = signal_reload(load_config())
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


def _handle_reload():
    path = signal_reload(load_config())
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "reload"}, summary={"reload_event": path})


def _handle_stop():
    path = signal_stop(load_config())
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "stop"}, summary={"stop_event": path})


def _handle_status():
    config = load_config()
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


def _start_watch_background() -> bool:
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    subprocess.Popen(
        _watch_start_argv(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        startupinfo=startupinfo,
        close_fds=True,
    )
    return True


def _watch_start_argv() -> list[str]:
    from sunpack.gui.launcher import watch_launch_argv

    return watch_launch_argv()
