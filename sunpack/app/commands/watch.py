from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sunpack.app.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.app.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.app.cli_types import CliCommandResult
from sunpack.config.loader import load_config
from sunpack.coordinator.runner import PipelineRunner
from sunpack.filesystem.watcher.service import (
    SERVICE_LOCK,
    WatchService,
    add_watch_roots,
    list_watch_roots,
    remove_watch_roots,
    service_state_dir,
    signal_reload,
    signal_stop,
)


COMMAND = "watch"
ORDER = 15
TEXTS = {
    "en": {
        "help": "Manage persistent watched folders and the background watcher.",
        "start": "Start the background watcher.",
        "add": "Add watched folders.",
        "remove": "Remove watched folders.",
        "list": "List watched folders.",
        "reload": "Reload the running watcher.",
        "stop": "Stop the running watcher.",
        "status": "Show watcher status.",
        "startup": "Manage Windows startup registration.",
        "paths": "Folders to add or remove.",
        "start_after_add": "Start the watcher after adding folders.",
        "once": "Run one watcher pass and exit.",
        "no_tray": "Run without a Windows tray icon.",
    },
    "zh": {
        "help": "管理持久监控目录和后台 watch。",
        "start": "启动后台 watch。",
        "add": "添加监控目录。",
        "remove": "移除监控目录。",
        "list": "列出监控目录。",
        "reload": "重新加载运行中的 watch。",
        "stop": "停止运行中的 watch。",
        "status": "查看 watch 状态。",
        "startup": "管理 Windows 开机自启动。",
        "paths": "要添加或移除的目录。",
        "start_after_add": "添加目录后启动 watch。",
        "once": "只运行一轮 watch 后退出。",
        "no_tray": "运行时不显示 Windows 托盘图标。",
    },
}


def register(subparsers, ctx):
    common = build_common_parser(ctx)
    parser = subparsers.add_parser(
        COMMAND,
        parents=[common],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack watch <add|remove|list|start|stop|reload|status|startup> [options]",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    actions = parser.add_subparsers(dest="watch_action", required=True)

    start_parser = actions.add_parser("start", parents=[common], help=ctx.t(TEXTS, "start"), formatter_class=CliHelpFormatter)
    start_parser.add_argument("--once", action="store_true", help=ctx.t(TEXTS, "once"))
    start_parser.add_argument("--no-tray", action="store_true", help=ctx.t(TEXTS, "no_tray"))

    add_parser = actions.add_parser("add", parents=[common], help=ctx.t(TEXTS, "add"), formatter_class=CliHelpFormatter)
    add_parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))
    add_parser.add_argument("--start", action="store_true", help=ctx.t(TEXTS, "start_after_add"))

    remove_parser = actions.add_parser("remove", parents=[common], help=ctx.t(TEXTS, "remove"), formatter_class=CliHelpFormatter)
    remove_parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))

    actions.add_parser("list", parents=[common], help=ctx.t(TEXTS, "list"), formatter_class=CliHelpFormatter)
    actions.add_parser("reload", parents=[common], help=ctx.t(TEXTS, "reload"), formatter_class=CliHelpFormatter)
    actions.add_parser("stop", parents=[common], help=ctx.t(TEXTS, "stop"), formatter_class=CliHelpFormatter)
    actions.add_parser("status", parents=[common], help=ctx.t(TEXTS, "status"), formatter_class=CliHelpFormatter)

    startup_parser = actions.add_parser("startup", parents=[common], help=ctx.t(TEXTS, "startup"), formatter_class=CliHelpFormatter)
    startup_parser.add_argument("startup_action", choices=["enable", "disable", "status"])


def handle(args, ctx):
    try:
        action = args.watch_action
        if action == "start":
            return _handle_start(args)
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
    return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[f"Unknown watch action: {action}"])


def _handle_start(args):
    tray_factory = None
    if not getattr(args, "no_tray", False) and not getattr(args, "once", False) and os.name == "nt":
        from sunpack.platform.windows.tray import WindowsTrayIcon

        tray_factory = WindowsTrayIcon
    service = WatchService(runner_factory=PipelineRunner, tray_factory=tray_factory)
    code = service.run(once=bool(getattr(args, "once", False)))
    if code == 2:
        return EXIT_TASK_FAILED, CliCommandResult(
            command=COMMAND,
            inputs={"action": "start"},
            summary={"running": True},
            errors=["Watch is already running."],
        )
    return code, CliCommandResult(command=COMMAND, inputs={"action": "start"}, summary={"exit_code": code})


def _handle_add(args):
    config_path, added = add_watch_roots(list(args.paths or []))
    config = load_config()
    reload_path = signal_reload(config)
    started = False
    if getattr(args, "start", False) and not _watch_running(config):
        started = _start_watch_background()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "add", "paths": list(args.paths or [])},
        summary={"config_path": str(config_path), "added": added, "reload_signal": reload_path, "started": started},
        items=added,
    )


def _handle_remove(args):
    config_path, removed = remove_watch_roots(list(args.paths or []))
    reload_path = signal_reload(load_config())
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "remove", "paths": list(args.paths or [])},
        summary={"config_path": str(config_path), "removed": removed, "reload_signal": reload_path},
        items=removed,
    )


def _handle_list():
    config_path, roots = list_watch_roots()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "list"},
        summary={"config_path": str(config_path), "count": len(roots)},
        items=roots,
    )


def _handle_reload():
    path = signal_reload(load_config())
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "reload"}, summary={"reload_signal": path})


def _handle_stop():
    path = signal_stop(load_config())
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "stop"}, summary={"stop_signal": path})


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
    if os.name != "nt":
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"action": "startup"}, summary={}, errors=["Startup integration is only available on Windows."])
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
    return os.path.exists(os.path.join(service_state_dir(config), SERVICE_LOCK))


def _start_watch_background() -> bool:
    creationflags = 0
    startupinfo = None
    if os.name == "nt":
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
    repo_script = Path(__file__).resolve().parents[3] / "sunpack.py"
    if repo_script.exists():
        return [sys.executable, str(repo_script), COMMAND, "start"]
    return [sys.executable, COMMAND, "start"]
