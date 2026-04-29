from __future__ import annotations

import os
import time

from sunpack.app.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.app.cli_parsers import (
    CliHelpFormatter,
    build_common_parser,
    build_extract_config_override_parser,
    build_password_parser,
    localize_help_action,
)
from sunpack.app.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_summary,
    collect_cli_passwords,
    password_summary_item,
    resolve_target_paths,
    result_for_missing,
)
from sunpack.app.cli_types import CliCommandResult
from sunpack.config.loader import load_config
from sunpack.coordinator.runner import PipelineRunner

COMMAND = "watch"
ORDER = 15
TEXTS = {
    "en": {
        "help": "Watch folders and automatically extract stable archive files.",
        "paths": "Folders or archive files to watch.",
        "started": "[WATCH] Watching {count} path(s). Output root: {out_dir}",
        "tick": "[WATCH] processed={processed} success={succeeded} failed={failed} pending={pending}",
        "stopped": "[WATCH] Stopped.",
        "interval": "Wake interval in seconds for stable-file checks.",
        "stable": "Seconds a file must stay unchanged before extraction.",
        "state": "Path to watcher state JSON file.",
        "once": "Run one polling pass and exit.",
        "no_recursive": "Only watch direct children of each folder.",
        "no_initial_scan": "Do not enqueue existing archive files when the watcher starts.",
        "max_folders": "Maximum number of folders/files accepted by one watcher.",
        "too_many_folders": "watch accepts at most {max_count} path(s).",
    },
    "zh": {
        "help": "监控文件夹，发现稳定的压缩文件后自动解压。",
        "paths": "要监控的文件夹或压缩文件。",
        "started": "[WATCH] 正在监控 {count} 个路径。输出根目录：{out_dir}",
        "tick": "[WATCH] processed={processed} success={succeeded} failed={failed} pending={pending}",
        "stopped": "[WATCH] 已停止。",
        "interval": "稳定文件检查唤醒间隔秒数。",
        "stable": "文件保持不变多少秒后才开始解压。",
        "state": "watcher 状态 JSON 文件路径。",
        "once": "只处理一轮事件队列后退出。",
        "no_recursive": "只监控每个文件夹的直接子项。",
        "no_initial_scan": "启动时不把已有压缩文件加入队列。",
        "max_folders": "单个 watcher 最多接受的监控路径数量。",
        "too_many_folders": "watch 最多接受 {max_count} 个路径。",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack watch [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))
    parser.add_argument("--interval", type=float, default=5.0, help=ctx.t(TEXTS, "interval"))
    parser.add_argument("--stable", type=float, default=10.0, help=ctx.t(TEXTS, "stable"))
    parser.add_argument("--state", dest="state_path", help=ctx.t(TEXTS, "state"))
    parser.add_argument("--once", action="store_true", help=ctx.t(TEXTS, "once"))
    parser.add_argument("--no-recursive", dest="recursive", action="store_false", default=True, help=ctx.t(TEXTS, "no_recursive"))
    parser.add_argument("--no-initial-scan", dest="initial_scan", action="store_false", default=True, help=ctx.t(TEXTS, "no_initial_scan"))
    parser.add_argument("--max-folders", type=int, default=16, help=ctx.t(TEXTS, "max_folders"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)
    if len(target_paths) > max(1, int(args.max_folders)):
        return EXIT_USAGE, CliCommandResult(
            command=COMMAND,
            inputs={"paths": list(args.paths)},
            summary={},
            errors=[ctx.t(TEXTS, "too_many_folders").format(max_count=args.max_folders)],
        )

    try:
        passwords = collect_cli_passwords(
            args,
            prompt_text=ctx.core_text("password_prompt"),
            input_prompt=ctx.core_text("password_input_prompt"),
        )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"paths": list(args.paths)}, summary={}, errors=[str(exc)])

    config = load_config()
    config_overrides = apply_runtime_config_overrides(config, args)
    password_summary = build_password_summary(passwords, use_builtin_passwords=not args.no_builtin_passwords)
    config["user_passwords"] = password_summary.user_passwords
    config["builtin_passwords"] = password_summary.builtin_passwords
    out_dir = config["output"]["root"]
    state_path = args.state_path or os.path.join(out_dir, ".sunpack_watch", "state.json")
    try:
        from sunpack.watch import WatchScheduler

        watcher = WatchScheduler(
            config,
            target_paths,
            out_dir=out_dir,
            state_path=state_path,
            interval_seconds=args.interval,
            stable_seconds=args.stable,
            recursive=args.recursive,
            initial_scan=args.initial_scan,
            runner_factory=PipelineRunner,
        )
    except Exception as exc:
        return EXIT_TASK_FAILED, CliCommandResult(
            command=COMMAND,
            inputs={"paths": target_paths, "out_dir": out_dir, "state_path": state_path},
            summary={},
            errors=[str(exc)],
            items=[password_summary_item(password_summary)],
        )
    reporter.info(ctx.t(TEXTS, "started").format(count=len(target_paths), out_dir=out_dir))

    results = []
    exit_code = 0
    try:
        watcher.start()
        if args.once:
            result = watcher.run_once()
            results.append(result)
            reporter.info(ctx.t(TEXTS, "tick").format(**result.__dict__))
        else:
            while True:
                result = watcher.run_once()
                results.append(result)
                reporter.info(ctx.t(TEXTS, "tick").format(**result.__dict__))
                time.sleep(watcher.interval_seconds)
    except KeyboardInterrupt:
        reporter.info(ctx.t(TEXTS, "stopped"))
    except Exception as exc:
        exit_code = EXIT_TASK_FAILED
        results.append(type("_Result", (), {"processed": 0, "succeeded": 0, "failed": 1, "pending": 0, "errors": [str(exc)]})())
    finally:
        watcher.stop()

    processed = sum(item.processed for item in results)
    succeeded = sum(item.succeeded for item in results)
    failed = sum(item.failed for item in results)
    pending = results[-1].pending if results else 0
    errors = [error for item in results for error in item.errors]
    return exit_code, CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "out_dir": out_dir,
            "state_path": state_path,
            "interval": args.interval,
            "stable": args.stable,
            "recursive": args.recursive,
            "once": args.once,
            "initial_scan": args.initial_scan,
            "max_folders": args.max_folders,
            "config_overrides": config_overrides,
        },
        summary={
            "processed_count": processed,
            "success_count": succeeded,
            "failed_count": failed,
            "pending_count": pending,
        },
        errors=errors,
        items=[password_summary_item(password_summary)],
    )
